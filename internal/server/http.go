package server

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	mcpserver "github.com/mark3labs/mcp-go/server"
	"github.com/tuannvm/mcp-trino/internal/auth"
	"github.com/tuannvm/mcp-trino/internal/config"
	"github.com/tuannvm/mcp-trino/internal/handlers"
	"github.com/tuannvm/mcp-trino/internal/trino"
)

// HTTPServer manages the HTTP/HTTPS server for MCP
type HTTPServer struct {
	mcpServer *mcpserver.MCPServer
	config    *config.TrinoConfig
	version   string
}

// NewHTTPServer creates a new HTTP server instance
func NewHTTPServer(mcpServer *mcpserver.MCPServer, config *config.TrinoConfig, version string) *HTTPServer {
	return &HTTPServer{
		mcpServer: mcpServer,
		config:    config,
		version:   version,
	}
}

// Start starts the HTTP server with the specified port
func (s *HTTPServer) Start(port string) error {
	addr := fmt.Sprintf(":%s", port)
	
	// Create StreamableHTTP server instance
	log.Println("Setting up StreamableHTTP server...")
	// Configure StreamableHTTPServer with OAuth support
	var streamableServer *mcpserver.StreamableHTTPServer
	if s.config.OAuthEnabled {
		// Create OAuth-aware HTTP context function
		oauthContextFunc := func(ctx context.Context, r *http.Request) context.Context {
			// Extract OAuth token from Authorization header
			authHeader := r.Header.Get("Authorization")
			if strings.HasPrefix(authHeader, "Bearer ") {
				token := strings.TrimPrefix(authHeader, "Bearer ")
				token = strings.TrimSpace(token)
				ctx = auth.WithOAuthToken(ctx, token)
				log.Printf("OAuth: Token extracted from request (length: %d)", len(token))
			} else {
				log.Printf("OAuth: No valid Authorization header found")
			}
			return ctx
		}
		
		streamableServer = mcpserver.NewStreamableHTTPServer(
			s.mcpServer,
			mcpserver.WithEndpointPath("/mcp"),
			mcpserver.WithHTTPContextFunc(oauthContextFunc),
			mcpserver.WithStateLess(false), // Enable session management
		)
	} else {
		streamableServer = mcpserver.NewStreamableHTTPServer(
			s.mcpServer,
			mcpserver.WithEndpointPath("/mcp"),
			mcpserver.WithStateLess(false), // Enable session management
		)
	}
	
	// Create HTTP mux for routing
	mux := http.NewServeMux()
	
	// Add status endpoint
	mux.HandleFunc("/", s.handleStatus)
	
	// Add OAuth metadata endpoints for MCP compliance
	// RFC 8414: OAuth 2.0 Authorization Server Metadata
	mux.HandleFunc("/.well-known/oauth-authorization-server", s.handleOAuthAuthorizationServerMetadata)
	// RFC 9728: OAuth 2.0 Protected Resource Metadata
	mux.HandleFunc("/.well-known/oauth-protected-resource", s.handleOAuthProtectedResourceMetadata)
	// Legacy endpoint for backward compatibility
	mux.HandleFunc("/.well-known/oauth-metadata", s.handleOAuthMetadata)
	
	// Add OAuth authorization flow endpoints
	if s.config.OAuthEnabled {
		mux.HandleFunc("/oauth/authorize", s.handleOAuthAuthorize)
		mux.HandleFunc("/oauth/callback", s.handleOAuthCallback)
		// Add a simple client registration endpoint that accepts mcp-remote
		mux.HandleFunc("/oauth/register", s.handleOAuthRegister)
	}
	
	// Shared MCP handler function for both endpoints
	mcpHandler := s.createMCPHandler(streamableServer)
	
	// Add MCP endpoint (modern)
	mux.HandleFunc("/mcp", mcpHandler)
	
	// Add SSE endpoint (backward compatibility)
	mux.HandleFunc("/sse", mcpHandler)

	httpServer := &http.Server{
		Addr:    addr,
		Handler: mux,
	}

	// Graceful shutdown
	done := make(chan bool, 1)
	go s.handleSignals(done)

	go func() {
		// Check for HTTPS certificates (independent of OAuth)
		certFile := getEnv("HTTPS_CERT_FILE", "")
		keyFile := getEnv("HTTPS_KEY_FILE", "")
		
		if certFile != "" && keyFile != "" {
			// Start HTTPS server
			oauthStatus := s.getOAuthStatus()
			
			log.Printf("Starting HTTPS server on %s%s", addr, oauthStatus)
			log.Printf("  - Modern endpoint: https://localhost%s/mcp", addr)
			log.Printf("  - Legacy endpoint: https://localhost%s/sse (backward compatibility)", addr)
			log.Printf("  - OAuth metadata: https://localhost%s/.well-known/oauth-authorization-server", addr)
			log.Printf("  - OAuth metadata (legacy): https://localhost%s/.well-known/oauth-metadata", addr)
			
			if err := httpServer.ListenAndServeTLS(certFile, keyFile); err != nil && err != http.ErrServerClosed {
				log.Fatalf("HTTPS server error: %v", err)
			}
		} else {
			// Start HTTP server
			oauthStatus := s.getOAuthStatusWithWarning()
			
			log.Printf("Starting HTTP server on %s%s", addr, oauthStatus)
			log.Printf("  - Modern endpoint: http://localhost%s/mcp", addr)
			log.Printf("  - Legacy endpoint: http://localhost%s/sse (backward compatibility)", addr)
			log.Printf("  - OAuth metadata: http://localhost%s/.well-known/oauth-authorization-server", addr)
			log.Printf("  - OAuth metadata (legacy): http://localhost%s/.well-known/oauth-metadata", addr)
			
			if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				log.Fatalf("HTTP server error: %v", err)
			}
		}
	}()

	<-done
	log.Println("Shutting down HTTP server...")
	
	// Allow 30 seconds for graceful shutdown
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	
	log.Println("Waiting for active connections to finish (max 30 seconds)...")
	if err := httpServer.Shutdown(ctx); err != nil {
		log.Printf("HTTP server forced shutdown after timeout: %v", err)
		return httpServer.Close()
	}
	log.Println("HTTP server shutdown completed gracefully")
	return nil
}

// createMCPHandler creates the shared MCP handler function
func (s *HTTPServer) createMCPHandler(streamableServer *mcpserver.StreamableHTTPServer) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Add CORS headers
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
		
		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}
		
		log.Printf("MCP %s %s", r.Method, r.URL.Path)
		
		// Check if OAuth is enabled and no token is provided
		if s.config.OAuthEnabled {
			authHeader := r.Header.Get("Authorization")
			if authHeader == "" || !strings.HasPrefix(authHeader, "Bearer ") {
				// Return 401 with OAuth discovery information
				log.Printf("OAuth: No bearer token provided, returning 401 with discovery info")
				
				// Use MCP server host/port, not Trino
				mcpHost := getEnv("MCP_HOST", "localhost")
				mcpPort := getEnv("MCP_PORT", "8080")
				
				w.Header().Set("WWW-Authenticate", fmt.Sprintf(`Bearer realm="%s", authorization_uri="%s/.well-known/oauth-authorization-server"`, 
					mcpHost, 
					fmt.Sprintf("https://%s:%s", mcpHost, mcpPort)))
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusUnauthorized)
				
				// Return error response that triggers OAuth discovery
				// This format is what mcp-remote expects
				// Use local registration endpoint that will accept mcp-remote and redirect to Okta
				response := map[string]interface{}{
					"jsonrpc": "2.0",
					"id": nil,
					"error": map[string]interface{}{
						"code": -32600,
						"message": "Invalid Request",
						"data": map[string]interface{}{
							"oauth": map[string]interface{}{
								"issuer":                                 fmt.Sprintf("https://%s:%s", mcpHost, mcpPort),
								"authorization_endpoint":                 fmt.Sprintf("https://%s:%s/oauth/authorize", mcpHost, mcpPort),
								"token_endpoint":                        s.config.OIDCIssuer + "/oauth2/v1/token",
								"registration_endpoint":                 fmt.Sprintf("https://%s:%s/oauth/register", mcpHost, mcpPort),
								"response_types_supported":              []string{"code"},
								"response_modes_supported":              []string{"query"},
								"grant_types_supported":                 []string{"authorization_code", "refresh_token"},
								"token_endpoint_auth_methods_supported": []string{"client_secret_basic", "client_secret_post", "none"},
								"code_challenge_methods_supported":      []string{"plain", "S256"},
							},
						},
					},
				}
				json.NewEncoder(w).Encode(response)
				return
			}
			
			// Add OAuth context
			contextFunc := auth.CreateHTTPContextFunc()
			ctx := contextFunc(r.Context(), r)
			r = r.WithContext(ctx)
		}
		
		// Handle MCP request using StreamableHTTP server
		streamableServer.ServeHTTP(w, r)
	}
}

// handleStatus handles the status endpoint
func (s *HTTPServer) handleStatus(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = fmt.Fprintf(w, `{"status":"ok","version":"%s"}`, s.version)
}

// handleOAuthMetadata handles the OAuth metadata endpoint for MCP compliance
func (s *HTTPServer) handleOAuthMetadata(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "public, max-age=300") // Cache for 5 minutes
	
	if r.Method != "GET" {
		w.WriteHeader(http.StatusMethodNotAllowed)
		_, _ = fmt.Fprintf(w, `{"error":"Method not allowed"}`)
		return
	}
	
	// Return OAuth metadata based on configuration
	if !s.config.OAuthEnabled {
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprintf(w, `{
			"oauth_enabled": false,
			"authentication_methods": ["none"],
			"mcp_version": "1.0.0"
		}`)
		return
	}
	
	// Create provider-specific metadata
	metadata := map[string]interface{}{
		"oauth_enabled": true,
		"authentication_methods": []string{"bearer_token"},
		"token_types": []string{"JWT"},
		"token_validation": "server_side",
		"supported_flows": []string{"claude_code", "mcp_remote"},
		"mcp_version": "1.0.0",
		"server_version": s.version,
		"provider": s.config.OAuthProvider,
		"authorization_endpoint": fmt.Sprintf("https://%s:%d/oauth/authorize", s.config.Host, s.config.Port),
		"token_endpoint": s.config.OIDCIssuer + "/oauth2/v1/token",
	}
	
	// Add provider-specific metadata
	switch s.config.OAuthProvider {
	case "hmac":
		metadata["validation_method"] = "hmac_sha256"
		metadata["signature_algorithm"] = "HS256"
		metadata["requires_secret"] = true
	case "okta":
		metadata["validation_method"] = "oidc_jwks"
		metadata["signature_algorithm"] = "RS256"
		metadata["requires_secret"] = false
		if s.config.OIDCIssuer != "" {
			metadata["issuer"] = s.config.OIDCIssuer
			metadata["jwks_uri"] = s.config.OIDCIssuer + "/.well-known/jwks.json"
		}
		if s.config.OIDCAudience != "" {
			metadata["audience"] = s.config.OIDCAudience
		}
	case "google":
		metadata["validation_method"] = "oidc_jwks"
		metadata["signature_algorithm"] = "RS256"
		metadata["requires_secret"] = false
		if s.config.OIDCIssuer != "" {
			metadata["issuer"] = s.config.OIDCIssuer
			metadata["jwks_uri"] = s.config.OIDCIssuer + "/.well-known/jwks.json"
		}
		if s.config.OIDCAudience != "" {
			metadata["audience"] = s.config.OIDCAudience
		}
	case "azure":
		metadata["validation_method"] = "oidc_jwks"
		metadata["signature_algorithm"] = "RS256"
		metadata["requires_secret"] = false
		if s.config.OIDCIssuer != "" {
			metadata["issuer"] = s.config.OIDCIssuer
			metadata["jwks_uri"] = s.config.OIDCIssuer + "/.well-known/jwks.json"
		}
		if s.config.OIDCAudience != "" {
			metadata["audience"] = s.config.OIDCAudience
		}
	}
	
	// Encode and send response
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(metadata); err != nil {
		log.Printf("Error encoding OAuth metadata: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
	}
}

// handleOAuthAuthorize handles OAuth authorization requests
func (s *HTTPServer) handleOAuthAuthorize(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Use MCP server host/port for callback URL
	mcpHost := getEnv("MCP_HOST", "localhost")
	mcpPort := getEnv("MCP_PORT", "8080")

	// Build Okta authorization URL
	authURL := fmt.Sprintf("%s/oauth2/v1/authorize?client_id=%s&response_type=code&scope=openid%%20profile%%20email&redirect_uri=%s&state=%s",
		s.config.OIDCIssuer,
		s.config.OIDCClientID,
		fmt.Sprintf("https://%s:%s/oauth/callback", mcpHost, mcpPort),
		"oauth-state-123", // TODO: Generate random state
	)

	log.Printf("OAuth: Redirecting to Okta authorization URL: %s", authURL)
	http.Redirect(w, r, authURL, http.StatusTemporaryRedirect)
}

// handleOAuthAuthorizationServerMetadata handles the standard OAuth 2.0 Authorization Server Metadata endpoint
func (s *HTTPServer) handleOAuthAuthorizationServerMetadata(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "public, max-age=300") // Cache for 5 minutes
	
	if r.Method != "GET" {
		w.WriteHeader(http.StatusMethodNotAllowed)
		_, _ = fmt.Fprintf(w, `{"error":"Method not allowed"}`)
		return
	}
	
	log.Printf("OAuth: Authorization Server Metadata request from %s", r.RemoteAddr)
	
	// Determine the correct host and port for MCP server (not Trino)
	mcpHost := getEnv("MCP_HOST", "localhost")
	mcpPort := getEnv("MCP_PORT", "8080")
	
	// Return OAuth 2.0 Authorization Server Metadata (RFC 8414)
	// This is what mcp-remote expects
	metadata := map[string]interface{}{
		"issuer":                                 fmt.Sprintf("https://%s:%s", mcpHost, mcpPort),
		"authorization_endpoint":                 fmt.Sprintf("https://%s:%s/oauth/authorize", mcpHost, mcpPort),
		"token_endpoint":                        fmt.Sprintf("https://%s:%s/oauth/token", mcpHost, mcpPort),
		"registration_endpoint":                 fmt.Sprintf("https://%s:%s/oauth/register", mcpHost, mcpPort),
		"response_types_supported":              []string{"code"},
		"response_modes_supported":              []string{"query"},
		"grant_types_supported":                 []string{"authorization_code", "refresh_token"},
		"token_endpoint_auth_methods_supported": []string{"client_secret_basic", "client_secret_post", "none"},
		"code_challenge_methods_supported":      []string{"plain", "S256"},
		"revocation_endpoint":                   fmt.Sprintf("https://%s:%s/oauth/revoke", mcpHost, mcpPort),
	}
	
	// Encode and send response
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(metadata); err != nil {
		log.Printf("Error encoding OAuth Authorization Server metadata: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
	}
}

// handleOAuthProtectedResourceMetadata handles the OAuth 2.0 Protected Resource Metadata endpoint
func (s *HTTPServer) handleOAuthProtectedResourceMetadata(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "public, max-age=300") // Cache for 5 minutes
	
	if r.Method != "GET" {
		w.WriteHeader(http.StatusMethodNotAllowed)
		_, _ = fmt.Fprintf(w, `{"error":"Method not allowed"}`)
		return
	}
	
	log.Printf("OAuth: Protected Resource Metadata request from %s", r.RemoteAddr)
	
	// Use MCP server host/port for URLs
	mcpHost := getEnv("MCP_HOST", "localhost")
	mcpPort := getEnv("MCP_PORT", "8080")
	
	// Return OAuth 2.0 Protected Resource Metadata (RFC 9728)
	metadata := map[string]interface{}{
		"resource":                               fmt.Sprintf("https://%s:%s", mcpHost, mcpPort),
		"authorization_servers":                  []string{fmt.Sprintf("https://%s:%s", mcpHost, mcpPort)},
		"bearer_methods_supported":              []string{"header"},
		"resource_signing_alg_values_supported": []string{"RS256"},
		"resource_documentation":                fmt.Sprintf("https://%s:%s/docs", mcpHost, mcpPort),
		"resource_policy_uri":                   fmt.Sprintf("https://%s:%s/policy", mcpHost, mcpPort),
		"resource_tos_uri":                      fmt.Sprintf("https://%s:%s/tos", mcpHost, mcpPort),
	}
	
	// Encode and send response
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(metadata); err != nil {
		log.Printf("Error encoding OAuth Protected Resource metadata: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
	}
}

// handleOAuthCallback handles OAuth callback from Okta
func (s *HTTPServer) handleOAuthCallback(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Extract authorization code and state
	code := r.URL.Query().Get("code")
	state := r.URL.Query().Get("state")
	errorParam := r.URL.Query().Get("error")

	log.Printf("OAuth: Callback received - code: %s, state: %s, error: %s", 
		code[:10]+"...", state, errorParam)

	if errorParam != "" {
		errorDesc := r.URL.Query().Get("error_description")
		log.Printf("OAuth: Authorization error: %s - %s", errorParam, errorDesc)
		http.Error(w, fmt.Sprintf("Authorization failed: %s", errorDesc), http.StatusBadRequest)
		return
	}

	if code == "" {
		log.Printf("OAuth: No authorization code received")
		http.Error(w, "No authorization code received", http.StatusBadRequest)
		return
	}

	// TODO: Validate state parameter for CSRF protection
	// TODO: Exchange code for tokens
	// TODO: Store tokens in session

	// For now, return success page
	w.Header().Set("Content-Type", "text/html")
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, `
		<html>
		<head><title>OAuth Success</title></head>
		<body>
			<h2>Authentication Successful!</h2>
			<p>You have been successfully authenticated with Okta.</p>
			<p>You can now close this window and return to your application.</p>
		</body>
		</html>
	`)
}

// handleSignals handles graceful shutdown signals
func (s *HTTPServer) handleSignals(done chan<- bool) {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGINT, syscall.SIGTERM)
	<-ch
	done <- true
}

// getOAuthStatus returns OAuth status string
func (s *HTTPServer) getOAuthStatus() string {
	if s.config.OAuthEnabled {
		return " (OAuth enabled)"
	}
	return " (OAuth disabled)"
}

// getOAuthStatusWithWarning returns OAuth status with warning for HTTP
func (s *HTTPServer) getOAuthStatusWithWarning() string {
	if s.config.OAuthEnabled {
		return " (OAuth enabled - WARNING: HTTPS recommended for production)"
	}
	return " (OAuth disabled)"
}

// NewMCPServer creates a new MCP server with the given configuration
func NewMCPServer(trinoClient *trino.Client, trinoConfig *config.TrinoConfig, version string) *mcpserver.MCPServer {
	// Create hooks for server-level authentication
	hooks := &mcpserver.Hooks{}
	// NOTE: We don't add authentication hooks here anymore
	// OAuth discovery happens at the HTTP transport level
	
	mcpServer := mcpserver.NewMCPServer("Trino MCP Server", version,
		mcpserver.WithToolCapabilities(true),
		mcpserver.WithHooks(hooks),
	)

	// Setup OAuth authentication with provider support
	if err := auth.SetupOAuthServer(trinoConfig, mcpServer); err != nil {
		log.Printf("Warning: Failed to setup OAuth server: %v", err)
	}

	// Initialize tool handlers
	trinoHandlers := handlers.NewTrinoHandlers(trinoClient)
	handlers.RegisterTrinoTools(mcpServer, trinoHandlers)

	return mcpServer
}

// ServeStdio starts the MCP server with STDIO transport
func ServeStdio(mcpServer *mcpserver.MCPServer) error {
	return mcpserver.ServeStdio(mcpServer)
}


// handleOAuthRegister handles OAuth dynamic client registration for mcp-remote
func (s *HTTPServer) handleOAuthRegister(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	log.Printf("OAuth: Client registration request from %s", r.RemoteAddr)

	// Parse the registration request
	var regRequest map[string]interface{}
	if err := json.NewDecoder(r.Body).Decode(&regRequest); err != nil {
		log.Printf("OAuth: Failed to parse registration request: %v", err)
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	log.Printf("OAuth: Registration request: %+v", regRequest)

	// Accept any client registration from mcp-remote
	// Return our pre-configured Okta client_id
	response := map[string]interface{}{
		"client_id":                s.config.OIDCClientID, // Use our Okta client ID
		"client_secret":            "", // Public client, no secret  
		"client_id_issued_at":      time.Now().Unix(),
		"grant_types":              []string{"authorization_code", "refresh_token"},
		"response_types":           []string{"code"},
		"redirect_uris":            regRequest["redirect_uris"],
		"token_endpoint_auth_method": "none",
		"application_type":         "native",
		"client_name":              regRequest["client_name"],
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	if err := json.NewEncoder(w).Encode(response); err != nil {
		log.Printf("OAuth: Failed to encode registration response: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
	}
}

// getEnv gets environment variable with default value
func getEnv(key, def string) string {
	if v, ok := os.LookupEnv(key); ok {
		return v
	}
	return def
}