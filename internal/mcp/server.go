package mcp

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
	"github.com/tuannvm/mcp-trino/internal/config"
	"github.com/tuannvm/mcp-trino/internal/oauth"
	"github.com/tuannvm/mcp-trino/internal/trino"
)

// Server represents the MCP server with all its components
type Server struct {
	mcpServer    *mcpserver.MCPServer
	config       *config.TrinoConfig
	version      string
	oauthHandler *oauth.OAuth2Handler
}

// NewServer creates a new MCP server instance with all components
func NewServer(trinoClient *trino.Client, trinoConfig *config.TrinoConfig, version string) *Server {
	// Create MCP server
	mcpServer := createMCPServer(trinoClient, trinoConfig, version)
	
	// Create OAuth2 handler if OAuth is enabled
	var oauthHandler *oauth.OAuth2Handler
	if trinoConfig.OAuthEnabled {
		oauthHandler = oauth.CreateOAuth2Handler(trinoConfig, version)
	}
	
	return &Server{
		mcpServer:    mcpServer,
		config:       trinoConfig,
		version:      version,
		oauthHandler: oauthHandler,
	}
}

// createMCPServer creates the core MCP server with tools and authentication
func createMCPServer(trinoClient *trino.Client, trinoConfig *config.TrinoConfig, version string) *mcpserver.MCPServer {
	// Create hooks for server-level authentication
	hooks := &mcpserver.Hooks{}
	
	mcpServer := mcpserver.NewMCPServer("Trino MCP Server", version,
		mcpserver.WithToolCapabilities(true),
		mcpserver.WithHooks(hooks),
	)

	// Setup OAuth authentication with provider support
	if err := setupOAuthServer(trinoConfig, mcpServer); err != nil {
		log.Printf("Warning: Failed to setup OAuth server: %v", err)
	}

	// Initialize tool handlers
	trinoHandlers := &TrinoHandlers{TrinoClient: trinoClient}
	RegisterTrinoTools(mcpServer, trinoHandlers)

	return mcpServer
}

// ServeStdio starts the MCP server with STDIO transport
func (s *Server) ServeStdio() error {
	return mcpserver.ServeStdio(s.mcpServer)
}

// ServeHTTP starts the MCP server with HTTP transport
func (s *Server) ServeHTTP(port string) error {
	addr := fmt.Sprintf(":%s", port)
	
	// Create StreamableHTTP server instance
	log.Println("Setting up StreamableHTTP server...")
	var streamableServer *mcpserver.StreamableHTTPServer
	if s.config.OAuthEnabled {
		// Create OAuth-aware HTTP context function
		oauthContextFunc := func(ctx context.Context, r *http.Request) context.Context {
			authHeader := r.Header.Get("Authorization")
			if strings.HasPrefix(authHeader, "Bearer ") {
				token := strings.TrimPrefix(authHeader, "Bearer ")
				token = strings.TrimSpace(token)
				ctx = oauth.WithOAuthToken(ctx, token)
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
			mcpserver.WithStateLess(false),
		)
	} else {
		streamableServer = mcpserver.NewStreamableHTTPServer(
			s.mcpServer,
			mcpserver.WithEndpointPath("/mcp"),
			mcpserver.WithStateLess(false),
		)
	}
	
	// Create HTTP mux for routing
	mux := http.NewServeMux()
	
	// Add status endpoint
	mux.HandleFunc("/", s.handleStatus)
	
	// Add OAuth metadata endpoints for MCP compliance
	if s.config.OAuthEnabled && s.oauthHandler != nil {
		// RFC 8414: OAuth 2.0 Authorization Server Metadata
		mux.HandleFunc("/.well-known/oauth-authorization-server", s.oauthHandler.HandleAuthorizationServerMetadata)
		// RFC 9728: OAuth 2.0 Protected Resource Metadata
		mux.HandleFunc("/.well-known/oauth-protected-resource", s.oauthHandler.HandleProtectedResourceMetadata)
		// Legacy endpoint for backward compatibility
		mux.HandleFunc("/.well-known/oauth-metadata", s.oauthHandler.HandleMetadata)
		
		// Add OAuth authorization flow endpoints
		mux.HandleFunc("/oauth/authorize", s.oauthHandler.HandleAuthorize)
		mux.HandleFunc("/oauth/callback", s.oauthHandler.HandleCallback)
		mux.HandleFunc("/oauth/register", s.oauthHandler.HandleRegister)
		mux.HandleFunc("/oauth/token", s.oauthHandler.HandleToken)
		
		// Add /callback redirect for Claude Code compatibility
		mux.HandleFunc("/callback", s.oauthHandler.HandleCallbackRedirect)
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
		// Check for HTTPS certificates
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
			if s.config.OAuthEnabled {
				log.Printf("  - OAuth callback: https://localhost%s/oauth/callback", addr)
				log.Printf("  - OAuth callback (Claude Code): https://localhost%s/callback (redirects to /oauth/callback)", addr)
			}
			
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
			if s.config.OAuthEnabled {
				log.Printf("  - OAuth callback: http://localhost%s/oauth/callback", addr)
				log.Printf("  - OAuth callback (Claude Code): http://localhost%s/callback (redirects to /oauth/callback)", addr)
			}
			
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
func (s *Server) createMCPHandler(streamableServer *mcpserver.StreamableHTTPServer) http.HandlerFunc {
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
								"token_endpoint":                        fmt.Sprintf("https://%s:%s/oauth/token", mcpHost, mcpPort),
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
				_ = json.NewEncoder(w).Encode(response)
				return
			}
			
			// Add OAuth context
			contextFunc := oauth.CreateHTTPContextFunc()
			ctx := contextFunc(r.Context(), r)
			r = r.WithContext(ctx)
		}
		
		// Handle MCP request using StreamableHTTP server
		streamableServer.ServeHTTP(w, r)
	}
}

// handleStatus handles the status endpoint
func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = fmt.Fprintf(w, `{"status":"ok","version":"%s"}`, s.version)
}

// handleSignals handles graceful shutdown signals
func (s *Server) handleSignals(done chan<- bool) {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGINT, syscall.SIGTERM)
	<-ch
	done <- true
}

// getOAuthStatus returns OAuth status string
func (s *Server) getOAuthStatus() string {
	if s.config.OAuthEnabled {
		return " (OAuth enabled)"
	}
	return " (OAuth disabled)"
}

// getOAuthStatusWithWarning returns OAuth status with warning for HTTP
func (s *Server) getOAuthStatusWithWarning() string {
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
	if err := setupOAuthServer(trinoConfig, mcpServer); err != nil {
		log.Printf("Warning: Failed to setup OAuth server: %v", err)
	}

	// Initialize tool handlers
	trinoHandlers := &TrinoHandlers{TrinoClient: trinoClient}
	RegisterTrinoTools(mcpServer, trinoHandlers)

	return mcpServer
}

// ServeStdio starts the MCP server with STDIO transport
func ServeStdio(mcpServer *mcpserver.MCPServer) error {
	return mcpserver.ServeStdio(mcpServer)
}

// setupOAuthServer initializes OAuth validation and sets up MCP server with middleware
func setupOAuthServer(cfg *config.TrinoConfig, mcpServer *mcpserver.MCPServer) error {
	if !cfg.OAuthEnabled {
		log.Println("OAuth authentication disabled")
		return nil
	}

	// Initialize OAuth provider using oauth package
	validator, err := oauth.SetupOAuth(cfg)
	if err != nil {
		return fmt.Errorf("failed to setup OAuth: %w", err)
	}

	if validator == nil {
		return nil // OAuth disabled
	}

	// Apply OAuth middleware to server
	if err := applyOAuthMiddleware(mcpServer, validator, cfg.OAuthEnabled); err != nil {
		return fmt.Errorf("failed to apply OAuth middleware: %w", err)
	}

	return nil
}


// applyOAuthMiddleware applies OAuth middleware to the MCP server
func applyOAuthMiddleware(mcpServer *mcpserver.MCPServer, validator oauth.TokenValidator, enabled bool) error {
	// Create middleware function
	middleware := oauth.OAuthMiddleware(validator, enabled)

	// Store the middleware in the server for use during tool handler registration
	// This will be applied when handlers are registered
	setOAuthMiddleware(mcpServer, middleware)

	return nil
}

// Middleware storage for the MCP server
var serverMiddleware map[*mcpserver.MCPServer]func(mcpserver.ToolHandlerFunc) mcpserver.ToolHandlerFunc

func init() {
	serverMiddleware = make(map[*mcpserver.MCPServer]func(mcpserver.ToolHandlerFunc) mcpserver.ToolHandlerFunc)
}

// setOAuthMiddleware stores the OAuth middleware for a server
func setOAuthMiddleware(mcpServer *mcpserver.MCPServer, middleware func(mcpserver.ToolHandlerFunc) mcpserver.ToolHandlerFunc) {
	serverMiddleware[mcpServer] = middleware
}

// GetOAuthMiddleware retrieves the OAuth middleware for a server
func GetOAuthMiddleware(mcpServer *mcpserver.MCPServer) func(mcpserver.ToolHandlerFunc) mcpserver.ToolHandlerFunc {
	return serverMiddleware[mcpServer]
}

// getEnv gets environment variable with default value
func getEnv(key, def string) string {
	if v, ok := os.LookupEnv(key); ok {
		return v
	}
	return def
}



