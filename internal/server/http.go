package server

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
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
	streamableServer := mcpserver.NewStreamableHTTPServer(
		s.mcpServer,
		mcpserver.WithEndpointPath("/mcp"),
		mcpserver.WithHTTPContextFunc(auth.CreateHTTPContextFunc()),
		mcpserver.WithStateLess(false), // Enable session management
	)
	
	// Create HTTP mux for routing
	mux := http.NewServeMux()
	
	// Add status endpoint
	mux.HandleFunc("/", s.handleStatus)
	
	// Add OAuth metadata endpoint for MCP compliance
	mux.HandleFunc("/.well-known/oauth-metadata", s.handleOAuthMetadata)
	
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
			log.Printf("  - OAuth metadata: https://localhost%s/.well-known/oauth-metadata", addr)
			
			if err := httpServer.ListenAndServeTLS(certFile, keyFile); err != nil && err != http.ErrServerClosed {
				log.Fatalf("HTTPS server error: %v", err)
			}
		} else {
			// Start HTTP server
			oauthStatus := s.getOAuthStatusWithWarning()
			
			log.Printf("Starting HTTP server on %s%s", addr, oauthStatus)
			log.Printf("  - Modern endpoint: http://localhost%s/mcp", addr)
			log.Printf("  - Legacy endpoint: http://localhost%s/sse (backward compatibility)", addr)
			log.Printf("  - OAuth metadata: http://localhost%s/.well-known/oauth-metadata", addr)
			
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
	
	// OAuth enabled - return configuration metadata
	w.WriteHeader(http.StatusOK)
	_, _ = fmt.Fprintf(w, `{
		"oauth_enabled": true,
		"authentication_methods": ["bearer_token"],
		"token_types": ["JWT"],
		"token_validation": "server_side",
		"supported_flows": ["claude_code", "mcp_remote"],
		"mcp_version": "1.0.0",
		"server_version": "%s"
	}`, s.version)
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
	if trinoConfig.OAuthEnabled {
		hooks.AddOnRequestInitialization(auth.CreateRequestAuthHook())
	}
	
	mcpServer := mcpserver.NewMCPServer("Trino MCP Server", version,
		mcpserver.WithToolCapabilities(true),
		mcpserver.WithHooks(hooks),
	)

	// Initialize tool handlers
	trinoHandlers := handlers.NewTrinoHandlers(trinoClient)
	handlers.RegisterTrinoTools(mcpServer, trinoHandlers)

	return mcpServer
}

// ServeStdio starts the MCP server with STDIO transport
func ServeStdio(mcpServer *mcpserver.MCPServer) error {
	return mcpserver.ServeStdio(mcpServer)
}

// getEnv gets environment variable with default value
func getEnv(key, def string) string {
	if v, ok := os.LookupEnv(key); ok {
		return v
	}
	return def
}