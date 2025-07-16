package auth

import (
	"fmt"
	"log"

	"github.com/mark3labs/mcp-go/server"
	"github.com/tuannvm/mcp-trino/internal/config"
)

// SetupOAuthServer initializes OAuth validation and sets up MCP server with middleware
func SetupOAuthServer(cfg *config.TrinoConfig, mcpServer *server.MCPServer) error {
	if !cfg.OAuthEnabled {
		log.Println("OAuth authentication disabled")
		return nil
	}

	// Initialize OAuth provider based on configuration
	validator, err := createValidator(cfg)
	if err != nil {
		return fmt.Errorf("failed to create OAuth validator: %w", err)
	}

	if err := validator.Initialize(cfg); err != nil {
		return fmt.Errorf("failed to initialize OAuth validator: %w", err)
	}

	// Apply OAuth middleware to server
	if err := applyOAuthMiddleware(mcpServer, validator, cfg.OAuthEnabled); err != nil {
		return fmt.Errorf("failed to apply OAuth middleware: %w", err)
	}

	log.Printf("OAuth authentication enabled with provider: %s", cfg.OAuthProvider)
	return nil
}

// CreateValidator creates the appropriate token validator based on configuration (exported)
func CreateValidator(cfg *config.TrinoConfig) (TokenValidator, error) {
	switch cfg.OAuthProvider {
	case "hmac":
		return &HMACValidator{}, nil
	case "okta", "google", "azure":
		return &OIDCValidator{}, nil
	default:
		log.Printf("Unknown OAuth provider '%s', defaulting to HMAC", cfg.OAuthProvider)
		return &HMACValidator{}, nil
	}
}

// createValidator creates the appropriate token validator based on configuration (internal)
func createValidator(cfg *config.TrinoConfig) (TokenValidator, error) {
	return CreateValidator(cfg)
}

// applyOAuthMiddleware applies OAuth middleware to the MCP server
func applyOAuthMiddleware(mcpServer *server.MCPServer, validator TokenValidator, enabled bool) error {
	// Create middleware function
	middleware := OAuthMiddleware(validator, enabled)

	// Store the middleware in the server for use during tool handler registration
	// This will be applied when handlers are registered
	setOAuthMiddleware(mcpServer, middleware)

	return nil
}

// Middleware storage for the MCP server
var serverMiddleware map[*server.MCPServer]func(server.ToolHandlerFunc) server.ToolHandlerFunc

func init() {
	serverMiddleware = make(map[*server.MCPServer]func(server.ToolHandlerFunc) server.ToolHandlerFunc)
}

// setOAuthMiddleware stores the OAuth middleware for a server
func setOAuthMiddleware(mcpServer *server.MCPServer, middleware func(server.ToolHandlerFunc) server.ToolHandlerFunc) {
	serverMiddleware[mcpServer] = middleware
}

// GetOAuthMiddleware retrieves the OAuth middleware for a server
func GetOAuthMiddleware(mcpServer *server.MCPServer) func(server.ToolHandlerFunc) server.ToolHandlerFunc {
	return serverMiddleware[mcpServer]
}