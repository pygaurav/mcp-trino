package auth

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"strings"

	"github.com/golang-jwt/jwt/v5"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

// Context keys
type contextKey string

const (
	oauthTokenKey contextKey = "oauth_token"
	userContextKey contextKey = "user"
)

// WithOAuthToken adds an OAuth token to the context
func WithOAuthToken(ctx context.Context, token string) context.Context {
	return context.WithValue(ctx, oauthTokenKey, token)
}

// GetOAuthToken extracts an OAuth token from the context
func GetOAuthToken(ctx context.Context) (string, bool) {
	token, ok := ctx.Value(oauthTokenKey).(string)
	return token, ok
}

// OAuthMiddleware creates an authentication middleware for MCP tools
func OAuthMiddleware(enabled bool) func(server.ToolHandlerFunc) server.ToolHandlerFunc {
	return func(next server.ToolHandlerFunc) server.ToolHandlerFunc {
		return func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			if !enabled {
				// OAuth disabled, allow all requests
				log.Printf("OAuth: Authentication disabled - allowing tool: %s", req.Params.Name)
				return next(ctx, req)
			}

			// Extract token from context (set by HTTP context function)
			tokenString, ok := GetOAuthToken(ctx)
			if !ok {
				log.Printf("OAuth: No token found in context for tool: %s", req.Params.Name)
				return nil, fmt.Errorf("authentication required: missing OAuth token")
			}

			// Log token for debugging (first 50 chars)
			tokenPreview := tokenString
			if len(tokenString) > 50 {
				tokenPreview = tokenString[:50] + "..."
			}
			log.Printf("OAuth: Received token: %s", tokenPreview)

			// Basic JWT validation (simplified)
			user, err := validateJWT(tokenString)
			if err != nil {
				log.Printf("OAuth: Token validation failed for tool %s: %v", req.Params.Name, err)
				return nil, fmt.Errorf("authentication failed: %w", err)
			}

			// Add user to context
			ctx = context.WithValue(ctx, userContextKey, user)
			
			log.Printf("OAuth: Authenticated user %s for tool: %s", user.Username, req.Params.Name)
			return next(ctx, req)
		}
	}
}

// User represents an authenticated user
type User struct {
	Username string
	Email    string
	Subject  string
}

// validateJWT performs basic JWT validation
func validateJWT(tokenString string) (*User, error) {
	// Remove Bearer prefix if present
	tokenString = strings.TrimPrefix(tokenString, "Bearer ")
	
	// Parse JWT without verification for now (simplified)
	// In production, you should verify with proper key
	token, _, err := new(jwt.Parser).ParseUnverified(tokenString, jwt.MapClaims{})
	if err != nil {
		return nil, fmt.Errorf("failed to parse token: %w", err)
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, fmt.Errorf("invalid token claims")
	}

	// Extract user information
	user := &User{
		Subject:  getStringClaim(claims, "sub"),
		Username: getStringClaim(claims, "preferred_username"),
		Email:    getStringClaim(claims, "email"),
	}

	if user.Subject == "" {
		return nil, fmt.Errorf("missing subject in token")
	}

	return user, nil
}

// getStringClaim safely extracts a string claim
func getStringClaim(claims jwt.MapClaims, key string) string {
	if val, ok := claims[key].(string); ok {
		return val
	}
	return ""
}

// GetUserFromContext extracts user from context
func GetUserFromContext(ctx context.Context) (*User, bool) {
	user, ok := ctx.Value(userContextKey).(*User)
	return user, ok
}

// CreateHTTPContextFunc creates the HTTP context function for token extraction
func CreateHTTPContextFunc() func(context.Context, *http.Request) context.Context {
	return func(ctx context.Context, r *http.Request) context.Context {
		// Extract Bearer token from Authorization header
		authHeader := r.Header.Get("Authorization")
		if strings.HasPrefix(authHeader, "Bearer ") {
			token := strings.TrimPrefix(authHeader, "Bearer ")
			// Clean any whitespace
			token = strings.TrimSpace(token)
			ctx = WithOAuthToken(ctx, token)
			log.Printf("OAuth: Token extracted from request (length: %d)", len(token))
		} else if authHeader != "" {
			preview := authHeader
			if len(authHeader) > 30 {
				preview = authHeader[:30] + "..."
			}
			log.Printf("OAuth: Invalid Authorization header format: %s", preview)
		}
		return ctx
	}
}

// CreateRequestAuthHook creates a server-level authentication hook for all MCP requests
func CreateRequestAuthHook() func(context.Context, interface{}, interface{}) error {
	return func(ctx context.Context, id interface{}, message interface{}) error {
		// Extract token from context (set by HTTP context function)
		tokenString, ok := GetOAuthToken(ctx)
		if !ok {
			log.Printf("OAuth: No token found in context for request ID: %v", id)
			return fmt.Errorf("authentication required: missing OAuth token")
		}

		// Log token for debugging (first 50 chars)
		tokenPreview := tokenString
		if len(tokenString) > 50 {
			tokenPreview = tokenString[:50] + "..."
		}
		log.Printf("OAuth: Received token for request ID %v: %s", id, tokenPreview)

		// Basic JWT validation (simplified)
		user, err := validateJWT(tokenString)
		if err != nil {
			log.Printf("OAuth: Token validation failed for request ID %v: %v", id, err)
			return fmt.Errorf("authentication failed: %w", err)
		}

		log.Printf("OAuth: Authenticated user %s for request ID: %v", user.Username, id)
		return nil // Allow request to proceed
	}
}