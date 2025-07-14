package auth

import (
	"context"
	"fmt"
	"log"
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

// OAuthMiddleware creates an authentication middleware for MCP tools
func OAuthMiddleware(enabled bool) func(server.ToolHandlerFunc) server.ToolHandlerFunc {
	return func(next server.ToolHandlerFunc) server.ToolHandlerFunc {
		return func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			if !enabled {
				// OAuth disabled, allow all requests
				return next(ctx, req)
			}

			// Extract token from context (set by SSE context function)
			token := ctx.Value(oauthTokenKey)
			if token == nil {
				log.Printf("OAuth: No token found in context for tool: %s", req.Params.Name)
				return nil, fmt.Errorf("authentication required")
			}

			tokenString, ok := token.(string)
			if !ok {
				log.Printf("OAuth: Invalid token type in context for tool: %s", req.Params.Name)
				return nil, fmt.Errorf("invalid token format")
			}

			// Basic JWT validation (simplified)
			user, err := validateJWT(tokenString)
			if err != nil {
				log.Printf("OAuth: Token validation failed for tool %s: %v", req.Params.Name, err)
				return nil, fmt.Errorf("invalid token: %w", err)
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