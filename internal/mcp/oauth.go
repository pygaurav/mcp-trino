package mcp

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

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

// JWT secret caching
var (
	jwtSecret     string
	jwtSecretOnce sync.Once
)

// getJWTSecret retrieves and caches the JWT secret from environment
func getJWTSecret() (string, error) {
	jwtSecretOnce.Do(func() {
		jwtSecret = os.Getenv("JWT_SECRET")
	})
	
	if jwtSecret == "" {
		return "", fmt.Errorf("JWT_SECRET environment variable is required")
	}
	return jwtSecret, nil
}

// WithOAuthToken adds an OAuth token to the context
func WithOAuthToken(ctx context.Context, token string) context.Context {
	return context.WithValue(ctx, oauthTokenKey, token)
}

// GetOAuthToken extracts an OAuth token from the context
func GetOAuthToken(ctx context.Context) (string, bool) {
	token, ok := ctx.Value(oauthTokenKey).(string)
	return token, ok
}

// authenticateRequest is deprecated - authentication is now handled by provider-based middleware
func authenticateRequest(ctx context.Context, operation string) (context.Context, error) {
	return ctx, fmt.Errorf("deprecated authentication function called - use provider-based validation")
}

// OAuthMiddleware creates an authentication middleware for MCP tools
func OAuthMiddleware(validator TokenValidator, enabled bool) func(server.ToolHandlerFunc) server.ToolHandlerFunc {
	return func(next server.ToolHandlerFunc) server.ToolHandlerFunc {
		return func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			if !enabled {
				// OAuth disabled, allow all requests
				log.Printf("OAuth: Authentication disabled - allowing tool: %s", req.Params.Name)
				return next(ctx, req)
			}

			// Extract token from context (set by HTTP middleware)
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
			log.Printf("OAuth: Received token for tool %s: %s", req.Params.Name, tokenPreview)

			// Validate token using configured provider
			user, err := validator.ValidateToken(tokenString)
			if err != nil {
				log.Printf("OAuth: Token validation failed for tool %s: %v", req.Params.Name, err)
				return nil, fmt.Errorf("authentication failed: %w", err)
			}

			// Add user to context for downstream handlers
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

// validateJWT is deprecated - use provider-based validation instead

// validateTokenClaims validates standard JWT claims
func validateTokenClaims(claims jwt.MapClaims) error {
	// Validate expiration
	if exp, ok := claims["exp"]; ok {
		if expTime, ok := exp.(float64); ok {
			if time.Now().Unix() > int64(expTime) {
				return fmt.Errorf("token expired")
			}
		}
	}
	
	// Validate not before
	if nbf, ok := claims["nbf"]; ok {
		if nbfTime, ok := nbf.(float64); ok {
			if time.Now().Unix() < int64(nbfTime) {
				return fmt.Errorf("token not yet valid")
			}
		}
	}
	
	// Validate issued at (should not be in the future)
	if iat, ok := claims["iat"]; ok {
		if iatTime, ok := iat.(float64); ok {
			if time.Now().Unix() < int64(iatTime) {
				return fmt.Errorf("token issued in the future")
			}
		}
	}
	
	return nil
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
func CreateRequestAuthHook(validator TokenValidator) func(context.Context, interface{}, interface{}) error {
	return func(ctx context.Context, id interface{}, message interface{}) error {
		// Extract OAuth token from context
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
		log.Printf("OAuth: Validating token for request ID %v: %s", id, tokenPreview)

		// Validate token using configured provider
		user, err := validator.ValidateToken(tokenString)
		if err != nil {
			log.Printf("OAuth: Token validation failed for request ID %v: %v", id, err)
			return fmt.Errorf("authentication failed: %w", err)
		}

		// Add user to context for downstream handlers
		ctx = context.WithValue(ctx, userContextKey, user)
		log.Printf("OAuth: Authenticated user %s for request ID: %v", user.Username, id)

		return nil // Success
	}
}