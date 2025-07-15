package auth

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

// authenticateRequest performs JWT validation and returns user context
// This shared function consolidates authentication logic used by both OAuthMiddleware and CreateRequestAuthHook
func authenticateRequest(ctx context.Context, operation string) (context.Context, error) {
	tokenString, ok := GetOAuthToken(ctx)
	if !ok {
		log.Printf("OAuth: No token found in context for %s", operation)
		return ctx, fmt.Errorf("authentication required: missing OAuth token")
	}

	// Log token for debugging (first 50 chars)
	tokenPreview := tokenString
	if len(tokenString) > 50 {
		tokenPreview = tokenString[:50] + "..."
	}
	log.Printf("OAuth: Received token for %s: %s", operation, tokenPreview)

	// JWT validation
	user, err := validateJWT(tokenString)
	if err != nil {
		log.Printf("OAuth: Token validation failed for %s: %v", operation, err)
		return ctx, fmt.Errorf("authentication failed: %w", err)
	}

	// Add user to context
	ctx = context.WithValue(ctx, userContextKey, user)
	log.Printf("OAuth: Authenticated user %s for %s", user.Username, operation)
	return ctx, nil
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

			// Use shared authentication logic
			authenticatedCtx, err := authenticateRequest(ctx, fmt.Sprintf("tool: %s", req.Params.Name))
			if err != nil {
				return nil, err
			}

			return next(authenticatedCtx, req)
		}
	}
}

// User represents an authenticated user
type User struct {
	Username string
	Email    string
	Subject  string
}

// validateJWT performs JWT validation with proper signature verification
func validateJWT(tokenString string) (*User, error) {
	// Remove Bearer prefix if present
	tokenString = strings.TrimPrefix(tokenString, "Bearer ")
	
	// Get cached JWT secret
	secret, err := getJWTSecret()
	if err != nil {
		return nil, fmt.Errorf("JWT secret not configured: %w", err)
	}
	
	// Parse and validate JWT with signature verification
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		// Validate signing method
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(secret), nil
	})
	
	if err != nil {
		return nil, fmt.Errorf("failed to parse and validate token: %w", err)
	}

	if !token.Valid {
		return nil, fmt.Errorf("invalid token")
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, fmt.Errorf("invalid token claims")
	}

	// Validate required claims
	if err := validateTokenClaims(claims); err != nil {
		return nil, fmt.Errorf("token validation failed: %w", err)
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
func CreateRequestAuthHook() func(context.Context, interface{}, interface{}) error {
	return func(ctx context.Context, id interface{}, message interface{}) error {
		// Use shared authentication logic
		_, err := authenticateRequest(ctx, fmt.Sprintf("request ID: %v", id))
		return err // Return error if authentication failed, nil if successful
	}
}