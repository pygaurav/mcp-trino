package middleware

import (
	"context"
	"log"
	"net/http"
	"strings"

	"github.com/tuannvm/mcp-trino/internal/auth"
	"github.com/tuannvm/mcp-trino/internal/config"
)

// AuthMiddleware provides HTTP authentication middleware
type AuthMiddleware struct {
	config    *config.TrinoConfig
	validator *auth.BearerTokenValidator
}

// UserContextKey is the context key for user information
type UserContextKey string

const (
	// UserContext is the key for storing user information in request context
	UserContext UserContextKey = "user"
)

// NewAuthMiddleware creates a new authentication middleware
func NewAuthMiddleware(config *config.TrinoConfig, validator *auth.BearerTokenValidator) *AuthMiddleware {
	return &AuthMiddleware{
		config:    config,
		validator: validator,
	}
}

// AuthenticateRequest validates OAuth bearer tokens for HTTP requests
func (m *AuthMiddleware) AuthenticateRequest(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Skip authentication if OAuth is disabled
		if !m.config.OAuthEnabled {
			next.ServeHTTP(w, r)
			return
		}

		// Extract Bearer token from Authorization header
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			m.writeOAuthError(w, "invalid_request", "Missing Authorization header", http.StatusUnauthorized)
			return
		}

		if !strings.HasPrefix(authHeader, "Bearer ") {
			m.writeOAuthError(w, "invalid_request", "Invalid Authorization header format", http.StatusUnauthorized)
			return
		}

		token := strings.TrimPrefix(authHeader, "Bearer ")
		if token == "" {
			m.writeOAuthError(w, "invalid_token", "Empty bearer token", http.StatusUnauthorized)
			return
		}

		// Validate the token
		userInfo, err := m.validator.ValidateToken(token)
		if err != nil {
			log.Printf("Authentication failed: %v", err)
			m.writeOAuthError(w, "invalid_token", "Invalid or expired token", http.StatusUnauthorized)
			return
		}

		// Add user information to request context
		ctx := context.WithValue(r.Context(), UserContext, userInfo)
		r = r.WithContext(ctx)

		// Log successful authentication
		log.Printf("Authenticated user: %s (%s)", userInfo.Username, userInfo.Email)

		next.ServeHTTP(w, r)
	})
}

// writeOAuthError writes an OAuth 2.1 compliant error response
func (m *AuthMiddleware) writeOAuthError(w http.ResponseWriter, errorCode, description string, statusCode int) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("WWW-Authenticate", `Bearer realm="mcp-trino"`)
	w.WriteHeader(statusCode)

	// Write error response (simplified - in production, use proper JSON encoding)
	_, _ = w.Write([]byte(`{"error":"` + errorCode + `","error_description":"` + description + `"}`))
}

// GetUserFromContext extracts user information from request context
func GetUserFromContext(ctx context.Context) (*auth.UserInfo, bool) {
	user, ok := ctx.Value(UserContext).(*auth.UserInfo)
	return user, ok
}

// LogAuthenticationInfo logs authentication information for debugging
func LogAuthenticationInfo(ctx context.Context, operation string) {
	if user, ok := GetUserFromContext(ctx); ok {
		log.Printf("Operation: %s, User: %s (%s)", operation, user.Username, user.Email)
	} else {
		log.Printf("Operation: %s, User: anonymous", operation)
	}
}