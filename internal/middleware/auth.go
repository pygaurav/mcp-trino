package middleware

import (
	"context"
	"log"
	"net/http"

	"github.com/tuannvm/mcp-trino/internal/auth"
	"github.com/tuannvm/mcp-trino/internal/config"
)

// AuthMiddleware provides authentication middleware for HTTP requests
type AuthMiddleware struct {
	config    *config.TrinoConfig
	validator *auth.BearerTokenValidator
}

// NewAuthMiddleware creates a new authentication middleware
func NewAuthMiddleware(cfg *config.TrinoConfig, validator *auth.BearerTokenValidator) *AuthMiddleware {
	return &AuthMiddleware{
		config:    cfg,
		validator: validator,
	}
}

// AuthenticateRequest is the main authentication middleware
func (m *AuthMiddleware) AuthenticateRequest(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check if OAuth is enabled
		if !m.config.OAuthEnabled {
			// OAuth disabled, allow request without authentication
			next.ServeHTTP(w, r)
			return
		}

		// OAuth enabled, require authentication
		m.requireAuthentication(next).ServeHTTP(w, r)
	})
}

// requireAuthentication enforces Bearer token authentication
func (m *AuthMiddleware) requireAuthentication(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Extract Bearer token
		tokenString, err := auth.ExtractBearerToken(r)
		if err != nil {
			log.Printf("Authentication failed: %v", err)
			m.writeAuthError(w, "Authorization required", http.StatusUnauthorized)
			return
		}

		// Validate token
		userCtx, err := m.validator.ValidateToken(tokenString)
		if err != nil {
			log.Printf("Token validation failed: %v", err)
			
			// Provide specific error messages for different failure types
			switch err {
			case auth.ErrTokenExpired:
				m.writeAuthError(w, "Token expired", http.StatusUnauthorized)
			case auth.ErrInvalidBearerToken:
				m.writeAuthError(w, "Invalid token", http.StatusUnauthorized)
			case auth.ErrInvalidTokenFormat:
				m.writeAuthError(w, "Invalid token format", http.StatusUnauthorized)
			default:
				m.writeAuthError(w, "Authentication failed", http.StatusUnauthorized)
			}
			return
		}

		// Log successful authentication
		log.Printf("User authenticated: %s (%s)", userCtx.Username, userCtx.Subject)

		// Add user context to request
		ctx := auth.WithUserContext(r.Context(), userCtx)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// OptionalAuthentication provides optional authentication middleware
func (m *AuthMiddleware) OptionalAuthentication(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check if OAuth is enabled
		if !m.config.OAuthEnabled {
			// OAuth disabled, proceed without authentication
			next.ServeHTTP(w, r)
			return
		}

		// Try to authenticate if token is present
		tokenString, err := auth.ExtractBearerToken(r)
		if err != nil {
			// No token found, continue without authentication
			next.ServeHTTP(w, r)
			return
		}

		// Validate token if present
		userCtx, err := m.validator.ValidateToken(tokenString)
		if err != nil {
			// Invalid token, log warning and continue without authentication
			log.Printf("Optional authentication failed: %v", err)
			next.ServeHTTP(w, r)
			return
		}

		// Log successful authentication
		log.Printf("User optionally authenticated: %s (%s)", userCtx.Username, userCtx.Subject)

		// Add user context to request
		ctx := auth.WithUserContext(r.Context(), userCtx)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// writeAuthError writes a standardized authentication error response
func (m *AuthMiddleware) writeAuthError(w http.ResponseWriter, message string, statusCode int) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("WWW-Authenticate", "Bearer")
	w.WriteHeader(statusCode)
	
	// Write JSON error response (simplified to avoid unused variable)
	
	// Simple JSON encoding to avoid additional dependencies
	if statusCode == http.StatusUnauthorized {
		w.Write([]byte(`{"error":"authentication_required","error_description":"` + message + `","status_code":401}`))
	} else {
		w.Write([]byte(`{"error":"authentication_failed","error_description":"` + message + `","status_code":` + string(rune(statusCode)) + `}`))
	}
}

// GetUserFromContext extracts authenticated user from request context
func GetUserFromContext(ctx context.Context) (*auth.UserContext, bool) {
	return auth.GetUserContext(ctx)
}

// LogAuthenticationInfo logs authentication information for debugging
func LogAuthenticationInfo(ctx context.Context, action string) {
	if userCtx, ok := auth.GetUserContext(ctx); ok {
		log.Printf("Authenticated action: %s by user %s (%s)", action, userCtx.Username, userCtx.Subject)
	} else {
		log.Printf("Unauthenticated action: %s", action)
	}
}

// CORSMiddleware adds CORS headers for OAuth-enabled endpoints
func CORSMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Set CORS headers
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Requested-With")
		w.Header().Set("Access-Control-Max-Age", "86400")

		// Handle preflight requests
		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// SecurityHeadersMiddleware adds security headers for OAuth endpoints
func SecurityHeadersMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Security headers
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-XSS-Protection", "1; mode=block")
		w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		w.Header().Set("Content-Security-Policy", "default-src 'self'")

		next.ServeHTTP(w, r)
	})
}

// LoggingMiddleware provides request logging with authentication context
func LoggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Log request
		userInfo := "anonymous"
		if userCtx, ok := auth.GetUserContext(r.Context()); ok {
			userInfo = userCtx.Username + " (" + userCtx.Subject + ")"
		}

		log.Printf("Request: %s %s from %s by %s", r.Method, r.URL.Path, r.RemoteAddr, userInfo)

		next.ServeHTTP(w, r)
	})
}