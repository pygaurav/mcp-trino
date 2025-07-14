package auth

import (
	"context"
	"crypto/rsa"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

var (
	// ErrNoBearerToken is returned when no Bearer token is found in the request
	ErrNoBearerToken = errors.New("no Bearer token found in Authorization header")
	// ErrInvalidBearerToken is returned when the Bearer token is invalid
	ErrInvalidBearerToken = errors.New("invalid Bearer token")
	// ErrTokenExpired is returned when the token has expired
	ErrTokenExpired = errors.New("token has expired")
	// ErrInvalidTokenFormat is returned when the token format is invalid
	ErrInvalidTokenFormat = errors.New("invalid token format")
)

// UserContext holds authenticated user information
type UserContext struct {
	UserID    string    `json:"user_id"`
	Username  string    `json:"username"`
	Email     string    `json:"email"`
	Subject   string    `json:"sub"`
	Issuer    string    `json:"iss"`
	ExpiresAt time.Time `json:"exp"`
	IssuedAt  time.Time `json:"iat"`
}

// BearerTokenValidator handles JWT Bearer token validation
type BearerTokenValidator struct {
	publicKey *rsa.PublicKey
	issuer    string
	audience  string
}

// NewBearerTokenValidator creates a new Bearer token validator
func NewBearerTokenValidator(publicKey *rsa.PublicKey, issuer, audience string) *BearerTokenValidator {
	return &BearerTokenValidator{
		publicKey: publicKey,
		issuer:    issuer,
		audience:  audience,
	}
}

// ExtractBearerToken extracts the Bearer token from the Authorization header
func ExtractBearerToken(r *http.Request) (string, error) {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		return "", ErrNoBearerToken
	}

	// Check if the header starts with "Bearer "
	const bearerPrefix = "Bearer "
	if !strings.HasPrefix(authHeader, bearerPrefix) {
		return "", ErrNoBearerToken
	}

	// Extract the token part
	token := strings.TrimPrefix(authHeader, bearerPrefix)
	if token == "" {
		return "", ErrNoBearerToken
	}

	return token, nil
}

// ValidateToken validates a JWT Bearer token and returns user context
func (v *BearerTokenValidator) ValidateToken(tokenString string) (*UserContext, error) {
	// Parse the token
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (any, error) {
		// Validate the signing method
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return v.publicKey, nil
	})

	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidBearerToken, err)
	}

	// Check if token is valid
	if !token.Valid {
		return nil, ErrInvalidBearerToken
	}

	// Extract claims
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, ErrInvalidTokenFormat
	}

	// Validate standard claims
	if err := v.validateClaims(claims); err != nil {
		return nil, err
	}

	// Extract user context
	userCtx := &UserContext{
		Subject:  getStringClaim(claims, "sub"),
		Issuer:   getStringClaim(claims, "iss"),
		Username: getStringClaim(claims, "preferred_username"),
		Email:    getStringClaim(claims, "email"),
		UserID:   getStringClaim(claims, "user_id"),
	}

	// Extract timestamps
	if exp, ok := claims["exp"].(float64); ok {
		userCtx.ExpiresAt = time.Unix(int64(exp), 0)
	}
	if iat, ok := claims["iat"].(float64); ok {
		userCtx.IssuedAt = time.Unix(int64(iat), 0)
	}

	return userCtx, nil
}

// validateClaims validates standard JWT claims
func (v *BearerTokenValidator) validateClaims(claims jwt.MapClaims) error {
	now := time.Now()

	// Check expiration
	if exp, ok := claims["exp"].(float64); ok {
		if now.Unix() > int64(exp) {
			return ErrTokenExpired
		}
	}

	// Check issuer
	if v.issuer != "" {
		if iss, ok := claims["iss"].(string); ok {
			if iss != v.issuer {
				return fmt.Errorf("%w: invalid issuer", ErrInvalidBearerToken)
			}
		}
	}

	// Check audience
	if v.audience != "" {
		if aud, ok := claims["aud"].(string); ok {
			if aud != v.audience {
				return fmt.Errorf("%w: invalid audience", ErrInvalidBearerToken)
			}
		}
	}

	return nil
}

// getStringClaim safely extracts a string claim from JWT claims
func getStringClaim(claims jwt.MapClaims, key string) string {
	if value, ok := claims[key].(string); ok {
		return value
	}
	return ""
}

// AuthContextKey is the key used to store auth context in request context
type AuthContextKey struct{}

// WithUserContext adds user context to the request context
func WithUserContext(ctx context.Context, userCtx *UserContext) context.Context {
	return context.WithValue(ctx, AuthContextKey{}, userCtx)
}

// GetUserContext extracts user context from request context
func GetUserContext(ctx context.Context) (*UserContext, bool) {
	userCtx, ok := ctx.Value(AuthContextKey{}).(*UserContext)
	return userCtx, ok
}

// RequireAuthentication middleware that requires valid Bearer token authentication
func RequireAuthentication(validator *BearerTokenValidator) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Extract Bearer token
			tokenString, err := ExtractBearerToken(r)
			if err != nil {
				http.Error(w, "Authorization required", http.StatusUnauthorized)
				return
			}

			// Validate token
			userCtx, err := validator.ValidateToken(tokenString)
			if err != nil {
				if errors.Is(err, ErrTokenExpired) {
					http.Error(w, "Token expired", http.StatusUnauthorized)
					return
				}
				http.Error(w, "Invalid token", http.StatusUnauthorized)
				return
			}

			// Add user context to request
			ctx := WithUserContext(r.Context(), userCtx)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// OptionalAuthentication middleware that optionally validates Bearer token
func OptionalAuthentication(validator *BearerTokenValidator) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Try to extract Bearer token
			tokenString, err := ExtractBearerToken(r)
			if err != nil {
				// No token found, continue without authentication
				next.ServeHTTP(w, r)
				return
			}

			// Validate token if present
			userCtx, err := validator.ValidateToken(tokenString)
			if err != nil {
				// Invalid token, continue without authentication
				next.ServeHTTP(w, r)
				return
			}

			// Add user context to request
			ctx := WithUserContext(r.Context(), userCtx)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}