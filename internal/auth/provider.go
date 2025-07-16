package auth

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/golang-jwt/jwt/v5"
	"github.com/tuannvm/mcp-trino/internal/config"
)

// TokenValidator interface for OAuth token validation
type TokenValidator interface {
	ValidateToken(token string) (*User, error)
	Initialize(cfg *config.TrinoConfig) error
}

// HMACValidator validates JWT tokens using HMAC-SHA256 (backward compatibility)
type HMACValidator struct {
	secret     string
	secretOnce sync.Once
}

// OIDCValidator validates JWT tokens using OIDC/JWKS (Okta, Google, Azure)
type OIDCValidator struct {
	verifier *oidc.IDTokenVerifier
	provider *oidc.Provider
}

// Initialize sets up the HMAC validator with JWT secret
func (v *HMACValidator) Initialize(cfg *config.TrinoConfig) error {
	v.secretOnce.Do(func() {
		v.secret = cfg.JWTSecret
	})
	
	if v.secret == "" {
		return fmt.Errorf("JWT_SECRET is required for HMAC provider")
	}
	
	return nil
}

// ValidateToken validates JWT token using HMAC-SHA256
func (v *HMACValidator) ValidateToken(tokenString string) (*User, error) {
	// Remove Bearer prefix if present
	tokenString = strings.TrimPrefix(tokenString, "Bearer ")
	
	// Parse and validate JWT with signature verification
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		// Validate signing method
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(v.secret), nil
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

// Initialize sets up the OIDC validator with provider discovery
func (v *OIDCValidator) Initialize(cfg *config.TrinoConfig) error {
	// Use standard library context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	
	// Configure HTTP client with appropriate timeouts and TLS settings
	httpClient := &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: false, // Verify TLS certificates
				MinVersion:         tls.VersionTLS12,
			},
			IdleConnTimeout:     90 * time.Second,
			TLSHandshakeTimeout: 10 * time.Second,
			MaxIdleConns:        100,
			MaxIdleConnsPerHost: 10,
		},
	}
	
	// Create OIDC provider with custom HTTP client
	provider, err := oidc.NewProvider(
		oidc.ClientContext(ctx, httpClient), 
		cfg.OIDCIssuer,
	)
	if err != nil {
		return fmt.Errorf("failed to initialize OIDC provider: %w", err)
	}
	
	// Configure token verifier with required validation settings
	verifier := provider.Verifier(&oidc.Config{
		ClientID:             cfg.OIDCAudience,
		SupportedSigningAlgs: []string{oidc.RS256, oidc.ES256},
		SkipClientIDCheck:    false, // Verify audience
		SkipExpiryCheck:      false, // Verify expiration
		SkipIssuerCheck:      false, // Verify issuer
	})
	
	v.provider = provider
	v.verifier = verifier
	return nil
}

// ValidateToken validates JWT token using OIDC/JWKS
func (v *OIDCValidator) ValidateToken(tokenString string) (*User, error) {
	// Remove Bearer prefix if present
	tokenString = strings.TrimPrefix(tokenString, "Bearer ")
	
	// Use standard library context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	
	// go-oidc handles RSA signature validation, JWKS fetching, and key rotation
	idToken, err := v.verifier.Verify(ctx, tokenString)
	if err != nil {
		return nil, fmt.Errorf("token verification failed: %w", err)
	}
	
	// Extract claims from verified token
	var claims struct {
		Subject           string `json:"sub"`
		PreferredUsername string `json:"preferred_username"`
		Email             string `json:"email"`
		EmailVerified     bool   `json:"email_verified,omitempty"`
		Name              string `json:"name,omitempty"`
		// Standard OIDC claims are validated by go-oidc:
		// - iss (issuer)
		// - aud (audience) 
		// - exp (expiration)
		// - iat (issued at)
		// - nbf (not before)
	}
	
	if err := idToken.Claims(&claims); err != nil {
		return nil, fmt.Errorf("failed to extract claims: %w", err)
	}
	
	return &User{
		Subject:  claims.Subject,
		Username: claims.PreferredUsername,
		Email:    claims.Email,
	}, nil
}