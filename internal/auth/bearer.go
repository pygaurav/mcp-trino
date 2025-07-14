package auth

import (
	"crypto/rsa"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// BearerTokenValidator validates JWT bearer tokens
type BearerTokenValidator struct {
	publicKey *rsa.PublicKey
	issuer    string
	audience  string
}

// UserInfo represents authenticated user information
type UserInfo struct {
	UserID   string
	Username string
	Email    string
	Name     string
	Roles    []string
}

// NewBearerTokenValidator creates a new JWT validator
func NewBearerTokenValidator(publicKey *rsa.PublicKey, issuer, audience string) *BearerTokenValidator {
	return &BearerTokenValidator{
		publicKey: publicKey,
		issuer:    issuer,
		audience:  audience,
	}
}

// ValidateToken validates a JWT bearer token and extracts user information
func (v *BearerTokenValidator) ValidateToken(tokenString string) (*UserInfo, error) {
	// Remove "Bearer " prefix if present
	tokenString = strings.TrimPrefix(tokenString, "Bearer ")
	
	// Parse and validate the JWT token
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		// Verify signing method
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return v.publicKey, nil
	})

	if err != nil {
		return nil, fmt.Errorf("failed to parse token: %w", err)
	}

	if !token.Valid {
		return nil, errors.New("invalid token")
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, errors.New("invalid token claims")
	}

	// Validate standard claims
	if err := v.validateClaims(claims); err != nil {
		return nil, fmt.Errorf("invalid claims: %w", err)
	}

	// Extract user information
	userInfo := &UserInfo{
		UserID:   getStringClaim(claims, "sub"),
		Username: getStringClaim(claims, "preferred_username"),
		Email:    getStringClaim(claims, "email"),
		Name:     getStringClaim(claims, "name"),
		Roles:    getStringSliceClaim(claims, "roles"),
	}

	return userInfo, nil
}

// validateClaims validates standard JWT claims
func (v *BearerTokenValidator) validateClaims(claims jwt.MapClaims) error {
	// Validate issuer
	if iss, ok := claims["iss"].(string); !ok || iss != v.issuer {
		return fmt.Errorf("invalid issuer: expected %s, got %s", v.issuer, iss)
	}

	// Validate audience
	if aud, ok := claims["aud"].(string); !ok || aud != v.audience {
		return fmt.Errorf("invalid audience: expected %s, got %s", v.audience, aud)
	}

	// Validate expiration
	if exp, ok := claims["exp"].(float64); !ok {
		return errors.New("missing exp claim")
	} else if time.Now().Unix() > int64(exp) {
		return errors.New("token expired")
	}

	// Validate not before
	if nbf, ok := claims["nbf"].(float64); ok && time.Now().Unix() < int64(nbf) {
		return errors.New("token not yet valid")
	}

	// Validate issued at
	if iat, ok := claims["iat"].(float64); ok && time.Now().Unix() < int64(iat) {
		return errors.New("token issued in the future")
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

// getStringSliceClaim safely extracts a string slice claim
func getStringSliceClaim(claims jwt.MapClaims, key string) []string {
	if val, ok := claims[key].([]interface{}); ok {
		result := make([]string, 0, len(val))
		for _, v := range val {
			if str, ok := v.(string); ok {
				result = append(result, str)
			}
		}
		return result
	}
	return nil
}