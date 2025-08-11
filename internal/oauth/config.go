package oauth

import (
	"fmt"
	"log"

	"github.com/tuannvm/mcp-trino/internal/config"
)

// SetupOAuth initializes OAuth validation and sets up OAuth configuration
func SetupOAuth(cfg *config.TrinoConfig) (TokenValidator, error) {
	if !cfg.OAuthEnabled {
		log.Println("OAuth authentication disabled")
		return nil, nil
	}

	// Initialize OAuth provider based on configuration
	validator, err := createValidator(cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to create OAuth validator: %w", err)
	}

	if err := validator.Initialize(cfg); err != nil {
		return nil, fmt.Errorf("failed to initialize OAuth validator: %w", err)
	}

	log.Printf("OAuth authentication enabled with provider: %s", cfg.OAuthProvider)
	return validator, nil
}

// createValidator creates the appropriate token validator based on configuration
func createValidator(cfg *config.TrinoConfig) (TokenValidator, error) {
	switch cfg.OAuthProvider {
	case "hmac":
		return &HMACValidator{}, nil
	case "okta", "google", "azure":
		return &OIDCValidator{}, nil
	default:
		return nil, fmt.Errorf("unknown OAuth provider: %s", cfg.OAuthProvider)
	}
}

// CreateOAuth2Handler creates a new OAuth2 handler for HTTP endpoints
func CreateOAuth2Handler(cfg *config.TrinoConfig, version string) *OAuth2Handler {
	if !cfg.OAuthEnabled {
		return nil
	}

	oauth2Config := NewOAuth2ConfigFromTrinoConfig(cfg, version)
	return NewOAuth2Handler(oauth2Config)
}
