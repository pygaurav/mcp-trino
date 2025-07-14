package oauth

import (
	"context"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"os"
	"time"
)

// OAuthConfig holds OAuth provider configuration
type OAuthConfig struct {
	ProviderURL            string   `json:"provider_url"`
	ClientID               string   `json:"client_id"`
	ClientSecret           string   `json:"client_secret"`
	RedirectURI            string   `json:"redirect_uri"`
	Scopes                 string   `json:"scopes"`
	AuthorizationURL       string   `json:"authorization_url"`
	TokenURL               string   `json:"token_url"`
	UserInfoURL            string   `json:"userinfo_url"`
	JWKSURL                string   `json:"jwks_url"`
	Issuer                 string   `json:"issuer"`
	SupportedGrantTypes    []string `json:"supported_grant_types"`
	SupportedResponseTypes []string `json:"supported_response_types"`
	SupportedScopes        []string `json:"supported_scopes"`
}

// DiscoveryDocument represents an OpenID Connect Discovery document
type DiscoveryDocument struct {
	Issuer                            string   `json:"issuer"`
	AuthorizationEndpoint             string   `json:"authorization_endpoint"`
	TokenEndpoint                     string   `json:"token_endpoint"`
	UserinfoEndpoint                  string   `json:"userinfo_endpoint"`
	JWKSURI                           string   `json:"jwks_uri"`
	ScopesSupported                   []string `json:"scopes_supported"`
	ResponseTypesSupported            []string `json:"response_types_supported"`
	GrantTypesSupported               []string `json:"grant_types_supported"`
	SubjectTypesSupported             []string `json:"subject_types_supported"`
	IDTokenSigningAlgValuesSupported  []string `json:"id_token_signing_alg_values_supported"`
	TokenEndpointAuthMethodsSupported []string `json:"token_endpoint_auth_methods_supported"`
	ClaimsSupported                   []string `json:"claims_supported"`
	CodeChallengeMethodsSupported     []string `json:"code_challenge_methods_supported"`
}

// JWKSDocument represents a JSON Web Key Set document
type JWKSDocument struct {
	Keys []JWK `json:"keys"`
}

// JWK represents a JSON Web Key
type JWK struct {
	Kid string `json:"kid"`
	Kty string `json:"kty"`
	Use string `json:"use"`
	Alg string `json:"alg"`
	N   string `json:"n"`
	E   string `json:"e"`
}

// OAuthDiscoveryClient handles OAuth provider discovery
type OAuthDiscoveryClient struct {
	httpClient *http.Client
}

// NewOAuthDiscoveryClient creates a new OAuth discovery client
func NewOAuthDiscoveryClient() *OAuthDiscoveryClient {
	return &OAuthDiscoveryClient{
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// DiscoverProvider discovers OAuth provider configuration using OpenID Connect Discovery
func (c *OAuthDiscoveryClient) DiscoverProvider(ctx context.Context, providerURL string) (*OAuthConfig, error) {
	// Construct the well-known discovery URL
	discoveryURL := fmt.Sprintf("%s/.well-known/openid-configuration", providerURL)

	// Fetch the discovery document
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, discoveryURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create discovery request: %w", err)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch discovery document: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("discovery request failed with status %d", resp.StatusCode)
	}

	// Parse the discovery document
	var doc DiscoveryDocument
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		return nil, fmt.Errorf("failed to parse discovery document: %w", err)
	}

	// Create OAuth configuration
	config := &OAuthConfig{
		ProviderURL:            providerURL,
		Issuer:                 doc.Issuer,
		AuthorizationURL:       doc.AuthorizationEndpoint,
		TokenURL:               doc.TokenEndpoint,
		UserInfoURL:            doc.UserinfoEndpoint,
		JWKSURL:                doc.JWKSURI,
		SupportedGrantTypes:    doc.GrantTypesSupported,
		SupportedResponseTypes: doc.ResponseTypesSupported,
		SupportedScopes:        doc.ScopesSupported,
	}

	return config, nil
}

// FetchJWKS fetches the JSON Web Key Set from the provider
func (c *OAuthDiscoveryClient) FetchJWKS(ctx context.Context, jwksURL string) (*JWKSDocument, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, jwksURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create JWKS request: %w", err)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch JWKS: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("JWKS request failed with status %d", resp.StatusCode)
	}

	var jwks JWKSDocument
	if err := json.NewDecoder(resp.Body).Decode(&jwks); err != nil {
		return nil, fmt.Errorf("failed to parse JWKS: %w", err)
	}

	return &jwks, nil
}

// GetPublicKey extracts the RSA public key from JWK
func (jwk *JWK) GetPublicKey() (*rsa.PublicKey, error) {
	if jwk.Kty != "RSA" {
		return nil, fmt.Errorf("unsupported key type: %s", jwk.Kty)
	}

	// Parse the RSA public key components using base64 URL decoding
	nBytes, err := base64.RawURLEncoding.DecodeString(jwk.N)
	if err != nil {
		return nil, fmt.Errorf("failed to decode N component: %w", err)
	}

	eBytes, err := base64.RawURLEncoding.DecodeString(jwk.E)
	if err != nil {
		return nil, fmt.Errorf("failed to decode E component: %w", err)
	}

	// Convert to big integers
	n := new(big.Int).SetBytes(nBytes)
	e := 0
	for _, b := range eBytes {
		e = e*256 + int(b)
	}

	return &rsa.PublicKey{
		N: n,
		E: e,
	}, nil
}

// ConfigureFromEnvironment creates OAuth configuration from environment variables
func ConfigureFromEnvironment() (*OAuthConfig, error) {
	config := &OAuthConfig{
		ProviderURL:  getEnvOrDefault("OAUTH_PROVIDER_URL", ""),
		ClientID:     getEnvOrDefault("OAUTH_CLIENT_ID", ""),
		ClientSecret: getEnvOrDefault("OAUTH_CLIENT_SECRET", ""),
		RedirectURI:  getEnvOrDefault("OAUTH_REDIRECT_URI", ""),
		Scopes:       getEnvOrDefault("OAUTH_SCOPES", "openid profile email"),
	}

	// Validate required fields
	if config.ProviderURL == "" {
		return nil, fmt.Errorf("OAUTH_PROVIDER_URL is required")
	}

	return config, nil
}

// ValidateConfiguration validates OAuth configuration
func (c *OAuthConfig) ValidateConfiguration() error {
	if c.ProviderURL == "" {
		return fmt.Errorf("provider URL is required")
	}
	if c.ClientID == "" {
		return fmt.Errorf("client ID is required")
	}
	if c.ClientSecret == "" {
		return fmt.Errorf("client secret is required")
	}
	if c.RedirectURI == "" {
		return fmt.Errorf("redirect URI is required")
	}
	return nil
}

// getEnvOrDefault gets environment variable or returns default value
func getEnvOrDefault(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

// SetupOAuthConfiguration sets up OAuth configuration with discovery
func SetupOAuthConfiguration(ctx context.Context, providerURL string) (*OAuthConfig, error) {
	client := NewOAuthDiscoveryClient()

	// Discover provider configuration
	config, err := client.DiscoverProvider(ctx, providerURL)
	if err != nil {
		return nil, fmt.Errorf("failed to discover OAuth provider: %w", err)
	}

	// Load additional configuration from environment
	config.ClientID = getEnvOrDefault("OAUTH_CLIENT_ID", "")
	config.ClientSecret = getEnvOrDefault("OAUTH_CLIENT_SECRET", "")
	config.RedirectURI = getEnvOrDefault("OAUTH_REDIRECT_URI", "")
	config.Scopes = getEnvOrDefault("OAUTH_SCOPES", "openid profile email")

	// Validate configuration
	if err := config.ValidateConfiguration(); err != nil {
		return nil, fmt.Errorf("invalid OAuth configuration: %w", err)
	}

	return config, nil
}
