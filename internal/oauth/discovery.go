package oauth

import (
	"context"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"strings"
	"time"
)

// OAuthConfig holds OAuth provider configuration
type OAuthConfig struct {
	ProviderURL            string   `json:"provider_url"`
	ClientID               string   `json:"client_id"`
	ClientSecret           string   `json:"client_secret"`
	Issuer                 string   `json:"issuer"`
	AuthorizationURL       string   `json:"authorization_endpoint"`
	TokenURL               string   `json:"token_endpoint"`
	UserInfoURL            string   `json:"userinfo_endpoint"`
	JWKSURL                string   `json:"jwks_uri"`
	SupportedScopes        []string `json:"scopes_supported"`
	SupportedResponseTypes []string `json:"response_types_supported"`
	SupportedGrantTypes    []string `json:"grant_types_supported"`
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

// SetupOAuthConfiguration discovers OAuth provider configuration
func SetupOAuthConfiguration(ctx context.Context, providerURL string) (*OAuthConfig, error) {
	client := NewOAuthDiscoveryClient()
	
	// Discover OAuth provider metadata
	discoveryURL := strings.TrimSuffix(providerURL, "/") + "/.well-known/openid-configuration"
	
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, discoveryURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create discovery request: %w", err)
	}
	
	resp, err := client.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch discovery metadata: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("discovery request failed with status: %d", resp.StatusCode)
	}
	
	var metadata map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&metadata); err != nil {
		return nil, fmt.Errorf("failed to decode discovery metadata: %w", err)
	}
	
	// Extract configuration from metadata
	config := &OAuthConfig{
		ProviderURL:            providerURL,
		Issuer:                 getStringValue(metadata, "issuer"),
		AuthorizationURL:       getStringValue(metadata, "authorization_endpoint"),
		TokenURL:               getStringValue(metadata, "token_endpoint"),
		UserInfoURL:            getStringValue(metadata, "userinfo_endpoint"),
		JWKSURL:                getStringValue(metadata, "jwks_uri"),
		SupportedScopes:        getStringSliceValue(metadata, "scopes_supported"),
		SupportedResponseTypes: getStringSliceValue(metadata, "response_types_supported"),
		SupportedGrantTypes:    getStringSliceValue(metadata, "grant_types_supported"),
	}
	
	// Validate required fields
	if config.Issuer == "" || config.AuthorizationURL == "" || config.TokenURL == "" || config.JWKSURL == "" {
		return nil, fmt.Errorf("incomplete OAuth provider metadata")
	}
	
	return config, nil
}

// JWK represents a JSON Web Key
type JWK struct {
	KeyType   string `json:"kty"`
	Use       string `json:"use"`
	KeyID     string `json:"kid"`
	Algorithm string `json:"alg"`
	Modulus   string `json:"n"`
	Exponent  string `json:"e"`
}

// JWKS represents a JSON Web Key Set
type JWKS struct {
	Keys []JWK `json:"keys"`
}

// GetPublicKey converts a JWK to an RSA public key
func (jwk *JWK) GetPublicKey() (*rsa.PublicKey, error) {
	if jwk.KeyType != "RSA" {
		return nil, fmt.Errorf("unsupported key type: %s", jwk.KeyType)
	}
	
	// Decode base64url-encoded modulus and exponent
	nBytes, err := base64.RawURLEncoding.DecodeString(jwk.Modulus)
	if err != nil {
		return nil, fmt.Errorf("failed to decode modulus: %w", err)
	}
	
	eBytes, err := base64.RawURLEncoding.DecodeString(jwk.Exponent)
	if err != nil {
		return nil, fmt.Errorf("failed to decode exponent: %w", err)
	}
	
	// Convert to big integers
	n := new(big.Int).SetBytes(nBytes)
	e := new(big.Int).SetBytes(eBytes)
	
	// Create RSA public key
	pubKey := &rsa.PublicKey{
		N: n,
		E: int(e.Int64()),
	}
	
	return pubKey, nil
}

// FetchJWKS fetches the JSON Web Key Set from the provider
func (c *OAuthDiscoveryClient) FetchJWKS(ctx context.Context, jwksURL string) (*JWKS, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, jwksURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create JWKS request: %w", err)
	}
	
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch JWKS: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("JWKS request failed with status: %d", resp.StatusCode)
	}
	
	var jwks JWKS
	if err := json.NewDecoder(resp.Body).Decode(&jwks); err != nil {
		return nil, fmt.Errorf("failed to decode JWKS: %w", err)
	}
	
	return &jwks, nil
}

// getStringValue safely extracts a string value from a map
func getStringValue(m map[string]interface{}, key string) string {
	if val, ok := m[key].(string); ok {
		return val
	}
	return ""
}

// getStringSliceValue safely extracts a string slice value from a map
func getStringSliceValue(m map[string]interface{}, key string) []string {
	if val, ok := m[key].([]interface{}); ok {
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