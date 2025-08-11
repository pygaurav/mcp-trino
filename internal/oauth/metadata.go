package oauth

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"
)

// HandleMetadata handles the legacy OAuth metadata endpoint for MCP compliance
func (h *OAuth2Handler) HandleMetadata(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "public, max-age=300") // Cache for 5 minutes

	if r.Method != "GET" {
		http.Error(w, `{"error":"Method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}

	// Return OAuth metadata based on configuration
	if !h.config.Enabled {
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprintf(w, `{
			"oauth_enabled": false,
			"authentication_methods": ["none"],
			"mcp_version": "1.0.0"
		}`)
		return
	}

	// Create provider-specific metadata
	metadata := map[string]interface{}{
		"oauth_enabled":          true,
		"authentication_methods": []string{"bearer_token"},
		"token_types":            []string{"JWT"},
		"token_validation":       "server_side",
		"supported_flows":        []string{"claude_code", "mcp_remote"},
		"mcp_version":            "1.0.0",
		"server_version":         h.config.Version,
		"provider":               h.config.Provider,
		"authorization_endpoint": fmt.Sprintf("%s://%s:%s/oauth/authorize", h.config.Scheme, h.config.MCPHost, h.config.MCPPort),
		"token_endpoint":         h.oauth2Config.Endpoint.TokenURL,
	}

	// Add provider-specific metadata
	switch h.config.Provider {
	case "hmac":
		metadata["validation_method"] = "hmac_sha256"
		metadata["signature_algorithm"] = "HS256"
		metadata["requires_secret"] = true
	case "okta", "google", "azure":
		metadata["validation_method"] = "oidc_jwks"
		metadata["signature_algorithm"] = "RS256"
		metadata["requires_secret"] = false
		if h.config.Issuer != "" {
			metadata["issuer"] = h.config.Issuer
			metadata["jwks_uri"] = h.config.Issuer + "/.well-known/jwks.json"
		}
		if h.config.Audience != "" {
			metadata["audience"] = h.config.Audience
		}
	}

	// Encode and send response
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(metadata); err != nil {
		log.Printf("OAuth2: Error encoding metadata: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
	}
}

// HandleAuthorizationServerMetadata handles the standard OAuth 2.0 Authorization Server Metadata endpoint
func (h *OAuth2Handler) HandleAuthorizationServerMetadata(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "public, max-age=300") // Cache for 5 minutes

	if r.Method != "GET" {
		http.Error(w, `{"error":"Method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}

	// Return OAuth 2.0 Authorization Server Metadata (RFC 8414)
	metadata := map[string]interface{}{
		"issuer":                                h.config.MCPURL,
		"authorization_endpoint":                fmt.Sprintf("%s/oauth/authorize", h.config.MCPURL),
		"token_endpoint":                        fmt.Sprintf("%s/oauth/token", h.config.MCPURL),
		"registration_endpoint":                 fmt.Sprintf("%s/oauth/register", h.config.MCPURL),
		"response_types_supported":              []string{"code"},
		"response_modes_supported":              []string{"query"},
		"grant_types_supported":                 []string{"authorization_code", "refresh_token"},
		"token_endpoint_auth_methods_supported": []string{"client_secret_basic", "client_secret_post", "none"},
		"code_challenge_methods_supported":      []string{"plain", "S256"},
		"revocation_endpoint":                   fmt.Sprintf("%s/oauth/revoke", h.config.MCPURL),
	}

	// Encode and send response
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(metadata); err != nil {
		log.Printf("OAuth2: Error encoding Authorization Server metadata: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
	}
}

// HandleProtectedResourceMetadata handles the OAuth 2.0 Protected Resource Metadata endpoint
func (h *OAuth2Handler) HandleProtectedResourceMetadata(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "public, max-age=300") // Cache for 5 minutes

	if r.Method != "GET" {
		http.Error(w, `{"error":"Method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}

	// Return OAuth 2.0 Protected Resource Metadata (RFC 9728)
	metadata := map[string]interface{}{
		"resource":                              h.config.MCPURL,
		"authorization_servers":                 []string{h.config.MCPURL},
		"bearer_methods_supported":              []string{"header"},
		"resource_signing_alg_values_supported": []string{"RS256"},
		"resource_documentation":                fmt.Sprintf("%s/docs", h.config.MCPURL),
		"resource_policy_uri":                   fmt.Sprintf("%s/policy", h.config.MCPURL),
		"resource_tos_uri":                      fmt.Sprintf("%s/tos", h.config.MCPURL),
	}

	// Encode and send response
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(metadata); err != nil {
		log.Printf("OAuth2: Error encoding Protected Resource metadata: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
	}
}

// HandleRegister handles OAuth dynamic client registration for mcp-remote
func (h *OAuth2Handler) HandleRegister(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Parse the registration request
	var regRequest map[string]interface{}
	if err := json.NewDecoder(r.Body).Decode(&regRequest); err != nil {
		log.Printf("OAuth2: Failed to parse registration request: %v", err)
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	log.Printf("OAuth2: Registration request: %+v", regRequest)

	// Accept any client registration from mcp-remote
	// Return our pre-configured client_id
	response := map[string]interface{}{
		"client_id":                  h.config.ClientID,
		"client_secret":              "", // Public client, no secret
		"client_id_issued_at":        time.Now().Unix(),
		"grant_types":                []string{"authorization_code", "refresh_token"},
		"response_types":             []string{"code"},
		"token_endpoint_auth_method": "none",
		"application_type":           "native",
		"client_name":                regRequest["client_name"],
	}

	// Use fixed redirect URI if configured, otherwise use client's redirect URIs
	if h.config.RedirectURI != "" {
		response["redirect_uris"] = []string{h.config.RedirectURI}
		log.Printf("OAuth2: Registration response using fixed redirect URI: %s", h.config.RedirectURI)
	} else {
		response["redirect_uris"] = regRequest["redirect_uris"]
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	if err := json.NewEncoder(w).Encode(response); err != nil {
		log.Printf("OAuth2: Failed to encode registration response: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
	}
}

// HandleCallbackRedirect handles the /callback redirect for Claude Code compatibility
func (h *OAuth2Handler) HandleCallbackRedirect(w http.ResponseWriter, r *http.Request) {
	// Preserve all query parameters when redirecting
	redirectURL := "/oauth/callback"
	if r.URL.RawQuery != "" {
		redirectURL += "?" + r.URL.RawQuery
	}
	http.Redirect(w, r, redirectURL, http.StatusFound)
}
