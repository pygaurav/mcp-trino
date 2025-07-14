# OAuth Implementation Plan for Trino MCP Server

Based on the Trino Go client documentation and current codebase analysis, here's a comprehensive plan for implementing OAuth support:

## Authentication Flow Options

**Recommended: OAuth 2.0 Authorization Code Flow with PKCE (Simplified)**
- User-friendly browser-based authentication
- Minimal configuration required - just specify Trino server URL
- Automatic OAuth provider discovery via Trino's well-known endpoint
- No client secrets needed (PKCE for security)
- Handles token refresh automatically

**Alternative: OAuth 2.0 Client Credentials Flow**
- For service-to-service authentication scenarios
- Requires manual OAuth provider configuration
- More complex setup but suitable for headless environments

## MCP June 2025 Specification Compliance

### Key Requirements from MCP Specification:
1. **OAuth 2.1 Compliance**: Use OAuth 2.1 with appropriate security measures
2. **Resource Indicators (RFC 8707)**: MUST implement to prevent token misuse
3. **PKCE**: Required for public clients (browser-based auth)
4. **Dynamic Client Registration**: Support OAuth 2.0 Dynamic Client Registration Protocol
5. **Authorization Server Metadata**: Implement OAuth 2.0 Authorization Server Metadata (RFC 8414)
6. **Bearer Token Authentication**: Use `Authorization: Bearer <token>` header
7. **HTTPS Enforcement**: All authorization endpoints must use HTTPS

### 1. MCP-Compliant OAuth Configuration (`internal/config/config.go`)
```go
type OAuthConfig struct {
    Enabled       bool   `env:"TRINO_OAUTH_ENABLED" default:"false"`
    TrinoURL      string `env:"TRINO_URL"` // Base Trino server URL for discovery
    LocalPort     int    `env:"TRINO_OAUTH_PORT" default:"8080"` // Local callback port
    RefreshBuffer int    `env:"TRINO_OAUTH_REFRESH_BUFFER" default:"300"` // seconds
    
    // MCP Resource Indicator (RFC 8707) - canonical URI for this MCP server
    ResourceIndicator string // Generated from TrinoURL
    
    // Auto-discovered from Trino's .well-known/oauth-authorization-server
    ClientID      string // Discovered automatically
    AuthURL       string // Discovered automatically  
    TokenURL      string // Discovered automatically
    Scopes        string // Discovered automatically
    
    // MCP-specific OAuth 2.1 settings
    PKCEEnabled   bool   `default:"true"` // Always enabled for security
    HTTPSRequired bool   `default:"true"` // MCP requires HTTPS
}
```

### 2. MCP-Compliant OAuth Discovery (`internal/oauth/discovery.go`)
- Fetch OAuth configuration from Trino's `.well-known/oauth-authorization-server`
- Parse authorization server metadata (RFC 8414)
- Validate HTTPS endpoints (MCP requirement)
- Configure OAuth client automatically
- Generate Resource Indicator URI from Trino URL
- Handle discovery errors gracefully

### 3. MCP-Compliant Browser Authentication (`internal/oauth/browser.go`)
- Start local HTTPS server for OAuth callback (MCP requirement)
- Generate PKCE code verifier/challenge (RFC 7636)
- Include Resource Indicator in authorization request (RFC 8707)
- Open browser to OAuth authorization URL
- Handle callback with authorization code
- Exchange code for access/refresh tokens with Resource Indicator
- Validate token audience matches Resource Indicator

### 4. MCP-Compliant OAuth Client (`internal/oauth/client.go`)
- Token acquisition and refresh logic with Resource Indicators
- Automatic token renewal before expiration
- Thread-safe token management
- Secure token storage (keyring/encrypted file)
- Validate token audience matches Resource Indicator
- Implement OAuth 2.1 security measures
- Fallback to basic auth when OAuth disabled

### 5. MCP-Compliant Trino Client Integration (`internal/trino/client.go`)
- Use `AccessToken` field instead of username/password in DSN
- Remove basic auth credentials when OAuth enabled
- Handle token refresh failures gracefully
- Ensure HTTPS connections (MCP requirement)

### 6. MCP Handler Authentication (`internal/handlers/middleware.go`)
- **REQUIRED**: Validate incoming Bearer tokens for HTTP transport
- Return 401 Unauthorized for missing/invalid tokens
- Return 403 Forbidden for insufficient permissions
- Extract user context from JWT claims
- Pass user information to Trino queries via `X-Trino-User` header
- Validate token audience matches MCP server Resource Indicator

### 7. MCP-Compliant HTTP Transport Updates (`cmd/main.go`)
- **REQUIRED**: Support Bearer token authentication on all endpoints
- Use `Authorization: Bearer <token>` header format
- Add authentication middleware to HTTP handlers
- Return proper HTTP error codes (401, 403, 400)
- Enforce HTTPS for all authorization endpoints
- Maintain backward compatibility with basic auth for non-MCP clients

## Simplified User Experience

### For Claude Desktop Users
```json
{
  "mcpServers": {
    "trino": {
      "command": "mcp-trino",
      "env": {
        "TRINO_URL": "https://trino.example.com",
        "TRINO_OAUTH_ENABLED": "true"
      }
    }
  }
}
```

### MCP-Compliant Authentication Flow
1. **First Run**: MCP server detects no stored tokens
2. **Auto-Discovery**: Fetches OAuth config from `https://trino.example.com/.well-known/oauth-authorization-server`
3. **Resource Indicator**: Generates canonical URI for MCP server (e.g., `https://trino.example.com/mcp`)
4. **Browser Launch**: Opens browser to OAuth authorization URL with PKCE + Resource Indicator
5. **User Login**: User authenticates with their OAuth provider (Google, Azure AD, etc.)
6. **Token Exchange**: Exchanges authorization code for tokens with Resource Indicator
7. **Token Validation**: Validates token audience matches Resource Indicator
8. **Token Storage**: Securely stores access/refresh tokens locally
9. **Subsequent Runs**: Uses stored tokens, refreshes automatically with Resource Indicator

## Key Implementation Details

### Token Management
- **Storage**: Secure local storage (OS keyring or encrypted file)
- **Refresh Strategy**: Refresh when token expires within buffer time
- **Error Handling**: Fallback to basic auth on OAuth failures
- **Concurrency**: Thread-safe token access with mutex

### MCP-Compliant Security Considerations
- **OAuth 2.1**: Full compliance with OAuth 2.1 security measures
- **Resource Indicators (RFC 8707)**: MUST implement to prevent token misuse
- **PKCE**: Required for public clients - uses Proof Key for Code Exchange
- **Token Validation**: Verify JWT signature, expiration, and audience
- **Audience Validation**: Ensure token audience matches Resource Indicator
- **Scope Validation**: Ensure tokens have required Trino access scopes
- **HTTPS Enforcement**: All authorization endpoints must use HTTPS
- **Secure Storage**: Use OS keyring or encrypted file for token storage
- **Error Logging**: Log OAuth failures without exposing sensitive data
- **Token Passthrough Prevention**: Validate tokens are for this specific MCP server

### Configuration Priority
1. OAuth (when enabled and properly configured)
2. Basic Auth (fallback when OAuth disabled/failed)
3. Anonymous (when no credentials provided)

## Benefits of This Simplified Approach

1. **User-Friendly**: Only requires Trino server URL - no complex OAuth configuration
2. **Automatic Discovery**: Fetches OAuth configuration from Trino's well-known endpoint
3. **Secure**: Uses PKCE flow - no client secrets needed
4. **Persistent**: Securely stores tokens for seamless subsequent use
5. **Trino Compatibility**: Leverages existing JWT support in Trino Go client
6. **Backward Compatibility**: Maintains existing basic auth functionality
7. **Cross-Platform**: Works on macOS, Windows, and Linux

## MCP-Compliant Implementation Order

1. **OAuth Discovery**: Implement automatic OAuth provider discovery with RFC 8414 support
2. **Resource Indicators**: Implement RFC 8707 Resource Indicators for token scoping
3. **Browser Authentication**: Create PKCE-based browser authentication flow
4. **Token Storage**: Implement secure token storage and retrieval
5. **Token Validation**: Add audience validation and OAuth 2.1 security measures
6. **Trino Integration**: Connect OAuth tokens to Trino client
7. **MCP Handler Authentication**: Add required authentication for HTTP transport
8. **Error Handling**: Implement proper HTTP error codes (401, 403, 400)
9. **HTTPS Enforcement**: Ensure all authorization endpoints use HTTPS
10. **Fallback Handling**: Ensure graceful fallback to basic auth
11. **Testing**: Comprehensive testing with various OAuth providers

This MCP-compliant approach reduces user configuration to just the Trino server URL while providing enterprise-grade security that meets the latest MCP specification requirements.

## Current Authentication Implementation

The mcp-trino project currently implements **basic username/password authentication** only:

### Configuration (`internal/config/config.go`)
- **Username**: `TRINO_USER` environment variable (default: "trino")
- **Password**: `TRINO_PASSWORD` environment variable (default: "")
- **SSL/TLS**: `TRINO_SSL` (default: true), `TRINO_SSL_INSECURE` (default: true)
- **Scheme**: `TRINO_SCHEME` (default: "https")

### Connection String Construction (`internal/trino/client.go`)
The client builds a DSN (Data Source Name) string with basic auth:
```go
dsn := fmt.Sprintf("%s://%s:%s@%s:%d?catalog=%s&schema=%s&SSL=%t&SSLInsecure=%t",
    cfg.Scheme,
    url.QueryEscape(cfg.User),
    url.QueryEscape(cfg.Password),
    cfg.Host,
    cfg.Port,
    url.QueryEscape(cfg.Catalog),
    url.QueryEscape(cfg.Schema),
    cfg.SSL,
    cfg.SSLInsecure)
```

## Trino Go Client Authentication Capabilities

The `github.com/trinodb/trino-go-client` v0.323.0 supports several authentication methods:

### Supported Methods:
1. **HTTP Basic Authentication** (currently implemented)
2. **Kerberos Authentication** (not implemented)
3. **JWT Authentication** via `AccessToken` field (not implemented)
4. **Authorization Header Forwarding** (not implemented)
5. **Per-Query User Information** (not implemented)

### JWT/OAuth Support:
- **JWT**: Set `AccessToken` field in Config struct
- **OAuth**: Not directly supported - requires OAuth-to-JWT bridge pattern
- **Authorization Header**: Can forward headers per query with `ForwardAuthorizationHeader: true`

## Security Architecture

### Current Security Model:
- **SQL Injection Protection**: `isReadOnlyQuery()` function blocks write operations
- **Query Restrictions**: Only SELECT, SHOW, DESCRIBE, EXPLAIN, WITH queries allowed by default
- **Write Query Override**: `TRINO_ALLOW_WRITE_QUERIES=true` bypasses restrictions (with warning)

### Current Limitations:
- **No Authentication on MCP Layer**: No authentication required for MCP tool calls
- **Basic Auth Only**: No support for modern authentication methods
- **No Authorization**: No user-based access control or permissions
- **No Session Management**: No token refresh or session handling

## Key Integration Points for Future OAuth Implementation

Based on the current architecture, OAuth/JWT authentication would need to be added at:

1. **Config Layer**: Add OAuth/JWT configuration parameters
2. **Client Layer**: Modify DSN construction to use `AccessToken` instead of username/password
3. **Handler Layer**: Add authentication middleware to validate tokens
4. **Transport Layer**: Add Bearer token extraction and validation
5. **MCP Layer**: Add authentication context to tool calls

The current codebase provides a solid foundation for adding OAuth/JWT authentication, but no authentication mechanisms beyond basic username/password are currently implemented.