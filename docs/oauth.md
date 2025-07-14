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

## Simplified Implementation Architecture

### 1. Minimal OAuth Configuration (`internal/config/config.go`)
```go
type OAuthConfig struct {
    Enabled       bool   `env:"TRINO_OAUTH_ENABLED" default:"false"`
    TrinoURL      string `env:"TRINO_URL"` // Base Trino server URL for discovery
    LocalPort     int    `env:"TRINO_OAUTH_PORT" default:"8080"` // Local callback port
    RefreshBuffer int    `env:"TRINO_OAUTH_REFRESH_BUFFER" default:"300"` // seconds
    
    // Auto-discovered from Trino's .well-known/oauth-authorization-server
    ClientID      string // Discovered automatically
    AuthURL       string // Discovered automatically  
    TokenURL      string // Discovered automatically
    Scopes        string // Discovered automatically
}
```

### 2. OAuth Discovery (`internal/oauth/discovery.go`)
- Fetch OAuth configuration from Trino's well-known endpoint
- Parse authorization server metadata
- Configure OAuth client automatically
- Handle discovery errors gracefully

### 3. Browser-Based Authentication Flow (`internal/oauth/browser.go`)
- Start local HTTP server for OAuth callback
- Generate PKCE code verifier/challenge
- Open browser to OAuth authorization URL
- Handle callback with authorization code
- Exchange code for access/refresh tokens

### 4. OAuth Client (`internal/oauth/client.go`)
- Token acquisition and refresh logic
- Automatic token renewal before expiration
- Thread-safe token management
- Secure token storage (keyring/encrypted file)
- Fallback to basic auth when OAuth disabled

### 5. Trino Client Integration (`internal/trino/client.go`)
- Use `AccessToken` field instead of username/password in DSN
- Remove basic auth credentials when OAuth enabled
- Handle token refresh failures gracefully

### 6. MCP Handler Authentication (`internal/handlers/middleware.go`)
- Optional: Validate incoming Bearer tokens for MCP calls
- Extract user context from JWT claims
- Pass user information to Trino queries via `X-Trino-User` header

### 7. HTTP Transport Updates (`cmd/main.go`)
- Support Bearer token authentication on `/api/query` endpoint
- Add authentication middleware to HTTP handlers
- Maintain backward compatibility with basic auth

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

### Authentication Flow
1. **First Run**: MCP server detects no stored tokens
2. **Auto-Discovery**: Fetches OAuth config from `https://trino.example.com/.well-known/oauth-authorization-server`
3. **Browser Launch**: Opens browser to OAuth authorization URL with PKCE
4. **User Login**: User authenticates with their OAuth provider (Google, Azure AD, etc.)
5. **Token Storage**: Securely stores access/refresh tokens locally
6. **Subsequent Runs**: Uses stored tokens, refreshes automatically

## Key Implementation Details

### Token Management
- **Storage**: Secure local storage (OS keyring or encrypted file)
- **Refresh Strategy**: Refresh when token expires within buffer time
- **Error Handling**: Fallback to basic auth on OAuth failures
- **Concurrency**: Thread-safe token access with mutex

### Security Considerations
- **PKCE**: No client secrets needed - uses Proof Key for Code Exchange
- **Token Validation**: Verify JWT signature and expiration
- **Scope Validation**: Ensure tokens have required Trino access scopes
- **Secure Storage**: Use OS keyring or encrypted file for token storage
- **Error Logging**: Log OAuth failures without exposing sensitive data

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

## Implementation Order

1. **OAuth Discovery**: Implement automatic OAuth provider discovery
2. **Browser Authentication**: Create PKCE-based browser authentication flow
3. **Token Storage**: Implement secure token storage and retrieval
4. **Trino Integration**: Connect OAuth tokens to Trino client
5. **Fallback Handling**: Ensure graceful fallback to basic auth
6. **Testing**: Comprehensive testing with various OAuth providers

This simplified approach reduces user configuration to just the Trino server URL while providing a secure, modern authentication experience.

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