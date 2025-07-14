# OAuth Implementation Plan for Trino MCP Server

Based on the Trino Go client documentation and current codebase analysis, here's a comprehensive plan for implementing OAuth support:

## Prerequisites

**IMPORTANT: Trino Cluster OAuth Configuration Required**

Before implementing OAuth in the MCP server, you must have a Trino cluster that is already configured with OAuth authentication. This includes:

1. **Trino Server OAuth Setup**: Trino coordinator must be configured with OAuth authentication
2. **OAuth Provider**: A configured OAuth provider (Google, Azure AD, Okta, etc.)
3. **HTTPS Required**: Trino must be configured with HTTPS (required for OAuth 2.0)
4. **OpenID Connect Discovery**: Trino uses OpenID Connect Discovery by default for OAuth metadata
5. **JWT Support**: Trino must be configured to accept JWT tokens for authentication
6. **Callback URL**: OAuth provider must be configured with Trino's callback URL: `https://<trino-coordinator>/oauth2/callback`

### Trino OAuth Configuration Example
```properties
# coordinator/config.properties
http-server.authentication.type=oauth2
http-server.authentication.oauth2.issuer=https://your-oauth-provider.com
http-server.authentication.oauth2.client-id=your-client-id
http-server.authentication.oauth2.client-secret=your-client-secret

# Required for OAuth 2.0
http-server.https.enabled=true
http-server.https.port=443
node.internal-address-source=FQDN

# Optional OAuth 2.0 settings
http-server.authentication.oauth2.scopes=openid,profile,email
http-server.authentication.oauth2.refresh-tokens=true
http-server.authentication.oauth2.user-mapping.pattern=(.*)
```

## Authentication Flow Options

**Recommended: OAuth 2.0 Authorization Code Flow with PKCE (Simplified)**
- User-friendly browser-based authentication
- Minimal configuration required - just specify Trino server URL
- Automatic OAuth provider discovery via Trino's well-known endpoint
- No client secrets needed (PKCE for security)
- Handles token refresh automatically
- **Requires**: Trino cluster with OAuth already configured

**Alternative: OAuth 2.0 Client Credentials Flow**
- For service-to-service authentication scenarios
- Requires manual OAuth provider configuration
- More complex setup but suitable for headless environments
- **Requires**: Trino cluster with OAuth already configured

## MCP June 2025 Specification Compliance

### Key Requirements from MCP Specification:
1. **OAuth 2.1 Compliance**: Use OAuth 2.1 with appropriate security measures
2. **Resource Indicators (RFC 8707)**: MUST implement to prevent token misuse
3. **PKCE**: Required for public clients (browser-based auth)
4. **Dynamic Client Registration**: Support OAuth 2.0 Dynamic Client Registration Protocol
5. **Authorization Server Metadata**: Implement OAuth 2.0 Authorization Server Metadata (RFC 8414)
6. **Bearer Token Authentication**: Use `Authorization: Bearer <token>` header
7. **HTTPS Enforcement**: All authorization endpoints must use HTTPS

### 1. Enhanced TrinoConfig with OAuth Support (`internal/config/config.go`)
```go
// TrinoConfig holds Trino connection parameters
type TrinoConfig struct {
    // Basic connection parameters
    Host              string
    Port              int
    User              string
    Password          string
    Catalog           string
    Schema            string
    Scheme            string
    SSL               bool
    SSLInsecure       bool
    AllowWriteQueries bool          // Controls whether non-read-only SQL queries are allowed
    QueryTimeout      time.Duration // Query execution timeout
    
    // OAuth 2.1 configuration
    OAuthEnabled       bool   `env:"TRINO_OAUTH_ENABLED" default:"false"`
    OAuthLocalPort     int    `env:"TRINO_OAUTH_PORT" default:"8080"` // Local callback port
    OAuthRefreshBuffer int    `env:"TRINO_OAUTH_REFRESH_BUFFER" default:"300"` // seconds
    
    // MCP Resource Indicator (RFC 8707) - canonical URI for this MCP server
    // Generated from Host:Port when OAuth is enabled
    OAuthResourceIndicator string // Generated from existing Host/Port/Scheme
    
    // Auto-discovered from Trino's .well-known/oauth-authorization-server
    OAuthClientID      string // Discovered automatically
    OAuthAuthURL       string // Discovered automatically  
    OAuthTokenURL      string // Discovered automatically
    OAuthScopes        string // Discovered automatically
}
```

### 2. MCP-Compliant OAuth Discovery (`internal/oauth/discovery.go`)
- Fetch OAuth configuration using OpenID Connect Discovery from `{scheme}://{host}:{port}/.well-known/openid-configuration`
- Parse authorization server metadata (RFC 8414)
- Validate HTTPS endpoints (MCP requirement)
- Configure OAuth client automatically
- Generate Resource Indicator URI from existing Host/Port/Scheme
- Handle discovery errors gracefully
- Support Trino's OpenID Connect Discovery by default

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

### 5. Authentication-Aware Trino Client Integration (`internal/trino/client.go`)
- **OAuth Mode**: Use `AccessToken` field in Trino client config
- **Basic Auth Mode**: Use username/password in DSN
- Connection method determined by `TrinoConfig.OAuthEnabled`
- Handle token refresh failures for OAuth mode
- Ensure HTTPS connections for OAuth (MCP requirement)

### 6. MCP Handler Authentication (`internal/handlers/middleware.go`)
- **OAuth Mode**: Validate incoming Bearer tokens for HTTP transport
- **Basic Auth Mode**: No additional authentication required
- Return 401 Unauthorized for missing/invalid tokens (OAuth mode)
- Return 403 Forbidden for insufficient permissions (OAuth mode)
- Extract user context from JWT claims (OAuth) or config (Basic)
- Pass user information to Trino queries via `X-Trino-User` header
- Validate token audience matches MCP server Resource Indicator (OAuth mode)

### 7. Authentication-Aware HTTP Transport Updates (`cmd/main.go`)
- **OAuth Mode**: Support Bearer token authentication on all endpoints
- **Basic Auth Mode**: Use existing authentication approach
- Authentication method determined by configuration
- Use `Authorization: Bearer <token>` header format (OAuth mode)
- Return proper HTTP error codes (401, 403, 400)
- Enforce HTTPS for OAuth authorization endpoints

## Authentication Configuration Options

### Option 1: OAuth 2.1 Authentication (Recommended)
```json
{
  "mcpServers": {
    "trino": {
      "command": "mcp-trino",
      "env": {
        "TRINO_HOST": "trino.example.com",
        "TRINO_PORT": "443",
        "TRINO_SCHEME": "https",
        "TRINO_OAUTH_ENABLED": "true"
      }
    }
  }
}
```

### Option 2: Basic Authentication (Current/Legacy)
```json
{
  "mcpServers": {
    "trino": {
      "command": "mcp-trino",
      "env": {
        "TRINO_HOST": "trino.example.com",
        "TRINO_PORT": "443",
        "TRINO_USER": "myuser",
        "TRINO_PASSWORD": "mypassword",
        "TRINO_SSL": "true"
      }
    }
  }
}
```

### OAuth 2.1 Authentication Flow
1. **First Run**: MCP server detects no stored tokens
2. **Auto-Discovery**: Fetches OAuth config from `{scheme}://{host}:{port}/.well-known/openid-configuration`
3. **Resource Indicator**: Generates canonical URI for MCP server (e.g., `https://trino.example.com:443/mcp`)
4. **Browser Launch**: Opens browser to OAuth authorization URL with PKCE + Resource Indicator
5. **User Login**: User authenticates with their OAuth provider (Google, Azure AD, etc.)
6. **Token Exchange**: Exchanges authorization code for tokens with Resource Indicator
7. **Token Validation**: Validates token audience matches Resource Indicator
8. **Token Storage**: Securely stores access/refresh tokens locally
9. **Subsequent Runs**: Uses stored tokens, refreshes automatically with Resource Indicator

**Note**: This flow creates a separate OAuth client for the MCP server, distinct from Trino's own OAuth configuration.

## Key Implementation Details

### Token Management (OAuth Mode Only)
- **Storage**: Secure local storage (OS keyring or encrypted file)
- **Refresh Strategy**: Refresh when token expires within buffer time
- **Error Handling**: Return authentication errors - no fallback
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

### Authentication Method Selection
- **OAuth 2.1**: When `TRINO_OAUTH_ENABLED=true`
- **Basic Auth**: When `TRINO_OAUTH_ENABLED=false` or not set
- **Anonymous**: When no credentials provided (uses default "trino" user)

## Benefits of This Approach

1. **User-Friendly**: OAuth requires only Trino server URL - no complex configuration
2. **Automatic Discovery**: Fetches OAuth configuration from Trino's well-known endpoint
3. **Secure**: Uses PKCE flow - no client secrets needed
4. **Persistent**: Securely stores tokens for seamless subsequent use
5. **Trino Compatibility**: Leverages existing JWT support in Trino Go client
6. **Clear Separation**: OAuth and basic auth are separate modes - no mixing
7. **Cross-Platform**: Works on macOS, Windows, and Linux
8. **MCP Compliant**: Meets June 2025 MCP specification requirements

## Limitations and Requirements

**Prerequisites:**
- Trino cluster must already be configured with OAuth authentication
- OAuth provider (Google, Azure AD, etc.) must be set up and configured in Trino
- Trino must be configured with HTTPS (required for OAuth 2.0)
- Trino must expose OAuth metadata via OpenID Connect Discovery
- Network connectivity to OAuth provider required during authentication
- Browser access required for initial authentication

**Important Notes:**
- Trino uses Authorization Code flow (not Client Credentials)
- Trino callback URL: `https://<trino-coordinator>/oauth2/callback`
- MCP server will create its own OAuth client registration
- Refresh tokens are supported for longer sessions

**Not Suitable For:**
- Trino clusters without OAuth support
- Environments where browser access is not available
- Scenarios requiring custom authentication flows

## MCP-Compliant Implementation Order

1. **Enhance TrinoConfig**: Add OAuth fields to existing TrinoConfig structure
2. **OAuth Discovery**: Implement automatic OAuth provider discovery with RFC 8414 support
3. **Resource Indicators**: Implement RFC 8707 Resource Indicators for token scoping
4. **Browser Authentication**: Create PKCE-based browser authentication flow
5. **Token Storage**: Implement secure token storage and retrieval
6. **Token Validation**: Add audience validation and OAuth 2.1 security measures
7. **Trino Integration**: Connect OAuth tokens to Trino client (OAuth mode)
8. **MCP Handler Authentication**: Add OAuth authentication for HTTP transport
9. **Error Handling**: Implement proper HTTP error codes (401, 403, 400)
10. **HTTPS Enforcement**: Ensure OAuth authorization endpoints use HTTPS
11. **Mode Selection**: Implement authentication method selection logic
12. **Testing**: Comprehensive testing with both OAuth and basic auth modes

This approach provides two distinct authentication modes: OAuth 2.1 for modern security and basic auth for existing deployments, with clear separation between the two.

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