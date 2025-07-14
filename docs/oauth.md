# OAuth Implementation Plan for Trino MCP Server with mcp-remote

Based on the Trino Go client documentation and mcp-remote integration analysis, here's a simplified plan for implementing OAuth support using mcp-remote as the authentication proxy:

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

## Architecture Overview

**Claude Code Native Remote MCP Support (Recommended)**
- **Claude Code** connects directly to remote MCP servers with OAuth
- **Claude Code** handles OAuth flow and token management natively
- **MCP Server** receives authenticated requests with Bearer tokens
- **Trino Database** uses JWT tokens for authentication

**Benefits of Claude Code Native Support:**
- No proxy needed - direct connection to remote MCP servers
- Native OAuth 2.1 and MCP Authorization specification compliance
- Built-in PKCE support and automatic token refresh
- Simplified setup - just authenticate once
- Remote deployment ready

**Alternative: mcp-remote Proxy Architecture**
- For Claude Desktop or environments where Claude Code native support isn't available
- **Claude Desktop** connects to local `mcp-remote` proxy
- **mcp-remote** handles OAuth flow and token management
- Same benefits as Claude Code native support

## Authentication Flow Options

**Recommended: Claude Code Native Remote MCP with OAuth 2.0**
- **Claude Code** handles browser-based authentication natively
- Built-in PKCE support for security
- Automatic token refresh and storage
- Full MCP Authorization specification compliance
- **Requires**: Trino cluster with OAuth already configured

**Alternative: mcp-remote Proxy with OAuth 2.0**
- For Claude Desktop or other MCP clients without native remote support
- **mcp-remote** handles browser-based authentication
- Built-in PKCE support for security
- Automatic token refresh and storage
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

### 1. Simplified TrinoConfig with Bearer Token Support (`internal/config/config.go`)
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
    
    // OAuth mode configuration (simplified with mcp-remote)
    OAuthEnabled      bool   `env:"TRINO_OAUTH_ENABLED" default:"false"`
    
    // Runtime fields (populated from HTTP headers via mcp-remote)
    BearerToken       string // JWT token from Authorization header
    AuthenticatedUser string // User extracted from JWT token
}
```

### 2. Bearer Token Validation (`internal/auth/bearer.go`)
- Extract Bearer token from HTTP Authorization header
- Validate JWT token format and basic claims
- Extract user information from JWT token
- Handle token validation errors gracefully
- **Note**: Token acquisition and refresh handled by mcp-remote

### 3. OAuth Discovery for mcp-remote Configuration (`internal/oauth/discovery.go`)
- Fetch OAuth configuration from Trino's OpenID Connect Discovery endpoint
- Generate OAuth client metadata for mcp-remote
- Provide configuration helper for mcp-remote setup
- **Note**: Only needed for initial mcp-remote configuration

### 4. HTTP Authentication Middleware (`internal/middleware/auth.go`)
- Extract Bearer token from Authorization header
- Validate JWT token and extract user context
- Pass authenticated user to downstream handlers
- Return 401 for missing/invalid tokens
- Return 403 for insufficient permissions

### 5. Simplified Trino Client Integration (`internal/trino/client.go`)
- **OAuth Mode**: Use Bearer token from mcp-remote as `AccessToken` in Trino client config
- **Basic Auth Mode**: Use username/password in DSN (unchanged)
- Connection method determined by `TrinoConfig.OAuthEnabled`
- No token refresh logic needed (handled by mcp-remote)
- Ensure HTTPS connections for OAuth (MCP requirement)

### 6. Simplified HTTP Transport Updates (`cmd/main.go`)
- **OAuth Mode**: Add authentication middleware to validate Bearer tokens
- **Basic Auth Mode**: Use existing authentication approach (unchanged)
- Authentication method determined by configuration
- Return proper HTTP error codes (401, 403, 400)
- Must run as HTTP server (not STDIO) for mcp-remote compatibility

## Authentication Configuration Options

### Option 1: OAuth 2.1 with Claude Code Native Support (Recommended)

**Step 1: Deploy MCP Server with OAuth Support**
```bash
# Deploy mcp-trino server with OAuth enabled
export TRINO_HOST=trino.example.com
export TRINO_PORT=443
export TRINO_SCHEME=https
export TRINO_OAUTH_ENABLED=true
export MCP_TRANSPORT=http
export MCP_PORT=8080

./mcp-trino
```

**Step 2: Configure Claude Code with Remote MCP Server**
```bash
# Claude Code will handle OAuth flow automatically
claude mcp add https://your-mcp-server.com:8080
```

**Alternative: Option 2: OAuth 2.1 with mcp-remote (For Claude Desktop)**

**Step 1: Deploy MCP Server (same as above)**

**Step 2: Configure Claude Desktop with mcp-remote**
```json
{
  "mcpServers": {
    "trino": {
      "command": "npx",
      "args": [
        "mcp-remote",
        "https://your-mcp-server.com:8080/sse"
      ]
    }
  }
}
```

### Option 3: Basic Authentication (Current/Legacy - Local Only)
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

### Simplified OAuth 2.1 Authentication Flow with Claude Code Native Support
1. **User Adds Remote MCP Server**: `claude mcp add https://your-server.com:8080`
2. **Claude Code OAuth Discovery**: Claude Code discovers OAuth configuration from MCP server
3. **Browser Authentication**: Claude Code opens browser for OAuth authentication
4. **User Login**: User authenticates with OAuth provider (Google, Azure AD, etc.)
5. **Token Storage**: Claude Code securely stores OAuth tokens locally
6. **Authenticated Requests**: Claude Code adds `Authorization: Bearer <token>` to all MCP requests
7. **Token Refresh**: Claude Code automatically refreshes expired tokens
8. **MCP Server Validation**: MCP server validates Bearer tokens and extracts user context
9. **Trino Authentication**: MCP server uses JWT token to authenticate with Trino database

**Key Benefits:**
- **No OAuth complexity in MCP server** - just validate Bearer tokens
- **Native integration** - no proxy needed with Claude Code
- **Automatic token management** - Claude Code handles all OAuth flows
- **MCP Authorization spec compliance** - built into Claude Code
- **Remote deployment ready** - can deploy MCP server anywhere
- **Authenticate once** - seamless experience across sessions

## Key Implementation Details

### Simplified Token Management (Claude Code handles complexity)
- **Storage**: Handled by Claude Code locally (secure keychain/credential storage)
- **Refresh Strategy**: Automatic refresh handled by Claude Code
- **Error Handling**: Return authentication errors - no fallback
- **Validation**: MCP server only validates Bearer tokens from HTTP headers

### MCP-Compliant Security Considerations
- **OAuth 2.1**: Full compliance provided by Claude Code
- **Resource Indicators (RFC 8707)**: Implemented by Claude Code
- **PKCE**: Built into Claude Code for security
- **Token Validation**: MCP server validates JWT format, expiration, and basic claims
- **HTTPS Enforcement**: Required for both Claude Code and MCP server
- **Secure Storage**: Claude Code handles secure token storage
- **Error Logging**: Log authentication failures without exposing token data
- **Bearer Token Validation**: Validate tokens are valid JWT format and not expired

### Authentication Method Selection
- **OAuth 2.1**: When `TRINO_OAUTH_ENABLED=true`
- **Basic Auth**: When `TRINO_OAUTH_ENABLED=false` or not set
- **Anonymous**: When no credentials provided (uses default "trino" user)

## Benefits of Claude Code Native OAuth Approach

1. **Dramatically Simplified**: No complex OAuth middleware in MCP server
2. **User-Friendly**: Claude Code handles all OAuth complexity automatically
3. **Native Integration**: No proxy needed - direct connection to remote MCP servers
4. **Secure**: Built-in OAuth 2.1, PKCE, and MCP Authorization spec compliance
5. **Persistent**: Claude Code handles secure token storage and refresh
6. **Trino Compatibility**: Leverages existing JWT support in Trino Go client
7. **Remote Deployment**: Can deploy MCP server anywhere with HTTPS
8. **Cross-Platform**: Works on macOS, Windows, and Linux
9. **MCP Compliant**: Full compliance with June 2025 MCP specification
10. **Separation of Concerns**: OAuth complexity separated from business logic
11. **Easy Testing**: Can test OAuth and MCP server independently
12. **Authenticate Once**: Seamless experience across Claude Code sessions

## Limitations and Requirements

**Prerequisites:**
- Trino cluster must already be configured with OAuth authentication
- OAuth provider (Google, Azure AD, etc.) must be set up and configured in Trino
- Trino must be configured with HTTPS (required for OAuth 2.0)
- Trino must expose OAuth metadata via OpenID Connect Discovery
- Network connectivity to OAuth provider required during authentication
- Browser access required for initial authentication (handled by mcp-remote)
- MCP server must be deployed with HTTPS (for mcp-remote compatibility)

**Important Notes:**
- mcp-remote handles all OAuth flows - no browser integration needed in MCP server
- MCP server must run as HTTP server (not STDIO) for mcp-remote
- mcp-remote creates its own OAuth client registration
- All OAuth complexity is handled by mcp-remote

**Not Suitable For:**
- Trino clusters without OAuth support
- Environments where mcp-remote cannot be installed
- Scenarios requiring custom authentication flows beyond OAuth 2.1

## Simplified Implementation Order with mcp-remote

1. **Enhance TrinoConfig**: Add simple OAuth fields to existing TrinoConfig structure
2. **Bearer Token Validation**: Implement HTTP Authorization header extraction and JWT validation
3. **HTTP Authentication Middleware**: Add middleware to validate Bearer tokens
4. **Trino Integration**: Connect Bearer tokens to Trino client as AccessToken
5. **HTTP Transport**: Ensure HTTP server mode and proper error handling
6. **Mode Selection**: Implement authentication method selection logic
7. **Testing**: Test with mcp-remote for OAuth flows and basic auth separately

**Key Simplifications:**
- **No OAuth discovery needed** - mcp-remote handles this
- **No browser integration** - mcp-remote handles OAuth flows
- **No token storage** - mcp-remote manages tokens
- **No PKCE implementation** - mcp-remote provides this
- **No Resource Indicators** - mcp-remote handles MCP Authorization spec
- **Just Bearer token validation** - much simpler implementation

This approach provides a dramatically simplified OAuth implementation by leveraging mcp-remote for all OAuth complexity while maintaining two distinct authentication modes.

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