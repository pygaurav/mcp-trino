# OAuth Implementation Plan for Trino MCP Server

Based on Claude Code native OAuth support and custom server-side OAuth implementation, here's a plan for adding OAuth 2.1 authentication to the Trino MCP server:

## Prerequisites

**IMPORTANT: MCP Server as OAuth Resource Server**

The MCP server acts as an OAuth 2.1 resource server, handling all OAuth-related authorization and token validation. The underlying Trino database does **not** need to support OAuth directly. This includes:

1. **OAuth Provider**: A configured OAuth provider (Google, Azure AD, Okta, etc.) for user authentication
2. **HTTPS Required**: MCP server must be configured with HTTPS (required for OAuth 2.0)
3. **OpenID Connect Discovery**: OAuth provider must support OpenID Connect Discovery for metadata
4. **JWT Token Support**: MCP server validates JWT tokens from Claude Code
5. **Trino Connection**: Trino can use basic authentication, anonymous access, or any existing authentication method

### MCP Server OAuth Configuration Example
```bash
# MCP server environment variables
export TRINO_HOST=trino.example.com
export TRINO_PORT=443
export TRINO_USER=service-account
export TRINO_PASSWORD=service-password
export TRINO_OAUTH_ENABLED=true
export MCP_TRANSPORT=http
export MCP_PORT=8080
export MCP_HTTPS=true
```

### OAuth Provider Configuration
- **Callback URL**: Configure OAuth provider with MCP server's callback URL: `https://<mcp-server>/oauth2/callback`
- **Scopes**: Typically `openid,profile,email` for user identification
- **Client Registration**: Can use dynamic client registration or pre-configured client credentials

## Architecture Overview

**Claude Code Native Remote MCP Support (Recommended)**
- **Claude Code** connects directly to remote MCP servers with OAuth
- **Claude Code** handles OAuth flow and token management natively
- **MCP Server** acts as OAuth resource server, validating Bearer tokens
- **Trino Database** uses existing authentication (basic auth, anonymous, etc.)

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
- **Requires**: OAuth provider configured for MCP server authentication

**Alternative: mcp-remote Proxy with OAuth 2.0**
- For Claude Desktop or other MCP clients without native remote support
- **mcp-remote** handles browser-based authentication
- Built-in PKCE support for security
- Automatic token refresh and storage
- **Requires**: OAuth provider configured for MCP server authentication

## MCP June 2025 Specification Compliance

### Key Requirements from MCP Specification:
1. **OAuth 2.1 Compliance**: OAuth 2.1 support with appropriate security measures
2. **Resource Indicators (RFC 8707)**: Implemented to prevent token misuse
3. **PKCE**: PKCE support for public clients (browser-based auth)
4. **Dynamic Client Registration**: OAuth 2.0 Dynamic Client Registration Protocol support
5. **Authorization Server Metadata**: OAuth 2.0 Authorization Server Metadata (RFC 8414) support
6. **Bearer Token Authentication**: `Authorization: Bearer <token>` header processing
7. **HTTPS Enforcement**: HTTPS enforcement for all authorization endpoints

### Implementation Architecture:
- **Client-Side OAuth**: Claude Code/mcp-remote handles OAuth flows, PKCE, token management
- **Server-Side OAuth**: Custom implementation for JWT validation and resource server functionality
- **mcp-go Role**: Provides MCP protocol support and client-side OAuth capabilities (not server-side)
- **Custom Authentication**: Bearer token validation, middleware, and user context handling

### 1. TrinoConfig with OAuth Support (`internal/config/config.go`)
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
    
    // OAuth mode configuration
    OAuthEnabled      bool   // Enable OAuth 2.1 authentication
}
```

### 2. Bearer Token Validation (`internal/auth/bearer.go`)
- **Custom JWT Processing**: Comprehensive JWT token validation using golang-jwt/jwt
- **RSA Signature Verification**: Validate tokens using OAuth provider's public keys
- **User Context Extraction**: Extract user information from JWT claims
- **Error Handling**: Standardized error responses for authentication failures
- **Token Lifecycle**: Handle token expiration, validation, and user context creation
- **Note**: Token acquisition and refresh handled by Claude Code/mcp-remote

### 3. OAuth Discovery for MCP Server Configuration (`internal/oauth/discovery.go`)
- **OpenID Connect Discovery**: Custom client for fetching OAuth provider metadata
- **JWKS Integration**: Fetch and parse JSON Web Key Sets for token validation
- **Configuration Management**: OAuth provider configuration and validation
- **Environment Integration**: Load OAuth settings from environment variables
- **Public Key Extraction**: Parse RSA public keys from JWKS for JWT validation

### 4. HTTP Authentication Middleware (`internal/middleware/auth.go`)
- **Custom Authentication Middleware**: Bearer token extraction and validation
- **User Context Injection**: Add authenticated user context to requests
- **HTTP Status Codes**: Proper 401/403 error responses
- **Security Headers**: CORS, security headers, and authentication headers
- **Conditional Authentication**: OAuth mode vs basic auth mode selection

### 5. Simplified Trino Client Integration (`internal/trino/client.go`)
- **OAuth Mode**: Use existing basic auth or anonymous connection to Trino (unchanged)
- **Basic Auth Mode**: Use username/password in DSN (unchanged)
- **Authorization**: MCP server handles authorization before requests reach Trino
- No token refresh logic needed (handled by Claude Code/mcp-remote)
- Trino connection method remains independent of OAuth authentication

### 6. HTTP Transport Updates (`cmd/main.go`)
- **OAuth Integration**: Custom authentication middleware integration
- **Middleware Stack**: Security headers, CORS, logging, and authentication
- **Configuration-Driven**: OAuth vs basic auth mode selection
- **Error Handling**: Proper HTTP status codes and error responses
- **Remote Access**: HTTP server setup for remote MCP client connections

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
8. **MCP Server Authorization**: MCP server validates Bearer tokens and authorizes access to tools
9. **Trino Connection**: MCP server connects to Trino using existing authentication (basic auth/anonymous)

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
6. **Trino Compatibility**: Works with any Trino authentication method (basic auth, anonymous, Kerberos, etc.)
7. **Remote Deployment**: Can deploy MCP server anywhere with HTTPS
8. **Cross-Platform**: Works on macOS, Windows, and Linux
9. **MCP Compliant**: Full compliance with June 2025 MCP specification
10. **Separation of Concerns**: OAuth complexity separated from business logic
11. **Easy Testing**: Can test OAuth and MCP server independently
12. **Authenticate Once**: Seamless experience across Claude Code sessions

## Limitations and Requirements

**Prerequisites:**
- OAuth provider (Google, Azure AD, etc.) must be set up and configured for MCP server
- MCP server must be deployed with HTTPS (required for OAuth 2.0)
- OAuth provider must expose OAuth metadata via OpenID Connect Discovery
- Network connectivity to OAuth provider required during authentication
- Browser access required for initial authentication (handled by Claude Code/mcp-remote)
- Trino cluster must be accessible to MCP server (any authentication method supported)

**Important Notes:**
- Claude Code/mcp-remote handles all OAuth flows - no browser integration needed in MCP server
- MCP server must run as HTTP server (not STDIO) for remote access
- Claude Code/mcp-remote creates its own OAuth client registration
- All OAuth complexity is handled by Claude Code/mcp-remote

**Not Suitable For:**
- Environments where Claude Code/mcp-remote cannot be installed
- Scenarios requiring custom authentication flows beyond OAuth 2.1
- Use cases requiring direct MCP server access without OAuth (use basic auth mode instead)

## Implementation Order

1. **Upgrade mcp-go**: Update to v0.33.0 for enhanced MCP protocol support
   ```bash
   go get github.com/mark3labs/mcp-go@v0.33.0
   go mod tidy
   ```
2. **Enhance TrinoConfig**: Add OAuth configuration fields
3. **Implement Bearer Token Validation**: Custom JWT validation using golang-jwt/jwt
4. **Create OAuth Discovery Client**: OpenID Connect Discovery and JWKS fetching
5. **Build Authentication Middleware**: Custom middleware for Bearer token handling
6. **Update HTTP Transport**: Integrate middleware stack with OAuth support
7. **Add Environment Configuration**: OAuth provider and client configuration
8. **Testing**: Test with Claude Code native OAuth and mcp-remote for compatibility

**Key Implementation Details:**
- **Custom OAuth Resource Server** - We implement server-side OAuth validation (mcp-go provides client-side only)
- **Client-Side OAuth Handled by Claude Code/mcp-remote** - No server-side OAuth flows needed
- **JWT Token Validation** - Custom implementation using golang-jwt/jwt library
- **OpenID Connect Discovery** - Custom client for OAuth provider metadata
- **Bearer Token Middleware** - Custom authentication middleware
- **No Trino OAuth setup** - MCP server acts as authorization gateway

This approach provides OAuth 2.1 authentication by implementing the server-side OAuth resource server functionality that mcp-go doesn't provide, while leveraging Claude Code/mcp-remote for client-side OAuth complexity.

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

## Key Integration Points for OAuth Implementation

Based on the current architecture, OAuth/JWT authentication needs to be added at:

1. **Library Upgrade**: Update to mcp-go v0.33.0 for enhanced MCP protocol support
2. **Config Layer**: Add OAuth/JWT configuration parameters
3. **Authentication Layer**: Implement custom JWT validation and Bearer token handling
4. **Middleware Layer**: Create custom authentication middleware
5. **Handler Layer**: Add authentication logging and user context handling
6. **Transport Layer**: Integrate authentication middleware with HTTP server
7. **Discovery Layer**: Implement OAuth provider discovery and JWKS fetching

The current codebase provides a solid foundation for adding OAuth/JWT authentication. Since mcp-go v0.33.0 provides client-side OAuth capabilities but no server-side authentication, we implement the necessary server-side OAuth resource server functionality.