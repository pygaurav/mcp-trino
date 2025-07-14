# OAuth Implementation Plan for Trino MCP Server with mcp-go v0.33.0

Based on the mcp-go v0.33.0 OAuth 2.1 capabilities and Claude Code native OAuth support, here's a simplified plan for implementing OAuth support leveraging the built-in MCP Authorization specification:

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

## MCP June 2025 Specification Compliance with mcp-go v0.33.0

### Key Requirements from MCP Specification (Built into mcp-go v0.33.0):
1. **OAuth 2.1 Compliance**: Full OAuth 2.1 support with appropriate security measures
2. **Resource Indicators (RFC 8707)**: Built-in implementation to prevent token misuse
3. **PKCE**: Integrated PKCE support for public clients (browser-based auth)
4. **Dynamic Client Registration**: OAuth 2.0 Dynamic Client Registration Protocol support
5. **Authorization Server Metadata**: OAuth 2.0 Authorization Server Metadata (RFC 8414) support
6. **Bearer Token Authentication**: Native `Authorization: Bearer <token>` header processing
7. **HTTPS Enforcement**: Automatic HTTPS enforcement for all authorization endpoints

### mcp-go v0.33.0 OAuth 2.1 Features:
- **Native OAuth Server**: Built-in OAuth 2.1 authorization server capabilities
- **Token Validation**: Comprehensive JWT token validation and processing
- **Client Management**: Dynamic and static OAuth client registration
- **Security Headers**: Automatic security header management
- **Session Management**: Built-in session and token lifecycle management

### 1. Simplified TrinoConfig with mcp-go v0.33.0 OAuth Support (`internal/config/config.go`)
```go
import (
    "github.com/mark3labs/mcp-go/pkg/auth"
    "github.com/mark3labs/mcp-go/pkg/oauth"
)

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
    
    // OAuth mode configuration (using mcp-go v0.33.0)
    OAuthEnabled      bool                 `env:"TRINO_OAUTH_ENABLED" default:"false"`
    OAuthConfig       *oauth.ServerConfig  // mcp-go OAuth server configuration
    
    // Runtime fields (populated by mcp-go authentication middleware)
    AuthContext       *auth.Context // mcp-go authentication context
}
```

### 2. Bearer Token Validation (`internal/auth/bearer.go`)
- **Leverage mcp-go v0.33.0**: Use built-in Bearer token extraction and validation
- **JWT Processing**: Utilize mcp-go's comprehensive JWT token validation
- **User Context**: Extract user information using mcp-go's token parsing
- **Error Handling**: Leverage mcp-go's standardized error responses
- **Note**: Token acquisition and refresh handled by Claude Code/mcp-remote

### 3. OAuth Discovery for MCP Server Configuration (`internal/oauth/discovery.go`)
- **mcp-go v0.33.0 Integration**: Use built-in OpenID Connect Discovery client
- **Automatic Configuration**: Leverage mcp-go's OAuth provider metadata fetching
- **Client Registration**: Use mcp-go's dynamic client registration capabilities
- **Configuration Helper**: Provide setup assistance using mcp-go's configuration tools
- **Note**: Simplified with mcp-go v0.33.0's built-in discovery mechanisms

### 4. HTTP Authentication Middleware (`internal/middleware/auth.go`)
- **mcp-go v0.33.0 Middleware**: Use built-in authentication middleware
- **Automatic Token Processing**: Leverage mcp-go's Bearer token extraction
- **User Context Injection**: Use mcp-go's standardized user context handling
- **HTTP Status Codes**: Rely on mcp-go's compliant 401/403 error responses
- **Permission Validation**: Integrate with mcp-go's authorization framework

### 5. Simplified Trino Client Integration (`internal/trino/client.go`)
- **OAuth Mode**: Use existing basic auth or anonymous connection to Trino (unchanged)
- **Basic Auth Mode**: Use username/password in DSN (unchanged)
- **Authorization**: MCP server handles authorization before requests reach Trino
- No token refresh logic needed (handled by Claude Code/mcp-remote)
- Trino connection method remains independent of OAuth authentication

### 6. Simplified HTTP Transport Updates (`cmd/main.go`)
- **mcp-go v0.33.0 Server**: Use built-in OAuth-enabled HTTP server
- **Authentication Integration**: Leverage mcp-go's authentication middleware
- **Configuration-Driven**: Use mcp-go's configuration-based auth method selection
- **Standard HTTP Responses**: Rely on mcp-go's compliant error handling
- **Remote Access**: Built-in support for remote MCP server deployment

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

## Simplified Implementation Order with mcp-go v0.33.0

1. **Upgrade mcp-go**: Update to v0.33.0 for OAuth 2.1 support
   ```bash
   go get github.com/mark3labs/mcp-go@v0.33.0
   go mod tidy
   ```
2. **Enhance TrinoConfig**: Add simple OAuth fields to existing TrinoConfig structure
3. **Integrate OAuth Middleware**: Use mcp-go v0.33.0's built-in authentication middleware
4. **Bearer Token Validation**: Leverage mcp-go's JWT token validation capabilities
5. **HTTP Transport**: Configure mcp-go's OAuth-enabled HTTP server
6. **Trino Integration**: Keep existing Trino connection method (basic auth/anonymous)
7. **Mode Selection**: Implement configuration-based authentication method selection
8. **Testing**: Test with Claude Code native OAuth and mcp-remote for compatibility

**Key Simplifications with mcp-go v0.33.0:**
- **Built-in OAuth Server** - mcp-go v0.33.0 provides complete OAuth 2.1 implementation
- **No OAuth discovery needed** - Claude Code/mcp-remote handles this
- **No browser integration** - Claude Code/mcp-remote handles OAuth flows
- **No token storage** - Claude Code/mcp-remote manages tokens
- **No PKCE implementation** - Built into mcp-go v0.33.0
- **No Resource Indicators** - Built into mcp-go v0.33.0 MCP Authorization spec
- **Simplified Bearer token validation** - Use mcp-go's built-in JWT processing
- **No Trino OAuth setup** - MCP server acts as authorization gateway

This approach provides a dramatically simplified OAuth implementation by leveraging both mcp-go v0.33.0's built-in capabilities and Claude Code/mcp-remote for OAuth complexity while maintaining two distinct authentication modes.

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

## Key Integration Points for OAuth Implementation with mcp-go v0.33.0

Based on the current architecture, OAuth/JWT authentication with mcp-go v0.33.0 would need to be added at:

1. **Library Upgrade**: Update to mcp-go v0.33.0 for OAuth 2.1 support
2. **Config Layer**: Add OAuth/JWT configuration parameters using mcp-go's configuration system
3. **Middleware Layer**: Integrate mcp-go's built-in authentication middleware
4. **Handler Layer**: Use mcp-go's standardized authenticated request handling
5. **Transport Layer**: Configure mcp-go's OAuth-enabled HTTP server
6. **MCP Layer**: Leverage mcp-go's authentication context for tool calls

The current codebase provides a solid foundation for adding OAuth/JWT authentication, and mcp-go v0.33.0 provides the necessary OAuth 2.1 infrastructure to significantly simplify the implementation.