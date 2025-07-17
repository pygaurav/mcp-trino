# OAuth 2.0 Authentication Architecture

This document outlines the OAuth 2.0 authentication architecture for the mcp-trino server, providing secure access control for AI assistants accessing Trino databases.

## Architecture Overview

The mcp-trino server implements OAuth 2.0 as a **resource server**, validating JWT tokens from clients while maintaining existing Trino authentication methods. This separation allows for flexible deployment scenarios.

### Key Components

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   AI Client     │    │   OAuth         │    │   MCP Server    │
│ (Claude Code /  │────│   Provider      │────│   (mcp-trino)   │
│  mcp-remote)    │    │ (Okta/Google/   │    │                 │
│                 │    │  Azure AD)      │    │                 │
└─────────────────┘    └─────────────────┘    └─────────────────┘
                                                       │
                                                       │
                                               ┌─────────────────┐
                                               │ Trino Database  │
                                               │ (Any Auth Type) │
                                               └─────────────────┘
```

### Authentication Flow

1. **Client Authentication**: AI clients authenticate with OAuth provider
2. **Token Validation**: MCP server validates JWT tokens using OIDC/JWKS
3. **Database Access**: Server connects to Trino using configured authentication
4. **Authorization**: User context from JWT used for logging and access control

## Supported Authentication Modes

### 1. OIDC Provider Mode (Production)
- **Providers**: Okta, Google, Azure AD, and other OIDC-compliant providers
- **Validation**: JWKS-based signature verification with automatic key rotation
- **Configuration**: `OAUTH_PROVIDER=okta|google|azure`

### 2. HMAC-SHA256 Mode (Development/Testing)
- **Use Case**: Service-to-service authentication and testing
- **Validation**: Shared secret validation
- **Configuration**: `OAUTH_PROVIDER=hmac`

### 3. No Authentication Mode (Default)
- **Use Case**: Local development and trusted environments
- **Configuration**: `TRINO_OAUTH_ENABLED=false`

## Key Features

### Security Implementation
- **Token Caching**: SHA256-based token validation caching (5-minute expiration)
- **PKCE Support**: Full OAuth 2.1 PKCE implementation for public clients
- **TLS Security**: Secure HTTP client configuration with proper certificate validation
- **Context Timeouts**: Proper timeout handling for all OAuth operations

### MCP Compliance
- **OAuth Metadata**: RFC 8414 compliant authorization server metadata endpoints
- **Dynamic Registration**: RFC 7591 dynamic client registration support
- **Resource Indicators**: RFC 8707 support for token audience specification
- **Bearer Token Validation**: OAuth 2.1 Section 5 compliant token validation

### Integration Points
- **Claude Code**: Native remote MCP server support with OAuth
- **mcp-remote**: Proxy support for Claude Desktop and other clients
- **HTTP Transport**: StreamableHTTP endpoint (`/mcp`) with backward compatibility (`/sse`)
- **Multiple Providers**: Configurable provider selection via environment variables

## Configuration

### Environment Variables

```bash
# OAuth Configuration
TRINO_OAUTH_ENABLED=true
OAUTH_PROVIDER=okta          # hmac|okta|google|azure
JWT_SECRET=your-secret-key   # Required for HMAC mode

# OIDC Provider Configuration
OIDC_ISSUER=https://your-domain.okta.com
OIDC_AUDIENCE=https://your-domain.okta.com
OIDC_CLIENT_ID=your-client-id

# MCP Server Configuration
MCP_TRANSPORT=http
MCP_PORT=8080
MCP_HOST=localhost

# HTTPS Configuration (Production)
HTTPS_CERT_FILE=/path/to/cert.pem
HTTPS_KEY_FILE=/path/to/key.pem
```

## Deployment Scenarios

### Development Setup
```bash
# HMAC mode for testing
TRINO_OAUTH_ENABLED=true \
OAUTH_PROVIDER=hmac \
JWT_SECRET=development-secret \
MCP_TRANSPORT=http \
./mcp-trino
```

### Production Deployment
```bash
# OIDC mode with HTTPS
TRINO_OAUTH_ENABLED=true \
OAUTH_PROVIDER=okta \
OIDC_ISSUER=https://company.okta.com \
OIDC_AUDIENCE=https://mcp-server.company.com \
MCP_TRANSPORT=http \
HTTPS_CERT_FILE=/etc/ssl/certs/server.pem \
HTTPS_KEY_FILE=/etc/ssl/private/server.key \
./mcp-trino
```

### Client Configuration
```json
{
  "mcpServers": {
    "trino-oauth": {
      "url": "https://your-mcp-server.com/mcp",
      "headers": {
        "Authorization": "Bearer YOUR_JWT_TOKEN"
      }
    }
  }
}
```

## Benefits

- **Simplified Architecture**: OAuth complexity handled by clients (Claude Code/mcp-remote)
- **Flexible Authentication**: Works with any Trino authentication method
- **Production Ready**: Full OIDC support with proper security measures
- **MCP Compliant**: Implements OAuth 2.1 and MCP authorization specifications
- **Remote Deployment**: Supports distributed MCP server architecture
- **Multi-Provider**: Configurable OAuth provider support

## Security Considerations

- **Token Validation**: Proper JWT signature verification with JWKS
- **HTTPS Required**: Production deployments must use HTTPS
- **Token Expiration**: Implement appropriate token lifetimes
- **Provider Trust**: Use established OAuth providers for production
- **Network Security**: Secure communication between all components
- **Audit Logging**: User actions logged with JWT claims for accountability

## Implementation Status

✅ **Complete OAuth 2.0 Implementation**
- Provider abstraction with HMAC and OIDC support
- Token validation middleware with caching
- OAuth flow handlers (authorize, token, callback)
- RFC-compliant metadata endpoints
- MCP server integration with HTTP transport
- HTTPS support for production deployments

The OAuth implementation is production-ready and supports major OAuth providers through a secure, standards-compliant architecture.