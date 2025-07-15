# OAuth Configuration Guide

This guide explains how to configure OAuth 2.1 authentication for the Trino MCP server.

## Environment Variables

### Required OAuth Configuration

When `TRINO_OAUTH_ENABLED=true`, the following environment variables are required:

```bash
# OAuth Provider Configuration
OAUTH_PROVIDER_URL=https://your-oauth-provider.com   # Required: OAuth provider base URL
OAUTH_CLIENT_ID=your-client-id                       # Required: OAuth client ID
OAUTH_CLIENT_SECRET=your-client-secret               # Required: OAuth client secret
OAUTH_REDIRECT_URI=https://your-mcp-server.com/callback  # Required: OAuth callback URL
OAUTH_SCOPES=openid,profile,email                    # Optional: OAuth scopes (default: openid,profile,email)
```

### Trino Configuration

```bash
# Enable OAuth authentication
TRINO_OAUTH_ENABLED=true

# Trino connection (uses existing authentication to Trino)
TRINO_HOST=trino.example.com
TRINO_PORT=443
TRINO_USER=service-account    # Service account for MCP server
TRINO_PASSWORD=service-password
TRINO_SCHEME=https
TRINO_SSL=true
```

### MCP Server Configuration

```bash
# HTTP transport required for OAuth
MCP_TRANSPORT=http
MCP_PORT=8080
MCP_HOST=localhost
```

## OAuth Provider Setup

### Google OAuth Provider

1. **Create OAuth Application**:
   - Go to [Google Cloud Console](https://console.cloud.google.com/)
   - Create a new project or select existing
   - Enable Google+ API
   - Create OAuth 2.0 credentials

2. **Configure OAuth Client**:
   ```bash
   OAUTH_PROVIDER_URL=https://accounts.google.com
   OAUTH_CLIENT_ID=your-google-client-id.apps.googleusercontent.com
   OAUTH_CLIENT_SECRET=your-google-client-secret
   OAUTH_REDIRECT_URI=https://your-mcp-server.com/callback
   OAUTH_SCOPES=openid,profile,email
   ```

3. **Google OAuth Endpoints**:
   - Authorization: `https://accounts.google.com/o/oauth2/v2/auth`
   - Token: `https://oauth2.googleapis.com/token`
   - UserInfo: `https://www.googleapis.com/oauth2/v2/userinfo`
   - JWKS: `https://www.googleapis.com/oauth2/v3/certs`

### Azure AD OAuth Provider

1. **Register Application**:
   - Go to [Azure Portal](https://portal.azure.com/)
   - Navigate to Azure Active Directory > App registrations
   - Create new registration

2. **Configure OAuth Client**:
   ```bash
   OAUTH_PROVIDER_URL=https://login.microsoftonline.com/your-tenant-id
   OAUTH_CLIENT_ID=your-azure-client-id
   OAUTH_CLIENT_SECRET=your-azure-client-secret
   OAUTH_REDIRECT_URI=https://your-mcp-server.com/callback
   OAUTH_SCOPES=openid,profile,email
   ```

### Okta OAuth Provider

1. **Create Application**:
   - Go to Okta Admin Console
   - Navigate to Applications > Create App Integration
   - Select OIDC and Web Application

2. **Configure OAuth Client**:
   ```bash
   OAUTH_PROVIDER_URL=https://your-domain.okta.com
   OAUTH_CLIENT_ID=your-okta-client-id
   OAUTH_CLIENT_SECRET=your-okta-client-secret
   OAUTH_REDIRECT_URI=https://your-mcp-server.com/callback
   OAUTH_SCOPES=openid,profile,email
   ```

## Deployment Configuration

### Local Development

```bash
# .env file for local development
TRINO_OAUTH_ENABLED=true
OAUTH_PROVIDER_URL=https://accounts.google.com
OAUTH_CLIENT_ID=your-client-id
OAUTH_CLIENT_SECRET=your-client-secret
OAUTH_REDIRECT_URI=http://localhost:8080/callback
OAUTH_SCOPES=openid,profile,email

TRINO_HOST=localhost
TRINO_PORT=8080
TRINO_USER=trino
TRINO_PASSWORD=
TRINO_SCHEME=http
TRINO_SSL=false

MCP_TRANSPORT=http
MCP_PORT=8080
MCP_HOST=localhost
```

### Production Deployment

```bash
# Production environment variables
TRINO_OAUTH_ENABLED=true
OAUTH_PROVIDER_URL=https://your-oauth-provider.com
OAUTH_CLIENT_ID=your-production-client-id
OAUTH_CLIENT_SECRET=your-production-client-secret
OAUTH_REDIRECT_URI=https://your-mcp-server.com/callback
OAUTH_SCOPES=openid,profile,email

TRINO_HOST=trino.production.com
TRINO_PORT=443
TRINO_USER=mcp-service-account
TRINO_PASSWORD=secure-password
TRINO_SCHEME=https
TRINO_SSL=true

MCP_TRANSPORT=http
MCP_PORT=8080
MCP_HOST=0.0.0.0
```

## Authentication Flow

1. **Client Registration**: Claude Code or mcp-remote registers with OAuth provider
2. **Authorization**: User authenticates with OAuth provider via browser
3. **Token Exchange**: Authorization code exchanged for access token
4. **API Requests**: Access token sent as `Authorization: Bearer <token>`
5. **Token Validation**: MCP server validates JWT token using JWKS
6. **Trino Access**: MCP server uses service account to access Trino

## Security Considerations

### Token Validation

- **JWT Signature**: Tokens validated using OAuth provider's public keys
- **Token Expiration**: Expired tokens automatically rejected
- **Audience Validation**: Tokens validated for correct audience
- **Issuer Validation**: Tokens validated for correct issuer

### Network Security

- **HTTPS Required**: All OAuth endpoints must use HTTPS
- **Secure Headers**: Security headers automatically added
- **CORS Protection**: CORS headers configured for OAuth endpoints

### Access Control

- **Authentication**: All MCP tools require valid Bearer token when OAuth enabled
- **Authorization**: User context available for fine-grained access control
- **Logging**: All authentication events logged for audit

## Testing Configuration

### Test OAuth Flow

```bash
# Test with Claude Code
claude mcp add https://your-mcp-server.com:8080

# Test with mcp-remote
npx mcp-remote https://your-mcp-server.com:8080/sse
```

### Verify Token Validation

```bash
# Test direct API access
curl -H "Authorization: Bearer <token>" \
     -H "Content-Type: application/json" \
     -d '{"query": "SHOW CATALOGS"}' \
     https://your-mcp-server.com:8080/api/query
```

## Troubleshooting

### Common Issues

1. **Token Validation Failed**:
   - Check JWKS URL accessibility
   - Verify token issuer matches configuration
   - Ensure token hasn't expired

2. **OAuth Provider Configuration**:
   - Verify redirect URI matches exactly
   - Check client ID and secret
   - Ensure scopes are supported

3. **HTTPS Requirements**:
   - OAuth 2.1 requires HTTPS for production
   - Use valid SSL certificates
   - Check firewall and proxy settings

### Debug Logging

Enable debug logging to troubleshoot OAuth issues:

```bash
# Enable debug logging
export DEBUG=oauth,auth,jwt
./mcp-trino
```

### Health Check

Test server health and OAuth configuration:

```bash
# Check server status
curl https://your-mcp-server.com:8080/

# Check OAuth discovery
curl https://your-oauth-provider.com/.well-known/openid-configuration
```

## Migration from Basic Auth

To migrate from basic authentication to OAuth:

1. **Set up OAuth provider** (Google, Azure AD, Okta)
2. **Configure environment variables** as shown above
3. **Set `TRINO_OAUTH_ENABLED=true`**
4. **Update Claude Code configuration** to use remote server
5. **Test authentication flow**
6. **Update documentation** for users

Basic authentication remains available when `TRINO_OAUTH_ENABLED=false` (default).