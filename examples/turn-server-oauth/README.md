# TURN Server with OAuth Authentication (RFC 7635)

This example demonstrates how to configure a TURN server with OAuth-based third-party authorization as specified in [RFC 7635](https://tools.ietf.org/html/rfc7635).

## Overview

OAuth authentication provides an alternative to traditional long-term credentials, allowing TURN servers to delegate authentication to an external OAuth authorization server.

### Benefits

- **Centralized Authentication**: Use your existing OAuth infrastructure
- **Token-Based**: No need to share passwords with the TURN server
- **Fine-Grained Control**: OAuth server can implement complex authorization logic
- **Secure**: Tokens are encrypted with AES-256-GCM and bound to specific servers
- **Time-Limited**: Tokens have configurable lifetimes

## Running the Example

### Option 1: With Mock OAuth Server (Recommended for Testing)

```bash
# Terminal 1: Start mock OAuth server
cd ../mock-oauth-server
go run main.go

# Copy the encryption key from the output, then...

# Terminal 2: Start TURN server with the same key
cd ../turn-server-oauth
go run main.go -public-ip=127.0.0.1 -oauth-uri=http://localhost:8080/token -key=PASTE_KEY_HERE
```

### Option 2: Generate Key in TURN Server

```bash
go run main.go -public-ip=YOUR_PUBLIC_IP -oauth-uri=https://your-oauth-server.com/token
# Copy the generated key and configure your OAuth server to use it
```

### Parameters

**Required:**
- `-public-ip`: The public IP address where clients can reach the TURN server
- `-oauth-uri`: The OAuth authorization server URI where clients should request tokens

**Optional:**
- `-key`: Encryption key in hex (64 characters). If not provided, generates a random key
- `-port`: TURN server port (default: 3478)
- `-realm`: Authentication realm (default: pion.ly)

## Authentication Flow

1. **Client** → **TURN Server**: Allocate request (no credentials)
2. **TURN Server** → **Client**: 401 Unauthorized + THIRD-PARTY-AUTHORIZATION attribute
3. **Client** → **OAuth Server**: Token request (with client credentials)
4. **OAuth Server** → **Client**: Access token + MAC key
5. **Client** → **TURN Server**: Allocate request + ACCESS-TOKEN + MESSAGE-INTEGRITY
6. **TURN Server**: Decrypts token, validates, creates allocation

## OAuth Server Requirements

Your OAuth server must:

1. **Share the encryption key** with the TURN server (32 bytes for AES-256)
2. **Generate MAC keys** (at least 20 bytes / 160 bits)
3. **Create encrypted tokens** using the pion/turn TokenManager
4. **Return both** the access token and MAC key to clients

### Example OAuth Server Response

```json
{
  "access_token": "base64-encoded-encrypted-token",
  "token_type": "Bearer",
  "expires_in": 3600,
  "mac_key": "base64-encoded-mac-key"
}
```

## Security Considerations

### Encryption Key Management

- Generate a cryptographically secure 32-byte key
- Store in a secrets manager (e.g., HashiCorp Vault, AWS Secrets Manager)
- Share securely with the OAuth server
- Rotate periodically
- Never commit to version control

### Token Lifetime

- Keep tokens short-lived (recommended: 1 hour)
- Balance security vs. user experience
- Consider refresh token mechanisms

### Transport Security

- Use TLS/DTLS for TURN connections
- Use HTTPS for OAuth server communication
- Protect MAC keys in transit

### Server Name Binding

- Tokens are bound to the server name (Additional Authenticated Data)
- Prevents token reuse across different TURN servers
- Use a consistent server name (IP or hostname)

## Advanced Configuration

### Custom Token Validation

```go
TokenAuthHandler: func(macKey []byte, ra *turn.RequestAttributes) (username string, ok bool) {
    // Validate user permissions
    if !hasPermission(ra.Username) {
        return "", false
    }

    // Apply rate limiting
    if exceeded := checkRateLimit(ra.SrcAddr); exceeded {
        return "", false
    }

    // Audit logging
    log.Printf("OAuth auth: user=%s ip=%s", ra.Username, ra.SrcAddr)

    return ra.Username, true
}
```

### Dual Authentication Mode

You can enable both OAuth and traditional authentication simultaneously:

```go
turn.ServerConfig{
    // OAuth configuration
    OAuthConfig: &turn.OAuthConfig{
        EncryptionKey:  encryptionKey,
        ServerName:     serverIP,
        OAuthServerURI: oauthURI,
    },

    // Traditional authentication (fallback)
    AuthHandler: func(username, realm string, srcAddr net.Addr) ([]byte, bool) {
        // Check username/password database
        return generateKey(username, realm, password), true
    },
}
```

Clients can use either authentication method - the server will accept both.

## Testing

Test OAuth authentication with the integration tests:

```bash
cd ../..
go test -run TestOAuth -v
```

## Troubleshooting

### "Token validation failed"

- Check that encryption keys match between TURN and OAuth servers
- Verify server name matches
- Ensure token hasn't expired

### "Invalid MESSAGE-INTEGRITY"

- Verify MAC key from OAuth server matches the one in the token
- Check that MESSAGE-INTEGRITY is added after all other attributes

### Clients not receiving THIRD-PARTY-AUTHORIZATION

- Verify `OAuthConfig.OAuthServerURI` is set
- Check that `TokenManager` initialized successfully
- Ensure clients are sending requests without credentials first

## References

- [RFC 7635: Session Traversal Utilities for NAT (STUN) Extension for Third-Party Authorization](https://tools.ietf.org/html/rfc7635)
- [RFC 5389: Session Traversal Utilities for NAT (STUN)](https://tools.ietf.org/html/rfc5389)
- [RFC 5766: Traversal Using Relays around NAT (TURN)](https://tools.ietf.org/html/rfc5766)
