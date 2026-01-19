# Mock OAuth Authorization Server

A simple OAuth server for testing RFC 7635 third-party authorization with the Pion TURN server.

⚠️ **WARNING**: This is a DEMO server for testing only. Do NOT use in production!

## Quick Start

### 1. Start the Mock OAuth Server

```bash
cd examples/mock-oauth-server
go run main.go
```

The server will:
- Generate a random encryption key
- Print the key (copy it!)
- Listen on port 8080
- Accept any username/password (for testing)

### 2. Start the TURN Server with OAuth

In another terminal, use the encryption key from step 1:

```bash
cd examples/turn-server-oauth
go run main.go \
  -public-ip=127.0.0.1 \
  -oauth-uri=http://localhost:8080/token
```

**Important**: Modify the example to use the encryption key from the OAuth server:

```go
// In main.go, replace this line:
encryptionKey := make([]byte, 32)
if _, err := rand.Read(encryptionKey); err != nil {
    log.Fatalf("Failed to generate encryption key: %v", err)
}

// With this (paste the hex key from OAuth server):
encryptionKey, _ := hex.DecodeString("PASTE_KEY_HERE")
```

### 3. Test the Flow

Request a token from the OAuth server:

```bash
curl -X POST http://localhost:8080/token \
  -H "Content-Type: application/json" \
  -d '{
    "grant_type": "password",
    "username": "alice",
    "password": "secret123"
  }'
```

Response:
```json
{
  "access_token": "base64-encoded-encrypted-token",
  "token_type": "Bearer",
  "expires_in": 3600,
  "mac_key": "base64-encoded-mac-key",
  "username": "alice"
}
```

## Using with Custom Encryption Key

To use the same key on both servers:

```bash
# Generate a key (or use the one printed by the OAuth server)
KEY="abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"

# Start OAuth server with the key
go run main.go -key=$KEY -server=turn.example.com

# Start TURN server with the same key (modify the example code)
```

## API Reference

### POST /token

Request an access token.

**Request:**
```json
{
  "grant_type": "password",
  "username": "alice",
  "password": "secret"
}
```

**Response:**
```json
{
  "access_token": "BASE64_ENCODED_TOKEN",
  "token_type": "Bearer",
  "expires_in": 3600,
  "mac_key": "BASE64_ENCODED_MAC_KEY",
  "username": "alice"
}
```

**Fields:**
- `access_token`: RFC 7635 encrypted token to send to TURN server
- `token_type`: Always "Bearer"
- `expires_in`: Token lifetime in seconds
- `mac_key`: MAC key for MESSAGE-INTEGRITY (client needs this!)
- `username`: Username to use in TURN requests

### GET /health

Health check endpoint.

## Security Notes

This mock server:
- ✅ Generates cryptographically secure tokens
- ✅ Uses AES-256-GCM encryption
- ✅ Includes proper MAC keys
- ❌ Accepts ANY username/password (not secure!)
- ❌ Doesn't validate credentials
- ❌ Doesn't use HTTPS
- ❌ Doesn't implement proper OAuth flows

For production, you need:
- Real user authentication
- HTTPS/TLS
- Proper OAuth 2.0 flows (authorization code, client credentials, etc.)
- Token revocation
- Rate limiting
- Audit logging

## Testing the Complete Flow

See the parent directory README for a complete client example that:
1. Sends Allocate request to TURN server
2. Receives 401 + THIRD-PARTY-AUTHORIZATION
3. Requests token from this OAuth server
4. Retries Allocate with ACCESS-TOKEN
5. Successfully creates allocation
