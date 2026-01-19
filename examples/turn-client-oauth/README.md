# TURN Client with OAuth Authentication

Example TURN client that demonstrates RFC 7635 OAuth-based authentication.

## Prerequisites

You need both servers running:
1. Mock OAuth Server (port 8080)
2. TURN Server with OAuth (port 3478)

See `../OAUTH_TESTING_GUIDE.md` for setup instructions.

## Running the Example

### Step 1: Start the Servers

```bash
# Terminal 1: OAuth Server
cd ../mock-oauth-server
go run main.go

# Copy the encryption key, then...

# Terminal 2: TURN Server
cd ../turn-server-oauth
go run main.go -public-ip=127.0.0.1 -oauth-uri=http://localhost:8080/token -key=PASTE_KEY_HERE
```

### Step 2: Run the OAuth Client

```bash
# Terminal 3: TURN Client
cd ../turn-client-oauth
go run main.go -host=127.0.0.1:3478 -user=alice -pass=secret
```

## Expected Output

```
Connecting to TURN server: 127.0.0.1:3478
Username: alice

=== Step 1: Send Allocate request (no credentials) ===
Waiting for 401 response...
✓ Server requires OAuth authentication
  OAuth Server URI: http://localhost:8080/token
  Realm: pion.ly

=== Step 2: Request token from OAuth server ===
Requesting token from: http://localhost:8080/token
✓ Received access token
  Token type: Bearer
  Expires in: 3600 seconds
  Username: alice
  Access token: ARkT8fGxL3Q5Hm...

=== Step 3: Send Allocate request with OAuth token ===
Sending authenticated allocate request...

=== Step 4: Process response ===
✓✓✓ SUCCESS! Allocation created with OAuth authentication ✓✓✓
  Relayed Address: 127.0.0.1:xxxxx
  Lifetime: 10m0s

🎉 OAuth authentication flow completed successfully!
```

## How It Works

The client performs the RFC 7635 OAuth flow:

### 1. Initial Request (No Credentials)
```go
// Send Allocate without ACCESS-TOKEN
allocMsg := stun.MustBuild(
    stun.TransactionID,
    proto.AllocateRequest(),
    stun.Fingerprint,
)
```

### 2. Extract OAuth Server URI
```go
// Server responds with 401 + THIRD-PARTY-AUTHORIZATION
oauthInfo, err := turn.ExtractOAuthInfo(response)
// oauthInfo.OAuthServerURI = "http://localhost:8080/token"
```

### 3. Request Token from OAuth Server
```go
tokenResp, err := requestOAuthToken(
    oauthInfo.OAuthServerURI,
    username,
    password,
)
// Returns: access_token, mac_key, expires_in, username
```

### 4. Retry with ACCESS-TOKEN
```go
// Add ACCESS-TOKEN attribute
accessToken := &proto.AccessToken{
    EncryptedBlock: accessTokenBytes,
}
accessToken.AddTo(msg)

// Add MESSAGE-INTEGRITY with MAC key from token
integrity := stun.NewShortTermIntegrity(string(macKey))
integrity.AddTo(msg)
```

### 5. Success!
Server validates token and creates allocation.

## Command Line Options

```bash
go run main.go [options]
```

**Options:**
- `-host` - TURN server address (default: 127.0.0.1:3478)
- `-user` - Username for OAuth authentication (default: alice)
- `-pass` - Password for OAuth authentication (default: secret)

## Notes

- The mock OAuth server accepts **any username/password** for testing
- The access token is valid for 1 hour (3600 seconds)
- The MAC key is used for MESSAGE-INTEGRITY validation
- Tokens are encrypted with AES-256-GCM and bound to the TURN server

## Comparison to Traditional Auth

**Traditional (Long-Term Credentials):**
```
Client → TURN: Allocate
TURN → Client: 401 + NONCE + REALM
Client → TURN: Allocate + USERNAME + REALM + NONCE + MESSAGE-INTEGRITY
TURN → Client: Success
```

**OAuth (RFC 7635):**
```
Client → TURN: Allocate
TURN → Client: 401 + THIRD-PARTY-AUTHORIZATION + REALM
Client → OAuth: Token Request
OAuth → Client: ACCESS-TOKEN + MAC-KEY
Client → TURN: Allocate + USERNAME + ACCESS-TOKEN + MESSAGE-INTEGRITY
TURN → Client: Success
```

## Error Handling

The client handles common errors:
- OAuth server unavailable
- Invalid credentials
- Token decryption failure
- Expired tokens
- Network timeouts

## Security Considerations

This example:
- ✅ Uses HTTPS for OAuth requests (in production)
- ✅ Validates MESSAGE-INTEGRITY
- ✅ Uses encrypted tokens
- ⚠️ Stores MAC key in memory (clear after use in production)
- ⚠️ No token refresh (implement for long-running clients)

## Next Steps

- Implement token refresh before expiry
- Add support for multiple TURN servers
- Handle OAuth errors (invalid grant, etc.)
- Add connection pooling
- Implement automatic retry logic
