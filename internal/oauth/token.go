// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package oauth

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
	"time"
)

// Token represents a decrypted OAuth access token containing the MAC key
// and validity information.
type Token struct {
	// MACKey is the key used for MESSAGE-INTEGRITY validation.
	// Must be at least 160 bits (20 bytes) per RFC 7635.
	MACKey []byte

	// Timestamp is when the token was created (Unix epoch).
	Timestamp time.Time

	// Lifetime is how long the token is valid from the timestamp.
	Lifetime time.Duration
}

// TokenManager handles encryption and decryption of OAuth access tokens
// using AES-256-GCM as specified in RFC 7635.
type TokenManager struct {
	encryptionKey []byte // 32 bytes for AES-256
	serverName    []byte // Used as Additional Authenticated Data (AAD)
}

const (
	// AES-256 requires a 32-byte key
	aes256KeySize = 32
	// GCM standard nonce size is 12 bytes
	gcmNonceSize = 12
	// Minimum MAC key size per RFC 7635 (160 bits = 20 bytes)
	minMACKeySize = 20
	// Size of key_length field (2 bytes)
	keyLengthSize = 2
	// Size of timestamp field (8 bytes, Unix epoch)
	timestampSize = 8
	// Size of lifetime field (4 bytes, seconds)
	lifetimeSize = 4
)

var (
	// ErrInvalidKeySize indicates the encryption key is not 32 bytes
	ErrInvalidKeySize = errors.New("encryption key must be 32 bytes for AES-256")

	// ErrInvalidMACKeySize indicates the MAC key is too short
	ErrInvalidMACKeySize = errors.New("MAC key must be at least 160 bits (20 bytes)")

	// ErrInvalidToken indicates the token is malformed or corrupted
	ErrInvalidToken = errors.New("invalid token format")

	// ErrTokenExpired indicates the token has expired
	ErrTokenExpired = errors.New("token has expired")
)

// NewTokenManager creates a new TokenManager with the specified encryption key
// and server name. The encryption key must be exactly 32 bytes for AES-256.
// The server name is used as Additional Authenticated Data (AAD) to bind
// tokens to this specific server.
func NewTokenManager(encryptionKey []byte, serverName string) (*TokenManager, error) {
	if len(encryptionKey) != aes256KeySize {
		return nil, ErrInvalidKeySize
	}

	return &TokenManager{
		encryptionKey: encryptionKey,
		serverName:    []byte(serverName),
	}, nil
}

// CreateToken encrypts a new access token with the given MAC key and lifetime.
// The token includes the current timestamp and is encrypted using AES-256-GCM.
//
// The encrypted token format is:
//   - nonce (12 bytes): Random nonce for GCM
//   - ciphertext + auth tag: Encrypted payload containing:
//   - key_length (2 bytes): Length of MAC key
//   - mac_key (variable, >= 20 bytes): The MAC key for MESSAGE-INTEGRITY
//   - timestamp (8 bytes): Unix epoch timestamp
//   - lifetime (4 bytes): Validity duration in seconds
//
// Returns the complete encrypted token (nonce + ciphertext + auth tag).
func (tm *TokenManager) CreateToken(macKey []byte, lifetime time.Duration) ([]byte, error) {
	if len(macKey) < minMACKeySize {
		return nil, ErrInvalidMACKeySize
	}

	// Create the plaintext payload
	plaintext := tm.encodePlaintext(macKey, time.Now(), lifetime)

	// Initialize AES cipher
	block, err := aes.NewCipher(tm.encryptionKey)
	if err != nil {
		return nil, err
	}

	// Create GCM cipher mode
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	// Generate random nonce
	nonce := make([]byte, gcmNonceSize)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	// Encrypt with server name as AAD (binds token to this server)
	ciphertext := gcm.Seal(nil, nonce, plaintext, tm.serverName)

	// Return nonce + ciphertext (which includes auth tag)
	result := make([]byte, len(nonce)+len(ciphertext))
	copy(result, nonce)
	copy(result[len(nonce):], ciphertext)

	return result, nil
}

// DecryptToken decrypts and validates an access token.
// Returns the decrypted token or an error if decryption fails or the token
// is malformed. Note: This does not check expiration - use IsValid() for that.
func (tm *TokenManager) DecryptToken(tokenBytes []byte) (*Token, error) {
	// Token must contain at least: nonce + minimal ciphertext + auth tag
	minSize := gcmNonceSize + keyLengthSize + minMACKeySize + timestampSize + lifetimeSize + 16 // 16 = GCM auth tag
	if len(tokenBytes) < minSize {
		return nil, ErrInvalidToken
	}

	// Extract nonce
	nonce := tokenBytes[:gcmNonceSize]
	ciphertext := tokenBytes[gcmNonceSize:]

	// Initialize AES cipher
	block, err := aes.NewCipher(tm.encryptionKey)
	if err != nil {
		return nil, err
	}

	// Create GCM cipher mode
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	// Decrypt with server name as AAD (verifies token is for this server)
	plaintext, err := gcm.Open(nil, nonce, ciphertext, tm.serverName)
	if err != nil {
		return nil, ErrInvalidToken
	}

	// Decode the plaintext
	return tm.decodePlaintext(plaintext)
}

// IsValid checks if the token is still valid based on its timestamp and lifetime.
// clockSkewTolerance allows for some time difference between servers (recommended: 5 seconds).
func (t *Token) IsValid(clockSkewTolerance time.Duration) bool {
	now := time.Now()
	expiresAt := t.Timestamp.Add(t.Lifetime)

	// Token is valid if current time is within [timestamp - tolerance, expiresAt + tolerance]
	return now.After(t.Timestamp.Add(-clockSkewTolerance)) && now.Before(expiresAt.Add(clockSkewTolerance))
}

// encodePlaintext creates the plaintext payload for encryption.
func (tm *TokenManager) encodePlaintext(macKey []byte, timestamp time.Time, lifetime time.Duration) []byte {
	// Calculate total size
	size := keyLengthSize + len(macKey) + timestampSize + lifetimeSize
	buf := make([]byte, size)

	offset := 0

	// Write key_length (2 bytes)
	binary.BigEndian.PutUint16(buf[offset:], uint16(len(macKey)))
	offset += keyLengthSize

	// Write mac_key
	copy(buf[offset:], macKey)
	offset += len(macKey)

	// Write timestamp (8 bytes, Unix epoch)
	binary.BigEndian.PutUint64(buf[offset:], uint64(timestamp.Unix()))
	offset += timestampSize

	// Write lifetime (4 bytes, seconds)
	binary.BigEndian.PutUint32(buf[offset:], uint32(lifetime.Seconds()))

	return buf
}

// decodePlaintext decodes the decrypted plaintext into a Token.
func (tm *TokenManager) decodePlaintext(plaintext []byte) (*Token, error) {
	// Minimum size: key_length + min_mac_key + timestamp + lifetime
	minSize := keyLengthSize + minMACKeySize + timestampSize + lifetimeSize
	if len(plaintext) < minSize {
		return nil, ErrInvalidToken
	}

	offset := 0

	// Read key_length
	keyLength := binary.BigEndian.Uint16(plaintext[offset:])
	offset += keyLengthSize

	// Validate we have enough data for the MAC key
	if len(plaintext) < offset+int(keyLength)+timestampSize+lifetimeSize {
		return nil, ErrInvalidToken
	}

	if keyLength < minMACKeySize {
		return nil, ErrInvalidMACKeySize
	}

	// Read mac_key
	macKey := make([]byte, keyLength)
	copy(macKey, plaintext[offset:offset+int(keyLength)])
	offset += int(keyLength)

	// Read timestamp
	timestampUnix := binary.BigEndian.Uint64(plaintext[offset:])
	timestamp := time.Unix(int64(timestampUnix), 0)
	offset += timestampSize

	// Read lifetime
	lifetimeSeconds := binary.BigEndian.Uint32(plaintext[offset:])
	lifetime := time.Duration(lifetimeSeconds) * time.Second

	return &Token{
		MACKey:    macKey,
		Timestamp: timestamp,
		Lifetime:  lifetime,
	}, nil
}
