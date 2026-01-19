// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package turn

import (
	"crypto/rand"
	"testing"
	"time"

	"github.com/pion/stun/v3"
	"github.com/pion/turn/v5/internal/oauth"
	"github.com/pion/turn/v5/internal/proto"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestOAuthExtractInfo tests extracting OAuth server information from error responses
func TestOAuthExtractInfo(t *testing.T) {
	t.Run("WithThirdPartyAuth", func(t *testing.T) {
		msg := new(stun.Message)
		msg.TransactionID = [12]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12}
		msg.Type = stun.NewType(stun.MethodAllocate, stun.ClassErrorResponse)

		tpa := &proto.ThirdPartyAuthorization{
			ServerURI: "https://oauth.example.com/token",
		}
		require.NoError(t, tpa.AddTo(msg))

		realm := stun.NewRealm("example.com")
		require.NoError(t, realm.AddTo(msg))

		msg.WriteHeader()

		info, err := ExtractOAuthInfo(msg)
		assert.NoError(t, err)
		assert.NotNil(t, info)
		assert.Equal(t, "https://oauth.example.com/token", info.OAuthServerURI)
		assert.Equal(t, "example.com", info.Realm)
	})

	t.Run("WithoutThirdPartyAuth", func(t *testing.T) {
		msg := new(stun.Message)
		msg.TransactionID = [12]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12}
		msg.Type = stun.NewType(stun.MethodAllocate, stun.ClassErrorResponse)
		msg.WriteHeader()

		info, err := ExtractOAuthInfo(msg)
		assert.Error(t, err)
		assert.Nil(t, info)
	})
}

// TestOAuthAddAccessToken tests adding ACCESS-TOKEN to messages
func TestOAuthAddAccessToken(t *testing.T) {
	t.Run("AddToken", func(t *testing.T) {
		msg := new(stun.Message)
		msg.TransactionID = [12]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12}
		msg.Type = proto.AllocateRequest()

		// Simulate token bytes from OAuth server
		tokenBytes := make([]byte, 100)
		_, err := rand.Read(tokenBytes)
		require.NoError(t, err)

		err = AddAccessToken(msg, tokenBytes)
		assert.NoError(t, err)

		// Verify the token was added
		msg.WriteHeader()
		assert.True(t, msg.Contains(proto.AttrAccessToken))

		// Verify we can read it back
		accessToken := &proto.AccessToken{}
		err = accessToken.GetFrom(msg)
		assert.NoError(t, err)
		assert.Equal(t, tokenBytes, accessToken.EncryptedBlock)
	})
}

// TestOAuthEndToEndFlow tests the complete OAuth authentication flow
func TestOAuthEndToEndFlow(t *testing.T) {
	// Setup: Create a token manager (simulating the TURN server side)
	encryptionKey := make([]byte, 32)
	_, err := rand.Read(encryptionKey)
	require.NoError(t, err)

	serverName := "turn.example.com"
	tokenManager, err := oauth.NewTokenManager(encryptionKey, serverName)
	require.NoError(t, err)

	// Generate a MAC key (simulating the OAuth server)
	macKey := make([]byte, 20)
	_, err = rand.Read(macKey)
	require.NoError(t, err)

	// Create an access token (simulating the OAuth server)
	tokenBytes, err := tokenManager.CreateToken(macKey, time.Hour)
	require.NoError(t, err)

	t.Run("SuccessfulAuth", func(t *testing.T) {
		// Client creates a request with ACCESS-TOKEN
		msg := new(stun.Message)
		msg.TransactionID = [12]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12}
		msg.Type = proto.AllocateRequest()

		username := stun.NewUsername("alice")
		require.NoError(t, username.AddTo(msg))

		// Add access token
		err = AddAccessToken(msg, tokenBytes)
		require.NoError(t, err)

		// Add MESSAGE-INTEGRITY using the MAC key
		msg.WriteHeader()
		integrity := stun.NewShortTermIntegrity(string(macKey))
		require.NoError(t, integrity.AddTo(msg))

		msg.WriteHeader()

		// Verify the message can be authenticated (simulating server-side)
		accessToken := &proto.AccessToken{}
		err = accessToken.GetFrom(msg)
		require.NoError(t, err)

		// Decrypt and validate the token
		token, err := tokenManager.DecryptToken(accessToken.EncryptedBlock)
		require.NoError(t, err)
		assert.True(t, token.IsValid(5*time.Second))
		assert.Equal(t, macKey, token.MACKey)

		// Verify MESSAGE-INTEGRITY
		err = stun.MessageIntegrity(macKey).Check(msg)
		assert.NoError(t, err)
	})

	t.Run("ExpiredToken", func(t *testing.T) {
		// Create a token with very short lifetime
		shortLivedToken, err := tokenManager.CreateToken(macKey, 50*time.Millisecond)
		require.NoError(t, err)

		// Wait for it to expire (beyond the clock skew tolerance)
		time.Sleep(100 * time.Millisecond)

		// Try to use the expired token
		token, err := tokenManager.DecryptToken(shortLivedToken)
		require.NoError(t, err)

		// Token should be invalid (use small tolerance to ensure it fails)
		assert.False(t, token.IsValid(10*time.Millisecond))
	})

	t.Run("WrongServer", func(t *testing.T) {
		// Create a token manager for a different server
		differentManager, err := oauth.NewTokenManager(encryptionKey, "different.example.com")
		require.NoError(t, err)

		// Try to decrypt a token meant for a different server
		_, err = differentManager.DecryptToken(tokenBytes)
		assert.Error(t, err)
	})
}
