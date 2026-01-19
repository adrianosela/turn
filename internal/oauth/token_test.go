// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package oauth

import (
	"crypto/rand"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewTokenManager(t *testing.T) {
	t.Run("ValidKey", func(t *testing.T) {
		key := make([]byte, 32)
		_, err := rand.Read(key)
		require.NoError(t, err)

		tm, err := NewTokenManager(key, "turn.example.com")
		assert.NoError(t, err)
		assert.NotNil(t, tm)
	})

	t.Run("InvalidKeySize", func(t *testing.T) {
		testCases := []struct {
			name string
			size int
		}{
			{"too short", 16},
			{"too long", 64},
			{"empty", 0},
			{"slightly short", 31},
			{"slightly long", 33},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				key := make([]byte, tc.size)
				tm, err := NewTokenManager(key, "turn.example.com")
				assert.ErrorIs(t, err, ErrInvalidKeySize)
				assert.Nil(t, tm)
			})
		}
	})
}

func TestTokenManager_CreateToken(t *testing.T) {
	key := make([]byte, 32)
	_, err := rand.Read(key)
	require.NoError(t, err)

	tm, err := NewTokenManager(key, "turn.example.com")
	require.NoError(t, err)

	t.Run("ValidToken", func(t *testing.T) {
		macKey := make([]byte, 20)
		_, err := rand.Read(macKey)
		require.NoError(t, err)

		tokenBytes, err := tm.CreateToken(macKey, time.Hour)
		assert.NoError(t, err)
		assert.NotNil(t, tokenBytes)
		// Token should contain: nonce (12) + encrypted data + auth tag (16)
		assert.Greater(t, len(tokenBytes), 28)
	})

	t.Run("LargeMACKey", func(t *testing.T) {
		macKey := make([]byte, 64) // Larger than minimum
		_, err := rand.Read(macKey)
		require.NoError(t, err)

		tokenBytes, err := tm.CreateToken(macKey, time.Hour)
		assert.NoError(t, err)
		assert.NotNil(t, tokenBytes)
	})

	t.Run("MACKeyTooSmall", func(t *testing.T) {
		macKey := make([]byte, 19) // Less than 20 bytes
		tokenBytes, err := tm.CreateToken(macKey, time.Hour)
		assert.ErrorIs(t, err, ErrInvalidMACKeySize)
		assert.Nil(t, tokenBytes)
	})

	t.Run("DifferentLifetimes", func(t *testing.T) {
		macKey := make([]byte, 20)
		_, err := rand.Read(macKey)
		require.NoError(t, err)

		lifetimes := []time.Duration{
			time.Second,
			time.Minute,
			time.Hour,
			24 * time.Hour,
		}

		for _, lifetime := range lifetimes {
			tokenBytes, err := tm.CreateToken(macKey, lifetime)
			assert.NoError(t, err)
			assert.NotNil(t, tokenBytes)
		}
	})
}

func TestTokenManager_RoundTrip(t *testing.T) {
	key := make([]byte, 32)
	_, err := rand.Read(key)
	require.NoError(t, err)

	tm, err := NewTokenManager(key, "turn.example.com")
	require.NoError(t, err)

	t.Run("BasicRoundTrip", func(t *testing.T) {
		macKey := make([]byte, 20)
		_, err := rand.Read(macKey)
		require.NoError(t, err)

		lifetime := time.Hour

		// Create token
		tokenBytes, err := tm.CreateToken(macKey, lifetime)
		require.NoError(t, err)

		// Decrypt token
		token, err := tm.DecryptToken(tokenBytes)
		assert.NoError(t, err)
		assert.Equal(t, macKey, token.MACKey)
		assert.Equal(t, lifetime, token.Lifetime)
		assert.WithinDuration(t, time.Now(), token.Timestamp, 2*time.Second)
	})

	t.Run("MultipleMACKeySizes", func(t *testing.T) {
		sizes := []int{20, 32, 64, 128}

		for _, size := range sizes {
			macKey := make([]byte, size)
			_, err := rand.Read(macKey)
			require.NoError(t, err)

			tokenBytes, err := tm.CreateToken(macKey, time.Hour)
			require.NoError(t, err)

			token, err := tm.DecryptToken(tokenBytes)
			assert.NoError(t, err)
			assert.Equal(t, macKey, token.MACKey)
		}
	})
}

func TestTokenManager_DecryptToken(t *testing.T) {
	key := make([]byte, 32)
	_, err := rand.Read(key)
	require.NoError(t, err)

	tm, err := NewTokenManager(key, "turn.example.com")
	require.NoError(t, err)

	t.Run("InvalidToken_TooShort", func(t *testing.T) {
		token, err := tm.DecryptToken([]byte("short"))
		assert.ErrorIs(t, err, ErrInvalidToken)
		assert.Nil(t, token)
	})

	t.Run("InvalidToken_Random", func(t *testing.T) {
		randomBytes := make([]byte, 100)
		_, err := rand.Read(randomBytes)
		require.NoError(t, err)

		token, err := tm.DecryptToken(randomBytes)
		assert.ErrorIs(t, err, ErrInvalidToken)
		assert.Nil(t, token)
	})

	t.Run("InvalidToken_WrongKey", func(t *testing.T) {
		// Create token with one manager
		macKey := make([]byte, 20)
		_, err := rand.Read(macKey)
		require.NoError(t, err)

		tokenBytes, err := tm.CreateToken(macKey, time.Hour)
		require.NoError(t, err)

		// Try to decrypt with different manager (different key)
		differentKey := make([]byte, 32)
		_, err = rand.Read(differentKey)
		require.NoError(t, err)

		tm2, err := NewTokenManager(differentKey, "turn.example.com")
		require.NoError(t, err)

		token, err := tm2.DecryptToken(tokenBytes)
		assert.ErrorIs(t, err, ErrInvalidToken)
		assert.Nil(t, token)
	})

	t.Run("InvalidToken_WrongServerName", func(t *testing.T) {
		// Create token for one server
		macKey := make([]byte, 20)
		_, err := rand.Read(macKey)
		require.NoError(t, err)

		tokenBytes, err := tm.CreateToken(macKey, time.Hour)
		require.NoError(t, err)

		// Try to decrypt with same key but different server name
		tm2, err := NewTokenManager(key, "different-server.example.com")
		require.NoError(t, err)

		token, err := tm2.DecryptToken(tokenBytes)
		assert.ErrorIs(t, err, ErrInvalidToken)
		assert.Nil(t, token)
	})

	t.Run("InvalidToken_Corrupted", func(t *testing.T) {
		macKey := make([]byte, 20)
		_, err := rand.Read(macKey)
		require.NoError(t, err)

		tokenBytes, err := tm.CreateToken(macKey, time.Hour)
		require.NoError(t, err)

		// Corrupt the token
		tokenBytes[len(tokenBytes)/2] ^= 0xFF

		token, err := tm.DecryptToken(tokenBytes)
		assert.ErrorIs(t, err, ErrInvalidToken)
		assert.Nil(t, token)
	})
}

func TestToken_IsValid(t *testing.T) {
	tolerance := 5 * time.Second

	t.Run("ValidToken_Current", func(t *testing.T) {
		token := &Token{
			MACKey:    make([]byte, 20),
			Timestamp: time.Now(),
			Lifetime:  time.Hour,
		}
		assert.True(t, token.IsValid(tolerance))
	})

	t.Run("ValidToken_WithinTolerance", func(t *testing.T) {
		token := &Token{
			MACKey:    make([]byte, 20),
			Timestamp: time.Now().Add(-3 * time.Second),
			Lifetime:  time.Hour,
		}
		assert.True(t, token.IsValid(tolerance))
	})

	t.Run("InvalidToken_Expired", func(t *testing.T) {
		token := &Token{
			MACKey:    make([]byte, 20),
			Timestamp: time.Now().Add(-2 * time.Hour),
			Lifetime:  time.Hour,
		}
		assert.False(t, token.IsValid(tolerance))
	})

	t.Run("InvalidToken_NotYetValid", func(t *testing.T) {
		token := &Token{
			MACKey:    make([]byte, 20),
			Timestamp: time.Now().Add(10 * time.Second),
			Lifetime:  time.Hour,
		}
		assert.False(t, token.IsValid(tolerance))
	})

	t.Run("ValidToken_JustAboutToExpire", func(t *testing.T) {
		token := &Token{
			MACKey:    make([]byte, 20),
			Timestamp: time.Now().Add(-time.Hour + 10*time.Second),
			Lifetime:  time.Hour,
		}
		assert.True(t, token.IsValid(tolerance))
	})

	t.Run("InvalidToken_JustExpired", func(t *testing.T) {
		token := &Token{
			MACKey:    make([]byte, 20),
			Timestamp: time.Now().Add(-time.Hour - 10*time.Second),
			Lifetime:  time.Hour,
		}
		assert.False(t, token.IsValid(tolerance))
	})

	t.Run("ValidToken_EdgeOfTolerance", func(t *testing.T) {
		// Token created 4 seconds in future (within 5 second tolerance)
		token := &Token{
			MACKey:    make([]byte, 20),
			Timestamp: time.Now().Add(4 * time.Second),
			Lifetime:  time.Hour,
		}
		assert.True(t, token.IsValid(tolerance))
	})
}

func TestTokenManager_Integration(t *testing.T) {
	key := make([]byte, 32)
	_, err := rand.Read(key)
	require.NoError(t, err)

	tm, err := NewTokenManager(key, "turn.example.com")
	require.NoError(t, err)

	t.Run("CreateMultipleTokens", func(t *testing.T) {
		// Create multiple tokens and verify they're all different
		tokens := make([][]byte, 10)
		for i := 0; i < 10; i++ {
			macKey := make([]byte, 20)
			_, err := rand.Read(macKey)
			require.NoError(t, err)

			tokens[i], err = tm.CreateToken(macKey, time.Hour)
			require.NoError(t, err)
		}

		// Verify all tokens are unique (due to random nonce)
		for i := 0; i < len(tokens); i++ {
			for j := i + 1; j < len(tokens); j++ {
				assert.NotEqual(t, tokens[i], tokens[j])
			}
		}
	})

	t.Run("TokenValidityLifecycle", func(t *testing.T) {
		macKey := make([]byte, 20)
		_, err := rand.Read(macKey)
		require.NoError(t, err)

		// Create token with 1 second lifetime
		lifetime := time.Second
		tolerance := 100 * time.Millisecond // Use small tolerance for testing
		tokenBytes, err := tm.CreateToken(macKey, lifetime)
		require.NoError(t, err)

		// Should be valid immediately
		token, err := tm.DecryptToken(tokenBytes)
		require.NoError(t, err)
		assert.True(t, token.IsValid(tolerance))

		// Wait for expiration (lifetime + tolerance + buffer)
		time.Sleep(1200 * time.Millisecond)

		// Should now be invalid
		assert.False(t, token.IsValid(tolerance))

		// But should still decrypt successfully
		token2, err := tm.DecryptToken(tokenBytes)
		require.NoError(t, err)
		assert.Equal(t, token.MACKey, token2.MACKey)
	})
}

func BenchmarkTokenManager(b *testing.B) {
	key := make([]byte, 32)
	_, err := rand.Read(key)
	require.NoError(b, err)

	tm, err := NewTokenManager(key, "turn.example.com")
	require.NoError(b, err)

	macKey := make([]byte, 20)
	_, err = rand.Read(macKey)
	require.NoError(b, err)

	b.Run("CreateToken", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			_, err := tm.CreateToken(macKey, time.Hour)
			require.NoError(b, err)
		}
	})

	tokenBytes, err := tm.CreateToken(macKey, time.Hour)
	require.NoError(b, err)

	b.Run("DecryptToken", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			_, err := tm.DecryptToken(tokenBytes)
			require.NoError(b, err)
		}
	})

	token, err := tm.DecryptToken(tokenBytes)
	require.NoError(b, err)

	b.Run("IsValid", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			_ = token.IsValid(5 * time.Second)
		}
	})
}
