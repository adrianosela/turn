// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package proto

import (
	"testing"

	"github.com/pion/stun/v3"
	"github.com/stretchr/testify/assert"
)

func TestAccessToken(t *testing.T) {
	t.Run("AddTo", func(t *testing.T) {
		m := new(stun.Message)
		token := AccessToken{
			Nonce:          []byte("test-nonce"),
			EncryptedBlock: []byte("encrypted-data-here"),
		}
		assert.NoError(t, token.AddTo(m))
		m.WriteHeader()

		t.Run("GetFrom", func(t *testing.T) {
			decoded := new(stun.Message)
			_, err := decoded.Write(m.Raw)
			assert.NoError(t, err)

			gotToken := AccessToken{}
			assert.NoError(t, gotToken.GetFrom(decoded))
			assert.Equal(t, token.Nonce, gotToken.Nonce)
			assert.Equal(t, token.EncryptedBlock, gotToken.EncryptedBlock)
		})
	})

	t.Run("EmptyNonce", func(t *testing.T) {
		m := new(stun.Message)
		token := AccessToken{
			Nonce:          []byte{},
			EncryptedBlock: []byte("encrypted-data"),
		}
		assert.NoError(t, token.AddTo(m))
		m.WriteHeader()

		decoded := new(stun.Message)
		_, err := decoded.Write(m.Raw)
		assert.NoError(t, err)

		gotToken := AccessToken{}
		assert.NoError(t, gotToken.GetFrom(decoded))
		assert.Empty(t, gotToken.Nonce)
		assert.Equal(t, token.EncryptedBlock, gotToken.EncryptedBlock)
	})

	t.Run("EmptyEncryptedBlock", func(t *testing.T) {
		m := new(stun.Message)
		token := AccessToken{
			Nonce:          []byte("nonce"),
			EncryptedBlock: []byte{},
		}
		assert.NoError(t, token.AddTo(m))
		m.WriteHeader()

		decoded := new(stun.Message)
		_, err := decoded.Write(m.Raw)
		assert.NoError(t, err)

		gotToken := AccessToken{}
		assert.NoError(t, gotToken.GetFrom(decoded))
		assert.Equal(t, token.Nonce, gotToken.Nonce)
		assert.Empty(t, gotToken.EncryptedBlock)
	})

	t.Run("NonceTooLarge", func(t *testing.T) {
		m := new(stun.Message)
		// Create a nonce larger than uint16 max
		largeNonce := make([]byte, 0x10000)
		token := AccessToken{
			Nonce:          largeNonce,
			EncryptedBlock: []byte("data"),
		}
		err := token.AddTo(m)
		assert.ErrorIs(t, err, ErrInvalidAccessToken)
	})

	t.Run("GetFromErrors", func(t *testing.T) {
		t.Run("AttributeNotFound", func(t *testing.T) {
			m := new(stun.Message)
			token := AccessToken{}
			assert.ErrorIs(t, token.GetFrom(m), stun.ErrAttributeNotFound)
		})

		t.Run("TooShort", func(t *testing.T) {
			m := new(stun.Message)
			// Only 1 byte when we need at least 2 for nonce_length
			m.Add(AttrAccessToken, []byte{0x01})
			token := AccessToken{}
			assert.ErrorIs(t, token.GetFrom(m), ErrInvalidAccessToken)
		})

		t.Run("InvalidNonceLength", func(t *testing.T) {
			m := new(stun.Message)
			// Says nonce is 100 bytes but only provides 2 bytes total
			m.Add(AttrAccessToken, []byte{0x00, 0x64})
			token := AccessToken{}
			assert.ErrorIs(t, token.GetFrom(m), ErrInvalidAccessToken)
		})
	})

	t.Run("RoundTrip", func(t *testing.T) {
		testCases := []struct {
			name  string
			token AccessToken
		}{
			{
				name: "typical token",
				token: AccessToken{
					Nonce:          []byte("random-nonce-12345"),
					EncryptedBlock: []byte("AES-GCM-encrypted-payload-with-auth-tag"),
				},
			},
			{
				name: "short nonce",
				token: AccessToken{
					Nonce:          []byte("x"),
					EncryptedBlock: []byte("encrypted"),
				},
			},
			{
				name: "large token",
				token: AccessToken{
					Nonce:          make([]byte, 1000),
					EncryptedBlock: make([]byte, 5000),
				},
			},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				m := new(stun.Message)
				assert.NoError(t, tc.token.AddTo(m))
				m.WriteHeader()

				decoded := new(stun.Message)
				_, err := decoded.Write(m.Raw)
				assert.NoError(t, err)

				gotToken := AccessToken{}
				assert.NoError(t, gotToken.GetFrom(decoded))
				assert.Equal(t, tc.token.Nonce, gotToken.Nonce)
				assert.Equal(t, tc.token.EncryptedBlock, gotToken.EncryptedBlock)
			})
		}
	})
}

func BenchmarkAccessToken(b *testing.B) {
	b.Run("AddTo", func(b *testing.B) {
		b.ReportAllocs()
		m := new(stun.Message)
		token := AccessToken{
			Nonce:          []byte("test-nonce-value"),
			EncryptedBlock: make([]byte, 256),
		}
		for i := 0; i < b.N; i++ {
			assert.NoError(b, token.AddTo(m))
			m.Reset()
		}
	})

	b.Run("GetFrom", func(b *testing.B) {
		m := new(stun.Message)
		token := AccessToken{
			Nonce:          []byte("test-nonce-value"),
			EncryptedBlock: make([]byte, 256),
		}
		assert.NoError(b, token.AddTo(m))

		for i := 0; i < b.N; i++ {
			got := AccessToken{}
			assert.NoError(b, got.GetFrom(m))
		}
	})
}
