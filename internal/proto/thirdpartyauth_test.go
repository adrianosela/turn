// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package proto

import (
	"testing"

	"github.com/pion/stun/v3"
	"github.com/stretchr/testify/assert"
)

func TestThirdPartyAuthorization(t *testing.T) {
	t.Run("AddTo", func(t *testing.T) {
		m := new(stun.Message)
		auth := ThirdPartyAuthorization{
			ServerURI: "https://oauth.example.com/token",
		}
		assert.NoError(t, auth.AddTo(m))
		m.WriteHeader()

		t.Run("GetFrom", func(t *testing.T) {
			decoded := new(stun.Message)
			_, err := decoded.Write(m.Raw)
			assert.NoError(t, err)

			gotAuth := ThirdPartyAuthorization{}
			assert.NoError(t, gotAuth.GetFrom(decoded))
			assert.Equal(t, auth.ServerURI, gotAuth.ServerURI)
		})
	})

	t.Run("EmptyURI", func(t *testing.T) {
		m := new(stun.Message)
		auth := ThirdPartyAuthorization{
			ServerURI: "",
		}
		assert.NoError(t, auth.AddTo(m))
		m.WriteHeader()

		decoded := new(stun.Message)
		_, err := decoded.Write(m.Raw)
		assert.NoError(t, err)

		gotAuth := ThirdPartyAuthorization{}
		assert.NoError(t, gotAuth.GetFrom(decoded))
		assert.Equal(t, "", gotAuth.ServerURI)
	})

	t.Run("GetFromErrors", func(t *testing.T) {
		t.Run("AttributeNotFound", func(t *testing.T) {
			m := new(stun.Message)
			auth := ThirdPartyAuthorization{}
			assert.ErrorIs(t, auth.GetFrom(m), stun.ErrAttributeNotFound)
		})
	})

	t.Run("RoundTrip", func(t *testing.T) {
		testCases := []struct {
			name      string
			serverURI string
		}{
			{
				name:      "https URL",
				serverURI: "https://oauth.example.com/token",
			},
			{
				name:      "http URL",
				serverURI: "http://localhost:8080/oauth/token",
			},
			{
				name:      "URL with query params",
				serverURI: "https://auth.server.com/token?client_id=turn-server",
			},
			{
				name:      "long URL",
				serverURI: "https://very-long-domain-name-for-oauth-server.example.com/v1/api/oauth2/token/endpoint",
			},
			{
				name:      "URL with port",
				serverURI: "https://oauth.example.com:8443/token",
			},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				m := new(stun.Message)
				auth := ThirdPartyAuthorization{ServerURI: tc.serverURI}
				assert.NoError(t, auth.AddTo(m))
				m.WriteHeader()

				decoded := new(stun.Message)
				_, err := decoded.Write(m.Raw)
				assert.NoError(t, err)

				gotAuth := ThirdPartyAuthorization{}
				assert.NoError(t, gotAuth.GetFrom(decoded))
				assert.Equal(t, tc.serverURI, gotAuth.ServerURI)
			})
		}
	})
}

func BenchmarkThirdPartyAuthorization(b *testing.B) {
	b.Run("AddTo", func(b *testing.B) {
		b.ReportAllocs()
		m := new(stun.Message)
		auth := ThirdPartyAuthorization{
			ServerURI: "https://oauth.example.com/token",
		}
		for i := 0; i < b.N; i++ {
			assert.NoError(b, auth.AddTo(m))
			m.Reset()
		}
	})

	b.Run("GetFrom", func(b *testing.B) {
		m := new(stun.Message)
		auth := ThirdPartyAuthorization{
			ServerURI: "https://oauth.example.com/token",
		}
		assert.NoError(b, auth.AddTo(m))

		for i := 0; i < b.N; i++ {
			got := ThirdPartyAuthorization{}
			assert.NoError(b, got.GetFrom(m))
		}
	})
}
