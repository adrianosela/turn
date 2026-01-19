// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package proto

import (
	"github.com/pion/stun/v3"
)

// ThirdPartyAuthorization represents the THIRD-PARTY-AUTHORIZATION attribute.
//
// The THIRD-PARTY-AUTHORIZATION attribute is sent by the TURN server in
// error responses (typically 401 Unauthorized) to indicate that OAuth-based
// authentication is required. The attribute contains the URI of the OAuth
// authorization server where the client should obtain an access token.
//
// The attribute value is a variable-length UTF-8 encoded string containing
// the OAuth server URI.
//
// RFC 7635 Section 6.1.
type ThirdPartyAuthorization struct {
	// ServerURI is the OAuth authorization server URI where clients
	// should request access tokens.
	ServerURI string
}

// AddTo adds THIRD-PARTY-AUTHORIZATION attribute to the message.
func (t ThirdPartyAuthorization) AddTo(m *stun.Message) error {
	m.Add(AttrThirdPartyAuthorization, []byte(t.ServerURI))
	return nil
}

// GetFrom decodes THIRD-PARTY-AUTHORIZATION attribute from the message.
func (t *ThirdPartyAuthorization) GetFrom(m *stun.Message) error {
	v, err := m.Get(AttrThirdPartyAuthorization)
	if err != nil {
		return err
	}

	t.ServerURI = string(v)
	return nil
}
