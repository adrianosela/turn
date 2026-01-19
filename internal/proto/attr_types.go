// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package proto

import (
	"github.com/pion/stun/v3"
)

// RFC 7635 Third-Party Authorization attribute types.
// These attributes enable OAuth-based authentication for TURN servers.
const (
	// AttrAccessToken represents the ACCESS-TOKEN attribute (0x001B).
	// This attribute contains an encrypted token from an OAuth server
	// that includes the MAC key for MESSAGE-INTEGRITY validation.
	//
	// RFC 7635 Section 6.2.
	AttrAccessToken stun.AttrType = 0x001B

	// AttrThirdPartyAuthorization represents the THIRD-PARTY-AUTHORIZATION attribute (0x802E).
	// This attribute is sent by the server in error responses to indicate
	// that OAuth-based authentication is required. It contains the URI
	// of the OAuth authorization server.
	//
	// RFC 7635 Section 6.1.
	AttrThirdPartyAuthorization stun.AttrType = 0x802E
)
