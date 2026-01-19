// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package turn

import (
	"github.com/pion/stun/v3"
	"github.com/pion/turn/v5/internal/proto"
)

// OAuthTokenInfo contains information extracted from a TURN server's
// THIRD-PARTY-AUTHORIZATION response per RFC 7635.
type OAuthTokenInfo struct {
	// OAuthServerURI is the URI where the client should request an access token.
	OAuthServerURI string
	// Realm is the authentication realm from the server.
	Realm string
}

// ExtractOAuthInfo extracts OAuth authorization information from a TURN error response.
// Returns nil if the message doesn't contain THIRD-PARTY-AUTHORIZATION attribute.
//
// Typical client flow:
//  1. Client sends Allocate request without credentials
//  2. Server responds with 401 + THIRD-PARTY-AUTHORIZATION
//  3. Client calls ExtractOAuthInfo() to get OAuth server URI
//  4. Client requests token from OAuth server
//  5. Client retries Allocate with ACCESS-TOKEN
func ExtractOAuthInfo(msg *stun.Message) (*OAuthTokenInfo, error) {
	// Check if this is an error response with THIRD-PARTY-AUTHORIZATION
	tpa := &proto.ThirdPartyAuthorization{}
	if err := tpa.GetFrom(msg); err != nil {
		return nil, err
	}

	info := &OAuthTokenInfo{
		OAuthServerURI: tpa.ServerURI,
	}

	// Extract realm if present
	realm := &stun.Realm{}
	if err := realm.GetFrom(msg); err == nil {
		info.Realm = realm.String()
	}

	return info, nil
}

// AddAccessToken adds an ACCESS-TOKEN attribute to a STUN message.
// The tokenBytes parameter should contain the encrypted token obtained from
// the OAuth authorization server.
//
// Note: The client must also add MESSAGE-INTEGRITY using the MAC key
// contained within the encrypted token. The MAC key is encrypted within
// the token and only the TURN server can decrypt it.
//
// Example usage:
//
//	// After receiving token from OAuth server
//	msg := stun.MustBuild(stun.TransactionID, proto.AllocateRequest())
//	username := stun.NewUsername("alice")
//	username.AddTo(msg)
//
//	// Add the access token
//	if err := AddAccessToken(msg, tokenBytes); err != nil {
//	    return err
//	}
//
//	// Add MESSAGE-INTEGRITY with the MAC key from token
//	// (The MAC key must be extracted from the token by the client's
//	//  OAuth server or provided separately)
//	integrity := stun.NewShortTermIntegrity(macKey)
//	integrity.AddTo(msg)
func AddAccessToken(msg *stun.Message, tokenBytes []byte) error {
	// The token is already in the encrypted format from the OAuth server
	// We need to wrap it in an AccessToken attribute with a nonce

	// For client-side, we typically receive the full token from the OAuth server
	// which already includes the nonce and encrypted block.
	// If the OAuth server returns just the encrypted block, the client would need
	// to add a nonce. For simplicity, we assume the OAuth server provides the
	// complete token in the format expected by the TURN server.

	accessToken := &proto.AccessToken{
		Nonce:          nil, // Nonce is included in tokenBytes from OAuth server
		EncryptedBlock: tokenBytes,
	}

	return accessToken.AddTo(msg)
}
