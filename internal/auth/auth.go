// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

// Package auth provides internal authentication / authorization
// types and utilities for the TURN server.
package auth

import (
	"crypto/tls"
	"net"
)

// RequestAttributes represents attributes of a TURN request which
// may be useful for authorizing the underlying request.
type RequestAttributes struct {
	Username string
	Realm    string
	SrcAddr  net.Addr
	TLS      *tls.ConnectionState

	// AccessToken contains the raw ACCESS-TOKEN attribute bytes from RFC 7635
	// OAuth-based authentication. If present, OAuth authentication is being used.
	AccessToken []byte

	// extend as needed
}

// AuthHandler is a callback used to handle incoming auth requests,
// allowing users to customize Pion TURN with custom behavior.
type AuthHandler func(ra *RequestAttributes) (userID string, key []byte, ok bool)

// TokenAuthHandler is a callback used to handle OAuth token-based authentication.
// It receives the decrypted MAC key from the access token and the request attributes,
// and can perform additional validation (e.g., check user permissions, token claims).
// Returns the username to associate with this session, or empty string to deny.
//
// This is called after token decryption and expiry validation, but before
// MESSAGE-INTEGRITY verification. The returned username will be used for the session.
//
// If nil, all valid tokens are accepted without additional validation.
type TokenAuthHandler func(macKey []byte, ra *RequestAttributes) (username string, ok bool)
