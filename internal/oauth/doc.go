// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

// Package oauth implements RFC 7635 Third-Party Authorization for TURN.
//
// This package provides token encryption and decryption functionality using
// AES-256-GCM as specified in RFC 7635. Tokens contain the MAC key used for
// MESSAGE-INTEGRITY validation, along with timestamp and lifetime information.
//
// The TokenManager handles encryption and decryption of tokens, using the
// TURN server name as Additional Authenticated Data (AAD) to bind tokens
// to specific servers and prevent token reuse across different servers.
package oauth
