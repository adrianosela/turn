// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package proto

import (
	"encoding/binary"
	"errors"

	"github.com/pion/stun/v3"
)

// AccessToken represents the ACCESS-TOKEN attribute.
//
// The ACCESS-TOKEN attribute is used to carry an OAuth access token
// in TURN requests. The token contains an encrypted block that includes
// the MAC key for MESSAGE-INTEGRITY validation, along with timestamp
// and lifetime information.
//
// The attribute format is:
//   - nonce_length (2 bytes): Length of the nonce in bytes
//   - nonce (variable): Random nonce value
//   - encrypted_block (variable): AES-256-GCM encrypted token data
//
// RFC 7635 Section 6.2.
type AccessToken struct {
	// Nonce is a random value used for replay protection.
	Nonce []byte
	// EncryptedBlock contains the AES-256-GCM encrypted token data.
	EncryptedBlock []byte
}

const (
	// Minimum size for ACCESS-TOKEN: 2 bytes for nonce_length
	minAccessTokenSize = 2
)

var (
	// ErrInvalidAccessToken indicates the ACCESS-TOKEN attribute is malformed.
	ErrInvalidAccessToken = errors.New("invalid ACCESS-TOKEN attribute")
)

// AddTo adds ACCESS-TOKEN attribute to the message.
func (a AccessToken) AddTo(m *stun.Message) error {
	if len(a.Nonce) > 0xFFFF {
		return ErrInvalidAccessToken
	}

	// Calculate total size: 2 bytes (nonce_length) + nonce + encrypted_block
	totalSize := 2 + len(a.Nonce) + len(a.EncryptedBlock)
	v := make([]byte, totalSize)

	// Write nonce_length (2 bytes, big-endian)
	binary.BigEndian.PutUint16(v[0:2], uint16(len(a.Nonce)))

	// Write nonce
	offset := 2
	copy(v[offset:], a.Nonce)
	offset += len(a.Nonce)

	// Write encrypted_block
	copy(v[offset:], a.EncryptedBlock)

	m.Add(AttrAccessToken, v)
	return nil
}

// GetFrom decodes ACCESS-TOKEN attribute from the message.
func (a *AccessToken) GetFrom(m *stun.Message) error {
	v, err := m.Get(AttrAccessToken)
	if err != nil {
		return err
	}

	if len(v) < minAccessTokenSize {
		return ErrInvalidAccessToken
	}

	// Read nonce_length
	nonceLength := binary.BigEndian.Uint16(v[0:2])

	// Validate that we have enough data
	if len(v) < 2+int(nonceLength) {
		return ErrInvalidAccessToken
	}

	// Extract nonce
	offset := 2
	a.Nonce = make([]byte, nonceLength)
	copy(a.Nonce, v[offset:offset+int(nonceLength)])
	offset += int(nonceLength)

	// Extract encrypted_block (remaining bytes)
	if offset < len(v) {
		a.EncryptedBlock = make([]byte, len(v)-offset)
		copy(a.EncryptedBlock, v[offset:])
	} else {
		a.EncryptedBlock = nil
	}

	return nil
}
