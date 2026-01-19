// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package server

import (
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/pion/stun/v3"
	"github.com/pion/turn/v5/internal/auth"
	"github.com/pion/turn/v5/internal/oauth"
	"github.com/pion/turn/v5/internal/proto"
)

const (
	// See: https://tools.ietf.org/html/rfc5766#section-6.2 defines 3600 seconds recommendation.
	maximumAllocationLifetime = time.Hour
)

func buildAndSend(conn net.PacketConn, dst net.Addr, attrs ...stun.Setter) error {
	msg, err := stun.Build(attrs...)
	if err != nil {
		return err
	}
	_, err = conn.WriteTo(msg.Raw, dst)
	if errors.Is(err, net.ErrClosed) {
		return nil
	}

	return err
}

// Send a STUN packet and return the original error to the caller.
func buildAndSendErr(conn net.PacketConn, dst net.Addr, err error, attrs ...stun.Setter) error {
	if sendErr := buildAndSend(conn, dst, attrs...); sendErr != nil {
		err = fmt.Errorf("%w %v %v", errFailedToSendError, sendErr, err) //nolint:errorlint
	}

	return err
}

func buildMsg(
	transactionID [stun.TransactionIDSize]byte,
	msgType stun.MessageType,
	additional ...stun.Setter,
) []stun.Setter {
	return append([]stun.Setter{&stun.Message{TransactionID: transactionID}, msgType}, additional...)
}

// respondWithThirdPartyAuth sends a 401 Unauthorized response with THIRD-PARTY-AUTHORIZATION
// attribute, indicating that OAuth-based authentication is required.
func respondWithThirdPartyAuth(req Request, stunMsg *stun.Message, callingMethod stun.Method, oauthServerURI string) error {
	return buildAndSend(req.Conn, req.SrcAddr, buildMsg(stunMsg.TransactionID,
		stun.NewType(callingMethod, stun.ClassErrorResponse),
		&stun.ErrorCodeAttribute{Code: stun.CodeUnauthorized},
		&proto.ThirdPartyAuthorization{ServerURI: oauthServerURI},
		stun.NewRealm(req.Realm),
	)...)
}

// authenticateWithToken handles OAuth token-based authentication per RFC 7635.
// Returns the MAC key from the token, username, and any error.
func authenticateWithToken(req Request, stunMsg *stun.Message, tokenManager *oauth.TokenManager, tokenAuthHandler auth.TokenAuthHandler) (
	macKey []byte,
	username string,
	err error,
) {
	// Extract ACCESS-TOKEN attribute
	accessTokenAttr := &proto.AccessToken{}
	if err := accessTokenAttr.GetFrom(stunMsg); err != nil {
		return nil, "", err
	}

	// Decrypt the token
	token, err := tokenManager.DecryptToken(accessTokenAttr.EncryptedBlock)
	if err != nil {
		return nil, "", fmt.Errorf("failed to decrypt token: %w", err)
	}

	// Validate token timestamp and lifetime (5 second clock skew tolerance per RFC 7635)
	const clockSkewTolerance = 5 * time.Second
	if !token.IsValid(clockSkewTolerance) {
		return nil, "", oauth.ErrTokenExpired
	}

	// Extract username from the message (still required)
	usernameAttr := &stun.Username{}
	if err := usernameAttr.GetFrom(stunMsg); err != nil {
		return nil, "", fmt.Errorf("username required with access token: %w", err)
	}

	// If token auth handler is provided, call it for additional validation
	if tokenAuthHandler != nil {
		realmAttr := &stun.Realm{}
		_ = realmAttr.GetFrom(stunMsg) // Realm is optional with tokens

		validatedUsername, ok := tokenAuthHandler(token.MACKey, &auth.RequestAttributes{
			Username:    usernameAttr.String(),
			Realm:       realmAttr.String(),
			SrcAddr:     req.SrcAddr,
			TLS:         req.TLS,
			AccessToken: accessTokenAttr.EncryptedBlock,
		})

		if !ok {
			return nil, "", fmt.Errorf("token validation failed")
		}

		// Use the username returned by the handler (may differ from the one in the message)
		if validatedUsername != "" {
			username = validatedUsername
		} else {
			username = usernameAttr.String()
		}
	} else {
		username = usernameAttr.String()
	}

	return token.MACKey, username, nil
}

func authenticateRequest(req Request, stunMsg *stun.Message, callingMethod stun.Method) (
	messageIntegrity stun.MessageIntegrity,
	hasAuth bool,
	username string,
	err error,
) {
	respondWithNonce := func(responseCode stun.ErrorCode) (stun.MessageIntegrity, bool, string, error) {
		nonce, err := req.NonceHash.Generate()
		if err != nil {
			return nil, false, "", err
		}

		return nil, false, "", buildAndSend(req.Conn, req.SrcAddr, buildMsg(stunMsg.TransactionID,
			stun.NewType(callingMethod, stun.ClassErrorResponse),
			&stun.ErrorCodeAttribute{Code: responseCode},
			stun.NewNonce(nonce),
			stun.NewRealm(req.Realm),
		)...)
	}

	if !stunMsg.Contains(stun.AttrMessageIntegrity) {
		// Check if OAuth is configured and respond with THIRD-PARTY-AUTHORIZATION
		if req.TokenManager != nil && req.OAuthServerURI != "" {
			return nil, false, "", respondWithThirdPartyAuth(req, stunMsg, callingMethod, req.OAuthServerURI)
		}
		return respondWithNonce(stun.CodeUnauthorized)
	}

	badRequestMsg := buildMsg(
		stunMsg.TransactionID,
		stun.NewType(callingMethod, stun.ClassErrorResponse),
		&stun.ErrorCodeAttribute{Code: stun.CodeBadRequest},
	)

	// Try OAuth authentication first if ACCESS-TOKEN is present and OAuth is configured
	if stunMsg.Contains(proto.AttrAccessToken) && req.TokenManager != nil {
		macKey, username, err := authenticateWithToken(req, stunMsg, req.TokenManager, req.TokenAuthHandler)
		if err != nil {
			// OAuth authentication failed - respond with error
			// Log the error server-side for debugging (don't send details to client)
			req.Log.Debugf("OAuth authentication failed from %v: %v", req.SrcAddr, err)
			return nil, false, "", buildAndSendErr(req.Conn, req.SrcAddr, err, badRequestMsg...)
		}

		// Verify MESSAGE-INTEGRITY using the MAC key from the token
		req.Log.Debugf("Verifying MESSAGE-INTEGRITY for user %s with MAC key length: %d", username, len(macKey))
		if err := stun.MessageIntegrity(macKey).Check(stunMsg); err != nil {
			req.Log.Errorf("MESSAGE-INTEGRITY verification failed for user %s from %v: %v", username, req.SrcAddr, err)
			genAuthEvent(req, stunMsg, callingMethod, false)
			return nil, false, "", buildAndSendErr(req.Conn, req.SrcAddr, err, badRequestMsg...)
		}
		req.Log.Debugf("MESSAGE-INTEGRITY verified successfully for user %s", username)

		genAuthEvent(req, stunMsg, callingMethod, true)
		return stun.MessageIntegrity(macKey), true, username, nil
	}

	// Fall back to traditional nonce-based authentication
	nonceAttr := &stun.Nonce{}
	usernameAttr := &stun.Username{}
	realmAttr := &stun.Realm{}

	// No Auth handler is set, server is running in STUN only mode
	// Respond with 400 so clients don't retry.
	if req.AuthHandler == nil {
		sendErr := buildAndSend(req.Conn, req.SrcAddr, badRequestMsg...)

		return nil, false, "", sendErr
	}

	if err := nonceAttr.GetFrom(stunMsg); err != nil {
		return nil, false, "", buildAndSendErr(req.Conn, req.SrcAddr, err, badRequestMsg...)
	}

	// Assert Nonce is signed and is not expired.
	if err := req.NonceHash.Validate(nonceAttr.String()); err != nil {
		return respondWithNonce(stun.CodeStaleNonce)
	}

	if err := realmAttr.GetFrom(stunMsg); err != nil {
		return nil, false, "", buildAndSendErr(req.Conn, req.SrcAddr, err, badRequestMsg...)
	} else if err := usernameAttr.GetFrom(stunMsg); err != nil {
		return nil, false, "", buildAndSendErr(req.Conn, req.SrcAddr, err, badRequestMsg...)
	}

	userID, ourKey, ok := req.AuthHandler(&auth.RequestAttributes{
		Username: usernameAttr.String(),
		Realm:    realmAttr.String(),
		SrcAddr:  req.SrcAddr,
		TLS:      req.TLS,
	})
	if !ok {
		return nil, false, "", buildAndSendErr(
			req.Conn,
			req.SrcAddr,
			fmt.Errorf("%w %s", errNoSuchUser, usernameAttr.String()),
			badRequestMsg...,
		)
	}

	if err := stun.MessageIntegrity(ourKey).Check(stunMsg); err != nil {
		genAuthEvent(req, stunMsg, callingMethod, false)

		return nil, false, "", buildAndSendErr(req.Conn, req.SrcAddr, err, badRequestMsg...)
	}

	genAuthEvent(req, stunMsg, callingMethod, true)

	return stun.MessageIntegrity(ourKey), true, userID, nil
}

func genAuthEvent(req Request, stunMsg *stun.Message, callingMethod stun.Method, verdict bool) {
	if req.AllocationManager.EventHandler.OnAuth == nil {
		return
	}

	realmAttr := &stun.Realm{}
	if err := realmAttr.GetFrom(stunMsg); err != nil {
		return
	}

	// Auth event is generated per the username, not the user-id.
	usernameAttr := &stun.Username{}
	if err := usernameAttr.GetFrom(stunMsg); err != nil {
		return
	}

	transportAttr := &proto.RequestedTransport{}
	if err := transportAttr.GetFrom(stunMsg); err != nil {
		transportAttr = &proto.RequestedTransport{Protocol: proto.ProtoUDP}
	}

	req.AllocationManager.EventHandler.OnAuth(req.SrcAddr, req.Conn.LocalAddr(),
		transportAttr.Protocol.String(), usernameAttr.String(), realmAttr.String(),
		callingMethod.String(), verdict)
}

func allocationLifeTime(req Request, m *stun.Message) time.Duration {
	lifetimeDuration := req.AllocationLifetime

	var lifetime proto.Lifetime
	if err := lifetime.GetFrom(m); err == nil {
		if lifetime.Duration < maximumAllocationLifetime {
			lifetimeDuration = lifetime.Duration
		}
	}

	return lifetimeDuration
}
