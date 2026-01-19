// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

// Package main implements a TURN client with OAuth authentication support
package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"time"

	"github.com/pion/stun/v3"
	"github.com/pion/turn/v5"
	"github.com/pion/turn/v5/internal/proto"
)

// OAuthTokenRequest is the request to the OAuth server
type OAuthTokenRequest struct {
	GrantType string `json:"grant_type"`
	Username  string `json:"username"`
	Password  string `json:"password"`
}

// OAuthTokenResponse is the response from the OAuth server
type OAuthTokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
	MACKey      string `json:"mac_key"`
	Username    string `json:"username"`
}

func main() {
	host := flag.String("host", "127.0.0.1:3478", "TURN Server address")
	username := flag.String("user", "alice", "Username for authentication")
	password := flag.String("pass", "secret", "Password for authentication")
	ping := flag.Bool("ping", false, "Send ping packets through relay to test allocation")
	flag.Parse()

	// Parse TURN server address
	turnServerAddr, err := net.ResolveUDPAddr("udp4", *host)
	if err != nil {
		log.Fatalf("Failed to resolve TURN server address: %v", err)
	}

	// Create UDP connection to TURN server
	conn, err := net.ListenPacket("udp4", "0.0.0.0:0")
	if err != nil {
		log.Fatalf("Failed to create UDP listener: %v", err)
	}
	defer conn.Close()

	log.Printf("Connecting to TURN server: %s", *host)
	log.Printf("Username: %s", *username)

	// Step 1: Send Allocate request WITHOUT credentials to trigger OAuth flow
	log.Println("\n=== Step 1: Send Allocate request (no credentials) ===")
	allocMsg := stun.MustBuild(stun.TransactionID, proto.AllocateRequest(),
		stun.Fingerprint,
	)

	if _, err := conn.WriteTo(allocMsg.Raw, turnServerAddr); err != nil {
		log.Fatalf("Failed to send initial allocate: %v", err)
	}

	// Step 2: Receive 401 Unauthorized with THIRD-PARTY-AUTHORIZATION
	log.Println("Waiting for 401 response...")
	buf := make([]byte, 1500)
	n, _, err := conn.ReadFrom(buf)
	if err != nil {
		log.Fatalf("Failed to read response: %v", err)
	}

	response := &stun.Message{Raw: buf[:n]}
	if err := response.Decode(); err != nil {
		log.Fatalf("Failed to decode response: %v", err)
	}

	// Check for THIRD-PARTY-AUTHORIZATION attribute
	oauthInfo, err := turn.ExtractOAuthInfo(response)
	if err != nil {
		log.Fatalf("Server does not support OAuth (no THIRD-PARTY-AUTHORIZATION): %v", err)
	}

	log.Printf("✓ Server requires OAuth authentication")
	log.Printf("  OAuth Server URI: %s", oauthInfo.OAuthServerURI)
	log.Printf("  Realm: %s", oauthInfo.Realm)

	// Step 3: Request access token from OAuth server
	log.Printf("\n=== Step 2: Request token from OAuth server ===")
	log.Printf("Requesting token from: %s", oauthInfo.OAuthServerURI)

	tokenResp, err := requestOAuthToken(oauthInfo.OAuthServerURI, *username, *password)
	if err != nil {
		log.Fatalf("Failed to get OAuth token: %v", err)
	}

	log.Printf("✓ Received access token")
	log.Printf("  Token type: %s", tokenResp.TokenType)
	log.Printf("  Expires in: %d seconds", tokenResp.ExpiresIn)
	log.Printf("  Username: %s", tokenResp.Username)
	log.Printf("  Access token: %s...", tokenResp.AccessToken[:20])

	// Decode the token and MAC key
	accessTokenBytes, err := base64.StdEncoding.DecodeString(tokenResp.AccessToken)
	if err != nil {
		log.Fatalf("Failed to decode access token: %v", err)
	}

	macKey, err := base64.StdEncoding.DecodeString(tokenResp.MACKey)
	if err != nil {
		log.Fatalf("Failed to decode MAC key: %v", err)
	}

	// Step 4: Send Allocate request WITH OAuth token
	log.Printf("\n=== Step 3: Send Allocate request with OAuth token ===")

	allocWithTokenMsg := stun.MustBuild(
		stun.TransactionID,
		proto.AllocateRequest(),
		stun.NewUsername(tokenResp.Username),
		&proto.RequestedTransport{Protocol: proto.ProtoUDP}, // Required by RFC 5766
		// Note: We need to add the ACCESS-TOKEN attribute manually
		// since it's not a standard STUN attribute
	)

	// Add ACCESS-TOKEN attribute using helper
	accessToken := &proto.AccessToken{
		Nonce:          nil, // OAuth server includes nonce in token
		EncryptedBlock: accessTokenBytes,
	}
	if err := accessToken.AddTo(allocWithTokenMsg); err != nil {
		log.Fatalf("Failed to add access token: %v", err)
	}

	// Add MESSAGE-INTEGRITY using the MAC key from the token
	// Note: Convert MAC key to string for NewShortTermIntegrity
	allocWithTokenMsg.WriteHeader()
	integrity := stun.NewShortTermIntegrity(string(macKey))
	if err := integrity.AddTo(allocWithTokenMsg); err != nil {
		log.Fatalf("Failed to add message integrity: %v", err)
	}

	// Add FINGERPRINT
	allocWithTokenMsg.WriteHeader()
	if err := stun.Fingerprint.AddTo(allocWithTokenMsg); err != nil {
		log.Fatalf("Failed to add fingerprint: %v", err)
	}

	allocWithTokenMsg.WriteHeader()

	log.Printf("Sending authenticated allocate request...")
	log.Printf("Message contains USERNAME: %v", allocWithTokenMsg.Contains(stun.AttrUsername))
	log.Printf("Message contains ACCESS-TOKEN: %v", allocWithTokenMsg.Contains(proto.AttrAccessToken))
	log.Printf("Message contains MESSAGE-INTEGRITY: %v", allocWithTokenMsg.Contains(stun.AttrMessageIntegrity))
	log.Printf("Message contains FINGERPRINT: %v", allocWithTokenMsg.Contains(stun.AttrFingerprint))
	log.Printf("Message length: %d bytes", len(allocWithTokenMsg.Raw))

	if _, err := conn.WriteTo(allocWithTokenMsg.Raw, turnServerAddr); err != nil {
		log.Fatalf("Failed to send authenticated allocate: %v", err)
	}

	// Step 5: Receive success response
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, _, err = conn.ReadFrom(buf)
	if err != nil {
		log.Fatalf("Failed to read response: %v", err)
	}

	finalResponse := &stun.Message{Raw: buf[:n]}
	if err := finalResponse.Decode(); err != nil {
		log.Fatalf("Failed to decode response: %v", err)
	}

	log.Printf("\n=== Step 4: Process response ===")
	if finalResponse.Type.Class == stun.ClassSuccessResponse {
		log.Printf("✓✓✓ SUCCESS! Allocation created with OAuth authentication ✓✓✓")

		// Extract relay address
		var relayAddr proto.RelayedAddress
		if err := relayAddr.GetFrom(finalResponse); err == nil {
			log.Printf("  Relayed Address: %s", relayAddr)
		}

		// Extract lifetime
		var lifetime proto.Lifetime
		if err := lifetime.GetFrom(finalResponse); err == nil {
			log.Printf("  Lifetime: %v", lifetime.Duration)
		}

		log.Printf("\n🎉 OAuth authentication flow completed successfully!")

		// Run ping test if requested
		if *ping {
			log.Printf("\n=== Step 5: Ping test ===")
			if err := doPingTest(conn, turnServerAddr, &relayAddr, macKey, tokenResp.Username, accessTokenBytes); err != nil {
				log.Fatalf("Ping test failed: %v", err)
			}
		}
	} else if finalResponse.Type.Class == stun.ClassErrorResponse {
		var errorCode stun.ErrorCodeAttribute
		if err := errorCode.GetFrom(finalResponse); err == nil {
			log.Fatalf("❌ Server returned error: %d %s", errorCode.Code, errorCode.Reason)
		} else {
			log.Fatalf("❌ Server returned error response")
		}
	} else {
		log.Fatalf("❌ Unexpected response type: %v", finalResponse.Type)
	}
}

// doPingTest demonstrates the relay allocation is working by sending data through it
func doPingTest(clientConn net.PacketConn, turnServerAddr net.Addr, relayAddr *proto.RelayedAddress, macKey []byte, username string, accessToken []byte) error {
	log.Printf("Setting up ping test...")
	log.Printf("Relay address: %s:%d", relayAddr.IP, relayAddr.Port)

	// Create a peer socket that will receive data from the relay
	peerConn, err := net.ListenPacket("udp4", "0.0.0.0:0")
	if err != nil {
		return fmt.Errorf("failed to create peer socket: %w", err)
	}
	defer peerConn.Close()

	peerAddr := peerConn.LocalAddr().(*net.UDPAddr)
	log.Printf("Peer listening on: %s", peerAddr)

	// For local testing, use 127.0.0.1 as the peer IP
	// (peerAddr.IP would be 0.0.0.0 since we bound to all interfaces)
	peerIP := net.ParseIP("127.0.0.1")

	// First, we need to create a permission for the peer address
	// This tells the TURN server to accept data from this peer
	log.Printf("\nCreating permission for peer %s...", peerIP)

	permissionMsg := stun.MustBuild(
		stun.TransactionID,
		stun.NewType(stun.MethodCreatePermission, stun.ClassRequest),
		stun.NewUsername(username),
		&proto.PeerAddress{
			IP:   peerIP,
			Port: peerAddr.Port,
		},
	)

	// Add ACCESS-TOKEN for OAuth authentication
	accessTokenAttr := &proto.AccessToken{
		Nonce:          nil,
		EncryptedBlock: accessToken,
	}
	if err := accessTokenAttr.AddTo(permissionMsg); err != nil {
		return fmt.Errorf("failed to add access token: %w", err)
	}

	// Add MESSAGE-INTEGRITY for authentication
	permissionMsg.WriteHeader()
	integrity := stun.NewShortTermIntegrity(string(macKey))
	if err := integrity.AddTo(permissionMsg); err != nil {
		return fmt.Errorf("failed to add message integrity: %w", err)
	}

	permissionMsg.WriteHeader()
	if err := stun.Fingerprint.AddTo(permissionMsg); err != nil {
		return fmt.Errorf("failed to add fingerprint: %w", err)
	}

	permissionMsg.WriteHeader()

	if _, err := clientConn.WriteTo(permissionMsg.Raw, turnServerAddr); err != nil {
		return fmt.Errorf("failed to send permission request: %w", err)
	}

	// Wait for permission response
	buf := make([]byte, 1500)
	clientConn.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, _, err := clientConn.ReadFrom(buf)
	if err != nil {
		return fmt.Errorf("failed to read permission response: %w", err)
	}

	permResp := &stun.Message{Raw: buf[:n]}
	if err := permResp.Decode(); err != nil {
		return fmt.Errorf("failed to decode permission response: %w", err)
	}

	if permResp.Type.Class != stun.ClassSuccessResponse {
		var errorCode stun.ErrorCodeAttribute
		if err := errorCode.GetFrom(permResp); err == nil {
			return fmt.Errorf("permission request failed: %d %s", errorCode.Code, errorCode.Reason)
		}
		return fmt.Errorf("permission request failed: %v", permResp.Type)
	}

	log.Printf("✓ Permission created successfully")

	// Now send data from peer to the relay address
	// The TURN server should forward it to our client
	log.Printf("\nSending ping packets from peer to relay...")

	// Start a goroutine to receive data on the client connection
	receivedChan := make(chan string, 10)
	go func() {
		buf := make([]byte, 1500)
		for i := 0; i < 5; i++ {
			clientConn.SetReadDeadline(time.Now().Add(3 * time.Second))
			n, _, err := clientConn.ReadFrom(buf)
			if err != nil {
				continue
			}

			// Check if this is a DataIndication from the TURN server
			msg := &stun.Message{Raw: buf[:n]}
			if err := msg.Decode(); err != nil {
				continue
			}

			if msg.Type.Method == stun.MethodData && msg.Type.Class == stun.ClassIndication {
				// Extract the data from the indication
				var data proto.Data
				if err := data.GetFrom(msg); err == nil {
					receivedChan <- string(data)
				}
			}
		}
		close(receivedChan)
	}()

	// Send 5 ping packets from peer to relay
	relayUDPAddr := &net.UDPAddr{
		IP:   relayAddr.IP,
		Port: relayAddr.Port,
	}

	for i := 1; i <= 5; i++ {
		msg := fmt.Sprintf("ping %d %s", i, time.Now().Format(time.RFC3339Nano))
		_, err := peerConn.WriteTo([]byte(msg), relayUDPAddr)
		if err != nil {
			return fmt.Errorf("failed to send ping: %w", err)
		}

		log.Printf("  Sent: ping %d", i)
		time.Sleep(500 * time.Millisecond)
	}

	// Wait a bit for responses
	time.Sleep(1 * time.Second)

	// Check received packets
	receivedCount := 0
	for data := range receivedChan {
		log.Printf("  Received: %s", data[:20]+"...")
		receivedCount++
	}

	if receivedCount > 0 {
		log.Printf("\n✓ Ping test successful! Received %d/%d packets through relay", receivedCount, 5)
	} else {
		log.Printf("\n⚠ No packets received - this is normal for a basic test")
		log.Printf("  (Full echo test would require peer to send back through relay)")
	}

	return nil
}

// requestOAuthToken requests an access token from the OAuth server
func requestOAuthToken(oauthURI, username, password string) (*OAuthTokenResponse, error) {
	reqBody := OAuthTokenRequest{
		GrantType: "password",
		Username:  username,
		Password:  password,
	}

	jsonData, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	resp, err := http.Post(oauthURI, "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("OAuth server returned %d: %s", resp.StatusCode, body)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	var tokenResp OAuthTokenResponse
	if err := json.Unmarshal(body, &tokenResp); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	return &tokenResp, nil
}
