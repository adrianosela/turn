// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

// Package main implements a TURN server with OAuth authentication support (RFC 7635)
package main

import (
	"crypto/rand"
	"flag"
	"log"
	"net"
	"os"
	"os/signal"
	"strconv"
	"syscall"

	"github.com/pion/logging"
	"github.com/pion/turn/v5"
)

func main() {
	publicIP := flag.String("public-ip", "", "IP Address that TURN can be contacted by")
	port := flag.Int("port", 3478, "Listening port")
	realm := flag.String("realm", "pion.ly", "Realm (defaults to pion.ly)")
	oauthServerURI := flag.String("oauth-uri", "https://oauth.example.com/token", "OAuth authorization server URI")
	flag.Parse()

	if len(*publicIP) == 0 {
		log.Fatalf("'public-ip' is required")
	}

	// Generate a random 32-byte encryption key for AES-256-GCM
	// In production, this key should be:
	// 1. Stored securely (e.g., in a secrets manager)
	// 2. Shared with the OAuth authorization server
	// 3. Rotated periodically
	encryptionKey := make([]byte, 32)
	if _, err := rand.Read(encryptionKey); err != nil {
		log.Fatalf("Failed to generate encryption key: %v", err)
	}

	log.Printf("Encryption key (hex): %x", encryptionKey)
	log.Printf("Share this key with your OAuth server!")

	// Create a UDP listener to pass into pion/turn
	udpListener, err := net.ListenPacket("udp4", "0.0.0.0:"+strconv.Itoa(*port))
	if err != nil {
		log.Fatalf("Failed to create TURN server listener: %s", err)
	}

	// Configure OAuth-based authentication
	oauthConfig := &turn.OAuthConfig{
		EncryptionKey:  encryptionKey,
		ServerName:     *publicIP, // Use server IP/hostname as AAD
		OAuthServerURI: *oauthServerURI,

		// Optional: Custom token validation handler
		// This is called after token decryption and expiry validation
		// but before MESSAGE-INTEGRITY verification
		TokenAuthHandler: func(macKey []byte, ra *turn.RequestAttributes) (username string, ok bool) {
			// You can perform additional validation here:
			// - Check if the user has permission for TURN
			// - Validate token claims (if stored separately)
			// - Apply rate limiting
			// - Log authentication attempts

			log.Printf("OAuth authentication for user: %s from %s", ra.Username, ra.SrcAddr)

			// For this example, accept all valid tokens
			// Return the username from the request
			return ra.Username, true
		},
	}

	// Create the TURN server with OAuth support
	s, err := turn.NewServer(turn.ServerConfig{
		Realm: *realm,
		// OAuth configuration enables RFC 7635 third-party authorization
		OAuthConfig: oauthConfig,

		// Traditional AuthHandler can coexist with OAuth
		// If both are configured, clients can use either authentication method
		// Uncomment to enable traditional authentication alongside OAuth:
		// AuthHandler: func(username, realm string, srcAddr net.Addr) ([]byte, bool) {
		//     if key, ok := usersMap()[username]; ok {
		//         return key, true
		//     }
		//     return nil, false
		// },

		PacketConnConfigs: []turn.PacketConnConfig{
			{
				PacketConn: udpListener,
				RelayAddressGenerator: &turn.RelayAddressGeneratorStatic{
					RelayAddress: net.ParseIP(*publicIP),
					Address:      "0.0.0.0",
				},
			},
		},
		LoggerFactory: logging.NewDefaultLoggerFactory(),
	})
	if err != nil {
		log.Fatalf("Failed to create TURN server: %s", err)
	}

	log.Printf("TURN server listening on %s:%d", *publicIP, *port)
	log.Printf("OAuth Server URI: %s", *oauthServerURI)
	log.Printf("Realm: %s", *realm)
	log.Println()
	log.Println("Client authentication flow:")
	log.Println("1. Client sends Allocate request without credentials")
	log.Println("2. Server responds with 401 + THIRD-PARTY-AUTHORIZATION")
	log.Println("3. Client extracts OAuth server URI from response")
	log.Println("4. Client requests access token from OAuth server")
	log.Println("5. Client retries Allocate with ACCESS-TOKEN + MESSAGE-INTEGRITY")
	log.Println("6. Server decrypts token, validates, and creates allocation")

	// Wait for Ctrl+C
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	<-sigs

	if err = s.Close(); err != nil {
		log.Fatalf("Failed to close server: %s", err)
	}
}

// Example OAuth Server Implementation
//
// The OAuth server must:
// 1. Authenticate the client (e.g., using client credentials, password grant, etc.)
// 2. Generate a MAC key for MESSAGE-INTEGRITY
// 3. Create an encrypted access token using the shared encryption key
// 4. Return the token to the client
//
// Example pseudo-code for the OAuth server:
//
//	func handleTokenRequest(w http.ResponseWriter, r *http.Request) {
//	    // 1. Authenticate the client
//	    username, password := extractCredentials(r)
//	    if !validateCredentials(username, password) {
//	        http.Error(w, "Invalid credentials", http.StatusUnauthorized)
//	        return
//	    }
//
//	    // 2. Generate a MAC key (at least 160 bits / 20 bytes)
//	    macKey := make([]byte, 32) // 256 bits for extra security
//	    rand.Read(macKey)
//
//	    // 3. Create encrypted token using TokenManager
//	    tokenManager, _ := oauth.NewTokenManager(sharedEncryptionKey, turnServerName)
//	    tokenBytes, _ := tokenManager.CreateToken(macKey, time.Hour)
//
//	    // 4. Return token and MAC key to client
//	    json.NewEncoder(w).Encode(map[string]interface{}{
//	        "access_token": base64.StdEncoding.EncodeToString(tokenBytes),
//	        "token_type":   "Bearer",
//	        "expires_in":   3600,
//	        "mac_key":      base64.StdEncoding.EncodeToString(macKey), // Client needs this for MESSAGE-INTEGRITY
//	    })
//	}
