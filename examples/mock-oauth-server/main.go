// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

// Package main implements a mock OAuth authorization server for testing RFC 7635
package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/pion/turn/v5/internal/oauth"
)

var (
	tokenManager *oauth.TokenManager
	serverName   string
)

// TokenResponse is the OAuth token response format
type TokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
	MACKey      string `json:"mac_key"` // Base64-encoded MAC key for MESSAGE-INTEGRITY
	Username    string `json:"username"`
}

// TokenRequest represents the OAuth token request
type TokenRequest struct {
	GrantType string `json:"grant_type"`
	Username  string `json:"username"`
	Password  string `json:"password"`
}

func handleToken(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Parse request
	var req TokenRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	// Simple authentication (for demo only - use real auth in production!)
	if req.Username == "" || req.Password == "" {
		http.Error(w, "Username and password required", http.StatusUnauthorized)
		return
	}

	// For demo, accept any non-empty credentials
	// In production, validate against your user database
	log.Printf("Token request for user: %s", req.Username)

	// Generate a MAC key (must be at least 160 bits / 20 bytes per RFC 7635)
	macKey := make([]byte, 32) // Use 256 bits for extra security
	if _, err := rand.Read(macKey); err != nil {
		log.Printf("Failed to generate MAC key: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	// Create encrypted access token using TokenManager
	lifetime := time.Hour
	tokenBytes, err := tokenManager.CreateToken(macKey, lifetime)
	if err != nil {
		log.Printf("Failed to create token: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	// Return token response
	response := TokenResponse{
		AccessToken: base64.StdEncoding.EncodeToString(tokenBytes),
		TokenType:   "Bearer",
		ExpiresIn:   int(lifetime.Seconds()),
		MACKey:      base64.StdEncoding.EncodeToString(macKey),
		Username:    req.Username,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)

	log.Printf("Issued token for user: %s (expires in %v)", req.Username, lifetime)
}

func handleHealth(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, "Mock OAuth Server - Ready\n")
	fmt.Fprintf(w, "Server Name: %s\n", serverName)
}

func main() {
	port := flag.Int("port", 8080, "HTTP server port")
	encKeyHex := flag.String("key", "", "Encryption key in hex (64 chars for 32 bytes)")
	server := flag.String("server", "turn.example.com", "TURN server name (must match TURN server)")
	flag.Parse()

	serverName = *server

	// Parse or generate encryption key
	var encryptionKey []byte
	if *encKeyHex != "" {
		var err error
		encryptionKey, err = hex.DecodeString(*encKeyHex)
		if err != nil || len(encryptionKey) != 32 {
			log.Fatalf("Invalid encryption key. Must be 64 hex characters (32 bytes)")
		}
		log.Printf("Using provided encryption key")
	} else {
		// Generate random key for demo
		encryptionKey = make([]byte, 32)
		if _, err := rand.Read(encryptionKey); err != nil {
			log.Fatalf("Failed to generate encryption key: %v", err)
		}
		log.Printf("Generated encryption key: %x", encryptionKey)
		log.Printf("⚠️  IMPORTANT: Share this key with your TURN server!")
	}

	// Initialize token manager
	var err error
	tokenManager, err = oauth.NewTokenManager(encryptionKey, serverName)
	if err != nil {
		log.Fatalf("Failed to create token manager: %v", err)
	}

	// Setup HTTP handlers
	http.HandleFunc("/token", handleToken)
	http.HandleFunc("/health", handleHealth)
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head><title>Mock OAuth Server</title></head>
<body>
<h1>Mock OAuth Server for RFC 7635</h1>
<p>Endpoints:</p>
<ul>
<li><code>POST /token</code> - Request access token</li>
<li><code>GET /health</code> - Health check</li>
</ul>
<h2>Example Token Request</h2>
<pre>
curl -X POST http://localhost:%d/token \
  -H "Content-Type: application/json" \
  -d '{
    "grant_type": "password",
    "username": "alice",
    "password": "secret"
  }'
</pre>
<p><strong>Server Name:</strong> %s</p>
<p><strong>Encryption Key:</strong> <code>%x</code></p>
</body>
</html>`, *port, serverName, encryptionKey)
	})

	addr := fmt.Sprintf(":%d", *port)
	log.Printf("Mock OAuth Server starting on %s", addr)
	log.Printf("Token endpoint: http://localhost:%d/token", *port)
	log.Printf("Server name (must match TURN): %s", serverName)
	log.Printf("Encryption key: %x", encryptionKey)
	log.Println()
	log.Println("⚠️  This is a DEMO server. Do NOT use in production!")
	log.Println()

	if err := http.ListenAndServe(addr, nil); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}
