#!/bin/bash
# SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
# SPDX-License-Identifier: MIT

# Comprehensive OAuth flow test script
# This script starts all servers and runs the client with proper configuration

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${GREEN}=== OAuth TURN Server Test Script ===${NC}\n"

# Generate shared encryption key
KEY=$(openssl rand -hex 32)
echo -e "${GREEN}Generated shared encryption key:${NC}"
echo -e "${YELLOW}$KEY${NC}\n"

# Configuration
SERVER_IP="127.0.0.1"
TURN_PORT="3478"
OAUTH_PORT="8080"
OAUTH_URI="http://localhost:${OAUTH_PORT}/token"

echo -e "${GREEN}Configuration:${NC}"
echo "  Server IP: $SERVER_IP"
echo "  TURN Port: $TURN_PORT"
echo "  OAuth Port: $OAUTH_PORT"
echo "  OAuth URI: $OAUTH_URI"
echo ""

# Clean up function
cleanup() {
    echo -e "\n${YELLOW}Cleaning up...${NC}"
    if [ ! -z "$OAUTH_PID" ]; then
        kill $OAUTH_PID 2>/dev/null || true
        echo "  Stopped OAuth server (PID: $OAUTH_PID)"
    fi
    if [ ! -z "$TURN_PID" ]; then
        kill $TURN_PID 2>/dev/null || true
        echo "  Stopped TURN server (PID: $TURN_PID)"
    fi
    exit
}

trap cleanup EXIT INT TERM

# Build all components
echo -e "${GREEN}Building servers...${NC}"
cd mock-oauth-server
go build -o oauth-server
cd ../turn-server-oauth
go build -o turn-server
cd ../turn-client-oauth
cd ..

echo -e "${GREEN}✓ Build complete${NC}\n"

# Start OAuth server
echo -e "${GREEN}Starting OAuth server...${NC}"
./mock-oauth-server/oauth-server \
    -port=$OAUTH_PORT \
    -key=$KEY \
    -server=$SERVER_IP \
    > /tmp/oauth-server.log 2>&1 &
OAUTH_PID=$!

sleep 2

# Verify OAuth server is running
if ! ps -p $OAUTH_PID > /dev/null; then
    echo -e "${RED}✗ OAuth server failed to start${NC}"
    cat /tmp/oauth-server.log
    exit 1
fi

echo -e "${GREEN}✓ OAuth server running (PID: $OAUTH_PID)${NC}"
echo "  Logs: /tmp/oauth-server.log"
echo ""

# Test OAuth server health
echo -e "${GREEN}Testing OAuth server health...${NC}"
if curl -s http://localhost:${OAUTH_PORT}/health > /dev/null; then
    echo -e "${GREEN}✓ OAuth server is healthy${NC}"
    curl -s http://localhost:${OAUTH_PORT}/health | grep "Server Name:"
else
    echo -e "${RED}✗ OAuth server health check failed${NC}"
    exit 1
fi
echo ""

# Start TURN server
echo -e "${GREEN}Starting TURN server...${NC}"
./turn-server-oauth/turn-server \
    -public-ip=$SERVER_IP \
    -port=$TURN_PORT \
    -oauth-uri=$OAUTH_URI \
    -key=$KEY \
    > /tmp/turn-server.log 2>&1 &
TURN_PID=$!

sleep 2

# Verify TURN server is running
if ! ps -p $TURN_PID > /dev/null; then
    echo -e "${RED}✗ TURN server failed to start${NC}"
    cat /tmp/turn-server.log
    exit 1
fi

echo -e "${GREEN}✓ TURN server running (PID: $TURN_PID)${NC}"
echo "  Logs: /tmp/turn-server.log"
echo ""

# Wait a bit for servers to be ready
sleep 1

# Show server logs
echo -e "${GREEN}OAuth Server Output:${NC}"
echo "---"
cat /tmp/oauth-server.log
echo "---"
echo ""

echo -e "${GREEN}TURN Server Output:${NC}"
echo "---"
cat /tmp/turn-server.log
echo "---"
echo ""

# Run the client
echo -e "${GREEN}Running OAuth TURN client...${NC}"
echo "---"
cd turn-client-oauth
go run main.go \
    -host=${SERVER_IP}:${TURN_PORT} \
    -user=alice \
    -pass=secret123

CLIENT_EXIT=$?
cd ..

echo "---"
echo ""

# Check result
if [ $CLIENT_EXIT -eq 0 ]; then
    echo -e "${GREEN}✓✓✓ SUCCESS! OAuth flow completed successfully! ✓✓✓${NC}"
else
    echo -e "${RED}✗✗✗ FAILED! Client returned error code: $CLIENT_EXIT ✗✗✗${NC}"
    echo ""
    echo -e "${YELLOW}Showing last 20 lines of server logs:${NC}"
    echo ""
    echo -e "${YELLOW}OAuth Server Log:${NC}"
    tail -20 /tmp/oauth-server.log
    echo ""
    echo -e "${YELLOW}TURN Server Log:${NC}"
    tail -20 /tmp/turn-server.log
    exit 1
fi

echo ""
echo -e "${GREEN}All tests passed!${NC}"
