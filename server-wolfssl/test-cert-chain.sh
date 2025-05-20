#!/bin/bash

set -euo pipefail

# Function to ensure server is terminated on exit or error
cleanup() {
    if [[ -n "${SERVER_PID:-}" ]] && kill -0 "$SERVER_PID" 2>/dev/null; then
        echo "[INFO] Cleaning up: terminating server (PID $SERVER_PID)..."
        kill "$SERVER_PID"
        wait "$SERVER_PID" 2>/dev/null || true
    fi
}
trap cleanup EXIT

# Step 1: Build the binaries
echo "[INFO] Building project..."
cd build
cmake .. && make

# Step 2: Generate fresh certificates
echo "[INFO] Generating certificates..."
CERTDIR="certs"
mkdir -p "$CERTDIR"
./certgen "$CERTDIR"

# Step 3: Run the server in the background
echo "[INFO] Starting server..."
./tls13server \
  --certs "$CERTDIR/server-chain.crt" \
  --key "$CERTDIR/leaf.key" \
  --cafile "$CERTDIR/root.crt" \
  8000 &

SERVER_PID=$!
echo "[INFO] Server PID: $SERVER_PID"

# Step 4: Run the client in the foreground
echo "[INFO] Starting client..."
if ./tls13client \
    --cafile "$CERTDIR/root.crt" \
    --certs "$CERTDIR/client-chain.crt" \
    --key "$CERTDIR/client.key" \
    localhost 8000; then
    echo "[INFO] Client completed successfully."
else
    echo "[ERROR] Client encountered an error."
fi

# Cleanup will be handled by the trap
