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
mkdir -p build && cd build
cmake .. && make

# Step 2: Validate input
if [ "$#" -ne 1 ]; then
    echo "Usage: $0 <directory>"
    exit 1
fi
if [ -d "$1" ]; then
    CERTDIR="$1"
    echo "CERTDIR is set to: $CERTDIR"
else
    echo "Error: '$1' is not a valid directory."
    exit 1
fi

# Step 3: Run the server in the background
echo "[INFO] Starting server..."
./tls13server \
  --debug \
  --certs "$CERTDIR/server-chain.crt" \
  --key "$CERTDIR/leaf.key" \
  --cafile "$CERTDIR/root.crt" \
  8000 > server.log 2>&1 &

SERVER_PID=$!
echo "[INFO] Server PID: $SERVER_PID" && sleep 1

# Step 4: Run the client in the foreground
echo "[INFO] Starting client..."
if ./tls13client \
    --debug \
    --cafile "$CERTDIR/root.crt" \
    --certs "$CERTDIR/client-chain.crt" \
    --key "$CERTDIR/client.key" \
    localhost 8000 > client.log 2>&1; then
    echo "[INFO] Client completed successfully."
else
    echo "[ERROR] Client encountered an error."
fi

# Cleanup will be handled by the trap
