#!/bin/bash

# Test script to verify the signature fix

echo "=== Testing gvbyh-rust signature fix ==="
echo

# Clean old state files
echo "1. Cleaning old state files..."
rm -f .gvbyh-server-* .gvbyh-client-*
echo "   ✓ Cleaned"
echo

# Build binaries
echo "2. Building binaries..."
cargo build --bin gvbyh-server --release --quiet
cargo build --bin gvbyh-client --release --quiet
echo "   ✓ Built"
echo

# Start server in background
echo "3. Starting server..."
./target/release/gvbyh-server --log-level info > server.log 2>&1 &
SERVER_PID=$!
echo "   Server PID: $SERVER_PID"
sleep 5
echo

# Check if server started successfully
if ! ps -p $SERVER_PID > /dev/null; then
    echo "   ✗ Server failed to start"
    cat server.log
    exit 1
fi
echo "   ✓ Server started"
echo

# Start client in background
echo "4. Starting client..."
./target/release/gvbyh-client --log-level info > client.log 2>&1 &
CLIENT_PID=$!
echo "   Client PID: $CLIENT_PID"
sleep 10
echo

# Check if client started successfully
if ! ps -p $CLIENT_PID > /dev/null; then
    echo "   ✗ Client failed to start"
    cat client.log
    kill $SERVER_PID 2>/dev/null
    exit 1
fi
echo "   ✓ Client started"
echo

# Check for signature errors
echo "5. Checking for signature errors..."
SIGNATURE_ERRORS=$(grep -c "Signature invalid" server.log client.log 2>/dev/null || echo "0")

if [ "$SIGNATURE_ERRORS" -gt 0 ]; then
    echo "   ✗ Found $SIGNATURE_ERRORS signature errors"
    echo
    echo "=== Server Log ==="
    tail -30 server.log
    echo
    echo "=== Client Log ==="
    tail -30 client.log
    RESULT=1
else
    echo "   ✓ No signature errors found"
    RESULT=0
fi
echo

# Cleanup
echo "6. Cleaning up..."
kill $CLIENT_PID $SERVER_PID 2>/dev/null
wait $CLIENT_PID $SERVER_PID 2>/dev/null
echo "   ✓ Processes stopped"
echo

if [ $RESULT -eq 0 ]; then
    echo "=== ✓ TEST PASSED ==="
    echo "The signature validation fix is working correctly!"
else
    echo "=== ✗ TEST FAILED ==="
    echo "Signature errors still present. Check logs above."
fi

exit $RESULT
