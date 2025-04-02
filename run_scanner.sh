#!/bin/bash

# This wrapper adds operational security features to the scanner
SCANNER="$PWD/target/release/quantum_scanner"

# Ensure DNS requests go through Tor if available
if command -v tor &> /dev/null && pgrep tor > /dev/null; then
    export LD_PRELOAD=/usr/lib/x86_64-linux-gnu/libtsocks.so
    echo "[+] Routing traffic through Tor when available"
fi

# Add random timing to evade pattern detection
if [[ "$*" != *"--rate"* ]]; then
    RANDOM_RATE=$((100 + RANDOM % 400))
    ARGS="$@ --rate $RANDOM_RATE"
    echo "[+] Using randomized packet rate: $RANDOM_RATE pps"
else
    ARGS="$@"
fi

# Always enable evasion techniques
if [[ "$ARGS" != *"-e"* && "$ARGS" != *"--evasion"* ]]; then
    ARGS="$ARGS -e"
    echo "[+] Enabled evasion techniques"
fi

# Add a secure temporary directory for logs
TEMP_DIR=$(mktemp -d)
chmod 700 "$TEMP_DIR"
LOG_FILE="$TEMP_DIR/scan_log.tmp"

# Run the scanner with enhanced security
echo "[+] Starting scan with enhanced security features"
$SCANNER --log-file "$LOG_FILE" $ARGS

# Clean up
read -p "Press Enter to securely delete logs or Ctrl+C to keep them..."
shred -u "$LOG_FILE" 2>/dev/null || rm -f "$LOG_FILE"
rmdir "$TEMP_DIR"
