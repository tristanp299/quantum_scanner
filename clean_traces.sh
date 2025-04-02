#!/bin/bash

# Secure removal of logs and other artifacts
echo "[+] Cleaning scanner artifacts..."

# Remove scan logs
find . -name "scanner.log" -exec shred -uz {} \; 2>/dev/null || find . -name "scanner.log" -delete

# Clean bash history entries related to scanning
if [ -f "$HISTFILE" ]; then
    TEMP_HIST=$(mktemp)
    grep -v "quantum_scanner\|port.*scan\|nmap" "$HISTFILE" > "$TEMP_HIST" 2>/dev/null
    cat "$TEMP_HIST" > "$HISTFILE"
    rm -f "$TEMP_HIST"
    echo "[+] Cleaned command history"
fi

# Clear any output files
find . -name "scan_results*.txt" -exec shred -uz {} \; 2>/dev/null || find . -name "scan_results*.txt" -delete
find . -name "*.json" -exec grep -l "port.*scan" {} \; 2>/dev/null | xargs -r shred -uz 2>/dev/null

echo "[+] Cleanup complete"
