#!/bin/bash
# ======================================================================
# Quantum Scanner - Insecure Build Script
# ======================================================================
# This script builds the quantum_scanner with aggressive TLS/SSL verification
# bypass. USE AT YOUR OWN RISK - only for environments with SSL issues.
# ======================================================================

# ANSI color codes for pretty output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# Enable bash debugging and exit on errors
set -e

echo -e "${YELLOW}[!] INSECURE BUILD MODE - Bypassing SSL/TLS verification${NC}"
echo -e "${YELLOW}[!] WARNING: This is for environments with SSL certificate issues ONLY${NC}"
echo -e "${YELLOW}[!] DO NOT use this in production environments${NC}"
echo -e "${BLUE}[*] Setting up environment...${NC}"

# Configure git to ignore SSL verification globally
git config --global http.sslVerify false

# Set up .curlrc for insecure connections globally
echo "insecure" > ~/.curlrc

# Make sure ~/.cargo directory exists
mkdir -p ~/.cargo

# Create comprehensive cargo config to bypass cert checks
cat > ~/.cargo/config.toml << EOF
[http]
check-revoke = false
ssl-version = "tlsv1.2"
cainfo = ""
multiplexing = false
debug = false
timeout = 60
low-speed-limit = 5

[net]
retry = 10
git-fetch-with-cli = true
offline = false

[term]
quiet = false
EOF

# Set all environment variables for insecure SSL
export CARGO_HTTP_CHECK_REVOKE=false
export CARGO_NET_GIT_FETCH_WITH_CLI=true
export CARGO_HTTP_SSL_VERSION="tlsv1.2"
export CARGO_HTTP_CAINFO=""
export CARGO_HTTP_MULTIPLEXING=false
export RUSTUP_TLS_VERIFY_NONE=1
export SSL_CERT_DIR=""
export SSL_CERT_FILE=""
export REQUESTS_CA_BUNDLE=""
export CURL_CA_BUNDLE=""
export GIT_SSL_NO_VERIFY=true
export NODE_TLS_REJECT_UNAUTHORIZED=0

# Create a system-wide override for a while
sudo cp /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt.bak 2>/dev/null || true

# Check if rustup and cargo are already installed
echo -e "${BLUE}[*] Checking Rust installation...${NC}"
if ! command -v rustup &> /dev/null; then
    echo -e "${YELLOW}[!] rustup not found, installing...${NC}"
    # Download rustup-init with insecure flag
    curl -k --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs -o rustup-init.sh
    # Run rustup-init with all needed flags for insecure install
    RUSTUP_TLS_VERIFY_NONE=1 sh rustup-init.sh -y --default-toolchain stable
    # Remove the downloaded script
    rm rustup-init.sh
    # Source the cargo env
    source "$HOME/.cargo/env"
fi

# Add MUSL target
echo -e "${BLUE}[*] Adding MUSL target...${NC}"
rustup target add x86_64-unknown-linux-musl

# Check if libpcap-dev is installed
if ! dpkg -l | grep -q libpcap-dev; then
    echo -e "${YELLOW}[!] libpcap-dev not found, installing...${NC}"
    sudo apt-get update -qq && sudo apt-get install -y libpcap-dev
fi

# Check for musl-tools
if ! command -v musl-gcc &> /dev/null; then
    echo -e "${YELLOW}[!] musl-tools not found, installing...${NC}"
    sudo apt-get update -qq && sudo apt-get install -y musl-tools
fi

# Save the original Cargo.toml
cp Cargo.toml Cargo.toml.bak

# Modify Cargo.toml to use minimal features
echo -e "${BLUE}[*] Modifying Cargo.toml to use minimal features...${NC}"
sed -i 's/default = \["full"\]/default = \["minimal-static", "insecure-tls"\]/' Cargo.toml

# Clean any previous builds
echo -e "${BLUE}[*] Cleaning previous builds...${NC}"
cargo clean || echo -e "${YELLOW}[!] Cargo clean failed, continuing anyway...${NC}"

# Build with aggressive SSL bypass
echo -e "${BLUE}[*] Building with aggressive SSL bypass...${NC}"

# Try direct build first
set +e  # Temporarily disable exit on error
RUSTFLAGS="-C target-feature=+crt-static" cargo build --release --target=x86_64-unknown-linux-musl --no-default-features --features "minimal-static,insecure-tls"
BUILD_RESULT=$?
set -e  # Re-enable exit on error

# If that fails, try with additional flags
if [ $BUILD_RESULT -ne 0 ]; then
    echo -e "${YELLOW}[!] First build attempt failed, trying with additional flags...${NC}"
    set +e  # Temporarily disable exit on error
    RUSTC_BOOTSTRAP=1 RUSTFLAGS="-C target-feature=+crt-static" cargo build --release --target=x86_64-unknown-linux-musl --no-default-features --features "minimal-static,insecure-tls"
    BUILD_RESULT=$?
    set -e  # Re-enable exit on error
fi

# Check if build succeeded by checking if the binary exists
if [ -f "target/x86_64-unknown-linux-musl/release/quantum_scanner" ]; then
    echo -e "${GREEN}[+] Build completed successfully${NC}"
    cp target/x86_64-unknown-linux-musl/release/quantum_scanner ./quantum_scanner
    chmod +x ./quantum_scanner
    
    # Show final binary size
    BIN_SIZE=$(du -h ./quantum_scanner | cut -f1)
    echo -e "${GREEN}[+] Final binary size: ${YELLOW}$BIN_SIZE${NC}"
    
    # Restore original Cargo.toml
    mv Cargo.toml.bak Cargo.toml
    
    # Restore SSL settings
    if [ -f "/etc/ssl/certs/ca-certificates.crt.bak" ]; then
        sudo mv /etc/ssl/certs/ca-certificates.crt.bak /etc/ssl/certs/ca-certificates.crt 2>/dev/null || true
    fi
    
    echo -e "${GREEN}[+] Insecure build process completed successfully${NC}"
    echo -e "${GREEN}[+] Binary location: ${YELLOW}$(pwd)/quantum_scanner${NC}"
    exit 0
else
    echo -e "${RED}[!] Build failed, binary not created${NC}"
    echo -e "${BLUE}[*] Checking build directory:${NC}"
    find target -name "quantum_scanner" -type f 2>/dev/null || echo -e "${RED}[!] No binary found in target directory${NC}"
    
    # Restore original Cargo.toml
    mv Cargo.toml.bak Cargo.toml
    
    # Restore SSL settings
    if [ -f "/etc/ssl/certs/ca-certificates.crt.bak" ]; then
        sudo mv /etc/ssl/certs/ca-certificates.crt.bak /etc/ssl/certs/ca-certificates.crt 2>/dev/null || true
    fi
    
    exit 1
fi 