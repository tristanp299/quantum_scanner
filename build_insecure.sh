#!/bin/bash
# ======================================================================
# Quantum Scanner - Insecure Build Script
# ======================================================================
# This script provides a wrapper to build the project with SSL verification disabled.
# SECURITY WARNING: This script disables SSL certificate validation and should only be
# used in trusted environments where the reduced security is acceptable.
# ======================================================================

# ANSI color codes for pretty output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# Display security warning
echo -e "${RED}===========================================================${NC}"
echo -e "${RED}  SECURITY WARNING - SSL VERIFICATION DISABLED${NC}"
echo -e "${RED}===========================================================${NC}"
echo -e "${YELLOW}  This build disables SSL certificate validation for Cargo.${NC}"
echo -e "${YELLOW}  Only use this in trusted environments or when dealing with${NC}" 
echo -e "${YELLOW}  self-signed certificates in managed VM environments.${NC}"
echo -e "${RED}===========================================================${NC}"
echo ""
echo -e "${BLUE}Continuing in 3 seconds...${NC}"
sleep 3

# Ensure .cargo directory exists
mkdir -p .cargo

# Check if .cargo/config.toml exists, create it if not
if [ ! -f .cargo/config.toml ]; then
    echo -e "${BLUE}Creating .cargo/config.toml with SSL verification disabled...${NC}"
    cat > .cargo/config.toml << 'EOF'
# Cargo Configuration - SSL Verification Disabled
# WARNING: This reduces security but allows builds in environments with self-signed certificates

[http]
check-revoke = false

[net]
retry = 3
git-fetch-with-cli = true

[registries]
crates-io = { protocol = "sparse", ssl-verify = false }

[http.ssl]
verify-peer = false
cainfo = ""
EOF
    echo -e "${GREEN}Created .cargo/config.toml${NC}"
fi

# Set environment variables to handle SSL certificate issues
export CARGO_HTTP_CHECK_REVOKE=false
export CARGO_HTTP_SSL_VERSION_CHECK=false
export CARGO_NET_GIT_FETCH_WITH_CLI=true
export CARGO_REGISTRIES_CRATES_IO_PROTOCOL=sparse

echo -e "${BLUE}Building project with SSL verification disabled...${NC}"

# Run the main build script with the appropriate arguments
if [ -f "./build.sh" ]; then
    # Pass all arguments to the main build script
    ./build.sh "$@"
else
    # Fallback to direct cargo build if build.sh doesn't exist
    echo -e "${YELLOW}No build.sh found, running cargo build directly...${NC}"
    if [ "$1" == "--release" ] || [ "$1" == "-r" ]; then
        cargo build --release
    else
        cargo build
    fi
fi

echo ""
echo -e "${GREEN}Build process completed.${NC}"
echo -e "${YELLOW}Remember: This build used insecure SSL settings.${NC}" 