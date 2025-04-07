#!/bin/bash
# ======================================================================
# Quantum Scanner - Optimized Build Script
# ======================================================================
# This script builds the quantum_scanner with streamlined options for
# optimization and faster Docker-based static builds.
# ======================================================================

# ANSI color codes for pretty output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# Default configuration
STRIP_BINARY=false       # Whether to strip debug symbols
COMPRESS_BINARY=false    # Whether to use UPX compression
ULTRA_MINIMAL=false      # Whether to use extreme UPX compression
CLEAN_ARTIFACTS=false    # Whether to clean build artifacts
STATIC_BUILD=false       # Whether to build a fully static binary using Docker
BYPASS_TLS_SECURITY=false # Whether to bypass TLS certificate verification

# ======================================================================
# FUNCTIONS
# ======================================================================

# Function to display banner
show_banner() {
    echo -e "${BLUE}==========================================================${NC}"
    echo -e "${GREEN}  ██████  ██    ██  █████  ███    ██ ████████ ██    ██ ███    ███${NC}"
    echo -e "${GREEN} ██    ██ ██    ██ ██   ██ ████   ██    ██    ██    ██ ████  ████${NC}"
    echo -e "${GREEN} ██    ██ ██    ██ ███████ ██ ██  ██    ██    ██    ██ ██ ████ ██${NC}"
    echo -e "${GREEN} ██ ▄▄ ██ ██    ██ ██   ██ ██  ██ ██    ██    ██    ██ ██  ██  ██${NC}"
    echo -e "${GREEN}  ██████   ██████  ██   ██ ██   ████    ██     ██████  ██      ██${NC}"
    echo -e "${GREEN}     ▀▀                                                          ${NC}"
    echo -e "${BLUE}  SCANNER | RS Edition | Red Team Network Intelligence Tool${NC}"
    echo -e "${BLUE}==========================================================${NC}"
    echo -e "${YELLOW}  [!] OpSec-Enhanced Port Scanner and Service Identifier${NC}"
    echo -e "${BLUE}==========================================================${NC}"
    echo ""
}

# Function to display help
show_help() {
    echo -e "${BLUE}Usage:${NC} $0 [options]"
    echo ""
    echo -e "${BLUE}Options:${NC}"
    echo "  -h, --help            Show this help message"
    echo "  -s, --strip           Strip debug symbols from binary"
    echo "  -c, --compress        Apply UPX compression to reduce binary size"
    echo "  -u, --ultra           Apply ultra compression (very slow startup)"
    echo "  --static              Build 100% static binary using Docker"
    echo "  --clean               Clean build artifacts before building"
    echo "  --insecure            Bypass TLS certificate verification (for proxy environments)"
    echo ""
    echo -e "${BLUE}Examples:${NC}"
    echo "  $0                    Build in release mode (default)"
    echo "  $0 --strip            Build in release mode and strip symbols"
    echo "  $0 --strip --compress Build and apply compression"
    echo "  $0 --static           Build 100% static binary with Docker"
    echo "  $0 --static --compress Build static binary with UPX compression"
    echo "  $0 --static --ultra   Build static binary with extreme compression"
    echo "  $0 --insecure         Build with TLS verification disabled (for corporate proxies)"
    echo ""
}

# Function to parse command line arguments
parse_args() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            -h|--help)
                show_help
                exit 0
                ;;
            -s|--strip)
                STRIP_BINARY=true
                shift
                ;;
            -c|--compress)
                COMPRESS_BINARY=true
                shift
                ;;
            -u|--ultra)
                ULTRA_MINIMAL=true
                COMPRESS_BINARY=true
                shift
                ;;
            --static)
                STATIC_BUILD=true
                echo -e "${YELLOW}[!] Building fully static binary using Docker${NC}"
                shift
                ;;
            --clean)
                CLEAN_ARTIFACTS=true
                shift
                ;;
            --insecure)
                BYPASS_TLS_SECURITY=true
                echo -e "${YELLOW}[!] TLS certificate verification disabled - USE WITH CAUTION${NC}"
                shift
                ;;
            *)
                echo -e "${RED}Unknown option:${NC} $1"
                show_help
                exit 1
                ;;
        esac
    done
}

# Function to clean artifacts (simplified)
clean_artifacts() {
    if [ "$CLEAN_ARTIFACTS" = true ]; then
        echo -e "${BLUE}[*] Cleaning build artifacts...${NC}"
        cargo clean
        find . -name "*.log" -name "scanner.log*" -delete 2>/dev/null
        echo -e "${GREEN}[+] Build artifacts cleaned${NC}"
        return 10
    fi
    return 0
}

# Function to configure insecure connections if needed
configure_tls_bypass() {
    if [ "$BYPASS_TLS_SECURITY" = true ]; then
        echo -e "${YELLOW}[!] Setting up TLS certificate verification bypass...${NC}"
        
        # Configure git to ignore SSL verification globally
        git config --global http.sslVerify false
        
        # Create cargo config to bypass certificate checks
        mkdir -p ~/.cargo
        cat > ~/.cargo/config.toml << EOF
[http]
check-revoke = false

[net]
retry = 10
git-fetch-with-cli = true
EOF
        
        # Also set the environment variables for this session
        export CARGO_HTTP_CHECK_REVOKE=false
        export CARGO_NET_GIT_FETCH_WITH_CLI=true
        
        echo -e "${YELLOW}[!] TLS certificate verification has been disabled for this build${NC}"
    fi
}

# Function to build the project using standard cargo
build_project() {
    echo -e "${BLUE}[*] Building project in release mode...${NC}"
    
    # Check and install dependencies only if needed
    if ! dpkg -l | grep -q libpcap-dev; then
        echo -e "${YELLOW}[!] libpcap-dev not found, installing...${NC}"
        sudo apt-get update -qq && sudo apt-get install -y libpcap-dev
    fi
    
    # Configure TLS bypass if needed
    configure_tls_bypass
    
    # Run the build
    if cargo build --release; then
        echo -e "${GREEN}[+] Build completed successfully${NC}"
        cp target/release/quantum_scanner ./quantum_scanner
        chmod +x ./quantum_scanner
        return 0
    else
        echo -e "${RED}[!] Build failed${NC}"
        return 1
    fi
}

# Function to ensure rustup is installed
ensure_rustup() {
    if ! command -v rustup &> /dev/null; then
        echo -e "${YELLOW}[!] rustup not found, installing...${NC}"
        curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
        source "$HOME/.cargo/env"
        
        # Verify installation
        if ! command -v rustup &> /dev/null; then
            echo -e "${RED}[!] Failed to install rustup. Using system cargo only.${NC}"
            return 1
        fi
    fi
    return 0
}

# Function to build static binary using Docker (optimized)
build_static() {
    echo -e "${BLUE}[*] Building static binary using Docker...${NC}"
    
    # Check if Docker is installed
    if ! command -v docker &> /dev/null; then
        echo -e "${RED}[!] Docker is not installed, falling back to direct musl build.${NC}"
        build_static_directly
        return $?
    fi
    
    # One-time docker socket permission fix (if needed)
    if [ ! -w "/var/run/docker.sock" ] && [ -e "/var/run/docker.sock" ]; then
        echo -e "${YELLOW}[!] Fixing Docker socket permissions...${NC}"
        sudo chmod 666 /var/run/docker.sock || true
    fi
    
    # Set up build arguments for Docker
    DOCKER_BUILD_ARGS=""
    
    # Add TLS bypass if needed
    if [ "$BYPASS_TLS_SECURITY" = true ]; then
        DOCKER_BUILD_ARGS="$DOCKER_BUILD_ARGS --build-arg BYPASS_TLS_SECURITY=true"
        echo -e "${YELLOW}[!] TLS certificate verification will be disabled in Docker build${NC}"
    fi
    
    # Add compression flags if needed
    if [ "$COMPRESS_BINARY" = true ]; then
        DOCKER_BUILD_ARGS="$DOCKER_BUILD_ARGS --build-arg ENABLE_UPX=true"
    fi
    
    # Add ultra compression if needed
    if [ "$ULTRA_MINIMAL" = true ]; then
        DOCKER_BUILD_ARGS="$DOCKER_BUILD_ARGS --build-arg ULTRA_MINIMAL=true"
    fi

    # Ensure the Cargo.lock exists to avoid Docker build errors
    if [ ! -f "Cargo.lock" ]; then
        echo -e "${BLUE}[*] Creating Cargo.lock file...${NC}"
        cargo check || true
    fi
    
    # Build the Docker image with optimized caching
    echo -e "${BLUE}[*] Building Docker image...${NC}"
    if ! docker build $DOCKER_BUILD_ARGS -t quantum_scanner_static .; then
        echo -e "${RED}[!] Docker build failed, falling back to direct musl build.${NC}"
        build_static_directly
        return $?
    fi
    
    # Extract the binary from the image (single-step extraction)
    echo -e "${BLUE}[*] Extracting static binary...${NC}"
    docker create --name quantum_tmp quantum_scanner_static >/dev/null
    docker cp quantum_tmp:/quantum_scanner ./quantum_scanner
    docker rm quantum_tmp >/dev/null
    chmod +x ./quantum_scanner
    
    # Verify the binary (optional check)
    if command -v ldd &> /dev/null; then
        LDD_OUTPUT=$(ldd ./quantum_scanner 2>&1)
        if [[ "$LDD_OUTPUT" == *"not a dynamic executable"* ]]; then
            echo -e "${GREEN}[+] Successfully built static binary${NC}"
        fi
    fi
    
    # Show binary size
    BIN_SIZE=$(du -h ./quantum_scanner | cut -f1)
    echo -e "${GREEN}[+] Final static binary size: ${YELLOW}$BIN_SIZE${NC}"
    
    return 0
}

# Function to build static binary directly without Docker
build_static_directly() {
    echo -e "${BLUE}[*] Building static binary with musl...${NC}"
    
    # Install required tools if needed
    if ! command -v musl-gcc &> /dev/null; then
        echo -e "${YELLOW}[!] Installing musl-tools...${NC}"
        sudo apt-get update -qq && sudo apt-get install -y musl-tools musl-dev
    fi
    
    # Ensure rustup is installed
    ensure_rustup
    
    # Configure TLS bypass if needed
    configure_tls_bypass
    
    # Add musl target if rustup is available
    if command -v rustup &> /dev/null; then
        echo -e "${BLUE}[*] Adding musl target...${NC}"
        rustup target add x86_64-unknown-linux-musl
        
        # Build with musl target
        echo -e "${BLUE}[*] Building with musl target...${NC}"
        RUSTFLAGS="-C target-feature=+crt-static" cargo build --release --target=x86_64-unknown-linux-musl
        
        if [ $? -ne 0 ]; then
            echo -e "${RED}[!] Static build failed${NC}"
            return 1
        fi
        
        # Copy binary to root directory
        cp target/x86_64-unknown-linux-musl/release/quantum_scanner ./quantum_scanner
    else
        # Fallback to standard build if rustup is not available
        echo -e "${YELLOW}[!] rustup not available, using standard build with musl-gcc${NC}"
        
        # Set environment variables for musl
        export CC=musl-gcc
        
        # Build with cargo directly
        cargo build --release
        
        if [ $? -ne 0 ]; then
            echo -e "${RED}[!] Build failed${NC}"
            return 1
        fi
        
        # Copy binary to root directory
        cp target/release/quantum_scanner ./quantum_scanner
    fi
    
    chmod +x ./quantum_scanner
    
    # Show binary size
    BIN_SIZE=$(du -h ./quantum_scanner | cut -f1)
    echo -e "${GREEN}[+] Final static binary size: ${YELLOW}$BIN_SIZE${NC}"
    
    return 0
}

# Function to apply binary hardening (consolidated)
apply_binary_hardening() {
    # Strip binary if enabled
    if [ "$STRIP_BINARY" = true ]; then
        echo -e "${BLUE}[*] Stripping debug symbols...${NC}"
        strip -s ./quantum_scanner 2>/dev/null || true
    fi
    
    # Apply UPX compression if enabled
    if [ "$COMPRESS_BINARY" = true ]; then
        if ! command -v upx &> /dev/null; then
            echo -e "${YELLOW}[!] UPX not found, installing...${NC}"
            sudo apt-get update -qq && sudo apt-get install -y upx-ucl || sudo apt-get install -y upx
        fi
        
        echo -e "${BLUE}[*] Applying UPX compression...${NC}"
        if [ "$ULTRA_MINIMAL" = true ]; then
            echo -e "${YELLOW}[!] Using extreme compression (slows startup time)...${NC}"
            upx --no-backup --brute ./quantum_scanner 2>/dev/null || true
        else
            upx --no-backup ./quantum_scanner 2>/dev/null || true
        fi
    fi
    
    # Show final binary size
    BIN_SIZE=$(du -h ./quantum_scanner | cut -f1)
    echo -e "${GREEN}[+] Final binary size: ${YELLOW}$BIN_SIZE${NC}"
}

# Main function
main() {
    # Show banner
    show_banner
    
    # Parse command line arguments
    parse_args "$@"
    
    # Clean artifacts if requested
    clean_artifacts
    cleaning_result=$?
    
    # Exit if we only wanted to clean
    if [ "$CLEAN_ARTIFACTS" = true ] && [ $cleaning_result -eq 10 ]; then
        echo -e "${GREEN}[+] Clean operation completed successfully${NC}"
        exit 0
    fi
    
    # Build the project based on options
    if [ "$STATIC_BUILD" = true ]; then
        build_static
    else
        build_project
    fi
    
    # Apply binary hardening if build was successful
    if [ $? -eq 0 ]; then
        apply_binary_hardening
        echo -e "${GREEN}[+] Build process completed successfully${NC}"
    else
        echo -e "${RED}[!] Build process failed${NC}"
        exit 1
    fi
}

# Run the main function with all arguments
main "$@" 