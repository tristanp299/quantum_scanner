#!/bin/bash
# ======================================================================
# Quantum Scanner - Unified Build Script
# ======================================================================
# This script combines SSL certificate handling, dependency fixes, and 
# multiple build options into a single unified solution.
# ======================================================================

# ANSI color codes for pretty output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# Default configuration
BUILD_TYPE="release"     # Can be "release" or "debug"
STRIP_BINARY=false     # Whether to strip debug symbols
COMPRESS_BINARY=false  # Whether to use UPX compression
ULTRA_MINIMAL=false    # Whether to use extreme UPX compression
STATIC_BUILD=false     # Whether to build a static binary
FIX_DEPENDENCIES=true  # Whether to fix dependency formats in Cargo.toml
CLEAN_ARTIFACTS=false  # Whether to clean build artifacts

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
    echo "  -d, --debug           Build in debug mode (default: release)"
    echo "  -s, --strip           Strip debug symbols from binary"
    echo "  -c, --compress        Apply UPX compression to reduce binary size"
    echo "  -u, --ultra           Apply ultra compression (very slow startup)"
    echo "  --static              Build fully static binary"
    echo "  --clean               Clean build artifacts before building"
    echo "  --no-fix              Skip fixing dependencies in Cargo.toml"
    echo ""
    echo -e "${BLUE}Examples:${NC}"
    echo "  $0                    Build in release mode (default)"
    echo "  $0 --debug            Build in debug mode"
    echo "  $0 --strip            Build in release mode and strip symbols"
    echo "  $0 --static           Build fully static binary"
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
            -d|--debug)
                BUILD_TYPE="debug"
                shift
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
                STRIP_BINARY=true  # Always strip static builds for smaller size
                echo -e "${YELLOW}[!] Static builds with musl have compatibility issues.${NC}"
                echo -e "${YELLOW}[!] Building portable binary with dynamic linking instead.${NC}"
                shift
                ;;
            --clean)
                CLEAN_ARTIFACTS=true
                shift
                ;;
            --no-fix)
                FIX_DEPENDENCIES=false
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

# Function to create a backup of Cargo.toml
backup_cargo_toml() {
    if [ ! -f "Cargo.toml.bak" ]; then
        echo -e "${BLUE}[*] Creating backup of Cargo.toml...${NC}"
        cp Cargo.toml Cargo.toml.bak
        echo -e "${GREEN}[+] Backup created: Cargo.toml.bak${NC}"
    else
        echo -e "${YELLOW}[!] Backup already exists (Cargo.toml.bak)${NC}"
    fi
}

# Function to fix the Cargo.toml file
fix_cargo_toml() {
    if [ "$FIX_DEPENDENCIES" = false ]; then
        echo -e "${YELLOW}[!] Skipping dependency fixes (--no-fix option used)${NC}"
        return 0
    fi

    echo -e "${BLUE}[*] Fixing dependency formats in Cargo.toml...${NC}"
    
    # Use sed to fix dependency lines to use the full format for problematic crates
    # Convert simple format to table format for these specific crates
    sed -i 's/^aes-gcm = "\([^"]*\)"$/aes-gcm = { version = "\1" }/g' Cargo.toml
    sed -i 's/^sha2 = "\([^"]*\)"$/sha2 = { version = "\1" }/g' Cargo.toml
    sed -i 's/^chacha20poly1305 = "\([^"]*\)"$/chacha20poly1305 = { version = "\1" }/g' Cargo.toml
    
    echo -e "${GREEN}[+] Fixed dependency formats in Cargo.toml${NC}"
}

# Function to set up cargo configuration for SSL issues
setup_cargo_config() {
    echo -e "${BLUE}[*] Setting up cargo configuration for SSL issues...${NC}"
    mkdir -p .cargo
    
    cat > .cargo/config.toml << 'EOF'
# ======================================================================
# Cargo Configuration for SSL Certificate Issues
# ======================================================================

# Network settings - use git CLI for fetching
[net]
git-fetch-with-cli = true
retry = 10

# Disable SSL verification for the crates.io registry
[source.crates-io]
registry = "https://github.com/rust-lang/crates.io-index"
protocol = "sparse"
ssl-verify = false
EOF
    
    echo -e "${GREEN}[+] Created .cargo/config.toml${NC}"
}

# Function to set environment variables for build
set_env_vars() {
    echo -e "${BLUE}[*] Setting environment variables for build...${NC}"
    
    # SSL/TLS related variables
    export CARGO_HTTP_CHECK_REVOKE=false
    export CARGO_NET_GIT_FETCH_WITH_CLI=true
    
    # Build-related variables
    export CARGO_HTTP_DEBUG=true
    export CARGO_NET_RETRY=10
    
    # Set RUSTFLAGS based on build type
    if [ "$BUILD_TYPE" = "release" ]; then
        # Release mode: optimize for size and performance
        export RUSTFLAGS_BASE="-C opt-level=3 -C codegen-units=1 -C target-cpu=native"
        export RUSTFLAGS="$RUSTFLAGS_BASE -C panic=abort"
    else
        # Debug mode: include debug symbols and checks
        export RUSTFLAGS_BASE="-C debuginfo=2 -D warnings"
        export RUSTFLAGS="$RUSTFLAGS_BASE"
    fi
    
    echo -e "${GREEN}[+] Environment variables set${NC}"
}

# Function to clean artifacts
clean_artifacts() {
    if [ "$CLEAN_ARTIFACTS" = true ]; then
        echo -e "${BLUE}[*] Cleaning build artifacts...${NC}"
        cargo clean
        
        # Remove logs and temporary files
        find . -name "*.log" -delete
        find . -name "scanner.log*" -delete
        
        echo -e "${GREEN}[+] Build artifacts cleaned${NC}"
        
        # Return success code to indicate cleaning was performed
        return 10
    fi
    
    # Return normal code if no cleaning was done
    return 0
}

# Function to build the project
build_project() {
    echo -e "${BLUE}[*] Building project in ${YELLOW}$BUILD_TYPE${NC} mode...${NC}"
    
    # Set cargo flags for build type
    local cargo_flags=""
    if [ "$BUILD_TYPE" = "release" ]; then
        cargo_flags="--release"
    fi
    
    # Run the build
    if cargo build $cargo_flags; then
        echo -e "${GREEN}[+] Build completed successfully${NC}"
        return 0
    else
        echo -e "${RED}[!] Build failed${NC}"
        echo -e "${YELLOW}[!] Trying alternative build approach...${NC}"
        
        # If build fails, try with system CA certificates
        export SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt
        export SSL_CERT_DIR=/etc/ssl/certs
        
        if cargo build $cargo_flags; then
            echo -e "${GREEN}[+] Build with system CA certificates succeeded${NC}"
            return 0
        else
            echo -e "${RED}[!] All build attempts failed${NC}"
            return 1
        fi
    fi
}

# Function to build static binary using Docker
build_static() {
    echo -e "${BLUE}[*] Building static binary using Docker...${NC}"
    
    # Check if Docker is installed
    if ! command -v docker &> /dev/null; then
        echo -e "${RED}[!] Docker is not installed. Please install Docker to use static build.${NC}"
        echo -e "${YELLOW}[!] Falling back to local build method...${NC}"
        build_static_local
        return $?
    fi
    
    # === BEGIN DOCKER CERTIFICATE FIXES ===
    # This section handles common certificate issues with Docker on Kali Linux and similar distributions
    echo -e "${BLUE}[*] Applying Docker certificate fixes...${NC}"
    
    # Check if running as root and ask for sudo if needed
    if [ "$EUID" -ne 0 ]; then
        echo -e "${YELLOW}[!] Docker certificate fixes require root privileges${NC}"
        echo -e "${YELLOW}[!] Re-running with sudo for certificate fixes only...${NC}"
        
        # Execute just the certificate fixing part with sudo
        sudo bash -c "
            # Create Docker certificate directories
            mkdir -p /etc/docker/certs.d/docker.io
            mkdir -p /etc/docker/certs.d/registry.docker.io
            mkdir -p /etc/docker/certs.d/registry-1.docker.io
            mkdir -p /etc/docker/certs.d/index.docker.io
            mkdir -p /etc/docker/certs.d/auth.docker.io
            
            # Copy system certificates to Docker certificate directories
            cp /etc/ssl/certs/ca-certificates.crt /etc/docker/certs.d/docker.io/ca.crt
            cp /etc/ssl/certs/ca-certificates.crt /etc/docker/certs.d/registry.docker.io/ca.crt
            cp /etc/ssl/certs/ca-certificates.crt /etc/docker/certs.d/registry-1.docker.io/ca.crt
            cp /etc/ssl/certs/ca-certificates.crt /etc/docker/certs.d/index.docker.io/ca.crt
            cp /etc/ssl/certs/ca-certificates.crt /etc/docker/certs.d/auth.docker.io/ca.crt
            
            # Configure Docker daemon for secure registry access
            DOCKER_CONFIG_DIR=\"/etc/docker\"
            DOCKER_CONFIG_FILE=\"\$DOCKER_CONFIG_DIR/daemon.json\"
            
            if [ ! -f \"\$DOCKER_CONFIG_FILE\" ]; then
                echo '{
  \"insecure-registries\": [\"docker.io\", \"registry.docker.io\", \"registry-1.docker.io\", \"index.docker.io\"],
  \"allow-nondistributable-artifacts\": [\"docker.io\", \"registry.docker.io\", \"registry-1.docker.io\", \"index.docker.io\"],
  \"dns\": [\"8.8.8.8\", \"8.8.4.4\"],
  \"registry-mirrors\": [\"https://mirror.gcr.io\", \"https://docker-mirror.example.com\", \"https://registry-mirror.example.com\"]
}' > \"\$DOCKER_CONFIG_FILE\"
            else
                # Use grep to check if already configured
                if ! grep -q \"insecure-registries\" \"\$DOCKER_CONFIG_FILE\"; then
                    # Backup original file
                    cp \"\$DOCKER_CONFIG_FILE\" \"\$DOCKER_CONFIG_FILE.bak\"
                    
                    # Simple addition to existing file if jq not available
                    sed -i 's/}$/,\"insecure-registries\": [\"docker.io\", \"registry.docker.io\", \"registry-1.docker.io\", \"index.docker.io\"],\"allow-nondistributable-artifacts\": [\"docker.io\", \"registry.docker.io\", \"registry-1.docker.io\", \"index.docker.io\"]}/' \"\$DOCKER_CONFIG_FILE\" 
                fi
            fi
            
            # Add Docker registry entries to /etc/hosts if needed
            if ! grep -q \"registry-1.docker.io\" /etc/hosts; then
                echo \"# Docker registry hosts for certificate handling\" >> /etc/hosts
                echo \"44.194.136.173  registry-1.docker.io\" >> /etc/hosts
                echo \"3.213.10.128    auth.docker.io\" >> /etc/hosts
            fi
            
            # Restart Docker service
            echo \"Restarting Docker service...\"
            systemctl restart docker
            
            # Fix permissions for Docker socket
            echo \"Setting Docker socket permissions...\"
            chmod 666 /var/run/docker.sock
        "
        echo -e "${GREEN}[+] Docker certificate fixes applied${NC}"
    fi
    # === END DOCKER CERTIFICATE FIXES ===
    
    # Verify Docker is working
    echo -e "${BLUE}[*] Verifying Docker connection...${NC}"
    if ! docker info > /dev/null 2>&1; then
        echo -e "${RED}[!] Docker is not responding, falling back to local build${NC}"
        build_static_local
        return $?
    fi
    
    # Check if we can connect to Docker Hub
    echo -e "${BLUE}[*] Testing connection to Docker Hub...${NC}"
    if ! docker pull hello-world > /dev/null 2>&1; then
        echo -e "${YELLOW}[!] Cannot connect to Docker Hub, falling back to local build${NC}"
        build_static_local
        return $?
    fi
    
    # Generate a unique container name
    CONTAINER_NAME="quantum_scanner_build_$(date +%s)"
    
    # Configure Docker to use plain HTTP without client certificates
    echo -e "${BLUE}[*] Configuring Docker client...${NC}"
    
    # Remove any existing Docker client configuration that might be causing issues
    rm -f "${HOME}/.docker/ca.pem" "${HOME}/.docker/cert.pem" "${HOME}/.docker/key.pem" 2>/dev/null
    
    # Create Docker config directory if it doesn't exist
    mkdir -p "${HOME}/.docker"
    
    # Set up Docker client config to use plain HTTP
    echo '{
  "auths": {},
  "experimental": "enabled",
  "debug": true
}' > "${HOME}/.docker/config.json"
    
    # Use Docker context command if available to ensure we're using the default context
    if command -v docker context &> /dev/null; then
        echo -e "${BLUE}[*] Setting Docker context to default...${NC}"
        docker context use default 2>/dev/null || echo -e "${YELLOW}[!] Could not set Docker context, continuing...${NC}"
    fi
    
    # Unset any Docker TLS environment variables that might interfere
    unset DOCKER_CERT_PATH DOCKER_TLS DOCKER_TLS_VERIFY DOCKER_TLSCACERT DOCKER_TLSCERT DOCKER_TLSKEY
    
    # Set Docker host to use Unix socket
    export DOCKER_HOST="unix:///var/run/docker.sock"
    
    # Create a simpler Dockerfile for network-challenged environments
    echo -e "${BLUE}[*] Creating simplified Dockerfile for network issues...${NC}"
    cat > Dockerfile.offline << 'EOF'
# Simplified Dockerfile for network-challenged environments
FROM debian:bookworm-slim AS builder

# Install build dependencies
RUN apt-get update && apt-get install -y \
    curl \
    build-essential \
    pkg-config \
    libssl-dev \
    musl-tools \
    cmake

# Install Rust using local script
RUN curl --insecure -sSf https://sh.rustup.rs | sh -s -- -y
ENV PATH="/root/.cargo/bin:${PATH}"

# Create build directory
WORKDIR /build

# Copy source code
COPY . .

# Build statically linked executable using musl
RUN rustup target add x86_64-unknown-linux-musl
ENV CC_x86_64_unknown_linux_musl=musl-gcc
RUN RUSTFLAGS="-C target-feature=+crt-static" cargo build --release --target=x86_64-unknown-linux-musl

# Strip binary to reduce size
RUN strip -s target/x86_64-unknown-linux-musl/release/quantum_scanner

# Minimal image
FROM scratch
COPY --from=builder /build/target/x86_64-unknown-linux-musl/release/quantum_scanner /quantum_scanner
ENTRYPOINT ["/quantum_scanner"]
EOF
    
    # Try to use existing images or pull if needed
    echo -e "${BLUE}[*] Checking for existing Docker images...${NC}"
    if docker images | grep -q "rust" || docker images | grep -q "debian"; then
        echo -e "${GREEN}[+] Found existing images to use${NC}"
    else
        echo -e "${BLUE}[*] Attempting to pull images...${NC}"
        # Try multiple ways to pull an image
        docker pull rust:slim || \
        docker pull debian:bookworm-slim || \
        docker pull debian:stable-slim || \
        docker pull ubuntu:latest || \
        echo -e "${YELLOW}[!] All pull attempts failed, will try to use local images${NC}"
    fi
    
    # Try to use a Rust image if available, otherwise use the offline approach
    echo -e "${BLUE}[*] Building with Docker...${NC}"
    if docker images | grep -q "rust"; then
        echo -e "${GREEN}[+] Using available Rust image${NC}"
        docker build \
            --network=host \
            --no-cache \
            --build-arg ENABLE_UPX=$COMPRESS_BINARY \
            --build-arg ULTRA_MINIMAL=$ULTRA_MINIMAL \
            -t quantum_scanner_static_build .
    else
        echo -e "${YELLOW}[!] Using offline build approach with Debian/Ubuntu base${NC}"
        docker build \
            --network=host \
            --no-cache \
            -f Dockerfile.offline \
            -t quantum_scanner_static_build .
    fi
    
    # Extract the binary if build succeeded
    if [ $? -eq 0 ]; then
        echo -e "${BLUE}[*] Extracting binary from container...${NC}"
        docker create --name "$CONTAINER_NAME" quantum_scanner_static_build
        docker cp "$CONTAINER_NAME":/quantum_scanner . 
        docker rm "$CONTAINER_NAME"
    else
        echo -e "${RED}[!] Docker build failed, falling back to local build${NC}"
        build_static_local
        return $?
    fi
    
    if [ -f "quantum_scanner" ]; then
        chmod +x ./quantum_scanner
        echo -e "${GREEN}[+] Static binary built successfully: ./quantum_scanner${NC}"
        
        # Show binary size
        BIN_SIZE=$(du -h ./quantum_scanner | cut -f1)
        echo -e "${GREEN}[+] Final static binary size: ${YELLOW}$BIN_SIZE${NC}"
        return 0
    else
        echo -e "${RED}[!] Failed to build static binary with Docker, falling back to local build${NC}"
        build_static_local
        return $?
    fi
}

# Function to build static binary locally (fallback method)
build_static_local() {
    echo -e "${BLUE}[*] Building portable binary with musl...${NC}"
    
    # Check if musl-tools are installed
    if ! command -v musl-gcc &> /dev/null; then
        echo -e "${YELLOW}[!] musl-tools not found, installing...${NC}"
        sudo apt-get update && sudo apt-get install -y musl-tools build-essential
    fi
    
    # Check if cargo is available
    if ! command -v cargo &> /dev/null; then
        echo -e "${RED}[!] cargo not found, please install Rust manually${NC}"
        echo -e "${YELLOW}[!] Run: curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh${NC}"
        return 1
    fi
    
    # Add musl target
    rustup target add x86_64-unknown-linux-musl
    
    # Build with safer flags for musl
    echo -e "${BLUE}[*] Building with musl target...${NC}"
    if RUSTFLAGS="-C target-feature=+crt-static -C link-arg=-lgcc" cargo build --release --target=x86_64-unknown-linux-musl; then
        echo -e "${GREEN}[+] Build completed successfully${NC}"
        
        # Strip the binary if it exists
        echo -e "${BLUE}[*] Stripping debug symbols...${NC}"
        if [ -f "target/x86_64-unknown-linux-musl/release/quantum_scanner" ]; then
            strip -s target/x86_64-unknown-linux-musl/release/quantum_scanner || echo -e "${YELLOW}[!] Stripping failed, continuing...${NC}"
            
            # Copy to root directory
            cp target/x86_64-unknown-linux-musl/release/quantum_scanner ./quantum_scanner
            chmod +x ./quantum_scanner
            
            # Show binary size
            BIN_SIZE=$(du -h ./quantum_scanner | cut -f1)
            echo -e "${GREEN}[+] Final binary size: ${YELLOW}$BIN_SIZE${NC}"
            return 0
        else
            echo -e "${RED}[!] Binary not found at expected location${NC}"
            return 1
        fi
    else
        echo -e "${RED}[!] Build failed, trying without lgcc flag...${NC}"
        if RUSTFLAGS="-C target-feature=+crt-static" cargo build --release --target=x86_64-unknown-linux-musl; then
            echo -e "${GREEN}[+] Build completed successfully${NC}"
            
            # Strip the binary if it exists
            echo -e "${BLUE}[*] Stripping debug symbols...${NC}"
            if [ -f "target/x86_64-unknown-linux-musl/release/quantum_scanner" ]; then
                strip -s target/x86_64-unknown-linux-musl/release/quantum_scanner || echo -e "${YELLOW}[!] Stripping failed, continuing...${NC}"
                
                # Copy to root directory
                cp target/x86_64-unknown-linux-musl/release/quantum_scanner ./quantum_scanner
                chmod +x ./quantum_scanner
                
                # Show binary size
                BIN_SIZE=$(du -h ./quantum_scanner | cut -f1)
                echo -e "${GREEN}[+] Final binary size: ${YELLOW}$BIN_SIZE${NC}"
                return 0
            else
                echo -e "${RED}[!] Binary not found at expected location${NC}"
                return 1
            fi
        else
            echo -e "${RED}[!] All build attempts failed${NC}"
            return 1
        fi
    fi
}

# Function to apply binary hardening
apply_binary_hardening() {
    # Get binary path based on build type
    if [ "$STATIC_BUILD" = true ]; then
        # First check if we have a built binary
        if [ -f "./quantum_scanner" ]; then
            BINARY_PATH="./quantum_scanner"
        # Then check musl target
        elif [ -f "./target/x86_64-unknown-linux-musl/release/quantum_scanner" ]; then
            BINARY_PATH="./target/x86_64-unknown-linux-musl/release/quantum_scanner"
        # Finally check regular release path
        elif [ -f "./target/release/quantum_scanner" ]; then
            BINARY_PATH="./target/release/quantum_scanner"
        else
            echo -e "${RED}[!] Binary not found. Build may have failed.${NC}"
            return 1
        fi
    elif [ "$BUILD_TYPE" = "release" ]; then
        BINARY_PATH="./target/release/quantum_scanner"
    else
        BINARY_PATH="./target/debug/quantum_scanner"
    fi
    
    # Check if binary exists
    if [ ! -f "$BINARY_PATH" ]; then
        echo -e "${RED}[!] Binary not found at $BINARY_PATH. Build may have failed.${NC}"
        return 1
    fi
    
    echo -e "${BLUE}[*] Applying binary hardening...${NC}"
    
    # Strip binary if enabled
    if [ "$STRIP_BINARY" = true ]; then
        echo -e "${BLUE}[*] Stripping debug symbols...${NC}"
        strip -s "$BINARY_PATH" 2>/dev/null || echo -e "${YELLOW}[!] Stripping failed, continuing...${NC}"
    fi
    
    # Apply UPX compression if enabled
    if [ "$COMPRESS_BINARY" = true ]; then
        if command -v upx &> /dev/null; then
            echo -e "${BLUE}[*] Applying UPX compression...${NC}"
            
            if [ "$ULTRA_MINIMAL" = true ]; then
                echo -e "${YELLOW}[!] Using extreme compression (slows startup time)...${NC}"
                upx --no-backup --brute "$BINARY_PATH" || echo -e "${YELLOW}[!] UPX compression failed, continuing...${NC}"
            else
                upx --no-backup "$BINARY_PATH" || echo -e "${YELLOW}[!] UPX compression failed, continuing...${NC}"
            fi
        else
            echo -e "${YELLOW}[!] UPX not found, skipping compression. Install UPX with: sudo apt install upx${NC}"
        fi
    fi
    
    # Copy binary to root directory for convenience
    if [ "$BINARY_PATH" != "./quantum_scanner" ]; then
        cp "$BINARY_PATH" ./quantum_scanner
        echo -e "${GREEN}[+] Binary copied to ./quantum_scanner${NC}"
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
    
    # Create backup of Cargo.toml
    backup_cargo_toml
    
    # Fix Cargo.toml if needed
    fix_cargo_toml
    
    # Setup cargo config for SSL issues
    setup_cargo_config
    
    # Set environment variables
    set_env_vars
    
    # Clean artifacts if requested
    clean_artifacts
    cleaning_result=$?
    
    # Exit if we only wanted to clean
    if [ "$CLEAN_ARTIFACTS" = true ] && [ $cleaning_result -eq 10 ]; then
        echo -e "${GREEN}[+] Clean operation completed successfully${NC}"
        exit 0
    fi
    
    # Build the project
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