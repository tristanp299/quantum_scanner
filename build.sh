#!/bin/bash
# ======================================================================
# Quantum Scanner - Streamlined Build Script
# ======================================================================
# This script builds the quantum_scanner with options for optimization
# and includes a Docker-based static build option.
# ======================================================================

# ANSI color codes for pretty output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# Default configuration
BUILD_TYPE="release"     # Can be "release" or "debug"
STRIP_BINARY=false       # Whether to strip debug symbols
COMPRESS_BINARY=false    # Whether to use UPX compression
ULTRA_MINIMAL=false      # Whether to use extreme UPX compression
CLEAN_ARTIFACTS=false    # Whether to clean build artifacts
STATIC_BUILD=false       # Whether to build a fully static binary using Docker

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
    echo ""
    echo -e "${BLUE}Examples:${NC}"
    echo "  $0                    Build in release mode (default)"
    echo "  $0 --strip            Build in release mode and strip symbols"
    echo "  $0 --strip --compress Build and apply compression"
    echo "  $0 --static           Build 100% static binary with Docker"
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
            *)
                echo -e "${RED}Unknown option:${NC} $1"
                show_help
                exit 1
                ;;
        esac
    done
}

# Function to fix target directory permissions
fix_target_permissions() {
    echo -e "${BLUE}[*] Checking target directory permissions...${NC}"
    
    # Create target directory if it doesn't exist
    mkdir -p target
    
    # Check if target directory is owned by root
    if [ -d "target" ] && [ "$(stat -c '%U' target)" = "root" ]; then
        echo -e "${YELLOW}[!] Target directory is owned by root, fixing permissions...${NC}"
        if sudo chown -R "$(whoami):$(whoami)" target; then
            echo -e "${GREEN}[+] Target directory permissions fixed${NC}"
        else
            echo -e "${RED}[!] Failed to fix target directory permissions${NC}"
            echo -e "${YELLOW}[!] You may need to run: sudo chown -R $(whoami):$(whoami) target${NC}"
        fi
    fi
    
    # Fix permissions in .cargo directory if it exists
    if [ -d ".cargo" ]; then
        echo -e "${BLUE}[*] Ensuring .cargo directory has correct permissions...${NC}"
        if [ "$(stat -c '%U' .cargo)" != "$(whoami)" ]; then
            echo -e "${YELLOW}[!] .cargo directory has incorrect ownership, fixing...${NC}"
            if sudo chown -R "$(whoami):$(whoami)" .cargo; then
                echo -e "${GREEN}[+] .cargo directory permissions fixed${NC}"
            else
                echo -e "${RED}[!] Failed to fix .cargo directory permissions${NC}"
            fi
        fi
    fi
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

# Function to build the project using standard cargo
build_project() {
    echo -e "${BLUE}[*] Building project in release mode...${NC}"
    
    # Ensure libpcap-dev is installed
    if ! dpkg -l | grep -q libpcap-dev; then
        echo -e "${YELLOW}[!] libpcap-dev not found, installing...${NC}"
        sudo apt-get update
        sudo apt-get install -y libpcap-dev
    fi
    
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

# Function to build static binary using Docker
build_static() {
    echo -e "${BLUE}[*] Building static binary using Docker...${NC}"
    
    # Check if Docker is installed
    if ! command -v docker &> /dev/null; then
        echo -e "${RED}[!] Docker is not installed, falling back to direct musl build.${NC}"
        build_static_directly
        return $?
    fi
    
    # Fix Docker certificate issue
    echo -e "${BLUE}[*] Setting up Docker environment...${NC}"
    mkdir -p $HOME/.docker
    # Use simple config without certificates
    echo '{"auths":{}}' > $HOME/.docker/config.json
    
    # Try to ensure Docker socket has right permissions
    if [ ! -w "/var/run/docker.sock" ]; then
        echo -e "${YELLOW}[!] Docker socket needs permission fix, requires sudo...${NC}"
        sudo chmod 666 /var/run/docker.sock || true
    fi
    
    # Test if Docker works
    if ! docker info &>/dev/null; then
        echo -e "${YELLOW}[!] Docker appears to have issues, falling back to direct musl build.${NC}"
        build_static_directly
        return $?
    fi
    
    # Create simplified Dockerfile for the build
    echo -e "${BLUE}[*] Creating Dockerfile for static build...${NC}"
    cat > Dockerfile.static << 'EOF'
# Use a Debian-based image for building
FROM debian:bullseye-slim AS builder

# Install build dependencies
RUN apt-get update && apt-get install -y \
    curl \
    build-essential \
    pkg-config \
    libssl-dev \
    libpcap-dev \
    musl-tools \
    git

# Install Rust
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
ENV PATH="/root/.cargo/bin:${PATH}"

# Add musl target
RUN rustup target add x86_64-unknown-linux-musl

# Create build directory
WORKDIR /build

# Copy source code
COPY . .

# Build statically linked executable
RUN RUSTFLAGS="-C target-feature=+crt-static" cargo build --release --target=x86_64-unknown-linux-musl

# Strip binary
RUN strip -s target/x86_64-unknown-linux-musl/release/quantum_scanner

# Final stage - create minimal output image
FROM scratch
COPY --from=builder /build/target/x86_64-unknown-linux-musl/release/quantum_scanner /quantum_scanner
ENTRYPOINT ["/quantum_scanner"]
EOF
    
    # Build the Docker image
    echo -e "${BLUE}[*] Building Docker image...${NC}"
    if ! docker build -t quantum_scanner_static -f Dockerfile.static .; then
        echo -e "${RED}[!] Docker build failed, falling back to direct musl build.${NC}"
        build_static_directly
        return $?
    fi
    
    # Extract the binary from the image
    echo -e "${BLUE}[*] Extracting static binary...${NC}"
    
    # Create a container from the image
    CONTAINER_ID=$(docker create quantum_scanner_static)
    
    # Copy the binary from the container
    docker cp "$CONTAINER_ID":/quantum_scanner ./quantum_scanner
    
    # Remove the container
    docker rm "$CONTAINER_ID" > /dev/null
    
    # Make the binary executable
    chmod +x ./quantum_scanner
    
    # Verify the binary
    echo -e "${BLUE}[*] Verifying static binary...${NC}"
    if command -v ldd &> /dev/null; then
        LDD_OUTPUT=$(ldd ./quantum_scanner 2>&1)
        if [[ "$LDD_OUTPUT" == *"not a dynamic executable"* ]]; then
            echo -e "${GREEN}[+] Successfully built static binary${NC}"
        else
            echo -e "${YELLOW}[!] Warning: Binary may not be fully static${NC}"
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
    
    # Ensure required tools are installed
    if ! command -v musl-gcc &> /dev/null; then
        echo -e "${YELLOW}[!] Installing musl-tools...${NC}"
        sudo apt-get update
        sudo apt-get install -y musl-tools musl-dev
    fi
    
    # Add musl target if needed
    echo -e "${BLUE}[*] Ensuring musl target is available...${NC}"
    rustup target add x86_64-unknown-linux-musl
    
    # Build with musl target
    echo -e "${BLUE}[*] Building with musl target...${NC}"
    if ! RUSTFLAGS="-C target-feature=+crt-static" cargo build --release --target=x86_64-unknown-linux-musl; then
        echo -e "${RED}[!] Static build failed${NC}"
        return 1
    fi
    
    # Copy binary to root directory
    echo -e "${BLUE}[*] Copying binary to project root...${NC}"
    cp target/x86_64-unknown-linux-musl/release/quantum_scanner ./quantum_scanner
    chmod +x ./quantum_scanner
    
    # Verify the binary
    echo -e "${BLUE}[*] Verifying static binary...${NC}"
    if command -v ldd &> /dev/null; then
        LDD_OUTPUT=$(ldd ./quantum_scanner 2>&1)
        if [[ "$LDD_OUTPUT" == *"not a dynamic executable"* ]]; then
            echo -e "${GREEN}[+] Successfully built static binary${NC}"
        else
            echo -e "${YELLOW}[!] Warning: Binary may not be fully static${NC}"
        fi
    fi
    
    # Show binary size
    BIN_SIZE=$(du -h ./quantum_scanner | cut -f1)
    echo -e "${GREEN}[+] Final static binary size: ${YELLOW}$BIN_SIZE${NC}"
    
    return 0
}

# Function to apply binary hardening
apply_binary_hardening() {
    echo -e "${BLUE}[*] Applying binary hardening...${NC}"
    
    # Strip binary if enabled
    if [ "$STRIP_BINARY" = true ]; then
        echo -e "${BLUE}[*] Stripping debug symbols...${NC}"
        strip -s ./quantum_scanner || echo -e "${YELLOW}[!] Stripping failed, continuing...${NC}"
    fi
    
    # Apply UPX compression if enabled
    if [ "$COMPRESS_BINARY" = true ]; then
        if command -v upx &> /dev/null; then
            echo -e "${BLUE}[*] Applying UPX compression...${NC}"
            
            if [ "$ULTRA_MINIMAL" = true ]; then
                echo -e "${YELLOW}[!] Using extreme compression (slows startup time)...${NC}"
                upx --no-backup --brute ./quantum_scanner || echo -e "${YELLOW}[!] UPX compression failed, continuing...${NC}"
            else
                upx --no-backup ./quantum_scanner || echo -e "${YELLOW}[!] UPX compression failed, continuing...${NC}"
            fi
        else
            echo -e "${YELLOW}[!] UPX not found, skipping compression. Install UPX with: sudo apt install upx${NC}"
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
    
    # Fix target directory permissions
    fix_target_permissions
    
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