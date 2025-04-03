#!/bin/bash

# ======================================================================
# Quantum Scanner RS - Build and Test Script
# 
# This script automates the build, testing, and security improvements for 
# the Quantum Scanner Rust implementation.
# 
# Considerations for Red Team OpSec:
# - Securely cleans logs and artifacts
# - Provides randomized network behavior
# - Uses secure compilation flags
# - Compresses binaries to reduce size and obfuscate code
# - Adds options for evading detection
# ======================================================================

# ANSI color codes
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# ======================================================================
# GLOBAL CONFIGURATION
# ======================================================================
BINARY_NAME="quantum_scanner"
OUTPUT_DIR="./target/release"
BUILD_TYPE="release"  # Can be "release" or "debug"
CLEAN_ARTIFACTS=false  # Set to "true" to clean build artifacts
STRIP_BINARY=true     # Set to "false" to keep debug symbols
COMPRESS_BINARY=false  # Set to "false" to skip UPX compression
ULTRA_MINIMAL=false   # Set to "true" for extreme UPX compression (slower startup)
LOCAL_TEST_TARGET="127.0.0.1"  # Use loopback for safety

# ======================================================================
# FUNCTIONS
# ======================================================================

# Function to display banner
show_banner() {
    echo -e "${BLUE}=========================================================${NC}"
    echo -e "${GREEN}  ██████  ██    ██  █████  ███    ██ ████████ ██    ██ ███    ███${NC}"
    echo -e "${GREEN} ██    ██ ██    ██ ██   ██ ████   ██    ██    ██    ██ ████  ████${NC}"
    echo -e "${GREEN} ██    ██ ██    ██ ███████ ██ ██  ██    ██    ██    ██ ██ ████ ██${NC}"
    echo -e "${GREEN} ██ ▄▄ ██ ██    ██ ██   ██ ██  ██ ██    ██    ██    ██ ██  ██  ██${NC}"
    echo -e "${GREEN}  ██████   ██████  ██   ██ ██   ████    ██     ██████  ██      ██${NC}"
    echo -e "${GREEN}     ▀▀                                                          ${NC}"
    echo -e "${BLUE}  SCANNER | RS Edition | Red Team Network Intelligence Tool${NC}"
    echo -e "${BLUE}=========================================================${NC}"
    echo -e "${YELLOW}  [!] OpSec-Enhanced Port Scanner and Service Identifier${NC}"
    echo -e "${BLUE}=========================================================${NC}"
    echo ""
}

# Function to build fully static binary using Docker
build_static() {
    echo -e "[${BLUE}*${NC}] Building fully static binary using Docker..."
    
    # Check if Docker is installed
    if ! command -v docker &> /dev/null; then
        echo -e "[${RED}!${NC}] Docker is not installed. Please install Docker to use static build."
        exit 1
    fi
    
    # Check if Dockerfile exists, if not we'll create it
    if [ ! -f "Dockerfile" ]; then
        echo -e "[${RED}!${NC}] Dockerfile not found. Creating one..."
        
        # Create a Dockerfile with UPX configuration
        cat > Dockerfile << 'EOF'
# Multi-stage Dockerfile for building a static Quantum Scanner
FROM rust:slim AS builder

# Add build arguments for configuring UPX compression
ARG ENABLE_UPX=false
ARG ULTRA_MINIMAL=false

# Install build dependencies including musl tools
# UPX will only be installed if needed
RUN echo 'deb http://deb.debian.org/debian bookworm-backports main' > /etc/apt/sources.list.d/backports.list && \
    apt-get update && apt-get install -y \
    libssl-dev \
    pkg-config \
    musl-tools \
    build-essential \
    cmake \
    libpcap-dev \
    coreutils \
    binutils

# Install UPX only if compression is enabled
RUN if [ "$ENABLE_UPX" = "true" ] || [ "$ULTRA_MINIMAL" = "true" ]; then \
    apt-get install -y -t bookworm-backports upx-ucl; \
    fi

# Create build directory
WORKDIR /build

# Copy source code
COPY . .

# Build statically linked executable using musl
RUN rustup target add x86_64-unknown-linux-musl
# Use musl-gcc as the C compiler for the musl target
ENV CC_x86_64_unknown_linux_musl=musl-gcc
RUN RUSTFLAGS="-C target-feature=+crt-static" cargo build --release --target=x86_64-unknown-linux-musl

# Apply extreme binary optimization and compression
# 1. Strip all symbols
RUN strip -s target/x86_64-unknown-linux-musl/release/quantum_scanner

# 2. Apply UPX compression if enabled
RUN if [ "$ULTRA_MINIMAL" = "true" ]; then \
        echo "Applying ultra-minimal UPX compression..." && \
        stdbuf -o0 -e0 upx -vvv --best --ultra-brute target/x86_64-unknown-linux-musl/release/quantum_scanner || \
        echo "UPX ultra compression failed, continuing without it."; \
    elif [ "$ENABLE_UPX" = "true" ]; then \
        echo "Applying standard UPX compression..." && \
        stdbuf -o0 -e0 upx -vvv --best target/x86_64-unknown-linux-musl/release/quantum_scanner || \
        echo "UPX compression failed, continuing without it."; \
    else \
        echo "Skipping UPX compression"; \
    fi

# 3. Display final file size for verification
RUN ls -lh target/x86_64-unknown-linux-musl/release/quantum_scanner

# Use a minimal base for the final image
FROM scratch

# Copy the built binary from builder stage
COPY --from=builder /build/target/x86_64-unknown-linux-musl/release/quantum_scanner /quantum_scanner

# Set entrypoint
ENTRYPOINT ["/quantum_scanner"]
EOF
        echo -e "[${GREEN}+${NC}] Created Dockerfile for static builds."
    fi
    
    BUILD_TARGET_DIR=$(pwd)
    
    # Build the Docker image and extract binary
    echo -e "[${BLUE}*${NC}] Building static binary with Docker (this may take a while)..."
    
    # Generate a unique container name with timestamp to avoid conflicts
    CONTAINER_NAME="quantum_scanner_temp_$(date +%s)"
    
    # Remove any old containers with the same name if they exist (safety check)
    docker rm -f temp_container >/dev/null 2>&1 || true
    
    # Build with Docker, passing compression flags as build arguments
    echo -e "[${GREEN}+${NC}] Building with Docker and capturing output..."
    docker build \
        --build-arg ENABLE_UPX=$COMPRESS_BINARY \
        --build-arg ULTRA_MINIMAL=$ULTRA_MINIMAL \
        -t quantum_scanner_static_build . && \
    docker create --name "$CONTAINER_NAME" quantum_scanner_static_build && \
    docker cp "$CONTAINER_NAME":/quantum_scanner . && \
    docker rm "$CONTAINER_NAME"
    
    if [ -f "quantum_scanner" ]; then
        echo -e "[${GREEN}+${NC}] Static binary built successfully: ./quantum_scanner"
        chmod +x ./quantum_scanner
        
        # Show binary size
        BIN_SIZE=$(du -h ./quantum_scanner | cut -f1)
        echo -e "[${GREEN}+${NC}] Final static binary size: ${YELLOW}$BIN_SIZE${NC}"
    else
        echo -e "[${RED}!${NC}] Failed to build static binary."
        exit 1
    fi
}

# Function to build the Rust project
build_project() {
    local build_type=$1
    local features=$2
    
    echo -e "[${BLUE}*${NC}] Building project in ${YELLOW}$build_type${NC} mode..."
    
    # Set cargo flags for different build types
    local cargo_flags=""
    if [ "$build_type" = "release" ]; then
        cargo_flags="--release"
    fi
    
    # Add features if specified
    if [ -n "$features" ]; then
        cargo_flags="$cargo_flags --features $features"
    fi
    
    # Set RUSTFLAGS for improved performance and security
    if [ "$build_type" = "release" ]; then
        # Release mode: optimize for size and performance, with security mitigations
        # Store panic=abort in a separate variable so tests can run without it
        export RUSTFLAGS_BASE="-C opt-level=3 -C codegen-units=1 -C target-cpu=native -C strip=symbols"
        export RUSTFLAGS="$RUSTFLAGS_BASE -C panic=abort"
    else
        # Debug mode: include debug symbols and checks
        export RUSTFLAGS_BASE="-C debuginfo=2 -D warnings"
        export RUSTFLAGS="$RUSTFLAGS_BASE"
    fi
    
    # Notify about flags
    echo -e "[${GREEN}+${NC}] Using Rust flags: ${YELLOW}$RUSTFLAGS${NC}"
    
    # Run the build
    echo -e "[${BLUE}*${NC}] Running cargo build $cargo_flags..."
    if cargo build $cargo_flags; then
        echo -e "[${GREEN}+${NC}] Build completed successfully"
        return 0
    else
        echo -e "[${RED}!${NC}] Build failed"
        return 1
    fi
}

# Function to run tests
run_tests() {
    echo -e "[${BLUE}*${NC}] Running tests..."
    
    # We need to temporarily disable panic=abort for tests to work
    local original_rustflags="$RUSTFLAGS"
    # Remove panic=abort from RUSTFLAGS for testing only
    export RUSTFLAGS=$(echo "$RUSTFLAGS" | sed 's/-C panic=abort//')
    
    # Check if we have the comprehensive test script
    if [ -f "comprehensive_test.sh" ]; then
        echo -e "[${GREEN}+${NC}] Using comprehensive test script"
        
        if bash ./comprehensive_test.sh; then
            echo -e "[${GREEN}+${NC}] All tests passed"
            # Restore original RUSTFLAGS
            export RUSTFLAGS="$original_rustflags"
            return 0
        else
            echo -e "[${RED}!${NC}] Some tests failed"
            # Restore original RUSTFLAGS
            export RUSTFLAGS="$original_rustflags"
            return 1
        fi
    else
        # Fall back to cargo test
        echo -e "[${YELLOW}!${NC}] No test script found, running cargo tests"
        
        if cargo test; then
            echo -e "[${GREEN}+${NC}] All tests passed"
            # Restore original RUSTFLAGS
            export RUSTFLAGS="$original_rustflags"
            return 0
        else
            echo -e "[${RED}!${NC}] Some tests failed"
            # Restore original RUSTFLAGS
            export RUSTFLAGS="$original_rustflags"
            return 1
        fi
    fi
}

# Function to apply binary hardening techniques
apply_binary_hardening() {
    # Use the correct binary path based on build type and static flag
    if [ "$STATIC" = true ]; then
        BINARY_PATH="$BUILD_TARGET_DIR/quantum_scanner"
    elif [ "$BUILD_TYPE" = "release" ]; then
        BINARY_PATH="./target/release/quantum_scanner"
    else
        BINARY_PATH="./target/debug/quantum_scanner"
    fi
    
    # Check if binary exists before proceeding
    if [ ! -f "$BINARY_PATH" ]; then
        echo -e "[${RED}!${NC}] Binary not found at $BINARY_PATH. Build may have failed."
        echo -e "[${YELLOW}!${NC}] Skipping binary hardening steps."
        return 1
    fi
    
    echo -e "[${BLUE}*${NC}] Applying binary hardening techniques..."
    
    # Strip debug symbols
    if [ "$STRIP_BINARY" = true ]; then
        echo -e "[${GREEN}+${NC}] Stripping debug symbols and other metadata..."
        strip -s "$BINARY_PATH" 2>/dev/null || echo -e "[${YELLOW}!${NC}] Stripping failed, continuing without it."
    fi
    
    # Apply UPX compression if enabled
    if [ "$COMPRESS_BINARY" = true ]; then
        if command -v upx &> /dev/null; then
            echo -e "[${GREEN}+${NC}] Applying UPX compression to reduce binary size..."
            
            if [ "$ULTRA_MINIMAL" = true ]; then
                echo -e "[${YELLOW}!${NC}] Using extreme compression (may slow startup time)..."
                # Ultra-minimal compression with --ultra-brute
                stdbuf -o0 -e0 upx -vvv --best --ultra-brute "$BINARY_PATH" || \
                    echo -e "[${YELLOW}!${NC}] UPX ultra compression failed, continuing without it."
            else
                # Standard compression with --best
                stdbuf -o0 -e0 upx -vvv --best "$BINARY_PATH" || \
                    echo -e "[${YELLOW}!${NC}] UPX compression failed, continuing without it."
            fi
        else
            echo -e "[${YELLOW}!${NC}] UPX not found. Install UPX for better compression: sudo apt install upx"
        fi
    else
        echo -e "[${BLUE}*${NC}] Skipping UPX compression (use --compress or --ultra-minimal to enable)"
    fi
    
    # Apply sstrip for even more aggressive stripping if available
    if command -v sstrip &> /dev/null; then
        echo -e "[${GREEN}+${NC}] Applying super strip (sstrip) for maximum size reduction..."
        sstrip "$BINARY_PATH" 2>/dev/null || echo -e "[${YELLOW}!${NC}] Super strip failed, continuing without it."
    fi
    
    # Show binary size
    BIN_SIZE=$(du -h "$BINARY_PATH" | cut -f1)
    echo -e "[${GREEN}+${NC}] Final binary size: ${YELLOW}$BIN_SIZE${NC}"
    
    # Create a copy in the current directory for convenience
    cp "$BINARY_PATH" ./quantum_scanner
    echo -e "[${GREEN}+${NC}] Binary copied to ./quantum_scanner"
}

# Function to perform full cleanup
perform_full_cleanup() {
    echo -e "[${BLUE}*${NC}] Performing full cleanup..."
    cargo clean
    
    # Remove all logs and temporary files
    DELETED_FILES=$(find . -name "*.log" -o -name "scanner.log*" -o -name "*.o" -o -name "*.d" -o -name "*.gcda" -o -name "*.gcno" -o -name "*.bc" | wc -l)
    DELETED_SIZE=$(find . -name "*.log" -o -name "scanner.log*" -o -name "*.o" -o -name "*.d" -o -name "*.gcda" -o -name "*.gcno" -o -name "*.bc" -print0 | xargs -0 du -ch 2>/dev/null | grep total$ | cut -f1)
    
    find . -name "*.log" -delete
    find . -name "scanner.log*" -delete
    find . -name "*.o" -delete
    find . -name "*.d" -delete
    find . -name "*.gcda" -delete
    find . -name "*.gcno" -delete
    find . -name "*.bc" -delete
    [ -f "./quantum_scanner" ] && rm "./quantum_scanner"
    
    echo -e "     Removed ${DELETED_FILES} files, ${DELETED_SIZE:-0} total"
}

# Function to clean traces for opsec
clean_traces() {
    echo -e "[${BLUE}*${NC}] Cleaning scanner traces and artifacts for operational security..."
    
    # Remove scanner logs
    find . -name "scanner.log*" -type f -print0 | while IFS= read -r -d $'\0' file; do
        echo -e "     Securely deleting: $file"
        # Overwrite the file with random data before deleting
        dd if=/dev/urandom of="$file" bs=1k count=1 conv=notrunc 2>/dev/null
        rm -f "$file"
    done
    
    # Remove JSON result files
    find . -name "scan_results.json" -type f -print0 | while IFS= read -r -d $'\0' file; do
        echo -e "     Securely deleting: $file"
        dd if=/dev/urandom of="$file" bs=1k count=1 conv=notrunc 2>/dev/null
        rm -f "$file"
    done
    
    # Clean pcap files if any
    find . -name "*.pcap" -type f -print0 | while IFS= read -r -d $'\0' file; do
        echo -e "     Securely deleting: $file"
        dd if=/dev/urandom of="$file" bs=1k count=1 conv=notrunc 2>/dev/null
        rm -f "$file"
    done
    
    # Clean up any temporary files
    find /tmp -name "quantum_scanner_*" -type f -print0 2>/dev/null | while IFS= read -r -d $'\0' file; do
        echo -e "     Securely deleting: $file"
        dd if=/dev/urandom of="$file" bs=1k count=1 conv=notrunc 2>/dev/null
        rm -f "$file"
    done
    
    # Clean bash history to remove any references to scanner
    if [ -f ~/.bash_history ]; then
        sed -i '/quantum_scanner/d' ~/.bash_history 2>/dev/null || true
    fi
    
    # Clean zsh history if applicable
    if [ -f ~/.zsh_history ]; then
        sed -i '/quantum_scanner/d' ~/.zsh_history 2>/dev/null || true
    fi
    
    # Clean RAM disk if it exists
    if [ -d "/mnt/quantum_scanner_ramdisk" ]; then
        echo -e "     Cleaning RAM disk..."
        rm -rf /mnt/quantum_scanner_ramdisk/* 2>/dev/null || true
    fi
    
    echo -e "[${GREEN}+${NC}] Trace cleanup completed successfully"
    return 0
}

# Main build process
main() {
    # Show banner
    show_banner
    
    # Process command line arguments
    BUILD_TYPE="release"
    INSTALL=false
    CLEAN=false
    FULL_CLEAN=false
    # Set these to false by default - compression is now opt-in
    MINIMAL=false
    ULTRA_MINIMAL=false
    COMPRESS_BINARY=false
    STATIC=false
    RUN_TESTS=true
    RUN_SCAN=false
    CLEAN_TRACES_MODE=false
    BUILD_REQUESTED=true
    
    while [[ $# -gt 0 ]]; do
        case $1 in
            --debug)
                BUILD_TYPE="debug"
                shift
                ;;
            --install)
                INSTALL=true
                shift
                ;;
            --clean)
                CLEAN=true
                shift
                ;;
            --full-clean)
                FULL_CLEAN=true
                BUILD_REQUESTED=false  # Don't build if full-clean is specified
                shift
                ;;
            --compress)
                # Enable standard UPX compression
                COMPRESS_BINARY=true
                shift
                ;;
            --ultra-minimal)
                # Enable extreme UPX compression with ultra-brute settings
                COMPRESS_BINARY=true
                ULTRA_MINIMAL=true
                shift
                ;;
            --static)
                STATIC=true
                shift
                ;;
            --no-tests)
                RUN_TESTS=false
                shift
                ;;
            --run)
                # New flag to run scanner with opSec features
                RUN_SCAN=true
                shift
                break  # Stop processing our options and pass remaining to scanner
                ;;
            --clean-traces)
                # New flag to clean traces
                CLEAN_TRACES_MODE=true
                shift
                ;;
            --static-build)
                # New flag to build static binary with Docker
                echo -e "[${BLUE}*${NC}] Static build requested with current compression settings."
                # Carry over compression settings from main script
                COMPRESS_BINARY=$COMPRESS_BINARY
                ULTRA_MINIMAL=$ULTRA_MINIMAL
                build_static
                exit $?
                ;;
            --help)
                echo -e "${YELLOW}Quantum Scanner Build Script${NC}"
                echo -e "Options:"
                echo -e "  --debug          Build with debug symbols"
                echo -e "  --install        Install the binary after building"
                echo -e "  --clean          Clean previous builds before building"
                echo -e "  --full-clean     Remove all generated files including binaries (does not build)"
                echo -e "  --compress       Apply standard UPX compression to reduce binary size"
                echo -e "  --ultra-minimal  Apply extreme UPX compression for smallest possible binary (slower startup)"
                echo -e "  --static         Build fully static binaries (no external dependencies)"
                echo -e "  --no-tests       Skip running tests" 
                echo -e "  --run [args]     Run the scanner with enhanced security features"
                echo -e "  --clean-traces   Clean up scanner logs and artifacts"
                echo -e "  --static-build   Build a fully static binary using Docker"
                echo -e "  --help           Show this help message"
                echo -e ""
                exit 0
                ;;
            *)
                echo -e "[${RED}!${NC}] Unknown option: $1"
                exit 1
                ;;
        esac
    done
    
    # Clean if requested
    if [ "$CLEAN" = true ]; then
        echo -e "[${BLUE}*${NC}] Cleaning previous builds..."
        cargo clean --release
    fi
    
    # Handle full cleanup separately
    if [ "$FULL_CLEAN" = true ]; then
        perform_full_cleanup
        # Exit after cleanup since --full-clean doesn't build
        exit 0
    fi
    
    # Only build if we haven't used --full-clean
    if [ "$BUILD_REQUESTED" = true ]; then
        # Build the project
        build_project "$BUILD_TYPE"
        
        # Run tests if requested
        if [ "$RUN_TESTS" = true ]; then
            run_tests
        fi
        
        # Always apply binary hardening since MINIMAL is now true by default
        apply_binary_hardening
        
        # Install if requested
        if [ "$INSTALL" = true ]; then
            if [ "$BUILD_TYPE" != "release" ]; then
                echo -e "[${YELLOW}!${NC}] Warning: Installing a non-release build"
            fi
            install_binary
        fi
    fi
    
    # Run the scanner if requested
    if [ "$RUN_SCAN" = true ]; then
        echo -e "[${BLUE}*${NC}] Running Quantum Scanner..."
        sudo ./quantum_scanner "$@"
    fi
    
    # Clean traces if requested
    if [ "$CLEAN_TRACES_MODE" = true ]; then
        echo -e "[${BLUE}*${NC}] Cleaning traces and logs..."
        clean_traces
    fi
}

# Run the main function with all provided arguments
main "$@" 