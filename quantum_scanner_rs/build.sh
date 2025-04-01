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
COMPRESS_BINARY=true  # Set to "false" to skip UPX compression
LOCAL_TEST_TARGET="127.0.0.1"  # Use loopback for safety

# ======================================================================
# FUNCTIONS
# ======================================================================

# Display banner
show_banner() {
    echo -e "${BLUE}┌────────────────────────────────────────────────┐${NC}"
    echo -e "${BLUE}│     ${GREEN}Quantum Scanner${BLUE} - ${YELLOW}Build Script${BLUE}            │${NC}"
    echo -e "${BLUE}└────────────────────────────────────────────────┘${NC}"
}

# Log messages with timestamp and color
log() {
    local level=$1
    local message=$2
    local color=$NC
    local timestamp=$(date +"%Y-%m-%d %H:%M:%S")
    
    case $level in
        "INFO") color=$GREEN ;;
        "WARN") color=$YELLOW ;;
        "ERROR") color=$RED ;;
        "STEP") color=$BLUE ;;
    esac
    
    echo -e "${color}[${timestamp}] [${level}] ${message}${NC}"
}

# Check if a command exists
check_cmd() {
    if ! command -v $1 &> /dev/null; then
        log "ERROR" "Required command '$1' not found. Please install it."
        exit 1
    fi
}

# Secure deletion of files
secure_delete() {
    log "INFO" "Securely cleaning up artifacts..."
    if command -v shred &> /dev/null; then
        find . -name "*.o" -exec shred -u {} \; 2>/dev/null || true
        find . -name "*.d" -exec shred -u {} \; 2>/dev/null || true
        find . -name "*.gcda" -exec shred -u {} \; 2>/dev/null || true
        find . -name "*.gcno" -exec shred -u {} \; 2>/dev/null || true
    else
        # Fallback to less secure but still better than nothing
        find . -name "*.o" -delete 2>/dev/null || true
        find . -name "*.d" -delete 2>/dev/null || true
        find . -name "*.gcda" -delete 2>/dev/null || true
        find . -name "*.gcno" -delete 2>/dev/null || true
    fi
}

# Function to check for essential build tools
check_dependencies() {
    echo -e "[${GREEN}+${NC}] Checking build dependencies..."
    
    # Check for Rust and Cargo
    if ! command -v cargo &> /dev/null; then
        echo -e "[${RED}!${NC}] Rust and Cargo are required but not installed."
        echo -e "    Install with: curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh"
        exit 1
    fi
    
    # Check for libpcap development files
    if ! pkg-config --exists libpcap 2>/dev/null; then
        echo -e "[${YELLOW}!${NC}] libpcap development files not found"
        echo -e "    On Debian/Ubuntu: sudo apt install libpcap-dev"
        echo -e "    On RHEL/Fedora: sudo dnf install libpcap-devel"
        echo -e "    On Arch: sudo pacman -S libpcap"
        exit 1
    fi
    
    echo -e "[${GREEN}+${NC}] All dependencies satisfied"
}

# Function to clean previous builds
clean_build() {
    echo -e "[${GREEN}+${NC}] Cleaning previous builds..."
    cargo clean
}

# Function for full cleanup (removing all artifacts including binaries)
full_clean() {
    echo -e "[${GREEN}+${NC}] Performing full cleanup (removing all artifacts and binaries)..."
    cargo clean
    rm -rf ./target
    rm -f ./quantum_scanner
    echo -e "[${GREEN}+${NC}] Full cleanup completed."
}

# Function for security checks before build
security_checks() {
    echo -e "[${GREEN}+${NC}] Performing pre-build security checks..."
    
    # Check for Cargo Audit tool and install if needed
    if ! command -v cargo-audit &> /dev/null; then
        echo -e "[${YELLOW}!${NC}] cargo-audit not found, installing..."
        cargo install cargo-audit
    fi
    
    # Run cargo audit to check for vulnerable dependencies
    echo -e "[${GREEN}+${NC}] Checking for vulnerable dependencies with cargo-audit..."
    cargo audit || {
        echo -e "[${YELLOW}!${NC}] Warning: Security issues found in dependencies"
        echo -e "    Review the issues above and consider updating dependencies"
        read -p "Continue with build? (y/n): " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            echo -e "[${RED}!${NC}] Build aborted due to security concerns"
            exit 1
        fi
    }
    
    echo -e "[${GREEN}+${NC}] Security checks completed"
}

# Function to build the project
build_project() {
    BUILD_TYPE=$1
    
    echo -e "[${GREEN}+${NC}] Building Quantum Scanner (${BUILD_TYPE} build)..."
    
    if [ "$BUILD_TYPE" == "release" ]; then
        # Release build with optimizations
        cargo build --release
        
        if [ $? -eq 0 ]; then
            echo -e "[${GREEN}+${NC}] Release build completed successfully"
            echo -e "[${GREEN}+${NC}] Binary location: ${PWD}/target/release/quantum_scanner"
        else
            echo -e "[${RED}!${NC}] Release build failed"
            exit 1
        fi
    elif [ "$BUILD_TYPE" == "debug" ]; then
        # Debug build
        cargo build
        
        if [ $? -eq 0 ]; then
            echo -e "[${GREEN}+${NC}] Debug build completed successfully"
            echo -e "[${GREEN}+${NC}] Binary location: ${PWD}/target/debug/quantum_scanner"
        else
            echo -e "[${RED}!${NC}] Debug build failed"
            exit 1
        fi
    fi
}

# Function to run tests
run_tests() {
    echo -e "[${GREEN}+${NC}] Running tests..."
    
    # Run unit tests
    cargo test --release
    
    # Test basic functionality
    echo -e "[${GREEN}+${NC}] Testing command-line parsing..."
    
    local binary_path=""
    if [ "$BUILD_TYPE" == "release" ]; then
        binary_path="./target/release/quantum_scanner"
    else
        binary_path="./target/debug/quantum_scanner"
    fi
    
    "$binary_path" --help | grep -q "USAGE:" && \
        echo -e "[${GREEN}+${NC}] Command-line help works correctly" || \
        echo -e "[${RED}!${NC}] Command-line help failed"
    
    # Local scan test (only if running as root)
    if [ "$(id -u)" -eq 0 ]; then
        echo -e "[${GREEN}+${NC}] Running minimal local scan test..."
        "$binary_path" -p 80 -s syn --rate 10 --timeout 1 $LOCAL_TEST_TARGET > /dev/null && \
            echo -e "[${GREEN}+${NC}] Basic scan functionality working" || \
            echo -e "[${YELLOW}!${NC}] Basic scan test failed - check permissions and network"
    else
        echo -e "[${YELLOW}!${NC}] Skipping scan test: raw socket operations require root privileges"
        echo -e "    Run as root to enable scan tests: sudo $0"
    fi
}

# Function to apply binary hardening techniques
apply_binary_hardening() {
    BINARY_PATH=""
    if [ "$BUILD_TYPE" = "release" ]; then
        BINARY_PATH="./target/release/quantum_scanner"
    else
        BINARY_PATH="./target/debug/quantum_scanner"
    fi
    
    echo -e "[${BLUE}*${NC}] Applying binary hardening techniques..."
    
    # Strip debug symbols
    echo -e "[${GREEN}+${NC}] Stripping debug symbols and other metadata..."
    strip -s "$BINARY_PATH" 2>/dev/null || echo -e "[${YELLOW}!${NC}] Stripping failed, continuing without it."
    
    # Apply UPX compression
    if command -v upx &> /dev/null; then
        echo -e "[${GREEN}+${NC}] Applying UPX compression to reduce binary size..."
        
        if [ "$ULTRA_MINIMAL" = true ]; then
            echo -e "[${YELLOW}!${NC}] Using extreme compression (may slow startup time)..."
            upx --best --ultra-brute "$BINARY_PATH" 2>/dev/null || echo -e "[${YELLOW}!${NC}] UPX compression failed, continuing without it."
        else
            upx --best "$BINARY_PATH" 2>/dev/null || echo -e "[${YELLOW}!${NC}] UPX compression failed, continuing without it."
        fi
    else
        echo -e "[${YELLOW}!${NC}] UPX not found. Install UPX for better compression: sudo apt install upx"
    fi
    
    # Apply sstrip for even more aggressive stripping if available
    if command -v sstrip &> /dev/null && [ "$ULTRA_MINIMAL" = true ]; then
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

# Function to install the binary
install_binary() {
    echo -e "[${GREEN}+${NC}] Installing quantum_scanner..."
    
    # Check for root privileges for system-wide installation
    if [ "$EUID" -ne 0 ]; then
        # Install to user's ~/.local/bin if not root
        INSTALL_DIR="$HOME/.local/bin"
        mkdir -p "$INSTALL_DIR"
        
        cp target/release/quantum_scanner "$INSTALL_DIR/"
        
        if [ $? -eq 0 ]; then
            echo -e "[${GREEN}+${NC}] Installed to $INSTALL_DIR/quantum_scanner"
            
            # Check if ~/.local/bin is in PATH
            if [[ ":$PATH:" != *":$INSTALL_DIR:"* ]]; then
                echo -e "[${YELLOW}!${NC}] $INSTALL_DIR is not in your PATH"
                echo -e "    Consider adding: export PATH=\"\$PATH:$INSTALL_DIR\" to your shell profile"
            fi
        else
            echo -e "[${RED}!${NC}] Installation failed"
            exit 1
        fi
    else
        # System-wide installation
        cp target/release/quantum_scanner /usr/local/bin/
        
        if [ $? -eq 0 ]; then
            echo -e "[${GREEN}+${NC}] Installed to /usr/local/bin/quantum_scanner"
        else
            echo -e "[${RED}!${NC}] Installation failed"
            exit 1
        fi
    fi
}

# Create operational security scripts
create_opsec_scripts() {
    echo -e "[${GREEN}+${NC}] Creating operational security scripts..."
    
    # Create run_scanner.sh
    cat > "run_scanner.sh" << 'EOF'
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
EOF

    chmod +x "run_scanner.sh"
    
    # Create clean_traces.sh
    cat > "clean_traces.sh" << 'EOF'
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
EOF

    chmod +x "clean_traces.sh"
    echo -e "[${GREEN}+${NC}] Created operational security scripts"
}

# Function to display usage examples
print_usage() {
    echo -e "${YELLOW}Usage Examples:${NC}"
    echo -e "  ${GREEN}Basic SYN scan:${NC}"
    echo -e "    quantum_scanner 192.168.1.1"
    echo -e ""
    echo -e "  ${GREEN}Scan with specific ports:${NC}"
    echo -e "    quantum_scanner --ports 22,80,443,8080 192.168.1.1"
    echo -e ""
    echo -e "  ${GREEN}Scan top 100 most common ports:${NC}"
    echo -e "    quantum_scanner --top-100 192.168.1.1"
    echo -e ""
    echo -e "  ${GREEN}Multiple scan techniques:${NC}"
    echo -e "    quantum_scanner --scan-types syn,ack,fin 192.168.1.1"
    echo -e ""
    echo -e "  ${GREEN}Memory-only mode with enhanced evasion:${NC}"
    echo -e "    quantum_scanner --memory-only --enhanced-evasion 192.168.1.1"
    echo -e ""
    echo -e "  ${GREEN}Scan with protocol mimicry:${NC}"
    echo -e "    quantum_scanner --scan-types mimic --mimic-protocol HTTP 192.168.1.1"
    echo -e ""
    echo -e "  ${GREEN}Save results to file:${NC}"
    echo -e "    quantum_scanner --output results.txt 192.168.1.1"
    echo -e ""
    echo -e "  ${GREEN}Full scan with all security features:${NC}"
    echo -e "    quantum_scanner --enhanced-evasion --top-100 --use-tor 192.168.1.1"
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
    MINIMAL=false
    ULTRA_MINIMAL=false
    STATIC=false
    RUN_TESTS=true
    
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
                shift
                ;;
            --minimal)
                MINIMAL=true
                shift
                ;;
            --ultra-minimal)
                ULTRA_MINIMAL=true
                MINIMAL=true
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
            --help)
                echo -e "${YELLOW}Quantum Scanner Build Script${NC}"
                echo -e "Options:"
                echo -e "  --debug          Build with debug symbols"
                echo -e "  --install        Install the binary after building"
                echo -e "  --clean          Clean previous builds before building"
                echo -e "  --full-clean     Remove all generated files including binaries"
                echo -e "  --minimal        Build minimal size binaries with UPX compression"
                echo -e "  --ultra-minimal  Build extremely small binaries (slower startup)"
                echo -e "  --static         Build fully static binaries (no external dependencies)"
                echo -e "  --no-tests       Skip running tests"
                echo -e "  --help           Show this help message"
                exit 0
                ;;
            *)
                echo -e "[${RED}!${NC}] Unknown option: $1"
                exit 1
                ;;
        esac
    done
    
    # Execute appropriate action based on options
    if [ "$FULL_CLEAN" = true ]; then
        full_clean
        exit 0
    fi
    
    if [ "$CLEAN" = true ]; then
        clean_build
        # Only exit if no other build options specified
        if [ "$BUILD_TYPE" = "release" ] && [ "$INSTALL" = false ] && [ "$MINIMAL" = false ] && [ "$STATIC" = false ]; then
            echo -e "[${GREEN}+${NC}] Clean completed."
            exit 0
        fi
    fi
    
    # Check for required dependencies
    check_dependencies
    
    # Perform security checks
    security_checks
    
    # Set build flags based on options
    if [ "$STATIC" = true ]; then
        echo -e "[${BLUE}*${NC}] Building with static linking for maximum portability..."
        # Set environment variables for static linking
        export RUSTFLAGS="-C target-feature=+crt-static -C link-self-contained=yes -C prefer-dynamic=no"
    else
        # Standard optimization flags
        export RUSTFLAGS="-C opt-level=3 -C target-cpu=native -C lto=thin"
    fi
    
    # Build the project
    build_project "$BUILD_TYPE"
    
    # Run tests if requested
    if [ "$RUN_TESTS" = true ]; then
        run_tests
    fi
    
    # Apply binary hardening if requested
    if [ "$MINIMAL" = true ]; then
        apply_binary_hardening
    fi
    
    # Install if requested
    if [ "$INSTALL" = true ]; then
        if [ "$BUILD_TYPE" != "release" ]; then
            echo -e "[${YELLOW}!${NC}] Warning: Installing a non-release build"
        fi
        install_binary
    fi
    
    # Create OpSec scripts
    create_opsec_scripts
    
    # Print usage examples
    echo -e "${BLUE}════════════════════════════════════════════${NC}"
    print_usage
    echo -e "${BLUE}════════════════════════════════════════════${NC}"
    echo -e "${GREEN}Build completed successfully!${NC}"
    
    # Print additional info
    echo -e "[${GREEN}+${NC}] To run the scanner with enhanced security: ./run_scanner.sh [options] <target>"
    echo -e "[${GREEN}+${NC}] To clean up after usage: ./clean_traces.sh"
}

# Run the main function with all provided arguments
main "$@" 