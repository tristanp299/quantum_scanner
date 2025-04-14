#!/bin/bash
# ======================================================================
# Quantum Scanner - Consolidated Build Script
# ======================================================================
# This script consolidates all build functionality in one place, handling:
# - Dependency installation
# - Rustup/toolchain fixes
# - Docker certificate issues
# - TLS/SSL verification bypass when needed
# - Static builds via Docker or direct musl
# - Binary optimization (stripping, UPX compression)
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
INSTALL_DEPS=false       # Whether to install dependencies
FIX_DOCKER=false         # Whether to fix Docker certificates
TOOLCHAIN="stable"       # Default Rust toolchain to use
FORCE_REMOVE_SYSTEM_RUST=false # Whether to force remove system Rust

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
    echo "  --install-deps        Install all required dependencies"
    echo "  --fix-docker          Fix Docker certificate issues (run as root)"
    echo "  --nightly             Use nightly toolchain instead of stable"
    echo "  --beta                Use beta toolchain instead of stable"
    echo "  --force-remove-rust   Remove system Rust installation if it conflicts"
    echo ""
    echo -e "${BLUE}Examples:${NC}"
    echo "  $0                    Build in release mode (default)"
    echo "  $0 --strip            Build in release mode and strip symbols"
    echo "  $0 --static           Build 100% static binary with Docker"
    echo "  $0 --insecure         Build with TLS verification disabled (for corporate proxies)"
    echo "  $0 --install-deps     Install dependencies and then build"
    echo "  $0 --fix-docker       Fix Docker certificate issues (for Kali Linux)"
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
            --install-deps)
                INSTALL_DEPS=true
                shift
                ;;
            --fix-docker)
                FIX_DOCKER=true
                shift
                ;;
            --nightly)
                TOOLCHAIN="nightly"
                echo -e "${YELLOW}[!] Using nightly toolchain${NC}"
                shift
                ;;
            --beta)
                TOOLCHAIN="beta"
                echo -e "${YELLOW}[!] Using beta toolchain${NC}"
                shift
                ;;
            --force-remove-rust)
                FORCE_REMOVE_SYSTEM_RUST=true
                echo -e "${YELLOW}[!] Will attempt to remove system Rust installation if detected${NC}"
                shift
                ;;
            *)
                echo -e "${RED}Unknown option:${NC} $1"
                show_help
                exit 1
                ;;
        esac
    done

    # Check if we need to set SSL bypass automatically based on system configuration
    if [ "$BYPASS_TLS_SECURITY" != true ]; then
        # Test connection to crates.io
        echo -e "${BLUE}[*] Testing connection to crates.io...${NC}"
        if ! curl -s --head https://static.crates.io > /dev/null; then
            echo -e "${YELLOW}[!] Connection to crates.io failed - automatically enabling TLS bypass${NC}"
            BYPASS_TLS_SECURITY=true
        else
            # Try downloading a small crate to verify SSL works
            TMP_DIR=$(mktemp -d)
            if ! curl -s -o "$TMP_DIR/test.tar.gz" https://static.crates.io/crates/semver/1.0.20/download; then
                echo -e "${YELLOW}[!] SSL certificate verification issue detected - automatically enabling TLS bypass${NC}"
                BYPASS_TLS_SECURITY=true
            fi
            rm -rf "$TMP_DIR"
        fi
    fi
}

# Function to configure insecure connections if needed
configure_tls_bypass() {
    if [ "$BYPASS_TLS_SECURITY" = true ]; then
        echo -e "${YELLOW}[!] Setting up TLS certificate verification bypass...${NC}"
        echo -e "${YELLOW}[!] WARNING: This is insecure and should only be used in isolated environments${NC}"
        
        # Configure git to ignore SSL verification globally
        git config --global http.sslVerify false
        
        # Make sure ~/.cargo directory exists
        mkdir -p ~/.cargo
        
        # Create cargo config to bypass cert checks (excluding cainfo)
        cat > ~/.cargo/config.toml << EOF
[http]
check-revoke = false
ssl-version = "tlsv1.2"
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
        
        # Setup global curl config to ignore SSL verification
        mkdir -p ~/.curl
        echo "insecure" > ~/.curlrc
        
        # Set comprehensive environment variables for insecure SSL, ensuring they are exported
        export CARGO_HTTP_CHECK_REVOKE=false
        export CARGO_NET_GIT_FETCH_WITH_CLI=true
        export CARGO_HTTP_SSL_VERSION="tlsv1.2"
        export CARGO_HTTP_MULTIPLEXING=false
        export RUSTUP_TLS_VERIFY_NONE=1
        export SSL_CERT_DIR=""
        export SSL_CERT_FILE=""
        export REQUESTS_CA_BUNDLE=""
        export CURL_CA_BUNDLE=""
        export GIT_SSL_NO_VERIFY=true
        export NODE_TLS_REJECT_UNAUTHORIZED=0
        export CARGO_HTTP_SSL_NO_VERIFY=true
        
        echo -e "${YELLOW}[!] TLS certificate verification has been disabled for this build${NC}"
    fi
}

# Function to clean artifacts
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

# Function to check and handle system Rust installation
check_system_rust() {
    echo -e "${BLUE}[*] Checking for system Rust installation...${NC}"
    
    # Check if rustc is installed but not from rustup
    if command -v rustc &> /dev/null && ! command -v rustup &> /dev/null; then
        echo -e "${YELLOW}[!] System Rust installation detected${NC}"
        
        # Get system Rust version
        RUST_VERSION=$(rustc --version 2>/dev/null || echo "Unknown")
        echo -e "${YELLOW}[!] Current system Rust version: ${RUST_VERSION}${NC}"
        
        if [ "$FORCE_REMOVE_SYSTEM_RUST" = true ]; then
            echo -e "${YELLOW}[!] Attempting to remove system Rust installation...${NC}"
            
            # Try to detect package manager and remove Rust
            if command -v apt &> /dev/null; then
                echo -e "${BLUE}[*] Removing Rust using apt...${NC}"
                sudo apt remove -y rustc cargo rust-all rust-src rust-doc &>/dev/null || true
            elif command -v dnf &> /dev/null; then
                echo -e "${BLUE}[*] Removing Rust using dnf...${NC}"
                sudo dnf remove -y rust cargo rustfmt &>/dev/null || true
            elif command -v pacman &> /dev/null; then
                echo -e "${BLUE}[*] Removing Rust using pacman...${NC}"
                sudo pacman -R rust rust-docs &>/dev/null || true
            elif command -v zypper &> /dev/null; then
                echo -e "${BLUE}[*] Removing Rust using zypper...${NC}"
                sudo zypper remove -y rust cargo &>/dev/null || true
            else
                echo -e "${RED}[!] Unknown package manager. Please manually remove the system Rust installation.${NC}"
                return 1
            fi
            
            echo -e "${GREEN}[+] System Rust packages removed${NC}"
            return 0
        else
            echo -e "${RED}[!] System Rust installation conflicts with rustup.${NC}"
            echo -e "${RED}[!] Use --force-remove-rust to remove system Rust first,${NC}"
            echo -e "${RED}[!] or manually remove it with your package manager.${NC}"
            return 1
        fi
    fi
    
    # If rustup is installed but rustc isn't or doesn't work properly
    if command -v rustup &> /dev/null && ! rustc --version &> /dev/null; then
        echo -e "${YELLOW}[!] Rustup is installed but rustc doesn't work correctly${NC}"
        
        if [ "$FORCE_REMOVE_SYSTEM_RUST" = true ]; then
            echo -e "${YELLOW}[!] Removing existing rustup installation...${NC}"
            rustup self uninstall -y &>/dev/null || true
            rm -rf "$HOME/.rustup" "$HOME/.cargo" 2>/dev/null || true
            echo -e "${GREEN}[+] Existing rustup installation removed${NC}"
            return 0
        else
            echo -e "${RED}[!] Use --force-remove-rust to clean up the existing rustup installation.${NC}"
            return 1
        fi
    fi
    
    return 0
}

# Function to ensure rustup is installed with a default toolchain
fix_rustup() {
    # First check for system Rust installation
    check_system_rust
    if [ $? -ne 0 ]; then
        return 1
    fi
    
    # Check if rustup is already installed
    if command -v rustup &> /dev/null; then
        echo -e "${BLUE}[*] Rustup is already installed${NC}"
        
        # Check if we have a default toolchain
        if rustup default 2>/dev/null | grep -q "stable\|nightly\|beta"; then
            echo -e "${GREEN}[+] Rustup already has a default toolchain configured${NC}"
            rustup default
            echo -e "${BLUE}[*] Checking rust version...${NC}"
            rustc --version
            return 0
        else
            echo -e "${YELLOW}[!] No default rustup toolchain found, installing ${TOOLCHAIN}...${NC}"
            
            # Install the toolchain with appropriate TLS settings
            if [ "$BYPASS_TLS_SECURITY" = true ]; then
                RUSTUP_TLS_VERIFY_NONE=1 rustup toolchain install ${TOOLCHAIN} --profile minimal
                RUSTUP_TLS_VERIFY_NONE=1 rustup default ${TOOLCHAIN}
            else
                rustup toolchain install ${TOOLCHAIN} --profile minimal
                rustup default ${TOOLCHAIN}
            fi
            
            # Verify installation
            if rustup default 2>/dev/null | grep -q "${TOOLCHAIN}"; then
                echo -e "${GREEN}[+] Successfully configured rustup with ${TOOLCHAIN} toolchain${NC}"
                rustc --version
                return 0
            else
                echo -e "${RED}[!] Failed to set default rustup toolchain${NC}"
                return 1
            fi
        fi
    else
        echo -e "${YELLOW}[!] Rustup not found, installing...${NC}"
        
        # Use appropriate installation method based on TLS bypass setting
        if [ "$BYPASS_TLS_SECURITY" = true ]; then
            echo -e "${YELLOW}[!] Installing rustup with insecure mode${NC}"
            curl -k --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | RUSTUP_TLS_VERIFY_NONE=1 sh -s -- -y --default-toolchain ${TOOLCHAIN}
        else
            curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain ${TOOLCHAIN}
        fi
        
        # Make sure cargo environment variables are set
        source "$HOME/.cargo/env"
        
        # Verify installation
        if command -v rustup &> /dev/null && rustup default 2>/dev/null | grep -q "${TOOLCHAIN}"; then
            echo -e "${GREEN}[+] Successfully installed rustup with ${TOOLCHAIN} toolchain${NC}"
            rustc --version
            return 0
        else
            echo -e "${RED}[!] Failed to install rustup properly${NC}"
            return 1
        fi
    fi
}

# Function to fix Docker certificate issues
fix_docker_certs() {
    echo -e "${BLUE}[*] Fixing Docker certificate issues...${NC}"

    # Check if running as root
    if [ "$EUID" -ne 0 ]; then
      echo -e "${YELLOW}[!] Docker certificate fix requires root privileges${NC}"
      echo -e "${YELLOW}[!] Please run with sudo: sudo $0 --fix-docker${NC}"
      return 1
    fi

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

    # Ensure Docker daemon config exists and has proper settings
    DOCKER_CONFIG_DIR="/etc/docker"
    DOCKER_CONFIG_FILE="$DOCKER_CONFIG_DIR/daemon.json"

    # Create or update Docker daemon config
    if [ ! -f "$DOCKER_CONFIG_FILE" ]; then
        echo -e "${BLUE}[*] Creating Docker daemon configuration...${NC}"
        echo '{
  "insecure-registries": ["docker.io", "registry.docker.io", "registry-1.docker.io", "index.docker.io"],
  "allow-nondistributable-artifacts": ["docker.io", "registry.docker.io", "registry-1.docker.io", "index.docker.io"],
  "dns": ["8.8.8.8", "8.8.4.4"],
  "log-driver": "json-file",
  "log-opts": {
    "max-size": "10m",
    "max-file": "3"
  }
}' > "$DOCKER_CONFIG_FILE"
    else
        # Create a backup before modifying
        cp "$DOCKER_CONFIG_FILE" "$DOCKER_CONFIG_FILE.bak"
        
        # Create a new configuration file with required settings
        echo '{
  "insecure-registries": ["docker.io", "registry.docker.io", "registry-1.docker.io", "index.docker.io"],
  "allow-nondistributable-artifacts": ["docker.io", "registry.docker.io", "registry-1.docker.io", "index.docker.io"],
  "dns": ["8.8.8.8", "8.8.4.4"],
  "log-driver": "json-file",
  "log-opts": {
    "max-size": "10m",
    "max-file": "3"
  }
}' > "$DOCKER_CONFIG_FILE"
    fi

    # Add Docker registry entries to /etc/hosts if not already present
    if ! grep -q "registry-1.docker.io" /etc/hosts; then
        echo -e "${BLUE}[*] Adding Docker registry to /etc/hosts...${NC}"
        echo "# Docker registry hosts for certificate handling" >> /etc/hosts
        echo "44.194.136.173  registry-1.docker.io" >> /etc/hosts
        echo "3.213.10.128    auth.docker.io" >> /etc/hosts
    fi

    # Restart Docker service if it exists
    if systemctl list-units --full -all | grep -q "docker.service"; then
        echo -e "${BLUE}[*] Restarting Docker service...${NC}"
        systemctl restart docker
    else
        echo -e "${YELLOW}[!] Docker service not found, you may need to install Docker first${NC}"
    fi

    echo -e "${GREEN}[+] Docker certificate issues fixed!${NC}"
    return 0
}

# Function to install dependencies
install_dependencies() {
    echo -e "${BLUE}[*] Installing dependencies for Quantum Scanner...${NC}"
    
    # Detect OS type
    if [ -f /etc/debian_version ]; then
        echo -e "${BLUE}[*] Detected Debian/Ubuntu-based system${NC}"
        
        # Update package lists
        echo -e "${BLUE}[*] Updating package lists...${NC}"
        sudo apt-get update -qq
        
        # Install build dependencies
        echo -e "${BLUE}[*] Installing build dependencies...${NC}"
        sudo apt-get install -y build-essential pkg-config libssl-dev libpcap-dev
        
        # Install additional tools
        echo -e "${BLUE}[*] Installing additional tools...${NC}"
        sudo apt-get install -y curl git
        
        # Install musl for static builds
        if [ "$STATIC_BUILD" = true ]; then
            echo -e "${BLUE}[*] Installing musl toolchain for static builds...${NC}"
            sudo apt-get install -y musl-tools musl-dev
        fi
        
        # Install Docker if needed for static builds
        if [ "$STATIC_BUILD" = true ] && ! command -v docker &> /dev/null; then
            echo -e "${BLUE}[*] Docker not found, installing...${NC}"
            sudo apt-get install -y docker.io
            sudo systemctl enable docker
            sudo systemctl start docker
            sudo usermod -aG docker $USER
            echo -e "${YELLOW}[!] You may need to log out and back in for Docker permissions to take effect${NC}"
        fi
        
        # Install UPX if compression is enabled
        if [ "$COMPRESS_BINARY" = true ] && ! command -v upx &> /dev/null; then
            echo -e "${BLUE}[*] Installing UPX...${NC}"
            sudo apt-get install -y upx-ucl || sudo apt-get install -y upx
        fi
        
    # Check for Red Hat/Fedora
    elif [ -f /etc/redhat-release ]; then
        echo -e "${BLUE}[*] Detected Red Hat/Fedora-based system${NC}"
        
        # Install build dependencies
        echo -e "${BLUE}[*] Installing build dependencies...${NC}"
        sudo dnf install -y gcc make pkgconfig openssl-devel libpcap-devel
        
        # Install additional tools
        echo -e "${BLUE}[*] Installing additional tools...${NC}"
        sudo dnf install -y curl git
        
        # Install musl for static builds
        if [ "$STATIC_BUILD" = true ]; then
            echo -e "${BLUE}[*] Installing musl toolchain for static builds...${NC}"
            sudo dnf install -y musl-devel
        fi
        
        # Install Docker if needed for static builds
        if [ "$STATIC_BUILD" = true ] && ! command -v docker &> /dev/null; then
            echo -e "${BLUE}[*] Docker not found, installing...${NC}"
            sudo dnf install -y docker
            sudo systemctl enable docker
            sudo systemctl start docker
            sudo usermod -aG docker $USER
            echo -e "${YELLOW}[!] You may need to log out and back in for Docker permissions to take effect${NC}"
        fi
        
        # Install UPX if compression is enabled
        if [ "$COMPRESS_BINARY" = true ] && ! command -v upx &> /dev/null; then
            echo -e "${BLUE}[*] Installing UPX...${NC}"
            sudo dnf install -y upx
        fi
        
    # Check for Arch Linux
    elif [ -f /etc/arch-release ]; then
        echo -e "${BLUE}[*] Detected Arch Linux-based system${NC}"
        
        # Install build dependencies
        echo -e "${BLUE}[*] Installing build dependencies...${NC}"
        sudo pacman -S --needed --noconfirm base-devel openssl libpcap
        
        # Install additional tools
        echo -e "${BLUE}[*] Installing additional tools...${NC}"
        sudo pacman -S --needed --noconfirm curl git
        
        # Install musl for static builds
        if [ "$STATIC_BUILD" = true ]; then
            echo -e "${BLUE}[*] Installing musl toolchain for static builds...${NC}"
            sudo pacman -S --needed --noconfirm musl
        fi
        
        # Install Docker if needed for static builds
        if [ "$STATIC_BUILD" = true ] && ! command -v docker &> /dev/null; then
            echo -e "${BLUE}[*] Docker not found, installing...${NC}"
            sudo pacman -S --needed --noconfirm docker
            sudo systemctl enable docker
            sudo systemctl start docker
            sudo usermod -aG docker $USER
            echo -e "${YELLOW}[!] You may need to log out and back in for Docker permissions to take effect${NC}"
        fi
        
        # Install UPX if compression is enabled
        if [ "$COMPRESS_BINARY" = true ] && ! command -v upx &> /dev/null; then
            echo -e "${BLUE}[*] Installing UPX...${NC}"
            sudo pacman -S --needed --noconfirm upx
        fi
        
    else
        echo -e "${RED}[!] Unsupported Linux distribution${NC}"
        echo -e "${YELLOW}[!] Please install the following packages manually:${NC}"
        echo "  - build-essential or equivalent"
        echo "  - pkg-config"
        echo "  - libssl-dev"
        echo "  - libpcap-dev"
        echo "  - musl-tools (for static builds)"
        echo "  - docker (for Docker-based static builds)"
        echo "  - upx (for binary compression)"
        return 1
    fi
    
    echo -e "${GREEN}[+] Dependencies installed successfully!${NC}"
    return 0
}

# Function to build the project using standard cargo
build_project() {
    echo -e "${BLUE}[*] Building project in release mode...${NC}"
    
    # Configure TLS bypass if needed
    if [ "$BYPASS_TLS_SECURITY" = true ]; then
        configure_tls_bypass
    fi
    
    # Run the build with SSL environment variables if needed
    if [ "$BYPASS_TLS_SECURITY" = true ]; then
        # Clean first if this is an insecure build to avoid previous build artifacts
        cargo clean || true
        
        # Save the original Cargo.toml
        cp Cargo.toml Cargo.toml.bak
        
        # Modify Cargo.toml to avoid x509-parser dependency
        echo -e "${BLUE}[*] Modifying Cargo.toml to work around dependency issues...${NC}"
        
        # Set default features to exclude x509-parser to avoid asn1-rs-derive proc-macro
        sed -i 's/default = \["x509-parser"\]/default = \["insecure-tls"\]/' Cargo.toml
                
        # Configure TLS bypass environment variables
        echo -e "${BLUE}[*] Building with SSL verification disabled...${NC}"
        
        # Export environment variables for current shell session
        export RUSTC_BOOTSTRAP=1
        export CARGO_HTTP_CHECK_REVOKE=false
        export CARGO_NET_GIT_FETCH_WITH_CLI=true
        export CARGO_HTTP_SSL_VERSION="tlsv1.2"
        export CARGO_HTTP_MULTIPLEXING=false
        export RUSTUP_TLS_VERIFY_NONE=1
        export SSL_CERT_DIR=""
        export SSL_CERT_FILE=""
        export REQUESTS_CA_BUNDLE=""
        export CURL_CA_BUNDLE=""
        export GIT_SSL_NO_VERIFY=true
        export NODE_TLS_REJECT_UNAUTHORIZED=0
        export CARGO_HTTP_SSL_NO_VERIFY=true
        
        # Build with default features and insecure-tls
        cargo build --release
        BUILD_RESULT=$?
        
        # Restore original Cargo.toml regardless of result
        mv Cargo.toml.bak Cargo.toml
        
        if [ $BUILD_RESULT -eq 0 ]; then
            echo -e "${GREEN}[+] Insecure build completed successfully${NC}"
            cp target/release/quantum_scanner ./quantum_scanner
            chmod +x ./quantum_scanner
            return 0
        else
            echo -e "${RED}[!] Insecure build failed${NC}"
            return 1
        fi
    else
        # Standard build - capture output to check for SSL errors
        BUILD_OUTPUT=$(cargo build --release 2>&1)
        BUILD_RESULT=$?
        
        if [ $BUILD_RESULT -eq 0 ]; then
            echo -e "${GREEN}[+] Build completed successfully${NC}"
            cp target/release/quantum_scanner ./quantum_scanner
            chmod +x ./quantum_scanner
            return 0
        else
            # Check if the error is SSL related
            if echo "$BUILD_OUTPUT" | grep -q "SSL CA cert\|certificate verify\|SSL connection\|HTTPS protocol error"; then
                echo -e "${YELLOW}[!] SSL certificate verification issue detected during build${NC}"
                echo -e "${YELLOW}[!] Retrying build with SSL verification disabled...${NC}"

                # Enable SSL bypass and try again
                BYPASS_TLS_SECURITY=true
                configure_tls_bypass

                # Build with SSL verification disabled using default features
                echo -e "${BLUE}[*] Building with SSL verification disabled...${NC}"
                cargo build --release
                BUILD_RESULT=$?

                if [ $BUILD_RESULT -eq 0 ]; then
                    echo -e "${GREEN}[+] Build with SSL bypass completed successfully${NC}"
                    cp target/release/quantum_scanner ./quantum_scanner
                    chmod +x ./quantum_scanner
                    return 0
                else
                    echo -e "${RED}[!] Build failed even with SSL bypass${NC}"
                    return 1
                fi
            else
                echo -e "${RED}[!] Build failed${NC}"
                echo -e "${RED}[!] Error output:${NC}"
                echo -e "$BUILD_OUTPUT" | tail -n 20
                return 1
            fi
        fi
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
    
    # Extract the binary from the image
    echo -e "${BLUE}[*] Extracting static binary...${NC}"
    docker create --name quantum_tmp quantum_scanner_static >/dev/null
    docker cp quantum_tmp:/quantum_scanner ./quantum_scanner
    docker rm quantum_tmp >/dev/null
    chmod +x ./quantum_scanner
    
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
    fix_rustup
    
    # Configure TLS bypass if needed
    if [ "$BYPASS_TLS_SECURITY" = true ]; then
        configure_tls_bypass
    fi
    
    # Add musl target
    echo -e "${BLUE}[*] Adding musl target...${NC}"
    rustup target add x86_64-unknown-linux-musl
    
    # Build with musl target
    if [ "$BYPASS_TLS_SECURITY" = true ]; then
        echo -e "${BLUE}[*] Setting up insecure build with musl...${NC}"
        cp Cargo.toml Cargo.toml.bak
        sed -i 's/default = \["full"\]/default = \["minimal-static", "insecure-tls"\]/' Cargo.toml
        
        # Build with musl target and insecure flags
        echo -e "${BLUE}[*] Building with musl target and insecure flags...${NC}"
        RUSTFLAGS="-C target-feature=+crt-static" SSL_CERT_FILE="" RUSTUP_TLS_VERIFY_NONE=1 cargo build --release --target=x86_64-unknown-linux-musl --no-default-features --features "minimal-static,insecure-tls"
        BUILD_RESULT=$?
        
        # Restore original Cargo.toml
        mv Cargo.toml.bak Cargo.toml
        
        if [ $BUILD_RESULT -ne 0 ]; then
            echo -e "${RED}[!] Static build failed${NC}"
            return 1
        fi
    else
        # Standard static build with musl
        echo -e "${BLUE}[*] Building with musl target...${NC}"
        RUSTFLAGS="-C target-feature=+crt-static" cargo build --release --target=x86_64-unknown-linux-musl
        BUILD_RESULT=$?
        
        if [ $BUILD_RESULT -ne 0 ]; then
            # Try with SSL bypass
            echo -e "${YELLOW}[!] Build failed, trying with SSL verification disabled...${NC}"
            BYPASS_TLS_SECURITY=true
            configure_tls_bypass
            
            # Save the original Cargo.toml
            cp Cargo.toml Cargo.toml.bak
            
            # Modify Cargo.toml for insecure build
            echo -e "${BLUE}[*] Modifying Cargo.toml for insecure build...${NC}"
            sed -i 's/default = \["full"\]/default = \["minimal-static", "insecure-tls"\]/' Cargo.toml
            
            # Build with SSL verification disabled
            echo -e "${BLUE}[*] Building with musl target and SSL verification disabled...${NC}"
            RUSTFLAGS="-C target-feature=+crt-static" SSL_CERT_FILE="" RUSTUP_TLS_VERIFY_NONE=1 cargo build --release --target=x86_64-unknown-linux-musl --no-default-features --features "minimal-static,insecure-tls"
            BUILD_RESULT=$?
            
            # Restore original Cargo.toml
            mv Cargo.toml.bak Cargo.toml
            
            if [ $BUILD_RESULT -ne 0 ]; then
                echo -e "${RED}[!] Static build failed even with SSL bypass${NC}"
                return 1
            fi
        fi
    fi
    
    # Copy binary to root directory
    cp target/x86_64-unknown-linux-musl/release/quantum_scanner ./quantum_scanner
    chmod +x ./quantum_scanner
    
    # Show binary size
    BIN_SIZE=$(du -h ./quantum_scanner | cut -f1)
    echo -e "${GREEN}[+] Final static binary size: ${YELLOW}$BIN_SIZE${NC}"
    
    return 0
}

# Function to apply binary hardening
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
    
    # Fix Docker certificates if requested
    if [ "$FIX_DOCKER" = true ]; then
        fix_docker_certs
        # Exit if we were only fixing Docker
        if [ $? -eq 0 ] && [ "$INSTALL_DEPS" != true ]; then
            exit 0
        fi
    fi
    
    # Install dependencies if requested
    if [ "$INSTALL_DEPS" = true ]; then
        install_dependencies
        if [ $? -ne 0 ]; then
            echo -e "${RED}[!] Failed to install dependencies${NC}"
            exit 1
        fi
    fi
    
    # Fix rustup if needed
    if ! command -v rustc &> /dev/null || ! command -v rustup &> /dev/null; then
        echo -e "${YELLOW}[!] Rust toolchain issues detected, fixing...${NC}"
        fix_rustup
        if [ $? -ne 0 ]; then
            echo -e "${RED}[!] Failed to fix Rust toolchain${NC}"
            exit 1
        fi
    fi
    
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
    BUILD_RESULT=$?
    
    # Apply binary hardening if build was successful
    if [ $BUILD_RESULT -eq 0 ]; then
        apply_binary_hardening
        echo -e "${GREEN}[+] Build process completed successfully${NC}"
        echo -e "${GREEN}[+] Binary location: ${YELLOW}$(pwd)/quantum_scanner${NC}"
        
        # Verification step - just to confirm everything worked
        if [ -f "./quantum_scanner" ] && [ -x "./quantum_scanner" ]; then
            echo -e "${GREEN}[+] Build verification: Binary exists and is executable${NC}"
            
            # Check if it's static (optional)
            if command -v ldd &> /dev/null; then
                LDD_OUTPUT=$(ldd ./quantum_scanner 2>&1)
                if [[ "$LDD_OUTPUT" == *"not a dynamic executable"* ]]; then
                    echo -e "${GREEN}[+] Build verification: Binary is statically linked${NC}"
                fi
            fi
        else
            echo -e "${RED}[!] Build verification failed: Binary is missing or not executable${NC}"
            exit 1
        fi
    else
        echo -e "${RED}[!] Build process failed${NC}"
        exit 1
    fi
}

# Run the main function with all arguments
main "$@" 