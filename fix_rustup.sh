#!/bin/bash
# ======================================================================
# Fix Rustup Script - Quantum Scanner
# ======================================================================
# This script fixes the "rustup could not choose a version" error
# by installing rustup with a proper default toolchain or configuring
# an existing rustup installation with a default toolchain.
# ======================================================================

# ANSI color codes for pretty output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# Default configuration
BYPASS_TLS_SECURITY=false
TOOLCHAIN="stable"
FORCE_REMOVE_SYSTEM_RUST=false

# Function to display banner
show_banner() {
    echo -e "${BLUE}==========================================================${NC}"
    echo -e "${GREEN}  Rustup Fix Tool - Quantum Scanner${NC}"
    echo -e "${BLUE}==========================================================${NC}"
    echo -e "${YELLOW}  [!] Fixes the 'rustup could not choose a version' error${NC}"
    echo -e "${BLUE}==========================================================${NC}"
    echo ""
}

# Function to parse command line arguments
parse_args() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            --insecure)
                BYPASS_TLS_SECURITY=true
                echo -e "${YELLOW}[!] TLS certificate verification disabled - USE WITH CAUTION${NC}"
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
            --force-remove)
                FORCE_REMOVE_SYSTEM_RUST=true
                echo -e "${YELLOW}[!] Will attempt to remove system Rust installation if detected${NC}"
                shift
                ;;
            --help|-h)
                echo -e "${BLUE}Usage:${NC} $0 [options]"
                echo ""
                echo -e "${BLUE}Options:${NC}"
                echo "  --insecure     Bypass TLS certificate verification (for proxy environments)"
                echo "  --nightly      Use nightly toolchain instead of stable"
                echo "  --beta         Use beta toolchain instead of stable"
                echo "  --force-remove Remove system Rust installation if it conflicts with rustup"
                echo "  -h, --help     Show this help message"
                exit 0
                ;;
            *)
                echo -e "${RED}Unknown option:${NC} $1"
                echo -e "Use $0 --help for usage information"
                exit 1
                ;;
        esac
    done
}

# Function to set up TLS bypass if needed
configure_tls_bypass() {
    if [ "$BYPASS_TLS_SECURITY" = true ]; then
        echo -e "${YELLOW}[!] Setting up TLS certificate verification bypass...${NC}"
        echo -e "${YELLOW}[!] WARNING: This is insecure and should only be used in isolated environments${NC}"
        
        # Configure git to ignore SSL verification globally
        git config --global http.sslVerify false
        
        # Make sure ~/.cargo directory exists
        mkdir -p ~/.cargo
        
        # Create cargo config to bypass cert checks
        cat > ~/.cargo/config.toml << EOF
[http]
check-revoke = false
ssl-version = "tlsv1.2"
cainfo = ""
multiplexing = false

[net]
retry = 10
git-fetch-with-cli = true
EOF
        
        # Setup curl config to ignore SSL verification
        mkdir -p ~/.curl
        echo "insecure" > ~/.curlrc
        
        # Set environment variables for insecure SSL
        export RUSTUP_TLS_VERIFY_NONE=1
        export SSL_CERT_DIR=""
        export SSL_CERT_FILE=""
        export CURL_CA_BUNDLE=""
        export GIT_SSL_NO_VERIFY=true
        
        echo -e "${YELLOW}[!] TLS certificate verification has been disabled${NC}"
    fi
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
            echo -e "${RED}[!] Please use '--force-remove' option to remove system Rust first,${NC}"
            echo -e "${RED}[!] or manually remove it with your package manager:${NC}"
            echo -e "${GREEN}    sudo apt remove rustc cargo   # For Debian/Ubuntu${NC}"
            echo -e "${GREEN}    sudo dnf remove rust cargo    # For Fedora/RHEL${NC}"
            echo -e "${GREEN}    sudo pacman -R rust           # For Arch Linux${NC}"
            echo -e "${GREEN}    sudo zypper remove rust cargo # For openSUSE${NC}"
            echo ""
            echo -e "${RED}[!] Then run this script again.${NC}"
            return 1
        fi
    fi
    
    # If rustup is installed but rustc isn't or doesn't work properly
    if command -v rustup &> /dev/null && ! rustc --version &> /dev/null; then
        echo -e "${YELLOW}[!] Rustup is installed but rustc doesn't work correctly${NC}"
        echo -e "${BLUE}[*] This might be due to a broken rustup installation${NC}"
        
        # Check if ~/.rustup exists
        if [ -d "$HOME/.rustup" ]; then
            echo -e "${BLUE}[*] Found existing rustup installation in $HOME/.rustup${NC}"
            
            if [ "$FORCE_REMOVE_SYSTEM_RUST" = true ]; then
                echo -e "${YELLOW}[!] Removing existing rustup installation...${NC}"
                rustup self uninstall -y &>/dev/null || true
                rm -rf "$HOME/.rustup" "$HOME/.cargo" 2>/dev/null || true
                echo -e "${GREEN}[+] Existing rustup installation removed${NC}"
                return 0
            else
                echo -e "${RED}[!] Use '--force-remove' to clean up the existing rustup installation.${NC}"
                return 1
            fi
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
            echo -e "${YELLOW}[!] Checking for system Rust conflicts...${NC}"
            if command -v rustc &> /dev/null; then
                echo -e "${RED}[!] System Rust is still installed and may be conflicting.${NC}"
                echo -e "${RED}[!] Please run this script with --force-remove option.${NC}"
            fi
            return 1
        fi
    fi
}

# Main function
main() {
    # Show banner
    show_banner
    
    # Parse command line arguments
    parse_args "$@"
    
    # Configure TLS bypass if needed
    if [ "$BYPASS_TLS_SECURITY" = true ]; then
        configure_tls_bypass
    fi
    
    # Fix rustup
    fix_rustup
    
    # Final instructions for the user
    if [ $? -eq 0 ]; then
        echo ""
        echo -e "${GREEN}[+] Rustup has been successfully fixed!${NC}"
        echo -e "${BLUE}[*] You now have the ${TOOLCHAIN} toolchain installed as default${NC}"
        echo -e "${BLUE}[*] Try running your build again${NC}"
        
        # Remind to source environment variables if needed
        echo ""
        echo -e "${YELLOW}[!] If running in a different shell, remember to run:${NC}"
        echo -e "${GREEN}    source \"$HOME/.cargo/env\"${NC}"
        
        return 0
    else
        echo ""
        echo -e "${RED}[!] Failed to fix rustup${NC}"
        echo -e "${YELLOW}[!] You may need to:${NC}"
        echo -e "${YELLOW}[!] 1. Remove system Rust with --force-remove${NC}"
        echo -e "${YELLOW}[!] 2. Run rustup self uninstall manually${NC}"
        echo -e "${YELLOW}[!] 3. Clean up ~/.cargo and ~/.rustup directories${NC}"
        echo -e "${YELLOW}[!] Then try installing rustup again:${NC}"
        echo -e "${GREEN}    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh${NC}"
        
        return 1
    fi
}

# Run the main function with all arguments
main "$@" 