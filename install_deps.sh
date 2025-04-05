#!/bin/bash
# Install dependencies for Quantum Scanner
# =================================================================
# This script installs all required dependencies for building the
# quantum_scanner project, including static libraries for musl builds.
# =================================================================

# ANSI color codes for pretty output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo -e "${BLUE}===========================================================${NC}"
echo -e "${GREEN}  Installing dependencies for Quantum Scanner${NC}"
echo -e "${BLUE}===========================================================${NC}"

# Ask for sudo access upfront
echo -e "${YELLOW}[!] This script requires sudo privileges to install packages${NC}"
sudo -v

# Check if Ubuntu/Debian based
if [ -f /etc/debian_version ]; then
    echo -e "${BLUE}[*] Detected Debian/Ubuntu-based system${NC}"
    echo -e "${BLUE}[*] Updating package lists...${NC}"
    sudo apt-get update

    echo -e "${BLUE}[*] Installing build dependencies...${NC}"
    sudo apt-get install -y build-essential pkg-config libssl-dev libpcap-dev libpcap0.8-dev

    echo -e "${BLUE}[*] Installing musl toolchain for static builds...${NC}"
    sudo apt-get install -y musl-tools musl-dev

    # Check if static libpcap is available
    if [ -f /usr/lib/x86_64-linux-gnu/libpcap.a ]; then
        echo -e "${GREEN}[+] Static libpcap found at /usr/lib/x86_64-linux-gnu/libpcap.a${NC}"
    else
        echo -e "${RED}[!] Static libpcap not found${NC}"
        echo -e "${YELLOW}[!] Attempting to install static libraries...${NC}"
        sudo apt-get install -y libpcap-dev:amd64
    fi

# Check if Red Hat/Fedora based
elif [ -f /etc/redhat-release ]; then
    echo -e "${BLUE}[*] Detected Red Hat/Fedora-based system${NC}"
    echo -e "${BLUE}[*] Installing build dependencies...${NC}"
    sudo dnf install -y gcc make pkgconfig openssl-devel libpcap-devel libpcap-static 

    echo -e "${BLUE}[*] Installing musl toolchain for static builds...${NC}"
    sudo dnf install -y musl-devel musl-gcc

# Check if Arch Linux
elif [ -f /etc/arch-release ]; then
    echo -e "${BLUE}[*] Detected Arch Linux-based system${NC}"
    echo -e "${BLUE}[*] Installing build dependencies...${NC}"
    sudo pacman -S --needed base-devel openssl libpcap

    echo -e "${BLUE}[*] Installing musl toolchain for static builds...${NC}"
    sudo pacman -S --needed musl

else
    echo -e "${RED}[!] Unsupported Linux distribution${NC}"
    echo -e "${YELLOW}[!] Please install the following packages manually:${NC}"
    echo "  - build-essential or equivalent"
    echo "  - pkg-config"
    echo "  - libssl-dev"
    echo "  - libpcap-dev"
    echo "  - musl-tools (for static builds)"
fi

# Install Rust if not already installed
if ! command -v rustc &> /dev/null; then
    echo -e "${BLUE}[*] Installing Rust...${NC}"
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
    source "$HOME/.cargo/env"
else
    echo -e "${GREEN}[+] Rust is already installed${NC}"
    rustc --version
fi

# Add musl target
echo -e "${BLUE}[*] Adding musl target for static builds...${NC}"
rustup target add x86_64-unknown-linux-musl

echo -e "${BLUE}===========================================================${NC}"
echo -e "${GREEN}[+] All dependencies installed successfully!${NC}"
echo -e "${BLUE}===========================================================${NC}"
echo -e "${YELLOW}[!] You can now build Quantum Scanner with:${NC}"
echo -e "    ./build.sh            # Regular build"
echo -e "    ./build.sh --static   # Enhanced static build"
echo -e "${BLUE}===========================================================${NC}" 