#!/bin/bash
# ======================================================================
# Quick Fix for Docker Certificate Issues in Kali Linux
# ======================================================================
# This script fixes common Docker certificate issues on Kali Linux and
# similar security-focused distributions.
# ======================================================================

# ANSI color codes for pretty output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo -e "${BLUE}=========================================================${NC}"
echo -e "${YELLOW}      Docker Certificate Fix for Quantum Scanner${NC}"
echo -e "${BLUE}=========================================================${NC}"

# Check if running as root
if [ "$EUID" -ne 0 ]; then
  echo -e "${RED}[!] Please run as root (use sudo)${NC}"
  exit 1
fi

echo -e "${BLUE}[*] Fixing Docker certificate issues...${NC}"

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
    echo -e "${YELLOW}[!] Docker daemon configuration already exists${NC}"
    echo -e "${BLUE}[*] Ensuring required settings are present...${NC}"
    
    # Use jq if available to modify the JSON file, otherwise just create a new one
    if command -v jq &> /dev/null; then
        # Create a backup of the original file
        cp "$DOCKER_CONFIG_FILE" "$DOCKER_CONFIG_FILE.bak"
        
        # Add insecure-registries if not present
        if ! grep -q "insecure-registries" "$DOCKER_CONFIG_FILE"; then
            jq '. += {"insecure-registries": ["docker.io", "registry.docker.io", "registry-1.docker.io", "index.docker.io"]}' "$DOCKER_CONFIG_FILE" > "$DOCKER_CONFIG_FILE.tmp"
            mv "$DOCKER_CONFIG_FILE.tmp" "$DOCKER_CONFIG_FILE"
        fi
        
        # Add allow-nondistributable-artifacts if not present
        if ! grep -q "allow-nondistributable-artifacts" "$DOCKER_CONFIG_FILE"; then
            jq '. += {"allow-nondistributable-artifacts": ["docker.io", "registry.docker.io", "registry-1.docker.io", "index.docker.io"]}' "$DOCKER_CONFIG_FILE" > "$DOCKER_CONFIG_FILE.tmp"
            mv "$DOCKER_CONFIG_FILE.tmp" "$DOCKER_CONFIG_FILE"
        fi
    else
        echo -e "${YELLOW}[!] jq not found, creating new configuration${NC}"
        # Create a backup before overwriting
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
fi

# Check if /etc/hosts has entries for docker registry
if ! grep -q "registry-1.docker.io" /etc/hosts; then
    echo -e "${BLUE}[*] Adding Docker registry to /etc/hosts...${NC}"
    echo "# Docker registry hosts for certificate handling" >> /etc/hosts
    echo "44.194.136.173  registry-1.docker.io" >> /etc/hosts
    echo "3.213.10.128    auth.docker.io" >> /etc/hosts
fi

# Restart Docker service
echo -e "${BLUE}[*] Restarting Docker service...${NC}"
systemctl restart docker

echo -e "${GREEN}[+] Docker certificate issues fixed!${NC}"
echo -e "${BLUE}[*] You can now run: ./build.sh --static${NC}"
echo -e "${BLUE}=========================================================${NC}" 