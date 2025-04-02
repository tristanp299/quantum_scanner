#!/bin/bash

# Static build script for Quantum Scanner using Docker
# This creates a fully static executable that can run on any Linux system

# ANSI color codes for output formatting
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo -e "${GREEN}Building static Quantum Scanner using Docker...${NC}"

# Check if Docker is installed
if ! command -v docker &> /dev/null; then
    echo -e "${RED}Error: Docker is not installed. Please install Docker first.${NC}"
    exit 1
fi

# Create output directory
mkdir -p bin

# Build the Docker image
echo -e "${YELLOW}Building Docker image...${NC}"
docker build -t quantum-scanner .

if [ $? -ne 0 ]; then
    echo -e "${RED}Docker build failed!${NC}"
    exit 1
fi

# Run the container to copy the binary out
echo -e "${YELLOW}Extracting static binary...${NC}"
docker run --rm -v "$(pwd)/bin:/out" quantum-scanner cp /quantum_scanner /out/

if [ $? -ne 0 ]; then
    echo -e "${RED}Failed to extract binary!${NC}"
    exit 1
fi

echo -e "${GREEN}Static binary created at${NC} $(pwd)/bin/quantum_scanner"
echo -e "${YELLOW}This binary is completely self-contained and can run on any Linux system.${NC}"

# Make the binary executable
chmod +x bin/quantum_scanner

echo -e "${GREEN}Build completed successfully!${NC}" 