#!/bin/bash

# ======================================================================
# Quantum Scanner - Docker Test Environment
# ======================================================================
# 
# This script creates a Docker test environment for more thorough testing
# of the Quantum Scanner without risking the host system.
#
# For operational security:
# - Test environment is isolated from host network
# - Containers are ephemeral and cleaned up after testing
# - Network traffic stays within Docker bridge network
# - No external services are exposed
# 
# ======================================================================

# ANSI color codes
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# Create a unique network name to avoid conflicts
NETWORK_NAME="quantum_test_net_$(date +%s)"
TARGET_CONTAINER="quantum_target_$(date +%s)"

# ======================================================================
# HELPER FUNCTIONS
# ======================================================================

# Display banner
show_banner() {
    echo -e "${BLUE}=================================================================${NC}"
    echo -e "${GREEN}  QUANTUM SCANNER - DOCKER TEST ENVIRONMENT ${NC}"
    echo -e "${BLUE}=================================================================${NC}"
    echo -e "${YELLOW}  Setting up isolated testing environment ${NC}"
    echo -e "${BLUE}=================================================================${NC}"
    echo ""
}

# Clean up function
cleanup() {
    echo -e "\n${BLUE}Cleaning up test environment...${NC}"
    
    # Stop and remove the target container
    echo -e "${YELLOW}Stopping and removing target container...${NC}"
    docker stop "$TARGET_CONTAINER" >/dev/null 2>&1
    docker rm "$TARGET_CONTAINER" >/dev/null 2>&1
    
    # Remove the network
    echo -e "${YELLOW}Removing test network...${NC}"
    docker network rm "$NETWORK_NAME" >/dev/null 2>&1
    
    echo -e "${GREEN}Environment cleanup complete.${NC}"
    
    # If we're exiting due to a signal, exit with non-zero status
    if [ -n "$1" ]; then
        exit 1
    fi
}

# Set up trap to ensure cleanup on script exit or interruption
trap 'echo -e "${RED}Script interrupted. Cleaning up...${NC}"; cleanup interrupt' SIGINT SIGTERM EXIT

# ======================================================================
# MAIN SCRIPT
# ======================================================================

# Show banner
show_banner

# Check if Docker is installed
if ! command -v docker &> /dev/null; then
    echo -e "${RED}Error: Docker is not installed.${NC}"
    echo -e "Please install Docker to use this test environment."
    exit 1
fi

# Create Docker network for testing
echo -e "${BLUE}Creating isolated Docker network...${NC}"
if docker network create --driver bridge "$NETWORK_NAME"; then
    echo -e "${GREEN}Created network: $NETWORK_NAME${NC}"
else
    echo -e "${RED}Failed to create Docker network.${NC}"
    exit 1
fi

# Create target container with various services
echo -e "${BLUE}Creating target container with test services...${NC}"
docker run -d --name "$TARGET_CONTAINER" \
    --network "$NETWORK_NAME" \
    --cap-add=NET_ADMIN \
    -p 127.0.0.1:2222:22 \
    -p 127.0.0.1:8080:80 \
    -p 127.0.0.1:8443:443 \
    -e "DEBIAN_FRONTEND=noninteractive" \
    ubuntu:20.04 \
    /bin/bash -c "
        apt-get update && \
        apt-get install -y --no-install-recommends openssh-server apache2 nginx netcat-openbsd iptables iproute2 iputils-ping && \
        mkdir -p /run/sshd && \
        echo 'root:password' | chpasswd && \
        echo 'PermitRootLogin yes' >> /etc/ssh/sshd_config && \
        service ssh start && \
        service apache2 start && \
        echo '<html><body><h1>Test Target</h1></body></html>' > /var/www/html/index.html && \
        echo 'Starting test services...' && \
        # Setup UDP services
        nc -lup 53 -e /bin/echo 'MOCK DNS SERVICE' & \
        nc -lup 123 -e /bin/echo 'MOCK NTP SERVICE' & \
        # Keep container running
        while true; do sleep 10; done
    "

# Check if container was created successfully
if [ $? -ne 0 ]; then
    echo -e "${RED}Failed to create target container.${NC}"
    cleanup
    exit 1
fi

# Get the container's IP address
TARGET_IP=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$TARGET_CONTAINER")

if [ -z "$TARGET_IP" ]; then
    echo -e "${RED}Failed to get target container IP address.${NC}"
    cleanup
    exit 1
fi

echo -e "${GREEN}Target container running at IP: ${YELLOW}$TARGET_IP${NC}"
echo -e "${GREEN}Services available for testing:${NC}"
echo -e "  - SSH (22)"
echo -e "  - HTTP (80)"
echo -e "  - HTTPS (443)"
echo -e "  - DNS (UDP 53)"
echo -e "  - NTP (UDP 123)"

# Create a quantum_scanner.config file with the target IP
echo -e "${BLUE}Creating quantum_scanner.config file...${NC}"
cat > quantum_scanner.config << EOL
{
  "test_target": "$TARGET_IP",
  "ports": "22,53,80,123,443",
  "timeout_ms": 1000,
  "threads": 10,
  "evasion": true,
  "scan_types": ["syn", "connect", "fin", "null", "xmas", "udp"]
}
EOL

echo -e "${GREEN}Created configuration file with target IP.${NC}"

# Show instructions for testing
echo -e "\n${BLUE}=================================================================${NC}"
echo -e "${GREEN}TEST ENVIRONMENT READY${NC}"
echo -e "${BLUE}=================================================================${NC}"
echo -e "To test Quantum Scanner against this environment:"
echo -e ""
echo -e "1. Run Quantum Scanner with the target IP:"
echo -e "   ${YELLOW}./quantum_scanner --ports 22,53,80,123,443 $TARGET_IP${NC}"
echo -e ""
echo -e "2. Or use the configuration file:"
echo -e "   ${YELLOW}./quantum_scanner --config quantum_scanner.config${NC}"
echo -e ""
echo -e "3. Run the comprehensive test script:"
echo -e "   ${YELLOW}./test_quantum_scanner.sh --target $TARGET_IP${NC}"
echo -e ""
echo -e "4. Press Ctrl+C when done to clean up the test environment."
echo -e "${BLUE}=================================================================${NC}"

# Wait for user to finish testing
echo ""
echo -e "${BLUE}Test environment is running. Press Ctrl+C to clean up and exit.${NC}"
while true; do
    sleep 1
done 