#!/bin/bash

# =====================================================================
# Quantum Scanner - Functionality Test Suite
# =====================================================================
# 
# This script tests the basic functionality of the Quantum Scanner tool
# to ensure all scan types work correctly.
#
# Author: Security Tester
# Version: 1.0
# =====================================================================

# ANSI color codes for better readability
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Default values
TARGET_IP="172.18.0.2"  # Default Docker target IP
RESULT_DIR="functionality_test_results_$(date +%Y%m%d_%H%M%S)"
LOG_FILE="${RESULT_DIR}/test_log.txt"
SUCCESS_COUNT=0
FAILURE_COUNT=0
TOTAL_TESTS=0

# Function to display usage information
show_usage() {
    echo -e "${BLUE}=============================================================${NC}"
    echo -e "${YELLOW}Quantum Scanner - Functionality Test Suite${NC}"
    echo -e "${BLUE}=============================================================${NC}"
    echo -e "Usage: $0 [options]"
    echo -e ""
    echo -e "Options:"
    echo -e "  --target IP       Specify target IP address (default: ${TARGET_IP})"
    echo -e "  --help            Show this help message"
    echo -e ""
    echo -e "${BLUE}=============================================================${NC}"
}

# Function to log test output
log() {
    echo -e "$1" | tee -a "$LOG_FILE"
}

# Function to run a test with descriptive name
run_test() {
    local test_name="$1"
    local command="$2"
    local expected_status="$3"  # 0 for success, non-zero for failure
    local desc="$4"  # Test description
    
    echo -e "\n${BLUE}-------------------------------------------------------------${NC}"
    echo -e "${YELLOW}TEST: ${test_name}${NC}"
    if [ -n "$desc" ]; then
        echo -e "${CYAN}Description: ${desc}${NC}"
    fi
    echo -e "${CYAN}Command: ${command}${NC}"
    
    TOTAL_TESTS=$((TOTAL_TESTS + 1))
    
    # Log the test details
    log "\n## TEST: ${test_name}"
    log "Description: ${desc}"
    log "Command: ${command}"
    
    # Run the command and capture output and status
    OUTPUT=$(eval ${command} 2>&1)
    STATUS=$?
    
    # Log the output
    log "Output (truncated):"
    log "$(echo "$OUTPUT" | head -30)"
    log "Exit Status: ${STATUS}"
    
    # Check if the status is what we expect
    if [ $STATUS -eq $expected_status ]; then
        echo -e "${GREEN}✓ PASS: ${test_name}${NC}"
        log "RESULT: PASS"
        SUCCESS_COUNT=$((SUCCESS_COUNT + 1))
    else
        echo -e "${RED}✗ FAIL: ${test_name} (Expected status: ${expected_status}, Got: ${STATUS})${NC}"
        log "RESULT: FAIL (Expected status: ${expected_status}, Got: ${STATUS})"
        FAILURE_COUNT=$((FAILURE_COUNT + 1))
    fi
    
    # Output a sample of the command output
    echo -e "${CYAN}Output sample:${NC}"
    echo "$OUTPUT" | head -5
    echo -e "${BLUE}[...truncated...]${NC}"
    
    # Extract and display open ports if any
    local open_ports=$(echo "$OUTPUT" | grep -c "\[OPEN\]")
    echo -e "Open ports found: ${open_ports}"
    log "Open ports found: ${open_ports}"
    
    return $STATUS
}

# Parse command line arguments
while [ "$1" != "" ]; do
    case $1 in
        --target)
            shift
            TARGET_IP="$1"
            ;;
        --help)
            show_usage
            exit 0
            ;;
        *)
            echo -e "${RED}Error: Unknown option: $1${NC}"
            show_usage
            exit 1
            ;;
    esac
    shift
done

# Create results directory
mkdir -p "$RESULT_DIR"
touch "$LOG_FILE"

# Print test information
echo -e "${BLUE}=============================================================${NC}"
echo -e "${YELLOW}Starting Quantum Scanner Functionality Tests${NC}"
echo -e "${BLUE}=============================================================${NC}"
echo -e "Target IP: ${TARGET_IP}"
echo -e "Output Directory: ${RESULT_DIR}"
echo -e "${BLUE}=============================================================${NC}"

# Log test information
log "# Quantum Scanner Functionality Test Results"
log "Date: $(date)"
log "Target IP: ${TARGET_IP}"
log "-------------------------------------------------------------"

# Check if quantum_scanner binary exists
if [ ! -f "./quantum_scanner" ]; then
    echo -e "${RED}Error: quantum_scanner binary not found. Build it with ./build.sh first.${NC}"
    exit 1
fi

# =====================================================================
# BASIC SCAN TESTS
# =====================================================================

# SYN scan test
run_test "SYN Scan" \
    "./quantum_scanner ${TARGET_IP} --ports 80,443 --scan-types syn --timeout 2" \
    0 \
    "Tests the basic SYN scan functionality to detect open ports"

# =====================================================================
# SCAN TYPE TESTS
# =====================================================================

# FIN scan
run_test "FIN Scan" \
    "./quantum_scanner ${TARGET_IP} --ports 80,443 --scan-types fin --timeout 2" \
    0 \
    "Tests the FIN scan for detecting open/filtered ports"

# NULL scan
run_test "NULL Scan" \
    "./quantum_scanner ${TARGET_IP} --ports 80,443 --scan-types null --timeout 2" \
    0 \
    "Tests the NULL scan for detecting open/filtered ports"

# XMAS scan
run_test "XMAS Scan" \
    "./quantum_scanner ${TARGET_IP} --ports 80,443 --scan-types xmas --timeout 2" \
    0 \
    "Tests the XMAS scan for detecting open/filtered ports"

# ACK scan
run_test "ACK Scan" \
    "./quantum_scanner ${TARGET_IP} --ports 80,443 --scan-types ack --timeout 2" \
    0 \
    "Tests the ACK scan for detecting stateful firewalls"

# Window scan
run_test "Window Scan" \
    "./quantum_scanner ${TARGET_IP} --ports 80,443 --scan-types window --timeout 2" \
    0 \
    "Tests the Window scan technique for detecting open ports via TCP window sizes"

# =====================================================================
# SPECIAL SCAN TESTS
# =====================================================================

# SSL scan
run_test "SSL Scan" \
    "./quantum_scanner ${TARGET_IP} --ports 443 --scan-types ssl --timeout 3" \
    0 \
    "Tests the SSL scan mode for gathering certificate information"

# UDP scan
run_test "UDP Scan" \
    "./quantum_scanner ${TARGET_IP} --ports 53 --scan-types udp --timeout 3" \
    0 \
    "Tests the UDP scan for detecting open UDP ports"

# Protocol mimicry scan
run_test "Mimicry Scan" \
    "./quantum_scanner ${TARGET_IP} --ports 80,443 --scan-types mimic --mimic-protocol HTTP --timeout 3" \
    0 \
    "Tests the protocol mimicry scan mode for evading detection"

# Fragment scan
run_test "Fragment Scan" \
    "./quantum_scanner ${TARGET_IP} --ports 80,443 --scan-types frag --timeout 3" \
    0 \
    "Tests the packet fragmentation scan mode for evading IDS/IPS"

# =====================================================================
# OPTION TESTS
# =====================================================================

# Top ports option
run_test "Top Ports Option" \
    "./quantum_scanner ${TARGET_IP} --top-100 --scan-types syn --timeout 3" \
    0 \
    "Tests scanning the top 100 common ports"

# JSON output
run_test "JSON Output" \
    "./quantum_scanner ${TARGET_IP} --ports 80,443 --scan-types syn --json --output ${RESULT_DIR}/test_output.json --timeout 2" \
    0 \
    "Tests JSON output format capability"

# Check if JSON file was created
if [ -f "${RESULT_DIR}/test_output.json" ]; then
    echo -e "${GREEN}✓ JSON file created successfully${NC}"
    log "JSON file created successfully"
else
    echo -e "${RED}✗ JSON file was not created${NC}"
    log "JSON file was not created"
    FAILURE_COUNT=$((FAILURE_COUNT + 1))
    TOTAL_TESTS=$((TOTAL_TESTS + 1))
fi

# =====================================================================
# GENERATE TEST SUMMARY
# =====================================================================
echo -e "\n${BLUE}=============================================================${NC}"
echo -e "${YELLOW}Functionality Test Summary${NC}"
echo -e "${BLUE}=============================================================${NC}"
echo -e "Total Tests Run: ${TOTAL_TESTS}"
echo -e "Successful Tests: ${GREEN}${SUCCESS_COUNT}${NC}"
echo -e "Failed Tests: ${RED}${FAILURE_COUNT}${NC}"
echo -e "Success Rate: $(echo "scale=2; ${SUCCESS_COUNT}*100/${TOTAL_TESTS}" | bc)%"
echo -e "${BLUE}=============================================================${NC}"

# Log test summary
log "\n## Functionality Test Summary"
log "Total Tests Run: ${TOTAL_TESTS}"
log "Successful Tests: ${SUCCESS_COUNT}"
log "Failed Tests: ${FAILURE_COUNT}"
log "Success Rate: $(echo "scale=2; ${SUCCESS_COUNT}*100/${TOTAL_TESTS}" | bc)%"

# Exit with appropriate status code
if [ $FAILURE_COUNT -gt 0 ]; then
    exit 1
else
    exit 0
fi 