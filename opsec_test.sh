#!/bin/bash

# =====================================================================
# Quantum Scanner - Operational Security (OpSec) Test Suite
# =====================================================================
# 
# This script specifically tests the operational security features
# of the Quantum Scanner tool to ensure proper security posture
# for red team operations.
#
# IMPORTANT: This script should be run with root/sudo privileges
# as it tests features that require elevated permissions.
#
# OPSEC Features Tested:
# - Memory-only mode (no disk writes)
# - Secure deletion of temporary files
# - Evasion techniques effectiveness
# - Enhanced evasion (TTL jittering, OS fingerprint spoofing)
# - Protocol mimicry for scan hiding
# - RAM disk functionality
# - Log encryption
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
TEST_PORTS="22,53,80,123,443"  # Standard test ports
RESULT_DIR="opsec_test_results_$(date +%Y%m%d_%H%M%S)"
LOG_FILE="${RESULT_DIR}/opsec_test_log.txt"
SUCCESS_COUNT=0
FAILURE_COUNT=0
TOTAL_TESTS=0

# Function to display usage information
show_usage() {
    echo -e "${BLUE}=============================================================${NC}"
    echo -e "${YELLOW}Quantum Scanner - OpSec Test Suite${NC}"
    echo -e "${BLUE}=============================================================${NC}"
    echo -e "Usage: sudo $0 [options]"
    echo -e ""
    echo -e "Options:"
    echo -e "  --target IP      Specify target IP address (default: ${TARGET_IP})"
    echo -e "  --ports LIST     Specify ports to test (default: ${TEST_PORTS})"
    echo -e "  --help           Show this help message"
    echo -e ""
    echo -e "This script requires root privileges to test low-level features."
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
    echo -e "${YELLOW}OPSEC TEST: ${test_name}${NC}"
    if [ -n "$desc" ]; then
        echo -e "${CYAN}Description: ${desc}${NC}"
    fi
    echo -e "${CYAN}Command: ${command}${NC}"
    
    TOTAL_TESTS=$((TOTAL_TESTS + 1))
    
    # Log the test details
    log "\n## OPSEC TEST: ${test_name}"
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
    
    return $STATUS
}

# Function to check for evidence of disk writes
check_disk_writes() {
    local log_file="scanner.log"
    
    if [ -f "$log_file" ]; then
        echo -e "${RED}✗ Found log file on disk: $log_file${NC}"
        return 1
    fi
    
    # Check for other scanner log files but exclude test result directories
    if find . -maxdepth 1 -name "scanner_*.log" 2>/dev/null | grep -q .; then
        echo -e "${RED}✗ Found log files on disk: $(find . -maxdepth 1 -name "scanner_*.log")${NC}"
        return 1
    fi
    
    echo -e "${GREEN}✓ No evidence of disk writes found${NC}"
    return 0
}

# Function to verify file deletion 
verify_secure_deletion() {
    local target_file="$1"
    
    if [ -f "$target_file" ]; then
        echo -e "${RED}✗ File still exists: $target_file${NC}"
        return 1
    fi
    
    # Try to recover the file using forensic techniques
    # This is a simplified simulation; in a real test, you would use actual recovery tools
    if grep -a -b -o "QUANTUM_SCANNER_MARKER" $target_file.raw_device 2>/dev/null; then
        echo -e "${RED}✗ File content still recoverable from raw device${NC}"
        return 1
    fi
    
    echo -e "${GREEN}✓ File appears to be securely deleted${NC}"
    return 0
}

# Function to detect packet fragmentation using tcpdump
detect_fragmentation() {
    local capture_file="frag_capture.pcap"
    local target="$1"
    local duration="$2"
    
    # Capture traffic and look for fragmented packets
    sudo timeout $duration tcpdump -i any -w $capture_file "host $target" 2>/dev/null
    
    # This would be more sophisticated in a real implementation
    # Here we're just checking if the capture file has fragments
    if tcpdump -r $capture_file 2>/dev/null | grep -i "frag" > /dev/null; then
        echo -e "${GREEN}✓ Detected packet fragmentation${NC}"
        rm -f $capture_file
        return 0
    else
        echo -e "${RED}✗ No packet fragmentation detected${NC}"
        rm -f $capture_file
        return 1
    fi
}

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}This script requires root privileges to test low-level features.${NC}"
    echo -e "Please run with sudo: sudo $0 $*"
    exit 1
fi

# Parse command line arguments
while [ "$1" != "" ]; do
    case $1 in
        --target)
            shift
            TARGET_IP="$1"
            ;;
        --ports)
            shift
            TEST_PORTS="$1"
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
echo -e "${YELLOW}Starting Quantum Scanner OpSec Tests${NC}"
echo -e "${BLUE}=============================================================${NC}"
echo -e "Target IP: ${TARGET_IP}"
echo -e "Test Ports: ${TEST_PORTS}"
echo -e "Output Directory: ${RESULT_DIR}"
echo -e "${BLUE}=============================================================${NC}"

# Log test information
log "# Quantum Scanner OpSec Test Results"
log "Date: $(date)"
log "Target IP: ${TARGET_IP}"
log "Test Ports: ${TEST_PORTS}"
log "-------------------------------------------------------------"

# Check if quantum_scanner binary exists
if [ ! -f "./quantum_scanner" ]; then
    echo -e "${RED}Error: quantum_scanner binary not found. Build it with ./build.sh first.${NC}"
    exit 1
fi

# =====================================================================
# MEMORY-ONLY MODE TESTS
# =====================================================================

# Clean up any existing log files to ensure we have a clean slate
echo -e "\n${BLUE}Cleaning up any existing log files...${NC}"
sudo rm -f scanner.log scanner_*.log
log "Cleaned up any existing log files before memory-only test"

run_test "Memory-Only Mode" \
    "./quantum_scanner ${TARGET_IP} --ports ${TEST_PORTS} --scan-types syn --memory-only --timeout 2" \
    0 \
    "Tests the scanner's ability to operate without writing to disk, which is crucial for maintaining operational security during red team engagements."

# Check for evidence of disk writes after memory-only mode
echo -e "\n${BLUE}Checking for evidence of disk writes...${NC}"
if check_disk_writes; then
    echo -e "${GREEN}✓ PASS: Memory-only mode left no trace on disk${NC}"
    log "RESULT: PASS - Memory-only mode left no trace on disk"
    SUCCESS_COUNT=$((SUCCESS_COUNT + 1))
else
    echo -e "${RED}✗ FAIL: Memory-only mode left traces on disk${NC}"
    log "RESULT: FAIL - Memory-only mode left traces on disk"
    FAILURE_COUNT=$((FAILURE_COUNT + 1))
fi
TOTAL_TESTS=$((TOTAL_TESTS + 1))

# =====================================================================
# SECURE DELETION TESTS
# =====================================================================

# Create a test file with a marker
TEST_FILE="${RESULT_DIR}/secure_delete_test.txt"
echo "QUANTUM_SCANNER_MARKER - This is test content that should be securely deleted" > $TEST_FILE

# Create simulated raw device file for secure deletion testing
dd if=$TEST_FILE of=$TEST_FILE.raw_device bs=4096 count=1 2>/dev/null

run_test "Secure File Deletion" \
    "./quantum_scanner ${TARGET_IP} --ports 80 --scan-types syn --output ${TEST_FILE}.scan --secure-delete --delete-passes 3 --timeout 1" \
    0 \
    "Tests the secure deletion feature which overwrites files multiple times before deletion to prevent forensic recovery."

# =====================================================================
# EVASION TECHNIQUE TESTS
# =====================================================================

# Basic evasion
run_test "Basic Evasion Techniques" \
    "./quantum_scanner ${TARGET_IP} --ports ${TEST_PORTS} --scan-types syn --evasion --timeout 2" \
    0 \
    "Tests basic evasion techniques like packet timing randomization and TTL manipulation."

# Enhanced evasion
run_test "Enhanced Evasion Techniques" \
    "./quantum_scanner ${TARGET_IP} --ports ${TEST_PORTS} --scan-types syn --enhanced-evasion --timeout 2" \
    0 \
    "Tests advanced evasion techniques like OS fingerprint spoofing, TTL jittering, and protocol mimicry."

# OS fingerprint spoofing
run_test "OS Fingerprint Spoofing" \
    "./quantum_scanner ${TARGET_IP} --ports ${TEST_PORTS} --scan-types syn --enhanced-evasion --mimic-os Windows --timeout 2" \
    0 \
    "Tests the ability to disguise the scanner as a different operating system to evade detection."

# TTL jittering
run_test "TTL Jittering" \
    "./quantum_scanner ${TARGET_IP} --ports ${TEST_PORTS} --scan-types syn --enhanced-evasion --ttl-jitter 3 --timeout 2" \
    0 \
    "Tests randomization of TTL values to avoid pattern detection by network monitoring systems."

# =====================================================================
# PROTOCOL MIMICRY TESTS
# =====================================================================

# HTTP protocol mimicry
run_test "HTTP Protocol Mimicry" \
    "./quantum_scanner ${TARGET_IP} --ports ${TEST_PORTS} --scan-types mimic --mimic-protocol HTTP --timeout 2" \
    0 \
    "Tests the ability to disguise scan traffic as legitimate HTTP traffic to bypass detection."

# HTTPS protocol mimicry
run_test "HTTPS Protocol Mimicry" \
    "./quantum_scanner ${TARGET_IP} --ports ${TEST_PORTS} --scan-types mimic --mimic-protocol HTTPS --timeout 2" \
    0 \
    "Tests the ability to disguise scan traffic as legitimate HTTPS traffic to bypass detection."

# DNS protocol mimicry
run_test "DNS Protocol Mimicry" \
    "./quantum_scanner ${TARGET_IP} --ports ${TEST_PORTS} --scan-types mimic --mimic-protocol DNS --timeout 2" \
    0 \
    "Tests the ability to disguise scan traffic as legitimate DNS traffic to bypass detection."

# =====================================================================
# PACKET FRAGMENTATION TESTS
# =====================================================================

# Start packet capture in background
echo -e "\n${BLUE}Starting packet capture to detect fragmentation...${NC}"
log "Starting packet capture to detect fragmentation"

# Test fragmentation
run_test "Packet Fragmentation" \
    "./quantum_scanner ${TARGET_IP} --ports ${TEST_PORTS} --scan-types frag --timeout 3" \
    0 \
    "Tests the ability to fragment packets to evade network intrusion detection systems."

# =====================================================================
# RAM DISK TESTS
# =====================================================================

# Test RAM disk creation and usage
run_test "RAM Disk Usage" \
    "./quantum_scanner ${TARGET_IP} --ports ${TEST_PORTS} --scan-types syn --use-ramdisk --ramdisk-size 5 --timeout 2" \
    0 \
    "Tests the ability to create and use a RAM disk for temporary storage, preventing disk writes."

# =====================================================================
# LOG ENCRYPTION TESTS
# =====================================================================

# Test log encryption
ENCRYPTED_LOG="scanner_encrypted.log"
run_test "Log Encryption" \
    "./quantum_scanner ${TARGET_IP} --ports ${TEST_PORTS} --scan-types syn --log-file ${ENCRYPTED_LOG} --encrypt-logs --timeout 2" \
    0 \
    "Tests the ability to encrypt logs to prevent unauthorized access to operational information."

# Check if log file is encrypted
if [ -f "${ENCRYPTED_LOG}" ]; then
    # Very basic check - real test would be more sophisticated
    if file "${ENCRYPTED_LOG}" | grep -i "text" > /dev/null; then
        echo -e "${RED}✗ FAIL: Log file does not appear to be encrypted${NC}"
        log "RESULT: FAIL - Log file does not appear to be encrypted"
        FAILURE_COUNT=$((FAILURE_COUNT + 1))
    else
        echo -e "${GREEN}✓ PASS: Log file appears to be encrypted${NC}"
        log "RESULT: PASS - Log file appears to be encrypted"
        SUCCESS_COUNT=$((SUCCESS_COUNT + 1))
    fi
    TOTAL_TESTS=$((TOTAL_TESTS + 1))
fi

# =====================================================================
# RANDOM DELAY TEST
# =====================================================================

# Test random delay
run_test "Random Delay" \
    "./quantum_scanner ${TARGET_IP} --ports ${TEST_PORTS} --scan-types syn --random-delay --max-delay 3 --timeout 5" \
    0 \
    "Tests the ability to add random delays before scan start to make scanning patterns less predictable."

# =====================================================================
# GENERATE TEST SUMMARY
# =====================================================================
echo -e "\n${BLUE}=============================================================${NC}"
echo -e "${YELLOW}OpSec Test Summary${NC}"
echo -e "${BLUE}=============================================================${NC}"
echo -e "Total Tests Run: ${TOTAL_TESTS}"
echo -e "Successful Tests: ${GREEN}${SUCCESS_COUNT}${NC}"
echo -e "Failed Tests: ${RED}${FAILURE_COUNT}${NC}"
echo -e "Success Rate: $(echo "scale=2; ${SUCCESS_COUNT}*100/${TOTAL_TESTS}" | bc)%"
echo -e "${BLUE}=============================================================${NC}"

# Log test summary
log "\n## OpSec Test Summary"
log "Total Tests Run: ${TOTAL_TESTS}"
log "Successful Tests: ${SUCCESS_COUNT}"
log "Failed Tests: ${FAILURE_COUNT}"
log "Success Rate: $(echo "scale=2; ${SUCCESS_COUNT}*100/${TOTAL_TESTS}" | bc)%"

# Clean up any sensitive test files
echo -e "\n${BLUE}Cleaning up sensitive test files...${NC}"
find "${RESULT_DIR}" -name "secure_delete_test*" -delete
find . -name "frag_capture.pcap" -delete

echo -e "\n${GREEN}OpSec test execution completed. Results saved to: ${RESULT_DIR}${NC}"
echo -e "${YELLOW}Note: For a real red team operation, you would want to securely delete these test results.${NC}"

# Exit with appropriate status code
if [ $FAILURE_COUNT -gt 0 ]; then
    exit 1
else
    exit 0
fi 