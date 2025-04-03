#!/bin/bash

# =====================================================================
# Quantum Scanner - Complete Test Suite Runner
# =====================================================================
# 
# This script runs all three test suites for Quantum Scanner:
# 1. Comprehensive functionality tests
# 2. Operational security (OpSec) tests
# 3. Penetration testing scenario tests
#
# OPSEC Considerations:
# - Tests are run in isolated Docker environment
# - Results are consolidated into a single report directory
# - Sensitive test files are securely deleted after testing
# 
# Author: Hamb0n3
# Version: 1.0
# =====================================================================

# ANSI color codes for better readability
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
NC='\033[0m' # No Color

# Default values
TARGET_IP="172.18.0.2"  # Default Docker target IP
MASTER_RESULT_DIR="quantum_scanner_all_tests_$(date +%Y%m%d_%H%M%S)"
SUMMARY_FILE="${MASTER_RESULT_DIR}/test_summary.txt"
MASTER_REPORT="${MASTER_RESULT_DIR}/master_report.html"
HTML_REPORT=true
TESTS_TO_RUN="all"
START_TIME=$(date +%s)

# Function to display usage information
show_usage() {
    echo -e "${BLUE}=============================================================${NC}"
    echo -e "${YELLOW}Quantum Scanner - Complete Test Suite Runner${NC}"
    echo -e "${BLUE}=============================================================${NC}"
    echo -e "Usage: sudo $0 [options]"
    echo -e ""
    echo -e "Options:"
    echo -e "  --target IP       Specify target IP address (default: ${TARGET_IP})"
    echo -e "  --no-html         Skip HTML report generation"
    echo -e "  --functional      Run only functionality tests"
    echo -e "  --opsec           Run only OpSec tests"
    echo -e "  --pentest         Run only penetration test scenarios"
    echo -e "  --help            Show this help message"
    echo -e ""
    echo -e "This script requires root privileges for certain scan types."
    echo -e "${BLUE}=============================================================${NC}"
}

# Function to log messages to summary file
log_summary() {
    echo -e "$1" | tee -a "$SUMMARY_FILE"
}

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}This script requires root privileges to run comprehensive tests.${NC}"
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
        --no-html)
            HTML_REPORT=false
            ;;
        --functional)
            TESTS_TO_RUN="functional"
            ;;
        --opsec)
            TESTS_TO_RUN="opsec"
            ;;
        --pentest)
            TESTS_TO_RUN="pentest"
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

# Create master results directory
mkdir -p "$MASTER_RESULT_DIR"
touch "$SUMMARY_FILE"

# Print test information
echo -e "${BLUE}=================================================================${NC}"
echo -e "${YELLOW}Starting Quantum Scanner Complete Test Suite${NC}"
echo -e "${BLUE}=================================================================${NC}"
echo -e "Target IP: ${TARGET_IP}"
echo -e "Master Results Directory: ${MASTER_RESULT_DIR}"
echo -e "Tests to Run: ${TESTS_TO_RUN}"
echo -e "${BLUE}=================================================================${NC}"

# Log test information
log_summary "# Quantum Scanner Complete Test Suite Results"
log_summary "Date: $(date)"
log_summary "Target IP: ${TARGET_IP}"
log_summary "Tests Run: ${TESTS_TO_RUN}"
log_summary "================================================================="

# Check if quantum_scanner binary exists and build it if necessary
if [ ! -f "./quantum_scanner" ]; then
    echo -e "${YELLOW}quantum_scanner binary not found. Building it now...${NC}"
    ./build.sh
    
    if [ ! -f "./quantum_scanner" ]; then
        echo -e "${RED}Error: Failed to build quantum_scanner. Cannot continue.${NC}"
        exit 1
    fi
fi

# Check if Docker is available
if ! command -v docker &> /dev/null && [ "$TARGET_IP" = "172.18.0.2" ]; then
    echo -e "${RED}Warning: Docker not found but testing against default Docker IP.${NC}"
    echo -e "Either install Docker or specify a different target IP with --target."
    exit 1
fi

# Make sure the Docker test environment is running
if [ "$TARGET_IP" = "172.18.0.2" ]; then
    # Check if our test container is already running
    if ! docker ps | grep -q "quantum_target"; then
        echo -e "${YELLOW}Setting up Docker test environment...${NC}"
        sudo ./docker_test_env.sh & 
        DOCKER_PID=$!
        
        # Give the Docker environment time to initialize
        echo -e "${CYAN}Waiting for Docker environment to initialize...${NC}"
        sleep 10
    else
        echo -e "${GREEN}Docker test environment is already running.${NC}"
    fi
fi

# Function to run a test suite and capture results
run_test_suite() {
    local suite_name="$1"
    local command="$2"
    local result_subdir="${MASTER_RESULT_DIR}/${suite_name,,}_results"
    
    echo -e "\n${BLUE}=================================================================${NC}"
    echo -e "${MAGENTA}Running Test Suite: ${suite_name}${NC}"
    echo -e "${BLUE}=================================================================${NC}"
    
    # Run the test command and capture exit status
    eval $command
    local status=$?
    
    # Find the most recent result directory created by the test
    local latest_dir=$(find . -maxdepth 1 -type d -name "${suite_name,,}_*" -printf "%T@ %p\n" | sort -nr | head -1 | cut -d' ' -f2-)
    
    if [ ! -z "$latest_dir" ] && [ -d "$latest_dir" ]; then
        # Move contents to master result directory
        mkdir -p "$result_subdir"
        cp -r "$latest_dir"/* "$result_subdir"/
        
        # Log results
        log_summary "\n## ${suite_name} Test Suite Results"
        
        # Extract summary information if available
        if [ -f "$latest_dir/test_log.txt" ] || [ -f "$latest_dir/${suite_name,,}_test_log.txt" ] || [ -f "$latest_dir/scenario_test_log.txt" ]; then
            local log_file=""
            
            if [ -f "$latest_dir/test_log.txt" ]; then
                log_file="$latest_dir/test_log.txt"
            elif [ -f "$latest_dir/${suite_name,,}_test_log.txt" ]; then
                log_file="$latest_dir/${suite_name,,}_test_log.txt"
            elif [ -f "$latest_dir/scenario_test_log.txt" ]; then
                log_file="$latest_dir/scenario_test_log.txt"
            fi
            
            # Extract summary info
            if [ ! -z "$log_file" ]; then
                if grep -q "Test Summary" "$log_file"; then
                    log_summary "$(sed -n '/Test Summary/,/=====/p' "$log_file")"
                elif grep -q "OpSec Test Summary" "$log_file"; then
                    log_summary "$(sed -n '/OpSec Test Summary/,/=====/p' "$log_file")"
                elif grep -q "Scenario Summary" "$log_file"; then
                    log_summary "$(sed -n '/Scenario Summary/,/=====/p' "$log_file")"
                fi
            fi
        fi
        
        # Clean up the original directory
        rm -rf "$latest_dir"
    else
        log_summary "No results found for ${suite_name} Test Suite."
    fi
    
    return $status
}

# Array to track test statuses
declare -a TEST_STATUSES
declare -a TEST_NAMES

# Run the comprehensive functionality tests
if [ "$TESTS_TO_RUN" = "all" ] || [ "$TESTS_TO_RUN" = "functional" ]; then
    run_test_suite "Functionality" "./test_quantum_scanner.sh --target $TARGET_IP"
    TEST_STATUSES+=($?)
    TEST_NAMES+=("Functionality Tests")
fi

# Run the OpSec tests
if [ "$TESTS_TO_RUN" = "all" ] || [ "$TESTS_TO_RUN" = "opsec" ]; then
    run_test_suite "OpSec" "./opsec_test.sh --target $TARGET_IP"
    TEST_STATUSES+=($?)
    TEST_NAMES+=("OpSec Tests")
fi

# Run the penetration testing scenario tests
if [ "$TESTS_TO_RUN" = "all" ] || [ "$TESTS_TO_RUN" = "pentest" ]; then
    run_test_suite "PenTest" "./pentest_scenario_test.sh --target $TARGET_IP"
    TEST_STATUSES+=($?)
    TEST_NAMES+=("Penetration Test Scenarios")
fi

# Calculate overall statistics
END_TIME=$(date +%s)
TOTAL_DURATION=$((END_TIME - START_TIME))
PASSED_SUITES=0
FAILED_SUITES=0

for status in "${TEST_STATUSES[@]}"; do
    if [ $status -eq 0 ]; then
        PASSED_SUITES=$((PASSED_SUITES + 1))
    else
        FAILED_SUITES=$((FAILED_SUITES + 1))
    fi
done

TOTAL_SUITES=${#TEST_STATUSES[@]}

# Generate overall summary
echo -e "\n${BLUE}=================================================================${NC}"
echo -e "${YELLOW}Complete Test Suite Summary${NC}"
echo -e "${BLUE}=================================================================${NC}"
echo -e "Total Test Suites Run: ${TOTAL_SUITES}"
echo -e "Passed Test Suites: ${GREEN}${PASSED_SUITES}${NC}"
echo -e "Failed Test Suites: ${RED}${FAILED_SUITES}${NC}"
echo -e "Total Duration: $(date -d@$TOTAL_DURATION -u +%H:%M:%S)"
echo -e "${BLUE}=================================================================${NC}"

# Display individual suite results
echo -e "\n${YELLOW}Individual Test Suite Results:${NC}"
for i in "${!TEST_NAMES[@]}"; do
    if [ ${TEST_STATUSES[$i]} -eq 0 ]; then
        echo -e "${TEST_NAMES[$i]}: ${GREEN}PASSED${NC}"
    else
        echo -e "${TEST_NAMES[$i]}: ${RED}FAILED${NC}"
    fi
done

# Log the summary
log_summary "\n## Complete Test Suite Summary"
log_summary "Total Test Suites Run: ${TOTAL_SUITES}"
log_summary "Passed Test Suites: ${PASSED_SUITES}"
log_summary "Failed Test Suites: ${FAILED_SUITES}"
log_summary "Total Duration: $(date -d@$TOTAL_DURATION -u +%H:%M:%S)"

log_summary "\nIndividual Test Suite Results:"
for i in "${!TEST_NAMES[@]}"; do
    if [ ${TEST_STATUSES[$i]} -eq 0 ]; then
        log_summary "${TEST_NAMES[$i]}: PASSED"
    else
        log_summary "${TEST_NAMES[$i]}: FAILED"
    fi
done

# Generate master HTML report if requested
if [ "$HTML_REPORT" = true ]; then
    echo -e "\n${BLUE}Generating master HTML report...${NC}"
    
    # Create a master HTML report
    cat > "${MASTER_REPORT}" << EOF
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Quantum Scanner Master Test Report</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            line-height: 1.6;
            margin: 0;
            padding: 20px;
            color: #333;
            background-color: #f5f5f5;
        }
        .container {
            max-width: 1200px;
            margin: 0 auto;
            background-color: #fff;
            padding: 20px;
            border-radius: 5px;
            box-shadow: 0 0 10px rgba(0,0,0,0.1);
        }
        h1, h2, h3 {
            color: #2c3e50;
        }
        .summary {
            display: flex;
            justify-content: space-between;
            background-color: #f8f9fa;
            padding: 15px;
            border-radius: 5px;
            margin-bottom: 20px;
        }
        .summary-item {
            text-align: center;
        }
        .summary-value {
            font-size: 24px;
            font-weight: bold;
        }
        .summary-label {
            font-size: 14px;
            color: #666;
        }
        .success { color: #28a745; }
        .failure { color: #dc3545; }
        table {
            width: 100%;
            border-collapse: collapse;
            margin-bottom: 20px;
        }
        th, td {
            padding: 12px 15px;
            border-bottom: 1px solid #ddd;
            text-align: left;
        }
        th {
            background-color: #f8f9fa;
        }
        tr:hover {
            background-color: #f1f1f1;
        }
        .pass { 
            background-color: rgba(40, 167, 69, 0.1);
        }
        .fail {
            background-color: rgba(220, 53, 69, 0.1);
        }
        pre {
            background-color: #f8f9fa;
            padding: 10px;
            border-radius: 5px;
            overflow-x: auto;
        }
        footer {
            text-align: center;
            margin-top: 20px;
            color: #666;
            font-size: 14px;
        }
        .tabs {
            display: flex;
            margin-bottom: 20px;
        }
        .tab {
            padding: 10px 15px;
            background-color: #f8f9fa;
            border: 1px solid #ddd;
            cursor: pointer;
            margin-right: 5px;
            border-radius: 5px 5px 0 0;
        }
        .tab.active {
            background-color: #fff;
            border-bottom: 1px solid #fff;
        }
        .tab-content {
            display: none;
            padding: 20px;
            border: 1px solid #ddd;
            border-radius: 0 5px 5px 5px;
        }
        .tab-content.active {
            display: block;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>Quantum Scanner - Complete Test Report</h1>
        <p>Date: $(date)</p>
        <p>Target IP: ${TARGET_IP}</p>
        
        <div class="summary">
            <div class="summary-item">
                <div class="summary-value">${TOTAL_SUITES}</div>
                <div class="summary-label">Test Suites</div>
            </div>
            <div class="summary-item">
                <div class="summary-value success">${PASSED_SUITES}</div>
                <div class="summary-label">Passed</div>
            </div>
            <div class="summary-item">
                <div class="summary-value failure">${FAILED_SUITES}</div>
                <div class="summary-label">Failed</div>
            </div>
            <div class="summary-item">
                <div class="summary-value">$(date -d@$TOTAL_DURATION -u +%H:%M:%S)</div>
                <div class="summary-label">Duration</div>
            </div>
        </div>
        
        <h2>Test Suite Results</h2>
        <table>
            <tr>
                <th>#</th>
                <th>Test Suite</th>
                <th>Result</th>
            </tr>
EOF

    # Add individual test suite results
    for i in "${!TEST_NAMES[@]}"; do
        if [ ${TEST_STATUSES[$i]} -eq 0 ]; then
            RESULT_CLASS="pass"
            RESULT_TEXT="PASSED"
        else
            RESULT_CLASS="fail"
            RESULT_TEXT="FAILED"
        fi
        
        echo "<tr class=\"${RESULT_CLASS}\">" >> "${MASTER_REPORT}"
        echo "    <td>$((i+1))</td>" >> "${MASTER_REPORT}"
        echo "    <td>${TEST_NAMES[$i]}</td>" >> "${MASTER_REPORT}"
        echo "    <td>${RESULT_TEXT}</td>" >> "${MASTER_REPORT}"
        echo "</tr>" >> "${MASTER_REPORT}"
    done
    
    # Create tabs for each test suite
    cat >> "${MASTER_REPORT}" << EOF
        </table>
        
        <h2>Detailed Results</h2>
        
        <div class="tabs">
EOF

    # Add tab buttons
    for i in "${!TEST_NAMES[@]}"; do
        ACTIVE=""
        if [ $i -eq 0 ]; then ACTIVE="active"; fi
        echo "            <div class=\"tab ${ACTIVE}\" onclick=\"openTab(event, 'tab${i}')\">
                ${TEST_NAMES[$i]}
            </div>" >> "${MASTER_REPORT}"
    done

    # Close tabs div and begin tab content
    cat >> "${MASTER_REPORT}" << EOF
        </div>
        
EOF

    # Add tab content
    for i in "${!TEST_NAMES[@]}"; do
        ACTIVE=""
        if [ $i -eq 0 ]; then ACTIVE="active"; fi
        SUITE_NAME=$(echo "${TEST_NAMES[$i]}" | awk '{print tolower($1)}')
        
        echo "        <div id=\"tab${i}\" class=\"tab-content ${ACTIVE}\">" >> "${MASTER_REPORT}"
        echo "            <h3>${TEST_NAMES[$i]} Details</h3>" >> "${MASTER_REPORT}"
        
        # Add test log summary if available
        LOG_FILE=""
        if [ -d "${MASTER_RESULT_DIR}/${SUITE_NAME}_results" ]; then
            if [ -f "${MASTER_RESULT_DIR}/${SUITE_NAME}_results/test_log.txt" ]; then
                LOG_FILE="${MASTER_RESULT_DIR}/${SUITE_NAME}_results/test_log.txt"
            elif [ -f "${MASTER_RESULT_DIR}/${SUITE_NAME}_results/${SUITE_NAME}_test_log.txt" ]; then
                LOG_FILE="${MASTER_RESULT_DIR}/${SUITE_NAME}_results/${SUITE_NAME}_test_log.txt"
            elif [ -f "${MASTER_RESULT_DIR}/${SUITE_NAME}_results/scenario_test_log.txt" ]; then
                LOG_FILE="${MASTER_RESULT_DIR}/${SUITE_NAME}_results/scenario_test_log.txt"
            fi
        fi
        
        if [ ! -z "$LOG_FILE" ] && [ -f "$LOG_FILE" ]; then
            echo "            <pre>" >> "${MASTER_REPORT}"
            # Extract a summary from the log file (first 50 lines should be enough for overview)
            head -50 "$LOG_FILE" >> "${MASTER_REPORT}"
            echo "            [...]" >> "${MASTER_REPORT}"
            echo "            </pre>" >> "${MASTER_REPORT}"
            echo "            <p><a href=\"./${SUITE_NAME}_results/\" target=\"_blank\">View Full Results</a></p>" >> "${MASTER_REPORT}"
        else
            echo "            <p>No detailed results available for this test suite.</p>" >> "${MASTER_REPORT}"
        fi
        
        echo "        </div>" >> "${MASTER_REPORT}"
    done
    
    # Finish the HTML file
    cat >> "${MASTER_REPORT}" << EOF
        
        <h2>System Information</h2>
        <pre>
OS: $(uname -a)
Kernel: $(uname -r)
CPU: $(grep "model name" /proc/cpuinfo | head -1 | cut -d ':' -f 2 | xargs)
Memory: $(free -h | grep Mem | awk '{print $2}')
Quantum Scanner Version: $(./quantum_scanner --version 2>&1 | head -1)
        </pre>
        
        <footer>
            Quantum Scanner Master Test Report - Generated on $(date)
        </footer>
    </div>
    
    <script>
        function openTab(evt, tabName) {
            var i, tabcontent, tablinks;
            
            // Hide all tab content
            tabcontent = document.getElementsByClassName("tab-content");
            for (i = 0; i < tabcontent.length; i++) {
                tabcontent[i].className = tabcontent[i].className.replace(" active", "");
            }
            
            // Remove active class from all tabs
            tablinks = document.getElementsByClassName("tab");
            for (i = 0; i < tablinks.length; i++) {
                tablinks[i].className = tablinks[i].className.replace(" active", "");
            }
            
            // Add active class to selected tab and its content
            document.getElementById(tabName).className += " active";
            evt.currentTarget.className += " active";
        }
    </script>
</body>
</html>
EOF

    echo -e "${GREEN}Master HTML report generated: ${MASTER_REPORT}${NC}"
    log_summary "Master HTML report generated: ${MASTER_REPORT}"
fi

# Clean up Docker test environment if we started it
if [ ! -z "$DOCKER_PID" ]; then
    echo -e "\n${BLUE}Cleaning up Docker test environment...${NC}"
    kill $DOCKER_PID 2>/dev/null
    
    # Wait for Docker environment to clean up
    sleep 5
fi

echo -e "\n${GREEN}All tests completed. Consolidated results saved to: ${MASTER_RESULT_DIR}${NC}"

# Exit with appropriate status code
if [ $FAILED_SUITES -gt 0 ]; then
    exit 1
else
    exit 0
fi 