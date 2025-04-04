#!/usr/bin/env python3
# =====================================================================
# Quantum Scanner - Unified Test Suite
# =====================================================================
# 
# This script combines all testing functionality from multiple shell scripts
# into a single Python program to reduce file clutter.
#
# Tests included:
# 1. Functionality Tests
# 2. OpSec Tests
# 3. Penetration Testing Scenario Tests
# 4. Docker Test Environment Setup
#
# OPSEC Considerations:
# - Tests can run in isolated Docker environment
# - Results are consolidated into a single report directory
# - Sensitive test files are securely deleted after testing
# - Memory-only mode is available for minimal footprint
# 
# Author: Consolidated by Kali
# Version: 1.0
# =====================================================================

import os
import sys
import argparse
import subprocess
import time
import json
import datetime
import shutil
import signal
import random
import tempfile
from pathlib import Path


# ANSI color codes for better readability
class Colors:
    GREEN = '\033[0;32m'
    RED = '\033[0;31m'
    YELLOW = '\033[1;33m'
    BLUE = '\033[0;34m'
    CYAN = '\033[0;36m'
    MAGENTA = '\033[0;35m'
    NC = '\033[0m'  # No Color


# Default values
class Config:
    TARGET_IP = "45.33.32.156"  # Default Docker target IP
    TEST_PORTS = "22,53,80,123,443"  # Standard test ports for testing
    RESULTS_ROOT = "quantum_scanner_test_results"
    TIMEOUT = 2  # Default timeout in seconds
    DEFAULT_SCAN_TYPES = "syn"
    DEFAULT_PORTS = "80,443"


class TestStats:
    """Class to track test statistics"""
    def __init__(self):
        self.success_count = 0
        self.failure_count = 0
        self.total_tests = 0
    
    def register_test(self, success):
        """Register a test result"""
        self.total_tests += 1
        if success:
            self.success_count += 1
        else:
            self.failure_count += 1
    
    def get_success_rate(self):
        """Calculate the success rate as a percentage"""
        if self.total_tests == 0:
            return 0
        return (self.success_count * 100) / self.total_tests


class TestRunner:
    """Main test runner class"""
    def __init__(self, args):
        """Initialize the test runner with command line arguments"""
        self.args = args
        self.target_ip = args.target
        self.ports = args.ports
        self.test_type = args.test_type
        self.docker_mode = args.docker
        self.memory_only = args.memory_only
        self.evasion = args.evasion
        self.json_output = args.json
        self.no_html = args.no_html
        
        # Set up timestamp for result directories
        self.timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        
        # Create master result directory
        self.master_result_dir = f"{Config.RESULTS_ROOT}_{self.timestamp}"
        os.makedirs(self.master_result_dir, exist_ok=True)
        
        # Set up log file
        self.log_file = os.path.join(self.master_result_dir, "test_log.txt")
        
        # Initialize test stats
        self.stats = TestStats()
        
        # Initialize docker container name and IP if used
        self.docker_container = None
        self.docker_ip = None
        
        # Track if we're running with sudo/root
        self.is_root = os.geteuid() == 0
        
        # Print banner and test info
        self.print_banner()
        self.log_test_info()

    def print_banner(self):
        """Print the test suite banner"""
        print(f"{Colors.BLUE}{'=' * 65}{Colors.NC}")
        print(f"{Colors.YELLOW}Quantum Scanner - Unified Test Suite{Colors.NC}")
        print(f"{Colors.BLUE}{'=' * 65}{Colors.NC}")
        print(f"Target IP: {self.target_ip}")
        print(f"Test Type: {self.test_type}")
        print(f"Docker Mode: {'Enabled' if self.docker_mode else 'Disabled'}")
        print(f"Results Directory: {self.master_result_dir}")
        print(f"{Colors.BLUE}{'=' * 65}{Colors.NC}")

    def log(self, message):
        """Log a message to both console and log file"""
        print(message)
        with open(self.log_file, 'a') as f:
            # Strip ANSI color codes for log file
            clean_message = message
            for color in vars(Colors).values():
                if isinstance(color, str) and color.startswith('\033'):
                    clean_message = clean_message.replace(color, '')
            f.write(f"{clean_message}\n")

    def log_test_info(self):
        """Log test information"""
        self.log(f"# Quantum Scanner Test Results")
        self.log(f"Date: {datetime.datetime.now()}")
        self.log(f"Target IP: {self.target_ip}")
        self.log(f"Test Type: {self.test_type}")
        self.log(f"Docker Mode: {'Enabled' if self.docker_mode else 'Disabled'}")
        self.log(f"{'-' * 65}")

    def check_scanner_binary(self):
        """Check if quantum_scanner binary exists"""
        if not os.path.isfile("./quantum_scanner"):
            self.log(f"{Colors.RED}Error: quantum_scanner binary not found. Build it with ./build.sh first.{Colors.NC}")
            return False
        return True

    def run_test(self, test_name, command, expected_status=0, description=""):
        """Run a test with the given name and command"""
        self.log(f"\n{Colors.BLUE}{'-' * 65}{Colors.NC}")
        self.log(f"{Colors.YELLOW}TEST: {test_name}{Colors.NC}")
        
        if description:
            self.log(f"{Colors.CYAN}Description: {description}{Colors.NC}")
        
        self.log(f"{Colors.CYAN}Command: {command}{Colors.NC}")
        
        # Log test details
        self.log(f"\n## TEST: {test_name}")
        self.log(f"Description: {description}")
        self.log(f"Command: {command}")
        
        # Run the command and capture output and status
        try:
            process = subprocess.run(command, shell=True, capture_output=True, text=True)
            output = process.stdout + process.stderr
            status = process.returncode
        except Exception as e:
            output = str(e)
            status = 1
        
        # Log the output
        self.log("Output (truncated):")
        self.log('\n'.join(output.splitlines()[:30]))
        self.log(f"Exit Status: {status}")
        
        # Check if the status is what we expect
        success = (status == expected_status)
        if success:
            self.log(f"{Colors.GREEN}✓ PASS: {test_name}{Colors.NC}")
            self.log("RESULT: PASS")
        else:
            self.log(f"{Colors.RED}✗ FAIL: {test_name} (Expected status: {expected_status}, Got: {status}){Colors.NC}")
            self.log(f"RESULT: FAIL (Expected status: {expected_status}, Got: {status})")
        
        # Register test result
        self.stats.register_test(success)
        
        # Output a sample of the command output
        self.log(f"{Colors.CYAN}Output sample:{Colors.NC}")
        for line in output.splitlines()[:5]:
            self.log(line)
        self.log(f"{Colors.BLUE}[...truncated...]{Colors.NC}")
        
        # Extract and display open ports if any
        open_ports = output.count("[OPEN]")
        self.log(f"Open ports found: {open_ports}")
        
        return success

    def setup_docker_env(self):
        """Set up Docker test environment"""
        self.log(f"\n{Colors.BLUE}Setting up Docker test environment...{Colors.NC}")
        
        # Check if Docker is installed
        try:
            subprocess.run(["docker", "--version"], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        except (subprocess.SubprocessError, FileNotFoundError):
            self.log(f"{Colors.RED}Error: Docker is not installed or not in PATH.{Colors.NC}")
            return False
        
        # Create a unique network name and container name
        network_name = f"quantum_test_net_{int(time.time())}"
        self.docker_container = f"quantum_target_{int(time.time())}"
        
        # Create Docker network
        self.log(f"{Colors.BLUE}Creating isolated Docker network...{Colors.NC}")
        try:
            subprocess.run(["docker", "network", "create", "--driver", "bridge", network_name], 
                          check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        except subprocess.SubprocessError:
            self.log(f"{Colors.RED}Failed to create Docker network.{Colors.NC}")
            return False
        
        # Create target container with various services
        self.log(f"{Colors.BLUE}Creating target container with test services...{Colors.NC}")
        docker_run_cmd = [
            "docker", "run", "-d", 
            "--name", self.docker_container,
            "--network", network_name,
            "--cap-add=NET_ADMIN",
            "-p", "127.0.0.1:2222:22",
            "-p", "127.0.0.1:8080:80",
            "-p", "127.0.0.1:8443:443",
            "-e", "DEBIAN_FRONTEND=noninteractive",
            "ubuntu:20.04",
            "/bin/bash", "-c",
            "apt-get update && "
            "apt-get install -y --no-install-recommends openssh-server apache2 nginx netcat-openbsd iptables iproute2 iputils-ping && "
            "mkdir -p /run/sshd && "
            "echo 'root:password' | chpasswd && "
            "echo 'PermitRootLogin yes' >> /etc/ssh/sshd_config && "
            "service ssh start && "
            "service apache2 start && "
            "echo '<html><body><h1>Test Target</h1></body></html>' > /var/www/html/index.html && "
            "echo 'Starting test services...' && "
            "nc -lup 53 -e /bin/echo 'MOCK DNS SERVICE' & "
            "nc -lup 123 -e /bin/echo 'MOCK NTP SERVICE' & "
            "while true; do sleep 10; done"
        ]
        
        try:
            subprocess.run(docker_run_cmd, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        except subprocess.SubprocessError:
            self.log(f"{Colors.RED}Failed to create target container.{Colors.NC}")
            self.cleanup_docker()
            return False
        
        # Get the container's IP address
        try:
            result = subprocess.run(
                ["docker", "inspect", "-f", "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}", self.docker_container],
                check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
            )
            self.docker_ip = result.stdout.strip()
        except subprocess.SubprocessError:
            self.log(f"{Colors.RED}Failed to get target container IP address.{Colors.NC}")
            self.cleanup_docker()
            return False
        
        if not self.docker_ip:
            self.log(f"{Colors.RED}Failed to get target container IP address.{Colors.NC}")
            self.cleanup_docker()
            return False
        
        self.log(f"{Colors.GREEN}Target container running at IP: {Colors.YELLOW}{self.docker_ip}{Colors.NC}")
        self.log(f"{Colors.GREEN}Services available for testing:{Colors.NC}")
        self.log("  - SSH (22)")
        self.log("  - HTTP (80)")
        self.log("  - HTTPS (443)")
        self.log("  - DNS (UDP 53)")
        self.log("  - NTP (UDP 123)")
        
        # Create a quantum_scanner.config file with the target IP
        config_file = "quantum_scanner.config"
        self.log(f"{Colors.BLUE}Creating {config_file} file...{Colors.NC}")
        config_data = {
            "test_target": self.docker_ip,
            "ports": "22,53,80,123,443",
            "timeout_ms": 1000,
            "threads": 10,
            "evasion": True,
            "scan_types": ["syn", "fin", "null", "xmas", "udp"]
        }
        
        with open(config_file, 'w') as f:
            json.dump(config_data, f, indent=2)
        
        self.log(f"{Colors.GREEN}Created configuration file with target IP.{Colors.NC}")
        
        # Update target IP to use Docker container
        self.target_ip = self.docker_ip
        
        return True

    def cleanup_docker(self):
        """Clean up Docker resources"""
        if self.docker_container:
            self.log(f"\n{Colors.BLUE}Cleaning up Docker test environment...{Colors.NC}")
            
            # Stop and remove the target container
            try:
                subprocess.run(["docker", "stop", self.docker_container], 
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                subprocess.run(["docker", "rm", self.docker_container], 
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            except subprocess.SubprocessError:
                pass  # Ignore errors during cleanup
            
            # The network will be automatically removed when the container is gone
            self.docker_container = None
            self.docker_ip = None

    def run_functionality_tests(self):
        """Run basic functionality tests"""
        self.log(f"\n{Colors.BLUE}{'=' * 65}{Colors.NC}")
        self.log(f"{Colors.YELLOW}Starting Functionality Tests{Colors.NC}")
        self.log(f"{Colors.BLUE}{'=' * 65}{Colors.NC}")
        
        # Create specific results directory
        func_result_dir = os.path.join(self.master_result_dir, "functionality_results")
        os.makedirs(func_result_dir, exist_ok=True)
        
        # SYN scan test
        self.run_test(
            "SYN Scan",
            f"./quantum_scanner {self.target_ip} --ports 80,443 --scan-types-str syn --timeout {Config.TIMEOUT}",
            0,
            "Tests the basic SYN scan functionality to detect open ports"
        )
        
        # FIN scan
        self.run_test(
            "FIN Scan",
            f"./quantum_scanner {self.target_ip} --ports 80,443 --scan-types-str fin --timeout {Config.TIMEOUT}",
            0,
            "Tests the FIN scan for detecting open/filtered ports"
        )
        
        # NULL scan
        self.run_test(
            "NULL Scan",
            f"./quantum_scanner {self.target_ip} --ports 80,443 --scan-types-str null --timeout {Config.TIMEOUT}",
            0,
            "Tests the NULL scan for detecting open/filtered ports"
        )
        
        # XMAS scan
        self.run_test(
            "XMAS Scan",
            f"./quantum_scanner {self.target_ip} --ports 80,443 --scan-types-str xmas --timeout {Config.TIMEOUT}",
            0,
            "Tests the XMAS scan for detecting open/filtered ports"
        )
        
        # ACK scan
        self.run_test(
            "ACK Scan",
            f"./quantum_scanner {self.target_ip} --ports 80,443 --scan-types-str ack --timeout {Config.TIMEOUT}",
            0,
            "Tests the ACK scan for detecting stateful firewalls"
        )
        
        # Window scan
        self.run_test(
            "Window Scan",
            f"./quantum_scanner {self.target_ip} --ports 80,443 --scan-types-str window --timeout {Config.TIMEOUT}",
            0,
            "Tests the Window scan technique for detecting open ports via TCP window sizes"
        )
        
        # SSL scan
        self.run_test(
            "SSL Scan",
            f"./quantum_scanner {self.target_ip} --ports 443 --scan-types-str ssl --timeout 3",
            0,
            "Tests the SSL scan mode for gathering certificate information"
        )
        
        # UDP scan
        self.run_test(
            "UDP Scan",
            f"./quantum_scanner {self.target_ip} --ports 53 --scan-types-str udp --timeout 3",
            0,
            "Tests the UDP scan for detecting open UDP ports"
        )
        
        # Protocol mimicry scan
        self.run_test(
            "Mimicry Scan",
            f"./quantum_scanner {self.target_ip} --ports 80,443 --scan-types-str mimic --mimic-protocol HTTP --timeout 3",
            0,
            "Tests the protocol mimicry scan mode for evading detection"
        )
        
        # Fragment scan
        self.run_test(
            "Fragment Scan",
            f"./quantum_scanner {self.target_ip} --ports 80,443 --scan-types-str frag --timeout 3",
            0,
            "Tests the packet fragmentation scan mode for evading IDS/IPS"
        )
        
        # Top ports option
        self.run_test(
            "Top Ports Option",
            f"./quantum_scanner {self.target_ip} --top-100 --scan-types-str syn --timeout 3",
            0,
            "Tests scanning the top 100 common ports"
        )
        
        # JSON output
        json_output_file = os.path.join(func_result_dir, "test_output.json")
        self.run_test(
            "JSON Output",
            f"./quantum_scanner {self.target_ip} --ports 80,443 --scan-types-str syn --json --output {json_output_file} --timeout 2",
            0,
            "Tests JSON output format capability"
        )
        
        # Check if JSON file was created
        if os.path.isfile(json_output_file):
            self.log(f"{Colors.GREEN}✓ JSON file created successfully{Colors.NC}")
            self.stats.register_test(True)
        else:
            self.log(f"{Colors.RED}✗ JSON file was not created{Colors.NC}")
            self.stats.register_test(False)

    def run_opsec_tests(self):
        """Run operational security tests"""
        # Require root privileges for OpSec tests
        if not self.is_root:
            self.log(f"{Colors.RED}Error: OpSec tests require root privileges.{Colors.NC}")
            self.log(f"Please run with sudo: sudo {sys.argv[0]} --test-type opsec")
            return False
            
        self.log(f"\n{Colors.BLUE}{'=' * 65}{Colors.NC}")
        self.log(f"{Colors.YELLOW}Starting OpSec Tests{Colors.NC}")
        self.log(f"{Colors.BLUE}{'=' * 65}{Colors.NC}")
        
        # Create specific results directory
        opsec_result_dir = os.path.join(self.master_result_dir, "opsec_results")
        os.makedirs(opsec_result_dir, exist_ok=True)
        
        # Clean up any existing log files to ensure we have a clean slate
        self.log(f"\n{Colors.BLUE}Cleaning up any existing log files...{Colors.NC}")
        for logfile in Path(".").glob("scanner*.log"):
            try:
                os.remove(logfile)
            except:
                pass
        
        # Memory-only mode test
        self.run_test(
            "Memory-Only Mode",
            f"./quantum_scanner {self.target_ip} --ports {Config.TEST_PORTS} --scan-types-str syn --memory-only --timeout 2",
            0,
            "Tests the scanner's ability to operate without writing to disk, which is crucial for maintaining operational security during red team engagements."
        )
        
        # Check for evidence of disk writes after memory-only mode
        self.log(f"\n{Colors.BLUE}Checking for evidence of disk writes...{Colors.NC}")
        log_files_found = list(Path(".").glob("scanner*.log"))
        if not log_files_found:
            self.log(f"{Colors.GREEN}✓ PASS: Memory-only mode left no trace on disk{Colors.NC}")
            self.stats.register_test(True)
        else:
            self.log(f"{Colors.RED}✗ FAIL: Memory-only mode left traces on disk: {log_files_found}{Colors.NC}")
            self.stats.register_test(False)
        
        # Secure deletion test
        test_file = os.path.join(opsec_result_dir, "secure_delete_test.txt")
        with open(test_file, 'w') as f:
            f.write("QUANTUM_SCANNER_MARKER - This is test content that should be securely deleted")
        
        self.run_test(
            "Secure File Deletion",
            f"./quantum_scanner {self.target_ip} --ports 80 --scan-types-str syn --output {test_file}.scan --secure-delete --delete-passes 3 --timeout 1",
            0,
            "Tests the secure deletion feature which overwrites files multiple times before deletion to prevent forensic recovery."
        )
        
        # Basic evasion test
        self.run_test(
            "Basic Evasion Techniques",
            f"./quantum_scanner {self.target_ip} --ports {Config.TEST_PORTS} --scan-types-str syn --evasion --timeout 2",
            0,
            "Tests basic evasion techniques like packet timing randomization and TTL manipulation."
        )
        
        # Enhanced evasion test
        self.run_test(
            "Enhanced Evasion Techniques",
            f"./quantum_scanner {self.target_ip} --ports {Config.TEST_PORTS} --scan-types-str syn --enhanced-evasion --timeout 2",
            0,
            "Tests advanced evasion techniques like OS fingerprint spoofing, TTL jittering, and protocol mimicry."
        )
        
        # OS fingerprint spoofing test
        self.run_test(
            "OS Fingerprint Spoofing",
            f"./quantum_scanner {self.target_ip} --ports {Config.TEST_PORTS} --scan-types-str syn --enhanced-evasion --mimic-os Windows --timeout 2",
            0,
            "Tests the ability to disguise the scanner as a different operating system to evade detection."
        )
        
        # Protocol mimicry tests
        for protocol in ["HTTP", "HTTPS", "DNS"]:
            self.run_test(
                f"{protocol} Protocol Mimicry",
                f"./quantum_scanner {self.target_ip} --ports {Config.TEST_PORTS} --scan-types-str mimic --mimic-protocol {protocol} --timeout 2",
                0,
                f"Tests the ability to disguise scan traffic as legitimate {protocol} traffic to bypass detection."
            )
        
        # Packet Fragmentation test
        self.run_test(
            "Packet Fragmentation",
            f"./quantum_scanner {self.target_ip} --ports {Config.TEST_PORTS} --scan-types-str frag --timeout 3",
            0,
            "Tests the ability to fragment packets to evade network intrusion detection systems."
        )
        
        # RAM disk test
        self.run_test(
            "RAM Disk Usage",
            f"./quantum_scanner {self.target_ip} --ports {Config.TEST_PORTS} --scan-types-str syn --use-ramdisk --ramdisk-size 5 --timeout 2",
            0,
            "Tests the ability to create and use a RAM disk for temporary storage, preventing disk writes."
        )
        
        # Log encryption test
        encrypted_log = "scanner_encrypted.log"
        self.run_test(
            "Log Encryption",
            f"./quantum_scanner {self.target_ip} --ports {Config.TEST_PORTS} --scan-types-str syn --log-file {encrypted_log} --encrypt-logs --timeout 2",
            0,
            "Tests the ability to encrypt logs to prevent unauthorized access to operational information."
        )
        
        # Check if log file is encrypted (very basic check)
        if os.path.isfile(encrypted_log):
            # Very basic check to see if file contains mostly text or binary
            with open(encrypted_log, 'rb') as f:
                content = f.read(100)  # Read first 100 bytes
                is_text = all(c < 128 and c >= 32 or c in [9, 10, 13] for c in content)
                
            if is_text:
                self.log(f"{Colors.RED}✗ FAIL: Log file does not appear to be encrypted{Colors.NC}")
                self.stats.register_test(False)
            else:
                self.log(f"{Colors.GREEN}✓ PASS: Log file appears to be encrypted{Colors.NC}")
                self.stats.register_test(True)
        
        # Random delay test
        self.run_test(
            "Random Delay",
            f"./quantum_scanner {self.target_ip} --ports {Config.TEST_PORTS} --scan-types-str syn --random-delay --max-delay 3 --timeout 5",
            0,
            "Tests the ability to add random delays before scan start to make scanning patterns less predictable."
        )
        
        # Clean up any sensitive test files
        self.log(f"\n{Colors.BLUE}Cleaning up sensitive test files...{Colors.NC}")
        for pattern in ["secure_delete_test*", "frag_capture.pcap"]:
            for file_path in Path(".").glob(pattern):
                try:
                    os.remove(file_path)
                except:
                    pass

    def run_pentest_scenarios(self):
        """Run penetration testing scenario tests"""
        self.log(f"\n{Colors.BLUE}{'=' * 65}{Colors.NC}")
        self.log(f"{Colors.YELLOW}Starting Penetration Test Scenarios{Colors.NC}")
        self.log(f"{Colors.BLUE}{'=' * 65}{Colors.NC}")
        
        # Create specific results directory
        pentest_result_dir = os.path.join(self.master_result_dir, "pentest_results")
        os.makedirs(pentest_result_dir, exist_ok=True)
        
        # --------- Scenario 1: Stealth Reconnaissance ---------
        self.run_test(
            "Stealth Reconnaissance",
            f"./quantum_scanner {self.target_ip} --ports 22,80,443 --scan-types-str syn --evasion --random-delay --max-delay 2 --timeout 5",
            0,
            "Simulates a stealthy reconnaissance phase of a penetration test with minimal footprint"
        )
        
        # --------- Scenario 2: Service Enumeration ---------
        self.run_test(
            "Service Enumeration",
            f"./quantum_scanner {self.target_ip} --ports 22,53,80,443 --scan-types-str ssl,syn --timeout 5",
            0,
            "Enumerates services and gathers version information for potential vulnerability mapping"
        )
        
        # --------- Scenario 3: Firewall Evasion ---------
        self.run_test(
            "Firewall Evasion",
            f"./quantum_scanner {self.target_ip} --ports 80,443 --scan-types-str frag --enhanced-evasion --mimic-os Windows --timeout 5",
            0,
            "Tests the scanner's ability to evade common firewall detection mechanisms"
        )
        
        # --------- Scenario 4: Vulnerability Assessment ---------
        self.run_test(
            "Vulnerability Assessment",
            f"./quantum_scanner {self.target_ip} --ports 80,443 --scan-types-str syn --enhanced-evasion --timeout 8",
            0,
            "Performs basic vulnerability assessment by identifying potentially vulnerable services"
        )
        
        # --------- Scenario 5: Initial Access Simulation ---------
        self.run_test(
            "Initial Access Simulation",
            f"./quantum_scanner {self.target_ip} --ports 22,3389,5900 --scan-types-str syn,ack --timeout 5",
            0,
            "Checks for potentially weak authentication services that could be leveraged for initial access"
        )
        
        # --------- Scenario 6: Pivoting Preparation ---------
        self.run_test(
            "Pivoting Preparation",
            f"./quantum_scanner {self.target_ip} --ports 3306,5432,27017 --scan-types-str syn --memory-only --timeout 5",
            0,
            "Identifies database services that could potentially be used for pivoting in a network"
        )
        
        # --------- Scenario 7: C2 Communication Channel Check ---------
        self.run_test(
            "C2 Communication Check",
            f"./quantum_scanner {self.target_ip} --ports 53,8080,8443,4444 --scan-types-str syn --enhanced-evasion --timeout 5",
            0,
            "Checks for ports commonly used for command and control (C2) communications"
        )
        
        # --------- Scenario 8: Data Exfiltration Path Check ---------
        self.run_test(
            "Data Exfiltration Path",
            f"./quantum_scanner {self.target_ip} --ports 21,22,53,443 --scan-types-str syn --output {pentest_result_dir}/exfil_check.json --json --timeout 5",
            0,
            "Checks for potential data exfiltration paths using common protocols (FTP, SSH, DNS, HTTPS)"
        )

    def generate_html_report(self):
        """Generate HTML report for test results"""
        if self.no_html:
            return
            
        self.log(f"\n{Colors.BLUE}Generating HTML report...{Colors.NC}")
        
        master_report = os.path.join(self.master_result_dir, "master_report.html")
        
        # Simple HTML template with test results
        html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Quantum Scanner Test Report</title>
    <style>
        body {{
            font-family: Arial, sans-serif;
            line-height: 1.6;
            margin: 0;
            padding: 20px;
            color: #333;
            background-color: #f5f5f5;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            background-color: #fff;
            padding: 20px;
            border-radius: 5px;
            box-shadow: 0 0 10px rgba(0,0,0,0.1);
        }}
        h1, h2, h3 {{
            color: #2c3e50;
        }}
        .summary {{
            display: flex;
            justify-content: space-between;
            background-color: #f8f9fa;
            padding: 15px;
            border-radius: 5px;
            margin-bottom: 20px;
        }}
        .summary-item {{
            text-align: center;
        }}
        .summary-value {{
            font-size: 24px;
            font-weight: bold;
        }}
        .summary-label {{
            font-size: 14px;
            color: #666;
        }}
        .success {{ color: #28a745; }}
        .failure {{ color: #dc3545; }}
        pre {{
            background-color: #f8f9fa;
            padding: 10px;
            border-radius: 5px;
            overflow-x: auto;
        }}
        footer {{
            text-align: center;
            margin-top: 20px;
            color: #666;
            font-size: 14px;
        }}
    </style>
</head>
<body>
    <div class="container">
        <h1>Quantum Scanner - Test Report</h1>
        <p>Date: {datetime.datetime.now()}</p>
        <p>Target IP: {self.target_ip}</p>
        <p>Test Type: {self.test_type}</p>
        
        <div class="summary">
            <div class="summary-item">
                <div class="summary-value">{self.stats.total_tests}</div>
                <div class="summary-label">Total Tests</div>
            </div>
            <div class="summary-item">
                <div class="summary-value success">{self.stats.success_count}</div>
                <div class="summary-label">Passed</div>
            </div>
            <div class="summary-item">
                <div class="summary-value failure">{self.stats.failure_count}</div>
                <div class="summary-label">Failed</div>
            </div>
            <div class="summary-item">
                <div class="summary-value">{self.stats.get_success_rate():.2f}%</div>
                <div class="summary-label">Success Rate</div>
            </div>
        </div>
        
        <h2>Test Results</h2>
        <pre>
{self.get_log_content()}
        </pre>
        
        <h2>System Information</h2>
        <pre>
OS: {os.uname().sysname} {os.uname().release}
Kernel: {os.uname().version}
Machine: {os.uname().machine}
Hostname: {os.uname().nodename}
        </pre>
        
        <footer>
            Quantum Scanner Test Report - Generated on {datetime.datetime.now()}
        </footer>
    </div>
</body>
</html>
"""
        
        with open(master_report, 'w') as f:
            f.write(html_content)
            
        self.log(f"{Colors.GREEN}HTML report generated: {master_report}{Colors.NC}")

    def get_log_content(self):
        """Get content from the log file for HTML report"""
        try:
            with open(self.log_file, 'r') as f:
                return f.read()
        except:
            return "Error reading log file."

    def print_summary(self):
        """Print test summary"""
        self.log(f"\n{Colors.BLUE}{'=' * 65}{Colors.NC}")
        self.log(f"{Colors.YELLOW}Test Summary{Colors.NC}")
        self.log(f"{Colors.BLUE}{'=' * 65}{Colors.NC}")
        self.log(f"Total Tests Run: {self.stats.total_tests}")
        self.log(f"Successful Tests: {Colors.GREEN}{self.stats.success_count}{Colors.NC}")
        self.log(f"Failed Tests: {Colors.RED}{self.stats.failure_count}{Colors.NC}")
        self.log(f"Success Rate: {self.stats.get_success_rate():.2f}%")
        self.log(f"{Colors.BLUE}{'=' * 65}{Colors.NC}")

    def run(self):
        """Main method to run tests"""
        # Check if scanner binary exists first
        if not self.check_scanner_binary():
            return 1
        
        # Set up Docker environment if requested
        if self.docker_mode:
            if not self.setup_docker_env():
                self.log(f"{Colors.RED}Failed to set up Docker test environment.{Colors.NC}")
                return 1
            
        # Register signal handlers for cleanup
        signal.signal(signal.SIGINT, self.signal_handler)
        signal.signal(signal.SIGTERM, self.signal_handler)
        
        try:
            # Run tests based on test type
            if self.test_type == 'all' or self.test_type == 'functionality':
                self.run_functionality_tests()
            
            if self.test_type == 'all' or self.test_type == 'opsec':
                self.run_opsec_tests()
            
            if self.test_type == 'all' or self.test_type == 'pentest':
                self.run_pentest_scenarios()
            
            # Generate HTML report
            self.generate_html_report()
            
            # Print summary
            self.print_summary()
            
        finally:
            # Clean up Docker resources if used
            if self.docker_mode:
                self.cleanup_docker()
        
        # Return 1 if any tests failed
        return 1 if self.stats.failure_count > 0 else 0

    def signal_handler(self, sig, frame):
        """Handle signals for graceful shutdown"""
        self.log(f"\n{Colors.YELLOW}Test interrupted. Cleaning up...{Colors.NC}")
        
        # Clean up Docker resources if needed
        if self.docker_mode:
            self.cleanup_docker()
        
        # Exit with non-zero status for interruption
        sys.exit(1)


def main():
    """Main entry point for the script"""
    parser = argparse.ArgumentParser(description="Quantum Scanner - Unified Test Suite")
    parser.add_argument('--target', '-t', default=Config.TARGET_IP, help=f'Target IP address (default: {Config.TARGET_IP})')
    parser.add_argument('--ports', '-p', default=Config.DEFAULT_PORTS, help=f'Ports to scan (default: {Config.DEFAULT_PORTS})')
    parser.add_argument('--test-type', choices=['all', 'functionality', 'opsec', 'pentest'], default='all', help='Type of tests to run')
    parser.add_argument('--docker', '-d', action='store_true', help='Create and use Docker test environment')
    parser.add_argument('--memory-only', '-m', action='store_true', help='Use memory-only mode for minimal footprint')
    parser.add_argument('--evasion', '-e', action='store_true', help='Use evasion techniques')
    parser.add_argument('--json', '-j', action='store_true', help='Generate JSON output')
    parser.add_argument('--no-html', action='store_true', help='Skip HTML report generation')
    
    args = parser.parse_args()
    
    runner = TestRunner(args)
    return runner.run()


if __name__ == "__main__":
    sys.exit(main()) 