# Quantum Scanner Testing Framework

This document outlines the comprehensive testing approach for the Quantum Scanner tool, including available test suites, execution methods, and test coverage.

## Overview

The testing framework consists of three specialized test suites that collectively provide complete coverage of Quantum Scanner's functionality and security aspects:

1. **Comprehensive Functional Testing** - Tests all features and command options
2. **Operational Security (OpSec) Testing** - Tests security and anti-forensic features
3. **Penetration Testing Scenario Testing** - Tests real-world usage patterns

A master test runner script combines and coordinates all test suites to provide a unified testing experience.

## Test Environment

All tests run in an isolated Docker test environment to ensure:

- Safe testing without affecting the host system
- Consistent and reproducible test environment
- No unauthorized external network traffic
- Simulated services for testing (SSH, HTTP, DNS, etc.)

The Docker test environment is automatically started by the test scripts when needed.

## Available Test Scripts

| Script | Description | Requires Root |
|--------|-------------|---------------|
| `test_quantum_scanner.sh` | Comprehensive tests for all features and options | Some tests |
| `opsec_test.sh` | Specialized tests for security and anti-forensic features | Yes |
| `pentest_scenario_test.sh` | Real-world penetration testing scenario simulations | Some tests |
| `run_all_tests.sh` | Master script that runs all the above test suites | Yes |

## Executing Tests

### Setting Up the Test Environment

The Docker test environment provides a safe and isolated testing environment:

```bash
# Set up test environment
sudo ./docker_test_env.sh
```

### Running Individual Test Suites

Each test suite can be run independently:

```bash
# Functional tests
sudo ./test_quantum_scanner.sh

# OpSec tests
sudo ./opsec_test.sh

# Penetration testing scenarios
sudo ./pentest_scenario_test.sh
```

### Running All Tests

To run all test suites together with a consolidated report:

```bash
# Run all tests
sudo ./run_all_tests.sh
```

### Test Options

Each test script supports several options:

- `--target IP` - Specify a target IP (default: Docker container IP)
- `--ports LIST` - Specify ports to test (default: 22,53,80,123,443)
- `--help` - Show help and options

The master script has additional options:

- `--functional` - Run only functional tests
- `--opsec` - Run only OpSec tests
- `--pentest` - Run only penetration test scenarios
- `--no-html` - Skip HTML report generation

## Test Coverage

### Functional Tests
- Command-line argument handling
- Basic port scanning functionality
- All scan types (SYN, ACK, FIN, XMAS, NULL, etc.)
- Output formats (normal, JSON)
- File output
- Concurrency and rate limiting

### OpSec Tests
- Memory-only mode (no disk writes)
- Secure deletion of temporary files
- Evasion techniques
- Enhanced evasion (TTL jittering, OS fingerprint spoofing)
- Protocol mimicry
- RAM disk functionality
- Log encryption

### Penetration Testing Scenarios
- Initial reconnaissance
- Stealthy scanning
- Comprehensive service enumeration
- Targeted service scanning
- UDP service discovery
- High-stealth penetration testing
- Protocol mimicry
- Time-constrained assessment
- Firewall evasion
- Red team operations

## Test Results

Test results are stored in timestamped directories:
- Functional tests: `test_results_YYYYMMDD_HHMMSS/`
- OpSec tests: `opsec_test_results_YYYYMMDD_HHMMSS/`
- Penetration tests: `pentest_scenarios_YYYYMMDD_HHMMSS/`
- All tests: `quantum_scanner_all_tests_YYYYMMDD_HHMMSS/`

Each results directory contains:
- Detailed log files of all test executions
- HTML reports for easy viewing of results
- Test output files and artifacts

## HTML Reports

Each test suite generates an HTML report with:
- Test summary statistics
- Detailed test results
- Pass/fail status for each test
- Command output samples
- System information

The master test runner generates a consolidated HTML report with:
- Overall test suite summary
- Individual test suite results
- Detailed tabs for each test suite
- System information

## OpSec Considerations

The testing framework is designed with operational security in mind:
- All tests run in isolated environments
- Sensitive test files can be securely deleted
- Memory-only operation is tested and verified
- No external network connections are made
- Test logs can be encrypted

For maximum operational security, consider running the tests with:

```bash
sudo ./run_all_tests.sh --secure-delete
```

## Extending the Tests

To add new tests:
1. Add new test cases to the appropriate test script
2. Follow the existing pattern for test implementation
3. Use the `run_test` or `run_scenario` functions to maintain consistency
4. Update this documentation if adding significant new test capability

## Troubleshooting

Common issues:
- **"Docker not found"**: Install Docker or specify a different target IP
- **"Permission denied"**: Run with sudo/root privileges
- **"Scan failed"**: Check that the Docker test environment is running
- **"Output file not created"**: Check filesystem permissions

# Testing Quantum Scanner

This document provides instructions for testing Quantum Scanner, including the full nDPI protocol detection capabilities.

## Prerequisites

Before testing the full nDPI integration, you need to install the nDPI library:

### On Debian/Ubuntu:
```bash
sudo apt-get update
sudo apt-get install libndpi-dev
```

### On Fedora/CentOS:
```bash
sudo dnf install ndpi-devel
```

### On Arch Linux:
```bash
sudo pacman -S ndpi
```

### On macOS with Homebrew:
```bash
brew install ndpi
```

## Building with Full nDPI Support

To build Quantum Scanner with full nDPI protocol detection:

```bash
# Clone the repository
git clone https://github.com/yourusername/quantum_scanner.git
cd quantum_scanner

# Build with full nDPI support
cargo build --release --features full-ndpi
```

## Testing Protocol Detection

To test the enhanced protocol detection capabilities:

```bash
# Run with verbose output to see protocol detection
sudo ./target/release/quantum_scanner -t <target_ip> --ports 1-1000 -v --service-scan

# For detailed protocol information
sudo ./target/release/quantum_scanner -t <target_ip> --ports 1-1000 -v --service-scan --protocol-details
```

## Available nDPI Protocols

To see all available nDPI protocols supported by your installation:

```bash
sudo ./target/release/quantum_scanner --list-protocols
```

This will output the complete list of protocols that your nDPI library version supports.

## Testing Individual Protocol Detection

You can test detection of specific protocols:

### HTTP/HTTPS:
```bash
sudo ./target/release/quantum_scanner -t example.com --ports 80,443 -v --service-scan
```

### SSH:
```bash
sudo ./target/release/quantum_scanner -t <target_ip> --ports 22 -v --service-scan
```

### Database Services:
```bash
sudo ./target/release/quantum_scanner -t <target_ip> --ports 3306,5432,1433,27017,6379 -v --service-scan
```

## Comparing Results

To compare the results of the full nDPI detection versus the minimal detection:

1. Run a scan with full nDPI enabled:
```bash
sudo ./target/release/quantum_scanner -t <target_ip> --ports 1-1000 -v --service-scan > full_ndpi_results.txt
```

2. Run the same scan with minimal detection:
```bash
sudo ./target/release/quantum_scanner -t <target_ip> --ports 1-1000 -v --service-scan --minimal > minimal_results.txt
```

3. Compare the results:
```bash
diff full_ndpi_results.txt minimal_results.txt
```

## Troubleshooting

If you encounter issues with nDPI detection:

1. Verify the nDPI library is properly installed:
```bash
pkg-config --modversion libndpi
```

2. Check if the scanner can find the nDPI library:
```bash
RUST_LOG=debug ./target/release/quantum_scanner --version
```

3. If using a custom nDPI installation location, specify it when building:
```bash
RUSTFLAGS="-L /path/to/ndpi/lib -I /path/to/ndpi/include" cargo build --release --features full-ndpi
```

## Expected Output

When full nDPI protocol detection is working correctly, you should see output similar to this:

```
Port 80/tcp: open
  Service: http
  Banner: Apache/2.4.41 (Ubuntu)
  Protocol family: Web
  Encrypted: No
  Additional details: HTTP/1.1 website
  Risk score: 0

Port 443/tcp: open
  Service: https
  Banner: nginx/1.18.0
  Protocol family: Web
  Encrypted: Yes
  Additional details: TLS v1.3, JA3: a0e9f5d64349fb13191bc781f81f42e1
  Risk score: 0
```

The extended protocol information (protocol family, encryption status, risk score) is available only with the full nDPI integration. 