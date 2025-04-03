# Quantum Scanner - Test Suite

This file contains information about the test suite for the Quantum Scanner utility.

## Overview

The test suite automatically tests various build configurations and scanner functionality in a controlled environment.

## Running Tests

To run the tests, use:

```bash
./test_quantum_scanner.sh [options]
```

## Available Options

- `--target IP`: Specify a test target IP (default: 127.0.0.1)
- `--ports LIST`: Specify comma-separated port list (default: 22,80,443,8080)
- `--skip-build`: Skip build option tests
- `--skip-function`: Skip functionality tests
- `--docker-env`: Set up and use a Docker test environment (recommended)
- `--no-html`: Skip HTML report generation
- `--help`: Show this help message

## Docker Test Environment

The Docker test environment creates an isolated network with a container running various services for safe testing.
This is the recommended way to run the tests as it provides a consistent environment without affecting the host system.

```bash
sudo ./test_quantum_scanner.sh --docker-env
```

## Test Results

Test results are stored in a timestamped directory (e.g., `test_results_20250403_004718`).
An HTML report is generated in the test results directory for easy viewing.

## Common Issues

1. If you see permission errors with scanner operations, make sure to run the tests with sudo.
2. Some scan types require root privileges, so warnings about non-zero exit codes are expected.
3. Make sure libpcap-dev, upx-ucl, and cargo are installed before running the tests.

