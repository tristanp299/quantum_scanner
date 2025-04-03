# Quantum Scanner (Rust Edition)

An advanced port scanner with evasion capabilities written in Rust.

## Features

- **Multiple Scan Techniques**: SYN, ACK, FIN, XMAS, NULL, SSL, UDP, and more
- **Stealthy Evasion**: Fragmentation, protocol mimicry, TLS echo scans
- **Enhanced Security**: Optional memory-only operation, RAM disk support, secure cleanup
- **Advanced Evasion**: OS fingerprint spoofing, TTL jittering, protocol mimicry
- **Tor Integration**: Optional traffic routing through Tor (when available)
- **Performance**: High-speed concurrent scanning leveraging Rust's async capabilities
- **Service Detection**: Identifies services running on open ports
- **SSL Analysis**: Examines SSL/TLS certificates and configuration
- **Ultra-Minimal Binaries**: Extreme UPX compression enabled by default for smallest possible executables
- **Cross-Platform**: Works on Linux, macOS, and Windows
- **Top Ports Scanning**: Quick scan of the top 100 most common ports

## Security Notice

This tool is designed for network security professionals conducting authorized security tests. 
Running port scans against networks or systems without explicit permission is illegal in many jurisdictions and violates most network use policies.

**You are responsible for using this tool ethically and legally.**

## Installation

### Prerequisites

- Rust 1.67.0 or later
- Cargo
- libpcap development files (for packet capture capabilities)
- UPX (Optional but recommended for binary compression - installed by default)

On Debian/Ubuntu systems:
```
sudo apt install libpcap-dev upx-ucl
```

On RHEL/Fedora:
```
sudo dnf install libpcap-devel upx
```

On macOS with Homebrew:
```
brew install libpcap upx
```

### Building from source

```
git clone https://github.com/yourusername/quantum_scanner_rs.git
cd quantum_scanner_rs
./build.sh
```

For additional build options:
```
./build.sh --help
```

To install the binary system-wide (requires root):
```
sudo ./build.sh --install
```

To build a fully static binary using Docker:
```
sudo ./build.sh --static-build
```

The compiled binary will be in `target/release/quantum_scanner` and also copied to `./quantum_scanner`.

## Usage

Basic syntax:
```
quantum_scanner [OPTIONS] <TARGET>
```

Examples:
```
# Simple SYN scan of common ports on a single host
quantum_scanner 192.168.1.1

# Scan the top 100 most common ports
quantum_scanner --top-100 192.168.1.1

# Comprehensive scan of a host with multiple techniques
quantum_scanner --scan-types syn,fin,ssl,udp --ports 1-1000 192.168.1.1

# Stealthy scan with evasion techniques
quantum_scanner --evasion 192.168.1.1

# Memory-only mode for enhanced operational security
quantum_scanner --memory-only 192.168.1.1

# Scan with protocol mimicry
quantum_scanner --scan-types mimic --mimic-protocol HTTP 192.168.1.1

# Scan an entire subnet
quantum_scanner --scan-types syn --ports 22,80,443 192.168.1.0/24
``` 