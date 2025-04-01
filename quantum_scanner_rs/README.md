# Quantum Scanner (Rust Edition)

An advanced port scanner with evasion capabilities written in Rust.

## Features

- **Multiple Scan Techniques**: SYN, ACK, FIN, XMAS, NULL, SSL, UDP, and more
- **Stealthy Evasion**: Fragmentation, protocol mimicry, TLS echo scans
- **Performance**: High-speed concurrent scanning leveraging Rust's async capabilities
- **Service Detection**: Identifies services running on open ports
- **SSL Analysis**: Examines SSL/TLS certificates and configuration
- **Cross-Platform**: Works on Linux, macOS, and Windows

## Security Notice

This tool is designed for network security professionals conducting authorized security tests. 
Running port scans against networks or systems without explicit permission is illegal in many jurisdictions and violates most network use policies.

**You are responsible for using this tool ethically and legally.**

## Installation

### Prerequisites

- Rust 1.67.0 or later
- Cargo
- libpcap development files (for packet capture capabilities)

On Debian/Ubuntu systems:
```
sudo apt install libpcap-dev
```

On RHEL/Fedora:
```
sudo dnf install libpcap-devel
```

On macOS with Homebrew:
```
brew install libpcap
```

### Building from source

```
git clone https://github.com/yourusername/quantum_scanner_rs.git
cd quantum_scanner_rs
cargo build --release
```

The compiled binary will be in `target/release/quantum_scanner`.

## Usage

Basic syntax:
```
quantum_scanner [OPTIONS] <TARGET>
```

Examples:
```
# Simple SYN scan of common ports on a single host
quantum_scanner -s syn 192.168.1.1

# Comprehensive scan of a host with multiple techniques
quantum_scanner -s syn,fin,ssl,udp -p 1-1000 192.168.1.1

# Stealthy fragmented scan with evasion techniques
quantum_scanner -s frag -e -p 80,443,8080 192.168.1.1

# Scan an entire subnet
quantum_scanner -s syn -p 22,80,443 192.168.1.0/24
```

## Command-line Options

```
USAGE:
    quantum_scanner [OPTIONS] <TARGET>

ARGS:
    <TARGET>    Target IP address, hostname, or CIDR notation for subnet

OPTIONS:
    -p, --ports <PORTS>                Ports to scan (comma-separated, ranges like 1-1000)
    -s, --scan-types <SCAN_TYPES>      Scan techniques to use [default: syn]
                                       [possible values: syn, ack, fin, xmas, null, window, ssl, udp, tls_echo, mimic, frag]
    -c, --concurrency <CONCURRENCY>    Maximum concurrent operations [default: 100]
    -r, --rate <RATE>                  Maximum packets per second [default: 500]
    -e, --evasion                      Enable evasion techniques
    -v, --verbose                      Enable verbose output
    -6, --ipv6                         Use IPv6
    -j, --json                         Output results in JSON format
    -o, --output <FILE>                Write results to file
    -t, --timeout <SECONDS>            Scan timeout in seconds [default: 3.0]
    -h, --help                         Print help information
    -V, --version                      Print version information
```

## Improvements over Python Version

- Faster execution using Rust's zero-cost abstractions
- Improved memory safety and thread safety
- More efficient async I/O with Tokio
- Better error handling with Rust's Result type
- No runtime dependencies once compiled
- More granular rate limiting and adaptive timing
- Enhanced packet crafting capabilities

## License

MIT License

## Acknowledgments

This is a Rust port of the original Python Quantum Scanner. 