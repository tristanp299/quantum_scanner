# Quantum Scanner

Advanced port scanner with evasion capabilities for red team operations.

## Features

- Multiple scan techniques (SYN, SSL, UDP, ACK, FIN, XMAS, NULL, Window, TLS-Echo, Mimic, Frag)
- Enhanced evasion techniques to avoid detection
- Memory-only mode for operations that require no disk artifacts
- Banner grabbing and service identification
- IPv6 support
- Tor routing support
- OpSec-focused design

## Building

The scanner includes a comprehensive build script that handles compilation for both regular and portable builds.

### Standard Build

```bash
./build.sh
```

### Portable Build (previously --static)

```bash
./build.sh --static
```

The `--static` flag now builds a well-optimized portable binary with dynamic linking, as full static builds with musl encountered compatibility issues. This approach provides better compatibility across systems.

### Additional Build Options

- `--strip`: Strip debug symbols (enabled by default for --static builds)
- `--compress`: Apply UPX compression to reduce binary size
- `--ultra`: Apply extreme UPX compression (slows startup time)
- `--debug`: Build in debug mode
- `--clean`: Clean build artifacts before building
- `--no-fix`: Skip fixing dependencies in Cargo.toml

### Build Improvements

Recent improvements to the build process include:
- Optimized dependency management
- Better error handling for cross-platform compatibility
- Enhanced performance with target-specific optimizations
- RAM disk support for secure operations
- Improved Docker integration for containerized builds

## Usage

```
quantum_scanner [OPTIONS] <TARGET>
```

Where `<TARGET>` is an IP address, hostname, or CIDR notation for subnet.

### Basic Example

```bash
sudo ./quantum_scanner 192.168.1.1
```

### Scan Specific Ports

```bash
sudo ./quantum_scanner -p 22,80,443 192.168.1.1
```

### Advanced Scan with Evasion Techniques

```bash
sudo ./quantum_scanner -E -s syn,fin,xmas 192.168.1.1 --random-delay
```

### Memory-Only Mode

```bash
sudo ./quantum_scanner -m 192.168.1.1
```

## Requirements

- Linux (tested on Kali, Ubuntu, Debian)
- Rust compiler
- Root privileges (for raw socket operations)

## Security Considerations

- Using the `-m` (memory-only) flag prevents writing logs to disk
- Use `--secure-delete` to securely delete log files after operation
- Consider using `--encrypt-logs` for sensitive operations
- The `--use-tor` flag can provide additional anonymity when Tor is installed

## License

See LICENSE file for details.

## Disclaimer

This tool is provided for legitimate security testing and red team operations only. Users are responsible for ensuring they have proper authorization before scanning any systems. 