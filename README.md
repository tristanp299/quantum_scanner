# Quantum Scanner

A sophisticated port scanner designed to evade firewalls and IDS/EDR systems using specialized scanning techniques.

## Overview

Quantum Scanner is an advanced multi-mode port scanner built in Python that offers comprehensive TCP/UDP scanning capabilities, including standard methods (SYN, ACK, FIN, etc.) and specialized evasion techniques like fragmented SYN scanning and protocol mimicry. It leverages Scapy for packet crafting and asyncio for efficient concurrent scanning.

## Key Features

- **Multiple Scan Types**
  - **TCP Scans**: SYN, ACK, FIN, XMAS, NULL, WINDOW
  - **UDP Scan**: Basic open/closed detection without ICMP dependency
  - **TLS Scans**: SSL probe (certificate analysis) and TLS Echo Mask scan
  - **Mimic Scan**: Sends protocol-specific banners in SYN packets (HTTP, SSH, FTP, etc.)
  - **Fragmented SYN**: Splits packets into multiple IP fragments to bypass firewall detection

- **Additional Capabilities**
  - **Banner Grabbing**: Automatically retrieves service banners from open TCP ports
  - **Service Fingerprinting**: Identifies services based on banners and port information
  - **Vulnerability Detection**: Basic identification of security issues

- **Evasion Techniques**
  - **TTL/Hop Limit Randomization**: Varies IPv4 TTL or IPv6 hop limit values
  - **Customizable Fragmentation**: Control fragment sizes, counts, and timing
  - **Protocol Mimicry**: Disguises scan packets as legitimate protocol responses

## Installation

### Prerequisites

- Python 3.7+ (tested with Python 3.10, 3.11)
- Appropriate permissions for raw socket operations:
  - Linux: Root access or CAP_NET_RAW capability
  - macOS/Windows: Administrator privileges

### Dependencies

```bash
pip install scapy cryptography rich
```

## Usage

### Basic Command Syntax

```bash
sudo python3 quantum_scanner.py [OPTIONS] target
```

### Required Arguments

- `target`: Hostname or IP address (IPv4 or IPv6)
- `-p/--ports`: Ports to scan, using any of these formats:
  - Single port: `-p 80`
  - Port range: `-p 1-100`
  - Multiple ports: `-p 22,80,443`

### Scan Type Selection

Use `-s` or `--scan-types` to select scan methods:

```bash
-s syn ssl udp ack fin xmas null window tls_echo mimic frag
```

If no scan type is specified, `syn` is used by default.

### Example Commands

Basic scan with multiple methods:
```bash
sudo python3 quantum_scanner.py -p 80,443 -s syn ssl udp --verbose 10.0.0.5
```

Full stealth scan with evasion techniques:
```bash
sudo python3 quantum_scanner.py -p 22,80,443 -s fin frag mimic --evasions --shuffle-ports 10.0.0.5
```

### Common Options

```
-v, --verbose         Print detailed debugging information
-e, --evasions        Enable additional evasion techniques
--ipv6                Use IPv6 for scanning
--json-output         Write results to scan_results.json
--shuffle-ports       Randomize port scanning order for detection avoidance
--log-file FILE       Specify custom log file path (default: scanner.log)
--max-rate N          Limit scanning rate to N packets/second (default: 500)
--concurrency N       Number of concurrent scanning tasks (default: 100)
```

### Timeout Settings

```
--timeout-scan N      Packet receive timeout in seconds (default: 3.0)
--timeout-connect N   TCP connection timeout in seconds (default: 3.0)
--timeout-banner N    Banner read timeout in seconds (default: 3.0)
```

## Advanced Scan Configuration

### Mimic Scan

The mimic scan sends partial protocol banners in TCP SYN packets to disguise the scan:

```
--mimic-protocol PROTOCOL   Protocol to mimic: HTTP, SSH, FTP, SMTP, IMAP, POP3 (default: HTTP)
```

Example:
```bash
sudo python3 quantum_scanner.py 10.0.0.5 -p 22 -s mimic --mimic-protocol SSH
```

### Fragmented SYN Scan

This scan splits TCP SYN packets into multiple IP fragments to evade detection:

```
--frag-min-size N     Minimum fragment size in bytes (default: 16)
--frag-max-size N     Maximum fragment size in bytes (default: 64)
--frag-min-delay N    Minimum delay between fragments in seconds (default: 0.01)
--frag-max-delay N    Maximum delay between fragments in seconds (default: 0.1)
--frag-timeout N      Timeout for fragmented scan response in seconds (default: 10)
--frag-first-min-size N  Minimum size for first fragment in bytes (default: 64)
--frag-two-frags      Use exactly two fragments per packet
```

Example:
```bash
sudo python3 quantum_scanner.py 10.0.0.5 -p 80 -s frag --frag-first-min-size 128 --frag-two-frags
```

> **Note**: Many modern firewalls detect or drop fragmented SYN packets. Results showing "filtered" may indicate this behavior rather than an actual closed port.

## Scan Results

Results are presented in a formatted table with columns showing:

- Port number
- TCP state (per scan type)
- UDP state
- Firewall filtering status
- Service identification
- Version information (from SSL or banners)
- Potential vulnerabilities
- OS fingerprinting results

When using `--json-output`, complete results are saved to `scan_results.json`.

## Advanced Scan Techniques Explained

### TLS Echo Mask Scan

This technique attempts to bypass firewalls by disguising TCP SYN packets as TLS handshake responses (Server Hello messages). Since this makes the packets appear as responses to legitimate client handshake requests, it may evade firewalls that:

- Allow TLS traffic on standard ports
- Don't perform deep packet inspection
- Lack full TLS state tracking capability

The scanner crafts packets with TLS record type 22 (handshake) and handshake type 2 (Server Hello) to simulate a TLS response.

### Protocol Mimic Scan

This scan sends SYN packets with partial protocol response data that matches the expected protocol for common services:

- Constructs IP/TCP(SYN)/Raw(payload) packets with payloads matching HTTP, SSH, FTP, etc.
- Analyzes responses: SYN-ACK (open), RST (closed), or no response (filtered)

This can bypass firewalls that allow certain protocols on their standard ports, even for unsolicited traffic.

### Fragmented SYN Scan

This technique attempts to avoid detection by splitting single SYN packets into multiple IP fragments:

- **Randomized Fragment Sizes**: Split payloads into fragments between min_frag_size and max_frag_size
- **Randomized Delays**: Add timing variations between fragment transmission
- **Proper Fragmentation**: Set correct fragment offsets and MF flags for proper reassembly
- **Customizable First Fragment**: Ensure TCP header is fully contained in first fragment

Fragment parameters can be fine-tuned:

- `--frag-first-min-size`: Ensures first fragment includes complete TCP header plus initial data
- `--frag-two-frags`: Uses exactly two fragments per packet for minimal fragmentation scenarios

## Legal Disclaimer

This tool is provided for educational and authorized security testing purposes only. Network scanning without explicit permission is illegal in many jurisdictions and violates most acceptable use policies. Always obtain appropriate authorization before scanning any systems you don't own.

## Author Notes

Quantum Scanner was originally created to overcome restrictive firewall and IDS/EDR systems that interrupt legitimate security testing. While the name suggests quantum encryption techniques, the current implementation focuses on conventional evasion methods that have proven effective in various testing scenarios.
