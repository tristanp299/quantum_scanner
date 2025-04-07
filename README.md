# Quantum Scanner

**An Advanced Port Scanner Optimized for Red Team Operations and Stealth**

Quantum Scanner is designed for security professionals engaged in authorized penetration testing and red team engagements. It incorporates multiple scanning techniques and advanced evasion features to minimize the operational footprint and bypass common security defenses.

## Core Features

This scanner provides a range of capabilities tailored for sophisticated network reconnaissance:

-   **Multiple Scan Techniques:** Offers flexibility to adapt to different network environments and security postures.
    -   `SYN` (Stealth/Half-Open): Initiates but doesn't complete TCP connections. Less likely to be logged by target applications but easily detected by modern firewalls/IDS.
    -   `SSL/TLS`: Connects to potential SSL/TLS ports to grab certificate information and confirm encryption.
    -   `UDP`: Scans for open UDP ports. Often slower and less reliable than TCP scans, but crucial as UDP services are frequently overlooked.
    -   `ACK`, `FIN`, `XMAS`, `NULL`, `Window`: These scans manipulate TCP flags in ways that can trick certain firewalls or IDS into revealing port states based on how they respond (or don't respond) according to RFC standards (or lack thereof). Effective against stateless firewalls but less so against stateful ones.
    -   `TLS-Echo`: A specialized technique for detecting services hidden behind TLS proxies or load balancers.
    -   `Mimic`: Attempts to make scan traffic resemble legitimate application traffic (e.g., web browsing) to blend in.
    -   `Frag`: Splits scan packets into smaller fragments, potentially bypassing older intrusion detection systems that don't reassemble packets properly.
    -   `DNS Tunnel`: Tunnels scan traffic through DNS queries to bypass restrictive firewalls that allow DNS traffic.
    -   `ICMP Tunnel`: Tunnels scan traffic through ICMP echo (ping) packets to bypass restrictive firewalls that allow ICMP traffic.

-   **Enhanced Evasion Techniques:** Employs methods to avoid detection by network security monitoring tools. This includes packet fragmentation (`Frag`), traffic mimicry (`Mimic`), random timing delays (`--random-delay`), source port manipulation, and potentially decoy scanning (consult specific options).

-   **Memory-Only Mode (`-m`):** Designed for high-stakes operations where leaving traces on disk is unacceptable. Aims to load and execute the scanner primarily in RAM, minimizing forensic artifacts on the host system. (Requires suitable OS support/configuration, may involve RAM disk usage).

-   **Banner Grabbing & Service Identification:** Attempts to retrieve service banners (e.g., SSH version, web server type) from open ports to help identify running software and potential vulnerabilities.

-   **ML-based Service Identification:** Uses machine learning techniques to accurately identify services and extract version information when traditional banner grabbing isn't conclusive. This feature can detect services even when banners are obfuscated or missing by analyzing response patterns, characteristics, and behavior.

-   **IPv6 Support:** Fully capable of scanning IPv6 addresses and subnets.

-   **Tor Routing Support (`--use-tor`):** Can route scan traffic through the Tor network for source IP address anonymization. Requires a working Tor instance on the system. (Be aware of Tor's limitations and potential performance impact).

-   **OpSec-Focused Design:** Built with operational security considerations at its core, including features for artifact reduction and network stealth.

## Building Quantum Scanner

The included `build.sh` script simplifies the compilation process.

### Standard Build

Compiles a standard dynamically linked executable.

```bash
./build.sh
```

### Portable Build (Optimized Dynamic Linking)

Previously known as `--static`, this option now creates a portable binary using optimized *dynamic* linking. Full static linking with `musl` often caused compatibility issues across different Linux distributions. This approach offers broad compatibility while keeping the binary relatively self-contained. Ideal for running the scanner on various target systems without needing to install dependencies.

```bash
./build.sh --static
```

### Docker-Based Builds

The scanner can be built using Docker with a consolidated, security-focused Dockerfile. The build script automatically handles the Docker build process when using the `--static` option.

Key Docker build features include:
- Automatic adaptation to requested compression options (`--compress`, `--ultra`)
- TLS/certificate issue workarounds for secure environments
- Memory-optimized build flags for reliability
- Fully static binary output using musl
- Minimal final image based on scratch

For custom Docker builds, you can also use build arguments directly:
```bash
docker build --build-arg ENABLE_UPX=true --build-arg BYPASS_TLS_SECURITY=true .
```

### Additional Build Options

-   `--strip`: **(Recommended for Ops)** Removes debugging symbols from the binary. This significantly reduces file size and makes reverse engineering more difficult for defenders. (Enabled by default when using `--static`).
-   `--compress`: Uses UPX (Ultimate Packer for Executables) to compress the binary. Reduces size, which can help with exfiltration or bypassing size-based detection rules. *Caution:* Compressed binaries can sometimes be flagged by antivirus software.
-   `--ultra`: Applies more aggressive UPX compression. Further reduces size but increases the binary's startup time and potentially the risk of AV detection.
-   `--debug`: Builds with debugging information included. **Only use for development purposes, never for actual operations.**
-   `--clean`: Removes previous build artifacts before starting a new build. Good practice for ensuring a clean state.
-   `--no-fix`: Skips the step where the build script might automatically adjust dependencies in `Cargo.toml`. For advanced users managing dependencies manually.

### Build Improvements Notes

The build process benefits from:
- Optimized dependencies for faster compilation and smaller binaries.
- Improved error handling during compilation.
- Target-specific optimizations for better performance.
- **RAM Disk Support:** Facilitates running operations from memory (see OpSec Guidance).
- Docker integration for consistent builds in containerized environments.

## Usage

Always run Quantum Scanner with appropriate privileges, typically root, especially for raw socket operations like SYN scans.

```
quantum_scanner [OPTIONS] <TARGET>
```

Where `<TARGET>` can be:
- A single IP address (e.g., `192.168.1.100`, `2001:db8::1`)
- A hostname (e.g., `target.local`, `example.com`)
- A CIDR range (e.g., `192.168.1.0/24`, `10.0.0.0/16`)

### Basic Example (Default Scan)

Performs a default scan (often a SYN scan of common TCP ports) against the target. Requires root privileges for SYN scans.

```bash
sudo ./quantum_scanner 192.168.1.1
```

### Scan Specific Ports

Scans only the specified ports (TCP 22, 80, 443 in this case).

```bash
sudo ./quantum_scanner -p 22,80,443 192.168.1.1
```

### Advanced Scan with Evasion

Combines multiple stealthy scan types (`syn`, `fin`, `xmas`) with general evasion techniques (`-E`) and adds random delays between probes (`--random-delay`) to make the scan less predictable and more likely to bypass rate limiting or simple pattern detection.

```bash
sudo ./quantum_scanner -E -s syn,fin,xmas 192.168.1.1 --random-delay
```

### Memory-Only Mode (High Stealth)

Instructs the scanner to operate entirely from RAM, avoiding disk writes for logs or temporary files. This is critical for minimizing forensic evidence on the source machine.

```bash
sudo ./quantum_scanner -m 192.168.1.1
```

### JSON Output for Tool Integration

Outputs scan results in JSON format for integration with other tools or data processing scripts.

```bash
sudo ./quantum_scanner -j 192.168.1.1
```

### Scanning Top Common Ports

Quickly scan only the top 100 most commonly used ports rather than a full range.

```bash
sudo ./quantum_scanner -T 192.168.1.1
```

### Routing Traffic Through Tor

Route scanning traffic through the Tor network for anonymization (requires Tor to be installed and running).

```bash
sudo ./quantum_scanner --use-tor 192.168.1.1
```

### Using DNS Tunneling for Restricted Networks

Scans the target using DNS tunneling to bypass firewalls that block traditional scan types but allow DNS traffic.

```bash
sudo ./quantum_scanner --dns-tunnel --lookup-domain example.com 10.0.0.1
```

### Using ICMP Tunneling for Restricted Networks

Scans the target using ICMP tunneling (ping packets) to bypass firewalls that block traditional scan types but allow ICMP traffic.

```bash
sudo ./quantum_scanner --icmp-tunnel 10.0.0.1
```

### Enhanced Service Identification with ML

Uses the ML-based service identification to accurately identify services even when traditional banner grabbing is inconclusive.

```bash
sudo ./quantum_scanner --ml-ident 192.168.1.1
```

### Comprehensive Command Options

Here's a list of all available command options and their descriptions:

#### Target and Port Selection
- `TARGET` - Target IP address, hostname, or CIDR subnet (required)
- `-p, --ports <PORTS>` - Ports to scan as comma-separated list or ranges (default: "1-1000")
- `-T, --top-100` - Scan the top 100 common ports instead of specified range

#### Scan Methods
- `-s, --scan-types-str <TYPES>` - Scan techniques to use as comma-separated list (default: "syn")
  - Available scan types: syn, ssl, udp, ack, fin, xmas, null, window, tls-echo, mimic, frag
  - Example: `-s syn,fin,xmas`
  
#### Scan Control
- `-c, --concurrency <NUM>` - Maximum concurrent scan operations (default: 100)
- `-r, --rate <RATE>` - Maximum packets per second (default: random between 100-500)
- `-t, --timeout <SECONDS>` - General scan timeout in seconds (default: 3.0)
- `--timeout-connect <SECONDS>` - Connection timeout in seconds (default: 3.0)
- `--timeout-banner <SECONDS>` - Banner grabbing timeout in seconds (default: 3.0)

#### Evasion Techniques
- `-e, --evasion` - Enable basic evasion techniques
- `-E, --enhanced-evasion` - Enable advanced evasion techniques (default: false) - disables banner grabbing to reduce detection footprint
- `--mimic-os <OS>` - OS to mimic in enhanced evasion (default: random)
- `--ttl-jitter <NUM>` - TTL jitter amount for enhanced evasion (1-5) (default: 2)
- `--protocol-variant <VARIANT>` - Protocol variant for protocol mimicry
- `--random-delay` - Add randomized delay before scan start (default: true)
- `--max-delay <SECONDS>` - Maximum random delay in seconds (default: 3)
- `--mimic-protocol <PROTOCOL>` - Protocol to mimic in mimic scans (default: "HTTP")

#### Fragmentation Options
- `--frag-min-size <SIZE>` - Minimum fragment size for fragmented scans (default: 24)
- `--frag-max-size <SIZE>` - Maximum fragment size for fragmented scans (default: 64)
- `--frag-min-delay <SECONDS>` - Minimum delay between fragments in seconds (default: 0.01)
- `--frag-max-delay <SECONDS>` - Maximum delay between fragments in seconds (default: 0.1)
- `--frag-timeout <SECONDS>` - Timeout for fragmented scans in seconds (default: 10)
- `--frag-first-min-size <SIZE>` - Minimum size of first fragment (default: 64)
- `--frag-two-frags` - Use exactly two fragments

#### Output Control
- `-v, --verbose` - Enable verbose output (detailed logs and scan information)
- `-j, --json` - Output results in JSON format
- `-o, --output <FILE>` - Write results to file
- `--color` - Use ANSI colors in output (default: true)

#### IPv6 Support
- `-6, --ipv6` - Use IPv6 addressing

#### Operational Security Features
- `-m, --memory-only` - Enable memory-only mode (no disk writes)
- `--use-tor` - Route traffic through Tor if available (default: true)
- `--use-ramdisk` - Create RAM disk for temporary files (default: true)
- `--ramdisk-size <SIZE>` - RAM disk size in MB (default: 10)
- `--ramdisk-mount <PATH>` - RAM disk mount point (default: "/mnt/quantum_scanner_ramdisk")
- `--encrypt-logs` - Encrypt logs with a password (default: true)
- `--log-password <PASSWORD>` - Password for log encryption
- `--log-file <PATH>` - Log file path (default: "scanner.log")
- `--secure-delete` - Securely delete files after scan (disabled by default for safety)
- `--delete-passes <PASSES>` - Number of secure delete passes (default: 3)

#### Special Operations
- `--fix-log-file <PATH>` - Path to a log file to unredact (without running a scan)

#### Protocol Tunneling Options
- `--dns-tunnel` - Enable DNS tunneling for scan traffic to bypass restrictive firewalls
- `--icmp-tunnel` - Enable ICMP tunneling for scan traffic to bypass restrictive firewalls
- `--dns-server <SERVER>` - Custom DNS server to use for DNS tunneling (IP address)
- `--lookup-domain <DOMAIN>` - Custom lookup domain to use for DNS tunneling (default: "scanner-probe.net")

#### Service Identification Options
- `--ml-ident` - Enable ML-based service identification for more accurate detection (default: true)

## Requirements

-   **Operating System:** Linux (tested primarily on Kali, Ubuntu, Debian). Compatibility with other distributions may vary.
-   **Compiler:** Rust compiler toolchain (install via `rustup`). Check for any specific version requirements.
-   **Privileges:** Root access (`sudo`) is required for raw socket operations (e.g., SYN, FIN, XMAS scans) and potentially for binding to privileged ports.
-   **Dependencies:** Ensure necessary build tools (`build-essential`, `pkg-config`, `libssl-dev`) and potentially packet capture libraries (`libpcap-dev`) are installed.

## Operational Security (OpSec) Guidance

**Crucial considerations for red team use:**

1.  **Execution Environment:**
    *   Avoid running directly from your primary user directory.
    *   Consider executing from a dedicated, encrypted volume or a RAM disk (`tmpfs`) to minimize disk artifacts.
    *   Rename the binary from `quantum_scanner` to something inconspicuous (e.g., `updater`, `mem_check`) to avoid easy identification if discovered.

2.  **Network Footprint:**
    *   **Source Anonymization:** Use the `--use-tor` option (requires Tor service) or route traffic through trusted redirectors or VPNs configured specifically for operations. Never scan directly from your real IP address during sensitive engagements.
    *   **Timing & Stealth:** Use `--random-delay` and consider rate-limiting options (if available) to blend in with normal traffic and avoid triggering IDS/IPS alerts based on scan speed.
    *   **Scan Selection:** Choose scan types (`-s`) appropriate for the target environment. A loud TCP connect scan might be fine in some contexts but disastrous in others. Start with stealthier methods.

3.  **Artifact Management:**
    *   **Memory-Only:** Prioritize using memory-only mode (`-m`) whenever possible to prevent logs and temporary files from being written to disk.
    *   **Logging:** If logging is absolutely necessary (e.g., for large scans needing later analysis), use `--encrypt-logs` and ensure logs are stored on an encrypted volume.
    *   **Cleanup:** Use `--secure-delete` cautiously for log cleanup. Understand that secure deletion on modern SSDs is complex due to wear-leveling and garbage collection; it's not foolproof. The best approach is to avoid creating the artifact in the first place (use `-m`). After building, use `./build.sh --clean` to remove intermediate build files.

4.  **Binary Handling:**
    *   Always use binaries compiled with `--strip`.
    *   Consider `--compress` if size is a concern, but be aware of potential AV flags.
    *   Verify the integrity of your tools before and after transferring them to ensure they haven't been tampered with.

5.  **Situational Awareness:**
    *   Understand the target's potential monitoring capabilities (IDS/IPS, EDR, SIEM).
    *   Correlate scan findings with other reconnaissance data. Don't rely solely on scanner output.
    *   Be prepared to modify or cease scanning activity if detection is suspected.

## Technical Feature Details

### Scan Types

Quantum Scanner supports multiple scan techniques, each with different advantages:

#### SYN Scan
- **Description:** Sends TCP SYN packets and analyzes responses.
- **Advantages:** Fast, efficient, relatively stealthy.
- **Detection:** Easily detected by modern IDS/IPS but less likely to be logged by applications.
- **Best For:** Initial port reconnaissance where basic stealth is sufficient.

#### SSL/TLS Scan  
- **Description:** Probes for SSL/TLS service information and certificates.
- **Advantages:** Provides detailed information about TLS implementation and certificates.
- **Detection:** Appears as normal SSL/TLS handshake.
- **Best For:** Identifying encryption services and analyzing certificate details.

#### UDP Scan
- **Description:** Probes UDP ports and analyzes ICMP responses.
- **Advantages:** Identifies UDP services often overlooked in TCP-only scans.
- **Detection:** Can be detected through ICMP monitoring.
- **Best For:** Comprehensive service discovery to include UDP services.

#### ACK, FIN, XMAS, NULL Scans
- **Description:** Uses non-standard TCP flag combinations.
- **Advantages:** May bypass simple packet filters or stateless firewalls.
- **Detection:** Easily detected by stateful inspection.
- **Best For:** Fingerprinting firewall capabilities or when other techniques fail.

#### TLS-Echo Scan
- **Description:** Specialized technique using TLS handshakes to probe services.
- **Advantages:** Can detect services hidden behind TLS proxies.
- **Detection:** Appears similar to a failed TLS handshake.
- **Best For:** Identifying hidden services behind TLS infrastructure.

#### Mimic Scan
- **Description:** Sends SYN packets with application-specific payloads.
- **Advantages:** Traffic resembles legitimate application communication.
- **Detection:** More difficult to detect as scanning activity.
- **Best For:** Evading pattern-based detection systems.

#### Frag Scan
- **Description:** Fragments scan packets into smaller pieces.
- **Advantages:** May bypass older IDS systems that don't reassemble fragments.
- **Detection:** Modern security systems typically reassemble and inspect fragments.
- **Best For:** Testing fragmentation handling or bypassing simple packet filters.

#### DNS Tunnel Scan
- **Description:** Tunnels scan traffic through DNS queries to a controlled domain.
- **Advantages:** Can bypass firewalls that block direct scanning but allow DNS traffic.
- **Detection:** Generates unusual DNS queries that may be detected by DNS monitoring systems.
- **Best For:** Scanning targets in highly restricted networks where traditional scanning methods are blocked.

#### ICMP Tunnel Scan
- **Description:** Encodes scan packets within ICMP echo (ping) packets.
- **Advantages:** Can bypass firewalls that allow ping traffic but block port scanning.
- **Detection:** May be detected by deep packet inspection or anomalous ICMP traffic patterns.
- **Best For:** Scanning targets with firewalls that allow ICMP traffic but restrict other protocols.

### Evasion Techniques

Quantum Scanner offers two levels of evasion capabilities:

#### Basic Evasion Mode (`-e`, `--evasion`)

When basic evasion is enabled, the scanner employs fundamental techniques to reduce detection:

- **Simple TTL Manipulation:** Uses common OS-specific TTL values to appear as normal traffic.
- **Basic Timing Randomization:** Adds small random delays between packets to avoid predictable patterns.
- **Minimal TCP Option Adjustment:** Modifies basic TCP options to avoid appearing as a scanner.
- **Packet Sequencing Randomization:** Uses random sequence numbers for TCP packets.

This mode is suitable for avoiding basic network monitoring tools but may still be detectable by sophisticated security systems.

#### Enhanced Evasion Mode (`-E`, `--enhanced-evasion`)

When enhanced evasion is enabled (default: false), Quantum Scanner employs sophisticated techniques to minimize detection:

- **Advanced OS Fingerprint Spoofing:** Precisely alters TTL, window sizes, and TCP options to mimic legitimate OS patterns for Windows, Linux, macOS, or Cisco devices.
- **Dynamic TTL Jittering:** Intelligently varies TTL values using jittering algorithms to avoid consistent patterns that might trigger detection.
- **Protocol-Specific Mimicry:** Generates protocol-specific payloads (HTTP, HTTPS, SSH, FTP, etc.) that closely resemble legitimate application traffic, complete with appropriate headers and version information.
- **Advanced Timing Randomization:** Uses statistical models to vary packet timing in ways that mimic real user behavior.
- **Variable Window Size Manipulation:** Dynamically adjusts window sizes to match target OS patterns.
- **Sophisticated Protocol Variants:** Can mimic specific protocol versions (e.g., HTTP/1.1, TLS 1.2) to blend with expected traffic patterns.
- **Banner Grabbing Suppression:** Completely disabled to reduce additional network traffic that would trigger detection systems.

**Features Disabled in Enhanced Evasion Mode:**
- **Banner Grabbing:** Completely disabled to reduce additional network traffic that would trigger detection systems.
- **Aggressive Service Detection:** Reduced to prevent generating patterns that could identify scanning activity.
- **Sequential Scanning:** Replaced with more randomized patterns to avoid triggering threshold-based alerts.

Enhanced evasion mode is suitable for environments with advanced security monitoring and can effectively reduce the scanner's detection footprint, at the cost of some detailed service information.

### Memory-Only Mode

The `-m` option enables memory-only operation:

- Logs are stored in memory buffers rather than written to disk.
- Temporary files are created in RAM disk if available.
- Scan results are only displayed in the terminal unless explicitly outputted.
- Leaves minimal forensic artifacts on the scanning system.

### Service and Vulnerability Detection

Quantum Scanner identifies service information through:

- Banner grabbing during connection to open ports.
- Analysis of SSL/TLS certificates for encrypted services.
- Protocol-specific probes for common services.
- Response pattern matching against known service fingerprints.

The scanner also performs basic vulnerability detection by:
- Identifying outdated service versions with known vulnerabilities.
- Checking for common misconfigurations in detected services.
- Looking for weak encryption or security implementations.

### ML-based Service Identification

The Quantum Scanner includes an advanced ML-based service identification system that can accurately identify services even when traditional banner grabbing methods are unreliable or inconclusive.

#### Core Capabilities:
- **Service Fingerprinting:** Analyzes service responses using multiple feature vectors rather than simple string matching.
- **Version Extraction:** Uses specialized patterns to extract version information from identified services.
- **Binary Protocol Analysis:** Can identify services using binary (non-text) protocols by analyzing response patterns.

#### Key Features:
- **Feature Vector Analysis:** Extracts dozens of features from service responses including character distributions, entropy, structural elements, and protocol indicators.
- **Port-Context Awareness:** Incorporates port information to improve classification accuracy.
- **Temporal Analysis:** Analyzes response timing characteristics which can help identify certain services.

#### When to Use:
- When services don't provide clear identification strings in banners
- For ambiguous or custom services that don't follow standard protocols
- When service banners have been deliberately modified to conceal the actual service

ML-based service identification is enabled by default (`--ml-ident`) and integrates seamlessly with the scanner's other service detection methods.

## License

Refer to the `LICENSE` file for distribution and usage rights.

## **Disclaimer: Use Responsibly**

**This tool is intended solely for authorized security testing and educational purposes.** Using Quantum Scanner against systems without explicit, written permission from the system owner is illegal and unethical. The developers assume no liability and are not responsible for any misuse or damage caused by this tool. **Always obtain proper authorization before conducting any scanning activity.**