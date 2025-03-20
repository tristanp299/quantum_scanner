# quantum_scanner

## Author Comments

quantum_scanner.py was originally made to circumvent firewalls and pesky IDS and EDRs that would stop my enumeration mid scan. BOOO! 

So instead of switching my exit node like a normal person I decided to create a port scanner that would utilize quantum computing ciphers and techniques to evade any stoppage.

Well believe it or not that stuff is hard, so for now I made a port scanner that has some special scanning methods that helped me around those walls of fire. 

## What is this thing?

Quantum Scanner is a Python-based multi-mode port scanner that offers both TCP/UDP scans (SYN, ACK, FIN, etc.) and additional specialized scans like a fragmented SYN scan and a mimic-based probe. It uses Scapy under the hood for packet crafting and sniffing, plus asyncio to manage concurrent scanning.
Features

    Multiple Scan Types
        TCP: SYN, ACK, FIN, XMAS, NULL, WINDOW
        UDP: Basic open/closed detection without relying heavily on ICMP
        TLS: SSL probe (to retrieve certificate info) and TLS Echo Mask scans
        Mimic: Sends a partial protocol banner in the SYN packet (HTTP, SSH, FTP, etc.)
        Fragmented SYN: Splits the SYN + data into multiple IP fragments, potentially bypassing some firewalls.

    Additional Tools
        Banner Grabbing: Automatically attempts to read a banner from open TCP ports.
        Service Fingerprinting: Guesses service based on banner or known ports.

    Evasion Options
        TTL/Hop Limit: Randomize the IPv4 TTL or IPv6 hlim.
        Fragmentation: Fine-tune fragment size, number of fragments, and timing.

Installation & Requirements

    Python 3.7+ (tested with Python 3.10, 3.11, etc.)
    Scapy – Used for packet creation and sniffing
    cryptography – For SSL certificate parsing
    rich – Pretty console output and progress bars

Install the dependencies:

pip install scapy cryptography rich

Make sure you have appropriate permissions for raw socket operations:

    Linux: Typically requires root (or CAP_NET_RAW).
    Mac/Windows: Administrator privileges.

Usage

python3 quantum_scanner.py [OPTIONS] target

Required Arguments

    target: A hostname or IP address (IPv4 or IPv6).
    -p/--ports: The ports you want to scan. Examples:
        Single port: -p 80
        Range of ports: -p 1-100
        Multiple definitions: -p 22,80,443

Common Scan Types

Use the -s or --scan-types option to select one or more scan types. For example:

-s syn ssl udp ack fin xmas null window tls_echo mimic frag

Defaults to ["syn"] if none are specified.
Example Command

sudo python3 quantum_scanner.py -p 80,443 -s syn ssl udp ack fin \
    --verbose 10.0.0.5

Additional Options

    -v, --verbose: Prints debug information.
    -e, --evasions: Enables additional evasion features (random TTL, fragmentation, etc.).
    --ipv6: Scans the target via IPv6.
    --json-output: Also writes results to scan_results.json.
    --shuffle-ports: Randomizes the port list to help avoid detection.
    --log-file: Specify a log file path (default scanner.log).
    --max-rate: Limit max packets/second (default=500).
    --concurrency: Number of asynchronous tasks (default=100).

Timeouts

    --timeout-scan: Packet receive timeout per scan (default=3.0s)
    --timeout-connect: TCP connection timeout for banner grabbing or SSL (default=3.0s)
    --timeout-banner: Banner read timeout (default=3.0s)

Mimic Scan

The mimic scan type sends a partial protocol banner in the TCP SYN packet.

    --mimic-protocol: Choose from "HTTP", "SSH", "FTP", etc. (default=HTTP)

sudo python3 quantum_scanner.py 10.0.0.5 -p 22 -s mimic --mimic-protocol SSH

Fragmented SYN Scan

The frag scan type intentionally splits a single TCP SYN packet + data into multiple IP fragments.

    --frag-min-size & --frag-max-size: Byte range of each fragment (defaults 16-64).
    --frag-min-delay & --frag-max-delay: Random delay between fragment sends (defaults 0.01-0.1s).
    --frag-timeout: Sniffer timeout to wait for responses (default=10s).

Additional Fragment Options

    --frag-first-min-size (default=64):
    Ensures the first fragment is at least this many bytes, so the entire TCP header (and possibly some data) is in fragment #1.

    --frag-two-frags:
    If used, the script sends exactly two fragments total for each SYN – the first includes the entire TCP header plus some data, the second includes any remaining data. Some firewalls block many-fragment scenarios but allow minimal fragmentation.

Example: Using frag with bigger first fragment and exactly two fragments:

sudo python3 quantum_scanner.py 10.0.0.5 -p 80 -s frag \
    --frag-first-min-size 128 \
    --frag-two-frags

Note: Modern firewalls often drop or ignore fragmented SYN packets, so you may see “filtered” even for an open port.
Output

After each scan completes, results are printed in a Rich table with columns:

    Port
    TCP states (e.g., syn: open, frag: filtered)
    UDP state
    Filtering
    Service name (heuristic or from banner)
    Version (from SSL or banner)
    Vulnerabilities (simple pattern matches)
    OS Guess (basic TTL-based heuristic)

If --json-output is set, scan_results.json will be generated with the same data in JSON form.
Development and Contributing

Pull requests and forks are welcome! For suggestions, please open an issue.
Because the script depends on raw packets, some features require root/administrator access.
Testing on a local lab or Docker environment without strict firewalls is recommended if you want to see the full effect of advanced fragmentation/evasions.

Disclaimer: This tool is provided for legitimate testing and research only. Be sure to have proper authorization for scanning remote systems.

## Special Port Scans

### TLS Echo Mask Scan

Designed to evade firewalls by disguising TCP SYN packets as part of a TLS handshake response (specifically, a Server Hello message). Since ICMP traffic is often blocked, this approach uses TLS. The scanner crafts packets that appear as responses to a non-existent client handshake, slipping past firewalls that don’t perform full TLS state tracking or deep packet inspection.

- Create a TCP SYN packet with a payload mimicking a TLS Server Hello message (TLS record type 22, handshake type 2). This makes it look like the target requested a TLS connection, and this is the server’s reply.

Note:
- Traditional scans don’t hide behind TLS handshake responses, giving this an edge against signature-based detection.
- Firewalls permitting TLS traffic (e.g., port 443) may allow this packet if they don’t inspect payloads or enforce strict handshake state tracking.
- Firewalls with TLS decryption or advanced stateful inspection might detect the lack of a prior Client Hello, so it’s not foolproof against high-end setups.

### Protocol Mimic Scan 

Sends a SYN packet with a payload from mimic_payloads to disguise the scan as a legitimate protocol response.

    - Constructs a packet with IP / TCP(SYN) / Raw(payload).
    - Sends it using Scapy’s sr1() and waits for a response.
    - Analyzes the TCP flags: SYN-ACK (open), RST (closed), or no response (filtered).

Note: 
- Firewalls allowing HTTP traffic on port 80 might permit a SYN packet with an HTTP payload, even if unsolicited.
- SSH traffic on port 22 or FTP on port 21 might be allowed if the payload matches expected protocol responses.

### Fragmented SYN Scan Function

Performs a SYN scan by fragmenting the packet into multiple IP fragments with randomized sizes and sending delays to evade detection.

    - Randomized Fragment Sizes: Splits a 1400-byte payload into fragments between min_frag_size and max_frag_size (multiples of 8 bytes).
    - Randomized Delays: Adds delays between fragments (between min_delay and max_delay) to make traffic less predictable.
    - Proper Fragmentation: Sets correct fragment offsets and "More Fragments" (MF) flags for reassembly.
    - Response Handling: Uses a separate sniffing thread to capture SYN-ACK or RST responses.

Note: 
- IP fragment offsets are in 8-byte units, and payload sizes (except the last) are multiples of 8 to ensure proper reassembly by the target.
- SYN packets with large payloads are non-standard, potentially bypassing DPI rules focused on typical scans.

##### Important fragmentation flags

- --frag-first-min-size:
Ensures the first fragment has room for the entire TCP header (often up to 60 bytes with options) plus some data.

    - Default is 64, making it more likely that the target’s TCP stack will see a valid SYN in that first fragment.

- --frag-two-frags:
If set, the scan splits the SYN + data into exactly two fragments. One includes at least --frag-first-min-size bytes; the second includes all remaining data.

    - This can help if a firewall or target OS is okay with minor fragmentation but discards heavily fragmented packets.

# Legal Disclaimer

This script is for educational purposes only. Network scanning without permission is illegal and unethical. Always obtain explicit consent before testing any system.
