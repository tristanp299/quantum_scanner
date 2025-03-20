# quantum_scanner

quantum_scanner.py was originally made to circumvent firewalls and pesky IDS and EDRs that would stop my enumeration mid scan. BOOO! 

So instead of switching my exit node like a normal person I decided to create a port scanner that would utilize quantum computing ciphers and techniques to evade any stoppage.

Well believe it or not that stuff if hard, so for now I made a port scanner that has some special scanning methods that helped me around those walls of fire. 

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