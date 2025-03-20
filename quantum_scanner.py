#!/usr/bin/env python3

# Yo! This is a pretty cool port scanner that can do all sorts of neat tricks
# It's got your basic SYN scans, SSL checks, UDP probes, and some fancy stuff
# like protocol mimicry and packet fragmentation. Basically, it's like a Swiss
# Army knife for network scanning. Oh, and it's got some stealth features too
# so you don't get caught by those pesky firewalls 😉

import asyncio
import logging
import random
import socket
import ssl
import sys
import os
import time
import threading
from argparse import ArgumentParser
from collections import deque
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional

# Import the good stuff we need
import scapy.all as scapy  # This is our packet manipulation buddy
from cryptography import x509  # For handling those SSL certs
from cryptography.hazmat.backends import default_backend
from rich.console import Console  # Makes our output look pretty
from rich.progress import Progress
from rich.table import Table

# Keep Scapy quiet 
scapy.conf.verb = 0
console = Console()

# Set up our logging - we want to see what's happening both in the file and console
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[logging.FileHandler("scanner.log"), logging.StreamHandler()],
)

# ################ ENUMS & DATA ################
class ScanType(Enum):
    '''
    Here's all the cool scanning techniques we can use:
    - SYN: The classic, fast and reliable
    - SSL: For checking those secure connections
    - UDP: When you need to check those UDP ports
    - ACK: Helps figure out if there's a firewall
    - FIN: Stealth mode activated
    - XMAS: Like FIN but with all the flags set
    - NULL: The minimalist approach
    - WINDOW: Checks those TCP window sizes
    - TLSECHO: Sneaky TLS detection
    - MIMIC: Makes our scan look like legit traffic
    - FRAG: Splits packets to sneak past firewalls
    '''
    SYN = "syn"
    SSL = "ssl"
    UDP = "udp"
    ACK = "ack"
    FIN = "fin"
    XMAS = "xmas"
    NULL = "null"
    WINDOW = "window"
    TLSECHO = "tls_echo"
    MIMIC = "mimic"  # Protocol Mimic Scan
    FRAG = "frag"    # Advanced Fragmented SYN Scan

@dataclass
class PortResult:
    '''
    This is where we store all the juicy info we find about each port.
    We keep track of:
    - What TCP states we found
    - UDP status
    - If there's a firewall in the way
    - What service is running
    - Version numbers
    - Any vulnerabilities we spot
    - SSL certificate details
    - Service banners
    - What OS we think it's running
    '''
    tcp_states: Dict[ScanType, str] = field(default_factory=dict)
    udp_state: str = ""
    filtering: str = ""
    service: str = ""
    version: str = ""
    vulns: List[str] = field(default_factory=list)
    cert_info: Optional[Dict] = None
    banner: str = ""
    os_guess: str = ""

# These are our protocol mimic payloads - they make our scans look legit
# Basically, we're pretending to be normal traffic to avoid detection
MIMIC_PAYLOADS = {
    "HTTP": b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n",
    "SSH": b"SSH-2.0-OpenSSH_8.2\r\n",
    "FTP": b"220 FTP Server Ready\r\n",
    "SMTP": b"220 mail.example.com ESMTP\r\n",
    "IMAP": b"* OK IMAP4rev1 Service Ready\r\n",
    "POP3": b"+OK POP3 server ready\r\n",
}

# ################ MAIN SCANNER ################
class QuantumScanner:
    '''
    This is our main scanner class - it's pretty awesome!
    Here's what it can do:
    1. Run all kinds of port scans
    2. Handle both IPv4 and IPv6 (future-proof!)
    3. Sneak past firewalls with evasion tricks
    4. Figure out what services are running
    5. Spot potential security issues
    '''
    def __init__(
        self,
        target: str,
        ports: List[int],
        scan_types: List[ScanType],
        concurrency: int = 100,
        max_rate: int = 500,
        evasions: bool = False,
        verbose: bool = False,
        use_ipv6: bool = False,
        json_output: bool = False,
        shuffle_ports: bool = False,
        timeout_scan: float = 3.0,
        timeout_connect: float = 3.0,
        timeout_banner: float = 3.0,
        # Fragment scan specific parameters
        mimic_protocol: str = "HTTP",
        frag_min_size: int = 16,
        frag_max_size: int = 64,
        frag_min_delay: float = 0.01,
        frag_max_delay: float = 0.1,
        frag_timeout: int = 10,
        frag_first_min_size: int = 64,
        frag_two_frags: bool = False
    ):
        '''
        Let's set up our scanner with all the good stuff!
        Here's what we need:
        - target: The machine we're gonna scan
        - ports: Which ports to check
        - scan_types: What kind of scans to run
        - concurrency: How many scans at once
        - max_rate: Don't overwhelm the target
        - evasions: Sneaky mode activated?
        - verbose: Want all the details?
        - use_ipv6: Future-proof scanning
        - json_output: Save results in JSON
        - shuffle_ports: Mix up the order
        - timeout_*: How long to wait
        - mimic_protocol: What to pretend to be
        - frag_*: Settings for packet splitting
        '''
        # Store our basic settings
        self.use_ipv6 = use_ipv6
        self.json_output = json_output
        self.shuffle_ports = shuffle_ports
        self.timeout_scan = timeout_scan
        self.timeout_connect = timeout_connect
        self.timeout_banner = timeout_banner
        self.mimic_protocol = mimic_protocol

        # Set up our fragmentation settings
        self.frag_min_size = max(frag_min_size, 24)  # Need enough space for TCP header
        self.frag_max_size = max(frag_max_size, self.frag_min_size)
        self.frag_min_delay = frag_min_delay
        self.frag_max_delay = frag_max_delay
        self.frag_timeout = frag_timeout
        self.frag_first_min_size = frag_first_min_size
        self.frag_two_frags = frag_two_frags

        # Figure out the target's IP address
        if not self.use_ipv6:
            self.target_ip = socket.gethostbyname(target)
            try:
                self.local_ip = scapy.conf.route.route(self.target_ip)[1]
            except Exception:
                self.local_ip = None
        else:
            info = socket.getaddrinfo(target, None, socket.AF_INET6)
            self.target_ip = info[0][4][0]
            self.local_ip = "::"

        # Get our ports ready
        if self.shuffle_ports:
            random.shuffle(ports)
        self.ports = ports
        self.scan_types = scan_types
        self.concurrency = concurrency
        self.max_rate = max_rate
        self.evasions = evasions
        self.verbose = verbose

        # Set up our results storage and rate limiting
        self.results: Dict[int, PortResult] = {}
        self.adaptation_factor = 1.0
        self.history = deque(maxlen=100)
        self.lock = asyncio.Lock()

        # Get SSL ready for secure connections
        self.ctx = ssl.create_default_context()
        self.ctx.check_hostname = False
        self.ctx.verify_mode = ssl.CERT_NONE

        # Check if we're root (needed for some cool tricks)
        if self.evasions and os.geteuid() != 0:
            logging.error("Hey! We need root privileges for the sneaky stuff! Exiting.")
            sys.exit(1)

        if self.verbose:
            logging.getLogger().setLevel(logging.DEBUG)

    async def run_scan(self):
        '''
        This is where the magic happens! Here's what we do:
        1. Set up our results storage
        2. Show a cool progress bar
        3. Run all our scans at once
        4. Figure out what services we found
        5. Look for security issues
        6. Show off our results
        '''
        logging.info(f"Starting scan of {self.target_ip}")
        for port in self.ports:
            self.results[port] = PortResult()

        with Progress() as progress:
            total_tasks = len(self.ports) * len(self.scan_types)
            task = progress.add_task("[cyan]Scanning...", total=total_tasks)
            sem = asyncio.Semaphore(self.concurrency)

            tasks = []
            for port in self.ports:
                tasks.append(asyncio.create_task(self.scan_port(port, progress, task, sem)))
            await asyncio.gather(*tasks)

        self.service_fingerprinting()
        self.analyze_vulnerabilities()
        self.generate_report()

    async def scan_port(self, port: int, progress, task, sem: asyncio.Semaphore):
        '''
        Let's scan a single port with all our cool techniques!
        We:
        1. Use a semaphore to not overwhelm things
        2. Run each type of scan we want
        3. Try to grab banners if we find something
        4. Keep the progress bar updated
        '''
        async with sem:
            for st in self.scan_types:
                # Run the right kind of scan
                if st == ScanType.SYN:
                    await self.syn_scan(port)
                elif st == ScanType.SSL:
                    await self.ssl_probe(port)
                elif st == ScanType.UDP:
                    await self.udp_scan(port)
                elif st == ScanType.ACK:
                    await self.ack_scan(port)
                elif st == ScanType.FIN:
                    await self.fin_scan(port)
                elif st == ScanType.XMAS:
                    await self.xmas_scan(port)
                elif st == ScanType.NULL:
                    await self.null_scan(port)
                elif st == ScanType.WINDOW:
                    await self.window_scan(port)
                elif st == ScanType.TLSECHO:
                    await self.tls_echo_mask_scan(port)
                elif st == ScanType.MIMIC:
                    await self.mimic_scan(port, self.mimic_protocol)
                elif st == ScanType.FRAG:
                    await self.fragmented_syn_scan(
                        port,
                        self.frag_min_size,
                        self.frag_max_size,
                        self.frag_min_delay,
                        self.frag_max_delay,
                        self.frag_timeout
                    )

                # If we found something open, let's grab its banner
                if any(state == "open" for state in self.results[port].tcp_states.values()):
                    await self.banner_grabbing(port)

                await self.adaptive_delay()

        progress.update(task, advance=len(self.scan_types))

    # -------------------- COMMON BUILDERS --------------------
    def build_ip_layer(self):
        '''
        Builds our IP packet layer - IPv4 or IPv6, whatever floats your boat!
        This is a helper that all our scan types use to make their packets.
        '''
        if not self.use_ipv6:
            ip_layer = scapy.IP(dst=self.target_ip)
            if self.local_ip:
                ip_layer.src = self.local_ip
            return ip_layer
        else:
            ip_layer = scapy.IPv6(dst=self.target_ip)
            if self.local_ip and self.local_ip != "::":
                ip_layer.src = self.local_ip
            return ip_layer

    def set_ip_ttl_or_hlim(self, ip_layer) -> None:
        '''
        Sets up the TTL (IPv4) or hop limit (IPv6) field.
        If we're in evasion mode, we randomize it to look less suspicious.
        '''
        if self.use_ipv6:
            ip_layer.hlim = random.choice([64, 128, 255]) if self.evasions else 64
        else:
            ip_layer.ttl = random.choice([64, 128, 255]) if self.evasions else 64

    # -------------------- SCAN METHODS --------------------
    async def syn_scan(self, port: int, max_tries=3):
        '''
        The classic SYN scan - fast and reliable!
        Here's how it works:
        1. Send a SYN packet
        2. Wait for the response
        3. Figure out what it means:
           - Got SYN/ACK? Port is open!
           - Got RST? Port is closed
           - Nothing? Might be filtered
        '''
        def do_syn_probe():
            for _ in range(max_tries):
                ip_layer = self.build_ip_layer()
                self.set_ip_ttl_or_hlim(ip_layer)
                sport = random.randint(1024, 65535)
                seq = random.randint(0, 2**32 - 1)
                tcp_layer = scapy.TCP(dport=port, sport=sport, flags="S", seq=seq)
                pkt = ip_layer / tcp_layer

                resp = scapy.sr1(pkt, timeout=self.timeout_scan, verbose=0)
                if resp is not None and resp.haslayer(scapy.TCP):
                    flags = int(resp[scapy.TCP].flags)
                    # Check for SYN/ACK => open
                    if (flags & 0x12) == 0x12:
                        # Send RST to close half-open
                        rst_pkt = ip_layer / scapy.TCP(dport=port, sport=sport, flags="R", seq=seq+1)
                        scapy.send(rst_pkt, verbose=0)
                        return "open", resp
                    # Check for RST => closed
                    elif (flags & 0x04) == 0x04:
                        return "closed", resp
            return "filtered", None

        loop = asyncio.get_running_loop()
        state, resp = await loop.run_in_executor(None, do_syn_probe)
        async with self.lock:
            self.results[port].tcp_states[ScanType.SYN] = state
            if state == "open" and resp is not None:
                self.os_fingerprint(port, resp)

    async def ack_scan(self, port: int):
        '''
        Let's check if there's a firewall in the way!
        This scan:
        1. Sends an ACK packet
        2. If we get RST back = no firewall
        3. If nothing = probably filtered
        '''
        def do_ack_probe():
            ip_layer = self.build_ip_layer()
            self.set_ip_ttl_or_hlim(ip_layer)
            tcp_layer = scapy.TCP(
                dport=port,
                sport=random.randint(1024, 65535),
                flags="A",
                seq=random.randint(0, 2**32 - 1)
            )
            pkt = ip_layer / tcp_layer
            resp = scapy.sr1(pkt, timeout=self.timeout_scan, verbose=0)
            if resp and resp.haslayer(scapy.TCP):
                flags = int(resp[scapy.TCP].flags)
                # If RST => port is "unfiltered"
                if (flags & 0x04) == 0x04:
                    return "unfiltered"
            return "filtered"

        loop = asyncio.get_running_loop()
        filtering = await loop.run_in_executor(None, do_ack_probe)
        async with self.lock:
            self.results[port].filtering = filtering

    async def fin_scan(self, port: int):
        '''
        Time for some stealth scanning!
        This one:
        1. Sends a FIN packet
        2. If nothing back = might be open
        3. If RST = definitely closed
        '''
        def do_fin_probe():
            ip_layer = self.build_ip_layer()
            self.set_ip_ttl_or_hlim(ip_layer)
            tcp_layer = scapy.TCP(
                dport=port,
                sport=random.randint(1024, 65535),
                flags="F",
                seq=random.randint(0, 2**32 - 1)
            )
            pkt = ip_layer / tcp_layer
            resp = scapy.sr1(pkt, timeout=self.timeout_scan, verbose=0)
            if resp and resp.haslayer(scapy.TCP):
                flags = int(resp[scapy.TCP].flags)
                if (flags & 0x04) == 0x04:
                    return "closed"
            return "open|filtered"

        loop = asyncio.get_running_loop()
        state = await loop.run_in_executor(None, do_fin_probe)
        async with self.lock:
            self.results[port].tcp_states[ScanType.FIN] = state

    async def xmas_scan(self, port: int):
        '''
        The Christmas tree scan - we set all the flags!
        Similar to FIN scan but more festive:
        1. Send packet with FIN+PSH+URG flags
        2. If nothing back = might be open
        3. If RST = definitely closed
        '''
        def do_xmas_probe():
            ip_layer = self.build_ip_layer()
            self.set_ip_ttl_or_hlim(ip_layer)
            tcp_layer = scapy.TCP(
                dport=port,
                sport=random.randint(1024, 65535),
                flags="FPU",
                seq=random.randint(0, 2**32 - 1)
            )
            pkt = ip_layer / tcp_layer
            resp = scapy.sr1(pkt, timeout=self.timeout_scan, verbose=0)
            if resp and resp.haslayer(scapy.TCP):
                flags = int(resp[scapy.TCP].flags)
                if (flags & 0x04) == 0x04:
                    return "closed"
            return "open|filtered"

        loop = asyncio.get_running_loop()
        state = await loop.run_in_executor(None, do_xmas_probe)
        async with self.lock:
            self.results[port].tcp_states[ScanType.XMAS] = state

    async def null_scan(self, port: int):
        '''
        The minimalist approach - no flags at all!
        Another stealth technique:
        1. Send packet with no flags
        2. If nothing back = might be open
        3. If RST = definitely closed
        '''
        def do_null_probe():
            ip_layer = self.build_ip_layer()
            self.set_ip_ttl_or_hlim(ip_layer)
            tcp_layer = scapy.TCP(
                dport=port,
                sport=random.randint(1024, 65535),
                flags=0,
                seq=random.randint(0, 2**32 - 1)
            )
            pkt = ip_layer / tcp_layer
            resp = scapy.sr1(pkt, timeout=self.timeout_scan, verbose=0)
            if resp and resp.haslayer(scapy.TCP):
                flags = int(resp[scapy.TCP].flags)
                if (flags & 0x04) == 0x04:
                    return "closed"
            return "open|filtered"

        loop = asyncio.get_running_loop()
        state = await loop.run_in_executor(None, do_null_probe)
        async with self.lock:
            self.results[port].tcp_states[ScanType.NULL] = state

    async def window_scan(self, port: int):
        '''
        Let's check those TCP window sizes!
        This scan:
        1. Sends an ACK packet
        2. Looks at the window size in response
        3. Sometimes spots open ports
        '''
        def do_window_probe():
            ip_layer = self.build_ip_layer()
            self.set_ip_ttl_or_hlim(ip_layer)
            tcp_layer = scapy.TCP(
                dport=port,
                sport=random.randint(1024, 65535),
                flags="A",
                seq=random.randint(0, 2**32 - 1)
            )
            pkt = ip_layer / tcp_layer
            resp = scapy.sr1(pkt, timeout=self.timeout_scan, verbose=0)
            if resp is None:
                return "filtered"
            if resp.haslayer(scapy.TCP):
                # If window != 0 => "open" in classic Window scan logic
                if resp[scapy.TCP].window != 0:
                    return "open"
                else:
                    return "closed"
            return "filtered"

        loop = asyncio.get_running_loop()
        state = await loop.run_in_executor(None, do_window_probe)
        async with self.lock:
            self.results[port].tcp_states[ScanType.WINDOW] = state

    async def udp_scan(self, port: int):
        '''
        Time to check those UDP ports!
        This scan:
        1. Sends a UDP packet
        2. Waits for response
        3. Checks for ICMP errors
        '''
        def do_udp_probe():
            ip_layer = self.build_ip_layer()
            self.set_ip_ttl_or_hlim(ip_layer)
            udp_layer = scapy.UDP(dport=port, sport=random.randint(1024, 65535))
            pkt = ip_layer / udp_layer / b"probe"
            resp = scapy.sr1(pkt, timeout=self.timeout_scan, verbose=0)
            if resp is None:
                return "open|filtered"
            if resp.haslayer(scapy.UDP):
                return "open"
            if resp.haslayer(scapy.ICMP):
                icmp = resp[scapy.ICMP]
                if icmp.type == 3 and icmp.code == 3:
                    return "closed"
                return "filtered"
            return "filtered"

        loop = asyncio.get_running_loop()
        state = await loop.run_in_executor(None, do_udp_probe)
        async with self.lock:
            self.results[port].udp_state = state

    async def ssl_probe(self, port: int):
        '''
        Let's check for SSL/TLS services!
        This probe:
        1. Tries to make an SSL connection
        2. Gets certificate info
        3. Checks SSL version
        4. Looks for security issues
        '''
        def do_ssl_connect():
            try:
                with socket.create_connection((self.target_ip, port), timeout=self.timeout_connect) as sock:
                    with self.ctx.wrap_socket(sock, server_hostname=self.target_ip) as ssock:
                        cert_bin = ssock.getpeercert(binary_form=True)
                        cert_info = self.parse_certificate(cert_bin) if cert_bin else {}
                        ssl_version = ssock.version()
                        return ("open", cert_info, ssl_version)
            except (ConnectionRefusedError, socket.timeout):
                return ("closed", None, "")
            except Exception as e:
                logging.debug(f"SSL probe error on port {port}: {e}")
                return ("closed", None, "")

        loop = asyncio.get_running_loop()
        state, cert_info, ssl_version = await loop.run_in_executor(None, do_ssl_connect)
        async with self.lock:
            self.results[port].tcp_states[ScanType.SSL] = state
            if state == "open":
                self.results[port].service = "SSL/TLS"
                self.results[port].cert_info = cert_info
                self.results[port].version = ssl_version or ""
                vulns = self.check_ssl_vulnerabilities(cert_info)
                self.results[port].vulns.extend(vulns)

    async def tls_echo_mask_scan(self, port: int):
        '''
        Sneaky TLS detection time!
        This technique:
        1. Sends SYN with minimal TLS data
        2. Can sneak past firewalls
        3. Spots TLS services
        '''
        def do_tls_echo_mask_probe():
            ip_layer = self.build_ip_layer()
            self.set_ip_ttl_or_hlim(ip_layer)
            tls_payload = (
                b"\x16"      # Content Type: Handshake
                b"\x03\x03"  # TLS 1.2
                b"\x00\x2f"  # length
                b"\x02"      # Handshake Type: Server Hello
                b"\x00\x00\x2b"  # Handshake length
                b"\x03\x03"  # Version repeated
                + os.urandom(32)  # Random
                + b"\x00"    # minimal
            )
            sport = random.randint(1024, 65535)
            seq = random.randint(0, 2**32 - 1)
            tcp_layer = scapy.TCP(dport=port, sport=sport, flags="S", seq=seq)
            pkt = ip_layer / tcp_layer / scapy.Raw(load=tls_payload)
            resp = scapy.sr1(pkt, timeout=3.0, verbose=0)
            if resp and resp.haslayer(scapy.TCP):
                flags = int(resp[scapy.TCP].flags)
                if (flags & 0x12) == 0x12:
                    # RST to close
                    rst_pkt = ip_layer / scapy.TCP(dport=port, sport=sport, flags="R", seq=seq+1)
                    scapy.send(rst_pkt, verbose=0)
                    return "open", resp
                elif (flags & 0x04) == 0x04:
                    return "closed", resp
            return "filtered", None

        loop = asyncio.get_running_loop()
        state, resp = await loop.run_in_executor(None, do_tls_echo_mask_probe)
        async with self.lock:
            self.results[port].tcp_states[ScanType.TLSECHO] = state
            if state == "open" and resp is not None:
                self.os_fingerprint(port, resp)

    # -------------------- MIMIC SCAN --------------------
    async def mimic_scan(self, port: int, protocol: str, max_tries=3):
        '''
        Let's pretend to be legit traffic!
        This technique:
        1. Sends SYN with protocol-specific data
        2. Looks like normal traffic
        3. Can sneak past IDS/IPS
        '''
        def do_mimic_probe():
            if protocol not in MIMIC_PAYLOADS:
                # Fall back to basic "HTTP" if unknown
                mimic_data = b""
                logging.warning(f"Unknown protocol '{protocol}', using empty payload.")
            else:
                mimic_data = MIMIC_PAYLOADS[protocol]

            ip_layer = self.build_ip_layer()
            self.set_ip_ttl_or_hlim(ip_layer)
            sport = random.randint(1024, 65535)
            seq = random.randint(0, 2**32 - 1)

            for _ in range(max_tries):
                tcp_layer = scapy.TCP(dport=port, sport=sport, flags="S", seq=seq)
                pkt = ip_layer / tcp_layer / scapy.Raw(load=mimic_data[:16])
                resp = scapy.sr1(pkt, timeout=self.timeout_scan, verbose=0)

                if resp and resp.haslayer(scapy.TCP):
                    flags = int(resp[scapy.TCP].flags)
                    if (flags & 0x12) == 0x12:
                        rst_pkt = ip_layer / scapy.TCP(dport=port, sport=sport, flags="R", seq=seq+1)
                        scapy.send(rst_pkt, verbose=0)
                        return "open"
                    elif (flags & 0x04) == 0x04:
                        return "closed"

            return "filtered"

        loop = asyncio.get_running_loop()
        state = await loop.run_in_executor(None, do_mimic_probe)
        async with self.lock:
            self.results[port].tcp_states[ScanType.MIMIC] = state

    # -------------------- FRAGMENTED SYN SCAN --------------------
    async def fragmented_syn_scan(
        self,
        port: int,
        min_frag_size: int,
        max_frag_size: int,
        min_delay: float,
        max_delay: float,
        timeout: int,
        max_tries: int = 3
    ):
        '''
        Time for some packet splitting action!
        This advanced technique:
        1. Splits SYN packet into pieces
        2. Sneaks past firewalls
        3. Can do two modes:
           - Two fragments (header + data)
           - Multiple random-sized fragments
        '''
        def do_frag_scan():
            ip_id = random.randint(1, 65535)
            ip_layer = self.build_ip_layer()
            self.set_ip_ttl_or_hlim(ip_layer)

            # Build a SYN packet with some data
            base_tcp = scapy.TCP(
                dport=port,
                sport=random.randint(1024, 65535),
                flags="S",
                seq=random.randint(0, 2**32 - 1)
            )
            payload_data = b"A" * 200

            # Convert to raw and re-parse so IPv4 sets ihl, etc.
            full_syn = ip_layer / base_tcp / scapy.Raw(load=payload_data)
            raw_syn = bytes(full_syn)

            if not self.use_ipv6:
                parsed_syn = scapy.IP(raw_syn)
                ip_header_len = parsed_syn.ihl * 4
            else:
                parsed_syn = scapy.IPv6(raw_syn)
                ip_header_len = 40  # typically 40 bytes for IPv6 main header

            # Slice out TCP + data
            ip_payload = raw_syn[ip_header_len:]
            total_size = len(ip_payload)

            final_state = ["filtered"]
            sniff_filter = f"tcp and host {self.target_ip} and port {port}"

            def capture_response(pkt):
                if (pkt.haslayer(scapy.TCP) and
                    pkt[scapy.IP].src == self.target_ip and
                    pkt[scapy.TCP].sport == port):
                    flags = pkt[scapy.TCP].flags
                    if (flags & 0x12) == 0x12:
                        final_state[0] = "open"
                    elif (flags & 0x04) == 0x04:
                        final_state[0] = "closed"

            def send_fragments():
                # If user wants exactly two fragments:
                if self.frag_two_frags:
                    # 1) First fragment: at least frag_first_min_size in size
                    first_size = min(total_size, max(self.frag_first_min_size, min_frag_size))
                    remain = total_size - first_size

                    # More fragments flag for the first if there's leftover
                    more_frag = "MF" if remain > 0 else 0
                    first_data = ip_payload[:first_size]

                    if not self.use_ipv6:
                        f1 = scapy.IP(
                            dst=ip_layer.dst,
                            src=ip_layer.src,
                            id=ip_id,
                            flags=more_frag,
                            frag=0,
                            ttl=ip_layer.ttl
                        ) / first_data
                    else:
                        f1 = scapy.IPv6(
                            dst=ip_layer.dst,
                            src=ip_layer.src,
                            hlim=ip_layer.hlim,
                            nh=6,  # TCP
                            fl=0
                        ) / first_data
                        if more_frag:
                            f1[scapy.IPv6].flags = 1

                    scapy.send(f1, verbose=0)
                    time.sleep(random.uniform(min_delay, max_delay))

                    if remain > 0:
                        # 2) Second fragment: whatever is left
                        f2_data = ip_payload[first_size:]
                        # no MF, since it's last
                        if not self.use_ipv6:
                            f2 = scapy.IP(
                                dst=ip_layer.dst,
                                src=ip_layer.src,
                                id=ip_id,
                                flags=0,
                                frag=(first_size // 8),
                                ttl=ip_layer.ttl
                            ) / f2_data
                        else:
                            f2 = scapy.IPv6(
                                dst=ip_layer.dst,
                                src=ip_layer.src,
                                hlim=ip_layer.hlim,
                                nh=6,
                                fl=0
                            ) / f2_data
                            f2[scapy.IPv6].frag = (first_size // 8)

                        scapy.send(f2, verbose=0)
                        time.sleep(random.uniform(min_delay, max_delay))
                else:
                    # Otherwise, do multi-fragment approach
                    offset_bytes = 0
                    remain = total_size

                    while remain > 0:
                        # For the first fragment, ensure >= frag_first_min_size
                        if offset_bytes == 0:
                            frag_size = max(self.frag_first_min_size, random.randint(min_frag_size, max_frag_size))
                        else:
                            frag_size = random.randint(min_frag_size, max_frag_size)

                        if frag_size > remain:
                            frag_size = remain

                        more_frag = "MF" if (frag_size < remain) else 0
                        frag_data = ip_payload[offset_bytes: offset_bytes + frag_size]

                        if not self.use_ipv6:
                            fragment = scapy.IP(
                                dst=ip_layer.dst,
                                src=ip_layer.src,
                                id=ip_id,
                                flags=more_frag,
                                frag=(offset_bytes // 8),
                                ttl=ip_layer.ttl
                            ) / frag_data
                        else:
                            fragment = scapy.IPv6(
                                dst=ip_layer.dst,
                                src=ip_layer.src,
                                hlim=ip_layer.hlim,
                                nh=6,
                                fl=0
                            ) / frag_data
                            fragment[scapy.IPv6].frag = (offset_bytes // 8)
                            if more_frag:
                                fragment[scapy.IPv6].flags = 1

                        scapy.send(fragment, verbose=0)
                        offset_bytes += frag_size
                        remain -= frag_size
                        time.sleep(random.uniform(min_delay, max_delay))

            # Try a few times to get a response
            for _ in range(max_tries):
                final_state[0] = "filtered"
                sniff_thread = threading.Thread(
                    target=scapy.sniff,
                    kwargs={
                        'filter': sniff_filter,
                        'prn': capture_response,
                        'timeout': timeout,
                        'store': False
                    }
                )
                sniff_thread.start()

                # Send our fragments
                send_fragments()

                sniff_thread.join()
                if final_state[0] in ["open", "closed"]:
                    break

            return final_state[0]

        loop = asyncio.get_running_loop()
        state = await loop.run_in_executor(None, do_frag_scan)
        async with self.lock:
            self.results[port].tcp_states[ScanType.FRAG] = state

    # -------------------- OS FINGERPRINTING --------------------
    def os_fingerprint(self, port: int, resp):
        '''
        Let's figure out what OS they're running!
        We check:
        1. TTL/hop limit values
        2. TCP options
        3. Window sizes
        '''
        if not resp.haslayer(scapy.TCP):
            return
        ip4 = resp.getlayer(scapy.IP)
        ip6 = resp.getlayer(scapy.IPv6)
        ttl_or_hlim = ip4.ttl if ip4 else ip6.hlim if ip6 else None
        if ttl_or_hlim is None:
            return
        tcp_layer = resp[scapy.TCP]
        options = tcp_layer.options
        os_guess = "Unknown"
        if ttl_or_hlim <= 64:
            os_guess = "Linux/Unix"
        elif ttl_or_hlim <= 128:
            os_guess = "Windows"
        else:
            os_guess = "Solaris/Cisco"
        if options:
            opts = dict((o[0], o[1]) for o in options if isinstance(o, tuple))
            if 'Timestamp' in opts:
                os_guess = "Linux/Unix (Timestamp)"
            elif 'MSS' in opts and opts['MSS'] == 1460:
                os_guess = "Linux/Unix"
        self.results[port].os_guess = os_guess

    async def banner_grabbing(self, port: int):
        '''
        Let's grab those service banners!
        This helps us know:
        1. What service is running
        2. What version it is
        3. Any extra details we can find
        '''
        def do_banner():
            try:
                with socket.create_connection((self.target_ip, port), timeout=self.timeout_connect) as sock:
                    service_guess = self.results[port].service.lower()
                    if "http" in service_guess:
                        req = f"GET / HTTP/1.1\r\nHost: {self.target_ip}\r\n\r\n".encode()
                    elif "ftp" in service_guess:
                        req = b"USER anonymous\r\n"
                    elif "ssh" in service_guess:
                        req = b"SSH-2.0-Test\r\n"
                    else:
                        req = b"HEAD / HTTP/1.0\r\n\r\n"
                    sock.sendall(req)
                    sock.settimeout(self.timeout_banner)
                    banner = sock.recv(1024)
                    return banner.decode(errors="ignore")
            except Exception as e:
                logging.debug(f"Banner grab failed on port {port}: {e}")
                return ""
        loop = asyncio.get_running_loop()
        banner_str = await loop.run_in_executor(None, do_banner)
        if banner_str:
            async with self.lock:
                self.results[port].banner = banner_str[:256]
                # Quick guess to override service if we see known text
                if "220" in banner_str and "ftp" in banner_str.lower():
                    self.results[port].service = "FTP"

    async def adaptive_delay(self):
        '''
        Smart rate limiting based on what we've seen before.
        This helps us:
        1. Not overwhelm the target
        2. Get better results
        3. Be more reliable
        '''
        if len(self.history) > 10:
            avg_delay = sum(self.history) / len(self.history)
            self.adaptation_factor = max(0.5, min(2.0, avg_delay * 1.2))
        base_delay = 1.0 / self.max_rate
        delay = base_delay * self.adaptation_factor
        self.history.append(delay)
        await asyncio.sleep(delay)

    # -------------------- SERVICE FINGERPRINTING, VULNS --------------------
    def service_fingerprinting(self):
        '''
        Let's figure out what services are running!
        We check:
        1. Common ports
        2. Service banners
        3. Protocol details
        '''
        service_map = {
            80: "HTTP",
            443: "HTTPS",
            53: "DNS",
            22: "SSH",
            25: "SMTP",
            3389: "RDP",
            21: "FTP",
            23: "Telnet",
            110: "POP3",
            995: "POP3S",
            143: "IMAP",
            993: "IMAPS",
            135: "MSRPC",
            139: "NetBIOS",
            445: "SMB",
            3306: "MySQL",
            1433: "MSSQL",
            1521: "Oracle",
            5432: "PostgreSQL",
            5900: "VNC",
            5060: "SIP",
        }
        for port, result in self.results.items():
            if not result.service:
                result.service = service_map.get(port, "unknown")
            if result.banner:
                b = result.banner.lower()
                if "ssh" in b:
                    result.service = "SSH"
                elif "http" in b:
                    result.service = "HTTP"

    def analyze_vulnerabilities(self):
        '''
        Let's look for security issues!
        We check:
        1. Service versions
        2. Known bugs
        3. Weak settings
        '''
        vuln_db = {
            "apache/2.4.49": ["CVE-2021-41773 (Path Traversal)"],
            "openssh_8.0": ["CVE-2021-41617 (SSH Agent Vulnerability)"],
            "iis/10.0": ["CVE-2020-0601 (CurveBall)"],
        }
        for port, result in self.results.items():
            version_lower = result.version.lower()
            banner_lower = result.banner.lower()
            for known_sig, vulns in vuln_db.items():
                if known_sig in version_lower or known_sig in banner_lower:
                    result.vulns.extend(vulns)
            # Example TLS 1.0 vulnerability
            if result.service == "SSL/TLS" and "tlsv1.0" in result.version.lower():
                result.vulns.append("Weak TLS version (TLSv1.0)")

    def parse_certificate(self, cert_bin: bytes) -> Dict:
        '''
        Let's look at those SSL certificates!
        We get:
        1. Who owns it
        2. Who issued it
        3. When it's valid
        4. Other cool details
        '''
        try:
            cert_obj = x509.load_der_x509_certificate(cert_bin, default_backend())
            return {
                "subject": cert_obj.subject.rfc4514_string(),
                "issuer": cert_obj.issuer.rfc4514_string(),
                "version": cert_obj.version.name,
                "serial": str(cert_obj.serial_number),
                "not_valid_before": str(cert_obj.not_valid_before),
                "not_valid_after": str(cert_obj.not_valid_after),
                "signature_algorithm": cert_obj.signature_algorithm_oid._name,
            }
        except Exception as e:
            logging.debug(f"parse_certificate error: {e}")
            return {}

    def check_ssl_vulnerabilities(self, cert_info: Dict) -> List[str]:
        '''
        Let's check those SSL certs for issues!
        We look for:
        1. Weak algorithms
        2. Expired certs
        3. Other problems
        '''
        vulns = []
        if cert_info.get("signature_algorithm") == "sha1WithRSAEncryption":
            vulns.append("Weak signature (SHA1)")
        return vulns

    # -------------------- REPORTING --------------------
    def generate_report(self):
        '''
        Time to show off what we found!
        We display:
        1. Port scan results
        2. Services we found
        3. Security issues
        4. OS info
        '''
        table = Table(title="Quantum Scan Results", show_lines=True)
        table.add_column("Port", style="cyan")
        table.add_column("TCP States", style="magenta")
        table.add_column("UDP State", style="magenta")
        table.add_column("Filtering", style="magenta")
        table.add_column("Service", style="green")
        table.add_column("Version")
        table.add_column("Vulnerabilities")
        table.add_column("OS Guess", style="yellow")
        for port, result in sorted(self.results.items()):
            tcp_states_str = ", ".join(f"{st.value}: {val}" for st, val in result.tcp_states.items())
            vulns_str = "\n".join(result.vulns) if result.vulns else ""
            table.add_row(
                str(port),
                tcp_states_str or "",
                result.udp_state,
                result.filtering,
                result.service,
                result.version,
                vulns_str,
                result.os_guess
            )
        console.print(table)
        self.print_statistics()
        if self.json_output:
            self.dump_results_json()

    def print_statistics(self):
        '''
        Let's show some cool stats!
        We display:
        1. Open ports we found
        2. Services we spotted
        3. Security issues
        '''
        open_tcp_ports = [p for p, r in self.results.items()
                          if any(st == "open" for st in r.tcp_states.values())]
        open_udp_ports = [p for p, r in self.results.items() if r.udp_state == "open"]
        total_vulns = sum(len(r.vulns) for r in self.results.values())
        console.print(f"\n[bold]Scan Statistics:[/]")
        console.print(f"Open TCP ports: {len(open_tcp_ports)} => {open_tcp_ports}")
        console.print(f"Open UDP ports: {len(open_udp_ports)} => {open_udp_ports}")
        console.print(f"Vulnerabilities found: {total_vulns}")

    def dump_results_json(self):
        '''
        Let's save our results to JSON!
        This helps with:
        1. Further analysis
        2. Using with other tools
        3. Making reports
        '''
        import json
        out_data = {}
        for port, result in self.results.items():
            out_data[port] = {
                "tcp_states": {k.value: v for k, v in result.tcp_states.items()},
                "udp_state": result.udp_state,
                "filtering": result.filtering,
                "service": result.service,
                "version": result.version,
                "vulns": result.vulns,
                "cert_info": result.cert_info,
                "banner": result.banner,
                "os_guess": result.os_guess,
            }
        with open("scan_results.json", "w") as fh:
            json.dump(out_data, fh, indent=4)
        console.print("[green]Results written to scan_results.json[/green]")

################# UTILITIES ################
def parse_ports(port_input: str) -> List[int]:
    '''
    Let's parse those port numbers!
    We handle:
    - Single port: "80"
    - Port range: "1-100"
    - Multiple ports: "80,443,8080"
    - Mixed: "80,1-100,443"
    '''
    ports = []
    if port_input.isdigit():
        p = int(port_input)
        if 1 <= p <= 65535:
            return [p]
        raise ValueError(f"Invalid port: {p}")
    for part in port_input.split(","):
        part = part.strip()
        if "-" in part:
            start, end = map(int, part.split("-"))
            if not (1 <= start <= end <= 65535):
                raise ValueError(f"Invalid range: {part}")
            ports.extend(range(start, end + 1))
        elif part.isdigit():
            p = int(part)
            if 1 <= p <= 65535:
                ports.append(p)
            else:
                raise ValueError(f"Invalid port: {p}")
        else:
            raise ValueError(f"Invalid port spec: {part}")
    return sorted(set(ports))

################# MAIN ################
if __name__ == "__main__":
    # Set up our command line arguments
    parser = ArgumentParser(description="Quantum Port Scanner with Additional Scan Methods")
    parser.add_argument("target", help="Target hostname or IP")
    parser.add_argument("-p", "--ports", required=True, help="e.g. 80, 1-100, 22,80")
    parser.add_argument("-s", "--scan-types", nargs="+", default=["syn"],
                        choices=[st.value for st in ScanType],
                        help="scan methods (syn ssl udp ack fin xmas null window tls_echo mimic frag)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose logging")
    parser.add_argument("-e", "--evasions", action="store_true", help="Enable fragmentation/TTL changes")
    parser.add_argument("--ipv6", action="store_true", help="Use IPv6 scanning")
    parser.add_argument("--json-output", action="store_true", help="Output results to JSON")
    parser.add_argument("--shuffle-ports", action="store_true", help="Randomize port list")
    parser.add_argument("--log-file", default="scanner.log", help="Log file path")
    parser.add_argument("--max-rate", type=int, default=500, help="Max pkts/sec")
    parser.add_argument("--concurrency", type=int, default=100, help="Concurrent tasks")

    # Timeout settings
    parser.add_argument("--timeout-scan", type=float, default=3.0,
                       help="Timeout for scan packets (seconds)")
    parser.add_argument("--timeout-connect", type=float, default=3.0,
                       help="Timeout for TCP connections (seconds)")
    parser.add_argument("--timeout-banner", type=float, default=3.0,
                       help="Timeout for banner grabbing (seconds)")

    # Fragment scan settings
    parser.add_argument("--mimic-protocol", default="HTTP",
                        help="Protocol to mimic (HTTP, SSH, FTP, SMTP, IMAP, POP3) when using 'mimic' scan type.")
    parser.add_argument("--frag-min-size", type=int, default=16,
                        help="Minimum fragment size in bytes (multiple of 8) for 'frag' scan.")
    parser.add_argument("--frag-max-size", type=int, default=64,
                        help="Maximum fragment size in bytes (multiple of 8) for 'frag' scan.")
    parser.add_argument("--frag-min-delay", type=float, default=0.01,
                        help="Minimum delay (seconds) between sending fragments for 'frag' scan.")
    parser.add_argument("--frag-max-delay", type=float, default=0.1,
                        help="Maximum delay (seconds) between sending fragments for 'frag' scan.")
    parser.add_argument("--frag-timeout", type=int, default=10,
                        help="Sniffing timeout (seconds) for 'frag' scan response capture.")
    parser.add_argument("--frag-first-min-size", type=int, default=64,
                        help="Minimum size (bytes) for the first fragment to hold the full TCP header.")
    parser.add_argument("--frag-two-frags", action="store_true",
                        help="Use exactly two fragments total (first for TCP header + some data, second for remainder).")

    # Parse args and run the scanner
    args = parser.parse_args()
    logging.getLogger().handlers.clear()
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s - %(levelname)s - %(message)s",
        handlers=[logging.FileHandler(args.log_file), logging.StreamHandler()],
    )
    try:
        ports = parse_ports(args.ports)
    except ValueError as exc:
        logging.error(f"Invalid ports: {exc}")
        sys.exit(1)

    scanner = QuantumScanner(
        target=args.target,
        ports=ports,
        scan_types=[ScanType(st) for st in args.scan_types],
        concurrency=args.concurrency,
        max_rate=args.max_rate,
        evasions=args.evasions,
        verbose=args.verbose,
        use_ipv6=args.ipv6,
        json_output=args.json_output,
        shuffle_ports=args.shuffle_ports,
        timeout_scan=args.timeout_scan,
        timeout_connect=args.timeout_connect,
        timeout_banner=args.timeout_banner,
        mimic_protocol=args.mimic_protocol,
        frag_min_size=args.frag_min_size,
        frag_max_size=args.frag_max_size,
        frag_min_delay=args.frag_min_delay,
        frag_max_delay=args.frag_max_delay,
        frag_timeout=args.frag_timeout,
        frag_first_min_size=args.frag_first_min_size,
        frag_two_frags=args.frag_two_frags
    )
    asyncio.run(scanner.run_scan())
