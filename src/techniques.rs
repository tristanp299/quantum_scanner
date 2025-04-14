use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};
use std::io::Read;

use anyhow::{Result, anyhow};
use log::{debug, error, warn};
use rand::{thread_rng, Rng};
use rustls::{ClientConfig, ClientConnection, RootCertStore};
// Import types from rustls::pki_types
use rustls::pki_types::ServerName;

// Importing Digest is necessary for the hasher.finalize() method used in parse_certificate
// Don't remove this import, even if it appears unused
#[allow(unused_imports)]
use sha2::{Sha256, Digest};
use tokio::net::{UdpSocket}; // Removed TcpSocket import
use tokio::time::{sleep, timeout};
// Comment out the unused import
// use webpki_roots::TLS_SERVER_ROOTS;

// --- pnet imports for raw socket scanning ---
// Import the Packet trait
use pnet::packet::Packet;
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::{MutableIpv4Packet, Ipv4Flags/*, Ipv4Packet*/};
use pnet::packet::ipv6::{MutableIpv6Packet/*, Ipv6Packet*/};
use pnet::packet::tcp::{MutableTcpPacket, TcpFlags, TcpOption};
// Removed unused udp imports: MutableUdpPacket, UdpPacket
use pnet::transport::{self, /*TransportReceiver, TransportSender,*/ TransportChannelType, transport_channel};
// --- End pnet imports ---

// --- Add ICMP/ICMPv6 imports ---
use pnet::packet::icmp::{self, IcmpTypes};
use pnet::packet::icmpv6::{self/*, Icmpv6Types*/};
// --- End pnet imports ---

// --- CORRECTED: IPv6 Fragment Header is an Extension Header, not a separate module ---
// Use types related to IPv6 extension headers generally
// Removed unused commented out imports
// Fragment-specific types might be nested or handled differently depending on pnet version
// Check if FragmentPacket/MutableFragmentPacket exist directly under ipv6 or nested
use pnet::packet::ipv6::{/*FragmentPacket,*/ MutableFragmentPacket}; // Assuming they exist directly for now
// --- End pnet imports ---

// Conditionally import x509-parser
#[cfg(not(feature = "minimal-static"))]
use x509_parser::prelude::*;
#[cfg(not(feature = "minimal-static"))]
use x509_parser::public_key::PublicKey;

use crate::models::{CertificateInfo, PortStatus};
use crate::utils; // Use utils module directly for random_high_port and find_local_ipv4

// --- Raw Socket Helper Functions ---

const IPV4_HEADER_LEN: usize = 20;
const IPV6_HEADER_LEN: usize = 40;
const TCP_HEADER_LEN: usize = 20; // Base TCP header length
const TCP_HEADER_LEN_WITH_OPTIONS: usize = 32; // Example with MSS option
// const MSS_OPTION_KIND: u8 = 2; // Not directly needed

/// Creates an IPv4/TCP packet buffer and populates headers.
/// Requires a mutable buffer slice `packet_buf` large enough for IPv4 + TCP headers + payload.
/// Returns the size of the constructed packet.
fn build_tcp_packet_v4(
    packet_buf: &mut [u8],
    source_ip: Ipv4Addr,
    dest_ip: Ipv4Addr,
    source_port: u16,
    dest_port: u16,
    tcp_flags: u8,
    seq_num: u32,
    ttl: u8,
) -> usize {
    let tcp_options = [TcpOption::mss(1460)]; // Set Maximum Segment Size
    let tcp_header_len = TCP_HEADER_LEN + (tcp_options.len() * 4);
    let total_len = IPV4_HEADER_LEN + tcp_header_len;

    if packet_buf.len() < total_len {
        panic!("Packet buffer too small ({} bytes) for IPv4+TCP headers ({} bytes)", packet_buf.len(), total_len);
    }

    // Setup IP header
    {
        let mut ip_header = MutableIpv4Packet::new(&mut packet_buf[..total_len]).unwrap();
        ip_header.set_version(4);
        ip_header.set_header_length(5);
        ip_header.set_total_length(total_len as u16);
        ip_header.set_ttl(ttl);
        ip_header.set_next_level_protocol(IpNextHeaderProtocols::Tcp);
        ip_header.set_source(source_ip);
        ip_header.set_destination(dest_ip);
        ip_header.set_flags(Ipv4Flags::DontFragment);
        ip_header.set_identification(rand::thread_rng().gen());
    }

    // Setup TCP header
    {
        let mut tcp_header = MutableTcpPacket::new(&mut packet_buf[IPV4_HEADER_LEN..total_len]).unwrap();
        tcp_header.set_source(source_port);
        tcp_header.set_destination(dest_port);
        tcp_header.set_sequence(seq_num);
        tcp_header.set_acknowledgement(0);
        tcp_header.set_data_offset(((tcp_header_len) / 4) as u8);
        // Cast tcp_flags (u8) to u16 for set_flags
        tcp_header.set_flags(tcp_flags.into());
        tcp_header.set_window(1024);
        tcp_header.set_urgent_ptr(0);
        tcp_header.set_checksum(0); // Zero out for calculation
        tcp_header.set_options(&tcp_options);
        // Use pnet::packet::tcp::ipv4_checksum for consistency
        let tcp_checksum = pnet::packet::tcp::ipv4_checksum(&tcp_header.to_immutable(), &source_ip, &dest_ip);
        tcp_header.set_checksum(tcp_checksum);
    }

    // Calculate and set IP checksum (must be done last)
    {
        let mut ip_header = MutableIpv4Packet::new(&mut packet_buf[..total_len]).unwrap();
        // Use pnet::packet::ipv4::checksum for consistency
        let checksum = pnet::packet::ipv4::checksum(&ip_header.to_immutable());
        ip_header.set_checksum(checksum);
    }

    total_len
}

/// Creates an IPv6/TCP packet buffer and populates headers.
/// Requires a mutable buffer slice `packet_buf` large enough for IPv6 + TCP headers + payload.
/// Returns the size of the constructed packet.
fn build_tcp_packet_v6(
    packet_buf: &mut [u8],
    source_ip: std::net::Ipv6Addr,
    dest_ip: std::net::Ipv6Addr,
    source_port: u16,
    dest_port: u16,
    tcp_flags: u8,
    seq_num: u32,
    hop_limit: u8,
) -> usize {
    let tcp_options = [TcpOption::mss(1440)]; // MSS for IPv6 is typically smaller (1440 vs 1460)
    let tcp_header_len = TCP_HEADER_LEN + (tcp_options.len() * 4);
    let total_len = IPV6_HEADER_LEN + tcp_header_len;
    let payload_len = tcp_header_len;

    if packet_buf.len() < total_len {
        panic!("Packet buffer too small ({} bytes) for IPv6+TCP headers ({} bytes)", packet_buf.len(), total_len);
    }

    // Setup IPv6 header
    {
        let mut ip_header = MutableIpv6Packet::new(&mut packet_buf[..total_len]).unwrap();
        ip_header.set_version(6);
        ip_header.set_traffic_class(0); // No specific traffic class
        ip_header.set_flow_label(0);    // No specific flow label
        ip_header.set_payload_length(payload_len as u16);
        ip_header.set_next_header(IpNextHeaderProtocols::Tcp);
        ip_header.set_hop_limit(hop_limit);
        ip_header.set_source(source_ip);
        ip_header.set_destination(dest_ip);
        // Note: IPv6 checksum is not in the header, it's handled by layers above/below
    }

    // Setup TCP header
    {
        let mut tcp_header = MutableTcpPacket::new(&mut packet_buf[IPV6_HEADER_LEN..total_len]).unwrap();
        tcp_header.set_source(source_port);
        tcp_header.set_destination(dest_port);
        tcp_header.set_sequence(seq_num);
        tcp_header.set_acknowledgement(0);
        tcp_header.set_data_offset(((tcp_header_len) / 4) as u8); // Data offset in 32-bit words
        // Cast tcp_flags (u8) to u16 for set_flags
        tcp_header.set_flags(tcp_flags.into());
        tcp_header.set_window(1024);
        tcp_header.set_urgent_ptr(0);
        tcp_header.set_options(&tcp_options);
        tcp_header.set_checksum(0); // Zero out for calculation

        // Calculate TCP checksum using the IPv6 pseudo-header
        // Use pnet::packet::tcp::ipv6_checksum for consistency
        let tcp_checksum = pnet::packet::tcp::ipv6_checksum(
            &tcp_header.to_immutable(),
            &source_ip,
            &dest_ip
        );
        tcp_header.set_checksum(tcp_checksum);
    }
    // IPv6 does not have a header checksum calculated at the IP layer.

    total_len
}

/// Sends a raw TCP packet (IPv4 or IPv6) and waits for a response matching the probe.
/// Requires root/administrator privileges.
/// Returns Ok(Some(received_tcp_packet)) on match, Ok(None) on timeout/filter/error, Err(e) on setup/send error.
async fn send_receive_raw_tcp(
    target_ip: IpAddr,
    port: u16,
    local_ip: IpAddr, // Accept generic IpAddr (must match target_ip family)
    tcp_flags_out: u8, // Keep as u8
    timeout_duration: Duration,
    ttl: u8, // <-- Add ttl parameter
) -> Result<Option<RawResponse>> {
    let source_port = utils::random_high_port();
    let seq_num: u32 = thread_rng().gen();

    // Enforce a reasonable minimum timeout (500ms) and maximum timeout (30s)
    let timeout_duration = if timeout_duration.as_millis() < 2000 {
        warn!("[Raw TCP:{}:{}] Timeout too short ({}ms), increasing to 2000ms", target_ip, port, timeout_duration.as_millis());
        Duration::from_millis(2000)
    } else if timeout_duration.as_secs() > 30 {
        Duration::from_secs(30)
    } else {
        timeout_duration
    };

    // Determine IP version and select appropriate protocol for transport channel
    let protocol = match target_ip {
        IpAddr::V4(_) => TransportChannelType::Layer4(transport::TransportProtocol::Ipv4(IpNextHeaderProtocols::Tcp)),
        IpAddr::V6(_) => TransportChannelType::Layer4(transport::TransportProtocol::Ipv6(IpNextHeaderProtocols::Tcp)),
    };
    
    // Create a single channel for both sending and receiving to avoid packet loss
    // This is important as creating a second channel might cause early responses to be missed
    let (mut tx, mut rx) = match transport_channel(4096, protocol) {
        Ok((tx, rx)) => (tx, rx),
        Err(e) => return Err(anyhow!("Failed to open raw socket channel for {} (requires root/admin privileges): {}", target_ip.is_ipv4().then(|| "IPv4").unwrap_or("IPv6"), e)),
    };

    // Build packet based on IP version
    let mut packet_buf = vec![0u8; 128]; // Buffer needs to be large enough for largest header combo (IPv6+TCP w/ Options)
    let packet_len = match (target_ip, local_ip) {
        (IpAddr::V4(dest_ip_v4), IpAddr::V4(local_ip_v4)) => {
            build_tcp_packet_v4(&mut packet_buf, local_ip_v4, dest_ip_v4, source_port, port, tcp_flags_out, seq_num, ttl)
        }
        (IpAddr::V6(dest_ip_v6), IpAddr::V6(local_ip_v6)) => {
            build_tcp_packet_v6(&mut packet_buf, local_ip_v6, dest_ip_v6, source_port, port, tcp_flags_out, seq_num, ttl)
        }
        _ => return Err(anyhow!("IP address family mismatch between target ({}) and local ({}) IP for raw socket scan", target_ip, local_ip)),
    };

    // Ensure buffer is large enough (build functions might panic, but double check)
    if packet_buf.len() < packet_len {
        // This case should ideally be prevented by the build functions' checks
        return Err(anyhow!("Internal error: Packet buffer too small after building headers."));
    }
    // Trim buffer to actual packet length before creating the final packet view
    packet_buf.truncate(packet_len);

    // Setup a TCP packet iterator for receiving responses before sending
    // This ensures we don't miss any responses that come back quickly
    let mut iter = transport::tcp_packet_iter(&mut rx);

    // Send packet
    match target_ip {
        IpAddr::V4(_) => {
            let ipv4_packet_to_send = MutableIpv4Packet::new(&mut packet_buf).unwrap();
            // Use packet() method from Packet trait
            if tx.send_to(ipv4_packet_to_send.to_immutable(), target_ip).is_err() {
                return Err(anyhow!("Failed to send raw IPv4 packet to {}", target_ip));
            }
        }
        IpAddr::V6(_) => {
            let ipv6_packet_to_send = MutableIpv6Packet::new(&mut packet_buf).unwrap();
            // Use packet() method from Packet trait
            if tx.send_to(ipv6_packet_to_send.to_immutable(), target_ip).is_err() {
                return Err(anyhow!("Failed to send raw IPv6 packet to {}", target_ip));
            }
        }
    }
    debug!("[Raw TCP:{}:{}] Sent flags {:#04x} from port {} ({} -> {})", target_ip, port, tcp_flags_out, source_port, local_ip, target_ip);

    // Use tokio's timeout for the receive wait loop instead of manual time tracking
    // This is more efficient and ensures we don't hang indefinitely
    let receive_future = async {
        // Set a reasonable number of iterations to check for packets
        // This prevents excessive CPU spinning while still allowing fast response
        let max_iterations = 50;
        let sleep_interval = Duration::from_millis(5);
        let mut iterations = 0;
        
        loop {
            match iter.next() {
                Ok((packet, addr)) => {
                    // Log all received packets for debugging
                    debug!("[Raw TCP:{}:{}] Received packet from {}, source port: {}, dest port: {}, flags: {:#04x}",
                           target_ip, port, addr, packet.get_source(), packet.get_destination(), packet.get_flags());
                    
                    // Much more permissive packet matching - any packet from target to our source port
                    // or any packet from the target port is considered a match
                    // This ensures we don't miss valid responses due to overly strict matching
                    if packet.get_destination() == source_port || packet.get_source() == port {
                        // Capture the TCP flags for analysis
                        let flags = packet.get_flags();
                        debug!("[Raw TCP:{}:{}] Matched response packet (flags: {:#04x})", target_ip, port, flags);
                        
                        // Clone packet data to avoid lifetime issues
                        let packet_data = packet.packet().to_vec();
                        
                        // Return the matched packet
                        return Some(RawResponse::TcpStatic {
                            flags: flags.into(), // Fix: explicitly convert to u16
                            data: packet_data,
                            source: packet.get_source(),
                            destination: packet.get_destination(),
                        });
                    }
                    
                    // Handle packets that don't match our criteria
                    if iterations % 5 == 0 {
                        tokio::time::sleep(sleep_interval).await;
                    }
                    iterations += 1;
                    
                    // Avoid infinite loop if we keep receiving irrelevant packets
                    if iterations >= max_iterations {
                        return None;
                    }
                }
                Err(e) => {
                    // Check for ICMP errors (although less direct with Layer 4 channel)
                    if e.kind() == std::io::ErrorKind::ConnectionRefused {
                        debug!("[Raw TCP:{}:{}] Received ICMP-like error (ConnectionRefused). Filtered?", target_ip, port);
                        return Some(RawResponse::IcmpFiltered(
                            IcmpTypes::DestinationUnreachable, 
                            icmp::IcmpCode::new(3))); // Port Unreachable
                    } else {
                        // Log but continue - this could be a temporary error
                        warn!("[Raw TCP:{}:{}] Error receiving: {}. May indicate filtering.", target_ip, port, e);
                        // Sleep briefly to not burn CPU when receiving errors
                        tokio::time::sleep(sleep_interval).await;
                        iterations += 1;
                        if iterations >= max_iterations {
                            return None;
                        }
                    }
                }
            }
        }
    };
    
    // Apply timeout to the receive future
    match tokio::time::timeout(timeout_duration, receive_future).await {
        Ok(Some(response)) => {
            // Successfully received a response before timeout
            Ok(Some(response))
        },
        Ok(None) => {
            // Receive future completed but didn't find a matching packet
            debug!("[Raw TCP:{}:{}] No matching response found within timeout of {:?}", target_ip, port, timeout_duration);
            // Return Timeout response instead of None to handle timeouts consistently
            Ok(Some(RawResponse::Timeout))
        },
        Err(_) => {
            // Timeout occurred
            debug!("[Raw TCP:{}:{}] Timeout waiting for response after {:?}", target_ip, port, timeout_duration);
            Ok(Some(RawResponse::Timeout))
        }
    }
}

// --- Added Enums ---

/// Represents the different outcomes of a raw TCP receive attempt.
#[derive(Debug)] // Add Debug trait for easier inspection
enum RawResponse {
    /// A TCP packet with owned data (static lifetime)
    TcpStatic {
        flags: u16, // Changed from u8 to u16 to match TcpPacket::get_flags
        data: Vec<u8>,
        source: u16,
        destination: u16,
    },
    /// An ICMPv4 error message relevant to filtering was received.
    IcmpFiltered(icmp::IcmpType, icmp::IcmpCode),
    /// An ICMPv6 error message relevant to filtering was received.
    Icmpv6Filtered(icmpv6::Icmpv6Type, icmpv6::Icmpv6Code),
    /// The receive operation timed out.
    Timeout,
}

/// Represents errors that can occur within the receive loop.
#[derive(Debug)] // Add Debug trait
enum RecvError {
    /// An I/O error occurred while trying to receive a packet.
    IoError(std::io::Error),
}

// --- End Raw Socket Helper Functions ---

// Add this helper function at the top, outside of any other function
/// Helper function to ensure TCP flags are converted to u16 for comparison
fn tcp_flags_as_u16(flags: u8) -> u16 {
    flags as u16
}

/// SYN scan implementation (using raw sockets)
///
/// Sends a TCP SYN packet and analyzes the response:
/// - SYN-ACK response indicates an open port
/// - RST response indicates a closed port
/// - No response indicates a filtered port
/// REQUIRES root/administrator privileges.
pub async fn syn_scan(
    target_ip: IpAddr,
    port: u16,
    local_ip_option: Option<IpAddr>,
    use_ipv6: bool,
    timeout_duration: Duration,
    enhanced_evasion: bool,
    mimic_os: &str,
    ttl_jitter: u8,
) -> Result<PortStatus> {
    debug!("[SYN Scan:{}:{}] Starting SYN scan", target_ip, port);
    
    // For environments with restrictive firewalls, sometimes a direct TCP connect
    // is more effective - we'll try both raw socket and direct connect methods
    // This is a key insight from successful scanners like nmap
    
    // First attempt: Raw socket SYN scan with improved reliability
    let raw_result = raw_syn_scan(
        target_ip, 
        port, 
        local_ip_option, 
        use_ipv6, 
        timeout_duration,
        enhanced_evasion,
        mimic_os,
        ttl_jitter
    ).await;
    
    match raw_result {
        Ok(status) => {
            // If we get a definitive result from raw scan, use it
            if status == PortStatus::Open || status == PortStatus::Closed {
                debug!("[SYN Scan:{}:{}] Raw socket scan successful: {:?}", target_ip, port, status);
                return Ok(status);
            }
            
            // For filtered/uncertain results, try a direct TCP connect as fallback
            debug!("[SYN Scan:{}:{}] Raw scan inconclusive ({:?}), trying direct connect", target_ip, port, status);
        },
        Err(e) => {
            // Raw socket scan failed, retry with direct connect
            debug!("[SYN Scan:{}:{}] Raw socket scan failed: {}, trying direct connect", target_ip, port, e);
        }
    }
    
    // Second attempt: Direct TCP connect (more reliable but less stealthy)
    let socket_addr = SocketAddr::new(target_ip, port);
    match tokio::time::timeout(timeout_duration, tokio::net::TcpStream::connect(socket_addr)).await {
        Ok(Ok(_)) => {
            debug!("[SYN Scan:{}:{}] Direct connect successful, port is OPEN", target_ip, port);
            Ok(PortStatus::Open)
        },
        Ok(Err(e)) => {
            // Connection errors typically mean closed port
            debug!("[SYN Scan:{}:{}] Direct connect failed: {:?}, port is CLOSED", target_ip, port, e);
            Ok(PortStatus::Closed)
        },
        Err(_) => {
            // Timeout usually means filtered 
            debug!("[SYN Scan:{}:{}] Direct connect timed out, port is FILTERED", target_ip, port);
            Ok(PortStatus::Filtered)
        }
    }
}

/// Helper function: Raw socket implementation of SYN scan
async fn raw_syn_scan(
    target_ip: IpAddr,
    port: u16,
    local_ip_option: Option<IpAddr>,
    use_ipv6: bool,
    timeout_duration: Duration,
    enhanced_evasion: bool,
    mimic_os: &str,
    ttl_jitter: u8,
) -> Result<PortStatus> {
    // Resolve local IP appropriate for the target IP family (v4 or v6)
    let local_ip: IpAddr = match target_ip {
        IpAddr::V4(target_ipv4) => {
            match local_ip_option {
                Some(IpAddr::V4(ip)) => IpAddr::V4(ip),
                Some(IpAddr::V6(_)) => return Err(anyhow!("Provided local IP is IPv6, but target is IPv4 for raw SYN scan.")),
                None => {
                    warn!("Local IPv4 address not specified for raw SYN scan to {}, attempting auto-detection.", target_ipv4);
                    IpAddr::V4(utils::find_local_ipv4().map_err(|e| anyhow!("Local IPv4 address required for raw SYN scan and auto-detection failed: {}", e))?)
                }
            }
        },
        IpAddr::V6(target_ipv6) => {
            if !use_ipv6 {
                return Err(anyhow!("Target is IPv6 ({}), but IPv6 scanning is not enabled via --ipv6 flag.", target_ipv6));
            }
            match local_ip_option {
                Some(IpAddr::V6(ip)) => IpAddr::V6(ip),
                Some(IpAddr::V4(_)) => return Err(anyhow!("Provided local IP is IPv4, but target is IPv6 for raw SYN scan.")),
                None => {
                    warn!("Local IPv6 address not specified for raw SYN scan to {}, attempting auto-detection.", target_ipv6);
                    IpAddr::V6(utils::find_local_ipv6().map_err(|e| anyhow!("Local IPv6 address required for raw SYN scan and auto-detection failed: {}", e))?)
                }
            }
        }
    };

    // Ensure the selected local IP matches the target family
    if local_ip.is_ipv4() != target_ip.is_ipv4() {
         return Err(anyhow!("Internal error: Mismatch between selected local IP ({}) and target IP ({}) family.", local_ip, target_ip));
    }

    // Calculate TTL
    let ttl = if enhanced_evasion {
        utils::get_advanced_ttl(mimic_os, ttl_jitter)
    } else {
        64 // Default TTL if not using enhanced evasion
    };

    debug!("[Raw SYN:{}:{}] Using local IP {} with TTL {}", target_ip, port, local_ip, ttl);
    
    // Ensure we have a sufficient timeout
    let timeout_duration = if timeout_duration < Duration::from_millis(2000) {
        warn!("[Raw SYN:{}:{}] Increasing timeout to 2000ms", target_ip, port);
        Duration::from_millis(2000)
    } else {
        timeout_duration
    };
    
    // Cast TcpFlags::SYN to u8
    let syn_flag: u8 = TcpFlags::SYN.into();
    
    // Send SYN packet and wait for response
    let response = match send_receive_raw_tcp(
        target_ip,
        port,
        local_ip,
        syn_flag,
        timeout_duration,
        ttl,
    ).await {
        Ok(r) => r,
        Err(e) => {
            if e.to_string().contains("requires root/admin") || e.to_string().contains("Permission") {
                return Err(anyhow!("Raw socket operations require administrator privileges: {}", e));
            }
            return Err(anyhow!("Raw socket error: {}", e));
        }
    };
    
    // Parse the response to determine port status
    match response {
        Some(RawResponse::TcpStatic { flags, .. }) => {
            // Convert TcpFlags constants to u16 for comparison
            let syn_flag = tcp_flags_as_u16(TcpFlags::SYN.into());
            let ack_flag = tcp_flags_as_u16(TcpFlags::ACK.into());
            let rst_flag = tcp_flags_as_u16(TcpFlags::RST.into());
            
            debug!("[Raw SYN:{}:{}] Received TCP flags: {:#04x}", target_ip, port, flags);
            
            // Check for SYN+ACK flags (open port)
            if (flags & syn_flag != 0) && (flags & ack_flag != 0) {
                debug!("[Raw SYN:{}:{}] SYN-ACK received, port is OPEN", target_ip, port);
                Ok(PortStatus::Open)
            }
            // Check for RST flag (closed port)
            else if (flags & rst_flag) != 0 {
                debug!("[Raw SYN:{}:{}] RST received, port is CLOSED", target_ip, port);
                Ok(PortStatus::Closed)
            }
            // Any other flags indicate possible filtering
            else {
                debug!("[Raw SYN:{}:{}] Unexpected flags: {:#04x}, assuming FILTERED", target_ip, port, flags);
                Ok(PortStatus::Filtered)
            }
        },
        Some(RawResponse::IcmpFiltered(..)) | Some(RawResponse::Icmpv6Filtered(..)) => {
            debug!("[Raw SYN:{}:{}] ICMP error received, port is FILTERED", target_ip, port);
            Ok(PortStatus::Filtered)
        },
        Some(RawResponse::Timeout) | None => {
            debug!("[Raw SYN:{}:{}] No response received, port is FILTERED", target_ip, port);
            Ok(PortStatus::Filtered)
        }
    }
}

/// SSL/TLS scan implementation
/// (remains unchanged, uses standard sockets)
pub async fn ssl_scan(
    target_ip: IpAddr,
    port: u16,
    timeout_duration: Duration,
) -> Result<(PortStatus, Option<CertificateInfo>, String)> {
    debug!("[TLS Scan:{}:{}] Performing standard socket TLS scan", target_ip, port);

    // Create a secure SSL/TLS configuration with system root certificates
    let mut root_store = RootCertStore::empty();
    
    // Add certificates directly
    let cert_der_bytes = webpki_roots::TLS_SERVER_ROOTS
        .iter()
        .flat_map(|ta| {
            let cert = rustls::pki_types::CertificateDer::from(ta.subject.to_vec());
            std::iter::once(cert)
        })
        .collect::<Vec<_>>();
    
    // Add certificates to store
    let (_added, skipped) = root_store.add_parsable_certificates(cert_der_bytes);
    if skipped > 0 {
        warn!("Skipped {} certificates when adding to root store", skipped);
    }

    let config = ClientConfig::builder()
        .with_root_certificates(Arc::new(root_store)) // Use builder with root certs
        .with_no_client_auth();

    // First establish a basic TCP connection
    let socket_addr = SocketAddr::new(target_ip, port);
    let jitter = rand::thread_rng().gen_range(5..30);
    sleep(Duration::from_millis(jitter)).await;
    let socket = match timeout(timeout_duration, tokio::net::TcpStream::connect(socket_addr)).await {
        Ok(Ok(socket)) => {
            debug!("[TLS Scan:{}:{}] TCP connection successful", target_ip, port);
            socket
        },
        Ok(Err(e)) => {
            debug!("[TLS Scan:{}:{}] TCP connection failed: {}", target_ip, port, e);
            return Ok((PortStatus::Closed, None, String::new()));
        },
        Err(_) => {
            debug!("[TLS Scan:{}:{}] TCP connection timeout", target_ip, port);
            return Ok((PortStatus::Filtered, None, String::new()));
        },
    };

    // Convert tokio socket to std socket for rustls
    let mut std_socket = match socket.into_std() {
        Ok(s) => s,
        Err(e) => {
            debug!("[TLS Scan:{}:{}] Failed to convert socket: {}", target_ip, port, e);
            return Ok((PortStatus::Open, None, "Socket conversion error".to_string()));
        }
    };
    if let Err(e) = std_socket.set_nonblocking(true) {
        debug!("[TLS Scan:{}:{}] Failed to set non-blocking mode: {}", target_ip, port, e);
        return Ok((PortStatus::Open, None, "Socket config error".to_string()));
    }

    // Get server name for TLS connection (the IP address as a string)
    let server_name = match ServerName::try_from(format!("scan.{}.example.com", target_ip.to_string())) {
        Ok(name) => name,
        Err(_) => {
            // If parsing fails, use a placeholder domain that should always parse successfully
            debug!("[TLS Scan:{}:{}] Using placeholder server name due to IP literal", target_ip, port);
            ServerName::try_from("placeholder-quantum-scanner.example.com").unwrap()
        }
    };

    // Set up TLS connection
    let conn_result = ClientConnection::new(Arc::new(config), server_name);
    let mut conn = match conn_result {
        Ok(conn) => conn,
        Err(e) => {
            // Port is clearly open if we got here, but TLS failed.
            debug!("[TLS Scan:{}:{}] TLS negotiation failed: {}", target_ip, port, e);
            return Ok((PortStatus::Open, None, format!("TLS error: {}", e)));
        }
    };

    // Perform handshake
    let mut tls_stream = rustls::Stream::new(&mut conn, &mut std_socket);
    let mut handshake_buf = [0u8; 1]; // Minimal read to drive handshake
    // Use a timeout for the handshake attempt itself
    let handshake_result = timeout(timeout_duration, async { tls_stream.read(&mut handshake_buf) }).await;

    // Even if handshake read times out or errors, we might still get cert/version info
     if handshake_result.is_err() {
         debug!("[TLS Scan:{}:{}] Handshake read timed out or failed, but proceeding to check cert/version", target_ip, port);
     }

    // Extract certificate information
    #[cfg(not(feature = "minimal-static"))]
    let cert_info = if let Some(certs) = conn.peer_certificates() {
        // Access certificate data using certs[0].as_ref()
        if !certs.is_empty() { parse_certificate(certs[0].as_ref()) } else { None }
    } else { None };
    #[cfg(feature = "minimal-static")]
    let cert_info = None;

    // Determine TLS protocol version
    let version = conn.protocol_version()
        .map(|v| format!("{:?}", v))
        .unwrap_or_else(|| "No TLS Version".to_string());

    debug!("[TLS Scan:{}:{}] Connection completed. Version: {}, Cert Subject: {}",
        target_ip, port, version, cert_info.as_ref().map_or("N/A", |c| c.subject.as_str()));
    // Status is Open because TCP connected, regardless of TLS handshake success
    Ok((PortStatus::Open, cert_info, version))
}


/// Parse an X.509 certificate and extract information
/// (remains unchanged)
#[cfg(not(feature = "minimal-static"))]
fn parse_certificate(cert_der: &[u8]) -> Option<CertificateInfo> {
    match x509_parser::parse_x509_certificate(cert_der) {
        Ok((_, cert)) => {
            // Safely extract fields, providing defaults or handling potential errors
            let subject = cert.subject().to_string();
            let issuer = cert.issuer().to_string();
            // Convert ASN.1 Time to DateTime<Utc>
            let not_before = cert.validity().not_before.to_datetime().to_string();
            let not_after = cert.validity().not_after.to_datetime().to_string();
            let serial_number = cert.serial.to_string();
            let signature_algorithm = cert.signature_algorithm.oid().to_id_string(); // Use OID string
            // Get version as u8 and handle potential errors
            let version = if cert.version().0 <= u8::MAX as u32 {
                cert.version().0 as u8
            } else {
                0 // Default to version 0 if out of range
            };

            let mut hasher = Sha256::new();
            hasher.update(cert_der);
            let fingerprint = format!("{:x}", hasher.finalize());

            let alt_names = cert.extensions().iter()
                .find(|ext| ext.oid == oid_registry::OID_X509_EXT_SUBJECT_ALT_NAME)
                .and_then(|ext| {
                    // Extract alternative names without relying on the private parsed_extension() API
                    // Instead we use the general_names API available in x509_parser
                    if ext.value.is_empty() {
                        return None;
                    }
                    // The subject_alternative_name method parses the extension value safely
                    match x509_parser::extensions::GeneralNames::from_der(ext.value) {
                        Ok((_, general_names)) => {
                            Some(general_names.iter().map(|n| n.to_string()).collect())
                        },
                        Err(_) => None
                    }
                })
                .unwrap_or_default();

            let (public_key_bits, key_algorithm) = match cert.public_key().parsed() {
                 Ok(PublicKey::RSA(rsa)) => (Some(rsa.key_size() as u16 * 8), Some("RSA".to_string())),
                 Ok(PublicKey::EC(ec)) => (Some(ec.key_size() as u16), Some("ECC".to_string())), // key_size() for EC gives bits directly
                 Ok(PublicKey::DSA(_)) => (None, Some("DSA".to_string())), // DSA key size is complex
                 _ => (None, None), // Handle other key types or errors
             };

            Some(CertificateInfo {
                subject,
                issuer,
                not_before,
                not_after,
                serial_number,
                signature_algorithm,
                version,
                fingerprint,
                alt_names,
                public_key_bits,
                key_algorithm,
            })
        },
        Err(e) => {
            debug!("Failed to parse certificate: {}", e);
            None
        },
    }
}


/// UDP scan implementation
/// (remains unchanged, uses standard sockets)
pub async fn udp_scan(
    target_ip: IpAddr,
    port: u16,
    _local_ip: Option<IpAddr>,
    use_ipv6: bool,
    timeout_duration: Duration,
) -> Result<PortStatus> {
    debug!("[UDP Scan:{}:{}] Performing standard socket UDP scan", target_ip, port);
    let bind_addr = if use_ipv6 { "[::]:0" } else { "0.0.0.0:0" };
    let socket = match UdpSocket::bind(bind_addr).await {
        Ok(s) => s,
        Err(e) => return Err(anyhow!("Failed to bind UDP socket: {}", e)),
    };

    let addr = SocketAddr::new(target_ip, port);
    // Connect doesn't establish a connection for UDP but sets the default destination
    // and potentially allows receiving ICMP errors on some OSes.
    if let Err(e) = socket.connect(addr).await {
         // This is often not critical for UDP sending, but log it.
         warn!("[UDP Scan:{}:{}] Failed to 'connect' UDP socket (may be ok): {}", target_ip, port, e);
    }

    let probe = b"QSCAN"; // Simple probe
    if let Err(e) = socket.send(probe).await {
         // If send fails, it's likely a real issue.
         return Err(anyhow!("[UDP Scan:{}:{}] Failed to send UDP probe: {}", target_ip, port, e));
    }

    let mut buf = [0u8; 1]; // Minimal buffer, we just care if we receive anything or error

    match timeout(timeout_duration, socket.recv(&mut buf)).await {
        Ok(Ok(_size)) => {
            // Received a response -> Open
            debug!("[UDP Scan:{}:{}] Port is open (received response)", target_ip, port);
            Ok(PortStatus::Open)
        },
        Ok(Err(e)) => {
             // Check if the error indicates ICMP Port Unreachable
             // ErrorKind::ConnectionRefused is the typical mapping on Unix/Linux
             // Windows might return different errors (e.g., TimedOut on receive failure?)
             if e.kind() == std::io::ErrorKind::ConnectionRefused {
                debug!("[UDP Scan:{}:{}] Port is closed (received ICMP Port Unreachable)", target_ip, port);
                Ok(PortStatus::Closed)
             } else {
                 // Other errors might indicate filtering or network issues
                 warn!("[UDP Scan:{}:{}] Recv error: {} (kind: {:?}). Assuming filtered.", target_ip, port, e, e.kind());
                 Ok(PortStatus::Filtered)
             }
        },
        Err(_) => {
            // Timeout -> Open or Filtered
            debug!("[UDP Scan:{}:{}] Port is open|filtered (timeout)", target_ip, port);
            Ok(PortStatus::OpenFiltered)
        },
    }
}

/// ACK scan implementation (using raw sockets)
///
/// Sends a TCP ACK packet to detect firewall filtering rules.
/// - RST response indicates an unfiltered port (stateful firewall allows RST through).
/// - No response or ICMP unreachable indicates a filtered port.
/// REQUIRES root/administrator privileges.
pub async fn ack_scan(
    target_ip: IpAddr,
    port: u16,
    local_ip_option: Option<IpAddr>,
    use_ipv6: bool,
    timeout_duration: Duration,
    enhanced_evasion: bool,
    mimic_os: &str,
    ttl_jitter: u8,
) -> Result<(PortStatus, String)> {
    // Determine the required local IP (similar logic as syn_scan)
    // Add type annotation : IpAddr
    let local_ip: IpAddr = match target_ip {
        IpAddr::V4(target_ipv4) => {
            match local_ip_option {
                Some(IpAddr::V4(ip)) => ip.into(),
                Some(IpAddr::V6(_)) => return Err(anyhow!("Provided local IP is IPv6, but target is IPv4 for raw ACK scan.")),
                None => {
                    warn!("Local IPv4 address not specified for raw ACK scan to {}, attempting auto-detection.", target_ipv4);
                    utils::find_local_ipv4().map_err(|e| anyhow!("Local IPv4 address required for raw ACK scan and auto-detection failed: {}", e))?.into()
                }
            }
        }
        IpAddr::V6(target_ipv6) => {
            if !use_ipv6 { return Err(anyhow!("Target is IPv6 ({}), but IPv6 scanning is not enabled via --ipv6 flag.", target_ipv6)); }
            match local_ip_option {
                Some(IpAddr::V6(ip)) => ip.into(),
                Some(IpAddr::V4(_)) => return Err(anyhow!("Provided local IP is IPv4, but target is IPv6 for raw ACK scan.")),
                None => {
                    warn!("Local IPv6 address not specified for raw ACK scan to {}, attempting auto-detection.", target_ipv6);
                    utils::find_local_ipv6().map_err(|e| anyhow!("Local IPv6 address required for raw ACK scan and auto-detection failed: {}", e))?.into()
                }
            }
        }
    };

    // Ensure the selected local IP matches the target family
    if local_ip.is_ipv4() != target_ip.is_ipv4() {
        return Err(anyhow!("Internal error: Mismatch between selected local IP ({}) and target IP ({}) family for ACK scan.", local_ip, target_ip));
    }

    // Calculate TTL
    let ttl = if enhanced_evasion {
        utils::get_advanced_ttl(mimic_os, ttl_jitter)
    } else {
        64
    };

    debug!("[ACK Scan:{}:{}] Performing raw ACK scan using local IP {} with TTL {} and timeout {:?}. Requires root/admin.", target_ip, port, local_ip, ttl, timeout_duration);

    // Cast TcpFlags::ACK to u8
    let ack_flag: u8 = TcpFlags::ACK.into();
    // Generate a random sequence number
    let _seq_num = rand::random::<u32>();
    
    // Generate a random source port (above 10000) if using enhanced evasion
    let _source_port = if enhanced_evasion {
        10000 + (rand::random::<u16>() % 55000)
    } else {
        12345 // Fixed source port if not using enhanced evasion
    };
    
    // Send ACK packet and wait for response
    match send_receive_raw_tcp(target_ip, port, local_ip, ack_flag, timeout_duration, ttl).await {
        Ok(Some(response)) => match response {
            RawResponse::TcpStatic { flags, .. } => {
                let rst_flag = u16::from(TcpFlags::RST);
                if (flags & rst_flag) != 0 {
                    debug!("[ACK Scan:{}:{}] Port is unfiltered (received RST)", target_ip, port);
                    Ok((PortStatus::Unfiltered, "No filtering detected".to_string()))
                } else {
                    warn!("[ACK Scan:{}:{}] Port returned unexpected TCP flags: {:#04x}", target_ip, port, flags);
                    Ok((PortStatus::Filtered, "Unexpected response".to_string()))
                }
            }
            RawResponse::IcmpFiltered(icmp_type, icmp_code) => {
                let filter_detail = format!("ICMPv4 type={:?} code={:?}", icmp_type, icmp_code);
                debug!("[ACK Scan:{}:{}] Port is filtered ({})", target_ip, port, filter_detail);
                Ok((PortStatus::Filtered, filter_detail))
            }
            RawResponse::Icmpv6Filtered(icmpv6_type, icmpv6_code) => {
                let filter_detail = format!("ICMPv6 type={:?} code={:?}", icmpv6_type, icmpv6_code);
                debug!("[ACK Scan:{}:{}] Port is filtered ({})", target_ip, port, filter_detail);
                Ok((PortStatus::Filtered, filter_detail))
            }
            RawResponse::Timeout => {
                debug!("[ACK Scan:{}:{}] Port is filtered (timeout)", target_ip, port);
                Ok((PortStatus::Filtered, "Timeout".to_string()))
            }
        },
        Ok(None) => {
            debug!("[ACK Scan:{}:{}] No response data (filtered)", target_ip, port);
            Ok((PortStatus::Filtered, "No response data".to_string()))
        },
        Err(e) => {
            error!("[ACK Scan:{}:{}] Error during scan: {}", target_ip, port, e);
            Err(e)
        }
    }
}

/// FIN scan implementation (using raw sockets)
/// Sends TCP FIN packet.
/// - No response -> Open or Filtered.
/// - RST response -> Closed.
/// REQUIRES root/administrator privileges.
pub async fn fin_scan(
    target_ip: IpAddr,
    port: u16,
    local_ip_option: Option<IpAddr>,
    use_ipv6: bool,
    timeout_duration: Duration,
    enhanced_evasion: bool,
    mimic_os: &str,
    ttl_jitter: u8,
) -> Result<PortStatus> {
    // Determine the required local IP (similar logic as syn_scan)
    // Add type annotation : IpAddr
    let local_ip: IpAddr = match target_ip {
        IpAddr::V4(target_ipv4) => {
            match local_ip_option {
                Some(IpAddr::V4(ip)) => ip.into(),
                Some(IpAddr::V6(_)) => return Err(anyhow!("Provided local IP is IPv6, but target is IPv4 for raw FIN scan.")),
                None => {
                    warn!("Local IPv4 address not specified for raw FIN scan to {}, attempting auto-detection.", target_ipv4);
                    utils::find_local_ipv4().map_err(|e| anyhow!("Local IPv4 address required for raw FIN scan and auto-detection failed: {}", e))?.into()
                }
            }
        }
        IpAddr::V6(target_ipv6) => {
            if !use_ipv6 { return Err(anyhow!("Target is IPv6 ({}), but IPv6 scanning is not enabled via --ipv6 flag.", target_ipv6)); }
            match local_ip_option {
                Some(IpAddr::V6(ip)) => ip.into(),
                Some(IpAddr::V4(_)) => return Err(anyhow!("Provided local IP is IPv4, but target is IPv6 for raw FIN scan.")),
                None => {
                    warn!("Local IPv6 address not specified for raw FIN scan to {}, attempting auto-detection.", target_ipv6);
                    utils::find_local_ipv6().map_err(|e| anyhow!("Local IPv6 address required for raw FIN scan and auto-detection failed: {}", e))?.into()
                }
            }
        }
    };

    if local_ip.is_ipv4() != target_ip.is_ipv4() {
        return Err(anyhow!("Internal error: Mismatch between selected local IP ({}) and target IP ({}) family for FIN scan.", local_ip, target_ip));
    }

    // Calculate TTL
    let ttl = if enhanced_evasion {
        utils::get_advanced_ttl(mimic_os, ttl_jitter)
    } else {
        64
    };

    debug!("[FIN Scan:{}:{}] Performing raw FIN scan using local IP {} with TTL {} and timeout {:?}. Requires root/admin.", target_ip, port, local_ip, ttl, timeout_duration);

    // Cast TcpFlags::FIN to u8
    match send_receive_raw_tcp(target_ip, port, local_ip, TcpFlags::FIN.into(), timeout_duration, ttl).await {
        Ok(Some(response)) => match response {
            RawResponse::TcpStatic { flags, .. } => {
                let rst_flag = u16::from(TcpFlags::RST);
                if (flags & rst_flag) != 0 {
                    debug!("[FIN Scan:{}:{}] Port is closed (received RST)", target_ip, port);
                    Ok(PortStatus::Closed)
                } else {
                    debug!("[FIN Scan:{}:{}] Port is filtered (unexpected response)", target_ip, port);
                    Ok(PortStatus::Filtered)
                }
            }
            RawResponse::IcmpFiltered(icmp_type, icmp_code) => {
                debug!("[FIN Scan:{}:{}] Port is filtered (received ICMPv4 {:?}/{:?})", target_ip, port, icmp_type, icmp_code);
                Ok(PortStatus::Filtered)
            }
            RawResponse::Icmpv6Filtered(icmpv6_type, icmpv6_code) => {
                debug!("[FIN Scan:{}:{}] Port is filtered (received ICMPv6 {:?}/{:?})", target_ip, port, icmpv6_type, icmpv6_code);
                Ok(PortStatus::Filtered)
            }
            RawResponse::Timeout => {
                // For FIN scan, no response typically means open|filtered
                debug!("[FIN Scan:{}:{}] Port is open|filtered (no response)", target_ip, port);
                Ok(PortStatus::OpenFiltered)
            }
        },
        Ok(None) => {
            debug!("[FIN Scan:{}:{}] No response data (open|filtered)", target_ip, port);
            Ok(PortStatus::OpenFiltered)
        },
        Err(e) => {
            error!("[FIN Scan:{}:{}] Error during scan: {}", target_ip, port, e);
            Err(e)
        }
    }
}

/// TLS Echo scan implementation
/// (remains unchanged, uses standard sockets)
pub async fn tls_echo_scan(
    target_ip: IpAddr,
    port: u16,
    _local_ip: Option<IpAddr>,
    _use_ipv6: bool,
    _evasion: bool,
    timeout_duration: Duration,
) -> Result<PortStatus> {
    debug!("[TLS Echo Scan:{}:{}] Performing standard socket TCP connect", target_ip, port);
    let socket_addr = SocketAddr::new(target_ip, port);

    match timeout(timeout_duration, tokio::net::TcpStream::connect(socket_addr)).await {
        Ok(Ok(_stream)) => {
             // Connected, assume open for TLS echo (doesn't perform TLS handshake)
             debug!("[TLS Echo Scan:{}:{}] Port is open (TCP connect succeeded)", target_ip, port);
             Ok(PortStatus::Open)
        },
        Ok(Err(_)) => {
            debug!("[TLS Echo Scan:{}:{}] Port is closed (TCP connect failed)", target_ip, port);
            Ok(PortStatus::Closed)
        },
        Err(_) => {
            debug!("[TLS Echo Scan:{}:{}] Port is filtered (TCP connect timed out)", target_ip, port);
            Ok(PortStatus::Filtered)
        },
    }
}

/// Mimic scan with custom protocol payload
/// (remains unchanged, uses standard sockets)
pub async fn mimic_scan_with_payload(
    target_ip: IpAddr,
    port: u16,
    _local_ip: Option<IpAddr>,
    _use_ipv6: bool, // Prefix unused variable
    _evasion: bool,
    _protocol: &str,
    payload: Vec<u8>,
    timeout_duration: Duration,
) -> Result<PortStatus> {
    debug!("[Mimic Scan:{}:{}] Performing standard socket TCP connect and write", target_ip, port);
    let socket_addr = SocketAddr::new(target_ip, port);

    let stream = match timeout(timeout_duration, tokio::net::TcpStream::connect(socket_addr)).await {
        Ok(Ok(stream)) => stream,
        Ok(Err(_)) => {
             debug!("[Mimic Scan:{}:{}] TCP connect failed", target_ip, port);
             return Ok(PortStatus::Closed); // Treat connect errors as closed
        }
        Err(_) => {
            debug!("[Mimic Scan:{}:{}] TCP connect timed out", target_ip, port);
            return Ok(PortStatus::Filtered); // Treat timeout as filtered
        }
    };

    // Add a small random delay? (evasion flag currently ignored)
    // if _evasion { ... }

    // Try to send the custom payload
    if let Err(e) = stream.writable().await {
         error!("[Mimic Scan:{}:{}] Failed write wait: {}", target_ip, port, e);
         // Can't write, connection might be dead
         return Ok(PortStatus::Filtered);
    }
    match stream.try_write(&payload) {
        Ok(bytes_written) => {
             if bytes_written == 0 {
                 warn!("[Mimic Scan:{}:{}] Wrote 0 bytes, connection may be closed.", target_ip, port);
                 return Ok(PortStatus::Filtered);
             }
             debug!("[Mimic Scan:{}:{}] Successfully wrote {} payload bytes", target_ip, port, bytes_written);
             // Wait for response briefly to see if connection is immediately closed or data arrives
             match timeout(Duration::from_millis(500), stream.readable()).await { // Short wait
                 Ok(Ok(_)) => {
                     let mut buf = [0u8; 1];
                     match stream.try_read(&mut buf) {
                         Ok(0) => {
                              debug!("[Mimic Scan:{}:{}] Connection closed immediately after write", target_ip, port);
                              Ok(PortStatus::Filtered)
                         }
                         Ok(_) => {
                             debug!("[Mimic Scan:{}:{}] Got response data", target_ip, port);
                             Ok(PortStatus::Open)
                         }
                         Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                             debug!("[Mimic Scan:{}:{}] No immediate response data (WouldBlock), assuming open", target_ip, port);
                             Ok(PortStatus::Open)
                         }
                         Err(e) => {
                             warn!("[Mimic Scan:{}:{}] Read error after write: {}", target_ip, port, e);
                             Ok(PortStatus::OpenFiltered) // Read error, assume open/filtered
                         }
                     }
                 },
                 Ok(Err(e)) => {
                    warn!("[Mimic Scan:{}:{}] Error waiting for readability: {}", target_ip, port, e);
                    Ok(PortStatus::Open) // Assume open if readability check errors
                 },
                 Err(_) => { // Timeout waiting for read
                     debug!("[Mimic Scan:{}:{}] Timeout waiting for read after write, assuming open", target_ip, port);
                     Ok(PortStatus::Open)
                 }
             }
        },
        Err(e) => {
            warn!("[Mimic Scan:{}:{}] Error writing payload: {}", target_ip, port, e);
            Ok(PortStatus::Closed) // Write error often means closed/rejected
        }
    }
}

// Placeholder comments for unimplemented scans
// pub async fn frag_scan(...) -> Result<PortStatus> { Err(anyhow!("Frag scan not implemented")) }
// pub async fn dns_tunnel_scan(...) -> Result<PortStatus> { Err(anyhow!("DNS Tunnel scan not implemented")) }
// pub async fn icmp_tunnel_scan(...) -> Result<PortStatus> { Err(anyhow!("ICMP Tunnel scan not implemented")) }

/// XMAS scan implementation (using raw sockets)
/// Sends packet with FIN, PSH, URG flags set.
/// - No response -> Open or Filtered.
/// - RST response -> Closed.
/// REQUIRES root/administrator privileges.
pub async fn xmas_scan(
    target_ip: IpAddr,
    port: u16,
    local_ip_option: Option<IpAddr>,
    use_ipv6: bool,
    timeout_duration: Duration,
    enhanced_evasion: bool,
    mimic_os: &str,
    ttl_jitter: u8,
) -> Result<PortStatus> {
    // Determine the required local IP (similar logic as syn_scan)
    // Use .into() to convert specific IP types to IpAddr
    let local_ip: IpAddr = match target_ip {
        IpAddr::V4(target_ipv4) => {
            match local_ip_option {
                Some(IpAddr::V4(ip)) => ip.into(),
                Some(IpAddr::V6(_)) => return Err(anyhow!("Local IP is V6, target is V4 for raw XMAS scan.")),
                None => {
                    warn!("Local IPv4 needed for raw XMAS scan to {}, auto-detecting.", target_ipv4);
                    utils::find_local_ipv4().map_err(|e| anyhow!("Local IPv4 required and auto-detection failed: {}", e))?.into()
                }
            }
        }
        IpAddr::V6(target_ipv6) => {
            if !use_ipv6 { return Err(anyhow!("Target is IPv6 ({}), but --ipv6 not enabled.", target_ipv6)); }
            match local_ip_option {
                Some(IpAddr::V6(ip)) => ip.into(),
                Some(IpAddr::V4(_)) => return Err(anyhow!("Local IP is V4, but target is IPv6 for raw XMAS scan.")),
                None => {
                    warn!("Local IPv6 needed for raw XMAS scan to {}, auto-detecting.", target_ipv6);
                    utils::find_local_ipv6().map_err(|e| anyhow!("Local IPv6 required and auto-detection failed: {}", e))?.into()
                }
            }
        }
    };

    if local_ip.is_ipv4() != target_ip.is_ipv4() {
        return Err(anyhow!("Internal error: Mismatch between selected local IP ({}) and target IP ({}) family for XMAS scan.", local_ip, target_ip));
    }

    // Calculate TTL
    let ttl = if enhanced_evasion {
        utils::get_advanced_ttl(mimic_os, ttl_jitter)
    } else {
        64
    };

    let xmas_flags = (tcp_flags_as_u16(TcpFlags::FIN) | tcp_flags_as_u16(TcpFlags::URG) | tcp_flags_as_u16(TcpFlags::PSH)) as u8;
    debug!("[XMAS Scan:{}:{}] Performing raw XMAS scan (flags {:#04x}) using local IP {} with TTL {} and timeout {:?}. Requires root/admin.", target_ip, port, xmas_flags, local_ip, ttl, timeout_duration);

    // Cast xmas_flags to u8
    match send_receive_raw_tcp(target_ip, port, local_ip, xmas_flags, timeout_duration, ttl).await {
        Ok(Some(response)) => match response {
            RawResponse::TcpStatic { flags, .. } => {
                let rst_flag = u16::from(TcpFlags::RST);
                if (flags & rst_flag) != 0 {
                    debug!("[XMAS Scan:{}:{}] Port is closed (received RST)", target_ip, port);
                    Ok(PortStatus::Closed)
                } else {
                    debug!("[XMAS Scan:{}:{}] Port is filtered (unexpected response)", target_ip, port);
                    Ok(PortStatus::Filtered)
                }
            }
            RawResponse::IcmpFiltered(icmp_type, icmp_code) => {
                debug!("[XMAS Scan:{}:{}] Port is filtered (received ICMPv4 {:?}/{:?})", target_ip, port, icmp_type, icmp_code);
                Ok(PortStatus::Filtered)
            }
            RawResponse::Icmpv6Filtered(icmpv6_type, icmpv6_code) => {
                debug!("[XMAS Scan:{}:{}] Port is filtered (received ICMPv6 {:?}/{:?})", target_ip, port, icmpv6_type, icmpv6_code);
                Ok(PortStatus::Filtered)
            }
            RawResponse::Timeout => {
                // For XMAS scan, no response typically means open|filtered
                debug!("[XMAS Scan:{}:{}] Port is open|filtered (no response)", target_ip, port);
                Ok(PortStatus::OpenFiltered)
            }
        },
        Ok(None) => {
            debug!("[XMAS Scan:{}:{}] No response data (open|filtered)", target_ip, port);
            Ok(PortStatus::OpenFiltered)
        },
        Err(e) => {
            error!("[XMAS Scan:{}:{}] Error during scan: {}", target_ip, port, e);
            Err(e)
        }
    }
}

/// NULL scan implementation (using raw sockets)
/// Sends packet with no flags set.
/// - No response -> Open or Filtered.
/// - RST response -> Closed.
/// REQUIRES root/administrator privileges.
pub async fn null_scan(
    target_ip: IpAddr,
    port: u16,
    local_ip_option: Option<IpAddr>,
    use_ipv6: bool,
    timeout_duration: Duration,
    enhanced_evasion: bool,
    mimic_os: &str,
    ttl_jitter: u8,
) -> Result<PortStatus> {
    // Determine the required local IP (similar logic as syn_scan)
    // Use .into() to convert specific IP types to IpAddr
    let local_ip: IpAddr = match target_ip {
        IpAddr::V4(target_ipv4) => {
            match local_ip_option {
                Some(IpAddr::V4(ip)) => ip.into(),
                Some(IpAddr::V6(_)) => return Err(anyhow!("Local IP is V6, target is V4 for raw NULL scan.")),
                None => {
                    warn!("Local IPv4 needed for raw NULL scan to {}, auto-detecting.", target_ipv4);
                    utils::find_local_ipv4().map_err(|e| anyhow!("Local IPv4 required and auto-detection failed: {}", e))?.into()
                }
            }
        }
        IpAddr::V6(target_ipv6) => {
            if !use_ipv6 { return Err(anyhow!("Target is IPv6 ({}), but --ipv6 not enabled.", target_ipv6)); }
            match local_ip_option {
                Some(IpAddr::V6(ip)) => ip.into(),
                Some(IpAddr::V4(_)) => return Err(anyhow!("Local IP is V4, but target is V6 for raw NULL scan.")),
                None => {
                    warn!("Local IPv6 needed for raw NULL scan to {}, auto-detecting.", target_ipv6);
                    utils::find_local_ipv6().map_err(|e| anyhow!("Local IPv6 required and auto-detection failed: {}", e))?.into()
                }
            }
        }
    };

    if local_ip.is_ipv4() != target_ip.is_ipv4() {
        return Err(anyhow!("Internal error: Mismatch between selected local IP ({}) and target IP ({}) family for NULL scan.", local_ip, target_ip));
    }

    // Calculate TTL
    let ttl = if enhanced_evasion {
        utils::get_advanced_ttl(mimic_os, ttl_jitter)
    } else {
        64
    };

    // Prefixed with underscore to silence unused variable warning
    let _null_flags = 0u8; // No flags set, explicit u8
    debug!("[NULL Scan:{}:{}] Performing raw NULL scan (no flags) using local IP {} with TTL {} and timeout {:?}. Requires root/admin.", target_ip, port, local_ip, ttl, timeout_duration);

    // Pass null_flags (u8) directly
    match send_receive_raw_tcp(target_ip, port, local_ip, 0, timeout_duration, ttl).await {
        Ok(Some(response)) => match response {
            RawResponse::TcpStatic { flags, .. } => {
                let rst_flag = u16::from(TcpFlags::RST);
                if (flags & rst_flag) != 0 {
                    debug!("[NULL Scan:{}:{}] Port is closed (received RST)", target_ip, port);
                    Ok(PortStatus::Closed)
                } else {
                    debug!("[NULL Scan:{}:{}] Port is filtered (unexpected response)", target_ip, port);
                    Ok(PortStatus::Filtered)
                }
            }
            RawResponse::IcmpFiltered(icmp_type, icmp_code) => {
                debug!("[NULL Scan:{}:{}] Port is filtered (received ICMPv4 {:?}/{:?})", target_ip, port, icmp_type, icmp_code);
                Ok(PortStatus::Filtered)
            }
            RawResponse::Icmpv6Filtered(icmpv6_type, icmpv6_code) => {
                debug!("[NULL Scan:{}:{}] Port is filtered (received ICMPv6 {:?}/{:?})", target_ip, port, icmpv6_type, icmpv6_code);
                Ok(PortStatus::Filtered)
            }
            RawResponse::Timeout => {
                // For NULL scan, no response typically means open|filtered
                debug!("[NULL Scan:{}:{}] Port is open|filtered (no response)", target_ip, port);
                Ok(PortStatus::OpenFiltered)
            }
        },
        Ok(None) => {
            debug!("[NULL Scan:{}:{}] No response data (open|filtered)", target_ip, port);
            Ok(PortStatus::OpenFiltered)
        },
        Err(e) => {
            error!("[NULL Scan:{}:{}] Error during scan: {}", target_ip, port, e);
            Err(e)
        }
    }
}

/// Window scan implementation (using raw sockets)
/// Sends TCP ACK packet and checks TCP window size in RST response.
/// - RST with non-zero window -> Open.
/// - RST with zero window -> Closed.
/// - No response / ICMP -> Filtered.
/// REQUIRES root/administrator privileges.
pub async fn window_scan(
    target_ip: IpAddr,
    port: u16,
    local_ip_option: Option<IpAddr>,
    use_ipv6: bool,
    timeout_duration: Duration,
    enhanced_evasion: bool,
    mimic_os: &str,
    ttl_jitter: u8,
) -> Result<PortStatus> {
    // Determine the required local IP
    let local_ip: IpAddr = match target_ip {
        IpAddr::V4(target_ipv4) => {
            match local_ip_option {
                Some(IpAddr::V4(ip)) => ip.into(),
                Some(IpAddr::V6(_)) => return Err(anyhow!("Local IP is V6, target is V4 for raw WINDOW scan.")),
                None => {
                    warn!("Local IPv4 needed for raw WINDOW scan to {}, auto-detecting.", target_ipv4);
                    utils::find_local_ipv4().map_err(|e| anyhow!("Local IPv4 required and auto-detection failed: {}", e))?.into()
                }
            }
        }
        IpAddr::V6(target_ipv6) => {
            if !use_ipv6 { return Err(anyhow!("Target is IPv6 ({}), but --ipv6 not enabled.", target_ipv6)); }
            match local_ip_option {
                Some(IpAddr::V6(ip)) => ip.into(),
                Some(IpAddr::V4(_)) => return Err(anyhow!("Local IP is V4, but target is V6 for raw WINDOW scan.")),
                None => {
                    warn!("Local IPv6 needed for raw WINDOW scan to {}, auto-detecting.", target_ipv6);
                    utils::find_local_ipv6().map_err(|e| anyhow!("Local IPv6 required and auto-detection failed: {}", e))?.into()
                }
            }
        }
    };

    if local_ip.is_ipv4() != target_ip.is_ipv4() {
        return Err(anyhow!("Internal error: Mismatch between selected local IP ({}) and target IP ({}) family for Window scan.", local_ip, target_ip));
    }

    // Calculate TTL
    let ttl = if enhanced_evasion {
        utils::get_advanced_ttl(mimic_os, ttl_jitter)
    } else {
        64
    };

    debug!("[Window Scan:{}:{}] Performing raw Window scan (ACK) using local IP {} with TTL {} and timeout {:?}. Requires root/admin.", target_ip, port, local_ip, ttl, timeout_duration);

    // Cast TcpFlags::ACK to u8
    let ack_flag: u8 = TcpFlags::ACK.into();
    // Generate a random sequence number
    let _seq_num = rand::random::<u32>();
    
    // Generate a random source port (above 10000) if using enhanced evasion
    let _source_port = if enhanced_evasion {
        10000 + (rand::random::<u16>() % 55000)
    } else {
        12345 // Fixed source port if not using enhanced evasion
    };
    
    // Send ACK packet and wait for response
    match send_receive_raw_tcp(target_ip, port, local_ip, ack_flag, timeout_duration, ttl).await {
        Ok(Some(response)) => match response {
            RawResponse::TcpStatic { flags, data, .. } => {
                let rst_flag = u16::from(TcpFlags::RST);
                if (flags & rst_flag) != 0 {
                    // Extract window size from TCP header
                    // TCP window size is bytes 14-15 in the TCP header
                    // This is a more accurate implementation than checking data length
                    if data.len() >= 20 {  // Minimum TCP header length
                        // TCP header window size is at offset 14 (0-indexed)
                        let window_size = u16::from(data[14]) << 8 | u16::from(data[15]);
                        if window_size > 0 {
                            debug!("[WINDOW Scan:{}:{}] Port is likely open (RST with non-zero window size: {})", 
                                    target_ip, port, window_size);
                            Ok(PortStatus::Open)
                        } else {
                            debug!("[WINDOW Scan:{}:{}] Port is likely closed (RST with zero window size)", target_ip, port);
                            Ok(PortStatus::Closed)
                        }
                    } else {
                        // Fallback to original behavior if TCP header is incomplete
                        if !data.is_empty() {
                            debug!("[WINDOW Scan:{}:{}] Port is likely open (RST with data)", target_ip, port);
                            Ok(PortStatus::Open)
                        } else {
                            debug!("[WINDOW Scan:{}:{}] Port is likely closed (RST with no data)", target_ip, port);
                            Ok(PortStatus::Closed)
                        }
                    }
                } else {
                    debug!("[WINDOW Scan:{}:{}] Port is filtered (no RST)", target_ip, port);
                    Ok(PortStatus::Filtered)
                }
            }
            RawResponse::IcmpFiltered(_, _) => {
                debug!("[Window Scan:{}:{}] Port is filtered (ICMP response)", target_ip, port);
                Ok(PortStatus::Filtered)
            }
            RawResponse::Icmpv6Filtered(_, _) => {
                debug!("[Window Scan:{}:{}] Port is filtered (ICMPv6 response)", target_ip, port);
                Ok(PortStatus::Filtered)
            }
            RawResponse::Timeout => {
                debug!("[Window Scan:{}:{}] Port is filtered (timeout)", target_ip, port);
                Ok(PortStatus::Filtered)
            }
        },
        Ok(None) => {
            debug!("[Window Scan:{}:{}] No response data (filtered)", target_ip, port);
            Ok(PortStatus::Filtered)
        },
        Err(e) => {
            error!("[Window Scan:{}:{}] Error during scan: {}", target_ip, port, e);
            Err(e)
        }
    }
}

/// Fragment Scan implementation (using raw sockets)
///
/// Sends a TCP SYN packet fragmented into multiple small IP packets.
/// This attempts to evade stateless packet filters.
/// Analyzes the response (if any) to determine port status:
/// - SYN-ACK response indicates an open port (target reassembled fragments)
/// - RST response indicates a closed port
/// - ICMP errors (e.g., Time Exceeded, Destination Unreachable/Fragmentation Needed) might indicate filtering or path issues.
/// - No response indicates a filtered port or packet loss.
/// REQUIRES root/administrator privileges.
/// NOTE: Current implementation fragments a standard TCP SYN packet. Evasion effectiveness varies.
pub async fn frag_scan(
    target_ip: IpAddr,
    port: u16,
    local_ip_option: Option<IpAddr>, // Renamed from local_ip for consistency
    use_ipv6: bool,
    // _evasion: bool, // Removed unused evasion flag
    timeout_duration: Duration,
    // Add parameters for enhanced evasion
    enhanced_evasion: bool,
    mimic_os: &str,
    ttl_jitter: u8,
) -> Result<PortStatus> {
    // Determine the required local IP and target IP based on family
    let (local_ip, target_ip_concrete) = match target_ip {
        IpAddr::V4(target_ipv4) => {
            let local_ip_v4 = match local_ip_option {
                Some(IpAddr::V4(ip)) => ip,
                Some(IpAddr::V6(_)) => return Err(anyhow!("Provided local IP is IPv6, but target is IPv4 for raw Frag scan.")),
                None => {
                    warn!("Local IPv4 address not specified for raw Frag scan to {}, attempting auto-detection.", target_ipv4);
                    utils::find_local_ipv4().map_err(|e| anyhow!("Local IPv4 address required for raw Frag scan and auto-detection failed: {}", e))?
                }
            };
            (IpAddr::V4(local_ip_v4), IpAddr::V4(target_ipv4)) // Return concrete types
        }
        IpAddr::V6(target_ipv6) => {
             // TODO: Implement IPv6 Fragment Scan -> Starting implementation
             if !use_ipv6 {
                  // Remove .to_string() from anyhow! macro call - Add target_ipv6 as argument
                  return Err(anyhow!("Target is IPv6 ({}), but IPv6 scanning is not enabled via --ipv6 flag.", target_ipv6));
             }
             let local_ip_v6 = match local_ip_option {
                 Some(IpAddr::V6(ip)) => ip,
                 // Remove .to_string() from anyhow! macro call
                 Some(IpAddr::V4(_)) => return Err(anyhow!("Provided local IP is IPv4, but target is IPv6 for raw Frag scan.")),
                 // Remove .to_string() from warn! macro call - Add target_ipv6 as argument
                 None => {
                     warn!("Local IPv6 address not specified for raw Frag scan to {}, attempting auto-detection.", target_ipv6);
                     utils::find_local_ipv6().map_err(|e| anyhow!("Local IPv6 address required for raw Frag scan and auto-detection failed: {}. Requires root/admin privileges.", e))?
                 }
             };
            (IpAddr::V6(local_ip_v6), IpAddr::V6(target_ipv6)) // Return concrete types
        }
    };

    // Calculate TTL based on evasion settings
    let ttl = if enhanced_evasion {
        utils::get_advanced_ttl(mimic_os, ttl_jitter)
    } else {
        64 // Default TTL if not using enhanced evasion
    };

    debug!("[Frag Scan:{}:{}] Performing raw fragment scan ({} -> {}) using TTL {} and timeout {:?}. Requires root/admin.",
        target_ip, port, local_ip, target_ip, ttl, timeout_duration);
    let source_port = utils::random_high_port();
    let seq_num: u32 = thread_rng().gen();

    // --- Transport Channel Setup ---
    // Need Layer 3 access to craft IP headers directly
    let protocol = match target_ip {
        IpAddr::V4(_) => TransportChannelType::Layer4(transport::TransportProtocol::Ipv4(IpNextHeaderProtocols::Tcp)),
        IpAddr::V6(_) => TransportChannelType::Layer4(transport::TransportProtocol::Ipv6(IpNextHeaderProtocols::Tcp)),
    };
    // Use the imported transport_channel function
    let (mut tx, _rx) = match transport_channel(4096, protocol) {
        Ok((tx, rx)) => (tx, rx),
        Err(e) => return Err(anyhow!("Failed to open raw socket channel for Frag scan ({}): {}. Requires root/admin privileges.",
            if target_ip.is_ipv4() { "IPv4" } else { "IPv6" }, e)),
    };

    // --- Build the *Payload* (TCP SYN Segment) ---
    let tcp_options = match target_ip_concrete {
        IpAddr::V4(_) => [TcpOption::mss(1460)], // Standard MSS for IPv4
        IpAddr::V6(_) => [TcpOption::mss(1440)], // Standard MSS for IPv6
    };
    let tcp_segment_len = TCP_HEADER_LEN + (tcp_options.len() * 4);
    let mut tcp_segment_buf = vec![0u8; tcp_segment_len];
    {
        let mut tcp_header = MutableTcpPacket::new(&mut tcp_segment_buf).unwrap();
        tcp_header.set_source(source_port);
        tcp_header.set_destination(port);
        tcp_header.set_sequence(seq_num);
        tcp_header.set_acknowledgement(0);
        tcp_header.set_data_offset(((tcp_segment_len) / 4) as u8);
        // Cast TcpFlags::SYN to u16 for set_flags
        tcp_header.set_flags(TcpFlags::SYN.into()); // Use into() instead of bits() as u8
        tcp_header.set_window(1024);
        tcp_header.set_urgent_ptr(0);
        tcp_header.set_options(&tcp_options);
        tcp_header.set_checksum(0); // Zero out checksum initially

        // Calculate TCP checksum *once* based on IP version
        let tcp_checksum = match (local_ip, target_ip_concrete) {
            (IpAddr::V4(src), IpAddr::V4(dst)) => {
                 // Use pnet::packet::tcp::ipv4_checksum for consistency
                 pnet::packet::tcp::ipv4_checksum(&tcp_header.to_immutable(), &src, &dst)
            }
            (IpAddr::V6(src), IpAddr::V6(dst)) => {
                 // Use pnet::packet::tcp::ipv6_checksum for consistency
                 pnet::packet::tcp::ipv6_checksum(&tcp_header.to_immutable(), &src, &dst)
            }
            _ => unreachable!("IP address family mismatch should be caught earlier"),
        };
        tcp_header.set_checksum(tcp_checksum);
    }

    // --- Fragmentation Logic ---
    const FRAGMENT_DATA_SIZE: usize = 8; // Keep small fragment size
    let tcp_data = &tcp_segment_buf[..]; // TCP segment is the data to be fragmented
    let mut fragments_sent = 0;
    let mut current_offset = 0;
    let identification: u32 = thread_rng().gen(); // Use u32 for IPv6 ID, cast later for IPv4

    while current_offset < tcp_data.len() {
        let remaining_data = tcp_data.len() - current_offset;
        let current_frag_size = std::cmp::min(FRAGMENT_DATA_SIZE, remaining_data);
        let is_last_fragment = (current_offset + current_frag_size) == tcp_data.len();
        let fragment_data = &tcp_data[current_offset..(current_offset + current_frag_size)];

        // Prepare packet buffer and build fragment header based on IP version
        match (local_ip, target_ip_concrete) {
            (IpAddr::V4(local_ip_v4), IpAddr::V4(dest_ip_v4)) => {
                // --- IPv4 Fragmentation ---
                let ip_total_len = IPV4_HEADER_LEN + current_frag_size;
                let mut packet_buf = vec![0u8; ip_total_len];
                
                // Fill in the IPv4 header fields
                let mut ip_header = MutableIpv4Packet::new(&mut packet_buf).unwrap();
                ip_header.set_version(4);
                ip_header.set_header_length(5);
                ip_header.set_total_length(ip_total_len as u16);
                ip_header.set_identification(identification as u16); // Use lower 16 bits for IPv4 ID
                ip_header.set_ttl(ttl);
                ip_header.set_next_level_protocol(IpNextHeaderProtocols::Tcp);
                ip_header.set_source(local_ip_v4);
                ip_header.set_destination(dest_ip_v4);

                let frag_offset_words = current_offset / 8;
                ip_header.set_fragment_offset(frag_offset_words as u16);
                if is_last_fragment {
                    // Set flags to 0 (no MoreFragments, no DontFragment)
                    ip_header.set_flags(0);
                } else {
                    ip_header.set_flags(Ipv4Flags::MoreFragments); // Not last: MF=1, DF=0
                }
                
                // Release the mutable borrow of packet_buf through ip_header
                drop(ip_header);
                
                // Now we can use packet_buf directly
                packet_buf[IPV4_HEADER_LEN..ip_total_len].copy_from_slice(fragment_data);
                
                // Create a new header instance to calculate and set the checksum
                let mut ip_header = MutableIpv4Packet::new(&mut packet_buf).unwrap();
                let ip_header_immutable = ip_header.to_immutable();
                let ip_checksum = pnet::packet::ipv4::checksum(&ip_header_immutable);
                ip_header.set_checksum(ip_checksum);
                
                // Release the mutable borrow again
                drop(ip_header);
                
                // Send IPv4 fragment - fix the temporary value issue
                let ip_packet = MutableIpv4Packet::new(&mut packet_buf).unwrap();
                let packet = ip_packet.to_immutable();
                if tx.send_to(packet, target_ip).is_err() {
                    return Err(anyhow!("[Frag Scan:{}:{}] Failed to send IPv4 fragment {} to {}", target_ip, port, fragments_sent + 1, target_ip));
                }
            }
            (IpAddr::V6(local_ip_v6), IpAddr::V6(dest_ip_v6)) => {
                // --- IPv6 Fragmentation ---
                const FRAG_HEADER_LEN: usize = 8;
                let ip_payload_len = FRAG_HEADER_LEN + current_frag_size;
                let total_len = IPV6_HEADER_LEN + ip_payload_len;
                let mut packet_buf = vec![0u8; total_len];
                {
                    let mut ip_header = MutableIpv6Packet::new(&mut packet_buf).unwrap();
                    ip_header.set_version(6);
                    ip_header.set_traffic_class(0);
                    ip_header.set_flow_label(0);
                    ip_header.set_payload_length(ip_payload_len as u16);
                    // Use the correct constant for IPv6 Fragment Header
                    ip_header.set_next_header(IpNextHeaderProtocols::Ipv6Frag);
                    ip_header.set_hop_limit(ttl);
                    ip_header.set_source(local_ip_v6);
                    ip_header.set_destination(dest_ip_v6);

                    // Build Fragment Header
                    // Correct typo: Use MutableFragmentPacket as imported
                    let mut frag_packet = MutableFragmentPacket::new(&mut packet_buf[IPV6_HEADER_LEN..]).unwrap();
                    frag_packet.set_next_header(IpNextHeaderProtocols::Tcp); // Protocol *after* fragment header
                    frag_packet.set_reserved(0);
                    let frag_offset_words = current_offset / 8;
                    frag_packet.set_fragment_offset(frag_offset_words as u16);
                    // Set the M flag directly in the buffer
                    // In IPv6 Fragment header, the M flag is bit 0 of the 3rd byte
                    if !is_last_fragment {
                        packet_buf[IPV6_HEADER_LEN + 3] |= 0x01; // Set the M flag
                    } else {
                        packet_buf[IPV6_HEADER_LEN + 3] &= 0xFE; // Clear the M flag
                    }
                    // Set identification field directly
                    let id_bytes = identification.to_be_bytes();
                    packet_buf[IPV6_HEADER_LEN + 4] = id_bytes[0];
                    packet_buf[IPV6_HEADER_LEN + 5] = id_bytes[1];
                    packet_buf[IPV6_HEADER_LEN + 6] = id_bytes[2];
                    packet_buf[IPV6_HEADER_LEN + 7] = id_bytes[3];

                    // Copy fragment data after the fragment header
                    packet_buf[IPV6_HEADER_LEN + FRAG_HEADER_LEN..total_len].copy_from_slice(fragment_data);
                }
                 // Send IPv6 fragment
                 // Clone target_ip before moving into the error message
                 let target_ip_clone = target_ip.clone();
                 if tx.send_to(MutableIpv6Packet::new(&mut packet_buf).unwrap().to_immutable(), target_ip).is_err() {
                     return Err(anyhow!("[Frag Scan:{}:{}] Failed to send IPv6 fragment {} to {}", target_ip_clone, port, fragments_sent + 1, target_ip_clone));
                 }
            }
            _ => unreachable!("IP family mismatch should have been caught"),
        }

        fragments_sent += 1;
        current_offset += current_frag_size;

        // Optional: Small delay between fragments
        // sleep(Duration::from_millis(5)).await;

    } // End fragmentation loop

    debug!("[Frag Scan:{}:{}] Sent {} fragments (total {} bytes TCP data) from port {} with ID {} using TTL {}",
           target_ip, port, fragments_sent, tcp_data.len(), source_port, identification, ttl);

    // --- Receive Logic (Similar approach as send_receive_raw_tcp to fix lifetime issues) ---
    // Create a new channel for receiving instead of reusing rx
    let (_, mut new_rx) = match transport_channel(4096, protocol) {
        Ok((tx, rx)) => (tx, rx),
        Err(e) => return Err(anyhow!("Failed to open receive socket channel: {}", e)),
    };

    // Set a timeout for receiving responses
    let start_time = Instant::now();
    while start_time.elapsed() < timeout_duration {
        // Small sleep to prevent CPU spinning
        tokio::time::sleep(Duration::from_millis(10)).await;
        
        // Use a buffer for receiving packets
        let mut iter = transport::tcp_packet_iter(&mut new_rx);
        
        match iter.next() {
            Ok((packet, addr)) => {
                if addr != target_ip { continue; } // Response must come from the target

                // TCP packet received directly due to the transport channel type
                if packet.get_destination() == source_port && packet.get_source() == port {
                    debug!("[Frag Scan:{}:{}] Received matching TCP response (flags: {:#04x})", 
                          target_ip, port, packet.get_flags());
                    
                    // Re-evaluate based on flags for Frag scan specifically
                    let flags: u16 = packet.get_flags().into(); // Use .into() to convert u8 to u16
                    let syn_flag = tcp_flags_as_u16(TcpFlags::SYN); 
                    let ack_flag = tcp_flags_as_u16(TcpFlags::ACK);
                    let rst_flag = tcp_flags_as_u16(TcpFlags::RST);
                    
                    if (flags & syn_flag) != 0 && (flags & ack_flag) != 0 {
                        debug!("[Frag Scan:{}:{}] Port is Open (received SYN-ACK)", target_ip, port);
                        return Ok(PortStatus::Open);
                    } else if (flags & rst_flag) != 0 {
                        debug!("[Frag Scan:{}:{}] Port is Closed (received RST)", target_ip, port);
                        return Ok(PortStatus::Closed);
                    } else {
                        debug!("[Frag Scan:{}:{}] Port is Filtered (unexpected TCP flags)", target_ip, port);
                        return Ok(PortStatus::Filtered);
                    }
                }
            }
            Err(e) => {
                // Check for ICMP errors via IO error type
                if e.kind() == std::io::ErrorKind::ConnectionRefused {
                    debug!("[Frag Scan:{}:{}] Received ICMP-like error (ConnectionRefused). Filtered?", 
                          target_ip, port);
                    return Ok(PortStatus::Filtered);
                } else {
                    warn!("[Frag Scan:{}:{}] Error receiving: {}. May indicate filtering.", 
                         target_ip, port, e);
                    // Continue the loop, don't return an error yet
                }
            }
        }
    }

    // Timeout occurred
    debug!("[Frag Scan:{}:{}] Timeout occurred. Assuming Filtered.", target_ip, port);
    return Ok(PortStatus::Filtered);
} 