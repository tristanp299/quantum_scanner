use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpStream};
use std::time::Duration;

use anyhow::{Context, Result};
use log::{debug, error, info};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::tcp::{MutableTcpPacket, TcpFlags, TcpOption, TcpPacket};
use pnet::packet::udp::MutableUdpPacket;
use pnet::packet::Packet;
use pnet::transport::{self, TransportChannelType, TransportProtocol};
use rand::{Rng, thread_rng};
use rustls::{ClientConfig, ClientConnection, RootCertStore, ServerName};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpSocket, UdpSocket};
use tokio::time::timeout;
use webpki_roots::TLS_SERVER_ROOTS;
use x509_parser::prelude::*;

use crate::models::{CertificateInfo, MimicPayloads, PortStatus};

/// Maximum number of retries for packet-based scans
const MAX_RETRIES: usize = 3;

/// Maximum packet size for crafting
const MAX_PACKET_SIZE: usize = 1500;

/// SYN scan implementation
///
/// Sends a TCP SYN packet and analyzes the response:
/// - SYN-ACK response indicates an open port
/// - RST response indicates a closed port
/// - No response indicates a filtered port
pub async fn syn_scan(
    target_ip: IpAddr,
    port: u16,
    local_ip: Option<IpAddr>,
    use_ipv6: bool,
    evasion: bool,
    timeout_duration: Duration,
) -> Result<PortStatus> {
    // Open raw socket for sending/receiving
    let (mut tx, mut rx) = transport::transport_channel(
        MAX_PACKET_SIZE,
        TransportChannelType::Layer4(TransportProtocol::Ipv4),
    )?;

    // Create a random source port and sequence number for evasion
    let mut rng = thread_rng();
    let source_port = rng.gen_range(49152..65535);
    let seq_num = rng.gen_range(0..u32::MAX);
    
    // Create the TCP packet
    let mut tcp_buffer = [0u8; MAX_PACKET_SIZE];
    let mut tcp_packet = MutableTcpPacket::new(&mut tcp_buffer).unwrap();
    
    // Set TCP header fields
    tcp_packet.set_source(source_port);
    tcp_packet.set_destination(port);
    tcp_packet.set_sequence(seq_num);
    tcp_packet.set_acknowledgement(0);
    tcp_packet.set_data_offset(5); // 5 32-bit words = 20 bytes (standard header size)
    tcp_packet.set_flags(TcpFlags::SYN); // SYN flag
    tcp_packet.set_window(65535); // Maximum window size
    tcp_packet.set_urgent_pointer(0);
    
    // Set random TTL and window size for evasion if enabled
    if evasion {
        tcp_packet.set_window(rng.gen_range(1024..65535));
        // TTL set at IP layer, not here
    }
    
    // Set checksum (normally would be calculated based on pseudo-header)
    tcp_packet.set_checksum(0); // Will be calculated by the OS
    
    // Set socket destination
    let socket_addr = SocketAddr::new(target_ip, port);
    
    // Send the packet with retries
    for _ in 0..MAX_RETRIES {
        tx.send_to(tcp_packet.to_immutable(), socket_addr)?;
        
        // Listen for response with timeout
        let start = std::time::Instant::now();
        while start.elapsed() < timeout_duration {
            match rx.next() {
                Ok((packet, addr)) => {
                    // Only process packets from our target
                    if addr.ip() != target_ip {
                        continue;
                    }
                    
                    // Parse TCP packet
                    let tcp = TcpPacket::new(packet.payload()).unwrap();
                    
                    // Check if this is a response to our probe
                    if tcp.get_destination() == source_port && tcp.get_source() == port {
                        let flags = tcp.get_flags();
                        
                        // Check for SYN-ACK (port is open)
                        if flags & TcpFlags::SYN != 0 && flags & TcpFlags::ACK != 0 {
                            // Send RST to close the connection
                            let mut rst_packet = tcp_packet.clone();
                            rst_packet.set_flags(TcpFlags::RST);
                            rst_packet.set_sequence(seq_num + 1);
                            tx.send_to(rst_packet.to_immutable(), socket_addr)?;
                            
                            return Ok(PortStatus::Open);
                        }
                        
                        // Check for RST (port is closed)
                        if flags & TcpFlags::RST != 0 {
                            return Ok(PortStatus::Closed);
                        }
                    }
                }
                Err(e) => {
                    error!("Error receiving packet: {}", e);
                    break;
                }
            }
        }
    }
    
    // No response after retries
    Ok(PortStatus::Filtered)
}

/// SSL/TLS scan implementation
///
/// Attempts to establish an SSL/TLS connection and retrieve certificate information
pub async fn ssl_scan(
    target_ip: IpAddr,
    port: u16,
    timeout_duration: Duration,
) -> Result<(PortStatus, Option<CertificateInfo>, String)> {
    // Create SSL configuration with system root certificates
    let mut root_store = RootCertStore::empty();
    root_store.add_server_trust_anchors(TLS_SERVER_ROOTS.0.iter().map(|ta| {
        rustls::OwnedTrustAnchor::from_subject_spki_name_constraints(
            ta.subject,
            ta.spki,
            ta.name_constraints,
        )
    }));
    
    let config = ClientConfig::builder()
        .with_safe_defaults()
        .with_root_certificates(root_store)
        .with_no_client_auth();
    
    // Create TCP connection
    let socket = match timeout(
        timeout_duration,
        TcpStream::connect(SocketAddr::new(target_ip, port))
    ).await {
        Ok(Ok(socket)) => socket,
        Ok(Err(_)) => return Ok((PortStatus::Closed, None, String::new())),
        Err(_) => return Ok((PortStatus::Filtered, None, String::new())),
    };
    
    // Setup non-blocking
    socket.set_nonblocking(true)?;
    
    // Convert to TLS connection
    let server_name = ServerName::try_from(target_ip.to_string().as_str())
        .unwrap_or_else(|_| ServerName::try_from("example.com").unwrap());
    
    let mut conn = ClientConnection::new(Arc::new(config), server_name)?;
    
    // Perform handshake
    let mut tls_stream = rustls::Stream::new(&mut conn, &mut socket);
    
    // Try to read certificate
    let cert_info = if conn.peer_certificates().is_some() && !conn.peer_certificates().unwrap().is_empty() {
        let cert_der = &conn.peer_certificates().unwrap()[0].0;
        parse_certificate(cert_der)
    } else {
        None
    };
    
    // Get protocol version
    let version = match conn.protocol_version() {
        Some(rustls::ProtocolVersion::TLSv1_3) => "TLSv1.3".to_string(),
        Some(rustls::ProtocolVersion::TLSv1_2) => "TLSv1.2".to_string(),
        Some(rustls::ProtocolVersion::TLSv1_1) => "TLSv1.1".to_string(),
        Some(rustls::ProtocolVersion::TLSv1_0) => "TLSv1.0".to_string(),
        Some(_) => "Unknown TLS version".to_string(),
        None => "".to_string(),
    };
    
    Ok((PortStatus::Open, cert_info, version))
}

/// Parse an X.509 certificate and extract information
fn parse_certificate(cert_der: &[u8]) -> Option<CertificateInfo> {
    match x509_parser::parse_x509_certificate(cert_der) {
        Ok((_, cert)) => {
            // Extract certificate details
            let subject = cert.subject().to_string();
            let issuer = cert.issuer().to_string();
            let not_before = chrono::DateTime::from_utc(
                chrono::NaiveDateTime::from_timestamp_opt(
                    cert.validity().not_before.timestamp(), 0
                ).unwrap_or_default(), 
                chrono::Utc
            );
            let not_after = chrono::DateTime::from_utc(
                chrono::NaiveDateTime::from_timestamp_opt(
                    cert.validity().not_after.timestamp(), 0
                ).unwrap_or_default(), 
                chrono::Utc
            );
            let serial_number = cert.serial_number().to_string();
            let signature_algorithm = cert.signature_algorithm.algorithm.to_string();
            let version = cert.version();
            
            // Calculate fingerprint
            let mut hasher = sha2::Sha256::new();
            hasher.update(cert_der);
            let fingerprint = format!("{:x}", hasher.finalize());
            
            // Extract subject alternative names
            let alt_names = match cert.extensions().iter()
                .find(|ext| ext.oid == oid_registry::OID_X509_EXT_SUBJECT_ALT_NAME) {
                Some(ext) => {
                    match ext.parsed_extension() {
                        ParsedExtension::SubjectAlternativeName(san) => {
                            san.general_names.iter()
                                .map(|name| name.to_string())
                                .collect()
                        },
                        _ => Vec::new(),
                    }
                },
                None => Vec::new(),
            };
            
            // Public key information
            let public_key_bits = match cert.public_key().parsed() {
                Ok(key) => match key {
                    PublicKey::RSA(rsa) => Some(rsa.key_size() as u16),
                    PublicKey::EC(_) => Some(256), // Approximate for common EC keys
                    _ => None,
                },
                Err(_) => None,
            };
            
            let key_algorithm = match cert.public_key().parsed() {
                Ok(key) => match key {
                    PublicKey::RSA(_) => Some("RSA".to_string()),
                    PublicKey::EC(_) => Some("ECC".to_string()),
                    PublicKey::DSA(_) => Some("DSA".to_string()),
                    _ => Some("Unknown".to_string()),
                },
                Err(_) => None,
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
        Err(_) => None,
    }
}

/// UDP scan implementation
pub async fn udp_scan(
    target_ip: IpAddr,
    port: u16,
    local_ip: Option<IpAddr>,
    use_ipv6: bool,
    timeout_duration: Duration,
) -> Result<PortStatus> {
    // Create UDP socket
    let socket = UdpSocket::bind(
        if use_ipv6 { "[::]:0" } else { "0.0.0.0:0" }
    ).await?;
    
    // Connect to target
    let addr = SocketAddr::new(target_ip, port);
    socket.connect(addr).await?;
    
    // Send UDP probe
    let probe = b"probe";
    socket.send(probe).await?;
    
    // Set up reception buffer
    let mut buf = [0u8; 1024];
    
    // Wait for response with timeout
    match timeout(timeout_duration, socket.recv(&mut buf)).await {
        Ok(Ok(_)) => Ok(PortStatus::Open),
        Ok(Err(_)) => Ok(PortStatus::Closed), // Error usually means ICMP unreachable
        Err(_) => Ok(PortStatus::OpenFiltered), // Timeout could mean either open or filtered
    }
}

/// ACK scan implementation
///
/// Sends a TCP ACK packet to detect firewall filtering rules
pub async fn ack_scan(
    target_ip: IpAddr,
    port: u16,
    local_ip: Option<IpAddr>,
    use_ipv6: bool,
    evasion: bool,
    timeout_duration: Duration,
) -> Result<(PortStatus, String)> {
    // Similar to SYN scan, but with ACK flag
    let (mut tx, mut rx) = transport::transport_channel(
        MAX_PACKET_SIZE,
        TransportChannelType::Layer4(TransportProtocol::Ipv4),
    )?;

    // Create a random source port and sequence number for evasion
    let mut rng = thread_rng();
    let source_port = rng.gen_range(49152..65535);
    let seq_num = rng.gen_range(0..u32::MAX);
    
    // Create the TCP packet
    let mut tcp_buffer = [0u8; MAX_PACKET_SIZE];
    let mut tcp_packet = MutableTcpPacket::new(&mut tcp_buffer).unwrap();
    
    // Set TCP header fields
    tcp_packet.set_source(source_port);
    tcp_packet.set_destination(port);
    tcp_packet.set_sequence(seq_num);
    tcp_packet.set_acknowledgement(0);
    tcp_packet.set_data_offset(5);
    tcp_packet.set_flags(TcpFlags::ACK); // ACK flag only
    tcp_packet.set_window(65535);
    tcp_packet.set_urgent_pointer(0);
    
    // Set evasion features if enabled
    if evasion {
        tcp_packet.set_window(rng.gen_range(1024..65535));
    }
    
    // Set checksum (will be calculated by OS)
    tcp_packet.set_checksum(0);
    
    // Set socket destination
    let socket_addr = SocketAddr::new(target_ip, port);
    
    // Send the packet with retries
    for _ in 0..MAX_RETRIES {
        tx.send_to(tcp_packet.to_immutable(), socket_addr)?;
        
        // Listen for response with timeout
        let start = std::time::Instant::now();
        while start.elapsed() < timeout_duration {
            match rx.next() {
                Ok((packet, addr)) => {
                    if addr.ip() != target_ip {
                        continue;
                    }
                    
                    let tcp = TcpPacket::new(packet.payload()).unwrap();
                    
                    if tcp.get_destination() == source_port && tcp.get_source() == port {
                        let flags = tcp.get_flags();
                        
                        // Check for RST response
                        if flags & TcpFlags::RST != 0 {
                            return Ok((PortStatus::Unfiltered, "unfiltered".to_string()));
                        }
                    }
                }
                Err(e) => {
                    error!("Error receiving packet: {}", e);
                    break;
                }
            }
        }
    }
    
    // No response means filtered
    Ok((PortStatus::Filtered, "filtered".to_string()))
}

/// Banner grabbing implementation
///
/// Attempts to connect to an open port and read the initial response
pub async fn banner_grabbing(
    target_ip: IpAddr,
    port: u16,
    timeout_duration: Duration,
) -> Result<String> {
    // Create TCP socket
    let socket = match target_ip {
        IpAddr::V4(_) => TcpSocket::new_v4()?,
        IpAddr::V6(_) => TcpSocket::new_v6()?,
    };
    
    // Set timeout
    socket.set_connect_timeout(Some(timeout_duration))?;
    
    // Connect to target
    let addr = SocketAddr::new(target_ip, port);
    let stream = socket.connect(addr).await?;
    
    // Set read timeout
    stream.set_read_timeout(Some(timeout_duration))?;
    
    // Read initial response
    let mut buffer = [0u8; 2048];
    
    // Try to read with timeout
    match timeout(timeout_duration, stream.read(&mut buffer)).await {
        Ok(Ok(n)) if n > 0 => {
            // Convert to string, replacing non-UTF8 chars
            let banner = String::from_utf8_lossy(&buffer[..n]).to_string();
            Ok(banner)
        },
        _ => {
            // Send a simple HTTP request if no initial data
            if is_likely_http_port(port) {
                let http_request = b"GET / HTTP/1.0\r\nHost: localhost\r\n\r\n";
                stream.write_all(http_request).await?;
                
                match timeout(timeout_duration, stream.read(&mut buffer)).await {
                    Ok(Ok(n)) if n > 0 => {
                        let banner = String::from_utf8_lossy(&buffer[..n]).to_string();
                        Ok(banner)
                    },
                    _ => Ok("".to_string()),
                }
            } else {
                Ok("".to_string())
            }
        }
    }
}

/// Check if a port is likely to be HTTP
fn is_likely_http_port(port: u16) -> bool {
    matches!(port, 80 | 81 | 443 | 8000 | 8080 | 8443 | 8888 | 3000)
}

// Additional scanning techniques would be implemented here 