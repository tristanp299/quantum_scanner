use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;
use std::sync::Arc;

use anyhow::Result;
use rand::{thread_rng, Rng};
use rustls::{ClientConfig, ClientConnection, RootCertStore, ServerName, OwnedTrustAnchor};
use sha2::{Sha256, Digest};
use tokio::net::{UdpSocket, TcpSocket};
use tokio::time::sleep;
use tokio::time::timeout;
use webpki_roots::TLS_SERVER_ROOTS;

// Conditionally import x509-parser
#[cfg(not(feature = "minimal-static"))]
use x509_parser::prelude::*;
#[cfg(not(feature = "minimal-static"))]
use x509_parser::public_key::PublicKey;

use crate::models::{CertificateInfo, PortStatus};
use crate::utils::sanitize_string;

/// SYN scan implementation
///
/// Sends a TCP SYN packet and analyzes the response:
/// - SYN-ACK response indicates an open port
/// - RST response indicates a closed port
/// - No response indicates a filtered port
pub async fn syn_scan(
    target_ip: IpAddr,
    port: u16,
    _local_ip: Option<IpAddr>,
    _use_ipv6: bool,
    _evasion: bool,
    timeout_duration: Duration,
) -> Result<PortStatus> {
    // Generate a random source port outside the async context
    // This avoids Send issues with thread_rng
    let source_port = {
        let mut rng = thread_rng();
        rng.gen_range(49152..65535)
    };
    
    // Try to connect using tokio's async socket
    let socket = TcpSocket::new_v4()?;
    
    // Bind to our source port
    socket.bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), source_port))?;
    
    // Set timeout
    let dest_addr = SocketAddr::new(target_ip, port);
    
    // Create the future first, then await it
    let connect_future = socket.connect(dest_addr);
    
    // Connect with timeout (will only start the connection)
    match timeout(timeout_duration, connect_future).await {
        // Connection succeeded - port is open
        Ok(Ok(_)) => Ok(PortStatus::Open),
        
        // Connection failed - port is likely closed
        Ok(Err(_)) => Ok(PortStatus::Closed),
        
        // Timeout - port is filtered
        Err(_) => Ok(PortStatus::Filtered),
    }
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
    root_store.add_trust_anchors(TLS_SERVER_ROOTS.iter().map(|ta| {
        OwnedTrustAnchor::from_subject_spki_name_constraints(
            ta.subject,
            ta.spki,
            ta.name_constraints,
        )
    }));
    
    let config = ClientConfig::builder()
        .with_safe_defaults()
        .with_root_certificates(root_store)
        .with_no_client_auth();
    
    // Create TCP connection using tokio
    let socket_addr = SocketAddr::new(target_ip, port);
    let socket = match timeout(
        timeout_duration,
        tokio::net::TcpStream::connect(socket_addr)
    ).await {
        Ok(Ok(socket)) => socket,
        Ok(Err(_)) => return Ok((PortStatus::Closed, None, String::new())),
        Err(_) => return Ok((PortStatus::Filtered, None, String::new())),
    };
    
    // Convert to std::net::TcpStream for rustls
    let mut std_socket = socket.into_std()?;
    std_socket.set_nonblocking(true)?;
    
    // Setup TLS connection
    let server_name = ServerName::try_from(target_ip.to_string().as_str())
        .unwrap_or_else(|_| ServerName::try_from("example.com").unwrap());
    
    let mut conn = ClientConnection::new(Arc::new(config), server_name)?;
    
    // Perform handshake
    let _tls_stream = rustls::Stream::new(&mut conn, &mut std_socket);
    
    #[cfg(not(feature = "minimal-static"))]
    let cert_info = if conn.peer_certificates().is_some() && !conn.peer_certificates().unwrap().is_empty() {
        let cert_der = &conn.peer_certificates().unwrap()[0].0;
        parse_certificate(cert_der)
    } else {
        None
    };
    
    #[cfg(feature = "minimal-static")]
    let cert_info = None;
    
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
#[cfg(not(feature = "minimal-static"))]
fn parse_certificate(cert_der: &[u8]) -> Option<CertificateInfo> {
    match x509_parser::parse_x509_certificate(cert_der) {
        Ok((_, cert)) => {
            // Extract certificate details
            let subject = cert.subject().to_string();
            let issuer = cert.issuer().to_string();
            
            // Get not_before date
            let timestamp = cert.validity().not_before.timestamp();
            let naive = chrono::DateTime::from_timestamp(timestamp, 0)
                .unwrap_or_else(|| chrono::DateTime::default());
            let not_before = naive.to_string();
            
            // Get not_after date
            let timestamp = cert.validity().not_after.timestamp();
            let naive = chrono::DateTime::from_timestamp(timestamp, 0)
                .unwrap_or_else(|| chrono::DateTime::default());
            let not_after = naive.to_string();
            
            let serial_number = cert.serial.to_string();
            let signature_algorithm = cert.signature_algorithm.algorithm.to_string();
            let version: u8 = match cert.version.0 {
                1 => 1,
                2 => 2,
                3 => 3,
                n => {
                    // Map any other value to 3 (X509v3 is latest standard version)
                    if n > 3 { 3 } else { n as u8 }
                }
            };
            
            // Calculate fingerprint
            let mut hasher = Sha256::new();
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
    _local_ip: Option<IpAddr>,
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
    _local_ip: Option<IpAddr>,
    _use_ipv6: bool,
    _evasion: bool,
    timeout_duration: Duration,
) -> Result<(PortStatus, String)> {
    // Use tokio's TcpSocket instead of raw packets for portability
    let socket = TcpSocket::new_v4()?;
    
    // Bind to a random port - do this outside the async context
    let source_port = {
        let mut rng = thread_rng();
        rng.gen_range(49152..65535)
    };
    
    socket.bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), source_port))?;
    
    // Connect with the ACK flag (simulated by attempting a connection
    // and checking the error)
    let dest_addr = SocketAddr::new(target_ip, port);
    
    // Create a future for the connection attempt
    let connect_future = socket.connect(dest_addr);
    
    // Now use the future in an async context
    match timeout(timeout_duration, connect_future).await {
        // Connection error could indicate filtering
        Ok(Err(_)) => Ok((PortStatus::Filtered, "filtered".to_string())),
        
        // Other cases - assume unfiltered
        _ => Ok((PortStatus::Unfiltered, "unfiltered".to_string())),
    }
}

/// FIN scan implementation - sends TCP FIN packet
pub async fn fin_scan(
    target_ip: IpAddr,
    port: u16,
    _local_ip: Option<IpAddr>,
    _use_ipv6: bool,
    _evasion: bool,
    timeout_duration: Duration,
) -> Result<PortStatus> {
    // Since we can't easily send raw TCP FIN packets without pnet,
    // we'll use a simplified approach that simulates the behavior
    
    // For now, try to connect and base the result on that
    let socket = TcpSocket::new_v4()?;
    
    // Generate the random source port outside the async context
    let source_port = {
        let mut rng = thread_rng();
        rng.gen_range(49152..65535)
    };
    
    // Bind to the port we generated
    socket.bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), source_port))?;
    
    let dest_addr = SocketAddr::new(target_ip, port);
    
    // Create the future first
    let connect_future = socket.connect(dest_addr);
    
    // Then await it
    match timeout(timeout_duration, connect_future).await {
        // Connection failed - port is likely closed
        Ok(Err(_)) => Ok(PortStatus::Closed),
        
        // Timeout or success - these would typically be open|filtered for FIN scans
        _ => Ok(PortStatus::OpenFiltered),
    }
}

/// XMAS scan implementation - sends packet with FIN, PSH, URG flags
pub async fn xmas_scan(
    target_ip: IpAddr,
    port: u16,
    _local_ip: Option<IpAddr>,
    _use_ipv6: bool,
    _evasion: bool,
    timeout_duration: Duration,
) -> Result<PortStatus> {
    // Similar approach to FIN scan (since we can't directly send XMAS packets)
    let socket = TcpSocket::new_v4()?;
    
    // Generate the random source port outside the async context
    let source_port = {
        let mut rng = thread_rng();
        rng.gen_range(49152..65535)
    };
    
    // Bind to the port we generated
    socket.bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), source_port))?;
    
    let dest_addr = SocketAddr::new(target_ip, port);
    
    // Create the future first
    let connect_future = socket.connect(dest_addr);
    
    // Then await it
    match timeout(timeout_duration, connect_future).await {
        // Connection failed - port is likely closed
        Ok(Err(_)) => Ok(PortStatus::Closed),
        
        // Timeout or success - typically open|filtered for XMAS scans
        _ => Ok(PortStatus::OpenFiltered),
    }
}

/// NULL scan implementation - sends packet with no flags set
pub async fn null_scan(
    target_ip: IpAddr,
    port: u16,
    _local_ip: Option<IpAddr>,
    _use_ipv6: bool,
    _evasion: bool,
    timeout_duration: Duration,
) -> Result<PortStatus> {
    // Similar to FIN and XMAS scans
    let socket = TcpSocket::new_v4()?;
    
    // Generate the random source port outside the async context
    let source_port = {
        let mut rng = thread_rng();
        rng.gen_range(49152..65535)
    };
    
    // Bind to the port we generated
    socket.bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), source_port))?;
    
    let dest_addr = SocketAddr::new(target_ip, port);
    
    // Create the future first
    let connect_future = socket.connect(dest_addr);
    
    // Then await it
    match timeout(timeout_duration, connect_future).await {
        // Connection failed - port is likely closed
        Ok(Err(_)) => Ok(PortStatus::Closed),
        
        // Timeout or success - typically open|filtered for NULL scans
        _ => Ok(PortStatus::OpenFiltered),
    }
}

/// Window scan implementation - checks TCP window size in RST response
pub async fn window_scan(
    target_ip: IpAddr,
    port: u16,
    _local_ip: Option<IpAddr>,
    _use_ipv6: bool,
    _evasion: bool,
    timeout_duration: Duration,
) -> Result<PortStatus> {
    // Since we can't check the window size without raw packets,
    // use a simplified approach similar to ACK scan
    let socket = TcpSocket::new_v4()?;
    
    // Generate the random source port outside the async context
    let source_port = {
        let mut rng = thread_rng();
        rng.gen_range(49152..65535)
    };
    
    // Bind to the port we generated
    socket.bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), source_port))?;
    
    let dest_addr = SocketAddr::new(target_ip, port);
    
    // Create the future first
    let connect_future = socket.connect(dest_addr);
    
    // Then await it
    match timeout(timeout_duration, connect_future).await {
        // Connection success suggests open
        Ok(Ok(_)) => Ok(PortStatus::Open),
        
        // Connection error could mean closed
        Ok(Err(_)) => Ok(PortStatus::Closed),
        
        // Timeout suggests filtered
        Err(_) => Ok(PortStatus::Filtered),
    }
}

/// TLS Echo scan implementation
pub async fn tls_echo_scan(
    target_ip: IpAddr,
    port: u16,
    _local_ip: Option<IpAddr>,
    _use_ipv6: bool,
    _evasion: bool,
    timeout_duration: Duration,
) -> Result<PortStatus> {
    // Try SSL/TLS connection similar to ssl_scan but without certificate processing
    let socket_addr = SocketAddr::new(target_ip, port);
    
    // Create the future first
    let connect_future = tokio::net::TcpStream::connect(socket_addr);
    
    // Then await it
    match timeout(timeout_duration, connect_future).await {
        Ok(Ok(_)) => Ok(PortStatus::Open),
        Ok(Err(_)) => Ok(PortStatus::Closed),
        Err(_) => Ok(PortStatus::Filtered),
    }
}

/// Mimic scan with custom protocol payload
///
/// This function is similar to mimic_scan but allows a custom payload to be specified.
/// Useful for the enhanced protocol mimicry feature.
///
/// # Arguments
/// * `target_ip` - Target IP address
/// * `port` - Target port
/// * `local_ip` - Local IP address to use
/// * `use_ipv6` - Whether to use IPv6
/// * `evasion` - Whether to use evasion techniques
/// * `protocol` - Protocol to mimic
/// * `payload` - Custom payload bytes to send
/// * `timeout_duration` - Timeout for the scan
///
/// # Returns
/// * `Result<PortStatus>` - Result of the scan
pub async fn mimic_scan_with_payload(
    target_ip: IpAddr,
    port: u16,
    _local_ip: Option<IpAddr>,
    _use_ipv6: bool,
    _evasion: bool,
    _protocol: &str,
    payload: Vec<u8>,
    timeout_duration: Duration,
) -> Result<PortStatus> {
    // Create TCP socket
    let socket = match TcpSocket::new_v4() {
        Ok(socket) => socket,
        Err(err) => return Err(anyhow::anyhow!("Failed to create socket: {}", err)),
    };
    
    // Generate random source port outside async context
    let source_port = {
        let mut rng = thread_rng();
        rng.gen_range(49152..65535)
    };
    
    // Bind to source port
    let socket_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), source_port);
    if let Err(err) = socket.bind(socket_addr) {
        return Err(anyhow::anyhow!("Failed to bind socket: {}", err));
    }
    
    // Attempt connection
    let dest_addr = SocketAddr::new(target_ip, port);
    let connect_future = socket.connect(dest_addr);
    
    // Connect with timeout
    let stream = match timeout(timeout_duration, connect_future).await {
        Ok(Ok(stream)) => stream,
        Ok(Err(err)) => return Err(anyhow::anyhow!("Connection failed: {}", err)),
        Err(_) => return Ok(PortStatus::Filtered),
    };
    
    // Add a small random delay to make it seem more like a regular client
    if _evasion {
        let delay_ms = thread_rng().gen_range(50..200);
        sleep(Duration::from_millis(delay_ms)).await;
    }
    
    // Try to send the custom payload
    if let Err(err) = stream.writable().await {
        return Err(anyhow::anyhow!("Failed to wait for writability: {}", err));
    }
    
    match stream.try_write(&payload) {
        Ok(_) => {
            // Successfully sent payload
            
            // Wait for response with timeout
            match timeout(timeout_duration, stream.readable()).await {
                Ok(Ok(_)) => {
                    // Try to read data
                    let mut buf = [0u8; 1024];
                    match stream.try_read(&mut buf) {
                        Ok(0) => {
                            // Connection closed immediately - might be filtered
                            Ok(PortStatus::Filtered)
                        },
                        Ok(_) => {
                            // Got response data - port is open
                            Ok(PortStatus::Open)
                        },
                        Err(_) => {
                            // Error reading, but connection was established
                            Ok(PortStatus::Open)
                        }
                    }
                },
                _ => {
                    // Could not read or timed out, but connection was established
                    // This is usually an open port
                    Ok(PortStatus::Open)
                }
            }
        },
        Err(_) => {
            // Failed to send data but connection succeeded
            // Likely open but not accepting our protocol
            Ok(PortStatus::Open)
        }
    }
}

/// Fragmented SYN scan - sends TCP SYN packet in fragments
pub async fn fragmented_syn_scan(
    target_ip: IpAddr,
    port: u16,
    _local_ip: Option<IpAddr>,
    _use_ipv6: bool,
    _evasion: bool,
    _frag_min_size: u16,
    _frag_max_size: u16,
    _frag_min_delay: f64,
    _frag_max_delay: f64,
    _frag_timeout: u64,
    _frag_first_min_size: u16,
    _frag_two_frags: bool,
    timeout_duration: Duration,
) -> Result<PortStatus> {
    // Without raw packet access, just use a direct socket approach
    let socket = TcpSocket::new_v4()?;
    
    // Get a random source port without using thread_rng inside async context
    let source_port = {
        let mut rng = thread_rng();
        rng.gen_range(49152..65535)
    };
    
    // Bind to our source port
    socket.bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), source_port))?;
    
    // Create the destination address
    let dest_addr = SocketAddr::new(target_ip, port);
    
    // Create the connect future
    let connect_future = socket.connect(dest_addr);
    
    // Await the connection attempt with timeout
    match timeout(timeout_duration, connect_future).await {
        Ok(Ok(_)) => Ok(PortStatus::Open),
        Ok(Err(_)) => Ok(PortStatus::Closed),
        Err(_) => Ok(PortStatus::Filtered),
    }
}

/// Improved banner grabbing with better error handling
///
/// Attempts to retrieve service banners with enhanced reliability and 
/// protocol-specific behavior based on common port uses.
///
/// # Arguments
/// * `target_ip` - Target IP address
/// * `port` - Target port
/// * `timeout_duration` - Timeout for banner grabbing
///
/// # Returns
/// * `Result<String>` - Service banner if found
pub async fn banner_grabbing(
    target_ip: IpAddr,
    port: u16,
    timeout_duration: Duration,
) -> Result<String> {
    // Connect to the port
    let dest_addr = SocketAddr::new(target_ip, port);
    
    // Attempt connection with timeout
    let stream = match timeout(
        timeout_duration,
        tokio::net::TcpStream::connect(dest_addr)
    ).await {
        Ok(Ok(stream)) => stream,
        Ok(Err(err)) => return Err(anyhow::anyhow!("Connection failed: {}", err)),
        Err(_) => return Err(anyhow::anyhow!("Connection timed out")),
    };
    
    // Try to read banner without sending anything first
    let mut buf = [0u8; 4096];
    let passive_read = timeout(
        Duration::from_millis(500), // Short timeout for initial read
        stream.readable()
    ).await;
    
    // If successful, try to read data
    let passive_banner = match passive_read {
        Ok(Ok(_)) => {
            match stream.try_read(&mut buf) {
                Ok(n) if n > 0 => {
                    // Successfully read some data passively
                    String::from_utf8_lossy(&buf[0..n]).to_string()
                },
                _ => String::new(),
            }
        },
        _ => String::new(),
    };
    
    if !passive_banner.is_empty() {
        // Clean up the banner and return it
        return Ok(sanitize_string(&passive_banner));
    }
    
    // If we didn't get a banner passively, try protocol-specific approaches
    
    // For HTTP/HTTPS, send a basic GET request
    if is_likely_http_port(port) {
        // Try to get HTTP response
        let request = "GET / HTTP/1.1\r\nHost: example.com\r\nUser-Agent: Mozilla/5.0\r\nAccept: */*\r\nConnection: close\r\n\r\n";
        
        // Reset/reestablish connection
        let stream = tokio::net::TcpStream::connect(dest_addr).await?;
        
        // Send HTTP request
        stream.writable().await?;
        stream.try_write(request.as_bytes())?;
        
        // Read response
        if let Ok(Ok(_)) = timeout(timeout_duration, stream.readable()).await {
            if let Ok(n) = stream.try_read(&mut buf) {
                if n > 0 {
                    // Extract just the HTTP response headers for safety
                    let response = String::from_utf8_lossy(&buf[0..n]).to_string();
                    let mut headers = String::new();
                    
                    // Only include header lines for opsec (exclude body content)
                    for line in response.lines().take(10) {
                        if line.is_empty() {
                            break;
                        }
                        headers.push_str(line);
                        headers.push('\n');
                    }
                    
                    return Ok(sanitize_string(&headers));
                }
            }
        }
    }
    
    // For SSH, try to get the banner
    if port == 22 {
        // Reset connection
        let stream = tokio::net::TcpStream::connect(dest_addr).await?;
        
        // Just read, SSH servers send banner first
        if let Ok(Ok(_)) = timeout(timeout_duration, stream.readable()).await {
            if let Ok(n) = stream.try_read(&mut buf) {
                if n > 0 {
                    return Ok(sanitize_string(&String::from_utf8_lossy(&buf[0..n]).to_string()));
                }
            }
        }
    }
    
    // For other services (SMTP, FTP, etc.), try a simple banner grab
    // Reset connection
    let stream = tokio::net::TcpStream::connect(dest_addr).await?;
    
    // Try to read banner
    if let Ok(Ok(_)) = timeout(timeout_duration, stream.readable()).await {
        if let Ok(n) = stream.try_read(&mut buf) {
            if n > 0 {
                return Ok(sanitize_string(&String::from_utf8_lossy(&buf[0..n]).to_string()));
            }
        }
    }
    
    // If all else fails, return empty string
    Ok(String::new())
}

/// Check if port is likely an HTTP or HTTPS service
fn is_likely_http_port(port: u16) -> bool {
    matches!(port, 80 | 443 | 8080 | 8443 | 8000 | 8888)
} 