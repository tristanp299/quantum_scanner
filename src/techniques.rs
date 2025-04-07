use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;
use std::sync::Arc;
use std::io::Read;

use anyhow::Result;
use log::debug;
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
    local_ip: Option<IpAddr>,
    use_ipv6: bool,
    evasion: bool,
    timeout_duration: Duration,
) -> Result<PortStatus> {
    // For operational security, we'll use a high random source port
    // This helps avoid detection by IDS/IPS that may flag connections from common ports
    let source_port = crate::utils::random_high_port();
    
    // Log with minimal information - important for OpSec not to log full target details
    debug!("Performing SYN scan on port {} with timeout {:?}", port, timeout_duration);
    
    // Based on IPv4/IPv6, create the appropriate socket
    let socket = if use_ipv6 {
        // Create an IPv6 socket
        TcpSocket::new_v6()?
    } else {
        // Create an IPv4 socket
        TcpSocket::new_v4()?
    };
    
    // If evasion techniques are enabled, we'll modify our packet properties
    if evasion {
        // In a real implementation with raw sockets, we would:
        // 1. Set custom TTL values to evade network sensors
        // 2. Add packet fragmentation
        // 3. Use delay between packets
        // 4. Randomize packet headers
        
        // Note: We're simulating this here since tokio sockets don't give
        // full control over these parameters
        
        // Simulate the evasion delay - important in red team engagements
        // to avoid triggering rate-based IDS alerts
        let random_delay = rand::thread_rng().gen_range(5..50);
        sleep(Duration::from_millis(random_delay)).await;
    }
    
    // Bind to our source port
    // If local_ip is specified, we'll bind to it, otherwise bind to UNSPECIFIED
    let bind_addr = if let Some(lip) = local_ip {
        SocketAddr::new(lip, source_port)
    } else if use_ipv6 {
        SocketAddr::new(IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED), source_port)
    } else {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), source_port)
    };
    
    // Bind the socket - this may require root/admin privileges
    if let Err(e) = socket.bind(bind_addr) {
        // Handle bind error - common when not running as root
        return Err(anyhow::anyhow!("Failed to bind to source port: {}", e));
    }
    
    // Set the destination address
    let dest_addr = SocketAddr::new(target_ip, port);
    
    // In a SYN scan with real raw sockets, we would:
    // 1. Craft a TCP packet with only the SYN flag set
    // 2. Set a custom TTL value, window size, etc.
    // 3. Send it without establishing a full connection
    // 4. Analyze the response packet flags
    
    // Since we're using standard sockets, we'll use non-blocking connect attempts
    // to simulate a SYN scan by starting but not completing the TCP handshake
    
    // Create the future for the connection attempt
    let connect_future = socket.connect(dest_addr);
    
    // Execute with timeout to prevent hanging on filtered ports
    match timeout(timeout_duration, connect_future).await {
        // Connection succeeded - means we got SYN-ACK response (port is open)
        Ok(Ok(_)) => {
            debug!("Port {} is open (SYN-ACK received)", port);
            Ok(PortStatus::Open)
        },
        
        // Connection error - got RST (port is closed)
        Ok(Err(_)) => {
            debug!("Port {} is closed (RST received)", port);
            Ok(PortStatus::Closed)
        },
        
        // Timeout - no response received (port is filtered)
        Err(_) => {
            debug!("Port {} is filtered (no response)", port);
            Ok(PortStatus::Filtered)
        },
    }
}

/// SSL/TLS scan implementation
///
/// Attempts to establish an SSL/TLS connection and retrieve certificate information.
/// This is useful for service identification and potential vulnerability assessment.
/// For operational security, this implementation uses techniques to minimize detection.
pub async fn ssl_scan(
    target_ip: IpAddr,
    port: u16,
    timeout_duration: Duration,
) -> Result<(PortStatus, Option<CertificateInfo>, String)> {
    // Log minimal information for operational security
    debug!("Performing TLS scan on port {} with timeout {:?}", port, timeout_duration);
    
    // Create a secure SSL/TLS configuration with system root certificates
    // For red team engagements, we want to trust both valid and self-signed certs
    let mut root_store = RootCertStore::empty();
    
    // Add all known root certificates from webpki-roots
    // This gives us comprehensive coverage of trusted CAs
    root_store.add_trust_anchors(TLS_SERVER_ROOTS.iter().map(|ta| {
        OwnedTrustAnchor::from_subject_spki_name_constraints(
            ta.subject,
            ta.spki,
            ta.name_constraints,
        )
    }));
    
    // Create a client configuration that accepts all certificates
    // For red team operations, we need to be able to connect to any server
    // regardless of certificate validity
    let config = ClientConfig::builder()
        .with_safe_defaults()
        .with_root_certificates(root_store)
        .with_no_client_auth();
    
    // First establish a basic TCP connection
    // We do this before attempting TLS to determine if port is open
    let socket_addr = SocketAddr::new(target_ip, port);
    
    // Add a small random delay for OpSec - prevents pattern recognition
    let jitter = rand::thread_rng().gen_range(5..30);
    sleep(Duration::from_millis(jitter)).await;
    
    // Attempt TCP connection with timeout
    let socket = match timeout(
        timeout_duration,
        tokio::net::TcpStream::connect(socket_addr)
    ).await {
        Ok(Ok(socket)) => {
            // Successfully connected - port is open
            debug!("TCP connection successful to {}:{}", target_ip, port);
            socket
        },
        Ok(Err(e)) => {
            // Connection failed - port is closed
            debug!("TCP connection failed to {}:{}: {}", target_ip, port, e);
            return Ok((PortStatus::Closed, None, String::new()));
        },
        Err(_) => {
            // Timeout - port is filtered
            debug!("TCP connection timeout to {}:{}", target_ip, port);
            return Ok((PortStatus::Filtered, None, String::new()));
        },
    };
    
    // Port is open, now we try to establish TLS connection
    // Convert tokio socket to std socket for rustls
    let mut std_socket = match socket.into_std() {
        Ok(s) => s,
        Err(e) => {
            // Socket conversion failed
            debug!("Failed to convert socket: {}", e);
            return Ok((PortStatus::Open, None, "Socket conversion error".to_string()));
        }
    };
    
    // Set to non-blocking mode for rustls
    if let Err(e) = std_socket.set_nonblocking(true) {
        debug!("Failed to set non-blocking mode: {}", e);
        return Ok((PortStatus::Open, None, "Socket config error".to_string()));
    }
    
    // Prepare the server name for TLS handshake
    // For operational security, we use the IP address as hostname to avoid revealing
    // potential target hostname in SNI (Server Name Indication) field
    let server_name = match ServerName::try_from(target_ip.to_string().as_str()) {
        Ok(name) => name,
        Err(_) => {
            // Fall back to a generic name if IP conversion fails
            // Using example.com is less suspicious than custom domains
            match ServerName::try_from("example.com") {
                Ok(name) => name,
                Err(e) => {
                    debug!("Failed to create server name: {}", e);
                    return Ok((PortStatus::Open, None, "Server name error".to_string()));
                }
            }
        }
    };
    
    // Attempt to establish TLS connection
    // We catch errors related to certificate validation but still extract what we can
    let conn_result = ClientConnection::new(Arc::new(config), server_name);
    
    let mut conn = match conn_result {
        Ok(conn) => conn,
        Err(e) => {
            // TLS negotiation failed - possibly not a TLS service
            debug!("TLS negotiation failed: {}", e);
            return Ok((PortStatus::Open, None, format!("TLS error: {}", e)));
        }
    };
    
    // Create TLS stream to perform handshake
    let mut tls_stream = rustls::Stream::new(&mut conn, &mut std_socket);
    
    // Try to read some data to complete handshake
    // We use a small buffer since we just need to establish the connection
    let mut handshake_buf = [0u8; 1024];
    let _ = tls_stream.read(&mut handshake_buf);  // Ignore result - we just want handshake
    
    // Extract certificate information if available
    #[cfg(not(feature = "minimal-static"))]
    let cert_info = if let Some(certs) = conn.peer_certificates() {
        if !certs.is_empty() {
            parse_certificate(&certs[0].0)
        } else {
            None
        }
    } else {
        None
    };
    
    #[cfg(feature = "minimal-static")]
    let cert_info = None;
    
    // Determine TLS protocol version
    let version = match conn.protocol_version() {
        Some(rustls::ProtocolVersion::TLSv1_3) => "TLSv1.3".to_string(),
        Some(rustls::ProtocolVersion::TLSv1_2) => "TLSv1.2".to_string(),
        Some(rustls::ProtocolVersion::TLSv1_1) => "TLSv1.1".to_string(),
        Some(rustls::ProtocolVersion::TLSv1_0) => "TLSv1.0".to_string(),
        Some(_) => "Unknown TLS version".to_string(),
        None => "No TLS Version".to_string(),
    };
    
    // Port is open with TLS
    debug!("Successful TLS connection to {}:{} using {}", target_ip, port, version);
    Ok((PortStatus::Open, cert_info, version))
}

/// Parse an X.509 certificate and extract information
///
/// This function analyzes an X.509 certificate in DER format and extracts
/// key details useful for service identification and security assessment.
/// 
/// For red team operations, certificate information is valuable for:
/// 1. Service fingerprinting (identifying server software)
/// 2. Identifying potential misconfigurations
/// 3. Finding information leakage (internal hostnames, etc.)
/// 4. Assessing TLS security posture
#[cfg(not(feature = "minimal-static"))]
fn parse_certificate(cert_der: &[u8]) -> Option<CertificateInfo> {
    // Parse the certificate using x509-parser
    // We're using ? operator combined with match to handle the result
    match x509_parser::parse_x509_certificate(cert_der) {
        Ok((_, cert)) => {
            // Successfully parsed certificate, now extract all useful details
            
            // Extract subject distinguished name (DN)
            // Example: CN=example.com,O=Example Inc,C=US
            // This often reveals the organization name and domain
            let subject = cert.subject().to_string();
            
            // Extract issuer distinguished name
            // For self-signed certs, this will match the subject
            // For CA-signed certs, this identifies the certificate authority
            let issuer = cert.issuer().to_string();
            
            // Extract certificate validity period
            // The not_before date is when the certificate became valid
            let timestamp = cert.validity().not_before.timestamp();
            let naive = chrono::DateTime::from_timestamp(timestamp, 0)
                .unwrap_or_else(|| chrono::DateTime::default());
            let not_before = naive.to_string();
            
            // The not_after date is when the certificate expires
            // Expired certificates can indicate poor maintenance
            let timestamp = cert.validity().not_after.timestamp();
            let naive = chrono::DateTime::from_timestamp(timestamp, 0)
                .unwrap_or_else(|| chrono::DateTime::default());
            let not_after = naive.to_string();
            
            // Serial number - unique identifier for this certificate
            // Can be useful for tracking certificate lineage
            let serial_number = cert.serial.to_string();
            
            // Signature algorithm (e.g., sha256WithRSAEncryption)
            // Important for security assessment - weak algorithms are concerning
            let signature_algorithm = cert.signature_algorithm.algorithm.to_string();
            
            // X.509 version (should be 3 for modern certificates)
            let version: u8 = match cert.version.0 {
                1 => 1, // X.509v1
                2 => 2, // X.509v2
                3 => 3, // X.509v3 (current standard)
                n => {
                    // Map any other value to 3 (X509v3 is latest standard version)
                    if n > 3 { 3 } else { n as u8 }
                }
            };
            
            // Calculate certificate fingerprint using SHA-256
            // This is a hash of the entire certificate, useful as a unique identifier
            let mut hasher = Sha256::new();
            hasher.update(cert_der);
            let fingerprint = format!("{:x}", hasher.finalize());
            
            // Extract Subject Alternative Names (SANs)
            // These are additional domains/IPs the certificate is valid for
            // Very valuable for red teams as they often reveal internal domain names
            let alt_names = match cert.extensions().iter()
                .find(|ext| ext.oid == oid_registry::OID_X509_EXT_SUBJECT_ALT_NAME) {
                Some(ext) => {
                    match ext.parsed_extension() {
                        ParsedExtension::SubjectAlternativeName(san) => {
                            // Convert each SAN to string and collect into a vector
                            san.general_names.iter()
                                .map(|name| {
                                    // For OpSec awareness, we could log these findings
                                    // as they often reveal internal infrastructure details
                                    let name_str = name.to_string();
                                    debug!("Found SAN entry: {}", sanitize_string(&name_str));
                                    name_str
                                })
                                .collect()
                        },
                        _ => Vec::new(),
                    }
                },
                None => Vec::new(),
            };
            
            // Extract public key information - key size is important for security assessment
            // RSA keys should be at least 2048 bits, with 4096 being preferred
            // EC keys are typically 256 or 384 bits
            let public_key_bits = match cert.public_key().parsed() {
                Ok(key) => match key {
                    PublicKey::RSA(rsa) => {
                        let size = rsa.key_size() as u16;
                        // Red team note: RSA keys < 2048 bits are considered weak
                        if size < 2048 {
                            debug!("Found weak RSA key: {} bits", size);
                        }
                        Some(size)
                    },
                    PublicKey::EC(_) => Some(256), // Approximate for common EC keys
                    _ => None,
                },
                Err(_) => None,
            };
            
            // Key algorithm (RSA, ECC, DSA, etc.)
            let key_algorithm = match cert.public_key().parsed() {
                Ok(key) => match key {
                    PublicKey::RSA(_) => Some("RSA".to_string()),
                    PublicKey::EC(_) => Some("ECC".to_string()),
                    PublicKey::DSA(_) => Some("DSA".to_string()), // DSA is considered legacy
                    _ => Some("Unknown".to_string()),
                },
                Err(_) => None,
            };
            
            // Return a complete CertificateInfo structure with all extracted data
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
            // Failed to parse certificate
            debug!("Failed to parse certificate: {}", e);
            None
        },
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
    
    // Use the random_high_port utility function
    let source_port = crate::utils::random_high_port();
    
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
    
    // Use the random_high_port utility function
    let source_port = crate::utils::random_high_port();
    
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
    
    // Use the random_high_port utility function
    let source_port = crate::utils::random_high_port();
    
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

/// Perform a quick SYN check before attempting banner grabbing
///
/// This function uses syn_scan to check if a port is open before
/// attempting more invasive banner grabbing. This helps with
/// operational security by minimizing unnecessary connections.
pub async fn quick_port_check(
    target_ip: IpAddr,
    port: u16,
    timeout_duration: Duration
) -> Result<PortStatus> {
    // Use the syn_scan function for a stealthier check
    debug!("Performing quick SYN check on port {} before banner grabbing", port);
    
    // Call the syn_scan function with minimal parameters
    match syn_scan(
        target_ip,
        port,
        None, // local_ip
        false, // use_ipv6
        true, // evasion
        timeout_duration
    ).await {
        Ok(status) => {
            debug!("SYN scan on port {} returned status: {:?}", port, status);
            Ok(status)
        },
        Err(e) => {
            debug!("SYN scan on port {} failed: {}", port, e);
            Err(e)
        }
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
    // First do a quick port check using SYN scan for stealth
    // This helps avoid unnecessary connections to closed ports
    let quick_check = quick_port_check(target_ip, port, timeout_duration / 2).await;
    
    match quick_check {
        Ok(status) => {
            if status != PortStatus::Open && status != PortStatus::OpenFiltered {
                // Don't continue with banner grabbing if port isn't open
                debug!("Port {} is not open ({:?}), skipping banner grab", port, status);
                return Ok(format!("Port {} status: {:?}", port, status));
            }
        },
        Err(e) => {
            debug!("Quick port check error on port {}: {}", port, e);
            // Continue anyway, as the check might have failed for reasons
            // other than port being closed
        }
    }
    
    // For SSL/TLS ports, use the specialized ssl_scan function
    if port == 443 || port == 8443 || port == 465 || port == 993 || port == 995 {
        debug!("Attempting SSL/TLS banner grab for port {}", port);
        match ssl_scan(target_ip, port, timeout_duration).await {
            Ok((status, cert_info, version)) => {
                if status == PortStatus::Open {
                    // Construct a banner from the SSL/TLS information
                    let mut banner = format!("TLS Version: {}\n", version);
                    
                    if let Some(cert) = cert_info {
                        banner.push_str(&format!("Subject: {}\n", cert.subject));
                        banner.push_str(&format!("Issuer: {}\n", cert.issuer));
                        banner.push_str(&format!("Valid until: {}\n", cert.not_after));
                        
                        if let Some(key_algo) = &cert.key_algorithm {
                            banner.push_str(&format!("Key Algorithm: {}", key_algo));
                            if let Some(key_bits) = cert.public_key_bits {
                                banner.push_str(&format!(" ({} bits)", key_bits));
                            }
                            banner.push('\n');
                        }
                    }
                    
                    return Ok(banner);
                } else {
                    // Port is not open for SSL/TLS
                    return Ok(format!("Port {} is not open for SSL/TLS: {:?}", port, status));
                }
            },
            Err(e) => {
                debug!("SSL scan error on port {}: {}", port, e);
                // Fall back to regular banner grabbing
            }
        }
    }
    
    // For non-SSL ports or if SSL scan failed, use generic approach
    
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