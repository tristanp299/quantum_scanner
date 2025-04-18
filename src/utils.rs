use std::net::{IpAddr, Ipv4Addr, Ipv6Addr/*, SocketAddr*/};
use std::time::{Duration, Instant};
use chrono::{Utc};
// use std::fs::{/*File,*/ OpenOptions};
// use std::io::{/*Read,*/ Write, Seek, SeekFrom};
// use std::path::PathBuf;

use log::{debug, warn, info};
// use pnet::datalink;
use rand::{Rng, thread_rng, distributions::{Distribution, Uniform}};
use rand::seq::SliceRandom;
use regex;

// Network packet imports for ICMP
use pnet::transport::{transport_channel, TransportChannelType, TransportProtocol};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::icmp::{IcmpTypes, IcmpCode, MutableIcmpPacket};
use pnet::packet::icmpv6::{Icmpv6Types, Icmpv6Code, MutableIcmpv6Packet};
use pnet::packet::Packet;

use anyhow::{Result, anyhow};

/// Finds a suitable non-loopback IPv4 address for the default interface.
///
/// This is crucial for raw socket scans which require a specific source IP.
/// It prioritizes non-loopback, non-link-local, non-multicast IPv4 addresses.
///
/// # Returns
/// * `Result<Ipv4Addr, anyhow::Error>` - The preferred IPv4 address or an error if none found.
///
/// # Opsec Considerations
/// - Binding to the correct source IP is important for scans to work and potentially
///   for evasion (appearing to originate from the expected interface).
pub fn find_local_ipv4() -> Result<Ipv4Addr> {
    // Get all network interfaces
    let interfaces = pnet_datalink::interfaces();

    // Find the first suitable non-loopback IPv4 address
    for interface in &interfaces {
        // Skip loopback, down, or non-running interfaces
        if interface.is_loopback() || !interface.is_up() || !interface.is_running() {
            continue;
        }

        for ip_network in &interface.ips {
            if let IpAddr::V4(ipv4) = ip_network.ip() {
                // Check if it's a usable address (not loopback, link-local, multicast, etc.)
                if !ipv4.is_loopback() && !ipv4.is_link_local() && !ipv4.is_multicast() && !ipv4.is_documentation() && !ipv4.is_unspecified() {
                    debug!("Found suitable local IPv4 address: {} on interface {}", ipv4, interface.name);
                    return Ok(ipv4);
                }
            }
        }
    }

    // If no suitable interface found after checking all, return an error.
    warn!("No suitable non-loopback local IPv4 address found.");
    Err(anyhow!("Could not automatically determine a suitable local IPv4 address for raw socket operations."))
}

/// Finds a suitable non-loopback, non-link-local IPv6 address for the default interface.
///
/// This is crucial for raw socket scans which require a specific source IP.
/// It prioritizes global unicast IPv6 addresses.
///
/// # Returns
/// * `Result<Ipv6Addr, anyhow::Error>` - The preferred IPv6 address or an error if none found.
///
/// # Opsec Considerations
/// - Binding to the correct source IP is important for scans to work and potentially
///   for evasion (appearing to originate from the expected interface).
/// - Using temporary or privacy addresses might be preferred for stealth, but this
///   function currently prioritizes stable global unicast addresses for simplicity.
pub fn find_local_ipv6() -> Result<Ipv6Addr> {
    // Get all network interfaces
    let interfaces = pnet_datalink::interfaces();

    // Find the first suitable non-loopback IPv6 address
    for interface in &interfaces {
        // Skip loopback, down, or non-running interfaces
        if interface.is_loopback() || !interface.is_up() || !interface.is_running() {
            continue;
        }

        for ip_network in &interface.ips {
            if let IpAddr::V6(ipv6) = ip_network.ip() {
                // Check if it's a usable global unicast address
                // (not loopback, link-local, unique local, unspecified, multicast, documentation)
                if !ipv6.is_loopback()
                    && !ipv6.is_unspecified()
                    && !ipv6.is_multicast()
                    && !is_link_local_ipv6(&ipv6) // Check manually as pnet IpNetwork might not expose it easily
                    && !is_unique_local_ipv6(&ipv6)
                    && !is_documentation_ipv6(&ipv6)
                    && is_global_unicast_ipv6(&ipv6) // Prefer global addresses
                {
                    debug!("Found suitable local IPv6 address: {} on interface {}", ipv6, interface.name);
                    return Ok(ipv6);
                }
            }
        }
    }

    // If no suitable interface found after checking all, return an error.
    warn!("No suitable non-loopback global unicast local IPv6 address found.");
    Err(anyhow!("Could not automatically determine a suitable local IPv6 address for raw socket operations."))
}

// Helper functions for IPv6 address classification (std::net::Ipv6Addr doesn't have all helpers)

/// Check if an IPv6 address is link-local (fe80::/10).
fn is_link_local_ipv6(ip: &Ipv6Addr) -> bool {
    (ip.segments()[0] & 0xffc0) == 0xfe80
}

/// Check if an IPv6 address is unique local (fc00::/7).
fn is_unique_local_ipv6(ip: &Ipv6Addr) -> bool {
    (ip.segments()[0] & 0xfe00) == 0xfc00
}

/// Check if an IPv6 address is documentation (2001:db8::/32).
fn is_documentation_ipv6(ip: &Ipv6Addr) -> bool {
    ip.segments()[0] == 0x2001 && ip.segments()[1] == 0x0db8
}

/// Check if an IPv6 address is global unicast.
/// This is a simplified check: not loopback, multicast, link-local, unique-local, unspecified, documentation.
fn is_global_unicast_ipv6(ip: &Ipv6Addr) -> bool {
    !ip.is_loopback()
        && !ip.is_multicast()
        && !ip.is_unspecified()
        && !is_link_local_ipv6(ip)
        && !is_unique_local_ipv6(ip)
        && !is_documentation_ipv6(ip)
}

/// Get the default interface's IPv4 address (Kept for reference, use find_local_ipv4 for raw sockets)
///
/// This function attempts to find a suitable IPv4 address for the default network interface.
/// It prioritizes non-loopback interfaces with global addresses.
///
/// # Returns
/// * `Option<IpAddr>` - The IPv4 address if found, otherwise None
pub fn get_default_interface_ipv4() -> Option<IpAddr> {
    // Get all network interfaces
    let interfaces = pnet_datalink::interfaces();
    
    // First, try to find a non-loopback interface with an IPv4 address
    for interface in &interfaces {
        // Skip loopback interfaces
        if interface.is_loopback() {
            continue;
        }
        
        // Find the first IPv4 address
        for ip in &interface.ips {
            if let IpAddr::V4(ipv4) = ip.ip() {
                if !ipv4.is_loopback() && !ipv4.is_link_local() && !ipv4.is_multicast() {
                    debug!("Found IPv4 address: {} on interface {}", ipv4, interface.name);
                    return Some(IpAddr::V4(ipv4));
                }
            }
        }
    }
    
    // If no suitable interface found, try to use a dummy address
    // This is better than nothing for many scan operations
    warn!("No suitable IPv4 interface found, using fallback 127.0.0.1 (Warning: May not work for all scans)");
    Some(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)))
}

/// Get the default interface's IPv6 address
/// 
/// This function attempts to find a suitable IPv6 address for the default network interface.
/// It prioritizes non-loopback interfaces with global addresses.
///
/// # Returns
/// * `Option<IpAddr>` - The IPv6 address if found, otherwise None
pub fn get_default_interface_ipv6() -> Option<IpAddr> {
    // Get all network interfaces
    let interfaces = pnet_datalink::interfaces();
    
    // First, try to find a non-loopback interface with an IPv6 address
    for interface in &interfaces {
        // Skip loopback interfaces
        if interface.is_loopback() {
            continue;
        }
        
        // Find the first IPv6 address
        for ip in &interface.ips {
            if let IpAddr::V6(ipv6) = ip.ip() {
                if !ipv6.is_loopback() && !ipv6.is_multicast() && !ipv6.is_unspecified() {
                    debug!("Found IPv6 address: {} on interface {}", ipv6, interface.name);
                    return Some(IpAddr::V6(ipv6));
                }
            }
        }
    }
    
    // If no suitable interface found, try to use a dummy address
    // WARNING: This fallback is NOT suitable for raw socket source IP binding.
    warn!("No suitable IPv6 interface found, using fallback ::1 (Warning: May not work for all scans)");
    Some(IpAddr::V6(Ipv6Addr::LOCALHOST))
}

/// Generate a random source port for TCP/UDP packets
///
/// This generates a port in the ephemeral port range (49152-65535)
/// which is less likely to conflict with well-known services.
#[allow(dead_code)]
pub fn random_high_port() -> u16 {
    thread_rng().gen_range(49152..65535)
}

/// Generate a random IP ID field value
///
/// Used for IP packet identification to maintain uniqueness.
#[allow(dead_code)]
pub fn random_ip_id() -> u16 {
    thread_rng().gen_range(1..65535)
}

/// Generate a random TCP sequence number
///
/// Used to make packets more difficult to identify as
/// coming from a scanner.
#[allow(dead_code)]
pub fn random_tcp_seq() -> u32 {
    thread_rng().gen::<u32>()
}

/// Get a randomized TTL value for evading signature detection
///
/// When evasion is enabled, this will generate a TTL based on common
/// operating system profiles to help blend in with normal traffic patterns.
/// Returns a randomized TTL value within a realistic range.
///
/// # Arguments
/// * `evasion` - Whether evasion techniques should be used
/// * `os_profile` - Optional OS profile to mimic (windows, linux, macos)
///
/// # Returns
/// * `u8` - A TTL value that mimics normal OS behavior
pub fn get_ttl(evasion: bool, os_profile: Option<&str>) -> u8 {
    if !evasion {
        return 64; // Default TTL
    }
    
    // TTL values based on common OS profiles
    match os_profile {
        Some("windows") => {
            // Windows typically uses TTL 128
            // Add some randomization to avoid perfect fingerprinting
            let dist = Uniform::new_inclusive(126, 130);
            dist.sample(&mut thread_rng())
        },
        Some("linux") => {
            // Linux typically uses TTL 64
            // Add some randomization to avoid perfect fingerprinting
            let dist = Uniform::new_inclusive(63, 66);
            dist.sample(&mut thread_rng())
        },
        Some("macos") => {
            // macOS typically uses TTL 64
            // Add some randomization to avoid perfect fingerprinting
            let dist = Uniform::new_inclusive(63, 66);
            dist.sample(&mut thread_rng())
        },
        _ => {
            // Randomly choose one of the common TTL values to avoid
            // easy fingerprinting of our scanner
            *[64, 128, 255].choose(&mut thread_rng()).unwrap()
        }
    }
}

/// Calculate an exponential backoff delay for retries
///
/// This increases the delay between retries to avoid overwhelming
/// the target system or network.
///
/// # Arguments
/// * `retry` - The current retry number (0-based)
/// * `base_ms` - The base delay in milliseconds
/// * `max_ms` - The maximum delay in milliseconds
///
/// # Returns
/// * `Duration` - The delay to wait before the next retry
#[allow(dead_code)]
pub fn backoff_delay(retry: usize, base_ms: u64, max_ms: u64) -> Duration {
    let delay_ms = (base_ms * 2u64.pow(retry as u32)).min(max_ms);
    Duration::from_millis(delay_ms)
}

/// Generate a random User-Agent string for mimicking browser traffic
///
/// Used when performing application-level scans to blend in with
/// normal HTTP traffic patterns and avoid obvious scanner signatures.
///
/// # Arguments
/// * `browser_type` - Optional browser to mimic
///
/// # Returns
/// * `String` - A realistic user agent string
#[allow(dead_code)]
pub fn get_random_user_agent(browser_type: Option<&str>) -> String {
    let mut rng = thread_rng();
    
    // Common modern browser User-Agents
    let all_agents = [
        // Chrome agents
        ("chrome", [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/90.0.4430.212 Safari/537.36",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.107 Safari/537.36"
        ]),
        // Firefox agents
        ("firefox", [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:88.0) Gecko/20100101 Firefox/88.0",
            "Mozilla/5.0 (X11; Linux i686; rv:90.0) Gecko/20100101 Firefox/90.0"
        ]),
        // Safari agents
        ("safari", [
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15",
            "Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0 Mobile/15E148 Safari/604.1",
            "Mozilla/5.0 (iPad; CPU OS 14_7_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.2 Mobile/15E148 Safari/604.1"
        ]),
        // Edge agents
        ("edge", [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36 Edg/91.0.864.59",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.107 Safari/537.36 Edg/92.0.902.55",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.107 Safari/537.36 Edg/92.0.902.55"
        ])
    ];
    
    // Select browser based on requested type or random
    match browser_type {
        Some(browser) => {
            // Find the matching browser group
            for (browser_name, agents) in all_agents.iter() {
                if browser.to_lowercase() == *browser_name {
                    return agents[rng.gen_range(0..agents.len())].to_string();
                }
            }
            // Fallback to random if browser type not found
            let (_, agents) = all_agents.choose(&mut rng).unwrap();
            agents[rng.gen_range(0..agents.len())].to_string()
        },
        None => {
            // Select a random browser type
            let (_, agents) = all_agents.choose(&mut rng).unwrap();
            agents[rng.gen_range(0..agents.len())].to_string()
        }
    }
}

/// Advanced TTL jittering for enhanced evasion
/// 
/// Creates non-deterministic TTL values that vary within a specific OS range
/// but change slightly for each packet to avoid detection based on TTL patterns
/// 
/// # Arguments
/// * `os_profile` - The OS to mimic ("windows", "linux", "macos", "cisco", or "random")
/// * `jitter_amount` - How much to randomize the TTL (1-5)
/// 
/// # Returns
/// * `u8` - Randomized TTL value that looks like the target OS but with variance
pub fn get_advanced_ttl(os_profile: &str, jitter_amount: u8) -> u8 {
    // Base TTL values for common operating systems
    let base_ttl: u8 = match os_profile.to_lowercase().as_str() {
        "windows" => 128,
        "linux" => 64,
        "macos" => 64,
        "cisco" => 255,
        "random" => {
            // Randomly pick one of the common TTL values
            let bases = [64u8, 128u8, 255u8];
            *bases.choose(&mut thread_rng()).unwrap()
        },
        _ => 64, // Default to Linux-like
    };
    
    // Limit jitter to reasonable values (1-5)
    let jitter = jitter_amount.min(5).max(1);
    
    // Apply random jitter while keeping TTL within reasonable range for the OS
    // This is important for making the packet seem normal but not exactly predictable
    match base_ttl {
        64 => {
            // For Linux/macOS (typically 64)
            let variance = thread_rng().gen_range(0..=jitter);
            if thread_rng().gen_bool(0.7) {
                // Usually decrement because most Linux TTLs arrive lower than 64
                base_ttl.saturating_sub(variance)
            } else {
                // Sometimes increment to appear like a router might have
                base_ttl.saturating_add(variance)
            }
        },
        128 => {
            // For Windows (typically 128)
            let variance = thread_rng().gen_range(0..=jitter);
            if thread_rng().gen_bool(0.6) {
                // Windows packets often arrive with TTL 127-128
                base_ttl.saturating_sub(variance)
            } else {
                // Sometimes slightly higher to mimic certain configs
                base_ttl.saturating_add(variance)
            }
        },
        255 => {
            // For network devices (typically 255)
            // Cisco/network devices almost always have lower TTL than 255 when they arrive
            let variance = thread_rng().gen_range(2..=(jitter + 2));
            base_ttl.saturating_sub(variance)
        },
        _ => {
            // For any other base TTL
            let variance = thread_rng().gen_range(0..=jitter);
            if thread_rng().gen_bool(0.5) {
                base_ttl.saturating_sub(variance)
            } else {
                base_ttl.saturating_add(variance)
            }
        }
    }
}

/// Generate advanced protocol mimicry payloads that match realistic application behavior
///
/// Creates payloads that more closely resemble actual client traffic for various protocols.
/// These include version-specific behavior, headers and flags matching common implementations.
///
/// # Arguments
/// * `protocol` - The protocol to mimic (e.g., "HTTP", "SSH", "TLS")
/// * `variant` - Optional variant/version of the protocol to mimic
///
/// # Returns
/// * `Vec<u8>` - Byte vector containing the mimicked payload
pub fn generate_advanced_mimicry(protocol: &str, variant: Option<&str>) -> Vec<u8> {
    match protocol.to_uppercase().as_str() {
        "HTTP" => {
            // Model HTTP client requests after common browsers
            let user_agent = match variant {
                Some("firefox") => "Mozilla/5.0 (X11; Linux x86_64; rv:96.0) Gecko/20100101 Firefox/96.0",
                Some("chrome") => "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/94.0.4606.81 Safari/537.36",
                Some("safari") => "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.0 Safari/605.1.15",
                Some(v) if v == "1.0" || v == "1.1" || v == "2.0" => {
                    // HTTP version-specific UA
                    "Mozilla/5.0 (compatible; QuickCheck/1.0)"
                },
                _ => {
                    // Random common browser
                    let user_agents = [
                        "Mozilla/5.0 (X11; Linux x86_64; rv:96.0) Gecko/20100101 Firefox/96.0",
                        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/94.0.4606.81 Safari/537.36",
                        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/95.0.4638.69 Safari/537.36",
                        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:94.0) Gecko/20100101 Firefox/94.0",
                        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.0 Safari/605.1.15",
                    ];
                    user_agents[thread_rng().gen_range(0..user_agents.len())]
                }
            };
            
            // Build a realistic HTTP request with headers commonly seen in browsers
            // Including things like Accept, Accept-Language helps bypass DPI
            let mut request = format!(
                "GET / HTTP/1.1\r\n\
                Host: example.com\r\n\
                User-Agent: {}\r\n\
                Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8\r\n\
                Accept-Language: en-US,en;q=0.5\r\n\
                Accept-Encoding: gzip, deflate\r\n\
                Connection: keep-alive\r\n\
                Upgrade-Insecure-Requests: 1\r\n\
                Sec-Fetch-Dest: document\r\n\
                Sec-Fetch-Mode: navigate\r\n\
                Sec-Fetch-Site: none\r\n\
                Sec-Fetch-User: ?1\r\n\
                Cache-Control: max-age=0\r\n\r\n",
                user_agent
            );
            
            // Add some randomness to make it less predictable
            if thread_rng().gen_bool(0.3) {
                // Sometimes add a DNT (Do Not Track) header
                request = request.replace("\r\n\r\n", "\r\nDNT: 1\r\n\r\n");
            }
            
            request.into_bytes()
        },
        "HTTPS" | "TLS" => {
            // ClientHello packet for TLS that mimics browser behavior
            // This is a simplified version - real TLS ClientHello is more complex
            // Format: [content_type, version_major, version_minor, length_hi, length_lo, handshake_type, ...]
            
            // Choose TLS version based on variant or randomly
            let (version_major, version_minor) = match variant {
                Some("1.0") => (3, 1),
                Some("1.1") => (3, 2),
                Some("1.2") => (3, 3),
                Some("1.3") => (3, 4),
                _ => {
                    // Default to TLS 1.2 (most common) or randomly select
                    if thread_rng().gen_bool(0.8) {
                        (3, 3) // TLS 1.2
                    } else {
                        (3, 4) // TLS 1.3
                    }
                }
            };
            
            // Start with the TLS record layer
            let mut tls_hello = vec![
                0x16,                   // Content Type: Handshake
                version_major,          // Version Major
                version_minor,          // Version Minor
                0x00, 0x2a,             // Length (placeholder)
                0x01,                   // Handshake Type: Client Hello
                0x00, 0x00, 0x26,       // Handshake Length (placeholder)
            ];
            
            // Add client random (32 bytes)
            let mut client_random = vec![0u8; 32];
            for i in 0..client_random.len() {
                client_random[i] = thread_rng().gen();
            }
            tls_hello.extend_from_slice(&client_random);
            
            // We're simplifying the rest of the ClientHello packet
            // In a real implementation, you'd include cipher suites, extensions, etc.
            
            tls_hello
        },
        "SSH" => {
            // Create a realistic SSH client banner that looks like OpenSSH
            // SSH protocol requires the client send a banner first
            
            let versions = ["7.9", "8.0", "8.1", "8.2", "8.3", "8.4", "8.5", "8.6"];
            let ssh_version = match variant {
                Some(v) => v.to_string(),
                None => versions[thread_rng().gen_range(0..versions.len())].to_string()
            };
            
            // Vary the SSH implementation details to look more realistic
            let implementation = if thread_rng().gen_bool(0.9) {
                format!("OpenSSH_{}", ssh_version)
            } else {
                // Occasionally use other client implementations
                let alt_clients = ["PuTTY_Release_0.75", "libssh2_1.10.0", "JSCH-0.1.55"];
                alt_clients[thread_rng().gen_range(0..alt_clients.len())].to_string()
            };
            
            format!("SSH-2.0-{}\r\n", implementation).into_bytes()
        },
        "FTP" => {
            // Realistic FTP client behavior
            match variant {
                Some("auth") => b"USER anonymous\r\n".to_vec(),
                Some("list") => b"LIST\r\n".to_vec(), 
                _ => b"USER anonymous\r\n".to_vec() // default to basic auth
            }
        },
        "SMB" => {
            // SMB protocol negotiation packet (simplified)
            // This would need significant expansion for real use
            vec![0xff, 0x53, 0x4d, 0x42, 0x72, 0x00, 0x00, 0x00, 0x00]
        },
        _ => {
            // For unknown protocols, create generic binary data
            // that doesn't look like a scanner pattern
            let length = thread_rng().gen_range(16..32);
            let mut data = Vec::with_capacity(length);
            for _ in 0..length {
                data.push(thread_rng().gen());
            }
            data
        }
    }
}

/// Encrypt sensitive log data for enhanced operational security
///
/// # Arguments
/// * `data` - The sensitive data to encrypt
/// * `key` - Optional encryption key (will generate if not provided)
///
/// # Returns
/// * `(String, Option<Vec<u8>>)` - (Encrypted data as hex string, key if generated)
#[allow(dead_code)]
pub fn encrypt_sensitive_data(data: &str, key: Option<Vec<u8>>) -> (String, Option<Vec<u8>>) {
    // If encryption is not requested, just return the data as is
    if data.is_empty() {
        return (String::new(), None);
    }
    
    use aes_gcm::{
        aead::{Aead, AeadCore, KeyInit, OsRng},
        Aes256Gcm
    };
    
    // Generate or use provided key
    let encryption_key = if let Some(ref k) = key {
        k.clone()
    } else {
        // Generate a random key
        let key_array = Aes256Gcm::generate_key(OsRng);
        key_array.to_vec()
    };
    
    // Create cipher instance
    let key_slice: &[u8] = &encryption_key;
    let cipher = Aes256Gcm::new(key_slice.into());
    
    // Generate a random nonce
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
    
    // Encrypt the data
    match cipher.encrypt(&nonce, data.as_bytes()) {
        Ok(ciphertext) => {
            // Combine nonce and ciphertext for storage
            let mut encrypted = nonce.to_vec();
            encrypted.extend_from_slice(&ciphertext);
            
            // Convert to hex string for easy storage
            let hex_data = encrypted.iter()
                .map(|b| format!("{:02x}", b))
                .collect::<String>();
            
            // Return the hex string and the key if we generated it
            (hex_data, if key.is_some() { None } else { Some(encryption_key) })
        },
        Err(_) => {
            // If encryption fails, return a placeholder
            // In real implementation, handle this error properly
            ("ENCRYPTION_FAILED".to_string(), None)
        }
    }
}

/// Decrypt sensitive data from hex format
///
/// # Arguments
/// * `hex_data` - The encrypted data in hex format
/// * `key` - The encryption key
///
/// # Returns
/// * `Option<String>` - The decrypted data if successful
pub fn decrypt_sensitive_data(hex_data: &str, key: &[u8]) -> Option<String> {
    // Check for encrypted format
    if !hex_data.starts_with("ENCRYPTED:") {
        return Some(hex_data.to_string());
    }
    
    // Extract the hex data part
    let hex_data = &hex_data["ENCRYPTED:".len()..];
    
    // Convert hex to bytes
    let mut data = Vec::with_capacity(hex_data.len() / 2);
    for i in (0..hex_data.len()).step_by(2) {
        if i + 2 > hex_data.len() {
            return None;
        }
        
        match u8::from_str_radix(&hex_data[i..i+2], 16) {
            Ok(byte) => data.push(byte),
            Err(_) => return None,
        }
    }
    
    // Check length for minimum nonce size
    if data.len() < 8 {
        return None;
    }
    
    // Extract nonce counter
    let mut nonce_bytes = [0u8; 8];
    nonce_bytes.copy_from_slice(&data[0..8]);
    let nonce_counter = u64::from_le_bytes(nonce_bytes);
    
    // Decrypt the data (simple XOR decryption)
    let mut decrypted = Vec::with_capacity(data.len() - 8);
    for (i, byte) in data[8..].iter().enumerate() {
        let key_idx = i % key.len();
        let xor_byte = byte ^ key[key_idx] ^ ((nonce_counter >> (i % 8)) as u8);
        decrypted.push(xor_byte);
    }
    
    // Convert back to string
    match String::from_utf8(decrypted) {
        Ok(plaintext) => Some(plaintext),
        Err(_) => None,
    }
}

/// In-memory log buffer that stores logs without writing to disk
///
/// This type allows for storing logs in memory only, improving operational security
/// by avoiding disk writes that could be forensically recovered.
#[derive(Default, Clone)]
pub struct MemoryLogBuffer {
    /// Vector of log entries, each as a tuple of (timestamp, level, message)
    entries: std::sync::Arc<parking_lot::Mutex<Vec<(chrono::DateTime<Utc>, String, String)>>>,
    
    /// Optional encryption key
    encryption_key: Option<Vec<u8>>,
    
    /// Maximum number of entries to keep
    max_entries: usize,
    
    /// Whether to encrypt entries
    encrypt: bool,
    
    /// Nonce counter for encryption uniqueness
    nonce_counter: std::sync::Arc<parking_lot::Mutex<u64>>,
    
    /// Last export time (to prevent frequent exporting that could leak info)
    last_export: std::sync::Arc<parking_lot::Mutex<Option<Instant>>>,
    
    /// Minimum seconds between exports (to prevent timing analysis)
    min_export_interval: u64,
}

impl MemoryLogBuffer {
    /// Create a new memory log buffer
    ///
    /// # Arguments
    /// * `max_entries` - Maximum number of log entries to keep (0 for unlimited)
    /// * `encrypt` - Whether to encrypt log entries
    pub fn new(max_entries: usize, encrypt: bool) -> Self {
        let encryption_key = if encrypt {
            // Generate a random encryption key with proper error handling
            // Just use thread_rng directly without the unused imports
            let mut key = vec![0u8; 32]; // AES-256 key size
            thread_rng().fill(key.as_mut_slice());
            Some(key)
        } else {
            None
        };
        
        Self {
            entries: std::sync::Arc::new(parking_lot::Mutex::new(Vec::new())),
            encryption_key,
            max_entries: if max_entries == 0 { usize::MAX } else { max_entries },
            encrypt,
            nonce_counter: std::sync::Arc::new(parking_lot::Mutex::new(0)),
            last_export: std::sync::Arc::new(parking_lot::Mutex::new(None)),
            min_export_interval: 5, // 5 seconds minimum between exports
        }
    }
    
    /// Add a log entry
    ///
    /// # Arguments
    /// * `level` - Log level (e.g., "INFO", "ERROR")
    /// * `message` - Log message
    pub fn log(&self, level: &str, message: &str) {
        let timestamp = Utc::now();
        let mut entries = self.entries.lock();
        
        // Encrypt message if enabled
        let message = if self.encrypt {
            if let Some(key) = &self.encryption_key {
                // Increment nonce counter to ensure uniqueness
                let mut counter = self.nonce_counter.lock();
                *counter += 1;
                
                // Use counter in encryption to ensure unique nonces
                match encrypt_sensitive_data_with_nonce(message, Some(key.clone()), *counter) {
                    Ok(encrypted) => encrypted,
                    Err(_) => {
                        // Fallback if encryption fails - mark as encryption error
                        format!("ENCRYPTION_ERROR:{}", sanitize_string(message))
                    }
                }
            } else {
                message.to_string()
            }
        } else {
            message.to_string()
        };
        
        // Add the entry
        entries.push((timestamp, level.to_string(), message));
        
        // Trim if needed
        if entries.len() > self.max_entries {
            // Securely clear the oldest entries
            let to_remove = entries.len() - self.max_entries;
            for _ in 0..to_remove {
                if let Some((_, _, message)) = entries.first() {
                    // Overwrite the message with zeros before removing
                    let mut overwrite = String::with_capacity(message.len());
                    for _ in 0..message.len() {
                        overwrite.push('\0');
                    }
                    
                    // This is an approximate secure wipe - not perfect but better than nothing
                    if let Some(entry) = entries.first_mut() {
                        entry.2 = overwrite;
                    }
                }
                
                entries.remove(0);
            }
        }
    }
    
    /// Get all log entries, optionally decrypted
    ///
    /// # Arguments
    /// * `decrypt` - Whether to decrypt entries (if encrypted)
    ///
    /// # Returns
    /// * `Vec<(chrono::DateTime<Utc>, String, String)>` - Vector of (timestamp, level, message)
    pub fn get_entries(&self, decrypt: bool) -> Vec<(chrono::DateTime<Utc>, String, String)> {
        // Update last export time for rate limiting
        let mut last_export = self.last_export.lock();
        
        // Check for rate limiting of exports - prevents timing analysis attacks
        if let Some(last) = *last_export {
            let elapsed = last.elapsed().as_secs();
            if elapsed < self.min_export_interval {
                // Add random delay to prevent timing analysis
                let delay = thread_rng().gen_range(50..200);
                std::thread::sleep(Duration::from_millis(delay));
            }
        }
        
        // Update last export time
        *last_export = Some(Instant::now());
        
        let entries = self.entries.lock();
        
        if !self.encrypt || !decrypt {
            // Return as-is if not encrypted or decryption not requested
            // Clone to avoid holding the lock
            entries.clone()
        } else {
            // Decrypt entries
            entries.iter().map(|(timestamp, level, message)| {
                // Don't try to decrypt messages that weren't encrypted
                if !message.starts_with("ENCRYPTED:") && !message.starts_with("ENCRYPTION_ERROR:") {
                    return (*timestamp, level.clone(), message.clone());
                }
                
                // Skip decrypt for encryption errors
                if message.starts_with("ENCRYPTION_ERROR:") {
                    return (*timestamp, level.clone(), message.replace("ENCRYPTION_ERROR:", "[Encryption Failed] "));
                }
                
                let decrypted = if let Some(key) = &self.encryption_key {
                    match decrypt_sensitive_data(message, key) {
                        Some(text) => text,
                        None => "[DECRYPTION_FAILED]".to_string()
                    }
                } else {
                    "[NO_DECRYPTION_KEY]".to_string()
                };
                
                (*timestamp, level.clone(), decrypted)
            }).collect()
        }
    }
    
    /// Clear all log entries with secure wiping
    #[allow(dead_code)]
    pub fn clear(&self) {
        let mut entries = self.entries.lock();
        
        // First overwrite all messages with zeros
        for entry in entries.iter_mut() {
            let msg_len = entry.2.len();
            entry.2 = "\0".repeat(msg_len);
        }
        
        // Then clear the vector
        entries.clear();
    }
    
    /// Get the number of log entries
    pub fn len(&self) -> usize {
        self.entries.lock().len()
    }
    
    /// Check if there are any log entries
    #[allow(dead_code)]
    pub fn is_empty(&self) -> bool {
        self.entries.lock().is_empty()
    }
    
    /// Format all logs as a string, optionally decrypted
    ///
    /// # Arguments
    /// * `decrypt` - Whether to decrypt entries (if encrypted)
    ///
    /// # Returns
    /// * `String` - Formatted log string
    pub fn format_logs(&self, decrypt: bool) -> String {
        let entries = self.get_entries(decrypt);
        
        entries.iter()
            .map(|(timestamp, level, message)| {
                format!("[{}] {} - {}", 
                    timestamp.format("%Y-%m-%d %H:%M:%S%.3f"),
                    level, 
                    sanitize_string(message) // Sanitize to prevent log injection
                )
            })
            .collect::<Vec<_>>()
            .join("\n")
    }
    
    /// Export logs to a file with encryption
    ///
    /// # Arguments
    /// * `path` - File path to export to
    /// * `password` - Optional password for file encryption
    ///
    /// # Returns
    /// * `Result<(), String>` - Success or error message
    #[allow(dead_code)]
    pub fn export_to_file(&self, path: &std::path::Path, password: Option<&str>) -> Result<(), String> {
        // Check path for safety
        let path_str = path.to_string_lossy();
        if path_str.contains("..") || path_str.contains("~") {
            return Err("Invalid export path".to_string());
        }
        
        // Get log entries
        let entries = self.get_entries(true);
        
        // Format logs
        let log_content = entries.iter()
            .map(|(timestamp, level, message)| {
                format!("[{}] {} - {}", 
                    timestamp.format("%Y-%m-%d %H:%M:%S%.3f"),
                    level, 
                    sanitize_string(message)
                )
            })
            .collect::<Vec<_>>()
            .join("\n");
        
        // Encrypt file if password provided
        let file_content = if let Some(pwd) = password {
            // Simple password-based encryption without specialized crates
            let key = pwd.as_bytes().to_vec();
            // Use existing encrypt_sensitive_data function
            match encrypt_sensitive_data(&log_content, Some(key)) {
                (encrypted, _) => format!("ENCRYPTED_LOG_FILE_V1\n{}", encrypted),
            }
        } else {
            log_content
        };
        
        // Write to file
        match std::fs::write(path, file_content) {
            Ok(_) => Ok(()),
            Err(e) => Err(format!("Failed to write log file: {}", e)),
        }
    }
}

/// Encrypt sensitive data with a specific nonce counter
///
/// # Arguments
/// * `data` - Data to encrypt
/// * `key` - Optional encryption key (will generate one if None)
/// * `nonce_counter` - Counter value to use in nonce generation
///
/// # Returns
/// * `Result<String, &'static str>` - Encrypted data in hex format
pub fn encrypt_sensitive_data_with_nonce(data: &str, key: Option<Vec<u8>>, nonce_counter: u64) -> Result<String, &'static str> {
    // Simplified encryption without AES-GCM complexity
    // For production use, a more robust approach would be needed
    
    // Get or generate a key
    let key = key.unwrap_or_else(|| {
        let mut key = vec![0u8; 32]; // 256-bit key size
        thread_rng().fill(key.as_mut_slice());
        key
    });
    
    // Create a basic XOR encryption with the key and nonce
    let mut encrypted = Vec::with_capacity(data.len() + 8);
    
    // Add the nonce counter to the beginning for decryption
    encrypted.extend_from_slice(&nonce_counter.to_le_bytes());
    
    // Simple XOR encryption (not secure for production)
    for (i, byte) in data.as_bytes().iter().enumerate() {
        let key_idx = i % key.len();
        let xor_byte = byte ^ key[key_idx] ^ ((nonce_counter >> (i % 8)) as u8);
        encrypted.push(xor_byte);
    }
    
    // Convert to hex string for storage
    let hex = encrypted.iter()
        .map(|b| format!("{:02x}", b))
        .collect::<String>();
    
    Ok(format!("ENCRYPTED:{}", hex))
}

/// Extract version information from a service banner
/// 
/// This function attempts to identify version information in service banners
/// by looking for common patterns used by various services.
/// 
/// # Arguments
/// * `service_name` - The name of the service (e.g., "http", "ssh")
/// * `banner` - The banner text received from the service
/// 
/// # Returns
/// * `Option<String>` - Extracted version string, if found
pub fn extract_version_from_banner(service_name: &str, banner: &str) -> Option<String> {
    // First try to use the new extractors
    if service_name.to_lowercase() == "mysql" {
        if let Some(version) = extract_mysql_version(banner) {
            return Some(version);
        }
    } else if service_name.to_lowercase() == "mariadb" {
        if let Some(version) = extract_mariadb_version(banner) {
            return Some(version);
        }
    } else if service_name.to_lowercase() == "postgresql" {
        if let Some(version) = extract_postgresql_version(banner) {
            return Some(version);
        }
    }
    
    // Fall back to the old pattern matching
    match service_name.to_lowercase().as_str() {
        "ssh" => {
            // SSH version format: SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.1
            let parts: Vec<&str> = banner.split_whitespace().collect();
            if parts.len() >= 1 {
                let version_part = parts[0];
                if version_part.starts_with("SSH-") {
                    let version_parts: Vec<&str> = version_part.split('-').collect();
                    if version_parts.len() >= 3 {
                        // Extract OpenSSH version
                        let software = version_parts[2];
                        if software.starts_with("OpenSSH_") {
                            let version = &software["OpenSSH_".len()..];
                            return Some(format!("OpenSSH {}", version));
                        }
                        return Some(software.to_string());
                    }
                }
            }
            None
        },
        
        "http" | "https" => {
            // Try to extract from Server header
            if let Some(server) = banner.lines()
                .find(|line| line.to_lowercase().starts_with("server:"))
            {
                let parts: Vec<&str> = server.splitn(2, ':').collect();
                if parts.len() == 2 {
                    let server = parts[1].trim();
                    
                    // Check for known server types
                    if server.to_lowercase().contains("apache") {
                        let re = regex::Regex::new(r"Apache/([\d.]+)").ok()?;
                        if let Some(caps) = re.captures(server) {
                            return Some(format!("Apache {}", &caps[1]));
                        }
                    } else if server.to_lowercase().contains("nginx") {
                        let re = regex::Regex::new(r"nginx/([\d.]+)").ok()?;
                        if let Some(caps) = re.captures(server) {
                            return Some(format!("Nginx {}", &caps[1]));
                        }
                    } else if server.to_lowercase().contains("microsoft-iis") {
                        let re = regex::Regex::new(r"Microsoft-IIS/([\d.]+)").ok()?;
                        if let Some(caps) = re.captures(server) {
                            return Some(format!("IIS {}", &caps[1]));
                        }
                    }
                    
                    // Return the entire server string if no specific version found
                    return Some(server.to_string());
                }
            }
            None
        },
        
        "smtp" => {
            // SMTP banner format: 220 mail.example.com ESMTP Postfix
            let first_line = banner.lines().next()?;
            if first_line.starts_with("220 ") {
                let parts: Vec<&str> = first_line.split_whitespace().collect();
                if parts.len() >= 3 {
                    if parts.contains(&"Postfix") {
                        return Some("Postfix".to_string());
                    } else if parts.contains(&"Exchange") {
                        return Some("Exchange Server".to_string());
                    } else if parts.contains(&"Exim") {
                        let re = regex::Regex::new(r"Exim ([\d.]+)").ok()?;
                        if let Some(caps) = re.captures(first_line) {
                            return Some(format!("Exim {}", &caps[1]));
                        }
                        return Some("Exim".to_string());
                    }
                    
                    // If no known server found, use the ESMTP identifier
                    if parts.len() >= 4 && parts[2] == "ESMTP" {
                        return Some(parts[3].to_string());
                    }
                }
            }
            None
        },
        
        // Add other service types as needed
        _ => None
    }
}

/// Assess the security posture of a service based on its configuration
/// 
/// Evaluates the security of a service by analyzing its version, banner,
/// and certificate information. Returns a string describing the security posture.
/// 
/// # Arguments
/// * `service_name` - The name of the service
/// * `version` - Optional version string
/// * `banner` - Optional banner text
/// * `cert_info` - Optional SSL/TLS certificate information
/// 
/// # Returns
/// * `Option<String>` - Security assessment, if available
pub fn assess_service_security(
    service_name: &str,
    version: Option<&str>,
    banner: Option<&str>,
    cert_info: Option<&crate::models::CertificateInfo>,
) -> Option<String> {
    let service = service_name.to_lowercase();
    
    // Start with no assessment
    let mut assessment = Vec::new();
    
    // Check for version-based security issues
    if let Some(version_str) = version {
        match service.as_str() {
            "http" | "https" => {
                // Check for outdated web servers
                if version_str.contains("Apache/1.") || version_str.contains("Apache/2.0") || version_str.contains("Apache/2.2") {
                    assessment.push("Outdated Apache version with known vulnerabilities");
                } else if version_str.contains("Apache/2.4") {
                    assessment.push("Modern Apache version, check patch level");
                }
                
                if version_str.contains("nginx/0.") || version_str.contains("nginx/1.0") || version_str.contains("nginx/1.1") {
                    assessment.push("Outdated nginx version with known vulnerabilities");
                } else if version_str.contains("nginx/1.") {
                    assessment.push("Relatively modern nginx version");
                }
                
                if version_str.contains("IIS/5.") || version_str.contains("IIS/6.") || version_str.contains("IIS/7.") {
                    assessment.push("Outdated IIS version with known vulnerabilities");
                }
            },
            "ssh" => {
                // Check for outdated SSH versions
                if version_str.contains("SSH-1.") {
                    assessment.push("Critical: SSHv1 protocol is fundamentally insecure");
                }
                
                if version_str.contains("OpenSSH_4.") || version_str.contains("OpenSSH_5.") || 
                   version_str.contains("OpenSSH_6.") || version_str.contains("OpenSSH_7.0") {
                    assessment.push("Outdated OpenSSH version with known vulnerabilities");
                } else if version_str.contains("OpenSSH_8.") || version_str.contains("OpenSSH_9.") {
                    assessment.push("Modern OpenSSH version with good security");
                }
            },
            "ftp" => {
                // Check FTP server security
                if version_str.contains("vsftpd 2.") {
                    assessment.push("Older vsftpd version, potential vulnerabilities");
                }
                
                if version_str.contains("ProFTPD 1.3.3") || version_str.contains("ProFTPD 1.3.4") {
                    assessment.push("Outdated ProFTPD with known vulnerabilities");
                }
            },
            "mysql" | "mariadb" => {
                // Check MySQL/MariaDB versions
                if version_str.contains("5.0.") || version_str.contains("5.1.") || version_str.contains("5.5.") {
                    assessment.push("Outdated MySQL version with known vulnerabilities");
                }
            },
            // Add more service-specific checks as needed
            _ => {
                // Generic version check
                if version_str.contains("beta") || version_str.contains("alpha") {
                    assessment.push("Pre-release software may have security issues");
                }
            }
        }
    }
    
    // Check banner for security issues
    if let Some(banner_text) = banner {
        // Check for server information disclosure
        if banner_text.contains("Server:") || banner_text.contains("X-Powered-By:") {
            assessment.push("Information disclosure: Server details revealed in headers");
        }
        
        // Check for debug information
        if banner_text.contains("DEBUG") || banner_text.contains("TRACE") {
            assessment.push("Debug information present in responses");
        }
        
        // Service-specific banner checks
        match service.as_str() {
            "ftp" => {
                if banner_text.contains("anonymous") || banner_text.to_lowercase().contains("anon") {
                    assessment.push("Anonymous FTP access may be enabled");
                }
            },
            "smtp" => {
                if banner_text.contains("VRFY") || banner_text.contains("EXPN") {
                    assessment.push("SMTP server allows user enumeration (VRFY/EXPN commands)");
                }
            },
            // Add more service-specific banner checks
            _ => {}
        }
    }
    
    // Check SSL/TLS certificates for security issues
    if let Some(cert) = cert_info {
        // Check for self-signed certificates
        if cert.subject == cert.issuer {
            assessment.push("Self-signed certificate in use");
        }
        
        // Check for expired certificates
        if let Ok(not_after) = chrono::DateTime::parse_from_rfc3339(&cert.not_after) {
            let now = chrono::Utc::now();
            if now > not_after {
                assessment.push("Critical: SSL/TLS certificate has expired");
            } else {
                // Check if certificate is nearing expiration (within 30 days)
                let thirty_days = chrono::Duration::days(30);
                if now + thirty_days > not_after {
                    assessment.push("Warning: SSL/TLS certificate expires within 30 days");
                }
            }
        }
        
        // Check for weak key sizes
        if let Some(key_bits) = cert.public_key_bits {
            if key_bits < 2048 {
                assessment.push("Weak SSL/TLS key size (less than 2048 bits)");
            }
        }
        
        // Check for weak signature algorithms
        if cert.signature_algorithm.contains("MD5") || cert.signature_algorithm.contains("SHA1") {
            assessment.push("Weak signature algorithm in certificate");
        }
    }
    
    // Return combined assessment
    if assessment.is_empty() {
        None
    } else {
        Some(assessment.join("; "))
    }
}

/// Detect anomalies in service responses that might indicate honeypots or security devices
/// 
/// Identifies unusual patterns in service responses that might suggest the presence
/// of a honeypot, security device, or other anomaly.
/// 
/// # Arguments
/// * `service_name` - The name of the service
/// * `banner` - Optional banner text
/// * `cert_info` - Optional SSL/TLS certificate information
/// 
/// # Returns
/// * `Vec<String>` - List of detected anomalies
pub fn detect_response_anomalies(
    service_name: &str,
    banner: Option<&str>,
    cert_info: Option<&crate::models::CertificateInfo>,
) -> Vec<String> {
    let mut anomalies = Vec::new();
    let service = service_name.to_lowercase();
    
    // Check for banner anomalies
    if let Some(banner_text) = banner {
        // Check for inconsistent version information
        if banner_text.contains("Apache") && banner_text.contains("nginx") {
            anomalies.push("Conflicting server software signatures".to_string());
        }
        
        // Check for unusual or fake banner patterns
        if banner_text.contains("honeypot") || banner_text.contains("honeynet") {
            anomalies.push("Explicit honeypot identification in banner".to_string());
        }
        
        // Check for unusually generic responses
        if banner_text.is_empty() || banner_text.len() < 5 {
            anomalies.push("Unusually brief response".to_string());
        }
        
        // Service-specific anomaly checks
        match service.as_str() {
            "ssh" => {
                // SSH anomalies
                if banner_text.contains("SSH-") && !banner_text.contains("OpenSSH") && 
                   !banner_text.contains("Dropbear") && !banner_text.contains("libssh") {
                    anomalies.push("Unusual SSH server implementation".to_string());
                }
            },
            "http" | "https" => {
                // Unusual HTTP server signatures
                if banner_text.contains("Server:") && banner_text.contains("FAKE") {
                    anomalies.push("Suspicious server signature".to_string());
                }
            },
            "telnet" => {
                // Telnet is often emulated in honeypots
                if !banner_text.contains("login:") && !banner_text.contains("Username:") {
                    anomalies.push("Unusual telnet prompt".to_string());
                }
            },
            // Add more service-specific anomaly checks
            _ => {}
        }
        
        // Check for repeating patterns that might indicate template responses
        let chars: Vec<char> = banner_text.chars().collect();
        if chars.len() > 8 {
            let mut repeat_count = 0;
            for i in 0..chars.len()-4 {
                if chars[i] == chars[i+4] && chars[i+1] == chars[i+5] &&
                   chars[i+2] == chars[i+6] && chars[i+3] == chars[i+7] {
                    repeat_count += 1;
                }
            }
            if repeat_count > chars.len() / 8 {
                anomalies.push("Suspiciously repetitive pattern in response".to_string());
            }
        }
    }
    
    // Check certificate anomalies
    if let Some(cert) = cert_info {
        // Check for honeypot-like certificates
        if cert.subject.contains("honeypot") || cert.issuer.contains("honeypot") {
            anomalies.push("Honeypot indicator in certificate".to_string());
        }
        
        // Check for unusual issuers
        if !cert.issuer.contains("Let's Encrypt") && 
           !cert.issuer.contains("Comodo") && 
           !cert.issuer.contains("DigiCert") && 
           !cert.issuer.contains("GlobalSign") && 
           !cert.issuer.contains("GoDaddy") && 
           !cert.issuer.contains("Sectigo") &&
           cert.subject != cert.issuer {  // Exclude self-signed
            anomalies.push("Unusual certificate authority".to_string());
        }
        
        // Check for odd validity periods
        if let (Ok(not_before), Ok(not_after)) = (
            chrono::DateTime::parse_from_rfc3339(&cert.not_before),
            chrono::DateTime::parse_from_rfc3339(&cert.not_after)
        ) {
            let validity_days = (not_after - not_before).num_days();
            
            // Most legitimate certs are ~90 days (Let's Encrypt) or ~365/730 days
            if validity_days > 10 * 365 { // More than 10 years
                anomalies.push("Suspiciously long certificate validity period".to_string());
            } else if validity_days < 10 { // Less than 10 days
                anomalies.push("Suspiciously short certificate validity period".to_string());
            }
        }
    }
    
    anomalies
}

/// Check for potential vulnerabilities in the service
/// 
/// Analyzes service information to identify potential security vulnerabilities
/// based on service type, version, configuration, and known issues.
/// 
/// # Arguments
/// * `service_name` - The name of the service
/// * `version` - Optional version string
/// * `banner` - Optional banner text
/// * `_cert_info` - Optional SSL/TLS certificate information
/// 
/// # Returns
/// * `Vec<String>` - List of potential vulnerabilities
pub fn check_service_vulns(
    service_name: &str,
    version: Option<&str>,
    banner: Option<&str>,
    _cert_info: Option<&crate::models::CertificateInfo>,
) -> Vec<String> {
    let mut vulns = Vec::new();
    let service = service_name.to_lowercase();
    
    // Check common service vulnerabilities based on service type and version
    if let Some(version_str) = version {
        match service.as_str() {
            "http" | "https" => {
                // Apache vulnerabilities
                if version_str.contains("Apache/2.4.49") {
                    vulns.push("CVE-2021-41773: Path Traversal and RCE in Apache 2.4.49".to_string());
                } else if version_str.contains("Apache/2.4.50") {
                    vulns.push("CVE-2021-42013: Path Traversal in Apache 2.4.50".to_string());
                } else if version_str.contains("Apache/2.2.") {
                    vulns.push("Multiple vulnerabilities in Apache 2.2.x (EOL)".to_string());
                }
                
                // Nginx vulnerabilities
                if version_str.contains("nginx/1.16.") || version_str.contains("nginx/1.17.") {
                    vulns.push("CVE-2019-9513: HTTP/2 DoS vulnerability in nginx 1.16.x-1.17.x".to_string());
                }
                
                // IIS vulnerabilities
                if version_str.contains("Microsoft-IIS/7.5") {
                    vulns.push("CVE-2010-3972: Information disclosure in IIS 7.5".to_string());
                }
            },
            "ssh" => {
                // OpenSSH vulnerabilities
                if version_str.contains("OpenSSH_7.2") {
                    vulns.push("CVE-2016-6210: User enumeration via timing attack in OpenSSH 7.2".to_string());
                } else if version_str.contains("OpenSSH_5.") {
                    vulns.push("Multiple vulnerabilities in OpenSSH 5.x (EOL)".to_string());
                }
                
                if version_str.contains("Dropbear_2016") {
                    vulns.push("CVE-2016-7406: Remote overflow vulnerability in Dropbear 2016.73".to_string());
                }
            },
            "ftp" => {
                // vsftpd vulnerabilities
                if version_str.contains("vsftpd 2.3.4") {
                    vulns.push("Backdoor in vsftpd 2.3.4".to_string());
                }
                
                // ProFTPD vulnerabilities
                if version_str.contains("ProFTPD 1.3.3") {
                    vulns.push("CVE-2010-4652: Remote command execution in ProFTPD 1.3.3".to_string());
                }
            },
            "smtp" => {
                // Exim vulnerabilities
                if version_str.contains("Exim 4.8") || version_str.contains("Exim 4.9.0") {
                    vulns.push("CVE-2019-15846: Remote command execution in Exim".to_string());
                }
            },
            "mysql" | "mariadb" => {
                // MySQL vulnerabilities
                if version_str.contains("5.5.") || version_str.contains("5.6.") {
                    vulns.push("Multiple vulnerabilities in older MySQL versions".to_string());
                }
            },
            // Add more service-specific vulnerability checks
            _ => {}
        }
    }
    
    // Check for vulnerabilities based on banner content
    if let Some(banner_text) = banner {
        // Check for default credentials in banners
        if banner_text.contains("default password") || banner_text.contains("admin/admin") {
            vulns.push("Banner suggests default credentials".to_string());
        }
        
        // Server information disclosure
        if service == "http" || service == "https" {
            if banner_text.contains("X-Powered-By:") {
                vulns.push("Information disclosure via X-Powered-By header".to_string());
            }
        }
    }
    
    vulns
}

/// Check for SSL/TLS vulnerabilities
/// 
/// Analyzes SSL/TLS certificate information to identify potential vulnerabilities.
/// 
/// # Arguments
/// * `cert_info` - SSL/TLS certificate information
/// 
/// # Returns
/// * `Vec<String>` - List of potential SSL/TLS vulnerabilities
pub fn check_ssl_vulnerabilities(cert_info: &crate::models::CertificateInfo) -> Vec<String> {
    let mut vulns = Vec::new();
    
    // Check for expired certificates
    if let Ok(not_after) = chrono::DateTime::parse_from_rfc3339(&cert_info.not_after) {
        let now = chrono::Utc::now();
        if now > not_after {
            vulns.push("Expired SSL/TLS certificate".to_string());
        }
    }
    
    // Check for self-signed certificates
    if cert_info.subject == cert_info.issuer {
        vulns.push("Self-signed certificate (not inherently vulnerable, but not trusted)".to_string());
    }
    
    // Check for weak key lengths
    if let Some(key_bits) = cert_info.public_key_bits {
        if key_bits < 2048 {
            vulns.push(format!("Weak key length: {} bits (should be at least 2048)", key_bits));
        }
    }
    
    // Check for weak signature algorithms
    if cert_info.signature_algorithm.contains("MD5") {
        vulns.push("Critical: MD5 signature algorithm (broken)".to_string());
    } else if cert_info.signature_algorithm.contains("SHA1") {
        vulns.push("Weak: SHA1 signature algorithm (deprecated)".to_string());
    }
    
    // Check for wildcard certificates
    for alt_name in &cert_info.alt_names {
        if alt_name.starts_with("*.") {
            vulns.push("Wildcard certificate in use (reduced security)".to_string());
            break;
        }
    }
    
    vulns
}

/// Create a DNS resolver with a custom DNS server
///
/// - DNS requests can be monitored at the specified server
/// - Choose trustworthy DNS server for sensitive operations

/// Configure the system to route traffic through Tor
///
/// # OPSEC considerations:
/// - Using Tor can provide anonymity but may slow down scanning
/// - Some organizations monitor/block Tor exit nodes
/// - Not all scanning techniques work effectively through Tor
///
/// # Arguments
/// * `use_tor` - Whether to enable or disable Tor routing
///
/// # Returns
/// * `bool` - True if Tor routing was successfully enabled
pub fn configure_tor_routing(enable: bool) -> bool {
    if !enable {
        return true; // Nothing to do if not enabling
    }
    
    // Check if Tor is installed and running
    let tor_running = match std::process::Command::new("sh")
        .arg("-c")
        .arg("systemctl status tor 2>/dev/null || pgrep -x tor 2>/dev/null || pgrep -x tor.real 2>/dev/null")
        .output() {
            Ok(output) => output.status.success(),
            Err(_) => false
        };
    
    if !tor_running {
        warn!("Tor service is not running. Cannot route traffic through Tor.");
        return false;
    }
    
    // Check for various Tor libraries
    let lib_paths = [
        "libtorsocks.so",
        "/usr/lib/libtorsocks.so",
        "/usr/lib/x86_64-linux-gnu/libtorsocks.so",
        "/usr/lib/torsocks/libtorsocks.so",
        "libtsocks.so",
        "/usr/lib/libtsocks.so"
    ];
    
    // Find first available Tor library
    let tor_lib = lib_paths.iter().find(|&path| {
        std::process::Command::new("sh")
            .arg("-c")
            .arg(format!("ldconfig -p | grep -q {}", path))
            .status()
            .map(|s| s.success())
            .unwrap_or(false) || std::path::Path::new(path).exists()
    });
    
    let lib_path = match tor_lib {
        Some(path) => path,
        None => {
            warn!("Could not find Tor libraries. Make sure torsocks/tsocks is installed.");
            return false;
        }
    };
    
    // Set environment variables for Tor routing
    // Note: std::env::set_var returns () not Result, so we can't check for errors
    std::env::set_var("LD_PRELOAD", lib_path);
    
    // Check SOCKS port for Tor
    let tor_port = match std::process::Command::new("sh")
        .arg("-c")
        .arg("grep -o 'SOCKSPort [0-9]\\+' /etc/tor/torrc 2>/dev/null | awk '{print $2}'")
        .output() {
            Ok(output) => {
                if output.status.success() && !output.stdout.is_empty() {
                    String::from_utf8_lossy(&output.stdout).trim().to_string()
                } else {
                    "9050".to_string() // Default Tor SOCKS port
                }
            },
            Err(_) => "9050".to_string()
        };
    
    // Set Tor SOCKS proxy port
    // Note: std::env::set_var returns () not Result, so we can't check for errors
    std::env::set_var("TORSOCKS_PORT", &tor_port);
    
    info!("Tor routing configured successfully using port {} with library {}", tor_port, lib_path);
    true
}

/// Generate DNS tunnel session identifier
///
/// Creates a unique but not obviously random session ID for DNS tunneling
/// to avoid standing out in DNS logs.
///
/// # OPSEC considerations:
/// - DNS tunneling can be detected by volume or pattern analysis
/// - Using patterns that resemble normal DNS traffic helps avoid detection
///
/// # Returns
/// * `String` - DNS tunnel session identifier
pub fn generate_dns_tunnel_id() -> String {
    // Generate parts that look like subdomains with common patterns
    // But are actually encoding random data
    
    let alphanumeric_chars: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789";
    let mut rng = thread_rng();
    
    // First part: "cdn", "api", "www", "app", etc.
    let prefixes = ["cdn", "api", "www", "app", "static", "img", "m", "s"];
    let prefix = prefixes[rng.gen_range(0..prefixes.len())];
    
    // Second part: random alphanumeric string of length 4-6
    // Do this character by character for better readability
    let mut id_part = String::with_capacity(6);
    let len = rng.gen_range(4..=6);
    for _ in 0..len {
        id_part.push(alphanumeric_chars[rng.gen_range(0..alphanumeric_chars.len())] as char);
    }
    
    // Third part: numeric string like a date, version or cache buster
    let numeric_part = rng.gen_range(101..999);
    
    // Combine them in a way that looks like a normal subdomain
    format!("{}-{}-{}", prefix, id_part, numeric_part)
}

/// Resolves a hostname to an IP address using the system DNS resolver
///
/// # Arguments
/// * `hostname` - The hostname to resolve
///
/// # Returns
/// * `Result<IpAddr, anyhow::Error>` - The resolved IP address or an error
///
/// # OPSEC Considerations
/// - DNS queries can sometimes be monitored by defenders
/// - Using the system resolver is less suspicious than custom DNS configurations
pub async fn resolve_hostname(hostname: &str) -> Result<IpAddr, anyhow::Error> {
    // Try to parse as IP address first - no DNS query needed
    if let Ok(ip) = hostname.parse::<IpAddr>() {
        return Ok(ip);
    }
    
    // Use tokio's DNS resolver which is simpler than dealing with hickory-resolver API changes
    match tokio::net::lookup_host(format!("{}:0", hostname)).await {
        Ok(mut addrs) => {
            // Try to find an IPv4 address first, then fall back to any address
            let ip = addrs.find(|addr| addr.ip().is_ipv4())
                .or_else(|| addrs.next())
                .map(|addr| addr.ip())
                .ok_or_else(|| anyhow!("No IP addresses found for hostname: {}", hostname))?;
            
            debug!("Resolved hostname {} to {}", hostname, ip);
            Ok(ip)
        },
        Err(e) => {
            Err(anyhow!("DNS resolution failed for {}: {}", hostname, e))
        }
    }
}

/// Extract MariaDB version from a server banner
///
/// # Arguments
/// * `banner` - The server banner string
///
/// # Returns
/// * `Option<String>` - The extracted version or None if not found
pub fn extract_mariadb_version(banner: &str) -> Option<String> {
    // Match patterns like "mariadb-10.5.12"
    let re = regex::Regex::new(r"mariadb[-\s]+(\d+\.\d+\.\d+[\w\.-]*)").ok()?;
    re.captures(banner).map(|caps| format!("MariaDB {}", &caps[1]))
}

/// Extract PostgreSQL version from a server banner
///
/// # Arguments
/// * `banner` - The server banner string
///
/// # Returns
/// * `Option<String>` - The extracted version or None if not found
pub fn extract_postgresql_version(banner: &str) -> Option<String> {
    // Match patterns like "PostgreSQL 12.7"
    let re = regex::Regex::new(r"postgresql\s+(\d+(?:\.\d+)*)").ok()?;
    re.captures(&banner.to_lowercase()).map(|caps| format!("PostgreSQL {}", &caps[1]))
}

/// Send an ICMP packet with a custom payload to a target
/// 
/// # OPSEC considerations:
/// - Sending custom ICMP packets may trigger network monitoring systems
/// - Limit frequency and target selection to reduce detection
pub fn send_icmp_packet(target_ip: IpAddr, payload: &[u8], ttl: u8) -> Result<bool, anyhow::Error> {
    // Log the operation
    debug!("Sending ICMP packet to {} with TTL {} and {} bytes payload", target_ip, ttl, payload.len());
    
    // Create a transport channel for sending ICMP packets
    let protocol = match target_ip {
        IpAddr::V4(_) => TransportChannelType::Layer4(TransportProtocol::Ipv4(IpNextHeaderProtocols::Icmp)),
        IpAddr::V6(_) => TransportChannelType::Layer4(TransportProtocol::Ipv6(IpNextHeaderProtocols::Icmpv6)),
    };
    
    let (mut tx, _) = match transport_channel(4096, protocol) {
        Ok((tx, rx)) => (tx, rx),
        Err(e) => return Err(anyhow!("Failed to create transport channel for ICMP: {}", e)),
    };
    
    // If payload is too short, add random padding to make it look like normal ICMP traffic
    // This is done to avoid suspicion from network monitoring systems
    let mut extended_payload = payload.to_vec();
    if extended_payload.len() < 16 {
        let mut rng = thread_rng();
        let padding_size = 16 - extended_payload.len();
        for _ in 0..padding_size {
            extended_payload.push(rng.gen());
        }
    }
    
    match target_ip {
        IpAddr::V4(_) => {
            // Create an ICMP echo request packet (ping)
            let mut icmp_buffer = vec![0u8; 8 + extended_payload.len()];
            let mut icmp_packet = MutableIcmpPacket::new(&mut icmp_buffer)
                .ok_or(anyhow!("Failed to create ICMP packet"))?;
            
            // Set ICMP header fields
            icmp_packet.set_icmp_type(IcmpTypes::EchoRequest);
            icmp_packet.set_icmp_code(IcmpCode::new(0));
            
            // Set a random identifier and sequence for the echo request
            let ident = random_high_port();
            let seq = thread_rng().gen::<u16>();
            
            // Create a temporary buffer for the full payload
            let mut full_payload = Vec::with_capacity(4 + extended_payload.len());
            
            // Add the identifier and sequence
            full_payload.extend_from_slice(&ident.to_be_bytes());
            full_payload.extend_from_slice(&seq.to_be_bytes());
            
            // Add the actual payload
            full_payload.extend_from_slice(&extended_payload);
            
            // Set the payload
            icmp_packet.set_payload(&full_payload);
            
            // Calculate the ICMP checksum
            let checksum = pnet::packet::icmp::checksum(&icmp_packet.to_immutable());
            icmp_packet.set_checksum(checksum);
            
            // Send the ICMP packet
            match tx.send_to(icmp_packet, target_ip) {
                Ok(_) => Ok(true),
                Err(e) => Err(anyhow!("Failed to send ICMP packet: {}", e)),
            }
        },
        IpAddr::V6(_) => {
            // Create an ICMPv6 echo request packet
            let mut icmp_buffer = vec![0u8; 8 + extended_payload.len()];
            let mut icmp_packet = MutableIcmpv6Packet::new(&mut icmp_buffer)
                .ok_or(anyhow!("Failed to create ICMPv6 packet"))?;
            
            // Set ICMPv6 header fields
            icmp_packet.set_icmpv6_type(Icmpv6Types::EchoRequest);
            icmp_packet.set_icmpv6_code(Icmpv6Code::new(0));
            
            // Set a random identifier and sequence for the echo request
            let ident = random_high_port();
            let seq = thread_rng().gen::<u16>();
            
            // Create a temporary buffer for the full payload
            let mut full_payload = Vec::with_capacity(4 + extended_payload.len());
            
            // Add the identifier and sequence
            full_payload.extend_from_slice(&ident.to_be_bytes());
            full_payload.extend_from_slice(&seq.to_be_bytes());
            
            // Add the actual payload
            full_payload.extend_from_slice(&extended_payload);
            
            // Set the payload
            icmp_packet.set_payload(&full_payload);
            
            // ICMPv6 checksum is calculated by the kernel
            
            // Send the ICMPv6 packet
            match tx.send_to(icmp_packet, target_ip) {
                Ok(_) => Ok(true),
                Err(e) => Err(anyhow!("Failed to send ICMPv6 packet: {}", e)),
            }
        }
    }
}

/// Receive and check for ICMP packet responses 
/// 
/// # OPSEC considerations:
/// - Intercepting ICMP packets requires raw socket privileges
/// - May be detected by host-based security systems
pub fn receive_icmp_packet(target_ip: IpAddr, expected_key: &[u8]) -> Result<bool, anyhow::Error> {
    // Log the operation
    debug!("Waiting for ICMP response from {}", target_ip);
    
    // Create a transport channel for receiving ICMP packets
    let protocol = match target_ip {
        IpAddr::V4(_) => TransportChannelType::Layer4(TransportProtocol::Ipv4(IpNextHeaderProtocols::Icmp)),
        IpAddr::V6(_) => TransportChannelType::Layer4(TransportProtocol::Ipv6(IpNextHeaderProtocols::Icmpv6)),
    };
    
    let (_, mut rx) = match transport_channel(4096, protocol) {
        Ok((tx, rx)) => (tx, rx),
        Err(e) => return Err(anyhow!("Failed to create transport channel for ICMP receive: {}", e)),
    };
    
    // Create ICMP packet iterator
    match target_ip {
        IpAddr::V4(_) => {
            let mut iter = pnet::transport::icmp_packet_iter(&mut rx);
            
            // Try to receive for a limited time
            // This is a non-blocking receive with a timeout
            for _ in 0..5 {
                match iter.next() {
                    Ok((packet, addr)) => {
                        // Check if response is from our target
                        if addr == target_ip {
                            debug!("Received ICMP response from target {}", addr);
                            
                            // Analyze the packet payload to check if it contains our expected key
                            if packet.get_icmp_type() == IcmpTypes::EchoReply {
                                let payload = packet.payload();
                                
                                // Check payload length - need at least 4 bytes for key
                                if payload.len() >= expected_key.len() + 4 {
                                    // The key should be at offset 4 after ident and sequence
                                    let key_portion = &payload[4..4 + expected_key.len()];
                                    if key_portion == expected_key {
                                        return Ok(true);
                                    }
                                }
                            }
                            
                            // If we received a response but didn't match our key exactly
                            return Ok(false);
                        }
                    }
                    Err(e) => {
                        debug!("Error receiving ICMP packet: {}", e);
                        // Continue trying to receive
                    }
                }
                
                // Short delay between receive attempts
                std::thread::sleep(std::time::Duration::from_millis(100));
            }
        }
        IpAddr::V6(_) => {
            let mut iter = pnet::transport::icmpv6_packet_iter(&mut rx);
            
            // Try to receive for a limited time
            for _ in 0..5 {
                match iter.next() {
                    Ok((packet, addr)) => {
                        // Check if response is from our target
                        if addr == target_ip {
                            debug!("Received ICMPv6 response from target {}", addr);
                            
                            // Analyze the packet payload to check if it contains our expected key
                            if packet.get_icmpv6_type() == pnet::packet::icmpv6::Icmpv6Types::EchoReply {
                                let payload = packet.payload();
                                
                                // Check payload length - need at least 4 bytes for key
                                if payload.len() >= expected_key.len() + 4 {
                                    // The key should be at offset 4 after ident and sequence
                                    let key_portion = &payload[4..4 + expected_key.len()];
                                    if key_portion == expected_key {
                                        return Ok(true);
                                    }
                                }
                            }
                            
                            // If we received a response but didn't match our key exactly
                            return Ok(false);
                        }
                    }
                    Err(e) => {
                        debug!("Error receiving ICMPv6 packet: {}", e);
                        // Continue trying to receive
                    }
                }
                
                // Short delay between receive attempts
                std::thread::sleep(std::time::Duration::from_millis(100));
            }
        }
    }
    
    // If we reach here, no matching response was received
    debug!("No matching ICMP response received from {}", target_ip);
    Ok(false)
}


/// Sanitize a string for safe logging and output
/// 
/// Removes control characters and other potentially dangerous sequences.
/// 
/// # Arguments
/// * `input` - The string to sanitize
/// 
/// # Returns
/// * `String` - The sanitized string
/// 
/// # OPSEC considerations:
/// - Important for logging user-supplied data
pub fn sanitize_string(input: &str) -> String {
    // Remove control characters and other potentially dangerous characters
    let sanitized = input
        .chars()
        .filter(|&c| !c.is_control() && c != '\'' && c != '\"' && c != '\\')
        .collect::<String>();
        
    // Limit length to prevent log flooding
    if sanitized.len() > 4000 {
        sanitized[..4000].to_string() + "...(truncated)"
    } else {
        sanitized
    }
}

/// Extract MySQL version from a server banner
///
/// # Arguments
/// * `banner` - The server banner string
///
/// # Returns
/// * `Option<String>` - The extracted version or None if not found
pub fn extract_mysql_version(banner: &str) -> Option<String> {
    // Match patterns like "5.7.35-0ubuntu0.18.04.1"
    let re = regex::Regex::new(r"(\d+\.\d+\.\d+[\w\.-]*)").ok()?;
    re.captures(banner).map(|caps| caps[1].to_string())
}

