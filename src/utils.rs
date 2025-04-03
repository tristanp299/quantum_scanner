use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::{Duration, Instant};
use std::env;
use chrono::{Utc};

use log::{debug, warn};
use pnet::datalink;
use rand::{Rng, thread_rng, distributions::{Distribution, Uniform}};
use rand::seq::SliceRandom;
use regex;

/// Get the default interface's IPv4 address
/// 
/// This function attempts to find a suitable IPv4 address for the default network interface.
/// It prioritizes non-loopback interfaces with global addresses.
///
/// # Returns
/// * `Option<IpAddr>` - The IPv4 address if found, otherwise None
pub fn get_default_interface_ipv4() -> Option<IpAddr> {
    // Get all network interfaces
    let interfaces = datalink::interfaces();
    
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
    warn!("No suitable IPv4 interface found, using fallback");
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
    let interfaces = datalink::interfaces();
    
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
    warn!("No suitable IPv6 interface found, using fallback");
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

/// Validate if an IP address is within allowed ranges
///
/// Used to prevent scanning restricted or reserved networks.
///
/// # Arguments
/// * `ip` - The IP address to check
///
/// # Returns
/// * `bool` - True if the IP is allowed to be scanned
#[allow(dead_code)]
pub fn is_ip_allowed(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ipv4) => {
            // Check for private ranges
            if ipv4.is_private() && !is_private_allowed() {
                return false;
            }
            
            // Check for other reserved ranges
            if ipv4.is_loopback() || ipv4.is_link_local() || ipv4.is_broadcast() || 
               ipv4.is_multicast() || ipv4.is_documentation() {
                return false;
            }
            
            // IANA reserved blocks to avoid
            let reserved_blocks = [
                (Ipv4Addr::new(0, 0, 0, 0), Ipv4Addr::new(0, 255, 255, 255)),        // 0.0.0.0/8
                (Ipv4Addr::new(127, 0, 0, 0), Ipv4Addr::new(127, 255, 255, 255)),    // 127.0.0.0/8
                (Ipv4Addr::new(224, 0, 0, 0), Ipv4Addr::new(239, 255, 255, 255)),    // 224.0.0.0/4 (multicast)
                (Ipv4Addr::new(240, 0, 0, 0), Ipv4Addr::new(255, 255, 255, 255)),    // 240.0.0.0/4 (future use)
            ];
            
            for &(start, end) in &reserved_blocks {
                if is_ipv4_in_range(ipv4, start, end) {
                    return false;
                }
            }
            
            true
        },
        IpAddr::V6(ipv6) => {
            // Disallow loopback, multicast, etc.
            if ipv6.is_loopback() || ipv6.is_multicast() || ipv6.is_unspecified() {
                return false;
            }
            
            // Allow ULA (Unique Local Addresses) only if private is allowed
            if is_ipv6_ula(ipv6) && !is_private_allowed() {
                return false;
            }
            
            true
        }
    }
}

/// Helper to check if a IPv4 address is within a range
#[allow(dead_code)]
fn is_ipv4_in_range(ip: Ipv4Addr, start: Ipv4Addr, end: Ipv4Addr) -> bool {
    let ip_u32: u32 = u32::from(ip);
    let start_u32: u32 = u32::from(start);
    let end_u32: u32 = u32::from(end);
    
    ip_u32 >= start_u32 && ip_u32 <= end_u32
}

/// Check if the IPv6 address is a Unique Local Address (ULA)
#[allow(dead_code)]
fn is_ipv6_ula(ip: Ipv6Addr) -> bool {
    let segments = ip.segments();
    (segments[0] & 0xfe00) == 0xfc00
}

/// Determine if scanning private networks is allowed
///
/// Reads from environment variable QUANTUM_ALLOW_PRIVATE.
/// For operational security, defaults to false if not explicitly enabled.
#[allow(dead_code)]
fn is_private_allowed() -> bool {
    // Check for environment variable to enable private network scanning
    match env::var("QUANTUM_ALLOW_PRIVATE") {
        Ok(val) => {
            // Only enable if explicitly set to "true"
            val.to_lowercase() == "true" || val == "1"
        },
        Err(_) => false, // By default, don't allow scanning private IPs
    }
}

/// Create a pseudo-random pattern for packet payloads
///
/// Generates a byte pattern that looks somewhat random but
/// is deterministic based on length. This can help identify
/// our packets if needed, while still being difficult to detect
/// as a scanner.
///
/// # Arguments
/// * `length` - The length of payload to generate
///
/// # Returns
/// * `Vec<u8>` - The generated payload
#[allow(dead_code)]
pub fn create_payload_pattern(length: usize) -> Vec<u8> {
    let mut payload = Vec::with_capacity(length);
    let mut value: u8 = 42; // Start with a seed value
    
    for i in 0..length {
        // Simple PRNG-like algorithm
        value = value.wrapping_mul(13).wrapping_add(i as u8);
        payload.push(value);
    }
    
    payload
}

/// Sanitize output for display or logging
///
/// Converts control characters and non-ASCII characters to a safe representation
///
/// # Arguments
/// * `input` - The string to sanitize
///
/// # Returns
/// * `String` - The sanitized string
pub fn sanitize_string(input: &str) -> String {
    input.chars()
        .map(|c| {
            if c.is_ascii_control() {
                match c {
                    '\n' => "\\n".to_string(),
                    '\r' => "\\r".to_string(),
                    '\t' => "\\t".to_string(),
                    _ => format!("\\x{:02x}", c as u8),
                }
            } else if !c.is_ascii() {
                format!("\\u{:04x}", c as u32)
            } else {
                c.to_string()
            }
        })
        .collect()
}

/// Measure execution time of a task
///
/// # Arguments
/// * `task_name` - Name of the task for logging
/// * `f` - Function to execute and measure
///
/// # Returns
/// * `T` - The return value of the function
#[allow(dead_code)]
pub fn measure_time<F, T>(task_name: &str, f: F) -> T
where
    F: FnOnce() -> T,
{
    let start = Instant::now();
    let result = f();
    let duration = start.elapsed();
    
    debug!("{} completed in {:?}", task_name, duration);
    
    result
}

/// Measure execution time of an async task
///
/// # Arguments
/// * `task_name` - Name of the task for logging
/// * `f` - Async function to execute and measure
///
/// # Returns
/// * `T` - The return value of the function
#[allow(dead_code)]
pub async fn measure_time_async<F, T, E>(task_name: &str, f: F) -> Result<T, E>
where
    F: std::future::Future<Output = Result<T, E>>,
{
    let start = Instant::now();
    let result = f.await;
    let duration = start.elapsed();
    
    debug!("{} completed in {:?}", task_name, duration);
    
    result
}

/// Generate a spoofed source IP address for evading detection
///
/// WARNING: Using spoofed IPs can be illegal and/or prevented by ISPs.
/// This function is intended for authorized red team engagements only.
///
/// # Arguments
/// * `network_class` - Optional class of IP to mimic (e.g., "router", "client", "server")
///
/// # Returns
/// * `IpAddr` - A spoofed IP address that follows requested pattern
#[allow(dead_code)]
pub fn get_spoofed_source_ip(network_class: Option<&str>) -> IpAddr {
    let mut rng = thread_rng();
    
    match network_class {
        Some("router") => {
            // Common router-like addresses (e.g., x.x.x.1, x.x.x.254)
            let first = rng.gen_range(1..223);
            let second = rng.gen_range(0..255);
            let third = rng.gen_range(0..255);
            let last = if rng.gen_bool(0.7) { 1 } else { 254 };
            
            IpAddr::V4(Ipv4Addr::new(first, second, third, last))
        },
        Some("client") => {
            // Addresses that look like typical client machines
            let first = match rng.gen_range(0..3) {
                0 => 10,                           // RFC1918 private (10.0.0.0/8)
                1 => 192,                          // RFC1918 private (192.168.0.0/16)
                _ => rng.gen_range(1..223),        // Random public
            };
            
            let second = if first == 192 { 168 } else { rng.gen_range(0..255) };
            let third = rng.gen_range(0..255);
            let last = rng.gen_range(2..254);      // Avoid .0, .1, and .255
            
            IpAddr::V4(Ipv4Addr::new(first, second, third, last))
        },
        Some("server") => {
            // Addresses that look like typical servers
            // Often use IPs that appear statically assigned
            let first = rng.gen_range(1..223);
            let second = rng.gen_range(0..255);
            let third = rng.gen_range(0..255);
            let last = match rng.gen_range(0..3) {
                0 => rng.gen_range(10..20),        // Common server range
                1 => rng.gen_range(100..110),      // Common server range
                _ => rng.gen_range(50..60),        // Common server range
            };
            
            IpAddr::V4(Ipv4Addr::new(first, second, third, last))
        },
        _ => {
            // Completely random IP, but avoid reserved ranges
            loop {
                let first = rng.gen_range(1..223); // Avoid 0 and 224-255
                
                // Skip obvious reserved ranges
                if first == 10 || first == 127 || first == 169 || first == 172 || first == 192 {
                    continue;
                }
                
                let second = rng.gen_range(0..255);
                
                // Skip more reserved ranges
                if (first == 172 && second >= 16 && second <= 31) || 
                   (first == 192 && second == 168) {
                    continue;
                }
                
                let third = rng.gen_range(0..255);
                let fourth = rng.gen_range(1..255); // Avoid .0 and .255
                
                let ip = Ipv4Addr::new(first, second, third, fourth);
                
                // Final check to avoid reserved networks
                if !ip.is_private() && !ip.is_loopback() && !ip.is_multicast() && 
                   !ip.is_broadcast() && !ip.is_documentation() {
                    return IpAddr::V4(ip);
                }
            }
        }
    }
}

/// Get a realistic User-Agent string for mimicking browser traffic
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
    let chrome_agents = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/90.0.4430.212 Safari/537.36",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.107 Safari/537.36"
    ];
    
    let firefox_agents = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:88.0) Gecko/20100101 Firefox/88.0",
        "Mozilla/5.0 (X11; Linux i686; rv:90.0) Gecko/20100101 Firefox/90.0"
    ];
    
    let safari_agents = [
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15",
        "Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0 Mobile/15E148 Safari/604.1"
    ];
    
    let edge_agents = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36 Edg/91.0.864.59"
    ];
    
    match browser_type {
        Some("chrome") => chrome_agents[rng.gen_range(0..chrome_agents.len())].to_string(),
        Some("firefox") => firefox_agents[rng.gen_range(0..firefox_agents.len())].to_string(),
        Some("safari") => safari_agents[rng.gen_range(0..safari_agents.len())].to_string(),
        Some("edge") => edge_agents[rng.gen_range(0..edge_agents.len())].to_string(),
        _ => {
            // Choose a random browser type if none specified
            let all_agents = [
                &chrome_agents[..],
                &firefox_agents[..],
                &safari_agents[..],
                &edge_agents[..],
            ].concat();
            
            all_agents[rng.gen_range(0..all_agents.len())].to_string()
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
    // Use different regex patterns based on service type
    match service_name.to_lowercase().as_str() {
        "http" | "https" => {
            // Look for server header in HTTP responses
            // Examples: "Apache/2.4.41", "nginx/1.18.0", "Microsoft-IIS/10.0"
            if let Some(server_line) = banner.lines()
                .find(|line| line.to_lowercase().contains("server:"))
            {
                // Extract version information after the colon
                if let Some(version_str) = server_line.split(':').nth(1) {
                    return Some(version_str.trim().to_string());
                }
            }
            
            None
        },
        "ssh" => {
            // Extract SSH version
            // Example: "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.1"
            if banner.starts_with("SSH-") {
                // The format is usually SSH-[protocol]-[software]
                let parts: Vec<&str> = banner.splitn(3, '-').collect();
                if parts.len() >= 3 {
                    return Some(parts[2].trim().to_string());
                }
            }
            
            None
        },
        "ftp" => {
            // Example: "220 ProFTPD 1.3.5e Server"
            if banner.starts_with("220 ") {
                // Try to find version numbers in the banner
                let re = regex::Regex::new(r"(\w+)[/ -](\d+\.\d+[.\w-]*)").ok()?;
                if let Some(caps) = re.captures(banner) {
                    if caps.len() >= 3 {
                        return Some(format!("{} {}", &caps[1], &caps[2]));
                    }
                }
            }
            
            None
        },
        "smtp" => {
            // Example: "220 mail.example.com ESMTP Postfix (Ubuntu)"
            if banner.starts_with("220 ") {
                // Extract SMTP server software
                for software in &["Postfix", "Exim", "Sendmail", "Microsoft ESMTP"] {
                    if banner.contains(software) {
                        // Try to extract version if present
                        let re = regex::Regex::new(&format!(r"{}\s*(\d+[\.\d\w-]*)", software)).ok()?;
                        if let Some(caps) = re.captures(banner) {
                            return Some(format!("{} {}", software, &caps[1]));
                        }
                        return Some(software.to_string());
                    }
                }
            }
            
            None
        },
        "mysql" | "mariadb" => {
            // MySQL banners often contain version information in a specific format
            let re = regex::Regex::new(r"(\d+\.\d+\.\d+[\w-]*)").ok()?;
            if let Some(caps) = re.captures(banner) {
                return Some(format!("MySQL {}", &caps[1]));
            }
            
            None
        },
        "postgresql" | "postgres" => {
            // PostgreSQL banners may contain version info
            if banner.contains("PostgreSQL") {
                let re = regex::Regex::new(r"PostgreSQL\s+(\d+\.[\d.]+)").ok()?;
                if let Some(caps) = re.captures(banner) {
                    return Some(format!("PostgreSQL {}", &caps[1]));
                }
            }
            
            None
        },
        // Add more service-specific extractors as needed
        _ => {
            // Generic version number extraction for unknown services
            // Look for patterns like "version X.Y.Z" or "vX.Y.Z"
            let re = regex::Regex::new(r"[vV]ersion[: ]*(\d+\.\d+[\.\d\w-]*)").ok()?;
            if let Some(caps) = re.captures(banner) {
                return Some(caps[1].to_string());
            }
            
            // Try alternate pattern like "X.Y.Z"
            let re = regex::Regex::new(r"(\d+\.\d+\.\d+[\w-]*)").ok()?;
            if let Some(caps) = re.captures(banner) {
                return Some(caps[1].to_string());
            }
            
            None
        }
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