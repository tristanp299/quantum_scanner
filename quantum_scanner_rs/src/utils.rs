use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::{Duration, Instant};

use anyhow::Result;
use log::{debug, error, warn};
use pnet::datalink;
use rand::{Rng, thread_rng};

/// Get the default interface's IPv4 address
/// 
/// This function attempts to find a suitable IPv4 address for the default network interface.
/// It prioritizes non-loopback interfaces with global addresses.
///
/// # Returns
/// * `Option<IpAddr>` - The IPv4 address if found, otherwise None
pub fn get_default_interface_ipv4() -> Option<IpAddr> {
    // Get all network interfaces
    let interfaces = match datalink::interfaces() {
        Ok(i) => i,
        Err(_) => {
            warn!("Failed to get network interfaces");
            return None;
        }
    };
    
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
    let interfaces = match datalink::interfaces() {
        Ok(i) => i,
        Err(_) => {
            warn!("Failed to get network interfaces");
            return None;
        }
    };
    
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
pub fn random_high_port() -> u16 {
    thread_rng().gen_range(49152..65535)
}

/// Generate a random IP ID field value
///
/// Used for IP packet identification to maintain uniqueness.
pub fn random_ip_id() -> u16 {
    thread_rng().gen_range(1..65535)
}

/// Generate a random TCP sequence number
///
/// Used to make packets more difficult to identify as
/// coming from a scanner.
pub fn random_tcp_seq() -> u32 {
    thread_rng().gen::<u32>()
}

/// Generate a random TTL value for IP packets
///
/// When evasion is enabled, this will return one of the common OS TTL values
/// (64, 128, 255) to blend in with normal traffic.
/// Otherwise, it returns the standard value of 64.
pub fn get_ttl(evasion: bool) -> u8 {
    if evasion {
        *[64, 128, 255].choose(&mut thread_rng()).unwrap()
    } else {
        64
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
fn is_ipv4_in_range(ip: Ipv4Addr, start: Ipv4Addr, end: Ipv4Addr) -> bool {
    let ip_u32: u32 = ip.into();
    let start_u32: u32 = start.into();
    let end_u32: u32 = end.into();
    
    ip_u32 >= start_u32 && ip_u32 <= end_u32
}

/// Check if the IPv6 address is a Unique Local Address (ULA)
fn is_ipv6_ula(ip: Ipv6Addr) -> bool {
    let segments = ip.segments();
    (segments[0] & 0xfe00) == 0xfc00
}

/// Determine if scanning private networks is allowed
///
/// In a real implementation, this would check configuration options.
/// For this example, we default to false for safety.
fn is_private_allowed() -> bool {
    // This could be driven by a configuration option
    // For safety, default to false
    false
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