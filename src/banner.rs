use log::{debug, trace};
use std::net::{IpAddr, SocketAddr};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;
use anyhow::Result;

/// Grab a service banner from the specified IP address and port
/// 
/// This function attempts to connect to the given port and capture
/// any initial data sent by the service (banner). For operational security,
/// various connection strategies are used to avoid detection.
pub async fn grab_banner(target_ip: IpAddr, port: u16) -> Result<String> {
    let addr = SocketAddr::new(target_ip, port);
    trace!("Initiating service analysis on {}:{}", target_ip, port);
    
    // Use a shorter initial connection timeout (1.5 seconds instead of 3)
    let conn_result = timeout(
        std::time::Duration::from_millis(1500),
        TcpStream::connect(&addr)
    ).await;
    
    match conn_result {
        Ok(Ok(mut stream)) => {
            trace!("Connection established to {}:{}", target_ip, port);
            
            // Try different grabbing strategies based on the port
            let banner = match port {
                21 | 25 | 110 | 143 => {
                    // These protocols typically send a banner immediately
                    // Just read initial data without sending anything
                    let mut buffer = vec![0; 2048];
                    // Reduced timeout from 2 seconds to 1 second
                    let timeout_duration = std::time::Duration::from_millis(1000);
                    
                    match timeout(timeout_duration, stream.read(&mut buffer)).await {
                        Ok(Ok(n)) if n > 0 => {
                            String::from_utf8_lossy(&buffer[0..n]).to_string()
                        },
                        _ => "".to_string()
                    }
                },
                80 | 443 | 8080 | 8443 => {
                    // HTTP/HTTPS - send a minimal HTTP request
                    let request = format!(
                        "GET / HTTP/1.0\r\n\
                         Host: {}\r\n\
                         User-Agent: Mozilla/5.0\r\n\
                         Connection: close\r\n\r\n",
                        if target_ip.is_ipv4() { target_ip.to_string() } else { format!("[{}]", target_ip) }
                    );
                    
                    // Send the request with timeout
                    match timeout(
                        std::time::Duration::from_millis(1000),
                        stream.write_all(request.as_bytes())
                    ).await {
                        Ok(Ok(_)) => {
                            // Read the response
                            let mut buffer = vec![0; 4096];
                            // Reduced timeout from 3 seconds to 1.5 seconds
                            let timeout_duration = std::time::Duration::from_millis(1500);
                            
                            match timeout(timeout_duration, stream.read(&mut buffer)).await {
                                Ok(Ok(n)) if n > 0 => {
                                    String::from_utf8_lossy(&buffer[0..n]).to_string()
                                },
                                _ => "".to_string()
                            }
                        },
                        _ => "".to_string()
                    }
                },
                22 => {
                    // SSH - just read the banner, no need to send anything
                    let mut buffer = vec![0; 256];
                    // Keep SSH timeout at 1 second
                    let timeout_duration = std::time::Duration::from_secs(1);
                    
                    match timeout(timeout_duration, stream.read(&mut buffer)).await {
                        Ok(Ok(n)) if n > 0 => {
                            String::from_utf8_lossy(&buffer[0..n]).to_string()
                        },
                        _ => "".to_string()
                    }
                },
                _ => {
                    // Generic approach - try passive grabbing only without active probing
                    // which was causing hanging issues in some cases
                    
                    // First try passive grabbing (just read)
                    let mut buffer = vec![0; 1024];
                    // Reduced timeout from 800ms to 500ms
                    let timeout_duration = std::time::Duration::from_millis(500);
                    
                    match timeout(timeout_duration, stream.read(&mut buffer)).await {
                        Ok(Ok(n)) if n > 0 => {
                            String::from_utf8_lossy(&buffer[0..n]).to_string()
                        },
                        _ => "".to_string()
                    }
                    
                    // We removed the active grabbing code that was causing hangs
                }
            };
            
            if banner.is_empty() {
                debug!("No banner retrieved from {}:{}", target_ip, port);
                Ok("".to_string())
            } else {
                trace!("Banner retrieved from {}:{} ({} bytes)", target_ip, port, banner.len());
                Ok(banner)
            }
        },
        _ => {
            debug!("Failed to connect to {}:{} for banner grabbing", target_ip, port);
            Err(anyhow::anyhow!("Connection failed"))
        }
    }
}

/// Grab a service banner as raw bytes from the specified IP address and port
/// 
/// Similar to grab_banner but returns raw bytes instead of a string.
/// This is useful for binary protocols where UTF-8 conversion might lose information.
/// 
/// # Arguments
/// * `target_ip` - The IP address to connect to
/// * `port` - The port to connect to
/// * `timeout_duration` - The timeout duration for the operation
/// 
/// # Returns
/// * `Result<Vec<u8>>` - The raw banner bytes or an error
pub async fn grab_banner_raw(target_ip: IpAddr, port: u16, timeout_duration: std::time::Duration) -> Result<Vec<u8>> {
    let addr = SocketAddr::new(target_ip, port);
    trace!("Initiating raw banner grab on {}:{}", target_ip, port);
    
    // Connect with timeout
    let conn_result = timeout(
        timeout_duration,
        TcpStream::connect(&addr)
    ).await;
    
    match conn_result {
        Ok(Ok(mut stream)) => {
            trace!("Connection established to {}:{} for raw banner grab", target_ip, port);
            
            // Try different grabbing strategies based on the port
            let banner = match port {
                21 | 25 | 110 | 143 => {
                    // These protocols typically send a banner immediately
                    // Just read initial data without sending anything
                    let mut buffer = vec![0; 2048];
                    
                    match timeout(timeout_duration, stream.read(&mut buffer)).await {
                        Ok(Ok(n)) if n > 0 => buffer[0..n].to_vec(),
                        _ => Vec::new()
                    }
                },
                80 | 443 | 8080 | 8443 => {
                    // HTTP/HTTPS - send a minimal HTTP request
                    let request = format!(
                        "GET / HTTP/1.0\r\n\
                         Host: {}\r\n\
                         User-Agent: Mozilla/5.0\r\n\
                         Connection: close\r\n\r\n",
                        if target_ip.is_ipv4() { target_ip.to_string() } else { format!("[{}]", target_ip) }
                    );
                    
                    // Send the request with timeout
                    match timeout(
                        timeout_duration,
                        stream.write_all(request.as_bytes())
                    ).await {
                        Ok(Ok(_)) => {
                            // Read the response
                            let mut buffer = vec![0; 4096];
                            
                            match timeout(timeout_duration, stream.read(&mut buffer)).await {
                                Ok(Ok(n)) if n > 0 => buffer[0..n].to_vec(),
                                _ => Vec::new()
                            }
                        },
                        _ => Vec::new()
                    }
                },
                22 => {
                    // SSH - just read the banner, no need to send anything
                    let mut buffer = vec![0; 256];
                    
                    match timeout(timeout_duration, stream.read(&mut buffer)).await {
                        Ok(Ok(n)) if n > 0 => buffer[0..n].to_vec(),
                        _ => Vec::new()
                    }
                },
                _ => {
                    // Generic approach - try passive grabbing 
                    let mut buffer = vec![0; 1024];
                    
                    match timeout(timeout_duration, stream.read(&mut buffer)).await {
                        Ok(Ok(n)) if n > 0 => buffer[0..n].to_vec(),
                        _ => Vec::new()
                    }
                }
            };
            
            if banner.is_empty() {
                debug!("No raw banner retrieved from {}:{}", target_ip, port);
                Ok(Vec::new())
            } else {
                trace!("Raw banner retrieved from {}:{} ({} bytes)", target_ip, port, banner.len());
                Ok(banner)
            }
        },
        _ => {
            debug!("Failed to connect to {}:{} for raw banner grabbing", target_ip, port);
            Err(anyhow::anyhow!("Connection failed"))
        }
    }
}

/// Identify service from a banner string
///
/// This function analyzes a service banner to determine the service type.
/// It uses pattern matching against common service signatures.
pub fn identify_service_from_banner(banner: &str, port: u16) -> Option<String> {
    // Check if banner is empty
    if banner.is_empty() {
        return None;
    }
    
    // For operational security, log with minimal information
    debug!("Analyzing service response on port {}", port);
    
    // Convert to lowercase for case-insensitive matching
    let banner_lower = banner.to_lowercase();
    
    // HTTP/HTTPS
    if banner_lower.starts_with("http/") || banner_lower.contains("server:") {
        return Some("http".to_string());
    }
    
    // SSH
    if banner_lower.contains("ssh-") || banner_lower.contains("openssh") {
        return Some("ssh".to_string());
    }
    
    // FTP
    if banner_lower.contains("ftp") || banner_lower.starts_with("220 ") {
        return Some("ftp".to_string());
    }
    
    // SMTP
    if banner_lower.contains("smtp") || banner_lower.starts_with("220 ") && 
       (banner_lower.contains("mail") || banner_lower.contains("smtp")) {
        return Some("smtp".to_string());
    }
    
    // POP3
    if banner_lower.contains("pop3") || banner_lower.starts_with("+ok") {
        return Some("pop3".to_string());
    }
    
    // IMAP
    if banner_lower.contains("imap") || banner_lower.starts_with("* ok") {
        return Some("imap".to_string());
    }
    
    // MySQL
    if banner_lower.contains("mysql") || banner.contains("\u{0000}\u{0000}\u{0000}\u{0000}\u{000a}") {
        return Some("mysql".to_string());
    }
    
    // PostgreSQL
    if banner_lower.contains("postgresql") {
        return Some("postgresql".to_string());
    }
    
    // If no match based on banner, use port-based fallback
    let port_service = match port {
        21 => Some("ftp"),
        22 => Some("ssh"),
        23 => Some("telnet"),
        25 => Some("smtp"),
        80 => Some("http"),
        110 => Some("pop3"),
        143 => Some("imap"),
        443 => Some("https"),
        3306 => Some("mysql"),
        5432 => Some("postgresql"),
        8080 => Some("http-alt"),
        _ => None
    };
    
    port_service.map(|s| s.to_string())
}

/// Display the scanner's banner on program start
///
/// This function returns a string containing the ASCII art banner for the scanner.
/// If colors are enabled, ANSI color codes are included.
///
/// # Arguments
/// * `use_colors` - Whether to include ANSI color codes in the output
///
/// # Returns
/// * `String` - The formatted banner text
pub fn display_banner(use_colors: bool) -> String {
    if use_colors {
        let blue = "\x1b[0;34m";
        let green = "\x1b[0;32m";
        let yellow = "\x1b[1;33m";
        let reset = "\x1b[0m";
        
        format!(
            "{blue}=========================================================={reset}\n\
            {green}  ██████  ██    ██  █████  ███    ██ ████████ ██    ██ ███    ███{reset}\n\
            {green} ██    ██ ██    ██ ██   ██ ████   ██    ██    ██    ██ ████  ████{reset}\n\
            {green} ██    ██ ██    ██ ███████ ██ ██  ██    ██    ██    ██ ██ ████ ██{reset}\n\
            {green} ██ ▄▄ ██ ██    ██ ██   ██ ██  ██ ██    ██    ██    ██ ██  ██  ██{reset}\n\
            {green}  ██████   ██████  ██   ██ ██   ████    ██     ██████  ██      ██{reset}\n\
            {green}     ▀▀                                                          {reset}\n\
            {blue}  SCANNER | RS Edition | Red Team Network Intelligence Tool{reset}\n\
            {blue}=========================================================={reset}\n\
            {yellow}  [!] OpSec-Enhanced Port Scanner and Service Identifier{reset}\n\
            {blue}=========================================================={reset}\n"
        )
    } else {
        String::from(
            "==========================================================\n\
              ██████  ██    ██  █████  ███    ██ ████████ ██    ██ ███    ███\n\
             ██    ██ ██    ██ ██   ██ ████   ██    ██    ██    ██ ████  ████\n\
             ██    ██ ██    ██ ███████ ██ ██  ██    ██    ██    ██ ██ ████ ██\n\
             ██ ▄▄ ██ ██    ██ ██   ██ ██  ██ ██    ██    ██    ██ ██  ██  ██\n\
              ██████   ██████  ██   ██ ██   ████    ██     ██████  ██      ██\n\
                 ▀▀                                                          \n\
              SCANNER | RS Edition | Red Team Network Intelligence Tool\n\
            ==========================================================\n\
              [!] OpSec-Enhanced Port Scanner and Service Identifier\n\
            ==========================================================\n"
        )
    }
} 