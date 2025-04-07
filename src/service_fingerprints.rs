use std::collections::HashMap;
use regex::Regex;
use log::{debug, info};

/// Service fingerprint database for identifying services and versions
#[allow(dead_code)]
pub struct ServiceFingerprints {
    /// Map of service signatures by port
    port_signatures: HashMap<u16, Vec<(String, String)>>,
    /// Map of pattern-based signatures
    pattern_signatures: Vec<(Regex, String, String)>,
}

impl ServiceFingerprints {
    /// Create a new fingerprint database with common services
    #[allow(dead_code)]
    pub fn new() -> Self {
        let mut port_signatures = HashMap::new();
        let mut pattern_signatures = Vec::new();
        
        // Add common port-based signatures
        
        // FTP signatures
        port_signatures.insert(21, vec![
            ("FTP".to_string(), "220.*FileZilla".to_string()),
            ("FTP".to_string(), "220.*ProFTPD".to_string()),
            ("FTP".to_string(), "220.*vsFTPd".to_string()),
            ("FTP".to_string(), "220.*Pure-FTPd".to_string()),
            ("FTP".to_string(), "220.*FTP server".to_string()),
        ]);
        
        // SSH signatures
        port_signatures.insert(22, vec![
            ("SSH".to_string(), "SSH-2.0-OpenSSH".to_string()),
            ("SSH".to_string(), "SSH-1.99-OpenSSH".to_string()),
            ("SSH".to_string(), "SSH-2.0-dropbear".to_string()),
        ]);
        
        // Telnet signatures
        port_signatures.insert(23, vec![
            ("Telnet".to_string(), ".*Welcome to.*telnet".to_string()),
            ("Telnet".to_string(), ".*login:".to_string()),
            ("Telnet".to_string(), ".*Username:".to_string()),
        ]);
        
        // SMTP signatures
        port_signatures.insert(25, vec![
            ("SMTP".to_string(), "220.*ESMTP".to_string()),
            ("SMTP".to_string(), "220.*Postfix".to_string()),
            ("SMTP".to_string(), "220.*Sendmail".to_string()),
            ("SMTP".to_string(), "220.*Exim".to_string()),
            ("SMTP".to_string(), "220.*SMTP".to_string()),
        ]);
        
        // HTTP/HTTPS signatures
        port_signatures.insert(80, vec![
            ("HTTP".to_string(), "HTTP/1".to_string()),
            ("HTTP".to_string(), "HTTP/2".to_string()),
        ]);
        
        port_signatures.insert(443, vec![
            ("HTTPS".to_string(), "HTTP/1".to_string()),
            ("HTTPS".to_string(), "HTTP/2".to_string()),
        ]);
        
        // Add more complex pattern-based signatures
        let pattern_defs = [
            // SSH patterns
            (r"SSH-2\.0-OpenSSH_([0-9\.]+)", "SSH", "OpenSSH $1"),
            (r"SSH-2\.0-dropbear_([0-9\.]+)", "SSH", "Dropbear SSH $1"),
            
            // FTP patterns
            (r"220.*FTP.*\nVSFTPD ([0-9\.]+)", "FTP", "vsFTPd $1"),
            (r"220.*FileZilla Server\s+version\s+([0-9\.]+)", "FTP", "FileZilla Server $1"),
            (r"220.*ProFTPD\s+([0-9\.]+)", "FTP", "ProFTPD $1"),
            
            // HTTP server patterns
            (r"Server: Apache/([0-9\.]+)", "HTTP", "Apache $1"),
            (r"Server: nginx/([0-9\.]+)", "HTTP", "nginx $1"),
            (r"Server: Microsoft-IIS/([0-9\.]+)", "HTTP", "IIS $1"),
            (r"Server: lighttpd/([0-9\.]+)", "HTTP", "lighttpd $1"),
            
            // Web application patterns
            (r"X-Powered-By: PHP/([0-9\.]+)", "HTTP", "PHP $1"),
            (r"X-Powered-By: ASP\.NET", "HTTP", "ASP.NET"),
            
            // Mail server patterns
            (r"220.*ESMTP\s+Postfix", "SMTP", "Postfix"),
            (r"220.*ESMTP\s+Sendmail\s+([0-9\.]+)", "SMTP", "Sendmail $1"),
            (r"220.*ESMTP\s+Exim\s+([0-9\.]+)", "SMTP", "Exim $1"),
            
            // Database patterns
            (r"MySQL.*?([0-9]+\.[0-9]+\.[0-9]+)", "MySQL", "MySQL $1"),
            (r"PostgreSQL\s+([0-9\.]+)", "PostgreSQL", "PostgreSQL $1"),
        ];
        
        for (pattern, service, version_format) in pattern_defs.iter() {
            if let Ok(re) = Regex::new(pattern) {
                pattern_signatures.push((re, service.to_string(), version_format.to_string()));
            } else {
                debug!("Failed to compile regex pattern: {}", pattern);
            }
        }
        
        Self {
            port_signatures,
            pattern_signatures,
        }
    }
    
    /// Identify service from a banner on a specific port
    #[allow(dead_code)]
    pub fn identify_service(&self, port: u16, banner: &str) -> Option<(String, Option<String>)> {
        debug!("Attempting to identify service on port {} from banner", port);
        
        // First try port-specific signatures
        if let Some(signatures) = self.port_signatures.get(&port) {
            for (service, pattern) in signatures {
                if let Ok(re) = Regex::new(&pattern) {
                    if re.is_match(banner) {
                        debug!("Matched port-specific signature for {} on port {}", service, port);
                        return Some((service.clone(), None));
                    }
                }
            }
        }
        
        // Then try all pattern signatures for version detection
        for (pattern, service, version_format) in &self.pattern_signatures {
            if let Some(captures) = pattern.captures(banner) {
                debug!("Matched pattern signature for {}", service);
                
                let mut version = version_format.clone();
                
                // Replace capture groups in version format
                for i in 1..captures.len() {
                    if let Some(m) = captures.get(i) {
                        version = version.replace(&format!("${}", i), m.as_str());
                    }
                }
                
                if version == *version_format {
                    // No replacements were made, return without version
                    return Some((service.clone(), None));
                } else {
                    // Replacements were made, return with version
                    info!("Detected service {} version {}", service, version);
                    return Some((service.clone(), Some(version)));
                }
            }
        }
        
        // Default well-known port mappings as fallback
        match port {
            21 => Some(("FTP".to_string(), None)),
            22 => Some(("SSH".to_string(), None)),
            23 => Some(("Telnet".to_string(), None)),
            25 => Some(("SMTP".to_string(), None)),
            53 => Some(("DNS".to_string(), None)),
            80 => Some(("HTTP".to_string(), None)),
            110 => Some(("POP3".to_string(), None)),
            143 => Some(("IMAP".to_string(), None)),
            443 => Some(("HTTPS".to_string(), None)),
            465 => Some(("SMTPS".to_string(), None)),
            993 => Some(("IMAPS".to_string(), None)),
            995 => Some(("POP3S".to_string(), None)),
            3306 => Some(("MySQL".to_string(), None)),
            3389 => Some(("RDP".to_string(), None)),
            5432 => Some(("PostgreSQL".to_string(), None)),
            8080 => Some(("HTTP-ALT".to_string(), None)),
            _ => None
        }
    }
    
    /// Get appropriate service probe for a port
    #[allow(dead_code)]
    pub fn get_service_probe(&self, port: u16) -> Vec<u8> {
        match port {
            21 => b"USER anonymous\r\n".to_vec(),
            22 => b"SSH-2.0-OpenSSH_8.4p1\r\n".to_vec(),
            23 => b"\r\n".to_vec(),
            25 => b"EHLO test\r\n".to_vec(),
            80 | 443 | 8080 | 8443 => 
                b"GET / HTTP/1.1\r\nHost: localhost\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36\r\nAccept: */*\r\nConnection: close\r\n\r\n".to_vec(),
            110 => b"USER test\r\n".to_vec(),
            143 => b"A001 CAPABILITY\r\n".to_vec(),
            _ => Vec::new(),
        }
    }
    
    /// Test if a port is likely to be the expected service based on pattern
    #[allow(dead_code)]
    pub fn test_service_response(&self, port: u16, data: &[u8]) -> bool {
        if data.is_empty() {
            return false;
        }
        
        if let Ok(str_data) = std::str::from_utf8(data) {
            // Check against common patterns for this port
            match port {
                21 => str_data.starts_with("220 ") && 
                     (str_data.contains("FTP") || str_data.contains("ftp")),
                22 => str_data.starts_with("SSH-"),
                23 => str_data.contains("login:") || str_data.contains("Username:"),
                25 => str_data.starts_with("220 ") && 
                     (str_data.contains("SMTP") || str_data.contains("mail")),
                80 | 443 | 8080 | 8443 => str_data.starts_with("HTTP/") ||
                                         str_data.contains("<html") || 
                                         str_data.contains("<HTML"),
                110 => str_data.starts_with("+OK"),
                143 => str_data.starts_with("* OK"),
                _ => false
            }
        } else {
            // Binary data - could be a binary protocol
            // For now, just return true for SSL/TLS ports with non-empty data
            port == 443 || port == 465 || port == 993 || port == 995 || port == 8443
        }
    }
}

/// Identify a service based on port, banner, and certificate info
/// 
/// This is a high-level wrapper around the ServiceFingerprints struct
/// that identifies services and their versions from banner data.
/// 
/// # Arguments
/// * `port` - The port number
/// * `banner` - Optional banner text
/// * `cert_info` - Optional SSL/TLS certificate information
/// 
/// # Returns
/// * `(Option<String>, Option<String>)` - (service name, version) tuple
pub fn identify_service(
    port: u16,
    banner: Option<&str>,
    cert_info: Option<&crate::models::CertificateInfo>,
) -> (Option<String>, Option<String>) {
    // Create fingerprint database
    let fingerprints = ServiceFingerprints::new();
    
    // Try to identify from banner if available
    if let Some(banner_text) = banner {
        if let Some((service, version)) = fingerprints.identify_service(port, banner_text) {
            return (Some(service), version);
        }
    }
    
    // Try to identify from certificate if available
    if let Some(cert) = cert_info {
        // If we have a certificate, this is likely a TLS service
        // Try to identify specifically based on common subjectAltNames
        if cert.alt_names.iter().any(|name| name.contains("smtp") || name.contains("mail")) {
            return (Some("smtps".to_string()), None);
        } else if cert.alt_names.iter().any(|name| name.contains("imap")) {
            return (Some("imaps".to_string()), None);
        } else if cert.alt_names.iter().any(|name| name.contains("pop3")) {
            return (Some("pop3s".to_string()), None);
        } else if port == 443 || port == 8443 {
            return (Some("https".to_string()), None);
        } else {
            return (Some("tls-service".to_string()), None);
        }
    }
    
    // Default identification based on well-known ports
    match port {
        21 => (Some("ftp".to_string()), None),
        22 => (Some("ssh".to_string()), None),
        23 => (Some("telnet".to_string()), None),
        25 => (Some("smtp".to_string()), None),
        53 => (Some("dns".to_string()), None),
        80 => (Some("http".to_string()), None),
        110 => (Some("pop3".to_string()), None),
        143 => (Some("imap".to_string()), None),
        443 => (Some("https".to_string()), None),
        465 => (Some("smtps".to_string()), None),
        993 => (Some("imaps".to_string()), None),
        995 => (Some("pop3s".to_string()), None),
        3306 => (Some("mysql".to_string()), None),
        3389 => (Some("rdp".to_string()), None),
        5432 => (Some("postgresql".to_string()), None),
        8080 => (Some("http-proxy".to_string()), None),
        8443 => (Some("https-alt".to_string()), None),
        _ => (crate::models::CommonPorts::get_service(port).map(String::from), None)
    }
} 