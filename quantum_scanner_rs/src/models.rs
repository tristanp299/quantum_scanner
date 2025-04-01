use std::collections::{HashMap, HashSet};
use std::fmt;
use std::net::IpAddr;
use std::ops::RangeInclusive;
use std::str::FromStr;
use chrono::{DateTime, Utc};
use serde::{Serialize, Deserialize};
use thiserror::Error;

/// Supported scan types
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ScanType {
    /// Standard TCP SYN scan - efficient and relatively stealthy
    Syn,
    /// Probes for SSL/TLS service information and certificates
    Ssl,
    /// Basic UDP port scan with custom payload options
    Udp,
    /// TCP ACK scan to detect firewall filtering rules
    Ack,
    /// Stealthy scan using TCP FIN flags to bypass basic filters
    Fin,
    /// TCP scan with FIN, URG, and PUSH flags set
    Xmas,
    /// TCP scan with no flags set, may bypass some packet filters
    Null,
    /// Analyzes TCP window size responses to determine port status
    Window,
    /// Uses fake TLS server responses to evade detection
    TlsEcho,
    /// Sends SYN packets with protocol-specific payloads
    Mimic,
    /// Fragments packets to bypass deep packet inspection
    Frag,
}

impl fmt::Display for ScanType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ScanType::Syn => write!(f, "SYN"),
            ScanType::Ssl => write!(f, "SSL"),
            ScanType::Udp => write!(f, "UDP"),
            ScanType::Ack => write!(f, "ACK"),
            ScanType::Fin => write!(f, "FIN"),
            ScanType::Xmas => write!(f, "XMAS"),
            ScanType::Null => write!(f, "NULL"),
            ScanType::Window => write!(f, "WINDOW"),
            ScanType::TlsEcho => write!(f, "TLS_ECHO"),
            ScanType::Mimic => write!(f, "MIMIC"),
            ScanType::Frag => write!(f, "FRAG"),
        }
    }
}

/// Port status enum
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PortStatus {
    Open,
    Closed,
    Filtered,
    Unfiltered,
    OpenFiltered,
}

impl fmt::Display for PortStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PortStatus::Open => write!(f, "open"),
            PortStatus::Closed => write!(f, "closed"),
            PortStatus::Filtered => write!(f, "filtered"),
            PortStatus::Unfiltered => write!(f, "unfiltered"),
            PortStatus::OpenFiltered => write!(f, "open|filtered"),
        }
    }
}

impl FromStr for PortStatus {
    type Err = String;
    
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "open" => Ok(PortStatus::Open),
            "closed" => Ok(PortStatus::Closed),
            "filtered" => Ok(PortStatus::Filtered),
            "unfiltered" => Ok(PortStatus::Unfiltered),
            "open|filtered" => Ok(PortStatus::OpenFiltered),
            _ => Err(format!("Invalid port status: {}", s)),
        }
    }
}

/// SSL/TLS certificate information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertificateInfo {
    pub subject: String,
    pub issuer: String,
    pub not_before: DateTime<Utc>,
    pub not_after: DateTime<Utc>,
    pub serial_number: String,
    pub signature_algorithm: String,
    pub version: u8,
    pub fingerprint: String,
    pub alt_names: Vec<String>,
    pub public_key_bits: Option<u16>,
    pub key_algorithm: Option<String>,
}

/// Port scan result structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortResult {
    pub tcp_states: HashMap<ScanType, PortStatus>,
    pub udp_state: Option<PortStatus>,
    pub filtering: Option<String>,
    pub service: Option<String>,
    pub version: Option<String>,
    pub vulns: Vec<String>,
    pub cert_info: Option<CertificateInfo>,
    pub banner: Option<String>,
    pub os_guess: Option<String>,
    pub scan_time: DateTime<Utc>,
}

impl Default for PortResult {
    fn default() -> Self {
        Self {
            tcp_states: HashMap::new(),
            udp_state: None,
            filtering: None,
            service: None,
            version: None,
            vulns: Vec::new(),
            cert_info: None,
            banner: None,
            os_guess: None,
            scan_time: Utc::now(),
        }
    }
}

/// Overall scan results
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanResults {
    pub target: String,
    pub target_ip: IpAddr,
    pub open_ports: HashSet<u16>,
    pub results: HashMap<u16, PortResult>,
    pub start_time: DateTime<Utc>,
    pub end_time: DateTime<Utc>,
    pub scan_types: Vec<ScanType>,
}

/// Error types for port range parsing
#[derive(Error, Debug)]
pub enum PortRangeError {
    #[error("Invalid port number: {0}")]
    InvalidPort(String),
    
    #[error("Invalid port range: {0}")]
    InvalidRange(String),
    
    #[error("Port range start is greater than end: {0} > {1}")]
    RangeStartGreaterThanEnd(u16, u16),
}

/// Single port or range of ports
#[derive(Debug, Clone)]
pub enum PortRange {
    Single(u16),
    Range(u16, u16),
}

impl PortRange {
    /// Parse a string like "80,443,8000-9000" into a vector of PortRange
    pub fn parse(port_str: &str) -> Result<Vec<Self>, PortRangeError> {
        let mut ranges = Vec::new();
        
        for part in port_str.split(',') {
            let part = part.trim();
            if part.is_empty() {
                continue;
            }
            
            if part.contains('-') {
                // Parse as range
                let mut parts = part.split('-');
                let start_str = parts.next().unwrap_or("");
                let end_str = parts.next().unwrap_or("");
                
                // Parse start port
                let start = match start_str.parse::<u16>() {
                    Ok(p) => p,
                    Err(_) => return Err(PortRangeError::InvalidPort(start_str.to_string())),
                };
                
                // Parse end port
                let end = match end_str.parse::<u16>() {
                    Ok(p) => p,
                    Err(_) => return Err(PortRangeError::InvalidPort(end_str.to_string())),
                };
                
                // Make sure start <= end
                if start > end {
                    return Err(PortRangeError::RangeStartGreaterThanEnd(start, end));
                }
                
                ranges.push(PortRange::Range(start, end));
            } else {
                // Parse as single port
                match part.parse::<u16>() {
                    Ok(port) => ranges.push(PortRange::Single(port)),
                    Err(_) => return Err(PortRangeError::InvalidPort(part.to_string())),
                }
            }
        }
        
        Ok(ranges)
    }
}

/// Iterator to flatten port ranges into individual ports
impl IntoIterator for PortRange {
    type Item = u16;
    type IntoIter = PortRangeIterator;
    
    fn into_iter(self) -> Self::IntoIter {
        match self {
            PortRange::Single(port) => PortRangeIterator {
                current: port,
                end: port,
                done: false,
            },
            PortRange::Range(start, end) => PortRangeIterator {
                current: start,
                end,
                done: false,
            },
        }
    }
}

/// Iterator for port ranges
pub struct PortRangeIterator {
    current: u16,
    end: u16,
    done: bool,
}

impl Iterator for PortRangeIterator {
    type Item = u16;
    
    fn next(&mut self) -> Option<Self::Item> {
        if self.done {
            return None;
        }
        
        let current = self.current;
        
        if current == self.end {
            self.done = true;
        } else {
            self.current += 1;
        }
        
        Some(current)
    }
}

/// Wrapper struct for Vec<PortRange> to avoid orphan rule issues
#[derive(Debug)]
pub struct PortRanges(pub Vec<PortRange>);

impl PortRanges {
    pub fn new(ranges: Vec<PortRange>) -> Self {
        PortRanges(ranges)
    }
}

/// Iterator for a collection of port ranges
impl IntoIterator for PortRanges {
    type Item = u16;
    type IntoIter = PortRangesIterator;
    
    fn into_iter(self) -> Self::IntoIter {
        PortRangesIterator {
            ranges: self.0,
            current_range_index: 0,
            current_iter: None,
        }
    }
}

/// Iterator for a vector of port ranges
pub struct PortRangesIterator {
    ranges: Vec<PortRange>,
    current_range_index: usize,
    current_iter: Option<PortRangeIterator>,
}

impl Iterator for PortRangesIterator {
    type Item = u16;
    
    fn next(&mut self) -> Option<Self::Item> {
        loop {
            // If we have a current iterator, try to get next
            if let Some(iter) = &mut self.current_iter {
                if let Some(port) = iter.next() {
                    return Some(port);
                }
                
                // Current iterator is exhausted
                self.current_iter = None;
            }
            
            // Try to get next range
            if self.current_range_index < self.ranges.len() {
                let range = &self.ranges[self.current_range_index];
                self.current_range_index += 1;
                
                match range {
                    PortRange::Single(port) => {
                        self.current_iter = Some(PortRangeIterator {
                            current: *port,
                            end: *port,
                            done: false,
                        });
                    },
                    PortRange::Range(start, end) => {
                        self.current_iter = Some(PortRangeIterator {
                            current: *start,
                            end: *end,
                            done: false,
                        });
                    },
                }
            } else {
                // No more ranges
                return None;
            }
        }
    }
}

/// Protocol-specific payloads for protocol mimicry
#[derive(Debug)]
pub struct MimicPayloads;

impl MimicPayloads {
    /// Get bytes for the specified protocol
    pub fn get(protocol: &str) -> &'static [u8] {
        match protocol.to_uppercase().as_str() {
            "HTTP" => b"HTTP/1.1 200 OK\r\nServer: Apache\r\nContent-Length: 0\r\n\r\n",
            "SSH" => b"SSH-2.0-OpenSSH_8.2p1\r\n",
            "FTP" => b"220 FTP Server Ready\r\n",
            "SMTP" => b"220 mail.example.com ESMTP Postfix\r\n",
            "IMAP" => b"* OK IMAP4rev1 Server Ready\r\n",
            "POP3" => b"+OK POP3 server ready\r\n",
            "MYSQL" => b"\x4a\x00\x00\x00\x0a\x35\x2e\x37\x2e\x33\x39\x00",
            "RDP" => b"\x03\x00\x00\x13\x0e\xd0\x00\x00\x124\x00\x02\x01\x08\x00\x01\x00\x00\x00",
            _ => b"", // Default to empty payload
        }
    }
}

/// Common service port mappings
#[derive(Debug)]
pub struct CommonPorts;

impl CommonPorts {
    /// Get service name for a port number
    pub fn get_service(port: u16) -> Option<&'static str> {
        match port {
            21 => Some("ftp"),
            22 => Some("ssh"),
            23 => Some("telnet"),
            25 => Some("smtp"),
            53 => Some("dns"),
            80 => Some("http"),
            110 => Some("pop3"),
            111 => Some("rpcbind"),
            135 => Some("msrpc"),
            139 => Some("netbios-ssn"),
            143 => Some("imap"),
            443 => Some("https"),
            445 => Some("microsoft-ds"),
            993 => Some("imaps"),
            995 => Some("pop3s"),
            1723 => Some("pptp"),
            3306 => Some("mysql"),
            3389 => Some("ms-wbt-server"),
            5432 => Some("postgresql"),
            5900 => Some("vnc"),
            8080 => Some("http-proxy"),
            8443 => Some("https-alt"),
            _ => None,
        }
    }
} 