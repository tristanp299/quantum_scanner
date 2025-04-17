use std::collections::{HashMap, HashSet};
use std::fmt;
use std::str::FromStr;
use chrono::{DateTime, Utc};
use serde::{Serialize, Deserialize};
use thiserror::Error;
use std::time::Duration;

/// Define NdpiRisk struct here as it's used across modules
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NdpiRisk {
    /// Numeric score representing the risk level.
    pub score: u32,
    /// Descriptive name of the risk (e.g., "Malicious Traffic", "Excessive Connections").
    pub name: String,
}

/// ScanType defines the different techniques that can be used for port scanning
///
/// Each scan type has different characteristics in terms of stealth, accuracy,
/// and the ability to bypass different security measures. From an OpSec perspective,
/// choosing the right scan type (e.g., Syn for stealth, Ack for firewall mapping)
/// is crucial to avoid detection.
///
/// We derive `PartialOrd` and `Ord` to allow sorting of scan types, which might be
/// useful for consistent reporting or internal logic. `Eq` and `PartialEq` are already
/// present for equality checks. `Hash` allows use in hash maps/sets.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum ScanType {
    /// Standard TCP SYN scan - efficient and relatively stealthy
    /// 
    /// Sends SYN packets and analyzes the response. A SYN-ACK indicates an open port,
    /// while RST indicates closed. No response or ICMP errors suggest filtered ports.
    Syn,
    
    /// Probes for SSL/TLS service information and certificates
    /// 
    /// Attempts to establish SSL/TLS connections to detect secure services and
    /// gather certificate information for further analysis.
    /// 
    /// ! OPSEC WARNING !
    /// Uses full TCP connections that can be easily logged by target systems.
    /// Creates more forensic evidence than raw socket scans like SYN, FIN, etc.
    /// Only use when certificate details are essential for your operation.
    Ssl,
    
    /// Basic UDP port scan with custom payload options
    /// 
    /// Sends UDP packets and analyzes responses. ICMP "port unreachable" messages
    /// indicate closed ports, while no response suggests open or filtered.
    Udp,
    
    /// TCP ACK scan to detect firewall filtering rules
    /// 
    /// Sends ACK packets (not establishing connections) to determine if ports
    /// are filtered by firewalls. Useful for mapping firewall rulesets.
    Ack,
    
    /// Stealthy scan using TCP FIN flags to bypass basic filters
    /// 
    /// Sends packets with the FIN flag set. Closed ports should respond with RST
    /// while open ports may drop these packets. Can bypass simple firewall rules.
    Fin,
    
    /// TCP scan with FIN, URG, and PUSH flags set
    /// 
    /// A more unusual flag combination that may evade basic packet filtering.
    /// Similar detection logic to FIN scans.
    Xmas,
    
    /// TCP scan with no flags set, may bypass some packet filters
    /// 
    /// Sends TCP packets with no flags set, which may bypass simple packet
    /// inspection systems. Similar detection logic to FIN scans.
    Null,
    
    /// Analyzes TCP window size responses to determine port status
    /// 
    /// Examines the TCP window size in RST packets to differentiate between
    /// open and closed ports, even when both return RST packets.
    Window,
    
    /// Sends SYN packets with protocol-specific payloads
    /// 
    /// Crafts SYN packets with data that mimics legitimate protocol behavior
    /// to bypass advanced inspection systems.
    /// 
    /// ! OPSEC WARNING !
    /// Uses full TCP connections and sends application-layer data that may be logged.
    /// Creates significantly more forensic evidence than stealthier scan types.
    /// Only use when protocol-specific behavior testing is required.
    Mimic,
    
    /// Fragments packets to bypass deep packet inspection
    /// 
    /// Splits TCP packets into multiple IP fragments that may bypass certain
    /// types of deep packet inspection systems.
    Frag,
    
    /// Tunnels scan through DNS queries to bypass restrictive firewalls
    /// 
    /// Encodes scan traffic within DNS queries, which are often allowed through
    /// firewalls even in restrictive environments.
    DnsTunnel,
    
    /// Tunnels scan through ICMP echo requests to bypass restrictive firewalls
    /// 
    /// Encodes scan traffic within ICMP echo (ping) packets, which are sometimes
    /// allowed through firewalls when other traffic is blocked.
    IcmpTunnel,
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
            ScanType::Mimic => write!(f, "MIMIC"),
            ScanType::Frag => write!(f, "FRAG"),
            ScanType::DnsTunnel => write!(f, "DNS_TUNNEL"),
            ScanType::IcmpTunnel => write!(f, "ICMP_TUNNEL"),
        }
    }
}

/// Port status enumeration for scan results
///
/// Different scan types can report different statuses for ports,
/// representing various network conditions and configurations. Understanding these
/// nuances is vital for interpreting scan results accurately, especially when
/// dealing with firewalls or IDS/IPS systems.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PortStatus {
    /// Port is confirmed to be listening and accepting connections
    Open,
    
    /// Port is confirmed to be not listening
    Closed,
    
    /// Port is blocked by a firewall or not responding
    /// 
    /// Could be due to firewalls, network issues, or the port being closed
    /// but with filtering in place.
    Filtered,
    
    /// Port is accessible but state cannot be determined
    /// 
    /// Typically seen in ACK scans where the port responds but
    /// the actual state (open/closed) cannot be determined.
    Unfiltered,
    
    /// Port could be either open or filtered
    /// 
    /// Used when the scan cannot differentiate between open and filtered
    /// states, such as in UDP or certain stealth scans.
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

/// SSL/TLS certificate information collected during scans
///
/// This structure contains detailed information about SSL/TLS certificates
/// encountered during scanning. Analyzing certificate details (issuer, validity, algorithms)
/// can reveal information about the target's infrastructure, potential vulnerabilities
/// (e.g., weak algorithms, expired certs), and sometimes internal hostnames (via alt_names).
/// OpSec consideration: Requesting certificates might be logged by the target.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertificateInfo {
    /// Certificate subject (Common Name or CN): Often reveals the primary domain name.
    pub subject: String,
    
    /// Certificate issuer: Identifies the Certificate Authority (CA). A self-signed
    /// certificate might indicate a less mature or internal system.
    pub issuer: String,
    
    /// Start date of certificate validity period. Useful for assessing certificate age.
    pub not_before: String,
    
    /// End date of certificate validity period. Expired certificates are a security risk.
    pub not_after: String,
    
    /// Unique identifier for the certificate. Can sometimes be used to track certificates
    /// across different services or IPs.
    pub serial_number: String,
    
    /// Algorithm used to sign the certificate (e.g., SHA256withRSA). Weak algorithms
    /// (like MD5 or SHA1) are a security risk.
    pub signature_algorithm: String,
    
    /// X.509 version of the certificate (typically 3).
    pub version: u8,
    
    /// Cryptographic hash (fingerprint) of the certificate (e.g., SHA-1, SHA-256).
    /// Used for verification and identification.
    pub fingerprint: String,
    
    /// Subject Alternative Names (SANs): Lists additional hostnames/IPs covered by the certificate.
    /// Can reveal other related domains or internal server names.
    pub alt_names: Vec<String>,
    
    /// Size of the public key in bits (e.g., 2048, 4096). Indicates cryptographic strength.
    /// Smaller key sizes (e.g., <2048) are less secure.
    pub public_key_bits: Option<u16>,
    
    /// Algorithm used for the public key (e.g., RSA, ECC).
    pub key_algorithm: Option<String>,
}

/// Detailed results for a single port scan
///
/// Contains all information collected about a specific port during various scan types.
/// This aggregated data provides a comprehensive view of the service running on the port,
/// its potential vulnerabilities, and configuration details.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortResult {
    /// Results from different TCP scan methods (e.g., SYN, FIN, XMAS).
    /// Maps each ScanType used to the observed PortStatus. This allows comparing
    /// results from different techniques, which can help infer firewall rules
    /// (e.g., SYN open but FIN closed might indicate a stateful firewall).
    pub tcp_states: HashMap<ScanType, PortStatus>,
    
    /// Result from UDP scan (if performed). UDP scanning is often slower and less
    /// reliable than TCP, but necessary for UDP-based services (e.g., DNS, SNMP).
    pub udp_state: Option<PortStatus>,
    
    /// Information about firewall or filtering behavior detected for this specific port.
    /// For example, noting if ACK scan reported 'unfiltered' while SYN reported 'filtered'.
    pub filtering: Option<String>,
    
    /// Identified service name (e.g., "http", "ssh", "smb"). Based on port number,
    /// banner grabbing, and protocol-specific probes.
    pub service: Option<String>,
    
    /// Identified service version (e.g., "Apache/2.4.52", "OpenSSH_8.9p1"). Crucial
    /// for vulnerability identification. OpSec note: Aggressive version probing might
    /// be detected.
    pub version: Option<String>,
    
    /// Potential vulnerabilities identified for this service/version based on integrated
    /// or external vulnerability databases. Stores detailed VulnInfo structs.
    pub vulns: Vec<VulnInfo>,
    
    /// SSL/TLS certificate information if the service uses TLS (e.g., HTTPS on port 443).
    pub cert_info: Option<CertificateInfo>,

    /// Detailed HTTP information gathered if the service is HTTP/HTTPS.
    /// Includes headers, status codes, technologies, etc. See `HttpInfo`.
    pub http_info: Option<HttpInfo>,
    
    /// Service banner collected during connection attempts or probing. Banners can
    /// reveal service type, version, and sometimes operating system information.
    /// OpSec note: Banner grabbing is easily logged.
    pub banner: Option<String>,
    
    /// OS fingerprint guess based on responses observed on this port.
    pub os_guess: Option<String>,
    
    /// Timestamp when the scan for this specific port concluded.
    #[serde(with = "chrono::serde::ts_milliseconds")]
    pub scan_time: DateTime<Utc>,
    
    /// Overall assessment of the security implications of this port/service.
    /// E.g., "High risk: Outdated OpenSSH version with known exploits".
    pub security_posture: Option<String>,
    
    /// Any unusual or unexpected behavior observed during scanning this port.
    /// E.g., "Unexpected RST packet during SYN scan", "Non-standard HTTP header".
    pub anomalies: Vec<String>,
    
    /// Analysis of response times (RTT) which can sometimes infer network distance
    /// or server load.
    pub timing_analysis: Option<String>, // Placeholder, could be struct with avg/min/max RTT
    
    /// Additional details specific to the detected service (e.g., SMB shares, SNMP info).
    /// Could be a map or a specific enum/struct.
    pub service_details: Option<serde_json::Value>, // Use JSON Value for flexibility

    /// TLS protocol version if detected (e.g., "TLSv1.2", "TLSv1.3").
    pub tls_protocol_version: Option<String>,
    
    /// Final determined status for the port considering all scan types performed.
    /// This field is used to determine the overall status of the port for reporting.
    /// It prioritizes Open > OpenFiltered > other statuses.
    pub final_status: PortStatus,
    
    /// Detailed reason why this port has its current status. Provides context about
    /// why a port was classified as open, closed, filtered, etc. Examples include
    /// "SYN+ACK received", "RST received", "ICMP unreachable", "timeout".
    /// This helps operators understand the underlying network behavior.
    pub reason: Option<String>,
    
    /// Stores scan-specific reasons for each TCP scan type.
    /// This allows displaying different reasons for different scan types,
    /// providing more detailed and accurate information about responses for each technique.
    pub tcp_reasons: HashMap<ScanType, String>,

    /// Detailed protocol information derived from nDPI analysis.
    /// Contains protocol IDs, names, category, risk, hostname, etc.
    pub ndpi_protocol: Option<NDPIProtocolInfo>,

    /// Confidence level of the nDPI detection (placeholder).
    /// Currently uses String to match output.rs expectation, could be f32 later.
    pub ndpi_confidence: Option<String>,
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
            http_info: None,
            banner: None,
            os_guess: None,
            scan_time: Utc::now(),
            security_posture: None,
            anomalies: Vec::new(),
            timing_analysis: None,
            service_details: None,
            tls_protocol_version: None,
            final_status: PortStatus::Filtered, // Default to Filtered
            reason: None, // Default to None
            tcp_reasons: HashMap::new(),
            ndpi_protocol: None, // Initialize renamed field
            ndpi_confidence: None, // Initialize new field
        }
    }
}

/// Overall scan results for a target
///
/// Aggregates all information collected during the scanning process for a single target host,
/// including port-specific results and summary information. This provides a holistic
/// view of the target's network posture.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanResults {
    /// Target hostname or IP address as specified by the user.
    pub target: String,
    
    /// Resolved IP address of the target used for the scan. Important if the target
    /// was specified as a hostname.
    pub target_ip: String,
    
    /// A quick-reference set of all ports confirmed to be 'Open'.
    pub open_ports: HashSet<u16>,
    
    /// Detailed results map. Key is the port number, value is the `PortResult` struct
    /// containing all findings for that specific port.
    pub results: HashMap<u16, PortResult>,
    
    /// Timestamp when the overall scan for this target started.
    pub start_time: DateTime<Utc>,
    
    /// Timestamp when the overall scan for this target completed. Duration = end_time - start_time.
    pub end_time: DateTime<Utc>,
    
    /// List of scan types (`ScanType`) used during this scan operation.
    pub scan_types: Vec<ScanType>,
    
    /// Total raw network packets sent during the scan for this target. Includes probes,
    /// handshakes, retries, etc. High packet counts increase the chance of detection (OpSec).
    pub packets_sent: usize,
    
    /// Number of scan operations (e.g., probing a specific port with a specific method)
    /// that completed successfully (received a definitive response or timed out as expected).
    pub successful_scans: usize,
    
    /// Summary of detected operating systems based on information gathered from all
    /// scanned ports. Provides a consolidated guess about the target OS.
    pub os_summary: Option<String>,
    
    /// Overall security risk assessment for the target, calculated based on the number
    /// and type of open ports, identified services, versions, and potential vulnerabilities.
    /// Could be a qualitative score (Low, Medium, High) or a quantitative metric.
    pub risk_assessment: Option<String>,
    
    /// Groups detected services into logical categories (e.g., "web", "database", "remote_access")
    /// along with the ports where they were found. Helps in quickly understanding the
    /// types of services exposed by the target.
    pub service_categories: Option<HashMap<String, Vec<u16>>>,
}

/// Represents information about a potential vulnerability detected.
///
/// Storing identified vulnerabilities is key for reporting. 
/// OpSec Note: The method of vulnerability detection (e.g., specific probes vs. banner/version matching)
/// can affect stealth. Simple version matching is less intrusive.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VulnInfo {
    /// Vulnerability identifier (e.g., CVE-2021-44228, OSVDB-12345).
    /// Standard identifiers help in referencing external databases.
    pub id: String,

    /// Description of the vulnerability.
    /// Provides context about the potential issue.
    pub description: String,

    /// Severity assessment (e.g., "Critical", "High", "Medium", "Low", "Info").
    /// Helps prioritize findings.
    pub severity: String,
    // Potential future fields: CVSS score, references, remediation steps
}

// Implement the Display trait for VulnInfo for user-friendly printing.
impl fmt::Display for VulnInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Format: "[Severity] ID: Description"
        // Example: "[High] CVE-2021-44228: Apache Log4j Remote Code Execution"
        write!(f, "[{}] {}: {}", self.severity, self.id, self.description)
    }
}

/// Error types for port range parsing
///
/// These errors help provide clear feedback when port specifications
/// are invalid or potentially harmful.
#[derive(Error, Debug)]
pub enum PortRangeError {
    /// General formatting error
    #[allow(dead_code)]
    #[error("Invalid format: {0}")]
    InvalidFormat(String),
    
    /// Invalid port number (must be 1-65535)
    #[error("Invalid port number: {0}")]
    InvalidPort(String),
    
    /// Invalid port range specification
    #[allow(dead_code)]
    #[error("Invalid port range: {0}")]
    InvalidRange(String),
    
    /// Range start is greater than range end
    #[error("Port range start is greater than end: {0} > {1}")]
    RangeStartGreaterThanEnd(u16, u16),
}

/// Represents a single port or a range of ports
///
/// Used to efficiently parse and represent port specifications
/// from user input without immediately expanding large ranges.
#[derive(Debug, Clone)]
pub enum PortRange {
    /// A single port (e.g., "80")
    Single(u16),
    
    /// A range of ports (e.g., "1000-2000")
    Range(u16, u16),
}

impl PortRange {
    /// Parse a string like "80,443,8000-9000" into a vector of PortRange
    ///
    /// # Arguments
    /// * `port_str` - String containing port specifications
    ///
    /// # Returns
    /// * `Result<Vec<Self>, PortRangeError>` - The parsed port ranges or an error
    ///
    /// # Examples
    /// ```
    /// let ranges = PortRange::parse("22,80,443,8000-8100").unwrap();
    /// // Results in:
    /// // - Single(22)
    /// // - Single(80)
    /// // - Single(443)
    /// // - Range(8000, 8100)
    /// ```
    pub fn parse(port_str: &str) -> Result<Vec<Self>, PortRangeError> {
        let mut ranges = Vec::new();
        
        // Check for empty input
        if port_str.trim().is_empty() {
            return Err(PortRangeError::InvalidFormat("Empty port specification".to_string()));
        }
        
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
                
                // Check if there are too many parts in the range (like "80-443-8000")
                if parts.next().is_some() {
                    return Err(PortRangeError::InvalidFormat(
                        format!("Invalid port range format: {} (expected format: start-end)", part)
                    ));
                }
                
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
                
                // Validate range size to prevent excessive memory usage
                if end - start > 10000 {
                    return Err(PortRangeError::InvalidRange(
                        format!("Port range {}-{} is too large (max 10000 ports per range)", start, end)
                    ));
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
        
        if ranges.is_empty() {
            return Err(PortRangeError::InvalidFormat("No valid port ranges specified".to_string()));
        }
        
        Ok(ranges)
    }
}

/// Iterator to flatten port ranges into individual ports
///
/// Allows iterating over a PortRange as a sequence of port numbers.
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

/// Iterator implementation for a single port range
///
/// Provides sequential access to all ports in a range.
pub struct PortRangeIterator {
    /// Current port being iterated
    current: u16,
    
    /// End port of the range
    end: u16,
    
    /// Whether iteration is complete
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
///
/// Allows implementing IntoIterator for a collection of PortRange objects.
#[derive(Debug)]
pub struct PortRanges(pub Vec<PortRange>);

impl PortRanges {
    /// Create a new PortRanges from a vector of PortRange objects
    pub fn new(ranges: Vec<PortRange>) -> Self {
        PortRanges(ranges)
    }
    
    /// Parse a port specification string into a vector of PortRange objects
    ///
    /// # Arguments
    /// * `port_str` - A port specification string (e.g., "80,443,8000-9000")
    ///
    /// # Returns
    /// * `Result<Vec<PortRange>, PortRangeError>` - Vector of parsed port ranges or an error
    pub fn parse(port_str: &str) -> Result<Vec<PortRange>, PortRangeError> {
        PortRange::parse(port_str)
    }
}

/// Iterator for a collection of port ranges
///
/// Allows seamless iteration over multiple port ranges as a single sequence.
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

/// Iterator implementation for multiple port ranges
///
/// Manages iteration across multiple ranges, transitioning between them
/// as needed to provide a continuous sequence of ports.
pub struct PortRangesIterator {
    /// Vector of port ranges to iterate over
    ranges: Vec<PortRange>,
    
    /// Index of the current range being iterated
    current_range_index: usize,
    
    /// Iterator for the current range
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
                
                // Create iterator for this range
                self.current_iter = Some(match range {
                    PortRange::Single(port) => PortRangeIterator {
                        current: *port,
                        end: *port,
                        done: false,
                    },
                    PortRange::Range(start, end) => PortRangeIterator {
                        current: *start,
                        end: *end,
                        done: false,
                    },
                });
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

/// Top ports commonly scanned
#[derive(Debug)]
pub struct TopPorts;

impl TopPorts {
    /// Get the top 100 most common ports to scan
    pub fn top_100() -> Vec<u16> {
        vec![
            // Most common web and service ports
            80, 443, 22, 21, 25, 3389, 110, 445, 139, 143, 53, 135, 3306, 8080, 1723, 111, 995, 993, 5900,
            1025, 587, 8888, 199, 1720, 465, 548, 113, 81, 6001, 10000, 514, 5060, 179, 1026, 2000, 8443,
            8000, 32768, 554, 26, 1433, 49152, 2001, 515, 8008, 49154, 1027, 5666, 646, 5000, 5631, 631,
            49153, 8081, 2049, 88, 79, 5800, 106, 2121, 1110, 49155, 6000, 513, 990, 5357, 427, 49156,
            543, 544, 5101, 144, 7, 389, 8009, 3128, 444, 9999, 5009, 7070, 5190, 3000, 5432, 1900, 3986,
            13, 1029, 9, 5051, 6646, 49157, 1028, 873, 1755, 2717, 4899, 9100, 119, 37
        ]
    }
    
    #[allow(dead_code)]
    pub fn top_10() -> Vec<u16> {
        vec![80, 443, 22, 21, 25, 3389, 110, 445, 139, 143]
    }
}

/// HTTP security header type
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum HttpSecurityHeader {
    ContentSecurityPolicy(String),
    XContentTypeOptions(String),
    XFrameOptions(String),
    XXssProtection(String),
    StrictTransportSecurity(String),
    ReferrerPolicy(String),
    FeaturePolicy(String),
    Other(String, String),
}

/// Detailed information gathered specifically from HTTP/HTTPS services.
///
/// Provides insights into web server configuration, application details,
/// and potential web-specific vulnerabilities or misconfigurations.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct HttpInfo {
    /// HTTP protocol version detected (e.g., "HTTP/1.1", "HTTP/2").
    pub http_version: Option<String>,
    
    /// HTTP status code returned (e.g., 200, 404, 500). Indicates the result
    /// of the initial HTTP request probe.
    pub status_code: Option<u16>,
    
    /// HTTP status text accompanying the status code (e.g., "OK", "Not Found").
    pub status_text: Option<String>,
    
    /// Map of HTTP response headers. Headers can reveal server software (`Server` header),
    /// web application technologies (`X-Powered-By`), caching policies, security settings, etc.
    /// Analyzing headers is crucial for web reconnaissance.
    pub headers: HashMap<String, String>,
    
    /// Value of the `Content-Type` header, indicating the type of resource returned
    /// (e.g., "text/html", "application/json").
    pub content_type: Option<String>,
    
    /// Size of the HTTP response body in bytes.
    pub response_size: Option<usize>,
    
    /// Time taken to receive the HTTP response in seconds. Can indicate server load or network latency.
    pub response_time: Option<f64>,
    
    /// Content of the HTML `<title>` tag, if found. Often gives context about the web page/application.
    pub title: Option<String>,
    
    /// List of cookies set by the server (`Set-Cookie` header). Cookies can reveal session management
    /// mechanisms and potentially tracking information.
    pub cookies: Vec<String>,
    
    /// List of redirection URLs encountered (e.g., from 301/302 status codes). Shows how the
    /// application routes requests.
    pub redirects: Vec<String>,
    
    /// Parsed list of common HTTP security headers found in the response. The presence and configuration
    /// of these headers (CSP, HSTS, X-Frame-Options, etc.) are important security indicators.
    pub security_headers: Vec<HttpSecurityHeader>,
    
    /// List of web technologies detected (e.g., "WordPress", "React", "jQuery", "PHP").
    /// Identified through headers, HTML content, cookies, etc. Useful for finding technology-specific vulnerabilities.
    pub technologies: Vec<String>,

    /// Value of the `Server` header, often indicating the web server software (e.g., "nginx", "Apache").
    /// OpSec note: Some servers are configured to hide or obfuscate this header.
    pub server: Option<String>,
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

/// Represents the outcome of scanning a single port.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanResult {
    /// Port number
    pub port: u16,
    /// Current status of the port (e.g., Open, Closed, Filtered)
    pub status: PortStatus,
    /// Service identified on the port (e.g., "http", "ssh")
    pub service_name: Option<String>,
    /// Version of the service identified
    pub service_version: Option<String>,
    /// Banner received from the service
    pub banner: Option<String>,
    /// SSL/TLS certificate information, if applicable
    pub certificate_info: Option<CertificateInfo>,
    /// Reason for filtered status, if applicable (e.g., "ICMP Port Unreachable")
    pub filter_reason: Option<String>,
    /// Detailed error message if the scan for this port failed
    pub error: Option<String>,
    /// OS fingerprint guess based on passive analysis
    pub os_fingerprint: Option<String>,
    /// TLS protocol version if detected (e.g., "TLSv1.2")
    pub tls_protocol_version: Option<String>,
    /// Timestamp when this specific port was scanned. Useful for correlating logs
    #[serde(with = "chrono::serde::ts_milliseconds")]
    pub scan_time: DateTime<Utc>,
    /// Detailed reason for the port status (e.g., "SYN-ACK received", "RST received")
    /// Provides technical explanation of why this port was classified with its status
    pub reason: Option<String>,
    /// Type of scan used for this result
    pub scan_type: Option<ScanType>,
}

impl ScanResult {
    /// Create a new ScanResult with basic information
    pub fn new(port: u16, status: PortStatus) -> Self {
        Self {
            port,
            status,
            service_name: None,
            service_version: None,
            banner: None,
            certificate_info: None,
            filter_reason: None,
            error: None,
            os_fingerprint: None,
            tls_protocol_version: None,
            scan_time: Utc::now(),
            reason: None,
            scan_type: None,
        }
    }
    
    /// Create a new ScanResult for a port with an error
    pub fn new_with_error(port: u16, error: String) -> Self {
        Self {
            port,
            status: PortStatus::Filtered,
            service_name: None,
            service_version: None,
            banner: None,
            certificate_info: None,
            filter_reason: None,
            error: Some(error),
            os_fingerprint: None,
            tls_protocol_version: None,
            scan_time: Utc::now(),
            reason: Some("Scan error".to_string()),
            scan_type: None,
        }
    }
    
    /// Set certificate info
    pub fn set_certificate_info(&mut self, cert_info: Option<CertificateInfo>) {
        self.certificate_info = cert_info;
    }
    
    /// Set filter reason
    pub fn set_filter_reason(&mut self, reason: Option<String>) {
        self.filter_reason = reason;
    }
    
    /// Set protocol version
    pub fn set_protocol_version(&mut self, version: Option<String>) {
        self.tls_protocol_version = version;
    }
    
    /// Set reason for port status
    pub fn set_reason(&mut self, reason: Option<String>) {
        self.reason = reason;
    }
}

/// Represents the overall results for a single target host.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TargetResult {
    /// The IP address or hostname of the target.
    pub target: String,
    /// List of results for each scanned port.
    pub port_results: Vec<ScanResult>,
    /// Overall scan status for this target (e.g., "Completed", "Failed").
    pub status: String,
    /// Timestamp when the overall scan for this target started.
    #[serde(with = "chrono::serde::ts_milliseconds")]
    pub start_time: DateTime<Utc>,
    /// Timestamp when the overall scan for this target finished.
    #[serde(with = "chrono::serde::ts_milliseconds")]
    pub end_time: DateTime<Utc>,
    /// Total duration of the scan for this target.
    #[serde(with = "humantime_serde")] // Use humantime for Duration
    pub duration: Duration,
    /// Any error encountered during the scan for this target.
    pub error: Option<String>,
}

/// Determines if any of the selected scan types require raw socket access.
///
/// Raw sockets typically require root/administrator privileges.
///
/// # Arguments
/// * `scan_types` - A slice of `ScanType` enums selected for the scan.
///
/// # Returns
/// * `bool` - True if any scan type needs raw sockets, false otherwise.
///
/// # Opsec Considerations
/// - Running scans requiring raw sockets (like SYN, FIN, Xmas) without root/Administrator privileges will likely fail silently or be blocked by the OS.
/// - This check is crucial to prevent unexpected failures and inform the user about privilege requirements.
pub fn requires_raw_sockets(scan_types: &[ScanType]) -> bool {
    scan_types.iter().any(|&st| matches!(
        st,
        ScanType::Syn | ScanType::Ack | ScanType::Fin |
        ScanType::Xmas | ScanType::Null | ScanType::Window |
        ScanType::Frag // Fragmentation likely needs raw sockets too
        // Tunneling might or might not depending on implementation
    ))
}

/// Metrics collected during scanning process
/// Used to track scanner performance and activity
#[derive(Debug, Clone)]
pub struct ScanMetrics {
    /// Total number of packets sent (estimates actual network traffic)
    pub packets_sent: u64,
    
    /// Number of successful scan operations (connection attempts that completed)
    pub successful_scans: u64,
    
    /// Number of ports found to be open
    pub open_ports_found: u32,
    
    /// Number of ports found to be closed
    pub closed_ports_found: u32,
    
    /// Number of ports found to be filtered
    pub filtered_ports_found: u32,
    
    /// Time spent in milliseconds on scanning
    pub scan_time_ms: u64,
    
    /// Time spent in milliseconds on port discovery
    pub discovery_time_ms: u64,
    
    /// Time spent in milliseconds on service identification
    pub service_id_time_ms: u64,
}

impl ScanMetrics {
    /// Create a new metrics instance with zeroed counters
    pub fn new() -> Self {
        Self {
            packets_sent: 0,
            successful_scans: 0,
            open_ports_found: 0,
            closed_ports_found: 0,
            filtered_ports_found: 0,
            scan_time_ms: 0,
            discovery_time_ms: 0,
            service_id_time_ms: 0,
        }
    }
    
    /// Reset all counters to zero
    pub fn reset(&mut self) {
        self.packets_sent = 0;
        self.successful_scans = 0;
        self.open_ports_found = 0;
        self.closed_ports_found = 0;
        self.filtered_ports_found = 0;
        self.scan_time_ms = 0;
        self.discovery_time_ms = 0;
        self.service_id_time_ms = 0;
    }
}

/// Represents detailed protocol information obtained from nDPI analysis.
/// Add Serialize and Deserialize derives to fix errors E0277
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NDPIProtocolInfo {
    /// Master protocol identifier (e.g., Ethernet, IP).
    pub master_protocol_id: u16,
    /// Application protocol identifier (e.g., HTTP, DNS).
    pub application_protocol_id: u16,
    /// Protocol identifier for tunneling protocols (if any).
    pub tunnel_protocol_id: u16, // Added field for tunnel info
    /// High-level name of the detected protocol (e.g., "HTTP", "TLS").
    pub protocol_name: String,
    /// Functional category of the protocol (e.g., "Web", "Messaging", "Security").
    pub category_name: String,
    /// Indicates if the detected protocol is typically encrypted.
    pub is_encrypted: bool,
    /// Confidence level of the detection (e.g., Certain, Likely, Possible).
    pub confidence: NdpiConfidence,
    /// Risk associated with the protocol or flow.
    pub risk: Option<NdpiRisk>,
    /// Raw risk value from nDPI (for reference).
    pub raw_risk_value: Option<u32>,
    /// Hostname associated with the protocol
    pub hostname: Option<String>,
    // Removed category_id, app_protocol_name, protocol_stack as they are redundant or handled differently
}

/// Enum representing the confidence level of nDPI detection.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum NdpiConfidence {
    Certain,
    Likely,
    Possible,
    Unknown, // Default or when confidence is not applicable
}

// Conversion from nDPI confidence enum/value if available.
// This is a placeholder implementation assuming ndpi_confidence_t maps 0-3.
impl From<u32> for NdpiConfidence { // Or from the actual C enum type if available in bindings
    fn from(val: u32) -> Self {
        match val { // Adjust values based on actual nDPI enum definitions
            0 => NdpiConfidence::Certain, // Assuming 0 maps to highest confidence
            1 => NdpiConfidence::Likely,
            2 => NdpiConfidence::Possible,
            _ => NdpiConfidence::Unknown, // Default to Unknown
        }
    }
} 