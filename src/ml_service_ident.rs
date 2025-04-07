use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;

use anyhow::{Context, Result};
use log::{debug, info, warn};
use rand::prelude::*;
use serde::{Deserialize, Serialize};

/// Feature vector representation of a service response
/// 
/// This captures the characteristics of a service that can be
/// used for machine learning classification without requiring
/// the full banner or response content.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceFeatureVector {
    // Numeric features derived from banner/response
    /// Length of the response/banner
    pub response_length: f32,
    /// Ratio of printable ASCII characters
    pub printable_ratio: f32,
    /// Ratio of alphabetic characters
    pub alpha_ratio: f32,
    /// Ratio of numeric characters
    pub numeric_ratio: f32,
    /// Ratio of whitespace characters
    pub whitespace_ratio: f32,
    /// Ratio of special characters
    pub special_ratio: f32,
    /// Entropy of the response (randomness measure)
    pub entropy: f32,
    /// Average line length
    pub avg_line_length: f32,
    /// Maximum line length
    pub max_line_length: f32,
    /// Number of lines
    pub line_count: f32,
    /// Number of null bytes (important for binary protocols)
    pub null_count: f32,
    
    // Binary features (presence/absence)
    /// Contains version number pattern
    pub has_version_number: bool,
    /// Contains server software identification
    pub has_server_id: bool,
    /// Contains date information
    pub has_date: bool,
    /// Contains IP address pattern
    pub has_ip_address: bool,
    /// Contains hostname pattern
    pub has_hostname: bool,
    /// Contains status code pattern (like HTTP 200)
    pub has_status_code: bool,
    /// Contains HTML tags
    pub has_html: bool,
    /// Contains XML structure
    pub has_xml: bool,
    /// Contains JSON structure
    pub has_json: bool,
    /// Contains binary data (non-printable characters)
    pub has_binary: bool,
    
    // Port-related features
    /// The port number being scanned
    pub port: u16,
    /// Is this a well-known port?
    pub is_well_known_port: bool,
    /// Is this a registered port?
    pub is_registered_port: bool,
    
    // Protocol hint features
    /// Response starts with HTTP
    pub starts_with_http: bool,
    /// Response starts with SSH
    pub starts_with_ssh: bool,
    /// Response starts with FTP
    pub starts_with_ftp: bool,
    /// Response starts with SMTP
    pub starts_with_smtp: bool,
    /// Response starts with POP3
    pub starts_with_pop3: bool,
    /// Response starts with IMAP
    pub starts_with_imap: bool,
    
    // Connection behavior features
    /// Connection was immediately closed
    pub immediate_close: bool,
    /// Server initiated data without prompt
    pub server_initiated: bool,
    /// Response time in milliseconds
    pub response_time_ms: f32,
}

impl ServiceFeatureVector {
    /// Extract feature vector from service banner and metadata
    pub fn from_banner(
        banner: &str, 
        port: u16, 
        response_time_ms: f32, 
        immediate_close: bool,
        server_initiated: bool
    ) -> Self {
        let response_length = banner.len() as f32;
        
        // Character type ratios
        let chars = banner.chars().collect::<Vec<_>>();
        let char_count = chars.len() as f32;
        let printable_count = chars.iter().filter(|c| c.is_ascii_graphic()).count() as f32;
        let alpha_count = chars.iter().filter(|c| c.is_alphabetic()).count() as f32;
        let numeric_count = chars.iter().filter(|c| c.is_numeric()).count() as f32;
        let whitespace_count = chars.iter().filter(|c| c.is_whitespace()).count() as f32;
        let special_count = chars.iter().filter(|c| c.is_ascii_punctuation()).count() as f32;
        
        // Calculate ratios
        let printable_ratio = if char_count > 0.0 { printable_count / char_count } else { 0.0 };
        let alpha_ratio = if char_count > 0.0 { alpha_count / char_count } else { 0.0 };
        let numeric_ratio = if char_count > 0.0 { numeric_count / char_count } else { 0.0 };
        let whitespace_ratio = if char_count > 0.0 { whitespace_count / char_count } else { 0.0 };
        let special_ratio = if char_count > 0.0 { special_count / char_count } else { 0.0 };
        
        // Calculate Shannon entropy
        let mut char_freq = HashMap::new();
        for c in chars.iter() {
            *char_freq.entry(*c).or_insert(0) += 1;
        }
        
        let entropy = char_freq.values().fold(0.0, |acc, &count| {
            let p = count as f32 / char_count;
            acc - p * p.log2()
        });
        
        // Line analysis
        let lines = banner.lines().collect::<Vec<_>>();
        let line_count = lines.len() as f32;
        let line_lengths = lines.iter().map(|line| line.len() as f32).collect::<Vec<_>>();
        let avg_line_length = if !line_lengths.is_empty() {
            line_lengths.iter().sum::<f32>() / line_lengths.len() as f32
        } else {
            0.0
        };
        let max_line_length = line_lengths.iter().fold(0.0f32, |max, &len| max.max(len));
        
        // Pattern detection using simple regex
        use regex::Regex;
        
        // Precompile regexes for efficiency
        let version_regex = Regex::new(r"(?i)version[:\s]+\d+(\.\d+)+|v\d+(\.\d+)+").unwrap();
        let server_id_regex = Regex::new(r"(?i)server[:]\s+\S+|powered by|nginx|apache|iis|openssh|exim|postfix").unwrap();
        let date_regex = Regex::new(r"\d{4}[-/]\d{1,2}[-/]\d{1,2}|\d{1,2}[-/]\d{1,2}[-/]\d{2,4}").unwrap();
        let ip_regex = Regex::new(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}").unwrap();
        let hostname_regex = Regex::new(r"(?i)[a-z0-9][-a-z0-9]*(\.[a-z0-9][-a-z0-9]*)+").unwrap();
        let status_code_regex = Regex::new(r"HTTP/[\d.]+ \d{3}").unwrap();
        let html_regex = Regex::new(r"(?i)<html|<body|<div|<span|<a\s|<img|<script|<head").unwrap();
        let xml_regex = Regex::new(r"(?i)<\?xml|<[a-z]+:.+?</[a-z]+:|xmlns:").unwrap();
        let json_regex = Regex::new(r#"(?i)^\s*[\{\[].*[\}\]]\s*$|"[^"]+":|(null|true|false),"#).unwrap();
        
        // Protocol start patterns
        let has_binary = chars.iter().any(|&c| (c as u32) > 127 || ((c as u32) < 32 && c != '\n' && c != '\r' && c != '\t'));
        let starts_with_http = banner.starts_with("HTTP/") || banner.starts_with("GET ") || banner.starts_with("POST ");
        let starts_with_ssh = banner.starts_with("SSH-");
        let starts_with_ftp = banner.starts_with("220 ") && banner.contains("FTP");
        let starts_with_smtp = banner.starts_with("220 ") && (banner.contains("SMTP") || banner.contains("mail"));
        let starts_with_pop3 = banner.starts_with("+OK");
        let starts_with_imap = banner.starts_with("* OK") || banner.starts_with("* PREAUTH");
        
        // Port classification
        let is_well_known_port = port < 1024;
        let is_registered_port = port >= 1024 && port <= 49151;
        
        ServiceFeatureVector {
            response_length,
            printable_ratio,
            alpha_ratio,
            numeric_ratio,
            whitespace_ratio,
            special_ratio,
            entropy,
            avg_line_length,
            max_line_length,
            line_count,
            null_count: 0.0,
            
            has_version_number: version_regex.is_match(banner),
            has_server_id: server_id_regex.is_match(banner),
            has_date: date_regex.is_match(banner),
            has_ip_address: ip_regex.is_match(banner),
            has_hostname: hostname_regex.is_match(banner),
            has_status_code: status_code_regex.is_match(banner),
            has_html: html_regex.is_match(banner),
            has_xml: xml_regex.is_match(banner),
            has_json: json_regex.is_match(banner),
            has_binary,
            
            port,
            is_well_known_port,
            is_registered_port,
            
            starts_with_http,
            starts_with_ssh,
            starts_with_ftp,
            starts_with_smtp,
            starts_with_pop3,
            starts_with_imap,
            
            immediate_close,
            server_initiated,
            response_time_ms,
        }
    }
    
    /// Create service feature vector from binary data
    /// 
    /// This method analyzes binary protocol data to create a feature vector
    /// that can be used for service identification.
    /// 
    /// For operational security, we use statistical analysis rather than
    /// signature matching to avoid detection by security monitoring tools.
    pub fn from_binary(
        data: &[u8], 
        port: u16, 
        response_time_ms: f32, 
        immediate_close: bool,
        server_initiated: bool
    ) -> Self {
        // Convert to string if possible for some text-based analysis
        // For binary protocols, this will contain many non-printable chars
        let banner = String::from_utf8(data.to_vec())
            .unwrap_or_else(|_| format!("[Binary data of length {}]", data.len()));
        
        // Calculate binary-specific features
        // For operational security, we analyze statistical properties
        // rather than using specific signatures that could be flagged
        let response_length = data.len() as f32;
        
        // Basic character analysis
        let printable_count = data.iter().filter(|&&b| b >= 32 && b <= 126).count() as f32;
        let ascii_count = data.iter().filter(|&&b| b <= 127).count() as f32;
        let null_count = data.iter().filter(|&&b| b == 0).count() as f32;
        let binary_indicator = data.iter().any(|&b| b > 127);
        
        // Calculate ratios
        let printable_ratio = if response_length > 0.0 { printable_count / response_length } else { 0.0 };
        let binary_ratio = if response_length > 0.0 { (response_length - ascii_count) / response_length } else { 0.0 };
        
        // Byte frequency analysis for entropy calculation
        // High entropy indicates encryption or compression
        // Low entropy with structure indicates a binary protocol
        let mut byte_freq = HashMap::new();
        for b in data {
            *byte_freq.entry(*b).or_insert(0) += 1;
        }
        
        // Calculate Shannon entropy - a measure of randomness in the data
        // Encrypted data typically has entropy > 7.0
        // Compressed data typically has entropy > 6.5
        // Structured binary protocols typically have entropy between 3.0-6.0
        let entropy = byte_freq.values().fold(0.0, |acc, &count| {
            let p = count as f32 / response_length;
            acc - p * p.log2()
        });
        
        // Use text-based analysis first to extract common features
        let mut text_features = Self::from_banner(&banner, port, response_time_ms, immediate_close, server_initiated);
        
        // Override with binary-specific features
        text_features.response_length = response_length;
        text_features.printable_ratio = printable_ratio;
        text_features.entropy = entropy;
        text_features.has_binary = binary_indicator;
        text_features.null_count = null_count;
        
        // Use null_count to help identify binary protocols with null-padding
        if null_count > 0.0 {
            // Binary formats often contain null bytes for padding or as delimiters
            let null_ratio = null_count / response_length;
            
            // Adjust entropy interpretation based on null byte presence
            // High null ratio with non-zero binary_ratio suggests a structured binary format
            if null_ratio > 0.1 && binary_ratio > 0.0 {
                // This is characteristic of many binary protocols like MySQL, SMB, etc.
                text_features.has_binary = true;
                
                // For operational security, we don't log specific protocol detection
                // but adjust our analysis based on characteristics
                
                // Binary protocols don't use these text-based formats
                text_features.has_html = false;
                text_features.has_xml = false;
                text_features.has_json = false;
            }
        }
        
        // Use binary_ratio to improve classification accuracy
        if binary_ratio > 0.0 {
            // Greater than 20% binary data strongly indicates binary protocol
            if binary_ratio > 0.2 {
                text_features.has_binary = true;
                
                // Adjust entropy interpretation based on binary ratio
                // Binary protocols with structure tend to have specific entropy ranges
                if binary_ratio > 0.8 && entropy < 6.0 {
                    // This pattern suggests a structured binary protocol rather than
                    // encrypted data (which would have higher entropy)
                    text_features.has_server_id = true;  // Many binary protocols include server identification
                }
            }
        }
        
        // Advanced protocol detection heuristics for red team operations
        // These patterns help identify specific protocol families
        
        // Database protocol detection
        if (null_count > 5.0 && response_length < 100.0) || 
           (port == 3306 || port == 5432 || port == 1433) {
            // Probable database protocol (MySQL, PostgreSQL, MSSQL)
            text_features.has_server_id = true;
        }
        
        // TLS/SSL detection
        if (response_length > 5.0 && data[0] == 0x16 && data[1] <= 0x03) ||
           (port == 443 || port == 8443) {
            // Probable TLS handshake
            text_features.has_binary = true;
            text_features.has_server_id = true;
        }
        
        text_features
    }
}

/// ML-based service identifier for ambiguous or unusual services
/// 
/// This is a simplified implementation of a machine learning approach to 
/// service identification that doesn't rely on external dependencies.
/// In a production environment, this would use a trained model loaded 
/// from a file or embedded binary data.
pub struct MlServiceIdentifier {
    /// Common services fingerprints (trained feature vectors)
    fingerprints: HashMap<String, Vec<ServiceFeatureVector>>,
    
    /// Version detection rules for identified services
    version_patterns: HashMap<String, Vec<(regex::Regex, String)>>,
    
    /// Alternative names for services (e.g., "www" -> "http")
    service_aliases: HashMap<String, String>,
}

impl Default for MlServiceIdentifier {
    fn default() -> Self {
        let mut identifier = Self::new();
        
        // Load embedded fingerprints
        identifier.load_embedded_fingerprints();
        
        // Initialize version detection rules
        identifier.initialize_version_patterns();
        
        // Initialize service aliases
        identifier.initialize_service_aliases();
        
        identifier
    }
}

impl MlServiceIdentifier {
    /// Create a new ML service identifier with an empty fingerprint database
    pub fn new() -> Self {
        Self {
            fingerprints: HashMap::new(),
            version_patterns: HashMap::new(),
            service_aliases: HashMap::new(),
        }
    }
    
    /// Load fingerprints from a file
    /// 
    /// In a real implementation, this would load a model file containing
    /// trained fingerprints. For this implementation, we'll use embedded data.
    #[allow(dead_code)]
    pub fn load_fingerprints(&mut self, _filepath: &Path) -> Result<()> {
        // In a real implementation, this would:
        // 1. Load a file containing serialized service fingerprints
        // 2. Deserialize into the fingerprints HashMap
        // 3. Return success or an error
        
        // For now, just use the embedded fingerprints
        self.load_embedded_fingerprints();
        
        Ok(())
    }
    
    /// Load embedded fingerprints for common services
    /// 
    /// This creates a set of simulated "trained" fingerprints for common services
    /// based on known characteristics. In a real implementation, these would be
    /// generated from a large dataset of actual service responses.
    fn load_embedded_fingerprints(&mut self) {
        // Clear existing fingerprints
        self.fingerprints.clear();
        
        // Create HTTP fingerprints
        let mut http_fingerprints = Vec::new();
        
        // Typical HTTP server response
        http_fingerprints.push(ServiceFeatureVector {
            response_length: 500.0,
            printable_ratio: 0.99,
            alpha_ratio: 0.65,
            numeric_ratio: 0.05,
            whitespace_ratio: 0.15,
            special_ratio: 0.15,
            entropy: 4.5,
            avg_line_length: 30.0,
            max_line_length: 80.0,
            line_count: 10.0,
            null_count: 0.0,
            
            has_version_number: true,
            has_server_id: true,
            has_date: true,
            has_ip_address: false,
            has_hostname: true,
            has_status_code: true,
            has_html: true,
            has_xml: false,
            has_json: false,
            has_binary: false,
            
            port: 80,
            is_well_known_port: true,
            is_registered_port: false,
            
            starts_with_http: true,
            starts_with_ssh: false,
            starts_with_ftp: false,
            starts_with_smtp: false,
            starts_with_pop3: false,
            starts_with_imap: false,
            
            immediate_close: false,
            server_initiated: false,
            response_time_ms: 50.0,
        });
        
        // Add more HTTP variants
        // HTTP on alternate port
        let mut http_alt = http_fingerprints[0].clone();
        http_alt.port = 8080;
        http_alt.is_well_known_port = false;
        http_alt.is_registered_port = true;
        http_fingerprints.push(http_alt);
        
        // HTTP minimal response
        let mut http_minimal = http_fingerprints[0].clone();
        http_minimal.response_length = 200.0;
        http_minimal.has_server_id = false;
        http_minimal.has_date = false;
        http_minimal.has_html = false;
        http_fingerprints.push(http_minimal);
        
        // Add HTTP fingerprints to the database
        self.fingerprints.insert("http".to_string(), http_fingerprints);
        
        // Create SSH fingerprints
        let mut ssh_fingerprints = Vec::new();
        ssh_fingerprints.push(ServiceFeatureVector {
            response_length: 25.0,
            printable_ratio: 1.0,
            alpha_ratio: 0.7,
            numeric_ratio: 0.2,
            whitespace_ratio: 0.0,
            special_ratio: 0.1,
            entropy: 3.8,
            avg_line_length: 25.0,
            max_line_length: 25.0,
            line_count: 1.0,
            null_count: 0.0,
            
            has_version_number: true,
            has_server_id: true,
            has_date: false,
            has_ip_address: false,
            has_hostname: false,
            has_status_code: false,
            has_html: false,
            has_xml: false,
            has_json: false,
            has_binary: false,
            
            port: 22,
            is_well_known_port: true,
            is_registered_port: false,
            
            starts_with_http: false,
            starts_with_ssh: true,
            starts_with_ftp: false,
            starts_with_smtp: false,
            starts_with_pop3: false,
            starts_with_imap: false,
            
            immediate_close: false,
            server_initiated: true,
            response_time_ms: 20.0,
        });
        
        // Add SSH fingerprints to the database
        self.fingerprints.insert("ssh".to_string(), ssh_fingerprints);
        
        // Add fingerprints for other common services
        // (In a real implementation, there would be dozens or hundreds of services with
        // multiple fingerprints each, trained on real-world data)
        
        // FTP
        let mut ftp_fingerprints = Vec::new();
        ftp_fingerprints.push(ServiceFeatureVector {
            response_length: 40.0,
            printable_ratio: 1.0,
            alpha_ratio: 0.6,
            numeric_ratio: 0.1,
            whitespace_ratio: 0.1,
            special_ratio: 0.2,
            entropy: 3.9,
            avg_line_length: 40.0,
            max_line_length: 40.0,
            line_count: 1.0,
            null_count: 0.0,
            
            has_version_number: true,
            has_server_id: true,
            has_date: false,
            has_ip_address: false,
            has_hostname: true,
            has_status_code: false,
            has_html: false,
            has_xml: false,
            has_json: false,
            has_binary: false,
            
            port: 21,
            is_well_known_port: true,
            is_registered_port: false,
            
            starts_with_http: false,
            starts_with_ssh: false,
            starts_with_ftp: true,
            starts_with_smtp: false,
            starts_with_pop3: false,
            starts_with_imap: false,
            
            immediate_close: false,
            server_initiated: true,
            response_time_ms: 30.0,
        });
        
        self.fingerprints.insert("ftp".to_string(), ftp_fingerprints);
        
        // SMTP
        let mut smtp_fingerprints = Vec::new();
        smtp_fingerprints.push(ServiceFeatureVector {
            response_length: 50.0,
            printable_ratio: 1.0,
            alpha_ratio: 0.6,
            numeric_ratio: 0.1,
            whitespace_ratio: 0.1,
            special_ratio: 0.2,
            entropy: 4.0,
            avg_line_length: 50.0,
            max_line_length: 50.0,
            line_count: 1.0,
            null_count: 0.0,
            
            has_version_number: true,
            has_server_id: true,
            has_date: false,
            has_ip_address: false,
            has_hostname: true,
            has_status_code: false,
            has_html: false,
            has_xml: false,
            has_json: false,
            has_binary: false,
            
            port: 25,
            is_well_known_port: true,
            is_registered_port: false,
            
            starts_with_http: false,
            starts_with_ssh: false,
            starts_with_ftp: false,
            starts_with_smtp: true,
            starts_with_pop3: false,
            starts_with_imap: false,
            
            immediate_close: false,
            server_initiated: true,
            response_time_ms: 40.0,
        });
        
        self.fingerprints.insert("smtp".to_string(), smtp_fingerprints);
        
        // MySQL - more binary
        let mut mysql_fingerprints = Vec::new();
        mysql_fingerprints.push(ServiceFeatureVector {
            response_length: 40.0,
            printable_ratio: 0.5,
            alpha_ratio: 0.3,
            numeric_ratio: 0.1,
            whitespace_ratio: 0.0,
            special_ratio: 0.1,
            entropy: 5.5,
            avg_line_length: 0.0,
            max_line_length: 0.0,
            line_count: 0.0,
            null_count: 0.0,
            
            has_version_number: true,
            has_server_id: false,
            has_date: false,
            has_ip_address: false,
            has_hostname: false,
            has_status_code: false,
            has_html: false,
            has_xml: false,
            has_json: false,
            has_binary: true,
            
            port: 3306,
            is_well_known_port: false,
            is_registered_port: true,
            
            starts_with_http: false,
            starts_with_ssh: false,
            starts_with_ftp: false,
            starts_with_smtp: false,
            starts_with_pop3: false,
            starts_with_imap: false,
            
            immediate_close: false,
            server_initiated: true,
            response_time_ms: 20.0,
        });
        
        self.fingerprints.insert("mysql".to_string(), mysql_fingerprints);
    }
    
    /// Initialize version detection patterns for common services
    fn initialize_version_patterns(&mut self) {
        use regex::Regex;
        
        // HTTP/Web servers
        let http_patterns = vec![
            (Regex::new(r"Server: Apache/(\d+\.\d+\.\d+)").unwrap(), "Apache $1".to_string()),
            (Regex::new(r"Server: nginx/(\d+\.\d+\.\d+)").unwrap(), "nginx $1".to_string()),
            (Regex::new(r"Server: Microsoft-IIS/(\d+\.\d+)").unwrap(), "IIS $1".to_string()),
            (Regex::new(r"Server: lighttpd/(\d+\.\d+\.\d+)").unwrap(), "lighttpd $1".to_string()),
        ];
        self.version_patterns.insert("http".to_string(), http_patterns);
        
        // SSH
        let ssh_patterns = vec![
            (Regex::new(r"SSH-2\.0-OpenSSH_(\d+\.\d+\w*)").unwrap(), "OpenSSH $1".to_string()),
            (Regex::new(r"SSH-2\.0-(\w+)_(\d+\.\d+\.\d+)").unwrap(), "$1 $2".to_string()),
        ];
        self.version_patterns.insert("ssh".to_string(), ssh_patterns);
        
        // FTP
        let ftp_patterns = vec![
            (Regex::new(r"220.*FileZilla Server\s+version\s+(\d+\.\d+\.\d+)").unwrap(), "FileZilla $1".to_string()),
            (Regex::new(r"220.*ProFTPD\s+(\d+\.\d+\.\d+)").unwrap(), "ProFTPD $1".to_string()),
            (Regex::new(r"220.*FTP\s+server\s+\((\w+)\s+(\d+\.\d+\.\d+)\)").unwrap(), "$1 $2".to_string()),
        ];
        self.version_patterns.insert("ftp".to_string(), ftp_patterns);
        
        // SMTP
        let smtp_patterns = vec![
            (Regex::new(r"220.*Postfix\s+\((\d+\.\d+\.\d+)\)").unwrap(), "Postfix $1".to_string()),
            (Regex::new(r"220.*Sendmail\s+(\d+\.\d+\.\d+)").unwrap(), "Sendmail $1".to_string()),
            (Regex::new(r"220.*Exim\s+(\d+\.\d+\.\d+)").unwrap(), "Exim $1".to_string()),
        ];
        self.version_patterns.insert("smtp".to_string(), smtp_patterns);
    }
    
    /// Initialize service aliases (alternative names for services)
    fn initialize_service_aliases(&mut self) {
        // HTTP/HTTPS related
        self.service_aliases.insert("www".to_string(), "http".to_string());
        self.service_aliases.insert("https".to_string(), "http".to_string());
        self.service_aliases.insert("http-alt".to_string(), "http".to_string());
        self.service_aliases.insert("web".to_string(), "http".to_string());
        
        // SSH related
        self.service_aliases.insert("sshd".to_string(), "ssh".to_string());
        
        // Mail related
        self.service_aliases.insert("mail".to_string(), "smtp".to_string());
        self.service_aliases.insert("smtps".to_string(), "smtp".to_string());
        self.service_aliases.insert("imaps".to_string(), "imap".to_string());
        self.service_aliases.insert("pop3s".to_string(), "pop3".to_string());
    }
    
    /// Calculate the Euclidean distance between two feature vectors
    /// 
    /// Uses a weighted approach to give more importance to key features
    /// while downplaying the influence of less reliable ones.
    fn calculate_distance(&self, a: &ServiceFeatureVector, b: &ServiceFeatureVector) -> f32 {
        let mut distance = 0.0;
        
        // Numeric features - weighted by importance
        distance += 0.8 * (a.response_length - b.response_length).powf(2.0) / 1000000.0; // Normalize large values
        distance += 2.0 * (a.printable_ratio - b.printable_ratio).powf(2.0);
        distance += 1.5 * (a.alpha_ratio - b.alpha_ratio).powf(2.0);
        distance += 0.8 * (a.numeric_ratio - b.numeric_ratio).powf(2.0);
        distance += 0.5 * (a.whitespace_ratio - b.whitespace_ratio).powf(2.0);
        distance += 0.5 * (a.special_ratio - b.special_ratio).powf(2.0);
        distance += 3.0 * (a.entropy - b.entropy).powf(2.0) / 36.0; // Normalize to 0-1 range (max entropy ~6)
        distance += 0.5 * (a.avg_line_length - b.avg_line_length).powf(2.0) / 10000.0;
        distance += 0.3 * (a.max_line_length - b.max_line_length).powf(2.0) / 10000.0;
        distance += 0.7 * (a.line_count - b.line_count).powf(2.0) / 1000.0;
        
        // Binary features - convert to 0.0/1.0 and use high weights for distinctive features
        distance += 5.0 * (a.has_version_number as i32 - b.has_version_number as i32).pow(2) as f32;
        distance += 3.0 * (a.has_server_id as i32 - b.has_server_id as i32).pow(2) as f32;
        distance += 0.5 * (a.has_date as i32 - b.has_date as i32).pow(2) as f32;
        distance += 1.0 * (a.has_ip_address as i32 - b.has_ip_address as i32).pow(2) as f32;
        distance += 1.0 * (a.has_hostname as i32 - b.has_hostname as i32).pow(2) as f32;
        distance += 3.0 * (a.has_status_code as i32 - b.has_status_code as i32).pow(2) as f32;
        distance += 4.0 * (a.has_html as i32 - b.has_html as i32).pow(2) as f32;
        distance += 4.0 * (a.has_xml as i32 - b.has_xml as i32).pow(2) as f32;
        distance += 4.0 * (a.has_json as i32 - b.has_json as i32).pow(2) as f32;
        distance += 5.0 * (a.has_binary as i32 - b.has_binary as i32).pow(2) as f32;
        
        // Port-related features - less weight to allow for non-standard ports
        distance += 0.1 * (a.port as f32 - b.port as f32).powf(2.0) / 65536.0; // Normalize port difference
        distance += 0.2 * (a.is_well_known_port as i32 - b.is_well_known_port as i32).pow(2) as f32;
        distance += 0.2 * (a.is_registered_port as i32 - b.is_registered_port as i32).pow(2) as f32;
        
        // Protocol indicators - very high weight for definitive protocol markers
        distance += 8.0 * (a.starts_with_http as i32 - b.starts_with_http as i32).pow(2) as f32;
        distance += 8.0 * (a.starts_with_ssh as i32 - b.starts_with_ssh as i32).pow(2) as f32;
        distance += 8.0 * (a.starts_with_ftp as i32 - b.starts_with_ftp as i32).pow(2) as f32;
        distance += 8.0 * (a.starts_with_smtp as i32 - b.starts_with_smtp as i32).pow(2) as f32;
        distance += 8.0 * (a.starts_with_pop3 as i32 - b.starts_with_pop3 as i32).pow(2) as f32;
        distance += 8.0 * (a.starts_with_imap as i32 - b.starts_with_imap as i32).pow(2) as f32;
        
        // Connection behavior - high weight for distinctive behavior
        distance += 3.0 * (a.immediate_close as i32 - b.immediate_close as i32).pow(2) as f32;
        distance += 3.0 * (a.server_initiated as i32 - b.server_initiated as i32).pow(2) as f32;
        distance += 0.5 * (a.response_time_ms - b.response_time_ms).powf(2.0) / 10000.0; // Normalize time
        
        distance.sqrt() // Return Euclidean distance
    }
    
    /// Identify a service based on banner and metadata using ML approach
    /// 
    /// Uses a k-Nearest Neighbors approach to classify the service based on
    /// its feature vector compared to known service fingerprints.
    pub fn identify_service(
        &self,
        banner: &str,
        port: u16,
        response_time_ms: f32,
        immediate_close: bool,
        server_initiated: bool
    ) -> Option<(String, Option<String>)> {
        // Extract feature vector from banner
        let features = ServiceFeatureVector::from_banner(
            banner, port, response_time_ms, immediate_close, server_initiated
        );
        
        debug!("Extracted feature vector for port {} with entropy {:.2}", port, features.entropy);
        
        // Try quick identification first based on definitive protocol markers
        if let Some(service) = self.quick_identify(&features) {
            debug!("Quick identification found service: {}", service);
            
            // Try to extract version
            let version = self.extract_version(service, banner);
            
            return Some((service.to_string(), version));
        }
        
        // If quick identification fails, use KNN algorithm
        
        // Calculate distances to all known fingerprints
        let mut distances = Vec::new();
        
        for (service_name, fingerprints) in &self.fingerprints {
            for fingerprint in fingerprints {
                let distance = self.calculate_distance(&features, fingerprint);
                distances.push((service_name.clone(), distance));
            }
        }
        
        // Sort by distance (closest first)
        distances.sort_by(|a, b| a.1.partial_cmp(&b.1).unwrap_or(std::cmp::Ordering::Equal));
        
        // Take top K results
        const K: usize = 3;
        let top_k = distances.iter().take(K).collect::<Vec<_>>();
        
        // Check if we have enough matches
        if top_k.is_empty() {
            return None;
        }
        
        // Check if the closest match is significantly closer than others
        // (strong confidence in the classification)
        if top_k.len() == 1 || (top_k[0].1 < 5.0 && top_k[0].1 * 1.5 < top_k[1].1) {
            let service = &top_k[0].0;
            debug!("Confident ML identification: {} (distance: {:.2})", service, top_k[0].1);
            
            // Try to extract version
            let version = self.extract_version(service, banner);
            
            return Some((service.clone(), version));
        }
        
        // Otherwise, use voting approach for top K
        let mut votes = HashMap::new();
        for (service, distance) in top_k {
            // Weight vote by inverse distance
            let weight = 1.0 / (distance + 0.1); // Add small constant to avoid division by zero
            *votes.entry(service.clone()).or_insert(0.0) += weight;
        }
        
        // Find service with highest weighted vote
        let mut best_service = None;
        let mut best_vote = 0.0;
        
        for (service, vote) in votes {
            if vote > best_vote {
                best_vote = vote;
                best_service = Some(service);
            }
        }
        
        // Return the best service with version if found
        if let Some(service) = best_service {
            debug!("ML identification by voting: {} (score: {:.2})", service, best_vote);
            
            // Try to extract version
            let version = self.extract_version(&service, banner);
            
            return Some((service, version));
        }
        
        None
    }
    
    /// Quick identification based on definitive protocol markers
    fn quick_identify(&self, features: &ServiceFeatureVector) -> Option<&str> {
        // Check for definitive protocol markers first
        if features.starts_with_http {
            return Some("http");
        } else if features.starts_with_ssh {
            return Some("ssh");
        } else if features.starts_with_ftp {
            return Some("ftp");
        } else if features.starts_with_smtp {
            return Some("smtp");
        } else if features.starts_with_pop3 {
            return Some("pop3");
        } else if features.starts_with_imap {
            return Some("imap");
        }
        
        // No definitive marker found
        None
    }
    
    /// Extract version information from banner using service-specific patterns
    fn extract_version(&self, service: &str, banner: &str) -> Option<String> {
        // Check if we have version patterns for this service
        if let Some(patterns) = self.version_patterns.get(service) {
            for (regex, format) in patterns {
                if let Some(captures) = regex.captures(banner) {
                    let mut version = format.clone();
                    
                    // Replace capture groups in version format
                    for i in 1..captures.len() {
                        if let Some(m) = captures.get(i) {
                            version = version.replace(&format!("${}", i), m.as_str());
                        }
                    }
                    
                    debug!("Extracted version for {}: {}", service, version);
                    return Some(version);
                }
            }
        }
        
        // Check for aliases
        if let Some(canonical) = self.service_aliases.get(service) {
            return self.extract_version(canonical, banner);
        }
        
        None
    }
    
    /// Identify service from binary data
    ///
    /// This function analyzes binary protocol responses to identify the service type.
    /// For operational security, this approach avoids using predefined signatures that
    /// could be flagged by defensive measures. Instead, it uses statistical analysis
    /// of response characteristics to identify services.
    pub fn identify_binary_service(
        &self,
        data: &[u8],
        port: u16,
        response_time_ms: f32,
        immediate_close: bool,
        server_initiated: bool
    ) -> Option<(String, Option<String>)> {
        // First, create a feature vector from the binary data
        // This extracts statistical properties without relying on exact pattern matching
        let features = ServiceFeatureVector::from_binary(
            data, 
            port, 
            response_time_ms, 
            immediate_close, 
            server_initiated
        );
        
        // Log minimal information for operational security
        // Avoid logging the actual binary data which could contain sensitive information
        debug!("Analyzing binary protocol response on port {} - Length: {}, Entropy: {:.2}, Binary: {}", 
               port, data.len(), features.entropy, features.has_binary);
        
        // First attempt a quick identification based on port number and obvious indicators
        // This is faster and often sufficient for common services
        if let Some(service_name) = self.quick_identify(&features) {
            // For OpSec, we use a sanitized string representation that doesn't include
            // the entire binary payload in logs
            let banner = String::from_utf8_lossy(data);
            
            // Try to extract the version from any ASCII parts of the response
            let version = self.extract_version(service_name, &banner);
            
            return Some((service_name.to_string(), version));
        }
        
        // If quick identification didn't work, proceed with more detailed analysis
        // Calculate distance-based similarity to all known service fingerprints
        let mut best_match: Option<(String, f32)> = None;
        let mut best_distance = f32::MAX;
        
        // For operational security, we iterate through all fingerprints to maintain
        // consistent timing regardless of whether we find a match quickly
        for (service_name, fingerprints) in &self.fingerprints {
            for fingerprint in fingerprints {
                // Calculate vector distance using specialized weights for binary protocols
                let mut distance = self.calculate_distance(&features, fingerprint);
                
                // Apply heuristic adjustments for binary protocols to improve accuracy
                // This is important for red team operations where false positives could
                // lead to incorrect assumptions about target systems
                if features.has_binary {
                    // Reduce distance (increase similarity) for services commonly using binary protocols
                    if service_name == "tls" || 
                       service_name == "ssl" || 
                       service_name == "rdp" || 
                       service_name == "mysql" || 
                       service_name == "smb" {
                        distance *= 0.8;  // 20% boost in confidence for known binary protocols
                    }
                    
                    // Further adjust based on entropy comparison
                    // Binary protocols have characteristic entropy signatures
                    let entropy_diff = (features.entropy - fingerprint.entropy).abs();
                    if entropy_diff < 1.0 {
                        distance *= 0.9;  // 10% boost for matching entropy profile
                    }
                    
                    // Port-based adjustment - higher confidence when on standard ports
                    if features.port == fingerprint.port {
                        distance *= 0.85;  // 15% boost for standard port match
                    }
                }
                
                // Track the best match we've found so far
                if distance < best_distance {
                    best_distance = distance;
                    best_match = Some((service_name.clone(), distance));
                }
            }
        }
        
        // Use a more permissive threshold for binary protocols
        // Binary protocols often have more variance than text-based ones
        let binary_threshold = 5.0;
        
        // If we found a match within our confidence threshold
        if let Some((service_name, distance)) = best_match {
            if distance < binary_threshold {
                // Calculate a confidence score between 0-1 for operational assessment
                let confidence = 1.0 - distance/binary_threshold;
                debug!("Binary protocol identified as {} with confidence {:.2}", 
                       service_name, confidence);
                
                // For red team operations, version information is highly valuable
                // Try to extract version info from any readable text portions
                let banner = String::from_utf8_lossy(data);
                let version = self.extract_version(&service_name, &banner);
                
                return Some((service_name, version));
            }
        }
        
        // If no specific match was found, attempt to categorize based on characteristics
        // This is still valuable information for red team operations
        if features.has_binary {
            if features.entropy > 7.0 {
                // Very high entropy often indicates encryption or compression
                // For red team operations, identifying encrypted channels is valuable
                debug!("Detected high-entropy encrypted protocol on port {}", port);
                return Some(("encrypted".to_string(), None));
            } else if features.printable_ratio < 0.2 {
                // Mostly binary data with very few printable characters
                // Classic binary protocol signature
                debug!("Detected binary protocol on port {}", port);
                return Some(("binary-protocol".to_string(), None));
            } else if features.null_count > 10.0 && features.printable_ratio > 0.4 {
                // Mixed binary and text with null bytes - often indicates
                // a database protocol or similar structured binary format
                debug!("Detected structured binary protocol on port {}", port);
                return Some(("structured-binary".to_string(), None));
            }
        }
        
        // No confident identification possible
        None
    }
}

/// Create a new ML-based service identifier
pub fn create_ml_identifier() -> MlServiceIdentifier {
    MlServiceIdentifier::default()
} 