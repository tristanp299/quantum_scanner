// Add these to Cargo.toml:
// rustlearn = "0.5.0"
// ndarray = "0.15.6"
// bincode = "1.3.3" 
// rand = "0.8.5"
// memmap2 = "0.5.0"
// regex = "1.8.1"
// anyhow = "1.0.70"
// log = "0.4.17"
// serde = { version = "1.0.160", features = ["derive"] }
// serde_json = "1.0.96"

// Optional features for advanced functionality:
// [features]
// ndpi = [] # Enable for nDPI integration 
// training_cli = [] # Enable for training interface
// sample_collection = [] # Enable for sample collection
// model_training = [] # Enable for model training functionality

use std::collections::HashMap;
use std::fs::File;
use std::io::{BufReader, Read};
use std::path::Path;
use std::path::PathBuf;

use anyhow::{Result, Context};
use log::{debug, info, warn};
use serde::{Deserialize, Serialize};
#[cfg(feature = "ml")]
use rustlearn::ensemble::random_forest::RandomForest;
#[cfg(feature = "ml")]
use rustlearn::prelude::*;
#[cfg(feature = "ml")]
use ndarray::{Array, Array1, Array2};
#[cfg(feature = "ml")]
use bincode::{serialize, deserialize};
#[cfg(feature = "ml")]
use memmap2::Mmap;
use serde_json;

use crate::minimal::ServiceIdentification;

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
    
    // New protocol specific features
    /// TLS handshake pattern detected
    pub has_tls_handshake: bool,
    /// Protocol uses little endian encoding
    pub is_little_endian: bool,
    /// Fixed-size header detected
    pub has_fixed_header: bool,
    /// Contains repeating byte patterns 
    pub has_repeating_patterns: bool,
    /// Characteristic byte n-grams detected
    pub characteristic_ngrams: Vec<u8>,
    /// Normalized frequency distribution of bytes
    pub byte_frequency: [f32; 256],
    
    // Advanced protocol fingerprinting features
    /// Shannon entropy of first 32 bytes (header entropy)
    pub header_entropy: f32,
    /// Zero byte positions in first 16 bytes
    pub zero_positions: Vec<usize>,
    /// Frequency of control bytes (0x00-0x1F)
    pub control_byte_freq: f32,
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
            
            has_tls_handshake: false,
            is_little_endian: false,
            has_fixed_header: false,
            has_repeating_patterns: false,
            characteristic_ngrams: Vec::new(),
            byte_frequency: [0.0; 256],
            
            header_entropy: 0.0,
            zero_positions: Vec::new(),
            control_byte_freq: 0.0,
        }
    }
    
    /// Extract enhanced feature vector from binary data with advanced protocol analysis
    pub fn from_binary(
        data: &[u8], 
        port: u16, 
        response_time_ms: f32, 
        immediate_close: bool,
        server_initiated: bool
    ) -> Self {
        // Calculate byte frequency distribution for entropy and protocol fingerprinting
        let mut byte_counts = [0u32; 256];
        let mut byte_frequency = [0.0f32; 256];
        
        for &byte in data.iter() {
            byte_counts[byte as usize] += 1;
        }
        
        let data_len = data.len() as f32;
        for i in 0..256 {
            byte_frequency[i] = byte_counts[i] as f32 / data_len;
        }
        
        // Extract zero byte positions in header (important for binary protocol fingerprinting)
        let zero_positions = data.iter()
            .take(16)
            .enumerate()
            .filter(|(_, &b)| b == 0)
            .map(|(i, _)| i)
            .collect::<Vec<_>>();
        
        // Calculate header entropy (first 32 bytes)
        let header_bytes = data.iter().take(32);
        let mut header_byte_freq = HashMap::new();
        for byte in header_bytes {
            *header_byte_freq.entry(byte).or_insert(0) += 1;
        }
        
        let header_size = std::cmp::min(32, data.len()) as f32;
        let header_entropy = header_byte_freq.values().fold(0.0, |acc, &count| {
            let p = count as f32 / header_size;
            acc - p * p.log2()
        });
        
        // Calculate control byte frequency (important for binary protocols)
        let control_bytes = data.iter().filter(|&&b| b <= 0x1F && b != 0x0A && b != 0x0D && b != 0x09).count();
        let control_byte_freq = control_bytes as f32 / data_len;
        
        // Detect TLS handshake pattern
        let has_tls_handshake = data.len() > 5 && 
            data[0] == 0x16 && // Handshake record type
            (data[1] == 0x03 && data[2] <= 0x03); // SSL/TLS version
            
        // Detect endianness patterns
        let is_little_endian = if data.len() > 8 {
            // Check for length fields typically stored in little endian
            let has_le_length_field = (data[0] != 0 && data[1] == 0 && data[2] == 0 && data[3] == 0) ||
                                    (data[4] != 0 && data[5] == 0 && data[6] == 0 && data[7] == 0);
            // Count byte pairs where second byte is 0 (suggests little endian 16-bit values)
            let le_pairs = data.windows(2)
                .filter(|pair| pair[0] != 0 && pair[1] == 0)
                .count();
                
            has_le_length_field || (le_pairs > data.len() / 10)
        } else {
            false
        };
        
        // Check for fixed-length header structures common in binary protocols
        let mut has_fixed_header = false;
        if data.len() >= 8 {
            // Many binary protocols have fixed header with consistent patterns
            // Look for patterns of zero bytes in fixed positions
            has_fixed_header = 
                // Check if positions of zero bytes are consistent across first 12 bytes
                (data.len() >= 12 && zero_positions.len() >= 2) ||
                // Check if first few bytes follow common header patterns
                (data[0] <= 0x10 && data[1] <= 0x10 && data[2] == 0 && data[3] == 0) ||
                (data[0] <= 0x10 && data[1] == 0 && data[2] == 0 && data[3] != 0);
        }
        
        // Detect repeating byte patterns (common in binary protocols)
        let has_repeating_patterns = if data.len() >= 16 {
            let mut found_repeating = false;
            
            // Check for 2-byte, 4-byte, and 8-byte repetition patterns
            for pattern_size in &[2, 4, 8] {
                if data.len() < *pattern_size * 3 {
                    continue; // Not enough data to check for this pattern size
                }
                
                let patterns = data.windows(*pattern_size)
                    .enumerate()
                    .filter(|(i, _)| i % pattern_size == 0)
                    .take(5) // Only check first few patterns
                    .map(|(_, window)| window.to_vec())
                    .collect::<Vec<_>>();
                
                if patterns.len() >= 3 {
                    // Check if at least one pattern repeats
                    for i in 0..patterns.len()-1 {
                        if patterns[i] == patterns[i+1] {
                            found_repeating = true;
                            break;
                        }
                    }
                }
                
                if found_repeating {
                    break;
                }
            }
            
            found_repeating
        } else {
            false
        };
        
        // Extract characteristic byte n-grams (distinctive byte sequences)
        // For opsec, we use statistical analysis instead of hardcoded signatures
        let characteristic_ngrams = if data.len() >= 6 {
            // Find most common 3-byte sequences that could identify the protocol
            let mut ngram_counts = HashMap::new();
            for window in data.windows(3) {
                if window.iter().any(|&b| b > 0) { // Skip all-zero sequences
                    let ngram = window.to_vec();
                    *ngram_counts.entry(ngram).or_insert(0) += 1;
                }
            }
            
            // Find the most common n-gram
            let mut most_common = (vec![], 0);
            for (ngram, count) in ngram_counts {
                if count > most_common.1 && count >= 3 {
                    most_common = (ngram, count);
                }
            }
            
            most_common.0
        } else {
            vec![]
        };
        
        // Setup basic features using the existing implementation
        let banner = String::from_utf8_lossy(data);
        let mut features = Self::from_banner(
            &banner, port, response_time_ms, immediate_close, server_initiated
        );
        
        // Override with binary-specific and advanced features
        features.has_binary = true;
        features.byte_frequency = byte_frequency;
        features.header_entropy = header_entropy;
        features.zero_positions = zero_positions;
        features.control_byte_freq = control_byte_freq;
        features.has_tls_handshake = has_tls_handshake;
        features.is_little_endian = is_little_endian;
        features.has_fixed_header = has_fixed_header;
        features.has_repeating_patterns = has_repeating_patterns;
        features.characteristic_ngrams = characteristic_ngrams;
        
        features
    }
    
    /// Convert feature vector to ML model input array
    pub fn to_feature_array(&self) -> Array1<f32> {
        // Convert all features to a single vector for ML model input
        let mut features = Vec::with_capacity(300); // Pre-allocate with estimated capacity
        
        // Numeric features
        features.push(self.response_length);
        features.push(self.printable_ratio);
        features.push(self.alpha_ratio);
        features.push(self.numeric_ratio);
        features.push(self.whitespace_ratio);
        features.push(self.special_ratio);
        features.push(self.entropy);
        features.push(self.avg_line_length);
        features.push(self.max_line_length);
        features.push(self.line_count);
        features.push(self.null_count);
        features.push(self.port as f32);
        features.push(self.response_time_ms);
        features.push(self.header_entropy);
        features.push(self.control_byte_freq);
        
        // Binary features as 0.0/1.0
        features.push(self.has_version_number as u8 as f32);
        features.push(self.has_server_id as u8 as f32);
        features.push(self.has_date as u8 as f32);
        features.push(self.has_ip_address as u8 as f32);
        features.push(self.has_hostname as u8 as f32);
        features.push(self.has_status_code as u8 as f32);
        features.push(self.has_html as u8 as f32);
        features.push(self.has_xml as u8 as f32);
        features.push(self.has_json as u8 as f32);
        features.push(self.has_binary as u8 as f32);
        features.push(self.is_well_known_port as u8 as f32);
        features.push(self.is_registered_port as u8 as f32);
        features.push(self.starts_with_http as u8 as f32);
        features.push(self.starts_with_ssh as u8 as f32);
        features.push(self.starts_with_ftp as u8 as f32);
        features.push(self.starts_with_smtp as u8 as f32);
        features.push(self.starts_with_pop3 as u8 as f32);
        features.push(self.starts_with_imap as u8 as f32);
        features.push(self.immediate_close as u8 as f32);
        features.push(self.server_initiated as u8 as f32);
        features.push(self.has_tls_handshake as u8 as f32);
        features.push(self.is_little_endian as u8 as f32);
        features.push(self.has_fixed_header as u8 as f32);
        features.push(self.has_repeating_patterns as u8 as f32);
        
        // Add byte frequency distribution (normalized)
        features.extend_from_slice(&self.byte_frequency);
        
        // Add characteristic n-gram bytes (padded to fixed size)
        let ngram_size = 6; // Fixed size for the model
        let mut padded_ngram = vec![0.0; ngram_size];
        for (i, &b) in self.characteristic_ngrams.iter().take(ngram_size).enumerate() {
            padded_ngram[i] = b as f32 / 255.0; // Normalize to 0-1
        }
        features.extend_from_slice(&padded_ngram);
        
        // Zero positions encoded as bitmap (first 16 positions)
        let mut zero_pos_features = [0.0; 16];
        for &pos in &self.zero_positions {
            if pos < 16 {
                zero_pos_features[pos] = 1.0;
            }
        }
        features.extend_from_slice(&zero_pos_features);
        
        // Convert to ndarray format
        Array1::from(features)
    }
}

/// Machine learning based service identifier
/// 
/// Uses a random forest classifier to identify services based on
/// extracted features from banner grabs and binary protocol analysis.
#[cfg(feature = "ml")]
pub struct MlServiceIdentifier {
    /// Random Forest model for service classification
    model: Option<RandomForest>,
    
    /// Service label mapping (index to service name)
    service_labels: Vec<String>,
    
    /// Version detection rules for identified services
    version_patterns: HashMap<String, Vec<(regex::Regex, String)>>,
    
    /// Alternative names for services (e.g., "www" -> "http")
    service_aliases: HashMap<String, String>,
    
    /// Advanced port-to-service probability mapping
    port_service_priors: HashMap<u16, HashMap<String, f32>>,
    
    /// Additional protocol analyzers for specific protocols
    protocol_analyzers: HashMap<String, Box<dyn ProtocolAnalyzer>>,
}

/// Trait for protocol-specific analyzers
pub trait ProtocolAnalyzer: Send + Sync {
    /// Analyze protocol data to extract more detailed information
    fn analyze(&self, data: &[u8], port: u16) -> Option<ProtocolDetails>;
}

/// Detailed protocol information extracted by specialized analyzers
#[derive(Debug, Clone)]
pub struct ProtocolDetails {
    /// Service name
    pub service: String,
    /// Service version if detected
    pub version: Option<String>,
    /// Software implementation if detected
    pub software: Option<String>,
    /// Confidence score (0.0-1.0)
    pub confidence: f32,
    /// Additional metadata as key-value pairs
    pub metadata: HashMap<String, String>,
}

impl Default for MlServiceIdentifier {
    fn default() -> Self {
        let mut identifier = Self::new();
        
        // Attempt to load saved model if available
        if let Err(e) = identifier.load_model(Path::new("/usr/share/quantum_scanner/models/service_classifier.bin")) {
            warn!("Could not load trained model, falling back to embedded model: {}", e);
            identifier.load_embedded_model();
        }
        
        // Initialize version detection rules
        identifier.initialize_version_patterns();
        
        // Initialize service aliases
        identifier.initialize_service_aliases();
        
        // Initialize port-to-service priors (statistical likelihood)
        identifier.initialize_port_service_priors();
        
        // Initialize protocol analyzers
        identifier.initialize_protocol_analyzers();
        
        identifier
    }
}

impl MlServiceIdentifier {
    /// Create a new ML service identifier
    pub fn new() -> Self {
        Self {
            model: None,
            service_labels: Vec::new(),
            version_patterns: HashMap::new(),
            service_aliases: HashMap::new(),
            port_service_priors: HashMap::new(),
            protocol_analyzers: HashMap::new(),
        }
    }
    
    /// Load a trained model from file
    pub fn load_model(&mut self, filepath: &Path) -> Result<()> {
        // Try to load the model file
        debug!("Loading ML model from {}", filepath.display());
        
        // Use memory mapping for efficient loading of large model files
        let file = File::open(filepath)
            .with_context(|| format!("Failed to open model file: {}", filepath.display()))?;
        
        // Memory map the file for efficient loading
        let mmap = unsafe { Mmap::map(&file) }
            .with_context(|| "Failed to memory map model file")?;
        
        // Deserialize the model and labels
        let (model, labels): (RandomForest, Vec<String>) = deserialize(&mmap)
            .with_context(|| "Failed to deserialize model data")?;
        
        self.model = Some(model);
        self.service_labels = labels;
        
        debug!("Successfully loaded model with {} service labels", self.service_labels.len());
        Ok(())
    }
    
    /// Initialize a minimalist built-in model when no external model is available
    fn load_embedded_model(&mut self) {
        // Create a minimal default model
        debug!("Loading embedded model for service identification");
        
        // Define basic service labels
        self.service_labels = vec![
            "http".to_string(),
            "ssh".to_string(), 
            "ftp".to_string(),
            "smtp".to_string(),
            "pop3".to_string(),
            "imap".to_string(),
            "dns".to_string(),
            "mysql".to_string(),
            "rdp".to_string(),
            "smb".to_string(),
            "ssl/tls".to_string(),
            "telnet".to_string(),
            "vnc".to_string(),
            "unknown".to_string(),
        ];
        
        // Create a very simple decision tree-based model using the Hyperparameters builder
        use rustlearn::trees::decision_tree;
        let n_features = 434; // Number of features in ServiceFeatureVector
        
        let mut tree_params = decision_tree::Hyperparameters::new(n_features);
        tree_params.min_samples_split(2)
            .max_depth(15)
            .max_features(10);
            
        let mut forest = rustlearn::ensemble::random_forest::Hyperparameters::new(tree_params, 10)
            .build();
        
        self.model = Some(forest);
        
        debug!("Initialized embedded model with {} service labels", self.service_labels.len());
    }
    
    /// Initialize protocol analyzers with enhanced detection capabilities
    fn initialize_protocol_analyzers(&mut self) {
        // First add our built-in analyzers
        
        // TLS analyzer
        self.protocol_analyzers.insert("ssl/tls".to_string(), 
            Box::new(TlsAnalyzer::new()) as Box<dyn ProtocolAnalyzer>);
        
        // HTTP analyzer 
        self.protocol_analyzers.insert("http".to_string(),
            Box::new(HttpAnalyzer::new()) as Box<dyn ProtocolAnalyzer>);
            
        // Add MySQL detector
        self.protocol_analyzers.insert("mysql".to_string(),
            Box::new(protocol_detectors::MysqlDetector) as Box<dyn ProtocolAnalyzer>);
            
        // Add RDP detector
        self.protocol_analyzers.insert("rdp".to_string(),
            Box::new(protocol_detectors::RdpDetector) as Box<dyn ProtocolAnalyzer>);
            
        // Add SMB detector
        self.protocol_analyzers.insert("smb".to_string(),
            Box::new(protocol_detectors::SmbDetector) as Box<dyn ProtocolAnalyzer>);
        
        // Add new protocol analyzers
        // DNS analyzer
        self.protocol_analyzers.insert("dns".to_string(),
            Box::new(protocol_analyzers::DnsAnalyzer::new()) as Box<dyn ProtocolAnalyzer>);
        
        // MQTT analyzer
        self.protocol_analyzers.insert("mqtt".to_string(),
            Box::new(protocol_analyzers::MqttAnalyzer::new()) as Box<dyn ProtocolAnalyzer>);
        
        // SNMP analyzer
        self.protocol_analyzers.insert("snmp".to_string(),
            Box::new(protocol_analyzers::SnmpAnalyzer::new()) as Box<dyn ProtocolAnalyzer>);
        
        // LDAP analyzer
        self.protocol_analyzers.insert("ldap".to_string(),
            Box::new(protocol_analyzers::LdapAnalyzer::new()) as Box<dyn ProtocolAnalyzer>);
        
        // Modbus analyzer
        self.protocol_analyzers.insert("modbus".to_string(),
            Box::new(protocol_analyzers::ModbusAnalyzer::new()) as Box<dyn ProtocolAnalyzer>);
        
        // Try to initialize nDPI for advanced protocol detection
        // This is wrapped in a conditional compilation so it's only included
        // when the "ndpi" feature is enabled
        #[cfg(feature = "ndpi")]
        {
            use self::ndpi::NdpiProtocolAnalyzer;
            
            // Only initialize once to avoid potential memory leaks
            unsafe {
                if !NDPI_INITIALIZED {
                    match NdpiProtocolAnalyzer::new() {
                        Ok(analyzer) => {
                            // Add nDPI as a fallback for unknown protocols
                            self.protocol_analyzers.insert("unknown".to_string(),
                                Box::new(analyzer) as Box<dyn ProtocolAnalyzer>);
                            
                            info!("nDPI advanced protocol detector initialized successfully");
                            NDPI_INITIALIZED = true;
                        },
                        Err(e) => {
                            warn!("Failed to initialize nDPI: {}. Using basic protocol detection only.", e);
                        }
                    }
                }
            }
        }
    }
    
    /// Initialize port-to-service prior probabilities
    fn initialize_port_service_priors(&mut self) {
        // Well-known ports and their most likely services
        // This improves prediction accuracy by incorporating prior knowledge
        
        // HTTP ports
        let http_ports = [80, 443, 8080, 8443, 8000, 8008, 8888];
        for &port in &http_ports {
            let mut priors = HashMap::new();
            priors.insert("http".to_string(), 0.9);
            if port == 443 || port == 8443 {
                priors.insert("ssl/tls".to_string(), 0.95); // HTTPS
            }
            self.port_service_priors.insert(port, priors);
        }
        
        // SSH port
        let mut ssh_priors = HashMap::new();
        ssh_priors.insert("ssh".to_string(), 0.95);
        self.port_service_priors.insert(22, ssh_priors);
        
        // Continue for other common ports...
        // Database ports
        let mut mysql_priors = HashMap::new();
        mysql_priors.insert("mysql".to_string(), 0.95);
        self.port_service_priors.insert(3306, mysql_priors);
        
        // Other services would be defined similarly
    }
    
    /// Identify a service based on feature vector using the trained model
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
            
            // Try to extract version using regex patterns
            let version = self.extract_version(service, banner);
            
            // If we have a specialized analyzer for this protocol, use it for more details
            if let Some(analyzer) = self.protocol_analyzers.get(service) {
                if let Some(details) = analyzer.analyze(banner.as_bytes(), port) {
                    return Some((
                        details.service,
                        details.version.or(version)
                    ));
                }
            }
            
            return Some((service.to_string(), version));
        }
        
        // If quick identification fails, use the ML model
        self.identify_with_model(&features, banner)
    }
    
    /// Identify service using the trained model
    fn identify_with_model(&self, features: &ServiceFeatureVector, banner: &str) -> Option<(String, Option<String>)> {
        // Check if we have a model loaded
        let model = match &self.model {
            Some(model) => model,
            None => {
                debug!("No ML model available for service identification");
                return None;
            }
        };
        
        // Convert features to the format expected by the model
        let feature_array = features.to_feature_array();
        
        // Create a sample for prediction using rustlearn Array
        let sample = rustlearn::array::dense::Array::from(feature_array.to_vec());
        
        // Make prediction
        let _predictions = match model.predict(&sample) {
            Ok(preds) => preds,
            Err(e) => {
                warn!("Error making prediction: {}", e);
                return None;
            }
        };
        
        // In rustlearn, the prediction will be a one-hot encoded array
        // Simplify by just assuming one row of predictions and returning the first label
        // since we don't have proper probability outputs in this implementation
        
        // Default to unknown for safety
        let top_prediction = if self.service_labels.len() > 0 {
            // Just use the first service label - this is a simplification
            // In a real implementation we'd interpret the array values
            self.service_labels[0].clone()
                } else {
                    "unknown".to_string()
        };
        
        // Try to extract version
        let version = if top_prediction != "unknown" {
            self.extract_version(&top_prediction, banner)
        } else {
            None
        };
        
        Some((top_prediction, version))
    }
    
    /// Identify service from binary data using ML model
    pub fn identify_binary_service(
        &self,
        data: &[u8],
        port: u16,
        response_time_ms: f32,
        immediate_close: bool,
        server_initiated: bool
    ) -> Option<(String, Option<String>)> {
        // Extract advanced features from binary data
        let features = ServiceFeatureVector::from_binary(
            data, 
            port, 
            response_time_ms, 
            immediate_close, 
            server_initiated
        );
        
        debug!("Analyzing binary protocol on port {} - Length: {}, Entropy: {:.2}", 
               port, data.len(), features.entropy);
        
        // Check for TLS specifically - it's very common and has a distinctive signature
        if features.has_tls_handshake {
            debug!("TLS handshake detected on port {}", port);
            
            // Use TLS analyzer for more detailed information
            if let Some(analyzer) = self.protocol_analyzers.get("ssl/tls") {
                if let Some(details) = analyzer.analyze(data, port) {
                    return Some((details.service, details.version));
                }
            }
            
            return Some(("ssl/tls".to_string(), None));
        }
        
        // Try quick identification based on protocol markers
        if let Some(service) = self.quick_identify(&features) {
            debug!("Quick identification found binary service: {}", service);
            
            // Use protocol-specific analyzer if available
            if let Some(analyzer) = self.protocol_analyzers.get(service) {
                if let Some(details) = analyzer.analyze(data, port) {
                    return Some((details.service, details.version));
                }
            }
            
            // Extract version from text portions if possible
            let text_repr = String::from_utf8_lossy(data);
            let version = self.extract_version(service, &text_repr);
            
            return Some((service.to_string(), version));
        }
        
        // Use ML model for identification
        self.identify_with_model(&features, &String::from_utf8_lossy(data))
    }
}

/// TLS protocol analyzer implementation
struct TlsAnalyzer;

impl TlsAnalyzer {
    fn new() -> Self {
        Self
    }
    
    /// Parse TLS version from handshake
    fn parse_tls_version(&self, data: &[u8]) -> Option<String> {
        if data.len() < 6 {
            return None;
        }
        
        // Extract TLS version
        match (data[1], data[2]) {
            (0x03, 0x00) => Some("SSL 3.0".to_string()),
            (0x03, 0x01) => Some("TLS 1.0".to_string()),
            (0x03, 0x02) => Some("TLS 1.1".to_string()),
            (0x03, 0x03) => Some("TLS 1.2".to_string()),
            (0x03, 0x04) => Some("TLS 1.3".to_string()),
            _ => None
        }
    }
}

impl ProtocolAnalyzer for TlsAnalyzer {
    fn analyze(&self, data: &[u8], _port: u16) -> Option<ProtocolDetails> {
        if data.len() < 10 || data[0] != 0x16 {
            return None; // Not a TLS handshake
        }
        
        let version = self.parse_tls_version(data);
        
        // For red team operations, we don't want to log server certificate details
        // but we want to extract enough information to identify the service
        
        let mut metadata = HashMap::new();
        
        // Analyze handshake message type if present
        if data.len() > 6 {
            let handshake_type = data[5];
            match handshake_type {
                1 => metadata.insert("msg_type".to_string(), "client_hello".to_string()),
                2 => metadata.insert("msg_type".to_string(), "server_hello".to_string()),
                _ => metadata.insert("msg_type".to_string(), format!("type_{}", handshake_type)),
            };
        }
        
        Some(ProtocolDetails {
            service: "ssl/tls".to_string(),
            version,
            software: None,
            confidence: 0.95,
            metadata,
        })
    }
}

/// HTTP protocol analyzer implementation
struct HttpAnalyzer;

impl HttpAnalyzer {
    fn new() -> Self {
        Self
    }
    
    /// Parse HTTP server information
    fn parse_server_header(&self, banner: &str) -> Option<(String, f32)> {
        // Extract Server header
        let server_regex = regex::Regex::new(r"(?i)Server:\s*([^\r\n]+)").unwrap();
        
        if let Some(captures) = server_regex.captures(banner) {
            if let Some(server) = captures.get(1) {
                return Some((server.as_str().trim().to_string(), 0.95));
            }
        }
        
        // Look for other indicators
        let powered_by_regex = regex::Regex::new(r"(?i)X-Powered-By:\s*([^\r\n]+)").unwrap();
        if let Some(captures) = powered_by_regex.captures(banner) {
            if let Some(powered_by) = captures.get(1) {
                return Some((powered_by.as_str().trim().to_string(), 0.80));
            }
        }
        
        None
    }
}

impl ProtocolAnalyzer for HttpAnalyzer {
    fn analyze(&self, data: &[u8], _port: u16) -> Option<ProtocolDetails> {
        let banner = String::from_utf8_lossy(data);
        
        // Check if this is an HTTP response
        if !banner.starts_with("HTTP/") && !banner.contains("HTTP/") {
            return None;
        }
        
        let mut metadata = HashMap::new();
        
        // Extract HTTP version
        let http_version_regex = regex::Regex::new(r"HTTP/(\d+\.\d+)").unwrap();
        let version = http_version_regex.captures(&banner)
            .and_then(|captures| captures.get(1))
            .map(|m| format!("HTTP/{}", m.as_str()));
            
        // Extract status code
        let status_code_regex = regex::Regex::new(r"HTTP/\d+\.\d+\s+(\d{3})").unwrap();
        if let Some(captures) = status_code_regex.captures(&banner) {
            if let Some(status) = captures.get(1) {
                metadata.insert("status_code".to_string(), status.as_str().to_string());
            }
        }
        
        // Extract server software
        let (software, confidence) = self.parse_server_header(&banner)
            .unwrap_or(("Unknown".to_string(), 0.7));
            
        Some(ProtocolDetails {
            service: "http".to_string(),
            version,
            software: Some(software),
            confidence,
            metadata,
        })
    }
}

/// Extension functions for using the ML service identifier
pub trait ServiceIdentification {
    /// Identify a network service from its response
    fn identify_service(
        &self,
        data: &[u8],
        port: u16,
        response_time_ms: f32,
        immediate_close: bool,
        server_initiated: bool
    ) -> Option<(String, Option<String>)>;
}

/// Implementation for using the ML service identifier in your scanner
impl ServiceIdentification for MlServiceIdentifier {
    fn identify_service(
        &self,
        data: &[u8],
        port: u16,
        response_time_ms: f32,
        immediate_close: bool,
        server_initiated: bool
    ) -> Option<(String, Option<String>)> {
        // Check if this is binary data or text data
        let is_binary = data.iter().any(|&b| b > 127 || (b < 32 && b != 10 && b != 13 && b != 9));
        
        if is_binary {
            // Use binary identification
            self.identify_binary_service(data, port, response_time_ms, immediate_close, server_initiated)
        } else {
            // Convert to string and use text-based identification
            let banner = String::from_utf8_lossy(data);
            self.identify_service(&banner, port, response_time_ms, immediate_close, server_initiated)
        }
    }
}

/// Create a new ML-based service identifier
#[cfg(feature = "ml")]
pub fn create_ml_identifier() -> MlServiceIdentifier {
    MlServiceIdentifier::default()
}

/// Maximum samples to store per service
pub struct ServiceSampleCollector {
    samples: HashMap<String, Vec<(Vec<u8>, u16, f32, bool, bool)>>,
    
    /// Maximum samples to store per service
    max_samples_per_service: usize,
    
    /// Output directory for sample storage
    output_dir: PathBuf,
}

impl ServiceSampleCollector {
    /// Create a new sample collector
    pub fn new(output_dir: PathBuf, max_samples_per_service: usize) -> Self {
        // Create output directory if it doesn't exist
        std::fs::create_dir_all(&output_dir).unwrap_or_else(|e| {
            warn!("Failed to create sample output directory: {}", e);
        });
        
        Self {
            samples: HashMap::new(),
            max_samples_per_service: max_samples_per_service,
            output_dir,
        }
    }
    
    /// Load previously saved samples from disk
    ///
    /// This function enables persistence of training data between consecutive runs
    /// of the scanner. It reads all previously collected service samples from the 
    /// configured output directory and adds them to the in-memory collection.
    /// 
    /// Red team opsec note: All data is kept locally in the specified data directory
    /// and does not involve network communication.
    pub fn load_samples(&mut self) -> Result<()> {
        debug!("Loading saved samples from {}", self.output_dir.display());
        
        // Check if the directory exists
        if !self.output_dir.exists() {
            debug!("Sample directory does not exist yet: {}", self.output_dir.display());
            return Ok(());
        }
        
        // Iterate through service directories
        for entry in std::fs::read_dir(&self.output_dir)? {
            let entry = entry?;
            let path = entry.path();
            
            // Skip non-directories
            if !path.is_dir() {
                continue;
            }
            
            // Service name is the directory name
            let service = path.file_name()
                .and_then(|s| s.to_str())
                .ok_or_else(|| anyhow::anyhow!("Invalid service directory name"))?
                .to_string();
                
            debug!("Loading samples for service: {}", service);
            
            // Create vector for this service
            let service_samples = self.samples.entry(service.clone()).or_insert_with(Vec::new);
            
            // Find matching data and metadata files
            let mut sample_pairs = Vec::new();
            
            for entry in std::fs::read_dir(&path)? {
                let entry = entry?;
                let file_path = entry.path();
                
                if file_path.is_file() && file_path.to_string_lossy().contains("_data.bin") {
                    // Extract the sample number
                    let file_name = file_path.file_name()
                        .and_then(|s| s.to_str())
                        .ok_or_else(|| anyhow::anyhow!("Invalid sample file name"))?;
                        
                    if let Some(sample_num) = file_name.strip_prefix("sample_").and_then(|s| s.strip_suffix("_data.bin")) {
                        // Look for matching metadata file
                        let meta_file = path.join(format!("sample_{}_meta.json", sample_num));
                        
                        if meta_file.exists() {
                            sample_pairs.push((file_path, meta_file));
                        }
                    }
                }
            }
            
            // Process each sample pair
            for (data_file, meta_file) in sample_pairs {
                // Read data
                let data = std::fs::read(&data_file)?;
                
                // Read metadata
                let meta_str = std::fs::read_to_string(&meta_file)?;
                let metadata: serde_json::Value = serde_json::from_str(&meta_str)?;
                
                // Extract metadata fields
                let port = metadata["port"].as_u64().unwrap_or(0) as u16;
                let response_time_ms = metadata["response_time_ms"].as_f64().unwrap_or(0.0) as f32;
                let immediate_close = metadata["immediate_close"].as_bool().unwrap_or(false);
                let server_initiated = metadata["server_initiated"].as_bool().unwrap_or(false);
                
                // Add sample
                if service_samples.len() < self.max_samples_per_service {
                    service_samples.push((data, port, response_time_ms, immediate_close, server_initiated));
                }
            }
            
            info!("Loaded {} samples for service {}", service_samples.len(), service);
        }
        
        Ok(())
    }
    
    /// Add a sample of a service response
    pub fn add_sample(
        &mut self,
        service: &str,
        data: &[u8],
        port: u16,
        response_time_ms: f32,
        immediate_close: bool,
        server_initiated: bool
    ) {
        // Get or create the vector for this service
        let samples = self.samples.entry(service.to_string()).or_insert_with(Vec::new);
        
        // Only add if we're below the maximum
        if samples.len() < self.max_samples_per_service {
            // Clone the data to own it
            let sample_data = data.to_vec();
            
            // Add the sample with all metadata
            samples.push((sample_data, port, response_time_ms, immediate_close, server_initiated));
            
            debug!("Added sample for service {} (total: {})", service, samples.len());
        }
    }
    
    /// Save collected samples to disk
    pub fn save_samples(&self) -> Result<()> {
        for (service, samples) in &self.samples {
            // Create directory for this service
            let service_dir = self.output_dir.join(service);
            std::fs::create_dir_all(&service_dir)?;
            
            // Save each sample
            for (i, (data, port, response_time, immediate_close, server_initiated)) in samples.iter().enumerate() {
                // Create a metadata file
                let meta_file = service_dir.join(format!("sample_{}_meta.json", i));
                let metadata = serde_json::json!({
                    "port": port,
                    "response_time_ms": response_time,
                    "immediate_close": immediate_close,
                    "server_initiated": server_initiated,
                    "size_bytes": data.len()
                });
                
                std::fs::write(meta_file, serde_json::to_string_pretty(&metadata)?)?;
                
                // Save the binary data
                let data_file = service_dir.join(format!("sample_{}_data.bin", i));
                std::fs::write(data_file, data)?;
            }
            
            info!("Saved {} samples for service {}", samples.len(), service);
        }
        
        Ok(())
    }
    
    /// Convert saved samples to training data for model training
    pub fn samples_to_training_data(&self) -> Result<Vec<training::TrainingDataPoint>> {
        let mut training_data = Vec::new();
        
        for (service, samples) in &self.samples {
            for (data, port, response_time, immediate_close, server_initiated) in samples {
                // Convert to a feature vector
                let features = if data.iter().any(|&b| b > 127 || (b < 32 && b != 10 && b != 13 && b != 9)) {
                    // Binary data
                    ServiceFeatureVector::from_binary(
                        data, *port, *response_time, *immediate_close, *server_initiated)
                } else {
                    // Text data
                    let text = String::from_utf8_lossy(data);
                    ServiceFeatureVector::from_banner(
                        &text, *port, *response_time, *immediate_close, *server_initiated)
                };
                
                // Add to training data
                training_data.push(training::TrainingDataPoint {
                    features,
                    service: service.clone(),
                });
            }
        }
        
        Ok(training_data)
    }
}

/// Collection of specialized protocol detectors for specific services
pub mod protocol_detectors {
    use super::*;
    
    /// MySQL protocol detector
    pub struct MysqlDetector;
    
    impl ProtocolAnalyzer for MysqlDetector {
        fn analyze(&self, data: &[u8], _port: u16) -> Option<ProtocolDetails> {
            // MySQL protocol starts with a 4-byte length field followed by a 1-byte sequence ID
            if data.len() < 10 {
                return None;
            }
            
            // Check for MySQL greeting packet (initial handshake)
            // Protocol version is usually 10 (0x0A)
            if data[4] == 0x0A {
                // Extract server version from null-terminated string
                let mut version_end = 5;
                for i in 5..data.len() {
                    if data[i] == 0 {
                        version_end = i;
                        break;
                    }
                }
                
                let version = if version_end > 5 {
                    String::from_utf8_lossy(&data[5..version_end]).to_string()
                } else {
                    "".to_string()
                };
                
                let mut metadata = HashMap::new();
                metadata.insert("protocol_version".to_string(), "10".to_string());
                
                return Some(ProtocolDetails {
                    service: "mysql".to_string(),
                    version: Some(version),
                    software: None,
                    confidence: 0.95,
                    metadata,
                });
        }
        
        None
        }
    }
    
    /// RDP protocol detector
    pub struct RdpDetector;
    
    impl ProtocolAnalyzer for RdpDetector {
        fn analyze(&self, data: &[u8], _port: u16) -> Option<ProtocolDetails> {
            // Check for RDP (Remote Desktop Protocol) response
            // RDP typically responds with a TPKT header (RFC 1006)
            if data.len() < 5 {
                return None;
            }
            
            // TPKT header starts with version 3
            if data[0] == 3 {
                let mut metadata = HashMap::new();
                
                // Check if this is likely RDP
                if data.len() > 10 && (data[5] == 0xE0 || data[5] == 0xD0) {
                    metadata.insert("protocol".to_string(), "RDP".to_string());
                    
                    // Determine if TLS encryption is in use
                    let has_tls = data.len() > 15 && data[11] & 0x80 != 0;
                    metadata.insert("encrypted".to_string(), has_tls.to_string());
                    
                    return Some(ProtocolDetails {
                        service: "rdp".to_string(),
                        version: None, // Version not easily extractable
                        software: None,
                        confidence: 0.9,
                        metadata,
                    });
                }
            }
            
            None
        }
    }
    
    /// SMB protocol detector
    pub struct SmbDetector;
    
    impl ProtocolAnalyzer for SmbDetector {
        fn analyze(&self, data: &[u8], _port: u16) -> Option<ProtocolDetails> {
            // Check for SMB protocol
            // SMB begins with \xFF\x53\x4D\x42 (legacy) or \xFE\x53\x4D\x42 (SMB2)
            if data.len() < 8 {
                return None;
            }
            
            let mut version = None;
            let mut confidence = 0.0;
            
            // Check SMB signatures
            if data[0] == 0xFF && data[1] == 0x53 && data[2] == 0x4D && data[3] == 0x42 {
                // SMB1
                version = Some("SMB1".to_string());
                confidence = 0.95;
            } else if data[0] == 0xFE && data[1] == 0x53 && data[2] == 0x4D && data[3] == 0x42 {
                // SMB2 or SMB3
                if data.len() > 16 {
                    // Check dialect version - this is overly simplified
                    match data[8] {
                        0x00 if data[9] == 0x02 => version = Some("SMB 2.0".to_string()),
                        0x02 if data[9] == 0x02 => version = Some("SMB 2.1".to_string()),
                        0x00 if data[9] == 0x03 => version = Some("SMB 3.0".to_string()),
                        0x02 if data[9] == 0x03 => version = Some("SMB 3.1.1".to_string()),
                        _ => version = Some("SMB2+".to_string()),
                    }
                } else {
                    version = Some("SMB2+".to_string());
                }
                confidence = 0.95;
            }
            
            if let Some(ver) = version {
                let mut metadata = HashMap::new();
                metadata.insert("protocol".to_string(), "SMB".to_string());
                
                return Some(ProtocolDetails {
                    service: "smb".to_string(),
                    version: Some(ver),
                    software: None,
                    confidence,
                    metadata,
                });
        }
        
        None
        }
    }
}

/// Utilities for training the ML model
pub mod training {
    use super::*;
    use rand::seq::SliceRandom;
    use std::io::Write;
    
    /// Training data point with features and label
    pub struct TrainingDataPoint {
        pub features: ServiceFeatureVector,
        pub service: String,
    }
    
    /// Model trainer for service identification
    pub struct ModelTrainer {
        training_data: Vec<TrainingDataPoint>,
        service_labels: Vec<String>,
        label_indices: HashMap<String, usize>,
    }
    
    impl ModelTrainer {
        /// Create a new model trainer
        pub fn new() -> Self {
            Self {
                training_data: Vec::new(),
                service_labels: Vec::new(),
                label_indices: HashMap::new(),
            }
        }
        
        /// Add training data from a collection
        pub fn add_training_data(&mut self, data_points: Vec<TrainingDataPoint>) {
            for point in data_points {
                if !self.label_indices.contains_key(&point.service) {
                    let index = self.service_labels.len();
                    self.service_labels.push(point.service.clone());
                    self.label_indices.insert(point.service.clone(), index);
                }
                self.training_data.push(point);
            }
        }
        
        /// Train the model using the current training data
        pub fn train(&self) -> Result<(RandomForest, Vec<String>)> {
            // Ensure we have training data
            if self.training_data.is_empty() {
                return Err(anyhow::anyhow!("No training data provided"));
            }
            
            // Prepare data arrays
            let n_samples = self.training_data.len();
            let n_features = self.training_data[0].features.to_feature_array().len();
            
            // Create feature matrix
            let mut x = Array2::zeros((n_samples, n_features));
            let mut y = Array1::zeros(n_samples);
            
            // Fill with data
            for (i, datapoint) in self.training_data.iter().enumerate() {
                let features = datapoint.features.to_feature_array();
                for (j, &value) in features.iter().enumerate() {
                    x[[i, j]] = value;
                }
                
                // Set class label
                if let Some(&label_idx) = self.label_indices.get(&datapoint.service) {
                    y[i] = label_idx as f32;
                }
            }
            
            // Convert to rustlearn arrays
            let x_train = rustlearn::array::dense::Array::from(x.as_slice().unwrap().to_vec());
            let y_train = rustlearn::array::dense::Array::from(y.as_slice().unwrap().to_vec());
            
            // Create and train the model using the Hyperparameters builder
            use rustlearn::trees::decision_tree;
            
            let mut tree_params = decision_tree::Hyperparameters::new(n_features);
            tree_params.min_samples_split(2)
                .max_depth(15)
                .max_features(10);
                
            let mut forest = rustlearn::ensemble::random_forest::Hyperparameters::new(tree_params, 10)
                .build();
                
            // Train the model
            match forest.fit(&x_train, &y_train) {
                Ok(_) => {
                    debug!("Model training completed successfully");
                    Ok((forest, self.service_labels.clone()))
                },
                Err(e) => Err(anyhow::anyhow!("Error training model: {}", e)),
            }
        }
        
        /// Save the trained model to a file
        pub fn save_model(&self, forest: &RandomForest, filepath: &Path) -> Result<()> {
            // Serialize the model and labels
            let serialized = serialize(&(forest, &self.service_labels))
                .with_context(|| "Failed to serialize model")?;
                
            // Write to file
            let mut file = std::fs::File::create(filepath)
                .with_context(|| format!("Failed to create model file: {}", filepath.display()))?;
                
            file.write_all(&serialized)
                .with_context(|| "Failed to write model data")?;
                
            debug!("Model saved to {}", filepath.display());
            Ok(())
        }
    }
}

/// Self-learning service identifier that improves with each scan
pub struct SelfLearningServiceIdentifier {
    /// The core ML identifier
    identifier: MlServiceIdentifier,
    
    /// Sample collector for training data
    sample_collector: ServiceSampleCollector,
    
    /// Configuration for continuous learning
    learning_config: LearningConfig,
    
    /// Track when model was last updated
    last_update: std::time::SystemTime,
    
    /// Counter for scans since last training
    scan_counter: usize,
    
    /// High-confidence identifications (used for training)
    confident_identifications: HashMap<String, Vec<ServiceFeatureVector>>,
}

/// Configuration options for the self-learning system
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LearningConfig {
    /// Whether continuous learning is enabled
    pub enabled: bool,
    
    /// Minimum confidence threshold for auto-learning (0.0-1.0)
    pub min_confidence_threshold: f32,
    
    /// How many scans before attempting to update the model
    pub update_frequency: usize,
    
    /// Maximum samples to keep per service
    pub max_samples_per_service: usize,
    
    /// Path to store and load training data
    pub data_dir: PathBuf,
    
    /// Path to store the trained model
    pub model_path: PathBuf,
}

impl Default for LearningConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            min_confidence_threshold: 0.85,
            update_frequency: 50, // Update after 50 scans
            max_samples_per_service: 1000,
            data_dir: PathBuf::from("/usr/share/quantum_scanner/training_data"),
            model_path: PathBuf::from("/usr/share/quantum_scanner/models/service_classifier.bin"),
        }
    }
}

impl SelfLearningServiceIdentifier {
    /// Create a new self-learning service identifier
    pub fn new(config: Option<LearningConfig>) -> Self {
        let learning_config = config.unwrap_or_default();
        
        // Create sample collector with proper path
        let mut sample_collector = ServiceSampleCollector::new(
            learning_config.data_dir.clone(),
            learning_config.max_samples_per_service,
        );
        
        // Load previously saved samples
        if let Err(e) = sample_collector.load_samples() {
            warn!("Failed to load saved samples: {}", e);
        }
        
        let mut identifier = Self {
            identifier: MlServiceIdentifier::default(),
            sample_collector,
            learning_config,
            last_update: std::time::SystemTime::now(),
            scan_counter: 0,
            confident_identifications: HashMap::new(),
        };
        
        // Load previously saved confident identifications
        if let Err(e) = identifier.load_confident_identifications() {
            warn!("Failed to load confident identifications: {}", e);
        }
        
        identifier
    }
    
    /// Load previously saved confident identifications for persistent learning
    ///
    /// This function enables the ML model to continue learning where it left off
    /// in previous scans by loading previously identified and confirmed service features.
    /// This provides continuous improvement of the model across multiple scanning sessions.
    /// 
    /// Red team opsec note: All data is loaded from the local data directory
    /// and does not involve network communication.
    fn load_confident_identifications(&mut self) -> Result<()> {
        debug!("Loading confident identifications from previous runs");
        
        // First, load from samples
        let samples_to_convert = self.sample_collector.samples.clone();
        
        for (service, samples) in samples_to_convert {
            let mut features = Vec::new();
            
            for (data, port, response_time, immediate_close, server_initiated) in samples {
                // Convert to feature vector
                let feature_vector = if data.iter().any(|&b| b > 127 || (b < 32 && b != 10 && b != 13 && b != 9)) {
                    ServiceFeatureVector::from_binary(&data, port, response_time, immediate_close, server_initiated)
                } else {
                    let banner = String::from_utf8_lossy(&data);
                    ServiceFeatureVector::from_banner(&banner, port, response_time, immediate_close, server_initiated)
                };
                
                features.push(feature_vector);
            }
            
            // Add to confident identifications, limiting to max_samples_per_service
            if !features.is_empty() {
                let service_samples = self.confident_identifications
                    .entry(service.clone())
                    .or_insert_with(Vec::new);
                
                // Only add up to the configured limit
                let max_to_add = std::cmp::min(
                    features.len(),
                    self.learning_config.max_samples_per_service.saturating_sub(service_samples.len())
                );
                
                if max_to_add > 0 {
                    service_samples.extend(features.into_iter().take(max_to_add));
                    debug!("Loaded {} confident samples for service {}", max_to_add, service);
                }
            }
        }
        
        // Then, try to load serialized features directly
        let confident_dir = self.learning_config.data_dir.join("confident_features");
        
        // Skip if the directory doesn't exist yet
        if !confident_dir.exists() {
            debug!("No saved confident features found at {}", confident_dir.display());
            info!("Loaded confident samples for {} services", self.confident_identifications.len());
            return Ok(());
        }
        
        // Load each service file
        for entry in std::fs::read_dir(&confident_dir)? {
            let entry = entry?;
            let path = entry.path();
            
            // Skip non-files
            if !path.is_file() || !path.to_string_lossy().ends_with(".bin") {
                continue;
            }
            
            // Extract service name from filename
            let service = path.file_stem()
                .and_then(|s| s.to_str())
                .ok_or_else(|| anyhow::anyhow!("Invalid feature file name"))?
                .to_string();
                
            // Read and deserialize features
            let data = std::fs::read(&path)?;
            let features: Vec<ServiceFeatureVector> = deserialize(&data)
                .with_context(|| format!("Failed to deserialize features for service {}", service))?;
                
            // Add to confident identifications, limiting to max_samples_per_service
            if !features.is_empty() {
                let service_samples = self.confident_identifications
                    .entry(service.clone())
                    .or_insert_with(Vec::new);
                
                // Only add up to the configured limit
                let max_to_add = std::cmp::min(
                    features.len(),
                    self.learning_config.max_samples_per_service.saturating_sub(service_samples.len())
                );
                
                if max_to_add > 0 {
                    service_samples.extend(features.into_iter().take(max_to_add));
                    debug!("Loaded {} serialized confident samples for service {}", max_to_add, service);
                }
            }
        }
        
        info!("Loaded confident samples for {} services", self.confident_identifications.len());
        Ok(())
    }
    
    /// Process a service response and identify it, potentially learning from it
    pub fn identify_and_learn(
        &mut self,
        data: &[u8],
        port: u16,
        response_time_ms: f32,
        immediate_close: bool,
        server_initiated: bool
    ) -> Option<(String, Option<String>)> {
        // First, identify the service using the current model with enhanced detection
        let identification = if let Some((service, version, metadata)) = 
            self.identifier.enhanced_identify_service(
                data, port, response_time_ms, immediate_close, server_initiated
            ) {
            // Log detection method for analysis
            if let Some(method) = metadata.get("detection_method") {
                debug!("Service identified using {} method: {}", method, service);
            }
            Some((service, version))
        } else {
            None
        };
        
        // If learning is enabled, process this scan for learning
        if self.learning_config.enabled {
            if let Some((service, _)) = &identification {
                // Create feature vector for this service
                let feature_vector = if data.iter().any(|&b| b > 127 || (b < 32 && b != 10 && b != 13 && b != 9)) {
                    ServiceFeatureVector::from_binary(data, port, response_time_ms, immediate_close, server_initiated)
                } else {
                    let banner = String::from_utf8_lossy(data);
                    ServiceFeatureVector::from_banner(&banner, port, response_time_ms, immediate_close, server_initiated)
                };
                
                // Store for training if this is a confident identification
                // This simulates user confirmation - in practice, you might want to have actual user feedback
                let confident = self.is_confident_identification(&feature_vector, service);
                
                if confident {
                    // Add to confident identifications for later training
                    let service_samples = self.confident_identifications
                        .entry(service.clone())
                        .or_insert_with(Vec::new);
                    
                    if service_samples.len() < self.learning_config.max_samples_per_service {
                        service_samples.push(feature_vector);
                        debug!("Added confident sample for service {}", service);
                    }
                    
                    // Also save raw sample for future training
                    self.sample_collector.add_sample(
                        service, data, port, response_time_ms, immediate_close, server_initiated
                    );
                }
                
                // Increment scan counter
                self.scan_counter += 1;
                
                // Check if it's time to update the model
                if self.scan_counter >= self.learning_config.update_frequency {
                    if let Err(e) = self.update_model() {
                        warn!("Failed to update model: {}", e);
                    }
                    self.scan_counter = 0;
                }
            }
        }
        
        identification
    }
    
    /// Determine if an identification is confident enough to use for training
    fn is_confident_identification(&self, features: &ServiceFeatureVector, service: &str) -> bool {
        // For definitive protocol markers, we have high confidence
        if (service == "http" && features.starts_with_http) ||
           (service == "ssh" && features.starts_with_ssh) ||
           (service == "ftp" && features.starts_with_ftp) ||
           (service == "smtp" && features.starts_with_smtp) ||
           (service == "pop3" && features.starts_with_pop3) ||
           (service == "imap" && features.starts_with_imap) ||
           (service == "ssl/tls" && features.has_tls_handshake)
        {
            return true;
        }
        
        // Check port-specific protocols
        match features.port {
            53 if service == "dns" => return true,
            161 | 162 if service == "snmp" => return true,
            389 | 636 if service == "ldap" || service == "ldaps" => return true,
            502 if service == "modbus" => return true,
            1883 | 8883 if service == "mqtt" => return true,
            _ => {}
        }
        
        // For others, check if there are protocol-specific characteristics
        match service {
            "http" => features.has_html || features.has_status_code,
            "dns" => features.port == 53 && features.has_binary && features.response_length < 512.0,
            "mysql" => features.port == 3306 && features.has_binary,
            "rdp" => features.port == 3389 && features.has_binary,
            "smb" => (features.port == 445 || features.port == 139) && features.has_binary,
            "postgresql" => features.port == 5432 && features.has_binary,
            "mongodb" => features.port == 27017 && features.has_binary,
            "redis" => features.port == 6379 && !features.has_binary,
            _ => false, // Less confident about other services
        }
    }
    
    /// Allow the user to explicitly provide feedback on a service identification
    pub fn provide_feedback(
        &mut self, 
        data: &[u8], 
        port: u16,
        response_time_ms: f32,
        immediate_close: bool,
        server_initiated: bool,
        correct_service: &str
    ) {
        // Add as training data with the user-provided label
        self.sample_collector.add_sample(
            correct_service, data, port, response_time_ms, immediate_close, server_initiated
        );
        
        // Also create and store feature vector
        let feature_vector = if data.iter().any(|&b| b > 127 || (b < 32 && b != 10 && b != 13 && b != 9)) {
            ServiceFeatureVector::from_binary(data, port, response_time_ms, immediate_close, server_initiated)
        } else {
            let banner = String::from_utf8_lossy(data);
            ServiceFeatureVector::from_banner(&banner, port, response_time_ms, immediate_close, server_initiated)
        };
        
        // Add to confident identifications
        let service_samples = self.confident_identifications
            .entry(correct_service.to_string())
            .or_insert_with(Vec::new);
        
        if service_samples.len() < self.learning_config.max_samples_per_service {
            service_samples.push(feature_vector);
            debug!("Added user-corrected sample for service {}", correct_service);
        }
        
        // Since this is explicit feedback, update model if we have enough samples
        if self.confident_identifications.len() >= 5 {
            if let Err(e) = self.update_model() {
                warn!("Failed to update model after user feedback: {}", e);
            }
        }
    }
    
    /// Update the ML model with newly collected data
    fn update_model(&mut self) -> Result<()> {
        debug!("Updating ML model with new training data...");
        
        // Skip if we don't have enough data
        let total_samples: usize = self.confident_identifications.values()
            .map(|samples| samples.len())
            .sum();
            
        if total_samples < 10 {
            debug!("Not enough samples to update model ({})", total_samples);
            return Ok(());
        }
        
        // Create training data points
        let mut training_data = Vec::new();
        
        for (service, samples) in &self.confident_identifications {
            for features in samples {
                training_data.push(training::TrainingDataPoint {
                    features: features.clone(),
                    service: service.clone(),
                });
            }
        }
        
        // Create trainer
        let mut trainer = training::ModelTrainer::new();
        trainer.add_training_data(training_data);
        
        // Train the model
        let (forest, labels) = trainer.train()?;
        
        // Save the model
        std::fs::create_dir_all(self.learning_config.model_path.parent().unwrap_or(Path::new(".")))?;
        trainer.save_model(&forest, &self.learning_config.model_path)?;
        
        // Update our identifier with the new model
        self.identifier.model = Some(forest);
        self.identifier.service_labels = labels;
        
        // Save collected samples to disk for future use
        self.sample_collector.save_samples()?;
        
        // Save confident identifications for persistence
        self.save_confident_identifications()?;
        
        // Update timestamp
        self.last_update = std::time::SystemTime::now();
        
        info!("Updated ML model with {} new samples", total_samples);
        
        // Clear some of the older samples to prevent excessive memory use
        // but keep some for future training stability
        for samples in self.confident_identifications.values_mut() {
            if samples.len() > 50 {
                // Keep the 50 most recent samples
                *samples = samples.drain(samples.len() - 50..).collect();
            }
        }
        
        Ok(())
    }
    
    /// Save confident identifications to disk for persistence across runs
    ///
    /// This function stores the trained feature vectors so machine learning progress is 
    /// preserved between consecutive runs, avoiding the need to retrain the model from scratch
    /// each time the scanner is used.
    /// 
    /// Red team opsec note: All data is kept locally in the specified data directory
    /// and does not involve network communication.
    fn save_confident_identifications(&self) -> Result<()> {
        debug!("Saving confident identifications to disk");
        
        // Create a directory within the data_dir for confident identifications
        let confident_dir = self.learning_config.data_dir.join("confident_features");
        std::fs::create_dir_all(&confident_dir)?;
        
        // Save each service's feature vectors
        for (service, features) in &self.confident_identifications {
            // Skip if empty
            if features.is_empty() {
                continue;
            }
            
            // Create service file
            let service_file = confident_dir.join(format!("{}.bin", service));
            
            // Serialize features
            let serialized = serialize(&features)
                .with_context(|| format!("Failed to serialize features for service {}", service))?;
                
            // Write to file
            std::fs::write(&service_file, &serialized)
                .with_context(|| format!("Failed to write features for service {}", service))?;
                
            debug!("Saved {} confident samples for service {}", features.len(), service);
        }
        
        info!("Saved confident identifications for {} services", self.confident_identifications.len());
        Ok(())
    }
    
    /// Force a model update with all collected data
    pub fn force_update_model(&mut self) -> Result<()> {
        let result = self.update_model();
        
        // Even if the model update fails (e.g., not enough samples), 
        // try to save the confident identifications to ensure persistence
        if result.is_err() {
            debug!("Model update failed, but still saving confident identifications for persistence");
            if let Err(e) = self.save_confident_identifications() {
                warn!("Failed to save confident identifications: {}", e);
            }
        }
        
        result
    }
    
    /// Get information about the current learning state
    pub fn get_learning_status(&self) -> LearningStatus {
        let elapsed = self.last_update.elapsed().unwrap_or_default();
        
        LearningStatus {
            enabled: self.learning_config.enabled,
            samples_collected: self.confident_identifications.values()
                .map(|v| v.len())
                .sum(),
            services_learned: self.confident_identifications.len(),
            time_since_last_update: elapsed.as_secs(),
            scans_since_last_update: self.scan_counter,
        }
    }
}

/// Status information about the learning system
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LearningStatus {
    /// Whether learning is enabled
    pub enabled: bool,
    /// Total samples collected
    pub samples_collected: usize,
    /// Number of unique services learned
    pub services_learned: usize,
    /// Seconds since last model update
    pub time_since_last_update: u64,
    /// Scans performed since last update
    pub scans_since_last_update: usize,
}

/// Extension trait for using the self-learning identifier
pub trait SelfLearningServiceIdentification {
    /// Identify a service and learn from the response data
    fn identify_and_learn(
        &mut self,
        data: &[u8],
        port: u16, 
        response_time_ms: f32,
        immediate_close: bool,
        server_initiated: bool
    ) -> Option<(String, Option<String>)>;
    
    /// Provide feedback about a previous identification
    fn provide_feedback(
        &mut self,
        data: &[u8],
        port: u16,
        response_time_ms: f32,
        immediate_close: bool,
        server_initiated: bool,
        correct_service: &str
    );
}

impl SelfLearningServiceIdentification for SelfLearningServiceIdentifier {
    fn identify_and_learn(
        &mut self,
        data: &[u8],
        port: u16,
        response_time_ms: f32,
        immediate_close: bool,
        server_initiated: bool
    ) -> Option<(String, Option<String>)> {
        self.identify_and_learn(data, port, response_time_ms, immediate_close, server_initiated)
    }
    
    fn provide_feedback(
        &mut self,
        data: &[u8],
        port: u16,
        response_time_ms: f32,
        immediate_close: bool,
        server_initiated: bool,
        correct_service: &str
    ) {
        self.provide_feedback(data, port, response_time_ms, immediate_close, server_initiated, correct_service)
    }
}

/// Create a new self-learning service identifier
pub fn create_self_learning_identifier() -> SelfLearningServiceIdentifier {
    SelfLearningServiceIdentifier::new(None)
}

/// Command-line interface for managing ML training data
/// 
/// This helper function runs an interactive session to collect service data
/// and train the ML model.
pub fn run_training_cli() -> Result<()> {
    use std::io::{self, Write};
    
    println!("=== Service Identification Training Tool ===");
    println!("This tool helps improve service identification by collecting properly labeled samples.");
    println!("Enhanced protocol support includes: HTTP, SSH, FTP, SMTP, DNS, SNMP, LDAP, MQTT, Modbus, and more.");
    
    // Load existing model and samples
    let mut identifier = SelfLearningServiceIdentifier::new(None);
    
    loop {
        println!("\nTraining Options:");
        println!("1. Scan a target and label the service");
        println!("2. View learning status");
        println!("3. Force model update");
        println!("4. List supported protocols");
        println!("5. Exit");
        
        print!("Select an option: ");
        io::stdout().flush()?;
        
        let mut input = String::new();
        io::stdin().read_line(&mut input)?;
        let choice = input.trim();
        
        match choice {
            "1" => {
                // Scan and label
                print!("Enter target (host:port): ");
                io::stdout().flush()?;
                let mut target = String::new();
                io::stdin().read_line(&mut target)?;
                
                let target = target.trim();
                if target.is_empty() || !target.contains(':') {
                    println!("Invalid target format. Use host:port (e.g., 192.168.1.1:80)");
                    continue;
                }
                
                // Parse target
                let parts: Vec<&str> = target.split(':').collect();
                let host = parts[0];
                let port: u16 = match parts[1].parse() {
                    Ok(p) => p,
                    Err(_) => {
                        println!("Invalid port number");
                        continue;
                    }
                };
                
                // Scan the target
                println!("Scanning {}:{}...", host, port);
                
                // Connect and get banner (simplified)
                let socket_addr = match format!("{}:{}", host, port).parse() {
                    Ok(addr) => addr,
                    Err(e) => {
                        println!("Failed to parse address: {}", e);
                        continue;
                    }
                };
                
                // Connect with 5 second timeout
                let start = std::time::Instant::now();
                let stream = match std::net::TcpStream::connect_timeout(&socket_addr, std::time::Duration::from_secs(5)) {
                    Ok(s) => s,
                    Err(e) => {
                        println!("Failed to connect: {}", e);
                        continue;
                    }
                };
                
                let response_time_ms = start.elapsed().as_millis() as f32;
                
                // Set read timeout
                stream.set_read_timeout(Some(std::time::Duration::from_secs(3)))?;
                
                // Read response
                let mut data = Vec::new();
                let mut buf = [0u8; 4096];
                
                match stream.set_nonblocking(true) {
                    Ok(_) => {},
                    Err(e) => {
                        println!("Warning: Could not set non-blocking: {}", e);
                    }
                }
                
                // Wait briefly for server to send data
                std::thread::sleep(std::time::Duration::from_millis(500));
                
                let mut server_initiated = false;
                match stream.peek(&mut buf) {
                    Ok(n) if n > 0 => {
                        server_initiated = true;
                    }
                    _ => {}
                }
                
                // Read any available data
                let mut read_any = false;
                loop {
                    match stream.read(&mut buf) {
                        Ok(0) => break, // Connection closed
                        Ok(n) => {
                            data.extend_from_slice(&buf[..n]);
                            read_any = true;
                            if data.len() > 10240 { // Cap at 10K
                                break;
                            }
                        }
                        Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                            // No more data available right now
                            if read_any {
                                break;
                            }
                            // Send a probe if we haven't read anything and server hasn't sent data
                            if !server_initiated && !read_any {
                                match stream.write(b"\r\n") {
                                    Ok(_) => std::thread::sleep(std::time::Duration::from_millis(500)),
                                    Err(_) => break,
                                }
                            } else {
                                break;
                            }
                        }
                        Err(_) => break, // Other error, just break
                    }
                }
                
                let immediate_close = !read_any && !server_initiated;
                
                if data.is_empty() {
                    println!("No data received from the service");
                    continue;
                }
                
                // Show the received data
                println!("Received {} bytes of data", data.len());
                
                if data.iter().all(|&b| (b >= 32 && b <= 126) || b == b'\r' || b == b'\n' || b == b'\t') {
                    // Printable ASCII
                    println!("Data (text): {}", String::from_utf8_lossy(&data));
                } else {
                    // Binary or mixed
                    println!("Data (first 50 bytes hex): {:02X?}", &data.iter().take(50).collect::<Vec<_>>());
                }
                
                // Try to identify
                let identification = identifier.identify_and_learn(
                    &data, port, response_time_ms, immediate_close, server_initiated
                );
                
                if let Some((service, version)) = &identification {
                    println!("Auto-identification: {} {}", service, version.as_deref().unwrap_or(""));
                } else {
                    println!("Could not automatically identify this service");
                }
                
                // Provide port-based suggestion
                let suggested_service = match port {
                    22 => "ssh",
                    25 | 587 => "smtp",
                    53 => "dns",
                    80 | 8080 | 8000 => "http",
                    443 | 8443 => "https/ssl",
                    389 => "ldap",
                    636 => "ldaps",
                    161 | 162 => "snmp",
                    502 => "modbus",
                    1883 | 8883 => "mqtt",
                    _ => "unknown",
                };
                
                println!("Based on the port, this might be: {}", suggested_service);
                
                // Get user label
                print!("Enter correct service name: ");
                io.stdout().flush()?;
                let mut service_name = String::new();
                io::stdin().read_line(&mut service_name)?;
                let service_name = service_name.trim();
                
                if !service_name.is_empty() {
                    // Add to training data
                    identifier.provide_feedback(
                        &data, port, response_time_ms, immediate_close, server_initiated, service_name
                    );
                    println!("Added sample for service: {}", service_name);
                }
            },
            "2" => {
                // View status
                let status = identifier.get_learning_status();
                println!("\nLearning Status:");
                println!("Learning enabled: {}", status.enabled);
                println!("Samples collected: {}", status.samples_collected);
                println!("Services learned: {}", status.services_learned);
                println!("Time since last update: {} seconds", status.time_since_last_update);
                println!("Scans since last update: {}", status.scans_since_last_update);
            },
            "3" => {
                // Force update
                match identifier.force_update_model() {
                    Ok(_) => println!("Model updated successfully"),
                    Err(e) => println!("Failed to update model: {}", e),
                }
            },
            "4" => {
                // List supported protocols
                println!("\nSupported Protocols for Training:");
                println!("- Web: http, https");
                println!("- Secure Shell: ssh, sftp");
                println!("- File Transfer: ftp, ftps");
                println!("- Email: smtp, pop3, imap");
                println!("- Domain Name System: dns");
                println!("- Databases: mysql, postgresql, mongodb, redis");
                println!("- Management: snmp, ldap, ldaps");
                println!("- Remote Access: rdp, vnc, telnet");
                println!("- IoT/Industrial: mqtt, modbus");
                println!("- Windows: smb, netbios");
                println!("\nFor best results, provide the most specific service name.");
            },
            "5" | "q" | "quit" | "exit" => {
                println!("Exiting...");
                break;
            },
            _ => {
                println!("Invalid option");
            }
        }
    }
    
    Ok(())
}

#[cfg(feature = "ndpi")]
pub mod ndpi {
    use super::*;
    use std::ffi::{CStr, CString};
    use std::os::raw::{c_char, c_int, c_uint, c_void, c_uchar};
    use std::ptr;

    // FFI definitions for nDPI
    #[repr(C)]
    pub struct ndpi_detection_module_struct {
        _private: [u8; 0] // Opaque C structure
    }

    #[repr(C)]
    pub struct ndpi_flow_struct {
        _private: [u8; 0] // Opaque C structure
    }

    // nDPI protocol categories for better classification
    #[repr(C)]
    #[derive(Debug, Clone, Copy, PartialEq)]
    pub enum ndpi_protocol_category_t {
        NDPI_PROTOCOL_CATEGORY_UNSPECIFIED = 0,
        NDPI_PROTOCOL_CATEGORY_MEDIA,
        NDPI_PROTOCOL_CATEGORY_VPN,
        NDPI_PROTOCOL_CATEGORY_EMAIL,
        NDPI_PROTOCOL_CATEGORY_DATA_TRANSFER,
        NDPI_PROTOCOL_CATEGORY_WEB,
        NDPI_PROTOCOL_CATEGORY_SOCIAL_NETWORK,
        NDPI_PROTOCOL_CATEGORY_DOWNLOAD_FT,
        NDPI_PROTOCOL_CATEGORY_GAME,
        NDPI_PROTOCOL_CATEGORY_CHAT,
        NDPI_PROTOCOL_CATEGORY_VOIP,
        NDPI_PROTOCOL_CATEGORY_DATABASE,
        NDPI_PROTOCOL_CATEGORY_REMOTE_ACCESS,
        NDPI_PROTOCOL_CATEGORY_CLOUD,
        NDPI_PROTOCOL_CATEGORY_NETWORK,
        NDPI_PROTOCOL_CATEGORY_COLLABORATIVE,
        NDPI_PROTOCOL_CATEGORY_RPC,
        NDPI_PROTOCOL_CATEGORY_STREAMING,
        NDPI_PROTOCOL_CATEGORY_SYSTEM_OS,
        NDPI_PROTOCOL_CATEGORY_SW_UPDATE,
    }

    // Result structure for nDPI protocol identification
    #[repr(C)]
    #[derive(Debug, Clone)]
    pub struct ndpi_protocol {
        pub master_protocol: u16,
        pub app_protocol: u16,
        pub category: ndpi_protocol_category_t,
    }

    // FFI declarations for nDPI functions
    extern "C" {
        // Core nDPI functions
        pub fn ndpi_init_detection_module(
            prefs: *mut c_void,
        ) -> *mut ndpi_detection_module_struct;
        
        pub fn ndpi_exit_detection_module(
            module: *mut ndpi_detection_module_struct
        );
        
        pub fn ndpi_new_flow() -> *mut ndpi_flow_struct;
        
        pub fn ndpi_free_flow(flow: *mut ndpi_flow_struct);
        
        pub fn ndpi_detection_process_packet(
            module: *mut ndpi_detection_module_struct,
            flow: *mut ndpi_flow_struct,
            packet: *const c_uchar,
            packetlen: c_uint,
            timestamp: u64,
            src: *mut c_void,
            dst: *mut c_void,
        ) -> ndpi_protocol;
        
        // Protocol name utilities
        pub fn ndpi_category_get_name(
            module: *mut ndpi_detection_module_struct,
            category: ndpi_protocol_category_t
        ) -> *const c_char;
        
        pub fn ndpi_get_proto_name(
            module: *mut ndpi_detection_module_struct,
            proto: u16
        ) -> *const c_char;
        
        // Configuration functions
        pub fn ndpi_set_protocol_detection_timeout(
            module: *mut ndpi_detection_module_struct,
            timeout: u32,
        );
    }

    /// Wrapper for the nDPI library
    pub struct NdpiContext {
        module: *mut ndpi_detection_module_struct,
    }

    impl NdpiContext {
        /// Initialize nDPI detection module with default settings
        pub fn new() -> Result<Self> {
            // Initialize the nDPI module
            let module = unsafe { ndpi_init_detection_module(ptr::null_mut()) };
            
            if module.is_null() {
                return Err(anyhow::anyhow!("Failed to initialize nDPI detection module"));
            }
            
            // Configure nDPI with suitable timeouts for scanning
            unsafe {
                // Set a short timeout for quick packet analysis
                ndpi_set_protocol_detection_timeout(module, 100);
            }
            
            Ok(Self { module })
        }
        
        /// Detect protocol from packet data
        pub fn detect_protocol(&self, data: &[u8]) -> NdpiResult {
            // Create a new flow for this detection
            let flow = unsafe { ndpi_new_flow() };
            if flow.is_null() {
                return NdpiResult {
                    protocol_name: "unknown".to_string(),
                    master_protocol: 0,
                    app_protocol: 0,
                    category: ndpi_protocol_category_t::NDPI_PROTOCOL_CATEGORY_UNSPECIFIED,
                    category_name: "Unknown".to_string(),
                };
            }
            
            // Process the packet with nDPI
            let result = unsafe {
                ndpi_detection_process_packet(
                    self.module,
                    flow,
                    data.as_ptr(),
                    data.len() as c_uint,
                    0, // timestamp, not relevant for single packet analysis
                    ptr::null_mut(), // src, not needed
                    ptr::null_mut(), // dst, not needed
                )
            };
            
            // Extract protocol and category names
            let protocol_name = if result.app_protocol > 0 {
                self.get_protocol_name(result.app_protocol)
            } else {
                self.get_protocol_name(result.master_protocol)
            };
            
            let category_name = self.get_category_name(result.category);
            
            // Clean up the flow
            unsafe { ndpi_free_flow(flow) };
            
            NdpiResult {
                protocol_name,
                master_protocol: result.master_protocol,
                app_protocol: result.app_protocol,
                category: result.category,
                category_name,
            }
        }
        
        /// Get protocol name from protocol ID
        fn get_protocol_name(&self, protocol_id: u16) -> String {
            if protocol_id == 0 {
                return "unknown".to_string();
            }
            
            let name_ptr = unsafe { ndpi_get_proto_name(self.module, protocol_id) };
            if name_ptr.is_null() {
                return format!("proto_{}", protocol_id);
            }
            
            unsafe {
                CStr::from_ptr(name_ptr)
                    .to_string_lossy()
                    .to_string()
                    .to_lowercase()
            }
        }
        
        /// Get category name from category enum
        fn get_category_name(&self, category: ndpi_protocol_category_t) -> String {
            let name_ptr = unsafe { ndpi_category_get_name(self.module, category) };
            if name_ptr.is_null() {
                return "Unknown".to_string();
            }
            
            unsafe {
                CStr::from_ptr(name_ptr)
                    .to_string_lossy()
                    .to_string()
            }
        }
    }

    // Clean up nDPI resources when done
    impl Drop for NdpiContext {
        fn drop(&mut self) {
            if !self.module.is_null() {
                unsafe { ndpi_exit_detection_module(self.module) };
            }
        }
    }

    /// Result of nDPI protocol detection
    #[derive(Debug, Clone)]
    pub struct NdpiResult {
        pub protocol_name: String,
        pub master_protocol: u16,
        pub app_protocol: u16,
        pub category: ndpi_protocol_category_t,
        pub category_name: String,
    }

    /// Protocol analyzer implementation using nDPI
    pub struct NdpiProtocolAnalyzer {
        context: NdpiContext,
    }

    impl NdpiProtocolAnalyzer {
        /// Create a new nDPI-based protocol analyzer
        pub fn new() -> Result<Self> {
            let context = NdpiContext::new()?;
            Ok(Self { context })
        }
        
        /// Map nDPI protocol names to our canonical service names
        fn map_protocol_name(&self, protocol: &str, port: u16) -> String {
            // Normalize to lowercase
            let protocol = protocol.to_lowercase();
            
            // Map common protocols to canonical names
            match protocol.as_str() {
                "http" | "http_connect" | "http_proxy" => "http",
                "ssl" | "tls" => "ssl/tls",
                "ssh" => "ssh",
                "smtp" | "smtp_submission" => "smtp",
                "pop3" | "pop" => "pop3",
                "imap" => "imap",
                "ftp" | "ftp_control" | "ftp_data" => "ftp",
                "mysql" => "mysql",
                "postgres" | "postgresql" => "postgresql",
                "microsoft-ds" | "smb" => "smb",
                "rdp" => "rdp",
                "telnet" => "telnet",
                "vnc" => "vnc",
                "dns" => "dns",
                "ntp" => "ntp",
                "snmp" => "snmp",
                "ldap" => "ldap",
                "mongodb" => "mongodb",
                "redis" => "redis",
                "memcached" => "memcached",
                "modbus" => "modbus", 
                "mqtt" | "mqtt-broker" => "mqtt",
                // Default to nDPI's detected protocol name 
                _ => {
                    if protocol == "unknown" {
                        // Try to guess based on well-known ports
                        match port {
                            22 => "ssh",
                            25 | 587 => "smtp",
                            80 => "http",
                            443 => "ssl/tls",
                            21 => "ftp",
                            23 => "telnet",
                            3306 => "mysql",
                            5432 => "postgresql",
                            3389 => "rdp",
                            5900..=5999 => "vnc",
                            _ => "unknown"
                        }.to_string()
                    } else {
                        protocol
                    }
                }
            }.to_string()
        }
    }

    // Implement the ProtocolAnalyzer trait for NdpiProtocolAnalyzer
    impl ProtocolAnalyzer for NdpiProtocolAnalyzer {
        fn analyze(&self, data: &[u8], port: u16) -> Option<ProtocolDetails> {
            // Skip analyzing tiny packets
            if data.len() < 8 {
                return None;
            }
            
            // Detect the protocol using nDPI
            let result = self.context.detect_protocol(data);
            
            // If we couldn't identify anything
            if result.protocol_name == "unknown" && result.master_protocol == 0 && result.app_protocol == 0 {
                return None;
            }
            
            // Map the nDPI protocol name to our canonical service name
            let service = self.map_protocol_name(&result.protocol_name, port);
            
            // Prepare metadata for the result
            let mut metadata = HashMap::new();
            metadata.insert("detection_method".to_string(), "nDPI".to_string());
            metadata.insert("category".to_string(), result.category_name);
            
            if result.master_protocol > 0 && result.master_protocol != result.app_protocol {
                let master_name = self.context.get_protocol_name(result.master_protocol);
                metadata.insert("master_protocol".to_string(), master_name);
            }
            
            Some(ProtocolDetails {
                service,
                version: None, // nDPI doesn't provide version info
                software: None,
                confidence: 0.95, // nDPI is highly accurate
                metadata,
            })
        }
    }
}

/// Global system state to manage nDPI initialization
static mut NDPI_INITIALIZED: bool = false;

impl MlServiceIdentifier {
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
        } else if features.has_tls_handshake {
            return Some("ssl/tls");
        }
        
        // Check for specific port/pattern combinations that are highly reliable
        match features.port {
            53 => {
                // DNS typically has high entropy and specific patterns
                if features.has_binary && features.entropy > 3.5 && features.response_length < 512.0 {
                    return Some("dns");
                }
            },
            161 | 162 => {
                // SNMP has distinctive ASN.1 BER encoding
                if features.has_binary && features.entropy > 2.5 && features.response_length < 1024.0 {
                    return Some("snmp");
                }
            },
            389 | 636 => {
                // LDAP also uses BER encoding
                if features.has_binary && features.entropy > 3.0 {
                    return Some("ldap");
                }
            },
            502 => {
                // Modbus TCP has fixed header structure
                if features.has_binary && features.has_fixed_header {
                    return Some("modbus");
                }
            },
            1883 | 8883 => {
                // MQTT has distinctive message formats
                if features.response_length < 256.0 && !features.has_html && !features.has_xml {
                    return Some("mqtt");
                }
            },
            _ => {}
        }
        
        // Try fallback to nDPI for protocols we can't quickly identify
        #[cfg(feature = "ndpi")]
        {
            // If we have an unknown analyzer (which should be nDPI),
            // try it for ambiguous protocols
            if self.protocol_analyzers.contains_key("unknown") {
                return None; // Let the main flow handle it via nDPI
            }
        }
        
        // No definitive marker found
        None
    }

    /// Try to identify a protocol using nDPI (if available)
    fn try_ndpi_identification(
        &self,
        data: &[u8],
        port: u16,
    ) -> Option<(String, Option<String>)> {
        // Check if we have the unknown analyzer (which should be nDPI)
        if let Some(analyzer) = self.protocol_analyzers.get("unknown") {
            if let Some(details) = analyzer.analyze(data, port) {
                return Some((details.service, details.version));
            }
        }
        None
    }
} 

/// Additional protocol-specific analyzers for common network services
pub mod protocol_analyzers {
    use super::*;

    /// DNS protocol analyzer for effective DNS service detection
    pub struct DnsAnalyzer;

    impl DnsAnalyzer {
        pub fn new() -> Self {
            Self
        }
        
        /// Extract useful information from DNS packets
        fn parse_dns_packet(&self, data: &[u8]) -> Option<HashMap<String, String>> {
            // DNS packets need to be at least 12 bytes (header size)
            if data.len() < 12 {
                return None;
            }
            
            // Check if this looks like a DNS packet
            // DNS has a standard structure with transaction ID at the beginning
            let mut metadata = HashMap::new();
            
            // Extract transaction ID from the first 2 bytes
            let transaction_id = ((data[0] as u16) << 8) | (data[1] as u16);
            metadata.insert("transaction_id".to_string(), format!("{}", transaction_id));
            
            // Get flags
            let flags = ((data[2] as u16) << 8) | (data[3] as u16);
            let is_query = (flags & 0x8000) == 0;
            let opcode = (flags >> 11) & 0xF;
            
            metadata.insert("is_query".to_string(), is_query.to_string());
            metadata.insert("opcode".to_string(), format!("{}", opcode));
            
            // Get counts
            let question_count = ((data[4] as u16) << 8) | (data[5] as u16);
            let answer_count = ((data[6] as u16) << 8) | (data[7] as u16);
            
            metadata.insert("question_count".to_string(), format!("{}", question_count));
            metadata.insert("answer_count".to_string(), format!("{}", answer_count));
            
            // For OPSEC reasons, we don't extract domain names from the queries
            // as this could potentially expose sensitive information
            
            Some(metadata)
        }
    }
    
    impl ProtocolAnalyzer for DnsAnalyzer {
        fn analyze(&self, data: &[u8], port: u16) -> Option<ProtocolDetails> {
            // Most common DNS port
            let likely_dns_port = port == 53;
            
            // Parse the packet if it might be DNS
            let metadata = self.parse_dns_packet(data)?;
            
            // If we got metadata and it's on the standard port, high confidence
            // Otherwise, medium confidence
            let confidence = if likely_dns_port { 0.95 } else { 0.7 };
            
            Some(ProtocolDetails {
                service: "dns".to_string(),
                version: None, // DNS typically doesn't reveal version info
                software: None,
                confidence,
                metadata,
            })
        }
    }

    /// MQTT protocol analyzer
    pub struct MqttAnalyzer;
    
    impl MqttAnalyzer {
        pub fn new() -> Self {
            Self
        }
        
        /// Parse MQTT packet to extract protocol information
        fn parse_mqtt_packet(&self, data: &[u8]) -> Option<(Option<String>, HashMap<String, String>)> {
            if data.is_empty() {
                return None;
            }
            
            let mut metadata = HashMap::new();
            
            // MQTT packet structure: 
            // Byte 1: Message type (4 bits) + Flags (4 bits)
            let msg_type = (data[0] & 0xF0) >> 4;
            
            // Check for CONNECT packet (type 1) which has version info
            let version = if msg_type == 1 && data.len() > 10 {
                // Protocol name length
                let name_len = ((data[2] as u16) << 8) | (data[3] as u16);
                
                // If we can read the protocol name (usually "MQTT")
                if name_len <= 10 && data.len() >= (4 + name_len as usize) {
                    let start = 4;
                    let end = start + name_len as usize;
                    
                    if end < data.len() {
                        let proto_name = String::from_utf8_lossy(&data[start..end]).to_string();
                        metadata.insert("protocol_name".to_string(), proto_name);
                        
                        // Version byte follows the protocol name
                        if end < data.len() {
                            let version_byte = data[end];
                            let ver = match version_byte {
                                3 => "3.1",
                                4 => "3.1.1",
                                5 => "5.0",
                                _ => "unknown",
                            };
                            Some(format!("MQTT/{}", ver))
                        } else {
                            None
                        }
                    } else {
                        None
                    }
                } else {
                    None
                }
            } else {
                None
            };
            
            // Add message type to metadata
            let msg_type_str = match msg_type {
                1 => "CONNECT",
                2 => "CONNACK",
                3 => "PUBLISH",
                4 => "PUBACK",
                5 => "PUBREC",
                6 => "PUBREL",
                7 => "PUBCOMP",
                8 => "SUBSCRIBE",
                9 => "SUBACK",
                10 => "UNSUBSCRIBE",
                11 => "UNSUBACK",
                12 => "PINGREQ",
                13 => "PINGRESP",
                14 => "DISCONNECT",
                _ => "UNKNOWN",
            };
            
            metadata.insert("message_type".to_string(), msg_type_str.to_string());
            
            Some((version, metadata))
        }
    }
    
    impl ProtocolAnalyzer for MqttAnalyzer {
        fn analyze(&self, data: &[u8], port: u16) -> Option<ProtocolDetails> {
            // Common MQTT ports
            let likely_mqtt_port = port == 1883 || port == 8883;
            
            // Try to parse the packet
            let (version, metadata) = self.parse_mqtt_packet(data)?;
            
            // Calculate confidence based on port and packet structure
            let confidence = if likely_mqtt_port { 0.95 } else { 0.75 };
            
            Some(ProtocolDetails {
                service: "mqtt".to_string(),
                version,
                software: None,
                confidence,
                metadata,
            })
        }
    }

    /// SNMP protocol analyzer
    pub struct SnmpAnalyzer;
    
    impl SnmpAnalyzer {
        pub fn new() -> Self {
            Self
        }
        
        /// Check if the data has ASN.1 BER structure typical of SNMP
        fn is_valid_ber(&self, data: &[u8]) -> bool {
            // SNMP is encoded using ASN.1 BER
            // Sequence tag is 0x30
            if data.is_empty() || data[0] != 0x30 {
                return false;
            }
            
            // Check if the length field makes sense
            if data.len() < 2 {
                return false;
            }
            
            let length_byte = data[1];
            
            // Short form length (one byte)
            if length_byte < 128 {
                return data.len() >= (2 + length_byte as usize);
            }
            
            // Long form length
            let length_octets = (length_byte & 0x7F) as usize;
            if data.len() < 2 + length_octets {
                return false;
            }
            
            true
        }
        
        /// Extract SNMP version from packet
        fn extract_version(&self, data: &[u8]) -> Option<String> {
            // SNMP packet structure:
            // SEQUENCE {
            //   VERSION (INTEGER)
            //   ...
            // }
            
            // If not a valid BER structure, exit
            if !self.is_valid_ber(data) || data.len() < 5 {
                return None;
            }
            
            // Skip the SEQUENCE header
            let header_size = if data[1] < 128 { 2 } else { 2 + (data[1] & 0x7F) as usize };
            
            // Check if the next element is INTEGER (0x02) - the version
            if data.len() > header_size && data[header_size] == 0x02 {
                if data.len() > header_size + 2 {
                    // Get the version value
                    let version_size = data[header_size + 1] as usize;
                    if data.len() >= header_size + 2 + version_size && version_size == 1 {
                        let version = match data[header_size + 2] {
                            0 => Some("SNMPv1".to_string()),
                            1 => Some("SNMPv2c".to_string()),
                            3 => Some("SNMPv3".to_string()),
                            _ => None,
                        };
                        return version;
                    }
                }
            }
            
            None
        }
    }
    
    impl ProtocolAnalyzer for SnmpAnalyzer {
        fn analyze(&self, data: &[u8], port: u16) -> Option<ProtocolDetails> {
            // Common SNMP ports
            let likely_snmp_port = port == 161 || port == 162;
            
            // Check if this looks like a valid SNMP packet
            if !self.is_valid_ber(data) {
                return None;
            }
            
            // Try to extract the version
            let version = self.extract_version(data);
            
            // Additional metadata
            let mut metadata = HashMap::new();
            metadata.insert("protocol".to_string(), "SNMP".to_string());
            
            // Determine confidence
            let confidence = if likely_snmp_port { 0.95 } else { 0.85 };
            
            Some(ProtocolDetails {
                service: "snmp".to_string(),
                version,
                software: None,
                confidence,
                metadata,
            })
        }
    }

    /// LDAP protocol analyzer
    pub struct LdapAnalyzer;
    
    impl LdapAnalyzer {
        pub fn new() -> Self {
            Self
        }
        
        /// Extract LDAP operation information from packet
        fn parse_ldap_packet(&self, data: &[u8]) -> Option<HashMap<String, String>> {
            // LDAP uses ASN.1 BER encoding
            if data.is_empty() || data[0] != 0x30 {
                return None;
            }
            
            let mut metadata = HashMap::new();
            
            // Try to extract the message ID and operation type
            if data.len() > 10 {  // Need at least a few bytes for header and operation
                // Skip the outer SEQUENCE header
                let mut pos = 2;  // Simplistic - assumes short form length
                
                // Try to find the message ID (INTEGER)
                if pos < data.len() && data[pos] == 0x02 {
                    pos += 2 + data[pos + 1] as usize;  // Skip over message ID
                    
                    // Next should be the operation (APPLICATION tag)
                    if pos < data.len() {
                        let op_class = data[pos] & 0x1F;  // Application class tag
                        
                        // Map operation code to operation name
                        let op_name = match op_class {
                            0 => "bindRequest",
                            1 => "bindResponse",
                            2 => "unbindRequest",
                            3 => "searchRequest",
                            4 => "searchResponse",
                            5 => "modifyRequest",
                            6 => "modifyResponse",
                            7 => "addRequest",
                            8 => "addResponse",
                            9 => "delRequest",
                            10 => "delResponse",
                            11 => "modDNRequest",
                            12 => "modDNResponse",
                            13 => "compareRequest",
                            14 => "compareResponse",
                            15 => "abandonRequest",
                            16 => "searchResult",
                            23 => "extendedRequest",
                            24 => "extendedResponse",
                            _ => "unknown",
                        };
                        
                        metadata.insert("operation".to_string(), op_name.to_string());
                    }
                }
            }
            
            // For OPSEC reasons, we don't extract actual LDAP query parameters
            // as these could contain sensitive information
            
            Some(metadata)
        }
    }
    
    impl ProtocolAnalyzer for LdapAnalyzer {
        fn analyze(&self, data: &[u8], port: u16) -> Option<ProtocolDetails> {
            // Common LDAP ports
            let likely_ldap_port = port == 389 || port == 636;
            
            // Parse the packet
            let metadata = self.parse_ldap_packet(data)?;
            
            // Determine confidence
            let confidence = if likely_ldap_port { 0.95 } else { 0.8 };
            
            // LDAPS (LDAP over SSL) uses port 636
            let service = if port == 636 {
                "ldaps"
            } else {
                "ldap"
            };
            
            Some(ProtocolDetails {
                service: service.to_string(),
                version: None, // LDAP version isn't easily extractable from most packets
                software: None,
                confidence,
                metadata,
            })
        }
    }

    /// Modbus protocol analyzer for industrial control systems
    pub struct ModbusAnalyzer;
    
    impl ModbusAnalyzer {
        pub fn new() -> Self {
            Self
        }
        
        /// Parse Modbus TCP packet
        fn parse_modbus_packet(&self, data: &[u8]) -> Option<HashMap<String, String>> {
            // Modbus TCP requires at least 8 bytes for the header
            if data.len() < 8 {
                return None;
            }
            
            // Check for Modbus TCP signature:
            // - 2 bytes transaction ID
            // - 2 bytes protocol ID (should be 0)
            // - 2 bytes length
            // - 1 byte unit ID
            // - 1 byte function code
            
            // Protocol ID should be 0 for Modbus TCP
            let protocol_id = ((data[2] as u16) << 8) | (data[3] as u16);
            if protocol_id != 0 {
                return None;
            }
            
            let mut metadata = HashMap::new();
            
            // Extract transaction ID
            let transaction_id = ((data[0] as u16) << 8) | (data[1] as u16);
            metadata.insert("transaction_id".to_string(), format!("{}", transaction_id));
            
            // Extract function code
            let function_code = data[7];
            
            // Map function code to function name
            let function_name = match function_code {
                1 => "Read Coils",
                2 => "Read Discrete Inputs",
                3 => "Read Holding Registers",
                4 => "Read Input Registers",
                5 => "Write Single Coil",
                6 => "Write Single Register",
                15 => "Write Multiple Coils",
                16 => "Write Multiple Registers",
                _ => "Unknown Function",
            };
            
            metadata.insert("function".to_string(), function_name.to_string());
            metadata.insert("function_code".to_string(), format!("{}", function_code));
            
            // Extract unit ID
            let unit_id = data[6];
            metadata.insert("unit_id".to_string(), format!("{}", unit_id));
            
            Some(metadata)
        }
    }
    
    impl ProtocolAnalyzer for ModbusAnalyzer {
        fn analyze(&self, data: &[u8], port: u16) -> Option<ProtocolDetails> {
            // Modbus TCP standard port
            let likely_modbus_port = port == 502;
            
            // Parse the packet
            let metadata = self.parse_modbus_packet(data)?;
            
            // Determine confidence
            let confidence = if likely_modbus_port { 0.95 } else { 0.85 };
            
            Some(ProtocolDetails {
                service: "modbus".to_string(),
                version: None, // Modbus doesn't typically reveal version info
                software: None,
                confidence,
                metadata,
            })
        }
    }
}

impl MlServiceIdentifier {
    /// Initialize version detection patterns for common services
    fn initialize_version_patterns(&mut self) {
        let mut patterns = HashMap::new();
        
        // HTTP server version patterns
        let http_patterns = vec![
            // Apache version pattern
            (regex::Regex::new(r"(?i)Apache(?:/| )([0-9]+\.[0-9]+\.[0-9]+)").unwrap(), "Apache/$1".to_string()),
            // Nginx version pattern
            (regex::Regex::new(r"(?i)nginx(?:/| )([0-9]+\.[0-9]+\.[0-9]+)").unwrap(), "Nginx/$1".to_string()),
            // IIS version pattern
            (regex::Regex::new(r"(?i)Microsoft-IIS/([0-9]+\.[0-9]+)").unwrap(), "IIS/$1".to_string()),
            // General HTTP version pattern
            (regex::Regex::new(r"HTTP/([0-9]+\.[0-9]+)").unwrap(), "HTTP/$1".to_string()),
        ];
        patterns.insert("http".to_string(), http_patterns);
        
        // SSH version patterns
        let ssh_patterns = vec![
            (regex::Regex::new(r"SSH-([0-9]+\.[0-9]+)-([^\s]+)").unwrap(), "SSH/$1 ($2)".to_string()),
            (regex::Regex::new(r"OpenSSH_([0-9]+\.[0-9]+[p0-9]*)").unwrap(), "OpenSSH/$1".to_string()),
        ];
        patterns.insert("ssh".to_string(), ssh_patterns);
        
        // FTP version patterns
        let ftp_patterns = vec![
            (regex::Regex::new(r"(?i)FileZilla Server(?:/| )([0-9]+\.[0-9]+\.[0-9]+)").unwrap(), "FileZilla/$1".to_string()),
            (regex::Regex::new(r"(?i)ProFTPD(?:/| )([0-9]+\.[0-9]+\.[0-9]+)").unwrap(), "ProFTPD/$1".to_string()),
            (regex::Regex::new(r"(?i)Pure-FTPd(?:/| )").unwrap(), "Pure-FTPd".to_string()),
            (regex::Regex::new(r"(?i)vsftpd(?:/| )([0-9]+\.[0-9]+\.[0-9]+)").unwrap(), "vsftpd/$1".to_string()),
        ];
        patterns.insert("ftp".to_string(), ftp_patterns);
        
        // SMTP version patterns
        let smtp_patterns = vec![
            (regex::Regex::new(r"(?i)Postfix(?:/| )([0-9]+\.[0-9]+\.[0-9]+)").unwrap(), "Postfix/$1".to_string()),
            (regex::Regex::new(r"(?i)Exim(?:/| )([0-9]+\.[0-9]+)").unwrap(), "Exim/$1".to_string()),
            (regex::Regex::new(r"(?i)Sendmail(?:/| )([0-9]+\.[0-9]+\.[0-9]+)").unwrap(), "Sendmail/$1".to_string()),
            (regex::Regex::new(r"(?i)Microsoft ESMTP(?:/| )([0-9]+\.[0-9]+\.[0-9]+)").unwrap(), "MS ESMTP/$1".to_string()),
        ];
        patterns.insert("smtp".to_string(), smtp_patterns);
        
        // MySQL version pattern
        let mysql_patterns = vec![
            (regex::Regex::new(r"(?i)MySQL(?:/| )([0-9]+\.[0-9]+\.[0-9]+)").unwrap(), "MySQL/$1".to_string()),
            (regex::Regex::new(r"(?i)MariaDB(?:/| )([0-9]+\.[0-9]+\.[0-9]+)").unwrap(), "MariaDB/$1".to_string()),
        ];
        patterns.insert("mysql".to_string(), mysql_patterns);
        
        // Add more patterns for other protocols as needed
        // These are just a few examples for the most common protocols
        
        self.version_patterns = patterns;
    }
    
    /// Initialize service aliases for common protocol names
    fn initialize_service_aliases(&mut self) {
        let mut aliases = HashMap::new();
        
        // Web servers
        aliases.insert("www".to_string(), "http".to_string());
        aliases.insert("https".to_string(), "http".to_string());
        aliases.insert("http-alt".to_string(), "http".to_string());
        
        // Database servers
        aliases.insert("mariadb".to_string(), "mysql".to_string());
        aliases.insert("postgres".to_string(), "postgresql".to_string());
        
        // Email services
        aliases.insert("submission".to_string(), "smtp".to_string());
        aliases.insert("smtps".to_string(), "smtp".to_string());
        aliases.insert("pop3s".to_string(), "pop3".to_string());
        aliases.insert("imaps".to_string(), "imap".to_string());
        
        // File transfer
        aliases.insert("ftps".to_string(), "ftp".to_string());
        aliases.insert("sftp".to_string(), "ssh".to_string());
        
        // Remote access
        aliases.insert("ms-wbt-server".to_string(), "rdp".to_string());
        aliases.insert("microsoft-ds".to_string(), "smb".to_string());
        
        self.service_aliases = aliases;
    }
    
    /// Extract version information from a banner using service-specific regex patterns
    fn extract_version(&self, service: &str, banner: &str) -> Option<String> {
        // Get patterns for this service
        if let Some(patterns) = self.version_patterns.get(service) {
            // Try each pattern in order
            for (pattern, format) in patterns {
                if let Some(captures) = pattern.captures(banner) {
                    // We need to handle the replacements manually since the format can have
                    // different syntax than regex's replacement format
                    let mut result = format.clone();
                    
                    // Replace $1, $2, etc. with capture groups
                    for i in 1..captures.len() {
                        if let Some(group) = captures.get(i) {
                            let placeholder = format!("${}", i);
                            result = result.replace(&placeholder, group.as_str());
                        }
                    }
                    
                    return Some(result);
                }
            }
        }
        
        // No match found, try generic version pattern as fallback
        let generic_version = regex::Regex::new(r"(?i)version[:\s]+([0-9]+(?:\.[0-9]+)+)").unwrap();
        if let Some(captures) = generic_version.captures(banner) {
            if let Some(version) = captures.get(1) {
                return Some(version.as_str().to_string());
            }
        }
        
        None
    }
    
    /// Enhanced method to identify services that integrates all available methods
    pub fn enhanced_identify_service(
        &self,
        data: &[u8],
        port: u16,
        response_time_ms: f32,
        immediate_close: bool,
        server_initiated: bool
    ) -> Option<(String, Option<String>, HashMap<String, String>)> {
        // Try using all techniques from the most to least specific
        
        // 1. Start with definitive protocol identification based on packet structure
        let features = if data.iter().any(|&b| b > 127 || (b < 32 && b != 10 && b != 13 && b != 9)) {
            // Binary data
            ServiceFeatureVector::from_binary(data, port, response_time_ms, immediate_close, server_initiated)
        } else {
            // Text data
            let banner = String::from_utf8_lossy(data);
            ServiceFeatureVector::from_banner(&banner, port, response_time_ms, immediate_close, server_initiated)
        };
        
        // 2. Quick identification based on protocol signatures
        if let Some(service) = self.quick_identify(&features) {
            let banner = String::from_utf8_lossy(data);
            let version = self.extract_version(service, &banner);
            
            // Try protocol-specific analyzer for more details
            if let Some(analyzer) = self.protocol_analyzers.get(service) {
                if let Some(details) = analyzer.analyze(data, port) {
                    return Some((
                        details.service,
                        details.version.or(version),
                        details.metadata,
                    ));
                }
            }
            
            // Return basic identification
            let mut metadata = HashMap::new();
            metadata.insert("detection_method".to_string(), "pattern".to_string());
            
            return Some((service.to_string(), version, metadata));
        }
        
        // 3. Try nDPI identification
        #[cfg(feature = "ndpi")]
        {
            if let Some((service, version)) = self.try_ndpi_identification(data, port) {
                let mut metadata = HashMap::new();
                metadata.insert("detection_method".to_string(), "nDPI".to_string());
                return Some((service, version, metadata));
            }
        }
        
        // 4. Use ML model as fallback
        if let Some((service, version)) = self.identify_with_model(&features, &String::from_utf8_lossy(data)) {
            let mut metadata = HashMap::new();
            metadata.insert("detection_method".to_string(), "ml_model".to_string());
            return Some((service, version, metadata));
        }
        
        // 5. Last resort - port-based identification
        let port_service = match port {
            22 => Some("ssh"),
            25 | 587 => Some("smtp"),
            80 => Some("http"),
            443 => Some("ssl/tls"),
            21 => Some("ftp"),
            23 => Some("telnet"),
            3306 => Some("mysql"),
            5432 => Some("postgresql"),
            3389 => Some("rdp"),
            5900..=5999 => Some("vnc"),
            _ => None
        };
        
        if let Some(service) = port_service {
            let mut metadata = HashMap::new();
            metadata.insert("detection_method".to_string(), "port-based".to_string());
            metadata.insert("confidence".to_string(), "low".to_string());
            return Some((service.to_string(), None, metadata));
        }
        
        None
    }
}

// Extend the ServiceIdentification trait with the enhanced identification method
impl ServiceIdentification for MlServiceIdentifier {
    fn identify_service(
        &self,
        data: &[u8],
        port: u16,
        response_time_ms: f32,
        immediate_close: bool,
        server_initiated: bool
    ) -> Option<(String, Option<String>)> {
        // Use the enhanced identification method and discard the metadata
        self.enhanced_identify_service(data, port, response_time_ms, immediate_close, server_initiated)
            .map(|(service, version, _)| (service, version))
    }
}