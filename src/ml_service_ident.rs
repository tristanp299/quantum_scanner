// ML Service Identification Module
// This file provides a unified interface for service identification using ML, pattern matching,
// and nDPI deep packet inspection for advanced service detection. ML is now mandatory.

// Define the ServiceIdentification trait
/// Trait for service identification implementations
/// Allows different strategies for identifying services from banner data
pub trait ServiceIdentification {
    /// Identify a service from a byte stream (usually a banner)
    /// 
    /// # Parameters
    /// * `data` - The raw data/banner received from the service
    /// * `port` - The port number the service is running on
    /// * `response_time_ms` - Response time in milliseconds
    /// * `immediate_close` - Whether the connection was closed immediately
    /// * `server_initiated` - Whether the server initiated the connection
    /// 
    /// # Returns
    /// * `Option<(String, Option<String>)>` - Tuple of (service name, optional version)
    fn identify_service(
        &self,
        data: &[u8], 
        port: u16,
        response_time_ms: f32,
        immediate_close: bool,
        server_initiated: bool
    ) -> Option<(String, Option<String>)>;
}

use rustlearn::ensemble::random_forest::RandomForest;
use bincode::deserialize;
use memmap2::Mmap;

use std::collections::HashMap;
use std::path::PathBuf;
use std::fs::File;
use anyhow::Result;
use log::{debug, warn};
use regex;
use rustlearn::prelude::*;
use rustlearn::array::dense::Array as RustlearnArray;

/// ML-based service identifier implementation
#[derive(Default)]
pub struct MlServiceIdentifier {
    // Internal implementation details
    model: Option<RandomForest>,
    service_labels: Vec<String>,
    version_patterns: HashMap<String, Vec<(regex::Regex, String)>>,
}

impl MlServiceIdentifier {
    pub fn new() -> Self {
        // Create a new ML service identifier with model loading
        let mut identifier = Self::default();
        
        // Initialize service labels - these must match the model's class labels
        identifier.service_labels = vec![
            "http".to_string(),
            "https".to_string(),
            "ssh".to_string(),
            "ftp".to_string(),
            "smtp".to_string(),
            "pop3".to_string(),
            "imap".to_string(),
            "dns".to_string(),
            "mysql".to_string(),
            "postgresql".to_string(),
            "telnet".to_string(),
            "rdp".to_string(),
            "vnc".to_string(),
            "snmp".to_string(),
            "ldap".to_string(),
            "sip".to_string(),
            "ntp".to_string(),
            "rtsp".to_string(),
            "redis".to_string(),
            "mongodb".to_string(),
            "unknown".to_string(),
        ];
        
        // Try to load model from embedded binary or external file
        // Embedded binary approach is more secure for red teaming
        if let Err(e) = identifier.load_model() {
            warn!("Could not load ML model: {}", e);
            // Model loading failed, but we can still continue with nDPI functionality
        }
        
        // Initialize version patterns for common services
        identifier.initialize_version_patterns();
        
        identifier
    }
    
    /// Load the ML model from an embedded binary or external file
    fn load_model(&mut self) -> Result<()> {
        // First try to load from embedded binary (preferred for red teaming)
        // This data would be embedded during compilation
        #[cfg(feature = "embedded_model")]
        {
            const MODEL_DATA: &[u8] = include_bytes!("../models/service_model.bin");
            match deserialize(MODEL_DATA) {
                Ok(model) => {
                    self.model = Some(model);
                    debug!("Loaded ML model from embedded binary");
                    return Ok(());
                },
                Err(e) => {
                    warn!("Could not deserialize embedded ML model: {}", e);
                    // Continue to try file-based model
                }
            }
        }
        
        // If not embedded, try to load from file
        let model_path = PathBuf::from("models/service_model.bin");
        if model_path.exists() {
            match File::open(&model_path) {
                Ok(file) => {
                    match unsafe { Mmap::map(&file) } {
                        Ok(mmap) => {
                            match deserialize(&mmap[..]) {
                                Ok(model) => {
                                    self.model = Some(model);
                                    debug!("Loaded ML model from file");
                                    return Ok(());
                                },
                                Err(e) => {
                                    warn!("Could not deserialize ML model from file: {}", e);
                                }
                            }
                        },
                        Err(e) => {
                            warn!("Could not memory map ML model file: {}", e);
                        }
                    }
                },
                Err(e) => {
                    warn!("Could not open ML model file: {}", e);
                }
            }
        }
        
        warn!("No ML model found or could not be loaded, using fallback identification methods");
        Err(anyhow::anyhow!("ML model not found or could not be loaded"))
    }
    
    /// Initialize regex patterns for extracting version information
    fn initialize_version_patterns(&mut self) {
        let mut patterns = HashMap::new();
        
        // SSH version patterns
        let ssh_patterns = vec![
            (regex::Regex::new(r"SSH-2\.0-OpenSSH_([0-9\.]+)").unwrap(), "OpenSSH $1".to_string()),
            (regex::Regex::new(r"SSH-2\.0-dropbear_([0-9\.]+)").unwrap(), "Dropbear $1".to_string()),
        ];
        patterns.insert("ssh".to_string(), ssh_patterns);
        
        // HTTP server patterns
        let http_patterns = vec![
            (regex::Regex::new(r"Server: Apache/([0-9\.]+)").unwrap(), "Apache $1".to_string()),
            (regex::Regex::new(r"Server: nginx/([0-9\.]+)").unwrap(), "nginx $1".to_string()),
            (regex::Regex::new(r"Server: Microsoft-IIS/([0-9\.]+)").unwrap(), "IIS $1".to_string()),
        ];
        patterns.insert("http".to_string(), http_patterns);
        
        // Database patterns
        let mysql_patterns = vec![
            (regex::Regex::new(r"([0-9]+\.[0-9]+\.[0-9]+)-MariaDB").unwrap(), "MariaDB $1".to_string()),
            (regex::Regex::new(r"mysql_native_password.*([0-9]+\.[0-9]+\.[0-9]+)").unwrap(), "MySQL $1".to_string()),
        ];
        patterns.insert("mysql".to_string(), mysql_patterns);
        
        // Add more database systems
        let postgresql_patterns = vec![
            (regex::Regex::new(r"PostgreSQL ([0-9]+\.[0-9]+)").unwrap(), "PostgreSQL $1".to_string()),
        ];
        patterns.insert("postgresql".to_string(), postgresql_patterns);
        
        // Add SMTP patterns
        let smtp_patterns = vec![
            (regex::Regex::new(r"220.*Postfix \(([^)]+)\)").unwrap(), "Postfix $1".to_string()),
            (regex::Regex::new(r"220.*Exim ([0-9\.]+)").unwrap(), "Exim $1".to_string()),
        ];
        patterns.insert("smtp".to_string(), smtp_patterns);
        
        // Add POP3 patterns
        let pop3_patterns = vec![
            (regex::Regex::new(r"\+OK.*([0-9\.]+)").unwrap(), "POP3 $1".to_string()),
        ];
        patterns.insert("pop3".to_string(), pop3_patterns);
        
        // Add IMAP patterns
        let imap_patterns = vec![
            (regex::Regex::new(r"\* OK.*IMAP.*([0-9\.]+)").unwrap(), "IMAP $1".to_string()),
        ];
        patterns.insert("imap".to_string(), imap_patterns);
        
        self.version_patterns = patterns;
    }
    
    /// Extract features from service response for ML classification
    fn extract_features(&self, data: &[u8], port: u16, response_time_ms: f32, 
                      immediate_close: bool, server_initiated: bool) -> Vec<f32> {
        // Feature vector for the ML model
        let mut features = Vec::with_capacity(32);
        
        // Port as a normalized feature (divide by 65535 to get 0-1 range)
        features.push(port as f32 / 65535.0);
        
        // Response time as a feature (normalized by dividing by 10s)
        features.push(response_time_ms / 10000.0);
        
        // Connection behavior features
        features.push(if immediate_close { 1.0 } else { 0.0 });
        features.push(if server_initiated { 1.0 } else { 0.0 });
        
        // Data-based features
        if data.is_empty() {
            // Padding with zeros for empty response
            features.extend(vec![0.0; 28]);
        } else {
            // Content features
            // 1. Length (normalized by dividing by 1000)
            features.push((data.len() as f32).min(1000.0) / 1000.0);
            
            // 2. Printable character ratio
            let printable_count = data.iter()
                .filter(|&&b| b >= 32 && b <= 126)
                .count();
            features.push(printable_count as f32 / data.len() as f32);
            
            // 3. Byte histograms - create a histogram of byte values
            // Group bytes into 16 buckets for dimensionality reduction
            let mut histogram = vec![0.0; 16];
            for &byte in data {
                let bucket = (byte as usize) / 16;
                histogram[bucket] += 1.0;
            }
            // Normalize histogram
            let sum: f32 = histogram.iter().sum();
            if sum > 0.0 {
                for val in &mut histogram {
                    *val /= sum;
                }
            }
            features.extend(histogram);
            
            // 4. ASCII word patterns
            let text = String::from_utf8_lossy(data);
            
            // Check for HTTP patterns
            features.push(if text.contains("HTTP/") { 1.0 } else { 0.0 });
            
            // Check for SSH patterns
            features.push(if text.contains("SSH-") { 1.0 } else { 0.0 });
            
            // Check for SMTP patterns
            features.push(if text.contains("SMTP") || text.contains("220 ") { 1.0 } else { 0.0 });
            
            // Check for FTP patterns
            features.push(if text.contains("FTP") || text.contains("220-") { 1.0 } else { 0.0 });
            
            // Check for database patterns
            features.push(if text.contains("MySQL") || text.contains("PostgreSQL") { 1.0 } else { 0.0 });
            
            // Byte distribution entropy - measure of randomness
            let mut entropy = 0.0;
            let mut byte_counts = [0.0f32; 256];
            let total_bytes = data.len() as f32;
            
            // Count occurrences of each byte value
            for &byte in data {
                byte_counts[byte as usize] += 1.0;
            }
            
            // Calculate entropy based on byte distribution
            for count in byte_counts.iter() {
                if *count > 0.0 {
                    let probability = *count / total_bytes;
                    entropy -= probability * probability.log2();
                }
            }
            // Normalize entropy to 0-1 range (divide by maximum possible entropy)
            entropy /= 8.0;
            
            // Add entropy as a feature - high entropy often indicates encryption or compression
            features.push(entropy);
            
            // Add binary protocol detection features
            // Binary protocols often have specific byte patterns in headers
            features.push(if data.len() >= 4 && data[0] == 0x03 && data[1] == 0x00 { 1.0 } else { 0.0 }); // Possible RDP
            features.push(if data.len() >= 2 && data[0] == 0x16 && data[1] == 0x03 { 1.0 } else { 0.0 }); // Possible TLS
            
            // Remaining feature slots (pad if needed)
            while features.len() < 32 {
                features.push(0.0);
            }
        }
        
        // Truncate to exactly 32 features if we have more
        features.truncate(32);
        
        features
    }
    
    /// Extract version information from service response data
    fn extract_version_info(&self, service_name: &str, data: &[u8]) -> Option<String> {
        // Convert binary data to string for pattern matching
        let text = String::from_utf8_lossy(data);
        
        // Check if we have patterns for this service
        if let Some(patterns) = self.version_patterns.get(&service_name.to_lowercase()) {
            // Try each pattern in order
            for (regex, template) in patterns {
                if let Some(captures) = regex.captures(&text) {
                    let mut result = template.clone();
                    // Replace capture groups in version format
                    for i in 1..captures.len() {
                        if let Some(m) = captures.get(i) {
                            result = result.replace(&format!("${}", i), m.as_str());
                        }
                    }
                    return Some(result);
                }
            }
        }
        
        // Fallback to generalized version extraction
        crate::utils::extract_version_from_banner(service_name, &text)
    }
}

// Implement the ServiceIdentification trait for ML-based identification
impl ServiceIdentification for MlServiceIdentifier {
    /// Identifies the service running on a port based on banner data and metadata.
    /// 
    /// # Identification Strategy
    /// 1. **ML Prediction:** If the ML model is loaded, extract features and predict the service.
    /// 2. **Pattern Matching:** If ML fails or is disabled, try matching common banner patterns (e.g., "HTTP/", "SSH-").
    /// 3. **Port-Based Fallback:** If patterns don't match, guess based on standard port numbers.
    /// 
    /// Version extraction is attempted after a service name is determined (by ML or pattern).
    fn identify_service(
        &self,
        data: &[u8],        // The banner or initial data received.
        port: u16,          // The port number.
        response_time_ms: f32, // How long the service took to respond.
        immediate_close: bool, // Did the connection close immediately after opening?
        server_initiated: bool // Did the server send data first? (Less common for TCP)
    ) -> Option<(String, Option<String>)> { // Returns (ServiceName, Option<VersionString>)
        
        // --- Step 1: Attempt ML-Based Identification ---
        // Only try if we have a model loaded
        if let Some(model) = &self.model {
            debug!("ML model is loaded, attempting ML-based identification");
            // Extract features from the data and metadata.
            let features_vec = self.extract_features(data, port, response_time_ms, 
                                                 immediate_close, server_initiated);
            
            // Ensure the number of features matches the model's expectation (implicitly 32 here).
            if features_vec.len() == 32 { // Check expected feature count
                // Create a new Array with the features
                let mut features_matrix = RustlearnArray::zeros(1, 32);
                
                // Fill the array with our feature values
                for (i, val) in features_vec.iter().enumerate() {
                    features_matrix.set(0, i, *val);
                }
                
                // Perform the prediction using the RandomForest model.
                match model.predict(&features_matrix) { 
                    Ok(prediction_array) => {
                        // Check dimensions before accessing the element
                        if prediction_array.rows() > 0 && prediction_array.cols() > 0 { 
                            // Directly use the result of get(0, 0) as f32
                            let predicted_index_val = prediction_array.get(0, 0);
                            let index = predicted_index_val as usize;
                            // Map the index to a service label from our predefined list.
                            if let Some(service_name) = self.service_labels.get(index) {
                                debug!("ML prediction: Index={}, Service='{}'", index, service_name);
                                // Avoid returning "unknown" if ML predicts it; let fallbacks provide more context if possible.
                                if service_name != "unknown" {
                                    // Attempt to extract version info using regex patterns for the predicted service.
                                    let version_info = self.extract_version_info(service_name, data);
                                    // Return the ML-identified service and optional version.
                                    return Some((service_name.clone(), version_info)); 
                                } else {
                                    debug!("ML predicted 'unknown', proceeding to fallbacks for potential refinement.");
                                }
                            } else {
                                warn!("ML predicted index {} which is out of bounds for service_labels ({} labels)", index, self.service_labels.len());
                            }
                        } else {
                             warn!("ML prediction array was empty or had invalid dimensions.");
                        }
                    },
                    Err(e) => {
                        // Log errors during prediction.
                        warn!("ML prediction execution failed: {}", e);
                    }
                }
            } else {
                 warn!("Feature vector size mismatch (expected 32, got {}), skipping ML prediction.", features_vec.len());
            }
        } else {
             // Model not loaded - this is logged during initialization.
             debug!("ML model not loaded, skipping ML prediction and proceeding to fallbacks.");
        }
        
        // --- Step 2: Fallback to Pattern-Based Identification ---
        // Use simple string matching on the banner if ML didn't provide a confident answer or failed.
        debug!("Attempting fallback pattern-based identification for port {}", port);
        let text_data = String::from_utf8_lossy(data);
        
        // Check for common protocol identifiers at the start or within the banner.
        if text_data.starts_with("HTTP/") || (text_data.contains("Server:") && (port == 80 || port == 443 || port > 1024)) {
             debug!("Pattern match: Detected HTTP/HTTPS based on banner content.");
            let service = if port == 443 || text_data.contains("https") { "https" } else { "http" };
            let version = self.extract_version_info(service, data);
            return Some((service.to_string(), version));
        } else if text_data.starts_with("SSH-") {
             debug!("Pattern match: Detected SSH based on banner content.");
            let version = self.extract_version_info("ssh", data);
            return Some(("ssh".to_string(), version));
        } else if text_data.starts_with("220 ") && (text_data.contains("FTP") || text_data.contains("FileZilla") || text_data.contains("vsftpd") || text_data.contains("ProFTPD")) {
             debug!("Pattern match: Detected FTP based on banner content.");
            let version = self.extract_version_info("ftp", data);
            return Some(("ftp".to_string(), version));
        } else if text_data.starts_with("220 ") && (text_data.contains("SMTP") || text_data.contains("ESMTP") || text_data.contains("Postfix") || text_data.contains("Exim")) {
             debug!("Pattern match: Detected SMTP based on banner content.");
            let version = self.extract_version_info("smtp", data);
            return Some(("smtp".to_string(), version));
        } else if text_data.contains("RFB ") { // VNC often starts with RFB protocol version
             debug!("Pattern match: Detected VNC based on banner content (RFB).");
             let version = self.extract_version_info("vnc", data); // Assuming patterns exist for VNC
             return Some(("vnc".to_string(), version));
        } else if data.len() > 5 && data[5..].starts_with(b"MySQL") || text_data.contains("-MariaDB") { // Check binary prefix or MariaDB string
             debug!("Pattern match: Detected MySQL/MariaDB based on banner content.");
             let version = self.extract_version_info("mysql", data);
             return Some(("mysql".to_string(), version));
        } else if text_data.starts_with("+OK ") && (text_data.contains("POP3") || port == 110) {
             debug!("Pattern match: Detected POP3 based on banner content.");
             let version = self.extract_version_info("pop3", data);
             return Some(("pop3".to_string(), version));
        } else if text_data.starts_with("* OK ") && (text_data.contains("IMAP") || port == 143) {
             debug!("Pattern match: Detected IMAP based on banner content.");
             let version = self.extract_version_info("imap", data);
             return Some(("imap".to_string(), version));
        }

        // --- Step 3: Fallback to Port-Based Identification ---
        // If ML and pattern matching fail, make a guess based on the well-known port number.
        // This is the least reliable method.
        debug!("Attempting fallback port-based identification for port {}", port);
        let port_based_service = match port {
            21 => Some("ftp"),
            22 => Some("ssh"),
            23 => Some("telnet"),
            25 | 587 => Some("smtp"), // Common ports for SMTP
            53 => Some("dns"),       // Often UDP, but sometimes TCP
            80 | 8080 | 8000 => Some("http"), // Common HTTP ports
            110 => Some("pop3"),
            143 => Some("imap"),
            443 | 8443 => Some("https"), // Common HTTPS ports
            445 => Some("smb"),
            389 | 636 => Some("ldap"), // LDAP / LDAPS
            3306 => Some("mysql"),
            3389 => Some("rdp"),
            5432 => Some("postgresql"),
            5900 | 5901 => Some("vnc"), // Common VNC ports
            6379 => Some("redis"),
            27017 | 27018 => Some("mongodb"), // Common MongoDB ports
            _ => None, // No common association for this port
        };
        
        if let Some(service) = port_based_service {
            debug!("Fallback identification: Guessed service '{}' based on port {}", service, port);
            // Don't try version extraction for port-based guesses, as there's no banner evidence.
            return Some((service.to_string(), None));
        }

        // --- Final Fallback ---
        // If all methods fail, return None (service unknown).
        debug!("Service identification failed for port {}", port);
        None
    }
}

// Extract version information using regex patterns
fn extract_version_with_patterns(text: &str, patterns: &[(regex::Regex, String)]) -> Option<String> {
    for (regex, template) in patterns {
        if let Some(captures) = regex.captures(text) {
            let mut result = template.clone();
            for i in 1..captures.len() {
                if let Some(m) = captures.get(i) {
                    result = result.replace(&format!("${}", i), m.as_str());
                }
            }
            return Some(result);
        }
    }
    None
}

// Helper function to create and initialize a new ML service identifier
// This is a convenience function that ensures consistent initialization
pub fn create_ml_identifier() -> MlServiceIdentifier {
    MlServiceIdentifier::new()
} 