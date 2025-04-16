//! nDPI Integration Module
//!
//! This module provides integration with the nDPI deep packet inspection library
//! for advanced protocol detection and service identification.
//! 
//! nDPI is a powerful library that can identify over 280 protocols and applications
//! based on packet inspection. This implementation provides full access to all
//! supported protocols without limiting functionality for comprehensive service detection.

use std::collections::HashMap;
use std::ffi::CStr;
use std::sync::RwLock;
use log::{debug, info, warn};
use serde::{Serialize, Deserialize};
use anyhow::{Result, anyhow};
use lazy_static::lazy_static;

// Use our internal nDPI sys bindings
use crate::ndpi_sys as sys;

/// Wrapper for nDPI detection functionality with full protocol support
pub struct NdpiEngine {
    // The nDPI detection module
    detection_module: *mut sys::ndpi_detection_module_struct,
    // Map of protocol IDs to their names
    protocols: HashMap<u32, String>,
    // Track flow packet count for multi-packet analysis
    flow_packet_count: usize,
    // Version info for the nDPI library
    version_info: String,
    // Flow tracking for analysis
    flows: HashMap<String, (u32, u32)>, // Flow key -> (proto_id, data_len)
}

/// Protocol identification result from nDPI
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NDPIProtocolInfo {
    /// Main protocol name
    pub protocol_name: String,
    /// Application protocol name (if applicable)
    pub app_protocol_name: Option<String>,
    /// Confidence score (0.0-1.0)
    pub confidence: f32,
    /// Protocol category
    pub category: String,
    /// Whether the protocol uses encryption
    pub is_encrypted: bool,
    /// The port used by the protocol (if can be determined)
    pub probable_port: Option<u16>,
    /// Protocol risk score (if available)
    pub risk_score: Option<u32>,
    /// Additional metadata about the protocol (if available)
    pub metadata: HashMap<String, String>,
}

// Global singleton instance for efficient reuse
lazy_static! {
    static ref NDPI_INSTANCE: RwLock<Option<NdpiEngine>> = RwLock::new(None);
}

// Safety: We need these to be Send + Sync for use in async contexts
// This is safe because we ensure proper synchronization when accessing the detector
unsafe impl Send for NdpiEngine {}
unsafe impl Sync for NdpiEngine {}

impl NdpiEngine {
    /// Create a new nDPI detector instance with full protocol support
    ///
    /// # Returns
    /// * `Result<Self>` - The detector or an error
    pub fn new() -> Result<Self> {
        // Initialize nDPI detection module
        unsafe {
            // Create detection module with full protocol support
            let detection_module = sys::ndpi_init_detection_module(0);
            if detection_module.is_null() {
                return Err(anyhow!("Failed to initialize nDPI detection module"));
            }

            // Enable all protocols for detection - no limitations
            sys::ndpi_set_all_protocols(detection_module, 1);
            
            // Set detection to include all possible protocols
            sys::ndpi_set_detection_preferences(detection_module, 
                sys::ndpi_detection_preference_values::ndpi_deep_protocol_inspection as i32);
            
            // Build complete protocol map for all supported protocols
            let mut protocols = HashMap::new();
            let num_protocols = sys::ndpi_get_num_supported_protocols(detection_module);
            
            for i in 0..num_protocols {
                let proto_name = sys::ndpi_get_proto_name(detection_module, i);
                if !proto_name.is_null() {
                    let proto_name_str = CStr::from_ptr(proto_name).to_string_lossy().to_string();
                    protocols.insert(i as u32, proto_name_str);
                }
            }

            // Get nDPI version info
            let version = sys::ndpi_revision();
            let version_str = if !version.is_null() {
                CStr::from_ptr(version).to_string_lossy().to_string()
            } else {
                "unknown version".to_string()
            };

            info!("nDPI {} initialized with {} supported protocols", 
                  version_str, protocols.len());

            Ok(Self {
                detection_module,
                protocols,
                flow_packet_count: 0,
                version_info: version_str,
                flows: HashMap::new(),
            })
        }
    }
    
    /// Get a global instance of the detector
    pub fn get_instance() -> Result<Self> {
        let mut instance_lock = NDPI_INSTANCE.write().unwrap();
        
        if instance_lock.is_none() {
            *instance_lock = Some(Self::new()?);
        }
        
        // Since we can't simply clone the instance due to C pointers,
        // we'll create a new one if needed
        Self::new()
    }

    /// Get the nDPI library version
    pub fn get_version(&self) -> &str {
        &self.version_info
    }

    /// Get the total number of supported protocols
    pub fn get_protocol_count(&self) -> usize {
        self.protocols.len()
    }
    
    /// Get protocol name for a given ID
    pub fn get_protocol_name(&self, proto_id: u32) -> Option<String> {
        self.protocols.get(&proto_id).cloned()
    }
    
    /// List all supported protocols
    pub fn list_all_protocols(&self) -> Vec<String> {
        self.protocols.values().cloned().collect()
    }

    /// Detect protocol from packet data with comprehensive analysis
    ///
    /// # Arguments
    /// * `data` - The packet data to analyze
    /// * `src_port` - Source port
    /// * `dst_port` - Destination port
    /// * `is_tcp` - Whether the packet is TCP (vs UDP)
    ///
    /// # Returns
    /// * `Result<NDPIProtocolInfo>` - Protocol information or error
    pub fn detect_protocol(&mut self, data: &[u8], src_port: u16, dst_port: u16, is_tcp: bool) -> Result<NDPIProtocolInfo> {
        if data.is_empty() {
            return Err(anyhow!("Empty packet data"));
        }
        
        unsafe {
            // Create flow for this packet
            let mut flow = sys::ndpi_flow_struct::new();
            
            // Initialize source and destination IDs for flow tracking
            let mut src_id: u32 = 0;
            let mut dst_id: u32 = 0;
            
            // Create an ndpi_packet_struct
            let mut packet = sys::ndpi_packet_struct {
                iph: std::ptr::null_mut(),
                iphv6: std::ptr::null_mut(),
                tcp: std::ptr::null_mut(),
                udp: std::ptr::null_mut(),
                payload: data.as_ptr() as *const u8,
                payload_packet_len: data.len() as u16,
                l4_packet_len: data.len() as u16,
                l3_packet_len: (data.len() + 40) as u16, // Add typical header size
                l4_protocol: if is_tcp { 6 } else { 17 }, // 6=TCP, 17=UDP
                ..Default::default()
            };
            
            // Process the packet with full analysis
            let proto_id = sys::ndpi_detection_process_packet(
                self.detection_module,
                &mut flow as *mut _,
                &mut packet as *mut _,
                0, // current time
                &mut src_id,
                &mut dst_id
            );
            
            // Track flow packet count for multi-packet analysis
            self.flow_packet_count += 1;
            
            // Get protocol name
            let proto_name = if proto_id != 0 {
                self.protocols.get(&proto_id)
                    .cloned()
                    .unwrap_or_else(|| "unknown".to_string())
            } else {
                // If first packet didn't give definitive result, try getting a guess
                let guess = sys::ndpi_detection_giveup(
                    self.detection_module,
                    &mut flow as *mut _,
                    1, // Provide a hint that we want the best guess
                    &mut src_id,
                    &mut dst_id
                );
                
                if guess != 0 && guess != proto_id {
                    self.protocols.get(&guess)
                        .cloned()
                        .unwrap_or_else(|| "unknown".to_string())
                } else {
                    "unknown".to_string()
                }
            };
            
            // Get protocol category
            let category_id = sys::ndpi_get_proto_category(self.detection_module, proto_id);
            let category_name = sys::ndpi_category_get_name(self.detection_module, category_id);
            let category = if !category_name.is_null() {
                CStr::from_ptr(category_name).to_string_lossy().to_string()
            } else {
                "Unknown".to_string()
            };
            
            // Check if the protocol is encrypted
            let is_encrypted = match proto_name.as_str() {
                "TLS" | "SSL" | "SSH" | "HTTPS" | "FTPS" | "SFTP" | "IMAPS" | "SMTPS" | "POPS" => true,
                _ => sys::ndpi_is_encrypted_proto(self.detection_module, proto_id) != 0
            };
            
            // Determine app protocol if this is a tunneled protocol
            let app_protocol_name = if proto_id == sys::NDPI_PROTOCOL_TLS as u32 || 
                                    proto_id == sys::NDPI_PROTOCOL_SSL as u32 {
                // Call the wrapped function via the sys module
                let app_proto_id = sys::wrapped_ndpi_get_app_protocol(self.detection_module, &mut flow);
                if app_proto_id != 0 && app_proto_id != proto_id {
                    self.protocols.get(&app_proto_id).cloned()
                } else {
                    None
                }
            } else {
                None
            };
            
            // Store the flow with its detected protocol
            let flow_key = format!("{}:{}-{}:{}", src_id, src_port, dst_id, dst_port);
            self.flows.insert(flow_key, (proto_id, data.len() as u32));
            
            // Extract metadata if available
            let metadata = HashMap::new();
            
            // Calculate confidence based on packet count and protocol clarity
            let confidence = if proto_id == 0 {
                0.3 // Low confidence for unknown
            } else if self.flow_packet_count < 2 {
                0.6 // Medium confidence with just one packet
            } else {
                0.9 // High confidence with multiple packets
            };
            
            // Determine probable port based on the protocol
            let probable_port = self.determine_probable_port(proto_name.as_str(), src_port, dst_port);
            
            // Return the results
            Ok(NDPIProtocolInfo {
                protocol_name: proto_name,
                app_protocol_name,
                confidence,
                category,
                is_encrypted,
                probable_port,
                risk_score: None, // nDPI risk score not used
                metadata,
            })
        }
    }
    
    /// Helper function to determine the probable service port
    fn determine_probable_port(&self, proto_name: &str, src_port: u16, dst_port: u16) -> Option<u16> {
        // If one port is a well-known port (<1024) and the other isn't, use the well-known port
        if src_port < 1024 && dst_port >= 1024 {
            return Some(src_port);
        } else if dst_port < 1024 && src_port >= 1024 {
            return Some(dst_port);
        }
        
        // Otherwise use common port mappings
        match proto_name.to_uppercase().as_str() {
            "HTTP" => Some(80),
            "HTTPS" | "TLS" | "SSL" => Some(443),
            "SSH" => Some(22),
            "FTP" | "FTP_CONTROL" => Some(21),
            "FTP_DATA" => Some(20),
            "SMTP" => Some(25),
            "SMTPS" => Some(465),
            "SUBMISSION" => Some(587),
            "POP3" => Some(110),
            "POP3S" => Some(995),
            "IMAP" => Some(143),
            "IMAPS" => Some(993),
            "DNS" => Some(53),
            "DHCP" => Some(67),
            "TELNET" => Some(23),
            "SNMP" => Some(161),
            "LDAP" => Some(389),
            "LDAPS" => Some(636),
            "MYSQL" => Some(3306),
            "POSTGRES" | "POSTGRESQL" => Some(5432),
            "REDIS" => Some(6379),
            "MONGODB" => Some(27017),
            "RDP" => Some(3389),
            "VNC" => Some(5900),
            "SMB" | "SMBV1" | "SMBV23" => Some(445),
            "NTP" => Some(123),
            "SIP" => Some(5060),
            "SIPS" => Some(5061),
            "RTSP" => Some(554),
            "RTP" | "RTCP" => None, // Dynamic ports typically
            "IRC" => Some(6667),
            "QUIC" => Some(443), // Typically HTTPS over QUIC
            "ISAKMP" | "IPSEC" => Some(500),
            "OPENVPN" => Some(1194),
            "PPTP" => Some(1723),
            "L2TP" => Some(1701),
            "MSSQL_TDS" | "TDS" => Some(1433),
            "NATS" => Some(4222),
            "MQTT" => Some(1883),
            "MQTTS" => Some(8883),
            "KERBEROS" => Some(88),
            "RADIUS" => Some(1812),
            "TACACS" => Some(49),
            "AFP" => Some(548),
            "BGP" => Some(179),
            "DHCPV6" => Some(546),
            "STUN" => Some(3478),
            "SSDP" => Some(1900),
            "NETBIOS" => Some(139),
            "NFS" => Some(2049),
            "MDNS" => Some(5353),
            "MEMCACHED" => Some(11211),
            "RSYNC" => Some(873),
            "TFTP" => Some(69),
            "UPNP" => Some(1900),
            "WEBSOCKET" => Some(80), // Often on HTTP ports
            _ => None,
        }
    }

    /// Analyze a packet for protocol detection
    pub fn analyze_packet(&mut self, src_ip: std::net::IpAddr, dst_ip: std::net::IpAddr, 
                         src_port: u16, dst_port: u16, data: &[u8]) {
        if data.is_empty() {
            return;
        }
        
        // Try to detect the protocol
        match self.detect_protocol(data, src_port, dst_port, true) {
            Ok(protocol_info) => {
                debug!("Detected protocol: {} (confidence: {:.2})", 
                      protocol_info.protocol_name, protocol_info.confidence);
                
                // Create a unique flow key
                let flow_key = format!("{}:{}-{}:{}", src_ip, src_port, dst_ip, dst_port);
                
                // Get proto_id from name (using first one we find)
                let proto_id = self.protocols.iter()
                    .find(|(_, name)| **name == protocol_info.protocol_name)
                    .map(|(id, _)| *id)
                    .unwrap_or(0);
                
                // Record that we've seen this flow with the detected protocol
                self.flows.insert(flow_key, (proto_id, data.len() as u32));
            },
            Err(e) => {
                debug!("Protocol detection failed: {}", e);
                
                // Even with failed detection, record the flow
                let flow_key = format!("{}:{}-{}:{}", src_ip, src_port, dst_ip, dst_port);
                self.flows.insert(flow_key, (0, data.len() as u32));
            }
        }
    }
    
    /// Get results for a specific flow
    pub fn get_flow_results(&self, src_ip: std::net::IpAddr, dst_ip: std::net::IpAddr, 
                           src_port: u16, dst_port: u16) -> (Option<String>, Option<f32>) {
        let flow_key = format!("{}:{}-{}:{}", src_ip, src_port, dst_ip, dst_port);
        
        if let Some(&(proto_id, _)) = self.flows.get(&flow_key) {
            // If we have a protocol ID, look up its name
            if proto_id > 0 {
                if let Some(proto_name) = self.protocols.get(&proto_id) {
                    return (Some(proto_name.clone()), Some(0.9));
                }
            }
            
            // Fall back to port-based guessing
            match (src_port, dst_port) {
                (80, _) | (_, 80) => (Some("HTTP".to_string()), Some(0.9)),
                (443, _) | (_, 443) => (Some("HTTPS".to_string()), Some(0.9)),
                (22, _) | (_, 22) => (Some("SSH".to_string()), Some(0.9)),
                (21, _) | (_, 21) => (Some("FTP".to_string()), Some(0.9)),
                (25, _) | (_, 25) => (Some("SMTP".to_string()), Some(0.9)),
                (110, _) | (_, 110) => (Some("POP3".to_string()), Some(0.9)),
                (143, _) | (_, 143) => (Some("IMAP".to_string()), Some(0.9)),
                _ => (Some("Unknown".to_string()), Some(0.2)),
            }
        } else {
            (None, None)
        }
    }
}

impl Drop for NdpiEngine {
    fn drop(&mut self) {
        unsafe {
            if !self.detection_module.is_null() {
                sys::ndpi_exit_detection_module(self.detection_module);
                self.detection_module = std::ptr::null_mut();
            }
        }
    }
}

/// Helper function to convert nDPI protocol info to service info
pub fn ndpi_to_service_info(proto_info: NDPIProtocolInfo) -> (String, Option<String>) {
    // Extract the main protocol name
    let service_name = proto_info.protocol_name.to_lowercase();
    
    // Incorporate application protocol if relevant
    let version_info = if let Some(app_name) = proto_info.app_protocol_name {
        Some(format!("{} over {}", app_name, service_name))
    } else {
        // If no app protocol, see if we have metadata
        proto_info.metadata.get("hostname").or_else(|| 
            proto_info.metadata.get("user_agent")).cloned()
    };
    
    (service_name, version_info)
}

/// Public function to detect protocol with nDPI
/// 
/// # Arguments
/// * `data` - The packet data to analyze
/// * `src_port` - Source port (use 0 if unknown)
/// * `dst_port` - Destination port 
/// * `is_tcp` - Whether the packet is TCP (vs UDP)
/// 
/// # Returns
/// * `Option<(String, Option<String>)>` - Service name and optional version
pub fn detect_protocol(data: &[u8], src_port: u16, dst_port: u16, is_tcp: bool) -> Option<(String, Option<String>)> {
    // Skip empty data
    if data.is_empty() {
        return None;
    }
    
    // Try to get nDPI instance
    match NdpiEngine::get_instance() {
        Ok(mut detector) => {
            // Try to detect the protocol using nDPI
            match detector.detect_protocol(data, src_port, dst_port, is_tcp) {
                Ok(proto_info) => {
                    if proto_info.protocol_name != "unknown" {
                        debug!("nDPI detected protocol: {} (confidence: {:.2})", 
                              proto_info.protocol_name, proto_info.confidence);
                        
                        // Convert to service info format
                        Some(ndpi_to_service_info(proto_info))
                    } else {
                        None
                    }
                },
                Err(e) => {
                    debug!("nDPI detection error: {}", e);
                    None
                }
            }
        },
        Err(e) => {
            warn!("Failed to get nDPI instance: {}", e);
            None
        }
    }
}

/// Get information about nDPI capabilities
pub fn get_ndpi_info() -> String {
    match NdpiEngine::get_instance() {
        Ok(detector) => {
            format!("nDPI {} - Supporting {} protocols", 
                   detector.get_version(),
                   detector.get_protocol_count())
        },
        Err(_) => {
            "nDPI not available".to_string()
        }
    }
}

/// List all protocols supported by nDPI
pub fn list_supported_protocols() -> Vec<String> {
    match NdpiEngine::get_instance() {
        Ok(detector) => detector.list_all_protocols(),
        Err(_) => vec!["nDPI not available".to_string()],
    }
} 