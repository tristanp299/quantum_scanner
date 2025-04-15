//! nDPI Integration Module
//!
//! This module provides integration with the nDPI deep packet inspection library
//! for advanced protocol detection and service identification.
//! 
//! nDPI is a powerful library that can identify over 280 protocols and applications
//! based on packet inspection. This implementation provides full access to all
//! supported protocols without limiting functionality for comprehensive service detection.

use std::collections::HashMap;
use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_int, c_void};
use std::sync::RwLock;
use log::{debug, info, error, warn};
use serde::{Serialize, Deserialize};
use anyhow::{Result, anyhow};
use lazy_static::lazy_static;

// Use our internal nDPI sys bindings
use crate::ndpi_sys as sys;

/// Wrapper for nDPI detection functionality with full protocol support
pub struct NDPIDetector {
    // The nDPI detection module
    detection_module: *mut sys::ndpi_detection_module_struct,
    // Map of protocol IDs to their names
    protocols: HashMap<u32, String>,
    // Track flow packet count for multi-packet analysis
    flow_packet_count: usize,
    // Version info for the nDPI library
    version_info: String,
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
    static ref NDPI_INSTANCE: RwLock<Option<NDPIDetector>> = RwLock::new(None);
}

// Safety: We need these to be Send + Sync for use in async contexts
// This is safe because we ensure proper synchronization when accessing the detector
unsafe impl Send for NDPIDetector {}
unsafe impl Sync for NDPIDetector {}

impl NDPIDetector {
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
            
            #[cfg(feature = "full-protocol-detection")]
            {
                // Set detection to include all possible protocols
                sys::ndpi_set_detection_preferences(detection_module, 
                    sys::ndpi_detection_preference_values::ndpi_deep_protocol_inspection as i32);
            }
            
            #[cfg(not(feature = "full-protocol-detection"))]
            {
                // Default detection preferences
                sys::ndpi_set_detection_preferences(detection_module, 
                    sys::ndpi_detection_preference_values::ndpi_no_prefs as i32);
            }
            
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
            })
        }
    }

    /// Get a global instance of the detector
    pub fn get_instance() -> Result<NDPIDetector> {
        let mut instance_lock = NDPI_INSTANCE.write().unwrap();
        
        if instance_lock.is_none() {
            *instance_lock = Some(Self::new()?);
        }
        
        let instance = instance_lock.as_ref().unwrap().clone();
        Ok(instance)
    }

    /// Get the nDPI library version
    pub fn get_version(&self) -> &str {
        &self.version_info
    }

    /// Get the total number of supported protocols
    pub fn get_protocol_count(&self) -> usize {
        self.protocols.len()
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
                let app_proto_id = sys::ndpi_get_app_protocol(self.detection_module, &mut flow);
                if app_proto_id != 0 && app_proto_id != proto_id {
                    self.protocols.get(&app_proto_id).cloned()
                } else {
                    None
                }
            } else {
                None
            };
            
            // Extract risk if available
            // Make sure we handle cases where the function might not be available
            let risk_score = if cfg!(feature = "full-protocol-detection") && cfg!(feature = "ndpi_risk") {
                #[cfg(feature = "ndpi_risk")]
                {
                    // Get protocol risk if the feature is enabled and function is available
                    Some(sys::ndpi_risk_get_score(self.detection_module, flow.risk))
                }
                
                #[cfg(not(feature = "ndpi_risk"))]
                {
                    None
                }
            } else {
                None
            };
            
            // Extract metadata if available
            let mut metadata = HashMap::new();
            
            #[cfg(feature = "full-protocol-detection")]
            #[cfg(feature = "ndpi_extended_info")]
            {
                // Add flow metadata if available - these functions might not exist in older nDPI versions
                // so we need to handle them conditionally
                
                // Try to get hostname from flow
                if let Ok(hostname) = std::panic::catch_unwind(|| {
                    let hostname_ptr = sys::ndpi_get_flow_info_hostname(&flow);
                    if !hostname_ptr.is_null() {
                        Some(CStr::from_ptr(hostname_ptr).to_string_lossy().to_string())
                    } else {
                        None
                    }
                }) {
                    if let Some(hostname_str) = hostname {
                        metadata.insert("hostname".to_string(), hostname_str);
                    }
                }
                
                // Try to get user agent from flow
                if let Ok(user_agent) = std::panic::catch_unwind(|| {
                    let ua_ptr = sys::ndpi_get_flow_info_user_agent(&flow);
                    if !ua_ptr.is_null() {
                        Some(CStr::from_ptr(ua_ptr).to_string_lossy().to_string())
                    } else {
                        None
                    }
                }) {
                    if let Some(ua_str) = user_agent {
                        metadata.insert("user_agent".to_string(), ua_str);
                    }
                }
            }
            
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
            
            // Clean up flow resources
            sys::ndpi_free_flow(&mut flow);
            
            Ok(NDPIProtocolInfo {
                protocol_name: proto_name,
                app_protocol_name,
                confidence,
                category,
                is_encrypted,
                probable_port,
                risk_score,
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
    
    /// Get protocol name for a given ID
    pub fn get_protocol_name(&self, proto_id: u32) -> Option<String> {
        self.protocols.get(&proto_id).cloned()
    }
    
    /// List all supported protocols
    pub fn list_all_protocols(&self) -> Vec<String> {
        self.protocols.values().cloned().collect()
    }
}

impl Clone for NDPIDetector {
    fn clone(&self) -> Self {
        // Create a new instance rather than trying to clone the C objects
        Self::new().unwrap_or_else(|_| panic!("Failed to clone NDPIDetector"))
    }
}

impl Drop for NDPIDetector {
    fn drop(&mut self) {
        // Clean up nDPI resources when the detector is destroyed
        unsafe {
            if !self.detection_module.is_null() {
                sys::ndpi_exit_detection_module(self.detection_module);
                self.detection_module = std::ptr::null_mut();
            }
        }
    }
}

/// Convert nDPI protocol info to service identification format
///
/// # Arguments
/// * `proto_info` - The protocol information from nDPI
///
/// # Returns
/// * `(String, Option<String>)` - Service name and optional version
pub fn ndpi_to_service_info(proto_info: NDPIProtocolInfo) -> (String, Option<String>) {
    // Map nDPI protocol name to service name convention
    let service_name = proto_info.protocol_name.to_lowercase();
    
    // For service version, use app protocol if available or metadata
    let mut service_version = proto_info.app_protocol_name;
    
    // If we have metadata that could give us version info, use that
    if service_version.is_none() && !proto_info.metadata.is_empty() {
        // Try to extract version info from user-agent or other metadata
        if let Some(user_agent) = proto_info.metadata.get("user_agent") {
            // Extract version from user agent if possible
            service_version = Some(user_agent.clone());
        }
    }
    
    (service_name, service_version)
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
    match NDPIDetector::get_instance() {
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
    match NDPIDetector::get_instance() {
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
    match NDPIDetector::get_instance() {
        Ok(detector) => detector.list_all_protocols(),
        Err(_) => vec!["nDPI not available".to_string()],
    }
} 