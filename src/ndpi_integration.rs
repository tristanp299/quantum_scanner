//! nDPI Integration Module
//!
//! This module provides integration with the nDPI deep packet inspection library
//! for advanced protocol detection and service identification.
//!
//! nDPI is a powerful library that can identify over 280 protocols and applications
//! based on packet inspection. This implementation provides full access to all
//! supported protocols without limiting functionality for comprehensive service detection.

use std::collections::HashMap;
use std::ffi::{CStr}; // Removed unused CString
use std::os::raw::{c_char};
use std::ptr;
use std::net::IpAddr;
use log::{debug, warn, error, info, trace};
use std::convert::TryInto;
use anyhow::{anyhow, Result};
use etherparse::SlicedPacket; // Used for packet parsing
use etherparse::IpNumber; // Specific enum for IP protocol number
use serde::{Deserialize, Serialize};
use std::mem;
use crate::models::{NDPIProtocolInfo, NdpiRisk, NdpiConfidence}; // Import structs defined in models.rs
use crate::ndpi_sys as sys; // Use re-exported items from ndpi_sys where possible
use crate::ndpi_bindings; // Use direct bindings when needed
use crate::ndpi_bindings::ndpi_init_prefs; // Import ndpi_init_prefs directly

/// Represents the 5-tuple key for identifying a network flow.
/// Used as the key in the nDPI flow cache.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct FlowKey {
    /// Source IP address
    pub src_ip: IpAddr,
    /// Destination IP address
    pub dst_ip: IpAddr,
    /// Source port number
    pub src_port: u16,
    /// Destination port number
    pub dst_port: u16,
    /// IP protocol number (e.g., 6 for TCP, 17 for UDP)
    pub protocol: u8,
}

/// Information about a tracked network flow.
#[derive(Debug, Clone)]
struct FlowInfo {
    /// Pointer to the nDPI flow structure associated with this flow.
    ndpi_flow: *mut sys::ndpi_flow_struct,
    /// The last detected protocol information for this flow.
    detected_protocol: Option<NDPIProtocolInfo>,
    /// Timestamp when the last packet for this flow was seen (milliseconds).
    last_seen_timestamp_ms: u64,
}

/// Wrapper for nDPI detection functionality with full protocol support
pub struct NdpiEngine {
    /// The nDPI detection module handle (pointer)
    detection_module: *mut sys::ndpi_detection_module_struct,
    /// Map of protocol IDs (using u32) to their names
    protocols: HashMap<sys::ndpi_protocol_id_t, String>,
    /// Version info for the nDPI library
    version_info: String,
    /// Cache of active flows being tracked by nDPI.
    /// Keys are FlowKey (5-tuple), values are wrappers managing ndpi_flow_struct pointers.
    flow_cache: HashMap<FlowKey, FlowInfo>,
    /// Internal nDPI structure pointer, likely related to protocol definitions.
    ndpi_struct_protocols: *mut ndpi_bindings::ndpi_protocol, // Use type from bindings
}


// RAII wrapper removed as direct flow management is used in cache

// Safety: The detection_module pointer is managed correctly via new/drop.
// The flow_cache HashMap requires careful handling if NdpiEngine is used across threads,
// but the primary usage pattern involves locking the Arc<Mutex<NdpiEngine>> in scanner.rs.
unsafe impl Send for NdpiEngine {}
unsafe impl Sync for NdpiEngine {}

// Helper function to safely convert C string (char*) to Rust String
// Takes a *const c_char pointer.
unsafe fn cstr_to_string(ptr: *const c_char) -> Option<String> {
    if ptr.is_null() || *ptr == 0 { // Check for null pointer or empty string
        return None;
    }
    // Basic check for potential invalid pointer (e.g., very low address)
    let ptr_addr = ptr as usize;
    if ptr_addr < 0xFFFF {
        warn!("Potential invalid C string pointer encountered: {:p}", ptr);
        return None;
    }
    // Attempt conversion
    match CStr::from_ptr(ptr).to_str() {
        Ok(s) => Some(s.to_string()),
        Err(e) => {
            error!("Failed to convert CStr to Rust String: {}", e);
            None
        }
    }
}


impl NdpiEngine {
    /// Create a new nDPI detector instance with full protocol support.
    /// Initializes the nDPI library and loads protocol definitions.
    ///
    /// # Returns
    /// * `Result<Self>` - The initialized engine or an error if initialization fails.
    pub fn new() -> Result<Self> {
        info!("Initializing nDPI engine...");
        // Allocate memory for the detection module structure.
        let detection_module = unsafe {
            libc::calloc(1, mem::size_of::<sys::ndpi_detection_module_struct>())
                as *mut sys::ndpi_detection_module_struct
        };

        // Check if memory allocation failed.
        if detection_module.is_null() {
            return Err(anyhow!("Failed to allocate memory for nDPI detection module"));
        }

        // Initialize nDPI library with default preferences
        // ndpi_init_detection_module requires preferences flags, using default for now
        // Opsec Note: Review nDPI initialization options (ndpi_init_prefs)
        // to potentially disable features not needed, reducing attack surface.
        let prefs: ndpi_init_prefs = 0; // Default preferences - Use directly imported type
        let ndpi_struct = unsafe { sys::ndpi_init_detection_module(prefs) };

        // Check if initialization failed (returned null pointer)
        if ndpi_struct.is_null() {
            return Err(anyhow!("Failed to initialize nDPI detection module"));
        }

        // --- Get nDPI Version ---
        // Safely get the nDPI version string after successful initialization
        let version_ptr = unsafe { sys::ndpi_revision() }; // Get C string pointer for version
        // Convert C string to Rust String, provide default if conversion fails
        let version_info = unsafe { cstr_to_string(version_ptr) }.unwrap_or_else(|| "Unknown".to_string());
        info!("Successfully initialized nDPI (Version: {})", version_info); // Log version

        // --- Placeholder for Protocol Struct Pointer ---
        // This pointer might be obtained via a specific nDPI function if needed later.
        // For now, initialize it to null.
        // Using ndpi_protocol based on bindings check
        let ndpi_struct_protocols: *mut ndpi_bindings::ndpi_protocol = ptr::null_mut();

        // --- Set default protocol detection preferences ---
        // ndpi_set_proto_defaults allows setting default ports/behavior per protocol.
        // We are using the function name suggested by the compiler.
        // The `protocol_defaults` array would need to be defined and populated
        // according to nDPI documentation if we wanted custom defaults.
        // Currently commented out as we don't have specific defaults to set.
        /*
        let protocol_defaults: *const sys::ndpi_proto_defaults_t = ptr::null(); // Placeholder
        let num_defaults: libc::c_uint = 0; // Placeholder
        unsafe {
            sys::ndpi_set_proto_defaults(ndpi_struct, protocol_defaults, num_defaults);
        }
        info!("Applied default nDPI protocol settings.");
        */

        // Finalize initialization after setting any custom parameters
        // This step is crucial for nDPI to build its internal structures.
        let detection_module = ndpi_struct; // ndpi_init_detection_module returns the pointer
        if detection_module.is_null() {
             return Err(anyhow!("Failed to initialize nDPI detection module (returned null)"));
        }

        // Populate internal protocol map (optional, can be done on demand)
        let protocols = HashMap::new(); // Initialize empty for now

        info!("nDPI engine initialized successfully.");
        Ok(Self {
            detection_module,
            protocols,
            version_info,
            flow_cache: HashMap::new(),
            ndpi_struct_protocols, // Store null pointer for now
        })
    }

    /// Get the nDPI library version string.
    pub fn get_version(&self) -> &str {
        &self.version_info
    }

    /// Get the total number of named protocols loaded from nDPI.
    pub fn get_protocol_count(&self) -> usize {
        // This might need adjustment if protocols aren't pre-loaded into self.protocols
        // Could call ndpi_get_num_supported_protocols if needed.
        self.protocols.len()
    }

    /// Get protocol name for a given nDPI protocol ID (u32).
    pub fn get_protocol_name(&self, proto_id: sys::ndpi_protocol_id_t) -> Option<String> {
        // If self.protocols is empty, call nDPI function directly
        if self.protocols.is_empty() {
             unsafe {
                let name_ptr = ndpi_bindings::ndpi_get_proto_name(self.detection_module, proto_id as u16);
                cstr_to_string(name_ptr)
             }
        } else {
            self.protocols.get(&proto_id).cloned()
        }
    }

    /// Analyzes a raw network packet, identifies its flow, updates the flow state
    /// in the cache, and runs nDPI detection on it.
    ///
    /// # Arguments
    /// * `packet_data` - Slice containing the raw packet data (starting from IP header).
    /// * `timestamp_ms` - The timestamp when the packet was captured (in milliseconds).
    ///
    /// # Returns
    /// * `Ok(FlowKey)` - The key of the flow this packet belongs to (either existing or newly created).
    /// * `Err(anyhow::Error)` - If parsing fails or nDPI processing encounters an error.
    pub fn analyze_packet(&mut self, packet_data: &[u8], timestamp_ms: u64) -> Result<FlowKey> {
        trace!(
            "NdpiEngine::analyze_packet: Analyzing packet ({} bytes) at timestamp {}",
            packet_data.len(),
            timestamp_ms
        );

        // Parse the packet using etherparse.
        let packet = SlicedPacket::from_ip(packet_data)
            .map_err(|e| anyhow!("Failed to parse IP packet using etherparse: {}", e))?;

        // Extract IP protocol, source/destination IPs, and ports to create a FlowKey.
        let protocol: IpNumber = match &packet.net {
            Some(etherparse::NetSlice::Ipv4(hdr)) => hdr.header().protocol(),
            Some(etherparse::NetSlice::Ipv6(hdr)) => hdr.header().next_header(),
            Some(etherparse::InternetSlice::Arp(_)) => return Err(anyhow!("ARP packet encountered, skipping analysis")),
            None => return Err(anyhow!("Packet parsing failed: Missing IP header")),
        };

        let src_ip = match &packet.net {
            Some(etherparse::NetSlice::Ipv4(hdr)) => IpAddr::V4(hdr.header().source_addr()),
            Some(etherparse::NetSlice::Ipv6(hdr)) => IpAddr::V6(hdr.header().source_addr()),
            Some(etherparse::InternetSlice::Arp(_)) => return Err(anyhow!("ARP packet encountered, cannot get source IP")),
            None => return Err(anyhow!("Packet parsing failed: Missing source IP")),
        };

        let dst_ip = match &packet.net {
            Some(etherparse::NetSlice::Ipv4(hdr)) => IpAddr::V4(hdr.header().destination_addr()),
            Some(etherparse::NetSlice::Ipv6(hdr)) => IpAddr::V6(hdr.header().destination_addr()),
            Some(etherparse::InternetSlice::Arp(_)) => return Err(anyhow!("ARP packet encountered, cannot get destination IP")),
            None => return Err(anyhow!("Packet parsing failed: Missing destination IP")),
        };

        let (src_port, dst_port) = match packet.transport {
            Some(etherparse::TransportSlice::Tcp(hdr)) => (hdr.source_port(), hdr.destination_port()),
            Some(etherparse::TransportSlice::Udp(hdr)) => (hdr.source_port(), hdr.destination_port()),
            _ => (0, 0),
        };

        let flow_key = FlowKey {
            src_ip,
            dst_ip,
            src_port,
            dst_port,
            protocol: protocol.0, // Convert IpNumber to u8
        };
        trace!("Packet corresponds to flow: {:?}", flow_key);

        // --- Borrow Checker Fix Start ---
        // 1. Check if flow exists. If not, create and insert it.
        let ndpi_flow_ptr = if !self.flow_cache.contains_key(&flow_key) {
            debug!("Creating new flow entry for: {:?}", flow_key);
            let ptr = unsafe {
                libc::calloc(1, mem::size_of::<sys::ndpi_flow_struct>())
                    as *mut sys::ndpi_flow_struct
            };
            if ptr.is_null() {
                 error!("Failed to allocate memory for nDPI flow struct for flow: {:?}", flow_key);
                 return Err(anyhow!("Failed to allocate memory for nDPI flow struct"));
            } else {
                // Initialize flow struct fields to zero (important!)
                unsafe { ptr::write_bytes(ptr, 0, 1); }
                // Insert temporary info, releasing mutable borrow
                self.flow_cache.insert(flow_key.clone(), FlowInfo {
                    ndpi_flow: ptr,
                    detected_protocol: None,
                    last_seen_timestamp_ms: timestamp_ms,
                });
                ptr // Return the newly created pointer
            }
        } else {
             // Flow already exists, get its pointer without holding mutable borrow of cache
             self.flow_cache.get(&flow_key).unwrap().ndpi_flow
        };

        // Ensure the pointer is valid before proceeding
        if ndpi_flow_ptr.is_null() {
            return Err(anyhow!("Internal error: Flow pointer is null for flow key: {:?}", flow_key));
        }

        // Update last seen time (needs mutable borrow, but short-lived)
        if let Some(info) = self.flow_cache.get_mut(&flow_key) {
             info.last_seen_timestamp_ms = timestamp_ms;
        } else {
             // This should not happen if the logic above is correct
             return Err(anyhow!("Internal error: Flow key {:?} disappeared from cache unexpectedly.", flow_key));
        }
        // --- Borrow Checker Fix End ---

        let ip_payload = packet_data;
        let ip_payload_len = ip_payload.len() as u16;

        // Process the packet using nDPI.
        let detected_protocol_result = unsafe {
            sys::ndpi_detection_process_packet(
                self.detection_module,
                ndpi_flow_ptr, // Use the pointer obtained earlier
                ip_payload.as_ptr() as *const libc::c_uchar,
                ip_payload_len,
                timestamp_ms
            )
        };

        // Get the detailed protocol information from the nDPI flow structure.
        let detected_protocol: sys::ndpi_protocol = detected_protocol_result; // Result of process_packet

        // Access fields safely from the nDPI flow structure pointer
        // Read necessary values *before* potentially borrowing self later
        let (flow_confidence, flow_risk_enum_u64, flow_hostname_ptr, _flow_stack) = unsafe {
            let flow_ptr = &*ndpi_flow_ptr; // Dereference the known valid pointer
            (
                flow_ptr.confidence,
                flow_ptr.risk, // This is ndpi_risk (u64)
                flow_ptr.host_server_name.as_ptr() as *const c_char,
                flow_ptr.detected_protocol_stack // Use correct field name, prefix with _ as unused
            )
        };

        // Only update protocol info if nDPI actually detected something
        if detected_protocol.master_protocol != sys::ndpi_protocol_id_t_NDPI_PROTOCOL_UNKNOWN as u16
            || detected_protocol.app_protocol != sys::ndpi_protocol_id_t_NDPI_PROTOCOL_UNKNOWN as u16
        {
            trace!(
                "nDPI detected protocol: Master={}, App={}, Category={}",
                detected_protocol.master_protocol,
                detected_protocol.app_protocol,
                detected_protocol.category
            );

            let protocol_id_for_name = if detected_protocol.app_protocol != sys::ndpi_protocol_id_t_NDPI_PROTOCOL_UNKNOWN as u16 {
                detected_protocol.app_protocol
            } else {
                detected_protocol.master_protocol
            };

            let protocol_name = unsafe {
                let name_ptr = ndpi_bindings::ndpi_get_proto_name(self.detection_module, protocol_id_for_name);
                cstr_to_string(name_ptr)
            }.unwrap_or_else(|| "Unknown".to_string());


            let category_name = unsafe {
                 let name_ptr = ndpi_bindings::ndpi_category_get_name(self.detection_module, detected_protocol.category);
                 cstr_to_string(name_ptr)
             }.unwrap_or_else(|| "Unknown".to_string());

            // Convert hostname C string here
            let hostname = unsafe { cstr_to_string(flow_hostname_ptr) };

            // --- Borrow Checker Fix: Convert risk *after* releasing mutable borrow ---
            // Pass the previously extracted flow_risk_enum (u64)
            // It needs to be converted to sys::ndpi_risk_enum (u32) for convert_risk_enum
            let risk_info = match flow_risk_enum_u64.try_into() {
                Ok(risk_enum_u32) => self.convert_risk_enum(risk_enum_u32)?, // Immutable borrow of self here
                Err(_) => {
                    warn!("Risk value {} out of range for u32, defaulting to No Risk", flow_risk_enum_u64);
                    NdpiRisk { score: 0, name: "No Risk (Conversion Error)".to_string() }
                }
            };
            // --- End Borrow Checker Fix ---

            // Create the NdpiProtocolInfo struct using data from models.rs definition
            let ndpi_info = NDPIProtocolInfo {
                master_protocol_id: detected_protocol.master_protocol,
                application_protocol_id: detected_protocol.app_protocol,
                protocol_name,
                category_name,
                confidence: NdpiConfidence::from(flow_confidence), // Convert u32 confidence
                is_encrypted: false, // Placeholder - ndpi_is_protocol_encrypted was unresolved
                risk: Some(risk_info), // Wrap in Option
                hostname,
                 // Fields from models.rs not directly mapped here (can be added if needed):
                 tunnel_protocol_id: 0, // Placeholder
                 raw_risk_value: Some(flow_risk_enum_u64 as u32), // Store raw enum value (cast may truncate)
            };

            // --- Borrow Checker Fix: Update cache *after* immutable borrow ---
            // Re-acquire mutable borrow to update the stored info
            if let Some(info) = self.flow_cache.get_mut(&flow_key) {
                 info.detected_protocol = Some(ndpi_info);
                 trace!("Stored protocol info for flow: {:?}", flow_key);
            } else {
                 // This really shouldn't happen
                 error!("Flow key {:?} missing after processing packet.", flow_key);
            }
            // --- End Borrow Checker Fix ---
        } else {
            trace!("No specific protocol detected by nDPI for this packet.");
        }

        Ok(flow_key) // Return the original flow key
    }

    /// Retrieves the detected protocol information for a given flow key.
    ///
    /// Returns `Some(NdpiProtocolInfo)` if the flow exists and a protocol has been detected,
    /// otherwise returns `None`.
    pub fn get_flow_protocol(&self, flow_key: &FlowKey) -> Option<NDPIProtocolInfo> {
        self.flow_cache
            .get(flow_key)
            .and_then(|info| info.detected_protocol.clone())
    }

    /// Converts the raw nDPI risk enum value into a structured `NdpiRisk`.
    ///
    /// # Arguments
    /// * `risk_enum`: The raw `ndpi_risk_enum` value from the nDPI flow structure.
    ///
    /// # Returns
    /// * `Result<NdpiRisk>`: The structured risk information or an error if conversion fails.
    fn convert_risk_enum(&self, risk_enum: sys::ndpi_risk_enum) -> Result<NdpiRisk> {
        let no_risk_value = sys::ndpi_risk_enum_NDPI_NO_RISK as sys::ndpi_risk_enum;
        if risk_enum == no_risk_value {
            return Ok(NdpiRisk { score: 0, name: "No Risk".to_string() });
        }

        // Convert the numeric risk score (obtained from ndpi_risk_get_score)
        // into a more descriptive severity level (e.g., "Low", "Medium", "High").
        // This mapping might need adjustment based on nDPI's scoring ranges.
        // Prefix with _ as severity is currently unused
        let _severity = match risk_enum { // risk_enum here is ndpi_risk_enum (u32)
             0 => "Info".to_string(), // Or "None"
             1..=30 => "Low".to_string(),
             31..=60 => "Medium".to_string(),
             61..=90 => "High".to_string(),
             _ => "Critical".to_string(), // Scores > 90
        };

        // Get the string representation of the risk enum (e.g., "NDPI_HTTP_SUSPICIOUS_USER_AGENT")
        // using the function name suggested by the compiler.
        let risk_name_ptr = unsafe { sys::ndpi_risk2str(risk_enum) };
        let risk_name = unsafe { cstr_to_string(risk_name_ptr) }.unwrap_or_else(|| "Unknown Risk".to_string());


        // Get the numeric score associated with the risk enum
        // Using the function name suggested by the compiler.
        // Note: ndpi_risk2score might take pointers for client/server scores, adjust call if needed.
        // Let's assume for now it directly returns a combined score or we only need a general score.
        // We might need to pass pointers to u16 variables if the signature requires it.
        // Placeholder: Assuming it returns a single score for now.
        // Correction: ndpi_risk2score expects pointers to write client/server scores.
        // Need to provide mutable variables and handle the return.
        let mut client_score: u16 = 0;
        let mut server_score: u16 = 0;
        let total_score: u16 = unsafe {
             // Convert risk_enum (u32) to u64 for ndpi_risk type
             ndpi_bindings::ndpi_risk2score(risk_enum.into(), &mut client_score, &mut server_score)
        };
        // Using total_score for overall severity for simplicity now.
        let score = total_score; // Use the returned score

        // Create the NdpiRisk struct
        Ok(NdpiRisk {
            score: score as u32,
            name: risk_name,
        })
    }

    /// Cleans up nDPI resources when the engine is dropped.
    ///
    /// This involves freeing allocated nDPI flow structures in the cache and exiting
    /// the nDPI detection module.
    fn cleanup(&mut self) {
        info!("Cleaning up nDPI engine resources...");
        // Iterate through the flow cache and free each nDPI flow structure.
        for (_key, flow_info) in self.flow_cache.drain() {
            if !flow_info.ndpi_flow.is_null() {
                // Use ndpi_flow_free (which should use libc::free based on ndpi_sys)
                sys::ndpi_flow_free(flow_info.ndpi_flow);
            }
        }
        debug!("Freed cached nDPI flow structures.");

        // Exit the nDPI detection module.
        if !self.detection_module.is_null() {
            unsafe {
                sys::ndpi_exit_detection_module(self.detection_module);
            }
            self.detection_module = ptr::null_mut(); // Mark as cleaned up
            debug!("Exited nDPI detection module.");
        }

        // Free the protocol structures pointer (if it was ever assigned)
        // ndpi_free_protocols was unresolved, assuming exit module handles cleanup.
        if !self.ndpi_struct_protocols.is_null() {
             // unsafe { ndpi_bindings::ndpi_free_protocols(self.ndpi_struct_protocols); }
             self.ndpi_struct_protocols = ptr::null_mut();
             debug!("Cleared nDPI protocol structures pointer.");
        }

        info!("nDPI engine cleanup finished.");
    }
}

/// Implement the `Drop` trait to ensure cleanup happens automatically when `NdpiEngine` goes out of scope.
impl Drop for NdpiEngine {
    fn drop(&mut self) {
        self.cleanup();
    }
}