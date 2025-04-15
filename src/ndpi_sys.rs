//! FFI bindings for nDPI library
//! 
//! This module provides low-level bindings to the nDPI C library functions.
//! Configured to support all available nDPI protocols and features for
//! comprehensive service identification.

#![allow(non_camel_case_types)]
#![allow(non_snake_case)]

use std::os::raw::{c_char, c_int, c_uint, c_void, c_ushort, c_uchar};

// Basic type definitions for nDPI FFI
pub type ndpi_protocol_category_t = u32;
pub type ndpi_protocol_id_t = u16;
pub type ndpi_risk_enum = u64;

// nDPI detection module and flow structs
pub enum ndpi_detection_module_struct {}

#[repr(C)]
pub struct ndpi_flow_struct {
    // We only need a few fields here, others are opaque to us
    pub detected_protocol_stack: [u16; 2],
    pub risk: ndpi_risk_enum,
    pub host_server_name: [c_char; 256], // Buffer for hostname
    // Rest of fields omitted - we access via explicit functions
}

// Packet structure used by nDPI for analysis
#[repr(C)]
pub struct ndpi_packet_struct {
    pub iph: *const c_void,           // IPv4 header
    pub iphv6: *const c_void,         // IPv6 header
    pub tcp: *const c_void,           // TCP header
    pub udp: *const c_void,           // UDP header
    pub payload: *const u8,           // Packet payload
    pub payload_packet_len: u16,      // Payload length
    pub l4_packet_len: u16,           // Layer 4 packet length
    pub l3_packet_len: u16,           // Layer 3 packet length
    pub l4_protocol: u8,              // Layer 4 protocol (TCP=6, UDP=17)
    pub packet_direction: u8,         // Packet direction (0=outgoing, 1=incoming)
    pub packet_lines_parsed_complete: u8, // Whether packet lines were completely parsed
    pub packet_lines_parsed: u16,     // Number of packet lines parsed
    pub empty_line_position: u16,     // Position of empty line
    pub host_line_len: u16,           // Host line length
    pub http_url_name_len: u16,       // HTTP URL name length
    pub content_line_len: u16,        // Content line length
    pub content_len: c_int,           // Content length
    pub current_line_len: u16,        // Current line length
    pub current_line_ptr: *const c_char, // Current line pointer
    pub host_line_ptr: *const c_char, // Host line pointer
    pub referer_line_ptr: *const c_char, // Referer line pointer
    pub content_line_ptr: *const c_char, // Content line pointer
    pub accept_line_ptr: *const c_char, // Accept line pointer
    pub authorization_line_ptr: *const c_char, // Authorization line pointer
    pub user_agent_line_ptr: *const c_char, // User agent line pointer
    pub http_url_name_ptr: *const c_char, // HTTP URL name pointer
    pub http_method_ptr: *const c_char, // HTTP method pointer
    pub http_version_ptr: *const c_char, // HTTP version pointer
    pub server_line_ptr: *const c_char, // Server line pointer
    pub http_origin_ptr: *const c_char, // HTTP origin pointer
    pub boundary_ptr: *const c_char,  // Boundary pointer
    pub content_type_ptr: *const c_char, // Content type pointer
    pub content_encoding_ptr: *const c_char, // Content encoding pointer
    pub cookie_ptr: *const c_char,    // Cookie pointer
    pub content_type_line_len: u16,   // Content type line length
    pub media_type_ptr: *const c_char, // Media type pointer
    pub packet_time_ms: u32,          // Packet timestamp in ms
    pub current_time_ms: u32,         // Current time in ms
}

impl Default for ndpi_packet_struct {
    fn default() -> Self {
        unsafe { std::mem::zeroed() }
    }
}

// nDPI preference values
#[repr(C)]
pub enum ndpi_detection_preference_values {
    ndpi_no_prefs = 0,
    ndpi_dont_load_tor_entries,
    ndpi_dont_init_libgcrypt,
    ndpi_enable_ja3_plus,
    ndpi_deep_protocol_inspection,
}

// Known protocol identifiers - we define a subset here for direct use
// The full list is dynamically obtained from the nDPI library
pub const NDPI_PROTOCOL_UNKNOWN: u16 = 0;
pub const NDPI_PROTOCOL_FTP: u16 = 1;
pub const NDPI_PROTOCOL_MAIL_POP: u16 = 2;
pub const NDPI_PROTOCOL_MAIL_SMTP: u16 = 3;
pub const NDPI_PROTOCOL_MAIL_IMAP: u16 = 4;
pub const NDPI_PROTOCOL_DNS: u16 = 5;
pub const NDPI_PROTOCOL_HTTP: u16 = 7;
pub const NDPI_PROTOCOL_SSL: u16 = 91;
pub const NDPI_PROTOCOL_SSH: u16 = 92;
pub const NDPI_PROTOCOL_TELNET: u16 = 93;
pub const NDPI_PROTOCOL_TLS: u16 = 91; // Same as SSL in nDPI

// External FFI functions from nDPI
extern "C" {
    // Initialization and cleanup
    pub fn ndpi_init_detection_module(
        detection_ticks: u32
    ) -> *mut ndpi_detection_module_struct;
    
    pub fn ndpi_exit_detection_module(
        ndpi_struct: *mut ndpi_detection_module_struct
    );
    
    pub fn ndpi_set_protocol_detection_bitmask2(
        ndpi_struct: *mut ndpi_detection_module_struct,
        detection_bitmask: *const c_void
    );
    
    // Protocol detection functions
    pub fn ndpi_detection_process_packet(
        ndpi_struct: *mut ndpi_detection_module_struct,
        flow: *mut ndpi_flow_struct,
        packet: *mut ndpi_packet_struct,
        time_ms: u32,
        src_id: *mut u32,
        dst_id: *mut u32
    ) -> u32;
    
    pub fn ndpi_detection_giveup(
        ndpi_struct: *mut ndpi_detection_module_struct,
        flow: *mut ndpi_flow_struct,
        enable_guess: c_int,
        src_id: *mut u32,
        dst_id: *mut u32
    ) -> u32;
    
    pub fn ndpi_get_proto_name(
        ndpi_struct: *mut ndpi_detection_module_struct,
        proto: c_int
    ) -> *const c_char;
    
    pub fn ndpi_get_num_supported_protocols(
        ndpi_struct: *mut ndpi_detection_module_struct
    ) -> c_int;
    
    // Protocol category functions
    pub fn ndpi_get_proto_category(
        ndpi_struct: *mut ndpi_detection_module_struct,
        proto: u32
    ) -> ndpi_protocol_category_t;
    
    pub fn ndpi_category_get_name(
        ndpi_struct: *mut ndpi_detection_module_struct,
        category: ndpi_protocol_category_t
    ) -> *const c_char;
    
    // Protocol properties functions
    pub fn ndpi_is_encrypted_proto(
        ndpi_struct: *mut ndpi_detection_module_struct,
        proto: u32
    ) -> c_int;
    
    pub fn ndpi_get_app_protocol(
        ndpi_struct: *mut ndpi_detection_module_struct,
        flow: *mut ndpi_flow_struct
    ) -> u32;
    
    // Protocol configuration functions
    pub fn ndpi_set_all_protocols(
        ndpi_struct: *mut ndpi_detection_module_struct,
        status: c_int
    );
    
    pub fn ndpi_set_detection_preferences(
        ndpi_struct: *mut ndpi_detection_module_struct,
        preferences: c_int
    );

    // Flow handling functions
    pub fn ndpi_flow_struct_size() -> c_int;
    
    pub fn ndpi_free_flow(flow: *mut ndpi_flow_struct);
    
    // Version information
    pub fn ndpi_revision() -> *const c_char;
    
    // Risk assessment functions
    pub fn ndpi_risk_get_score(
        ndpi_struct: *mut ndpi_detection_module_struct,
        risk: ndpi_risk_enum
    ) -> u32;
    
    pub fn ndpi_risk_enum_to_str(
        risk: ndpi_risk_enum
    ) -> *const c_char;
    
    // Flow metadata extraction
    pub fn ndpi_get_flow_info_hostname(
        flow: *const ndpi_flow_struct
    ) -> *const c_char;
    
    pub fn ndpi_get_flow_info_user_agent(
        flow: *const ndpi_flow_struct
    ) -> *const c_char;
    
    // Extended protocol information
    pub fn ndpi_get_proto_breed(
        ndpi_struct: *mut ndpi_detection_module_struct,
        proto: u32
    ) -> c_int;
    
    pub fn ndpi_get_proto_breed_name(
        ndpi_struct: *mut ndpi_detection_module_struct,
        breed: c_int
    ) -> *const c_char;
    
    // Custom protocol matching functions
    pub fn ndpi_add_string_to_automa(
        ndpi_struct: *mut ndpi_detection_module_struct,
        automa_type: c_int,
        string_to_match: *const c_char
    ) -> c_int;
    
    pub fn ndpi_finalize_automa(
        ndpi_struct: *mut ndpi_detection_module_struct,
        automa_type: c_int
    ) -> c_int;
    
    // Additional metadata functions
    pub fn ndpi_serialize_string_boolean(
        serializer: *mut c_void,
        key: *const c_char,
        value: c_int
    ) -> c_int;
    
    pub fn ndpi_serialize_string_uint32(
        serializer: *mut c_void,
        key: *const c_char,
        value: u32
    ) -> c_int;
    
    pub fn ndpi_risk_suspicious_entropy(flow: *const ndpi_flow_struct) -> c_int;
    
    pub fn ndpi_enable_loaded_file_detection(
        ndpi_struct: *mut ndpi_detection_module_struct,
        enable: c_int
    );
    
    pub fn ndpi_enable_ja3_plus(
        ndpi_struct: *mut ndpi_detection_module_struct,
        enable: c_int
    );
}

// Wrapper for creating a new ndpi_flow_struct (since it's an opaque type)
impl ndpi_flow_struct {
    pub fn new() -> Self {
        unsafe {
            let flow_size = ndpi_flow_struct_size() as usize;
            let flow_ptr = libc::calloc(1, flow_size) as *mut ndpi_flow_struct;
            
            if flow_ptr.is_null() {
                panic!("Failed to allocate memory for ndpi_flow_struct");
            }
            
            std::ptr::read(flow_ptr)
        }
    }
}

// Ensure we clean up the flow struct when it's dropped
impl Drop for ndpi_flow_struct {
    fn drop(&mut self) {
        unsafe {
            let ptr = self as *mut ndpi_flow_struct;
            libc::free(ptr as *mut c_void);
        }
    }
} 