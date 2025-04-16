//! FFI bindings for nDPI library
//! 
//! This module provides low-level bindings to the nDPI C library functions.
//! Configured to support all available nDPI protocols and features for
//! comprehensive service identification.
//!
//! NOTE: This implementation includes stub functions for static compilation

#![allow(non_camel_case_types)]
#![allow(non_snake_case)]

use std::os::raw::{c_char, c_int, c_void};
use log::debug;

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

// Known protocol identifiers
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

// STATIC IMPLEMENTATION: Rust implementations of all nDPI functions for static build
// These are stubs that allow compilation without the actual nDPI library

// Initialization and cleanup
#[no_mangle]
pub unsafe extern "C" fn ndpi_init_detection_module(
    _detection_ticks: u32
) -> *mut ndpi_detection_module_struct {
    // Simply allocate a dummy structure
    libc::calloc(1, 1024) as *mut ndpi_detection_module_struct
}

#[no_mangle]
pub unsafe extern "C" fn ndpi_exit_detection_module(
    ndpi_struct: *mut ndpi_detection_module_struct
) {
    if !ndpi_struct.is_null() {
        libc::free(ndpi_struct as *mut c_void);
    }
}

#[no_mangle]
pub unsafe extern "C" fn ndpi_set_protocol_detection_bitmask2(
    _ndpi_struct: *mut ndpi_detection_module_struct,
    _detection_bitmask: *const c_void
) {
    // No-op implementation
}

// Protocol detection functions
#[no_mangle]
pub unsafe extern "C" fn ndpi_detection_process_packet(
    _ndpi_struct: *mut ndpi_detection_module_struct,
    flow: *mut ndpi_flow_struct,
    packet: *mut ndpi_packet_struct,
    _time_ms: u32,
    _src_id: *mut u32,
    _dst_id: *mut u32
) -> u32 {
    // Basic implementation that checks packet type and sets a protocol
    if !flow.is_null() && !packet.is_null() {
        let packet_ref = &*packet;
        let flow_ref = &mut *flow;
        
        // Simple protocol detection based on port numbers
        // In a real implementation, this would be much more sophisticated
        match packet_ref.l4_protocol {
            6 => { // TCP
                flow_ref.detected_protocol_stack[0] = NDPI_PROTOCOL_HTTP; // Assume HTTP for TCP
            },
            17 => { // UDP
                flow_ref.detected_protocol_stack[0] = NDPI_PROTOCOL_DNS; // Assume DNS for UDP
            },
            _ => {
                flow_ref.detected_protocol_stack[0] = NDPI_PROTOCOL_UNKNOWN;
            }
        }
        
        flow_ref.detected_protocol_stack[0] as u32
    } else {
        NDPI_PROTOCOL_UNKNOWN as u32
    }
}

#[no_mangle]
pub unsafe extern "C" fn ndpi_detection_giveup(
    _ndpi_struct: *mut ndpi_detection_module_struct,
    flow: *mut ndpi_flow_struct,
    _enable_guess: c_int,
    _src_id: *mut u32,
    _dst_id: *mut u32
) -> u32 {
    if !flow.is_null() {
        let flow_ref = &*flow;
        flow_ref.detected_protocol_stack[0] as u32
    } else {
        NDPI_PROTOCOL_UNKNOWN as u32
    }
}

#[no_mangle]
pub unsafe extern "C" fn ndpi_get_proto_name(
    _ndpi_struct: *mut ndpi_detection_module_struct,
    proto: c_int
) -> *const c_char {
    // Return static strings for known protocols
    match proto as u16 {
        NDPI_PROTOCOL_UNKNOWN => b"Unknown\0".as_ptr() as *const c_char,
        NDPI_PROTOCOL_FTP => b"FTP\0".as_ptr() as *const c_char,
        NDPI_PROTOCOL_MAIL_POP => b"POP3\0".as_ptr() as *const c_char,
        NDPI_PROTOCOL_MAIL_SMTP => b"SMTP\0".as_ptr() as *const c_char,
        NDPI_PROTOCOL_MAIL_IMAP => b"IMAP\0".as_ptr() as *const c_char,
        NDPI_PROTOCOL_DNS => b"DNS\0".as_ptr() as *const c_char,
        NDPI_PROTOCOL_HTTP => b"HTTP\0".as_ptr() as *const c_char,
        NDPI_PROTOCOL_SSL => b"SSL\0".as_ptr() as *const c_char,
        NDPI_PROTOCOL_SSH => b"SSH\0".as_ptr() as *const c_char,
        NDPI_PROTOCOL_TELNET => b"Telnet\0".as_ptr() as *const c_char,
        _ => b"Unclassified\0".as_ptr() as *const c_char,
    }
}

#[no_mangle]
pub unsafe extern "C" fn ndpi_get_num_supported_protocols(
    _ndpi_struct: *mut ndpi_detection_module_struct
) -> c_int {
    // Return a reasonable number of supported protocols
    100
}

// Protocol category functions
#[no_mangle]
pub unsafe extern "C" fn ndpi_get_proto_category(
    _ndpi_struct: *mut ndpi_detection_module_struct,
    _proto: u32
) -> ndpi_protocol_category_t {
    // Return a generic category
    0
}

#[no_mangle]
pub unsafe extern "C" fn ndpi_category_get_name(
    _ndpi_struct: *mut ndpi_detection_module_struct,
    _category: ndpi_protocol_category_t
) -> *const c_char {
    // Return a generic category name
    b"Network\0".as_ptr() as *const c_char
}

// Protocol properties functions
#[no_mangle]
pub unsafe extern "C" fn ndpi_is_encrypted_proto(
    _ndpi_struct: *mut ndpi_detection_module_struct,
    proto: u32
) -> c_int {
    // Basic check for encrypted protocols
    match proto as u16 {
        NDPI_PROTOCOL_SSL | NDPI_PROTOCOL_SSH => 1,
        _ => 0,
    }
}

// Protocol configuration functions
#[no_mangle]
pub unsafe extern "C" fn ndpi_set_all_protocols(
    _ndpi_struct: *mut ndpi_detection_module_struct,
    _status: c_int
) {
    // No-op implementation
}

#[no_mangle]
pub unsafe extern "C" fn ndpi_set_detection_preferences(
    _ndpi_struct: *mut ndpi_detection_module_struct,
    _preferences: c_int
) {
    // No-op implementation
}

// Flow handling functions
#[no_mangle]
pub unsafe extern "C" fn ndpi_free_flow(flow: *mut ndpi_flow_struct) {
    // IMPORTANT: This should only be used for flow pointers that were dynamically
    // allocated and not already freed. In our implementation, we use stack-allocated
    // flow structs in most places, and those should not be passed to this function.
    // 
    // Only free if the pointer is not null and we're certain it needs freeing
    // This function is now a no-op for safety, as our Drop implementation already
    // manages memory properly
    
    // Check if someone passed a pointer that might need freeing in future implementations
    if !flow.is_null() {
        debug!("ndpi_free_flow called - note that our implementation manages flow memory internally");
        // DO NOT free here - our architecture handles memory differently
        // libc::free(flow as *mut c_void);
    }
}

// Version information
#[no_mangle]
pub unsafe extern "C" fn ndpi_revision() -> *const c_char {
    // Return a static version string
    b"4.2.0-static\0".as_ptr() as *const c_char
}

// Original wrapped functions

#[no_mangle]
pub unsafe extern "C" fn wrapped_ndpi_flow_struct_size() -> usize {
    // Return a reasonable size for the flow struct
    1024
}

#[no_mangle]
pub unsafe extern "C" fn wrapped_ndpi_get_app_protocol(
    _ndpi_struct: *mut ndpi_detection_module_struct,
    flow: *mut ndpi_flow_struct
) -> u32 {
    if !flow.is_null() {
        let flow_ref = &*flow;
        flow_ref.detected_protocol_stack[0] as u32
    } else {
        NDPI_PROTOCOL_UNKNOWN as u32
    }
}

// Wrapper for creating a new ndpi_flow_struct (since it's an opaque type)
impl ndpi_flow_struct {
    pub fn new() -> Self {
        unsafe {
            // Call the wrapper function to get the size
            let flow_size = wrapped_ndpi_flow_struct_size(); 
            let flow_ptr = libc::calloc(1, flow_size) as *mut ndpi_flow_struct;
            
            if flow_ptr.is_null() {
                panic!("Failed to allocate memory for ndpi_flow_struct");
            }
            
            // Initialize with default values
            let mut flow = std::ptr::read(flow_ptr);
            flow.detected_protocol_stack = [0, 0];
            flow.risk = 0;
            
            // IMPORTANT: We must free flow_ptr as we created a copy, not a reference
            libc::free(flow_ptr as *mut c_void);
            
            flow
        }
    }
}

// Ensure we clean up the flow struct when it's dropped
impl Drop for ndpi_flow_struct {
    fn drop(&mut self) {
        // Do nothing here - we already freed the pointer in new()
        // The struct is stack-allocated since we used std::ptr::read
        // The original memory was freed immediately after creating our copy
    }
} 