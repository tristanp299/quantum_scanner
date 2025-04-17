//! Low-level FFI bindings and related functions for interacting with the nDPI library.
//! This module aims to provide a safe abstraction over the raw C API where possible,
//! but primarily re-exports necessary types and functions from the generated `ndpi_bindings.rs`.

// Re-export key types and functions from the raw bindings for easier use.
// Use `pub use` to make them accessible from other modules using `crate::ndpi_sys::`. 
pub use crate::ndpi_bindings::{ // Using pub use to re-export
    // Core Structures
    ndpi_detection_module_struct,
    ndpi_flow_struct,
    // ndpi_protocol_struct, // Likely exists but caused issues, use ndpi_protocol_id_t based on suggestion
    ndpi_protocol_id_t, // Protocol ID type (Used suggestion)
    ndpi_protocol,
    ndpi_risk_enum, // Risk enum type
    // ndpi_proto_defaults_t, // Unused
    // ndpi_protocol_category_t, // Unused warning
    // ndpi_risk, // Unused warning

    // Initialization & Configuration Functions
    ndpi_init_detection_module,
    ndpi_exit_detection_module,
    // ndpi_set_detection_preferences, // Unused
    // ndpi_load_protocols, // Removed, likely ndpi_load_protocols_file or not needed
    // ndpi_set_proto_defaults, // Unused
    // ndpi_free_protocols, // Removed, likely handled by exit module
    // ndpi_protocol_breed_t, // Removed unused
    // ndpi_detection_preference_NDPI_DETECTION_PREF_DEFAULT, // Unresolved - Name likely different in bindings

    // Processing Function
    ndpi_detection_process_packet,

    // Information Retrieval Functions
    // ndpi_get_proto_name, // Unused
    // ndpi_get_num_supported_protocols, // Unused warning
    // ndpi_get_category_name, // Use suggested ndpi_get_category_id?
    // ndpi_get_category_id, // Unused
    ndpi_revision, // Used
    // ndpi_is_protocol_detected, // Unused
    // ndpi_get_api_version, // Unused

    // Risk Handling
    ndpi_risk2str, // Used
    // ndpi_risk2int, // Unresolved, suggested ndpi_risk2str which is likely incorrect for score
    // Keep removed, call site in ndpi_integration needs direct binding call if function exists
    // Consider ndpi_risk_get_score if ndpi_risk2int remains problematic

    // Constants & Enums (Examples)
    // ndpi_protocol_category_NDPI_PROTOCOL_CATEGORY_SECURITY, // Use suggested ..._MEDIA?
    // ndpi_protocol_category_t_NDPI_PROTOCOL_CATEGORY_MEDIA, // Use suggested name
    // ndpi_protocol_category_t_NDPI_PROTOCOL_CATEGORY_UNSPECIFIED, // Removed unused
    // ndpi_protocol_category_NDPI_PROTOCOL_CATEGORY_NUM, // Use suggested ..._VPN?
    // ndpi_protocol_category_t_NDPI_PROTOCOL_CATEGORY_VPN, // Use suggested name pattern
    // ndpi_protocol_breed_NDPI_PROTOCOL_FUN, // Unresolved
    // ndpi_protocol_breed_t_NDPI_PROTOCOL_FUN, // Use suggested name
    // ndpi_prefs_t, // Use suggested ndpi_prefix_t?
    // ndpi_prefix_t, // Unused
    // ndpi_init_prefs, // Unused warning
    ndpi_protocol_id_t_NDPI_PROTOCOL_UNKNOWN, // Used
    ndpi_risk_enum_NDPI_NO_RISK, // Used
    // Unused constants
    // ndpi_protocol_category_t_NDPI_PROTOCOL_CATEGORY_MEDIA,
    // ndpi_protocol_category_t_NDPI_PROTOCOL_CATEGORY_VPN,
    // ndpi_protocol_breed_t_NDPI_PROTOCOL_FUN,
};

// Re-export necessary libc types
// pub use libc::{
//     c_char,
//     c_int,
//     c_uint,
//     c_uchar,
//     c_void,
//     // time_t, // Not directly used
//     // timeval, // Not directly used
//     calloc, // Used for manual allocation
//     free, // Used implicitly via ndpi_flow_free etc.
// };

// Helper function to potentially get nDPI version string (may require linking correctly)
// This requires the nDPI library to be linked, and the function `ndpi_revision` to exist.
// use std::ffi::{CStr, CString};
// use std::os::raw::c_char; // Removed unused import

/*
// Example function to get the nDPI version string.
// Safety: Assumes `ndpi_revision` is correctly linked and returns a valid C string pointer.
pub fn get_ndpi_version_string() -> String {
    unsafe {
        let version_ptr = ndpi_revision(); // Call the FFI function
        if version_ptr.is_null() {
            "<nDPI version unknown: null pointer returned>".to_string()
        } else {
            // Convert the C string pointer to a Rust String, handling potential errors.
            CStr::from_ptr(version_ptr)
                .to_str()
                .unwrap_or("<nDPI version unknown: invalid UTF-8>")
                .to_string()
        }
    }
}

// Helper to convert C string pointer to Option<String>
// Safety: Caller must ensure ptr is valid or null.
// #[inline]
pub unsafe fn cstr_to_string(ptr: *const c_char) -> Option<String> {
    if ptr.is_null() {
        None
    } else {
        match CStr::from_ptr(ptr).to_str() {
            Ok(s) => Some(s.to_owned()),
            Err(e) => {
                // Log the error if possible, return None or a placeholder
                // eprintln!("Failed to convert C string from nDPI: {}", e);
                None
            }
        }
    }
}

// Helper to convert Rust numeric types to u16 for nDPI calls
// TODO: Add proper error handling for potential overflow.
// #[inline]
pub fn as_u16<T: TryInto<u16>>(val: T) -> u16 {
    val.try_into().unwrap_or_else(|_| {
        // eprintln!("Warning: Value conversion to u16 failed, defaulting to 0");
        0 // Default or panic, depending on context
    })
}
*/

// FFI safe function wrappers or helpers (optional)
use std::ffi::CStr;
// Removed duplicate c_char import: use std::os::raw::c_char;

// Removed unused imports:
// pub use bindings::ndpi_packet_struct;
// pub use bindings::ndpi_detection_preference;
// pub use bindings::ndpi_detection_giveup;

// Helper function to get version string (example)
// Removed broken helper function get_ndpi_version_string due to E0599/E0308

// Helper function to get revision string (example)
pub fn get_ndpi_revision_string() -> String {
    unsafe {
        let rev_ptr = ndpi_revision();
        if rev_ptr.is_null() {
            "N/A".to_string()
        } else {
            CStr::from_ptr(rev_ptr).to_string_lossy().into_owned()
        }
    }
}

// Example of constants if they are not directly exposed by bindgen allowlist_var
// pub const NDPI_PREFS_DEFAULT: ndpi_prefs_t = 0;

// Helper for allocating/freeing flow structs (avoids direct libc calls in engine)
// Ensure these match the actual nDPI API for flow management if available.
// Sometimes nDPI provides its own allocators/deallocators.

// Placeholder function: Check if ndpi_malloc exists in your bindings
pub fn ndpi_flow_malloc() -> *mut ndpi_flow_struct {
    // If nDPI provides ndpi_malloc, use it. Otherwise, fallback to libc.
    // unsafe { sys::ndpi_malloc(std::mem::size_of::<ndpi_flow_struct>()) as *mut ndpi_flow_struct }
    unsafe { libc::malloc(std::mem::size_of::<ndpi_flow_struct>()) as *mut ndpi_flow_struct }
}

// Placeholder function: Check if ndpi_free exists in your bindings
pub fn ndpi_flow_free(flow: *mut ndpi_flow_struct) {
    // If nDPI provides ndpi_free, use it.
    // unsafe { sys::ndpi_free(flow as *mut libc::c_void) }
    unsafe { libc::free(flow as *mut libc::c_void) }
}

// Add other necessary re-exports or helper functions here.