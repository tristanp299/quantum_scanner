// build.rs - Quantum Scanner Build Configuration
use std::env;

fn main() {
    // Print build info for debugging
    println!("cargo:warning=Building Quantum Scanner for Rust");
    
    // Check if we're building with musl (static build)
    let target = env::var("TARGET").unwrap_or_else(|_| String::from(""));
    let is_musl = target.contains("musl");
    
    if is_musl {
        println!("cargo:warning=Building with musl target: {}", target);
        
        // Link to libpcap dynamically (works better with musl)
        println!("cargo:rustc-link-lib=dylib=pcap");
    } else {
        // For regular builds, link to pcap dynamically
        println!("cargo:rustc-link-lib=dylib=pcap");
    }
    
    // Check if we're building for release
    let profile = env::var("PROFILE").unwrap_or_else(|_| String::from(""));
    if profile == "release" {
        println!("cargo:warning=Building in release mode");
    }
    
    // Note about privileges
    println!("cargo:warning=Note: Raw socket operations require root/sudo privileges");
    
    // Rerun the build script if certain files change
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=Cargo.toml");
    
    // Set up features based on platform
    #[cfg(unix)]
    println!("cargo:rustc-cfg=feature=\"unix_sockets\"");
    
    #[cfg(windows)]
    println!("cargo:rustc-cfg=feature=\"windows_sockets\"");
} 