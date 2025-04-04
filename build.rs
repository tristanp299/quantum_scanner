// build.rs - Quantum Scanner Build Configuration
use std::env;
use std::process::Command;

fn main() {
    // Print build info for debugging
    println!("cargo:warning=Building Quantum Scanner for Rust");
    
    // Check if we're building with musl
    let target = env::var("TARGET").unwrap_or_else(|_| String::from(""));
    if target.contains("musl") {
        println!("cargo:warning=Building with musl target: {}", target);
        
        // Set appropriate linker flags for musl static builds
        println!("cargo:rustc-link-arg=-static");
        println!("cargo:rustc-link-arg=-no-pie");
        
        // Tell cargo to use musl-gcc if available
        if Command::new("which").arg("musl-gcc").status().is_ok() {
            println!("cargo:rustc-env=CC=musl-gcc");
        }
    }
    
    // Check if we're building for release
    let profile = env::var("PROFILE").unwrap_or_else(|_| String::from(""));
    if profile == "release" {
        println!("cargo:warning=Building in release mode");
        
        // Add specific optimizations for release builds
        println!("cargo:rustc-link-arg=-Wl,--gc-sections");
    }
    
    // Note about privileges
    println!("cargo:warning=Note: Raw socket operations require root/sudo privileges");
    
    // Rerun the build script if certain files change
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=Cargo.toml");
    
    // The user has manually installed libpcap, so we can now link to it
    println!("cargo:rustc-link-lib=pcap");
    
    // Check for libc availability (required for privilege checks)
    #[cfg(unix)]
    {
        println!("cargo:rustc-link-lib=dylib=c");
    }
    
    // Set up features based on platform
    #[cfg(unix)]
    println!("cargo:rustc-cfg=feature=\"unix_sockets\"");
    
    #[cfg(windows)]
    println!("cargo:rustc-cfg=feature=\"windows_sockets\"");
} 