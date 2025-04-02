fn main() {
    println!("cargo:warning=Building Quantum Scanner for Rust");
    println!("cargo:warning=Note: Raw socket operations require root/sudo privileges");
    
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