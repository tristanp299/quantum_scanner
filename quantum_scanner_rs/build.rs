use std::env;
use std::process::Command;

fn main() {
    // Check for libpcap development files
    #[cfg(target_os = "linux")]
    {
        let pcap_check = Command::new("sh")
            .arg("-c")
            .arg("ldconfig -p | grep -q libpcap")
            .status();
        
        match pcap_check {
            Ok(status) if !status.success() => {
                println!("cargo:warning=libpcap development files not found.");
                println!("cargo:warning=Please install libpcap-dev (Debian/Ubuntu) or libpcap-devel (RHEL/Fedora).");
            },
            Err(_) => {
                println!("cargo:warning=Failed to check for libpcap. Please ensure libpcap-dev is installed.");
            },
            _ => {
                println!("cargo:rustc-link-lib=pcap");
            }
        }
    }
    
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
    
    // Print build information
    println!("cargo:warning=Building Quantum Scanner for Rust");
    
    // Print information about privileges required
    if cfg!(unix) {
        println!("cargo:warning=Note: Raw socket operations require root/sudo privileges");
    } else if cfg!(windows) {
        println!("cargo:warning=Note: Raw socket operations require Administrator privileges");
    }
} 