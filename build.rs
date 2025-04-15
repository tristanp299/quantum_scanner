// build.rs - Quantum Scanner Build Configuration
use std::env;
use std::process::Command;
use std::path::Path;

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
    
    // Handle nDPI configuration based on features
    let is_ndpi_enabled = env::var("CARGO_FEATURE_NDPI").is_ok();
    let is_full_ndpi = env::var("CARGO_FEATURE_FULL_NDPI").is_ok();
    
    if is_ndpi_enabled || is_full_ndpi {
        println!("cargo:warning=nDPI support enabled");
        
        // Check if nDPI is available and get its version
        match check_ndpi_library() {
            Some(version) => {
                println!("cargo:warning=Found nDPI library version {}", version);
                println!("cargo:rustc-cfg=feature=\"has_ndpi\"");
                
                // Parse version components for conditional compilation
                if let Some(version_num) = parse_ndpi_version(&version) {
                    // Enable features based on nDPI version
                    if version_num >= 400 { // v4.0.0+
                        println!("cargo:rustc-cfg=feature=\"ndpi_v4\"");
                    }
                    if version_num >= 408 { // v4.8.0+
                        println!("cargo:rustc-cfg=feature=\"ndpi_v48\"");
                    }
                    if version_num >= 420 { // v4.2.0+
                        println!("cargo:rustc-cfg=feature=\"ndpi_risk\"");
                        println!("cargo:warning=Enabling risk assessment features (nDPI >= 4.2.0)");
                    }
                    if version_num >= 430 { // v4.3.0+
                        println!("cargo:rustc-cfg=feature=\"ndpi_ja3plus\"");
                        println!("cargo:warning=Enabling JA3+ fingerprinting (nDPI >= 4.3.0)");
                    }
                    if version_num >= 452 { // v4.5.2+
                        println!("cargo:rustc-cfg=feature=\"ndpi_extended_info\"");
                        println!("cargo:warning=Enabling extended protocol metadata (nDPI >= 4.5.2)");
                    }
                }
                
                // Link with nDPI
                println!("cargo:rustc-link-lib=dylib=ndpi");
                
                // Report build configuration
                if is_full_ndpi {
                    println!("cargo:warning=Building with FULL nDPI protocol detection");
                } else {
                    println!("cargo:warning=Building with standard nDPI protocol detection");
                }
            },
            None => {
                println!("cargo:warning=ERROR: nDPI library not found but required by enabled features!");
                println!("cargo:warning=Make sure libndpi-dev (or equivalent) is installed on your system.");
                println!("cargo:warning=On Debian/Ubuntu, run: apt-get install libndpi-dev");
                println!("cargo:warning=On Fedora/CentOS, run: dnf install ndpi-devel");
                println!("cargo:warning=On Arch Linux, run: pacman -S ndpi");
                println!("cargo:warning=On macOS with Homebrew, run: brew install ndpi");
                println!("cargo:warning=Will continue build using minimal service identification.");
                
                // Define a fallback feature so we can handle missing nDPI gracefully
                println!("cargo:rustc-cfg=feature=\"ndpi_not_found\"");
            }
        }
    } else {
        println!("cargo:warning=Building without nDPI support (using minimal service identification)");
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
    println!("cargo:rerun-if-changed=src/ndpi_sys.rs");
    println!("cargo:rerun-if-changed=src/ndpi_integration.rs");
    
    // Set up features based on platform
    #[cfg(unix)]
    println!("cargo:rustc-cfg=feature=\"unix_sockets\"");
    
    #[cfg(windows)]
    println!("cargo:rustc-cfg=feature=\"windows_sockets\"");
}

/// Check if nDPI library is available and return version if found
fn check_ndpi_library() -> Option<String> {
    // Try pkg-config first as it's the most reliable method
    if let Ok(status) = Command::new("pkg-config")
        .arg("--exists")
        .arg("libndpi")
        .status()
    {
        if status.success() {
            println!("cargo:warning=Found nDPI via pkg-config");
            
            // Found via pkg-config, get the version
            if let Ok(output) = Command::new("pkg-config")
                .arg("--modversion")
                .arg("libndpi")
                .output()
            {
                let version = String::from_utf8_lossy(&output.stdout).trim().to_string();
                if !version.is_empty() {
                    // Also get the include path
                    if let Ok(output) = Command::new("pkg-config")
                        .arg("--cflags")
                        .arg("libndpi")
                        .output()
                    {
                        let cflags = String::from_utf8_lossy(&output.stdout);
                        for flag in cflags.split_whitespace() {
                            if flag.starts_with("-I") {
                                println!("cargo:include={}", &flag[2..]);
                            }
                        }
                    }
                    
                    // And the library path
                    if let Ok(output) = Command::new("pkg-config")
                        .arg("--libs")
                        .arg("libndpi")
                        .output()
                    {
                        let libs = String::from_utf8_lossy(&output.stdout);
                        for flag in libs.split_whitespace() {
                            if flag.starts_with("-L") {
                                println!("cargo:rustc-link-search={}", &flag[2..]);
                            }
                        }
                    }
                    
                    return Some(version);
                }
            }
        }
    }
    
    println!("cargo:warning=pkg-config not found or libndpi not registered, trying manual detection");
    
    // Manual search as fallback
    let include_paths = [
        "/usr/include/ndpi",
        "/usr/local/include/ndpi",
        "/opt/ndpi/include",
        "/usr/include",
        "/usr/local/include",
        "/usr/include/libndpi",
        "/usr/local/include/libndpi",
    ];
    
    let lib_paths = [
        "/usr/lib",
        "/usr/local/lib",
        "/usr/lib/x86_64-linux-gnu",
        "/usr/lib/aarch64-linux-gnu",
        "/opt/ndpi/lib",
        "/usr/lib64",
    ];
    
    // Find header first
    let mut header_path = None;
    
    for &path in &include_paths {
        // Try different header files - some distros use different paths
        let headers = [
            Path::new(path).join("ndpi_api.h"),
            Path::new(path).join("libndpi/ndpi_api.h"),
        ];
        
        for header in &headers {
            if header.exists() {
                println!("cargo:warning=Found nDPI header at: {}", header.display());
                println!("cargo:include={}", path);
                header_path = Some(header.clone());
                break;
            }
        }
        
        if header_path.is_some() {
            break;
        }
    }
    
    // Find lib - check for both .so and .a files
    let mut lib_found = false;
    let mut lib_path_str = String::new();
    
    for &path in &lib_paths {
        let lib_files = [
            Path::new(path).join("libndpi.so"),
            Path::new(path).join("libndpi.a"),
            Path::new(path).join("libndpi.dylib"), // macOS
        ];
        
        for lib_file in &lib_files {
            if lib_file.exists() {
                lib_path_str = path.to_string();
                println!("cargo:warning=Found nDPI library at: {}", lib_file.display());
                println!("cargo:rustc-link-search={}", path);
                lib_found = true;
                break;
            }
        }
        
        if lib_found {
            break;
        }
    }
    
    // Try to extract version from header if found
    if let Some(header) = header_path {
        if lib_found {
            // Read the header to find version information
            if let Ok(content) = std::fs::read_to_string(header) {
                // Look for NDPI_VERSION_MAJOR, NDPI_VERSION_MINOR, etc.
                let mut major = None;
                let mut minor = None;
                let mut patch = None;
                
                for line in content.lines() {
                    if line.contains("NDPI_VERSION_MAJOR") && line.contains("#define") {
                        if let Some(num) = extract_version_number(line) {
                            major = Some(num);
                        }
                    } else if line.contains("NDPI_VERSION_MINOR") && line.contains("#define") {
                        if let Some(num) = extract_version_number(line) {
                            minor = Some(num);
                        }
                    } else if line.contains("NDPI_VERSION_PATCH") && line.contains("#define") {
                        if let Some(num) = extract_version_number(line) {
                            patch = Some(num);
                        }
                    }
                }
                
                if let (Some(maj), Some(min), Some(pat)) = (major, minor, patch) {
                    return Some(format!("{}.{}.{}", maj, min, pat));
                } else if let (Some(maj), Some(min)) = (major, minor) {
                    return Some(format!("{}.{}.0", maj, min));
                }
            }
        }
    }
    
    // See if we can run ndpiReader and get version
    println!("cargo:warning=Trying to detect nDPI version from ndpiReader command");
    if let Ok(output) = Command::new("ndpiReader")
        .arg("-v")
        .output()
    {
        let output_str = String::from_utf8_lossy(&output.stdout);
        for line in output_str.lines() {
            if line.contains("version") {
                if let Some(version) = line.split("version").nth(1) {
                    let version_str = version.trim_start_matches(|c: char| !c.is_digit(10));
                    if !version_str.is_empty() {
                        if lib_found {
                            return Some(version_str.to_string());
                        } else {
                            println!("cargo:warning=Found nDPI version {} via ndpiReader but could not locate library", version_str);
                        }
                    }
                }
            }
        }
    }
    
    // If we found the library but couldn't determine version, return default
    if lib_found {
        println!("cargo:warning=Found nDPI library at {}, assuming version 4.0.0", lib_path_str);
        return Some("4.0.0".to_string()); // Assume a reasonably recent version
    }
    
    println!("cargo:warning=nDPI library not found on this system");
    None
}

/// Helper function to extract version number from a #define line
fn extract_version_number(line: &str) -> Option<u32> {
    let parts: Vec<&str> = line.split_whitespace().collect();
    if parts.len() >= 3 {
        return parts[2].parse::<u32>().ok();
    }
    None
}

/// Parse nDPI version string to a comparable integer
fn parse_ndpi_version(version: &str) -> Option<u32> {
    let parts: Vec<&str> = version.split('.').collect();
    if parts.len() >= 2 {
        let major = parts[0].parse::<u32>().ok()?;
        let minor = parts[1].parse::<u32>().ok()?;
        let patch = if parts.len() >= 3 { parts[2].parse::<u32>().ok()? } else { 0 };
        
        // Create a version number like 408 for 4.8.0
        let version_num = major * 100 + minor * 10 + (patch / 10);
        println!("cargo:warning=Parsed nDPI version {}.{}.{} to version number {}", 
                major, minor, patch, version_num);
        return Some(version_num);
    }
    None
} 