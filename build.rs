// build.rs - Quantum Scanner Build Configuration
use std::env;
use std::process::Command;
use std::path::Path;
use std::fs::File;
use std::io::Write;

fn main() {
    // Print build info for debugging
    println!("cargo:warning=Building Quantum Scanner for Rust");
    
    // Check if we're building with musl (static build)
    let target = env::var("TARGET").unwrap_or_else(|_| String::from(""));
    let is_musl = target.contains("musl");
    
    // Create a dummy C file for cc to compile
    let out_dir = env::var("OUT_DIR").unwrap();
    let dummy_path = Path::new(&out_dir).join("dummy.c");
    let mut file = File::create(&dummy_path).unwrap();
    writeln!(file, "// Dummy C file with required functions\n\
                   #include <stddef.h>\n\
                   \n\
                   // Dummy function to ensure proper static linking\n\
                   size_t dummy_function() {{ return 1; }}\n").unwrap();
    
    // We need to use the cc crate for proper static linking
    cc::Build::new()
        .file(&dummy_path)
        .compile("dummy");
    
    // Handle nDPI configuration based on features
    let is_ndpi_enabled = env::var("CARGO_FEATURE_NDPI").is_ok();
    let is_full_ndpi = env::var("CARGO_FEATURE_FULL_NDPI").is_ok();
    
    if is_ndpi_enabled || is_full_ndpi {
        println!("cargo:warning=nDPI support enabled (static implementation)");
        
        // We're no longer linking to the nDPI library directly
        // Instead, we're using our own Rust implementations
        
        // Enable our has_ndpi feature
        println!("cargo:rustc-cfg=feature=\"has_ndpi\"");
        println!("cargo:rustc-cfg=feature=\"ndpi_v4\"");
        println!("cargo:rustc-cfg=feature=\"ndpi_risk\"");
        
        // Report build configuration
        if is_full_ndpi {
            println!("cargo:warning=Building with FULL nDPI protocol detection (static)");
        } else {
            println!("cargo:warning=Building with standard nDPI protocol detection (static)");
        }
    } else {
        println!("cargo:warning=Building without nDPI support (using minimal service identification)");
    }
    
    // Link pcap last
    if is_musl {
        // Static linking for pcap when using musl
        println!("cargo:rustc-link-lib=static=pcap");
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
    println!("cargo:rerun-if-changed=src/ndpi_sys.rs");
    println!("cargo:rerun-if-changed=src/ndpi_integration.rs");
    
    // Set up features based on platform
    #[cfg(unix)]
    println!("cargo:rustc-cfg=feature=\"unix_sockets\"");
    
    #[cfg(windows)]
    println!("cargo:rustc-cfg=feature=\"windows_sockets\"");
}

/// Compile the ndpi_wrapper.c file and link it statically
/* // REMOVED: Wrapper compilation is no longer needed for static linking
fn compile_wrapper() {
    let out_dir = env::var("OUT_DIR").unwrap();
    let wrapper_path = "wrapper/ndpi_wrapper.c";
    
    // Ensure wrapper directory and file exist
    if !Path::new(wrapper_path).exists() {
        panic!("Wrapper file not found at: {}", wrapper_path);
    }
    
    // Compile the wrapper with cc
    cc::Build::new()
        .file(wrapper_path)
        .compile("ndpi_wrapper");
    
    println!("cargo:warning=Successfully compiled ndpi_wrapper.c");
    println!("cargo:rustc-link-search={}", out_dir);
}
*/

/// Check if nDPI library is available and return version if found
fn check_ndpi_library() -> Option<String> {
    // Get target and musl info - adding these variables at the function level
    let target = env::var("TARGET").unwrap_or_else(|_| String::from(""));
    let is_musl = target.contains("musl");
    
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
                    
                    // And the library path and specific libraries to link
                    if let Ok(output) = Command::new("pkg-config")
                        .arg("--libs")
                        .arg("libndpi")
                        .output()
                    {
                        let libs = String::from_utf8_lossy(&output.stdout);
                        println!("cargo:warning=Linking nDPI dependencies: {}", libs.trim());
                        
                        for flag in libs.split_whitespace() {
                            if flag.starts_with("-L") {
                                // Add library search path
                                println!("cargo:rustc-link-search=native={}", &flag[2..]);
                            } else if flag.starts_with("-l") {
                                let lib_name = &flag[2..];
                                // Link nDPI statically, dependencies dynamically (unless musl)
                                if lib_name == "ndpi" {
                                    println!("cargo:rustc-link-lib=static=ndpi");
                                } else if lib_name != "dl" { // Ignore libdl, not needed without wrapper
                                    if is_musl {
                                        println!("cargo:rustc-link-lib=static={}", lib_name);
                                    } else {
                                        println!("cargo:rustc-link-lib=dylib={}", lib_name);
                                    }
                                } else {
                                    println!("cargo:warning=Ignoring -ldl flag from pkg-config");
                                }
                            }
                            // Add other flags if necessary (e.g., -pthread)
                            // else {
                            //     println!("cargo:rustc-link-arg={}", flag);
                            // }
                        }
                        
                        return Some(version);
                    }
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
    
    // Prioritize static library for manual search
    let mut static_lib_found = false;
    
    for &path in &lib_paths {
        let lib_files = [
            Path::new(path).join("libndpi.a"),
            Path::new(path).join("libndpi.dylib"), // macOS
            Path::new(path).join("libndpi.so"), // Check .so last
        ];
        
        for lib_file in &lib_files {
            if lib_file.exists() {
                lib_path_str = path.to_string();
                println!("cargo:warning=Found nDPI library at: {}", lib_file.display());
                println!("cargo:rustc-link-search=native={}", path);
                lib_found = true;
                
                // Check if it's the static library
                if lib_file.extension().map_or(false, |ext| ext == "a") {
                    println!("cargo:rustc-link-lib=static=ndpi");
                    static_lib_found = true;
                } else if !static_lib_found {
                    // Only link dynamically if static wasn't found yet
                    println!("cargo:rustc-link-lib=dylib=ndpi");
                    println!("cargo:warning=Found dynamic nDPI library (.so/.dylib). Static linking requires libndpi.a");
                }
                
                break;
            }
        }
        
        if lib_found {
            break;
        }
    }
    
    // Manually link known nDPI dependencies if library was found
    // This is a fallback if pkg-config wasn't used or didn't list them
    if lib_found {
        if is_musl {
            println!("cargo:rustc-link-lib=static=gcrypt");
            println!("cargo:rustc-link-lib=static=gpg-error");
            // musl doesn't usually need pthread explicitly linked
        } else {
            println!("cargo:rustc-link-lib=dylib=gcrypt");
            println!("cargo:rustc-link-lib=dylib=gpg-error");
            // Link pthread if not on Windows or macOS (where it's often implicit)
            if !target.contains("windows") && !target.contains("darwin") {
                println!("cargo:rustc-link-lib=dylib=pthread");
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
        // If we only found the dynamic lib manually, issue warning again
        if !static_lib_found {
            println!("cargo:warning=Could not find libndpi.a manually. Static linking may fail. Ensure the static library is installed.");
        }
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