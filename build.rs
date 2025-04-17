// build.rs - Quantum Scanner Build Configuration
use std::env;
use std::process::Command;
use std::path::{Path, PathBuf};
// Removed File and Write imports as dummy.c is no longer needed
// use std::fs::File;
// use std::io::Write;

fn main() {
    // Print build info for debugging
    println!("cargo:warning=Building Quantum Scanner for Rust #");
    
    // Check if we're building with musl (static build)
    let target = env::var("TARGET").unwrap_or_else(|_| String::from(""));
    let is_musl = target.contains("musl");
    
    // Removed dummy C file creation and compilation
    /* 
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
    */
    
    // Handle nDPI configuration - attempt to find and link the library
    // Store include paths found by pkg-config or manual search
    let mut ndpi_include_paths: Vec<PathBuf> = Vec::new();
    let ndpi_version = check_ndpi_library(&mut ndpi_include_paths);
    
    if let Some(version) = ndpi_version {
        println!("cargo:warning=Successfully configured nDPI version {}", version);
        // Set a feature flag indicating nDPI is linked (can be used in Rust code)
        println!("cargo:rustc-cfg=feature=\"has_linked_ndpi\"");
        
        // Run bindgen to generate Rust bindings for nDPI
        generate_ndpi_bindings(&ndpi_include_paths);
        
        // Optional: Parse version and set feature flags for specific versions if needed
        /* 
        Example: if let Some(v_num) = parse_ndpi_version(&version) {
            if v_num >= 400 { // Example: nDPI 4.x.x or later
                println!("cargo:rustc-cfg=feature=\"ndpi_v4\"");
            }
        }
        */
    } else {
        println!("cargo:warning=nDPI library not found or linking failed. Building without nDPI support.");
        // No feature flag set, Rust code can check for `has_linked_ndpi`
    }
    
    // Link pcap last
    // Note: nDPI itself might depend on pcap, linking order can matter.
    // pkg-config should handle dependencies correctly. If using manual linking,
    // ensure dependencies like libgcrypt, libgpg-error, pthread are linked *after* nDPI.
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
    println!("cargo:warning=Note: Raw socket operations require root/sudo privileges #");
    
    // Rerun the build script if certain files change
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=Cargo.toml");
    // Rerun if the main nDPI header changes (if found)
    if let Some(header_path) = find_ndpi_header_path(&ndpi_include_paths) {
        println!("cargo:rerun-if-changed={}", header_path.display());
    }
    // No longer directly depend on these for build logic after removing stubs
    // println!("cargo:rerun-if-changed=src/ndpi_sys.rs"); 
    // println!("cargo:rerun-if-changed=src/ndpi_integration.rs");
    
    // Set up features based on platform
    #[cfg(unix)]
    println!("cargo:rustc-cfg=feature=\"unix_sockets\"");
    
    #[cfg(windows)]
    println!("cargo:rustc-cfg=feature=\"windows_sockets\"");
}

// Removed compile_wrapper function as it's not needed

/// Check if nDPI library is available and return version if found
/// Sets cargo:rustc-link flags if found and populates include paths.
fn check_ndpi_library(include_paths_out: &mut Vec<PathBuf>) -> Option<String> {
    // Get target and musl info
    let target = env::var("TARGET").unwrap_or_else(|_| String::from(""));
    let is_musl = target.contains("musl");
    
    // Try pkg-config first
    if let Ok(library) = pkg_config::Config::new().atleast_version("3.0").probe("libndpi") {
        println!("cargo:warning=Found nDPI version {} via pkg-config", library.version);
        // pkg_config::Config automatically prints the necessary cargo flags (libs, search paths)
        
        // Manually adjust nDPI linkage type based on musl
        // Remove the automatic static linkage from pkg-config if not musl
        // Note: This assumes pkg-config doesn't add other static links we need to keep.
        // A more robust approach might parse pkg-config's output manually here.
        if !is_musl {
             println!("cargo:rustc-link-lib=dylib=ndpi"); // Prefer dynamic unless musl
             // Also link dependencies dynamically unless musl
             for lib in &library.libs {
                 if lib != "ndpi" && lib != "dl" { // Ignore dl
                     println!("cargo:rustc-link-lib=dylib={}", lib);
                 }
             }
        } else {
            println!("cargo:rustc-link-lib=static=ndpi"); // Keep static for musl
            // Link dependencies statically for musl
             for lib in &library.libs {
                 if lib != "ndpi" && lib != "dl" { 
                     println!("cargo:rustc-link-lib=static={}", lib);
                 }
             }
        }

        // Extract include paths manually for bindgen
        for path in library.include_paths {
             println!("cargo:include={}", path.display());
             include_paths_out.push(path);
        }

        return Some(library.version);
    }
    
    println!("cargo:warning=pkg-config failed for libndpi, trying manual detection");
    
    // Manual search as fallback (Simplified - consider using the vcpkg crate or similar for robust cross-platform builds)
    let common_include_paths: [&str; 6] = [
        "/usr/include",
        "/usr/local/include", 
        "/opt/local/include",
        "/opt/homebrew/include", // macOS specific
        "/usr/include/ndpi",
        "/usr/local/include/ndpi"
    ];
    
    let common_lib_paths: [&str; 6] = [
        "/usr/lib",
        "/usr/local/lib",
        "/opt/local/lib",
        "/opt/homebrew/lib", // macOS specific
        "/usr/lib/x86_64-linux-gnu", // Debian/Ubuntu specific
        "/usr/lib64" // Fedora/CentOS specific
    ];

    // ... (Keep the manual header finding logic) ...
    
    let mut header_found_path: Option<PathBuf> = None;
    for &path_str in &common_include_paths {
        let path = Path::new(path_str);
        let headers = [
            path.join("ndpi_api.h"),
            path.join("libndpi/ndpi_api.h"), // Some installations might have it nested
        ];
        for header in &headers {
            if header.exists() {
                println!("cargo:warning=Found nDPI header manually at: {}", header.display());
                println!("cargo:include={}", path_str); // Tell subsequent build steps (like bindgen)
                include_paths_out.push(path.to_path_buf());
                header_found_path = Some(header.clone()); // Store the full path to the header
                break;
            }
        }
        if header_found_path.is_some() { break; }
    }
    
    // Find lib - check for both .so and .a files
    let mut lib_found = false;
    let mut lib_path_str = String::new();
    let mut ndpi_link_type = "dylib"; // Default to dynamic

    for &path_str in &common_lib_paths {
        let path = Path::new(path_str);
        let static_lib = path.join("libndpi.a");
        let dynamic_lib_so = path.join("libndpi.so");
        let dynamic_lib_dylib = path.join("libndpi.dylib"); // macOS

        let mut found_lib_path = None;

        if is_musl && static_lib.exists() {
            // Prefer static for musl build if available
            println!("cargo:warning=Found static nDPI library (libndpi.a) for musl build at: {}", static_lib.display());
            ndpi_link_type = "static";
            found_lib_path = Some(static_lib);
        } else if dynamic_lib_so.exists() {
             println!("cargo:warning=Found dynamic nDPI library (libndpi.so) manually at: {}", dynamic_lib_so.display());
             ndpi_link_type = "dylib";
             found_lib_path = Some(dynamic_lib_so);
        } else if dynamic_lib_dylib.exists() {
             println!("cargo:warning=Found dynamic nDPI library (libndpi.dylib) manually at: {}", dynamic_lib_dylib.display());
             ndpi_link_type = "dylib";
             found_lib_path = Some(dynamic_lib_dylib);
        } else if !is_musl && static_lib.exists() {
             // Use static as fallback if dynamic not found (and not musl)
             println!("cargo:warning=Found static nDPI library (libndpi.a) manually (dynamic preferred): {}", static_lib.display());
             ndpi_link_type = "static";
             found_lib_path = Some(static_lib);
        }
        
        if let Some(_lib_file) = found_lib_path { // Use _lib_file as it's not used directly
            lib_path_str = path_str.to_string();
            println!("cargo:rustc-link-search=native={}", path_str);
            println!("cargo:rustc-link-lib={}={}", ndpi_link_type, "ndpi");
            lib_found = true;
            break;
        }
    }

    // Manually link known nDPI dependencies if library was found AND we linked manually
    // This is a fallback if pkg-config wasn't used
    if lib_found && header_found_path.is_some() { // Only proceed if both lib and header are found
        let dep_link_type = if is_musl { "static" } else { "dylib" };
        println!("cargo:warning=Manually linking nDPI dependencies as type: {}", dep_link_type);
        println!("cargo:rustc-link-lib={}=gcrypt", dep_link_type);
        println!("cargo:rustc-link-lib={}=gpg-error", dep_link_type);
        // Link pthread if not on Windows or macOS (where it's often implicit) and not musl
        if !is_musl && !target.contains("windows") && !target.contains("darwin") {
            println!("cargo:rustc-link-lib=dylib=pthread");
        }
        
        // Try to get version via ndpiReader command as before
        println!("cargo:warning=Trying to detect nDPI version from ndpiReader command");
        if let Ok(output) = Command::new("ndpiReader").arg("-v").output() {
            // ... (keep existing ndpiReader version parsing logic) ...
            let output_str = String::from_utf8_lossy(&output.stdout);
            for line in output_str.lines() {
                 if line.contains("version") {
                     if let Some(version) = line.split("version").nth(1) {
                         let version_str = version.trim_start_matches(|c: char| !c.is_digit(10)).trim();
                         if !version_str.is_empty() {
                             return Some(version_str.to_string());
                         }
                     }
                 }
            }
        }
        
        // If we found the library but couldn't determine version, return default
        println!("cargo:warning=Found nDPI library manually at {}, but couldn't determine version. Assuming 4.0.0", lib_path_str);
        return Some("4.0.0".to_string()); 
    }
    
    println!("cargo:warning=Manual search failed to find nDPI library or header.");
    None
}

/// Helper function to find the primary nDPI header file path
fn find_ndpi_header_path(include_paths: &[PathBuf]) -> Option<PathBuf> {
    for path in include_paths {
        let headers = [
            path.join("ndpi_api.h"),
            path.join("libndpi/ndpi_api.h"),
        ];
        for header in &headers {
            if header.exists() {
                return Some(header.clone());
            }
        }
    }
    None
}

/// Generate Rust bindings for nDPI using bindgen
fn generate_ndpi_bindings(include_paths: &[PathBuf]) {
    println!("cargo:warning=Generating nDPI bindings...");

    // Find the primary header file (e.g., ndpi_api.h)
    let header_path = match find_ndpi_header_path(include_paths) {
        Some(path) => path,
        None => {
            println!("cargo:warning=Cannot find nDPI header file (e.g., ndpi_api.h) in provided include paths. Skipping bindgen.");
            return;
        }
    };

    let bindings = bindgen::Builder::default()
        // Input header
        .header(header_path.to_string_lossy())
        // Tell cargo to invalidate build cache if wrapper changes
        .parse_callbacks(Box::new(bindgen::CargoCallbacks::new()))
        // Add include paths for bindgen to find nested headers
        .clang_args(include_paths.iter().map(|p| format!("-I{}", p.display())))
        // Allowlist types and functions needed for safety and reduced size
        .allowlist_function("ndpi_.*")
        .allowlist_type("ndpi_.*")
        .allowlist_var("NDPI_.*") // Constants like NDPI_PROTOCOL_TLS
        // Use core definitions where possible
        .use_core()
        // Use libc types for C standard types
        .ctypes_prefix("libc")
        // Blocklist opaque types that don't need a definition
        .blocklist_type("__va_list_tag") // Often causes issues
        // Generate the bindings
        .generate()
        .expect("Unable to generate nDPI bindings");

    // Write the bindings to the $OUT_DIR/bindings.rs file.
    let out_path = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap()).join("src");
    bindings
        .write_to_file(out_path.join("ndpi_bindings.rs"))
        .expect("Couldn't write nDPI bindings!");

    println!("cargo:warning=Successfully generated nDPI bindings to {}", out_path.join("ndpi_bindings.rs").display());
}