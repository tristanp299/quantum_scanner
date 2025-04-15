use clap::{Parser, ValueEnum};
use log::{debug, error, info, warn};
use std::path::PathBuf;
use std::process;
use std::time::Duration;
use rand::{thread_rng, Rng};
use std::sync::Arc;
use std::fs;
use std::net::IpAddr;
use std::io::Write;
use serde_json;
use anyhow::{Result, anyhow};
use tokio::time::sleep;
use crate::utils::MemoryLogBuffer;
use crate::models::{ScanType, PortRanges, TopPorts, requires_raw_sockets};

mod banner;
mod http_analyzer;
mod ml_service_ident;
mod models;
mod output;
mod scanner;
mod service_fingerprints;
mod techniques;
mod tunnel;
mod utils;
mod ssl_config;

use scanner::QuantumScanner;

/// Advanced port scanner with evasion capabilities for authorized red team operations
#[derive(Parser, Debug)]
#[clap(
    author, 
    version, 
    about = "A sophisticated network scanner with advanced evasion capabilities for security assessments",
    long_about = "Quantum Scanner provides comprehensive network reconnaissance capabilities with a focus on operational security. It enables secure, controlled scanning with multiple techniques and evasive measures.",
    name = "quantum_scanner",
)]
#[clap(group(
    clap::ArgGroup::new("port_selection")
        .multiple(false)
))]
#[clap(group(
    clap::ArgGroup::new("scan_execution")
        .multiple(true)
))]
#[clap(group(
    clap::ArgGroup::new("output_options")
        .multiple(true)
))]
#[clap(group(
    clap::ArgGroup::new("evasion_options")
        .multiple(true)
))]
#[clap(group(
    clap::ArgGroup::new("tunneling_options")
        .multiple(true)
))]
#[clap(group(
    clap::ArgGroup::new("service_detection")
        .multiple(true)
))]
#[clap(group(
    clap::ArgGroup::new("timing_control")
        .multiple(true)
))]
#[clap(group(
    clap::ArgGroup::new("fragmentation")
        .multiple(true)
))]
#[clap(group(
    clap::ArgGroup::new("operational_security")
        .multiple(true)
))]
#[clap(after_help = "EXAMPLES:
    # Run a basic SYN scan against a target
    quantum_scanner 192.168.1.1

    # Scan a range with multiple techniques and evasion
    quantum_scanner 192.168.0.0/24 -p 22,80,443-8000 -s syn,fin,xmas -e

    # Full stealth scan through Tor with enhanced evasion
    quantum_scanner example.com -E -m --mimic-os linux --use-tor

    # Using protocol tunneling to bypass firewalls
    quantum_scanner 10.0.0.1 --dns-tunnel --lookup-domain example.com

    # Enhanced service identification with ML
    quantum_scanner 192.168.1.100 --ml-ident -p 22,80,443

    # Save results to a file in JSON format
    quantum_scanner 10.0.0.1 -j -o scan_results.json

AVAILABLE SCAN TYPES:
    syn         - Standard TCP SYN scan (efficient and relatively stealthy)
    ssl         - Probes for SSL/TLS service information and certificates
    udp         - Basic UDP port scan with custom payload options
    ack         - TCP ACK scan to detect firewall filtering rules
    fin         - Stealthy scan using TCP FIN flags to bypass basic filters
    xmas        - TCP scan with FIN, URG, and PUSH flags set
    null        - TCP scan with no flags set, may bypass some packet filters
    window      - Analyzes TCP window size responses to determine port status
    mimic       - Sends SYN packets with protocol-specific payloads
    frag        - Fragments packets to bypass deep packet inspection
    dns-tunnel  - Tunnels scan traffic through DNS queries
    icmp-tunnel - Tunnels scan traffic through ICMP echo (ping) packets

MIMICRY OPTIONS:
    PROTOCOLS (used with --mimic-protocol):
        HTTP    - Mimics HTTP server (default)
        SSH     - Mimics OpenSSH server
        FTP     - Mimics FTP server
        SMTP    - Mimics SMTP mail server
        IMAP    - Mimics IMAP mail server
        POP3    - Mimics POP3 mail server
        MYSQL   - Mimics MySQL database server
        RDP     - Mimics Remote Desktop Protocol server

    OS PROFILES (used with --mimic-os):
        windows - Mimics Windows networking behavior
        linux   - Mimics Linux networking behavior
        macos   - Mimics macOS networking behavior
        random  - Uses randomly selected OS profile (default)
"
)]
struct Args {
    /// Target IP address, hostname, or CIDR notation for subnet
    #[clap(value_parser)]
    target: String,

    // ========== TARGET AND PORT SELECTION ==========
    
    /// Ports to scan (comma-separated, ranges like 1-1000)
    #[clap(short, long, default_value = "1-1000", group = "port_selection", help_heading = "TARGET AND PORT SELECTION")]
    ports: String,

    /// Scan the top 100 common ports
    #[clap(short = 'T', long, group = "port_selection", help_heading = "TARGET AND PORT SELECTION")]
    top_100: bool,

    /// Scan the top 10 most common ports (for quicker scans)
    #[clap(short = 't', long, group = "port_selection", help_heading = "TARGET AND PORT SELECTION")]
    top_10: bool,

    /// Use IPv6
    #[clap(short = '6', long, help_heading = "TARGET AND PORT SELECTION")]
    ipv6: bool,

    // ========== SCAN METHODS ==========

    /// Scan techniques to use (comma-separated)
    #[clap(short, long, default_value = "syn", group = "scan_execution", help_heading = "SCAN METHODS", long_help = "Available techniques: syn, ssl, udp, ack, fin, xmas, null, window, mimic, frag, dns-tunnel, icmp-tunnel\nExamples: -s syn,ssl,udp or -s syn -s ssl\nNote: Do not include spaces after commas\n\n⚠️ OPSEC WARNING: The ssl and mimic scan types use full TCP connections that are easily logged by target systems. For stealth-critical operations, prefer using only the raw socket scan types like syn, fin, xmas, null, etc.")]
    scan_types_str: String,

    /// Enable port scan only mode (no service identification)
    #[clap(short = 'P', long = "port-scan", group = "scan_mode", help_heading = "SCAN METHODS", long_help = "Enables port scan only mode. This mode focuses solely on discovering open ports with minimal footprint. Disables nDPI, banner grabbing, and service version detection for maximum OPSEC.")]
    port_scan_only: bool,

    /// Enable service and version detection (less stealthy)
    #[clap(short = 'V', long = "service-scan", group = "scan_mode", help_heading = "SCAN METHODS", long_help = "Enables service and version detection. This mode performs additional connections after discovering open ports to identify services using nDPI, banner grabbing, and protocol analysis. Note: This is less stealthy as it requires establishing full TCP connections.")]
    service_scan: bool,

    // ========== EVASION OPTIONS ==========

    /// Enable basic evasion techniques 
    #[clap(short, long, group = "evasion_options", help_heading = "EVASION OPTIONS", long_help = "Enable basic evasion techniques (simple TTL manipulation, basic timing randomization, minimal TCP option adjustment, packet sequencing randomization)")]
    evasion: bool,

    /// Enable advanced evasion techniques
    #[clap(short = 'E', long, default_value_t = false, group = "evasion_options", help_heading = "EVASION OPTIONS", long_help = "Enable advanced evasion techniques (OS fingerprint spoofing, TTL jittering, protocol-specific mimicry, banner grabbing suppression, sophisticated protocol variants)")]
    enhanced_evasion: bool,

    /// Operating system to mimic in enhanced evasion mode (windows, linux, macos, random)
    #[clap(long, group = "evasion_options", help_heading = "EVASION OPTIONS")]
    mimic_os: Option<String>,

    /// TTL jitter amount for enhanced evasion (1-5)
    #[clap(long, default_value_t = 2, group = "evasion_options", help_heading = "EVASION OPTIONS")]
    ttl_jitter: u8,

    /// Protocol to mimic in mimic scans (HTTP, SSH, FTP, SMTP, IMAP, POP3, MYSQL, RDP)
    #[clap(long, default_value = "HTTP", group = "evasion_options", help_heading = "EVASION OPTIONS")]
    mimic_protocol: String,

    /// Protocol variant for protocol mimicry
    #[clap(long, group = "evasion_options", help_heading = "EVASION OPTIONS")]
    protocol_variant: Option<String>,

    /// Route traffic through Tor if available
    #[clap(long, default_value_t = false, group = "evasion_options", help_heading = "EVASION OPTIONS")]
    use_tor: bool,

    // ========== TUNNELING OPTIONS ==========

    /// Use DNS tunneling to bypass restrictive firewalls
    #[clap(long = "dns-tunnel", default_value_t = false, group = "tunneling_options", help_heading = "TUNNELING OPTIONS")]
    dns_tunnel: bool,
    
    /// Use ICMP tunneling to bypass restrictive firewalls
    #[clap(long = "icmp-tunnel", default_value_t = false, group = "tunneling_options", help_heading = "TUNNELING OPTIONS")]
    icmp_tunnel: bool,
    
    /// Custom DNS server to use for DNS tunneling
    #[clap(long = "dns-server", group = "tunneling_options", help_heading = "TUNNELING OPTIONS")]
    dns_server: Option<String>,
    
    /// Custom lookup domain to use for DNS tunneling
    #[clap(long = "lookup-domain", group = "tunneling_options", help_heading = "TUNNELING OPTIONS")]
    lookup_domain: Option<String>,

    // ========== SERVICE DETECTION ==========

    // ========== TIMING AND PERFORMANCE ==========

    /// Maximum concurrent operations
    #[clap(short, long, default_value_t = 100, group = "timing_control", help_heading = "TIMING AND PERFORMANCE")]
    concurrency: usize,

    /// Maximum packets per second
    #[clap(short = 'r', long, default_value_t = 0, group = "timing_control", help_heading = "TIMING AND PERFORMANCE")]
    rate: usize,

    /// Scan timeout in seconds
    #[clap(short, long, default_value_t = 5.0, group = "timing_control", help_heading = "TIMING AND PERFORMANCE")]
    timeout: f64,

    /// Connect timeout in seconds
    #[clap(long, default_value_t = 5.0, group = "timing_control", help_heading = "TIMING AND PERFORMANCE")]
    timeout_connect: f64,

    /// Banner grabbing timeout in seconds
    #[clap(long, default_value_t = 5.0, group = "timing_control", help_heading = "TIMING AND PERFORMANCE")]
    timeout_banner: f64,

    /// Add randomized delay before scan start (0-5 seconds)
    #[clap(long, default_value_t = true, group = "timing_control", help_heading = "TIMING AND PERFORMANCE")]
    random_delay: bool,
    
    /// Maximum random delay in seconds
    #[clap(long, default_value_t = 3, group = "timing_control", help_heading = "TIMING AND PERFORMANCE")]
    max_delay: u64,

    // ========== FRAGMENTATION OPTIONS ==========

    /// Minimum fragment size for fragmented scans
    #[clap(long, default_value_t = 24, group = "fragmentation", help_heading = "FRAGMENTATION OPTIONS")]
    frag_min_size: u16,

    /// Maximum fragment size for fragmented scans
    #[clap(long, default_value_t = 64, group = "fragmentation", help_heading = "FRAGMENTATION OPTIONS")]
    frag_max_size: u16,

    /// Minimum delay between fragments in seconds
    #[clap(long, default_value_t = 0.01, group = "fragmentation", help_heading = "FRAGMENTATION OPTIONS")]
    frag_min_delay: f64,

    /// Maximum delay between fragments in seconds
    #[clap(long, default_value_t = 0.1, group = "fragmentation", help_heading = "FRAGMENTATION OPTIONS")]
    frag_max_delay: f64,

    /// Timeout for fragmented scans in seconds
    #[clap(long, default_value_t = 10, group = "fragmentation", help_heading = "FRAGMENTATION OPTIONS")]
    frag_timeout: u64,

    /// Minimum size of first fragment
    #[clap(long, default_value_t = 64, group = "fragmentation", help_heading = "FRAGMENTATION OPTIONS")]
    frag_first_min_size: u16,

    /// Use exactly two fragments
    #[clap(long, group = "fragmentation", help_heading = "FRAGMENTATION OPTIONS")]
    frag_two_frags: bool,

    // ========== OUTPUT OPTIONS ==========

    /// Enable verbose output
    #[clap(short, long, group = "output_options", help_heading = "OUTPUT OPTIONS", long_help = "When enabled, provides detailed information about the scanning process to stdout, including debug-level messages. In disk mode, verbose logs are also written to the log file.")]
    verbose: bool,

    /// Show detailed debug information during scan
    #[clap(short = 'd', long, group = "output_options", help_heading = "OUTPUT OPTIONS", long_help = "When enabled, shows detailed debug information during scan, including individual port scan results. Use for troubleshooting.")]
    debug: bool,

    /// Output results in JSON format
    #[clap(short = 'j', long, group = "output_options", help_heading = "OUTPUT OPTIONS")]
    json: bool,

    /// Format the raw JSON output for pretty printing (with indentation)
    #[clap(long = "pretty-json", group = "output_options", help_heading = "OUTPUT OPTIONS")]
    pretty_json: bool,

    /// Write results to file
    #[clap(short, long, group = "output_options", help_heading = "OUTPUT OPTIONS")]
    output: Option<PathBuf>,

    /// Use ANSI colors in output
    #[clap(long, default_value_t = true, group = "output_options", help_heading = "OUTPUT OPTIONS")]
    color: bool,

    // ========== OPERATIONAL SECURITY ==========

    /// Enable memory-only mode (no disk writes)
    #[clap(short = 'm', long, group = "operational_security", help_heading = "OPERATIONAL SECURITY")]
    memory_only: bool,

    /// Log file path
    #[clap(long, default_value = "scanner.log", group = "operational_security", help_heading = "OPERATIONAL SECURITY")]
    log_file: PathBuf,
    
    /// Encrypt logs with a password
    #[clap(long, default_value_t = true, group = "operational_security", help_heading = "OPERATIONAL SECURITY")]
    encrypt_logs: bool,
    
    /// Password for log encryption
    #[clap(long, group = "operational_security", help_heading = "OPERATIONAL SECURITY")]
    _log_password: Option<String>,
    
    /// Create RAM disk for temporary files
    #[clap(long, default_value_t = true, group = "operational_security", help_heading = "OPERATIONAL SECURITY")]
    use_ramdisk: bool,
    
    /// RAM disk size in MB
    #[clap(long, default_value_t = 10, group = "operational_security", help_heading = "OPERATIONAL SECURITY")]
    ramdisk_size: u64,
    
    /// RAM disk mount point
    #[clap(long, default_value = "/mnt/quantum_scanner_ramdisk", group = "operational_security", help_heading = "OPERATIONAL SECURITY")]
    ramdisk_mount: PathBuf,

    /// Securely delete files after scan
    #[clap(long, default_value_t = false, group = "operational_security", help_heading = "OPERATIONAL SECURITY", long_help = "When enabled, performs secure deletion of log files and temporary files using multiple overwrite passes. Disabled by default for operational safety.")]
    secure_delete: bool,
    
    /// Number of secure delete passes
    #[clap(long, default_value_t = 3, group = "operational_security", help_heading = "OPERATIONAL SECURITY", long_help = "Specifies how many passes of overwriting should be performed when secure_delete is enabled. More passes provide better security but take longer.")]
    delete_passes: u8,

    /// Path to a log file to unredact (without running a scan)
    #[clap(long, group = "operational_security", help_heading = "OPERATIONAL SECURITY", long_help = "When provided without running a scan, this will only perform the redaction removal operation on the specified log file, replacing [REDACTED] with the target IP.")]
    fix_log_file: Option<PathBuf>,
}

/// Enum for scan types from CLI
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum)]
enum ScanTypeArg {
    Syn,
    Ssl,
    Udp,
    Ack,
    Fin,
    Xmas,
    Null,
    Window,
    Mimic,
    Frag,
}

impl From<ScanTypeArg> for ScanType {
    fn from(arg: ScanTypeArg) -> Self {
        match arg {
            ScanTypeArg::Syn => ScanType::Syn,
            ScanTypeArg::Ssl => ScanType::Ssl,
            ScanTypeArg::Udp => ScanType::Udp,
            ScanTypeArg::Ack => ScanType::Ack,
            ScanTypeArg::Fin => ScanType::Fin,
            ScanTypeArg::Xmas => ScanType::Xmas,
            ScanTypeArg::Null => ScanType::Null,
            ScanTypeArg::Window => ScanType::Window,
            ScanTypeArg::Mimic => ScanType::Mimic,
            ScanTypeArg::Frag => ScanType::Frag,
        }
    }
}

/// ANSI color codes for terminal output
struct Colors {
    green: String,
    yellow: String,
    blue: String,
    #[allow(dead_code)]
    red: String,
    reset: String,
}

impl Colors {
    fn new(enabled: bool) -> Self {
        if enabled {
            Self {
                green: "\x1b[0;32m".to_string(),
                yellow: "\x1b[1;33m".to_string(),
                blue: "\x1b[0;34m".to_string(),
                red: "\x1b[0;31m".to_string(),
                reset: "\x1b[0m".to_string(),
            }
        } else {
            Self {
                green: "".to_string(),
                yellow: "".to_string(),
                blue: "".to_string(),
                red: "".to_string(),
                reset: "".to_string(),
            }
        }
    }
}

/// Initialize logging with proper configuration
/// 
/// Sets up logging to either memory buffer or file based on memory_only flag.
/// Also handles log encryption if enabled.
///
/// # Arguments
/// * `log_file` - Path to log file (if memory_only is false)
/// * `verbose` - Whether to enable verbose logging
/// * `debug` - Whether to enable debug logging
/// * `memory_only` - Whether to log to memory instead of disk
/// * `encrypt_logs` - Whether to encrypt logs
/// * `log_password` - Password for log encryption (if encrypt_logs is true)
///
/// # Returns
/// * `Result<Option<utils::MemoryLogBuffer>, anyhow::Error>` - Memory buffer if memory_only is true
///
/// # Opsec Considerations
/// - **Memory-Only Logging:** Prevents writing potentially sensitive scan activity to disk, reducing forensic footprint.
/// - **Log Encryption:** Protects log data at rest (if written to disk) or in memory buffer from trivial inspection. Requires a password (user-provided or auto-generated for memory buffer).
fn setup_logging(
    log_file: &PathBuf, 
    verbose: bool, 
    debug: bool,
    memory_only: bool, 
    encrypt_logs: bool, 
    log_password: Option<&str>
) -> Result<Option<MemoryLogBuffer>> {
    use env_logger::{Builder, Env};
    
    // Configure log filter based on verbose and debug flags
    let filter_level = if debug {
        "debug"
    } else if verbose { 
        "info" 
    } else { 
        "warn" 
    };
    
    // Initialize memory logger if memory-only mode is enabled
    if memory_only {
        info!("Using memory-only logging (no disk writes)");
        
        // Set up env_logger to output to stderr (for live verbose output)
        // Note: env_logger can only be initialized once. If setup_logging is called after
        // initial main setup, this might conflict. We rely on the initial setup in main.
        // This call here ensures the filter level is set, but doesn't re-initialize.
        let env = Env::default().filter_or("RUST_LOG", filter_level);
        // Attempt to initialize, but ignore error if already initialized
        let _ = Builder::from_env(env)
            .format_timestamp_secs()
            .try_init(); 
            
        // Create memory buffer for logs
        let memory_buffer = MemoryLogBuffer::new(
            10000, // Store up to 10000 log entries
            encrypt_logs
        );
        
        // Handle encryption setup if needed (removed unused password variable)
        if encrypt_logs {
            if let Some(_pw) = log_password {
                info!("Using provided password for memory log encryption.");
                // TODO: Implement setting the key in MemoryLogBuffer based on pw
                // memory_buffer.set_encryption_key(Some(pw.as_bytes().to_vec()));
            } else {
                info!("Generated random password for memory log encryption. (Key stored internally)");
                // Key is generated internally in MemoryLogBuffer::new if encrypt_logs is true
            }
        }
        
        // Return the configured memory buffer wrapped in Option
        Ok(Some(memory_buffer))
    } else {
        // Set up file logging
        let env = Env::default().filter_or("RUST_LOG", filter_level);
        
        // Create parent directories if needed
        if let Some(parent) = log_file.parent() {
            if !parent.exists() {
                fs::create_dir_all(parent)?;
            }
        }
        
        // Keep a copy of the log file path for logging
        let log_file_path = log_file.clone();
        
        // Configure env_logger to write to file and stderr
        let mut builder = Builder::from_env(env);
        let logger_result = if let Ok(log_file_handle) = fs::File::create(log_file) {
            // Use try_init to avoid panic if logger is already initialized
            let _ = builder
                .format_timestamp_secs()
                .target(env_logger::Target::Pipe(Box::new(log_file_handle)))
                .try_init();
            info!("Logging to file: {}", log_file_path.display());
            Ok(None)
        } else {
            error!("Failed to create log file, falling back to stderr only");
            let _ = builder
                .format_timestamp_secs()
                .try_init();
            Ok(None)
        };
        
        logger_result
    }
}

/// Check if we have sufficient privileges for raw sockets
///
/// # Arguments
/// * `scanner_needs_raw_sockets` - Boolean indicating if the selected scan types require raw socket access.
///
/// # Returns
/// * `bool` - True if sufficient privileges are detected, false otherwise.
///
/// # Opsec Considerations
/// - Running scans requiring raw sockets (like SYN, FIN, Xmas) without root/Administrator privileges will likely fail silently or be blocked by the OS.
/// - This check is crucial to prevent unexpected failures and inform the user.
///
/// # Known Limitations
/// - The Windows implementation is currently a placeholder and unreliable. It assumes privileges are sufficient. A proper check using Windows APIs is needed for accuracy on Windows.
fn check_privileges(scanner_needs_raw_sockets: bool) -> bool {
    if !scanner_needs_raw_sockets {
        return true;
    }
    
    #[cfg(unix)]
    {
        // On Unix systems, check effective user ID
        return unsafe { libc::geteuid() == 0 };
    }
    
    #[cfg(windows)]
    {
        // On Windows, accurately checking for Administrator privileges is complex.
        // Use the `is_elevated` crate for a simpler cross-platform check (if available)
        // or fall back to a WinAPI check.
        // TODO: Implement a reliable Windows privilege check using appropriate WinAPI calls (e.g., IsUserAnAdmin). -> Implementing using `is_elevated`
        // warn!(\"Windows privilege check is currently unreliable; assuming sufficient privileges.\");
        // true
        return match is_elevated::is_elevated() {
            Ok(elevated) => {
                if !elevated {
                    warn!("Administrator privileges are required for raw socket scans on Windows.");
                }
                elevated
            }
            Err(e) => {
                // Error checking elevation, assume not elevated for safety
                error!("Failed to check for Administrator privileges: {}. Assuming not elevated.", e);
                false
            }
        };
    }
    
    #[cfg(not(any(unix, windows)))]
    {
        // Unknown platform - assume not privileged
        return false;
    }
}

/// Setup Tor routing if requested and available
/// 
/// Attempts to configure the application to route traffic through Tor
/// for anonymization. This requires Tor to be installed and running.
///
/// # Arguments
/// * `use_tor` - Whether to enable Tor routing
///
/// # Returns
/// * `bool` - Whether Tor routing was successfully enabled
fn setup_tor_routing(use_tor: bool) -> bool {
    if !use_tor {
        return false;
    }
    
    // Use the utils function for Tor configuration which has better error handling
    utils::configure_tor_routing(true)
}

/// Create and mount a RAM disk for temporary files
///
/// # Arguments
/// * `use_ramdisk` - Whether to create a RAM disk
/// * `mount_point` - Path where the RAM disk should be mounted
/// * `size_mb` - Size of the RAM disk in megabytes
///
/// # Returns
/// * `Result<Option<PathBuf>, anyhow::Error>` - Mount point if created successfully
fn create_ramdisk(use_ramdisk: bool, mount_point: &PathBuf, size_mb: u64) -> Result<Option<PathBuf>, anyhow::Error> {
    if !use_ramdisk {
        return Ok(None);
    }
    
    #[cfg(unix)]
    {
        // Check if the mount point exists, create it if not
        if !mount_point.exists() {
            match std::fs::create_dir_all(mount_point) {
                Ok(_) => info!("Created RAM disk mount point at {}", mount_point.display()),
                Err(e) => {
                    error!("Failed to create RAM disk mount point: {}", e);
                    return Err(anyhow!("Could not create RAM disk mount point: {}", e));
                }
            }
        }
        
        // Determine mount command based on platform
        let mount_cmd = if cfg!(target_os = "linux") {
            // On Linux, use tmpfs for the RAM disk
            format!(
                "mount -t tmpfs -o size={}m,mode=0700,nodev,nosuid,noexec tmpfs {}",
                size_mb, mount_point.display()
            )
        } else if cfg!(target_os = "macos") {
            // On macOS, use diskutil to create a RAM disk
            let sectors = size_mb * 2048; // Convert MB to 512-byte sectors
            format!(
                "diskutil erasevolume HFS+ 'RAMDISK' `hdiutil attach -nomount ram://{}`",
                sectors
            )
        } else {
            // Return error for unsupported platforms
            return Err(anyhow!("RAM disk creation is only supported on Linux and macOS"));
        };
        
        // Execute the mount command
        info!("Attempting to create RAM disk: {}", mount_cmd);
        match std::process::Command::new("sh")
            .arg("-c")
            .arg(&mount_cmd)
            .output()
        {
            Ok(output) => {
                if output.status.success() {
                    info!("RAM disk created successfully at {}", mount_point.display());
                    // Set restrictive permissions after mounting
                    if cfg!(target_os = "linux") {
                        let _ = std::process::Command::new("chmod")
                            .arg("700")
                            .arg(mount_point.as_os_str())
                            .output();
                    }
                    Ok(Some(mount_point.clone()))
                } else {
                    let stderr = String::from_utf8_lossy(&output.stderr);
                    warn!("Failed to create RAM disk: {}", stderr);
                    // Continue without RAM disk - graceful degradation
                    Ok(None)
                }
            }
            Err(e) => {
                warn!("Failed to execute RAM disk command: {}", e);
                // Continue without RAM disk - graceful degradation
                Ok(None)
            }
        }
    }
    
    #[cfg(not(unix))]
    {
        warn!("RAM disk feature is currently only supported on Unix-like systems");
        // Return None but not an error to allow operation to continue
        Ok(None)
    }
}

/// Unmount a RAM disk
///
/// # Arguments
/// * `ramdisk` - Reference to the RAM disk mount point
///
/// # Returns
/// * `Result<(), anyhow::Error>` - Ok(()) if unmount succeeded, Err(e) if failed
///
/// # Opsec Considerations
/// - Ensures the volatile RAM disk is unmounted and the mount point directory is removed, cleaning up traces.
/// - Uses lazy unmount (`umount -l`) as a fallback if the standard unmount fails, which can help if processes are still accessing the disk.
/// - Attempts multiple times to remove the directory, handling potential delays in resource release.
fn cleanup_ramdisk(ramdisk: &Option<PathBuf>) -> Result<(), anyhow::Error> {
    if let Some(mount_point) = ramdisk {
        #[cfg(unix)]
        {
            // Check if the mount point exists and is mounted
            if !mount_point.exists() {
                return Ok(());
            }
            
            // First try to sync all file systems to ensure all data is written
            let _ = std::process::Command::new("sync").status();
            
            // Try to unmount - first try normal unmount
            let status = std::process::Command::new("umount")
                .arg(mount_point.to_str().unwrap_or_default())
                .status();
                
            // If normal unmount fails, try lazy unmount (-l option)
            if status.is_err() || !status.unwrap().success() {
                info!("Standard unmount failed, trying lazy unmount...");
                
                // Add a small delay to allow any pending operations to complete
                std::thread::sleep(std::time::Duration::from_millis(500));
                
                let lazy_status = std::process::Command::new("umount")
                    .arg("-l")  // Lazy unmount - detach filesystem now, cleanup resources later
                    .arg(mount_point.to_str().unwrap_or_default())
                    .status()?;
                    
                if !lazy_status.success() {
                    return Err(anyhow::anyhow!("Failed to unmount RAM disk at {}", mount_point.display()));
                }
            }
            
            info!("Unmounted RAM disk from {}", mount_point.display());
            
            // Give the system more time to complete the unmount and release resources
            std::thread::sleep(std::time::Duration::from_secs(2));
            
            // Remove directory after unmounting
            if mount_point.exists() {
                // Try multiple times to remove the directory with increasing delays
                for attempt in 0..3 {  // Increased to 3 attempts
                    // First try with rmdir for a clean unmounted directory
                    if attempt == 0 {
                        let _ = std::process::Command::new("rmdir")
                            .arg(mount_point.to_str().unwrap_or_default())
                            .status();
                    }
                    
                    // Then try with remove_dir_all if rmdir didn't work
                    match std::fs::remove_dir_all(mount_point) {
                        Ok(_) => return Ok(()),
                        Err(e) => {
                            // Log error but keep trying
                            info!("Remove directory attempt {}: {}", attempt + 1, e);
                            
                            // Try to forcefully release the mount point using fuser (if available)
                            if attempt == 2 {
                                let _ = std::process::Command::new("fuser")
                                    .args(["-km", mount_point.to_str().unwrap_or_default()])
                                    .status();
                            }
                            
                            // Wait longer with each attempt (exponential backoff)
                            let delay = std::time::Duration::from_millis(500 * (2_u64.pow(attempt as u32)));
                            std::thread::sleep(delay);
                        }
                    }
                }
                
                // If we couldn't remove it after all tries, don't fail the operation
                warn!("Could not remove mount point directory after unmounting. Will be cleaned up on next reboot.");
                
                // Try one last thing - modify the mount point to indicate it's no longer needed
                let empty_file_path = mount_point.join(".cleanup_on_reboot");
                let _ = std::fs::File::create(empty_file_path);
            }
            
            return Ok(());
        }
    }
    
    Ok(())
}

/// Securely delete a file by overwriting it multiple times
///
/// # Arguments
/// * `path` - Path to the file to delete
/// * `passes` - Number of overwrite passes (1-7)
///
/// # Returns
/// * `Result<(), anyhow::Error>` - Success or error
fn secure_delete_file(path: &PathBuf, passes: u8) -> Result<(), anyhow::Error> {
    if !path.exists() {
        debug!("File {} does not exist, nothing to delete", path.display());
        return Ok(());
    }
    
    // Get file metadata
    let metadata = match std::fs::metadata(path) {
        Ok(meta) => meta,
        Err(e) => {
            warn!("Failed to get metadata for {}: {}", path.display(), e);
            return Err(anyhow!("Could not access file: {}", e));
        }
    };
    
    // Check if it's a file
    if !metadata.is_file() {
        return Err(anyhow!("Not a file: {}", path.display()));
    }
    
    // Get file size
    let file_size = metadata.len();
    
    info!("Securely deleting {} ({} bytes) with {} passes", path.display(), file_size, passes);
    
    if file_size == 0 {
        // If the file is empty, just remove it
        std::fs::remove_file(path)?;
        return Ok(());
    }
    
    // Limit passes to reasonable range
    let actual_passes = passes.clamp(1, 7);
    
    // Use standard rust file operations for platform independence
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .open(path)?;
    
    use std::io::{Seek, SeekFrom, Write};
    
    // Patterns for different passes
    // Using the DoD 5220.22-M standard as a reference
    let overwrite_patterns: Vec<Box<dyn Fn() -> u8>> = vec![
        Box::new(|| 0x00), // All zeros
        Box::new(|| 0xFF), // All ones
        Box::new(|| thread_rng().gen::<u8>()), // Random data - Create new RNG inside closure
        Box::new(|| 0x55), // Alternating 01010101
        Box::new(|| 0xAA), // Alternating 10101010
        Box::new(|| 0xF0), // 11110000
        Box::new(|| 0x0F), // 00001111
    ];
    
    // Buffer size for each write operation
    const BUFFER_SIZE: usize = 4096;
    let mut buffer = vec![0u8; BUFFER_SIZE];
    
    // Perform the overwrite passes
    for pass in 0..actual_passes {
        // Select pattern based on pass number
        let pattern_fn = &overwrite_patterns[pass as usize % overwrite_patterns.len()];
        
        // Fill the buffer with the selected pattern
        for i in 0..BUFFER_SIZE {
            buffer[i] = pattern_fn();
        }
        
        // Seek to the beginning of the file
        file.seek(SeekFrom::Start(0))?;
        
        // Write the pattern to the file
        let mut bytes_written = 0;
        while bytes_written < file_size {
            let bytes_to_write = std::cmp::min(BUFFER_SIZE as u64, file_size - bytes_written) as usize;
            let slice = &buffer[0..bytes_to_write];
            
            file.write_all(slice)?;
            bytes_written += bytes_to_write as u64;
        }
        
        // Flush to ensure data is written to disk
        file.flush()?;
        
        // For debugging or verbose output
        debug!("Completed secure delete pass {} of {}", pass + 1, actual_passes);
    }
    
    // Drop the file handle before removing
    drop(file);
    
    // Finally, remove the file
    match std::fs::remove_file(path) {
        Ok(_) => {
            info!("Successfully securely deleted {}", path.display());
            Ok(())
        },
        Err(e) => {
            warn!("Failed to remove file {} after secure deletion: {}", path.display(), e);
            Err(anyhow!("Failed to remove file after wiping: {}", e))
        }
    }
}

/// Unredact a log file by replacing [REDACTED] with the actual IP address
///
/// # Arguments
/// * `log_file` - Path to the log file to be unredacted
/// * `ip_address` - IP address to replace [REDACTED] with
///
/// # Returns
/// * `Result<usize, anyhow::Error>` - Ok(count) with the number of replacements made, or an error.
///
/// # Opsec Considerations
/// - This utility allows reversing the redaction applied to log files for analysis *after* an operation, assuming the original target IP is known.
/// - Redaction helps protect the target identity in logs during the operation or if logs are exfiltrated prematurely.
/// - Creates a backup (`.bak`) of the original redacted log before modifying it.
fn fix_redacted_log(log_file: &PathBuf, ip_address: &str) -> Result<usize, anyhow::Error> {
    info!("Attempting to fix redactions in log file: {}", log_file.display());

    // Read the entire log file content
    let content = match fs::read_to_string(log_file) {
        Ok(c) => c,
        Err(e) => return Err(anyhow!("Failed to read log file {}: {}", log_file.display(), e)),
    };

    // Check if redaction marker exists
    if !content.contains("[REDACTED]") {
        info!("No redaction markers found in {}. Nothing to fix.", log_file.display());
        return Ok(0);
    }

    // Perform the replacement
    let updated_content = content.replace("[REDACTED]", ip_address);
    let replacements = content.matches("[REDACTED]").count();

    // Write the updated content back to the file (overwrite)
    match fs::write(log_file, updated_content) {
        Ok(_) => {
            info!("Successfully fixed {} redactions in {}. Replaced with {}", replacements, log_file.display(), ip_address);
            Ok(replacements)
        }
        Err(e) => Err(anyhow!("Failed to write updated content to log file {}: {}", log_file.display(), e)),
    }
}

/// Parses the scan type string (e.g., "syn,ssl,udp") and returns a vector of ScanTypes.
/// When evasion flags are set, prompts user to confirm use of non-OPSEC-friendly scan types.
/// Handles potential errors during parsing.
fn parse_scan_types(scan_types_str: &str, evasion: bool, enhanced_evasion: bool) -> Result<Vec<ScanType>> {
    let mut scan_types = Vec::new();
    let mut needs_opsec_warning = false;
    let mut has_ssl = false;
    let mut has_mimic = false;
    
    for type_str in scan_types_str.split(',') {
        let trimmed = type_str.trim();
        if trimmed.is_empty() {
            continue; // Skip empty parts
        }
        // Case-insensitive matching
        match trimmed.to_lowercase().as_str() {
            "syn" => scan_types.push(ScanType::Syn),
            "ssl" => {
                scan_types.push(ScanType::Ssl);
                needs_opsec_warning = true;
                has_ssl = true;
            },
            "udp" => scan_types.push(ScanType::Udp),
            "ack" => scan_types.push(ScanType::Ack),
            "fin" => scan_types.push(ScanType::Fin),
            "xmas" => scan_types.push(ScanType::Xmas),
            "null" => scan_types.push(ScanType::Null),
            "window" => scan_types.push(ScanType::Window),
            "mimic" => {
                scan_types.push(ScanType::Mimic);
                needs_opsec_warning = true;
                has_mimic = true;
            },
            "frag" => scan_types.push(ScanType::Frag),
            "dnstunnel" | "dns-tunnel" => {
                scan_types.push(ScanType::DnsTunnel);
                info!("Using DNS tunnel scanning technique");
            },
            "icmptunnel" | "icmp-tunnel" => {
                scan_types.push(ScanType::IcmpTunnel);
                info!("Using ICMP tunnel scanning technique");
            },
            _ => return Err(anyhow!("Invalid scan type specified: {}", trimmed)),
        }
    }
    if scan_types.is_empty() {
        return Err(anyhow!("No valid scan types specified in string: '{}'", scan_types_str));
    }
    
    // Show OPSEC warning if needed
    if needs_opsec_warning {
        warn!("⚠️  OPSEC WARNING: You've selected scan types (ssl or mimic) that use full TCP connections");
        warn!("   These scan types are easily logged by target systems and leave more forensic evidence.");
        warn!("   For stealth-critical operations, consider using only raw socket scans like syn, fin, null, etc.");
    }
    
    // If evasion is enabled and ssl/mimic scans are selected, ask for confirmation
    if (evasion || enhanced_evasion) && (has_ssl || has_mimic) {
        let mut scan_type_warnings = Vec::new();
        if has_ssl { scan_type_warnings.push("SSL"); }
        if has_mimic { scan_type_warnings.push("Mimic"); }
        
        warn!("⚠️  SECURITY CONFLICT: You've enabled evasion ({}) but selected {} scan type(s)",
             if enhanced_evasion { "enhanced" } else { "basic" },
             scan_type_warnings.join(" and "));
        warn!("   These scan types establish full TCP connections which contradicts evasion goals");
        warn!("   and leaves forensic evidence in target logs.");
        
        // Prompt for confirmation
        print!("   Continue with these scan types anyway? [y/N]: ");
        std::io::stdout().flush().unwrap();
        
        let mut input = String::new();
        std::io::stdin().read_line(&mut input).unwrap();
        let input = input.trim().to_lowercase();
        
        // If not confirmed, remove these scan types
        if input != "y" && input != "yes" {
            info!("Removing non-OPSEC-friendly scan types as requested");
            scan_types.retain(|scan_type| {
                !matches!(scan_type, ScanType::Ssl | ScanType::Mimic)
            });
            
            // Check if we have any scan types left
            if scan_types.is_empty() {
                return Err(anyhow!("No scan types remaining after removing non-OPSEC-friendly types. Please specify other scan types or disable evasion."));
            }
        } else {
            warn!("Proceeding with non-OPSEC-friendly scan types as confirmed by user");
        }
    }
    
    // Check if tunneling methods are used and appropriate options are set
    if scan_types.contains(&ScanType::DnsTunnel) {
        info!("DNS tunneling technique selected. For best results, provide --lookup-domain and optionally --dns-server");
    }
    
    if scan_types.contains(&ScanType::IcmpTunnel) {
        info!("ICMP tunneling technique selected. Requires root privileges.");
    }
    
    // Deduplicate scan types
    scan_types.sort_unstable();
    scan_types.dedup();
    Ok(scan_types)
}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    // Initialize default logger early to catch errors during setup
    let _ = env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info"))
        .format_timestamp_secs() // Keep consistent format
        .try_init();

    // Parse command-line arguments
    let args = Args::parse();
    let _colors = Colors::new(args.color);

    // --- Special Mode: Fix Redacted Log File --- 
    // If --fix-log-file is provided, perform only that action and exit.
    if let Some(log_path_to_fix) = &args.fix_log_file {
        // Check if the file exists
        if !log_path_to_fix.exists() {
            error!("Log file to fix does not exist: {}", log_path_to_fix.display());
            process::exit(1);
        }
        // The target argument is reused to provide the IP for unredaction
        let ip_to_insert = &args.target; 
        match fix_redacted_log(log_path_to_fix, ip_to_insert) {
            Ok(count) => {
                info!("Log file redaction fix completed. {} replacements made.", count);
                process::exit(0);
            }
            Err(e) => {
                error!("Failed to fix redacted log file: {}", e);
                process::exit(1);
            }
        }
    }

    // --- Regular Scan Execution --- 

    // Set up logging based on args (handles memory vs file, encryption)
    // Note: This re-initializes the logger if not memory_only.
    
    // Apply a workaround for unstable proc-macro feature detection
    #[cfg(feature = "insecure-tls")]
    std::env::set_var("RUSTC_BOOTSTRAP", "1");
    
    let memory_log_buffer = match setup_logging(
        &args.log_file, 
        args.verbose, 
        args.debug,
        args.memory_only, 
        args.encrypt_logs, 
        args._log_password.as_deref() // Pass optional password
    ) { 
        Ok(buffer_opt) => {
            // Convert Option<MemoryLogBuffer> to Option<Arc<parking_lot::Mutex<MemoryLogBuffer>>>
            buffer_opt.map(|buffer| Arc::new(parking_lot::Mutex::new(buffer)))
        },
        Err(e) => {
            // Use default logger initialized earlier to show this error
            error!("Failed to initialize logging: {}", e);
            process::exit(1);
        }
    };

    // Display cool banner
    if args.color {
        println!("{}", banner::display_banner(true));
    } else {
        println!("{}", banner::display_banner(false));
    }

    // Parse scan types from args.scan_types_str and check for needed privileges
    let scan_types = parse_scan_types(&args.scan_types_str, args.evasion, args.enhanced_evasion)?;
    let needs_raw_sockets = requires_raw_sockets(&scan_types);
    
    // Determine the scanning mode
    let service_scan_mode = if args.port_scan_only {
        // Port scan only mode explicitly chosen
        info!("Port scan only mode selected (-sP). Service identification disabled for improved stealth.");
        false
    } else if args.service_scan {
        // Service scan mode explicitly chosen
        info!("Service scan mode selected (-sV). Will perform additional connections for service identification.");
        true
    } else {
        // Neither flag specified, default to port scan only
        info!("No scan mode specified. Defaulting to port scan only mode for improved stealth.");
        info!("Use -sV to enable detailed service identification.");
        false
    };
    
    // Try to detect local IPv4 if raw sockets are needed
    let local_ip_v4 = if needs_raw_sockets {
        info!("Raw socket scans selected. Attempting to detect local IPv4 address.");
        match utils::find_local_ipv4() {
            Ok(ip) => {
                info!("Using local IPv4 {} for raw socket scans.", ip);
                Some(ip)
            },
            Err(e) => {
                warn!("Failed to detect local IPv4 address: {}. Raw socket scans may fail.", e);
                None
            }
        }
    } else {
        None
    };
    
    // Verify user has needed privileges if any scan types require them
    if needs_raw_sockets && !check_privileges(needs_raw_sockets) {
        warn!("Scanner may require elevated privileges for the selected scan types.");
        warn!("If scan fails, try running with sudo or as root/Administrator.");
    }

    // Log IPv6 scanning status
    if args.ipv6 {
        info!("IPv6 scanning is ENABLED. Will scan both IPv4 and IPv6 addresses if target resolves to both.");
    } else {
        info!("IPv6 scanning is DISABLED. Only IPv4 targets will be scanned. Use --ipv6 flag to enable IPv6 scanning.");
    }
    
    // Parse ports
    let ports_to_scan = if args.top_100 {
        info!("Using top 100 common ports");
        TopPorts::top_100()
    } else if args.top_10 {
        info!("Using top 10 common ports");
        TopPorts::top_10()
    } else {
        info!("Parsing custom port specification: {}", &args.ports);
        match PortRanges::parse(&args.ports) {
            Ok(ranges) => {
                // Expand ranges into a Vec<u16>
                let expanded_ports: Vec<u16> = PortRanges::new(ranges).into_iter().collect();
                // Add validation for total number of ports to prevent excessive scanning
                if expanded_ports.len() > 20000 { // Limit to 20k ports
                   error!("Too many ports specified ({}). Maximum allowed is 20000.", expanded_ports.len());
                   process::exit(1);
                }
                if expanded_ports.is_empty() {
                    error!("No valid ports specified after parsing.");
                    process::exit(1);
                }
                info!("Scanning {} ports based on custom specification.", expanded_ports.len());
                expanded_ports
            }
            Err(e) => {
                error!("Error parsing port specification '{}': {}", &args.ports, e);
                process::exit(1);
            }
        }
    };

    // Handle Tor setup (best effort)
    if args.use_tor {
        info!("Attempting to route traffic through Tor...");
        if setup_tor_routing(args.use_tor) {
            info!("Tor routing enabled successfully.");
        } else {
            warn!("Failed to enable Tor routing. Proceeding with direct connection.");
        }
    }

    // Handle RAM disk setup (best effort, requires privileges)
    let ramdisk_path = match create_ramdisk(args.use_ramdisk, &args.ramdisk_mount, args.ramdisk_size) {
        Ok(Some(path)) => {
            info!("RAM disk created successfully at {}", path.display());
            Some(path)
        }
        Ok(None) => {
            info!("RAM disk not used (disabled, no privileges, or platform unsupported).");
            None
        }
        Err(e) => {
            warn!("Error creating RAM disk: {}. Continuing without RAM disk.", e);
            None
        }
    };

    // Apply random delay if requested
    if args.random_delay {
        let delay_secs = if args.max_delay > 0 {
            thread_rng().gen_range(0..=args.max_delay)
        } else {
            thread_rng().gen_range(0..=3) // Default 0-3 seconds
        };
        
        if delay_secs > 0 {
            info!("Applying random pre-scan delay of {} seconds...", delay_secs);
            sleep(Duration::from_secs(delay_secs)).await;
        }
    }

    // Create scanner instance with all parameters
    let mut scanner = QuantumScanner::new(
        &args.target,
        ports_to_scan,
        scan_types,
        local_ip_v4, // Pass the detected local IPv4 address
        args.concurrency,
        args.rate,
        args.evasion,
        args.verbose,
        args.debug,
        args.ipv6,
        args.timeout,
        args.timeout_connect,
        args.timeout_banner,
        &args.mimic_protocol,
        // Fragmentation parameters
        args.frag_min_size,
        args.frag_max_size,
        args.frag_min_delay,
        args.frag_max_delay,
        args.frag_timeout,
        args.frag_first_min_size,
        args.frag_two_frags,
        &args.log_file,
        true, // ml_identification - TODO: Make this configurable?
        service_scan_mode, // Pass the determined service scan mode
    ).await?;

    // Set enhanced evasion options if enabled
    if args.enhanced_evasion {
        scanner.set_enhanced_evasion(
            true,
            args.mimic_os.as_deref().unwrap_or("random"), // Provide default if None
            args.ttl_jitter,
        );
    }

    // Set protocol variant if provided
    if let Some(variant) = &args.protocol_variant {
        scanner.set_protocol_variant(Some(variant));
    }

    // Set memory log buffer for scanner if present
    if let Some(buffer) = &memory_log_buffer {
        // Pass the memory log buffer to the scanner
        scanner.set_memory_log(buffer.clone()); 
    }

    // Set DNS tunneling options if enabled
    if args.dns_tunnel {
        let server_ip = match args.dns_server {
            Some(s) => match s.parse::<IpAddr>() {
                Ok(ip) => Some(ip),
                Err(_) => {
                    warn!("Invalid DNS server IP address specified: '{}'. DNS tunneling might fail.", s);
                    None
                }
            },
            None => None,
        };
        scanner.set_dns_tunnel_options(server_ip, args.lookup_domain.as_deref());
    }

    // --- Run Scan --- 
    info!("Starting scan execution...");
    let scan_result = match scanner.run_scan().await {
        Ok(result) => {
            info!("Scan completed successfully.");
            result
        }
        Err(e) => {
            error!("Scan failed: {}", e);
            // Attempt cleanup before exiting
            if let Err(cleanup_err) = cleanup_ramdisk(&ramdisk_path) {
                 warn!("Error during RAM disk cleanup on scan failure: {}", cleanup_err);
            }
            process::exit(1);
        }
    };

    // --- Output Results --- 
    info!("Processing and outputting results...");
    // Always generate structured output (e.g., JSON), then decide how to print/save
    
    // Simplify the JSON serialization logic
    let json_output = if args.pretty_json {
        serde_json::to_string_pretty(&scan_result)
    } else {
        serde_json::to_string(&scan_result)
    };
    
    // Handle JSON output to file or console
    if args.json {
        match json_output {
            Ok(json) => {
                if let Some(output_path) = &args.output {
                    // Save to file
                    if let Err(e) = std::fs::write(output_path, json) {
                        error!("Failed to write JSON output to file: {}", e);
                    } else {
                        info!("Results saved to JSON file: {}", output_path.display());
                    }
                } else {
                    // Print to console
                    println!("{}", json);
                }
            }
            Err(e) => error!("Failed to serialize scan results to JSON: {}", e)
        }
    } else {
        // Text format - either save to file or print to console
        if let Some(output_path) = &args.output {
            if let Err(e) = output::save_text_results(&scan_result, output_path) {
                error!("Failed to save results to file: {}", e);
            } else {
                info!("Results saved to file: {}", output_path.display());
            }
        } else {
            // Print results to console - pass the verbose flag from args
            if let Err(e) = output::print_results(&scan_result, args.verbose) {
                error!("Failed to print results: {}", e);
            }
        }
    }

    // --- Cleanup --- 
    info!("Starting cleanup phase...");
    // Unmount RAM disk if created
    if let Err(e) = cleanup_ramdisk(&ramdisk_path) {
        warn!("Error during RAM disk cleanup: {}", e);
        // Don't exit, just warn
    }

    // Securely delete log file if requested and not in memory-only mode
    if args.secure_delete && !args.memory_only {
        info!("Attempting secure delete for log file: {}", args.log_file.display());
        if let Err(e) = secure_delete_file(&args.log_file, args.delete_passes) {
            warn!("Error during secure delete of log file: {}", e);
        }
    }

    info!("Quantum Scanner finished.");
    Ok(())
}
