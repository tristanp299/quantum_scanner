use clap::{Parser, ValueEnum};
use log::{error, info, warn};
use std::path::PathBuf;
use std::process;
use std::time::Duration;
use rand::{thread_rng, Rng};
use std::env;
use std::sync::Arc;

mod scanner;
mod models;
mod techniques;
mod utils;
mod output;

use scanner::QuantumScanner;
use models::{ScanType, PortRange, PortRanges, PortStatus, TopPorts};

/// Advanced port scanner with evasion capabilities
#[derive(Parser)]
#[clap(author, version, about, long_about = None)]
struct Args {
    /// Target IP address, hostname, or CIDR notation for subnet
    #[clap(value_parser)]
    target: String,

    /// Ports to scan (comma-separated, ranges like 1-1000)
    #[clap(short, long, default_value = "1-1000")]
    ports: String,

    /// Enable memory-only mode (no disk writes)
    #[clap(short = 'm', long)]
    memory_only: bool,

    /// Scan techniques to use
    #[clap(short, long, value_enum, use_value_delimiter = true, value_delimiter = ',', default_value = "syn")]
    scan_types: Vec<ScanTypeArg>,

    /// Maximum concurrent operations
    #[clap(short, long, default_value_t = 100)]
    concurrency: usize,

    /// Maximum packets per second
    #[clap(short = 'r', long, default_value_t = 0)]
    rate: usize,

    /// Enable evasion techniques
    #[clap(short, long)]
    evasion: bool,

    /// Enable verbose output
    #[clap(short, long)]
    verbose: bool,

    /// Use IPv6
    #[clap(short = '6', long)]
    ipv6: bool,

    /// Output results in JSON format
    #[clap(short = 'j', long)]
    json: bool,

    /// Write results to file
    #[clap(short, long)]
    output: Option<PathBuf>,

    /// Scan timeout in seconds
    #[clap(short, long, default_value_t = 3.0)]
    timeout: f64,

    /// Connect timeout in seconds
    #[clap(long, default_value_t = 3.0)]
    timeout_connect: f64,

    /// Banner grabbing timeout in seconds
    #[clap(long, default_value_t = 3.0)]
    timeout_banner: f64,

    /// Protocol to mimic in mimic scans
    #[clap(long, default_value = "HTTP")]
    mimic_protocol: String,

    /// Minimum fragment size for fragmented scans
    #[clap(long, default_value_t = 24)]
    frag_min_size: u16,

    /// Maximum fragment size for fragmented scans
    #[clap(long, default_value_t = 64)]
    frag_max_size: u16,

    /// Minimum delay between fragments in seconds
    #[clap(long, default_value_t = 0.01)]
    frag_min_delay: f64,

    /// Maximum delay between fragments in seconds
    #[clap(long, default_value_t = 0.1)]
    frag_max_delay: f64,

    /// Timeout for fragmented scans in seconds
    #[clap(long, default_value_t = 10)]
    frag_timeout: u64,

    /// Minimum size of first fragment
    #[clap(long, default_value_t = 64)]
    frag_first_min_size: u16,

    /// Use exactly two fragments
    #[clap(long)]
    frag_two_frags: bool,

    /// Log file path
    #[clap(long, default_value = "scanner.log")]
    log_file: PathBuf,
    
    /// Encrypt logs with a password
    #[clap(long, default_value_t = true)]
    encrypt_logs: bool,
    
    /// Password for log encryption
    #[clap(long)]
    log_password: Option<String>,
    
    /// Enable enhanced evasion techniques
    #[clap(long, default_value_t = true)]
    enhanced_evasion: bool,
    
    /// Operating system to mimic in enhanced evasion mode
    #[clap(long)]
    mimic_os: Option<String>,
    
    /// TTL jitter amount for enhanced evasion (1-5)
    #[clap(long, default_value_t = 2)]
    ttl_jitter: u8,
    
    /// Protocol variant for protocol mimicry
    #[clap(long)]
    protocol_variant: Option<String>,
    
    /// Add randomized delay before scan start (0-5 seconds)
    #[clap(long, default_value_t = true)]
    random_delay: bool,
    
    /// Maximum random delay in seconds
    #[clap(long, default_value_t = 3)]
    max_delay: u64,
    
    /// Route traffic through Tor if available
    #[clap(long, default_value_t = true)]
    use_tor: bool,
    
    /// Create RAM disk for temporary files
    #[clap(long, default_value_t = true)]
    use_ramdisk: bool,
    
    /// RAM disk size in MB
    #[clap(long, default_value_t = 10)]
    ramdisk_size: u64,
    
    /// RAM disk mount point
    #[clap(long, default_value = "/mnt/quantum_scanner_ramdisk")]
    ramdisk_mount: PathBuf,
    
    /// Use ANSI colors in output
    #[clap(long, default_value_t = true)]
    color: bool,
    
    /// Securely delete files after scan
    #[clap(long, default_value_t = true)]
    secure_delete: bool,
    
    /// Number of secure delete passes
    #[clap(long, default_value_t = 3)]
    delete_passes: u8,

    /// Scan the top 100 common ports
    #[clap(short = 't', long)]
    top_100: bool,
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
    TlsEcho,
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
            ScanTypeArg::TlsEcho => ScanType::TlsEcho,
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
fn setup_logging(log_file: &PathBuf, verbose: bool, memory_only: bool, encrypt_logs: bool, log_password: Option<&str>) -> Result<Option<utils::MemoryLogBuffer>, anyhow::Error> {
    // Setup memory logger if memory-only mode is enabled
    if memory_only {
        // When in memory-only mode, do not create any log files on disk
        info!("Running in memory-only mode - logs will not be written to disk");
        
        // Create memory logger with encryption if specified
        let buffer = utils::MemoryLogBuffer::new(10000, encrypt_logs);
        
        // Configure environment variable for env_logger
        let log_level = if verbose { "debug" } else { "info" };
        std::env::set_var("RUST_LOG", log_level);
        
        // Log initialization message
        buffer.log("INFO", &format!("Quantum Scanner started in memory-only mode"));
        if verbose {
            buffer.log("DEBUG", "Verbose logging enabled");
        }
        
        return Ok(Some(buffer));
    }
    
    // Normal file-based logging
    
    // Create log directory if needed
    if let Some(parent) = log_file.parent() {
        if !parent.exists() {
            std::fs::create_dir_all(parent)?;
        }
    }

    // Set log level based on verbosity
    let log_level = if verbose { "debug" } else { "info" };
    
    // Configure environment variable for env_logger
    std::env::set_var("RUST_LOG", log_level);
    
    // If encryption is enabled, we'll need to intercept logs
    if encrypt_logs {
        // We need a custom logger for encryption
        // For simplicity in this implementation, we'll disable encryption for normal file mode
        // A full implementation would use a custom log appender with encryption
        warn!("Log encryption is only fully supported in memory-only mode");
    }
    
    // Initialize the logger with disk file
    info!("Running in disk mode - logs will be written to {}", log_file.display());
    env_logger::Builder::from_default_env()
        .format_timestamp_secs()
        .format_module_path(true)
        .format_target(false)
        .target(env_logger::Target::Pipe(Box::new(
            std::fs::File::create(log_file)?
        )))
        .init();
    
    Ok(None)
}

/// Check if we have sufficient privileges for raw sockets
fn check_privileges(scanner_needs_raw_sockets: bool) -> bool {
    if !scanner_needs_raw_sockets {
        return true;
    }
    
    #[cfg(unix)]
    {
        // On Unix systems, check effective user ID
        unsafe { libc::geteuid() == 0 }
    }
    
    #[cfg(windows)]
    {
        // On Windows, this is more complex and not reliable
        // For a real implementation, use IsUserAnAdmin or similar
        // This is a simplified version
        true
    }
    
    #[cfg(not(any(unix, windows)))]
    {
        // Unknown platform - assume not privileged
        false
    }
}

/// Check if Tor is available and set up LD_PRELOAD if needed
fn setup_tor_routing(use_tor: bool) -> bool {
    if !use_tor {
        return false;
    }
    
    // Check if Tor is installed and running
    #[cfg(unix)]
    {
        // Try to find the tor process
        if std::process::Command::new("pgrep")
            .arg("tor")
            .output()
            .map(|output| output.status.success())
            .unwrap_or(false)
        {
            // Check if libtsocks is available
            if std::path::Path::new("/usr/lib/x86_64-linux-gnu/libtsocks.so").exists() {
                // Set LD_PRELOAD environment variable for Tor routing
                std::env::set_var("LD_PRELOAD", "/usr/lib/x86_64-linux-gnu/libtsocks.so");
                return true;
            }
        }
    }
    
    false
}

/// Create a RAM disk for temporary files
fn create_ramdisk(use_ramdisk: bool, mount_point: &PathBuf, size_mb: u64) -> Result<Option<PathBuf>, anyhow::Error> {
    if !use_ramdisk {
        return Ok(None);
    }
    
    #[cfg(unix)]
    {
        // Check if we have root privileges
        if unsafe { libc::geteuid() != 0 } {
            warn!("RAM disk creation requires root privileges");
            return Ok(None);
        }
        
        // Create mount point directory
        std::fs::create_dir_all(mount_point)?;
        
        // Mount a tmpfs filesystem
        let status = std::process::Command::new("mount")
            .args([
                "-t", "tmpfs",
                "-o", &format!("size={}M,mode=0700", size_mb),
                "tmpfs",
                mount_point.to_str().unwrap()
            ])
            .status()?;
        
        if status.success() {
            info!("Created RAM disk at {}", mount_point.display());
            return Ok(Some(mount_point.clone()));
        } else {
            warn!("Failed to create RAM disk");
        }
    }
    
    Ok(None)
}

/// Unmount a RAM disk
fn cleanup_ramdisk(ramdisk: &Option<PathBuf>) -> Result<(), anyhow::Error> {
    if let Some(mount_point) = ramdisk {
        #[cfg(unix)]
        {
            let status = std::process::Command::new("umount")
                .arg(mount_point)
                .status()?;
            
            if status.success() {
                info!("Unmounted RAM disk at {}", mount_point.display());
                // Try to remove the directory
                let _ = std::fs::remove_dir(mount_point);
            } else {
                warn!("Failed to unmount RAM disk at {}", mount_point.display());
            }
        }
    }
    
    Ok(())
}

/// Securely delete a file using available utilities or fallback methods
fn secure_delete_file(path: &PathBuf, passes: u8) -> Result<(), anyhow::Error> {
    if !path.exists() {
        return Ok(());
    }
    
    #[cfg(unix)]
    {
        // Try using 'shred' first
        if std::process::Command::new("which")
            .arg("shred")
            .output()
            .map(|output| output.status.success())
            .unwrap_or(false) 
        {
            let status = std::process::Command::new("shred")
                .args(["-uzn", &passes.to_string(), path.to_str().unwrap()])
                .status()?;
            
            if status.success() {
                return Ok(());
            }
        }
        
        // Try using 'wipe' next
        if std::process::Command::new("which")
            .arg("wipe")
            .output()
            .map(|output| output.status.success())
            .unwrap_or(false) 
        {
            let status = std::process::Command::new("wipe")
                .args(["-f", path.to_str().unwrap()])
                .status()?;
            
            if status.success() {
                return Ok(());
            }
        }
        
        // Try using 'srm' next
        if std::process::Command::new("which")
            .arg("srm")
            .output()
            .map(|output| output.status.success())
            .unwrap_or(false) 
        {
            let status = std::process::Command::new("srm")
                .args(["-z", path.to_str().unwrap()])
                .status()?;
            
            if status.success() {
                return Ok(());
            }
        }
        
        // Fallback: overwrite with random data and delete
        let file = std::fs::OpenOptions::new()
            .write(true)
            .open(path)?;
        
        // Get file size
        let metadata = file.metadata()?;
        let size = metadata.len();
        
        // Create buffer of random data
        let mut rng = thread_rng();
        let mut buffer = vec![0u8; std::cmp::min(size as usize, 1024)];
        
        // Overwrite file for specified number of passes
        for _ in 0..passes {
            for chunk in buffer.chunks_mut(1024) {
                rng.fill(chunk);
            }
            
            let _ = std::process::Command::new("dd")
                .args([
                    "if=/dev/urandom",
                    &format!("of={}", path.to_str().unwrap()),
                    "bs=1k",
                    &format!("count={}", (size + 1023) / 1024), // Round up
                    "conv=notrunc"
                ])
                .output()?;
        }
        
        // Finally, delete the file
        std::fs::remove_file(path)?;
    }
    
    #[cfg(not(unix))]
    {
        // On non-Unix platforms, just delete the file
        std::fs::remove_file(path)?;
    }
    
    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    // Parse command-line arguments
    let mut args = Args::parse();
    
    // Setup colors for output
    let colors = Colors::new(args.color);
    
    // Display banner
    if args.color {
        println!("{}╔══════════════════════════════════════════╗{}", colors.blue, colors.reset);
        println!("{}║     {}Quantum Scanner{} - {}Enhanced Edition{}     ║{}", 
            colors.blue, colors.green, colors.blue, colors.yellow, colors.blue, colors.reset);
        println!("{}╚══════════════════════════════════════════╝{}", colors.blue, colors.reset);
    } else {
        println!("┌──────────────────────────────────────────┐");
        println!("│      Quantum Scanner - Enhanced Edition      │");
        println!("└──────────────────────────────────────────┘");
    }
    
    // Setup Tor routing if available and enabled
    let tor_enabled = setup_tor_routing(args.use_tor);
    if tor_enabled {
        println!("[{}+{}] Routing traffic through Tor", colors.green, colors.reset);
    }
    
    // Check for RAM disk support for temporary files
    let ramdisk = if args.memory_only && args.use_ramdisk {
        match create_ramdisk(args.use_ramdisk, &args.ramdisk_mount, args.ramdisk_size) {
            Ok(Some(path)) => {
                println!("[{}+{}] Created RAM disk for temporary files at {}", 
                    colors.green, colors.reset, path.display());
                
                // Use RAM disk for log file
                args.log_file = path.join("scanner.log");
                Some(path)
            },
            Ok(None) => None,
            Err(e) => {
                println!("[{}!{}] Failed to create RAM disk: {}", colors.yellow, colors.reset, e);
                None
            }
        }
    } else {
        None
    };
    
    // Add random delay before scan if enabled
    if args.random_delay {
        let delay = thread_rng().gen_range(0..args.max_delay);
        if delay > 0 {
            println!("[{}+{}] Adding random delay before scan: {}s", 
                colors.green, colors.reset, delay);
            tokio::time::sleep(Duration::from_secs(delay)).await;
        }
    }
    
    // Use randomized packet rate if not specified
    if args.rate == 0 {
        args.rate = thread_rng().gen_range(100..500);
        println!("[{}+{}] Using randomized packet rate: {} pps", 
            colors.green, colors.reset, args.rate);
    }
    
    // Randomly select OS to mimic if not specified
    if args.mimic_os.is_none() {
        let os_types = ["windows", "linux", "macos", "random"];
        args.mimic_os = Some(os_types[thread_rng().gen_range(0..os_types.len())].to_string());
        println!("[{}+{}] Mimicking OS: {}", 
            colors.green, colors.reset, args.mimic_os.as_ref().unwrap());
    }
    
    // Select protocol variant for mimic scans if applicable and not specified
    if args.scan_types.contains(&ScanTypeArg::Mimic) && args.protocol_variant.is_none() {
        let variants = ["1.0", "1.1", "2.0"];
        args.protocol_variant = Some(variants[thread_rng().gen_range(0..variants.len())].to_string());
        println!("[{}+{}] Using HTTP/{} for protocol mimicry", 
            colors.green, colors.reset, args.protocol_variant.as_ref().unwrap());
    }
    
    // Setup logging with memory-only option
    let memory_logger = match setup_logging(
        &args.log_file, 
        args.verbose, 
        args.memory_only,
        args.encrypt_logs,
        args.log_password.as_deref()
    ) {
        Ok(logger) => logger,
        Err(e) => {
            eprintln!("Warning: Failed to set up logging: {}", e);
            None
        }
    };
    
    // Log memory-only mode info
    if args.memory_only {
        println!("[{}+{}] Running in memory-only mode - logs will be kept in memory only", 
            colors.green, colors.reset);
    } else {
        println!("[{}+{}] Running in disk mode - logs will be written to {}", 
            colors.green, colors.reset, args.log_file.display());
    }
    
    // Log enhanced evasion status
    if args.enhanced_evasion {
        println!("[{}+{}] Enhanced evasion techniques enabled", colors.green, colors.reset);
    }
    
    // Handle port selection, prioritizing top_100 over ports parameter if specified
    let ports_to_scan: Vec<u16> = if args.top_100 {
        let top_ports = TopPorts::top_100();
        println!("[{}+{}] Using top 100 common ports for scanning", colors.green, colors.reset);
        top_ports
    } else {
        // Parse port ranges
        let port_ranges = match PortRange::parse(&args.ports) {
            Ok(ranges) => ranges,
            Err(e) => {
                error!("Failed to parse port ranges: {}", e);
                eprintln!("Error: Invalid port range specification");
                process::exit(1);
            }
        };
        
        // Expand port ranges into a list of ports
        PortRanges::new(port_ranges).into_iter().collect()
    };
    
    if ports_to_scan.is_empty() {
        error!("No valid ports specified");
        eprintln!("Error: Invalid port range specification");
        process::exit(1);
    }
    
    // Convert scan type args to ScanType model
    let scan_types: Vec<ScanType> = args.scan_types.into_iter()
        .map(ScanType::from)
        .collect();
    
    // Check if we need raw socket privileges
    let needs_raw_sockets = scanner::requires_raw_sockets(&scan_types);
    if needs_raw_sockets && !check_privileges(needs_raw_sockets) {
        error!("This scan requires root/administrator privileges");
        eprintln!("Error: This scan requires root/administrator privileges");
        process::exit(1);
    }
    
    // Create scanner instance with enhanced evasion options
    let mut scanner = QuantumScanner::new(
        &args.target,
        ports_to_scan.clone(),
        scan_types,
        args.concurrency,
        args.rate,
        // Use enhanced evasion if specified
        args.evasion || args.enhanced_evasion,
        args.verbose,
        args.ipv6,
        args.json,
        args.timeout,
        args.timeout_connect,
        args.timeout_banner,
        &args.mimic_protocol,
        args.frag_min_size,
        args.frag_max_size,
        args.frag_min_delay,
        args.frag_max_delay,
        args.frag_timeout,
        args.frag_first_min_size,
        args.frag_two_frags,
        &args.log_file,
    ).await?;
    
    // Set enhanced evasion options
    if args.enhanced_evasion {
        scanner.set_enhanced_evasion(true, args.mimic_os.as_deref().unwrap_or("random"), args.ttl_jitter);
        scanner.set_protocol_variant(args.protocol_variant.as_deref());
    }
    
    // Set memory logger if available
    if let Some(logger) = memory_logger.clone() {
        scanner.set_memory_log(Arc::new(logger));
    }
    
    // Run the scan
    println!("[{}+{}] Starting scan of {} with {} ports", 
        colors.green, colors.reset, args.target, ports_to_scan.len());
    println!("{}════════════════════════════════════════════{}", colors.blue, colors.reset);
    
    let results = scanner.run_scan().await?;
    
    // Output results based on mode
    println!("{}════════════════════════════════════════════{}", colors.blue, colors.reset);
    println!("[{}+{}] Scan completed. Found {} open ports", 
        colors.green, colors.reset, results.open_ports.len());
    
    // Display results
    for port in results.open_ports.iter().cloned().collect::<Vec<_>>() {
        if let Some(result) = results.results.get(&port) {
            let status = result.tcp_states.values().next().unwrap_or(&PortStatus::Filtered);
            println!("Port {}:{} {}", port, colors.green, colors.reset);
            
            if let Some(service) = &result.service {
                println!("  Service: {}", service);
            }
            
            if let Some(version) = &result.version {
                println!("  Version: {}", version);
            }
        }
    }
    
    // Output to file if requested
    if let Some(output_path) = args.output {
        if args.json {
            output::save_json_results(&results, &output_path)?;
            println!("[{}+{}] Results saved to {} in JSON format", 
                colors.green, colors.reset, output_path.display());
        } else {
            output::save_text_results(&results, &output_path)?;
            println!("[{}+{}] Results saved to {}", 
                colors.green, colors.reset, output_path.display());
        }
    }
    
    // Print memory log summary if available
    if let Some(logger) = memory_logger {
        if args.verbose {
            println!("\nLog entries: {}", logger.len());
            println!("Log contents:");
            println!("{}", logger.format_logs(true));
        }
    }
    
    // Cleanup phase
    if args.memory_only && args.secure_delete {
        println!("[{}+{}] Performing secure cleanup...", colors.green, colors.reset);
        
        // Delete log file if it exists
        if args.log_file.exists() && !args.memory_only {
            match secure_delete_file(&args.log_file, args.delete_passes) {
                Ok(_) => println!("[{}+{}] Securely deleted log file", colors.green, colors.reset),
                Err(e) => println!("[{}!{}] Failed to securely delete log file: {}", 
                    colors.yellow, colors.reset, e),
            }
        }
        
        // Cleanup RAM disk if created
        if let Some(_) = ramdisk {
            cleanup_ramdisk(&ramdisk)?;
        }
    }
    
    println!("{}Quantum Scanner operation complete{}", colors.green, colors.reset);
    
    Ok(())
}
