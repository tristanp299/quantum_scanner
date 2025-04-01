use clap::{Parser, ValueEnum};
use log::{error, info};
use std::path::PathBuf;
use std::process;

mod scanner;
mod models;
mod techniques;
mod utils;
mod output;

use scanner::QuantumScanner;
use models::{ScanType, PortRange};

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

    /// Scan techniques to use
    #[clap(short, long, value_enum, use_value_delimiter = true, value_delimiter = ',', default_value = "syn")]
    scan_types: Vec<ScanTypeArg>,

    /// Maximum concurrent operations
    #[clap(short, long, default_value_t = 100)]
    concurrency: usize,

    /// Maximum packets per second
    #[clap(short = 'r', long, default_value_t = 500)]
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

/// Initialize logging with proper configuration
fn setup_logging(log_file: &PathBuf, verbose: bool) -> Result<(), anyhow::Error> {
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
    
    // Initialize the logger
    env_logger::Builder::from_default_env()
        .format_timestamp_secs()
        .format_module_path(true)
        .format_target(false)
        .target(env_logger::Target::Pipe(Box::new(
            std::fs::File::create(log_file)?
        )))
        .init();
    
    Ok(())
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

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    // Parse command-line arguments
    let args = Args::parse();
    
    // Setup logging
    if let Err(e) = setup_logging(&args.log_file, args.verbose) {
        eprintln!("Warning: Failed to set up logging: {}", e);
    }
    
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
    let ports: Vec<u16> = port_ranges.into_iter().collect();
    if ports.is_empty() {
        error!("No valid ports specified");
        eprintln!("Error: No valid ports specified");
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
    
    // Create scanner instance
    let mut scanner = QuantumScanner::new(
        &args.target,
        ports,
        scan_types,
        args.concurrency,
        args.rate,
        args.evasion,
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
    )?;
    
    // Run the scan
    info!("Starting scan of {} with {} ports", args.target, ports.len());
    let results = scanner.run_scan().await?;
    
    // Output results
    if let Some(output_path) = args.output {
        if args.json {
            output::save_json_results(&results, &output_path)?;
        } else {
            output::save_text_results(&results, &output_path)?;
        }
    }
    
    Ok(())
}
