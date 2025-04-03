use clap::{Parser, ValueEnum};

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
}

fn main() {
    // Check for help flag manually
    if std::env::args().any(|arg| arg == "--help" || arg == "-h") {
        println!("Help flag detected, clap will display help info");
        let _ = Args::parse(); // This will display help and exit
        return;
    }
    
    println!("Program execution would continue here if no help flag was present");
    
    // Parse command-line arguments normally
    let args = Args::parse();
    
    println!("Parsed arguments: target={}, ports={}", args.target, args.ports);
} 