use clap::Parser;

/// Simple test program for quantum_scanner
#[derive(Parser)]
#[clap(author, version, about, long_about = None, name = "quantum_test")]
struct Args {
    /// Target to scan
    target: String,
    
    /// Enable verbose output
    #[clap(short, long)]
    verbose: bool,
}

fn main() {
    // Print startup message
    println!("Quantum Scanner - Minimal Test Program");
    
    // Parse command line arguments
    let args = Args::parse();
    
    // Output the parsed arguments
    println!("Target: {}", args.target);
    println!("Verbose: {}", args.verbose);
    
    // Exit successfully
    println!("Test completed successfully!");
} 