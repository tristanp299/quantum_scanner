use std::fs::File;
use std::io::{self, Write};
use std::path::Path;

use anyhow::{Context, Result};
use chrono::Utc;
use console::{style, Term};
use log::debug;
use serde_json;

use crate::models::{PortResult, PortStatus, ScanResults, ScanType};
use crate::utils::sanitize_string;

/// Save scan results to a JSON file
///
/// # Arguments
/// * `results` - The scan results to save
/// * `output_path` - Path to the output file
///
/// # Returns
/// * `Result<()>` - Success or error
pub fn save_json_results(results: &ScanResults, output_path: &Path) -> Result<()> {
    let json = serde_json::to_string_pretty(results)?;
    let mut file = File::create(output_path)
        .with_context(|| format!("Failed to create output file: {:?}", output_path))?;
    
    file.write_all(json.as_bytes())
        .with_context(|| format!("Failed to write to output file: {:?}", output_path))?;
    
    Ok(())
}

/// Save scan results as formatted text
///
/// # Arguments
/// * `results` - The scan results to save
/// * `output_path` - Path to the output file
///
/// # Returns
/// * `Result<()>` - Success or error
pub fn save_text_results(results: &ScanResults, output_path: &Path) -> Result<()> {
    let mut file = File::create(output_path)
        .with_context(|| format!("Failed to create output file: {:?}", output_path))?;
    
    // Format header
    let header = format!(
        "# Quantum Scanner Results\n\
         Target: {}\n\
         IP: {}\n\
         Scan Time: {} to {}\n\
         Scan Types: {}\n\
         Open Ports: {}\n\n",
        results.target,
        results.target_ip,
        results.start_time.format("%Y-%m-%d %H:%M:%S"),
        results.end_time.format("%Y-%m-%d %H:%M:%S"),
        results.scan_types.iter()
            .map(|st| format!("{}", st))
            .collect::<Vec<_>>()
            .join(", "),
        results.open_ports.len()
    );
    
    file.write_all(header.as_bytes())?;
    
    // Format each port result
    if results.open_ports.is_empty() {
        file.write_all(b"No open ports found.\n")?;
    } else {
        file.write_all(b"## Open Ports\n\n")?;
        
        let mut ports: Vec<_> = results.open_ports.iter().collect();
        ports.sort_unstable();
        
        for &port in ports {
            if let Some(port_result) = results.results.get(port) {
                format_port_text(&mut file, port, port_result)?;
            }
        }
    }
    
    Ok(())
}

/// Format a single port result as text
fn format_port_text(file: &mut File, port: u16, result: &PortResult) -> Result<()> {
    // Basic port info
    let port_header = format!(
        "### Port {}\n\
         Service: {}\n",
        port,
        result.service.as_deref().unwrap_or("unknown")
    );
    
    file.write_all(port_header.as_bytes())?;
    
    // Version if available
    if let Some(version) = &result.version {
        writeln!(file, "Version: {}", version)?;
    }
    
    // Scan results for each technique
    if !result.tcp_states.is_empty() {
        file.write_all(b"\nTCP Scan Results:\n")?;
        for (scan_type, status) in &result.tcp_states {
            writeln!(file, "- {}: {}", scan_type, status)?;
        }
    }
    
    // UDP result if available
    if let Some(udp_status) = &result.udp_state {
        writeln!(file, "\nUDP: {}", udp_status)?;
    }
    
    // Firewall filtering
    if let Some(filtering) = &result.filtering {
        writeln!(file, "Filtering: {}", filtering)?;
    }
    
    // Banner if available
    if let Some(banner) = &result.banner {
        writeln!(file, "\nBanner: {}", sanitize_string(banner))?;
    }
    
    // Certificate info if available
    if let Some(cert) = &result.cert_info {
        file.write_all(b"\nSSL Certificate:\n")?;
        writeln!(file, "- Subject: {}", cert.subject)?;
        writeln!(file, "- Issuer: {}", cert.issuer)?;
        writeln!(file, "- Valid: {} to {}", 
            cert.not_before.format("%Y-%m-%d"),
            cert.not_after.format("%Y-%m-%d")
        )?;
        writeln!(file, "- Algorithm: {}", cert.signature_algorithm)?;
        if let Some(bits) = cert.public_key_bits {
            writeln!(file, "- Key: {} {} bits", 
                cert.key_algorithm.as_deref().unwrap_or("Unknown"),
                bits
            )?;
        }
    }
    
    // Vulnerabilities if found
    if !result.vulns.is_empty() {
        file.write_all(b"\nPotential Vulnerabilities:\n")?;
        for vuln in &result.vulns {
            writeln!(file, "- {}", vuln)?;
        }
    }
    
    // Add a separator
    file.write_all(b"\n----------\n\n")?;
    
    Ok(())
}

/// Print scan results to the terminal
///
/// # Arguments
/// * `results` - The scan results to display
pub fn print_results(results: &ScanResults) -> Result<()> {
    let term = Term::stdout();
    term.clear_screen()?;
    
    // Print header
    println!("{}", style("Quantum Scanner Results").cyan().bold());
    println!("Target: {} ({})", style(&results.target).green(), results.target_ip);
    println!("Scan Time: {} to {}", 
        results.start_time.format("%H:%M:%S"),
        results.end_time.format("%H:%M:%S")
    );
    println!("Scan Duration: {:.2} seconds", 
        (results.end_time - results.start_time).num_milliseconds() as f64 / 1000.0
    );
    
    println!("\n{} open ports discovered", style(results.open_ports.len()).yellow().bold());
    
    // If no open ports, end here
    if results.open_ports.is_empty() {
        println!("\nNo open ports found on target.");
        return Ok(());
    }
    
    // Print open ports summary
    println!("\n{}", style("PORT     STATE  SERVICE  VERSION").underlined());
    
    let mut ports: Vec<_> = results.open_ports.iter().collect();
    ports.sort_unstable();
    
    for &port in ports {
        if let Some(result) = results.results.get(port) {
            print_port_summary(port, result);
        }
    }
    
    // Print detailed information for interesting ports
    print_detailed_results(results)?;
    
    Ok(())
}

/// Print a summary line for a single port
fn print_port_summary(port: u16, result: &PortResult) {
    // Get the first "open" state
    let state = result.tcp_states.iter()
        .find(|(_, status)| **status == PortStatus::Open)
        .map(|(_, status)| status.to_string())
        .unwrap_or_else(|| "open".to_string());
    
    // Format the line
    println!("{:<8} {:<6} {:<8} {}", 
        style(port).green().bold(),
        state,
        result.service.as_deref().unwrap_or("-"),
        result.version.as_deref().unwrap_or("-")
    );
}

/// Print detailed information for interesting ports
fn print_detailed_results(results: &ScanResults) -> Result<()> {
    let mut ports: Vec<_> = results.open_ports.iter().collect();
    ports.sort_unstable();
    
    for &port in ports {
        if let Some(result) = results.results.get(port) {
            // Only print detailed info if there's something interesting
            let has_details = result.banner.is_some() || 
                              result.cert_info.is_some() || 
                              !result.vulns.is_empty();
            
            if has_details {
                println!("\n{} {}", style("Details for port").cyan().bold(), style(port).green().bold());
                
                // Print banner if available (truncated)
                if let Some(banner) = &result.banner {
                    let truncated = if banner.len() > 200 {
                        format!("{}... [truncated]", &banner[..200])
                    } else {
                        banner.clone()
                    };
                    println!("  Banner: {}", sanitize_string(&truncated));
                }
                
                // Print certificate info
                if let Some(cert) = &result.cert_info {
                    println!("  SSL Certificate:");
                    println!("    Subject: {}", cert.subject);
                    println!("    Issuer: {}", cert.issuer);
                    println!("    Valid: {} to {}", 
                        cert.not_before.format("%Y-%m-%d"),
                        cert.not_after.format("%Y-%m-%d")
                    );
                    
                    // Check if cert is expired
                    let now = Utc::now();
                    if now < cert.not_before {
                        println!("    {}", style("Certificate not yet valid!").red().bold());
                    } else if now > cert.not_after {
                        println!("    {}", style("Certificate expired!").red().bold());
                    }
                }
                
                // Print vulnerabilities
                if !result.vulns.is_empty() {
                    println!("  {}", style("Potential Vulnerabilities:").red().bold());
                    for vuln in &result.vulns {
                        println!("    - {}", vuln);
                    }
                }
            }
        }
    }
    
    Ok(())
}

/// Format a time duration as a human-readable string
fn format_duration(seconds: f64) -> String {
    if seconds < 0.001 {
        format!("{:.2} μs", seconds * 1_000_000.0)
    } else if seconds < 1.0 {
        format!("{:.2} ms", seconds * 1_000.0)
    } else if seconds < 60.0 {
        format!("{:.2} sec", seconds)
    } else {
        let minutes = (seconds / 60.0).floor();
        let secs = seconds - (minutes * 60.0);
        format!("{}m {:.2}s", minutes as u32, secs)
    }
} 