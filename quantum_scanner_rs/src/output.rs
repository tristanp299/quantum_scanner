use std::fs::File;
use std::io::Write;
use std::path::Path;
use std::collections::HashMap;

use anyhow::{Context, Result};
use chrono::Utc;
use console::{style, Term};
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

/// Convert scan results to a simple text report format
pub fn format_text_results(results: &ScanResults) -> String {
    let mut output = String::new();
    
    // Header
    output.push_str(&format!("# Quantum Scanner Report\n"));
    output.push_str(&format!("Target: {}\n", results.target));
    output.push_str(&format!("IP: {}\n", results.target_ip));
    output.push_str(&format!("Timestamp: {}\n", Utc::now()));
    output.push_str(&format!("Scan Duration: {:.2} seconds\n", 
        results.end_time.signed_duration_since(results.start_time).num_milliseconds() as f64 / 1000.0));
    
    // Scan types used
    output.push_str("Scan types: ");
    for (i, scan_type) in results.scan_types.iter().enumerate() {
        if i > 0 {
            output.push_str(", ");
        }
        output.push_str(&scan_type.to_string());
    }
    output.push_str("\n\n");
    
    // Open ports summary
    output.push_str(&format!("## Open Ports Summary\n"));
    if results.open_ports.is_empty() {
        output.push_str("No open ports found\n\n");
    } else {
        output.push_str(&format!("Found {} open ports:\n\n", results.open_ports.len()));
        output.push_str("PORT      STATE   SERVICE         VERSION\n");
        output.push_str("----------------------------------------------------\n");
        
        // Sort ports for consistent output
        let mut ports: Vec<u16> = results.open_ports.iter().copied().collect();
        ports.sort_unstable();
        
        for port in ports {
            if let Some(port_result) = results.results.get(&port) {
                // Find the first open state
                let state = if port_result.tcp_states.values().any(|s| *s == PortStatus::Open) {
                    "open"
                } else if port_result.udp_state == Some(PortStatus::Open) {
                    "open/udp"
                } else {
                    "open|filtered"
                };
                
                let service = port_result.service.as_deref().unwrap_or("unknown");
                let version = port_result.version.as_deref().unwrap_or("");
                
                output.push_str(&format!("{:<9} {:<7} {:<15} {}\n", 
                    port, state, service, version));
            }
        }
        output.push_str("\n");
    }
    
    // Detailed port information
    output.push_str("## Port Details\n\n");
    
    // Sort ports for consistent output
    let mut all_ports: Vec<u16> = results.results.keys().copied().collect();
    all_ports.sort_unstable();
    
    for port in all_ports {
        let port_result = &results.results[&port];
        
        // Skip ports with no interesting results
        let has_data = !port_result.tcp_states.is_empty() 
            || port_result.udp_state.is_some()
            || port_result.banner.is_some()
            || port_result.cert_info.is_some();
            
        if !has_data {
            continue;
        }
        
        output.push_str(&format!("### Port {}\n", port));
        
        // Service information
        if let Some(service) = &port_result.service {
            output.push_str(&format!("Service: {}\n", service));
        }
        
        if let Some(version) = &port_result.version {
            output.push_str(&format!("Version: {}\n", version));
        }
        
        // States by scan type
        if !port_result.tcp_states.is_empty() {
            output.push_str("TCP States:\n");
            for (scan_type, status) in &port_result.tcp_states {
                output.push_str(&format!("  - {} scan: {}\n", scan_type, status));
            }
        }
        
        if let Some(udp_state) = &port_result.udp_state {
            output.push_str(&format!("UDP State: {}\n", udp_state));
        }
        
        // Banner if available
        if let Some(banner) = &port_result.banner {
            output.push_str("Banner:\n");
            // Sanitize and format the banner
            let sanitized = sanitize_banner(banner);
            for line in sanitized.lines().take(5) {
                output.push_str(&format!("  {}\n", line));
            }
        }
        
        // Certificate info if available
        if let Some(cert) = &port_result.cert_info {
            output.push_str("SSL/TLS Certificate:\n");
            output.push_str(&format!("  Subject: {}\n", cert.subject));
            output.push_str(&format!("  Issuer: {}\n", cert.issuer));
            output.push_str(&format!("  Valid from: {}\n", cert.not_before));
            output.push_str(&format!("  Valid until: {}\n", cert.not_after));
            
            if !cert.alt_names.is_empty() {
                output.push_str("  Alternative Names:\n");
                for name in &cert.alt_names {
                    output.push_str(&format!("    - {}\n", name));
                }
            }
        }
        
        // Vulnerabilities if found
        if !port_result.vulns.is_empty() {
            output.push_str("Vulnerabilities:\n");
            for vuln in &port_result.vulns {
                output.push_str(&format!("  - {}\n", vuln));
            }
        }
        
        output.push_str("\n");
    }
    
    output
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
    let text = format_text_results(results);
    let mut file = File::create(output_path)
        .context(format!("Failed to create output file: {:?}", output_path))?;
    
    file.write_all(text.as_bytes())
        .context("Failed to write text results")?;
    
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
        if let Some(result) = results.results.get(&port) {
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
        if let Some(result) = results.results.get(&port) {
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

/// Print open ports to the console
pub fn print_open_ports(results: &ScanResults) -> Result<()> {
    println!("{}", style("OPEN PORTS:").cyan().bold());
    println!("{}", style("PORT      STATE   SERVICE").cyan());
    println!("{}", style("------------------------").cyan());
    
    if results.open_ports.is_empty() {
        println!("No open ports found");
        return Ok(());
    }
    
    // Sort ports for consistent output
    let mut ports: Vec<u16> = results.open_ports.iter().copied().collect();
    ports.sort_unstable();
    
    for port in ports {
        if let Some(result) = results.results.get(&port) {
            let service = result.service.as_deref().unwrap_or("unknown");
            println!("{:<9} {:<7} {}", 
                style(port).green(), 
                style("open").green(), 
                style(service).green());
        }
    }
    
    Ok(())
}

/// Print detailed port information to the console
pub fn print_port_details(results: &ScanResults, port: u16) -> Result<()> {
    if let Some(result) = results.results.get(&port) {
        println!("{} {}", style("PORT DETAILS:").cyan().bold(), style(port).cyan());
        println!("{}", style("------------------------").cyan());
        
        // Service information
        if let Some(service) = &result.service {
            println!("{}: {}", style("Service").yellow(), service);
        }
        
        if let Some(version) = &result.version {
            println!("{}: {}", style("Version").yellow(), version);
        }
        
        // States by scan type
        if !result.tcp_states.is_empty() {
            println!("{}: ", style("TCP States").yellow());
            for (scan_type, status) in &result.tcp_states {
                println!("  {} scan: {}", scan_type, status);
            }
        }
        
        if let Some(udp_state) = &result.udp_state {
            println!("{}: {}", style("UDP State").yellow(), udp_state);
        }
        
        // Banner if available
        if let Some(banner) = &result.banner {
            println!("{}:", style("Banner").yellow());
            let sanitized = sanitize_banner(banner);
            for line in sanitized.lines().take(5) {
                println!("  {}", line);
            }
        }
        
        // Certificate info if available
        if let Some(cert) = &result.cert_info {
            println!("{}:", style("SSL/TLS Certificate").yellow());
            println!("  Subject: {}", cert.subject);
            println!("  Issuer: {}", cert.issuer);
            println!("  Valid from: {}", cert.not_before);
            println!("  Valid until: {}", cert.not_after);
        }
        
        // Vulnerabilities if found
        if !result.vulns.is_empty() {
            println!("{}:", style("Vulnerabilities").yellow().bold());
            for vuln in &result.vulns {
                println!("  - {}", style(vuln).red());
            }
        }
    } else {
        println!("No information available for port {}", port);
    }
    
    Ok(())
}

/// Sanitize banner string for display
fn sanitize_banner(banner: &str) -> String {
    // Replace control characters with visible representations
    banner.chars()
        .map(|c| {
            if c.is_ascii_control() && c != '\n' && c != '\r' && c != '\t' {
                format!("\\x{:02x}", c as u8)
            } else {
                c.to_string()
            }
        })
        .collect()
}

/// Export results to CSV format
pub fn export_to_csv(results: &ScanResults, writer: &mut dyn Write) -> Result<()> {
    // Write CSV header
    writeln!(writer, "port,state,service,version,banner")?;
    
    // Sort ports for consistent output
    let mut ports: Vec<u16> = results.results.keys().copied().collect();
    ports.sort_unstable();
    
    for port in ports {
        if let Some(result) = results.results.get(&port) {
            // Find the most open state
            let state = if result.tcp_states.values().any(|s| *s == PortStatus::Open) {
                "open"
            } else if result.udp_state == Some(PortStatus::Open) {
                "open/udp"
            } else if result.tcp_states.values().any(|s| *s == PortStatus::OpenFiltered) {
                "open|filtered"
            } else if !result.tcp_states.is_empty() {
                "closed"
            } else {
                "unknown"
            };
            
            let service = result.service.as_deref().unwrap_or("").replace(",", "");
            let version = result.version.as_deref().unwrap_or("").replace(",", "");
            
            // Take first line of banner and escape quotes, commas
            let banner = match &result.banner {
                Some(b) => b.lines().next().unwrap_or("").replace("\"", "\"\"").replace(",", "\\,"),
                None => String::new(),
            };
            
            writeln!(writer, "{},{},{},{},\"{}\"", port, state, service, version, banner)?;
        }
    }
    
    Ok(())
} 