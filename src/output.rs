use std::fs::File;
use std::io::Write;
use std::path::Path;

use anyhow::{Context, Result};
use chrono::Utc;
use console::{style, Term};
use serde_json;

use crate::ScanType;
use crate::models::{PortResult, PortStatus, ScanResults};
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
pub fn format_text_results(results: &ScanResults, verbose: bool) -> String {
    let mut output = String::new();
    
    // Header
    output.push_str(&format!("# Quantum Scanner Report\n"));
    output.push_str(&format!("Target: {}\n", results.target));
    output.push_str(&format!("IP: {}\n", results.target_ip));
    output.push_str(&format!("Timestamp: {}\n", Utc::now()));
    output.push_str(&format!("Scan Duration: {:.2} seconds\n", 
        results.end_time.signed_duration_since(results.start_time).num_milliseconds() as f64 / 1000.0));
    
    // Indicate scan mode
    let has_service_info = results.results.values()
        .any(|r| r.service.is_some() || r.version.is_some() || r.banner.is_some() || r.ndpi_protocol.is_some());
    if has_service_info {
        output.push_str("Scan Mode: Service scan (-sV) - Includes service identification\n");
    } else {
        output.push_str("Scan Mode: Port scan (-sP) - Limited service information\n");
    }
    
    // Scan types used
    output.push_str("Scan types: ");
    for (i, scan_type) in results.scan_types.iter().enumerate() {
        if i > 0 {
            output.push_str(", ");
        }
        output.push_str(&scan_type.to_string());
    }
    output.push_str("\n\n");
    
    // Enhanced scan statistics - only in verbose mode
    if verbose {
        output.push_str("## Scan Statistics\n");
        output.push_str(&format!("Packets sent: {}\n", results.packets_sent));
        output.push_str(&format!("Successful operations: {}\n", results.successful_scans));
        if results.packets_sent > 0 {
            output.push_str(&format!("Success rate: {:.1}%\n", 
                                   (results.successful_scans as f64 / results.packets_sent as f64) * 100.0));
        }
        
        // OS detection summary if available
        if let Some(os_summary) = &results.os_summary {
            output.push_str(&format!("OS detection: {}\n", os_summary));
        }
        
        // Risk assessment if available
        if let Some(risk) = &results.risk_assessment {
            output.push_str(&format!("Risk assessment: {}\n", risk));
        }
        
        output.push_str("\n");
        
        // Service categories if available
        if let Some(categories) = &results.service_categories {
            output.push_str("## Service Categories\n");
            for (category, ports) in categories {
                let ports_str = ports.iter()
                    .map(|p| p.to_string())
                    .collect::<Vec<_>>()
                    .join(", ");
                output.push_str(&format!("- {}: {}\n", category, ports_str));
            }
            output.push_str("\n");
        }
    }
    
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
    
    // Detailed port information - only in verbose mode
    if verbose {
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
                || port_result.cert_info.is_some()
                || port_result.vulns.len() > 0
                || port_result.anomalies.len() > 0
                || port_result.security_posture.is_some();
                
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
            
            // nDPI protocol detection if available
            if let Some(protocol) = &port_result.ndpi_protocol {
                output.push_str(&format!("Protocol (nDPI): {}", protocol));
                if let Some(confidence) = &port_result.ndpi_confidence {
                    output.push_str(&format!(" (Confidence: {})", confidence));
                }
                output.push_str("\n");
            }
            
            // States by scan type
            if !port_result.tcp_states.is_empty() {
                output.push_str("TCP States:\n");
                // Sort scan types alphabetically
                let mut scan_types: Vec<(&ScanType, &PortStatus)> = port_result.tcp_states.iter().collect();
                scan_types.sort_by(|a, b| a.0.cmp(b.0));
                
                for (scan_type, status) in scan_types {
                    // Get reason for this specific scan type if available from tcp_reasons
                    let status_reason = if let Some(reason) = port_result.tcp_reasons.get(scan_type) {
                        // Always use the scan-specific reason from tcp_reasons when available
                        format!(" (Reason: {})", reason)
                    } else if let Some(reason) = &port_result.reason {
                        // Fall back to the general reason if no specific reason exists
                        format!(" (Reason: {})", reason)
                    } else {
                        String::new()
                    };
                    
                    output.push_str(&format!("  - {} scan: {}{}\n", scan_type, status, status_reason));
                }
            }
            
            if let Some(udp_state) = &port_result.udp_state {
                output.push_str(&format!("UDP State: {}\n", udp_state));
            }
            
            // Add reason if available
            if let Some(reason) = &port_result.reason {
                output.push_str(&format!("Status Reason: {}\n", reason));
            }
            
            // Enhanced security posture assessment
            if let Some(posture) = &port_result.security_posture {
                output.push_str("Security Assessment:\n");
                for item in posture.split(';') {
                    output.push_str(&format!("  - {}\n", item.trim()));
                }
            }
            
            // Enhanced anomaly detection
            if !port_result.anomalies.is_empty() {
                output.push_str("Detected Anomalies:\n");
                for anomaly in &port_result.anomalies {
                    output.push_str(&format!("  - {}\n", anomaly));
                }
            }
            
            // Timing analysis if available
            if let Some(timing) = &port_result.timing_analysis {
                output.push_str(&format!("Timing Analysis: {}\n", timing));
            }
            
            // Enhanced service details
            if let Some(details) = &port_result.service_details {
                output.push_str("Service Details:\n");
                for (key, value) in details {
                    output.push_str(&format!("  - {}: {}\n", key, value));
                }
            }
            
            // Banner if available
            if let Some(banner) = &port_result.banner {
                output.push_str("Banner:\n");
                // Sanitize and format the banner - always show full banner in saved format
                let sanitized = sanitize_banner(banner);
                output.push_str(&format!("```\n{}\n```\n", sanitized));
            }
            
            // Certificate info if available
            if let Some(cert) = &port_result.cert_info {
                output.push_str("SSL/TLS Certificate:\n");
                output.push_str(&format!("  Subject: {}\n", cert.subject));
                output.push_str(&format!("  Issuer: {}\n", cert.issuer));
                output.push_str(&format!("  Valid from: {}\n", cert.not_before));
                output.push_str(&format!("  Valid until: {}\n", cert.not_after));
                if !cert.alt_names.is_empty() {
                    output.push_str("  Subject Alternative Names:\n");
                    for san in &cert.alt_names {
                        output.push_str(&format!("    - {}\n", san));
                    }
                }
            }
            
            // Vulnerabilities if detected
            if !port_result.vulns.is_empty() {
                output.push_str("Potential Vulnerabilities:\n");
                for vuln in &port_result.vulns {
                    output.push_str(&format!("  - {} ({})\n", vuln.id, vuln.severity));
                    output.push_str(&format!("    Description: {}\n", vuln.description));
                }
            }
            
            output.push_str("\n");
        }
    }
    
    output
}

/// Save scan results to a text file
///
/// # Arguments
/// * `results` - The scan results to save
/// * `output_path` - Path to the output file
///
/// # Returns
/// * `Result<()>` - Success or error
pub fn save_text_results(results: &ScanResults, output_path: &Path) -> Result<()> {
    let text = format_text_results(results, true);  // Always use verbose mode for saved files
    let mut file = File::create(output_path)
        .with_context(|| format!("Failed to create output file: {:?}", output_path))?;
    
    file.write_all(text.as_bytes())
        .with_context(|| format!("Failed to write to output file: {:?}", output_path))?;
    
    Ok(())
}

#[allow(dead_code)]
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
        // Sort scan types alphabetically
        let mut scan_types: Vec<(&ScanType, &PortStatus)> = result.tcp_states.iter().collect();
        scan_types.sort_by(|a, b| a.0.cmp(b.0));
        
        for (scan_type, status) in scan_types {
            // Get reason for this specific scan type if available from tcp_reasons
            let status_reason = if let Some(reason) = result.tcp_reasons.get(scan_type) {
                // Always use the scan-specific reason from tcp_reasons when available
                format!(" (Reason: {})", reason)
            } else if let Some(reason) = &result.reason {
                // Fall back to the general reason if no specific reason exists
                format!(" (Reason: {})", reason)
            } else {
                String::new()
            };
            
            writeln!(file, "- {}: {}{}", scan_type, status, status_reason)?;
        }
    }
    
    // UDP result if available
    if let Some(udp_status) = &result.udp_state {
        writeln!(file, "\nUDP: {}", udp_status)?;
    }
    
    // Reason for port status if available
    if let Some(reason) = &result.reason {
        writeln!(file, "\nStatus Reason: {}", reason)?;
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
            cert.not_before,
            cert.not_after
        )?;
        writeln!(file, "- Signature Algo: {}", cert.signature_algorithm)?;
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

/// Print scan results to the console
pub fn print_results(results: &ScanResults, verbose: bool) -> Result<()> {
    let term = Term::stdout();
    term.clear_screen()?;
    
    // Print header
    println!("{}", style("Quantum Scanner Results").cyan().bold());
    println!("Target: {} ({})", style(&results.target).green(), results.target_ip);
    
    // Display scan mode
    let has_service_info = results.results.values()
        .any(|r| r.service.is_some() || r.version.is_some() || r.banner.is_some() || r.ndpi_protocol.is_some());
    if has_service_info {
        println!("Scan Mode: {}", style("Service scan (-sV)").yellow().bold());
    } else {
        println!("Scan Mode: {}", style("Port scan (-sP)").yellow().bold());
        println!("{}", style("Note: Limited service information. Use -sV for detailed service detection.").italic());
    }
    
    // Enhanced scan details when verbose mode is enabled
    if verbose {
        // Show detailed scan time information
        println!("Scan Start: {}", results.start_time.format("%Y-%m-%d %H:%M:%S"));
        println!("Scan End: {}", results.end_time.format("%Y-%m-%d %H:%M:%S"));
        
        // Display scan types used
        print!("Scan Types: ");
        for (i, scan_type) in results.scan_types.iter().enumerate() {
            if i > 0 {
                print!(", ");
            }
            print!("{}", style(scan_type).yellow());
        }
        println!("");
        
        // Display scan statistics
        println!("Total Packets: {}", results.packets_sent);
        println!("Successful Operations: {}", results.successful_scans);
        
        if results.packets_sent > 0 {
            let success_rate = (results.successful_scans as f64 / results.packets_sent as f64) * 100.0;
            println!("Success Rate: {:.1}%", success_rate);
        }
        
        // Print risk assessment if available 
        if let Some(risk) = &results.risk_assessment {
            println!("Risk Assessment: {}", style(risk).yellow());
        }
    } else {
        // Basic duration information for non-verbose mode
        println!("Scan Duration: {:.2} seconds", 
            (results.end_time - results.start_time).num_milliseconds() as f64 / 1000.0
        );
    }
    
    println!("\n{} open ports discovered", style(results.open_ports.len()).yellow().bold());
    
    // If no open ports, end here
    if results.open_ports.is_empty() {
        println!("\nNo open ports found on target.");
        return Ok(());
    }
    
    // Print open ports summary with enhanced information
    println!("\n{}", style("PORT     STATE  SERVICE  VERSION          BANNER").underlined());
    
    let mut ports: Vec<_> = results.open_ports.iter().collect();
    ports.sort_unstable();
    
    for &port in ports {
        if let Some(result) = results.results.get(&port) {
            print_port_summary(port, result);
        }
    }
    
    // Print detailed information for interesting ports only in verbose mode
    if verbose {
        print_detailed_results(results)?;
    }
    
    Ok(())
}

fn print_port_summary(port: u16, result: &PortResult) {
    // Determine the state (open, filtered, etc)
    let state = if result.tcp_states.values().any(|s| *s == PortStatus::Open) {
        "open"
    } else if result.udp_state == Some(PortStatus::Open) {
        "open/udp"
    } else {
        "open|filtered"
    };
    
    // Get service and version info
    let service = result.service.as_deref().unwrap_or("-");
    let version = result.version.as_deref().unwrap_or("-");
    
    // Get banner with more context for verbose output
    let banner = match &result.banner {
        Some(b) => {
            // We'll take the first line, but with a longer limit that won't truncate important information
            let first_line = b.lines().next().unwrap_or("").trim();
            
            // Check if this is an HTTP response and extract key information
            if first_line.starts_with("HTTP/") {
                // For HTTP, include status line and major headers
                let mut output = String::new();
                let mut lines = b.lines();
                
                // Add the status line (first line)
                if let Some(status) = lines.next() {
                    output.push_str(status);
                }
                
                // Handle the case where the terminal might be narrow
                if output.len() > 100 {
                    format!("{}...", &output[0..100])
                } else {
                    output
                }
            } else if first_line.len() > 80 {
                // For non-HTTP, we'll be more generous with space but still avoid overflowing the terminal
                format!("{}...", &first_line[0..80])
            } else {
                first_line.to_string()
            }
        },
        None => "-".to_string()
    };
    
    // Print the summary line with scan-specific reasons
    println!("{:<7} {:<6} {:<9} {:<16} {}", 
        style(port).yellow().bold(),
        style(state).green(),
        service,
        version,
        banner
    );
}

/// Print detailed results for all interesting ports
/// Only called when verbose mode is enabled
fn print_detailed_results(results: &ScanResults) -> Result<()> {
    let mut ports: Vec<_> = results.open_ports.iter().collect();
    ports.sort_unstable();
    
    println!("\n{}", style("Detailed Port Information").cyan().bold());
    println!("{}", style("=========================").cyan());
    
    for &port in ports {
        if let Some(result) = results.results.get(&port) {
            println!("\n{} - {}", 
                style(format!("Port {}", port)).yellow().bold(),
                style(result.service.as_deref().unwrap_or("unknown service")).green()
            );
            
            // Print version information
            if let Some(version) = &result.version {
                println!("  Version: {}", version);
            }
            
            // Print service fingerprinting information
            if !result.tcp_states.is_empty() {
                println!("  Scan Results:");
                // Sort scan types alphabetically
                let mut scan_types: Vec<(&ScanType, &PortStatus)> = result.tcp_states.iter().collect();
                scan_types.sort_by(|a, b| a.0.cmp(b.0));
                
                for (scan_type, status) in scan_types {
                    // Always get reason for this specific scan type from tcp_reasons when available
                    let status_reason = if let Some(reason) = result.tcp_reasons.get(scan_type) {
                        // Use the scan-specific reason from tcp_reasons when available
                        format!(" (Reason: {})", style(reason).yellow())
                    } else if let Some(reason) = &result.reason {
                        // Fall back to the general reason if no specific reason exists
                        format!(" (Reason: {})", style(reason).yellow())
                    } else {
                        String::new()
                    };
                    
                    println!("    - {} scan: {}{}", style(scan_type).cyan(), status, status_reason);
                }
            }
            
            if let Some(udp_state) = &result.udp_state {
                println!("  UDP: {}", udp_state);
                
                // Add UDP-specific reason if available (similar to how tcp_reasons works)
                if let Some(reason) = &result.reason {
                    if result.tcp_states.is_empty() { // Only show if this is primarily a UDP scan
                        println!("    UDP Reason: {}", style(reason).yellow());
                    }
                }
            }
            
            // Print banner information
            if let Some(banner) = &result.banner {
                let mut lines: Vec<&str> = banner.lines().collect();
                let display_lines = if lines.len() > 5 {
                    // If there are more than 5 lines, show first 3 and last 2
                    let first_lines = &lines[0..3];
                    let last_lines = &lines[lines.len() - 2..];
                    
                    let mut result = first_lines.to_vec();
                    result.push("...");
                    result.extend_from_slice(last_lines);
                    result
                } else {
                    lines
                };
                
                println!("  Banner:");
                for line in display_lines {
                    println!("    {}", line);
                }
            }
            
            // Print vulnerabilities if any found
            if !result.vulns.is_empty() {
                println!("\nPotential Vulnerabilities:");
                for vuln in &result.vulns {
                    println!("- {} ({})", style(&vuln.id).red().bold(), vuln.severity);
                    println!("  Description: {}", vuln.description);
                }
            }
        }
    }
    
    Ok(())
}

/// Print a summary of open ports to the terminal
///
/// # Arguments
/// * `results` - The scan results
/// * `verbose` - Whether to show verbose information
///
/// # Returns
/// * `Result<()>` - Success or error
pub fn print_open_ports(results: &ScanResults, verbose: bool) -> Result<()> {
    let term = Term::stdout();
    term.clear_screen()?;
    
    println!("{}", style("Open Ports").cyan().bold());
    println!("Target: {} ({})", style(&results.target).green(), results.target_ip);
    
    // Only show the scan duration in verbose mode
    if verbose {
        println!("Scan Duration: {:.2} seconds", 
            results.end_time.signed_duration_since(results.start_time).num_milliseconds() as f64 / 1000.0
        );
    }
    
    if results.open_ports.is_empty() {
        println!("\nNo open ports found on target.");
        return Ok(());
    }
    
    println!("\n{} open ports discovered:", results.open_ports.len());
    
    let mut ports: Vec<_> = results.open_ports.iter().collect();
    ports.sort_unstable();
    
    for &port in ports {
        if let Some(result) = results.results.get(&port) {
            let service = match &result.service {
                Some(s) => s,
                None => "unknown",
            };
            
            let reason_text = match &result.reason {
                Some(r) => format!(" (Reason: {})", r),
                None => String::new(),
            };
            
            println!("{:<5} {}{}", 
                style(port).yellow().bold(), 
                service,
                if verbose { reason_text } else { String::new() }
            );
        }
    }
    
    Ok(())
}

/// Print detailed information about a specific port
///
/// # Arguments
/// * `results` - The scan results
/// * `port` - The port to print details for
///
/// # Returns
/// * `Result<()>` - Success or error
pub fn print_port_details(results: &ScanResults, port: u16, verbose: bool) -> Result<()> {
    if let Some(port_result) = results.results.get(&port) {
        println!("{}", style(format!("Port {} Details", port)).cyan().bold());
        
        // Basic port info
        if let Some(service) = &port_result.service {
            println!("Service: {}", style(service).yellow());
        }
        
        if let Some(version) = &port_result.version {
            println!("Version: {}", version);
        }
        
        // nDPI protocol detection if available
        if let Some(protocol) = &port_result.ndpi_protocol {
            println!("Protocol (nDPI): {}", protocol);
            if let Some(confidence) = &port_result.ndpi_confidence {
                println!("Confidence: {}", confidence);
            }
        }
        
        // Determine state
        let mut states = Vec::new();
        
        // Sort scan types alphabetically
        let mut scan_types: Vec<(&ScanType, &PortStatus)> = port_result.tcp_states.iter().collect();
        scan_types.sort_by(|a, b| a.0.cmp(b.0));
        
        for (scan_type, status) in scan_types {
            // Get reason for this specific scan type if available from tcp_reasons
            let status_reason = if let Some(reason) = port_result.tcp_reasons.get(scan_type) {
                // Always use the scan-specific reason from tcp_reasons when available
                format!(" (Reason: {})", reason)
            } else if let Some(reason) = &port_result.reason {
                // Fall back to the general reason if no specific reason exists
                format!(" (Reason: {})", reason)
            } else {
                String::new()
            };
            
            states.push(format!("{} scan: {}{}", scan_type, style(status).green(), style(&status_reason).yellow()));
        }
        
        if let Some(udp_state) = &port_result.udp_state {
            // Get reason for UDP if available
            let status_reason = if let Some(reason) = &port_result.reason {
                format!(" (Reason: {})", reason)
            } else {
                String::new()
            };
            states.push(format!("UDP: {}{}", style(udp_state).green(), style(&status_reason).yellow()));
        }
        
        if !states.is_empty() {
            println!("States:");
            for state in states {
                println!("  - {}", state);
            }
        }
        
        // Print reason if available
        if let Some(reason) = &port_result.reason {
            println!("Status Reason: {}", style(reason).yellow());
        }
        
        // Only show detailed information in verbose mode
        if verbose {
            // Banner if available
            if let Some(banner) = &port_result.banner {
                println!("\n{}", style("Banner:").underlined());
                
                // Format and display the banner with proper sanitization
                let sanitized = sanitize_banner(banner);
                
                // Print the full banner without truncation in verbose mode
                println!("{}", sanitized);
            }
            
            // Certificate info for SSL services
            if let Some(cert) = &port_result.cert_info {
                println!("\n{}", style("SSL/TLS Certificate:").underlined());
                println!("Subject: {}", cert.subject);
                println!("Issuer:  {}", cert.issuer);
                println!("Valid:   {} to {}", cert.not_before, cert.not_after);
                
                if !cert.alt_names.is_empty() {
                    println!("Alternative Names:");
                    for san in &cert.alt_names {
                        println!("  - {}", san);
                    }
                }
            }
            
            // Vulnerabilities if detected
            if !port_result.vulns.is_empty() {
                println!("\n{}", style("Potential Vulnerabilities:").underlined());
                for vuln in &port_result.vulns {
                    println!("- {} ({})", style(&vuln.id).red().bold(), vuln.severity);
                    println!("  Description: {}", vuln.description);
                }
            }
        }
    } else {
        println!("No information available for port {}", port);
    }
    
    Ok(())
}

/// Sanitize a banner string for safe display
/// 
/// # Arguments
/// * `banner` - The banner string to sanitize
/// 
/// # Returns
/// * `String` - The sanitized banner
fn sanitize_banner(banner: &str) -> String {
    // Use our sanitize_string function to handle basic sanitization
    let sanitized = crate::utils::sanitize_string(banner);
    
    // Additional banner-specific processing
    // Limit to reasonable number of characters
    if sanitized.len() > 4000 {
        format!("{}... (truncated)", &sanitized[..3997])
    } else {
        sanitized
    }
}

#[allow(dead_code)]
pub fn export_to_csv(results: &ScanResults, writer: &mut dyn Write) -> Result<()> {
    // Write the header row
    writeln!(writer, "port,status,service,version,reason,banner")?;
    
    // Write each port result
    let mut ports: Vec<u16> = results.results.keys().copied().collect();
    ports.sort_unstable();
    
    for port in ports {
        if let Some(port_result) = results.results.get(&port) {
            // Determine the overall port status
            let status = match port_result.final_status {
                PortStatus::Open => "open",
                PortStatus::Closed => "closed", 
                PortStatus::Filtered => "filtered",
                PortStatus::Unfiltered => "unfiltered",
                PortStatus::OpenFiltered => "open|filtered",
            };
            
            // Get basic port information
            let service = port_result.service.as_deref().unwrap_or("").replace(",", "");
            let version = port_result.version.as_deref().unwrap_or("").replace(",", "");
            let reason = port_result.reason.as_deref().unwrap_or("").replace(",", "");
            
            // Get banner, limiting to first line
            let banner = match &port_result.banner {
                Some(b) => b.lines().next().unwrap_or("").replace(",", "").replace("\"", "'"),
                None => String::new(),
            };
            
            // Write the CSV row
            writeln!(writer, "{},{},{},{},{},\"{}\"", 
                port, status, service, version, reason, banner)?;
        }
    }
    
    Ok(())
} 