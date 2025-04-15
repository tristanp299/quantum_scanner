use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr/*, Ipv6Addr, SocketAddr*/};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
// use std::fs::File;
// Use comment style
// use std::io::Write;

use anyhow::{Result, anyhow};
use chrono::prelude::Utc;
use log::{debug, error, info, warn};
use tokio::sync::{Mutex, Semaphore};
use tokio::task::JoinHandle;
use futures::future::join_all;
// use rand::Rng;

use crate::models::{PortResult, ScanResults, ScanType, PortStatus, /*CertificateInfo, HttpInfo,*/ VulnInfo, ScanResult, requires_raw_sockets, MimicPayloads, ScanMetrics};
use crate::utils::{MemoryLogBuffer, sanitize_string};
use crate::techniques;
use crate::banner;
use crate::http_analyzer;
use crate::service_fingerprints::ServiceFingerprints;
use crate::ml_service_ident;
use crate::ml_service_ident::ServiceIdentification;

// --- Rate Limiting Imports ---
use governor::{Quota, RateLimiter, state::direct::NotKeyed, clock::DefaultClock};
use std::num::NonZeroU32;
// --- End Rate Limiting Imports ---

/// Main scanner implementation
/// Orchestrates port scanning using various techniques and performs post-scan analysis.
pub struct QuantumScanner {
    /// Target hostname or IP as provided by the user
    target: String,
    /// Resolved target IP address
    target_ip: IpAddr,
    /// Detected local IPv4 address (required for raw socket scans)
    local_ip_v4: Option<Ipv4Addr>,
    /// Ports to scan
    ports: Vec<u16>,
    /// Scan techniques to use
    scan_types: Vec<ScanType>,
    /// Maximum concurrent operations
    concurrency: usize,
    /// Maximum tasks per second (rate limiting, 0 for disabled)
    max_rate: usize,
    /// Rate limiter instance (if max_rate > 0)
    rate_limiter: Option<Arc<RateLimiter<NotKeyed, governor::state::InMemoryState, DefaultClock>>>,
    /// Use basic evasion techniques
    evasion: bool,
    /// Use IPv6
    use_ipv6: bool,
    /// Timeout for individual port scan attempts
    timeout_scan: Duration,
    /// Timeout specifically for the initial connection attempt
    timeout_connect: Duration,
    /// Timeout for banner grabbing attempts
    timeout_banner: Duration,
    /// Protocol to mimic for mimic scans (e.g., "HTTP", "SSH")
    mimic_protocol: String,
    /// Fragmentation: Minimum fragment size
    frag_min_size: u16,
    /// Fragmentation: Maximum fragment size
    frag_max_size: u16,
    /// Fragmentation: Minimum delay between fragments (seconds)
    frag_min_delay: f64,
    /// Fragmentation: Maximum delay between fragments (seconds)
    frag_max_delay: f64,
    /// Fragmentation: Timeout for reassembling fragments (seconds)
    frag_timeout: u64,
    /// Fragmentation: Minimum size of the first fragment
    frag_first_min_size: u16,
    /// Fragmentation: Use exactly two fragments
    frag_two_frags: bool,
    /// Path to the log file (used for context, actual logging handled by setup_logging)
    log_file: PathBuf,
    /// Enable verbose logging output
    verbose: bool,
    /// Enable debug mode (show detailed scan progress)
    debug: bool,
    /// Optional memory logger buffer
    memory_log: Option<Arc<parking_lot::Mutex<MemoryLogBuffer>>>,
    /// Enable enhanced evasion techniques
    enhanced_evasion: bool,
    /// OS profile to mimic for enhanced evasion
    mimic_os: String,
    /// TTL jitter amount for enhanced evasion
    ttl_jitter: u8,
    /// Protocol variant for mimicry scans
    protocol_variant: Option<String>,
    /// Enable ML-based service identification
    ml_identification: bool,
    /// DNS Tunneling: Custom server IP
    dns_tunnel_server: Option<IpAddr>,
    /// DNS Tunneling: Custom lookup domain
    dns_tunnel_domain: Option<String>,
    /// Metrics for scan performance and statistics collection
    metrics: Option<Arc<Mutex<ScanMetrics>>>,
    /// Results map to store scan results by port
    results_map: HashMap<u16, PortResult>,
    // TODO: Add state for rate limiting if max_rate > 0 - Implemented basic delay
}

impl QuantumScanner {
    /// Create a new scanner instance
    pub async fn new(
        target: &str,
        ports: Vec<u16>, // Use the ports parameter
        scan_types: Vec<ScanType>, // Use the scan_types parameter
        local_ip_v4: Option<Ipv4Addr>, // Added local_ip_v4 parameter
        concurrency: usize,
        max_rate: usize, // Use the max_rate parameter
        evasion: bool, // Use the evasion parameter
        verbose: bool, // Use the verbose parameter
        debug: bool, // Added debug parameter
        use_ipv6: bool, // Use the use_ipv6 parameter
        timeout_scan: f64, // Use the timeout_scan parameter
        timeout_connect: f64, // Use the timeout_connect parameter
        timeout_banner: f64, // Use the timeout_banner parameter
        mimic_protocol: &str, // Use the mimic_protocol parameter
        // Added fragmentation parameters
        frag_min_size: u16,
        frag_max_size: u16,
        frag_min_delay: f64,
        frag_max_delay: f64,
        frag_timeout: u64,
        frag_first_min_size: u16,
        frag_two_frags: bool,
        log_file: &Path, // Use the log_file parameter
        ml_identification: bool, // Added ml_identification parameter
    ) -> Result<Self> {
        // Log the start of the scanner initialization
        // This helps in debugging setup issues
        info!("Initializing QuantumScanner for target: {}", target);

        // Try to resolve target hostname to an IP address.
        // This is crucial for OpSec as it prevents sending DNS queries
        // during the actual scan phase if the target is already an IP.
        let target_ip = match target.parse::<IpAddr>() {
            Ok(ip) => {
                // Target is already an IP address.
                info!("Target is an IP address: {}", ip);
                // Check if we can use this IP based on IPv6 preferences
                if ip.is_ipv6() && !use_ipv6 {
                    warn!("Target is IPv6 but IPv6 scanning is not enabled. Enable with --ipv6 flag.");
                    return Err(anyhow!("IPv6 target detected but IPv6 scanning not enabled. Use --ipv6 flag."));
                }
                ip
            }
            Err(_) => {
                // Target is likely a hostname, attempt resolution.
                info!("Target is a hostname: {}. Attempting resolution..", target);
                
                // Try to use DNS resolution with better logging
                match tokio::net::lookup_host(format!("{}:0", target)).await {
                    Ok(addrs) => {
                        // Collect all addresses for logging purposes
                        let addrs_vec: Vec<_> = addrs.collect();
                        info!("Hostname {} resolved to {} addresses", target, addrs_vec.len());
                        
                        // If we find an IPv4 address, use it by default
                        let mut selected_ip = None;
                        let mut found_ipv4 = None;
                        let mut found_ipv6 = None;
                        
                        // Log all resolved IPs for debugging
                        for addr in &addrs_vec {
                            let ip = addr.ip();
                            info!("  Resolved address: {}", ip);
                            if ip.is_ipv4() {
                                info!("    IPv4 address detected: {}", ip);
                                found_ipv4 = Some(ip);
                            } else if ip.is_ipv6() {
                                info!("    IPv6 address detected: {}", ip);
                                if use_ipv6 {
                                    found_ipv6 = Some(ip);
                                } else {
                                    info!("    Skipping IPv6 address {} (IPv6 scanning not enabled)", ip);
                                }
                            }
                        }
                        
                        // Special handling for known hosts like scanme.nmap.org
                        if target.contains("scanme.nmap.org") && found_ipv4.is_none() {
                            // Use the canonical IP for scanme.nmap.org if DNS resolution failed to find IPv4
                            info!("Target is scanme.nmap.org but no IPv4 address found via DNS. Using canonical IP 45.33.32.156");
                            found_ipv4 = "45.33.32.156".parse::<IpAddr>().ok();
                        }
                        
                        // Prefer IPv4 by default, unless IPv6 flag is set and no IPv4 is available
                        if let Some(ipv4) = found_ipv4 {
                            selected_ip = Some(ipv4);
                            info!("Selected IPv4 address: {}", ipv4);
                        } else if let Some(ipv6) = found_ipv6 {
                            selected_ip = Some(ipv6);
                            info!("Selected IPv6 address: {}", ipv6);
                        }
                        
                        match selected_ip {
                            Some(ip) => {
                                info!("Using IP {} for target {}", ip, target);
                                ip
                            }
                            None => {
                                if use_ipv6 {
                                    error!("Could not resolve hostname {} to any IP address", target);
                                } else {
                                    error!("Could not resolve hostname {} to any IPv4 address. Try --ipv6 if the host has IPv6 connectivity.", target);
                                }
                                return Err(anyhow!("Could not resolve hostname '{}' to a suitable IP address", target));
                            }
                        }
                    },
                    Err(e) => {
                        // Failed to resolve the hostname.
                        error!("DNS resolution failed for hostname {}: {}", target, e);
                        
                        // Special handling for known hosts like scanme.nmap.org
                        if target.contains("scanme.nmap.org") {
                            info!("Target is scanme.nmap.org - using canonical IP 45.33.32.156 despite DNS failure");
                            match "45.33.32.156".parse::<IpAddr>() {
                                Ok(ip) => {
                                    info!("Using hardcoded IP {} for scanme.nmap.org", ip);
                                    ip
                                },
                                Err(_) => {
                                    return Err(anyhow!("Could not parse hardcoded IP for scanme.nmap.org"));
                                }
                            }
                        } else {
                            return Err(anyhow!("Could not resolve hostname '{}': {}", target, e));
                        }
                    }
                }
            }
        };

        // Ensure local IP is provided if raw sockets are needed
        if requires_raw_sockets(&scan_types) && local_ip_v4.is_none() {
            return Err(anyhow!("A local IPv4 address must be provided or detectable for raw socket scans (e.g., SYN, FIN)."));
        }

        // Convert timeout values from f64 seconds to Duration.
        // Using Duration::from_secs_f64 allows for fractional seconds.
        let timeout_scan_duration = Duration::from_secs_f64(timeout_scan);
        let timeout_connect_duration = Duration::from_secs_f64(timeout_connect);
        let timeout_banner_duration = Duration::from_secs_f64(timeout_banner);

        // Output debug information about scan configuration only when debug is enabled
        if debug {
            debug!("Scanner config: Ports={:?}, ScanTypes={:?}, Concurrency={}, Rate={}, Evasion={}, IPv6={}", 
                   ports, scan_types, concurrency, max_rate, evasion, use_ipv6);
            debug!("Scanner timeouts: Scan={:?}, Connect={:?}, Banner={:?}", 
                   timeout_scan_duration, timeout_connect_duration, timeout_banner_duration);
        }

        // Construct the QuantumScanner instance with all the parameters.
        Ok(Self {
            target: target.to_string(),
            target_ip,
            local_ip_v4, // Store the local IPv4 address
            ports,
            scan_types,
            concurrency,
            max_rate,
            // Initialize the rate limiter based on max_rate
            rate_limiter: if max_rate > 0 {
                match NonZeroU32::new(max_rate as u32) {
                    Some(rate) => {
                        let quota = Quota::per_second(rate);
                        Some(Arc::new(RateLimiter::direct(quota)))
                    }
                    None => {
                         warn!("Invalid max_rate value ({}), disabling rate limiting.", max_rate);
                         None // Invalid rate, disable limiter
                    }
                }
            } else {
                None // Rate limiting disabled
            },
            evasion,
            verbose,
            debug,
            use_ipv6,
            timeout_scan: timeout_scan_duration,
            timeout_connect: timeout_connect_duration,
            timeout_banner: timeout_banner_duration,
            mimic_protocol: mimic_protocol.to_string(),
            frag_min_size,
            frag_max_size,
            frag_min_delay,
            frag_max_delay,
            frag_timeout,
            frag_first_min_size,
            frag_two_frags,
            log_file: log_file.to_path_buf(),
            memory_log: None, // Initialize memory_log as None
            // Initialize enhanced evasion options to defaults
            enhanced_evasion: false,
            mimic_os: "random".to_string(),
            ttl_jitter: 0,
            protocol_variant: None,
            ml_identification,
            dns_tunnel_server: None,
            dns_tunnel_domain: None,
            metrics: None,
            results_map: HashMap::new(),
        })
    }
    
    /// Run the configured scan against the target.
    /// Includes core scanning loop and post-scan analysis.
    /// 
    /// # Opsec Considerations
    /// - Uses concurrency control via Semaphore.
    /// - Implements basic rate limiting (delay) to avoid overwhelming the target or triggering simple IDS.
    /// - Relies on `techniques` module functions for stealthiness of individual scan types.
    /// - Post-scan analysis (banner grabbing) occurs only on ports identified as potentially open.
    pub async fn run_scan(&mut self) -> Result<ScanResults> {
        let start_time = Utc::now();
        info!("Starting scan for target: {} ({})", self.target, self.target_ip);

        // Shared state for collecting results across asynchronous tasks.
        // - `results_map`: Stores detailed `PortResult` for each scanned port.
        // - `open_ports_set`: Quickly tracks ports found Open or OpenFiltered by any scan type.
        // - `packets_sent`: Basic counter for attempted scan tasks (see limitations).
        // - `successful_scans`: Basic counter for tasks that completed without error (see limitations).
        // - `semaphore`: Limits the number of concurrent scan tasks.
        let results_map = Arc::new(Mutex::new(HashMap::<u16, PortResult>::new()));
        let open_ports_set = Arc::new(Mutex::new(HashSet::<u16>::new()));
        let packets_sent = Arc::new(Mutex::new(0u64)); // Note: Counts tasks started, not actual network packets.
        let successful_scans = Arc::new(Mutex::new(0u64)); // Note: Counts tasks completed without error from techniques::*
        let semaphore = Arc::new(Semaphore::new(self.concurrency));
        // Initial tasks vector declaration
        
        // Create shared state for self fields that will be accessed from async tasks
        let target_ip = self.target_ip;
        let _use_ipv6 = self.use_ipv6;
        let _evasion = self.evasion;
        let _enhanced_evasion = self.enhanced_evasion;
        let _timeout_scan = self.timeout_scan;
        let _timeout_banner = self.timeout_banner; // Add underscore to silence warning
        let local_ip_v4 = self.local_ip_v4.clone();
        let _mimic_protocol = self.mimic_protocol.clone();
        let _mimic_os = self.mimic_os.clone();
        let _ttl_jitter = self.ttl_jitter;
        let _protocol_variant = self.protocol_variant.clone();
        let _ml_identification = self.ml_identification;
        let memory_log = self.memory_log.clone();
        let _verbose = self.verbose; // Prefix with underscore to avoid unused variable warning
        let debug_mode = self.debug; // Clone the debug flag to use in async closures
        let _scan_types = self.scan_types.clone(); // Adding underscore as we use self.scan_types directly
        
        // Clone the rate limiter Arc for use in the loop
        let _rate_limiter_clone = self.rate_limiter.clone(); // Adding underscore as we use self.rate_limiter directly

        // Check if raw sockets are needed and log a reminder about privileges.
        // The actual privilege check happens in main.rs, this is just a reminder.
        let needs_raw_sockets = requires_raw_sockets(&self.scan_types); // Using the function from models
        if needs_raw_sockets {
            debug!("Scan requires raw sockets. Ensure scanner is run with sufficient privileges (root/Administrator).");
        }

        // --- Core scanning phase (port discovery) ---
        // A vector to store all spawned task handles for joining later
        let mut tasks = Vec::new();
        
        // Scan each port with each scan type
        for scan_type in &self.scan_types {
            if self.verbose || self.debug {
                info!("Running {:?} scan on {} ports...", scan_type, self.ports.len());
            }
            
            // Run the scan tasks for this scan type on all ports
            let scan_tasks = self.run_port_scan_tasks(
                *scan_type,
                semaphore.clone(),
                results_map.clone(),
                open_ports_set.clone(),
                packets_sent.clone(),
                successful_scans.clone(),
                target_ip,
                local_ip_v4,
                &self.ports,
                self.timeout_scan,
                self.debug,
                self.use_ipv6,
                self.evasion,
                memory_log.clone(),
                self.enhanced_evasion,
                self.mimic_os.clone(),
                self.ttl_jitter,
                self.mimic_protocol.clone(),
                self.protocol_variant.clone(),
                self.ml_identification,
            ).await;
            
            // Add the tasks to our collection
            tasks.extend(scan_tasks);
        }
        
        // Add timeout for the core scanning phase to prevent hanging
        match tokio::time::timeout(
            Duration::from_secs(60 * 5), // 5 minute timeout for entire scan phase
            join_all(tasks)
        ).await {
            Ok(_) => info!("Core port scanning phase complete."),
            Err(_) => {
                warn!("Core port scanning timed out after 5 minutes. Some operations may not have completed.");
                info!("Proceeding with analysis of available results...");
            }
        }

        // Initialize metrics if not already initialized
        if self.metrics.is_none() {
            self.metrics = Some(Arc::new(Mutex::new(ScanMetrics::new())));
        }
        
        // Create service identification components
        // Use MinimalServiceIdentifier when the ml feature is disabled
        #[cfg(feature = "ml")]
        let ml_identifier = Arc::new(ml_service_ident::create_ml_identifier());
        #[cfg(not(feature = "ml"))]
        let ml_identifier = Arc::new(ml_service_ident::create_ml_identifier());
        
        let http_analyzer_instance = Arc::new(http_analyzer::HttpAnalyzer::new());
        let fingerprint_db = Arc::new(ServiceFingerprints::new());

        // --- Post-scan Analysis (Banner Grabbing, Service ID) ---
        // Clone needed values for the analysis tasks
        let analysis_semaphore = Arc::new(Semaphore::new(self.concurrency));
        let verbose = self.verbose;
        let debug = self.debug;
        let timeout_banner = self.timeout_banner;
        let ml_identification = self.ml_identification;
        
        // Create a new copy of self.memory_log to avoid borrowing self
        let memory_log_local = memory_log.clone();

        // Phase 2: Post-scan analysis (banner grabbing, service identification, etc.)
        // This phase is important for improving result accuracy with additional data
        if verbose || debug {
            info!("Starting post-scan analysis (banner grabbing, service ID)... (Concurrency: {})", 
                  self.concurrency);
        }
        
        // Clone the results map to avoid borrowing self
        let results_map_clone = results_map.clone();
        let open_ports = open_ports_set.lock().await.clone();
        info!("Found {} potentially open/open|filtered ports", open_ports.len());
        
        // Declare analysis_tasks vector outside the if block
        let mut analysis_tasks = Vec::new();
        
        // Skip post-scan analysis if no open ports found
        if !open_ports.is_empty() {
            // Now run banner grabbing and service identification for all open ports
            for port in &open_ports {
                let port = *port; // Dereference inside the loop
                let target_ip_clone = target_ip;
                let results_map_clone = results_map_clone.clone();
                let semaphore_clone = analysis_semaphore.clone();
                let verbose_clone = verbose;
                let debug_clone = debug;
                let _memory_log_clone = memory_log_local.clone();
                let ml_identification_clone = ml_identification;
                let _timeout_banner_clone = timeout_banner;
                let http_analyzer_clone = http_analyzer_instance.clone();
                let ml_identifier_clone = ml_identifier.clone();
                let fingerprint_db_clone = fingerprint_db.clone();
                
                // Spawn a task for banner grabbing and service identification
                let analysis_task = tokio::spawn(async move {
                    let permit = match semaphore_clone.acquire().await {
                        Ok(p) => p,
                        Err(_) => {
                            // If we can't get a permit, likely the semaphore was closed
                            return;
                        }
                    };
                    
                    // Banner grabbing - attempt to connect and get service banner
                    // This helps identify services running on the port
                    let banner_text = match banner::grab_banner(target_ip_clone, port).await {
                        Ok(b) => {
                            let sanitized = sanitize_string(&b);
                            if debug_clone {
                                debug!("Banner received for port {}: {}", port, sanitized);
                            }
                            if verbose_clone { info!("Banner for port {}: {}", port, sanitized); }
                            Some(sanitized)
                        },
                        Err(e) => {
                            if debug_clone {
                                debug!("Banner grabbing failed for port {}: {}", port, e);
                            }
                            if verbose_clone { warn!("Banner grabbing failed for port {}: {}", port, e); }
                            None
                        }
                    };

                    // Lock the results map once for this port's analysis
                    let mut map_guard = results_map_clone.lock().await;
                    if let Some(port_result) = map_guard.get_mut(&port) {
                        // Explicitly type port_result for clarity
                        let result_entry: &mut PortResult = port_result;
                        result_entry.banner = banner_text.clone(); // Store the banner
                        
                        // If banner grabbing was successful, that's a definitive sign that the port is open
                        // Update the port's status to Open if banner was retrieved successfully
                        if banner_text.is_some() {
                            // Update the open status for at least one scan type
                            if !result_entry.tcp_states.is_empty() {
                                // Update one of the TCP states to Open
                                if let Some((&first_scan_type, _)) = result_entry.tcp_states.iter().next() {
                                    result_entry.tcp_states.insert(first_scan_type, PortStatus::Open);
                                }
                            }
                        }

                        // --- Service/Version Identification Logic --- 
                        let mut identified_service: Option<String> = None;
                        let mut identified_version: Option<String> = None;

                        // Priority 1: Use existing certificate info if available
                        // If we have certificate information, we know it's an SSL/TLS service.
                        if let Some(cert_info_ref) = result_entry.cert_info.as_ref() { 
                            // Set service to ssl/tls
                            identified_service = Some("ssl/tls".to_string());
                            // Try to extract the Common Name (CN) from the certificate subject 
                            // as a potential hostname or version indicator.
                            if let Some(cn) = cert_info_ref.subject.split(',') // Split subject DN by comma
                                .find(|s| s.trim().starts_with("CN=")) // Find the CN component
                            {
                                identified_version = Some(cn.trim_start_matches("CN=").trim().to_string()); // Extract the CN value
                            }
                        }

                        // Priority 2: Fingerprint using Banner (if no SSL/TLS service identified yet)
                        if identified_service.is_none() {
                            if let Some(banner_str) = banner_text.as_ref() {
                                // Use the ServiceFingerprints instance method
                                if let Some((service, version)) = fingerprint_db_clone.identify_service(port, banner_str) {
                                    identified_service = Some(service);
                                    identified_version = version;
                                }
                            }
                        }

                        // Priority 3: Use ML identification if enabled and service is unknown/ambiguous
                        if ml_identification_clone && (identified_service.is_none() || identified_service.as_deref() == Some("unknown")) {
                            if let Some(ref banner_content) = result_entry.banner {
                                // Call the correct identification method based on feature flag
                                #[cfg(feature = "ml")]
                                if let Some((ml_service, ml_version)) = ml_identifier_clone.as_ref().identify_service(
                                    banner_content.as_str(),
                                    port,
                                    0.0,   // Placeholder for response_time_ms
                                    false, // Placeholder for immediate_close
                                    true   // Placeholder for server_initiated (assuming banner exists)
                                ) {
                                    debug!("ML identified service for port {}: {} (Version: {:?})", port, ml_service, ml_version);
                                    identified_service = Some(ml_service); // ml_service is already String
                                    // Use the version from ML if available, otherwise try banner extraction again
                                    identified_version = ml_version.or_else(|| {
                                        identified_service.as_deref().and_then(|service_name| {
                                            crate::utils::extract_version_from_banner(service_name, banner_content.as_str())
                                        })
                                    });
                                }

                                // Fallback version without ML feature flag
                                #[cfg(not(feature = "ml"))]
                                {
                                    // Create the bytes explicitly to help with type inference
                                    let content_bytes: &[u8] = banner_content.as_bytes();
                                    if let Some((ml_service, ml_version)) = ml_identifier_clone.as_ref().identify_service(
                                        content_bytes,
                                        port,
                                        0.0,  // response_time_ms (placeholder)
                                        false, // immediate_close (placeholder)
                                        true  // server_initiated (placeholder)
                                    ) {
                                        debug!("Minimal service identification for port {}: {} (Version: {:?})", port, ml_service, ml_version);
                                        identified_service = Some(ml_service); // ml_service is already String
                                        identified_version = ml_version;
                                    }
                                }
                            }
                        }

                        // Priority 4: Analyze HTTP Headers (if banner looks like HTTP)
                        let is_http_like = identified_service.as_deref() == Some("http") || 
                                          banner_text.as_deref().unwrap_or("").starts_with("HTTP/");
                        if is_http_like {
                            if let Some(banner_str) = banner_text.as_ref() {
                                // Use the HttpAnalyzer instance to analyze the response
                                let http_info = http_analyzer_clone.analyze_response(
                                    banner_str.as_bytes(), // Pass banner as bytes
                                    None // Pass None for response_time_ms (not tracked here)
                                );
                                // If Server header exists, use it as primary version for HTTP
                                if let Some(server) = &http_info.server {
                                    identified_service = Some("http".to_string()); // Confirm/set as HTTP
                                    identified_version = Some(server.clone());
                                }
                                result_entry.http_info = Some(http_info); // Store detailed HTTP info
                            }
                        }

                        // Priority 5: Fallback to Port Number Mapping
                        if identified_service.is_none() {
                            // Use the common port mapping from models.rs as a last resort
                            identified_service = crate::models::CommonPorts::get_service(port).map(String::from);
                        }

                        // Update the final service and version in the results
                        result_entry.service = identified_service;
                        result_entry.version = identified_version;

                        // --- Vulnerability Identification (Placeholder) ---
                        let mut vulns = Vec::<VulnInfo>::new();
                        // Example placeholder check:
                        if result_entry.service.as_deref() == Some("ssh") && result_entry.version.as_deref().map_or(false, |v| v.contains("OpenSSH_7")) {
                            vulns.push(VulnInfo { id: "CVE- Placeholder".to_string(), description: "Potential vulnerability in OpenSSH 7.x".to_string(), severity: "Info".to_string() });
                        }
                        result_entry.vulns = vulns;
                        // --- End Vulnerability Identification ---

                        if verbose_clone {
                            debug!("Analysis complete for port {}: Service={:?}, Version={:?}",
                                   port, result_entry.service, result_entry.version);
                        }
                    }
                    // Drop map guard and permit
                    drop(map_guard);
                    debug!("Finished analysis for port {}. Releasing permit.", port);
                    drop(permit);
                });
                analysis_tasks.push(analysis_task);
            }
        }

        // Add timeout for the analysis phase to prevent hanging
        match tokio::time::timeout(
            Duration::from_secs(60 * 2), // 2 minute timeout for analysis phase
            join_all(analysis_tasks)
        ).await {
            Ok(_) => info!("Post-scan analysis complete."),
            Err(_) => {
                warn!("Post-scan analysis timed out after 2 minutes. Some operations may not have completed.");
                info!("Proceeding with final result collection...");
            }
        }
        // --- End Post-scan Analysis ---

        let end_time = Utc::now();
        let final_results_map = results_map.lock().await.clone();
        let mut final_open_ports = open_ports_set.lock().await.clone();
        
        // Final pass: ensure all ports with Open or OpenFiltered status from any scan type are in open_ports
        for (&port, result) in &final_results_map {
            let is_open = result.tcp_states.values().any(|&status| 
                status == PortStatus::Open || status == PortStatus::OpenFiltered);
            
            let is_open_udp = result.udp_state.map_or(false, |status| 
                status == PortStatus::Open || status == PortStatus::OpenFiltered);
            
            // Consider service detection (banner grab, etc.) that identified a known service
            let has_service = result.service.is_some();
            
            if (is_open || is_open_udp || has_service) && !final_open_ports.contains(&port) {
                info!("Adding port {} to open ports list based on post-analysis", port);
                final_open_ports.insert(port);
            }
        }
        
        // Log a summary of all ports and their states
        if debug_mode {
            info!("Final scan results:");
            
            // Reset the open_ports list to use the final_status field
            final_open_ports.clear();
            
            for (&port, result) in &final_results_map {
                let states: Vec<(ScanType, PortStatus)> = result.tcp_states.iter()
                    .map(|(&s, &p)| (s, p))
                    .collect();
                
                // Use the final_status field to determine if the port should be added to open_ports
                if result.final_status == PortStatus::Open || result.final_status == PortStatus::OpenFiltered {
                    info!("Port {}: {} (from final_status) - Adding to open ports list", port, result.final_status);
                    final_open_ports.insert(port);
                } else {
                    info!("Port {}: {:?} - Status: {}", port, states, result.final_status);
                }
            }
        }
        
        let final_packets_sent = *packets_sent.lock().await;
        let final_successful_scans = *successful_scans.lock().await;

        info!("Scan finished in {} seconds. Found {} open/open|filtered ports.", (end_time - start_time).num_seconds(), final_open_ports.len());
        
        if debug_mode {
            debug!("Tasks attempted (packets_sent counter): {}, Tasks completed without error (successful_scans counter): {}", final_packets_sent, final_successful_scans);
        }

        Ok(ScanResults {
            target: self.target.clone(),
            target_ip: self.target_ip.to_string(),
            open_ports: final_open_ports,
            results: final_results_map, 
            start_time,
            end_time,
            scan_types: self.scan_types.clone(),
            packets_sent: final_packets_sent as usize, 
            successful_scans: final_successful_scans as usize,
            os_summary: None,
            risk_assessment: None,
            service_categories: None,
        })
    }

    /// Set enhanced evasion options
    pub fn set_enhanced_evasion(&mut self, enable: bool, os: &str, jitter: u8) {
        info!("Setting enhanced evasion: enabled={}, mimic_os={}, ttl_jitter={}", enable, os, jitter);
        // Store the provided values in the struct fields
        self.enhanced_evasion = enable;
        self.mimic_os = os.to_string();
        self.ttl_jitter = jitter;
    }

    /// Set protocol variant for mimicry scans
    pub fn set_protocol_variant(&mut self, variant: Option<&str>) {
        info!("Setting protocol variant: {:?}", variant);
        // Store the provided value in the struct field
        self.protocol_variant = variant.map(|s| s.to_string());
    }

    /// Set the memory log buffer (used if memory_only mode is enabled)
    pub fn set_memory_log(&mut self, buffer: Arc<parking_lot::Mutex<MemoryLogBuffer>>) {
        info!("Setting memory log buffer.");
        // Store the provided buffer in the struct field
        self.memory_log = Some(buffer);
    }

    /// Set DNS tunnel options
    pub fn set_dns_tunnel_options(&mut self, dns_server: Option<IpAddr>, domain: Option<&str>) {
        info!("Setting DNS tunnel options: server={:?}, domain={:?}", dns_server, domain);
        // Store the provided values in the struct fields
        self.dns_tunnel_server = dns_server;
        self.dns_tunnel_domain = domain.map(|s| s.to_string());
    }

    /// Run scan tasks for individual ports
    async fn run_port_scan_tasks(
        &self,
        scan_type: ScanType,
        semaphore: Arc<Semaphore>,
        results_map: Arc<Mutex<HashMap<u16, PortResult>>>,
        open_ports_set: Arc<Mutex<HashSet<u16>>>,
        packets_sent: Arc<Mutex<u64>>,
        successful_scans: Arc<Mutex<u64>>,
        target_ip: IpAddr,
        local_ip_v4: Option<Ipv4Addr>,
        ports: &[u16],
        timeout_scan: Duration,
        debug_mode: bool,
        use_ipv6: bool,
        evasion: bool,
        memory_log: Option<Arc<parking_lot::Mutex<MemoryLogBuffer>>>,
        enhanced_evasion: bool,
        mimic_os: String,
        ttl_jitter: u8,
        mimic_protocol: String,
        protocol_variant: Option<String>,
        _ml_identification: bool,
    ) -> Vec<JoinHandle<()>> {
        let mut tasks = Vec::with_capacity(ports.len());
        
        // Clone all values needed by the closure once outside the loop
        let rate_limiter = self.rate_limiter.clone();
        let frag_min_size = self.frag_min_size;
        let frag_max_size = self.frag_max_size;
        let frag_min_delay = self.frag_min_delay;
        let frag_max_delay = self.frag_max_delay;
        let frag_timeout = self.frag_timeout;
        let frag_first_min_size = self.frag_first_min_size;
        let frag_two_frags = self.frag_two_frags;
        
        // Process each port
        for &port in ports {
            // Create independent owned copies of all data needed for the task
            let semaphore_clone = semaphore.clone();
            let results_map_clone = results_map.clone();
            let open_ports_set_clone = open_ports_set.clone();
            let packets_sent_clone = packets_sent.clone();
            let successful_scans_clone = successful_scans.clone();
            let local_ip = local_ip_v4.map(IpAddr::V4);
            let target_ip_clone = target_ip;
            let timeout_scan_clone = timeout_scan;
            let use_ipv6_clone = use_ipv6;
            let _evasion_clone = evasion;
            let enhanced_evasion_clone = enhanced_evasion;
            let mimic_os_clone = mimic_os.clone();
            let ttl_jitter_clone = ttl_jitter;
            let mimic_protocol_clone = mimic_protocol.clone();
            let _protocol_variant_clone = protocol_variant.clone();
            let debug_mode_clone = debug_mode;
            let memory_log_clone = memory_log.clone();
            let rate_limiter_clone = rate_limiter.clone();
            let scan_type_clone = scan_type;
            let port_clone = port;
            
            // DNS tunnel specific variables
            let dns_server_clone = self.dns_tunnel_server;
            let dns_domain_clone = self.dns_tunnel_domain.clone();
            
            // Also clone fragment parameters
            let frag_min_size_clone = frag_min_size;
            let frag_max_size_clone = frag_max_size;
            let _frag_min_delay_clone = frag_min_delay;
            let _frag_max_delay_clone = frag_max_delay;
            let _frag_timeout_clone = frag_timeout;
            let _frag_first_min_size_clone = frag_first_min_size;
            let _frag_two_frags_clone = frag_two_frags;
            
            // Spawn a new async task for this port
            let task = tokio::spawn(async move {
                // Wait until we can acquire a permit from the semaphore
                let _permit = match semaphore_clone.acquire().await {
                    Ok(permit) => permit,
                    Err(e) => {
                        error!("Failed to acquire semaphore permit: {}", e);
                        return;
                    }
                };
                
                // Apply rate limiting if configured
                if let Some(limiter) = rate_limiter_clone {
                    if let Err(_wait_time) = limiter.check() {
                        // If rate limit reached, sleep for the required time
                        let sleep_time = std::time::Duration::from_millis(10); // Default sleep time
                        tokio::time::sleep(sleep_time).await;
                    }
                }
                
                // Increment packets sent counter
                {
                    let mut counter = packets_sent_clone.lock().await;
                    *counter += 1;
                }
                
                // Perform the specific scan type
                let result = match scan_type_clone {
                    ScanType::DnsTunnel => {
                        techniques::dns_tunnel_scan(
                            target_ip_clone,
                            port_clone,
                            local_ip,
                            use_ipv6_clone,
                            timeout_scan_clone,
                            dns_server_clone,
                            dns_domain_clone.clone()
                        ).await.map(|status| {
                            // Create reason for DNS tunnel scan
                            let reason = match status {
                                PortStatus::OpenFiltered => Some("DNS Tunnel scan: DNS query response received, port state ambiguous".to_string()),
                                PortStatus::Filtered => Some("DNS Tunnel scan: DNS query timeout or blocked".to_string()),
                                _ => Some("DNS Tunnel scan: Unexpected response".to_string()),
                            };
                            
                            let mut result = ScanResult::new(port_clone, status);
                            result.set_reason(reason.clone());
                            
                            // For converting to PortResult later
                            result.scan_type = Some(ScanType::DnsTunnel);
                            
                            result
                        })
                    },
                    ScanType::IcmpTunnel => {
                        techniques::icmp_tunnel_scan(
                            target_ip_clone,
                            port_clone,
                            local_ip,
                            use_ipv6_clone,
                            timeout_scan_clone
                        ).await.map(|status| {
                            // Create reason for ICMP tunnel scan
                            let reason = match status {
                                PortStatus::Open => Some("ICMP Tunnel scan: ICMP echo response with valid payload received".to_string()),
                                PortStatus::OpenFiltered => Some("ICMP Tunnel scan: Ambiguous ICMP response received".to_string()),
                                PortStatus::Filtered => Some("ICMP Tunnel scan: No ICMP response or timeout".to_string()),
                                _ => Some("ICMP Tunnel scan: Unexpected response".to_string()),
                            };
                            
                            let mut result = ScanResult::new(port_clone, status);
                            result.set_reason(reason.clone());
                            
                            // For converting to PortResult later
                            result.scan_type = Some(ScanType::IcmpTunnel);
                            
                            result
                        })
                    },
                    ScanType::Syn => {
                        techniques::syn_scan(
                            target_ip_clone,
                            port_clone,
                            local_ip,
                            use_ipv6_clone,
                            timeout_scan_clone,
                            enhanced_evasion_clone,
                            &mimic_os_clone,
                            ttl_jitter_clone
                        ).await.map(|status| {
                            // Create a reason string based on status for SYN scan
                            let reason = match status {
                                PortStatus::Open => Some("SYN scan: SYN-ACK response received, port is listening".to_string()),
                                PortStatus::Closed => Some("SYN scan: RST response received, port is not listening".to_string()),
                                PortStatus::Filtered => Some("SYN scan: No response or ICMP error, port is filtered by firewall".to_string()),
                                _ => None
                            };
                            
                            let mut result = ScanResult::new(port_clone, status);
                            result.set_reason(reason.clone());
                            
                            // For converting to PortResult later
                            result.scan_type = Some(ScanType::Syn);
                            
                            result
                        })
                    },
                    ScanType::Ssl => {
                        techniques::ssl_scan(
                            target_ip_clone,
                            port_clone,
                            timeout_scan_clone
                        ).await.map(|(status, cert_info, protocol)| {
                            // Create reason for SSL scan
                            let reason = match status {
                                PortStatus::Open => Some(format!("SSL scan: TLS handshake completed successfully using {}", protocol)),
                                PortStatus::Closed => Some("SSL scan: TCP connection refused, port is closed".to_string()),
                                PortStatus::Filtered => Some("SSL scan: TCP connection attempt timed out, port is filtered".to_string()),
                                PortStatus::OpenFiltered => Some("SSL scan: Connection established but TLS handshake timed out".to_string()),
                                _ => None
                            };
                            
                            let mut result = ScanResult::new(port_clone, status);
                            result.set_certificate_info(cert_info);
                            result.set_protocol_version(Some(protocol));
                            result.set_reason(reason.clone());
                            
                            // For converting to PortResult later
                            result.scan_type = Some(ScanType::Ssl);
                            
                            result
                        })
                    },
                    ScanType::Udp => {
                        techniques::udp_scan(
                            target_ip_clone,
                            port_clone,
                            local_ip,
                            use_ipv6_clone,
                            timeout_scan_clone
                        ).await.map(|status| {
                            // Create reason for UDP scan
                            let reason = match status {
                                PortStatus::Open => Some("UDP scan: Response data received from UDP service".to_string()),
                                PortStatus::Closed => Some("UDP scan: ICMP port unreachable message received (type 3, code 3)".to_string()),
                                PortStatus::OpenFiltered => Some("UDP scan: No response within timeout period, port may be open or filtered".to_string()),
                                PortStatus::Filtered => Some("UDP scan: Other ICMP error message received indicating filtered port".to_string()),
                                _ => None
                            };
                            
                            let mut result = ScanResult::new(port_clone, status);
                            result.set_reason(reason.clone());
                            
                            // For converting to PortResult later
                            result.scan_type = Some(ScanType::Udp);
                            
                            result
                        })
                    },
                    ScanType::Ack => {
                        techniques::ack_scan(
                            target_ip_clone,
                            port_clone,
                            local_ip,
                            use_ipv6_clone,
                            timeout_scan_clone,
                            enhanced_evasion_clone,
                            &mimic_os_clone,
                            ttl_jitter_clone
                        ).await.map(|(status, filter_reason)| {
                            let mut result = ScanResult::new(port_clone, status);
                            result.set_filter_reason(Some(filter_reason.clone()));
                            
                            // Use filter_reason directly as reason but prefix with scan type
                            result.set_reason(Some(format!("ACK scan: {}", filter_reason)));
                            
                            // For converting to PortResult later
                            result.scan_type = Some(ScanType::Ack);
                            
                            result
                        })
                    },
                    ScanType::Fin => {
                        techniques::fin_scan(
                            target_ip_clone,
                            port_clone,
                            local_ip,
                            use_ipv6_clone,
                            timeout_scan_clone,
                            enhanced_evasion_clone,
                            &mimic_os_clone,
                            ttl_jitter_clone
                        ).await.map(|status| {
                            // Create reason for FIN scan
                            let reason = match status {
                                PortStatus::Closed => Some("FIN scan: RST response received to FIN packet, RFC-compliant TCP stack indicates closed port".to_string()),
                                PortStatus::OpenFiltered => Some("FIN scan: No response to FIN packet, RFC-compliant TCP stack indicates open port or filtering".to_string()),
                                PortStatus::Filtered => Some("FIN scan: ICMP unreachable error received, port is filtered by firewall".to_string()),
                                _ => None
                            };
                            
                            let mut result = ScanResult::new(port_clone, status);
                            result.set_reason(reason.clone());
                            
                            // For converting to PortResult later
                            result.scan_type = Some(ScanType::Fin);
                            
                            result
                        })
                    },
                    ScanType::Xmas => {
                        techniques::xmas_scan(
                            target_ip_clone,
                            port_clone,
                            local_ip,
                            use_ipv6_clone,
                            timeout_scan_clone,
                            enhanced_evasion_clone,
                            &mimic_os_clone,
                            ttl_jitter_clone
                        ).await.map(|status| {
                            // Create reason for XMAS scan
                            let reason = match status {
                                PortStatus::Closed => Some("XMAS scan: RST response received to FIN+PSH+URG packet, RFC-compliant TCP stack indicates closed port".to_string()),
                                PortStatus::OpenFiltered => Some("XMAS scan: No response to FIN+PSH+URG packet, RFC-compliant TCP stack indicates open port or filtering".to_string()),
                                PortStatus::Filtered => Some("XMAS scan: ICMP unreachable error received, port is filtered by firewall".to_string()),
                                _ => None
                            };
                            
                            let mut result = ScanResult::new(port_clone, status);
                            result.set_reason(reason.clone());
                            
                            // For converting to PortResult later
                            result.scan_type = Some(ScanType::Xmas);
                            
                            result
                        })
                    },
                    ScanType::Null => {
                        techniques::null_scan(
                            target_ip_clone,
                            port_clone,
                            local_ip,
                            use_ipv6_clone,
                            timeout_scan_clone,
                            enhanced_evasion_clone,
                            &mimic_os_clone,
                            ttl_jitter_clone
                        ).await.map(|status| {
                            // Create reason for NULL scan
                            let reason = match status {
                                PortStatus::Closed => Some("NULL scan: RST response received to packet with no flags set, RFC-compliant TCP stack indicates closed port".to_string()),
                                PortStatus::OpenFiltered => Some("NULL scan: No response to packet with no flags set, RFC-compliant TCP stack indicates open port or filtering".to_string()),
                                PortStatus::Filtered => Some("NULL scan: ICMP unreachable error received, port is filtered by firewall".to_string()),
                                _ => None
                            };
                            
                            let mut result = ScanResult::new(port_clone, status);
                            result.set_reason(reason.clone());
                            
                            // For converting to PortResult later
                            result.scan_type = Some(ScanType::Null);
                            
                            result
                        })
                    },
                    ScanType::Window => {
                        techniques::window_scan(
                            target_ip_clone,
                            port_clone,
                            local_ip,
                            use_ipv6_clone,
                            timeout_scan_clone,
                            enhanced_evasion_clone,
                            &mimic_os_clone,
                            ttl_jitter_clone
                        ).await.map(|status| {
                            // Create reason for Window scan
                            let reason = match status {
                                PortStatus::Open => Some("Window scan: RST response received with non-zero TCP window size, OS fingerprint suggests open port".to_string()),
                                PortStatus::Closed => Some("Window scan: RST response received with zero TCP window size, OS fingerprint suggests closed port".to_string()),
                                PortStatus::Filtered => Some("Window scan: No response or ICMP error received, port is filtered by firewall".to_string()),
                                _ => None
                            };
                            
                            let mut result = ScanResult::new(port_clone, status);
                            result.set_reason(reason.clone());
                            
                            // For converting to PortResult later
                            result.scan_type = Some(ScanType::Window);
                            
                            result
                        })
                    },
                    ScanType::Frag => {
                        debug!("Using Fragmentation scan with min_size={}, max_size={}", frag_min_size_clone, frag_max_size_clone);
                        
                        techniques::frag_scan(
                            target_ip_clone,
                            port_clone,
                            local_ip,
                            use_ipv6_clone,
                            timeout_scan_clone,
                            enhanced_evasion_clone,
                            &mimic_os_clone,
                            ttl_jitter_clone
                        ).await.map(|status| {
                            // Create reason for fragmented scan
                            let reason = match status {
                                PortStatus::Open => Some("Fragmentation scan: SYN-ACK response received after fragmented SYN packet, port is open and reassembly succeeded".to_string()),
                                PortStatus::Closed => Some("Fragmentation scan: RST response received after fragmented SYN packet, port is closed and reassembly succeeded".to_string()),
                                PortStatus::Filtered => Some("Fragmentation scan: No response after fragmented SYN packet, port is filtered or fragments were blocked/dropped".to_string()),
                                _ => None
                            };
                            
                            let mut result = ScanResult::new(port_clone, status);
                            result.set_reason(reason.clone());
                            
                            // For converting to PortResult later
                            result.scan_type = Some(ScanType::Frag);
                            
                            result
                        })
                    },
                    ScanType::TlsEcho => {
                        let _payload: Vec<u8> = vec![]; // Empty payload in this case
                        techniques::tls_echo_scan(
                            target_ip_clone,
                            port_clone,
                            local_ip,
                            use_ipv6_clone,
                            _evasion_clone,
                            timeout_scan_clone
                        ).await.map(|status| {
                            // Create reason for TLS echo scan
                            let reason = match status {
                                PortStatus::Open => Some("TLS Echo scan: TCP connection established successfully, TLS service likely present".to_string()),
                                PortStatus::Closed => Some("TLS Echo scan: TCP connection refused, port is closed".to_string()),
                                PortStatus::Filtered => Some("TLS Echo scan: TCP connection attempt timed out, port is filtered by firewall".to_string()),
                                _ => None
                            };
                            
                            let mut result = ScanResult::new(port_clone, status);
                            result.set_reason(reason.clone());
                            
                            // For converting to PortResult later
                            result.scan_type = Some(ScanType::TlsEcho);
                            
                            result
                        })
                    },
                    ScanType::Mimic => {
                        let payload_bytes = MimicPayloads::get(&mimic_protocol_clone);
                        techniques::mimic_scan_with_payload(
                            target_ip_clone,
                            port_clone,
                            local_ip,
                            use_ipv6_clone,
                            _evasion_clone,
                            &mimic_protocol_clone,
                            payload_bytes.to_vec(),
                            timeout_scan_clone
                        ).await.map(|status| {
                            // Create reason for mimic scan
                            let reason = match status {
                                PortStatus::Open => Some(format!("Mimic scan: Response received after sending {} protocol payload, service identified", mimic_protocol_clone)),
                                PortStatus::Closed => Some(format!("Mimic scan: Connection refused when sending {} protocol payload, port is closed", mimic_protocol_clone)),
                                PortStatus::Filtered => Some(format!("Mimic scan: No response after sending {} protocol payload, port filtered or wrong service type", mimic_protocol_clone)),
                                PortStatus::OpenFiltered => Some(format!("Mimic scan: Ambiguous response to {} protocol payload, could be filtered or incorrect service", mimic_protocol_clone)),
                                _ => None
                            };
                            
                            let mut result = ScanResult::new(port_clone, status);
                            result.set_reason(reason.clone());
                            
                            // For converting to PortResult later
                            result.scan_type = Some(ScanType::Mimic);
                            
                            result
                        })
                    }
                };
                
                // Process the scan result
                if let Ok(scan_result) = &result {
                    // Increment successful scans counter
                    {
                        let mut counter = successful_scans_clone.lock().await;
                        *counter += 1;
                    }
                    
                    // Log result if memory logger is available and debug is enabled
                    if let Some(memory_log_ref) = &memory_log_clone {
                        // Create a log message string that's independent of any references
                        let log_message = format!("Scanned port {} with {} scan: {:?}", port_clone, scan_type_clone, result);
                        
                        // Now log the independent message - no need for await with parking_lot::Mutex
                        memory_log_ref.lock().log("DEBUG", &log_message);
                    }
                    
                    // Update the results map with the scan result
                    {
                        let mut results_guard = results_map_clone.lock().await;
                        
                        // Get or create the PortResult for this port
                        let port_result = results_guard.entry(port_clone).or_insert_with(PortResult::default);
                        
                        // Insert the status for this scan type (doesn't overwrite all results)
                        match scan_type_clone {
                            ScanType::Udp => {
                                port_result.udp_state = Some(scan_result.status);
                            },
                            _ => {
                                // Handle as a TCP scan type
                                port_result.tcp_states.insert(scan_type_clone, scan_result.status);
                                
                                // Store the scan-specific reason in tcp_reasons if available
                                if let Some(reason) = &scan_result.reason {
                                    port_result.tcp_reasons.insert(scan_type_clone, reason.clone());
                                }
                            }
                        }
                        
                        // Set other fields as needed
                        if let Some(reason) = &scan_result.reason {
                            if port_result.reason.is_none() || port_result.reason.as_ref().map_or(true, |r| r.is_empty()) {
                                port_result.reason = Some(reason.clone());
                            }
                        }
                        
                        // Copy certificate info if available
                        if scan_result.certificate_info.is_some() {
                            port_result.cert_info = scan_result.certificate_info.clone();
                        }
                        
                        // Copy protocol version if available and not already set
                        if scan_result.tls_protocol_version.is_some() && port_result.tls_protocol_version.is_none() {
                            port_result.tls_protocol_version = scan_result.tls_protocol_version.clone();
                        }
                        
                        // Update the port's final_status based on this scan result
                        match scan_result.status {
                            PortStatus::Open => {
                                if debug_mode_clone {
                                    info!("Adding port {} to open ports list (Open from {:?})", port_clone, scan_type_clone);
                                }
                                open_ports_set_clone.lock().await.insert(port_clone);
                                // Mark as definitely open in final_status
                                port_result.final_status = PortStatus::Open;
                            },
                            PortStatus::OpenFiltered => {
                                // Only update if not already Open
                                if port_result.final_status != PortStatus::Open {
                                    if debug_mode_clone {
                                        info!("Adding port {} to open ports list (OpenFiltered from {:?})", port_clone, scan_type_clone);
                                    }
                                    open_ports_set_clone.lock().await.insert(port_clone);
                                    port_result.final_status = PortStatus::OpenFiltered;
                                }
                            },
                            _ => {
                                // For other statuses, don't change final_status if already set as Open/OpenFiltered
                                if port_result.final_status == PortStatus::Filtered {
                                    port_result.final_status = scan_result.status;
                                }
                            }
                        }
                    }
                }
                else if let Err(e) = &result {
                    error!("Error scanning port {} with {}: {}", port_clone, scan_type_clone, e);
                    
                    // Even in case of error, we want to record something
                    let mut results_guard = results_map_clone.lock().await;
                    let port_result = results_guard.entry(port_clone).or_insert_with(PortResult::default);
                    
                    // Assume filtered in case of scan error but don't change any existing determinations
                    if port_result.final_status == PortStatus::Filtered {
                        port_result.final_status = PortStatus::Filtered;
                    }
                    
                    // Store error message as reason
                    if port_result.reason.is_none() {
                        port_result.reason = Some(format!("Error: {}", e));
                    }
                    
                    // Don't modify tcp_states or udp_state here
                }
            });
            
            tasks.push(task);
        }
        
        tasks
    }

    // Initialize all structures needed for scanning
    pub fn initialize_scan(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        // Create a ScanMetrics instance to track scan statistics
        let metrics = ScanMetrics::new();
        
        // Wrap metrics in Arc<Mutex<>> for thread-safe sharing
        let metrics = Arc::new(Mutex::new(metrics));
        
        // Share metrics with the scanner instance
        self.metrics = Some(metrics);
        
        // Initialize the results map
        self.results_map = HashMap::new();
        
        Ok(())
    }
}
