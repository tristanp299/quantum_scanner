use anyhow::{Context, Result};
use chrono::Utc;
use log::{debug, error, info, warn};
use std::collections::{HashMap, HashSet, VecDeque};
use std::net::IpAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{mpsc, Semaphore};
use tokio::time::sleep;
use parking_lot::Mutex;

// Replace trust-dns imports with hickory-dns
use hickory_resolver::config::{ResolverConfig, ResolverOpts};
use hickory_resolver::TokioAsyncResolver;

use crate::models::{PortResult, PortStatus, ScanResults, ScanType};
use crate::utils;

/// Determine if any of the scan types require raw socket capabilities
pub fn requires_raw_sockets(scan_types: &[ScanType]) -> bool {
    scan_types.iter().any(|&st| matches!(
        st,
        ScanType::Syn | ScanType::Fin | ScanType::Xmas | ScanType::Null | 
        ScanType::Window | ScanType::Frag
    ))
}

/// Main scanner implementation
pub struct QuantumScanner {
    /// Target hostname or IP
    target: String,
    
    /// Resolved target IP address
    target_ip: IpAddr,
    
    /// Local IP address for packet crafting
    local_ip: Option<IpAddr>,
    
    /// Ports to scan
    ports: Vec<u16>,
    
    /// Scan types to use
    scan_types: Vec<ScanType>,
    
    /// Maximum concurrent operations
    concurrency: usize,
    
    /// Maximum packets per second rate limit
    max_rate: usize,
    
    /// Enable evasion techniques
    evasions: bool,
    
    /// Enable verbose output
    verbose: bool,
    
    /// Use IPv6 addressing
    use_ipv6: bool,
    
    /// Output results in JSON format
    json_output: bool,
    
    /// Scan timeout
    timeout_scan: f64,
    
    /// Connect timeout
    timeout_connect: f64,
    
    /// Banner grabbing timeout
    timeout_banner: f64,
    
    /// Protocol to mimic in mimic scans
    mimic_protocol: String,
    
    // Fragmentation scan parameters
    frag_min_size: u16,
    frag_max_size: u16,
    frag_min_delay: f64,
    frag_max_delay: f64,
    frag_timeout: u64,
    frag_first_min_size: u16,
    frag_two_frags: bool,
    
    /// Scan results
    results: HashMap<u16, PortResult>,
    
    /// Open ports from any scan type
    open_ports: HashSet<u16>,
    
    /// History for rate limiting
    history: Arc<Mutex<VecDeque<Instant>>>,
    
    /// Adaptive rate limiting factor
    adaptation_factor: Arc<Mutex<f64>>,
    
    /// Scan start time
    scan_start_time: chrono::DateTime<Utc>,
    
    /// Scan end time
    scan_end_time: Option<chrono::DateTime<Utc>>,
    
    /// Packets sent counter
    packets_sent: Arc<Mutex<usize>>,
    
    /// Successful scans counter
    successful_scans: Arc<Mutex<usize>>,
    
    /// Whether to use enhanced evasion techniques
    enhanced_evasion: bool,
    
    /// Operating system to mimic in enhanced evasion mode
    mimic_os: String,
    
    /// TTL jitter amount for enhanced evasion
    ttl_jitter: u8,
    
    /// Protocol variant for protocol mimicry
    protocol_variant: Option<String>,
    
    /// Memory-only log buffer
    memory_log: Option<Arc<utils::MemoryLogBuffer>>,
}

impl QuantumScanner {
    /// Create a new scanner instance
    ///
    /// # Arguments
    /// * `target` - The target IP address, hostname, or CIDR notation
    /// * `ports` - List of ports to scan
    /// * `scan_types` - Types of scans to perform
    /// * Additional configuration parameters
    pub async fn new(
        target: &str,
        ports: Vec<u16>,
        scan_types: Vec<ScanType>,
        concurrency: usize,
        max_rate: usize,
        evasions: bool,
        verbose: bool,
        use_ipv6: bool,
        json_output: bool,
        timeout_scan: f64,
        timeout_connect: f64,
        timeout_banner: f64,
        mimic_protocol: &str,
        frag_min_size: u16,
        frag_max_size: u16,
        frag_min_delay: f64,
        frag_max_delay: f64,
        frag_timeout: u64,
        frag_first_min_size: u16,
        frag_two_frags: bool,
        _log_file: &Path,
    ) -> Result<Self> {
        // Resolve target to IP address
        let target_ip = Self::resolve_target(target, use_ipv6).await
            .context("Failed to resolve target hostname")?;
        
        // Get local IP address for creating packets
        let local_ip = if use_ipv6 {
            utils::get_default_interface_ipv6()
        } else {
            utils::get_default_interface_ipv4()
        };
        
        // Initialize results map
        let mut results = HashMap::new();
        for &port in &ports {
            results.insert(port, PortResult::default());
        }
        
        // Create scanner with initial configuration
        Ok(Self {
            target: target.to_string(),
            target_ip,
            local_ip,
            ports,
            scan_types,
            concurrency,
            max_rate,
            evasions,
            verbose,
            use_ipv6,
            json_output,
            timeout_scan,
            timeout_connect,
            timeout_banner,
            mimic_protocol: mimic_protocol.to_string(),
            frag_min_size,
            frag_max_size,
            frag_min_delay,
            frag_max_delay,
            frag_timeout,
            frag_first_min_size,
            frag_two_frags,
            results,
            open_ports: HashSet::new(),
            history: Arc::new(Mutex::new(VecDeque::new())),
            adaptation_factor: Arc::new(Mutex::new(1.0)),
            scan_start_time: Utc::now(),
            scan_end_time: None,
            packets_sent: Arc::new(Mutex::new(0)),
            successful_scans: Arc::new(Mutex::new(0)),
            enhanced_evasion: false,
            mimic_os: "random".to_string(),
            ttl_jitter: 2,
            protocol_variant: None,
            memory_log: None,
        })
    }
    
    /// Resolve a target name to an IP address
    async fn resolve_target(target: &str, use_ipv6: bool) -> Result<IpAddr> {
        // If it's already a valid IP, return it
        if let Ok(ip) = target.parse::<IpAddr>() {
            return Ok(ip);
        }
        
        // Otherwise, resolve the hostname
        let resolver = TokioAsyncResolver::tokio_from_system_conf()
            .context("Failed to create DNS resolver")?;
        
        // Choose IPv6 or IPv4 lookup based on configuration
        if use_ipv6 {
            let response = resolver.ipv6_lookup(target).await?;
            let record = response.iter().next()
                .context("No IPv6 addresses found for host")?;
            Ok(IpAddr::V6(record.0))
        } else {
            let response = resolver.ipv4_lookup(target).await?;
            let record = response.iter().next()
                .context("No IPv4 addresses found for host")?;
            Ok(IpAddr::V4(record.0))
        }
    }
    
    /// Set enhanced evasion options
    ///
    /// # Arguments
    /// * `enable` - Whether to enable enhanced evasion
    /// * `os` - OS to mimic (e.g., "windows", "linux", "macos")
    /// * `jitter` - TTL jitter amount (1-5)
    pub fn set_enhanced_evasion(&mut self, enable: bool, os: &str, jitter: u8) {
        self.enhanced_evasion = enable;
        self.mimic_os = os.to_string();
        self.ttl_jitter = jitter;
        
        debug!("Enhanced evasion {} with OS profile {} and TTL jitter {}", 
               if enable { "enabled" } else { "disabled" }, 
               os, 
               jitter);
    }
    
    /// Set the protocol variant for mimicry
    ///
    /// # Arguments
    /// * `variant` - Protocol variant (e.g., "1.1" for HTTP/1.1)
    pub fn set_protocol_variant(&mut self, variant: Option<&str>) {
        self.protocol_variant = variant.map(String::from);
        
        if let Some(v) = &self.protocol_variant {
            debug!("Protocol variant set to {}", v);
        }
    }
    
    /// Set memory log buffer
    ///
    /// # Arguments
    /// * `buffer` - Memory log buffer
    pub fn set_memory_log(&mut self, buffer: Arc<utils::MemoryLogBuffer>) {
        self.memory_log = Some(buffer);
    }
    
    /// Get a TTL value based on evasion settings
    ///
    /// Uses advanced TTL jittering when enhanced evasion is enabled
    fn get_ttl(&self) -> u8 {
        if self.enhanced_evasion {
            utils::get_advanced_ttl(&self.mimic_os, self.ttl_jitter)
        } else if self.evasions {
            utils::get_ttl(true, Some(&self.mimic_os))
        } else {
            utils::get_ttl(false, None)
        }
    }
    
    /// Get a protocol-specific payload based on mimicry settings
    ///
    /// Uses advanced protocol mimicry when enhanced evasion is enabled
    fn get_protocol_payload(&self, protocol: &str) -> Vec<u8> {
        if self.enhanced_evasion {
            utils::generate_advanced_mimicry(protocol, self.protocol_variant.as_deref())
        } else {
            // Use simpler payload from MimicPayloads
            crate::models::MimicPayloads::get(protocol).to_vec()
        }
    }
    
    /// Run the full scan process with enhanced error handling
    pub async fn run_scan(&mut self) -> Result<ScanResults> {
        // Set up semaphore for concurrency control
        let semaphore = Arc::new(Semaphore::new(self.concurrency));
        
        // Channel for scan results
        let (tx, mut rx) = mpsc::channel(100);
        
        // Set start time
        self.scan_start_time = Utc::now();
        
        // Counter for progress tracking
        let total_scans = self.ports.len() * self.scan_types.len();
        let mut completed = 0;
        
        // Clone shared resources for scan tasks
        let packets_sent = self.packets_sent.clone();
        let successful_scans = self.successful_scans.clone();
        let history = self.history.clone();
        let adaptation_factor = self.adaptation_factor.clone();
        
        // Store results from port scans to update later
        let mut scan_results = Vec::new();
        
        // Enhanced error handling - track failed scans
        let mut failed_scans = 0;
        let max_failed_ratio = 0.2; // Allow up to 20% of scans to fail before aborting
        
        // Log scan start with enhanced operational security
        let scan_info = format!("Starting scan of {} with {} scan types and {} ports",
            if self.enhanced_evasion { "[REDACTED]" } else { &self.target },
            self.scan_types.len(),
            self.ports.len()
        );
        info!("{}", scan_info);
        self.memory_log("INFO", &scan_info);
        
        // Launch a task for each port and scan type
        let mut scan_tasks = Vec::new();
        for &port in &self.ports {
            for &scan_type in &self.scan_types {
                // Create a copy of required resources for this task
                let semaphore_clone = semaphore.clone();
                let tx_clone = tx.clone();
                let packets_sent_clone = packets_sent.clone();
                let successful_scans_clone = successful_scans.clone();
                let history_clone = history.clone();
                let adaptation_factor_clone = adaptation_factor.clone();
                
                // Clone parameters needed for the scan
                let target_ip = self.target_ip;
                let local_ip = self.local_ip;
                let use_ipv6 = self.use_ipv6;
                let evasions = self.evasions;
                let enhanced_evasion = self.enhanced_evasion;
                let mimic_os = self.mimic_os.clone();
                let ttl_jitter = self.ttl_jitter;
                let protocol_variant = self.protocol_variant.clone();
                let timeout_scan = self.timeout_scan;
                let _timeout_banner = self.timeout_banner;
                let mimic_protocol = self.mimic_protocol.clone();
                let frag_min_size = self.frag_min_size;
                let frag_max_size = self.frag_max_size;
                let frag_min_delay = self.frag_min_delay;
                let frag_max_delay = self.frag_max_delay;
                let frag_timeout = self.frag_timeout;
                let frag_first_min_size = self.frag_first_min_size;
                let frag_two_frags = self.frag_two_frags;
                
                // Create the scan task
                let scan_task = tokio::spawn(async move {
                    // Acquire semaphore permit to control concurrency
                    match semaphore_clone.acquire().await {
                        Ok(_permit) => {},
                        Err(_) => return (port, scan_type, PortStatus::Filtered, None, Err(anyhow::anyhow!("Semaphore acquisition failed"))),
                    }
                    
                    // Implement rate limiting
                    Self::adaptive_delay_static(
                        history_clone.clone(), 
                        adaptation_factor_clone.clone(),
                        500 // Default max rate if needed
                    ).await;
                    
                    // Get TTL value based on evasion settings
                    let _ttl = if enhanced_evasion {
                        utils::get_advanced_ttl(&mimic_os, ttl_jitter)
                    } else if evasions {
                        utils::get_ttl(true, Some(&mimic_os))
                    } else {
                        utils::get_ttl(false, None)
                    };
                    
                    // Prepare protocol-specific payload if needed
                    let payload = if enhanced_evasion && matches!(scan_type, ScanType::Mimic) {
                        Some(utils::generate_advanced_mimicry(&mimic_protocol, protocol_variant.as_deref()))
                    } else {
                        None
                    };
                    
                    // Perform the actual scan based on scan type with improved error handling
                    let scan_result = match scan_type {
                        ScanType::Syn => {
                            crate::techniques::syn_scan(
                                target_ip,
                                port,
                                local_ip,
                                use_ipv6,
                                evasions,
                                Duration::from_secs_f64(timeout_scan),
                            ).await
                        },
                        ScanType::Ssl => {
                            let ssl_result = crate::techniques::ssl_scan(
                                target_ip,
                                port,
                                Duration::from_secs_f64(timeout_scan),
                            ).await;
                            
                            // Process SSL scan data and return port status
                            match ssl_result {
                                Ok((status, _, _)) => Ok(status),
                                Err(e) => Err(e),
                            }
                        },
                        ScanType::Udp => {
                            crate::techniques::udp_scan(
                                target_ip,
                                port,
                                local_ip,
                                use_ipv6,
                                Duration::from_secs_f64(timeout_scan),
                            ).await
                        },
                        ScanType::Ack => {
                            let ack_result = crate::techniques::ack_scan(
                                target_ip,
                                port,
                                local_ip,
                                use_ipv6,
                                evasions,
                                Duration::from_secs_f64(timeout_scan),
                            ).await;
                            
                            match ack_result {
                                Ok((status, _)) => Ok(status),
                                Err(e) => Err(e),
                            }
                        },
                        ScanType::Fin => crate::techniques::fin_scan(
                            target_ip,
                            port,
                            local_ip,
                            use_ipv6,
                            evasions,
                            Duration::from_secs_f64(timeout_scan),
                        ).await,
                        ScanType::Xmas => crate::techniques::xmas_scan(
                            target_ip,
                            port,
                            local_ip,
                            use_ipv6,
                            evasions,
                            Duration::from_secs_f64(timeout_scan),
                        ).await,
                        ScanType::Null => crate::techniques::null_scan(
                            target_ip,
                            port,
                            local_ip,
                            use_ipv6,
                            evasions,
                            Duration::from_secs_f64(timeout_scan),
                        ).await,
                        ScanType::Window => crate::techniques::window_scan(
                            target_ip,
                            port,
                            local_ip,
                            use_ipv6,
                            evasions,
                            Duration::from_secs_f64(timeout_scan),
                        ).await,
                        ScanType::TlsEcho => crate::techniques::tls_echo_scan(
                            target_ip,
                            port,
                            local_ip,
                            use_ipv6,
                            evasions,
                            Duration::from_secs_f64(timeout_scan),
                        ).await,
                        ScanType::Mimic => {
                            // Use enhanced protocol mimicry if available
                            let protocol_payload = payload.unwrap_or_else(|| {
                                crate::models::MimicPayloads::get(&mimic_protocol).to_vec()
                            });
                            
                            crate::techniques::mimic_scan_with_payload(
                                target_ip,
                                port,
                                local_ip,
                                use_ipv6,
                                evasions,
                                &mimic_protocol,
                                protocol_payload,
                                Duration::from_secs_f64(timeout_scan),
                            ).await
                        },
                        ScanType::Frag => crate::techniques::fragmented_syn_scan(
                            target_ip,
                            port,
                            local_ip,
                            use_ipv6,
                            evasions,
                            frag_min_size,
                            frag_max_size,
                            frag_min_delay,
                            frag_max_delay,
                            frag_timeout,
                            frag_first_min_size,
                            frag_two_frags,
                            Duration::from_secs_f64(timeout_scan),
                        ).await,
                    };
                    
                    // Process the result with enhanced error handling
                    let result = match scan_result {
                        Ok(status) => {
                            *successful_scans_clone.lock() += 1;
                            (port, scan_type, status, None, Ok(()))
                        },
                        Err(e) => {
                            // More detailed error handling
                            let error_msg = format!("Scan error on port {}: {}", port, e);
                            (port, scan_type, PortStatus::Filtered, Some(error_msg), Err(anyhow::anyhow!("{}", e)))
                        }
                    };
                    
                    // Always increment packet counter for stats
                    *packets_sent_clone.lock() += 1;
                    
                    // Create a clone of all values for the channel
                    let port_clone = result.0;
                    let scan_type_clone = result.1;
                    let status_clone = result.2.clone(); // Clone this field
                    let error_msg_clone = result.3.clone();
                    let result_clone = (
                        port_clone,
                        scan_type_clone,
                        status_clone,
                        error_msg_clone,
                        if result.4.is_ok() { Ok(()) } else { Err(anyhow::anyhow!("Error")) }
                    );
                    
                    // Send result back through channel (with a clone)
                    let _ = tx_clone.send(result_clone).await;
                    
                    result
                });
                
                scan_tasks.push(scan_task);
            }
        }
        
        // Drop our copy of the sender to allow the channel to close when all tasks are done
        drop(tx);
        
        // Process results as they come in
        while let Some((port, scan_type, status, error_msg_opt, result)) = rx.recv().await {
            // Track failed scans for adaptive error handling
            if result.is_err() {
                failed_scans += 1;
                
                // Log error message
                if let Some(error_msg) = error_msg_opt {
                    debug!("{}", error_msg);
                    self.memory_log("ERROR", &error_msg);
                }
                
                // Check if we're seeing too many failures - may indicate IDS blocking
                let completed_so_far = completed + 1;
                if completed_so_far > 10 && failed_scans as f64 / completed_so_far as f64 > max_failed_ratio {
                    // Too many failures - potential IDS/firewall blocking
                    let warning = "High scan failure rate detected, possible active blocking. Consider aborting scan.";
                    warn!("{}", warning);
                    self.memory_log("WARNING", warning);
                    
                    // Back off more aggressively
                    let mut factor = adaptation_factor.lock();
                    *factor = (*factor * 2.0).min(10.0);
                }
            }
            
            // Update our results map
            let port_result = self.results.entry(port).or_insert_with(PortResult::default);
            port_result.tcp_states.insert(scan_type, status.clone());
            
            // If the port is open, add it to our open ports set
            if status == PortStatus::Open || status == PortStatus::OpenFiltered {
                self.open_ports.insert(port);
            }
            
            // Save the result for processing later
            scan_results.push((port, scan_type, status, result));
            
            // Update progress counter
            completed += 1;
            
            // Log progress periodically
            if completed % 100 == 0 || completed == total_scans {
                let progress_msg = format!("Scan progress: {}/{} complete", completed, total_scans);
                debug!("{}", progress_msg);
                self.memory_log("DEBUG", &progress_msg);
            }
        }
        
        // Perform further analysis on open ports
        for port in self.open_ports.iter().cloned().collect::<Vec<_>>() {
            if !self.enhanced_evasion {
                // Only do banner grabbing if we're not in enhanced evasion mode
                // as it can generate additional traffic that might be detected
                if let Ok(banner) = crate::techniques::banner_grabbing(
                    self.target_ip,
                    port,
                    Duration::from_secs_f64(self.timeout_banner)
                ).await {
                    if let Some(port_result) = self.results.get_mut(&port) {
                        port_result.banner = Some(banner);
                    }
                }
            }
            
            // Try to identify the service based on port number
            if let Some(port_result) = self.results.get_mut(&port) {
                port_result.service = crate::models::CommonPorts::get_service(port).map(String::from);
            }
        }
        
        // Set end time
        self.scan_end_time = Some(Utc::now());
        
        // Create final results
        let results = ScanResults {
            target: self.target.clone(),
            target_ip: self.target_ip,
            open_ports: self.open_ports.clone(),
            results: self.results.clone(),
            start_time: self.scan_start_time,
            end_time: self.scan_end_time.unwrap(),
            scan_types: self.scan_types.clone(),
        };
        
        // Log scan completion with enhanced operational security
        let duration = self.scan_end_time.unwrap() - self.scan_start_time;
        let completion_msg = format!(
            "Scan completed in {}s. Found {} open ports of {} scanned",
            duration.num_milliseconds() as f64 / 1000.0,
            self.open_ports.len(),
            self.ports.len()
        );
        info!("{}", completion_msg);
        self.memory_log("INFO", &completion_msg);
        
        Ok(results)
    }
    
    /// Static version of adaptive delay for use in spawned tasks
    async fn adaptive_delay_static(
        history: Arc<Mutex<VecDeque<Instant>>>,
        adaptation_factor: Arc<Mutex<f64>>,
        max_rate: usize,
    ) {
        let now = Instant::now();
        let target_interval = Duration::from_secs_f64(1.0 / max_rate as f64);
        
        // Update history and calculate current rate
        let mut interval = {
            let mut h = history.lock();
            h.push_back(now);
            
            // Remove entries older than 1 second
            while h.len() > 1 && now.duration_since(*h.front().unwrap()) > Duration::from_secs(1) {
                h.pop_front();
            }
            
            // Calculate adaptive factor based on queue length
            let current_rate = h.len();
            let ratio = current_rate as f64 / max_rate as f64;
            
            // Update adaptation factor based on current rate
            let mut af = adaptation_factor.lock();
            if ratio > 1.1 {
                *af += 0.1;  // Slow down
            } else if ratio < 0.9 && *af > 1.0 {
                *af -= 0.05;  // Speed up, but don't go below baseline
            }
            
            // Apply adaptation factor to target interval
            target_interval.mul_f64(*af)
        };
        
        // Don't sleep for less than 1ms to avoid excessive CPU use
        if interval < Duration::from_millis(1) {
            interval = Duration::from_millis(1);
        }
        
        // Sleep for the calculated interval
        sleep(interval).await;
    }

    /// Adaptive rate limiting
    ///
    /// Adjusts delay between operations based on current rate and success rate
    async fn adaptive_delay(
        &self,
        history: Arc<Mutex<VecDeque<Instant>>>,
        adaptation_factor: Arc<Mutex<f64>>,
    ) {
        let now = Instant::now();
        let target_interval = Duration::from_secs_f64(1.0 / self.max_rate as f64);
        
        // Update history and calculate current rate
        let mut interval = {
            let mut h = history.lock();
            h.push_back(now);
            
            // Remove entries older than 1 second
            while h.len() > 1 && now.duration_since(*h.front().unwrap()) > Duration::from_secs(1) {
                h.pop_front();
            }
            
            // Calculate adaptive factor based on queue length
            let current_rate = h.len();
            let ratio = current_rate as f64 / self.max_rate as f64;
            
            // Update adaptation factor based on current rate
            let mut af = adaptation_factor.lock();
            if ratio > 1.1 {
                *af += 0.1;  // Slow down
            } else if ratio < 0.9 && *af > 1.0 {
                *af -= 0.05;  // Speed up, but don't go below baseline
            }
            
            // Apply adaptation factor to target interval
            target_interval.mul_f64(*af)
        };
        
        // Don't sleep for less than 1ms to avoid excessive CPU use
        if interval < Duration::from_millis(1) {
            interval = Duration::from_millis(1);
        }
        
        // Sleep for the calculated interval
        sleep(interval).await;
    }

    /// Service fingerprinting based on port and response
    fn service_fingerprinting(&mut self) {
        for (&port, result) in &mut self.results {
            // If we already have service info, skip
            if result.service.is_some() && result.service.as_deref().unwrap() != "unknown" {
                continue;
            }
            
            // First check if it's a well-known port
            if let Some(service) = crate::models::CommonPorts::get_service(port) {
                result.service = Some(service.to_string());
            } else {
                // If no well-known service, use port number
                result.service = Some(format!("unknown-{}", port));
            }
        }
    }

    /// Check for known vulnerabilities based on service and version
    fn analyze_vulnerabilities(&mut self) {
        // This is a simplified placeholder
        // In a real implementation, this would check against a vulnerability database
        for result in self.results.values_mut() {
            // Check for SSL/TLS vulnerabilities
            if let Some(cert_info) = &result.cert_info {
                // Example: Check for expired certificates
                let now = Utc::now();
                // Parse not_after string to DateTime for comparison
                if let Ok(not_after) = chrono::DateTime::parse_from_rfc3339(&cert_info.not_after) {
                    if now > not_after {
                        result.vulns.push("SSL Certificate expired".to_string());
                    }
                }
                
                // Example: Check for old SSL/TLS versions
                if let Some(version) = &result.version {
                    if version.contains("SSLv3") || version.contains("TLSv1.0") {
                        result.vulns.push(format!("Insecure protocol version: {}", version));
                    }
                }
            }
        }
    }

    /// Log an event to the memory buffer if available
    fn memory_log(&self, level: &str, message: &str) {
        if let Some(buffer) = &self.memory_log {
            buffer.log(level, message);
        }
    }
} 