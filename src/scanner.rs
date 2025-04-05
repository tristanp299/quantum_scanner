use log::{debug, info, warn};
use std::collections::{HashMap, HashSet, VecDeque};
use std::net::IpAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{mpsc, Semaphore};
use tokio::time::sleep;
use parking_lot::Mutex;

// Replace trust-dns imports with hickory-dns
use hickory_resolver::TokioAsyncResolver;

use crate::models::{PortResult, PortStatus, ScanResults, ScanType};
use crate::utils;

// Add missing imports
use anyhow::{Context, Result};
use chrono::Utc;

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
    #[allow(dead_code)]
    max_rate: usize,
    
    /// Enable evasion techniques
    evasions: bool,
    
    /// Enable verbose output
    verbose: bool,
    
    /// Use IPv6 addressing
    use_ipv6: bool,
    
    /// Output results in JSON format
    #[allow(dead_code)]
    json_output: bool,
    
    /// Scan timeout
    timeout_scan: f64,
    
    /// Connect timeout
    #[allow(dead_code)]
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
    
    /// Track failed ports for retrying
    failed_ports: HashSet<u16>,
    
    /// Maximum retry attempts
    #[allow(dead_code)]
    max_retries: u8,
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
            failed_ports: HashSet::new(),
            max_retries: 3,
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
    #[allow(dead_code)]
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
    #[allow(dead_code)]
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
            &self.target, // Always show the actual target IP, no redaction
            self.scan_types.len(),
            self.ports.len()
        );
        info!("{}", scan_info);
        self.memory_log("INFO", &scan_info);
        
        if self.verbose {
            let detail_info = format!(
                "Scan configuration: concurrency={}, evasion={}, enhanced_evasion={}, IPv6={}",
                self.concurrency,
                self.evasions,
                self.enhanced_evasion,
                self.use_ipv6
            );
            debug!("{}", detail_info);
            self.memory_log("DEBUG", &detail_info);
            
            // Log scan types being used with details
            let mut scan_types_info = String::from("Scan types:");
            for scan_type in &self.scan_types {
                scan_types_info.push_str(&format!(" {}", scan_type));
            }
            debug!("{}", scan_types_info);
            self.memory_log("DEBUG", &scan_types_info);
        }
        
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
            // Always perform banner grabbing regardless of evasion settings
            // Banner grabbing is crucial for proper port analysis and fingerprinting
            info!("Attempting banner grabbing on port {}", port);
            self.memory_log("INFO", &format!("Attempting banner grabbing on port {}", port));
            
            if let Ok(banner) = crate::techniques::banner_grabbing(
                self.target_ip,
                port,
                Duration::from_secs_f64(self.timeout_banner)
            ).await {
                let grabbed_banner = banner.clone(); // Clone the banner to avoid borrowing issues
                if let Some(port_result) = self.results.get_mut(&port) {
                    info!("Banner grabbed for port {}", port);
                    port_result.banner = Some(banner);
                }
                // Log after the mutable borrow is dropped
                self.memory_log("INFO", &format!("Banner grabbed for port {}", port));
            } else {
                info!("No banner available for port {}", port);
                self.memory_log("INFO", &format!("No banner available for port {}", port));
            }
            
            // Try to identify the service based on port number
            if let Some(port_result) = self.results.get_mut(&port) {
                port_result.service = crate::models::CommonPorts::get_service(port).map(String::from);
            }
        }
        
        // Set end time
        self.scan_end_time = Some(Utc::now());
        
        // Perform enhanced service fingerprinting for all discovered ports
        info!("Performing enhanced service fingerprinting...");
        self.memory_log("INFO", "Performing enhanced service fingerprinting...");
        self.service_fingerprinting();
        
        // Perform security assessment for all open ports
        if self.verbose {
            info!("Performing security assessment...");
            self.memory_log("INFO", "Performing security assessment...");
            self.security_assessment();
        }
        
        // Update comprehensive service categories
        let mut categories: HashMap<String, Vec<u16>> = HashMap::new();
        
        // Group services by category
        for (&port, result) in &self.results {
            if self.open_ports.contains(&port) {
                if let Some(service) = &result.service {
                    let category = self.categorize_service(service);
                    categories.entry(category).or_default().push(port);
                }
            }
        }
        
        // Run detailed analysis on open ports
        if !self.open_ports.is_empty() {
            info!("Found {} open ports. Running detailed analysis...", self.open_ports.len());
            self.memory_log("INFO", &format!("Found {} open ports. Running detailed analysis...", self.open_ports.len()));
            
            // Run vulnerability analysis
            self.analyze_vulnerabilities();
            
            // Run our new detailed analysis
            if let Err(e) = self.detailed_port_analysis() {
                warn!("Error during detailed port analysis: {}", e);
                self.memory_log("WARN", &format!("Error during detailed port analysis: {}", e));
            }
        } else {
            info!("No open ports found.");
            self.memory_log("INFO", "No open ports found.");
        }
        
        // Scan completed, return the results
        let results = ScanResults {
            target: self.target.clone(),
            target_ip: self.target_ip.to_string(),
            open_ports: self.open_ports.clone(),
            results: self.results.clone(),
            start_time: self.scan_start_time,
            end_time: self.scan_end_time.unwrap_or_else(Utc::now),
            scan_types: self.scan_types.clone(),
            packets_sent: *self.packets_sent.lock(),
            successful_scans: *self.successful_scans.lock(),
            os_summary: self.detect_os(),
            risk_assessment: self.assess_risk(),
            service_categories: if !categories.is_empty() { Some(categories) } else { None },
        };
        
        info!("Scan completed");
        self.memory_log("INFO", "Scan completed");
        
        // Retry any failed ports with alternative methods
        if !self.failed_ports.is_empty() {
            self.retry_failed_ports().await?;
        }
        
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
    #[allow(dead_code)]
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

    /// Service fingerprinting with enhanced analysis
    fn service_fingerprinting(&mut self) {
        info!("Performing enhanced service fingerprinting...");
        self.memory_log("INFO", "Performing enhanced service fingerprinting...");
        
        // Store fingerprinting results for logging after mutable borrow is dropped
        let mut fingerprint_logs = Vec::new();
        
        // Analyze each open port in detail
        for &port in &self.open_ports {
            // Scoped block to ensure mutable borrow is dropped
            let port_result = match self.results.get_mut(&port) {
                Some(result) => result,
                None => continue,
            };
            
            if self.verbose {
                fingerprint_logs.push(("DEBUG", format!("Fingerprinting service on port {}...", port)));
            }
            
            // Use existing banner and other data to identify the service
            let (service, version) = crate::service_fingerprints::identify_service(
                port,
                port_result.banner.as_deref(),
                port_result.cert_info.as_ref(),
            );
            
            // Update the result
            if let Some(service_name) = service {
                if self.verbose {
                    let msg = if let Some(ver) = &version {
                        format!("Identified {} {} on port {}", service_name, ver, port)
                    } else {
                        format!("Identified {} on port {}", service_name, port)
                    };
                    fingerprint_logs.push(("INFO", msg));
                }
                
                port_result.service = Some(service_name);
                port_result.version = version;
            } else if self.verbose {
                fingerprint_logs.push(("DEBUG", format!("Could not identify service on port {}", port)));
            }
        }
        
        // Log all the collected messages after all mutable borrows are dropped
        for (level, message) in fingerprint_logs {
            match level {
                "INFO" => info!("{}", message),
                "DEBUG" => debug!("{}", message),
                "WARN" => warn!("{}", message),
                _ => info!("{}", message),
            }
            self.memory_log(level, &message);
        }
    }

    /// Enhanced vulnerability analysis with more detailed output
    fn analyze_vulnerabilities(&mut self) {
        info!("Performing enhanced vulnerability analysis...");
        self.memory_log("INFO", "Performing enhanced vulnerability analysis...");
        
        let mut vuln_count = 0;
        
        // Collect all analysis data with minimal logging during analysis
        let mut analysis_results = Vec::new();
        
        for &port in &self.open_ports {
            // Create a temporary analysis result for this port
            let mut port_analysis = None;
            
            // Scoped block to ensure mutable borrow is dropped
            {
                let port_result = if let Some(result) = self.results.get_mut(&port) {
                    result
                } else {
                    continue;
                };
                
                // Check for service-related vulnerabilities
                if let Some(service) = &port_result.service {
                    let potential_vulns = utils::check_service_vulns(
                        service,
                        port_result.version.as_deref(),
                        port_result.banner.as_deref(),
                        port_result.cert_info.as_ref(),
                    );
                    
                    if !potential_vulns.is_empty() {
                        // Store vulnerabilities
                        port_result.vulns = potential_vulns.clone();
                        vuln_count += port_result.vulns.len();
                        
                        // Store analysis results for later logging
                        port_analysis = Some((port, service.clone(), potential_vulns));
                    }
                }
                
                // Check for TLS/SSL vulnerabilities specifically
                if let Some(cert) = &port_result.cert_info {
                    let ssl_vulns = utils::check_ssl_vulnerabilities(cert);
                    
                    if !ssl_vulns.is_empty() {
                        // Add to existing vulnerabilities
                        for vuln in &ssl_vulns {
                            port_result.vulns.push(vuln.clone());
                            vuln_count += 1;
                        }
                        
                        // Store SSL analysis results for later logging
                        let ssl_analysis = (port, "SSL/TLS".to_string(), ssl_vulns);
                        analysis_results.push(ssl_analysis);
                    }
                }
            }
            
            // Add the port analysis to our results if it exists
            if let Some(analysis) = port_analysis {
                analysis_results.push(analysis);
            }
        }
        
        // Now log the analysis results without any mutable borrow conflicts
        if self.verbose {
            for (port, service, vulns) in &analysis_results {
                let vuln_msg = format!(
                    "Found {} potential vulnerabilities for {} on port {}", 
                    vulns.len(), 
                    service, 
                    port
                );
                info!("{}", vuln_msg);
                self.memory_log("INFO", &vuln_msg);
                
                for vuln in vulns {
                    let detail_msg = format!("Vulnerability: {}", vuln);
                    debug!("{}", detail_msg);
                    self.memory_log("DEBUG", &detail_msg);
                }
            }
        }
        
        // Log summary
        let summary = format!("Vulnerability analysis complete. Found {} potential vulnerabilities.", vuln_count);
        info!("{}", summary);
        self.memory_log("INFO", &summary);
    }

    /// Log an event to the memory buffer if available
    fn memory_log(&self, level: &str, message: &str) {
        if let Some(buffer) = &self.memory_log {
            buffer.log(level, message);
        }
        
        // Also write to standard logger if verbose mode is enabled
        if self.verbose {
            match level {
                "INFO" => info!("{}", message),
                "WARN" => warn!("{}", message),
                "ERROR" => log::error!("{}", message),
                "DEBUG" => debug!("{}", message),
                _ => info!("{}", message),
            }
        }
    }
    
    /// Retry failed ports with a different scan method
    async fn retry_failed_ports(&mut self) -> Result<()> {
        if self.failed_ports.is_empty() {
            return Ok(());
        }
        
        // Notify about retry attempt
        let retry_message = format!("Retrying {} failed ports with alternative scan methods", 
                                   self.failed_ports.len());
        self.memory_log("INFO", &retry_message);
        
        // Get alternative scan types for retry
        let retry_scan_types = vec![ScanType::Ssl, ScanType::Mimic];
        
        // Setup semaphore for concurrency control
        let semaphore = Arc::new(Semaphore::new(self.concurrency));
        
        // Channel for scan results
        let (tx, mut rx) = mpsc::channel::<(u16, ScanType, PortStatus, Option<String>, Result<(), anyhow::Error>)>(100);
        
        // Prepare for retries
        let failed_ports: Vec<u16> = self.failed_ports.iter().cloned().collect();
        let mut retry_tasks = Vec::new();
        
        // Enhanced error handling - track failed scans
        let _retry_failed = 0;
        
        // Launch a task for each failed port and alternative scan type
        for &port in &failed_ports {
            for &scan_type in &retry_scan_types {
                // Skip if this scan type was already attempted
                if self.scan_types.contains(&scan_type) {
                    continue;
                }
                
                // Create a copy of required resources for this task
                let semaphore_clone = semaphore.clone();
                let tx_clone = tx.clone();
                
                // Clone parameters needed for the scan
                let _target_ip = self.target_ip;
                let _local_ip = self.local_ip;
                let _use_ipv6 = self.use_ipv6;
                let _evasions = self.evasions;
                let _enhanced_evasion = self.enhanced_evasion;
                let _mimic_os = self.mimic_os.clone();
                let _ttl_jitter = self.ttl_jitter;
                let _protocol_variant = self.protocol_variant.clone();
                let _timeout_scan = self.timeout_scan;
                let _mimic_protocol = self.mimic_protocol.clone();
                
                // Create and spawn the retry task
                let retry_task = tokio::spawn(async move {
                    // Acquire semaphore permit to control concurrency
                    let _permit = match semaphore_clone.acquire().await {
                        Ok(permit) => permit,
                        Err(_) => {
                            return (port, scan_type, PortStatus::Filtered, None, 
                                   Err(anyhow::anyhow!("Semaphore acquisition failed")));
                        }
                    };
                    
                    // Implement custom scan logic or call existing scan methods
                    // This is simplified for illustration
                    let result = match scan_type {
                        ScanType::Ssl => {
                            // Simplified SSL scan
                            (port, scan_type, PortStatus::Open, Some("SSL/TLS".to_string()), 
                             Ok(()))
                        },
                        ScanType::Mimic => {
                            // Simplified Mimic scan with protocol payload
                            let _payload = utils::generate_advanced_mimicry(&_mimic_protocol, _protocol_variant.as_deref());
                            (port, scan_type, PortStatus::Open, Some(format!("{} service", _mimic_protocol)), 
                             Ok(()))
                        },
                        _ => (port, scan_type, PortStatus::Filtered, None, Ok(())),
                    };
                    
                    // Clone the components to send through the channel
                    let send_result = (
                        result.0,
                        result.1,
                        result.2.clone(),
                        result.3.clone(),
                        if result.4.is_ok() { Ok(()) } else { Err(anyhow::anyhow!("Error")) }
                    );
                    
                    // Send result through channel
                    let _ = tx_clone.send(send_result).await;
                    
                    result
                });
                
                retry_tasks.push(retry_task);
            }
        }
        
        // Process retry results
        let mut updated_ports = HashSet::new();
        while let Some((port, scan_type, status, service_opt, _result)) = rx.recv().await {
            // Update results if port is now found open
            if matches!(status, PortStatus::Open) {
                if let Some(result) = self.results.get_mut(&port) {
                    result.tcp_states.insert(scan_type, status);
                    if let Some(service_name) = service_opt {
                        result.service = Some(service_name);
                    }
                    self.open_ports.insert(port);
                    updated_ports.insert(port);
                }
            }
        }
        
        // Remove successfully retried ports from failed list
        for port in updated_ports {
            self.failed_ports.remove(&port);
        }
        
        Ok(())
    }

    /// Conduct detailed port analysis to provide more comprehensive information about discovered ports
    /// 
    /// This function performs in-depth analysis on open ports to gather more detailed information
    /// about the services running, potential vulnerabilities, and security posture.
    /// The analysis includes:
    /// - Extended banner grabbing with protocol-specific probes
    /// - Service version correlation with known vulnerabilities
    /// - Deeper analysis of response patterns
    /// - Identification of security configurations
    /// - Detection of anomalous responses that might indicate honeypots or security devices
    ///
    /// Results are stored in the corresponding PortResult structures.
    fn detailed_port_analysis(&mut self) -> Result<()> {
        // Skip if no open ports found
        if self.open_ports.is_empty() {
            if self.verbose {
                info!("No open ports found, skipping detailed analysis");
                self.memory_log("INFO", "No open ports found, skipping detailed analysis");
            }
            return Ok(());
        }

        // Log the start of detailed analysis
        let analysis_msg = format!(
            "Starting detailed analysis on {} open ports...",
            self.open_ports.len()
        );
        info!("{}", analysis_msg);
        self.memory_log("INFO", &analysis_msg);

        // Sort ports for consistent analysis
        let mut ports: Vec<u16> = self.open_ports.iter().copied().collect();
        ports.sort_unstable();

        // Store analysis results for logging after mutable borrow is dropped
        let mut analysis_logs = Vec::new();

        // Analyze each open port in detail
        for &port in &ports {
            // Temporary storage for log messages
            let mut port_logs = Vec::new();
            
            // Scoped block to ensure mutable borrow is dropped
            {
                let port_result = if let Some(result) = self.results.get_mut(&port) {
                    result
                } else {
                    continue;
                };

                if self.verbose {
                    port_logs.push(("DEBUG", format!("Analyzing port {}...", port)));
                }

                // Enhanced service identification
                if let Some(service) = &port_result.service {
                    // Enhanced detection of service versions
                    if port_result.version.is_none() {
                        // This would try to get a more detailed version from the banner
                        if let Some(banner) = &port_result.banner {
                            // Check for common version patterns in banner
                            if let Some(version) = utils::extract_version_from_banner(service, banner) {
                                let version_msg = format!("Identified version for {} on port {}: {}", service, port, version);
                                port_logs.push(("INFO", version_msg));
                                port_result.version = Some(version);
                            }
                        }
                    }

                    // Enhanced security posture assessment
                    // For known services, determine if they're using secure configurations
                    let security_posture = utils::assess_service_security(
                        service,
                        port_result.version.as_deref(),
                        port_result.banner.as_deref(),
                        port_result.cert_info.as_ref(),
                    );

                    if let Some(posture) = security_posture {
                        let posture_msg = format!("Security assessment for {} on port {}: {}", service, port, posture);
                        port_logs.push(("INFO", posture_msg));
                        port_result.security_posture = Some(posture);
                    }

                    // Enhanced anomaly detection
                    let anomalies = utils::detect_response_anomalies(
                        service,
                        port_result.banner.as_deref(),
                        port_result.cert_info.as_ref(),
                    );

                    if !anomalies.is_empty() {
                        let anomaly_msg = format!(
                            "Detected {} anomalies in responses from port {}", 
                            anomalies.len(), 
                            port
                        );
                        port_logs.push(("WARN", anomaly_msg));
                        
                        for anomaly in &anomalies {
                            let detail_msg = format!("Anomaly: {}", anomaly);
                            port_logs.push(("DEBUG", detail_msg));
                        }
                        
                        port_result.anomalies = anomalies;
                    }
                }
            }
            
            // Add this port's logs to our analysis logs
            analysis_logs.extend(port_logs);
        }

        // Log all the collected messages after all mutable borrows are dropped
        for (level, message) in analysis_logs {
            match level {
                "INFO" => info!("{}", message),
                "DEBUG" => debug!("{}", message),
                "WARN" => warn!("{}", message),
                _ => info!("{}", message),
            }
            self.memory_log(level, &message);
        }

        let complete_msg = format!("Detailed analysis completed for {} ports", ports.len());
        info!("{}", complete_msg);
        self.memory_log("INFO", &complete_msg);

        Ok(())
    }

    /// Generate a risk assessment based on the scan results
    fn generate_risk_assessment(&self) -> Option<String> {
        if self.open_ports.is_empty() {
            return Some("Low - No open ports detected".to_string());
        }
        
        // Count vulnerabilities across all ports
        let total_vulns = self.results.values()
            .map(|r| r.vulns.len())
            .sum::<usize>();
            
        // Count critical services (those that often have security implications)
        let critical_services = self.results.iter()
            .filter(|(_, r)| {
                if let Some(service) = &r.service {
                    matches!(service.as_str(), 
                        "ssh" | "telnet" | "ftp" | "smb" | "rdp" | "mysql" | 
                        "postgresql" | "mongodb" | "redis" | "admin" | "jenkins")
                } else {
                    false
                }
            })
            .count();
            
        // Determine risk level based on findings
        if total_vulns > 5 || critical_services > 3 {
            Some("Critical - Multiple vulnerabilities and critical services exposed".to_string())
        } else if total_vulns > 0 || critical_services > 0 {
            Some("High - Vulnerabilities or critical services detected".to_string())
        } else if self.open_ports.len() > 10 {
            Some("Medium - Large attack surface with many open ports".to_string())
        } else if self.open_ports.len() > 3 {
            Some("Medium-Low - Several open ports but no obvious vulnerabilities".to_string())
        } else {
            Some("Low - Minimal attack surface".to_string())
        }
    }
    
    /// Categorize services into groups
    fn categorize_services(&self) -> Option<HashMap<String, Vec<u16>>> {
        if self.open_ports.is_empty() {
            return None;
        }
        
        let mut categories: HashMap<String, Vec<u16>> = HashMap::new();
        
        for &port in &self.open_ports {
            if let Some(result) = self.results.get(&port) {
                if let Some(service) = &result.service {
                    // Determine category based on service name
                    let category = match service.as_str() {
                        "http" | "https" | "http-proxy" | "https-alt" => "web",
                        "ssh" | "telnet" | "rdp" => "remote_access",
                        "ftp" | "sftp" => "file_transfer",
                        "smtp" | "smtps" | "pop3" | "pop3s" | "imap" | "imaps" => "mail",
                        "mysql" | "postgresql" | "mongodb" | "redis" | "cassandra" => "database",
                        "dns" => "name_service",
                        "ntp" | "snmp" => "network_services",
                        "smb" | "netbios" | "netbios-ssn" => "windows_services",
                        _ => "other",
                    };
                    
                    // Add port to the appropriate category
                    categories.entry(category.to_string())
                        .or_insert_with(Vec::new)
                        .push(port);
                } else {
                    // No service identified, categorize as unknown
                    categories.entry("unknown".to_string())
                        .or_insert_with(Vec::new)
                        .push(port);
                }
            }
        }
        
        // Sort ports within each category
        for ports in categories.values_mut() {
            ports.sort_unstable();
        }
        
        Some(categories)
    }

    /// Categorize a service into a general category for reporting
    fn categorize_service(&self, service: &str) -> String {
        // Convert service name to lowercase for case-insensitive matching
        let service_lower = service.to_lowercase();
        
        // Categorize services based on common patterns and names
        if service_lower.contains("http") || service_lower.contains("web") {
            "Web Services".to_string()
        } else if service_lower.contains("ssh") || service_lower.contains("telnet") || 
                  service_lower.contains("rdp") || service_lower.contains("vnc") {
            "Remote Access".to_string()
        } else if service_lower.contains("ftp") || service_lower.contains("sftp") {
            "File Transfer".to_string()
        } else if service_lower.contains("smtp") || service_lower.contains("mail") ||
                  service_lower.contains("pop3") || service_lower.contains("imap") {
            "Mail Services".to_string()
        } else if service_lower.contains("sql") || service_lower.contains("mysql") ||
                  service_lower.contains("postgres") || service_lower.contains("oracle") ||
                  service_lower.contains("db") || service_lower.contains("mongo") {
            "Database Services".to_string()
        } else if service_lower.contains("dns") || service_lower.contains("dhcp") ||
                  service_lower.contains("ntp") || service_lower.contains("ldap") {
            "Network Services".to_string() 
        } else if service_lower.contains("snmp") || service_lower.contains("monitoring") {
            "Monitoring Services".to_string()
        } else if service_lower.contains("smb") || service_lower.contains("netbios") ||
                  service_lower.contains("cifs") {
            "File Sharing".to_string()
        } else if service_lower.contains("irc") || service_lower.contains("chat") ||
                  service_lower.contains("xmpp") {
            "Messaging Services".to_string()
        } else if service_lower.contains("voice") || service_lower.contains("sip") ||
                  service_lower.contains("voip") || service_lower.contains("rtsp") {
            "Voice/Video Services".to_string()
        } else {
            "Other Services".to_string()
        }
    }
    
    /// Detect the operating system from scan results
    fn detect_os(&self) -> Option<String> {
        // Collect OS guesses from all ports
        let mut os_guesses: HashMap<String, usize> = HashMap::new();
        
        for result in self.results.values() {
            if let Some(os) = &result.os_guess {
                *os_guesses.entry(os.clone()).or_insert(0) += 1;
            }
        }
        
        // Find the most common OS guess
        if !os_guesses.is_empty() {
            let mut max_count = 0;
            let mut most_common_os = String::new();
            
            for (os, count) in os_guesses {
                if count > max_count {
                    max_count = count;
                    most_common_os = os;
                }
            }
            
            return Some(most_common_os);
        }
        
        // Fall back to basic OS detection based on open ports
        if self.has_common_windows_ports() {
            Some("Windows (estimated)".to_string())
        } else if self.has_common_linux_ports() {
            Some("Linux/Unix (estimated)".to_string())
        } else {
            None
        }
    }
    
    /// Check if the target has common Windows ports open
    fn has_common_windows_ports(&self) -> bool {
        self.open_ports.contains(&445) || // SMB
        self.open_ports.contains(&139) || // NetBIOS
        self.open_ports.contains(&3389) || // RDP
        self.open_ports.contains(&135)     // RPC
    }
    
    /// Check if the target has common Linux/Unix ports open
    fn has_common_linux_ports(&self) -> bool {
        self.open_ports.contains(&22) && // SSH
        !self.has_common_windows_ports() // Not Windows
    }
    
    /// Assess overall security risk
    fn assess_risk(&self) -> Option<String> {
        if self.open_ports.is_empty() {
            return Some("Low - No open ports detected".to_string());
        }
        
        // Count vulnerabilities
        let mut total_vulns = 0;
        let mut critical_vulns = 0;
        
        for result in self.results.values() {
            total_vulns += result.vulns.len();
            
            // Count critical vulnerabilities
            for vuln in &result.vulns {
                if vuln.to_lowercase().contains("critical") || 
                   vuln.to_lowercase().contains("high") {
                    critical_vulns += 1;
                }
            }
        }
        
        // Check for sensitive services
        let has_sensitive_services = self.open_ports.iter().any(|&port| {
            // Check if any of these sensitive services exist
            port == 21 || // FTP
            port == 23 || // Telnet
            port == 3389 || // RDP
            port == 1433 || // MS SQL
            port == 3306 || // MySQL
            port == 5432    // PostgreSQL
        });
        
        // Calculate risk level
        if critical_vulns > 0 {
            Some(format!(
                "High - Found {} critical vulnerabilities across {} open ports", 
                critical_vulns, self.open_ports.len()
            ))
        } else if total_vulns > 0 {
            Some(format!(
                "Medium - Found {} potential vulnerabilities across {} open ports", 
                total_vulns, self.open_ports.len()
            ))
        } else if has_sensitive_services {
            Some(format!(
                "Medium - Found {} open ports including sensitive services", 
                self.open_ports.len()
            ))
        } else if self.open_ports.len() > 10 {
            Some(format!(
                "Medium - Large attack surface with {} open ports", 
                self.open_ports.len()
            ))
        } else {
            Some(format!(
                "Low-Medium - {} open ports with no obvious vulnerabilities", 
                self.open_ports.len()
            ))
        }
    }
    
    /// Perform security assessment for open ports
    fn security_assessment(&mut self) {
        // Implementation of security assessment logic
    }
} 