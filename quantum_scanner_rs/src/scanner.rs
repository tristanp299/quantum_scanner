use std::collections::{HashMap, HashSet, VecDeque};
use std::net::{IpAddr, ToSocketAddrs};
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use chrono::Utc;
use console::style;
use futures::stream::{FuturesUnordered, StreamExt};
use indicatif::{MultiProgress, ProgressBar, ProgressStyle};
use log::{debug, error, info, warn};
use parking_lot::Mutex;
use rand::{Rng, thread_rng};
use tokio::runtime::Handle;
use tokio::sync::Semaphore;
use tokio::time::{sleep, timeout};
use trust_dns_resolver::config::{ResolverConfig, ResolverOpts};
use trust_dns_resolver::TokioAsyncResolver;

use crate::models::{PortResult, PortStatus, ScanResults, ScanType};
use crate::techniques;
use crate::utils;

/// Determine if scanning with these techniques requires root/admin privileges
pub fn requires_raw_sockets(scan_types: &[ScanType]) -> bool {
    // Raw socket operations typically require elevated privileges
    let raw_socket_types = [
        ScanType::Syn, ScanType::Ack, ScanType::Fin, 
        ScanType::Xmas, ScanType::Null, ScanType::Window,
        ScanType::TlsEcho, ScanType::Mimic, ScanType::Frag
    ];
    
    scan_types.iter().any(|st| raw_socket_types.contains(st))
}

/// The main scanner struct that manages all scanning operations
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
}

impl QuantumScanner {
    /// Create a new scanner instance
    ///
    /// # Arguments
    /// * `target` - Target hostname or IP address
    /// * `ports` - List of ports to scan
    /// * `scan_types` - List of scan techniques to use
    /// * `concurrency` - Maximum concurrent operations
    /// * `max_rate` - Maximum packets per second rate limit
    /// * `evasions` - Enable evasion techniques
    /// * `verbose` - Enable verbose output
    /// * `use_ipv6` - Use IPv6 addressing
    /// * `json_output` - Output results in JSON format
    /// * Additional parameters for specific scan types and timeouts
    ///
    /// # Returns
    /// * `Result<Self>` - New scanner instance or error
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
        log_file: &Path,
    ) -> Result<Self> {
        // Resolve target to IP address
        let target_ip = QuantumScanner::resolve_target(target, use_ipv6)
            .await
            .context("Failed to resolve target")?;
        
        info!("Resolved target {} to {}", target, target_ip);
        
        // Get local IP address for sending packets
        let local_ip = if !use_ipv6 {
            utils::get_default_interface_ipv4()
        } else {
            utils::get_default_interface_ipv6()
        };
        
        debug!("Using local IP: {:?}", local_ip);
        
        // Cap concurrency at a reasonable value
        let concurrency = concurrency.min(500);
        
        // Ensure fragment sizes are valid
        let frag_min_size = frag_min_size.max(24); // Need enough space for headers
        let frag_max_size = frag_max_size.max(frag_min_size);
        
        // Ensure delays are positive
        let frag_min_delay = frag_min_delay.max(0.001); 
        let frag_max_delay = frag_max_delay.max(frag_min_delay);
        
        // Create scanner instance
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
            results: HashMap::new(),
            open_ports: HashSet::new(),
            history: Arc::new(Mutex::new(VecDeque::with_capacity(100))),
            adaptation_factor: Arc::new(Mutex::new(1.0)),
            scan_start_time: Utc::now(),
            scan_end_time: None,
            packets_sent: Arc::new(Mutex::new(0)),
            successful_scans: Arc::new(Mutex::new(0)),
        })
    }

    /// Resolve a hostname or IP address to an IpAddr
    async fn resolve_target(target: &str, use_ipv6: bool) -> Result<IpAddr> {
        // First try simple parsing - if it's a valid IP address
        if let Ok(ip) = target.parse::<IpAddr>() {
            return Ok(ip);
        }
        
        // If not a direct IP address, use DNS resolver
        let resolver = TokioAsyncResolver::tokio(
            ResolverConfig::default(),
            ResolverOpts::default(),
        )
        .context("Failed to create DNS resolver")?;
        
        // Try to resolve the hostname
        let lookup = if use_ipv6 {
            resolver.ipv6_lookup(target).await?
        } else {
            resolver.ipv4_lookup(target).await?
        };
        
        // Get the first IP address from the lookup
        let ip = lookup
            .iter()
            .next()
            .context(format!("Could not resolve hostname {}", target))?;
        
        Ok(IpAddr::from(ip))
    }

    /// Run the scan
    ///
    /// # Returns
    /// * `Result<ScanResults>` - Scan results or error
    pub async fn run_scan(&mut self) -> Result<ScanResults> {
        info!("Starting scan of {} at {}", self.target_ip, self.scan_start_time);
        
        // Setup console output
        println!("{} {} ({} ports)", 
            style("Starting scan:").cyan().bold(),
            self.target_ip,
            self.ports.len()
        );
        
        // Initialize progress bars
        let multi_progress = MultiProgress::new();
        let progress_style = ProgressStyle::default_bar()
            .template("[{elapsed_precise}] {bar:40.cyan/blue} {pos:>7}/{len:7} {msg}")
            .unwrap()
            .progress_chars("##-");
        
        // Progress bar for overall scan
        let total_tasks = self.ports.len() * self.scan_types.len();
        let pb = multi_progress.add(ProgressBar::new(total_tasks as u64));
        pb.set_style(progress_style);
        pb.set_message("ports scanned");
        
        // Initialize results structure for all ports
        for &port in &self.ports {
            self.results.insert(port, PortResult::default());
        }
        
        // Create channel for results
        let (tx, mut rx) = tokio::sync::mpsc::channel(self.concurrency);
        
        // Create semaphore for limiting concurrency
        let semaphore = Arc::new(Semaphore::new(self.concurrency));
        
        // Start worker threads
        let pb_clone = pb.clone();
        let handle = Handle::current();
        
        // Spawn task to process results
        let process_task = tokio::spawn(async move {
            while let Some((port, scan_type, result)) = rx.recv().await {
                pb_clone.inc(1);
                // Processing handled by the sender side
            }
        });
        
        // Scan each port with each scan type
        let mut scan_tasks = FuturesUnordered::new();
        
        for &port in &self.ports {
            for &scan_type in &self.scan_types {
                let sem_clone = semaphore.clone();
                let tx_clone = tx.clone();
                let packets_sent = self.packets_sent.clone();
                let successful_scans = self.successful_scans.clone();
                let history = self.history.clone();
                let adaptation_factor = self.adaptation_factor.clone();
                
                let scan_task = self.create_scan_task(
                    port,
                    scan_type,
                    sem_clone,
                    tx_clone,
                    packets_sent,
                    successful_scans,
                    history,
                    adaptation_factor,
                );
                
                scan_tasks.push(scan_task);
            }
        }
        
        // Wait for all scan tasks to complete
        while let Some(result) = scan_tasks.next().await {
            if let Err(e) = result {
                error!("Error in scan task: {}", e);
            }
        }
        
        // Drop sender to signal task completion
        drop(tx);
        
        // Wait for result processing to complete
        let _ = process_task.await;
        
        // Perform post-scan processing
        self.scan_end_time = Some(Utc::now());
        self.service_fingerprinting();
        self.analyze_vulnerabilities();
        
        // Set progress bar to finished
        pb.finish_with_message("scan complete");
        
        // Create and return results
        Ok(ScanResults {
            target: self.target.clone(),
            target_ip: self.target_ip,
            open_ports: self.open_ports.clone(),
            results: self.results.clone(),
            start_time: self.scan_start_time,
            end_time: self.scan_end_time.unwrap_or_else(Utc::now),
            scan_types: self.scan_types.clone(),
        })
    }

    /// Create a scan task for a port and scan type
    async fn create_scan_task(
        &self,
        port: u16,
        scan_type: ScanType,
        semaphore: Arc<Semaphore>,
        tx: tokio::sync::mpsc::Sender<(u16, ScanType, Result<PortStatus>)>,
        packets_sent: Arc<Mutex<usize>>,
        successful_scans: Arc<Mutex<usize>>,
        history: Arc<Mutex<VecDeque<Instant>>>,
        adaptation_factor: Arc<Mutex<f64>>,
    ) -> Result<()> {
        // Acquire semaphore permit
        let _permit = semaphore.acquire().await?;
        
        // Apply rate limiting
        self.adaptive_delay(history.clone(), adaptation_factor.clone()).await;
        
        // Perform scan based on scan type
        let result = match scan_type {
            ScanType::Syn => techniques::syn_scan(
                self.target_ip,
                port,
                self.local_ip,
                self.use_ipv6,
                self.evasions,
                Duration::from_secs_f64(self.timeout_scan),
            ).await,
            ScanType::Ssl => {
                match techniques::ssl_scan(
                    self.target_ip,
                    port,
                    Duration::from_secs_f64(self.timeout_connect),
                ).await {
                    Ok((status, cert_info, version)) => {
                        // Update port result with certificate info
                        if let Some(port_result) = self.results.get_mut(&port) {
                            if let Some(cert) = cert_info {
                                port_result.cert_info = Some(cert);
                            }
                            
                            if !version.is_empty() {
                                port_result.version = Some(version);
                                port_result.service = Some("SSL/TLS".to_string());
                            }
                        }
                        
                        Ok(status)
                    },
                    Err(e) => Err(e),
                }
            },
            ScanType::Udp => {
                match techniques::udp_scan(
                    self.target_ip,
                    port,
                    self.local_ip,
                    self.use_ipv6,
                    Duration::from_secs_f64(self.timeout_scan),
                ).await {
                    Ok(status) => {
                        // Update UDP status in port result
                        if let Some(port_result) = self.results.get_mut(&port) {
                            port_result.udp_state = Some(status.clone());
                        }
                        
                        Ok(status)
                    },
                    Err(e) => Err(e),
                }
            },
            ScanType::Ack => {
                match techniques::ack_scan(
                    self.target_ip,
                    port,
                    self.local_ip,
                    self.use_ipv6,
                    self.evasions,
                    Duration::from_secs_f64(self.timeout_scan),
                ).await {
                    Ok((status, filtering)) => {
                        // Update filtering info in port result
                        if let Some(port_result) = self.results.get_mut(&port) {
                            port_result.filtering = Some(filtering);
                        }
                        
                        Ok(status)
                    },
                    Err(e) => Err(e),
                }
            },
            ScanType::Fin => techniques::fin_scan(
                self.target_ip,
                port,
                self.local_ip,
                self.use_ipv6,
                self.evasions,
                Duration::from_secs_f64(self.timeout_scan),
            ).await,
            ScanType::Xmas => techniques::xmas_scan(
                self.target_ip,
                port,
                self.local_ip,
                self.use_ipv6,
                self.evasions,
                Duration::from_secs_f64(self.timeout_scan),
            ).await,
            ScanType::Null => techniques::null_scan(
                self.target_ip,
                port,
                self.local_ip,
                self.use_ipv6,
                self.evasions,
                Duration::from_secs_f64(self.timeout_scan),
            ).await,
            ScanType::Window => techniques::window_scan(
                self.target_ip,
                port,
                self.local_ip,
                self.use_ipv6,
                self.evasions,
                Duration::from_secs_f64(self.timeout_scan),
            ).await,
            ScanType::TlsEcho => techniques::tls_echo_scan(
                self.target_ip,
                port,
                self.local_ip,
                self.use_ipv6,
                self.evasions,
                Duration::from_secs_f64(self.timeout_scan),
            ).await,
            ScanType::Mimic => techniques::mimic_scan(
                self.target_ip,
                port,
                self.local_ip,
                self.use_ipv6,
                self.evasions,
                &self.mimic_protocol,
                Duration::from_secs_f64(self.timeout_scan),
            ).await,
            ScanType::Frag => techniques::fragmented_syn_scan(
                self.target_ip,
                port,
                self.local_ip,
                self.use_ipv6,
                self.evasions,
                self.frag_min_size,
                self.frag_max_size,
                self.frag_min_delay,
                self.frag_max_delay,
                self.frag_timeout,
                self.frag_first_min_size,
                self.frag_two_frags,
                Duration::from_secs_f64(self.timeout_scan),
            ).await,
        };
        
        // Increment counters
        {
            let mut ps = packets_sent.lock();
            *ps += 1;
            
            if result.is_ok() {
                let mut ss = successful_scans.lock();
                *ss += 1;
            }
        }
        
        // Update results
        if let Ok(state) = &result {
            if let Some(port_result) = self.results.get_mut(&port) {
                port_result.tcp_states.insert(scan_type, state.clone());
                
                // Track open ports
                if *state == PortStatus::Open {
                    self.open_ports.insert(port);
                }
            }
        }
        
        // Send result
        tx.send((port, scan_type, result)).await?;
        
        // After scan completes, try banner grabbing for open ports
        if self.open_ports.contains(&port) {
            // This happens outside the normal scan flow
            let banner_result = techniques::banner_grabbing(
                self.target_ip,
                port,
                Duration::from_secs_f64(self.timeout_banner),
            ).await;
            
            if let Ok(banner) = banner_result {
                if !banner.is_empty() {
                    if let Some(port_result) = self.results.get_mut(&port) {
                        port_result.banner = Some(banner);
                    }
                }
            }
        }
        
        Ok(())
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
                if now > cert_info.not_after {
                    result.vulns.push("SSL Certificate expired".to_string());
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
} 