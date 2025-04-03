use std::collections::HashMap;
use log::{debug, info};
use crate::models::HttpInfo;
use crate::models::HttpSecurityHeader;

/// HTTP response analyzer for web services
#[allow(dead_code)]
pub struct HttpAnalyzer {
    /// Known security headers and their significance
    security_headers: HashMap<String, String>,
    /// Patterns for technology fingerprinting
    tech_patterns: HashMap<String, Vec<String>>,
}

impl HttpAnalyzer {
    /// Create a new HTTP analyzer with predefined patterns
    #[allow(dead_code)]
    pub fn new() -> Self {
        let mut security_headers = HashMap::new();
        security_headers.insert("Content-Security-Policy".to_string(), "high".to_string());
        security_headers.insert("X-Content-Type-Options".to_string(), "medium".to_string());
        security_headers.insert("X-Frame-Options".to_string(), "medium".to_string());
        security_headers.insert("X-XSS-Protection".to_string(), "medium".to_string());
        security_headers.insert("Strict-Transport-Security".to_string(), "high".to_string());
        security_headers.insert("Referrer-Policy".to_string(), "low".to_string());
        security_headers.insert("Feature-Policy".to_string(), "medium".to_string());
        security_headers.insert("Permissions-Policy".to_string(), "medium".to_string());
        
        // Add technology fingerprinting patterns
        let mut tech_patterns = HashMap::new();
        
        // Web servers
        tech_patterns.insert("Apache".to_string(), vec![
            "Server: Apache".to_string(),
            "<address>Apache/".to_string()
        ]);
        
        tech_patterns.insert("Nginx".to_string(), vec![
            "Server: nginx".to_string()
        ]);
        
        tech_patterns.insert("IIS".to_string(), vec![
            "Server: Microsoft-IIS".to_string(),
            "X-Powered-By: ASP.NET".to_string()
        ]);
        
        // Application frameworks
        tech_patterns.insert("PHP".to_string(), vec![
            "X-Powered-By: PHP".to_string(),
            "Set-Cookie: PHPSESSID".to_string()
        ]);
        
        tech_patterns.insert("WordPress".to_string(), vec![
            "wp-content".to_string(),
            "wp-includes".to_string(),
            "/wp-json/".to_string()
        ]);
        
        // JavaScript libraries
        tech_patterns.insert("jQuery".to_string(), vec![
            "jquery.js".to_string(),
            "jquery.min.js".to_string()
        ]);
        
        tech_patterns.insert("React".to_string(), vec![
            "react.js".to_string(),
            "react.production.min.js".to_string()
        ]);
        
        Self {
            security_headers,
            tech_patterns,
        }
    }
    
    /// Analyze an HTTP response and extract detailed information
    #[allow(dead_code)]
    pub fn analyze_response(&self, response: &[u8], response_time_ms: Option<f64>) -> HttpInfo {
        let mut http_info = HttpInfo::default();
        
        // Set response time if provided
        http_info.response_time = response_time_ms;
        
        // Set response size
        http_info.response_size = Some(response.len());
        
        if let Ok(response_str) = std::str::from_utf8(response) {
            debug!("Analyzing HTTP response ({} bytes)", response_str.len());
            
            // Extract status line
            if let Some(first_line) = response_str.lines().next() {
                if first_line.starts_with("HTTP/") {
                    let parts: Vec<&str> = first_line.split_whitespace().collect();
                    if parts.len() >= 3 {
                        http_info.http_version = Some(parts[0].replace("HTTP/", ""));
                        http_info.status_code = parts[1].parse::<u16>().ok();
                        http_info.status_text = Some(parts[2..].join(" "));
                        
                        debug!("Detected HTTP/{} status {}: {}", 
                            http_info.http_version.as_ref().unwrap_or(&"?".to_string()),
                            http_info.status_code.unwrap_or(0),
                            http_info.status_text.as_ref().unwrap_or(&"Unknown".to_string()));
                    }
                }
            }
            
            // Parse headers
            let mut headers = HashMap::new();
            let mut in_headers = true;
            
            for line in response_str.lines() {
                // Empty line marks end of headers
                if line.trim().is_empty() && in_headers {
                    in_headers = false;
                    continue;
                }
                
                if in_headers && line.contains(":") {
                    let parts: Vec<&str> = line.splitn(2, ":").collect();
                    if parts.len() == 2 {
                        let header_name = parts[0].trim().to_string();
                        let header_value = parts[1].trim().to_string();
                        
                        debug!("HTTP header: {} = {}", header_name, header_value);
                        headers.insert(header_name.clone(), header_value.clone());
                        
                        // Extract specific headers of interest
                        match header_name.to_lowercase().as_str() {
                            "server" => {
                                http_info.server = Some(header_value.clone());
                                info!("Server header: {}", header_value);
                            },
                            "content-type" => http_info.content_type = Some(header_value.clone()),
                            "set-cookie" => http_info.cookies.push(header_value.clone()),
                            "location" => http_info.redirects.push(header_value.clone()),
                            _ => {}
                        }
                        
                        // Check for security headers
                        if self.security_headers.contains_key(&header_name) {
                            let header_type = match header_name.as_str() {
                                "Content-Security-Policy" => 
                                    HttpSecurityHeader::ContentSecurityPolicy(header_value.clone()),
                                "X-Content-Type-Options" =>
                                    HttpSecurityHeader::XContentTypeOptions(header_value.clone()),
                                "X-Frame-Options" =>
                                    HttpSecurityHeader::XFrameOptions(header_value.clone()),
                                "X-XSS-Protection" =>
                                    HttpSecurityHeader::XXssProtection(header_value.clone()),
                                "Strict-Transport-Security" =>
                                    HttpSecurityHeader::StrictTransportSecurity(header_value.clone()),
                                "Referrer-Policy" =>
                                    HttpSecurityHeader::ReferrerPolicy(header_value.clone()),
                                "Feature-Policy" | "Permissions-Policy" =>
                                    HttpSecurityHeader::FeaturePolicy(header_value.clone()),
                                _ => HttpSecurityHeader::Other(header_name.clone(), header_value.clone()),
                            };
                            
                            http_info.security_headers.push(header_type);
                        }
                    }
                }
            }
            
            // Store all headers
            http_info.headers = headers;
            
            // Extract HTML title if available
            if let Some(title) = extract_html_title(response_str) {
                http_info.title = Some(title.clone());
                debug!("Extracted HTML title: {}", title);
            }
            
            // Detect technologies
            for (tech, patterns) in &self.tech_patterns {
                for pattern in patterns {
                    if response_str.contains(pattern) {
                        if !http_info.technologies.contains(tech) {
                            http_info.technologies.push(tech.clone());
                            debug!("Detected technology: {}", tech);
                        }
                        break;
                    }
                }
            }
        }
        
        http_info
    }
    
    /// Check for common HTTP security issues
    #[allow(dead_code)]
    pub fn check_vulnerabilities(&self, http_info: &HttpInfo) -> Vec<String> {
        let mut vulns = Vec::new();
        
        // Check missing important security headers
        let important_headers = [
            "Content-Security-Policy",
            "X-Content-Type-Options",
            "X-Frame-Options",
            "Strict-Transport-Security"
        ];
        
        let present_headers: Vec<String> = http_info.security_headers
            .iter()
            .map(|h| match h {
                HttpSecurityHeader::ContentSecurityPolicy(_) => "Content-Security-Policy".to_string(),
                HttpSecurityHeader::XContentTypeOptions(_) => "X-Content-Type-Options".to_string(),
                HttpSecurityHeader::XFrameOptions(_) => "X-Frame-Options".to_string(),
                HttpSecurityHeader::XXssProtection(_) => "X-XSS-Protection".to_string(),
                HttpSecurityHeader::StrictTransportSecurity(_) => "Strict-Transport-Security".to_string(),
                HttpSecurityHeader::ReferrerPolicy(_) => "Referrer-Policy".to_string(),
                HttpSecurityHeader::FeaturePolicy(_) => "Feature-Policy".to_string(),
                HttpSecurityHeader::Other(name, _) => name.clone(),
            })
            .collect();
        
        for header in important_headers.iter() {
            if !present_headers.iter().any(|h| h == header) {
                vulns.push(format!("Missing security header: {}", header));
            }
        }
        
        // Check for server information disclosure
        if let Some(server) = &http_info.server {
            if server.contains("/") {
                vulns.push("Server header reveals version information".to_string());
            }
        }
        
        // Check HSTS for HTTPS sites
        if http_info.headers.contains_key("Strict-Transport-Security") {
            let hsts = http_info.headers.get("Strict-Transport-Security").unwrap();
            if !hsts.contains("max-age=") || hsts.contains("max-age=0") {
                vulns.push("HSTS header with missing or zero max-age".to_string());
            }
        }
        
        vulns
    }
}

/// Extract HTML title from a response body
#[allow(dead_code)]
fn extract_html_title(html: &str) -> Option<String> {
    if let Some(title_start) = html.to_lowercase().find("<title>") {
        if let Some(title_end) = html.to_lowercase()[title_start..].find("</title>") {
            let title_content = &html[title_start + 7..title_start + title_end];
            return Some(title_content.trim().to_string());
        }
    }
    None
} 