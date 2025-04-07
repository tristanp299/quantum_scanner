/*
 * =====================================================
 * QUANTUM SCANNER - SSL/TLS Configuration Module
 * =====================================================
 * This module provides SSL/TLS configuration utilities
 * with options for insecure operation when needed.
 * =====================================================
 * SECURITY WARNING: 
 * The insecure TLS options should ONLY be used in controlled 
 * environments or when certificate validation is problematic.
 * Using these options in production is highly discouraged.
 * =====================================================
 */

use std::sync::Arc;
use rustls::{ClientConfig, ServerName, RootCertStore};
use rustls::client::ServerCertVerifier; // Import ServerCertVerifier directly
use std::convert::TryFrom;

/// Creates a TLS client configuration for the scanner
/// to use when connecting to TLS services.
/// 
/// When built with the 'insecure-tls' feature, this will
/// disable certificate verification making all connections insecure
/// but also more likely to succeed in environments with problematic
/// certificates or proxies.
pub fn create_tls_config() -> Arc<ClientConfig> {
    let mut root_store = RootCertStore::empty();
    
    // Add Mozilla's trusted root certificates
    // This method was updated between rustls versions
    #[allow(deprecated)]
    root_store.add_server_trust_anchors(
        webpki_roots::TLS_SERVER_ROOTS.iter().map(|ta| {
            rustls::OwnedTrustAnchor::from_subject_spki_name_constraints(
                ta.subject,
                ta.spki,
                ta.name_constraints,
            )
        })
    );

    #[cfg(not(feature = "insecure-tls"))]
    let config = ClientConfig::builder()
        .with_safe_defaults()
        .with_root_certificates(root_store)
        .with_no_client_auth();

    #[cfg(feature = "insecure-tls")]
    let config = {
        // Create a dangerous certificate verifier that accepts any certificate
        struct NoCertificateVerification {}
        impl ServerCertVerifier for NoCertificateVerification {
            fn verify_server_cert(
                &self,
                _end_entity: &rustls::Certificate,
                _intermediates: &[rustls::Certificate],
                _server_name: &rustls::ServerName,
                _scts: &mut dyn Iterator<Item = &[u8]>,
                _ocsp_response: &[u8],
                _now: std::time::SystemTime,
            ) -> Result<rustls::client::ServerCertVerified, rustls::Error> {
                // Accept any certificate
                Ok(rustls::client::ServerCertVerified::assertion())
            }
        }

        // Build a client config that uses the insecure verifier
        let mut config = ClientConfig::builder()
            .with_safe_defaults()
            .with_root_certificates(root_store)
            .with_no_client_auth();

        // Set the custom certificate verifier
        config.dangerous().set_certificate_verifier(Arc::new(NoCertificateVerification {}));
        
        config
    };

    Arc::new(config)
}

/// Determines whether a ServerName should be verified
/// based on build configuration
pub fn should_verify_server_name(_server_name: &str) -> bool {
    #[cfg(feature = "insecure-tls")]
    {
        // When using insecure TLS, we don't enforce strict server name verification
        false
    }
    
    #[cfg(not(feature = "insecure-tls"))]
    {
        // Normal operation - always verify server names
        true
    }
}

/// Converts a string to a ServerName, handling insecure mode
pub fn convert_to_server_name(name: &str) -> Result<ServerName, rustls::Error> {
    match ServerName::try_from(name) {
        Ok(server_name) => Ok(server_name),
        Err(_) => {
            #[cfg(feature = "insecure-tls")]
            {
                // In insecure mode, we can use a placeholder name for invalid server names
                // Convert the plain error to a rustls::Error to satisfy the return type
                match ServerName::try_from("invalid.example.com") {
                    Ok(placeholder) => Ok(placeholder),
                    Err(_) => Err(rustls::Error::General("Invalid server name".into())),
                }
            }
            
            #[cfg(not(feature = "insecure-tls"))]
            {
                // In normal mode, propagate the error as a rustls::Error
                Err(rustls::Error::General("Invalid server name".into()))
            }
        }
    }
} 