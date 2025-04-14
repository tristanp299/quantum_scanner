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

use rustls::{
    ClientConfig,
    RootCertStore,
    pki_types::ServerName
};
// Import TLS_SERVER_ROOTS where actually used (default_client_config function)
// use webpki_roots::TLS_SERVER_ROOTS;
// use rustls::pki_types::TrustAnchor;
use std::sync::Arc;
use anyhow::Result;
// use anyhow::anyhow;
use log::warn;

/// Creates a TLS client configuration for the scanner
/// to use when connecting to TLS services.
/// 
/// When built with the 'insecure-tls' feature, this will
/// disable certificate verification making all connections insecure
/// but also more likely to succeed in environments with problematic
/// certificates or proxies.
///
/// # OPSEC Considerations
/// - When using insecure TLS mode, the scanner will leave a different 
///   TLS handshake signature in logs compared to standard browsers
/// - In secure mode, client fingerprinting will match standard TLS libraries
/// - Consider using the secure mode when scanning security-conscious targets
pub fn create_tls_config(secure: bool) -> Arc<ClientConfig> {
    // Create a new RootCertStore to hold the trusted root certificates.
    let mut root_store = RootCertStore::empty();

    // Conditionally add native roots if the feature is enabled and we are in secure mode.
    // Note: Using rustls-native-certs directly, not a feature flag
    if secure {
        // Load native root certificates from the system.
        // Logs a warning if loading fails but continues, as it might not be critical depending on usage.
        match rustls_native_certs::load_native_certs() {
            Ok(certs) => {
                // Add the loaded certificates to the root store.
                // The second argument `true` indicates that duplicates should be ignored.
                root_store.add_parsable_certificates(certs);
            }
            Err(e) => {
                // Log the error encountered while loading native certs.
                log::warn!("Could not load native certificates: {:?}", e);
            }
        }
    }

    // Add certificates from rustls-native-certs if the feature is enabled and we are in secure mode.
    // This adds trust anchors from the webpki-roots crate.
    #[cfg(feature = "webpki-roots")]
    if secure {
        // Add trust anchors (predefined trusted CA certificates).
        root_store.add_trust_anchors(webpki_roots::TLS_SERVER_TRUST_ANCHORS.iter().map(|ta| {
            // Convert OwnedTrustAnchor to the required TrustAnchor format.
            // Note: .to_trust_anchor() is the correct method for recent rustls/webpki versions.
            OwnedTrustAnchor::from_subject_spki_name_constraints(
                ta.subject,
                ta.spki,
                ta.name_constraints,
            )
        }));
    }

    // Build the ClientConfig using the ConfigBuilder pattern.
    // Updated for rustls 0.22
    let config_builder = ClientConfig::builder();

    let client_config = if secure {
        // Configure with the root certificates loaded earlier for secure connections.
        config_builder
            .with_root_certificates(root_store)
            .with_no_client_auth() // Client authentication is not used.
    } else {
        // For insecure connections, configure a custom verifier that bypasses validation.
        // This is DANGEROUS and should only be used in controlled environments or for testing.
        config_builder
            .dangerous() // Access dangerous configuration options.
            .with_custom_certificate_verifier(Arc::new(danger::NoCertificateVerification {})) // Use the custom verifier.
            .with_no_client_auth() // Client authentication is not used.
    };

    // Return the final configuration wrapped in an Arc.
    Arc::new(client_config)
}

/// Determines whether a ServerName should be verified
/// based on build configuration
/// 
/// # Arguments
/// * `server_name` - The server name to check
///
/// # Returns
/// * `bool` - True if server name should be verified, false otherwise
///
/// # OPSEC Considerations
/// - Disabling server name verification creates a distinctive signature
/// - Enabling verification makes the connection appear like standard clients
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
/// 
/// # Arguments
/// * `name` - The server name string to convert
///
/// # Returns
/// * `Result<ServerName, rustls::Error>` - The converted ServerName or an error
///
/// # OPSEC Considerations
/// - In normal mode, this behaves like standard TLS libraries
/// - In insecure mode, invalid names are accepted but may create a detectable pattern
pub fn convert_to_server_name(name: &str) -> Result<ServerName, rustls::Error> {
    // Try to convert the name to a ServerName
    ServerName::try_from(name).or_else(|_| {
        // Handle the error differently based on configuration
        #[cfg(feature = "insecure-tls")]
        {
            // In insecure mode, we can use a placeholder name for invalid server names
            // This allows scanning to proceed but may create a detectable pattern
            if let Ok(placeholder) = ServerName::try_from("invalid.example.com") {
                return Ok(placeholder);
            }
        }
        
        // Default to returning an error
        Err(rustls::Error::General("Invalid server name".into()))
    })
}

/// Creates a default Rustls client configuration with common roots.
pub fn default_client_config() -> Result<Arc<ClientConfig>> {
    let mut root_store = RootCertStore::empty();
    
    // Convert WebPKI trust anchors to certificate DER format
    let certs = webpki_roots::TLS_SERVER_ROOTS
        .iter()
        .map(|ta| {
            // Access the raw DER data - TrustAnchor doesn't have a to_der method
            rustls::pki_types::CertificateDer::from(ta.subject.to_vec())
        })
        .collect::<Vec<_>>();
    
    // Add the certificates to the root store using the rustls 0.22 API
    let (added, skipped) = root_store.add_parsable_certificates(certs);
    
    if skipped > 0 {
        warn!("Skipped {} certificates when adding to root store (added {})", skipped, added);
    }
    
    // Build the client config
    let config = ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();
    
    Ok(Arc::new(config))
}

// A module for potentially dangerous or insecure configurations.
mod danger {
    // Necessary imports for implementing the custom verifier.
    use rustls::client::danger::{ServerCertVerified, ServerCertVerifier, HandshakeSignatureValid};
    use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
    use rustls::{Error, SignatureScheme};
    use rustls::DigitallySignedStruct;

    // A custom certificate verifier that performs no validation.
    // NOTE: Using this is a security risk! This is only useful in testing environments.
    #[derive(Debug)]
    pub(super) struct NoCertificateVerification {}

    // Implementation of the ServerCertVerifier trait for our custom verifier.
    impl ServerCertVerifier for NoCertificateVerification {
        // This function is called by rustls to verify the server's certificate.
        // Here, we simply return Ok, bypassing all verification.
        fn verify_server_cert(
            &self,
            _end_entity: &CertificateDer<'_>,
            _intermediates: &[CertificateDer<'_>],
            _server_name: &ServerName<'_>,
            _ocsp: &[u8],
            _now: UnixTime,
        ) -> Result<ServerCertVerified, Error> {
            // OPSEC WARNING: This bypasses ALL certificate validation
            // This allows connections to servers with invalid, expired, or self-signed certificates
            // May also enable MITM attacks as certificate chain is not validated
            Ok(ServerCertVerified::assertion())
        }

        // Verify the signature on a TLS handshake - we accept anything
        fn verify_tls12_signature(
            &self,
            _message: &[u8],
            _cert: &CertificateDer<'_>,
            _dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, Error> {
            // OPSEC WARNING: Accepting any signature allows connections to potentially compromised servers
            Ok(HandshakeSignatureValid::assertion())
        }

        // Verify the signature for TLS 1.3 - we accept anything
        fn verify_tls13_signature(
            &self,
            _message: &[u8],
            _cert: &CertificateDer<'_>,
            _dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, Error> {
            // OPSEC WARNING: Accepting any signature is insecure but allows connections to any server
            Ok(HandshakeSignatureValid::assertion())
        }

        // Return the list of signature schemes we support (all of them)
        fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
            // Return all signature schemes to maximize compatibility
            vec![
                SignatureScheme::RSA_PKCS1_SHA1,
                SignatureScheme::ECDSA_SHA1_Legacy,
                SignatureScheme::RSA_PKCS1_SHA256,
                SignatureScheme::ECDSA_NISTP256_SHA256,
                SignatureScheme::RSA_PKCS1_SHA384,
                SignatureScheme::ECDSA_NISTP384_SHA384,
                SignatureScheme::RSA_PKCS1_SHA512,
                SignatureScheme::ECDSA_NISTP521_SHA512,
                SignatureScheme::RSA_PSS_SHA256,
                SignatureScheme::RSA_PSS_SHA384,
                SignatureScheme::RSA_PSS_SHA512,
                SignatureScheme::ED25519,
                SignatureScheme::ED448,
            ]
        }
    }
} 