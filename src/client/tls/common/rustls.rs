use std::sync::Arc;

#[cfg(feature = "tls-with-tokio-rustls")]
use tokio_rustls::rustls;

use rustls::{
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    pki_types::{pem::PemObject, CertificateDer, PrivateKeyDer},
    ClientConfig, KeyLogFile, RootCertStore, SignatureScheme,
};

use crate::client::{tls::common::SSLKEYLOGFILE_ENV_VAR_NAME, ClientCertificate, ConnectionSettings, Error, Result};

#[derive(Debug)]
pub(crate) struct InsecureCertVerifier;

impl ServerCertVerifier for InsecureCertVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> std::result::Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        // TODO: We don't care but we have to return something, presumably
        // returning an empty vec is not an option... but what should we
        // return? The current set is permissive with the idea that we're not
        // verifying anyway so just do whatever it takes to let the connection
        // proceed. But should we still restrict this list to some approved set?
        vec![
            SignatureScheme::RSA_PKCS1_SHA1,
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::RSA_PKCS1_SHA384,
            SignatureScheme::RSA_PKCS1_SHA512,
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA512,
            SignatureScheme::ED448,
            SignatureScheme::ED25519,
        ]
    }
}

pub(crate) fn create_rustls_config<T>(conn_settings: &ConnectionSettings) -> Result<T>
where
    T: From<ClientConfig>,
{
    let mut root_store = RootCertStore {
        roots: webpki_roots::TLS_SERVER_ROOTS.into(),
    };

    if let Some(cert_bytes) = conn_settings.server_cert.as_ref() {
        root_store
            .add(CertificateDer::from_slice(cert_bytes.as_slice()))
            .map_err(|err| {
                Error::ConfigurationError(format!("Failed to parse PEM bytes for server certificate: {err}"))
            })?;
    }

    if let Some(cert_bytes) = conn_settings.ca_cert.as_ref() {
        root_store
            .add(CertificateDer::from_slice(cert_bytes.as_slice()))
            .map_err(|err| Error::ConfigurationError(format!("Failed to parse PEM bytes for CA certificate: {err}")))?;
    }

    let rustls_config_builder = rustls::ClientConfig::builder().with_root_certificates(root_store);

    let mut rustls_config = match &conn_settings.client_cert {
        Some(ClientCertificate::SeparatePem { cert_bytes, key_bytes }) => {
            let mut cert_chain = vec![];

            for res in CertificateDer::pem_slice_iter(&cert_bytes) {
                let cert = res.map_err(|err| {
                    Error::ConfigurationError(format!("Failed to parse PEM section from client certificate: {err}"))
                })?;
                cert_chain.push(cert);
            }

            let key_der = PrivateKeyDer::from_pem_slice(&key_bytes).map_err(|err| {
                Error::ConfigurationError(format!(
                    "Cannot parse PEM client certificate private key bytes: {}",
                    err
                ))
            })?;

            rustls_config_builder
                .with_client_auth_cert(cert_chain, key_der)
                .map_err(|err| {
                    Error::ConfigurationError(format!("Unable to use client certficate and private key: {}", err))
                })?
        }

        Some(ClientCertificate::CombinedPkcs12 { .. }) => {
            return Err(Error::ConfigurationError(
                "PKCS#12 format client certificate and key are not supported".to_string(),
            ));
        }
        None => rustls_config_builder.with_no_client_auth(),
    };

    if conn_settings.insecure {
        rustls_config
            .dangerous()
            .set_certificate_verifier(Arc::new(InsecureCertVerifier));
    }

    if std::env::var(SSLKEYLOGFILE_ENV_VAR_NAME).is_ok() {
        rustls_config.key_log = Arc::new(KeyLogFile::new());
    }

    Ok(rustls_config.into())
}
