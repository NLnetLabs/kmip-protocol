use std::{io::BufReader, sync::Arc};

use rustls_pemfile::Item;

use crate::client::{tls::common::SSLKEYLOGFILE_ENV_VAR_NAME, ClientCertificate, ConnectionSettings, Error, Result};

cfg_if::cfg_if! {
    if #[cfg(feature = "tls-with-tokio-rustls")] {
        use tokio_rustls::rustls::{Certificate, ClientConfig, KeyLogFile, PrivateKey, RootCertStore, ServerCertVerified, ServerCertVerifier, TLSError};
        use tokio_rustls::webpki::DNSNameRef;
    } else {
        use rustls::{Certificate, ClientConfig, KeyLogFile, PrivateKey, RootCertStore, ServerCertVerified, ServerCertVerifier, TLSError};
        use webpki::DNSNameRef;
    }
}

pub(crate) struct InsecureCertVerifier();

impl ServerCertVerifier for InsecureCertVerifier {
    fn verify_server_cert(
        &self,
        _roots: &RootCertStore,
        _presented_certs: &[Certificate],
        _dns_name: DNSNameRef,
        _ocsp_response: &[u8],
    ) -> std::result::Result<ServerCertVerified, TLSError> {
        Ok(ServerCertVerified::assertion())
    }
}

pub(crate) fn create_rustls_config<T>(conn_settings: &ConnectionSettings) -> Result<T>
where
    T: From<ClientConfig>,
{
    let mut rustls_config = ClientConfig::new();

    if conn_settings.insecure {
        rustls_config
            .dangerous()
            .set_certificate_verifier(Arc::new(InsecureCertVerifier()));
    } else {
        if let Some(cert_bytes) = conn_settings.server_cert.as_ref() {
            rustls_config
                .root_store
                .add_pem_file(&mut BufReader::new(cert_bytes.as_slice()))
                .map_err(|()| {
                    Error::ConfigurationError("Failed to parse PEM bytes for server certificate".to_string())
                })?;
        }

        if let Some(cert_bytes) = conn_settings.ca_cert.as_ref() {
            rustls_config
                .root_store
                .add_pem_file(&mut BufReader::new(cert_bytes.as_slice()))
                .map_err(|()| {
                    Error::ConfigurationError("Failed to parse PEM bytes for server CA certificate".to_string())
                })?;
        }
    }

    if let Some(cert) = &conn_settings.client_cert {
        match cert {
            ClientCertificate::SeparatePem {
                cert_bytes,
                key_bytes: Some(key_bytes),
            } => {
                let cert_chain = bytes_to_cert_chain(&cert_bytes)?;

                let key_der = bytes_to_private_key(&key_bytes).map_err(|err| {
                    Error::ConfigurationError(format!(
                        "Cannot parse PEM client certificate private key bytes: {}",
                        err
                    ))
                })?;

                rustls_config
                    .set_single_client_cert(cert_chain, key_der)
                    .map_err(|err| {
                        Error::ConfigurationError(format!("Unable to use client certficate and private key: {}", err))
                    })?;
            }
            ClientCertificate::SeparatePem {
                cert_bytes: _,
                key_bytes: None,
            } => {
                return Err(Error::ConfigurationError(
                    "Missing PEM client certificate private key".to_string(),
                ));
            }
            ClientCertificate::CombinedPkcs12 { .. } => {
                return Err(Error::ConfigurationError(
                    "PKCS#12 format client certificate and key are not supported".to_string(),
                ));
            }
        }
    }

    if std::env::var(SSLKEYLOGFILE_ENV_VAR_NAME).is_ok() {
        rustls_config.key_log = Arc::new(KeyLogFile::new());
    }

    Ok(rustls_config.into())
}

fn bytes_to_cert_chain(bytes: &[u8]) -> Result<Vec<Certificate>> {
    let cert_chain = rustls_pemfile::read_all(&mut BufReader::new(bytes))?;

    if cert_chain.iter().any(|i: &rustls_pemfile::Item| match i {
        Item::X509Certificate(_) => false,
        Item::RSAKey(_) => true,
        Item::PKCS8Key(_) => true,
    }) {
        return Err(Error::ConfigurationError(
            "Certificate chain contains one or more RSA or PKCS8 keys. Chain must consist of X509 certificates only."
                .to_string(),
        ));
    }

    let cert_chain = cert_chain
        .iter()
        .map(|i: &rustls_pemfile::Item| match i {
            rustls_pemfile::Item::X509Certificate(bytes) => Certificate(bytes.clone()),
            _ => unreachable!(),
        })
        .collect();
    Ok(cert_chain)
}

fn bytes_to_private_key(bytes: &[u8]) -> Result<PrivateKey> {
    let private_key = rustls_pemfile::read_one(&mut BufReader::new(bytes))?;

    let private_key = match private_key {
        Some(Item::PKCS8Key(bytes)) => PrivateKey(bytes.clone()),
        Some(Item::RSAKey(_)) => {
            return Err(Error::ConfigurationError(
                "Expected a PKCS8 key but found an RSA key".to_string(),
            ))
        }
        Some(Item::X509Certificate(_)) => {
            return Err(Error::ConfigurationError(
                "Expected a PKCS8 key but found an X509 certificates".to_string(),
            ))
        }
        None => {
            return Err(Error::ConfigurationError(
                "Expected a PKCS8 key but did not find any PEM sections".to_string(),
            ))
        }
    };

    Ok(private_key)
}
