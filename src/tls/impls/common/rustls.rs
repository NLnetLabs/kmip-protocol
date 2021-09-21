use std::{io::BufReader, sync::Arc};

use crate::tls::{
    config::{ClientCertificate, Config},
    impls::common::SSLKEYLOGFILE_ENV_VAR_NAME,
};

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
    ) -> Result<ServerCertVerified, TLSError> {
        Ok(ServerCertVerified::assertion())
    }
}

pub(crate) fn create_rustls_config<T>(config: &Config) -> Result<T, ()>
where
    T: From<ClientConfig>,
{
    let mut rustls_config = ClientConfig::new();

    if config.insecure {
        rustls_config
            .dangerous()
            .set_certificate_verifier(Arc::new(InsecureCertVerifier()));
    } else {
        if let Some(cert_bytes) = config.server_cert.as_ref() {
            rustls_config
                .root_store
                .add_pem_file(&mut BufReader::new(cert_bytes.as_slice()))
                .expect("Failed to parse PEM bytes for server certificate");
        }

        if let Some(cert_bytes) = config.ca_cert.as_ref() {
            rustls_config
                .root_store
                .add_pem_file(&mut BufReader::new(cert_bytes.as_slice()))
                .expect("Failed to parse PEM bytes for server CA certificate");
        }
    }

    if let Some(cert) = &config.client_cert {
        match cert {
            ClientCertificate::SeparatePem {
                cert_bytes,
                key_bytes: Some(key_bytes),
            } => {
                let cert_chain = bytes_to_cert_chain(&cert_bytes).expect("Cannot parse PEM client certificate bytes");
                let key_der =
                    bytes_to_private_key(&key_bytes).expect("Cannot parse PEM client certificate private key bytes");
                rustls_config.set_single_client_cert(cert_chain, key_der).unwrap();
            }
            ClientCertificate::SeparatePem {
                cert_bytes: _,
                key_bytes: None,
            } => {
                panic!("Missing PEM client certificate private key");
            }
            ClientCertificate::CombinedPkcs12 { .. } => {
                panic!("PKCS#12 format client certificate and key are not supported");
            }
        }
    }

    if std::env::var(SSLKEYLOGFILE_ENV_VAR_NAME).is_ok() {
        rustls_config.key_log = Arc::new(KeyLogFile::new());
    }

    Ok(rustls_config.into())
}

fn bytes_to_cert_chain(bytes: &[u8]) -> std::io::Result<Vec<Certificate>> {
    let cert_chain = rustls_pemfile::read_all(&mut BufReader::new(bytes))?
        .iter()
        .map(|i: &rustls_pemfile::Item| match i {
            rustls_pemfile::Item::X509Certificate(bytes) => Certificate(bytes.clone()),
            rustls_pemfile::Item::RSAKey(_) => panic!("Expected an X509 certificate, got an RSA key"),
            rustls_pemfile::Item::PKCS8Key(_) => panic!("Expected an X509 certificate, got a PKCS8 key"),
        })
        .collect();
    Ok(cert_chain)
}

fn bytes_to_private_key(bytes: &[u8]) -> std::io::Result<PrivateKey> {
    let private_key = rustls_pemfile::read_one(&mut BufReader::new(bytes))?
        .map(|i: rustls_pemfile::Item| match i {
            rustls_pemfile::Item::X509Certificate(_) => panic!("Expected a PKCS8 key, got an X509 certificate"),
            rustls_pemfile::Item::RSAKey(_) => panic!("Expected a PKCS8 key, got an RSA key"),
            rustls_pemfile::Item::PKCS8Key(bytes) => PrivateKey(bytes.clone()),
        })
        .unwrap();
    Ok(private_key)
}
