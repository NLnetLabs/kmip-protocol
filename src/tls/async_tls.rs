use std::io::BufReader;
use std::net::ToSocketAddrs;
use std::sync::Arc;

use crate::Config as KmipConfig;

use crate::tls::{config::Config, Client, ClientBuilder};

use log::info;

use rustls::{KeyLogFile, ServerCertVerifier};

use async_std::net::TcpStream;
use async_tls::{client::TlsStream, TlsConnector};

use super::config::ClientCertificate;
use super::SSLKEYLOGFILE_ENV_VAR_NAME;

pub async fn connect(config: Config) -> Client<TlsStream<TcpStream>> {
    let addr = format!("{}:{}", config.host, config.port)
        .to_socket_addrs()
        .expect("Error parsing host and port")
        .next()
        .expect("Internal error fetching parsed host and port from iterator");

    info!("Establishing TLS connection to server..");
    let connect_timeout = config.connect_timeout.clone();

    let do_conn = async {
        let tcp_stream = TcpStream::connect(&addr).await.expect("Failed to connect to host");

        let tls_connector = create_tls_connector(&config).expect("Failed to create TLS connector");

        let tls_stream = tls_connector
            .connect(&config.host, tcp_stream)
            .await
            .expect("Failed to establish TLS connection");

        Ok(create_kmip_client(tls_stream, config))
    };

    if let Some(timeout) = connect_timeout {
        async_std::io::timeout(timeout, do_conn)
            .await
            .expect("Failed to connect to host or timed out")
    } else {
        do_conn.await.expect("Failed to connect to host")
    }
}

fn create_kmip_client(tls_stream: TlsStream<TcpStream>, config: Config) -> Client<TlsStream<TcpStream>> {
    let mut client = ClientBuilder::new(tls_stream);

    if let Some(username) = config.username {
        client = client.with_credentials(username, config.password);
    }

    if let Some(max_bytes) = config.max_response_bytes {
        let reader_config = KmipConfig::default().with_max_bytes(max_bytes).with_read_buf();
        client = client.with_reader_config(reader_config);
    };

    client.build()
}

struct InsecureCertVerifier();

impl ServerCertVerifier for InsecureCertVerifier {
    fn verify_server_cert(
        &self,
        _roots: &rustls::RootCertStore,
        _presented_certs: &[rustls::Certificate],
        _dns_name: webpki::DNSNameRef,
        _ocsp_response: &[u8],
    ) -> Result<rustls::ServerCertVerified, rustls::TLSError> {
        Ok(rustls::ServerCertVerified::assertion())
    }
}

fn create_tls_connector(config: &Config) -> Result<TlsConnector, ()> {
    let mut rustls_config = rustls::ClientConfig::new();

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

fn bytes_to_cert_chain(bytes: &[u8]) -> std::io::Result<Vec<rustls::Certificate>> {
    let cert_chain = rustls_pemfile::read_all(&mut BufReader::new(bytes))?
        .iter()
        .map(|i: &rustls_pemfile::Item| match i {
            rustls_pemfile::Item::X509Certificate(bytes) => rustls::Certificate(bytes.clone()),
            rustls_pemfile::Item::RSAKey(_) => panic!("Expected an X509 certificate, got an RSA key"),
            rustls_pemfile::Item::PKCS8Key(_) => panic!("Expected an X509 certificate, got a PKCS8 key"),
        })
        .collect();
    Ok(cert_chain)
}

fn bytes_to_private_key(bytes: &[u8]) -> std::io::Result<rustls::PrivateKey> {
    let private_key = rustls_pemfile::read_one(&mut BufReader::new(bytes))?
        .map(|i: rustls_pemfile::Item| match i {
            rustls_pemfile::Item::X509Certificate(_) => panic!("Expected a PKCS8 key, got an X509 certificate"),
            rustls_pemfile::Item::RSAKey(_) => panic!("Expected a PKCS8 key, got an RSA key"),
            rustls_pemfile::Item::PKCS8Key(bytes) => rustls::PrivateKey(bytes.clone()),
        })
        .unwrap();
    Ok(private_key)
}
