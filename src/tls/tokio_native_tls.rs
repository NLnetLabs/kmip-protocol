use std::net::ToSocketAddrs;

use crate::Config as KmipConfig;

use crate::tls::{
    config::{ClientCertificate, Config},
    Client, ClientBuilder,
};

use log::info;

use tokio::net::TcpStream;
use tokio_native_tls::native_tls::{Certificate, Identity, Protocol, TlsConnector};
use tokio_native_tls::TlsStream;

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

        let tls_client = tokio_native_tls::TlsConnector::from(tls_connector);

        let tls_stream = tls_client
            .connect(&config.host, tcp_stream)
            .await
            .expect("Failed to establish TLS connection");

        create_kmip_client(tls_stream, config)
    };

    if let Some(timeout) = connect_timeout {
        tokio::time::timeout(timeout, do_conn)
            .await
            .expect("Failed to connect to host or timed out")
    } else {
        do_conn.await
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

fn create_tls_connector(config: &Config) -> Result<TlsConnector, tokio_native_tls::native_tls::Error> {
    let mut connector = TlsConnector::builder();

    if config.insecure {
        connector.danger_accept_invalid_certs(true);
        connector.danger_accept_invalid_hostnames(true);
    } else {
        connector.min_protocol_version(Some(Protocol::Tlsv12));

        if let Some(cert_bytes) = config.server_cert.as_ref() {
            let cert = Certificate::from_pem(&cert_bytes).expect("Failed to parse PEM bytes for server certificate");
            connector.add_root_certificate(cert);
        }

        if let Some(cert_bytes) = config.ca_cert.as_ref() {
            let cert = Certificate::from_pem(&cert_bytes).expect("Failed to parse PEM bytes for server CA certificate");
            connector.add_root_certificate(cert);
        }
    }

    if let Some(cert) = &config.client_cert {
        match cert {
            ClientCertificate::SeparatePem { .. } => {
                // From: https://docs.rs/tokio-native-tls/0.3.0/tokio_native_tls/native_tls/struct.Identity.html
                // openssl pkcs12 -export -out identity.pfx -inkey key.pem -in cert.pem -certfile chain_certs.pem
                /*return Err(... */
                panic!("PEM format client certificate and key are not supported");
            }
            ClientCertificate::CombinedPkcs12 { cert_bytes } => {
                const EMPTY_PASSWORD: &'static str = "";
                let identity = Identity::from_pkcs12(&cert_bytes, EMPTY_PASSWORD)
                    .expect("Failed to parse client certificate PKCS#12 bytes");
                connector.identity(identity);
            }
        }
    }

    connector.build()
}
