use std::net::ToSocketAddrs;

use crate::client::tls::common::util::create_kmip_client;
use crate::client::{Client, ClientCertificate, ConnectionSettings};

use log::info;

use tokio::net::TcpStream;
use tokio_native_tls::native_tls::{Certificate, Identity, Protocol, TlsConnector};
use tokio_native_tls::TlsStream;

pub async fn connect(conn_settings: &ConnectionSettings) -> Client<TlsStream<TcpStream>> {
    let addr = format!("{}:{}", conn_settings.host, conn_settings.port)
        .to_socket_addrs()
        .expect("Error parsing host and port")
        .next()
        .expect("Internal error fetching parsed host and port from iterator");

    info!("Establishing TLS connection to server..");
    let connect_timeout = conn_settings.connect_timeout.clone();

    let do_conn = async {
        let tcp_stream = TcpStream::connect(&addr).await.expect("Failed to connect to host");

        let tls_connector = create_tls_connector(conn_settings).expect("Failed to create TLS connector");

        let tls_client = tokio_native_tls::TlsConnector::from(tls_connector);

        let tls_stream = tls_client
            .connect(&conn_settings.host, tcp_stream)
            .await
            .expect("Failed to establish TLS connection");

        create_kmip_client(tls_stream, conn_settings)
    };

    if let Some(timeout) = connect_timeout {
        tokio::time::timeout(timeout, do_conn)
            .await
            .expect("Failed to connect to host or timed out")
    } else {
        do_conn.await
    }
}

fn create_tls_connector(
    conn_settings: &ConnectionSettings,
) -> Result<TlsConnector, tokio_native_tls::native_tls::Error> {
    let mut connector = TlsConnector::builder();

    if conn_settings.insecure {
        connector.danger_accept_invalid_certs(true);
        connector.danger_accept_invalid_hostnames(true);
    } else {
        connector.min_protocol_version(Some(Protocol::Tlsv12));

        if let Some(cert_bytes) = conn_settings.server_cert.as_ref() {
            let cert = Certificate::from_pem(&cert_bytes).expect("Failed to parse PEM bytes for server certificate");
            connector.add_root_certificate(cert);
        }

        if let Some(cert_bytes) = conn_settings.ca_cert.as_ref() {
            let cert = Certificate::from_pem(&cert_bytes).expect("Failed to parse PEM bytes for server CA certificate");
            connector.add_root_certificate(cert);
        }
    }

    if let Some(cert) = &conn_settings.client_cert {
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
