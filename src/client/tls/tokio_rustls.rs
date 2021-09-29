use std::net::ToSocketAddrs;
use std::sync::Arc;

use crate::client::tls::common::rustls::create_rustls_config;
use crate::client::tls::common::util::create_kmip_client;
use crate::client::{Client, ConnectionSettings};

use log::info;
use tokio::net::TcpStream;
use tokio_rustls::client::TlsStream;
use tokio_rustls::webpki::DNSNameRef;
use tokio_rustls::TlsConnector;

pub async fn connect(conn_settings: &ConnectionSettings) -> Client<TlsStream<TcpStream>> {
    let addr = format!("{}:{}", conn_settings.host, conn_settings.port)
        .to_socket_addrs()
        .expect("Error parsing host and port")
        .next()
        .expect("Internal error fetching parsed host and port from iterator");

    info!("Establishing TLS connection to server..");
    let host_str = conn_settings.host.clone();
    let hostname =
        DNSNameRef::try_from_ascii_str(&host_str).expect(&format!("Failed to parse hostname '{}'", conn_settings.host));
    let connect_timeout = conn_settings.connect_timeout.clone();

    let do_conn = async {
        let tcp_stream = TcpStream::connect(&addr).await.expect("Failed to connect to host");

        let rustls_config = create_rustls_config(conn_settings).expect("Failed to create RustLS config");

        let tls_connector = TlsConnector::from(Arc::new(rustls_config));

        let tls_stream = tls_connector
            .connect(hostname, tcp_stream)
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
