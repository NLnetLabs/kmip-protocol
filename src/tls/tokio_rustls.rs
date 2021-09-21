use std::net::ToSocketAddrs;
use std::sync::Arc;

use crate::Config as KmipConfig;

use crate::tls::rustls_common::create_rustls_config;
use crate::tls::{config::Config, Client, ClientBuilder};

use log::info;
use tokio::net::TcpStream;
use tokio_rustls::client::TlsStream;
use tokio_rustls::webpki::DNSNameRef;
use tokio_rustls::TlsConnector;

pub async fn connect(config: Config) -> Client<TlsStream<TcpStream>> {
    let addr = format!("{}:{}", config.host, config.port)
        .to_socket_addrs()
        .expect("Error parsing host and port")
        .next()
        .expect("Internal error fetching parsed host and port from iterator");

    info!("Establishing TLS connection to server..");
    let host_str = config.host.clone();
    let hostname = DNSNameRef::try_from_ascii_str(&host_str)
        .expect(&format!("Failed to parse hostname '{}'", config.host));
    let connect_timeout = config.connect_timeout.clone();

    let do_conn = async {
        let tcp_stream = TcpStream::connect(&addr).await.expect("Failed to connect to host");

        let rustls_config = create_rustls_config(&config).expect("Failed to create RustLS config");

        let tls_connector = TlsConnector::from(Arc::new(rustls_config));

        let tls_stream = tls_connector
            .connect(hostname, tcp_stream)
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