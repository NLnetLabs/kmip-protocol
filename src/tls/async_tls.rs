use std::net::ToSocketAddrs;

use crate::tls::rustls_common::create_rustls_config;
use crate::tls::util::create_kmip_client;
use crate::tls::{config::Config, Client};

use log::info;

use async_std::net::TcpStream;
use async_tls::{client::TlsStream, TlsConnector};

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

        let tls_connector: TlsConnector = create_rustls_config(&config).expect("Failed to create TLS connector");

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
