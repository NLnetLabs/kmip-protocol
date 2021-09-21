use std::net::ToSocketAddrs;

use crate::client::tls::common::{rustls::create_rustls_config, util::create_kmip_client};
use crate::client::{Client, ConnectionSettings};

use log::info;

use async_std::net::TcpStream;
use async_tls::{client::TlsStream, TlsConnector};

pub async fn connect(conn_settings: ConnectionSettings) -> Client<TlsStream<TcpStream>> {
    let addr = format!("{}:{}", conn_settings.host, conn_settings.port)
        .to_socket_addrs()
        .expect("Error parsing host and port")
        .next()
        .expect("Internal error fetching parsed host and port from iterator");

    info!("Establishing TLS connection to server..");
    let connect_timeout = conn_settings.connect_timeout.clone();

    let do_conn = async {
        let tcp_stream = TcpStream::connect(&addr).await.expect("Failed to connect to host");

        let tls_connector: TlsConnector = create_rustls_config(&conn_settings).expect("Failed to create TLS connector");

        let tls_stream = tls_connector
            .connect(&conn_settings.host, tcp_stream)
            .await
            .expect("Failed to establish TLS connection");

        Ok(create_kmip_client(tls_stream, conn_settings))
    };

    if let Some(timeout) = connect_timeout {
        async_std::io::timeout(timeout, do_conn)
            .await
            .expect("Failed to connect to host or timed out")
    } else {
        do_conn.await.expect("Failed to connect to host")
    }
}
