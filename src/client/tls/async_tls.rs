use std::future::Future;
use std::net::{SocketAddr, ToSocketAddrs};

use crate::client::tls::common::{rustls::create_rustls_config, util::create_kmip_client};
use crate::client::{Client, ConnectionSettings};

use log::info;

use async_std::net::TcpStream;
use async_tls::{client::TlsStream, TlsConnector};

async fn default_tcpstream_factory<'a>(addr: SocketAddr, _: &'a ConnectionSettings) -> TcpStream {
    TcpStream::connect(addr).await.expect("Failed to connect to host")
}

pub async fn connect<'a>(conn_settings: &'a ConnectionSettings) -> Client<TlsStream<TcpStream>> {
    connect_with_tcpstream_factory(conn_settings, default_tcpstream_factory).await
}

pub async fn connect_with_tcpstream_factory<'a, F, Fut>(
    conn_settings: &'a ConnectionSettings,
    tcpstream_factory: F,
) -> Client<TlsStream<TcpStream>>
where
    F: Fn(SocketAddr, &'a ConnectionSettings) -> Fut,
    Fut: Future<Output = TcpStream>,
{
    let addr = format!("{}:{}", conn_settings.host, conn_settings.port)
        .to_socket_addrs()
        .expect("Error parsing host and port")
        .next()
        .expect("Internal error fetching parsed host and port from iterator");

    info!("Establishing TLS connection to server..");
    let connect_timeout = conn_settings.connect_timeout.clone();

    let do_conn = async {
        let tcp_stream = (tcpstream_factory)(addr, conn_settings).await;

        let tls_connector: TlsConnector = create_rustls_config(conn_settings).expect("Failed to create TLS connector");

        let tls_stream = tls_connector
            .connect(&conn_settings.host, tcp_stream)
            .await
            .expect("Failed to establish TLS connection");

        Ok(create_kmip_client(tls_stream, &conn_settings))
    };

    if let Some(timeout) = connect_timeout {
        async_std::io::timeout(timeout, do_conn)
            .await
            .expect("Failed to connect to host or timed out")
    } else {
        do_conn.await.expect("Failed to connect to host")
    }
}
