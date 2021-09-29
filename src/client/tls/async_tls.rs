use std::future::Future;
use std::net::{SocketAddr, ToSocketAddrs};

use crate::client::tls::common::{rustls::create_rustls_config, util::create_kmip_client};
use crate::client::{Client, ConnectionSettings, Error, Result};

use log::info;

use async_std::net::TcpStream;
use async_tls::{client::TlsStream, TlsConnector};

async fn default_tcp_stream_factory<'a>(addr: SocketAddr, _: &'a ConnectionSettings) -> std::io::Result<TcpStream> {
    TcpStream::connect(addr).await
}

pub async fn connect<'a>(conn_settings: &'a ConnectionSettings) -> Result<Client<TlsStream<TcpStream>>> {
    connect_with_tcp_stream_factory(conn_settings, default_tcp_stream_factory).await
}

pub async fn connect_with_tcp_stream_factory<'a, F, Fut>(
    conn_settings: &'a ConnectionSettings,
    tcp_stream_factory: F,
) -> Result<Client<TlsStream<TcpStream>>>
where
    F: Fn(SocketAddr, &'a ConnectionSettings) -> Fut,
    Fut: Future<Output = std::io::Result<TcpStream>>,
{
    let addr = format!("{}:{}", conn_settings.host, conn_settings.port)
        .to_socket_addrs()?
        .next()
        .ok_or(Error::ConfigurationError(
            "Failed to parse KMIP server address:port".to_string(),
        ))?;

    info!("Establishing TLS connection to server..");
    let connect_timeout = conn_settings.connect_timeout.clone();

    let connect = async { (tcp_stream_factory)(addr, conn_settings).await };

    let tcp_stream = if let Some(timeout) = connect_timeout {
        async_std::io::timeout(timeout, connect).await?
    } else {
        connect.await?
    };

    let tls_connector: TlsConnector = create_rustls_config(conn_settings)?;
    let tls_stream = tls_connector.connect(&conn_settings.host, tcp_stream).await?;

    Ok(create_kmip_client(tls_stream, conn_settings))
}
