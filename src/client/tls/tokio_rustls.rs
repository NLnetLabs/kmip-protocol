use std::future::Future;
use std::net::{SocketAddr, ToSocketAddrs};
use std::sync::Arc;

use crate::client::tls::common::rustls::create_rustls_config;
use crate::client::tls::common::util::create_kmip_client;
use crate::client::{Client, ConnectionSettings, Error, Result};

use log::info;
use tokio::net::TcpStream;
use tokio_rustls::client::TlsStream;
use tokio_rustls::webpki::DNSNameRef;
use tokio_rustls::TlsConnector;

async fn default_tcpstream_factory<'a>(addr: SocketAddr, _: &'a ConnectionSettings) -> std::io::Result<TcpStream> {
    TcpStream::connect(addr).await
}

pub async fn connect<'a>(conn_settings: &'a ConnectionSettings) -> Result<Client<TlsStream<TcpStream>>> {
    connect_with_tcpstream_factory(conn_settings, default_tcpstream_factory).await
}

pub async fn connect_with_tcpstream_factory<'a, F, Fut>(
    conn_settings: &'a ConnectionSettings,
    tcpstream_factory: F,
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

    let host_str = conn_settings.host.clone();
    let hostname = DNSNameRef::try_from_ascii_str(&host_str).map_err(|err| {
        Error::ConfigurationError(format!("Failed to parse hostname '{}': {}", conn_settings.host, err))
    })?;
    let connect_timeout = conn_settings.connect_timeout.clone();

    let connect = async { (tcpstream_factory)(addr, conn_settings).await };

    let tcp_stream = if let Some(timeout) = connect_timeout {
        tokio::time::timeout(timeout, connect)
            .await
            .map_err(|err| Error::ConfigurationError(format!("Failed to connect to host or timed out: {}", err)))??
    } else {
        connect.await?
    };

    let rustls_config = create_rustls_config(conn_settings)?;
    let tls_connector = TlsConnector::from(Arc::new(rustls_config));
    let tls_stream = tls_connector.connect(hostname, tcp_stream).await?;

    Ok(create_kmip_client(tls_stream, conn_settings))
}
