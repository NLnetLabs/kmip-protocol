use std::{
    convert::TryFrom,
    net::{SocketAddr, TcpStream, ToSocketAddrs},
    sync::Arc,
};

use crate::client::{
    tls::common::{rustls::create_rustls_config, util::create_kmip_client},
    Error,
};

use crate::client::{ConnectionSettings, Result};

use rustls::{pki_types::ServerName, ClientConfig, ClientConnection, StreamOwned};

pub type Client = crate::client::Client<StreamOwned<ClientConnection, TcpStream>>;

pub fn connect(conn_settings: &ConnectionSettings) -> Result<Client> {
    connect_with_tcpstream_factory(conn_settings, |addr, settings| {
        let tcpstream = if let Some(timeout) = settings.connect_timeout {
            TcpStream::connect_timeout(addr, timeout)?
        } else {
            TcpStream::connect(addr)?
        };
        Ok(tcpstream)
    })
}

pub fn connect_with_tcpstream_factory<F>(conn_settings: &ConnectionSettings, tcpstream_factory: F) -> Result<Client>
where
    F: Fn(&SocketAddr, &ConnectionSettings) -> Result<TcpStream>,
{
    let addr = format!("{}:{}", conn_settings.host, conn_settings.port)
        .to_socket_addrs()?
        .next()
        .ok_or(Error::ConfigurationError(
            "Failed to parse KMIP server address:port".to_string(),
        ))?;

    let rustls_config: ClientConfig = create_rustls_config(conn_settings)?;
    let name = ServerName::try_from(conn_settings.host.clone())
        .map_err(|err| Error::ConfigurationError(format!("Invalid host '{}': {err}", conn_settings.host)))?;
    let conn = rustls::ClientConnection::new(Arc::new(rustls_config), name)
        .map_err(|err| Error::ConfigurationError(format!("Unreachable host '{}': {err}", conn_settings.host)))?;
    let sock = (tcpstream_factory)(&addr, conn_settings)?;
    let tls_stream = rustls::StreamOwned::new(conn, sock);

    Ok(create_kmip_client(tls_stream, conn_settings))
}
