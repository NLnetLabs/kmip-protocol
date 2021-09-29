use std::{
    net::{SocketAddr, TcpStream, ToSocketAddrs},
    sync::Arc,
};

use crate::client::{
    tls::common::{rustls::create_rustls_config, util::create_kmip_client},
    Error,
};

use crate::client::{Client, ConnectionSettings, Result};

use log::info;
use rustls::{ClientConfig, ClientSession, StreamOwned};

pub fn connect(conn_settings: &ConnectionSettings) -> Result<Client<StreamOwned<ClientSession, TcpStream>>> {
    connect_with_tcpstream_factory(conn_settings, |addr, settings| {
        let tcpstream = if let Some(timeout) = settings.connect_timeout {
            TcpStream::connect_timeout(addr, timeout)?
        } else {
            TcpStream::connect(addr)?
        };
        Ok(tcpstream)
    })
}

pub fn connect_with_tcpstream_factory<F>(
    conn_settings: &ConnectionSettings,
    tcpstream_factory: F,
) -> Result<Client<StreamOwned<ClientSession, TcpStream>>>
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
    let hostname = webpki::DNSNameRef::try_from_ascii_str(&conn_settings.host).map_err(|err| {
        Error::ConfigurationError(format!("Failed to parse hostname '{}': {}", conn_settings.host, err))
    })?;
    let sess = rustls::ClientSession::new(&Arc::new(rustls_config), hostname);
    let tcp_stream = (tcpstream_factory)(&addr, conn_settings)?;
    let tls_stream = StreamOwned::new(sess, tcp_stream);

    Ok(create_kmip_client(tls_stream, conn_settings))
}
