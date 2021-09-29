use std::future::Future;
use std::net::{SocketAddr, ToSocketAddrs};

use crate::client::tls::common::util::create_kmip_client;
use crate::client::{Client, ClientCertificate, ConnectionSettings, Error, Result};

use log::info;

use tokio::net::TcpStream;
use tokio_native_tls::native_tls::{Certificate, Identity, Protocol, TlsConnector};
use tokio_native_tls::TlsStream;

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

    let connect_timeout = conn_settings.connect_timeout.clone();

    let connect = async { (tcpstream_factory)(addr, conn_settings).await };

    let tcp_stream = if let Some(timeout) = connect_timeout {
        tokio::time::timeout(timeout, connect)
            .await
            .map_err(|err| Error::ConfigurationError(format!("Failed to connect to host or timed out: {}", err)))??
    } else {
        connect.await?
    };

    let tls_connector = create_tls_connector(conn_settings)?;

    let tls_client = tokio_native_tls::TlsConnector::from(tls_connector);

    let tls_stream = tls_client
        .connect(&conn_settings.host, tcp_stream)
        .await
        .map_err(|err| Error::ConfigurationError(format!("Failed to establish TLS connection: {}", err)))?;

    Ok(create_kmip_client(tls_stream, conn_settings))
}

fn create_tls_connector(conn_settings: &ConnectionSettings) -> Result<TlsConnector> {
    let mut connector = TlsConnector::builder();

    if conn_settings.insecure {
        connector.danger_accept_invalid_certs(true);
        connector.danger_accept_invalid_hostnames(true);
    } else {
        connector.min_protocol_version(Some(Protocol::Tlsv12));

        if let Some(cert_bytes) = conn_settings.server_cert.as_ref() {
            let cert = Certificate::from_pem(&cert_bytes)
                .map_err(|err| Error::ConfigurationError(format!("Failed to parse server certificate: {}", err)))?;
            connector.add_root_certificate(cert);
        }

        if let Some(cert_bytes) = conn_settings.ca_cert.as_ref() {
            let cert = Certificate::from_pem(&cert_bytes)
                .map_err(|err| Error::ConfigurationError(format!("Failed to parse CA certificate: {}", err)))?;
            connector.add_root_certificate(cert);
        }
    }

    if let Some(cert) = &conn_settings.client_cert {
        match cert {
            ClientCertificate::SeparatePem { .. } => {
                // From: https://docs.rs/tokio-native-tls/0.3.0/tokio_native_tls/native_tls/struct.Identity.html
                // openssl pkcs12 -export -out identity.pfx -inkey key.pem -in cert.pem -certfile chain_certs.pem
                return Err(Error::ConfigurationError(
                    "PEM format client certificate and key are not supported".to_string(),
                ));
            }
            ClientCertificate::CombinedPkcs12 { cert_bytes } => {
                const EMPTY_PASSWORD: &'static str = "";
                let identity = Identity::from_pkcs12(&cert_bytes, EMPTY_PASSWORD)
                    .map_err(|err| Error::ConfigurationError(format!("Failed to parse client certificate: {}", err)))?;
                connector.identity(identity);
            }
        }
    }

    let tls_connector = connector
        .build()
        .map_err(|err| Error::ConfigurationError(format!("Failed to build TLS connector: {}", err)))?;

    Ok(tls_connector)
}
