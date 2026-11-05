use std::{
    fs::OpenOptions,
    net::{SocketAddr, TcpStream, ToSocketAddrs},
};

use crate::net::{TlsServerAuth, tls::common::util::create_kmip_client};

use crate::net::{ConnectionSettings, NetError, NetResult, tls::common::SSLKEYLOGFILE_ENV_VAR_NAME};

use openssl::ssl::{SslConnector, SslMethod, SslStream, SslVerifyMode};

pub type Client = crate::net::Client<SslStream<TcpStream>>;

pub fn connect(conn_settings: &ConnectionSettings) -> NetResult<Client> {
    connect_with_tcpstream_factory(conn_settings, |addr, settings| {
        let tcp_stream = if let Some(timeout) = settings.connect_timeout {
            TcpStream::connect_timeout(addr, timeout)?
        } else {
            TcpStream::connect(addr)?
        };
        Ok(tcp_stream)
    })
}

pub fn connect_with_tcpstream_factory<F>(conn_settings: &ConnectionSettings, tcp_stream_factory: F) -> NetResult<Client>
where
    F: Fn(&SocketAddr, &ConnectionSettings) -> NetResult<TcpStream>,
{
    let addr = format!("{}:{}", conn_settings.host, conn_settings.port)
        .to_socket_addrs()?
        .next()
        .ok_or(NetError::ConfigurationError(
            "Failed to parse KMIP server address:port".to_string(),
        ))?;

    let tcp_stream = (tcp_stream_factory)(&addr, conn_settings)?;

    tcp_stream.set_read_timeout(conn_settings.read_timeout)?;
    tcp_stream.set_write_timeout(conn_settings.write_timeout)?;

    let tls_connector = create_tls_connector(conn_settings)
        .map_err(|err| NetError::ConfigurationError(format!("Failed to establish TLS connection: {}", err)))?;

    let sni_name = conn_settings
        .tls_server_name
        .as_ref()
        .map_or_else(|| conn_settings.host.clone(), |name| name.clone());

    let tls_stream = tls_connector
        .connect(&sni_name, tcp_stream)
        .map_err(|err| NetError::ConfigurationError(format!("Failed to establish TLS connection: {}", err)))?;

    Ok(create_kmip_client(tls_stream, conn_settings))
}

fn create_tls_connector(conn_settings: &ConnectionSettings) -> NetResult<SslConnector> {
    let mut tls_connector = SslConnector::builder(SslMethod::tls())
        .map_err(|err| NetError::ConfigurationError(format!("Failed to intialize TLS Connector: {}", err)))?;

    match &conn_settings.tls_server_auth {
        TlsServerAuth::None => {
            tls_connector.set_verify(SslVerifyMode::NONE);
        }

        TlsServerAuth::Default => {
            tls_connector.set_verify(SslVerifyMode::PEER);
        }

        TlsServerAuth::TrustCertificate(cert_bytes) => {
            tls_connector.set_verify(SslVerifyMode::PEER);
            let x509_cert = openssl::x509::X509::from_pem(cert_bytes)
                .map_err(|err| NetError::ConfigurationError(format!("Failed to parse server certificate: {}", err)))?;
            tls_connector.cert_store_mut().add_cert(x509_cert).map_err(|err| {
                NetError::ConfigurationError(format!(
                    "Failed to add server certificate to certificate store: {}",
                    err
                ))
            })?;
        }

        TlsServerAuth::TrustCertificateAuthority(ca_cert_bytes) => {
            tls_connector.set_verify(SslVerifyMode::PEER);
            let x509_cert = openssl::x509::X509::from_pem(ca_cert_bytes)
                .map_err(|err| NetError::ConfigurationError(format!("Failed to parse CA certificate: {}", err)))?;
            tls_connector.cert_store_mut().add_cert(x509_cert).map_err(|err| {
                NetError::ConfigurationError(format!("Failed to parse CA certificate to certificate store: {}", err))
            })?;
        }
    }

    if let Some(client_auth) = &conn_settings.tls_client_auth {
        let x509_cert = openssl::x509::X509::from_pem(&client_auth.cert_bytes)
            .map_err(|err| NetError::ConfigurationError(format!("Failed to parse PEM client certificate: {}", err)))?;
        tls_connector
            .set_certificate(&x509_cert)
            .map_err(|err| NetError::ConfigurationError(format!("Failed to set client certificate to use: {}", err)))?;

        // Quoting RFC-5246 Transport Layer Security (TLS) Protocol Version
        // 1.2 section 7.3 Handshake Protocol Overview:
        //
        // "The ClientKeyExchange message is now sent, and the content of
        //  that message will depend on the public key algorithm selected
        //  between the ClientHello and the ServerHello.  If the client
        //  has sent a certificate with signing ability, a digitally-signed
        //  CertificateVerify message is sent to explicitly verify possession
        //  of the private key in the certificate."
        //
        // From: https://datatracker.ietf.org/doc/html/rfc5246#section-7.3
        //
        // So, the client certificate private key is used to sign the
        // CertificateVerify message sent from client to server.
        let pkey = openssl::pkey::PKey::private_key_from_pem(&client_auth.private_key_bytes)
            .map_err(|err| NetError::ConfigurationError(format!("Failed to parse PEM client private key: {}", err)))?;
        tls_connector
            .set_private_key(&pkey)
            .map_err(|err| NetError::ConfigurationError(format!("Failed to set client private key to use: {}", err)))?;
    }

    if std::env::var(SSLKEYLOGFILE_ENV_VAR_NAME).is_ok() {
        tls_connector.set_keylog_callback(|_, line| {
            if let Ok(path) = std::env::var(SSLKEYLOGFILE_ENV_VAR_NAME)
                && let Ok(mut file) = OpenOptions::new().append(true).open(path)
            {
                use std::io::Write;
                writeln!(file, "{}", line).ok();
            }
        });
    }

    Ok(tls_connector.build())
}
