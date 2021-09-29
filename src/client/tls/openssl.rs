use std::{
    fs::OpenOptions,
    net::{SocketAddr, TcpStream, ToSocketAddrs},
};

use crate::client::tls::common::util::create_kmip_client;

use crate::client::{
    tls::common::SSLKEYLOGFILE_ENV_VAR_NAME, Client, ClientCertificate, ConnectionSettings, Error, Result,
};

use log::info;

use openssl::ssl::{SslConnector, SslMethod, SslStream, SslVerifyMode};

pub fn connect(conn_settings: &ConnectionSettings) -> Result<Client<SslStream<TcpStream>>> {
    connect_with_tcp_stream_factory(conn_settings, |addr, settings| {
        let tcp_stream = if let Some(timeout) = settings.connect_timeout {
            TcpStream::connect_timeout(addr, timeout)?
        } else {
            TcpStream::connect(addr)?
        };
        Ok(tcp_stream)
    })
}

pub fn connect_with_tcp_stream_factory<F>(
    conn_settings: &ConnectionSettings,
    tcp_stream_factory: F,
) -> Result<Client<SslStream<TcpStream>>>
where
    F: Fn(&SocketAddr, &ConnectionSettings) -> Result<TcpStream>,
{
    let addr = format!("{}:{}", conn_settings.host, conn_settings.port)
        .to_socket_addrs()?
        .next()
        .ok_or(Error::ConfigurationError(
            "Failed to parse KMIP server address:port".to_string(),
        ))?;

    let tcp_stream = (tcp_stream_factory)(&addr, conn_settings)?;

    tcp_stream.set_read_timeout(conn_settings.read_timeout)?;
    tcp_stream.set_write_timeout(conn_settings.write_timeout)?;

    let tls_connector = create_tls_connector(&conn_settings)
        .map_err(|err| Error::ConfigurationError(format!("Failed to establish TLS connection: {}", err)))?;

    let tls_stream = tls_connector
        .connect(&conn_settings.host, tcp_stream)
        .map_err(|err| Error::ConfigurationError(format!("Failed to establish TLS connection: {}", err)))?;

    Ok(create_kmip_client(tls_stream, conn_settings))
}

fn create_tls_connector(conn_settings: &ConnectionSettings) -> Result<SslConnector> {
    let mut tls_connector = SslConnector::builder(SslMethod::tls())
        .map_err(|err| Error::ConfigurationError(format!("Failed to intialize TLS Connector: {}", err)))?;

    if conn_settings.insecure {
        tls_connector.set_verify(SslVerifyMode::NONE);
    } else {
        if let Some(cert_bytes) = &conn_settings.server_cert {
            let x509_cert = openssl::x509::X509::from_pem(&cert_bytes)
                .map_err(|err| Error::ConfigurationError(format!("Failed to parse server certificate: {}", err)))?;
            tls_connector
                .cert_store_mut()
                .add_cert(x509_cert)
                .map_err(|err| Error::ConfigurationError(format!("Failed to parse server certificate: {}", err)))?;
        }

        if let Some(cert_bytes) = &conn_settings.ca_cert {
            let x509_cert = openssl::x509::X509::from_pem(&cert_bytes)
                .map_err(|err| Error::ConfigurationError(format!("Failed to parse CA certificate: {}", err)))?;
            tls_connector
                .cert_store_mut()
                .add_cert(x509_cert)
                .map_err(|err| Error::ConfigurationError(format!("Failed to parse CA certificate: {}", err)))?;
        }
    }

    if let Some(cert) = &conn_settings.client_cert {
        match cert {
            ClientCertificate::CombinedPkcs12 { .. } => {
                return Err(Error::ConfigurationError(
                    "PKCS#12 client certificate format is not supported".to_string(),
                ));
            }
            ClientCertificate::SeparatePem { cert_bytes, key_bytes } => {
                let x509_cert = openssl::x509::X509::from_pem(&cert_bytes)
                    .map_err(|err| Error::ConfigurationError(format!("Failed to parse client certificate: {}", err)))?;
                tls_connector
                    .set_certificate(&x509_cert)
                    .map_err(|err| Error::ConfigurationError(format!("Failed to parse client certificate: {}", err)))?;

                if let Some(key_bytes) = key_bytes {
                    // Quoting RFC-5246 Transport Layer Security (TLS) Protocol Version 1.2
                    // section 7.3 Handshake Protocol Overview:
                    //
                    // "The ClientKeyExchange message is now sent, and the content
                    //  of that message will depend on the public key algorithm selected
                    //  between the ClientHello and the ServerHello.  If the client has sent
                    //  a certificate with signing ability, a digitally-signed
                    //  CertificateVerify message is sent to explicitly verify possession of
                    //  the private key in the certificate."
                    //
                    // From: https://datatracker.ietf.org/doc/html/rfc5246#section-7.3
                    //
                    // So, the client certificate private key is used to sign the
                    // CertificateVerify message sent from client to server.
                    let pkey = openssl::pkey::PKey::private_key_from_pem(&key_bytes).map_err(|err| {
                        Error::ConfigurationError(format!("Failed to parse client certificate private key: {}", err))
                    })?;
                    tls_connector.set_private_key(&pkey).map_err(|err| {
                        Error::ConfigurationError(format!("Failed to parse client certificate private key: {}", err))
                    })?;
                }
            }
        }
    }

    if std::env::var(SSLKEYLOGFILE_ENV_VAR_NAME).is_ok() {
        tls_connector.set_keylog_callback(|_, line| {
            if let Ok(path) = std::env::var(SSLKEYLOGFILE_ENV_VAR_NAME) {
                if let Ok(mut file) = OpenOptions::new().write(true).append(true).open(path) {
                    use std::io::Write;
                    writeln!(file, "{}", line).ok();
                }
            }
        });
    }

    Ok(tls_connector.build())
}
