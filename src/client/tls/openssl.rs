use std::{
    fs::OpenOptions,
    net::{SocketAddr, TcpStream, ToSocketAddrs},
};

use crate::client::tls::common::util::create_kmip_client;

use crate::client::{tls::common::SSLKEYLOGFILE_ENV_VAR_NAME, Client, ClientCertificate, ConnectionSettings};

use log::info;

use openssl::ssl::{SslConnector, SslMethod, SslStream, SslVerifyMode};

pub fn connect(conn_settings: &ConnectionSettings) -> Client<SslStream<TcpStream>> {
    connect_with_tcpstream_factory(conn_settings, |addr, settings| {
        if let Some(timeout) = settings.connect_timeout {
            TcpStream::connect_timeout(addr, timeout).expect("Failed to connect to host with timeout")
        } else {
            TcpStream::connect(addr).expect("Failed to connect to host")
        }
    })
}

pub fn connect_with_tcpstream_factory<F>(
    conn_settings: &ConnectionSettings,
    tcpstream_factory: F,
) -> Client<SslStream<TcpStream>>
where
    F: Fn(&SocketAddr, &ConnectionSettings) -> TcpStream,
{
    let addr = format!("{}:{}", conn_settings.host, conn_settings.port)
        .to_socket_addrs()
        .expect("Error parsing host and port")
        .next()
        .expect("Internal error fetching parsed host and port from iterator");

    info!("Establishing TLS connection to server..");
    let tcp_stream = (tcpstream_factory)(&addr, conn_settings);

    tcp_stream
        .set_read_timeout(conn_settings.read_timeout)
        .expect("Failed to set read timeout on TCP connection");
    tcp_stream
        .set_write_timeout(conn_settings.write_timeout)
        .expect("Failed to set write timeout on TCP connection");

    let tls_client = create_tls_client(&conn_settings).expect("Failed to create TLS client");

    let tls_stream = tls_client
        .connect(&conn_settings.host, tcp_stream)
        .expect("Failed to establish TLS connection");

    create_kmip_client(tls_stream, conn_settings)
}

fn create_tls_client(conn_settings: &ConnectionSettings) -> Result<SslConnector, openssl::error::ErrorStack> {
    let mut connector = SslConnector::builder(SslMethod::tls())?;

    if conn_settings.insecure {
        connector.set_verify(SslVerifyMode::NONE);
    } else {
        if let Some(cert_bytes) = &conn_settings.server_cert {
            let x509_cert = openssl::x509::X509::from_pem(&cert_bytes)?;
            connector.cert_store_mut().add_cert(x509_cert)?;
        }

        if let Some(cert_bytes) = &conn_settings.ca_cert {
            let x509_cert = openssl::x509::X509::from_pem(&cert_bytes)?;
            connector.cert_store_mut().add_cert(x509_cert)?;
        }
    }

    if let Some(cert) = &conn_settings.client_cert {
        match cert {
            ClientCertificate::CombinedPkcs12 { .. } => {
                /*return Err(... */
                panic!("PKCS#12 client certificate format is not supported")
            }
            ClientCertificate::SeparatePem { cert_bytes, key_bytes } => {
                let x509_cert = openssl::x509::X509::from_pem(&cert_bytes)?;
                connector.set_certificate(&x509_cert)?;

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
                    let pkey = openssl::pkey::PKey::private_key_from_pem(&key_bytes)?;
                    connector.set_private_key(&pkey)?;
                }
            }
        }
    }

    if std::env::var(SSLKEYLOGFILE_ENV_VAR_NAME).is_ok() {
        connector.set_keylog_callback(|_, line| {
            if let Ok(path) = std::env::var(SSLKEYLOGFILE_ENV_VAR_NAME) {
                if let Ok(mut file) = OpenOptions::new().write(true).append(true).open(path) {
                    use std::io::Write;
                    writeln!(file, "{}", line).ok();
                }
            }
        });
    }

    Ok(connector.build())
}
