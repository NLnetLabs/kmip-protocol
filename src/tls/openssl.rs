use std::{
    fs::OpenOptions,
    net::{TcpStream, ToSocketAddrs},
};

use crate::tls::util::create_kmip_client;

use crate::tls::{
    config::{ClientCertificate, Config},
    Client, SSLKEYLOGFILE_ENV_VAR_NAME,
};

use log::info;

use openssl::ssl::{SslConnector, SslMethod, SslStream, SslVerifyMode};

pub fn connect(config: Config) -> Client<SslStream<TcpStream>> {
    let addr = format!("{}:{}", config.host, config.port)
        .to_socket_addrs()
        .expect("Error parsing host and port")
        .next()
        .expect("Internal error fetching parsed host and port from iterator");

    info!("Establishing TLS connection to server..");
    let tcp_stream = if let Some(timeout) = config.connect_timeout {
        TcpStream::connect_timeout(&addr, timeout).expect("Failed to connect to host with timeout")
    } else {
        TcpStream::connect(&addr).expect("Failed to connect to host")
    };

    tcp_stream
        .set_read_timeout(config.read_timeout)
        .expect("Failed to set read timeout on TCP connection");
    tcp_stream
        .set_write_timeout(config.write_timeout)
        .expect("Failed to set write timeout on TCP connection");

    let tls_client = create_tls_client(&config).expect("Failed to create TLS client");

    let tls_stream = tls_client
        .connect(&config.host, tcp_stream)
        .expect("Failed to establish TLS connection");

    create_kmip_client(tls_stream, config)
}

fn create_tls_client(config: &Config) -> Result<SslConnector, openssl::error::ErrorStack> {
    let mut connector = SslConnector::builder(SslMethod::tls())?;

    if config.insecure {
        connector.set_verify(SslVerifyMode::NONE);
    } else {
        if let Some(cert_bytes) = &config.server_cert {
            let x509_cert = openssl::x509::X509::from_pem(&cert_bytes)?;
            connector.cert_store_mut().add_cert(x509_cert)?;
        }

        if let Some(cert_bytes) = &config.ca_cert {
            let x509_cert = openssl::x509::X509::from_pem(&cert_bytes)?;
            connector.cert_store_mut().add_cert(x509_cert)?;
        }
    }

    if let Some(cert) = &config.client_cert {
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
