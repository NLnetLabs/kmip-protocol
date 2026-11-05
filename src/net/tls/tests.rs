cfg_if::cfg_if! {
    if #[cfg(any(feature = "tls-with-openssl", feature = "tls-with-openssl-vendored"))] {
        use crate::net::tls::openssl::connect_with_tcpstream_factory;
    } else if #[cfg(feature = "tls-with-rustls")] {
        use crate::net::tls::rustls::connect_with_tcpstream_factory;
    }
}

#[test]
#[cfg(any(
    feature = "tls-with-openssl",
    feature = "tls-with-openssl-vendored",
    feature = "tls-with-rustls"
))]
fn parse_pem_files_correctly() {
    // Server certificate was generated using command:
    //   rustls-cert-gen --country-name=NL --organization-name="NLnet Labs" --ed25519 --output=.
    //
    // Client certificate was generated using command.
    //   rustls-cert-gen --country-name=NL --organization-name="NLnet Labs" --ed25519 --output=. --client-auth --cert-file-name client-cert

    use crate::net::{ConnectionSettings, NetError, TlsClientAuth, TlsServerAuth};

    static ERR_MSG: &str = "configured but will not connect due to being a test";

    let server_cert = std::fs::read("test-data/cert.pem").unwrap();
    let ca_cert = std::fs::read("test-data/root-ca.pem").unwrap();
    let client_cert = std::fs::read("test-data/client-cert.pem").unwrap();
    let client_key = std::fs::read("test-data/client-cert.key.pem").unwrap();

    let tls_client_auth = Some(TlsClientAuth {
        cert_bytes: client_cert,
        private_key_bytes: client_key,
    });

    for tls_server_auth in [
        TlsServerAuth::TrustCertificate(server_cert),
        TlsServerAuth::TrustCertificate(ca_cert),
    ] {
        let conn_settings = ConnectionSettings {
            host: "localhost".to_string(),
            port: 12345,
            username: None,
            password: None,
            connect_timeout: None,
            read_timeout: None,
            write_timeout: None,
            max_response_bytes: None,
            tls_client_auth: tls_client_auth.clone(),
            tls_server_auth,
            tls_server_name: None,
        };

        let res = connect_with_tcpstream_factory(&conn_settings, |_addr, _settings| {
            Err(NetError::InternalError(ERR_MSG.to_string()))
        });

        // If the configuration settings including the provided PEM files
        // were parsed successfully we should have proceeded to the connection
        // attempt which should result in our custom error message.
        assert!(matches!(res.unwrap_err(), NetError::InternalError(msg) if msg == ERR_MSG));
    }
}
