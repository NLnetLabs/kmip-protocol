use std::{fs::File, io::Read};

use crate::client::{ConnectionSettings, Error};

cfg_if::cfg_if! {
    if #[cfg(any(feature = "tls-with-openssl", feature = "tls-with-openssl-vendored"))] {
        use crate::client::tls::openssl::connect_with_tcpstream_factory;
    } else if #[cfg(feature = "tls-with-rustls")] {
        use crate::client::tls::rustls::connect_with_tcpstream_factory;
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

    let mut server_cert = vec![];
    File::open("test-data/cert.pem")
        .unwrap()
        .read_to_end(&mut server_cert)
        .unwrap();

    let mut ca_cert = vec![];
    File::open("test-data/root-ca.pem")
        .unwrap()
        .read_to_end(&mut ca_cert)
        .unwrap();

    let mut client_cert = vec![];
    File::open("test-data/client-cert.pem")
        .unwrap()
        .read_to_end(&mut client_cert)
        .unwrap();

    let mut client_key = vec![];
    File::open("test-data/client-cert.key.pem")
        .unwrap()
        .read_to_end(&mut client_key)
        .unwrap();

    let client_cert = crate::client::ClientCertificate::SeparatePem {
        cert_bytes: client_cert,
        key_bytes: client_key,
    };

    let conn_settings = ConnectionSettings {
        host: "localhost".to_string(),
        port: 12345,
        username: None,
        password: None,
        insecure: false,
        client_cert: Some(client_cert),
        server_cert: Some(server_cert),
        ca_cert: Some(ca_cert),
        connect_timeout: None,
        read_timeout: None,
        write_timeout: None,
        max_response_bytes: None,
    };

    static ERR_MSG: &str = "configured but will not connect due to being a test";
    let res = connect_with_tcpstream_factory(&conn_settings, |_addr, _settings| {
        Err(Error::InternalError(ERR_MSG.to_string()))
    });

    // If the configuration settings including the provided PEM files
    // were parsed successfully we should have proceeded to the connection
    // attempt which should result in our custom error message.
    assert_eq!(res.unwrap_err(), Error::InternalError(ERR_MSG.to_string()));
}
