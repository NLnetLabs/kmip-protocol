#![cfg(all(test, feature = "sync"))]
use std::{
    io::{Cursor, Read, Write},
    net::TcpStream,
};

#[cfg(any(feature = "tls-with-openssl", feature = "tls-with-openssl-vendored"))]
use openssl::ssl::{SslConnector, SslFiletype, SslMethod, SslVerifyMode};

use crate::{
    net::ClientServerBuilder,
    types::{
        request::{QueryFunction, RequestPayload},
        response::ResponsePayload,
    },
};

struct MockStream {
    pub response: Cursor<Vec<u8>>,
}

impl Write for MockStream {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        std::io::sink().write(buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl Read for MockStream {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.response.read(buf)
    }
}

#[test]
fn test_query() {
    let response_hex = concat!(
        "42007B010000023042007A0100000048420069010000002042006A0200000004000000010000000042006B02000000040",
        "0000000000000004200920900000008000000004B7918AA42000D0200000004000000010000000042000F01000001D842",
        "005C0500000004000000180000000042007F0500000004000000000000000042007C01000001B042005C0500000004000",
        "000010000000042005C0500000004000000020000000042005C0500000004000000030000000042005C05000000040000",
        "00040000000042005C0500000004000000080000000042005C0500000004000000090000000042005C050000000400000",
        "00A0000000042005C05000000040000000B0000000042005C05000000040000000C0000000042005C0500000004000000",
        "0D0000000042005C05000000040000000E0000000042005C05000000040000000F0000000042005C05000000040000001",
        "00000000042005C0500000004000000110000000042005C0500000004000000120000000042005C050000000400000013",
        "0000000042005C0500000004000000140000000042005C0500000004000000150000000042005C0500000004000000160",
        "000000042005C0500000004000000180000000042005C0500000004000000190000000042005C05000000040000001A00",
        "0000004200570500000004000000010000000042005705000000040000000200000000420057050000000400000003000",
        "000004200570500000004000000040000000042005705000000040000000600000000"
    );
    let response_bytes = hex::decode(response_hex).unwrap();

    let mut stream = MockStream {
        response: Cursor::new(response_bytes),
    };

    let mut client = ClientServerBuilder::new(&mut stream).build();

    let response_payload = client.query().unwrap();

    dbg!(response_payload);
}

#[test]
fn test_create_rsa_key_pair() {
    let response_hex = concat!(
        "42007B01000000E042007A0100000048420069010000002042006A0200000004000000010000000042006B02000000040",
        "0000000000000004200920900000008000000004B73C13A42000D0200000004000000010000000042000F010000008842",
        "005C0500000004000000020000000042007F0500000004000000000000000042007C01000000604200940700000024383",
        "93566373263322D623230612D343964382D393530342D3664633231313563633034320000000042009407000000246132",
        "3432666361342D656266302D343339382D616336352D38373962616234393032353900000000"
    );
    let response_bytes = hex::decode(response_hex).unwrap();

    let mut stream = MockStream {
        response: Cursor::new(response_bytes),
    };

    let mut client = ClientServerBuilder::new(&mut stream).build();

    let response_payload = client
        .create_rsa_key_pair(1024, "My Private Key".into(), "My Public Key".into())
        .unwrap();

    dbg!(response_payload);
}

#[cfg(feature = "tls-with-openssl")]
#[test]
#[ignore = "Requires a running PyKMIP instance"]
fn test_pykmip_query_against_server_with_openssl() {
    let mut connector = SslConnector::builder(SslMethod::tls()).unwrap();
    connector.set_verify(SslVerifyMode::NONE);
    connector
        .set_certificate_file("/etc/pykmip/server.crt", SslFiletype::PEM)
        .unwrap();
    connector
        .set_private_key_file("/etc/pykmip/server.key", SslFiletype::PEM)
        .unwrap();
    let connector = connector.build();
    let stream = TcpStream::connect("localhost:5696").unwrap();
    let mut tls = connector.connect("localhost", stream).unwrap();

    let mut client = ClientServerBuilder::new(&mut tls)
        .with_reader_config(Config::default().with_max_bytes(64 * 1024))
        .build();

    let response_payload = client.query().unwrap();

    dbg!(response_payload);
}

#[cfg(feature = "tls-with-rustls")]
#[test]
#[ignore = "Requires a running PyKMIP instance"]
fn test_pykmip_query_against_server_with_rustls() {
    use rustls::pki_types::pem;
    use rustls::pki_types::pem::PemObject;
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
    use std::convert::TryFrom;
    use std::fs;
    use std::sync::Arc;

    // To setup input files for PyKMIP and RustLS to work together we must use a cipher they have in common, either
    // TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 or TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA384.
    //
    // To generate the required files use the following commands:
    //
    // ```
    // # Prepare a directory to contain the PyKMIP config file and supporting certificate files
    // sudo mkdir /etc/pykmip
    // sudo chown $USER: /etc/pykmip
    // cd /etc/pykmip
    //
    // # Prepare an OpenSSL configuration file for adding a Subject Alternative Name (SAN) to the generated CSR
    // # and certificate. Without the SAN we would need to use the RustDL "dangerous" feature to ignore the server/
    // # certificate mismatched name verification failure.
    // cat <<EOF >san.cnf
    // [ext]
    // subjectAltName = DNS:localhost
    // EOF
    //
    // # Prepare to do CA signing
    // mkdir demoCA
    // touch demoCA/index.txt
    // echo 01 > demoCA/serial
    //
    // # Generate CA key
    // # Warns: using curve name prime256v1 instead of secp256r1
    // openssl ecparam -out ca.key -name secp256r1 -genkey
    //
    // # Generate CA certificate
    // openssl req -x509 -new -key ca.key -out ca.crt -outform PEM -days 3650 -subj "/C=NL/ST=Noord Holland/L=Amsterdam/O=NLnet Labs/CN=localhost"
    //
    // # Generate PyKMIP server key
    // # Warns: using curve name prime256v1 instead of secp256r1
    // openssl ecparam -out server.key -name secp256r1 -genkey
    //
    // # Generate request for PyKMIP server certificate
    // openssl req -new -nodes -key server.key -outform pem -out server.csr -subj "/C=NL/ST=Noord Holland/L=Amsterdam/O=NLnet Labs/CN=localhost"
    //
    // # Ask the CA to sign the request to create the PyKMIP server certificate
    // openssl ca -keyfile ca.key -cert ca.crt -in server.csr -out server.crt -outdir . -batch -noemailDN -extfile san.cnf -extensions ext
    //
    // # Convert the server key from --BEGIN EC PRIVATE KEY-- format to --BEGIN PRIVATE KEY-- format
    // # as RustLS cannot pass the former as a client certificate when connecting...
    // openssl pkcs8 -topk8 -nocrypt -in server.key -out server.pkcs8.key
    //
    // # Replace the original server.key with the PKCS#8 format one because PyKMIP can use that as well
    // mv server.pkcs8.key server.key
    //
    // # Now write a PyKMIP config file that uses the generated files
    // cat <<EOF >server.conf
    // [server]
    // hostname=127.0.0.1
    // port=5696
    // certificate_path=/etc/pykmip/server.crt
    // key_path=/etc/pykmip/server.key
    // ca_path=/etc/pykmip/ca.crt
    // auth_suite=TLS1.2
    // enable_tls_client_auth=False
    // tls_cipher_suites=TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
    // logging_level=DEBUG
    // database_path=/tmp/pykmip.db
    // EOF
    //
    // # Lastly, run PyKMIP:
    // pykmip-server
    // ```

    // For more insight into what RustLS is doing enabling the "logging" feature of the RustLS crate and then use
    // a logging implementation here, e.g.
    //     stderrlog::new()
    //         .module(module_path!())
    //         .module("rustls")
    //         .quiet(false)
    //         .verbosity(5) // show INFO level logging by default, use -q to silence this
    //         .timestamp(stderrlog::Timestamp::Second)
    //         .init()
    //         .unwrap();

    fn bytes_to_cert_chain(bytes: &[u8]) -> Result<Vec<CertificateDer<'static>>, pem::Error> {
        let mut res = Vec::new();
        for item in CertificateDer::pem_slice_iter(bytes) {
            res.push(item?.into_owned());
        }
        Ok(res)
    }

    fn bytes_to_private_key(bytes: &[u8]) -> Result<PrivateKeyDer<'static>, pem::Error> {
        Ok(PrivateKeyDer::from_pem_slice(bytes)?.clone_key())
    }

    // Load files
    let ca_cert_pem = fs::read("/etc/pykmip/ca.crt").unwrap();
    let server_cert_pem = fs::read("/etc/pykmip/server.crt").unwrap();
    let server_key_pem = fs::read("/etc/pykmip/server.key").unwrap();

    let mut root_store = rustls::RootCertStore::empty();
    for item in CertificateDer::pem_slice_iter(ca_cert_pem.as_slice()) {
        root_store.add(item.unwrap()).unwrap();
    }
    for item in CertificateDer::pem_slice_iter(server_cert_pem.as_slice()) {
        root_store.add(item.unwrap()).unwrap();
    }

    let cert_chain = bytes_to_cert_chain(&server_cert_pem).unwrap();
    let key_der = bytes_to_private_key(&server_key_pem).unwrap();

    let config = rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_client_auth_cert(cert_chain, key_der)
        .unwrap();

    let rc_config = Arc::new(config);
    let localhost = ServerName::try_from("localhost").unwrap();
    let mut sess = rustls::ClientConnection::new(rc_config, localhost).unwrap();
    let mut stream = TcpStream::connect("localhost:5696").unwrap();
    let mut tls = rustls::Stream::new(&mut sess, &mut stream);

    let mut client = ClientServerBuilder::new(&mut tls).build();

    let response_payload = client.query().unwrap();

    dbg!(response_payload);
}

#[test]
#[cfg(any(feature = "tls-with-openssl", feature = "tls-with-openssl-vendored"))]
#[ignore = "Requires a running Kryptus instance"]
fn test_kryptus_query_against_server() {
    let mut connector = SslConnector::builder(SslMethod::tls()).unwrap();
    connector.set_verify(SslVerifyMode::NONE);
    let connector = connector.build();
    let host = std::env::var("KRYPTUS_HOST").unwrap();
    let port = std::env::var("KRYPTUS_PORT").unwrap();
    let stream = TcpStream::connect(format!("{}:{}", host, port)).unwrap();
    let mut tls = connector.connect(&host, stream).unwrap();

    let mut client = ClientServerBuilder::new(&mut tls)
        .with_credentials(
            std::env::var("KRYPTUS_USER").unwrap(),
            Some(std::env::var("KRYPTUS_PASS").unwrap()),
        )
        .with_reader_config(Config::default().with_max_bytes(64 * 1024))
        .build();

    let response_payload = client.query().unwrap();

    dbg!(response_payload);
}

#[test]
fn test_pykmip_query_response() {
    let response_hex = concat!(
        "42007b010000014042007a0100000048420069010000002042006a0200000004000000010000000042006b02000000040",
        "00000000000000042009209000000080000000060ff457142000d0200000004000000010000000042000f01000000e842",
        "005c0500000004000000180000000042007f0500000004000000000000000042007c01000000c042005c0500000004000",
        "000010000000042005c0500000004000000020000000042005c0500000004000000030000000042005c05000000040000",
        "00050000000042005c0500000004000000080000000042005c05000000040000000a0000000042005c050000000400000",
        "00b0000000042005c05000000040000000c0000000042005c0500000004000000120000000042005c0500000004000000",
        "130000000042005c0500000004000000140000000042005c05000000040000001800000000"
    );
    let response_bytes = hex::decode(response_hex).unwrap();

    let mut stream = MockStream {
        response: Cursor::new(response_bytes),
    };

    let mut client = ClientServerBuilder::new(&mut stream).build();

    let result = client
        .do_request_payload(RequestPayload::Query(vec![QueryFunction::QueryOperations]))
        .unwrap();

    if let ResponsePayload::Query(payload) = result {
        dbg!(payload);
    } else {
        panic!("Expected query response!");
    }
}
