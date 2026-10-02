#![cfg(all(test, feature = "sync"))]
use std::{
    io::{Cursor, Read, Write},
    net::TcpStream,
    time::SystemTime,
};

#[cfg(any(feature = "tls-with-openssl", feature = "tls-with-openssl-vendored"))]
use openssl::ssl::{SslConnector, SslFiletype, SslMethod, SslVerifyMode};

use crate::{
    net::{ClientBuilder, NetError, NetResult},
    ttlv::to_vec,
    types::{
        common::{ObjectType, Operation},
        request::{QueryFunction, RequestPayload},
        response::{
            self, ProtocolVersion, ResponseHeader, ResponseMessage, ResponsePayload, ResultReason, ResultStatus,
        },
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
    // Decoded by copying the quoted hex lines below into /tmp/t then running:
    //   cargo run -q --example hex_to_txt
    //
    // Tag: Response Message (0x42007B), Type: Structure (0x01), Data:
    //   Tag: Response Header (0x42007A), Type: Structure (0x01), Data:
    //     Tag: Protocol Version (0x420069), Type: Structure (0x01), Data:
    //       Tag: Protocol Version Major (0x42006A), Type: Integer (0x02), Data: 0x000001 (1)
    //       Tag: Protocol Version Minor (0x42006B), Type: Integer (0x02), Data: 0x000000 (0)
    //     Tag: Time Stamp (0x420092), Type: DateTime (0x09), Data: 0x4B7918AA
    //     Tag: Batch Count (0x42000D), Type: Integer (0x02), Data: 0x000001 (1)
    //   Tag: Batch Item (0x42000F), Type: Structure (0x01), Data:
    //     Tag: Operation (0x42005C), Type: Enumeration (0x05), Data: 0x000018 (24 = Query)
    //     Tag: Result Status (0x42007F), Type: Enumeration (0x05), Data: 0x000000 (0 = Success)
    //     Tag: Response Payload (0x42007C), Type: Structure (0x01), Data:
    //       Tag: Operation (0x42005C), Type: Enumeration (0x05), Data: 0x000001 (1 = Create)
    //       Tag: Operation (0x42005C), Type: Enumeration (0x05), Data: 0x000002 (2 = Create Key Pair)
    //       Tag: Operation (0x42005C), Type: Enumeration (0x05), Data: 0x000003 (3 = Register)
    //       Tag: Operation (0x42005C), Type: Enumeration (0x05), Data: 0x000004 (4 = Re-key)
    //       Tag: Operation (0x42005C), Type: Enumeration (0x05), Data: 0x000008 (8 = Locate)
    //       Tag: Operation (0x42005C), Type: Enumeration (0x05), Data: 0x000009 (9 = Check)
    //       Tag: Operation (0x42005C), Type: Enumeration (0x05), Data: 0x00000A (10 = Get)
    //       Tag: Operation (0x42005C), Type: Enumeration (0x05), Data: 0x00000B (11 = Get Attributes)
    //       Tag: Operation (0x42005C), Type: Enumeration (0x05), Data: 0x00000C (12 = Get Attribute List)
    //       Tag: Operation (0x42005C), Type: Enumeration (0x05), Data: 0x00000D (13 = Add Attribute)
    //       Tag: Operation (0x42005C), Type: Enumeration (0x05), Data: 0x00000E (14 = Modify Attribute)
    //       Tag: Operation (0x42005C), Type: Enumeration (0x05), Data: 0x00000F (15 = Delete Attribute)
    //       Tag: Operation (0x42005C), Type: Enumeration (0x05), Data: 0x000010 (16 = Obtain Lease)
    //       Tag: Operation (0x42005C), Type: Enumeration (0x05), Data: 0x000011 (17 = Get Usage Allocation)
    //       Tag: Operation (0x42005C), Type: Enumeration (0x05), Data: 0x000012 (18 = Activate)
    //       Tag: Operation (0x42005C), Type: Enumeration (0x05), Data: 0x000013 (19 = Revoke)
    //       Tag: Operation (0x42005C), Type: Enumeration (0x05), Data: 0x000014 (20 = Destroy)
    //       Tag: Operation (0x42005C), Type: Enumeration (0x05), Data: 0x000015 (21 = Archive)
    //       Tag: Operation (0x42005C), Type: Enumeration (0x05), Data: 0x000016 (22 = Recover)
    //       Tag: Operation (0x42005C), Type: Enumeration (0x05), Data: 0x000018 (24 = Query)
    //       Tag: Operation (0x42005C), Type: Enumeration (0x05), Data: 0x000019 (25 = Cancel)
    //       Tag: Operation (0x42005C), Type: Enumeration (0x05), Data: 0x00001A (26 = Poll)
    //       Tag: Object Type (0x420057), Type: Enumeration (0x05), Data: 0x000001 (1 = Certificate)
    //       Tag: Object Type (0x420057), Type: Enumeration (0x05), Data: 0x000002 (2 = Symmetric Key)
    //       Tag: Object Type (0x420057), Type: Enumeration (0x05), Data: 0x000003 (3 = Public Key)
    //       Tag: Object Type (0x420057), Type: Enumeration (0x05), Data: 0x000004 (4 = Private Key)
    //       Tag: Object Type (0x420057), Type: Enumeration (0x05), Data: 0x000006 (6 = Template)
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

    let mut client = ClientBuilder::new(&mut stream).build();

    let response_payload = client.query().unwrap();

    assert_eq!(
        response_payload.operations,
        Some(vec![
            Operation::Create,
            Operation::CreateKeyPair,
            Operation::Register,
            Operation::Rekey,
            Operation::Locate,
            Operation::Check,
            Operation::Get,
            Operation::GetAttributes,
            Operation::GetAttributeList,
            Operation::AddAttribute,
            Operation::ModifyAttribute,
            Operation::DeleteAttribute,
            Operation::ObtainLease,
            Operation::GetUsageAllocation,
            Operation::Activate,
            Operation::Revoke,
            Operation::Destroy,
            Operation::Archive,
            Operation::Recover,
            Operation::Query,
            Operation::Cancel,
            Operation::Poll,
        ])
    );
    assert_eq!(
        response_payload.object_types,
        Some(vec![
            ObjectType::Certificate,
            ObjectType::SymmetricKey,
            ObjectType::PublicKey,
            ObjectType::PrivateKey,
            ObjectType::Template
        ])
    );
    assert_eq!(response_payload.vendor_identification, None);
    assert_eq!(response_payload.server_information, None);
    assert_eq!(client.connection_error_count(), 0);
}

#[test]
fn test_create_rsa_key_pair() {
    // Decoded by copying the quoted hex lines below into /tmp/t then running:
    //   cargo run -q --example hex_to_txt
    //
    // Tag: Response Message (0x42007B), Type: Structure (0x01), Data:
    //   Tag: Response Header (0x42007A), Type: Structure (0x01), Data:
    //     Tag: Protocol Version (0x420069), Type: Structure (0x01), Data:
    //       Tag: Protocol Version Major (0x42006A), Type: Integer (0x02), Data: 0x000001 (1)
    //       Tag: Protocol Version Minor (0x42006B), Type: Integer (0x02), Data: 0x000000 (0)
    //     Tag: Time Stamp (0x420092), Type: DateTime (0x09), Data: 0x4B73C13A
    //     Tag: Batch Count (0x42000D), Type: Integer (0x02), Data: 0x000001 (1)
    //   Tag: Batch Item (0x42000F), Type: Structure (0x01), Data:
    //     Tag: Operation (0x42005C), Type: Enumeration (0x05), Data: 0x000002 (2 = Create Key Pair)
    //     Tag: Result Status (0x42007F), Type: Enumeration (0x05), Data: 0x000000 (0 = Success)
    //     Tag: Response Payload (0x42007C), Type: Structure (0x01), Data:
    //       Tag: Unique Identifier (0x420094), Type: TextString (0x07), Data: "895f72c2-b20a-49d8-9504-6dc2115cc042"
    //       Tag: Unique Identifier (0x420094), Type: TextString (0x07), Data: "a242fca4-ebf0-4398-ac65-879bab490259"
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

    let mut client = ClientBuilder::new(&mut stream).build();

    let response_payload = client
        .create_rsa_key_pair(1024, "My Private Key".into(), "My Public Key".into())
        .unwrap();

    assert_eq!(response_payload.0, "895f72c2-b20a-49d8-9504-6dc2115cc042");
    assert_eq!(response_payload.1, "a242fca4-ebf0-4398-ac65-879bab490259");
    assert_eq!(client.connection_error_count(), 0);
}

#[test]
fn test_multiple_requests() {
    // Define mock KMIP responses
    let payload = ResponsePayload::Query(response::QueryResponsePayload::default());
    let good_response_bytes =
        response::to_vec(payload_to_response(ResultStatus::Success, None, None, Some(payload)).unwrap()).unwrap();
    let bad_response_bytes =
        response::to_vec(payload_to_response(ResultStatus::OperationFailed, None, None, None).unwrap()).unwrap();

    // Define a sequence of mock responses to serve and whether the query
    // that receives the response should succeed or not.
    let test_entries = [
        (&good_response_bytes, true),
        (&bad_response_bytes, false),
        (&good_response_bytes, true),
        (&bad_response_bytes, false),
    ];

    // Configure the mock stream with the defined sequence of mock responses.
    let mut mock_response_stream = vec![];
    test_entries
        .iter()
        .for_each(|(bytes, _)| mock_response_stream.extend_from_slice(bytes));
    let mut stream = MockStream {
        response: Cursor::new(mock_response_stream),
    };

    // Create a real KMIP client that "connects" to a mock network stream.
    let mut client = ClientBuilder::new(&mut stream).build();

    // Query for each mock response and assert that the query succeeds or
    // fails as expected.
    for (_, expect_ok) in test_entries {
        assert_eq!(client.query().is_ok(), expect_ok);
    }

    assert_eq!(client.connection_error_count(), 0);
}

#[test]
fn test_connection_dropped() {
    // Configure the mock stream to be empty.
    let mut stream = MockStream {
        response: Cursor::new(vec![]),
    };

    // Create a real KMIP client that "connects" to a mock network stream.
    let mut client = ClientBuilder::new(&mut stream).build();

    // Attempt to query the mock server which should fail due to the lack
    // of response.
    assert!(matches!(
        client.query(),
        Err(crate::net::NetError::ResponseReadError(_))
    ));

    // The client closing the connection is NOT considered an error.
    assert_eq!(client.connection_error_count(), 0);
}

#[test]
fn test_connection_dropped_after_one_response() {
    let bad_response_bytes =
        response::to_vec(payload_to_response(ResultStatus::OperationFailed, None, None, None).unwrap()).unwrap();

    // Configure the mock stream to contain one response.
    let mut stream = MockStream {
        response: Cursor::new(bad_response_bytes),
    };

    // Create a real KMIP client that "connects" to a mock network stream.
    let mut client = ClientBuilder::new(&mut stream).build();

    // The first query should get the operation failed error response from
    // the mock server.
    assert!(matches!(client.query(), Err(crate::net::NetError::ServerError(_))));

    // The second query should fail with a network error as there are no
    // more bytes to read from the mock network stream.
    assert!(matches!(
        client.query(),
        Err(crate::net::NetError::ResponseReadError(_))
    ));

    // The client closing the connection is NOT considered an error.
    assert_eq!(client.connection_error_count(), 0);
}

#[test]
fn test_partial_response() {
    let mut response_bytes =
        response::to_vec(payload_to_response(ResultStatus::OperationFailed, None, None, None).unwrap()).unwrap();

    response_bytes.truncate(response_bytes.len() / 2);

    // Configure the mock stream to contain one response.
    let mut stream = MockStream {
        response: Cursor::new(response_bytes),
    };

    // Create a real KMIP client that "connects" to a mock network stream.
    let mut client = ClientBuilder::new(&mut stream).build();

    // The first query should fail with a network error as there are no
    // more bytes to read from the mock network stream.
    assert!(matches!(
        client.query(),
        Err(crate::net::NetError::ResponseReadError(_))
    ));

    // The client closing the connection is NOT considered an error.
    assert_eq!(client.connection_error_count(), 0);
}

#[test]
fn test_unsupported_valid_ttlv() {
    // Sere a protocol version TTLV instead of a ResponseMessage TTLV
    // as expected.
    let garbage_response = to_vec(|f| ProtocolVersion { major: 1, minor: 0 }.format(f)).unwrap();

    // Configure the mock stream to contain one response.
    let mut stream = MockStream {
        response: Cursor::new(garbage_response.clone()),
    };

    // Create a real KMIP client that "connects" to a mock network stream.
    let mut client = ClientBuilder::new(&mut stream).build();

    // The query should fail with a deserializer error as the Protocol
    // Version TTLV cannot be deserialized as a Response Message TTLV.
    let res = client.query();
    let Err(crate::net::NetError::DeserializeError { res, .. }) = res else {
        panic!("Expected deserialize error but got: {res:?}");
    };

    // Verify that the received response bytes were made available to us
    // in the error details.
    assert_eq!(*res, garbage_response);
    assert_eq!(client.connection_error_count(), 0);
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

    let mut client = ClientBuilder::new(&mut tls).build();

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

    let mut client = ClientBuilder::new(&mut tls).build();

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

    let mut client = ClientBuilder::new(&mut tls)
        .with_credentials(
            std::env::var("KRYPTUS_USER").unwrap(),
            Some(std::env::var("KRYPTUS_PASS").unwrap()),
        )
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

    let mut client = ClientBuilder::new(&mut stream).build();

    let mut batch_items = client
        .do_request_payload(RequestPayload::Query(vec![QueryFunction::QueryOperations]))
        .unwrap();

    assert!(!batch_items.is_empty());
    let batch_item = batch_items.pop().unwrap();
    assert!(matches!(
        batch_item.unwrap().payload,
        Some(ResponsePayload::Query { .. })
    ));
}

//------------ Helper functions ----------------------------------------------

fn batch_items_to_response(batch_items: Vec<response::BatchItem>) -> NetResult<ResponseMessage> {
    if batch_items.len() >= i32::MAX as usize {
        return Err(NetError::SerializeError(format!(
            "Too many batch items: {} > {}",
            batch_items.len(),
            i32::MAX
        )));
    }

    let timestamp = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs()
        .try_into()
        .unwrap();

    let protocol_version = batch_items
        .iter()
        .filter_map(|item| item.payload.as_ref())
        .map(|payload| payload.protocol_version())
        .max()
        .unwrap_or_default();

    Ok(ResponseMessage {
        header: ResponseHeader {
            protocol_version,
            timestamp,
            batch_count: batch_items.len().try_into().unwrap(),
        },
        batch_items,
    })
}

fn payload_to_response(
    result_status: ResultStatus,
    result_reason: Option<ResultReason>,
    result_message: Option<String>,
    payload: Option<ResponsePayload>,
) -> NetResult<ResponseMessage> {
    let batch_items = vec![response::BatchItem {
        operation: payload.as_ref().map(|p| p.operation()),
        unique_batch_item_id: None,
        result_status,
        result_reason,
        result_message,
        payload,
        message_extension: None,
    }];
    batch_items_to_response(batch_items)
}
