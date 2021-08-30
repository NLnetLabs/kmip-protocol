use std::{
    io::{Read, Write},
    ops::Deref,
};

use kmip_ttlv::Config;

use crate::{
    auth::{self, CredentialType},
    request::to_vec,
    types::{common::*, request, request::*, response::*},
};

#[derive(Debug)]
pub struct ClientBuilder<T: Read + Write> {
    username: Option<String>,
    password: Option<String>,
    stream: T,
    reader_config: Config,
}

impl<T: Read + Write> ClientBuilder<T> {
    pub fn new(stream: T) -> Self {
        Self {
            username: None,
            password: None,
            stream,
            reader_config: Config::default(),
        }
    }

    pub fn with_credentials(mut self, username: String, password: Option<String>) -> Self {
        self.username = Some(username);
        self.password = password;
        self
    }

    pub fn with_reader_config(mut self, reader_config: Config) -> Self {
        self.reader_config = reader_config;
        self
    }

    pub fn build(self) -> Client<T> {
        Client {
            username: self.username,
            password: self.password,
            stream: self.stream,
            reader_config: self.reader_config,
        }
    }
}

#[derive(Debug)]
pub struct Client<T: Read + Write> {
    username: Option<String>,
    password: Option<String>,
    stream: T,
    reader_config: Config,
}

#[allow(dead_code)]
#[derive(Debug)]
pub enum Error {
    Unknown,
}

pub type Result<T> = std::result::Result<T, Error>;

impl<T: Read + Write> Client<T> {
    fn auth(&self) -> Option<CredentialType> {
        if self.username.is_some() && self.password.is_some() {
            Some(CredentialType::UsernameAndPassword(
                auth::UsernameAndPasswordCredential::new(self.username.clone().unwrap(), self.password.clone()),
            ))
        } else {
            None
        }
    }

    pub fn do_request(&mut self, payload: RequestPayload) -> Result<ResponsePayload> {
        let operation = payload.operation();

        // Serialize and write the request
        let req_bytes = to_vec(payload, self.auth()).map_err(|e| {
            eprintln!("{}", e);
            Error::Unknown
        })?;
        self.stream.write_all(&req_bytes).map_err(|_| Error::Unknown)?;

        // Read and deserialize the response
        let mut res: ResponseMessage = kmip_ttlv::from_reader(&mut self.stream, &self.reader_config).map_err(|e| {
            eprintln!("Error: {:?}", e);
            Error::Unknown
        })?;
        // TODO: Handle operation failed here.
        if res.header.batch_count == 1 && res.batch_items.len() == 1 {
            let item = &mut res.batch_items[0];

            if item.result_status == ResultStatus::Success && item.operation == Some(operation) {
                if let Some(payload) = item.payload.take() {
                    return Ok(payload);
                }
            }
        }

        Err(Error::Unknown)
    }

    pub fn query(&mut self) -> Result<QueryResponsePayload> {
        // Setup the request
        let wanted_info = vec![
            QueryFunction::QueryOperations,
            QueryFunction::QueryObjects,
            QueryFunction::QueryServerInformation,
        ];
        let request = RequestPayload::Query(wanted_info);

        // Execute the request and capture the response
        let response = self.do_request(request)?;

        // Process the successful response
        if let ResponsePayload::Query(payload) = response {
            Ok(payload)
        } else {
            Err(Error::Unknown)
        }
    }

    // Returns the private and public unique key identifiers.
    pub fn create_rsa_key_pair(
        &mut self,
        key_length: i32,
        private_key_name: String,
        public_key_name: String,
    ) -> Result<(String, String)> {
        // Setup the request
        let request = RequestPayload::CreateKeyPair(
            Some(CommonTemplateAttribute::unnamed(vec![
                request::Attribute::CryptographicAlgorithm(CryptographicAlgorithm::RSA),
                request::Attribute::CryptographicLength(key_length),
            ])),
            Some(PrivateKeyTemplateAttribute::unnamed(vec![
                request::Attribute::Name(private_key_name),
                request::Attribute::CryptographicUsageMask(CryptographicUsageMask::Sign),
            ])),
            Some(PublicKeyTemplateAttribute::unnamed(vec![
                request::Attribute::Name(public_key_name),
                request::Attribute::CryptographicUsageMask(CryptographicUsageMask::Verify),
            ])),
        );

        // Execute the request and capture the response
        let response = self.do_request(request)?;

        // Process the successful response
        if let ResponsePayload::CreateKeyPair(payload) = response {
            Ok((
                payload.private_key_unique_identifier.deref().clone(),
                payload.public_key_unique_identifier.deref().clone(),
            ))
        } else {
            Err(Error::Unknown)
        }
    }

    pub fn rng_retrieve(&mut self, num_bytes: i32) -> Result<RNGRetrieveResponsePayload> {
        let request = RequestPayload::RNGRetrieve(DataLength(num_bytes));

        // Execute the request and capture the response
        let response = self.do_request(request)?;

        // Process the successful response
        if let ResponsePayload::RNGRetrieve(payload) = response {
            Ok(payload)
        } else {
            Err(Error::Unknown)
        }
    }

    // Takes the bytes to sign and the id of the private key to sign them with.
    // Returns the signed bytes.
    pub fn sign(&mut self, private_key_id: &str, in_bytes: &[u8]) -> Result<SignResponsePayload> {
        let request = RequestPayload::Sign(
            Some(UniqueIdentifier(private_key_id.to_owned())),
            Some(
                CryptographicParameters::default()
                    .with_padding_method(PaddingMethod::PKCS1_v1_5)
                    .with_hashing_algorithm(HashingAlgorithm::SHA256)
                    .with_cryptographic_algorithm(CryptographicAlgorithm::RSA),
            ),
            Data(in_bytes.to_vec()),
        );

        // Execute the request and capture the response
        let response = self.do_request(request)?;

        // Process the successful response
        if let ResponsePayload::Sign(payload) = response {
            Ok(payload)
        } else {
            Err(Error::Unknown)
        }
    }

    pub fn activate_key(&mut self, private_key_id: &str) -> Result<()> {
        let request = RequestPayload::Activate(Some(UniqueIdentifier(private_key_id.to_owned())));

        // Execute the request and capture the response
        let response = self.do_request(request)?;

        // Process the successful response
        if let ResponsePayload::Activate(_) = response {
            Ok(())
        } else {
            Err(Error::Unknown)
        }
    }

    pub fn revoke_key(&mut self, private_key_id: &str) -> Result<()> {
        let request = RequestPayload::Revoke(
            Some(UniqueIdentifier(private_key_id.to_owned())),
            RevocationReason(
                RevocationReasonCode::CessationOfOperation,
                Option::<RevocationMessage>::None,
            ),
            Option::<CompromiseOccurrenceDate>::None,
        );

        // Execute the request and capture the response
        let response = self.do_request(request)?;

        // Process the successful response
        if let ResponsePayload::Revoke(_) = response {
            Ok(())
        } else {
            Err(Error::Unknown)
        }
    }

    pub fn destroy_key(&mut self, key_id: &str) -> Result<()> {
        let request = RequestPayload::Destroy(Some(UniqueIdentifier(key_id.to_owned())));

        // Execute the request and capture the response
        let response = self.do_request(request)?;

        // Process the successful response
        if let ResponsePayload::Destroy(_) = response {
            Ok(())
        } else {
            Err(Error::Unknown)
        }
    }
}

#[cfg(test)]
mod test {
    use std::{
        io::{BufReader, Cursor, Read, Write},
        net::TcpStream,
        sync::Arc,
    };

    use kmip_ttlv::Config;
    use openssl::ssl::{SslConnector, SslFiletype, SslMethod, SslVerifyMode};

    use crate::{
        client::ClientBuilder,
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

        let mut client = ClientBuilder::new(&mut stream).configure();

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

        let mut client = ClientBuilder::new(&mut stream).configure();

        let response_payload = client
            .create_rsa_key_pair(1024, "My Private Key".into(), "My Public Key".into())
            .unwrap();

        dbg!(response_payload);
    }

    #[test]
    #[ignore = "Requires a running PyKMIP instance"]
    fn test_pykmip_query_against_server_with_openssl() {
        let mut connector = SslConnector::builder(SslMethod::tls()).unwrap();
        connector.set_verify(SslVerifyMode::NONE);
        connector
            .set_certificate_file("/etc/ssl/certs/selfsigned.crt", SslFiletype::PEM)
            .unwrap();
        connector
            .set_private_key_file("/etc/ssl/private/selfsigned.key", SslFiletype::PEM)
            .unwrap();
        let connector = connector.build();
        let stream = TcpStream::connect("localhost:5696").unwrap();
        let mut tls = connector.connect("localhost", stream).unwrap();

        let mut client = ClientBuilder::new(&mut tls)
            .with_reader_config(Config::default().with_max_bytes(64 * 1024))
            .configure();

        let response_payload = client.query().unwrap();

        dbg!(response_payload);
    }

    #[test]
    #[ignore = "Requires a running PyKMIP instance"]
    fn test_pykmip_query_against_server_with_rustls() {
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

        fn load_binary_file(path: &'static str) -> std::io::Result<Vec<u8>> {
            let mut buf = Vec::new();
            std::fs::File::open(path)?.read_to_end(&mut buf)?;
            Ok(buf)
        }

        fn bytes_to_cert_chain(bytes: &[u8]) -> std::io::Result<Vec<rustls::Certificate>> {
            let cert_chain = rustls_pemfile::read_all(&mut BufReader::new(bytes))?
                .iter()
                .map(|i: &rustls_pemfile::Item| match i {
                    rustls_pemfile::Item::X509Certificate(bytes) => rustls::Certificate(bytes.clone()),
                    rustls_pemfile::Item::RSAKey(_) => panic!("Expected an X509 certificate, got an RSA key"),
                    rustls_pemfile::Item::PKCS8Key(_) => panic!("Expected an X509 certificate, got a PKCS8 key"),
                })
                .collect();
            Ok(cert_chain)
        }

        fn bytes_to_private_key(bytes: &[u8]) -> std::io::Result<rustls::PrivateKey> {
            let private_key = rustls_pemfile::read_one(&mut BufReader::new(bytes))?
                .map(|i: rustls_pemfile::Item| match i {
                    rustls_pemfile::Item::X509Certificate(_) => panic!("Expected a PKCS8 key, got an X509 certificate"),
                    rustls_pemfile::Item::RSAKey(_) => panic!("Expected a PKCS8 key, got an RSA key"),
                    rustls_pemfile::Item::PKCS8Key(bytes) => rustls::PrivateKey(bytes.clone()),
                })
                .unwrap();
            Ok(private_key)
        }

        // Load files
        let ca_cert_pem = load_binary_file("/etc/pykmip/ca.crt").unwrap();
        let server_cert_pem = load_binary_file("/etc/pykmip/server.crt").unwrap();
        let server_key_pem = load_binary_file("/etc/pykmip/server.key").unwrap();

        let mut config = rustls::ClientConfig::new();
        config
            .root_store
            .add_pem_file(&mut BufReader::new(ca_cert_pem.as_slice()))
            .unwrap();
        config
            .root_store
            .add_pem_file(&mut BufReader::new(server_cert_pem.as_slice()))
            .unwrap();

        let cert_chain = bytes_to_cert_chain(&server_cert_pem).unwrap();
        let key_der = bytes_to_private_key(&server_key_pem).unwrap();
        config.set_single_client_cert(cert_chain, key_der).unwrap();

        let rc_config = Arc::new(config);
        let localhost = webpki::DNSNameRef::try_from_ascii_str("localhost").unwrap();
        let mut sess = rustls::ClientSession::new(&rc_config, localhost);
        let mut stream = TcpStream::connect("localhost:5696").unwrap();
        let mut tls = rustls::Stream::new(&mut sess, &mut stream);

        let mut client = ClientBuilder::new(&mut tls)
            .with_reader_config(Config::default().with_max_bytes(64 * 1024))
            .configure();

        let response_payload = client.query().unwrap();

        dbg!(response_payload);
    }

    #[test]
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
            .with_reader_config(Config::default().with_max_bytes(64 * 1024))
            .configure();

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

        let mut client = ClientBuilder::new(&mut stream).configure();

        let result = client
            .do_request(RequestPayload::Query(vec![QueryFunction::QueryOperations]))
            .unwrap();

        if let ResponsePayload::Query(payload) = result {
            dbg!(payload);
        } else {
            panic!("Expected query response!");
        }
    }
}
