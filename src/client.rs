use std::{
    io::{Read, Write},
    ops::Deref,
};

use krill_kmip_ttlv::Config;

use crate::{
    auth::{self, CredentialType},
    request::to_vec,
    types::{common::*, request, request::*, response::*},
};

pub struct ClientBuilder<'a, T: Read + Write> {
    username: Option<String>,
    password: Option<String>,
    stream: &'a mut T,
    reader_config: Config,
}

impl<'a, T: Read + Write> ClientBuilder<'a, T> {
    pub fn new(stream: &'a mut T) -> Self {
        Self {
            username: None,
            password: None,
            stream,
            reader_config: Config::default(),
        }
    }

    pub fn with_credentials(self, username: &str, password: Option<&str>) -> Self {
        Self {
            username: Some(username.to_string()),
            password: password.and(Some(password.unwrap().to_string())),
            ..self
        }
    }

    pub fn with_reader_config(self, reader_config: Config) -> Self {
        Self { reader_config, ..self }
    }

    pub fn unwrap(self) -> Client<'a, T> {
        Client {
            username: self.username,
            password: self.password,
            stream: self.stream,
            reader_config: self.reader_config,
        }
    }
}

pub struct Client<'a, T: Read + Write> {
    username: Option<String>,
    password: Option<String>,
    stream: &'a mut T,
    reader_config: Config,
}

#[allow(dead_code)]
#[derive(Debug)]
pub enum Error {
    Unknown,
}

pub type Result<T> = std::result::Result<T, Error>;

impl<'a, T: Read + Write> Client<'a, T> {
    fn auth(&self) -> Option<CredentialType> {
        if self.username.is_some() && self.password.is_some() {
            Some(CredentialType::UsernameAndPassword(
                auth::UsernameAndPasswordCredential::new(self.username.clone().unwrap(), self.password.clone()),
            ))
        } else {
            None
        }
    }

    fn do_request(&mut self, payload: RequestPayload) -> Result<ResponsePayload> {
        let operation = payload.operation();

        // Serialize and write the request
        let req_bytes = to_vec(payload, self.auth()).map_err(|e| {
            eprintln!("{}", e);
            Error::Unknown
        })?;
        self.stream.write_all(&req_bytes).map_err(|_| Error::Unknown)?;

        // The response data is untrusted input. If the reader buffers it could attempt to allocate a huge amount of
        // memory and cause a panic, so limit the amount we try to read in the worst case.

        // Read and deserialize the response
        let mut res: ResponseMessage = krill_kmip_ttlv::from_reader(self.stream, &self.reader_config).map_err(|e| {
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
    pub fn sign(&mut self, private_key_id: &str, in_bytes: &[u8]) -> Result<Vec<u8>> {
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
            Ok(payload.signature_data)
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

    pub fn destroy_key(&mut self, private_key_id: &str) -> Result<()> {
        let request = RequestPayload::Destroy(Some(UniqueIdentifier(private_key_id.to_owned())));

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
        io::{Cursor, Read, Write},
        net::TcpStream,
    };

    use krill_kmip_ttlv::Config;
    use openssl::ssl::{SslConnector, SslFiletype, SslMethod, SslVerifyMode};

    use crate::client::ClientBuilder;

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

        let mut client = ClientBuilder::new(&mut stream).unwrap();

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

        let mut client = ClientBuilder::new(&mut stream).unwrap();

        let response_payload = client
            .create_rsa_key_pair(1024, "My Private Key".into(), "My Public Key".into())
            .unwrap();

        dbg!(response_payload);
    }

    #[test]
    #[ignore = "Requires a running PyKMIP instance"]
    fn test_pykmip_query_against_server() {
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
            .unwrap();

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
                &std::env::var("KRYPTUS_USER").unwrap(),
                Some(&std::env::var("KRYPTUS_PASS").unwrap()),
            )
            .with_reader_config(Config::default().with_max_bytes(64 * 1024))
            .unwrap();

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

        let mut client = ClientBuilder::new(&mut stream).unwrap();

        let response_payload = client.query().unwrap();

        dbg!(response_payload);
    }
}
