//! A high level KMIP "operation" oriented client interface for request/response construction & (de)serialization.
use std::{
    cell::RefCell,
    ops::{Deref, DerefMut},
    sync::{
        atomic::{AtomicU8, Ordering},
        Arc, Mutex, PoisonError,
    },
};

use kmip_ttlv::{error::ErrorKind, Config, PrettyPrinter};
use log::trace;

use crate::{
    auth::{self, CredentialType},
    request::to_vec,
    tag_map,
    types::{common::*, request, request::*, response::*, traits::*},
};

/// There was a problem sending/receiving a KMIP request/response.
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Error {
    ConfigurationError(String),
    SerializeError(String),
    RequestWriteError(String),
    ResponseReadError(String),
    DeserializeError(String),
    ServerError(String),
    InternalError(String),
    ItemNotFound(String),
    Unknown(String),
}

impl Error {
    /// Is this a possibly transient problem with the connection to the server?
    pub fn is_connection_error(&self) -> bool {
        use Error::*;
        matches!(self, RequestWriteError(_) | ResponseReadError(_))
    }
}

impl std::error::Error for Error {}

impl From<std::io::Error> for Error {
    fn from(err: std::io::Error) -> Self {
        Error::ServerError(format!("I/O error: {}", err))
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::ConfigurationError(e) => f.write_fmt(format_args!("Configuration error: {}", e)),
            Error::SerializeError(e) => f.write_fmt(format_args!("Serialize error: {}", e)),
            Error::RequestWriteError(e) => f.write_fmt(format_args!("Request send error: {}", e)),
            Error::ResponseReadError(e) => f.write_fmt(format_args!("Response read error: {}", e)),
            Error::DeserializeError(e) => f.write_fmt(format_args!("Deserialize error: {}", e)),
            Error::ServerError(e) => f.write_fmt(format_args!("Server error: {}", e)),
            Error::InternalError(e) => f.write_fmt(format_args!("Internal error: {}", e)),
            Error::ItemNotFound(e) => f.write_fmt(format_args!("Item not found: {}", e)),
            Error::Unknown(e) => f.write_fmt(format_args!("Unknown error: {}", e)),
        }
    }
}

/// The successful or failed outcome resulting from sending a request to a KMIP server.
pub type Result<T> = std::result::Result<T, Error>;

impl<T> From<PoisonError<T>> for Error {
    fn from(err: PoisonError<T>) -> Self {
        Error::InternalError(err.to_string())
    }
}

/// Use this builder to construct a [Client] struct.
#[derive(Debug)]
pub struct ClientBuilder<T> {
    username: Option<String>,
    password: Option<String>,
    stream: T,
    reader_config: Config,
}

impl<T> ClientBuilder<T> {
    /// Build a [Client] struct that will read/write from/to the given stream.
    ///
    /// Creates a [ClientBuilder] which can be used to create a [Client] which will read/write from/to the given
    /// stream. The stream is expected to be a type which can read from and write to an established TCP connection to
    /// the KMIP server. In production the stream should also perform TLS de/encryption on the data read from/written
    /// to the stream.
    ///
    /// The `stream` argument must implement the read and write traits which the [Client] will use to read/write
    /// from/to the stream.
    pub fn new(stream: T) -> Self {
        Self {
            username: None,
            password: None,
            stream,
            reader_config: Config::default(),
        }
    }

    /// Configure the [Client] to do include username/password authentication credentials in KMIP requests.
    pub fn with_credentials(mut self, username: String, password: Option<String>) -> Self {
        self.username = Some(username);
        self.password = password;
        self
    }

    /// Configure the [Client] to use the given reader [Config].
    pub fn with_reader_config(mut self, reader_config: Config) -> Self {
        self.reader_config = reader_config;
        self
    }

    /// Build the configured [Client] struct instance.
    pub fn build(self) -> Client<T> {
        let mut pretty_printer = PrettyPrinter::new();
        pretty_printer.with_tag_prefix("4200".into());
        pretty_printer.with_tag_map(tag_map::make_kmip_tag_map());

        Client {
            username: self.username,
            password: self.password,
            stream: Arc::new(Mutex::new(self.stream)),
            reader_config: self.reader_config,
            connection_error_count: AtomicU8::new(0),
            last_req_diag_str: RefCell::new(None),
            last_res_diag_str: RefCell::new(None),
            pretty_printer,
        }
    }
}

/// Helper macro to avoid repetetive blocks of almost identical code
macro_rules! get_response_payload_for_type {
    ($response:expr, $response_type:path) => {{
        // Process the successful response
        if let $response_type(payload) = $response {
            Ok(payload)
        } else {
            Err(Error::InternalError(format!(
                "Expected {} response payload but got: {:?}",
                stringify!($response_type),
                $response
            )))
        }
    }};
}

/// A client for serializing KMIP and deserializing KMIP responses to/from an established read/write stream.
///
/// Use the [ClientBuilder] to build a [Client] instance to work with.
#[derive(Debug)]
pub struct Client<T> {
    username: Option<String>,
    password: Option<String>,
    stream: Arc<Mutex<T>>,
    reader_config: Config,
    connection_error_count: AtomicU8,
    last_req_diag_str: RefCell<Option<String>>,
    last_res_diag_str: RefCell<Option<String>>,
    pretty_printer: PrettyPrinter,
}

impl<T: ReadWrite> Client<T> {
    pub fn inner(&self) -> Arc<Mutex<T>> {
        self.stream.clone()
    }

    /// Write request bytes to the given stream and read, deserialize and sanity check the response.
    #[maybe_async::maybe_async]
    async fn send_and_receive(
        &self,
        operation: Operation,
        reader_config: &Config,
        req_bytes: &[u8],
        stream: Arc<Mutex<T>>,
    ) -> Result<ResponsePayload> {
        let mut lock = stream.lock()?;
        let stream = lock.deref_mut();

        stream
            .write_all(req_bytes)
            .await
            .map_err(|e| Error::RequestWriteError(e.to_string()))?;

        // Read and deserialize the response
        let mut res: ResponseMessage = kmip_ttlv::from_reader(stream, reader_config)
            .await
            .map_err(|err| match err.kind() {
                ErrorKind::IoError(e) => Error::ResponseReadError(e.to_string()),
                ErrorKind::ResponseSizeExceedsLimit(_) | ErrorKind::MalformedTtlv(_) => {
                    Error::DeserializeError(err.to_string())
                }
                _ => Error::InternalError(err.to_string()),
            })?;

        if res.header.batch_count == 1 && res.batch_items.len() == 1 {
            let item = &mut res.batch_items[0];

            match item.result_status {
                ResultStatus::OperationFailed => {
                    if matches!(item.result_reason, Some(ResultReason::ItemNotFound)) {
                        Err(Error::ItemNotFound(format!(
                            "Operation {:?} failed: {}",
                            operation,
                            item.result_message.as_ref().unwrap_or(&String::new()).clone()
                        )))
                    } else {
                        Err(Error::ServerError(format!(
                            "Operation {:?} failed: {}",
                            operation,
                            item.result_message.as_ref().unwrap_or(&String::new()).clone()
                        )))
                    }
                }
                ResultStatus::OperationPending => Err(Error::InternalError(
                    "Result status 'operation pending' is not supported".into(),
                )),
                ResultStatus::OperationUndone => Err(Error::InternalError(
                    "Result status 'operation undone' is not supported".into(),
                )),
                ResultStatus::Success => {
                    if item.operation == Some(operation) {
                        if let Some(payload) = item.payload.take() {
                            Ok(payload)
                        } else {
                            Err(Error::InternalError(
                                "Unable to process response payload due to wrong deserialized type!".into(),
                            ))
                        }
                    } else {
                        Err(Error::InternalError(format!(
                            "Response operation {:?} does not match request operation {}",
                            item.operation, operation
                        )))
                    }
                }
            }
        } else {
            Err(Error::ServerError(format!(
                "Expected one batch item in response but received {}",
                res.batch_items.len()
            )))
        }
    }

    /// Serialize the given request to the stream and deserialize the response.
    ///
    /// Automatically constructs the request message wrapper around the payload including the [RequestHeader] and
    /// [BatchItem].
    ///
    /// Only supports a single batch item.
    ///
    /// Sets the request operation to [RequestPayload::operation()].
    ///
    /// # Errors
    ///
    /// Will fail if there is a problem serializing the request, writing to or reading from the stream, deserializing
    /// the response or if the response does not indicate operation success or contains more than one batch item.
    ///
    /// Currently always returns [Error::Unknown] even though richer cause information is available.
    #[maybe_async::maybe_async]
    pub async fn do_request(&self, payload: RequestPayload) -> Result<ResponsePayload> {
        // Clear the diagnostic string representations of the request and response.
        *self.last_req_diag_str.borrow_mut() = None;
        *self.last_res_diag_str.borrow_mut() = None;

        // Save a copy of the KMIP operation identifier before the request payload object is consumed by the
        // TTLV serializer.
        let operation = payload.operation();

        // Serialize the request payload to TTLV byte form.
        let req_bytes = to_vec(payload, self.auth()).map_err(|err| match err.kind() {
            ErrorKind::IoError(e) => Error::SerializeError(e.to_string()),
            _ => Error::InternalError(err.to_string()),
        })?;

        // If the caller requested that diagnostic string representations of the TTLV request and response bytes be
        // captured then generate, record and log the diagnostic representation of the request.
        if self.reader_config.has_buf() {
            let diag_str = self.pretty_printer.to_diag_string(&req_bytes);
            trace!("KMIP TTLV request: {}", &diag_str);
            self.last_req_diag_str.borrow_mut().replace(diag_str);
        }

        // Prepare a helper closure for incrementing the number of connection errors encountered by this client.
        let incr_err_count = |err: Error| {
            if err.is_connection_error() {
                let _ = self.connection_error_count.fetch_add(1, Ordering::SeqCst);
            }
            Err(err)
        };

        // Send the serialized request and receive (and deserialize) the response.
        let res = self
            .send_and_receive(operation, &self.reader_config, &req_bytes, self.stream.clone())
            .await
            .or_else(incr_err_count);

        // If the caller requested that diagnostic string representations of the TTLV request and response bytes be
        // captured, then generate, record and log the diagnostic representation of the response.
        if let Some(buf) = self.reader_config.read_buf() {
            let diag_str = self.pretty_printer.to_diag_string(&buf);
            trace!("KMIP TTLV response: {}", &diag_str);
            self.last_res_diag_str.borrow_mut().replace(diag_str);
        }

        res
    }

    /// Serialize a KMIP 1.0 [Query](https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581232) request.
    ///
    /// See also: [do_request()](Self::do_request())
    #[maybe_async::maybe_async]
    pub async fn query(&self) -> Result<QueryResponsePayload> {
        // Setup the request
        let wanted_info = vec![
            QueryFunction::QueryOperations,
            QueryFunction::QueryObjects,
            QueryFunction::QueryServerInformation,
        ];
        let request = RequestPayload::Query(wanted_info);

        // Execute the request and capture the response
        let response = self.do_request(request).await?;

        // Process the successful response
        get_response_payload_for_type!(response, ResponsePayload::Query)
    }

    /// Serialize a KMIP 1.0 [Create Key Pair](https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581269) request to create an RSA key pair.
    ///
    /// See also: [do_request()](Self::do_request())
    ///
    /// Creates an RSA key pair.
    ///
    /// To create keys of other types or with other parameters you must compose the Create Key Pair request manually
    /// and pass it to [do_request()](Self::do_request()) directly.
    #[maybe_async::maybe_async]
    pub async fn create_rsa_key_pair(
        &self,
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
        let response = self.do_request(request).await?;

        // Process the successful response
        get_response_payload_for_type!(response, ResponsePayload::CreateKeyPair).map(|payload| {
            (
                payload.private_key_unique_identifier.deref().clone(),
                payload.public_key_unique_identifier.deref().clone(),
            )
        })
    }

    /// Serialize a KMIP 1.2 [Rng Retrieve](https://docs.oasis-open.org/kmip/spec/v1.2/os/kmip-spec-v1.2-os.html#_Toc409613562)
    /// operation to retrieve a number of random bytes.
    ///
    /// See also: [do_request()](Self::do_request())
    ///
    #[maybe_async::maybe_async]
    pub async fn rng_retrieve(&self, num_bytes: i32) -> Result<RNGRetrieveResponsePayload> {
        let request = RequestPayload::RNGRetrieve(DataLength(num_bytes));

        // Execute the request and capture the response
        let response = self.do_request(request).await?;

        // Process the successful response
        get_response_payload_for_type!(response, ResponsePayload::RNGRetrieve)
    }

    /// Serialize a KMIP 1.2 [Sign](https://docs.oasis-open.org/kmip/spec/v1.2/os/kmip-spec-v1.2-os.html#_Toc409613558)
    /// operation to sign the given bytes with the given private key ID.
    ///
    /// See also: [do_request()](Self::do_request())
    ///
    #[maybe_async::maybe_async]
    pub async fn sign(&self, private_key_id: &str, in_bytes: &[u8]) -> Result<SignResponsePayload> {
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
        let response = self.do_request(request).await?;

        get_response_payload_for_type!(response, ResponsePayload::Sign)
    }

    /// Serialize a KMIP 1.0 [Activate](https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581226)
    /// operation to activate a given private key ID.
    ///
    /// See also: [do_request()](Self::do_request())
    ///
    /// To activate other kinds of managed object you must compose the Activate request manually and pass it to
    /// [do_request()](Self::do_request()) directly.
    #[maybe_async::maybe_async]
    pub async fn activate_key(&self, private_key_id: &str) -> Result<()> {
        let request = RequestPayload::Activate(Some(UniqueIdentifier(private_key_id.to_owned())));

        // Execute the request and capture the response
        let response = self.do_request(request).await?;

        // Process the successful response
        get_response_payload_for_type!(response, ResponsePayload::Activate).map(|_| ())
    }

    /// Serialize a KMIP 1.0 [Revoke](https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581227)
    /// operation to deactivate a given private key ID.
    ///
    /// See also: [do_request()](Self::do_request())
    ///
    /// To deactivate other kinds of managed object you must compose the Revoke request manually and pass it to
    /// [do_request()](Self::do_request()) directly.
    #[maybe_async::maybe_async]
    pub async fn revoke_key(&self, private_key_id: &str) -> Result<()> {
        let request = RequestPayload::Revoke(
            Some(UniqueIdentifier(private_key_id.to_owned())),
            RevocationReason(
                RevocationReasonCode::CessationOfOperation,
                Option::<RevocationMessage>::None,
            ),
            Option::<CompromiseOccurrenceDate>::None,
        );

        // Execute the request and capture the response
        let response = self.do_request(request).await?;

        // Process the successful response
        get_response_payload_for_type!(response, ResponsePayload::Revoke).map(|_| ())
    }

    /// Serialize a KMIP 1.0 [Destroy](https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581228)
    /// operation to destroy a given private key ID.
    ///
    /// See also: [do_request()](Self::do_request())
    ///
    /// To destroy other kinds of managed object you must compose the Destroy request manually and pass it to
    /// [do_request()](Self::do_request()) directly.
    #[maybe_async::maybe_async]
    pub async fn destroy_key(&self, key_id: &str) -> Result<()> {
        let request = RequestPayload::Destroy(Some(UniqueIdentifier(key_id.to_owned())));

        // Execute the request and capture the response
        let response = self.do_request(request).await?;

        // Process the successful response
        get_response_payload_for_type!(response, ResponsePayload::Destroy).map(|_| ())
    }

    /// Serialize a KMIP 1.0 [ModifyAttribute](http://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581222)
    /// operation to rename a given key ID.
    ///
    /// See also: [do_request()](Self::do_request())
    ///
    /// To modify other attributes of managed objects you must compose the Modify Attribute request manually and pass
    /// it to [do_request()](Self::do_request()) directly.
    #[maybe_async::maybe_async]
    pub async fn rename_key(&self, key_id: &str, new_name: String) -> Result<ModifyAttributeResponsePayload> {
        // Setup the request
        let request = RequestPayload::ModifyAttribute(
            Some(UniqueIdentifier(key_id.to_string())),
            request::Attribute::Name(new_name),
        );

        // Execute the request and capture the response
        let response = self.do_request(request).await?;

        // Process the successful response
        get_response_payload_for_type!(response, ResponsePayload::ModifyAttribute)
    }

    /// Serialize a KMIP 1.0 [Get](http://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581218)
    /// operation to get the details of a given key ID.
    ///
    /// See also: [do_request()](Self::do_request())
    #[maybe_async::maybe_async]
    pub async fn get_key(&self, key_id: &str) -> Result<GetResponsePayload> {
        // Setup the request
        let request = RequestPayload::Get(
            Some(UniqueIdentifier(key_id.to_string())),
            Option::<KeyFormatType>::None,
            Option::<KeyCompressionType>::None,
            Option::<KeyWrappingSpecification>::None,
        );

        // Execute the request and capture the response
        let response = self.do_request(request).await?;

        // Process the successful response
        get_response_payload_for_type!(response, ResponsePayload::Get)
    }
}

impl<T> Clone for Client<T> {
    fn clone(&self) -> Self {
        Self {
            username: self.username.clone(),
            password: self.password.clone(),
            stream: self.stream.clone(),
            reader_config: self.reader_config.clone(),
            connection_error_count: AtomicU8::new(self.connection_error_count()),
            last_req_diag_str: self.last_req_diag_str.clone(),
            last_res_diag_str: self.last_res_diag_str.clone(),
            pretty_printer: self.pretty_printer.clone(),
        }
    }
}

impl<T> Client<T> {
    fn auth(&self) -> Option<CredentialType> {
        if self.username.is_some() && self.password.is_some() {
            Some(CredentialType::UsernameAndPassword(
                auth::UsernameAndPasswordCredential::new(self.username.clone().unwrap(), self.password.clone()),
            ))
        } else {
            None
        }
    }

    /// Get a clone of the client's last req diag str.
    pub fn last_req_diag_str(&self) -> Option<String> {
        self.last_req_diag_str.borrow().to_owned()
    }

    /// Get a clone of the client's last res diag str.
    pub fn last_res_diag_str(&self) -> Option<String> {
        self.last_res_diag_str.borrow().to_owned()
    }

    /// Get the count of connection errors experienced by this Client.
    pub fn connection_error_count(&self) -> u8 {
        self.connection_error_count.load(Ordering::SeqCst)
    }
}

#[cfg(test)]
mod test {
    use std::{
        io::{Cursor, Read, Write},
        net::TcpStream,
    };

    use kmip_ttlv::Config;

    #[cfg(feature = "tls-with-openssl")]
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

        let client = ClientBuilder::new(&mut stream).build();

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

        let client = ClientBuilder::new(&mut stream).build();

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

        let client = ClientBuilder::new(&mut tls)
            .with_reader_config(Config::default().with_max_bytes(64 * 1024))
            .build();

        let response_payload = client.query().unwrap();

        dbg!(response_payload);
    }

    #[cfg(feature = "tls-with-rustls")]
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

        let client = ClientBuilder::new(&mut tls)
            .with_reader_config(Config::default().with_max_bytes(64 * 1024))
            .build();

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

        let client = ClientBuilder::new(&mut tls)
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

        let client = ClientBuilder::new(&mut stream).build();

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
