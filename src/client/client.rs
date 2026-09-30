use std::sync::PoisonError;
use std::time::SystemTime;
use std::{
    mem::MaybeUninit,
    ops::{Deref, DerefMut},
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
};

#[cfg(feature = "tokio")]
use tokio::sync::Mutex;

#[cfg(not(feature = "tokio"))]
use std::sync::Mutex;

use crate::{
    ttlv::{FastScanError, FastScanner},
    types::{
        common::*,
        request::{
            self, Authentication, BatchItem, CommonTemplateAttribute, CredentialValue, KeyWrappingSpecification,
            MaximumResponseSize, Password, PrivateKeyTemplateAttribute, PublicKeyTemplateAttribute, QueryFunction,
            RequestHeader, RequestMessage, RequestPayload, RevocationReason, Username,
        },
        response::{
            self, GetResponsePayload, ModifyAttributeResponsePayload, QueryResponsePayload, RNGRetrieveResponsePayload,
            ResponseHeader, ResponseMessage, ResponsePayload, ResultReason, ResultStatus, SignResponsePayload,
        },
        traits::ReadWrite,
    },
};

use tracing::trace;

/// Use this builder to construct a [ClientServer] struct.
#[derive(Debug)]
pub struct ClientServerBuilder<T: ReadWrite> {
    stream: T,
    auth: Option<Authentication>,
    max_messagesize: i32,
}

impl<T: ReadWrite> ClientServerBuilder<T> {
    /// Build a [ClientServer] struct that will read/write from/to the given stream.
    ///
    /// Creates a [ClientServerBuilder] which can be used to create a [ClientServer] which
    /// will read/write from/to the given stream. The stream is expected to be
    /// a type which can read from and write to an established TCP connection
    /// to the KMIP server. In production the stream should also perform TLS
    /// de/encryption on the data read from/written to the stream.
    ///
    /// The `stream` argument must implement the read and write traits which
    /// the [ClientServer] will use to read/write from/to the stream.
    pub fn new(stream: T) -> Self {
        Self {
            stream,
            auth: None,
            max_messagesize: i32::MAX,
        }
    }

    /// Configure the [ClientServer] to include username/password authentication
    /// credentials in KMIP requests, or the server to require requests to
    /// be authenticated with the given credentials.
    pub fn with_credentials(mut self, username: String, password: Option<String>) -> Self {
        self.auth = Some(Authentication::build(CredentialValue::UsernameAndPassword(
            Username(username),
            password.map(Password),
        )));
        self
    }

    /// Configure the [ClientServer] or server to reject messages above a certain size.
    pub fn with_max_message_size(mut self, max: i32) -> Self {
        self.max_messagesize = max;
        self
    }

    /// Build the configured [ClientServer] struct instance.
    pub fn build(self) -> ClientServer<T> {
        let auth = self.auth;
        let stream = Arc::new(Mutex::new(self.stream));
        let max_message_size = self.max_messagesize;
        let read_buf = vec![0u8; 8192];
        let write_buf = vec![MaybeUninit::uninit(); 8192];
        let connection_error_count = Default::default();

        ClientServer {
            auth,
            max_message_size,
            stream,
            read_buf,
            write_buf,
            connection_error_count,
        }
    }
}

/// There was a problem sending/receiving a KMIP request/response.
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Error {
    AuthenticationError,
    ConfigurationError(String),
    SerializeError(String),
    NetworkWriteError(String),
    NetworkReadError(String),
    DeserializeError {
        err: String,

        /// The KMIP TTLV wire bytes of the request related to the response
        /// that could not be deserialized.
        req: Box<[u8]>,

        /// The KMIP TTLV wire bytes of the response that could not be
        /// deserialized.
        res: Box<[u8]>,
    },
    ServerError(String),
    InternalError(String),
    ItemNotFound(String),
    UnexpectedData(String),
    Unknown(String),
}

impl Error {
    pub fn deserialize_error(err: String) -> Self {
        Self::DeserializeError {
            err,
            req: Default::default(),
            res: Default::default(),
        }
    }

    /// Is this a possibly transient problem with the connection to the server?
    pub fn is_connection_error(&self) -> bool {
        use Error::*;
        matches!(self, NetworkWriteError(_) | NetworkReadError(_))
    }
}

impl std::error::Error for Error {}

impl From<std::io::Error> for Error {
    fn from(err: std::io::Error) -> Self {
        Error::ServerError(format!("I/O error: {err}"))
    }
}

/// Format the error for user-facing output.
///
/// Tip: examples/hex_to_txt.rs can be used to render KMIP TTLV protocol wire
/// request/response bytes into a form that can be more easily understood.
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::AuthenticationError => f.write_str("Authentication error"),
            Error::ConfigurationError(e) => write!(f, "Configuration error: {}", e),
            Error::SerializeError(e) => write!(f, "Serialize error: {}", e),
            Error::NetworkWriteError(e) => write!(f, "Request send error: {}", e),
            Error::NetworkReadError(e) => write!(f, "Response read error: {}", e),
            Error::DeserializeError { err: e, req, res } => write!(
                f,
                "Deserialize error: {e}\nRequest: {}\nResponse: {}",
                hex::encode_upper(req),
                hex::encode_upper(res)
            ),
            Error::ServerError(e) => write!(f, "Server error: {e}"),
            Error::InternalError(e) => write!(f, "Internal error: {}", e),
            Error::ItemNotFound(e) => write!(f, "Item not found: {}", e),
            Error::Unknown(e) => write!(f, "Unknown error: {}", e),
            Error::UnexpectedData(data) => write!(f, "Unexpected data: {data}"),
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

/// Helper macro to avoid repetetive blocks of almost identical code
macro_rules! get_response_payload_for_type {
    // $batch_items: Vec<Result<response::BatchItem>> {
    ($batch_items:expr, $payload_type:path) => {
        // Process the successful response. It should have a single batch item.
        if $batch_items.is_empty() {
            return Err(Error::UnexpectedData(format!(
                "Expected response with a single successful {} batch item but response is empty",
                stringify!($payload_type),
            )));
        } else if $batch_items.len() != 1 {
            return Err(Error::UnexpectedData(format!(
                "Expected response with a single successful {} batch item but response has {} batch items",
                stringify!($payload_type),
                $batch_items.len(),
            )));
        } else {
            $batch_items.pop().unwrap().and_then(|batch_item| {
                if let Some($payload_type(payload)) = batch_item.payload {
                    Ok(payload)
                } else {
                    Err(Error::UnexpectedData(format!(
                        "Expected {} response payload but response has: {:?}",
                        stringify!($payload_type),
                        batch_item.payload
                    )))
                }
            })
        }
    };
}

/// A client for serializing KMIP and deserializing KMIP responses to/from an established read/write stream.
///
/// Use the [ClientServerBuilder] to build a [ClientServer] instance to work with.
#[derive(Debug)]
pub struct ClientServer<T: ReadWrite> {
    auth: Option<Authentication>,
    max_message_size: i32,
    stream: Arc<Mutex<T>>,
    read_buf: Vec<u8>,
    write_buf: Vec<MaybeUninit<u8>>,
    connection_error_count: Arc<AtomicUsize>,
}

//--- High level client interface

impl<T: ReadWrite> ClientServer<T> {
    /// Serialize a KMIP 1.0 [Query](https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581232) request.
    ///
    /// See also: [do_request()](Self::do_request())
    #[maybe_async::maybe_async]
    pub async fn query(&mut self) -> Result<QueryResponsePayload> {
        // Setup the request
        let wanted_info = vec![
            QueryFunction::QueryOperations,
            QueryFunction::QueryObjects,
            QueryFunction::QueryServerInformation,
        ];
        let request = RequestPayload::Query(wanted_info);

        // Execute the request and capture the response
        let mut response = self.do_request_payload(request).await?;

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
        &mut self,
        key_length: i32,
        private_key_name: String,
        public_key_name: String,
    ) -> Result<(String, String)> {
        // Setup the request
        let request = RequestPayload::CreateKeyPair(
            Some(CommonTemplateAttribute::new(vec![
                request::Attribute::CryptographicAlgorithm(CryptographicAlgorithm::RSA),
                request::Attribute::CryptographicLength(key_length),
            ])),
            Some(PrivateKeyTemplateAttribute::new(vec![
                request::Attribute::Name(private_key_name),
                request::Attribute::CryptographicUsageMask(CryptographicUsageMask::Sign),
            ])),
            Some(PublicKeyTemplateAttribute::new(vec![
                request::Attribute::Name(public_key_name),
                request::Attribute::CryptographicUsageMask(CryptographicUsageMask::Verify),
            ])),
        );

        // Execute the request and capture the response
        let mut response = self.do_request_payload(request).await?;

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
    pub async fn rng_retrieve(&mut self, num_bytes: i32) -> Result<RNGRetrieveResponsePayload> {
        let request = RequestPayload::RNGRetrieve(DataLength(num_bytes));

        // Execute the request and capture the response
        let mut response = self.do_request_payload(request).await?;

        // Process the successful response
        get_response_payload_for_type!(response, ResponsePayload::RNGRetrieve)
    }

    /// Serialize a KMIP 1.2 [Sign](https://docs.oasis-open.org/kmip/spec/v1.2/os/kmip-spec-v1.2-os.html#_Toc409613558)
    /// operation to sign the given bytes with the given private key ID.
    ///
    /// See also: [do_request()](Self::do_request())
    ///
    #[maybe_async::maybe_async]
    pub async fn sign(&mut self, private_key_id: &str, in_bytes: &[u8]) -> Result<SignResponsePayload> {
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
        let mut response = self.do_request_payload(request).await?;

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
    pub async fn activate_key(&mut self, private_key_id: &str) -> Result<()> {
        let request = RequestPayload::Activate(UniqueIdentifier(private_key_id.to_owned()).into());

        // Execute the request and capture the response
        let mut response = self.do_request_payload(request).await?;

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
    pub async fn revoke_key(&mut self, private_key_id: &str) -> Result<()> {
        let request = RequestPayload::Revoke(
            Some(UniqueIdentifier(private_key_id.to_owned())),
            RevocationReason(
                RevocationReasonCode::CessationOfOperation,
                Option::<RevocationMessage>::None,
            ),
            Option::<CompromiseOccurrenceDate>::None,
        );

        // Execute the request and capture the response
        let mut response = self.do_request_payload(request).await?;

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
    pub async fn destroy_key(&mut self, key_id: &str) -> Result<()> {
        let request = RequestPayload::Destroy(Some(UniqueIdentifier(key_id.to_owned())));

        // Execute the request and capture the response
        let mut response = self.do_request_payload(request).await?;

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
    pub async fn rename_key(&mut self, key_id: &str, new_name: String) -> Result<ModifyAttributeResponsePayload> {
        // Setup the request
        let request = RequestPayload::ModifyAttribute(
            Some(UniqueIdentifier(key_id.to_string())),
            request::Attribute::Name(new_name),
        );

        // Execute the request and capture the response
        let mut response = self.do_request_payload(request).await?;

        // Process the successful response
        get_response_payload_for_type!(response, ResponsePayload::ModifyAttribute)
    }

    /// Serialize a KMIP 1.0 [Get](http://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581218)
    /// operation to get the details of a given key ID.
    ///
    /// See also: [do_request()](Self::do_request())
    #[maybe_async::maybe_async]
    pub async fn get_key(&mut self, key_id: &str) -> Result<GetResponsePayload> {
        // Setup the request
        let request = RequestPayload::Get(
            Some(UniqueIdentifier(key_id.to_string())),
            Option::<KeyFormatType>::None,
            Option::<KeyCompressionType>::None,
            Option::<KeyWrappingSpecification>::None,
        );

        // Execute the request and capture the response
        let mut response = self.do_request_payload(request).await?;

        // Process the successful response
        get_response_payload_for_type!(response, ResponsePayload::Get)
    }
}

//--- Lower level client interface
//
// For sending requests and receiving responses.

impl<T: ReadWrite> ClientServer<T> {
    /// Write request bytes to the given stream and read, deserialize and
    /// sanity check the response.
    ///
    /// Note: Enforcing a timeout on this operation is the responsibility of
    /// the caller.
    #[maybe_async::maybe_async]
    pub async fn do_request(&mut self, request: RequestMessage) -> Result<Vec<Result<response::BatchItem>>> {
        trace!("Serializing request to KMIP wire bytes");
        let len = self.write_buf.len();
        assert!(len <= i32::MAX as usize);
        let mut len = len as i32;

        let mut stream = Self::get_mut_stream(&self.stream).await?;
        let mut formatter;

        // TODO: Enforce a timeout on sending the request?
        let request_bytes = loop {
            formatter = crate::ttlv::Formatter::new(&mut self.write_buf);
            if request.format(&mut formatter).is_ok() {
                let request_bytes = formatter.filled().as_flattened();
                Self::write_to_stream(&mut stream, &request_bytes).await?;
                break request_bytes;
            } else if len >= self.max_message_size {
                // Buffer is already at the maximum possible size.
                return Err(Error::SerializeError(format!(
                    "Message too large: {len} > {}",
                    self.max_message_size
                )));
            } else {
                // Retry with a larger buffer.
                len = i32::max(self.max_message_size, len.saturating_mul(2));
                self.write_buf.resize(len as usize, MaybeUninit::uninit());
            }
        };

        trace!("Waiting for a response from the server");
        let res = Self::read_message_from_stream(
            &mut stream,
            &mut self.read_buf,
            self.max_message_size,
            ResponseMessage::fast_scan,
        )
        .await?;
        trace!("KMIP server response received");
        drop(stream);

        Self::post_process_response(res).await.map_err(|mut err| {
            if let Error::DeserializeError { req, .. } = &mut err {
                *req = request_bytes.into();
            }
            err
        })
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
    #[maybe_async::maybe_async]
    pub async fn do_request_payload(&mut self, payload: RequestPayload) -> Result<Vec<Result<response::BatchItem>>> {
        self.do_request(payload_to_request(
            self.auth.clone(),
            Some(MaximumResponseSize(self.max_message_size)),
            payload,
        )?)
        .await
    }

    #[maybe_async::maybe_async]
    pub async fn do_request_batch(&mut self, batch_items: Vec<BatchItem>) -> Result<Vec<Result<response::BatchItem>>> {
        self.do_request(batch_items_to_request(
            self.auth.clone(),
            Some(MaximumResponseSize(self.max_message_size)),
            batch_items,
        )?)
        .await
        .inspect_err(|err| {
            if err.is_connection_error() {
                let _ = self.connection_error_count.fetch_add(1, Ordering::SeqCst);
            }
        })
    }
}

//--- Lower level server interface
//
// For receiving requests and sending responses.

impl<T: ReadWrite> ClientServer<T> {
    /// Receive a KMIP request from the network.
    ///
    /// Unlike do_request() and do_requests() this function only performs the
    /// receiving half of the message exchange as the caller has to inspect the
    /// received message and determinate an appropriate response.
    #[maybe_async::maybe_async]
    pub async fn receive_request(&mut self) -> Result<RequestMessage> {
        trace!("Acquiring stream lock");
        let mut lock = Self::get_mut_stream(&self.stream).await?;
        let stream = lock.deref_mut();

        trace!("Waiting for a request from the client");
        let req = Self::read_message_from_stream(
            stream,
            &mut self.read_buf,
            self.max_message_size,
            RequestMessage::fast_scan,
        )
        .await?;
        drop(lock);

        // Check that the request is correctly authenticated.
        if req.header().authentication() != self.auth.as_ref() {
            return Err(Error::AuthenticationError);
        }

        Ok(req)
    }

    #[maybe_async::maybe_async]
    pub async fn send_response(&mut self, response: ResponseMessage) -> Result<()> {
        trace!("Serializing response to KMIP wire bytes");
        let len = self.write_buf.len();
        assert!(len <= i32::MAX as usize);
        let mut len = len as i32;

        // TODO: Enforce a timeout on sending the response?
        loop {
            let mut formatter = crate::ttlv::Formatter::new(&mut self.write_buf);
            if response.format(&mut formatter).is_ok() {
                let response_bytes = formatter.filled().as_flattened();
                let mut stream = Self::get_mut_stream(&self.stream).await?;
                trace!("Writing {} response bytes to the server", response_bytes.len());
                return stream.write_all(response_bytes).await.map_err(|err| {
                    Error::NetworkWriteError(format!("Failed to write KMIP response bytes to the stream: {err}"))
                });
            } else if len >= self.max_message_size {
                // Buffer is already at the maximum possible size.
                return Err(Error::SerializeError(format!(
                    "Message too large: {len} > {}",
                    self.max_message_size
                )));
            } else {
                // Retry with a larger buffer.
                len = i32::max(self.max_message_size, len.saturating_mul(2));
                self.write_buf.resize(len as usize, MaybeUninit::uninit());
            }
        }
    }

    #[maybe_async::maybe_async]
    pub async fn send_response_payload(
        &mut self,
        result_status: ResultStatus,
        result_reason: Option<ResultReason>,
        result_message: Option<String>,
        payload: Option<ResponsePayload>,
    ) -> Result<()> {
        self.send_response(payload_to_response(
            result_status,
            result_reason,
            result_message,
            payload,
        )?)
        .await
    }

    #[maybe_async::maybe_async]
    pub async fn send_response_batch(&mut self, batch_items: Vec<response::BatchItem>) -> Result<()> {
        self.send_response(batch_items_to_response(batch_items)?).await
    }
}

impl<T: ReadWrite> ClientServer<T> {
    #[cfg(feature = "tokio")]
    async fn get_mut_stream(stream: &Mutex<T>) -> Result<impl DerefMut<Target = T> + '_> {
        Ok(stream.lock().await)
    }

    #[cfg(not(feature = "tokio"))]
    fn get_mut_stream(stream: &Mutex<T>) -> Result<impl DerefMut<Target = T> + '_> {
        Ok(stream.lock()?)
    }

    #[maybe_async::maybe_async]
    async fn post_process_response(mut res: ResponseMessage) -> Result<Vec<Result<response::BatchItem>>> {
        if res.header.batch_count >= 1 && res.batch_items.len() >= 1 {
            let res = res
                .batch_items
                .drain(..)
                .map(|item| match item.result_status {
                    ResultStatus::OperationFailed => {
                        let reason = item.result_message.unwrap_or_default();
                        let operation = item
                            .operation
                            .map(|op| op.to_string())
                            .unwrap_or_else(|| "Unknown".to_string());
                        let err = format!("Operation {operation} failed: {reason}");
                        if matches!(item.result_reason, Some(ResultReason::ItemNotFound)) {
                            Err(Error::ItemNotFound(err))
                        } else {
                            Err(Error::ServerError(err))
                        }
                    }
                    ResultStatus::OperationPending => Err(Error::InternalError(
                        "Result status 'operation pending' is not supported".into(),
                    )),
                    ResultStatus::OperationUndone => Err(Error::InternalError(
                        "Result status 'operation undone' is not supported".into(),
                    )),
                    ResultStatus::Success => Ok(item),
                })
                .collect::<Vec<_>>();
            Ok(res)
        } else {
            let err = format!(
                "Expected at least one batch item in response but received {}",
                res.batch_items.len()
            );
            Err(Error::ServerError(err))
        }
    }

    #[maybe_async::maybe_async]
    async fn read_message_from_stream<F, R>(stream: &mut T, read_buf: &mut Vec<u8>, limit: i32, op: F) -> Result<R>
    where
        F: Fn(&mut FastScanner) -> std::result::Result<R, FastScanError>,
    {
        trace!("Awaiting KMIP server response");
        read_buf.clear();
        loop {
            // Try reading from the buffer.
            let available = read_buf.len();
            let available_rounded = read_buf.len() - available % 8;
            let ttlv_bytes = &read_buf[..available_rounded];
            let mut scanner = FastScanner::new(ttlv_bytes).expect("the provided buffer has a multiple of 8 bytes");
            match scanner.have_next() {
                Ok(()) => {
                    trace!(
                        "Received {available_rounded} bytes from the server: {}",
                        hex::encode_upper(ttlv_bytes)
                    );
                    // A complete TTLV element is available. Try to parse it.
                    return op(&mut scanner).map_err(|err| Error::DeserializeError {
                        err: err.to_string(),
                        req: Default::default(), // do_requests() will populate this
                        res: read_buf.clone().into(),
                    });
                }
                Err(Some(n)) => {
                    // n more bytes are needed to complete the current message
                    // in the buffer.
                    Self::enlarge_read_buffer_if_needed(read_buf, n as usize, limit)?;
                }
                Err(None) => {
                    // More bytes are needed to complete the current message
                    // in the buffer but we don't know how many so fetch at
                    // least 8 bytes (as TTLV messages are always a multiple
                    // of 8 bytes and thus FastScanner only accepts multiples
                    // of 8 bytes).
                    Self::enlarge_read_buffer_if_needed(read_buf, 8, limit)?;
                }
            }

            // The buffer did not contain enough data, try to read more.

            let write_start_idx = available;
            let updated_buffer_len = read_buf.len();
            let bytes_to_write_into = &mut read_buf[write_start_idx..updated_buffer_len];
            let read_byte_count = Self::read_from_stream(stream, bytes_to_write_into).await?;

            // Don't pass any extra zeroes in the buffer to the TTLV parser,
            // only give it bytes that we actually read.
            read_buf.truncate(write_start_idx + read_byte_count);
        }
    }

    #[maybe_async::maybe_async]
    async fn write_to_stream(stream: &mut T, bytes: &[u8]) -> Result<()> {
        trace!(
            "Writing {} bytes to the server: {}",
            bytes.len(),
            hex::encode_upper(bytes)
        );
        if let Err(err) = stream.write_all(&bytes).await {
            return Err(Error::NetworkWriteError(err.to_string()));
        }

        Ok(())
    }

    fn enlarge_read_buffer_if_needed(read_buf: &mut Vec<u8>, extra_bytes_needed: usize, limit: i32) -> Result<()> {
        // If the buffer is too small, try to expand it.
        let wanted_buf_size = read_buf.len() + extra_bytes_needed;
        if wanted_buf_size > read_buf.capacity() {
            if wanted_buf_size > limit as usize {
                return Err(Error::NetworkReadError(format!(
                    "Response too large: {wanted_buf_size} bytes > {limit} bytes"
                )));
            }
        }
        read_buf.resize(wanted_buf_size, 0);
        Ok(())
    }

    #[maybe_async::maybe_async]
    async fn read_from_stream(stream: &mut T, buffer: &mut [u8]) -> Result<usize> {
        trace!("Reading upto {} bytes from the KMIP server", buffer.len());
        match stream.read(buffer).await {
            // The client has closed the connection.
            Ok(0) => Err(Error::NetworkReadError(
                "Client closed connection with a partial request received".into(),
            )),

            // Some data was received successfully.
            Ok(amt) => {
                trace!("Read {amt} bytes from the KMIP server");
                Ok(amt)
            }

            // An unexpected error has occurred.
            Err(err) => {
                // TODO: Categorize the various std::io::ErrorKinds into fatal and
                // non-fatal variants and only abort on fatal errors.
                Err(Error::NetworkReadError(format!("I/O error: {err}")))
            }
        }
    }
}

impl<T: ReadWrite> Clone for ClientServer<T> {
    fn clone(&self) -> Self {
        Self {
            auth: self.auth.clone(),
            max_message_size: self.max_message_size.clone(),
            stream: self.stream.clone(),
            connection_error_count: self.connection_error_count.clone(),
            read_buf: vec![0u8; 8192],
            write_buf: vec![MaybeUninit::uninit(); 8192],
        }
    }
}

impl<T: ReadWrite> ClientServer<T> {
    /// Get the count of connection errors experienced by this ClientServer.
    pub fn connection_error_count(&self) -> usize {
        self.connection_error_count.load(Ordering::SeqCst)
    }
}

//------------ Tests ---------------------------------------------------------
//
#[cfg(all(test, feature = "sync"))]
mod test {
    use std::{
        io::{Cursor, Read, Write},
        net::TcpStream,
    };

    #[cfg(any(feature = "tls-with-openssl", feature = "tls-with-openssl-vendored"))]
    use openssl::ssl::{SslConnector, SslFiletype, SslMethod, SslVerifyMode};

    use crate::{
        client::client::ClientServerBuilder,
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

        let mut client = ClientServerBuilder::new(&mut tls).build();

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
}

pub fn batch_items_to_request(
    auth: Option<Authentication>,
    max_response_size: Option<MaximumResponseSize>,
    batch_items: Vec<request::BatchItem>,
) -> Result<RequestMessage> {
    if batch_items.is_empty() {
        return Err(Error::SerializeError("Cannot serialize an empty batch".to_string()));
    }

    if batch_items.len() >= i32::MAX as usize {
        return Err(Error::SerializeError(format!(
            "Too many batch items: {} > {}",
            batch_items.len(),
            i32::MAX
        )));
    }

    // Construct the request.
    let max_protocol_version = batch_items
        .iter()
        .map(|r| r.request_payload().protocol_version())
        .max()
        .unwrap();

    Ok(RequestMessage(
        RequestHeader(
            max_protocol_version,
            max_response_size,
            auth,
            request::BatchCount(batch_items.len().try_into().unwrap()),
        ),
        batch_items,
    ))
}

pub fn batch_items_to_response(batch_items: Vec<response::BatchItem>) -> Result<ResponseMessage> {
    if batch_items.len() >= i32::MAX as usize {
        return Err(Error::SerializeError(format!(
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

pub fn payload_to_request(
    auth: Option<Authentication>,
    max_response_size: Option<MaximumResponseSize>,
    payload: RequestPayload,
) -> Result<RequestMessage> {
    let batch_items = vec![request::BatchItem(payload.operation(), None, payload)];
    batch_items_to_request(auth, max_response_size, batch_items)
}

pub fn payload_to_response(
    result_status: ResultStatus,
    result_reason: Option<ResultReason>,
    result_message: Option<String>,
    payload: Option<ResponsePayload>,
) -> Result<ResponseMessage> {
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
