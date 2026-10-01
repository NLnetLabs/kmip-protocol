use std::sync::PoisonError;

/// There was a problem sending/receiving a KMIP request/response.
#[non_exhaustive]
#[derive(Debug)]
pub enum NetError {
    AuthenticationError,
    ConfigurationError(String),
    SerializeError(String),
    IoError(std::io::Error),
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

impl NetError {
    pub fn deserialize_error(err: String) -> Self {
        Self::DeserializeError {
            err,
            req: Default::default(),
            res: Default::default(),
        }
    }

    /// Is this a possibly transient problem with the connection to the server?
    pub fn is_connection_error(&self) -> bool {
        matches!(self, Self::IoError(_))
    }
}

impl std::error::Error for NetError {}

impl From<std::io::Error> for NetError {
    fn from(err: std::io::Error) -> Self {
        NetError::IoError(err)
    }
}

/// Format the error for user-facing output.
///
/// Tip: examples/hex_to_txt.rs can be used to render KMIP TTLV protocol wire
/// request/response bytes into a form that can be more easily understood.
impl std::fmt::Display for NetError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NetError::AuthenticationError => f.write_str("Authentication error"),
            NetError::ConfigurationError(err) => write!(f, "Configuration error: {err}"),
            NetError::SerializeError(err) => write!(f, "Serialize error: {err}"),
            NetError::IoError(err) => write!(f, "I/O error: {err}"),
            NetError::DeserializeError { err, req, res } => write!(
                f,
                "Deserialize error: {err}\nRequest: {}\nResponse: {}",
                hex::encode_upper(req),
                hex::encode_upper(res)
            ),
            NetError::ServerError(err) => write!(f, "Server error: {err}"),
            NetError::InternalError(err) => write!(f, "Internal error: {err}"),
            NetError::ItemNotFound(err) => write!(f, "Item not found: {err}"),
            NetError::Unknown(err) => write!(f, "Unknown error: {err}"),
            NetError::UnexpectedData(data) => write!(f, "Unexpected data: {data}"),
        }
    }
}

/// The successful or failed outcome resulting from sending a request to a KMIP server.
pub type NetResult<T> = std::result::Result<T, NetError>;

impl<T> From<PoisonError<T>> for NetError {
    fn from(err: PoisonError<T>) -> Self {
        NetError::InternalError(err.to_string())
    }
}
