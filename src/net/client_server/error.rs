use std::sync::PoisonError;

/// There was a problem sending/receiving a KMIP request/response.
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NetError {
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
        use NetError::*;
        matches!(self, NetworkWriteError(_) | NetworkReadError(_))
    }
}

impl std::error::Error for NetError {}

impl From<std::io::Error> for NetError {
    fn from(err: std::io::Error) -> Self {
        NetError::ServerError(format!("I/O error: {err}"))
    }
}

/// Format the error for user-facing output.
///
/// Note: Some error message variants carry request and response byte data.
/// This data isn't of use to an end user directly, rather it is more suited
/// to be logged and reported to someone with the means and knowledge to
/// interpret those KMIP protocol bytes. As such this Display impl does
/// not include that data in the output it produces, that data should be
/// deliberately handled by the calling code and provided in a manner suitable
/// to the application for providing to a support engineer.
///
/// Tip: examples/hex_to_txt.rs can be used to render KMIP TTLV protocol wire
/// request/response bytes into a form that can be more easily understood.
impl std::fmt::Display for NetError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NetError::AuthenticationError => f.write_str("Authentication error"),
            NetError::ConfigurationError(e) => f.write_fmt(format_args!("Configuration error: {}", e)),
            NetError::SerializeError(e) => f.write_fmt(format_args!("Serialize error: {}", e)),
            NetError::NetworkWriteError(e) => f.write_fmt(format_args!("Request send error: {}", e)),
            NetError::NetworkReadError(e) => f.write_fmt(format_args!("Response read error: {}", e)),
            NetError::DeserializeError { err: e, req, res } => f.write_fmt(format_args!(
                "Deserialize error: {e}\nRequest: {}\nResponse: {}",
                hex::encode_upper(req),
                hex::encode_upper(res)
            )),
            NetError::ServerError(e) => f.write_fmt(format_args!("Server error: {e}")),
            NetError::InternalError(e) => f.write_fmt(format_args!("Internal error: {}", e)),
            NetError::ItemNotFound(e) => f.write_fmt(format_args!("Item not found: {}", e)),
            NetError::Unknown(e) => f.write_fmt(format_args!("Unknown error: {}", e)),
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
