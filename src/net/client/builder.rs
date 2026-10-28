use std::{mem::MaybeUninit, sync::Arc};

#[cfg(feature = "tokio")]
use tokio::sync::Mutex;

#[cfg(not(feature = "tokio"))]
use std::sync::Mutex;

use crate::{
    net::client::Client,
    types::{
        request::{Authentication, CredentialValue, Password, Username},
        traits::ReadWrite,
    },
};

/// Use this builder to construct a [Client] struct.
#[derive(Debug)]
pub struct ClientBuilder<T: ReadWrite> {
    stream: T,
    auth: Option<Authentication>,
    max_messagesize: i32,
}

impl<T: ReadWrite> ClientBuilder<T> {
    /// Build a [Client] struct that will read/write from/to the given stream.
    ///
    /// Creates a [ClientBuilder] which can be used to create a [Client] which
    /// will read/write from/to the given stream. The stream is expected to be
    /// a type which can read from and write to an established TCP connection
    /// to the KMIP server. In production the stream should also perform TLS
    /// de/encryption on the data read from/written to the stream.
    ///
    /// The `stream` argument must implement the read and write traits which
    /// the [Client] will use to read/write from/to the stream.
    pub fn new(stream: T) -> Self {
        Self {
            stream,
            auth: None,
            max_messagesize: i32::MAX,
        }
    }

    /// Configure the [Client] to include username/password authentication
    /// credentials in KMIP requests, or the server to require requests to
    /// be authenticated with the given credentials.
    pub fn with_credentials(mut self, username: String, password: Option<String>) -> Self {
        self.auth = Some(Authentication::build(CredentialValue::UsernameAndPassword(
            Username(username),
            password.map(Password),
        )));
        self
    }

    /// Configure the [Client] or server to reject messages above a certain size.
    pub fn with_max_message_size(mut self, max: i32) -> Self {
        self.max_messagesize = max;
        self
    }

    /// Build the configured [Client] struct instance.
    pub fn build(self) -> Client<T> {
        let auth = self.auth;
        let stream = Arc::new(Mutex::new(self.stream));
        let max_message_size = self.max_messagesize;
        let read_buf = vec![0u8; 8192];
        let write_buf = vec![MaybeUninit::uninit(); 8192];
        let connection_error_count = Default::default();

        Client {
            auth,
            max_message_size,
            stream,
            read_buf,
            write_buf,
            connection_error_count,
        }
    }
}
