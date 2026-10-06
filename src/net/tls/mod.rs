//! TCP+TLS client "plugins" for various (a)sync TLS implementations.
//!
//! This module offers the following TCP+TLS "plugins" for use with the [Client] interface.
//!
//! Every "plugin" can be used by passing a [ConnectionSettings] instance to it:
//!
//! ```ignore
//! let client = kmip_protocol::client::tls::<MODULE>::connect(&settings)?;
//! ```
//!
//! This will cause a TCP+TLS connection to be established with the server defined by the settings, if possible.
//!
//! For more control you can supply your own `TcpStream` factory. For example you can use this to create a socket using
//! the [socket2] crate which allows you to tune the behaviour of the operating system networking stack specific to
//! your use case. To supply a `TcpStream` factory use this function instead:
//!
//! ```ignore
//! let client = kmip_protocol::client::tls::<MODULE>::connect_with_tcpstream_factory(&settings, factory_func)?;
//! ```
//!
//! The factory function must conform to this signature:
//!
//! ```ignore
//! Fn(&SocketAddr, &ConnectionSettings) -> Result<TcpStream>
//! ```
//!
//! Note: You do not need to use a factory function to set timeouts as these are already set by the `connect` functions.
//! For `async` connections the initial connection timeout is implemented as an `async` timeout around the connection
//! attempt. For `sync` cn
//!
//! [ConnectionSettings]: crate::net::ConnectionSettings
//! [socket2]: https://crates.io/crates/socket2/
//!
//! # Enabling a plugin
//!
//! To use the plugin it must also be enabled using the correct set of Cargo feature flags. The table below shows the
//! settings required to use each "plugin".
//!
//! | `<MODULE>`         |  Cargo.toml `kmip_protocol` Dependency Settings                       | Async Runtime | Crates.io                                         | Notes                                      |
//! |--------------------|----------------------------------------------------------------------|---------------|---------------------------------------------------|--------------------------------------------|
//! | `openssl`          | `features = ["tls-with-openssl"]`                                    | None          | [view](https://crates.io/crates/openssl)          | Synchronous, uses host O/S OpenSSL         |
//! | `openssl`          | `features = ["tls-with-openssl-vendored"]`                           | None          | [view](https://crates.io/crates/openssl)          | Synchronous, uses compiled in OpenSSL      |
//! | `rustls`           | `features = ["tls-with-rustls"]`                                     | None          | [view](https://crates.io/crates/rustls)           | Pure Rust, strict                          |
//! | `tokio_native_tls` | `default-features = false, features = ["tls-with-tokio-native-tls"]` | [Tokio]       | [view](https://crates.io/crates/tokio-native-tls) | Uses host O/S specific native TLS          |
//! | `tokio_rustls`     | `default-features = false, features = ["tls-with-tokio-rustls"]`     | [Tokio]       | [view](https://crates.io/crates/tokio-rustls)     | Powered by Rustls                          |
//!
//! [Client]: crate::net::Client
//! [Tokio]: https://crates.io/crates/tokio
//!
//! # Disabling default features
//!
//! To use a plugin that require an async runtime you must disable the default-features. This is because this
//! crate uses the [Maybe-Async] procedural macro to support both sync and async implementations with minimal code
//! duplication, but that also means that sync and async implementations cannot both be compiled at the same time.
//!
//! [Maybe-Async]: https://crates.io/crates/maybe-async
//!
//! # Using the async API
//!
//! The async API is identical to that of the sync API, you just have to call it from within a `sync` function and
//! remember to call `.await` when invoking the API.
//!
//! Sync plugin usage:
//!
//! ```ignore
//! fn some_function() -> ... {
//!      let client = kmip_protocol::client::tls::rustls::connect(settings)?;
//!      client.create_rsa_key_pair(2048, "pubkey".into(), "privkey".into())?;
//! }
//! ```
//!
//! Compare that with async plugin usage:
//!
//! ```ignore
//! async fn some_function() -> ... {
//!      let client = kmip_protocol::client::tls::tokio_rustls::connect(settings)?;
//!      client.create_rsa_key_pair(2048, "pubkey".into(), "privkey".into()).await?;
//! }
//! ```

#[doc(hidden)]
pub mod common;

#[cfg(any(feature = "tls-with-openssl", feature = "tls-with-openssl-vendored"))]
mod openssl;
#[cfg(any(feature = "tls-with-openssl", feature = "tls-with-openssl-vendored"))]
use openssl as backend;

#[cfg(feature = "tls-with-rustls")]
mod rustls;
#[cfg(feature = "tls-with-rustls")]
use rustls as backend;

#[cfg(feature = "tls-with-tokio-native-tls")]
mod tokio_native_tls;
#[cfg(feature = "tls-with-tokio-native-tls")]
use tokio_native_tls as backend;

#[cfg(feature = "tls-with-tokio-rustls")]
mod tokio_rustls;
#[cfg(feature = "tls-with-tokio-rustls")]
use tokio_rustls as backend;

pub use backend::{TlsClient, connect, connect_with_tcpstream_factory};

/// A provider of KMIP client instances connected to a specific server.
///
/// This trait provides access to ready to use [`backend::Client`] instances
/// connected via TCP+TLS to a particular KMIP server.
///
/// Whether or not the connection comes from a pool of already established
/// long lived connections or is established on use is determined by the
/// implementation.
#[maybe_async::maybe_async]
pub trait ConnectionProvider: std::fmt::Debug + Clone {
    /// If possible, obtain a TCP+TLS connection to the KMIP server.
    ///
    /// The connection may be an existing connection or a new connection.
    async fn get(&self) -> Result<TlsClient, String>;

    /// Returns a value that identifies which KMIP server is connected to.
    ///
    /// The value should be meaningful if displayed to an end user.
    ///
    /// Two different connections to the same KMIP server should return the
    /// same value.
    ///
    /// The return value should not be relied upon to have any particular
    /// structure.
    fn server_id(&self) -> &str;
}

#[maybe_async::maybe_async]
impl ConnectionProvider for TlsClient {
    async fn get(&self) -> Result<TlsClient, String> {
        Ok(self.clone())
    }

    fn server_id(&self) -> &str {
        self.server_id()
    }
}
