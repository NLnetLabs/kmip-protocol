// See: writing a library that can be reused across many runtimes (https://github.com/rust-lang/wg-async-foundations/issues/45)

mod client;

#[cfg(any(
    feature = "tls-with-async-tls",
    feature = "tls-with-rustls",
    feature = "tls-with-tokio-rustls"
))]
mod rustls_common;

#[cfg(any(
    feature = "tls-with-openssl",
    feature = "tls-with-async-tls",
    feature = "tls-with-rustls",
    feature = "tls-with-tokio-rustls",
))]
const SSLKEYLOGFILE_ENV_VAR_NAME: &'static str = "SSLKEYLOGFILE";

pub mod config;

pub use client::{Client, ClientBuilder, Error, ReadWrite, Result};

#[cfg(feature = "tls-with-async-tls")]
pub mod async_tls;

#[cfg(feature = "tls-with-openssl")]
pub mod openssl;

#[cfg(feature = "tls-with-rustls")]
pub mod rustls;

#[cfg(feature = "tls-with-tokio-native-tls")]
pub mod tokio_native_tls;

#[cfg(feature = "tls-with-tokio-rustls")]
pub mod tokio_rustls;
