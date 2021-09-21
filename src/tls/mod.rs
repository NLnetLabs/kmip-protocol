#[cfg(feature = "tls-with-async-tls")]
pub mod async_tls;

#[cfg(feature = "tls-with-openssl")]
pub mod openssl;

#[cfg(feature = "tls-with-tokio-native-tls")]
pub mod tokio_native_tls;

mod client;
pub mod config;

pub use client::{Client, ClientBuilder, Error, ReadWrite, Result};

#[cfg(any(feature = "tls-with-openssl", feature = "tls-with-async-tls"))]
const SSLKEYLOGFILE_ENV_VAR_NAME: &'static str = "SSLKEYLOGFILE";
