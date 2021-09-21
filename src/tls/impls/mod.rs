pub mod common;

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
