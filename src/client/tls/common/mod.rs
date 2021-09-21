#[cfg(any(
    feature = "tls-with-async-tls",
    feature = "tls-with-rustls",
    feature = "tls-with-tokio-rustls"
))]
pub(crate) mod rustls;
pub(crate) mod util;

#[cfg(any(
    feature = "tls-with-openssl",
    feature = "tls-with-openssl-vendored",
    feature = "tls-with-async-tls",
    feature = "tls-with-rustls",
    feature = "tls-with-tokio-rustls",
))]
pub(crate) const SSLKEYLOGFILE_ENV_VAR_NAME: &'static str = "SSLKEYLOGFILE";
