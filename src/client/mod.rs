//! For sending KMIP requests and receiving responses.

mod client;

#[doc(hidden)]
pub mod config;

pub mod tls;

pub use client::{Client, ClientBuilder, Error, Result};

#[doc(inline)]
pub use config::{ClientCertificate, ConnectionSettings};
