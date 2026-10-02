//! For sending KMIP requests and receiving responses.

#[allow(clippy::module_inception)]
mod client;

#[cfg(feature = "tls")]
pub mod tls;

pub use client::{
    Client,
    builder::ClientBuilder,
    error::{NetError, NetResult},
    util::{batch_items_to_request, payload_to_request},
};

mod config;

pub use config::{ClientCertificate, ConnectionSettings};
