//! For sending KMIP requests and receiving responses.

#[allow(clippy::module_inception)]
mod client_server;

#[cfg(feature = "tls")]
pub mod tls;

pub use client_server::{
    ClientServer,
    builder::ClientServerBuilder,
    error::{NetError, NetResult},
    util::{batch_items_to_request, batch_items_to_response, payload_to_request, payload_to_response},
};

mod config;

pub use config::{ClientCertificate, ConnectionSettings};
