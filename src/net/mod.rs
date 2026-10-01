//! For sending KMIP requests and receiving responses.

mod client;
mod common;
mod server;

#[cfg(feature = "tls")]
pub mod tls;

pub use common::error::{NetError, NetResult};

pub use client::{
    Client,
    builder::ClientBuilder,
    util::{batch_items_to_request, payload_to_request},
};

#[cfg(feature = "sync-pool")]
pub mod sync_pool;

#[cfg(feature = "async-pool")]
pub mod async_pool;

pub use server::{
    Server,
    builder::ServerBuilder,
    util::{batch_items_to_response, payload_to_response},
};

mod config;

pub use config::{ClientCertificate, ConnectionSettings};
