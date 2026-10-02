//! For sending KMIP requests and receiving responses.

#[allow(clippy::module_inception)]
mod client;

#[cfg(feature = "tls")]
pub mod tls;

#[cfg(feature = "sync-pool")]
pub mod sync_pool;

#[cfg(feature = "async-pool")]
pub mod async_pool;

pub mod pool {
    cfg_if::cfg_if! {
        if #[cfg(feature = "sync-pool")] {
            pub use super::sync_pool::*;
        } else if #[cfg(feature = "async-pool")] {
            pub use super::async_pool::*;
        }
    }
}

pub use client::{
    Client,
    builder::ClientBuilder,
    error::{NetError, NetResult},
    util::{batch_items_to_request, payload_to_request},
};

mod config;

pub use config::{ClientCertificate, ConnectionSettings};
