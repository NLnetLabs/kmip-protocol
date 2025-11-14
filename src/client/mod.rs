//! For sending KMIP requests and receiving responses.

mod client;

#[cfg(feature = "tls")]
mod tls;

#[cfg(feature = "sync-pool")]
mod sync_pool;

#[cfg(feature = "async-pool")]
mod async_pool;

#[doc(hidden)]
pub mod config;

pub mod pool {
    cfg_if::cfg_if! {
        if #[cfg(feature = "sync-pool")] {
            pub use super::sync_pool::*;
        } else if #[cfg(feature = "async-pool")] {
            pub use super::async_pool::*;
        }
    }
}

pub use client::{Client, ClientBuilder, Error, Result};

#[doc(inline)]
pub use config::{ClientCertificate, ConnectionSettings};
