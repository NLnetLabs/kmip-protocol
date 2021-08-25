//! KMIP protocol library
//!
//! This library provides strongly-typed interfaces for a subset of the [Oasis Key Management Interoperability Protocol]
//! aka KMIP.
//!
//! [Oasis Key Management Interoperability Protocol]: http://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html
//!
//! To use this library add the following to your `Cargo.toml`:
//!
//! ```toml
//! [dependencies]
//! kmip = "0.1.0"
//! ```
//!
//! # Usage
//!
//! For the details of how to create a TLS connection and instantiate the client to use it see the example code in the
//! repository at `examples/cli-tool.rs`.
//!
//! ```ignore
//! let tls_client = create_tls_client(&opt)?;
//! let tcp_stream = TcpStream::connect(format!("{}:{}", opt.host, opt.port))?;
//! let mut tls_stream = tls_client.connect(&opt.host, tcp_stream)?;
//! let mut client = create_kmip_client(&mut tls_stream, opt, password)?;
//!
//! if let Ok((private_key_id, public_key_id)) = client.create_rsa_key_pair(2048, "priv".into(), "pub".into()) {
//!     if client.activate_key(&private_key_id).is_ok() {
//!         if let Ok(payload) = client.sign(&private_key_id, &[1u8, 2u8, 3u8, 4u8, 5u8]) {
//!             // ...
//!         }
//!         client.revoke_key(&private_key_id).ok();
//!     }
//!     client.destroy_key(&public_key_id).ok();
//!     client.destroy_key(&private_key_id).ok();
//! }
//! ```
//!
//! # Advanced usage
//!
//! If none of the helper functions on the [Client] fit your needs you can use [Client::do_request] directly to handle
//! the request construction and response parsing yourself, for example:
//!
//! ```ignore
//! let mut client = ClientBuilder::new(&mut stream).configure();
//!
//! let result = client
//!     .do_request(RequestPayload::Query(vec![QueryFunction::QueryOperations]))
//!     .unwrap();
//!
//! if let ResponsePayload::Query(payload) = result {
//!     dbg!(payload);
//! } else {
//!     panic!("Expected query response!");
//! }
//! ```
pub mod auth;
pub mod client;
pub mod request;
pub mod response;
pub mod types;

#[cfg(test)]
mod tests;

pub use client::{Client, ClientBuilder};
pub use kmip_ttlv::Config;
