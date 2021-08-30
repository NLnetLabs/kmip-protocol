//! KMIP protocol library
//!
//! This library provides strongly-typed interfaces for a subset of the [Oasis Key Management Interoperability Protocol]
//! aka KMIP.
//!
//! [Oasis Key Management Interoperability Protocol]: http://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html
//!
//! # Usage
//!
//! Add the following to your `Cargo.toml`:
//!
//! ```toml
//! [dependencies]
//! kmip-protocol = "0.1.0"
//! ```
//!
//! This crate does not yet offer a TCP+TLS client for you to use. As such you will need to establish a connection
//! yourself. Once the connection is established the [Client] struct can be used to send serialize requests to the KMIP
//! server and to deserialize the response. The code might then look something like this:
//!
//! ```ignore
//! let tls_client = create_tls_client(&opt)?;
//! let tcp_stream = TcpStream::connect(format!("{}:{}", opt.host, opt.port))?;
//! let mut tls_stream = tls_client.connect(&opt.host, tcp_stream)?;
//! let mut client = create_kmip_client(&mut tls_stream, opt, password)?;
//!
//! let bit_len = 2048;
//! let private_key_name = "priv".to_string();
//! let public_key_name = "pub".to_string();
//! let some_bytes_to_sign = [1u8, 2u8, 3u8, 4u8, 5u8];
//!
//! if let Ok(res) = client.create_rsa_key_pair(bit_len, private_key_name, public_key_name) {
//!     let (private_key_id, public_key_id) = res;
//!     if client.activate_key(&private_key_id).is_ok() {
//!         if let Ok(payload) = client.sign(&private_key_id, &some_bytes_to_sign) {
//!             // ...
//!         }
//!         client.revoke_key(&private_key_id).ok();
//!     }
//!     client.destroy_key(&public_key_id).ok();
//!     client.destroy_key(&private_key_id).ok();
//! }
//! ```
//!
//! For more details on how to create the TLS connection and instantiate the client to use it see the example code in
//! the repository at `examples/cli-tool.rs` and the test cases in `client.rs`.
//!
//! # Advanced usage
//!
//! If none of the helper functions offered by the [Client] struct fit your needs you can use [Client::do_request]
//! directly to handle the request construction and response parsing yourself, for example:
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
