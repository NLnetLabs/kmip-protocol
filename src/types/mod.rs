//! Rust type definitions for `kmip-ttlv` based (de)serializing of KMIP message objects.
//!
//! These types are used when constructing requests to be sent to, and processing responses received from, a KMIP
//! server. The [Client](crate::Client) struct composes the request types into entire KMIP request message type trees for
//! serialization into the binary TTLV format and uses the response types to deserialize the binary KMIP response
//! format into rich Rust types.
//!
//! The attributes on the Rust types are used by the `kmip-ttlv` crate to guide the (de)serialization correctly to/from
//! the KMIP binary TTLV format.
pub mod common;
pub mod request;
pub mod response;
pub mod traits;
