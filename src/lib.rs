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
//! the repository at `examples/demo/` and the test cases in `src/client.rs`.
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
//!
//! # KMIP Operations Supported
//!
//! _Note: Supported operations may lack support for some attribute or managed object types. Vendor specific extensions are ignored._
//!
//! | KMIP Version | Operation | Support |
//! |---|---|---|
//! | 1.0 | Create               | &check; |
//! | 1.0 | Create Key Pair      | &check; _(lacks response public/private key attribute lists support)_ |
//! | 1.0 | Register             | &check; _(only supports a subset of managed object types at present)_ |
//! | 1.0 | Re-key               |  |
//! | 1.1 | Re-key Key Pair      |  |
//! | 1.0 | Derive Key           |  |
//! | 1.0 | Certify              |  |
//! | 1.0 | Re-certify           |  |
//! | 1.0 | Locate               | &check; _(lacks Maximum Items and Storage Status Mask support)_ |
//! | 1.0 | Check                |  |
//! | 1.0 | Get                  | &check; _(lacks Key Wrapping Specification, TransparentXXX, SplitKey, Template, SecretData and OpaqueObject support)_ |
//! | 1.0 | Get Attributes       | &check; _(lacks Big Integer and Interval support)_ |
//! | 1.0 | Get Attribute List   | &check; |
//! | 1.0 | Add Attribute        | &check; _(lacks Big Integer and Interval support)_ |
//! | 1.0 | Modify Attribute     | &check; _(lacks Big Integer and Interval support)_ |
//! | 1.0 | Delete Attribute     | &check; |
//! | 1.0 | Obtain Lease         |  |
//! | 1.0 | Get Usage Allocation |  |
//! | 1.0 | Activate             | &check; |
//! | 1.0 | Revoke               | &check; |
//! | 1.0 | Destroy              | &check; |
//! | 1.0 | Archive              |  |
//! | 1.0 | Recover              |  |
//! | 1.0 | Validate             |  |
//! | 1.0 | Query                | &check; _(lacks Query Application Namespaces support)_ |
//! | 1.1 | Discover Versions    | &check; |
//! | 1.0 | Cancel               |  |
//! | 1.0 | Poll                 |  |
//! | 1.2 | Encrypt              |  |
//! | 1.2 | Decrypt              |  |
//! | 1.2 | Sign                 | &check; |
//! | 1.2 | Signature Verify     |  |
//! | 1.2 | MAC                  |  |
//! | 1.2 | MAC Verify           |  |
//! | 1.2 | RNG Retrieve         | &check; |
//! | 1.2 | RNG Seed             |  |
//! | 1.2 | Hash                 |  |
//! | 1.2 | Create Split Key     |  |
//! | 1.2 | Join Split Key       |  |
//!
//! # KMIP Use/Test Case Coverage
//!
//! Each KMIP specification document is accompanied by a separate document that defines a set of use cases, renamed in KMIP
//! 1.1 to test cases. These show complete KMIP requests and responses. In the v1.0 and v1.1 versions each test case is
//! broken down into its constituent TTLV parts with the matching numeric values and an accompanying hexadecimal
//! representation of the serialized form. From v1.2 onwards the test case representation was changed from TTLV/hex based to
//! XML based.
//!
//! The subset of the TTLV/hex format test cases that this crate
//! [demonstrates compliance with](https://github.com/NLnetLabs/kmip-protocol/tree/main/src/tests) are represented below by
//! ticked boxes:
//!
//! **KMIP Use Cases [v1.0](https://docs.oasis-open.org/kmip/usecases/v1.0/cs01/kmip-usecases-1.0-cs-01.html)/[v1.1](https://docs.oasis-open.org/kmip/testcases/v1.1/kmip-testcases-v1.1.html):**
//!
//! - 3 Centralized Management
//!   - 3.1 Basic Functionality
//!     - [ ] 3.1.1 Use-case: Create / Destroy
//!     - [x] 3.1.2 Use-case: Register / Create / Get attributes / Destroy
//!     - [ ] 3.1.3 Use-case: Create / Locate / Get / Destroy
//!     - [ ] 3.1.4 Use-case: Dual client use-case, ID Placeholder linked Locate & Get batch
//!     - [ ] 3.1.5 Use-case: Register / Destroy Secret Data
//!   - [ ] 3.2 Use-case: Asynchronous Locate
//! - 4 Key life cycle support
//!   - [x] 4.1 Use-case: Revoke scenario
//! - 5 Auditing and reporting
//!   - [ ] 5.1 Use-case: Get usage allocation scenario
//! - 6 Key Interchange, Key Exchange
//!   - [ ] 6.1 Use-case: Import of a Third-party Key
//! - 7 Vendor Extensions
//!   - [ ] 7.1 Use-case: Unrecognized Message Extension with Criticality Indicator false
//!   - [ ] 7.2 Use-case: Unrecognized Message Extension with Criticality Indicator true
//! - 8 Asymmetric keys
//!   - [x] 8.1 Use-case: Create a Key Pair
//!   - [ ] 8.2 Use-case: Register Both Halves of a Key Pair
//! - 9 Key Roll-over
//!   - [ ] 9.1 Use-case: Create a Key, Re-key
//!   - [ ] 9.2 Use-case: Existing Key Expired, Re-key with Same lifecycle
//!   - [ ] 9.3 Use-case: Existing Key Compromised, Re-key with same lifecycle
//!   - [ ] 9.4 Use-case: Create key, Re-key with new lifecycle
//!   - [ ] 9.5 Use-case: Obtain Lease for Expired Key
//! - 10 Archival
//!   - [ ] 10.1 Use-case: Create a Key, Archive and Recover it
//! - 11 Access Control, Policies
//!   - [x] 11.1 Use-case: Credential, Operation Policy, Destroy Date _**(step 1 only for username/password auth test)**_
//!   - [ ] 11.2 Test Case: Device Credential, Operation Policy, Destroy Date _(Added in KMIP v1.1)_
//! - 12 Query, Maximum Response Size
//!   - [x] 12.1 Use-case: Query, Maximum Response Size _**(Implemented for both KMIP v1.0 and v1.1 test variants)**_
//!   - [ ] 12.2 Test Case: Query Vendor Extensions _(Added in KMIP v1.1)_
//! - 13     Asymmetric Keys and Certificates _(Added in KMIP v1.1)_
//!   - [ ] 13.1 Test Case: Register an Asymmetric Key Pair in PKCS#1 Format
//!   - [ ] 13.2 Test Case: Register an Asymmetric Key Pair and a Corresponding X.509 Certificate
//!   - [ ] 13.3 Test Case: Create, Re-key Key Pair
//!   - [ ] 13.4 Test Case: Register Key Pair, Certify and Re-certify Public Key
//! - 14     Key Wrapping _(Added in KMIP v1.1)_
//!   - [ ] 14.1 Test Case: Key Wrapping using AES Key Wrap and No Encoding
//!   - [ ] 14.2 Test Case: Key Wrapping using AES Key Wrap with Attributes
//! - 15     Groups _(Added in KMIP v1.1)_
//!   - [ ] 15.1 Test Case: Locate a Fresh Object from the Default Group
//!   - [ ] 15.2 Test Case: Client-side Group Management
//!   - [ ] 15.3 Test Case: Default Object Group Member
//! - 16     Discover Versions _(Added in KMIP v1.1)_
//!   - [x] 16.1 Test Case: Discover Versions
//! - 17     Attribute Handling _(Added in KMIP v1.1)_
//!   - [x] 17.1 Test Case: Handling of Attributes and Attribute Index Values
//! - 18     Digest _(Added in KMIP v1.1)_
//!   - [ ] 18.1 Test Case: Digests of Symmetric Keys
//!   - [ ] 18.2 Test Case: Digests of RSA Private Keys
//!
//! **Other (partially) implemented KMIP test cases:**
//!
//! - [Advanced Cryptographic Mandatory Test Cases KMIP v1.3 5.9.8.1 CS-AC-M-1-13](https://docs.oasis-open.org/kmip/profiles/v1.3/os/test-cases/kmip-v1.3/mandatory/CS-AC-M-1-13.xml) _(steps 1 & 2 only for sign operation test)_
//! - [RNG Cryptographic Mandatory Test Cases KMIP v1.3 5.9.9.1 CS-RNG-M-1-13](ttps://docs.oasis-open.org/kmip/profiles/v1.3/os/test-cases/kmip-v1.3/mandatory/CS-RNG-M-1-13.xml)
#![forbid(unsafe_code)]

#[cfg(all(
    feature = "sync",
    any(feature = "async-with-async-std", feature = "async-with-tokio")
))]
compile_error!("feature \"sync\" cannot be enabled at the same time as either of the \"async-with-async-std\" or \"async-with-tokio\" features");

#[cfg(all(feature = "async-std", not(feature = "async-with-async-std")))]
compile_error!("do not enable the \"async-std\" feature directly, instead enable the \"async-with-async-std\" feature");

#[cfg(all(feature = "tokio", not(feature = "async-with-tokio")))]
compile_error!("do not enable the \"tokio\" feature directly, instead enable the \"async-with-tokio\" feature");

pub mod auth;
pub mod request;
pub mod response;
pub mod tag_map;

#[cfg(any(
    feature = "tls-with-async-tls",
    feature = "tls-with-openssl",
    feature = "tls-with-tokio-native-tls"
))]
pub mod tls;

pub mod types;

#[cfg(test)]
mod tests;

mod util;

pub use kmip_ttlv::Config;
