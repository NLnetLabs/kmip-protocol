[![CI](https://github.com/NLnetLabs/kmip-protocol/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/NLnetLabs/kmip-protocol/actions/workflows/ci.yml)
[![Crate](https://img.shields.io/crates/v/kmip-protocol)](crates.io/crates/kmip-protocol)
[![Docs](https://img.shields.io/docsrs/kmip-protocol)](https://docs.rs/kmip-protocol/)

# kmip-protocol - A library for (de)serializing KMIP protocol objects

[KMIP](https://docs.oasis-open.org/kmip/spec/v1.0/kmip-spec-1.0.html):
> The OASIS Key Management Interoperability Protocol specifications which define message formats for the manipulation
> of cryptographic material on a key management server.

### Welcome

This crate offers a **partial implementation** of (de)serialization of KMIP v1.0-1.2 protocol messages for use
primarily by the [Krill](https://nlnetlabs.nl/projects/rpki/krill/) project. The interface offered is based on the
popular Rust [Serde](https://serde.rs/) (de)serialization framework for decorating arbitrary high level Rust "business 
object" structs with attributes that guide the (de)serialization process.

For details about the level of specification implementation and test coverage see the [crate documentation](https://docs.rs/kmip-protocol/).

### Scope

This crate consists of:
  - Many Serde attributed Rust type definitions that represent KMIP request and response business objects.
  - A `Client` struct that uses the `kmip-ttlv` crate to serialize entire KMIP requests (composed from business object
    types) to a writer and deserialize the responses from a reader.
  - Optional sample sync and async TLS implementations showing how the `Client` can be used to communicate with a KMIP
    server.

### Status

This is a work-in-progress. The interface offered by this library is expected to change and no guarantee of interface
stability is made at this time. At the time of writing limited manual testing with [PyKMIP](https://pykmip.readthedocs.io/)
([results](https://github.com/NLnetLabs/kmip-protocol/issues/14)) and [Kryptus HSM](https://kryptus.com/en/cloud-hsm/)
([results](https://github.com/NLnetLabs/kmip-protocol/issues/15)) appears to work as expected.

### Example Code

See [`examples/demo/`](examples/demo/). For more information about running the example see:

```bash
cargo run --example demo --features tls-with-rustls -- --help
```
