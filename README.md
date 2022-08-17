[![CI](https://github.com/NLnetLabs/kmip-protocol/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/NLnetLabs/kmip-protocol/actions/workflows/ci.yml)
[![Crate](https://img.shields.io/crates/v/kmip-protocol)](https://crates.io/crates/kmip-protocol)
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

### Diagnosing problems

This crate will by default log sent and received KMIP byte sequences in anonymized compact form at TRACE level, if the using crate provides a log implementation. For example:

```
[2022-08-17T13:27:37Z TRACE kmip_protocol::client::client] KMIP TTLV request: 78[77[69[6Ai6Bi]0C[23[24e1:25[99tA1t]]]0Di]0F[5Ce8:79[08[0At0Be4:]]]]
```

These so-called diagnostic strings can be expanded to a full KMIP spec like description of the request or response using the provided `diag_to_txt` example, e.g.:

```sh
$ echo "78[77[69[6Ai6Bi]0C[23[24e1:25[99tA1t]]]0Di]0F[5Ce8:79[08[0At0Be4:]]]]" | cargo run -q --example diag_to_txt -
Tag: Request Message (0x420078), Type: Structure (0x01), Data: 
  Tag: Request Header (0x420077), Type: Structure (0x01), Data: 
    Tag: Protocol Version (0x420069), Type: Structure (0x01), Data: 
      Tag: Protocol Version Major (0x42006A), Type: Integer (0x02), Data: <redacted>
      Tag: Protocol Version Minor (0x42006B), Type: Integer (0x02), Data: <redacted>
    Tag: Authentication (0x42000C), Type: Structure (0x01), Data: 
      Tag: Credential (0x420023), Type: Structure (0x01), Data: 
        Tag: Credential Type (0x420024), Type: Enumeration (0x05), Data: 1
        Tag: Credential Value (0x420025), Type: Structure (0x01), Data: 
          Tag: Username (0x420099), Type: TextString (0x07), Data: <redacted>
          Tag: Password (0x4200A1), Type: TextString (0x07), Data: <redacted>
    Tag: Batch Count (0x42000D), Type: Integer (0x02), Data: <redacted>
  Tag: Batch Item (0x42000F), Type: Structure (0x01), Data: 
    Tag: Operation (0x42005C), Type: Enumeration (0x05), Data: 8
    Tag: Request Payload (0x420079), Type: Structure (0x01), Data: 
      Tag: Attribute (0x420008), Type: Structure (0x01), Data: 
        Tag: Attribute Name (0x42000A), Type: TextString (0x07), Data: <redacted>
        Tag: Attribute Value (0x42000B), Type: Enumeration (0x05), Data: 4
Tag: 0x4200
```
