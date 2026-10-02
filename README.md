[![CI](https://github.com/NLnetLabs/kmip-protocol/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/NLnetLabs/kmip-protocol/actions/workflows/ci.yml)
[![Crate](https://img.shields.io/crates/v/kmip-protocol)](https://crates.io/crates/kmip-protocol)
[![Docs](https://img.shields.io/docsrs/kmip-protocol)](https://docs.rs/kmip-protocol/)

# kmip-protocol - A library for (de)serializing KMIP protocol objects

[KMIP](https://docs.oasis-open.org/kmip/spec/v1.0/kmip-spec-1.0.html):
> The OASIS Key Management Interoperability Protocol specifications which define message formats for the manipulation
> of cryptographic material on a key management server.

### Welcome

This crate offers a **partial implementation** of (de)serialization of KMIP v1.0-1.2 protocol messages for use
by the [Krill](https://nlnetlabs.nl/projects/krill/) and [Cascade](https://nlnetlabs.nl/projects/cascade) projects.

For details about the level of specification implementation and test coverage see the [crate documentation](https://docs.rs/kmip-protocol/).

### Scope

This crate consists of:
  - Many Rust type definitions that represent KMIP request and response business objects.
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
cargo run --example demo --features tls-with-rustls,ring -- --help
```

### Diagnosing problems

If this crate is unable to parse KMIP TTLV bytes received from the server it will return both the request and the
response bytes to the application which may then expose them if desired to the operator.

At TRACE log level this crate logs all sent and received KMIP messages in hexadecimal byte form, for example:

```
2026-09-29T12:20:47.590207Z  INFO demo: Creating RSA key pair
2026-09-29T12:20:47.590217Z TRACE kmip_protocol::net::client: Serializing request to KMIP wire bytes
2026-09-29T12:20:47.590257Z TRACE kmip_protocol::net::client: Writing 528 bytes to the server:
42007801000002084200770100000048420069010000002042006A020000000400000001000000
0042006B0200000004000000000000000042005002000000047FFFFFFF0000000042000D020000
0004000000010000000042000F01000001B042005C050000000400000002000000004200790100
00019842001F0100000070420008010000003042000A070000001743727970746F677261706869
6320416C676F726974686D0042000B05000000040000000400000000420008010000003042000A
070000001443727970746F67726170686963204C656E6774680000000042000B02000000040000
0800000000004200650100000088420008010000004842000A07000000044E616D650000000042
000B01000000304200550700000012746573745F305F707269766174655F6B6579000000000000
42005405000000040000000100000000420008010000003042000A070000001843727970746F67
726170686963205573616765204D61736B42000B0200000004000000010000000042006E010000
0088420008010000004842000A07000000044E616D650000000042000B01000000304200550700
000011746573745F305F7075626C69635F6B657900000000000000420054050000000400000001
00000000420008010000003042000A070000001843727970746F67726170686963205573616765
204D61736B42000B02000000040000000200000000
```

This crate contains an example tool called `hex_to_txt` which can be used to convert the hexadecimal byte sequences
into a more readable form (the same form used by the KMIP 1.0 specification test suite).

Assuming that the long hexadecimal byte sequence above has been written to file
`/tmp/kmip.txt` you can print it in the more readable form using the following
command:


```bash
$ cargo -q run --example hex_to_txt /tmp/kmip.txt
Tag: Request Message (0x420078), Type: Structure (0x01), Data:
  Tag: Request Header (0x420077), Type: Structure (0x01), Data:
    Tag: Protocol Version (0x420069), Type: Structure (0x01), Data:
      Tag: Protocol Version Major (0x42006A), Type: Integer (0x02), Data: 0x000001 (1)
      Tag: Protocol Version Minor (0x42006B), Type: Integer (0x02), Data: 0x000000 (0)
    Tag: Maximum Response Size (0x420050), Type: Integer (0x02), Data: 0x7FFFFFFF (2147483647)
    Tag: Batch Count (0x42000D), Type: Integer (0x02), Data: 0x000001 (1)
  Tag: Batch Item (0x42000F), Type: Structure (0x01), Data:
    Tag: Operation (0x42005C), Type: Enumeration (0x05), Data: 0x000002 (2 = Create Key Pair)
    Tag: Request Payload (0x420079), Type: Structure (0x01), Data:
      Tag: Common Template-Attribute (0x42001F), Type: Structure (0x01), Data:
        Tag: Attribute (0x420008), Type: Structure (0x01), Data:
          Tag: Attribute Name (0x42000A), Type: TextString (0x07), Data: "Cryptographic Algorithm"
          Tag: Attribute Value (0x42000B), Type: Enumeration (0x05), Data: 0x000004 (4 = ??)
        Tag: Attribute (0x420008), Type: Structure (0x01), Data:
          Tag: Attribute Name (0x42000A), Type: TextString (0x07), Data: "Cryptographic Length"
          Tag: Attribute Value (0x42000B), Type: Integer (0x02), Data: 0x000800 (2048)
      Tag: Private Key Template-Attribute (0x420065), Type: Structure (0x01), Data:
        Tag: Attribute (0x420008), Type: Structure (0x01), Data:
          Tag: Attribute Name (0x42000A), Type: TextString (0x07), Data: "Name"
          Tag: Attribute Value (0x42000B), Type: Structure (0x01), Data:
            Tag: Name Value (0x420055), Type: TextString (0x07), Data: "test_0_private_key"
            Tag: Name Type (0x420054), Type: Enumeration (0x05), Data: 0x000001 (1 = Uninterpreted Text String)
        Tag: Attribute (0x420008), Type: Structure (0x01), Data:
          Tag: Attribute Name (0x42000A), Type: TextString (0x07), Data: "Cryptographic Usage Mask"
          Tag: Attribute Value (0x42000B), Type: Integer (0x02), Data: 0x000001 (1)
      Tag: Public Key Template-Attribute (0x42006E), Type: Structure (0x01), Data:
        Tag: Attribute (0x420008), Type: Structure (0x01), Data:
          Tag: Attribute Name (0x42000A), Type: TextString (0x07), Data: "Name"
          Tag: Attribute Value (0x42000B), Type: Structure (0x01), Data:
            Tag: Name Value (0x420055), Type: TextString (0x07), Data: "test_0_public_key"
            Tag: Name Type (0x420054), Type: Enumeration (0x05), Data: 0x000001 (1 = Uninterpreted Text String)
        Tag: Attribute (0x420008), Type: Structure (0x01), Data:
          Tag: Attribute Name (0x42000A), Type: TextString (0x07), Data: "Cryptographic Usage Mask"
          Tag: Attribute Value (0x42000B), Type: Integer (0x02), Data: 0x000002 (2)
```

From this we can see that, as was indicated by the accompanying INFO level log
message, the bytes represent a KMIP Create Key request.
