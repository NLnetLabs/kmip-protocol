[![CI](https://github.com/NLnetLabs/krill-kmip-protocol/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/NLnetLabs/krill-kmip-protocol/actions/workflows/ci.yml)

# krill-kmip-protocol - A library for (de)serializing KMIP protocol messages

[Krill](https://nlnetlabs.nl/projects/rpki/krill/):
> A free, open source RPKI Certificate Authority that lets you run delegated RPKI under one or multiple Regional Internet Registries (RIRs).

[KMIP](http://docs.oasis-open.org/kmip/spec/v1.0/kmip-spec-1.0.html):
> The OASIS Key Management Interoperability Protocol specifications which define message formats for the manipulation of cryptographic material on a key management server.

### Welcome

This crate offers a **partial implementation** of (de)serialization of KMIP v1.0-1.2 protocol messages for use primarily by the [Krill](https://nlnetlabs.nl/projects/rpki/krill/) project.

### Scope

This crate is one of potentially several crates that will be implemented to add the ability to Krill to interact with KMIP compliant servers. The current thinking is that the work consists of separate chunks for TTLV (de)serialization, KMIP business object definitions, client request/response API and the TCP+TLS client.

### Status

This is a work-in-progress. The interface offered by this library is expected to change and no guarantee of interface stability is made at this time. The intention is publish this crate in the near future to https://crates.io/ to be depended on by Krill like any other Rust crate dependency.
