[![CI](https://github.com/NLnetLabs/krill-kmip-protocol/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/NLnetLabs/krill-kmip-protocol/actions/workflows/ci.yml)

# krill-kmip-protocol - A library for (de)serializing KMIP protocol messages

[Krill](https://nlnetlabs.nl/projects/rpki/krill/):
> A free, open source RPKI Certificate Authority that lets you run delegated RPKI under one or multiple Regional Internet Registries (RIRs).

[KMIP](https://docs.oasis-open.org/kmip/spec/v1.0/kmip-spec-1.0.html):
> The OASIS Key Management Interoperability Protocol specifications which define message formats for the manipulation of cryptographic material on a key management server.

### Welcome

This crate offers a **partial implementation** of (de)serialization of KMIP v1.0-1.2 protocol messages for use primarily by the [Krill](https://nlnetlabs.nl/projects/rpki/krill/) project.

### Scope

This crate is one of potentially several crates that will be implemented to add the ability to Krill to interact with KMIP compliant servers. The current thinking is that the work consists of separate chunks for TTLV (de)serialization, KMIP business object definitions, client request/response API and the TCP+TLS client.

### Status

This is a work-in-progress. The interface offered by this library is expected to change and no guarantee of interface stability is made at this time. The intention is publish this crate in the near future to https://crates.io/ to be depended on by Krill like any other Rust crate dependency.

### KMIP Use/Test Case Coverage

Each KMIP specification document is accompanied by a separate document that defines a set of use cases, renamed in KMIP 1.1 to test cases. These show complete KMIP requests and responses. In the v1.0 and v1.1 versions each test case is broken down into its constituent TTLV parts with the matching numeric values and an accompanying hexadecimal representation of the serialized form. From v1.2 onwards the test case representation was changed from TTLV/hex based to XML based.

The subset of the TTLV/hex format test cases that this crate [demonstrates compliance with](https://github.com/NLnetLabs/krill-kmip-protocol/tree/main/src/tests) are represented below by ticked boxes:

**[KMIP Use Cases v1.0](https://docs.oasis-open.org/kmip/usecases/v1.0/cs01/kmip-usecases-1.0-cs-01.html):**

- 3 Centralized Management
  - 3.1 Basic Functionality
    - [ ] 3.1.1 Use-case: Create / Destroy
    - [ ] 3.1.2 Use-case: Register / Create / Get attributes / Destroy
    - [ ] 3.1.3 Use-case: Create / Locate / Get / Destroy
    - [ ] 3.1.4 Use-case: Dual client use-case, ID Placeholder linked Locate & Get batch
    - [ ] 3.1.5 Use-case: Register / Destroy Secret Data
  - [ ] 3.2 Use-case: Asynchronous Locate
- 4 Key life cycle support
  - [ ] 4.1 Use-case: Revoke scenario
- 5 Auditing and reporting
  - [ ] 5.1 Use-case: Get usage allocation scenario
- 6 Key Interchange, Key Exchange
  - [ ] 6.1 Use-case: Import of a Third-party Key
- 7 Vendor Extensions
  - [ ] 7.1 Use-case: Unrecognized Message Extension with Criticality Indicator false
  - [ ] 7.2 Use-case: Unrecognized Message Extension with Criticality Indicator true
- 8 Asymmetric keys
  - [ ] 8.1 Use-case: Create a Key Pair
  - [ ] 8.2 Use-case: Register Both Halves of a Key Pair
- 9 Key Roll-over
  - [ ] 9.1 Use-case: Create a Key, Re-key
  - [ ] 9.2 Use-case: Existing Key Expired, Re-key with Same lifecycle
  - [ ] 9.3 Use-case: Existing Key Compromised, Re-key with same lifecycle
  - [ ] 9.4 Use-case: Create key, Re-key with new lifecycle
  - [ ] 9.5 Use-case: Obtain Lease for Expired Key
- 10 Archival
  - [ ] 10.1 Use-case: Create a Key, Archive and Recover it
- 11 Access Control, Policies
  - [ ] 11.1 Use-case: Credential, Operation Policy, Destroy Date
- 12 Query, Maximum Response Size
  - [x] 12.1 Use-case: Query, Maximum Response Size

**[KMIP Test Cases v1.1](https://docs.oasis-open.org/kmip/testcases/v1.1/kmip-testcases-v1.1.html):**

- 3       Centralized Management
  - 3.1     Basic Functionality
    - [ ] 3.1.1 Test Case: Create / Destroy
    - [ ] 3.1.2 Test Case: Register / Create / Get attributes / Destroy
    - [ ] 3.1.3 Test Case: Create / Locate / Get / Destroy
    - [ ] 3.1.4 Test Case: Dual Client Test Case, ID Placeholder-linked Locate & Get Batch
    - [ ] 3.1.5 Test Case: Register / Destroy Secret Data
  - [ ] 3.2 Test Case: Asynchronous Locate
- 4       Key Life Cycle Support
  - [ ] 4.1 Test Case: Revoke Scenario
- 5       Auditing and Reporting
  - [ ] 5.1 Test Case: Get Usage Allocation Scenario
- 6       Key Interchange, Key Exchange
  - [ ] 6.1 Test Case: Import of a Third-party Key
- 7       Vendor Extensions
  - [ ] 7.1 Test Case: Unrecognized Message Extension with Criticality Indicator False
  - [ ] 7.2 Test Case: Unrecognized Message Extension with Criticality Indicator True
- 8       Asymmetric Keys
  - [ ] 8.1 Test Case: Create a Key Pair
  - [ ] 8.2 Test Case: Register Both Halves of a Key Pair
- 9       Key Roll-over
  - [ ] 9.1 Test Case: Create a Key, Re-key
  - [ ] 9.2 Test Case: Existing Key Expired, Re-key with Same Life-cycle
  - [ ] 9.3 Test Case: Existing Key Compromised, Re-key with Same Life-cycle
  - [ ] 9.4 Test Case: Create Key, Re-key with New Life-cycle
  - [ ] 9.5 Test Case: Obtain Lease for Expired Key
- 10     Archival
  - [ ] 10.1 Test Case: Create a Key, Archive and Recover it
- 11     Access Control, Policies
  - [ ] 11.1 Test Case: Credential, Operation Policy, Destroy Date
  - [ ] 11.2 Test Case: Device Credential, Operation Policy, Destroy Date
- 12     Query, Maximum Response Size
  - [ ] 12.1 Test Case: Query, Maximum Response Size
  - [ ] 12.2 Test Case: Query Vendor Extensions
- 13     Asymmetric Keys and Certificates
  - [ ] 13.1 Test Case: Register an Asymmetric Key Pair in PKCS#1 Format
  - [ ] 13.2 Test Case: Register an Asymmetric Key Pair and a Corresponding X.509 Certificate
  - [ ] 13.3 Test Case: Create, Re-key Key Pair
  - [ ] 13.4 Test Case: Register Key Pair, Certify and Re-certify Public Key
- 14     Key Wrapping
  - [ ] 14.1 Test Case: Key Wrapping using AES Key Wrap and No Encoding
  - [ ] 14.2 Test Case: Key Wrapping using AES Key Wrap with Attributes
- 15     Groups
  - [ ] 15.1 Test Case: Locate a Fresh Object from the Default Group
  - [ ] 15.2 Test Case: Client-side Group Management
  - [ ] 15.3 Test Case: Default Object Group Member
- 16     Discover Versions
  - [ ] 16.1 Test Case: Discover Versions
- 17     Attribute Handling
  - [ ] 17.1 Test Case: Handling of Attributes and Attribute Index Values
- 18     Digest
  - [ ] 18.1 Test Case: Digests of Symmetric Keys
  - [ ] 18.2 Test Case: Digests of RSA Private Keys
