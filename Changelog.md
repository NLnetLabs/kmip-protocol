# Changelog

<!-- Changelog template (remove empty sections on release of a version)
## Unreleased version

Released yyyy-mm-dd.

### Breaking changes
### New
### Bug fixes
### Other changes
### Documentation improvements
### Known issues
### Acknowledgements
-->

# 0.5.1

Released 206-11-06.

Note: There are too many additions, fixes and breaking changes to the API to
list here, this is just a high level summary.

### Breaking changes

- New FastScan/Formatter (de)serializers. Note: Removes the old Serde based
  (de)serializers, diagnostic text support and the `diag_to_txt` example.
  ([#85] by @bal-e and @ximon18)
- Refactor client and TLS code under new 'net' module. ([#86] by @ximon18)
- Upgrade rustls to 0.23 and remove support for `async-std` ([#56] by @partim)
- Remove support for tokio-native-tls and CombinedPkcs12 client auth. ([#107]
  by @ximon18)
- Set MSRV to 1.88. ([698002f] by @mozzieongit)

### New

- Add support for optional Response Header fields. ([#68] by @ximon18)
- Add support for specifying the SNI name separately to the TCP host/domain.
  ([#69] by @ximon18)
- Add connection pool functionality. ([#88] by @ximon18)
- Add server functionality. ([#90] by @ximon18)
- Support use of KMIP batch placeholder IDs. ([#95] by @ximon18)
- Add support needed for a vendor specific extension to Cascade-HSM-Bridge to
  support Ed448 and Ed25519. ([#104] by @ximon18)

### Bug fixes

- `next` branch PEM parsing error (which has since been fixed in main). ([#59]
  by @ximon18 & @partim)
- The presence of optional Response Header fields causes response parsing to
  fail. ([#62] by @ximon18)
- Timestamp should be encoded as a KMIP TTLV Date-Time type, not as a Long
  Integer type. ([#85] by @bal-e)
- Only attempt to deserialize a payload if the operation was a success. ([#85]
  by @ximon18)
- Increment the connection count in all cases. ([#85] by @ximon18)
- Continue on network interruption, don't abort. ([#85] by @ximon18)
- Incorrect handling of `Key Material` type `X.509`. ([#85] by @ximon18)
- Fix disabled test and show that #66 is resolved by the new deserializer.
  ([#93] by @ximon18)
- Fix parsing of arbitrary Server Information by skipping the struct. ([#109]
  by @ximon18)

### Other changes

- Normalize the author field. ([#36] by @maertsen)
- CI fixes and improvements. ([1b5b1de], [7cfc752] & [#103] by @ximon, [#57]
  by @partim)
- Don't force the application to use `aws-lc-rs`. ([#90] by @ximon18)
- Upgraded dependencies. ([#100] by @ximon18)
- Add missing getters on Client. ([#94] by @ximon18)
- Responses to the `Query` operation are now cached. ([#104] by @ximon18)
- Fix incorrect panic string in example demo. ([5d0c88e] by @ximon18)
- Removed many dependencies, replaced others with higher
  quality alternatives. (@bal-e and @ximon18)
- Switched from `log` based logging to `tracing` based logging to match how
  `domain` logs. (by @ximon18)
- Test that certificate loading and parsing now works correctly. ([#65] &
  [#92] by @ximon18)

### Documentation improvements

- Add basic `CONTRIBUTING.md` with links to CoC and LLM policy. ([#54] by
  @ximon18)
- Add `SECURITY.md`. ([#55] by @ximon18)
- Update demo README to reflect removal of async TLS support. ([3e4c6df] by
  @ximon18)
- Add a `Changelog.md`. ([389589a] by @partim)
- Add a `README.md` to the `hex_to_txt` example. ([#85] by @ximon18)

[#36]: https://github.com/NLnetLabs/kmip-protocol/pull/36
[#54]: https://github.com/NLnetLabs/kmip-protocol/pull/54
[#55]: https://github.com/NLnetLabs/kmip-protocol/pull/55
[#56]: https://github.com/NLnetLabs/kmip-protocol/pull/56
[#57]: https://github.com/NLnetLabs/kmip-protocol/pull/57
[#59]: https://github.com/NLnetLabs/kmip-protocol/pull/59
[#62]: https://github.com/NLnetLabs/kmip-protocol/pull/62
[#65]: https://github.com/NLnetLabs/kmip-protocol/pull/65
[#66]: https://github.com/NLnetLabs/kmip-protocol/pull/66
[#68]: https://github.com/NLnetLabs/kmip-protocol/pull/68
[#69]: https://github.com/NLnetLabs/kmip-protocol/pull/69
[#85]: https://github.com/NLnetLabs/kmip-protocol/pull/85
[#86]: https://github.com/NLnetLabs/kmip-protocol/pull/86
[#88]: https://github.com/NLnetLabs/kmip-protocol/pull/88
[#90]: https://github.com/NLnetLabs/kmip-protocol/pull/90
[#92]: https://github.com/NLnetLabs/kmip-protocol/pull/92
[#93]: https://github.com/NLnetLabs/kmip-protocol/pull/93
[#94]: https://github.com/NLnetLabs/kmip-protocol/pull/94
[#95]: https://github.com/NLnetLabs/kmip-protocol/pull/95
[#103]: https://github.com/NLnetLabs/kmip-protocol/pull/103
[#100]: https://github.com/NLnetLabs/kmip-protocol/pull/100
[#104]: https://github.com/NLnetLabs/kmip-protocol/pull/104
[#107]: https://github.com/NLnetLabs/kmip-protocol/pull/107
[#109]: https://github.com/NLnetLabs/kmip-protocol/pull/109
[1b5b1de]: https://github.com/NLnetLabs/kmip-protocol/commit/1b5b1de4b601a9a019e839d2fc6d8148858e1e4e
[389589a]: https://github.com/NLnetLabs/kmip-protocol/commit/389589a56b6fc57aec736793aa6af6332abdae63
[3e4c6df]: https://github.com/NLnetLabs/kmip-protocol/commit/3e4c6df60e7ce6a444c84352300aed02617517ed
[5d0c88e]: https://github.com/NLnetLabs/kmip-protocol/commit/5d0c88eca44f6d57458fb20a345e3fc9c467e0a2
[698002f]: https://github.com/NLnetLabs/kmip-protocol/commit/698002f530738452e7c3bc405f1bb5a3849acb0f
[7cfc752]: https://github.com/NLnetLabs/kmip-protocol/commit/7cfc7522d507695cb8221524001570e645f79878


# 0.4.3

Released 2022-10-18.

Other changes

* Upgrade dev-dependency `pretty_assertions` to resolve a [Dependabot warning
  about the transitive dependency on the `ansi_term` 
  crate](https://github.com/NLnetLabs/kmip-protocol/security/dependabot/5).
  Note: This increases the MSRV from Rust 1.49.0 to Rust 1.54.0, but only for
  building the tests, not for building the library itself.
* Upgrade to the latest version of the `kmip-ttlv` crate.
* Minor Rust code quality improvements based on Clippy feedback from latest
  Rust.


# 0.4.2

Released 2022-08-02.

Other changes

* Increase MSRV from Rust 1.47.0 to Rust 1.49.0 to match the raised MSRV of
  the `kmip-ttlv` crate.
* Minor dependency version upgrades, triggered by security issues in
  dependencies of the `kmip-ttlv` crate and the
  [tokio](https://github.com/NLnetLabs/kmip-ttlv/security/dependabot/1),
  [crossbeam-utils](https://github.com/NLnetLabs/kmip-ttlv/security/dependabot/2)
  and openssl-src
  ([here](https://github.com/NLnetLabs/kmip-ttlv/security/dependabot/3) and
  [here](https://github.com/NLnetLabs/kmip-ttlv/security/dependabot/4)) 
  dependencies of this crate.


# 0.4.1

Released 2021-10-30.

Other changes

* Fix compilation on Rust 1.47.0.
* Fixed GitHub Actions CI workflow to actually build on the specified Rust
  versions.


# 0.4.0

Released 2021-10-14.

Breaking changes

* Differentiate item not found errors from other types of error, e.g. an
  attempt to sign with a non-existent private key.
* Mark the set of errors as `non_exhaustive` as we may add more in future.


# 0.3.1

Released 2021-10-05.

Bug fixes

* Fixed: a configuration error may be a hard error rather than a transient
  connection error.


# 0.3.0

Released 2021-09-29.

Breaking changes

* Removed INFO level "Establishing TLS connection" message (#24).
* Return errors from TLS `connect()` functions instead of panicking. (#25)
* Pass `ConnectionSettings` by reference instead of cloning. (#26)

New

* Support client supplied `TcpStream` factory so that low level control over
  the socket via [socket2](https://crates.io/crates/socket2) or similar is
  possible.
* Add a `rename_key()` function. (#27)
* Add a `get_key()` function. (#28)
* Count connection errors (see `Client::connection_error_count()`).

Improvements

* Re-enable commented out tests in client.rs. (#29)

Other changes

* Minor documentation fixes.


# 0.2.1

Released 2021-09-21.

Minor point release to fix broken docs.rs build.

# 0.2.0

Released 2021-09-21.

New

* Support for async (tokio and async-std).
* Bundled (demonstration) TCP+TLS client connection code for various Rust
  TLS client crates.
* Bundled tag map for pretty printing TTLV using human readable tag names
  instead of hex tag codes.
* Two new example programs: `diag_to_txt` and `hex_to_txt` relating to
  pretty printing of TTLV requests and responses.

Improvements

* Improvements to the TCP client code such as use of connection timeouts
  and `SSLKEYLOGFILE` support.
* More robust deserialization of opaque responses (e.g. `Server
  Information`).


# 0.1.0

Released 2021-08-30.

Initial release.

