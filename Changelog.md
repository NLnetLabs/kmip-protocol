# Change Log

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

