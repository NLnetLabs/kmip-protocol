This demo attempts to connect to a KMIP server using the KMIP TTLV protocol over a TCP+TLS connection.

Once connected it will ask the KMIP server to:
  - Report its properties (name, supported operations and types).
  - Create an RSA public/private key pair.
  - Activate the private key for signing.
  - Sign some short test data with the created private key.
  - Deactivate the private key.
  - Delete the created public/private key pair.
  - Request a small number of random bytes from the server.

For usage instructions run the demo using this command in a Git cloned copy of this repository:

```
cargo run --example demo --features tls-with-rustls -- --help
```