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

To test with PyKMIP 0.10.0 on Ubuntu 18.04 LTS:

```
apt update
apt install -y python3-pip
pip3 install pykmip

mkdir pykmip
cd pykmip
cat <<EOF >san.cnf
[ext]
subjectAltName = DNS:localhost
EOF

mkdir demoCA
touch demoCA/index.txt
echo 01 > demoCA/serial
openssl ecparam -out ca.key -name secp256r1 -genkey
openssl req -x509 -new -key ca.key -out ca.crt -outform PEM -days 3650 -subj "/C=NL/ST=Noord Holland/L=Amsterdam/O=NLnet Labs/CN=localhost"
openssl ecparam -out server.key -name secp256r1 -genkey
openssl req -new -nodes -key server.key -outform pem -out server.csr -subj "/C=NL/ST=Noord Holland/L=Amsterdam/O=NLnet Labs/CN=localhost"
openssl ca -keyfile ca.key -cert ca.crt -in server.csr -out server.crt -outdir . -batch -noemailDN -extfile san.cnf -extensions ext
openssl pkcs8 -topk8 -nocrypt -in server.key -out server.pkcs8.key
mv server.pkcs8.key server.key
openssl pkcs12 -export -inkey server.key -in server.crt -out identity.p12 -passout pass:

cat <<EOF >server.conf
[server]
hostname=localhost
port=5696
certificate_path=./server.crt
key_path=./server.key
ca_path=./ca.crt
auth_suite=TLS1.2
enable_tls_client_auth=False
tls_cipher_suites=TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
logging_level=DEBUG
database_path=./pykmip.db
EOF

pykmip-server -f ./server.conf
```

Now connect using the demo tool with one of the following invocations when `CONFDIR` is set to the path to the
directory containing the files output by the `openssl` commands above.

OpenSSL:
```
cargo run --features tls-with-openssl --example demo -- --server-cert $CONFDIR/server.crt --ca-cert $CONFDIR/ca.crt --client-cert $CONFDIR/server.crt --client-key $CONFDIR/server.key
```

OpenSSL (vendored):
```
cargo run --features tls-with-openssl-vendored --example demo -- --server-cert $CONFDIR/server.crt --ca-cert $CONFDIR/ca.crt --client-cert $CONFDIR/server.crt --client-key $CONFDIR/server.key
```

RustLS:
```
cargo run --features tls-with-rustls --example demo -- --server-cert $CONFDIR/server.crt --ca-cert $CONFDIR/ca.crt --client-cert $CONFDIR/server.crt --client-key $CONFDIR/server.key
```

Tokio (native TLS):
```
cargo run --no-default-features --features tls-with-tokio-native-tls --example demo -- --server-cert $CONFDIR/server.crt --ca-cert $CONFDIR/ca.crt --client-cert-and-key $CONFDIR/identity.p12
```

Tokio (RustLS):
```
cargo run --no-default-features --features tls-with-tokio-rustls --example demo -- --server-cert $CONFDIR/server.crt --ca-cert $CONFDIR/ca.crt --client-cert $CONFDIR/server.crt --client-key $CONFDIR/server.key
```

Async TLS:
```
cargo run --no-default-features --features tls-with-async-tls --example demo -- --server-cert $CONFDIR/server.crt --ca-cert $CONFDIR/ca.crt --client-cert $CONFDIR/server.crt --client-key $CONFDIR/server.key
```

You can also run the example demo with the `SSLKEYLOGFILE` environment variable set to the path to a file you want TLS
secrets to be stored in, which can be used to decrypt the communication using a program like Wireshark.

Run with `-v` for more detailed logging output.