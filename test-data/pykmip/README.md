# PyKMIP test server.

This directory contains configuration and data files for running the PyKMIP KMIP compatible software HSM tool.

The CI workflow uses PyKMIP with the 'demo' example.

## Running the demo.

Tested on Fedora Linux 44.

First, verify that the demo can be built successfully:

```
cargo build --example demo --no-default-features --features tls-with-openssl
```

Next, install and run PyKMIP inside a Python 3.11 (needed by PyKMIP) virtual environment using [uv](https://docs.astral.sh/uv/getting-started/installation/):

```
uv venv --python 3.11
source .venv/bin/activate
cd test-data/pykmip
uv pip install pykmip --constraint ./constraints.txt
python ./run-server.py &
```

Now test that the PyKMIP server can be connected to, at least via TLS:

```
sleep 5s
openssl s_client -connect 127.0.0.1:5696 || true
```

Finally, run the demo:

```
cd -
cargo run --example demo --no-default-features --features tls-with-openssl 2>&1
```

## Re-generating the TLS certificates used by the test

If the TLS certificates expire, they can be regenerated like so:

NOTE: These commands were originally run on Ubuntu 18.04 and have not been verified since then.

```
mkdir demoCA
touch demoCA/index.txt
echo 01 > demoCA/serial
openssl ecparam -out ca.key -name secp256r1 -genkey
openssl req -x509 -new -key ca.key -out ca.crt -outform PEM -days 3650 -subj "/C=NL/ST=Noord Holland/L=Amsterdam/O=NLnet Labs/CN=localhost"
openssl ecparam -out server.in.key -name secp256r1 -genkey
openssl req -new -nodes -key server.in.key -outform pem -out server.csr -subj "/C=NL/ST=Noord Holland/L=Amsterdam/O=NLnet Labs/CN=localhost"
OPENSSL_CONF=openssl.cnf openssl ca -keyfile ca.key -cert ca.crt -in server.csr -out server.crt -outdir . -batch -noemailDN -extfile san.cnf -extensions ext -days 3650
openssl pkcs8 -topk8 -nocrypt -in server.in.key -out server.key
```
