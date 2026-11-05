#[cfg(not(any(
    feature = "tls-with-openssl",
    feature = "tls-with-openssl-vendored",
    feature = "tls-with-rustls",
    feature = "tls-with-tokio-rustls",
)))]
compile_error!("This demo requires one of the tls-with-xxx features to be enabled.");

mod config;
mod util;

use std::time::Duration;

use kmip_protocol::net::{Client, ConnectionSettings, NetError, NetResult, TlsClientAuth, TlsServerAuth};
use kmip_protocol::types::common::Operation;
use kmip_protocol::types::traits::ReadWrite;
use log::{error, info};
use structopt::StructOpt;
use util::init_logging;

use crate::{config::Opt, util::ToCsvString};

#[cfg(any(
    feature = "tls-with-openssl",
    feature = "tls-with-openssl-vendored",
    feature = "tls-with-rustls"
))]
fn main() {
    let opt = Opt::from_args();
    let num_threads = opt.num_threads;

    init_logging(&opt);

    info!("Connecting to KMIP server at {}:{}", opt.host, opt.port);

    cfg_if::cfg_if! {
        if #[cfg(any(feature = "tls-with-openssl", feature = "tls-with-openssl-vendored"))] {
            let client = kmip_protocol::net::tls::openssl::connect(&opt.into());
        } else if #[cfg(feature = "tls-with-rustls")] {
            let client = kmip_protocol::net::tls::rustls::connect(&opt.into());
        }
    }

    let client = client.expect("Failed to establish TLS connection");

    let mut thread_handles = vec![];

    for i in 0..num_threads {
        let thread_client = client.clone();
        let handle = std::thread::spawn(move || {
            exec_test_requests(thread_client, &format!("test_{}", i))
                .map_err(|err| {
                    if matches!(err, NetError::DeserializeError { .. }) {
                        error!("Deserialization error: {err}");
                        Ok(())
                    } else {
                        Err(err)
                    }
                })
                .unwrap();
        });
        thread_handles.push(handle);
    }

    for handle in thread_handles {
        handle.join().unwrap();
    }
}

#[cfg(feature = "tls-with-tokio-rustls")]
#[tokio::main]
async fn main() {
    let opt = Opt::from_args();

    init_logging(&opt);

    info!("Connecting to KMIP server at {}:{}", opt.host, opt.port);

    cfg_if::cfg_if! {
        if #[cfg(feature = "tls-with-tokio-rustls")] {
            let client = kmip_protocol::net::tls::tokio_rustls::connect(&opt.into()).await;
        }
    }

    let client = client.expect("Failed to establish TLS connection");

    exec_test_requests(client, "test")
        .await
        .map_err(|err| {
            if matches!(err, NetError::DeserializeError { .. }) {
                error!("Deserialization error: {err}");
                Ok(())
            } else {
                Err(err)
            }
        })
        .unwrap();
}

#[maybe_async::maybe_async]
async fn exec_test_requests<T: ReadWrite>(mut client: Client<T>, key_name_prefix: &str) -> NetResult<()> {
    let supported_ops = query_server_properties(&mut client).await?;
    let mut key_needs_revoking = false;

    if supports(&supported_ops, Operation::CreateKeyPair) {
        // TODO: Maybe key creation should return a key object with further operations on it such as revoke, delete,
        // sign, etc, instead of following the KMIP functional model?
        info!("Creating RSA key pair");
        if let Ok((private_key_id, public_key_id)) = client
            .create_rsa_key_pair(
                2048,
                format!("{}_private_key", key_name_prefix),
                format!("{}_public_key", key_name_prefix),
            )
            .await
        {
            info!("Created key pair:");
            info!("  Private key ID: {}", private_key_id);
            info!("  Public key ID : {}", public_key_id);

            if supports(&supported_ops, Operation::Activate) {
                info!("Activating private key {}..", private_key_id);
                if client.activate_key(&private_key_id).await.is_ok() {
                    key_needs_revoking = true;
                }
            }

            if supports(&supported_ops, Operation::Sign) {
                info!("Signing with private key {}..", private_key_id);
                if let Ok(signature_data) = client.sign(&private_key_id, &[1u8, 2u8, 3u8, 4u8, 5u8]).await {
                    info!("{}", hex::encode_upper(signature_data));
                }
            }

            if supports(&supported_ops, Operation::Revoke) {
                if key_needs_revoking {
                    info!("Revoking private key {}..", private_key_id);
                    client.revoke_key(&private_key_id).await.ok();
                }
            }

            if supports(&supported_ops, Operation::Destroy) {
                info!("Deleting public key {}..", public_key_id);
                client.destroy_key(&public_key_id).await.ok();
            }

            if supports(&supported_ops, Operation::Revoke) {
                if key_needs_revoking {
                    info!("Revoking private key {}..", private_key_id);
                    client.revoke_key(&private_key_id).await.ok();
                }
            }

            if supports(&supported_ops, Operation::Destroy) {
                info!("Deleting private key {}..", private_key_id);
                client.destroy_key(&private_key_id).await.ok();
            }
        }
    }

    if supports(&supported_ops, Operation::RNGRetrieve) {
        info!("Requesting 32 random bytes..");
        if let Ok(random_bytes) = client.rng_retrieve(32).await {
            info!("{}", hex::encode_upper(random_bytes));
        }
    }

    Ok(())
}

#[maybe_async::maybe_async]
#[rustfmt::skip]
async fn query_server_properties<T: ReadWrite>(client: &mut Client<T>) -> NetResult<Option<Vec<Operation>>> {
    info!("Querying server properties..");
    let server_props = client.query().await?;

    info!("Server identification: {}", server_props.vendor_identification.unwrap_or("Not available".into()));
    info!("Server supported operations: {}", server_props.operations.clone().to_csv_string());
    info!("Server supported object types: {}", server_props.object_types.to_csv_string());

    Ok(server_props.operations)
}

fn load_binary_file(path: &std::path::Path) -> Vec<u8> {
    use std::{fs::File, io::Read};

    let mut bytes = Vec::new();
    File::open(path)
        .unwrap_or_else(|_| panic!("Failed to open open file '{:?}'", path))
        .read_to_end(&mut bytes)
        .unwrap_or_else(|_| panic!("Failed to read data from file '{:?}'", path));
    bytes
}

impl From<Opt> for ConnectionSettings {
    fn from(opt: Opt) -> Self {
        let password = std::env::var("HSM_PASSWORD").ok();

        let tls_client_auth = {
            match (&opt.client_cert_path, &opt.client_key_path) {
                (None, None) => None,
                (Some(_), None) => {
                    panic!("Client certificate key path requires a client private key path")
                }
                (None, Some(_)) => {
                    panic!("Client private key path requires a client certificate path")
                }
                (Some(cert_path), Some(key_path)) => Some(TlsClientAuth {
                    cert_bytes: load_binary_file(cert_path),
                    private_key_bytes: load_binary_file(key_path),
                }),
            }
        };

        let tls_server_auth = if opt.insecure {
            TlsServerAuth::None
        } else if let Some(cert_path) = &opt.server_cert_path {
            assert!(opt.ca_cert_path.is_none());
            TlsServerAuth::TrustCertificate(load_binary_file(cert_path))
        } else if let Some(cert_path) = &opt.ca_cert_path {
            assert!(opt.server_cert_path.is_none());
            TlsServerAuth::TrustCertificateAuthority(load_binary_file(cert_path))
        } else {
            TlsServerAuth::Default
        };

        let connect_timeout = Some(Duration::from_secs(opt.connect_timeout));
        let read_timeout = Some(Duration::from_secs(opt.read_timeout));
        let write_timeout = Some(Duration::from_secs(opt.write_timeout));

        ConnectionSettings {
            host: opt.host,
            port: opt.port,
            username: opt.username,
            password,
            tls_client_auth,
            tls_server_auth,
            tls_server_name: opt.server_name,
            connect_timeout,
            read_timeout,
            write_timeout,
            max_response_bytes: Some(4096),
        }
    }
}

fn supports(supported_ops: &Option<Vec<Operation>>, op: Operation) -> bool {
    let res = supported_ops.as_ref().map(|v| v.contains(&op)).unwrap_or_default();

    info!("KMIP server supports {op}? {res}");

    res
}
