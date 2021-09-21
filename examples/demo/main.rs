#[cfg(not(any(
    feature = "tls-with-openssl",
    feature = "tls-with-openssl-vendored",
    feature = "tls-with-rustls",
    feature = "tls-with-tokio-native-tls",
    feature = "tls-with-tokio-rustls",
    feature = "tls-with-async-tls"
)))]
compile_error!("This demo requires one of the tls-with-xxx features to be enabled.");

mod config;
mod util;

use std::time::Duration;

use kmip_protocol::client::{Client, ClientCertificate, ConnectionSettings};
use kmip_protocol::types::traits::ReadWrite;
use log::info;
use structopt::StructOpt;
use util::init_logging;

use crate::{
    config::Opt,
    util::{SelfLoggingError, ToCsvString},
};

#[cfg(any(
    feature = "tls-with-openssl",
    feature = "tls-with-openssl-vendored",
    feature = "tls-with-rustls"
))]
fn main() {
    let opt = Opt::from_args();

    init_logging(&opt);

    cfg_if::cfg_if! {
        if #[cfg(any(feature = "tls-with-openssl", feature = "tls-with-openssl-vendored"))] {
            let client = kmip_protocol::client::tls::openssl::connect(opt.into());
        } else if #[cfg(feature = "tls-with-rustls")] {
            let client = kmip_protocol::client::tls::rustls::connect(opt.into());
        }
    }

    let mut thread_handles = vec![];

    for i in 0..=1 {
        let thread_client = client.clone();
        let handle = std::thread::spawn(move || {
            exec_test_requests(thread_client, &format!("test_{}", i)).unwrap();
        });
        thread_handles.push(handle);
    }

    for handle in thread_handles {
        handle.join().unwrap();
    }
}

#[cfg(feature = "tls-with-async-tls")]
#[async_std::main]
async fn main() {
    let opt = Opt::from_args();

    init_logging(&opt);

    let client = kmip_protocol::client::tls::async_tls::connect(opt.into()).await;

    exec_test_requests(client, "test").await.unwrap();
}

#[cfg(any(feature = "tls-with-tokio-native-tls", feature = "tls-with-tokio-rustls",))]
#[tokio::main]
async fn main() {
    let opt = Opt::from_args();

    init_logging(&opt);

    cfg_if::cfg_if! {
        if #[cfg(feature = "tls-with-tokio-native-tls")] {
            let client = kmip_protocol::client::tls::tokio_native_tls::connect(opt.into()).await;
        } else if #[cfg(feature = "tls-with-tokio-rustls")] {
            let client = kmip_protocol::client::tls::tokio_rustls::connect(opt.into()).await;
        }
    }

    exec_test_requests(client, "test").await.unwrap();
}

#[maybe_async::maybe_async]
async fn exec_test_requests<T: ReadWrite>(
    client: Client<T>,
    key_name_prefix: &str,
) -> Result<(), kmip_protocol::client::Error> {
    query_server_properties(&client).await?;

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
        .log_error(&client)
    {
        info!("Created key pair:");
        info!("  Private key ID: {}", private_key_id);
        info!("  Public key ID : {}", public_key_id);
        let mut key_needs_revoking = false;

        info!("Activating private key {}..", private_key_id);
        if client.activate_key(&private_key_id).await.log_error(&client).is_ok() {
            key_needs_revoking = true;

            info!("Signing with private key {}..", private_key_id);
            if let Ok(payload) = client
                .sign(&private_key_id, &[1u8, 2u8, 3u8, 4u8, 5u8])
                .await
                .log_error(&client)
            {
                info!("{}", hex::encode_upper(payload.signature_data));
            }
        }

        info!("Deleting public key {}..", public_key_id);
        client.destroy_key(&public_key_id).await.log_error(&client).ok();

        if key_needs_revoking {
            info!("Revoking private key {}..", private_key_id);
            client.revoke_key(&private_key_id).await.log_error(&client).ok();
        }

        info!("Deleting private key {}..", private_key_id);
        client.destroy_key(&private_key_id).await.log_error(&client).ok();
    }

    info!("Requesting 32 random bytes..");
    if let Ok(payload) = client.rng_retrieve(32).await.log_error(&client) {
        info!("{}", hex::encode_upper(payload.data));
    }

    Ok(())
}

#[maybe_async::maybe_async]
#[rustfmt::skip]
async fn query_server_properties<T: ReadWrite>(client: &Client<T>) -> Result<(), kmip_protocol::client::Error> {
    info!("Querying server properties..");
    let server_props = client.query().await?;

    info!("Server identification: {}", server_props.vendor_identification.unwrap_or("Not available".into()));
    info!("Server supported operations: {}", server_props.operations.to_csv_string());
    info!("Server supported object types: {}", server_props.object_types.to_csv_string());

    Ok(())
}

fn load_binary_file(path: &std::path::PathBuf) -> Vec<u8> {
    use std::{fs::File, io::Read};

    let mut bytes = Vec::new();
    File::open(path)
        .expect(&format!("Failed to open open file '{:?}'", path))
        .read_to_end(&mut bytes)
        .expect(&format!("Failed to read data from file '{:?}'", path));
    bytes
}

impl From<Opt> for ConnectionSettings {
    fn from(opt: Opt) -> Self {
        let password = std::env::var("HSM_PASSWORD").ok();

        let client_cert = {
            match (&opt.client_cert_path, &opt.client_key_path, &opt.client_pkcs12_path) {
                (None, None, None) => None,
                (None, None, Some(path)) => Some(ClientCertificate::CombinedPkcs12 {
                    cert_bytes: load_binary_file(path),
                }),
                (Some(path), None, None) => Some(ClientCertificate::SeparatePem {
                    cert_bytes: load_binary_file(path),
                    key_bytes: None,
                }),
                (None, Some(_), None) => {
                    panic!("Client certificate key path requires a client certificate path")
                }
                (_, Some(_), Some(_)) | (Some(_), _, Some(_)) => {
                    panic!("Use either but not both of: client certificate and key PEM file paths, or a PCKS#12 certficate file path")
                }
                (Some(cert_path), Some(key_path), None) => Some(ClientCertificate::SeparatePem {
                    cert_bytes: load_binary_file(cert_path),
                    key_bytes: Some(load_binary_file(key_path)),
                }),
            }
        };

        let server_cert = opt.server_cert_path.map(|path| load_binary_file(&path));
        let ca_cert = opt.ca_cert_path.map(|path| load_binary_file(&path));

        let connect_timeout = Some(Duration::from_secs(opt.connect_timeout));
        let read_timeout = Some(Duration::from_secs(opt.read_timeout));
        let write_timeout = Some(Duration::from_secs(opt.write_timeout));

        ConnectionSettings {
            host: opt.host,
            port: opt.port,
            username: opt.username,
            password,
            insecure: opt.insecure,
            client_cert,
            server_cert,
            ca_cert,
            connect_timeout,
            read_timeout,
            write_timeout,
            max_response_bytes: Some(4096),
        }
    }
}
