mod config;
mod util;

use std::net::TcpStream;

use kmip_protocol::Client;
use log::info;
use openssl::ssl::SslStream;
use structopt::StructOpt;
use util::{connect, init_logging};

use crate::{
    config::Opt,
    util::{SelfDeletingKeyPair, SelfLoggingError, ToCsvString},
};

fn main() -> kmip_protocol::client::Result<()> {
    let opt = Opt::from_args();

    init_logging(&opt);

    let client = connect(opt);

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

    Ok(())
}

fn exec_test_requests(
    client: Client<SslStream<TcpStream>>,
    key_name_prefix: &str,
) -> Result<(), kmip_protocol::client::Error> {
    query_server_properties(&client)?;

    info!("Creating RSA key pair");
    if let Ok((private_key_id, public_key_id)) = client
        .create_rsa_key_pair(
            2048,
            format!("{}_private_key", key_name_prefix),
            format!("{}_public_key", key_name_prefix),
        )
        .log_error(&client)
    {
        // This key pair will be deleted when this variable goes out of scope, and if needed the key will be revoked
        // prior to attempting to delete it (which would fail otherwise).
        let mut key = SelfDeletingKeyPair::new(&client, private_key_id, public_key_id);

        info!("Created key pair:");
        info!("  Private key ID: {}", key.private_key_id());
        info!("  Public key ID : {}", key.public_key_id());

        info!("Activating private key {}..", key.private_key_id());
        if client.activate_key(key.private_key_id()).log_error(&client).is_ok() {
            // Let the self-deleting key know it needs to revoke the key first
            key.needs_revoking();

            info!("Signing with private key {}..", key.private_key_id());
            if let Ok(payload) = client
                .sign(&key.private_key_id(), &[1u8, 2u8, 3u8, 4u8, 5u8])
                .log_error(&client)
            {
                info!("{}", hex::encode_upper(payload.signature_data));
            }
        }
    }

    info!("Requesting 32 random bytes..");
    if let Ok(payload) = client.rng_retrieve(32).log_error(&client) {
        info!("{}", hex::encode_upper(payload.data));
    }

    Ok(())
}

#[rustfmt::skip]
fn query_server_properties(client: &Client<SslStream<TcpStream>>) -> Result<(), kmip_protocol::client::Error> {
    info!("Querying server properties..");
    let server_props = client.query()?;

    info!("Server identification: {}", server_props.vendor_identification.unwrap_or("Not available".into()));
    info!("Server supported operations: {}", server_props.operations.to_csv_string());
    info!("Server supported object types: {}", server_props.object_types.to_csv_string());

    Ok(())
}
