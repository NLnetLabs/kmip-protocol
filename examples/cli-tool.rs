use std::net::TcpStream;

use krill_kmip_protocol::ClientBuilder;
use log::{error, info};
use openssl::ssl::{SslConnector, SslMethod, SslVerifyMode};
use stderrlog::Timestamp;
use structopt::StructOpt;

/// A StructOpt example
#[derive(StructOpt, Debug)]
#[structopt()]
struct Opt {
    /// Silence all output
    #[structopt(short = "q", long = "quiet")]
    quiet: bool,

    /// Verbose mode (-v, -vv, -vvv, etc)
    #[structopt(short = "v", long = "verbose", parse(from_occurrences))]
    verbose: usize,

    /// HSM host/domain name
    #[structopt(short = "h", long = "host", default_value = "localhost")]
    host: String,

    /// HSM port number
    #[structopt(short = "p", long = "port", default_value = "5696")]
    port: u16,
}

fn main() {
    let opt = Opt::from_args();

    stderrlog::new()
        .module(module_path!())
        .module("krill_kmip_protocol")
        .module("krill_kmip_ttlv")
        .quiet(opt.quiet)
        .verbosity(opt.verbose)
        .timestamp(Timestamp::Second)
        .init()
        .unwrap();

    let mut connector = SslConnector::builder(SslMethod::tls()).unwrap();
    connector.set_verify(SslVerifyMode::NONE);
    let connector = connector.build();
    let host = std::env::var("KRYPTUS_HOST").unwrap();
    let port = std::env::var("KRYPTUS_PORT").unwrap();
    let stream = TcpStream::connect(format!("{}:{}", host, port)).unwrap();
    let mut tls = connector.connect(&host, stream).unwrap();

    let mut client = ClientBuilder::new(&mut tls)
        .with_credentials(
            &std::env::var("KRYPTUS_USER").unwrap(),
            Some(&std::env::var("KRYPTUS_PASS").unwrap()),
        )
        .unwrap();

    info!("Querying server properties..");
    info!("{:?}", client.query().unwrap());

    if let Ok((private_key_id, public_key_id)) =
        client.create_rsa_key_pair(2048, "my_private_key".into(), "my_public_key".into())
    {
        info!("Created key pair:");
        info!("  Private key ID: {}", private_key_id);
        info!("  Public key ID : {}", public_key_id);

        info!("Activating private key..");
        if client.activate_key(&private_key_id).is_ok() {
            info!("Signing with private key..");
            if let Ok(payload) = client.sign(&private_key_id, &[1u8, 2u8, 3u8, 4u8, 5u8]) {
                info!("{}", hex::encode_upper(payload.signature_data));
            } else {
                error!("Signing failed");
            }
            info!("Revoking private key..");
            client.revoke_key(&private_key_id).ok();
        }

        info!("Deleting public key..");
        client.destroy_key(&public_key_id).ok();

        info!("Deleting private key..");
        client.destroy_key(&private_key_id).ok();
    }

    info!("Requesting 32 random bytes..");
    if let Ok(payload) = client.rng_retrieve(32) {
        info!("{}", hex::encode_upper(payload.data));
    } else {
        error!("Request for 32 random bytes failed");
    }
}
