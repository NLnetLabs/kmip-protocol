use std::{net::TcpStream, path::PathBuf};

use krill_kmip_protocol::{Client, ClientBuilder};
use log::{error, info};
use openssl::ssl::{SslConnector, SslFiletype, SslMethod, SslStream, SslVerifyMode};
use stderrlog::Timestamp;
use structopt::StructOpt;

/// A StructOpt example
#[derive(StructOpt, Debug)]
#[structopt()]
#[rustfmt::skip]
struct Opt {
    /// Silence all output
    #[structopt(short = "q", long = "quiet")]
    quiet: bool,

    /// Verbose mode (-v, -vv, -vvv, etc)
    #[structopt(short = "v", long = "verbose", parse(from_occurrences), help = "Increase logging to DEBUG (-v) or TRACE (-vv) level")]
    verbose: usize,

    /// HSM host/domain name
    #[structopt(short = "h", long = "host", default_value = "localhost")]
    host: String,

    /// HSM port number
    #[structopt(short = "p", long = "port", default_value = "5696")]
    port: u16,

    /// HSM username
    #[structopt(short = "u", long = "user", help = "Specify an optional password in env var HSM_PASSWORD")]
    username: Option<String>,

    #[structopt(short = "i", long = "insecure", help = "Disable verification of the server certificate")]
    insecure: bool,

    #[structopt(short = "c", long = "client-cert", parse(from_os_str), help = "Path to the client certificate file in PEM format")]
    client_cert_path: Option<PathBuf>,

    #[structopt(short = "k", long = "client-key", parse(from_os_str), help = "Path to the client certifcate key file in PEM format")]
    client_key_path: Option<PathBuf>,
}

fn main() {
    let opt = Opt::from_args();

    stderrlog::new()
        .module(module_path!())
        .module("krill_kmip_protocol")
        .module("krill_kmip_ttlv")
        .quiet(opt.quiet)
        .verbosity(opt.verbose + 2) // show INFO level logging by default, use -q to silence this
        .timestamp(Timestamp::Second)
        .init()
        .unwrap();

    let password = std::env::var("HSM_PASSWORD").ok();
    let tls_client = create_tls_client(&opt);
    let tcp_stream = TcpStream::connect(format!("{}:{}", opt.host, opt.port)).unwrap();
    let tls_stream = tls_client.connect(&opt.host, tcp_stream).unwrap();
    let mut client = create_kmip_client(tls_stream, opt, password);

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

fn create_kmip_client<'a>(
    tls_stream: SslStream<TcpStream>,
    opt: Opt,
    password: Option<String>,
) -> Client<SslStream<TcpStream>> {
    let mut client = ClientBuilder::new(tls_stream);
    if let Some(username) = opt.username {
        client = client.with_credentials(username, password);
    }
    client.configure()
}

fn create_tls_client(opt: &Opt) -> SslConnector {
    let mut connector = SslConnector::builder(SslMethod::tls()).unwrap();
    connector.set_verify(SslVerifyMode::NONE);
    if opt.insecure {
        connector.set_verify(SslVerifyMode::NONE);
    }
    if let Some(path) = &opt.client_cert_path {
        connector.set_certificate_file(path, SslFiletype::PEM).unwrap();
    }
    if let Some(path) = &opt.client_key_path {
        connector.set_private_key_file(path, SslFiletype::PEM).unwrap();
    }
    connector.build()
}
