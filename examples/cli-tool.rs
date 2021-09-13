use std::{
    net::{TcpStream, ToSocketAddrs},
    path::PathBuf,
    time::Duration,
};

use kmip_protocol::{Client, ClientBuilder};
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

    /// TCP timeouts
    #[structopt(long = "connect-timeout", default_value = "2")]
    connect_timeout: u64,

    #[structopt(long = "read-timeout", default_value = "2")]
    read_timeout: u64,

    #[structopt(long = "write-timeout", default_value = "2")]
    write_timeout: u64,
}

fn main() -> kmip_protocol::client::Result<()> {
    let opt = Opt::from_args();

    stderrlog::new()
        .module(module_path!())
        .module("kmip_protocol")
        .module("kmip_ttlv")
        .quiet(opt.quiet)
        .verbosity(opt.verbose + 2) // show INFO level logging by default, use -q to silence this
        .timestamp(Timestamp::Second)
        .init()
        .expect("Failed to initialize logging");

    let addr = format!("{}:{}", opt.host, opt.port)
        .to_socket_addrs()
        .expect("Error parsing host and port")
        .next()
        .expect("Internal error fetching parsed host and port from iterator");

    let password = std::env::var("HSM_PASSWORD").ok();

    info!("Establishing TLS connection to server..");

    let tcp_stream = TcpStream::connect_timeout(&addr, Duration::new(opt.connect_timeout, 0))
        .expect("Failed to connect to host with timeout");
    tcp_stream
        .set_read_timeout(Some(Duration::new(opt.read_timeout, 0)))
        .expect("Failed to set read timeout on TCP connection");
    tcp_stream
        .set_write_timeout(Some(Duration::new(opt.write_timeout, 0)))
        .expect("Failed to set write timeout on TCP connection");

    let tls_client = create_tls_client(&opt).expect("Failed to create TLS client");

    let tls_stream = tls_client
        .connect(&opt.host, tcp_stream)
        .expect("Failed to establish TLS connection");

    let mut client = create_kmip_client(tls_stream, opt, password);

    info!("Querying server properties..");
    let server_props = client.query()?;
    info!(
        "Server identification: {}",
        server_props.vendor_identification.unwrap_or("Not available".into())
    );
    info!(
        "Server supported operations: {}",
        server_props
            .operations
            .unwrap_or(Vec::new())
            .iter()
            .map(|op| op.to_string())
            .collect::<Vec<String>>()
            .join(", ")
    );
    info!(
        "Server supported object types: {}",
        server_props
            .object_types
            .unwrap_or(Vec::new())
            .iter()
            .map(|obj_typ| obj_typ.to_string())
            .collect::<Vec<String>>()
            .join(", ")
    );

    info!("Creating RSA key pair");
    match client.create_rsa_key_pair(2048, "my_private_key".into(), "my_public_key".into()) {
        Err(err) => error!("{}", err),
        Ok((private_key_id, public_key_id)) => {
            info!("Created key pair:");
            info!("  Private key ID: {}", private_key_id);
            info!("  Public key ID : {}", public_key_id);

            info!("Activating private key..");
            match client.activate_key(&private_key_id) {
                Err(err) => error!("{}", err),
                Ok(()) => {
                    info!("Signing with private key..");
                    match client.sign(&private_key_id, &[1u8, 2u8, 3u8, 4u8, 5u8]) {
                        Err(err) => error!("{}", err),
                        Ok(payload) => info!("{}", hex::encode_upper(payload.signature_data)),
                    }

                    info!("Revoking private key..");
                    client.revoke_key(&private_key_id).ok();
                }
            }

            info!("Deleting public key..");
            if let Err(err) = client.destroy_key(&public_key_id) {
                error!("{}", err);
            }

            info!("Deleting private key..");
            if let Err(err) = client.destroy_key(&private_key_id) {
                error!("{}", err);
            }
        }
    }

    info!("Requesting 32 random bytes..");
    match client.rng_retrieve(32) {
        Err(err) => error!("{}", err),
        Ok(payload) => info!("{}", hex::encode_upper(payload.data)),
    }

    Ok(())
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
    client.build()
}

fn create_tls_client(opt: &Opt) -> Result<SslConnector, openssl::error::ErrorStack> {
    let mut connector = SslConnector::builder(SslMethod::tls())?;
    connector.set_verify(SslVerifyMode::NONE);
    if opt.insecure {
        connector.set_verify(SslVerifyMode::NONE);
    }
    if let Some(path) = &opt.client_cert_path {
        connector.set_certificate_file(path, SslFiletype::PEM)?;
    }
    if let Some(path) = &opt.client_key_path {
        connector.set_private_key_file(path, SslFiletype::PEM)?;
    }
    Ok(connector.build())
}
