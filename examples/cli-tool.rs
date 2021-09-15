use std::{
    fs::OpenOptions,
    io::{Read, Write},
    net::{TcpStream, ToSocketAddrs},
    path::PathBuf,
    time::Duration,
};

use kmip_protocol::{Client, ClientBuilder, Config};
use log::{error, info};
use openssl::ssl::{SslConnector, SslFiletype, SslMethod, SslStream, SslVerifyMode};
use structopt::StructOpt;

const SSLKEYLOGFILE_ENV_VAR_NAME: &'static str = "SSLKEYLOGFILE";

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
    #[structopt(long = "connect-timeout", default_value = "5")]
    connect_timeout: u64,

    #[structopt(long = "read-timeout", default_value = "5")]
    read_timeout: u64,

    #[structopt(long = "write-timeout", default_value = "5")]
    write_timeout: u64,
}

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
        let mut key = SelfDeletingKeyPair::new(&client, private_key_id, public_key_id);

        info!("Created key pair:");
        info!("  Private key ID: {}", key.private_key_id());
        info!("  Public key ID : {}", key.public_key_id());

        info!("Activating private key {}..", key.private_key_id());
        if client.activate_key(key.private_key_id()).log_error(&client).is_ok() {
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

fn query_server_properties(client: &Client<SslStream<TcpStream>>) -> Result<(), kmip_protocol::client::Error> {
    info!("Querying server properties..");
    let server_props = client.query()?;
    info!(
        "Server identification: {}",
        server_props.vendor_identification.unwrap_or("Not available".into())
    );
    info!(
        "Server supported operations: {}",
        server_props.operations.to_csv_string()
    );
    info!(
        "Server supported object types: {}",
        server_props.object_types.to_csv_string()
    );
    Ok(())
}

fn init_logging(opt: &Opt) {
    let level = match (opt.quiet, opt.verbose) {
        (true, _) => log::LevelFilter::Error,
        (false, 1) => log::LevelFilter::Debug,
        (false, n) if n >= 2 => log::LevelFilter::Trace,
        _ => log::LevelFilter::Info,
    };
    simple_logging::log_to_stderr(level);
        // .module(module_path!())
        // .module("kmip_protocol")
        // .module("kmip_ttlv")
        // .quiet(opt.quiet)
        // .verbosity(opt.verbose + 2) // show INFO level logging by default, use -q to silence this
        // .timestamp(Timestamp::Second)
        // .init()
        // .expect("Failed to initialize logging");
}

fn connect(opt: Opt) -> Client<SslStream<TcpStream>> {
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
    create_kmip_client(tls_stream, opt, password)
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
    client = client.with_reader_config(Config::default().with_max_bytes(4096).with_read_buf());
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
    if std::env::var(SSLKEYLOGFILE_ENV_VAR_NAME).is_ok() {
        connector.set_keylog_callback(|_, line| {
            if let Ok(path) = std::env::var(SSLKEYLOGFILE_ENV_VAR_NAME) {
                if let Ok(mut file) = OpenOptions::new().write(true).append(true).open(path) {
                    writeln!(file, "{}", line).ok();
                }
            }
        });
    }
    Ok(connector.build())
}

trait ToCsvString {
    fn to_csv_string(self) -> String;
}

impl<T> ToCsvString for Option<Vec<T>>
where
    T: ToString,
{
    fn to_csv_string(self) -> String {
        self.unwrap_or(Vec::new())
            .iter()
            .map(|op| op.to_string())
            .collect::<Vec<String>>()
            .join(", ")
    }
}

struct SelfDeletingKeyPair<'a, T: Read + Write> {
    client: &'a Client<T>,
    private_key_id: String,
    public_key_id: String,
    needs_revoking: bool,
}

impl<'a, T: Read + Write> SelfDeletingKeyPair<'a, T> {
    fn new(client: &'a Client<T>, private_key_id: String, public_key_id: String) -> Self {
        Self {
            client,
            private_key_id,
            public_key_id,
            needs_revoking: false,
        }
    }

    /// Get a reference to the self deleting key pair's private key id.
    fn private_key_id(&self) -> &str {
        self.private_key_id.as_str()
    }

    /// Get a reference to the self deleting key pair's public key id.
    fn public_key_id(&self) -> &str {
        self.public_key_id.as_str()
    }

    pub fn needs_revoking(&mut self) {
        self.needs_revoking = true;
    }
}

impl<'a, T: Read + Write> Drop for SelfDeletingKeyPair<'a, T> {
    fn drop(&mut self) {
        info!("Deleting public key {}..", self.public_key_id);
        self.client.destroy_key(&self.public_key_id).log_error(self.client).ok();

        if self.needs_revoking {
            info!("Revoking private key {}..", self.private_key_id);
            self.client.revoke_key(&self.private_key_id).log_error(self.client).ok();
        }

        info!("Deleting private key {}..", self.private_key_id);
        self.client
            .destroy_key(&self.private_key_id)
            .log_error(self.client)
            .ok();
    }
}

trait SelfLoggingError<T: Read + Write, U> {
    fn log_error(self, client: &Client<T>) -> Self;
}

impl<T: Read + Write, U> SelfLoggingError<T, U> for kmip_protocol::client::Result<U> {
    fn log_error(self, client: &Client<T>) -> Self {
        if let Err(err) = &self {
            error!(
                "{}: [req: {:?}, res: {:?}]",
                err,
                client.last_req_diag_str(),
                client.last_res_diag_str()
            );
        }
        self
    }
}
