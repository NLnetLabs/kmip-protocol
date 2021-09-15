use std::{fs::OpenOptions, io::{Read, Write}, net::{TcpStream, ToSocketAddrs}, time::Duration};

use kmip_protocol::{Client, ClientBuilder, Config};
use log::{error, info};
use openssl::ssl::{SslConnector, SslFiletype, SslMethod, SslStream, SslVerifyMode};

use crate::config::{Opt, SSLKEYLOGFILE_ENV_VAR_NAME};

pub(crate) fn init_logging(opt: &Opt) {
    let level = match (opt.quiet, opt.verbose) {
        (true, _) => log::LevelFilter::Error,
        (false, 1) => log::LevelFilter::Debug,
        (false, n) if n >= 2 => log::LevelFilter::Trace,
        _ => log::LevelFilter::Info,
    };
    simple_logging::log_to_stderr(level);
}

pub(crate) fn connect(opt: Opt) -> Client<SslStream<TcpStream>> {
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

pub(crate) trait ToCsvString {
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

pub(crate) struct SelfDeletingKeyPair<'a, T: Read + Write> {
    client: &'a Client<T>,
    private_key_id: String,
    public_key_id: String,
    needs_revoking: bool,
}

impl<'a, T: Read + Write> SelfDeletingKeyPair<'a, T> {
    pub(crate) fn new(client: &'a Client<T>, private_key_id: String, public_key_id: String) -> Self {
        Self {
            client,
            private_key_id,
            public_key_id,
            needs_revoking: false,
        }
    }

    /// Get a reference to the self deleting key pair's private key id.
    pub(crate) fn private_key_id(&self) -> &str {
        self.private_key_id.as_str()
    }

    /// Get a reference to the self deleting key pair's public key id.
    pub(crate) fn public_key_id(&self) -> &str {
        self.public_key_id.as_str()
    }

    pub(crate) fn needs_revoking(&mut self) {
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

pub(crate) trait SelfLoggingError<T: Read + Write, U> {
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
