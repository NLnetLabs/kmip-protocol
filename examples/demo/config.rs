use std::path::PathBuf;

use structopt::StructOpt;

/// A StructOpt example
#[derive(StructOpt, Debug)]
#[structopt()]
#[rustfmt::skip]
pub(crate) struct Opt {
    /// Silence all output
    #[structopt(short = "q", long = "quiet")]
    pub(crate) quiet: bool,

    /// Verbose mode (-v, -vv, -vvv, etc)
    #[structopt(short = "v", long = "verbose", parse(from_occurrences), help = "Increase logging to DEBUG (-v) or TRACE (-vv) level")]
    pub(crate) verbose: usize,

    /// HSM host/domain name
    #[structopt(short = "h", long = "host", default_value = "localhost")]
    pub(crate) host: String,

    /// HSM port number
    #[structopt(short = "p", long = "port", default_value = "5696")]
    pub(crate) port: u16,

    /// HSM username
    #[structopt(short = "u", long = "user", help = "Specify an optional password in env var HSM_PASSWORD")]
    pub(crate) username: Option<String>,

    #[structopt(short = "i", long = "insecure", help = "Disable verification of the server certificate")]
    pub(crate) insecure: bool,

    #[structopt(long = "client-cert", parse(from_os_str), help = "Path to the client certificate file in PEM format")]
    pub(crate) client_cert_path: Option<PathBuf>,

    #[structopt(long = "client-key", parse(from_os_str), help = "Path to the client certificate key file in PEM format")]
    pub(crate) client_key_path: Option<PathBuf>,

    #[structopt(long = "client-cert-and-key", parse(from_os_str), help = "Path to the client certificate and key file in PKCS#12 format")]
    pub(crate) client_pkcs12_path: Option<PathBuf>,

    #[structopt(long = "server-cert", parse(from_os_str), help = "Path to the server certificate file in PEM format")]
    pub(crate) server_cert_path: Option<PathBuf>,

    #[structopt(long = "ca-cert", parse(from_os_str), help = "Path to the CA certificate file in PEM format")]
    pub(crate) ca_cert_path: Option<PathBuf>,

    /// TCP timeouts
    #[structopt(long = "connect-timeout", default_value = "5")]
    pub(crate) connect_timeout: u64,

    #[structopt(long = "read-timeout", default_value = "5")]
    pub(crate) read_timeout: u64,

    #[structopt(long = "write-timeout", default_value = "5")]
    pub(crate) write_timeout: u64,
}
