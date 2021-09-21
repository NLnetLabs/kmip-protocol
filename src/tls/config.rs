use std::time::Duration;

#[derive(Debug)]
pub enum ClientCertificate {
    SeparatePem {
        cert_bytes: Vec<u8>,
        key_bytes: Option<Vec<u8>>,
    },
    CombinedPkcs12 {
        cert_bytes: Vec<u8>,
    },
}

#[derive(Default, Debug)]
pub struct Config {
    /// HSM host/domain name
    pub host: String,

    /// HSM port number
    pub port: u16,

    /// HSM username
    pub username: Option<String>,

    /// HSM password
    pub password: Option<String>,

    /// Disable security features such as server certificate verification
    pub insecure: bool,

    /// Client certificate authentication
    pub client_cert: Option<ClientCertificate>,

    /// Server certificate bytes in PEM format
    pub server_cert: Option<Vec<u8>>,

    /// Server CA certificate bytes in PEM format
    pub ca_cert: Option<Vec<u8>>,

    /// TCP connect timeout
    pub connect_timeout: Option<Duration>,

    /// TCP read timeout
    pub read_timeout: Option<Duration>,

    /// TCP write timeout
    pub write_timeout: Option<Duration>,

    /// Maximum number of HSM response bytes to accept
    pub max_response_bytes: Option<u32>,
}
