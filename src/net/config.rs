use std::time::Duration;

#[derive(Clone, Default, Debug, PartialEq, Eq)]
pub struct TlsClientAuth {
    /// Client certificate bytes in PEM format.
    pub cert_bytes: Vec<u8>,

    /// Client private key bytes in PEM format.
    pub private_key_bytes: Vec<u8>,
}

#[derive(Clone, Default, Debug, PartialEq, Eq)]
pub struct TlsServerAuth {
    /// Server certificate bytes in PEM format.
    pub cert_bytes: Vec<u8>,

    /// Server name for TLS SNI certificate matching.
    pub server_name: Option<String>,

    /// Server CA certificate bytes in PEM format.
    pub ca_cert_bytes: Option<Vec<u8>>,
}

/// TCP and TLS settings for connecting to a KMIP server.
#[derive(Clone, Default, Debug, PartialEq, Eq)]
pub struct ConnectionSettings {
    /// HSM host/domain name/IP address.
    pub host: String,

    /// HSM port number.
    pub port: u16,

    /// HSM username
    pub username: Option<String>,

    /// HSM password
    pub password: Option<String>,

    /// TLS client authentication.
    pub tls_client_auth: Option<TlsClientAuth>,

    /// TLS server authentication.
    ///
    /// If None, the server certificate will not be verified.
    pub tls_server_auth: Option<TlsServerAuth>,

    /// TCP connect timeout
    pub connect_timeout: Option<Duration>,

    /// TCP read timeout
    pub read_timeout: Option<Duration>,

    /// TCP write timeout
    pub write_timeout: Option<Duration>,

    /// Maximum number of HSM response bytes to accept
    pub max_response_bytes: Option<u32>,
}
