use std::time::Duration;

#[derive(Clone, Default, Debug, PartialEq, Eq)]
pub struct TlsClientAuth {
    /// Client certificate bytes in PEM format.
    pub cert_bytes: Vec<u8>,

    /// Client private key bytes in PEM format.
    pub private_key_bytes: Vec<u8>,
}

#[derive(Clone, Default, Debug, PartialEq, Eq)]
pub enum TlsServerAuth {
    /// Do not verify the identify of the server.
    None,

    /// Use only certificates provided in the default trust store.
    #[default]
    Default,

    /// The PEM encoded bytes of a certificate to trurst directly, e.g. a
    /// self-signed certificate.
    ///
    /// TODO: Add support for verifying certificates by their fingerprint.
    TrustCertificate(Vec<u8>),

    /// The PEM encoded bytes of the certificate of a Certificate Authority
    /// to add to the certificate trust store in order to be able to verify
    /// certificates issued by this authority, e.g. an in-house custom CA
    /// not present in the default trust store.
    TrustCertificateAuthority(Vec<u8>),
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

    /// Details needed to enable the TLS client to respond to a challenge from
    /// the server for the client to prove its identity.
    pub tls_client_auth: Option<TlsClientAuth>,

    /// Details used to verify the identify of the TLS server.
    pub tls_server_auth: TlsServerAuth,

    /// Server name for use with TLS SNI to direct the server to identify
    /// itself using a particular certificate, for servers that have more
    /// than one.
    pub tls_server_name: Option<String>,

    /// TCP connect timeout
    pub connect_timeout: Option<Duration>,

    /// TCP read timeout
    pub read_timeout: Option<Duration>,

    /// TCP write timeout
    pub write_timeout: Option<Duration>,

    /// Maximum number of HSM response bytes to accept
    pub max_response_bytes: Option<u32>,
}
