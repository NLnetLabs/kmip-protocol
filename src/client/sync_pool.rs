//! KMIP connection pool
//!
//! Used to:
//!  - Avoid repeated TCP connection setup and TLS session establishment
//!    for mutiple KMIP requests made close together in time.
//!  - Handle loss of connectivity by re-creating the connection when an
//!    existing connection is considered to be "broken" at the network
//!    level.
use core::fmt::Display;
use core::ops::Deref;
use std::string::String;
use std::{sync::Arc, time::Duration};

use crate::client::ConnectionSettings;

use log::error;
use r2d2::PooledConnection;

cfg_if::cfg_if! {
    if #[cfg(any(feature = "tls-with-openssl", feature = "tls-with-openssl-vendored"))] {
        use crate::client::tls::openssl::{Client, connect};
    } else if #[cfg(feature = "tls-with-rustls")] {
        use crate::client::tls::rustls::{Client, connect};
    } else {
        pub type Client = crate::client::Client<std::net::TcpStream>;
    }
}

//------------ KmipConnError -------------------------------------------------

#[derive(Clone, Debug)]
pub struct KmipConnError(String);

impl From<r2d2::Error> for KmipConnError {
    fn from(err: r2d2::Error) -> Self {
        Self(format!("{err}"))
    }
}

impl Display for KmipConnError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self.0)
    }
}

//------------ KmipConn ------------------------------------------------------

/// A KMIP connection pool connection.
pub struct KmipConn {
    conn: PooledConnection<ConnectionManager>,
}

impl KmipConn {
    fn new(conn: PooledConnection<ConnectionManager>) -> Self {
        Self { conn }
    }
}

impl Deref for KmipConn {
    type Target = Client;

    fn deref(&self) -> &Self::Target {
        self.conn.deref()
    }
}

/// A pool of already connected KMIP clients.
///
/// This pool can be used to acquire a KMIP client without first having to
/// wait for it to connect at the TCP/TLS level, and without unnecessarily
/// closing the connection when finished.
// TODO: Move this to the kmip-protocol crate and add an AsyncConnPool variant
// implemented using the bb8 crate instead of the r2d2 crate.
#[derive(Clone, Debug)]
pub struct SyncConnPool {
    server_id: String,
    conn_settings: Arc<ConnectionSettings>,
    pool: r2d2::Pool<ConnectionManager>,
}

impl SyncConnPool {
    pub fn new(
        server_id: String,
        conn_settings: Arc<ConnectionSettings>,
        max_conncurrent_connections: u32,
        max_life_time: Option<Duration>,
        max_idle_time: Option<Duration>,
    ) -> Result<SyncConnPool, KmipConnError> {
        let pool = r2d2::Pool::builder()
            // Don't pre-create idle connections to the KMIP server
            .min_idle(Some(0))
            // Create at most this many concurrent connections to the KMIP
            // server
            .max_size(max_conncurrent_connections)
            // Don't verify that a connection is usable when fetching it from
            // the pool (as doing so requires sending a request to the server
            // and we might as well just try the actual request that we want
            // the connection for)
            .test_on_check_out(false)
            // Don't use the default logging behaviour as `[ERROR] [r2d2]
            // Server error: ...` is a bit confusing for end users who
            // shouldn't know or care that we use the r2d2 crate.
            .error_handler(Box::new(ErrorLoggingHandler))
            // Don't keep using the same connection for longer than around N
            // minutes (unless in use in which case it will wait until the
            // connection is returned to the pool before closing it) - maybe
            // long held connections would run into problems with some
            // firewalls.
            .max_lifetime(max_life_time)
            // Don't keep connections open that were not used in the last N
            // minutes.
            .idle_timeout(max_idle_time)
            // Don't wait longer than N seconds for a new connection to be
            // established, instead try again to connect.
            .connection_timeout(conn_settings.connect_timeout.unwrap_or(Duration::from_secs(30)))
            // Use our connection manager to create connections in the pool
            // and to verify their health
            .build(ConnectionManager {
                conn_settings: conn_settings.clone(),
            })?;

        Ok(Self {
            server_id,
            conn_settings,
            pool,
        })
    }

    pub fn server_id(&self) -> &str {
        &self.server_id
    }

    pub fn conn_settings(&self) -> &ConnectionSettings {
        &self.conn_settings
    }

    pub fn get(&self) -> Result<KmipConn, KmipConnError> {
        Ok(KmipConn::new(self.pool.get()?))
    }
}

/// Manages KMIP TCP + TLS connection creation.
///
/// Uses the [r2d2] crate to manage a pool of connections.
///
/// [r2d2]: https://crates.io/crates/r2d2/
#[derive(Debug)]
pub struct ConnectionManager {
    conn_settings: Arc<ConnectionSettings>,
}

impl ConnectionManager
where
    Self: r2d2::ManageConnection,
{
    /// Create a pool of up-to N TCP + TLS connections to the KMIP server.
    #[rustfmt::skip]
    pub fn create_connection_pool(
        server_id: String,
        conn_settings: Arc<ConnectionSettings>,
        max_conncurrent_connections: u32,
        max_life_time: Option<Duration>,
        max_idle_time: Option<Duration>,
    ) -> Result<SyncConnPool, KmipConnError> {
        SyncConnPool::new(
            server_id,
            conn_settings,
            max_conncurrent_connections,
            max_life_time,
            max_idle_time,
        )
    }

    /// Connect using the given connection settings to a KMIP server.
    ///
    /// This function creates a new connection to the server. The connection
    /// is NOT taken from the connection pool.
    pub fn connect_one_off(settings: &ConnectionSettings) -> crate::client::Result<Client> {
        connect(settings)
    }
}

impl r2d2::ManageConnection for ConnectionManager {
    type Connection = Client;

    type Error = crate::client::Error;

    /// Establishes a KMIP server connection which will be added to the
    /// connection pool.
    fn connect(&self) -> Result<Self::Connection, Self::Error> {
        Self::connect_one_off(&self.conn_settings)
    }

    /// This function is never used because the [r2d2] `test_on_check_out`
    /// flag is set to false when the connection pool is created.
    ///
    /// [r2d2]: https://crates.io/crates/r2d2/
    fn is_valid(&self, _conn: &mut Self::Connection) -> Result<(), Self::Error> {
        unreachable!()
    }

    /// Quickly verify if an existing connection is broken.
    ///
    /// Used to discard and re-create connections that encounter multiple
    /// connection related errors.
    fn has_broken(&self, conn: &mut Self::Connection) -> bool {
        conn.connection_error_count() > 1
    }
}

/// Logs connection pool related connection error messages using the format
/// `"[<LEVEL>] Pool error: ..."` instead of
/// the default [r2d2] `"[ERROR] [r2d2] Server error: ..."` format. Assumes
/// that the logging framework will include the logging module context in the
/// logged message, i.e. `xxx::kmip::xxx` and thus we don't need to mention
/// KMIP in the logged message content.
///
/// Rationale:
///   - The use of the [r2d2] crate is an internal detail which of no use to
///     end users consulting the logs and which we may change at any time.
///   - Krill should be the one to determine the appropriate level to log a
///     connection issue at, not [r2d2].
#[derive(Debug)]
struct ErrorLoggingHandler;

impl<E> r2d2::HandleError<E> for ErrorLoggingHandler
where
    E: std::fmt::Display,
{
    fn handle_error(&self, err: E) {
        error!("Pool error: {}", err)
    }
}

#[cfg(test)]
mod tests {
    use std::{
        fs::File,
        io::{Read, Write},
        net::TcpListener,
    };

    cfg_if::cfg_if! {
        if #[cfg(any(feature = "tls-with-openssl", feature = "tls-with-openssl-vendored"))] {
            use crate::client::tls::openssl::connect_with_tcpstream_factory;
        } else if #[cfg(feature = "tls-with-rustls")] {
            use crate::client::tls::rustls::connect_with_tcpstream_factory;
        }
    }

    use rcgen::{CertifiedKey, generate_simple_self_signed};
    use rustls::{
        ServerConnection,
        pki_types::{PrivateKeyDer, pem::PemObject},
        server::ServerConfig,
    };

    use super::*;

    #[test]
    #[cfg(any(
        feature = "tls-with-openssl",
        feature = "tls-with-openssl-vendored",
        feature = "tls-with-rustls"
    ))]
    fn parse_pem_files_correctly() {
        // Server certificate was generated using command:
        //   rustls-cert-gen --country-name=NL --organization-name="NLnet Labs" --ed25519 --output=.
        //
        // Client certificate was generated using command.
        //   rustls-cert-gen --country-name=NL --organization-name="NLnet Labs" --ed25519 --output=. --client-auth --cert-file-name client-cert

        use crate::client::Error;

        let mut server_cert = vec![];
        File::open("test-data/cert.pem")
            .unwrap()
            .read_to_end(&mut server_cert)
            .unwrap();

        let mut ca_cert = vec![];
        File::open("test-data/root-ca.pem")
            .unwrap()
            .read_to_end(&mut ca_cert)
            .unwrap();

        let mut client_cert = vec![];
        File::open("test-data/client-cert.pem")
            .unwrap()
            .read_to_end(&mut client_cert)
            .unwrap();

        let mut client_key = vec![];
        File::open("test-data/client-cert.key.pem")
            .unwrap()
            .read_to_end(&mut client_key)
            .unwrap();

        let client_cert = crate::client::ClientCertificate::SeparatePem {
            cert_bytes: client_cert,
            key_bytes: client_key,
        };

        let conn_settings = ConnectionSettings {
            host: "localhost".to_string(),
            port: 12345,
            insecure: false,
            client_cert: Some(client_cert),
            server_cert: Some(server_cert),
            ca_cert: Some(ca_cert),
            ..Default::default()
        };

        static ERR_MSG: &str = "configured but will not connect due to being a test";
        let res = connect_with_tcpstream_factory(&conn_settings, |_addr, _settings| {
            Err(Error::InternalError(ERR_MSG.to_string()))
        });

        // If the configuration settings including the provided PEM files
        // were parsed successfully we should have proceeded to the connection
        // attempt which should result in our custom error message.
        assert_eq!(res.unwrap_err(), Error::InternalError(ERR_MSG.to_string()));
    }

    #[test]
    #[cfg(any(
        feature = "tls-with-openssl",
        feature = "tls-with-openssl-vendored",
        feature = "tls-with-rustls"
    ))]
    fn set_sni_server_name() {
        #[allow(non_snake_case)]
        let EXPECTED_SNI_NAME: String = "my.server.name".to_string();

        // Spin up the TLS server.
        let (listen_addr, server_handle) = mock_tls_server();

        // Connect to the TLS server.
        let conn_settings = ConnectionSettings {
            host: listen_addr.ip().to_string(),
            port: listen_addr.port(),
            insecure: true,
            server_name: Some(EXPECTED_SNI_NAME.clone()),
            ..Default::default()
        };

        cfg_if::cfg_if! {
            if #[cfg(any(feature = "tls-with-openssl", feature = "tls-with-openssl-vendored"))] {
                let client = crate::client::tls::openssl::connect(&conn_settings).unwrap();
            } else if #[cfg(feature = "tls-with-rustls")] {
                let client = crate::client::tls::rustls::connect(&conn_settings).unwrap();
            }
        }

        // Make a request to the server, any request, we don't care if it
        // succeeds or not,
        let _ = client.create_rsa_key_pair(2048, "pri".into(), "pub".into());

        // Wait for the server to exit.
        let seen_sni_name = server_handle.join().unwrap();

        // Verify the seen SNI name.
        assert_eq!(seen_sni_name, Some(EXPECTED_SNI_NAME));
    }

    fn mock_tls_server() -> (std::net::SocketAddr, std::thread::JoinHandle<Option<String>>) {
        // Generate a self-signed TLS certificate.
        let subject_alt_names = vec!["hello.world.example".to_string(), "localhost".to_string()];
        let CertifiedKey { cert, signing_key } = generate_simple_self_signed(subject_alt_names).unwrap();

        // Convert the cert and key to the format required by RustLS.
        let certs = vec![cert.der().clone()];
        let key = PrivateKeyDer::from_pem_slice(signing_key.serialize_pem().as_bytes()).unwrap();

        // Build TLS server configuration
        let config = ServerConfig::builder()
            .with_no_client_auth() // Standard TLS (no client cert required)
            .with_single_cert(certs, key)
            .unwrap();

        // Listen for incoming TCP connections on some port.
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let local_addr = listener.local_addr().unwrap();

        // Accept a single incoming connection and process it as TLS.
        let handle = std::thread::spawn(move || {
            let (mut tcp_stream, _) = listener.accept().unwrap();
            eprintln!("Connection received");
            let mut conn = ServerConnection::new(Arc::new(config)).unwrap();
            eprintln!("TLS connection accepted");

            // Receive a KMIP ReqeustMessage from the client.
            let mut tls_stream = rustls::Stream::new(&mut conn, &mut tcp_stream);
            let mut buf = [0; 64];
            let len = tls_stream.read(&mut buf).unwrap();

            // Verify receipt of the RequestMessage TTLV tag.
            assert!(len >= 3);
            assert_eq!(&buf[0..3], &[0x42, 0x00, 0x78]);

            // Verify that the expected SNI name was sent.
            let sni_name = tls_stream.conn.server_name().map(ToString::to_string);

            // Politely close the connection to prevent warnings from the
            // client about close notify not being sent by the serer.
            tls_stream.conn.send_close_notify();
            tls_stream.flush().unwrap();

            sni_name
        });

        // Return the listen address and thread handle to the caller
        (local_addr, handle)
    }
}
