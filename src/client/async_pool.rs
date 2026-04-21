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
use std::future::Future;
use std::string::String;
use std::{sync::Arc, time::Duration};

use crate::client::ConnectionSettings;

use bb8::PooledConnection;

cfg_if::cfg_if! {
    if #[cfg(feature = "tls-with-tokio-rustls")] {
        use crate::client::tls::tokio_rustls::{Client, connect};
    } else if #[cfg(feature = "tls-with-tokio-native-tls")] {
        use crate::client::tls::tokio_native_tls::{Client, connect};
    } else if #[cfg(feature = "async-with-tokio")] {
        pub type Client = crate::client::Client<tokio::net::TcpStream>;
    } else if #[cfg(feature = "async-with-async-std")] {
        use crate::client::Client;
    } else {
        unreachable!();
    }
}

//------------ KmipConnError -------------------------------------------------

#[derive(Clone, Debug)]
pub struct KmipConnError(String);

impl From<crate::client::Error> for KmipConnError {
    fn from(err: crate::client::Error) -> Self {
        KmipConnError(err.to_string())
    }
}

impl<E: std::error::Error + 'static> From<bb8::RunError<E>> for KmipConnError {
    fn from(err: bb8::RunError<E>) -> Self {
        KmipConnError(format!("{err}"))
    }
}

impl Display for KmipConnError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self.0)
    }
}

//------------ KmipConn ------------------------------------------------------

/// A KMIP connection pool connection.
pub struct KmipConn<'a> {
    conn: PooledConnection<'a, ConnectionManager>,
}

impl<'a> KmipConn<'a> {
    fn new(conn: PooledConnection<'a, ConnectionManager>) -> Self {
        Self { conn }
    }
}

impl<'a> Deref for KmipConn<'a> {
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
// implemented using the bb8 crate instead of the bb8 crate.
#[derive(Clone, Debug)]
pub struct AsyncConnPool {
    server_id: String,
    conn_settings: Arc<ConnectionSettings>,
    pool: bb8::Pool<ConnectionManager>,
}

impl AsyncConnPool {
    pub async fn new(
        server_id: String,
        conn_settings: Arc<ConnectionSettings>,
        max_conncurrent_connections: u32,
        max_life_time: Option<Duration>,
        max_idle_time: Option<Duration>,
    ) -> Result<AsyncConnPool, KmipConnError> {
        let pool = bb8::Pool::builder()
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
            })
            .await?;

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

    pub async fn get(&self) -> Result<KmipConn<'_>, KmipConnError> {
        Ok(KmipConn::new(self.pool.get().await?))
    }
}

/// Manages KMIP TCP + TLS connection creation.
///
/// Uses the [bb8] crate to manage a pool of connections.
///
/// [bb8]: https://crates.io/crates/bb8/
#[derive(Debug)]
pub struct ConnectionManager {
    conn_settings: Arc<ConnectionSettings>,
}

impl ConnectionManager
where
    Self: bb8::ManageConnection,
{
    /// Create a pool of up-to N TCP + TLS connections to the KMIP server.
    #[rustfmt::skip]
    pub async fn create_connection_pool(
        server_id: String,
        conn_settings: Arc<ConnectionSettings>,
        max_conncurrent_connections: u32,
        max_life_time: Option<Duration>,
        max_idle_time: Option<Duration>,
    ) -> Result<AsyncConnPool, KmipConnError> {
        AsyncConnPool::new(
            server_id,
            conn_settings,
            max_conncurrent_connections,
            max_life_time,
            max_idle_time,
        ).await
    }

    /// Connect using the given connection settings to a KMIP server.
    ///
    /// This function creates a new connection to the server. The connection
    /// is NOT taken from the connection pool.
    async fn connect_one_off(settings: &ConnectionSettings) -> crate::client::Result<Client> {
        connect(settings).await
    }
}

impl bb8::ManageConnection for ConnectionManager {
    type Connection = Client;

    type Error = crate::client::Error;

    /// Establishes a KMIP server connection which will be added to the
    /// connection pool.
    fn connect(&self) -> impl Future<Output = Result<Self::Connection, Self::Error>> + Send {
        Self::connect_one_off(&self.conn_settings)
    }

    /// This function is never used because the [bb8] `test_on_check_out`
    /// flag is set to false when the connection pool is created.
    ///
    /// [bb8]: https://crates.io/crates/bb8/
    fn is_valid(&self, _conn: &mut Self::Connection) -> impl Future<Output = Result<(), Self::Error>> + Send {
        unreachable!();

        // Weird workaround, without this this fn won't compile because () is not a future.
        #[allow(unreachable_code)]
        std::future::ready(Ok(()))
    }

    /// Quickly verify if an existing connection is broken.
    ///
    /// Used to discard and re-create connections that encounter multiple
    /// connection related errors.
    fn has_broken(&self, conn: &mut Self::Connection) -> bool {
        conn.connection_error_count() > 1
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_pool() {
        todo!()
    }
}
