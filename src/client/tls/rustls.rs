use std::{
    net::{TcpStream, ToSocketAddrs},
    sync::Arc,
};

use crate::client::tls::common::{rustls::create_rustls_config, util::create_kmip_client};

use crate::client::{Client, ConnectionSettings};

use log::info;
use rustls::{ClientConfig, ClientSession, StreamOwned};

pub fn connect(conn_settings: ConnectionSettings) -> Client<StreamOwned<ClientSession, TcpStream>> {
    let addr = format!("{}:{}", conn_settings.host, conn_settings.port)
        .to_socket_addrs()
        .expect("Error parsing host and port")
        .next()
        .expect("Internal error fetching parsed host and port from iterator");

    info!("Establishing TLS connection to server..");
    let rustls_config: ClientConfig = create_rustls_config(&conn_settings).expect("Failed to create RustLS config");
    let hostname = webpki::DNSNameRef::try_from_ascii_str(&conn_settings.host)
        .expect(&format!("Failed to parse hostname '{}'", conn_settings.host));
    let sess = rustls::ClientSession::new(&Arc::new(rustls_config), hostname);
    let tcp_stream = TcpStream::connect(&addr).expect("Failed to connect to host");
    let tls_stream = StreamOwned::new(sess, tcp_stream);

    create_kmip_client(tls_stream, conn_settings)
}
