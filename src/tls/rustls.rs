use std::{
    net::{TcpStream, ToSocketAddrs},
    sync::Arc,
};

use crate::{tls::rustls_common::create_rustls_config, Config as KmipConfig};

use crate::tls::{config::Config, Client, ClientBuilder};

use log::info;
use rustls::{ClientConfig, ClientSession, StreamOwned};

pub fn connect(config: Config) -> Client<StreamOwned<ClientSession, TcpStream>> {
    let addr = format!("{}:{}", config.host, config.port)
        .to_socket_addrs()
        .expect("Error parsing host and port")
        .next()
        .expect("Internal error fetching parsed host and port from iterator");

    info!("Establishing TLS connection to server..");
    let rustls_config: ClientConfig = create_rustls_config(&config).expect("Failed to create RustLS config");
    let hostname = webpki::DNSNameRef::try_from_ascii_str(&config.host)
        .expect(&format!("Failed to parse hostname '{}'", config.host));
    let sess = rustls::ClientSession::new(&Arc::new(rustls_config), hostname);
    let tcp_stream = TcpStream::connect(&addr).expect("Failed to connect to host");
    let tls_stream = StreamOwned::new(sess, tcp_stream);

    create_kmip_client(tls_stream, config)
}

fn create_kmip_client(
    tls_stream: StreamOwned<ClientSession, TcpStream>,
    config: Config,
) -> Client<StreamOwned<ClientSession, TcpStream>> {
    let mut client = ClientBuilder::new(tls_stream);

    if let Some(username) = config.username {
        client = client.with_credentials(username, config.password);
    }

    if let Some(max_bytes) = config.max_response_bytes {
        let reader_config = KmipConfig::default().with_max_bytes(max_bytes).with_read_buf();
        client = client.with_reader_config(reader_config);
    };

    client.build()
}
