use kmip_ttlv::Config as KmipConfig;

use crate::tls::{config::Config, Client, ClientBuilder};

pub(crate) fn create_kmip_client<T>(tls_stream: T, config: Config) -> Client<T> {
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
