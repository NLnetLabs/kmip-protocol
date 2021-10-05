use kmip_ttlv::Config as KmipConfig;

use crate::client::{Client, ClientBuilder, ConnectionSettings};

pub(crate) fn create_kmip_client<T>(tls_stream: T, conn_settings: &ConnectionSettings) -> Client<T> {
    let mut client = ClientBuilder::new(tls_stream);

    if let Some(username) = &conn_settings.username {
        client = client.with_credentials(username.clone(), conn_settings.password.clone());
    }

    let mut reader_config = KmipConfig::default().with_read_buf();
    if let Some(max_bytes) = conn_settings.max_response_bytes {
        reader_config = reader_config.with_max_bytes(max_bytes);
    };

    client = client.with_reader_config(reader_config);

    client.build()
}
