use crate::{
    net::{
        ConnectionSettings,
        client_server::{Client, builder::ClientBuilder},
    },
    types::traits::ReadWrite,
};

pub(crate) fn create_kmip_client<T: ReadWrite>(tls_stream: T, conn_settings: &ConnectionSettings) -> Client<T> {
    let mut client = ClientBuilder::new(tls_stream);

    if let Some(username) = &conn_settings.username {
        client = client.with_credentials(username.clone(), conn_settings.password.clone());
    }

    client.build()
}
