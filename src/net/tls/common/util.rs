use crate::{
    net::{
        ConnectionSettings,
        client_server::{ClientServer, builder::NetBuilder},
    },
    types::traits::ReadWrite,
};

pub(crate) fn create_kmip_client<T: ReadWrite>(tls_stream: T, conn_settings: &ConnectionSettings) -> ClientServer<T> {
    let mut client = NetBuilder::new(tls_stream, &conn_settings.host);

    if let Some(username) = &conn_settings.username {
        client = client.with_credentials(username.clone(), conn_settings.password.clone());
    }

    client.build()
}
