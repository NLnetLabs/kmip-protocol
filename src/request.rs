//! Serialiation of KMIP requests.
//!
//! See the [Client] module for a higher level interface.
//!
//! [Client]: crate::client::Client

use serde::Deserialize;
use kmip_ttlv::error::Result;

use crate::{
    auth::CredentialType,
    types::{
        common::UniqueBatchItemID,
        request::{
            Authentication, BatchCount, BatchItem, MaximumResponseSize, RequestHeader, RequestMessage, RequestPayload,
        },
    },
};


pub fn to_vec(payload: RequestPayload, credential: Option<CredentialType>) -> Result<Vec<u8>> {
    let operation = payload.operation();
    let request = RequestMessage(
        RequestHeader(
            payload.protocol_version(),
            Option::<MaximumResponseSize>::None,
            credential.map(Authentication::build),
            BatchCount(1),
        ),
        vec![BatchItem(operation, Option::<UniqueBatchItemID>::None, payload)],
    );
    kmip_ttlv::ser::to_vec(&request)
}

pub fn from_slice<'de, T>(bytes: &'de [u8]) -> Result<T>
where
    T: Deserialize<'de>,
{
    kmip_ttlv::de::from_slice(bytes)
}
