//! Serialiation of KMIP requests.

use crate::{
    auth::CredentialType,
    types::{
        common::UniqueBatchItemID,
        request::{
            Authentication, BatchCount, BatchItem, MaximumResponseSize, RequestHeader, RequestMessage, RequestPayload,
        },
    },
};

use kmip_ttlv::error::Result;

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
