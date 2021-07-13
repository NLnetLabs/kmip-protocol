use crate::{
    auth::CredentialType,
    types::{
        common::{Operation, UniqueBatchItemID},
        request::{
            Authentication, BatchCount, BatchItem, MaximumResponseSize, ProtocolVersion, ProtocolVersionMajor,
            ProtocolVersionMinor, RequestHeader, RequestMessage, RequestPayload,
        },
    },
};

use krill_kmip_ttlv::error::Result;

pub fn to_vec(operation: Operation, payload: RequestPayload, credential: Option<CredentialType>) -> Result<Vec<u8>> {
    let request = RequestMessage(
        RequestHeader(
            ProtocolVersion(ProtocolVersionMajor(1), ProtocolVersionMinor(0)),
            Option::<MaximumResponseSize>::None,
            credential.map(Authentication::build),
            BatchCount(1),
        ),
        vec![BatchItem(operation, Option::<UniqueBatchItemID>::None, payload)],
    );
    krill_kmip_ttlv::ser::to_vec(&request)
}
