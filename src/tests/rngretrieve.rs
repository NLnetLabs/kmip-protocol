#[allow(unused_imports)]
use pretty_assertions::{assert_eq, assert_ne};

use krill_kmip_ttlv::ser::to_vec;

use crate::types::{
    common::{DataLength, Operation, UniqueBatchItemID},
    request::{
        self, Authentication, BatchCount, BatchItem, MaximumResponseSize, ProtocolVersionMajor, ProtocolVersionMinor,
        RequestHeader, RequestMessage, RequestPayload,
    },
};

#[test]
fn rngretrieve_request_serializes_without_error() {
    let request = RequestMessage(
        RequestHeader(
            request::ProtocolVersion(ProtocolVersionMajor(1), ProtocolVersionMinor(2)),
            Option::<MaximumResponseSize>::None,
            Option::<Authentication>::None,
            BatchCount(1),
        ),
        vec![BatchItem(
            Operation::RNGRetrieve,
            Option::<UniqueBatchItemID>::None,
            RequestPayload::RNGRetrieve(DataLength(10)),
        )],
    );
    assert!(to_vec(&request).is_ok());
}

#[test]
#[ignore = "cannot be implemented until an authoritative response sample is available"]
fn rngretrieve_response_deserializes_without_error() {
    todo!();
}
