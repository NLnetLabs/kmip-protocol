use krill_kmip_ttlv::ser::to_vec;

use crate::types::{common::Operation, request::{Authentication, BatchCount, BatchItem, MaximumResponseSize, ProtocolVersion, ProtocolVersionMajor, ProtocolVersionMinor, QueryFunction, QueryPayload, RequestHeader, RequestMessage, RequestPayload}};

// See: http://docs.oasis-open.org/kmip/usecases/v1.0/cs01/kmip-usecases-1.0-cs-01.html#_Toc262822082

#[test]
fn query_operations_objects_max_response_size_256() {
    let use_case_request = RequestMessage(
        RequestHeader(
            ProtocolVersion(ProtocolVersionMajor(1), ProtocolVersionMinor(0)),
            Some(MaximumResponseSize(256)),
            Option::<Authentication>::None,
            BatchCount(1),
        ),
        vec![BatchItem(
            Operation::Query,
            RequestPayload::Query(QueryPayload(vec![
                QueryFunction::QueryOperations,
                QueryFunction::QueryObjects,
            ])),
        )],
    );

    let use_case_request_hex = "42007801000000904200770100000048420069010000002042006A0200000004000000010000000042006B020000000400000000000000004200500200000004000001000000000042000D0200000004000000010000000042000F010000003842005C0500000004000000180000000042007901000000204200740500000004000000010000000042007405000000040000000200000000";
    let actual_request_hex = hex::encode_upper(to_vec(&use_case_request).unwrap());

    assert_eq!(use_case_request_hex, actual_request_hex);
}
