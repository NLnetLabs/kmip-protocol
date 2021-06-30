//! See: http://docs.oasis-open.org/kmip/usecases/v1.0/cs01/kmip-usecases-1.0-cs-01.html#_Toc262822082

use krill_kmip_ttlv::ser::to_vec;

use crate::{
    response::from_slice,
    types::{
        common::Operation,
        request::{
            self, Authentication, BatchCount, BatchItem, MaximumResponseSize, ProtocolVersionMajor,
            ProtocolVersionMinor, QueryFunction, RequestHeader, RequestMessage, RequestPayload,
        },
        response::{ResponseMessage, ResultReason, ResultStatus},
    },
};

#[test]
fn query_operations_objects_max_response_size_256() {
    let use_case_request = RequestMessage(
        RequestHeader(
            request::ProtocolVersion(ProtocolVersionMajor(1), ProtocolVersionMinor(0)),
            Some(MaximumResponseSize(256)),
            Option::<Authentication>::None,
            BatchCount(1),
        ),
        vec![BatchItem(
            Operation::Query,
            RequestPayload::Query(vec![QueryFunction::QueryOperations, QueryFunction::QueryObjects]),
        )],
    );

    let use_case_request_hex = "42007801000000904200770100000048420069010000002042006A0200000004000000010000000042006B020000000400000000000000004200500200000004000001000000000042000D0200000004000000010000000042000F010000003842005C0500000004000000180000000042007901000000204200740500000004000000010000000042007405000000040000000200000000";
    let actual_request_hex = hex::encode_upper(to_vec(&use_case_request).unwrap());

    assert_eq!(use_case_request_hex, actual_request_hex);
}

#[test]
fn query_operation_failed_response_too_large() {
    let use_case_response_hex = "42007B01000000C842007A0100000048420069010000002042006A0200000004000000010000000042006B020000000400000000000000004200920900000008000000004B7918AA42000D0200000004000000010000000042000F010000007042007F0500000004000000010000000042007E0500000004000000020000000042007D0700000043526573706F6E73652073697A653A203536382C204D6178696D756D20526573706F6E73652053697A6520696E6469636174656420696E20726571756573743A203235360000000000";
    let ttlv_wire = hex::decode(use_case_response_hex).unwrap();
    let res: ResponseMessage = from_slice(ttlv_wire.as_ref()).unwrap();

    assert_eq!(res.header.protocol_version.major, 1);
    assert_eq!(res.header.protocol_version.minor, 0);
    assert_eq!(res.header.timestamp, 0x000000004B7918AA);
    assert_eq!(res.header.batch_count, 1);
    assert_eq!(res.batch_items.len(), 1);
    assert!(matches!(
        res.batch_items[0].result_status,
        ResultStatus::OperationFailed
    ));
    assert!(matches!(
        res.batch_items[0].result_reason,
        Some(ResultReason::ResponseTooLarge)
    ));
    assert_eq!(
        res.batch_items[0].result_message,
        Some("Response size: 568, Maximum Response Size indicated in request: 256".to_string())
    );
}
