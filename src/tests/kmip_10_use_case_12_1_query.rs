//! See: http://docs.oasis-open.org/kmip/usecases/v1.0/cs01/kmip-usecases-1.0-cs-01.html#_Toc262822082

use krill_kmip_ttlv::ser::to_vec;

use crate::{
    response::from_slice,
    types::{
        common::{ObjectType, Operation},
        request::{
            self, Authentication, BatchCount, BatchItem, MaximumResponseSize, ProtocolVersionMajor,
            ProtocolVersionMinor, QueryFunction, RequestHeader, RequestMessage, RequestPayload,
        },
        response::{ResponseMessage, ResponsePayload, ResultReason, ResultStatus},
    },
};

#[test]
fn query_request_operations_objects_max_response_size_256() {
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
fn query_response_operation_failed_response_too_large() {
    let use_case_response_hex = concat!(
    let ttlv_wire = hex::decode(use_case_response_hex).unwrap();
    let res: ResponseMessage = from_slice(ttlv_wire.as_ref()).unwrap();

    assert_eq!(res.header.protocol_version.major, 1);
    assert_eq!(res.header.protocol_version.minor, 0);
    assert_eq!(res.header.timestamp, 0x000000004B7918AA);
    assert_eq!(res.header.batch_count, 1);
    assert_eq!(res.batch_items.len(), 1);

    let item = &res.batch_items[0];
    assert!(matches!(item.result_status, ResultStatus::OperationFailed));
    assert!(matches!(item.result_reason, Some(ResultReason::ResponseTooLarge)));
    assert_eq!(
        item.result_message,
        Some("Response size: 568, Maximum Response Size indicated in request: 256".to_string())
    );
}

#[test]
fn query_request_operations_objects_max_response_size_2048() {
    let use_case_request = RequestMessage(
        RequestHeader(
            request::ProtocolVersion(ProtocolVersionMajor(1), ProtocolVersionMinor(0)),
            Some(MaximumResponseSize(2048)),
            Option::<Authentication>::None,
            BatchCount(1),
        ),
        vec![BatchItem(
            Operation::Query,
            RequestPayload::Query(vec![QueryFunction::QueryOperations, QueryFunction::QueryObjects]),
        )],
    );

    let use_case_request_hex = "42007801000000904200770100000048420069010000002042006A0200000004000000010000000042006B020000000400000000000000004200500200000004000008000000000042000D0200000004000000010000000042000F010000003842005C0500000004000000180000000042007901000000204200740500000004000000010000000042007405000000040000000200000000";
    let actual_request_hex = hex::encode_upper(to_vec(&use_case_request).unwrap());

    assert_eq!(use_case_request_hex, actual_request_hex);
}

#[test]
fn query_response_operation_succeeded() {
    let ttlv_wire = hex::decode(use_case_response_hex).unwrap();
    let res: ResponseMessage = from_slice(ttlv_wire.as_ref()).unwrap();

    assert_eq!(res.header.protocol_version.major, 1);
    assert_eq!(res.header.protocol_version.minor, 0);
    assert_eq!(res.header.timestamp, 0x000000004B7918AA);
    assert_eq!(res.header.batch_count, 1);
    assert_eq!(res.batch_items.len(), 1);

    let item = &res.batch_items[0];
    assert!(matches!(item.result_status, ResultStatus::Success));
    assert!(matches!(item.operation, Some(Operation::Query)));
    assert!(matches!(&item.payload, Some(ResponsePayload::Query(_))));

    if let Some(ResponsePayload::Query(payload)) = item.payload.as_ref() {
        assert_eq!(payload.operations.len(), 22);
        assert!(matches!(payload.operations[0], Operation::Create));
        assert!(matches!(payload.operations[1], Operation::CreateKeyPair));
        assert!(matches!(payload.operations[2], Operation::Register));
        assert!(matches!(payload.operations[3], Operation::Rekey));
        assert!(matches!(payload.operations[4], Operation::Locate));
        assert!(matches!(payload.operations[5], Operation::Check));
        assert!(matches!(payload.operations[6], Operation::Get));
        assert!(matches!(payload.operations[7], Operation::GetAttributes));
        assert!(matches!(payload.operations[8], Operation::GetAttributeList));
        assert!(matches!(payload.operations[9], Operation::AddAttribute));
        assert!(matches!(payload.operations[10], Operation::ModifyAttribute));
        assert!(matches!(payload.operations[11], Operation::DeleteAttribute));
        assert!(matches!(payload.operations[12], Operation::ObtainLease));
        assert!(matches!(payload.operations[13], Operation::GetUsageAllocation));
        assert!(matches!(payload.operations[14], Operation::Activate));
        assert!(matches!(payload.operations[15], Operation::Revoke));
        assert!(matches!(payload.operations[16], Operation::Destroy));
        assert!(matches!(payload.operations[17], Operation::Archive));
        assert!(matches!(payload.operations[18], Operation::Recover));
        assert!(matches!(payload.operations[19], Operation::Query));
        assert!(matches!(payload.operations[20], Operation::Cancel));
        assert!(matches!(payload.operations[21], Operation::Poll));

        assert_eq!(payload.object_types.len(), 5);
        assert!(matches!(payload.object_types[0], ObjectType::Certificate));
        assert!(matches!(payload.object_types[1], ObjectType::SymmetricKey));
        assert!(matches!(payload.object_types[2], ObjectType::PublicKey));
        assert!(matches!(payload.object_types[3], ObjectType::PrivateKey));
        assert!(matches!(payload.object_types[4], ObjectType::Template));

        assert!(payload.operations.contains(&Operation::Cancel));
        assert!(payload.object_types.contains(&ObjectType::Template));

        assert!(payload.vendor_identification.is_none());
        assert!(payload.server_information.is_none());
    } else {
        panic!("Wrong payload");
    }
}
