//! See: https://docs.oasis-open.org/kmip/usecases/v1.0/kmip-usecases-1.0.html#_Toc262822082

#[allow(unused_imports)]
use pretty_assertions::{assert_eq, assert_ne};

use krill_kmip_ttlv::ser::to_vec;

use crate::{
    response::from_slice,
    types::{
        common::{ObjectType, Operation, UniqueBatchItemID},
        request::{
            self, Authentication, BatchCount, BatchItem, MaximumResponseSize, ProtocolVersionMajor,
            ProtocolVersionMinor, QueryFunction, RequestHeader, RequestMessage, RequestPayload,
        },
        response::{ResponseMessage, ResponsePayload, ResultReason, ResultStatus},
    },
};

/// -------------------------------------------------------------------------------------------------------------------
/// 12.1 Use-case: Query, Maximum Response Size
/// -------------------------------------------------------------------------------------------------------------------

#[test]
fn kmip_1_0_usecase_12_1_step_1_query_operations_objects_max_response_size_256_request() {
    #[rustfmt::skip]
    let use_case_request = 
        RequestMessage(                             // Tag: 0x420078, Type: 0x01 (Structure)
            RequestHeader(                          //   Tag: 0x420077, Type: 0x01 (Structure)
                request::ProtocolVersion(           //     Tag: 0x420069, Type: 0x01 (Structure)
                    ProtocolVersionMajor(1),        //       Tag: 0x42006A, Type: 0x02 (Integer), Data: 0x00000001 (1)
                    ProtocolVersionMinor(0)         //       Tag: 0x42006B, Type: 0x02 (Integer), Data: 0x00000000 (0)
                ),                                  //
                Some(MaximumResponseSize(256)),     //     Tag: 0x420050, Type: 0x02 (Integer), Data: 0x00000100 (256)
                Option::<Authentication>::None,     //
                BatchCount(1),                      //     Tag: 0x42000D, Type: 0x02 (Integer), Data: 0x00000001 (1)
            ),                                      //
            vec![BatchItem(                         //   Tag: 0x42000F, Type: 0x01 (Structure)
                Operation::Query,                   //     Tag: 0x42005C, Type: 0x05 (Enumeration). Data: 0x00000018
                Option::<UniqueBatchItemID>::None,  //
                RequestPayload::Query(vec![         //     Tag: 0x420079, Type: 0x01 (Structure)
                    QueryFunction::QueryOperations, //       Tag: 0x420074, Type: 0x05 (Enumeration), Data: 0x00000001
                    QueryFunction::QueryObjects     //       Tag: 0x420074, Type: 0x05 (Enumeration), Data: 0x00000002
                ]),
            )],
        );

    #[rustfmt::skip]
    let use_case_request_hex = concat!(
        "42007801000000904200770100000048420069010000002042006A0200000004000000010000000042006B02000000040",
    //   ^RequestMessage ^RequestHeader  ^ProtocolVersion^ProtocolVersionMajor           ^ProtocolVersionMinor
        "0000000000000004200500200000004000001000000000042000D0200000004000000010000000042000F010000003842",
    //                  ^MaximumResponseSize            ^BatchCount                     ^BatchItem      ^O
        "005C050000000400000018000000004200790100000020420074050000000400000001000000004200740500000004000",
    //   peration                      ^RequestPayload ^QueryFunction::Operations      ^QueryFunction::Objects
        "0000200000000"
    );
    let actual_request_hex = hex::encode_upper(to_vec(&use_case_request).unwrap());

    assert_eq!(
        use_case_request_hex, actual_request_hex,
        "expected hex (left) differs to the generated hex (right)"
    );
}

#[test]
fn kmip_1_0_usecase_12_1_step_1_query_operation_failed_response_too_large_response() {
    let use_case_response_hex = concat!(
        "42007B01000000C842007A0100000048420069010000002042006A0200000004000000010000000042006B02000000040",
        "0000000000000004200920900000008000000004B7918AA42000D0200000004000000010000000042000F010000007042",
        "007F0500000004000000010000000042007E0500000004000000020000000042007D0700000043526573706F6E7365207",
        "3697A653A203536382C204D6178696D756D20526573706F6E73652053697A6520696E6469636174656420696E20726571",
        "756573743A203235360000000000"
    );
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
fn kmip_1_0_usecase_12_1_step_2_query_operations_objects_max_response_size_2048_request() {
    #[rustfmt::skip]
    let use_case_request = 
        RequestMessage(                             // Tag: 0x420078, Type: 0x01 (Structure)
            RequestHeader(                          //   Tag: 0x420077, Type: 0x01 (Structure)
                request::ProtocolVersion(           //     Tag: 0x420069, Type: 0x01 (Structure)
                    ProtocolVersionMajor(1),        //       Tag: 0x42006A, Type: 0x02 (Integer), Data: 0x00000001 (1)
                    ProtocolVersionMinor(0)         //       Tag: 0x42006B, Type: 0x02 (Integer), Data: 0x00000000 (0)
                ),                                  //
                Some(MaximumResponseSize(2048)),    //     Tag: 0x420050, Type: 0x02 (Integer), Data: 0x00000800 (2048)
                Option::<Authentication>::None,     //
                BatchCount(1),                      //     Tag: 0x42000D, Type: 0x02 (Integer), Data: 0x00000001 (1)
            ),                                      //
            vec![BatchItem(                         //   Tag: 0x42000F, Type: 0x01 (Structure)
                Operation::Query,                   //     Tag: 0x42005C, Type: 0x05 (Enumeration). Data: 0x00000018
                Option::<UniqueBatchItemID>::None,  //
                RequestPayload::Query(vec![         //     Tag: 0x420079, Type: 0x01 (Structure)
                    QueryFunction::QueryOperations, //       Tag: 0x420074, Type: 0x05 (Enumeration), Data: 0x00000001
                    QueryFunction::QueryObjects     //       Tag: 0x420074, Type: 0x05 (Enumeration), Data: 0x00000002
                ]),
            )],
        );

    #[rustfmt::skip]
    let use_case_request_hex = concat!(
        "42007801000000904200770100000048420069010000002042006A0200000004000000010000000042006B02000000040",
    //   ^RequestMessage ^RequestHeader  ^ProtocolVersion^ProtocolVersionMajor           ^ProtocolVersionMinor
        "0000000000000004200500200000004000008000000000042000D0200000004000000010000000042000F010000003842",
    //                  ^MaximumResponseSize            ^BatchCount                     ^BatchItem      ^O
        "005C050000000400000018000000004200790100000020420074050000000400000001000000004200740500000004000",
    //   peration                      ^RequestPayload ^QueryFunction::Operations      ^QueryFunction::Objects
        "0000200000000"
    );
    let actual_request_hex = hex::encode_upper(to_vec(&use_case_request).unwrap());

    assert_eq!(
        use_case_request_hex, actual_request_hex,
        "expected hex (left) differs to the generated hex (right)"
    );
}

#[test]
fn kmip_1_0_usecase_12_1_step_2_query_operation_succeeded_response() {
    let use_case_response_hex = concat!(
        "42007B010000023042007A0100000048420069010000002042006A0200000004000000010000000042006B02000000040",
        "0000000000000004200920900000008000000004B7918AA42000D0200000004000000010000000042000F01000001D842",
        "005C0500000004000000180000000042007F0500000004000000000000000042007C01000001B042005C0500000004000",
        "000010000000042005C0500000004000000020000000042005C0500000004000000030000000042005C05000000040000",
        "00040000000042005C0500000004000000080000000042005C0500000004000000090000000042005C050000000400000",
        "00A0000000042005C05000000040000000B0000000042005C05000000040000000C0000000042005C0500000004000000",
        "0D0000000042005C05000000040000000E0000000042005C05000000040000000F0000000042005C05000000040000001",
        "00000000042005C0500000004000000110000000042005C0500000004000000120000000042005C050000000400000013",
        "0000000042005C0500000004000000140000000042005C0500000004000000150000000042005C0500000004000000160",
        "000000042005C0500000004000000180000000042005C0500000004000000190000000042005C05000000040000001A00",
        "0000004200570500000004000000010000000042005705000000040000000200000000420057050000000400000003000",
        "000004200570500000004000000040000000042005705000000040000000600000000"
    );
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
        assert!(payload.operations.is_some());
        let ops = payload.operations.as_ref().unwrap();
        assert_eq!(ops.len(), 22);
        assert!(matches!(ops[0], Operation::Create));
        assert!(matches!(ops[1], Operation::CreateKeyPair));
        assert!(matches!(ops[2], Operation::Register));
        assert!(matches!(ops[3], Operation::Rekey));
        assert!(matches!(ops[4], Operation::Locate));
        assert!(matches!(ops[5], Operation::Check));
        assert!(matches!(ops[6], Operation::Get));
        assert!(matches!(ops[7], Operation::GetAttributes));
        assert!(matches!(ops[8], Operation::GetAttributeList));
        assert!(matches!(ops[9], Operation::AddAttribute));
        assert!(matches!(ops[10], Operation::ModifyAttribute));
        assert!(matches!(ops[11], Operation::DeleteAttribute));
        assert!(matches!(ops[12], Operation::ObtainLease));
        assert!(matches!(ops[13], Operation::GetUsageAllocation));
        assert!(matches!(ops[14], Operation::Activate));
        assert!(matches!(ops[15], Operation::Revoke));
        assert!(matches!(ops[16], Operation::Destroy));
        assert!(matches!(ops[17], Operation::Archive));
        assert!(matches!(ops[18], Operation::Recover));
        assert!(matches!(ops[19], Operation::Query));
        assert!(matches!(ops[20], Operation::Cancel));
        assert!(matches!(ops[21], Operation::Poll));

        assert!(payload.object_types.is_some());
        let types = payload.object_types.as_ref().unwrap();
        assert_eq!(types.len(), 5);
        assert!(matches!(types[0], ObjectType::Certificate));
        assert!(matches!(types[1], ObjectType::SymmetricKey));
        assert!(matches!(types[2], ObjectType::PublicKey));
        assert!(matches!(types[3], ObjectType::PrivateKey));
        assert!(matches!(types[4], ObjectType::Template));

        assert!(ops.contains(&Operation::Cancel));
        assert!(types.contains(&ObjectType::Template));

        assert!(payload.vendor_identification.is_none());
        assert!(payload.server_information.is_none());
    } else {
        panic!("Wrong payload");
    }
}
