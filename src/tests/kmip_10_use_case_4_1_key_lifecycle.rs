//! See: https://docs.oasis-open.org/kmip/usecases/v1.0/kmip-usecases-1.0.html#_Toc262822060
#[allow(unused_imports)]
use pretty_assertions::{assert_eq, assert_ne};

use krill_kmip_ttlv::{de::from_slice, ser::to_vec};

use crate::types::{
    common::{
        AttributeIndex, AttributeName, AttributeValue, CompromiseOccurrenceDate, CryptographicAlgorithm,
        CryptographicUsageMask, KeyCompressionType, KeyFormatType, KeyMaterial, ObjectType, Operation,
        RevocationMessage, RevocationReasonCode, State, UniqueBatchItemID, UniqueIdentifier,
    },
    request::{
        self, Attribute, Authentication, BatchCount, BatchItem, KeyWrappingSpecification, MaximumResponseSize,
        ProtocolVersionMajor, ProtocolVersionMinor, RequestHeader, RequestMessage, RequestPayload, RevocationReason,
        TemplateAttribute,
    },
    response::{ManagedObject, ResponseMessage, ResponsePayload, ResultStatus},
};

const KEY_ID: &'static str = "21d28b8a-06df-43c0-b72f-2a161633ada9";

/// -------------------------------------------------------------------------------------------------------------------
/// 4.1 Use-case: Revoke scenario
/// -------------------------------------------------------------------------------------------------------------------

#[test]
fn kmip_1_0_usecase_4_1_step_1_client_a_create_symmetric_key_request() {
    let use_case_request = RequestMessage(
        RequestHeader(
            request::ProtocolVersion(ProtocolVersionMajor(1), ProtocolVersionMinor(0)),
            Option::<MaximumResponseSize>::None,
            Option::<Authentication>::None,
            BatchCount(1),
        ),
        vec![BatchItem(
            Operation::Create,
            Option::<UniqueBatchItemID>::None,
            RequestPayload::Create(
                ObjectType::SymmetricKey,
                TemplateAttribute::unnamed(vec![
                    Attribute::CryptographicAlgorithm(CryptographicAlgorithm::AES),
                    Attribute::CryptographicLength(128),
                    Attribute::Name("Key1".into()),
                    Attribute::CryptographicUsageMask(CryptographicUsageMask::Encrypt),
                ]),
            ),
        )],
    );

    let use_case_request_hex = concat!(
        "42007801000001604200770100000038420069010000002042006A0200000004000000010000000042006B02000000040",
        "00000000000000042000D0200000004000000010000000042000F010000011842005C0500000004000000010000000042",
        "007901000001004200570500000004000000020000000042009101000000E8420008010000003042000A0700000017437",
        "27970746F6772617068696320416C676F726974686D0042000B0500000004000000030000000042000801000000304200",
        "0A070000001443727970746F67726170686963204C656E6774680000000042000B0200000004000000800000000042000",
        "8010000003842000A07000000044E616D650000000042000B010000002042005507000000044B65793100000000420054",
        "05000000040000000100000000420008010000003042000A070000001843727970746F677261706869632055736167652",
        "04D61736B42000B02000000040000000400000000",
    );
    let actual_request_hex = hex::encode_upper(to_vec(&use_case_request).unwrap());

    assert_eq!(
        use_case_request_hex, actual_request_hex,
        "expected hex (left) differs to the generated hex (right)"
    );
}

#[test]
fn kmip_1_0_usecase_4_1_step_1_client_a_create_symmetric_key_response() {
    // From: https://docs.oasis-open.org/kmip/usecases/v1.0/cs01/kmip-usecases-1.0-cs-01.html#_Toc262822060
    // Tag: Response Message (0x42007B), Type: Structure (0x01), Data:
    //   Tag: Response Header (0x42007A), Type: Structure (0x01), Data:
    //     Tag: Protocol Version (0x420069), Type: Structure (0x01), Data:
    //       Tag: Protocol Version Major (0x42006A), Type: Integer (0x02), Data: 0x00000001 (1)
    //       Tag: Protocol Version Minor (0x42006B), Type: Integer (0x02), Data: 0x00000000 (0)
    //     Tag: Time Stamp (0x420092), Type: Date-Time (0x09), Data: 0x000000004AFBED2B (Thu Nov 12 12:10:35 CET 2009)
    //     Tag: Batch Count (0x42000D), Type: Integer (0x02), Data: 0x00000001 (1)
    //   Tag: Batch Item (0x42000F), Type: Structure (0x01), Data:
    //     Tag: Operation (0x42005C), Type: Enumeration (0x05), Data: 0x00000001 (Create)
    //     Tag: Result Status (0x42007F), Type: Enumeration (0x05), Data: 0x00000000 (Success)
    //     Tag: Response Payload (0x42007C), Type: Structure (0x01), Data:
    //       Tag: Object Type (0x420057), Type: Enumeration (0x05), Data: 0x00000002 (Symmetric Key)
    //       Tag: Unique Identifier (0x420094), Type: Text String (0x07), Data: 21d28b8a-06df-43c0-b72f-2a161633ada9
    let use_case_response_hex = concat!(
        "42007B01000000C042007A0100000048420069010000002042006A0200000004000000010000000042006B02000000040",
        "0000000000000004200920900000008000000004AFBED2B42000D0200000004000000010000000042000F010000006842",
        "005C0500000004000000010000000042007F0500000004000000000000000042007C01000000404200570500000004000",
        "0000200000000420094070000002432316432386238612D303664662D343363302D623732662D32613136313633336164",
        "613900000000",
    );
    let ttlv_wire = hex::decode(use_case_response_hex).unwrap();
    let res: ResponseMessage = from_slice(ttlv_wire.as_ref()).unwrap();

    assert_eq!(res.header.protocol_version.major, 1);
    assert_eq!(res.header.protocol_version.minor, 0);
    assert_eq!(res.header.timestamp, 0x000000004AFBED2B);
    assert_eq!(res.header.batch_count, 1);
    assert_eq!(res.batch_items.len(), 1);

    let item = &res.batch_items[0];
    assert!(matches!(item.result_status, ResultStatus::Success));
    assert!(matches!(item.operation, Some(Operation::Create)));
    assert!(matches!(&item.payload, Some(ResponsePayload::Create(_))));

    if let Some(ResponsePayload::Create(payload)) = item.payload.as_ref() {
        assert!(matches!(payload.object_type, ObjectType::SymmetricKey));
        assert_eq!(&payload.unique_identifier, KEY_ID);
    } else {
        panic!("Wrong payload");
    }
}

#[test]
fn kmip_1_0_usecase_4_1_step_2_client_a_get_attribute_request() {
    let use_case_request = RequestMessage(
        RequestHeader(
            request::ProtocolVersion(ProtocolVersionMajor(1), ProtocolVersionMinor(0)),
            Option::<MaximumResponseSize>::None,
            Option::<Authentication>::None,
            BatchCount(1),
        ),
        vec![BatchItem(
            Operation::GetAttributes,
            Option::<UniqueBatchItemID>::None,
            RequestPayload::GetAttributes(
                Some(UniqueIdentifier(KEY_ID.into())),
                Some(vec![AttributeName("State".into())]),
            ),
        )],
    );

    let use_case_request_hex = concat!(
        "42007801000000A04200770100000038420069010000002042006A0200000004000000010000000042006B02000000040",
        "00000000000000042000D0200000004000000010000000042000F010000005842005C05000000040000000B0000000042",
        "00790100000040420094070000002432316432386238612D303664662D343363302D623732662D3261313631363333616",
        "461390000000042000A07000000055374617465000000",
    );
    let actual_request_hex = hex::encode_upper(to_vec(&use_case_request).unwrap());

    assert_eq!(
        use_case_request_hex, actual_request_hex,
        "expected hex (left) differs to the generated hex (right)"
    );
}

#[test]
fn kmip_1_0_usecase_4_1_step_2_client_a_get_attribute_response() {
    // From: https://docs.oasis-open.org/kmip/usecases/v1.0/cs01/kmip-usecases-1.0-cs-01.html#_Toc262822060
    // Tag: Response Message (0x42007B), Type: Structure (0x01), Data:
    //   Tag: Response Header (0x42007A), Type: Structure (0x01), Data:
    //     Tag: Protocol Version (0x420069), Type: Structure (0x01), Data:
    //       Tag: Protocol Version Major (0x42006A), Type: Integer (0x02), Data: 0x00000001 (1)
    //       Tag: Protocol Version Minor (0x42006B), Type: Integer (0x02), Data: 0x00000000 (0)
    //     Tag: Time Stamp (0x420092), Type: Date-Time (0x09), Data: 0x000000004AFBED2B (Thu Nov 12 12:10:35 CET 2009)
    //     Tag: Batch Count (0x42000D), Type: Integer (0x02), Data: 0x00000001 (1)
    //   Tag: Batch Item (0x42000F), Type: Structure (0x01), Data:
    //     Tag: Operation (0x42005C), Type: Enumeration (0x05), Data: 0x0000000B (Get Attributes)
    //     Tag: Result Status (0x42007F), Type: Enumeration (0x05), Data: 0x00000000 (Success)
    //     Tag: Response Payload (0x42007C), Type: Structure (0x01), Data:
    //       Tag: Unique Identifier (0x420094), Type: Text String (0x07), Data: 21d28b8a-06df-43c0-b72f-2a161633ada9
    //       Tag: Attribute (0x420008), Type: Structure (0x01), Data:
    //         Tag: Attribute Name (0x42000A), Type: Text String (0x07), Data: State
    //         Tag: Attribute Value (0x42000B), Type: Enumeration (0x05), Data: 0x00000001 (Pre-Active)
    let use_case_response_hex = concat!(
        "42007B01000000D842007A0100000048420069010000002042006A0200000004000000010000000042006B02000000040",
        "0000000000000004200920900000008000000004AFBED2B42000D0200000004000000010000000042000F010000008042",
        "005C05000000040000000B0000000042007F0500000004000000000000000042007C01000000584200940700000024323",
        "16432386238612D303664662D343363302D623732662D3261313631363333616461390000000042000801000000204200",
        "0A0700000005537461746500000042000B05000000040000000100000000",
    );
    let ttlv_wire = hex::decode(use_case_response_hex).unwrap();
    let res: ResponseMessage = from_slice(ttlv_wire.as_ref()).unwrap();

    assert_eq!(res.header.protocol_version.major, 1);
    assert_eq!(res.header.protocol_version.minor, 0);
    assert_eq!(res.header.timestamp, 0x000000004AFBED2B);
    assert_eq!(res.header.batch_count, 1);
    assert_eq!(res.batch_items.len(), 1);

    let item = &res.batch_items[0];
    assert!(matches!(item.result_status, ResultStatus::Success));
    assert!(matches!(item.operation, Some(Operation::GetAttributes)));
    assert!(matches!(&item.payload, Some(ResponsePayload::GetAttributes(_))));

    if let Some(ResponsePayload::GetAttributes(payload)) = item.payload.as_ref() {
        assert_eq!(&payload.unique_identifier, KEY_ID);
        assert!(payload.attributes.is_some());
        if let Some(attributes) = &payload.attributes {
            assert_eq!(attributes.len(), 1);
            assert_eq!(&attributes[0].name, "State");
            assert_eq!(attributes[0].value, AttributeValue::State(State::PreActive));
        }
    } else {
        panic!("Wrong payload");
    }
}

#[test]
fn kmip_1_0_usecase_4_1_step_3_client_a_activate_request() {
    let use_case_request = RequestMessage(
        RequestHeader(
            request::ProtocolVersion(ProtocolVersionMajor(1), ProtocolVersionMinor(0)),
            Option::<MaximumResponseSize>::None,
            Option::<Authentication>::None,
            BatchCount(1),
        ),
        vec![BatchItem(
            Operation::Activate,
            Option::<UniqueBatchItemID>::None,
            RequestPayload::Activate(Some(UniqueIdentifier(KEY_ID.into()))),
        )],
    );
    let use_case_request_hex = concat!(
        "42007801000000904200770100000038420069010000002042006A0200000004000000010000000042006B02000000040",
        "00000000000000042000D0200000004000000010000000042000F010000004842005C0500000004000000120000000042",
        "00790100000030420094070000002432316432386238612D303664662D343363302D623732662D3261313631363333616",
        "4613900000000",
    );
    let actual_request_hex = hex::encode_upper(to_vec(&use_case_request).unwrap());

    assert_eq!(
        use_case_request_hex, actual_request_hex,
        "expected hex (left) differs to the generated hex (right)"
    );
}

#[test]
fn kmip_1_0_usecase_4_1_step_3_client_a_activate_response() {
    // From: https://docs.oasis-open.org/kmip/usecases/v1.0/cs01/kmip-usecases-1.0-cs-01.html#_Toc262822060
    //  Tag: Response Message (0x42007B), Type: Structure (0x01), Data:
    //    Tag: Response Header (0x42007A), Type: Structure (0x01), Data:
    //      Tag: Protocol Version (0x420069), Type: Structure (0x01), Data:
    //        Tag: Protocol Version Major (0x42006A), Type: Integer (0x02), Data: 0x00000001 (1)
    //        Tag: Protocol Version Minor (0x42006B), Type: Integer (0x02), Data: 0x00000000 (0)
    //      Tag: Time Stamp (0x420092), Type: Date-Time (0x09), Data: 0x000000004AFBED2B (Thu Nov 12 12:10:35 CET 2009)
    //      Tag: Batch Count (0x42000D), Type: Integer (0x02), Data: 0x00000001 (1)
    //    Tag: Batch Item (0x42000F), Type: Structure (0x01), Data:
    //      Tag: Operation (0x42005C), Type: Enumeration (0x05), Data: 0x00000012 (Activate)
    //      Tag: Result Status (0x42007F), Type: Enumeration (0x05), Data: 0x00000000 (Success)
    //      Tag: Response Payload (0x42007C), Type: Structure (0x01), Data:
    //        Tag: Unique Identifier (0x420094), Type: Text String (0x07), Data: 21d28b8a-06df-43c0-b72f-2a161633ada9
    let use_case_response_hex = concat!(
        "42007B01000000B042007A0100000048420069010000002042006A0200000004000000010000000042006B02000000040",
        "0000000000000004200920900000008000000004AFBED2B42000D0200000004000000010000000042000F010000005842",
        "005C0500000004000000120000000042007F0500000004000000000000000042007C01000000304200940700000024323",
        "16432386238612D303664662D343363302D623732662D32613136313633336164613900000000",
    );
    let ttlv_wire = hex::decode(use_case_response_hex).unwrap();
    let res: ResponseMessage = from_slice(ttlv_wire.as_ref()).unwrap();

    assert_eq!(res.header.protocol_version.major, 1);
    assert_eq!(res.header.protocol_version.minor, 0);
    assert_eq!(res.header.timestamp, 0x000000004AFBED2B);
    assert_eq!(res.header.batch_count, 1);
    assert_eq!(res.batch_items.len(), 1);

    let item = &res.batch_items[0];
    assert!(matches!(item.result_status, ResultStatus::Success));
    assert!(matches!(item.operation, Some(Operation::Activate)));
    assert!(matches!(&item.payload, Some(ResponsePayload::Activate(_))));

    if let Some(ResponsePayload::Activate(payload)) = item.payload.as_ref() {
        assert_eq!(&payload.unique_identifier, KEY_ID);
    } else {
        panic!("Wrong payload");
    }
}

#[test]
fn kmip_1_0_usecase_4_1_step_4_client_a_get_attribute_request() {
    let use_case_request = RequestMessage(
        RequestHeader(
            request::ProtocolVersion(ProtocolVersionMajor(1), ProtocolVersionMinor(0)),
            Option::<MaximumResponseSize>::None,
            Option::<Authentication>::None,
            BatchCount(1),
        ),
        vec![BatchItem(
            Operation::GetAttributes,
            Option::<UniqueBatchItemID>::None,
            RequestPayload::GetAttributes(
                Some(UniqueIdentifier(KEY_ID.into())),
                Some(vec![AttributeName("State".into())]),
            ),
        )],
    );

    let use_case_request_hex = concat!(
        "42007801000000A04200770100000038420069010000002042006A0200000004000000010000000042006B02000000040",
        "00000000000000042000D0200000004000000010000000042000F010000005842005C05000000040000000B0000000042",
        "00790100000040420094070000002432316432386238612D303664662D343363302D623732662D3261313631363333616",
        "461390000000042000A07000000055374617465000000"
    );
    let actual_request_hex = hex::encode_upper(to_vec(&use_case_request).unwrap());

    assert_eq!(
        use_case_request_hex, actual_request_hex,
        "expected hex (left) differs to the generated hex (right)"
    );
}

#[test]
fn kmip_1_0_usecase_4_1_step_4_client_a_get_attribute_response() {
    // From: https://docs.oasis-open.org/kmip/usecases/v1.0/cs01/kmip-usecases-1.0-cs-01.html#_Toc262822060
    // Tag: Response Message (0x42007B), Type: Structure (0x01), Data:
    //   Tag: Response Header (0x42007A), Type: Structure (0x01), Data:
    //     Tag: Protocol Version (0x420069), Type: Structure (0x01), Data:
    //       Tag: Protocol Version Major (0x42006A), Type: Integer (0x02), Data: 0x00000001 (1)
    //       Tag: Protocol Version Minor (0x42006B), Type: Integer (0x02), Data: 0x00000000 (0)
    //     Tag: Time Stamp (0x420092), Type: Date-Time (0x09), Data: 0x000000004AFBED2B (Thu Nov 12 12:10:35 CET 2009)
    //     Tag: Batch Count (0x42000D), Type: Integer (0x02), Data: 0x00000001 (1)
    //   Tag: Batch Item (0x42000F), Type: Structure (0x01), Data:
    //     Tag: Operation (0x42005C), Type: Enumeration (0x05), Data: 0x0000000B (Get Attributes)
    //     Tag: Result Status (0x42007F), Type: Enumeration (0x05), Data: 0x00000000 (Success)
    //     Tag: Response Payload (0x42007C), Type: Structure (0x01), Data:
    //       Tag: Unique Identifier (0x420094), Type: Text String (0x07), Data: 21d28b8a-06df-43c0-b72f-2a161633ada9
    //       Tag: Attribute (0x420008), Type: Structure (0x01), Data:
    //         Tag: Attribute Name (0x42000A), Type: Text String (0x07), Data: State
    //         Tag: Attribute Value (0x42000B), Type: Enumeration (0x05), Data: 0x00000002 (Active)
    let use_case_response_hex = concat!(
        "42007B01000000D842007A0100000048420069010000002042006A0200000004000000010000000042006B02000000040",
        "0000000000000004200920900000008000000004AFBED2B42000D0200000004000000010000000042000F010000008042",
        "005C05000000040000000B0000000042007F0500000004000000000000000042007C01000000584200940700000024323",
        "16432386238612D303664662D343363302D623732662D3261313631363333616461390000000042000801000000204200",
        "0A0700000005537461746500000042000B05000000040000000200000000",
    );
    let ttlv_wire = hex::decode(use_case_response_hex).unwrap();
    let res: ResponseMessage = from_slice(ttlv_wire.as_ref()).unwrap();

    assert_eq!(res.header.protocol_version.major, 1);
    assert_eq!(res.header.protocol_version.minor, 0);
    assert_eq!(res.header.timestamp, 0x000000004AFBED2B);
    assert_eq!(res.header.batch_count, 1);
    assert_eq!(res.batch_items.len(), 1);

    let item = &res.batch_items[0];
    assert!(matches!(item.result_status, ResultStatus::Success));
    assert!(matches!(item.operation, Some(Operation::GetAttributes)));
    assert!(matches!(&item.payload, Some(ResponsePayload::GetAttributes(_))));

    if let Some(ResponsePayload::GetAttributes(payload)) = item.payload.as_ref() {
        assert_eq!(&payload.unique_identifier, KEY_ID);
        assert!(payload.attributes.is_some());
        if let Some(attributes) = &payload.attributes {
            assert_eq!(attributes.len(), 1);
            assert_eq!(&attributes[0].name, "State");
            assert_eq!(attributes[0].value, AttributeValue::State(State::Active));
        }
    } else {
        panic!("Wrong payload");
    }
}

#[test]
fn kmip_1_0_usecase_4_1_step_5_client_b_locate_symmetric_key_by_name_request() {
    let use_case_request = RequestMessage(
        RequestHeader(
            request::ProtocolVersion(ProtocolVersionMajor(1), ProtocolVersionMinor(0)),
            Option::<MaximumResponseSize>::None,
            Option::<Authentication>::None,
            BatchCount(1),
        ),
        vec![BatchItem(
            Operation::Locate,
            Option::<UniqueBatchItemID>::None,
            RequestPayload::Locate(vec![
                Attribute::ObjectType(ObjectType::SymmetricKey),
                Attribute::Name("Key1".into()),
            ]),
        )],
    );

    let use_case_request_hex = concat!(
        "42007801000000D04200770100000038420069010000002042006A0200000004000000010000000042006B02000000040",
        "00000000000000042000D0200000004000000010000000042000F010000008842005C0500000004000000080000000042",
        "00790100000070420008010000002842000A070000000B4F626A6563742054797065000000000042000B0500000004000",
        "0000200000000420008010000003842000A07000000044E616D650000000042000B010000002042005507000000044B65",
        "79310000000042005405000000040000000100000000",
    );
    let actual_request_hex = hex::encode_upper(to_vec(&use_case_request).unwrap());

    assert_eq!(
        use_case_request_hex, actual_request_hex,
        "expected hex (left) differs to the generated hex (right)"
    );
}

#[test]
fn kmip_1_0_usecase_4_1_step_5_client_b_locate_symmetric_key_by_name_response() {
    // From: https://docs.oasis-open.org/kmip/usecases/v1.0/cs01/kmip-usecases-1.0-cs-01.html#_Toc262822060
    // Tag: Response Message (0x42007B), Type: Structure (0x01), Data:
    //   Tag: Response Header (0x42007A), Type: Structure (0x01), Data:
    //     Tag: Protocol Version (0x420069), Type: Structure (0x01), Data:
    //       Tag: Protocol Version Major (0x42006A), Type: Integer (0x02), Data: 0x00000001 (1)
    //       Tag: Protocol Version Minor (0x42006B), Type: Integer (0x02), Data: 0x00000000 (0)
    //     Tag: Time Stamp (0x420092), Type: Date-Time (0x09), Data: 0x000000004AFBED2B (Thu Nov 12 12:10:35 CET 2009)
    //     Tag: Batch Count (0x42000D), Type: Integer (0x02), Data: 0x00000001 (1)
    //   Tag: Batch Item (0x42000F), Type: Structure (0x01), Data:
    //     Tag: Operation (0x42005C), Type: Enumeration (0x05), Data: 0x00000008 (Locate)
    //     Tag: Result Status (0x42007F), Type: Enumeration (0x05), Data: 0x00000000 (Success)
    //     Tag: Response Payload (0x42007C), Type: Structure (0x01), Data:
    //       Tag: Unique Identifier (0x420094), Type: Text String (0x07), Data: 21d28b8a-06df-43c0-b72f-2a161633ada9
    let use_case_response_hex = concat!(
        "42007B01000000B042007A0100000048420069010000002042006A0200000004000000010000000042006B02000000040",
        "0000000000000004200920900000008000000004AFBED2B42000D0200000004000000010000000042000F010000005842",
        "005C0500000004000000080000000042007F0500000004000000000000000042007C01000000304200940700000024323",
        "16432386238612D303664662D343363302D623732662D32613136313633336164613900000000",
    );
    let ttlv_wire = hex::decode(use_case_response_hex).unwrap();
    let res: ResponseMessage = from_slice(ttlv_wire.as_ref()).unwrap();

    assert_eq!(res.header.protocol_version.major, 1);
    assert_eq!(res.header.protocol_version.minor, 0);
    assert_eq!(res.header.timestamp, 0x000000004AFBED2B);
    assert_eq!(res.header.batch_count, 1);
    assert_eq!(res.batch_items.len(), 1);

    let item = &res.batch_items[0];
    assert!(matches!(item.result_status, ResultStatus::Success));
    assert!(matches!(item.operation, Some(Operation::Locate)));
    assert!(matches!(&item.payload, Some(ResponsePayload::Locate(_))));

    if let Some(ResponsePayload::Locate(payload)) = item.payload.as_ref() {
        assert_eq!(payload.unique_identifiers.len(), 1);
        assert_eq!(&payload.unique_identifiers[0], KEY_ID);
    } else {
        panic!("Wrong payload");
    }
}

#[test]
fn kmip_1_0_usecase_4_1_step_6_client_b_get_symmetric_key_request() {
    let use_case_request = RequestMessage(
        RequestHeader(
            request::ProtocolVersion(ProtocolVersionMajor(1), ProtocolVersionMinor(0)),
            Option::<MaximumResponseSize>::None,
            Option::<Authentication>::None,
            BatchCount(1),
        ),
        vec![BatchItem(
            Operation::Get,
            Option::<UniqueBatchItemID>::None,
            RequestPayload::Get(
                Some(UniqueIdentifier(KEY_ID.into())),
                Option::<KeyFormatType>::None,
                Option::<KeyCompressionType>::None,
                Option::<KeyWrappingSpecification>::None,
            ),
        )],
    );
    let use_case_request_hex = concat!(
        "42007801000000904200770100000038420069010000002042006A0200000004000000010000000042006B02000000040",
        "00000000000000042000D0200000004000000010000000042000F010000004842005C05000000040000000A0000000042",
        "00790100000030420094070000002432316432386238612D303664662D343363302D623732662D3261313631363333616",
        "4613900000000",
    );
    let actual_request_hex = hex::encode_upper(to_vec(&use_case_request).unwrap());

    assert_eq!(
        use_case_request_hex, actual_request_hex,
        "expected hex (left) differs to the generated hex (right)"
    );
}

#[test]
fn kmip_1_0_usecase_4_1_step_6_client_b_get_symmetric_key_response() {
    // From: https://docs.oasis-open.org/kmip/usecases/v1.0/cs01/kmip-usecases-1.0-cs-01.html#_Toc262822060
    // Tag: Response Message (0x42007B), Type: Structure (0x01), Data:
    //   Tag: Response Header (0x42007A), Type: Structure (0x01), Data:
    //     Tag: Protocol Version (0x420069), Type: Structure (0x01), Data:
    //       Tag: Protocol Version Major (0x42006A), Type: Integer (0x02), Data: 0x00000001 (1)
    //       Tag: Protocol Version Minor (0x42006B), Type: Integer (0x02), Data: 0x00000000 (0)
    //     Tag: Time Stamp (0x420092), Type: Date-Time (0x09), Data: 0x000000004AFBED2B (Thu Nov 12 12:10:35 CET 2009)
    //     Tag: Batch Count (0x42000D), Type: Integer (0x02), Data: 0x00000001 (1)
    //   Tag: Batch Item (0x42000F), Type: Structure (0x01), Data:
    //     Tag: Operation (0x42005C), Type: Enumeration (0x05), Data: 0x0000000A (Get)
    //     Tag: Result Status (0x42007F), Type: Enumeration (0x05), Data: 0x00000000 (Success)
    //     Tag: Response Payload (0x42007C), Type: Structure (0x01), Data:
    //       Tag: Object Type (0x420057), Type: Enumeration (0x05), Data: 0x00000002 (Symmetric Key)
    //       Tag: Unique Identifier (0x420094), Type: Text String (0x07), Data: 21d28b8a-06df-43c0-b72f-2a161633ada9
    //       Tag: Symmetric Key (0x42008F), Type: Structure (0x01), Data:
    //         Tag: Key Block (0x420040), Type: Structure (0x01), Data:
    //           Tag: Key Format Type (0x420042), Type: Enumeration (0x05), Data: 0x00000001
    //           Tag: Key Value (0x420045), Type: Structure (0x01), Data:
    //             Tag: Key Material (0x420043), Type: Octet String (0x08), Data: EF7833AB15F5A1EE5874BC0D9BBC4BE7
    //           Tag: Cryptographic Algorithm (0x420028), Type: Enumeration (0x05), Data: 0x00000003 (AES)
    //           Tag: Cryptographic Length (0x42002A), Type: Integer (0x02), Data: 0x00000080 (128)
    let use_case_response_hex = concat!(
        "42007B010000012042007A0100000048420069010000002042006A0200000004000000010000000042006B02000000040",
        "0000000000000004200920900000008000000004AFBED2B42000D0200000004000000010000000042000F01000000C842",
        "005C05000000040000000A0000000042007F0500000004000000000000000042007C01000000A04200570500000004000",
        "0000200000000420094070000002432316432386238612D303664662D343363302D623732662D32613136313633336164",
        "61390000000042008F0100000058420040010000005042004205000000040000000100000000420045010000001842004",
        "30800000010EF7833AB15F5A1EE5874BC0D9BBC4BE74200280500000004000000030000000042002A0200000004000000",
        "8000000000",
    );
    let ttlv_wire = hex::decode(use_case_response_hex).unwrap();
    let res: ResponseMessage = from_slice(ttlv_wire.as_ref()).unwrap();

    assert_eq!(res.header.protocol_version.major, 1);
    assert_eq!(res.header.protocol_version.minor, 0);
    assert_eq!(res.header.timestamp, 0x000000004AFBED2B);
    assert_eq!(res.header.batch_count, 1);
    assert_eq!(res.batch_items.len(), 1);

    let item = &res.batch_items[0];
    assert!(matches!(item.result_status, ResultStatus::Success));
    assert!(matches!(item.operation, Some(Operation::Get)));
    assert!(matches!(&item.payload, Some(ResponsePayload::Get(_))));

    if let Some(ResponsePayload::Get(payload)) = item.payload.as_ref() {
        assert_eq!(payload.object_type, ObjectType::SymmetricKey);
        assert_eq!(&payload.unique_identifier, KEY_ID);
        assert!(matches!(payload.cryptographic_object, ManagedObject::SymmetricKey(_)));

        if let ManagedObject::SymmetricKey(sk) = &payload.cryptographic_object {
            assert_eq!(sk.key_block.key_format_type, KeyFormatType::Raw);
            assert!(matches!(&sk.key_block.key_value.key_material, KeyMaterial::Bytes(_)));
            if let KeyMaterial::Bytes(bytes) = &sk.key_block.key_value.key_material {
                assert_eq!(bytes, &hex::decode("EF7833AB15F5A1EE5874BC0D9BBC4BE7").unwrap());
            }
            assert_eq!(sk.key_block.cryptographic_algorithm, Some(CryptographicAlgorithm::AES));
            assert_eq!(sk.key_block.cryptographic_length, Some(128));
        }
    } else {
        panic!("Wrong payload");
    }
}

#[test]
fn kmip_1_0_usecase_4_1_step_7_client_b_revoke_symmetric_key_compromised_request() {
    let use_case_request = RequestMessage(
        RequestHeader(
            request::ProtocolVersion(ProtocolVersionMajor(1), ProtocolVersionMinor(0)),
            Option::<MaximumResponseSize>::None,
            Option::<Authentication>::None,
            BatchCount(1),
        ),
        vec![BatchItem(
            Operation::Revoke,
            Option::<UniqueBatchItemID>::None,
            RequestPayload::Revoke(
                Some(UniqueIdentifier(KEY_ID.into())),
                RevocationReason(RevocationReasonCode::KeyCompromise, Option::<RevocationMessage>::None),
                Some(CompromiseOccurrenceDate(0x0000000000000006)),
            ),
        )],
    );
    let use_case_request_hex = concat!(
        "42007801000000B84200770100000038420069010000002042006A0200000004000000010000000042006B02000000040",
        "00000000000000042000D0200000004000000010000000042000F010000007042005C0500000004000000130000000042",
        "00790100000058420094070000002432316432386238612D303664662D343363302D623732662D3261313631363333616",
        "461390000000042008101000000104200820500000004000000020000000042002109000000080000000000000006",
    );
    let actual_request_hex = hex::encode_upper(to_vec(&use_case_request).unwrap());

    assert_eq!(
        use_case_request_hex, actual_request_hex,
        "expected hex (left) differs to the generated hex (right)"
    );
}

#[test]
fn kmip_1_0_usecase_4_1_step_7_client_b_revoke_symmetric_key_compromised_response() {
    // From: https://docs.oasis-open.org/kmip/usecases/v1.0/cs01/kmip-usecases-1.0-cs-01.html#_Toc262822060
    // Tag: Response Message (0x42007B), Type: Structure (0x01), Data:
    //   Tag: Response Header (0x42007A), Type: Structure (0x01), Data:
    //     Tag: Protocol Version (0x420069), Type: Structure (0x01), Data:
    //       Tag: Protocol Version Major (0x42006A), Type: Integer (0x02), Data: 0x00000001 (1)
    //       Tag: Protocol Version Minor (0x42006B), Type: Integer (0x02), Data: 0x00000000 (0)
    //     Tag: Time Stamp (0x420092), Type: Date-Time (0x09), Data: 0x000000004AFBED2B (Thu Nov 12 12:10:35 CET 2009)
    //     Tag: Batch Count (0x42000D), Type: Integer (0x02), Data: 0x00000001 (1)
    //   Tag: Batch Item (0x42000F), Type: Structure (0x01), Data:
    //     Tag: Operation (0x42005C), Type: Enumeration (0x05), Data: 0x00000013 (Revoke)
    //     Tag: Result Status (0x42007F), Type: Enumeration (0x05), Data: 0x00000000 (Success)
    //     Tag: Response Payload (0x42007C), Type: Structure (0x01), Data:
    //       Tag: Unique Identifier (0x420094), Type: Text String (0x07), Data: 21d28b8a-06df-43c0-b72f-2a161633ada9
    let use_case_response_hex = concat!(
        "42007B01000000B042007A0100000048420069010000002042006A0200000004000000010000000042006B02000000040",
        "0000000000000004200920900000008000000004AFBED2B42000D0200000004000000010000000042000F010000005842",
        "005C0500000004000000130000000042007F0500000004000000000000000042007C01000000304200940700000024323",
        "16432386238612D303664662D343363302D623732662D32613136313633336164613900000000",
    );
    let ttlv_wire = hex::decode(use_case_response_hex).unwrap();
    let res: ResponseMessage = from_slice(ttlv_wire.as_ref()).unwrap();

    assert_eq!(res.header.protocol_version.major, 1);
    assert_eq!(res.header.protocol_version.minor, 0);
    assert_eq!(res.header.timestamp, 0x000000004AFBED2B);
    assert_eq!(res.header.batch_count, 1);
    assert_eq!(res.batch_items.len(), 1);

    let item = &res.batch_items[0];
    assert!(matches!(item.result_status, ResultStatus::Success));
    assert!(matches!(item.operation, Some(Operation::Revoke)));
    assert!(matches!(&item.payload, Some(ResponsePayload::Revoke(_))));

    if let Some(ResponsePayload::Revoke(payload)) = item.payload.as_ref() {
        assert_eq!(&payload.unique_identifier, KEY_ID);
    } else {
        panic!("Wrong payload");
    }
}

#[test]
fn kmip_1_0_usecase_4_1_step_8_client_b_get_attribute_request() {
    let use_case_request = RequestMessage(
        RequestHeader(
            request::ProtocolVersion(ProtocolVersionMajor(1), ProtocolVersionMinor(0)),
            Option::<MaximumResponseSize>::None,
            Option::<Authentication>::None,
            BatchCount(1),
        ),
        vec![BatchItem(
            Operation::GetAttributes,
            Option::<UniqueBatchItemID>::None,
            RequestPayload::GetAttributes(
                Some(UniqueIdentifier(KEY_ID.into())),
                Some(vec![AttributeName("State".into())]),
            ),
        )],
    );

    let use_case_request_hex = concat!(
        "42007801000000A04200770100000038420069010000002042006A0200000004000000010000000042006B02000000040",
        "00000000000000042000D0200000004000000010000000042000F010000005842005C05000000040000000B0000000042",
        "00790100000040420094070000002432316432386238612D303664662D343363302D623732662D3261313631363333616",
        "461390000000042000A07000000055374617465000000",
    );
    let actual_request_hex = hex::encode_upper(to_vec(&use_case_request).unwrap());

    assert_eq!(
        use_case_request_hex, actual_request_hex,
        "expected hex (left) differs to the generated hex (right)"
    );
}

#[test]
fn kmip_1_0_usecase_4_1_step_8_client_b_get_attribute_response() {
    // From: https://docs.oasis-open.org/kmip/usecases/v1.0/cs01/kmip-usecases-1.0-cs-01.html#_Toc262822060
    // Tag: Response Message (0x42007B), Type: Structure (0x01), Data:
    //   Tag: Response Header (0x42007A), Type: Structure (0x01), Data:
    //     Tag: Protocol Version (0x420069), Type: Structure (0x01), Data:
    //       Tag: Protocol Version Major (0x42006A), Type: Integer (0x02), Data: 0x00000001 (1)
    //       Tag: Protocol Version Minor (0x42006B), Type: Integer (0x02), Data: 0x00000000 (0)
    //     Tag: Time Stamp (0x420092), Type: Date-Time (0x09), Data: 0x000000004AFBED2C (Thu Nov 12 12:10:36 CET 2009)
    //     Tag: Batch Count (0x42000D), Type: Integer (0x02), Data: 0x00000001 (1)
    //   Tag: Batch Item (0x42000F), Type: Structure (0x01), Data:
    //     Tag: Operation (0x42005C), Type: Enumeration (0x05), Data: 0x0000000B (Get Attributes)
    //     Tag: Result Status (0x42007F), Type: Enumeration (0x05), Data: 0x00000000 (Success)
    //     Tag: Response Payload (0x42007C), Type: Structure (0x01), Data:
    //       Tag: Unique Identifier (0x420094), Type: Text String (0x07), Data: 21d28b8a-06df-43c0-b72f-2a161633ada9
    //       Tag: Attribute (0x420008), Type: Structure (0x01), Data:
    //         Tag: Attribute Name (0x42000A), Type: Text String (0x07), Data: State
    //         Tag: Attribute Value (0x42000B), Type: Enumeration (0x05), Data: 0x00000004 (Compromised)
    let use_case_response_hex = concat!(
        "42007B01000000D842007A0100000048420069010000002042006A0200000004000000010000000042006B02000000040",
        "0000000000000004200920900000008000000004AFBED2C42000D0200000004000000010000000042000F010000008042",
        "005C05000000040000000B0000000042007F0500000004000000000000000042007C01000000584200940700000024323",
        "16432386238612D303664662D343363302D623732662D3261313631363333616461390000000042000801000000204200",
        "0A0700000005537461746500000042000B05000000040000000400000000",
    );
    let ttlv_wire = hex::decode(use_case_response_hex).unwrap();
    let res: ResponseMessage = from_slice(ttlv_wire.as_ref()).unwrap();

    assert_eq!(res.header.protocol_version.major, 1);
    assert_eq!(res.header.protocol_version.minor, 0);
    assert_eq!(res.header.timestamp, 0x000000004AFBED2C);
    assert_eq!(res.header.batch_count, 1);
    assert_eq!(res.batch_items.len(), 1);

    let item = &res.batch_items[0];
    assert!(matches!(item.result_status, ResultStatus::Success));
    assert!(matches!(item.operation, Some(Operation::GetAttributes)));
    assert!(matches!(&item.payload, Some(ResponsePayload::GetAttributes(_))));

    if let Some(ResponsePayload::GetAttributes(payload)) = item.payload.as_ref() {
        assert_eq!(&payload.unique_identifier, KEY_ID);
        assert!(payload.attributes.is_some());
        if let Some(attributes) = &payload.attributes {
            assert_eq!(attributes.len(), 1);
            assert_eq!(&attributes[0].name, "State");
            assert_eq!(attributes[0].value, AttributeValue::State(State::Compromised));
        }
    } else {
        panic!("Wrong payload");
    }
}

#[test]
fn kmip_1_0_usecase_4_1_step_9_client_a_get_attribute_list_request() {
    let use_case_request = RequestMessage(
        RequestHeader(
            request::ProtocolVersion(ProtocolVersionMajor(1), ProtocolVersionMinor(0)),
            Option::<MaximumResponseSize>::None,
            Option::<Authentication>::None,
            BatchCount(1),
        ),
        vec![BatchItem(
            Operation::GetAttributeList,
            Option::<UniqueBatchItemID>::None,
            RequestPayload::GetAttributeList(Some(UniqueIdentifier(KEY_ID.into()))),
        )],
    );

    let use_case_request_hex = concat!(
        "42007801000000904200770100000038420069010000002042006A0200000004000000010000000042006B02000000040",
        "00000000000000042000D0200000004000000010000000042000F010000004842005C05000000040000000C0000000042",
        "00790100000030420094070000002432316432386238612D303664662D343363302D623732662D3261313631363333616",
        "4613900000000",
    );
    let actual_request_hex = hex::encode_upper(to_vec(&use_case_request).unwrap());

    assert_eq!(
        use_case_request_hex, actual_request_hex,
        "expected hex (left) differs to the generated hex (right)"
    );
}

#[test]
fn kmip_1_0_usecase_4_1_step_9_client_a_get_attribute_list_response() {
    // From: https://docs.oasis-open.org/kmip/usecases/v1.0/cs01/kmip-usecases-1.0-cs-01.html#_Toc262822060
    // Tag: Response Message (0x42007B), Type: Structure (0x01), Data:
    //   Tag: Response Header (0x42007A), Type: Structure (0x01), Data:
    //     Tag: Protocol Version (0x420069), Type: Structure (0x01), Data:
    //       Tag: Protocol Version Major (0x42006A), Type: Integer (0x02), Data: 0x00000001 (1)
    //       Tag: Protocol Version Minor (0x42006B), Type: Integer (0x02), Data: 0x00000000 (0)
    //     Tag: Time Stamp (0x420092), Type: Date-Time (0x09), Data: 0x000000004AFBED2C (Thu Nov 12 12:10:36 CET 2009)
    //     Tag: Batch Count (0x42000D), Type: Integer (0x02), Data: 0x00000001 (1)
    //   Tag: Batch Item (0x42000F), Type: Structure (0x01), Data:
    //     Tag: Operation (0x42005C), Type: Enumeration (0x05), Data: 0x0000000C (Get Attribute List)
    //     Tag: Result Status (0x42007F), Type: Enumeration (0x05), Data: 0x00000000 (Success)
    //     Tag: Response Payload (0x42007C), Type: Structure (0x01), Data:
    //       Tag: Unique Identifier (0x420094), Type: Text String (0x07), Data: 21d28b8a-06df-43c0-b72f-2a161633ada9
    //       Tag: Attribute Name (0x42000A), Type: Text String (0x07), Data: Cryptographic Length
    //       Tag: Attribute Name (0x42000A), Type: Text String (0x07), Data: Cryptographic Algorithm
    //       Tag: Attribute Name (0x42000A), Type: Text String (0x07), Data: State
    //       Tag: Attribute Name (0x42000A), Type: Text String (0x07), Data: Compromise Occurrence Date
    //       Tag: Attribute Name (0x42000A), Type: Text String (0x07), Data: Compromise Date
    //       Tag: Attribute Name (0x42000A), Type: Text String (0x07), Data: Digest
    //       Tag: Attribute Name (0x42000A), Type: Text String (0x07), Data: Initial Date
    //       Tag: Attribute Name (0x42000A), Type: Text String (0x07), Data: Activation Date
    //       Tag: Attribute Name (0x42000A), Type: Text String (0x07), Data: Revocation Reason
    //       Tag: Attribute Name (0x42000A), Type: Text String (0x07), Data: Unique Identifier
    //       Tag: Attribute Name (0x42000A), Type: Text String (0x07), Data: Name
    //       Tag: Attribute Name (0x42000A), Type: Text String (0x07), Data: Cryptographic Usage Mask
    //       Tag: Attribute Name (0x42000A), Type: Text String (0x07), Data: Object Type
    //       Tag: Attribute Name (0x42000A), Type: Text String (0x07), Data: Last Change Date
    let use_case_response_hex = concat!(
        "42007B010000022042007A0100000048420069010000002042006A0200000004000000010000000042006B02000000040",
        "0000000000000004200920900000008000000004AFBED2C42000D0200000004000000010000000042000F01000001C842",
        "005C05000000040000000C0000000042007F0500000004000000000000000042007C01000001A04200940700000024323",
        "16432386238612D303664662D343363302D623732662D3261313631363333616461390000000042000A07000000144372",
        "7970746F67726170686963204C656E6774680000000042000A070000001743727970746F6772617068696320416C676F7",
        "26974686D0042000A0700000005537461746500000042000A070000001A436F6D70726F6D697365204F6363757272656E",
        "6365204461746500000000000042000A070000000F436F6D70726F6D69736520446174650042000A07000000064469676",
        "57374000042000A070000000C496E697469616C20446174650000000042000A070000000F41637469766174696F6E2044",
        "6174650042000A07000000115265766F636174696F6E20526561736F6E0000000000000042000A0700000011556E69717",
        "565204964656E7469666965720000000000000042000A07000000044E616D650000000042000A07000000184372797074",
        "6F67726170686963205573616765204D61736B42000A070000000B4F626A6563742054797065000000000042000A07000",
        "000104C617374204368616E67652044617465",
    );
    let ttlv_wire = hex::decode(use_case_response_hex).unwrap();
    let res: ResponseMessage = from_slice(ttlv_wire.as_ref()).unwrap();

    assert_eq!(res.header.protocol_version.major, 1);
    assert_eq!(res.header.protocol_version.minor, 0);
    assert_eq!(res.header.timestamp, 0x000000004AFBED2C);
    assert_eq!(res.header.batch_count, 1);
    assert_eq!(res.batch_items.len(), 1);

    let item = &res.batch_items[0];
    assert!(matches!(item.result_status, ResultStatus::Success));
    assert!(matches!(item.operation, Some(Operation::GetAttributeList)));
    assert!(matches!(&item.payload, Some(ResponsePayload::GetAttributeList(_))));

    if let Some(ResponsePayload::GetAttributeList(payload)) = item.payload.as_ref() {
        assert_eq!(&payload.unique_identifier, KEY_ID);
        assert_eq!(payload.attributes.len(), 14);
        assert_eq!(&payload.attributes[0], "Cryptographic Length");
        assert_eq!(&payload.attributes[1], "Cryptographic Algorithm");
        assert_eq!(&payload.attributes[2], "State");
        assert_eq!(&payload.attributes[3], "Compromise Occurrence Date");
        assert_eq!(&payload.attributes[4], "Compromise Date");
        assert_eq!(&payload.attributes[5], "Digest");
        assert_eq!(&payload.attributes[6], "Initial Date");
        assert_eq!(&payload.attributes[7], "Activation Date");
        assert_eq!(&payload.attributes[8], "Revocation Reason");
        assert_eq!(&payload.attributes[9], "Unique Identifier");
        assert_eq!(&payload.attributes[10], "Name");
        assert_eq!(&payload.attributes[11], "Cryptographic Usage Mask");
        assert_eq!(&payload.attributes[12], "Object Type");
        assert_eq!(&payload.attributes[13], "Last Change Date");
    } else {
        panic!("Wrong payload");
    }
}

// SKIP CLIENT A GET ATTRIBUTES AS IT IS IDENTICAL TO THE CLIENT B GET ATTRIBUTES REQUEST AND RESPONSE TEST ABOVE

#[test]
fn kmip_1_0_usecase_4_1_step_11_client_a_add_attribute_batch_request() {
    let use_case_request = RequestMessage(
        RequestHeader(
            request::ProtocolVersion(ProtocolVersionMajor(1), ProtocolVersionMinor(0)),
            Option::<MaximumResponseSize>::None,
            Option::<Authentication>::None,
            BatchCount(2),
        ),
        vec![
            BatchItem(
                Operation::AddAttribute,
                Some(UniqueBatchItemID(hex::decode("9D407FFB45C95672").unwrap())),
                RequestPayload::AddAttribute(
                    Some(UniqueIdentifier(KEY_ID.into())),
                    Attribute(
                        AttributeName("x-attribute1".into()),
                        Option::<AttributeIndex>::None,
                        AttributeValue::TextString("Value1".into()),
                    ),
                ),
            ),
            BatchItem(
                Operation::AddAttribute,
                Some(UniqueBatchItemID(hex::decode("D62107C3158409D8").unwrap())),
                RequestPayload::AddAttribute(
                    Some(UniqueIdentifier(KEY_ID.into())),
                    Attribute(
                        AttributeName("x-attribute2".into()),
                        Option::<AttributeIndex>::None,
                        AttributeValue::TextString("Value2".into()),
                    ),
                ),
            ),
        ],
    );

    let use_case_request_hex = concat!(
        "42007801000001604200770100000038420069010000002042006A0200000004000000010000000042006B02000000040",
        "00000000000000042000D0200000004000000020000000042000F010000008842005C05000000040000000D0000000042",
        "009308000000089D407FFB45C956724200790100000060420094070000002432316432386238612D303664662D3433633",
        "02D623732662D32613136313633336164613900000000420008010000002842000A070000000C782D6174747269627574",
        "65310000000042000B070000000656616C756531000042000F010000008842005C05000000040000000D0000000042009",
        "30800000008D62107C3158409D84200790100000060420094070000002432316432386238612D303664662D343363302D",
        "623732662D32613136313633336164613900000000420008010000002842000A070000000C782D6174747269627574653",
        "20000000042000B070000000656616C7565320000",
    );
    let actual_request_hex = hex::encode_upper(to_vec(&use_case_request).unwrap());

    assert_eq!(
        use_case_request_hex, actual_request_hex,
        "expected hex (left) differs to the generated hex (right)"
    );
}

#[test]
fn kmip_1_0_usecase_4_1_step_11_client_a_add_attribute_batch_response() {
    // From: http://docs.oasis-open.org/kmip/usecases/v1.0/cs01/kmip-usecases-1.0-cs-01.html#_Toc262822061
    // Tag: Response Message (0x42007B), Type: Structure (0x01), Data:
    //   Tag: Response Header (0x42007A), Type: Structure (0x01), Data:
    //     Tag: Protocol Version (0x420069), Type: Structure (0x01), Data:
    //       Tag: Protocol Version Major (0x42006A), Type: Integer (0x02), Data: 0x00000001 (1)
    //       Tag: Protocol Version Minor (0x42006B), Type: Integer (0x02), Data: 0x00000000 (0)
    //     Tag: Time Stamp (0x420092), Type: Date-Time (0x09), Data: 0x000000004AFBED2C (Thu Nov 12 12:10:36 CET 2009)
    //     Tag: Batch Count (0x42000D), Type: Integer (0x02), Data: 0x00000002 (2)
    //   Tag: Batch Item (0x42000F), Type: Structure (0x01), Data:
    //     Tag: Operation (0x42005C), Type: Enumeration (0x05), Data: 0x0000000D (Add Attribute)
    //     Tag: Unique Batch Item ID (0x420093), Type: Octet String (0x08), Data: 9D407FFB45C95672
    //     Tag: Result Status (0x42007F), Type: Enumeration (0x05), Data: 0x00000000 (Success)
    //     Tag: Response Payload (0x42007C), Type: Structure (0x01), Data:
    //       Tag: Unique Identifier (0x420094), Type: Text String (0x07), Data: 21d28b8a-06df-43c0-b72f-2a161633ada9
    //       Tag: Attribute (0x420008), Type: Structure (0x01), Data:
    //         Tag: Attribute Name (0x42000A), Type: Text String (0x07), Data: x-attribute1
    //         Tag: Attribute Value (0x42000B), Type: Text String (0x07), Data: Value1
    //   Tag: Batch Item (0x42000F), Type: Structure (0x01), Data:
    //     Tag: Operation (0x42005C), Type: Enumeration (0x05), Data: 0x0000000D (Add Attribute)
    //     Tag: Unique Batch Item ID (0x420093), Type: Octet String (0x08), Data: D62107C3158409D8
    //     Tag: Result Status (0x42007F), Type: Enumeration (0x05), Data: 0x00000000 (Success)
    //     Tag: Response Payload (0x42007C), Type: Structure (0x01), Data:
    //       Tag: Unique Identifier (0x420094), Type: Text String (0x07), Data: 21d28b8a-06df-43c0-b72f-2a161633ada9
    //       Tag: Attribute (0x420008), Type: Structure (0x01), Data:
    //         Tag: Attribute Name (0x42000A), Type: Text String (0x07), Data: x-attribute2
    //         Tag: Attribute Value (0x42000B), Type: Text String (0x07), Data: Value2
    let use_case_response_hex = concat!(
        "42007B010000019042007A0100000048420069010000002042006A0200000004000000010000000042006B02000000040",
        "0000000000000004200920900000008000000004AFBED2C42000D0200000004000000020000000042000F010000009842",
        "005C05000000040000000D0000000042009308000000089D407FFB45C9567242007F05000000040000000000000000420",
        "07C0100000060420094070000002432316432386238612D303664662D343363302D623732662D32613136313633336164",
        "613900000000420008010000002842000A070000000C782D617474726962757465310000000042000B070000000656616",
        "C756531000042000F010000009842005C05000000040000000D000000004200930800000008D62107C3158409D842007F",
        "0500000004000000000000000042007C0100000060420094070000002432316432386238612D303664662D343363302D6",
        "23732662D32613136313633336164613900000000420008010000002842000A070000000C782D61747472696275746532",
        "0000000042000B070000000656616C7565320000",
    );
    let ttlv_wire = hex::decode(use_case_response_hex).unwrap();
    let res: ResponseMessage = from_slice(ttlv_wire.as_ref()).unwrap();

    assert_eq!(res.header.protocol_version.major, 1);
    assert_eq!(res.header.protocol_version.minor, 0);
    assert_eq!(res.header.timestamp, 0x000000004AFBED2C);
    assert_eq!(res.header.batch_count, 2);
    assert_eq!(res.batch_items.len(), 2);

    let item = &res.batch_items[0];
    assert!(matches!(item.result_status, ResultStatus::Success));
    assert_eq!(
        item.unique_batch_item_id.as_ref().unwrap(),
        hex::decode("9D407FFB45C95672").unwrap()
    );
    assert!(matches!(item.operation, Some(Operation::AddAttribute)));
    assert!(matches!(&item.payload, Some(ResponsePayload::AddAttribute(_))));

    if let Some(ResponsePayload::AddAttribute(payload)) = item.payload.as_ref() {
        assert_eq!(&payload.unique_identifier, KEY_ID);
        assert_eq!(&payload.attribute.name, "x-attribute1");
        assert!(matches!(&payload.attribute.value, AttributeValue::TextString(str) if str == "Value1"));
    } else {
        panic!("Wrong payload for batch item 0");
    }

    let item = &res.batch_items[1];
    assert!(matches!(item.result_status, ResultStatus::Success));
    assert_eq!(
        item.unique_batch_item_id.as_ref().unwrap(),
        hex::decode("D62107C3158409D8").unwrap()
    );
    assert!(matches!(item.operation, Some(Operation::AddAttribute)));
    assert!(matches!(&item.payload, Some(ResponsePayload::AddAttribute(_))));

    if let Some(ResponsePayload::AddAttribute(payload)) = item.payload.as_ref() {
        assert_eq!(&payload.unique_identifier, KEY_ID);
        assert_eq!(&payload.attribute.name, "x-attribute2");
        assert!(matches!(&payload.attribute.value, AttributeValue::TextString(str) if str == "Value2"));
    } else {
        panic!("Wrong payload for batch item 1");
    }
}

#[test]
fn kmip_1_0_usecase_4_1_step_12_client_a_modify_attribute_batch_request() {
    let use_case_request = RequestMessage(
        RequestHeader(
            request::ProtocolVersion(ProtocolVersionMajor(1), ProtocolVersionMinor(0)),
            Option::<MaximumResponseSize>::None,
            Option::<Authentication>::None,
            BatchCount(2),
        ),
        vec![
            BatchItem(
                Operation::ModifyAttribute,
                Some(UniqueBatchItemID(hex::decode("47FB42CCECA3F6EC").unwrap())),
                RequestPayload::ModifyAttribute(
                    Some(UniqueIdentifier(KEY_ID.into())),
                    Attribute(
                        AttributeName("x-attribute1".into()),
                        Option::<AttributeIndex>::None,
                        AttributeValue::TextString("ModifiedValue1".into()),
                    ),
                ),
            ),
            BatchItem(
                Operation::ModifyAttribute,
                Some(UniqueBatchItemID(hex::decode("08019A230A05E9E1").unwrap())),
                RequestPayload::ModifyAttribute(
                    Some(UniqueIdentifier(KEY_ID.into())),
                    Attribute(
                        AttributeName("x-attribute2".into()),
                        Option::<AttributeIndex>::None,
                        AttributeValue::TextString("ModifiedValue2".into()),
                    ),
                ),
            ),
        ],
    );

    let use_case_request_hex = concat!(
        "42007801000001704200770100000038420069010000002042006A0200000004000000010000000042006B02000000040",
        "00000000000000042000D0200000004000000020000000042000F010000009042005C05000000040000000E0000000042",
        "0093080000000847FB42CCECA3F6EC4200790100000068420094070000002432316432386238612D303664662D3433633",
        "02D623732662D32613136313633336164613900000000420008010000003042000A070000000C782D6174747269627574",
        "65310000000042000B070000000E4D6F64696669656456616C756531000042000F010000009042005C050000000400000",
        "00E00000000420093080000000808019A230A05E9E14200790100000068420094070000002432316432386238612D3036",
        "64662D343363302D623732662D32613136313633336164613900000000420008010000003042000A070000000C782D617",
        "474726962757465320000000042000B070000000E4D6F64696669656456616C7565320000",
    );
    let actual_request_hex = hex::encode_upper(to_vec(&use_case_request).unwrap());

    assert_eq!(
        use_case_request_hex, actual_request_hex,
        "expected hex (left) differs to the generated hex (right)"
    );
}

#[test]
fn kmip_1_0_usecase_4_1_step_12_client_a_modify_attribute_batch_response() {
    // From: http://docs.oasis-open.org/kmip/usecases/v1.0/cs01/kmip-usecases-1.0-cs-01.html#_Toc262822061
    // Tag: Response Message (0x42007B), Type: Structure (0x01), Data:
    //   Tag: Response Header (0x42007A), Type: Structure (0x01), Data:
    //     Tag: Protocol Version (0x420069), Type: Structure (0x01), Data:
    //       Tag: Protocol Version Major (0x42006A), Type: Integer (0x02), Data: 0x00000001 (1)
    //       Tag: Protocol Version Minor (0x42006B), Type: Integer (0x02), Data: 0x00000000 (0)
    //     Tag: Time Stamp (0x420092), Type: Date-Time (0x09), Data: 0x000000004AFBED2D (Thu Nov 12 12:10:37 CET 2009)
    //     Tag: Batch Count (0x42000D), Type: Integer (0x02), Data: 0x00000002 (2)
    //   Tag: Batch Item (0x42000F), Type: Structure (0x01), Data:
    //     Tag: Operation (0x42005C), Type: Enumeration (0x05), Data: 0x0000000E (Modify Attribute)
    //     Tag: Unique Batch Item ID (0x420093), Type: Octet String (0x08), Data: 47FB42CCECA3F6EC
    //     Tag: Result Status (0x42007F), Type: Enumeration (0x05), Data: 0x00000000 (Success)
    //     Tag: Response Payload (0x42007C), Type: Structure (0x01), Data:
    //       Tag: Unique Identifier (0x420094), Type: Text String (0x07), Data: 21d28b8a-06df-43c0-b72f-2a161633ada9
    //       Tag: Attribute (0x420008), Type: Structure (0x01), Data:
    //         Tag: Attribute Name (0x42000A), Type: Text String (0x07), Data: x-attribute1
    //         Tag: Attribute Value (0x42000B), Type: Text String (0x07), Data: ModifiedValue1
    //   Tag: Batch Item (0x42000F), Type: Structure (0x01), Data:
    //     Tag: Operation (0x42005C), Type: Enumeration (0x05), Data: 0x0000000E (Modify Attribute)
    //     Tag: Unique Batch Item ID (0x420093), Type: Octet String (0x08), Data: 08019A230A05E9E1
    //     Tag: Result Status (0x42007F), Type: Enumeration (0x05), Data: 0x00000000 (Success)
    //     Tag: Response Payload (0x42007C), Type: Structure (0x01), Data:
    //       Tag: Unique Identifier (0x420094), Type: Text String (0x07), Data: 21d28b8a-06df-43c0-b72f-2a161633ada9
    //       Tag: Attribute (0x420008), Type: Structure (0x01), Data:
    //         Tag: Attribute Name (0x42000A), Type: Text String (0x07), Data: x-attribute2
    //         Tag: Attribute Value (0x42000B), Type: Text String (0x07), Data: ModifiedValue2
    let use_case_response_hex = concat!(
        "42007B01000001A042007A0100000048420069010000002042006A0200000004000000010000000042006B02000000040",
        "0000000000000004200920900000008000000004AFBED2D42000D0200000004000000020000000042000F01000000A042",
        "005C05000000040000000E00000000420093080000000847FB42CCECA3F6EC42007F05000000040000000000000000420",
        "07C0100000068420094070000002432316432386238612D303664662D343363302D623732662D32613136313633336164",
        "613900000000420008010000003042000A070000000C782D617474726962757465310000000042000B070000000E4D6F6",
        "4696669656456616C756531000042000F01000000A042005C05000000040000000E00000000420093080000000808019A",
        "230A05E9E142007F0500000004000000000000000042007C0100000068420094070000002432316432386238612D30366",
        "4662D343363302D623732662D32613136313633336164613900000000420008010000003042000A070000000C782D6174",
        "74726962757465320000000042000B070000000E4D6F64696669656456616C7565320000",
    );
    let ttlv_wire = hex::decode(use_case_response_hex).unwrap();
    let res: ResponseMessage = from_slice(ttlv_wire.as_ref()).unwrap();

    assert_eq!(res.header.protocol_version.major, 1);
    assert_eq!(res.header.protocol_version.minor, 0);
    assert_eq!(res.header.timestamp, 0x000000004AFBED2D);
    assert_eq!(res.header.batch_count, 2);
    assert_eq!(res.batch_items.len(), 2);

    let item = &res.batch_items[0];
    assert!(matches!(item.result_status, ResultStatus::Success));
    assert_eq!(
        item.unique_batch_item_id.as_ref().unwrap(),
        hex::decode("47FB42CCECA3F6EC").unwrap()
    );
    assert!(matches!(item.operation, Some(Operation::ModifyAttribute)));
    assert!(matches!(&item.payload, Some(ResponsePayload::ModifyAttribute(_))));

    if let Some(ResponsePayload::ModifyAttribute(payload)) = item.payload.as_ref() {
        assert_eq!(&payload.unique_identifier, KEY_ID);
        assert_eq!(&payload.attribute.name, "x-attribute1");
        assert!(matches!(&payload.attribute.value, AttributeValue::TextString(str) if str == "ModifiedValue1"));
    } else {
        panic!("Wrong payload for batch item 0");
    }

    let item = &res.batch_items[1];
    assert!(matches!(item.result_status, ResultStatus::Success));
    assert_eq!(
        item.unique_batch_item_id.as_ref().unwrap(),
        hex::decode("08019A230A05E9E1").unwrap()
    );
    assert!(matches!(item.operation, Some(Operation::ModifyAttribute)));
    assert!(matches!(&item.payload, Some(ResponsePayload::ModifyAttribute(_))));

    if let Some(ResponsePayload::ModifyAttribute(payload)) = item.payload.as_ref() {
        assert_eq!(&payload.unique_identifier, KEY_ID);
        assert_eq!(&payload.attribute.name, "x-attribute2");
        assert!(matches!(&payload.attribute.value, AttributeValue::TextString(str) if str == "ModifiedValue2"));
    } else {
        panic!("Wrong payload for batch item 1");
    }
}

#[test]
fn kmip_1_0_usecase_4_1_step_13_client_a_delete_attribute_batch_request() {
    let use_case_request = RequestMessage(
        RequestHeader(
            request::ProtocolVersion(ProtocolVersionMajor(1), ProtocolVersionMinor(0)),
            Option::<MaximumResponseSize>::None,
            Option::<Authentication>::None,
            BatchCount(2),
        ),
        vec![
            BatchItem(
                Operation::DeleteAttribute,
                Some(UniqueBatchItemID(hex::decode("3E2C080FA8806057").unwrap())),
                RequestPayload::DeleteAttribute(
                    Some(UniqueIdentifier(KEY_ID.into())),
                    AttributeName("x-attribute1".into()),
                    Option::<AttributeIndex>::None,
                ),
            ),
            BatchItem(
                Operation::DeleteAttribute,
                Some(UniqueBatchItemID(hex::decode("9D55988D43D23B82").unwrap())),
                RequestPayload::DeleteAttribute(
                    Some(UniqueIdentifier(KEY_ID.into())),
                    AttributeName("x-attribute2".into()),
                    Option::<AttributeIndex>::None,
                ),
            ),
        ],
    );

    let use_case_request_hex = concat!(
        "42007801000001304200770100000038420069010000002042006A0200000004000000010000000042006B02000000040",
        "00000000000000042000D0200000004000000020000000042000F010000007042005C05000000040000000F0000000042",
        "009308000000083E2C080FA88060574200790100000048420094070000002432316432386238612D303664662D3433633",
        "02D623732662D3261313631363333616461390000000042000A070000000C782D61747472696275746531000000004200",
        "0F010000007042005C05000000040000000F0000000042009308000000089D55988D43D23B82420079010000004842009",
        "4070000002432316432386238612D303664662D343363302D623732662D3261313631363333616461390000000042000A",
        "070000000C782D6174747269627574653200000000",
    );
    let actual_request_hex = hex::encode_upper(to_vec(&use_case_request).unwrap());

    assert_eq!(
        use_case_request_hex, actual_request_hex,
        "expected hex (left) differs to the generated hex (right)"
    );
}

#[test]
fn kmip_1_0_usecase_4_1_step_13_client_a_delete_attribute_batch_response() {
    // From: http://docs.oasis-open.org/kmip/usecases/v1.0/cs01/kmip-usecases-1.0-cs-01.html#_Toc262822061
    // Tag: Response Message (0x42007B), Type: Structure (0x01), Data:
    //   Tag: Response Header (0x42007A), Type: Structure (0x01), Data:
    //     Tag: Protocol Version (0x420069), Type: Structure (0x01), Data:
    //       Tag: Protocol Version Major (0x42006A), Type: Integer (0x02), Data: 0x00000001 (1)
    //       Tag: Protocol Version Minor (0x42006B), Type: Integer (0x02), Data: 0x00000000 (0)
    //     Tag: Time Stamp (0x420092), Type: Date-Time (0x09), Data: 0x000000004AFBED2D (Thu Nov 12 12:10:37 CET 2009)
    //     Tag: Batch Count (0x42000D), Type: Integer (0x02), Data: 0x00000002 (2)
    //   Tag: Batch Item (0x42000F), Type: Structure (0x01), Data:
    //     Tag: Operation (0x42005C), Type: Enumeration (0x05), Data: 0x0000000F (Delete Attribute)
    //     Tag: Unique Batch Item ID (0x420093), Type: Octet String (0x08), Data: 3E2C080FA8806057
    //     Tag: Result Status (0x42007F), Type: Enumeration (0x05), Data: 0x00000000 (Success)
    //     Tag: Response Payload (0x42007C), Type: Structure (0x01), Data:
    //       Tag: Unique Identifier (0x420094), Type: Text String (0x07), Data: 21d28b8a-06df-43c0-b72f-2a161633ada9
    //       Tag: Attribute (0x420008), Type: Structure (0x01), Data:
    //         Tag: Attribute Name (0x42000A), Type: Text String (0x07), Data: x-attribute1
    //         Tag: Attribute Value (0x42000B), Type: Text String (0x07), Data: ModifiedValue1
    //   Tag: Batch Item (0x42000F), Type: Structure (0x01), Data:
    //     Tag: Operation (0x42005C), Type: Enumeration (0x05), Data: 0x0000000F (Delete Attribute)
    //     Tag: Unique Batch Item ID (0x420093), Type: Octet String (0x08), Data: 9D55988D43D23B82
    //     Tag: Result Status (0x42007F), Type: Enumeration (0x05), Data: 0x00000000 (Success)
    //     Tag: Response Payload (0x42007C), Type: Structure (0x01), Data:
    //       Tag: Unique Identifier (0x420094), Type: Text String (0x07), Data: 21d28b8a-06df-43c0-b72f-2a161633ada9
    //       Tag: Attribute (0x420008), Type: Structure (0x01), Data:
    //         Tag: Attribute Name (0x42000A), Type: Text String (0x07), Data: x-attribute2
    //         Tag: Attribute Value (0x42000B), Type: Text String (0x07), Data: ModifiedValue2
    let use_case_response_hex = concat!(
        "42007B01000001A042007A0100000048420069010000002042006A0200000004000000010000000042006B02000000040",
        "0000000000000004200920900000008000000004AFBED2D42000D0200000004000000020000000042000F01000000A042",
        "005C05000000040000000F0000000042009308000000083E2C080FA880605742007F05000000040000000000000000420",
        "07C0100000068420094070000002432316432386238612D303664662D343363302D623732662D32613136313633336164",
        "613900000000420008010000003042000A070000000C782D617474726962757465310000000042000B070000000E4D6F6",
        "4696669656456616C756531000042000F01000000A042005C05000000040000000F0000000042009308000000089D5598",
        "8D43D23B8242007F0500000004000000000000000042007C0100000068420094070000002432316432386238612D30366",
        "4662D343363302D623732662D32613136313633336164613900000000420008010000003042000A070000000C782D6174",
        "74726962757465320000000042000B070000000E4D6F64696669656456616C7565320000",
    );
    let ttlv_wire = hex::decode(use_case_response_hex).unwrap();
    let res: ResponseMessage = from_slice(ttlv_wire.as_ref()).unwrap();

    assert_eq!(res.header.protocol_version.major, 1);
    assert_eq!(res.header.protocol_version.minor, 0);
    assert_eq!(res.header.timestamp, 0x000000004AFBED2D);
    assert_eq!(res.header.batch_count, 2);
    assert_eq!(res.batch_items.len(), 2);

    let item = &res.batch_items[0];
    assert!(matches!(item.result_status, ResultStatus::Success));
    assert_eq!(
        item.unique_batch_item_id.as_ref().unwrap(),
        hex::decode("3E2C080FA8806057").unwrap()
    );
    assert!(matches!(item.operation, Some(Operation::DeleteAttribute)));
    assert!(matches!(&item.payload, Some(ResponsePayload::DeleteAttribute(_))));

    if let Some(ResponsePayload::DeleteAttribute(payload)) = item.payload.as_ref() {
        assert_eq!(&payload.unique_identifier, KEY_ID);
        assert_eq!(&payload.attribute.name, "x-attribute1");
        assert!(matches!(&payload.attribute.value, AttributeValue::TextString(str) if str == "ModifiedValue1"));
    } else {
        panic!("Wrong payload for batch item 0");
    }

    let item = &res.batch_items[1];
    assert!(matches!(item.result_status, ResultStatus::Success));
    assert_eq!(
        item.unique_batch_item_id.as_ref().unwrap(),
        hex::decode("9D55988D43D23B82").unwrap()
    );
    assert!(matches!(item.operation, Some(Operation::DeleteAttribute)));
    assert!(matches!(&item.payload, Some(ResponsePayload::DeleteAttribute(_))));

    if let Some(ResponsePayload::DeleteAttribute(payload)) = item.payload.as_ref() {
        assert_eq!(&payload.unique_identifier, KEY_ID);
        assert_eq!(&payload.attribute.name, "x-attribute2");
        assert!(matches!(&payload.attribute.value, AttributeValue::TextString(str) if str == "ModifiedValue2"));
    } else {
        panic!("Wrong payload for batch item 1");
    }
}

// SKIP CLIENT A GET SYMMETRIC KEY AS IT IS IDENTICAL TO THE CLIENT B GET SYMMETRIC KEY REQUEST AND RESPONSE TEST ABOVE

#[test]
fn kmip_1_0_usecase_4_1_step_15_client_a_destroy_symmetric_key_request() {
    let use_case_request = RequestMessage(
        RequestHeader(
            request::ProtocolVersion(ProtocolVersionMajor(1), ProtocolVersionMinor(0)),
            Option::<MaximumResponseSize>::None,
            Option::<Authentication>::None,
            BatchCount(1),
        ),
        vec![BatchItem(
            Operation::Destroy,
            Option::<UniqueBatchItemID>::None,
            RequestPayload::Destroy(Some(UniqueIdentifier(KEY_ID.into()))),
        )],
    );

    let use_case_request_hex = concat!(
        "42007801000000904200770100000038420069010000002042006A0200000004000000010000000042006B02000000040",
        "00000000000000042000D0200000004000000010000000042000F010000004842005C0500000004000000140000000042",
        "00790100000030420094070000002432316432386238612D303664662D343363302D623732662D3261313631363333616",
        "4613900000000",
    );
    let actual_request_hex = hex::encode_upper(to_vec(&use_case_request).unwrap());

    assert_eq!(
        use_case_request_hex, actual_request_hex,
        "expected hex (left) differs to the generated hex (right)"
    );
}

#[test]
fn kmip_1_0_usecase_4_1_step_15_client_a_destroy_symmetric_key_response() {
    // From: http://docs.oasis-open.org/kmip/usecases/v1.0/cs01/kmip-usecases-1.0-cs-01.html#_Toc262822061
    // Tag: Response Message (0x42007B), Type: Structure (0x01), Data:
    //   Tag: Response Header (0x42007A), Type: Structure (0x01), Data:
    //     Tag: Protocol Version (0x420069), Type: Structure (0x01), Data:
    //       Tag: Protocol Version Major (0x42006A), Type: Integer (0x02), Data: 0x00000001 (1)
    //       Tag: Protocol Version Minor (0x42006B), Type: Integer (0x02), Data: 0x00000000 (0)
    //     Tag: Time Stamp (0x420092), Type: Date-Time (0x09), Data: 0x000000004AFBED2E (Thu Nov 12 12:10:38 CET 2009)
    //     Tag: Batch Count (0x42000D), Type: Integer (0x02), Data: 0x00000001 (1)
    //   Tag: Batch Item (0x42000F), Type: Structure (0x01), Data:
    //     Tag: Operation (0x42005C), Type: Enumeration (0x05), Data: 0x00000014 (Destroy)
    //     Tag: Result Status (0x42007F), Type: Enumeration (0x05), Data: 0x00000000 (Success)
    //     Tag: Response Payload (0x42007C), Type: Structure (0x01), Data:
    //       Tag: Unique Identifier (0x420094), Type: Text String (0x07), Data: 21d28b8a-06df-43c0-b72f-2a161633ada9
    let use_case_response_hex = concat!(
        "42007B01000000B042007A0100000048420069010000002042006A0200000004000000010000000042006B02000000040",
        "0000000000000004200920900000008000000004AFBED2E42000D0200000004000000010000000042000F010000005842",
        "005C0500000004000000140000000042007F0500000004000000000000000042007C01000000304200940700000024323",
        "16432386238612D303664662D343363302D623732662D32613136313633336164613900000000",
    );
    let ttlv_wire = hex::decode(use_case_response_hex).unwrap();
    let res: ResponseMessage = from_slice(ttlv_wire.as_ref()).unwrap();

    assert_eq!(res.header.protocol_version.major, 1);
    assert_eq!(res.header.protocol_version.minor, 0);
    assert_eq!(res.header.timestamp, 0x000000004AFBED2E);
    assert_eq!(res.header.batch_count, 1);
    assert_eq!(res.batch_items.len(), 1);

    let item = &res.batch_items[0];
    assert!(matches!(item.result_status, ResultStatus::Success));
    assert!(matches!(item.operation, Some(Operation::Destroy)));
    assert!(matches!(&item.payload, Some(ResponsePayload::Destroy(_))));

    if let Some(ResponsePayload::Destroy(payload)) = item.payload.as_ref() {
        assert_eq!(&payload.unique_identifier, KEY_ID);
    } else {
        panic!("Wrong payload");
    }
}
