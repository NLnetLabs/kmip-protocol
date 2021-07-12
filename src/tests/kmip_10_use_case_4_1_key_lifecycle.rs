//! See: https://docs.oasis-open.org/kmip/usecases/v1.0/cs01/kmip-usecases-1.0-cs-01.html#_Toc262822060

#[allow(unused_imports)]
use pretty_assertions::{assert_eq, assert_ne};

use krill_kmip_ttlv::{de::from_slice, ser::to_vec};

use crate::types::{
    common::{
        AttributeName, AttributeValue, CryptographicAlgorithm, CryptographicUsageMask, ObjectType, Operation, State,
        UniqueIdentifier,
    },
    request::{
        self, Attribute, Authentication, BatchCount, BatchItem, MaximumResponseSize, ProtocolVersionMajor,
        ProtocolVersionMinor, RequestHeader, RequestMessage, RequestPayload, TemplateAttribute,
    },
    response::{ResponseMessage, ResponsePayload, ResultStatus},
};

#[test]
fn client_a_create_request_symmetric_key() {
    let use_case_request = RequestMessage(
        RequestHeader(
            request::ProtocolVersion(ProtocolVersionMajor(1), ProtocolVersionMinor(0)),
            Option::<MaximumResponseSize>::None,
            Option::<Authentication>::None,
            BatchCount(1),
        ),
        vec![BatchItem(
            Operation::Create,
            RequestPayload::Create(
                ObjectType::SymmetricKey,
                TemplateAttribute::unnamed(vec![
                    Attribute::CryptographicAlgorithm(CryptographicAlgorithm::AES),
                    Attribute::CryptographicLength(128),
                    Attribute::Name("Key1".into()),
                    Attribute::CryptographicUsageMask(CryptographicUsageMask::Encrypt),
                ])
                .unwrap(),
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

    assert_eq!(use_case_request_hex, actual_request_hex);
}

#[test]
fn client_a_create_response() {
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
        assert_eq!(&payload.unique_identifier, "21d28b8a-06df-43c0-b72f-2a161633ada9");
    } else {
        panic!("Wrong payload");
    }
}

#[test]
fn client_a_get_state_attribute_request() {
    let use_case_request = RequestMessage(
        RequestHeader(
            request::ProtocolVersion(ProtocolVersionMajor(1), ProtocolVersionMinor(0)),
            Option::<MaximumResponseSize>::None,
            Option::<Authentication>::None,
            BatchCount(1),
        ),
        vec![BatchItem(
            Operation::GetAttributes,
            RequestPayload::GetAttributes(
                Some(UniqueIdentifier("21d28b8a-06df-43c0-b72f-2a161633ada9".into())),
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

    assert_eq!(use_case_request_hex, actual_request_hex);
}

#[test]
fn client_a_get_state_attribute_response() {
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
        assert!(payload.attributes.is_some());
        if let Some(attributes) = &payload.attributes {
            assert_eq!(attributes.len(), 1);

            let attr = &attributes[0];
            assert_eq!(&attr.name, "State");
            assert!(matches!(attr.value, AttributeValue::State(State::PreActive)));
        }
    } else {
        panic!("Wrong payload");
    }
}

#[test]
fn client_a_activate_request() {
    let use_case_request = RequestMessage(
        RequestHeader(
            request::ProtocolVersion(ProtocolVersionMajor(1), ProtocolVersionMinor(0)),
            Option::<MaximumResponseSize>::None,
            Option::<Authentication>::None,
            BatchCount(1),
        ),
        vec![BatchItem(
            Operation::Activate,
            RequestPayload::Activate(Some(UniqueIdentifier("21d28b8a-06df-43c0-b72f-2a161633ada9".into()))),
        )],
    );

    let use_case_request_hex = concat!(
        "42007801000000904200770100000038420069010000002042006A0200000004000000010000000042006B02000000040",
        "00000000000000042000D0200000004000000010000000042000F010000004842005C0500000004000000120000000042",
        "00790100000030420094070000002432316432386238612D303664662D343363302D623732662D3261313631363333616",
        "4613900000000",
    );
    let actual_request_hex = hex::encode_upper(to_vec(&use_case_request).unwrap());

    assert_eq!(use_case_request_hex, actual_request_hex);
}

#[test]
fn client_a_activate_response() {
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
        assert_eq!(&payload.unique_identifier, "21d28b8a-06df-43c0-b72f-2a161633ada9");
    } else {
        panic!("Wrong payload");
    }
}

#[test]
fn client_a_get_state_attribute_request2() {
    let use_case_request = RequestMessage(
        RequestHeader(
            request::ProtocolVersion(ProtocolVersionMajor(1), ProtocolVersionMinor(0)),
            Option::<MaximumResponseSize>::None,
            Option::<Authentication>::None,
            BatchCount(1),
        ),
        vec![BatchItem(
            Operation::GetAttributes,
            RequestPayload::GetAttributes(
                Some(UniqueIdentifier("21d28b8a-06df-43c0-b72f-2a161633ada9".into())),
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

    assert_eq!(use_case_request_hex, actual_request_hex);
}

#[test]
fn client_a_get_state_attribute_response2() {
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
        assert!(payload.attributes.is_some());
        if let Some(attributes) = &payload.attributes {
            assert_eq!(attributes.len(), 1);

            let attr = &attributes[0];
            assert_eq!(&attr.name, "State");
            assert!(matches!(attr.value, AttributeValue::State(State::Active)));
        }
    } else {
        panic!("Wrong payload");
    }
}

#[test]
fn client_b_locate_request_symmetric_key_by_name() {
    let use_case_request = RequestMessage(
        RequestHeader(
            request::ProtocolVersion(ProtocolVersionMajor(1), ProtocolVersionMinor(0)),
            Option::<MaximumResponseSize>::None,
            Option::<Authentication>::None,
            BatchCount(1),
        ),
        vec![BatchItem(
            Operation::Locate,
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

    assert_eq!(use_case_request_hex, actual_request_hex);
}

#[test]
fn client_b_locate_response() {
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
        assert_eq!(&payload.unique_identifiers[0], "21d28b8a-06df-43c0-b72f-2a161633ada9");
    } else {
        panic!("Wrong payload");
    }
}
