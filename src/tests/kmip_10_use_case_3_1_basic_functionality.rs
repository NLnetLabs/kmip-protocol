//! See: https://docs.oasis-open.org/kmip/usecases/v1.0/cs01/kmip-usecases-1.0-cs-01.html#_Toc262822054

#[allow(unused_imports)]
use pretty_assertions::{assert_eq, assert_ne};

use krill_kmip_ttlv::ser::to_vec;

use crate::{
    response::from_slice,
    types::{
        common::{
            ApplicationData, ApplicationNamespace, AttributeIndex, AttributeName, AttributeValue,
            CryptographicAlgorithm, CryptographicUsageMask, ObjectType, Operation, UniqueBatchItemID, UniqueIdentifier,
        },
        request::{
            self, Attribute, Authentication, BatchCount, BatchItem, ManagedObject, MaximumResponseSize,
            ProtocolVersionMajor, ProtocolVersionMinor, RequestHeader, RequestMessage, RequestPayload, Template,
            TemplateAttribute,
        },
        response::{ResponseMessage, ResponsePayload, ResultStatus},
    },
};

const UUID_ID: &'static str = "a6ebbb6f-4c54-4bbb-ad29-be6bad4ecad5";
const KEY_ID: &'static str = "61b10614-d8b5-46f9-8d17-2fa6ea1d747a";

#[test]
fn register_request() {
    let use_case_request = RequestMessage(
        RequestHeader(
            request::ProtocolVersion(ProtocolVersionMajor(1), ProtocolVersionMinor(0)),
            Option::<MaximumResponseSize>::None,
            Option::<Authentication>::None,
            BatchCount(1),
        ),
        vec![BatchItem(
            Operation::Register,
            Option::<UniqueBatchItemID>::None,
            RequestPayload::Register(
                ObjectType::Template,
                TemplateAttribute::unnamed(vec![]),
                Some(ManagedObject::Template(Template(vec![
                    Attribute::ObjectGroup("Group1".into()),
                    Attribute::ApplicationSpecificInformation(
                        ApplicationNamespace("ssl".into()),
                        ApplicationData("www.example.com".into()),
                    ),
                    Attribute::ContactInformation("Joe".into()),
                    Attribute(
                        AttributeName("x-Purpose".into()),
                        Option::<AttributeIndex>::None,
                        AttributeValue::TextString("demonstration".into()),
                    ),
                    Attribute::Name("Template1".into()),
                ]))),
            ),
        )],
    );

    let use_case_request_hex = concat!(
        "42007801000001C84200770100000038420069010000002042006A0200000004000000010000000042006B02000000040",
        "00000000000000042000D0200000004000000010000000042000F010000018042005C0500000004000000030000000042",
        "0079010000016842005705000000040000000600000000420091010000000042009001000001484200080100000028420",
        "00A070000000C4F626A6563742047726F75700000000042000B070000000647726F757031000042000801000000584200",
        "0A07000000204170706C69636174696F6E20537065636966696320496E666F726D6174696F6E42000B010000002842000",
        "3070000000373736C0000000000420002070000000F7777772E6578616D706C652E636F6D00420008010000003042000A",
        "0700000013436F6E7461637420496E666F726D6174696F6E000000000042000B07000000034A6F6500000000004200080",
        "10000003042000A0700000009782D507572706F73650000000000000042000B070000000D64656D6F6E7374726174696F",
        "6E000000420008010000004042000A07000000044E616D650000000042000B0100000028420055070000000954656D706",
        "C617465310000000000000042005405000000040000000100000000",
    );
    let actual_request_hex = hex::encode_upper(to_vec(&use_case_request).unwrap());

    assert_eq!(
        use_case_request_hex, actual_request_hex,
        "expected hex (left) differs to the generated hex (right)"
    );
}

#[test]
fn register_response() {
    // From: https://docs.oasis-open.org/kmip/usecases/v1.0/cs01/kmip-usecases-1.0-cs-01.html#_Toc262822054
    // Tag: Response Message (0x42007B), Type: Structure (0x01), Data:
    //   Tag: Response Header (0x42007A), Type: Structure (0x01), Data:
    //     Tag: Protocol Version (0x420069), Type: Structure (0x01), Data:
    //       Tag: Protocol Version Major (0x42006A), Type: Integer (0x02), Data: 0x00000001 (1)
    //       Tag: Protocol Version Minor (0x42006B), Type: Integer (0x02), Data: 0x00000000 (0)
    //     Tag: Time Stamp (0x420092), Type: Date-Time (0x09), Data: 0x000000004AFBE7C4 (Thu Nov 12 11:47:32 CET 2009)
    //     Tag: Batch Count (0x42000D), Type: Integer (0x02), Data: 0x00000001 (1)
    //   Tag: Batch Item (0x42000F), Type: Structure (0x01), Data:
    //     Tag: Operation (0x42005C), Type: Enumeration (0x05), Data: 0x00000003 (Register)
    //     Tag: Result Status (0x42007F), Type: Enumeration (0x05), Data: 0x00000000 (Success)
    //     Tag: Response Payload (0x42007C), Type: Structure (0x01), Data:
    //       Tag: Unique Identifier (0x420094), Type: Text String (0x07), Data: a6ebbb6f-4c54-4bbb-ad29-be6bad4ecad5
    let use_case_response_hex = concat!(
        "42007B01000000B042007A0100000048420069010000002042006A0200000004000000010000000042006B02000000040",
        "0000000000000004200920900000008000000004AFBE7C442000D0200000004000000010000000042000F010000005842",
        "005C0500000004000000030000000042007F0500000004000000000000000042007C01000000304200940700000024613",
        "66562626236662D346335342D346262622D616432392D62653662616434656361643500000000"
    );
    let ttlv_wire = hex::decode(use_case_response_hex).unwrap();
    let res: ResponseMessage = from_slice(ttlv_wire.as_ref()).unwrap();

    assert_eq!(res.header.protocol_version.major, 1);
    assert_eq!(res.header.protocol_version.minor, 0);
    assert_eq!(res.header.timestamp, 0x000000004AFBE7C4);
    assert_eq!(res.header.batch_count, 1);
    assert_eq!(res.batch_items.len(), 1);

    let item = &res.batch_items[0];
    assert!(matches!(item.result_status, ResultStatus::Success));
    assert!(matches!(item.operation, Some(Operation::Register)));
    assert!(matches!(&item.payload, Some(ResponsePayload::Register(_))));

    if let Some(ResponsePayload::Register(payload)) = item.payload.as_ref() {
        assert_eq!(&payload.unique_identifier, UUID_ID);
    } else {
        panic!("Wrong payload");
    }
}

#[test]
fn create_symmetric_key_request() {
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
                TemplateAttribute::named(
                    "Template1".into(),
                    vec![
                        Attribute::CryptographicAlgorithm(CryptographicAlgorithm::AES),
                        Attribute::CryptographicLength(128),
                        Attribute::CryptographicUsageMask(
                            CryptographicUsageMask::Encrypt | CryptographicUsageMask::Decrypt,
                        ),
                    ],
                ),
            ),
        )],
    );

    let use_case_request_hex = concat!(
        "42007801000001504200770100000038420069010000002042006A0200000004000000010000000042006B02000000040",
        "00000000000000042000D0200000004000000010000000042000F010000010842005C0500000004000000010000000042",
        "007901000000F04200570500000004000000020000000042009101000000D842005301000000284200550700000009546",
        "56D706C617465310000000000000042005405000000040000000100000000420008010000003042000A07000000174372",
        "7970746F6772617068696320416C676F726974686D0042000B05000000040000000300000000420008010000003042000",
        "A070000001443727970746F67726170686963204C656E6774680000000042000B02000000040000008000000000420008",
        "010000003042000A070000001843727970746F67726170686963205573616765204D61736B42000B02000000040000000",
        "C00000000",
    );
    let actual_request_hex = hex::encode_upper(to_vec(&use_case_request).unwrap());

    assert_eq!(
        use_case_request_hex, actual_request_hex,
        "expected hex (left) differs to the generated hex (right)"
    );
}

#[test]
fn create_response() {
    // From: https://docs.oasis-open.org/kmip/usecases/v1.0/cs01/kmip-usecases-1.0-cs-01.html#_Toc262822054
    // Tag: Response Message (0x42007B), Type: Structure (0x01), Data:
    //   Tag: Response Header (0x42007A), Type: Structure (0x01), Data:
    //     Tag: Protocol Version (0x420069), Type: Structure (0x01), Data:
    //       Tag: Protocol Version Major (0x42006A), Type: Integer (0x02), Data: 0x00000001 (1)
    //       Tag: Protocol Version Minor (0x42006B), Type: Integer (0x02), Data: 0x00000000 (0)
    //     Tag: Time Stamp (0x420092), Type: Date-Time (0x09), Data: 0x000000004AFBE7C5 (Thu Nov 12 11:47:33 CET 2009)
    //     Tag: Batch Count (0x42000D), Type: Integer (0x02), Data: 0x00000001 (1)
    //   Tag: Batch Item (0x42000F), Type: Structure (0x01), Data:
    //     Tag: Operation (0x42005C), Type: Enumeration (0x05), Data: 0x00000001 (Create)
    //     Tag: Result Status (0x42007F), Type: Enumeration (0x05), Data: 0x00000000 (Success)
    //     Tag: Response Payload (0x42007C), Type: Structure (0x01), Data:
    //       Tag: Object Type (0x420057), Type: Enumeration (0x05), Data: 0x00000002 (Symmetric Key)
    //       Tag: Unique Identifier (0x420094), Type: Text String (0x07), Data: 61b10614-d8b5-46f9-8d17-2fa6ea1d747a
    let use_case_response_hex = concat!(
        "42007B01000000C042007A0100000048420069010000002042006A0200000004000000010000000042006B02000000040",
        "0000000000000004200920900000008000000004AFBE7C542000D0200000004000000010000000042000F010000006842",
        "005C0500000004000000010000000042007F0500000004000000000000000042007C01000000404200570500000004000",
        "0000200000000420094070000002436316231303631342D643862352D343666392D386431372D32666136656131643734",
        "376100000000",
    );
    let ttlv_wire = hex::decode(use_case_response_hex).unwrap();
    let res: ResponseMessage = from_slice(ttlv_wire.as_ref()).unwrap();

    assert_eq!(res.header.protocol_version.major, 1);
    assert_eq!(res.header.protocol_version.minor, 0);
    assert_eq!(res.header.timestamp, 0x000000004AFBE7C5);
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
fn get_attributes_request() {
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
                Some(vec![
                    AttributeName("Object Group".into()), // TODO IN LOTS OF PLACES: pass &str instead of String
                    AttributeName("Application Specific Information".into()),
                    AttributeName("Contact Information".into()),
                    AttributeName("x-Purpose".into()),
                ]),
            ),
        )],
    );

    let use_case_request_hex = concat!(
        "42007801000001084200770100000038420069010000002042006A0200000004000000010000000042006B02000000040",
        "00000000000000042000D0200000004000000010000000042000F01000000C042005C05000000040000000B0000000042",
        "007901000000A8420094070000002436316231303631342D643862352D343666392D386431372D3266613665613164373",
        "437610000000042000A070000000C4F626A6563742047726F75700000000042000A07000000204170706C69636174696F",
        "6E20537065636966696320496E666F726D6174696F6E42000A0700000013436F6E7461637420496E666F726D6174696F6",
        "E000000000042000A0700000009782D507572706F736500000000000000",
    );
    let actual_request_hex = hex::encode_upper(to_vec(&use_case_request).unwrap());

    assert_eq!(
        use_case_request_hex, actual_request_hex,
        "expected hex (left) differs to the generated hex (right)"
    );
}

#[test]
fn get_attributes_response() {
    // From: https://docs.oasis-open.org/kmip/usecases/v1.0/cs01/kmip-usecases-1.0-cs-01.html#_Toc262822054
    // Tag: Response Message (0x42007B), Type: Structure (0x01), Data:
    //   Tag: Response Header (0x42007A), Type: Structure (0x01), Data:
    //     Tag: Protocol Version (0x420069), Type: Structure (0x01), Data:
    //       Tag: Protocol Version Major (0x42006A), Type: Integer (0x02), Data: 0x00000001 (1)
    //       Tag: Protocol Version Minor (0x42006B), Type: Integer (0x02), Data: 0x00000000 (0)
    //     Tag: Time Stamp (0x420092), Type: Date-Time (0x09), Data: 0x000000004AFBE7C6 (Thu Nov 12 11:47:34 CET 2009)
    //     Tag: Batch Count (0x42000D), Type: Integer (0x02), Data: 0x00000001 (1)
    //   Tag: Batch Item (0x42000F), Type: Structure (0x01), Data:
    //     Tag: Operation (0x42005C), Type: Enumeration (0x05), Data: 0x0000000B (Get Attributes)
    //     Tag: Result Status (0x42007F), Type: Enumeration (0x05), Data: 0x00000000 (Success)
    //     Tag: Response Payload (0x42007C), Type: Structure (0x01), Data:
    //       Tag: Unique Identifier (0x420094), Type: Text String (0x07), Data: 61b10614-d8b5-46f9-8d17-2fa6ea1d747a
    //       Tag: Attribute (0x420008), Type: Structure (0x01), Data:
    //         Tag: Attribute Name (0x42000A), Type: Text String (0x07), Data: Object Group
    //         Tag: Attribute Value (0x42000B), Type: Text String (0x07), Data: Group1
    //       Tag: Attribute (0x420008), Type: Structure (0x01), Data:
    //         Tag: Attribute Name (0x42000A), Type: Text String (0x07), Data: Application Specific Information
    //         Tag: Attribute Value (0x42000B), Type: Structure (0x01), Data:
    //           Tag: Application Namespace (0x420003), Type: Text String (0x07), Data: ssl
    //           Tag: Application Data (0x420002), Type: Text String (0x07), Data: www.example.com
    //       Tag: Attribute (0x420008), Type: Structure (0x01), Data:
    //         Tag: Attribute Name (0x42000A), Type: Text String (0x07), Data: Contact Information
    //         Tag: Attribute Value (0x42000B), Type: Text String (0x07), Data: Joe
    //       Tag: Attribute (0x420008), Type: Structure (0x01), Data:
    //         Tag: Attribute Name (0x42000A), Type: Text String (0x07), Data: x-Purpose
    //         Tag: Attribute Value (0x42000B), Type: Text String (0x07), Data: demonstration
    let use_case_response_hex = concat!(
        "42007B01000001B042007A0100000048420069010000002042006A0200000004000000010000000042006B02000000040",
        "0000000000000004200920900000008000000004AFBE7C642000D0200000004000000010000000042000F010000015842",
        "005C05000000040000000B0000000042007F0500000004000000000000000042007C01000001304200940700000024363",
        "16231303631342D643862352D343666392D386431372D3266613665613164373437610000000042000801000000284200",
        "0A070000000C4F626A6563742047726F75700000000042000B070000000647726F7570310000420008010000005842000",
        "A07000000204170706C69636174696F6E20537065636966696320496E666F726D6174696F6E42000B0100000028420003",
        "070000000373736C0000000000420002070000000F7777772E6578616D706C652E636F6D00420008010000003042000A0",
        "700000013436F6E7461637420496E666F726D6174696F6E000000000042000B07000000034A6F65000000000042000801",
        "0000003042000A0700000009782D507572706F73650000000000000042000B070000000D64656D6F6E7374726174696F6",
        "E000000",
    );
    let ttlv_wire = hex::decode(use_case_response_hex).unwrap();
    let res: ResponseMessage = from_slice(ttlv_wire.as_ref()).unwrap();

    assert_eq!(res.header.protocol_version.major, 1);
    assert_eq!(res.header.protocol_version.minor, 0);
    assert_eq!(res.header.timestamp, 0x000000004AFBE7C6);
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
            assert_eq!(attributes.len(), 4);
            assert_eq!(&attributes[0].name, "Object Group");
            assert_eq!(attributes[0].value, AttributeValue::ObjectGroup("Group1".into()));
            assert_eq!(&attributes[1].name, "Application Specific Information");
            assert_eq!(
                attributes[1].value,
                AttributeValue::ApplicationSpecificInformation(
                    ApplicationNamespace("ssl".into()),
                    ApplicationData("www.example.com".into())
                )
            );
            assert_eq!(&attributes[2].name, "Contact Information");
            assert_eq!(attributes[2].value, AttributeValue::ContactInformation("Joe".into()));
            assert_eq!(&attributes[3].name, "x-Purpose");
            assert_eq!(attributes[3].value, AttributeValue::TextString("demonstration".into()));
        }
    } else {
        panic!("Wrong payload");
    }
}

#[test]
fn destroy_symmetric_key_request() {
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
        "00790100000030420094070000002436316231303631342D643862352D343666392D386431372D3266613665613164373",
        "4376100000000",
    );
    let actual_request_hex = hex::encode_upper(to_vec(&use_case_request).unwrap());

    assert_eq!(
        use_case_request_hex, actual_request_hex,
        "expected hex (left) differs to the generated hex (right)"
    );
}

#[test]
fn destroy_symmetric_key_response() {
    // From: https://docs.oasis-open.org/kmip/usecases/v1.0/cs01/kmip-usecases-1.0-cs-01.html#_Toc262822054
    // Tag: Response Message (0x42007B), Type: Structure (0x01), Data:
    //   Tag: Response Header (0x42007A), Type: Structure (0x01), Data:
    //     Tag: Protocol Version (0x420069), Type: Structure (0x01), Data:
    //       Tag: Protocol Version Major (0x42006A), Type: Integer (0x02), Data: 0x00000001 (1)
    //       Tag: Protocol Version Minor (0x42006B), Type: Integer (0x02), Data: 0x00000000 (0)
    //     Tag: Time Stamp (0x420092), Type: Date-Time (0x09), Data: 0x000000004AFBE7C6 (Thu Nov 12 11:47:34 CET 2009)
    //     Tag: Batch Count (0x42000D), Type: Integer (0x02), Data: 0x00000001 (1)
    //   Tag: Batch Item (0x42000F), Type: Structure (0x01), Data:
    //     Tag: Operation (0x42005C), Type: Enumeration (0x05), Data: 0x00000014 (Destroy)
    //     Tag: Result Status (0x42007F), Type: Enumeration (0x05), Data: 0x00000000 (Success)
    //     Tag: Response Payload (0x42007C), Type: Structure (0x01), Data:
    //       Tag: Unique Identifier (0x420094), Type: Text String (0x07), Data: 61b10614-d8b5-46f9-8d17-2fa6ea1d747a
    let use_case_response_hex = concat!(
        "42007B01000000B042007A0100000048420069010000002042006A0200000004000000010000000042006B02000000040",
        "0000000000000004200920900000008000000004AFBE7C642000D0200000004000000010000000042000F010000005842",
        "005C0500000004000000140000000042007F0500000004000000000000000042007C01000000304200940700000024363",
        "16231303631342D643862352D343666392D386431372D32666136656131643734376100000000",
    );
    let ttlv_wire = hex::decode(use_case_response_hex).unwrap();
    let res: ResponseMessage = from_slice(ttlv_wire.as_ref()).unwrap();

    assert_eq!(res.header.protocol_version.major, 1);
    assert_eq!(res.header.protocol_version.minor, 0);
    assert_eq!(res.header.timestamp, 0x000000004AFBE7C6);
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

#[test]
fn destroy_uuid_template_request() {
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
            RequestPayload::Destroy(Some(UniqueIdentifier(UUID_ID.into()))),
        )],
    );

    let use_case_request_hex = concat!(
        "42007801000000904200770100000038420069010000002042006A0200000004000000010000000042006B02000000040",
        "00000000000000042000D0200000004000000010000000042000F010000004842005C0500000004000000140000000042",
        "00790100000030420094070000002461366562626236662D346335342D346262622D616432392D6265366261643465636",
        "1643500000000",
    );
    let actual_request_hex = hex::encode_upper(to_vec(&use_case_request).unwrap());

    assert_eq!(
        use_case_request_hex, actual_request_hex,
        "expected hex (left) differs to the generated hex (right)"
    );
}

#[test]
fn destroy_uuid_template_response() {
    // From: https://docs.oasis-open.org/kmip/usecases/v1.0/cs01/kmip-usecases-1.0-cs-01.html#_Toc262822054
    // Tag: Response Message (0x42007B), Type: Structure (0x01), Data:
    //   Tag: Response Header (0x42007A), Type: Structure (0x01), Data:
    //     Tag: Protocol Version (0x420069), Type: Structure (0x01), Data:
    //       Tag: Protocol Version Major (0x42006A), Type: Integer (0x02), Data: 0x00000001 (1)
    //       Tag: Protocol Version Minor (0x42006B), Type: Integer (0x02), Data: 0x00000000 (0)
    //     Tag: Time Stamp (0x420092), Type: Date-Time (0x09), Data: 0x000000004AFBE7C6 (Thu Nov 12 11:47:34 CET 2009)
    //     Tag: Batch Count (0x42000D), Type: Integer (0x02), Data: 0x00000001 (1)
    //   Tag: Batch Item (0x42000F), Type: Structure (0x01), Data:
    //     Tag: Operation (0x42005C), Type: Enumeration (0x05), Data: 0x00000014 (Destroy)
    //     Tag: Result Status (0x42007F), Type: Enumeration (0x05), Data: 0x00000000 (Success)
    //     Tag: Response Payload (0x42007C), Type: Structure (0x01), Data:
    //       Tag: Unique Identifier (0x420094), Type: Text String (0x07), Data: a6ebbb6f-4c54-4bbb-ad29-be6bad4ecad5
    let use_case_response_hex = concat!(
        "42007B01000000B042007A0100000048420069010000002042006A0200000004000000010000000042006B02000000040",
        "0000000000000004200920900000008000000004AFBE7C642000D0200000004000000010000000042000F010000005842",
        "005C0500000004000000140000000042007F0500000004000000000000000042007C01000000304200940700000024613",
        "66562626236662D346335342D346262622D616432392D62653662616434656361643500000000",
    );
    let ttlv_wire = hex::decode(use_case_response_hex).unwrap();
    let res: ResponseMessage = from_slice(ttlv_wire.as_ref()).unwrap();

    assert_eq!(res.header.protocol_version.major, 1);
    assert_eq!(res.header.protocol_version.minor, 0);
    assert_eq!(res.header.timestamp, 0x000000004AFBE7C6);
    assert_eq!(res.header.batch_count, 1);
    assert_eq!(res.batch_items.len(), 1);

    let item = &res.batch_items[0];
    assert!(matches!(item.result_status, ResultStatus::Success));
    assert!(matches!(item.operation, Some(Operation::Destroy)));
    assert!(matches!(&item.payload, Some(ResponsePayload::Destroy(_))));

    if let Some(ResponsePayload::Destroy(payload)) = item.payload.as_ref() {
        assert_eq!(&payload.unique_identifier, UUID_ID);
    } else {
        panic!("Wrong payload");
    }
}
