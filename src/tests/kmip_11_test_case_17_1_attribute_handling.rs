//! See: http://docs.oasis-open.org/kmip/testcases/v1.1/kmip-testcases-v1.1.html#_Toc333488820

#[allow(unused_imports)]
use pretty_assertions::{assert_eq, assert_ne};

use kmip_ttlv::ser::to_vec;

use crate::{
    response::from_slice,
    types::{
        common::{
            AttributeIndex, AttributeName, AttributeValue, CryptographicAlgorithm, CryptographicUsageMask, NameType,
            NameValue, ObjectType, Operation, UniqueBatchItemID, UniqueIdentifier,
        },
        request::{
            self, Authentication, BatchCount, BatchItem, MaximumResponseSize, ProtocolVersionMajor,
            ProtocolVersionMinor, RequestHeader, RequestMessage, RequestPayload,
        },
        request::{Attribute, TemplateAttribute},
        response::{ResponseMessage, ResponsePayload, ResultReason, ResultStatus},
    },
};

const KEY_ID: &'static str = "28c7bad1-bc9b-41df-b439-1ba04a6fd982";

/// -------------------------------------------------------------------------------------------------------------------
/// 17.1 Test Case: Handling of Attributes and Attribute Index Values
/// -------------------------------------------------------------------------------------------------------------------

#[test]
fn kmip_1_1_testcase_17_1_time_0_create_symmetric_key_request() {
    let use_case_request = RequestMessage(
        RequestHeader(
            request::ProtocolVersion(ProtocolVersionMajor(1), ProtocolVersionMinor(1)),
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
                    Attribute::CryptographicLength(256),
                    Attribute::CryptographicUsageMask(
                        CryptographicUsageMask::Encrypt | CryptographicUsageMask::Decrypt,
                    ),
                    Attribute::Name("FirstTestName".into()),
                    Attribute::Name("SecondTestName".into()),
                    Attribute::ContactInformation("admin@localhost".into()),
                ]),
            ),
        )],
    );

    let use_case_request_hex = concat!(
        "42007801000001F04200770100000038420069010000002042006A0200000004000000010000000042006B02000000040",
        "00000010000000042000D0200000004000000010000000042000F01000001A842005C0500000004000000010000000042",
        "00790100000190420057050000000400000002000000004200910100000178420008010000003042000A0700000017437",
        "27970746F6772617068696320416C676F726974686D0042000B0500000004000000030000000042000801000000304200",
        "0A070000001443727970746F67726170686963204C656E6774680000000042000B0200000004000001000000000042000",
        "8010000003042000A070000001843727970746F67726170686963205573616765204D61736B42000B0200000004000000",
        "0C00000000420008010000004042000A07000000044E616D650000000042000B0100000028420055070000000D4669727",
        "374546573744E616D6500000042005405000000040000000100000000420008010000004042000A07000000044E616D65",
        "0000000042000B0100000028420055070000000E5365636F6E64546573744E616D6500004200540500000004000000010",
        "0000000420008010000003842000A0700000013436F6E7461637420496E666F726D6174696F6E000000000042000B0700",
        "00000F61646D696E406C6F63616C686F737400"
    );
    let actual_request_hex = hex::encode_upper(to_vec(&use_case_request).unwrap());

    assert_eq!(
        use_case_request_hex, actual_request_hex,
        "expected hex (left) differs to the generated hex (right)"
    );
}

#[test]
fn kmip_1_1_testcase_17_1_time_0_create_symmetric_key_response() {
    let use_case_response_hex = concat!(
        "42007B01000000C042007A0100000048420069010000002042006A0200000004000000010000000042006B02000000040",
        "0000001000000004200920900000008000000004F9A557442000D0200000004000000010000000042000F010000006842",
        "005C0500000004000000010000000042007F0500000004000000000000000042007C01000000404200570500000004000",
        "0000200000000420094070000002432386337626164312D626339622D343164662D623433392D31626130346136666439",
        "383200000000",
    );
    let ttlv_wire = hex::decode(use_case_response_hex).unwrap();
    let res: ResponseMessage = from_slice(ttlv_wire.as_ref()).unwrap();

    assert_eq!(res.header.protocol_version.major, 1);
    assert_eq!(res.header.protocol_version.minor, 1);
    assert_eq!(res.header.timestamp, 0x000000004F9A5574);
    assert_eq!(res.header.batch_count, 1);
    assert_eq!(res.batch_items.len(), 1);

    let item = &res.batch_items[0];
    assert_eq!(item.result_status, ResultStatus::Success);
    assert_eq!(item.operation, Some(Operation::Create));
    assert!(matches!(&item.payload, Some(ResponsePayload::Create(_))));

    if let Some(ResponsePayload::Create(payload)) = item.payload.as_ref() {
        assert_eq!(payload.object_type, ObjectType::SymmetricKey);
        assert_eq!(&payload.unique_identifier, KEY_ID);
    }
}

#[test]
fn kmip_1_1_testcase_17_1_time_1_get_attributes_invalid_request() {
    let use_case_request = RequestMessage(
        RequestHeader(
            request::ProtocolVersion(ProtocolVersionMajor(1), ProtocolVersionMinor(1)),
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
                    AttributeName("Object Type".into()),
                    AttributeName("Object Type".into()),
                ]),
            ),
        )],
    );

    let use_case_request_hex = concat!(
        "42007801000000C04200770100000038420069010000002042006A0200000004000000010000000042006B02000000040",
        "00000010000000042000D0200000004000000010000000042000F010000007842005C05000000040000000B0000000042",
        "00790100000060420094070000002432386337626164312D626339622D343164662D623433392D3162613034613666643",
        "938320000000042000A070000000B4F626A6563742054797065000000000042000A070000000B4F626A65637420547970",
        "650000000000",
    );
    let actual_request_hex = hex::encode_upper(to_vec(&use_case_request).unwrap());

    assert_eq!(
        use_case_request_hex, actual_request_hex,
        "expected hex (left) differs to the generated hex (right)"
    );
}

#[test]
fn kmip_1_1_testcase_17_1_time_1_get_attributes_response() {
    let use_case_response_hex = concat!(
        "42007B01000000C842007A0100000048420069010000002042006A0200000004000000010000000042006B02000000040",
        "0000001000000004200920900000008000000004F9A557442000D0200000004000000010000000042000F010000007042",
        "005C05000000040000000B0000000042007F0500000004000000010000000042007E05000000040000000700000000420",
        "07D0700000034417474726962757465204E616D6520737065636966696564206D6F7265207468616E206F6E63653A204F",
        "626A656374205479706500000000",
    );
    let ttlv_wire = hex::decode(use_case_response_hex).unwrap();
    let res: ResponseMessage = from_slice(ttlv_wire.as_ref()).unwrap();

    assert_eq!(res.header.protocol_version.major, 1);
    assert_eq!(res.header.protocol_version.minor, 1);
    assert_eq!(res.header.timestamp, 0x000000004F9A5574);
    assert_eq!(res.header.batch_count, 1);
    assert_eq!(res.batch_items.len(), 1);

    let item = &res.batch_items[0];
    assert_eq!(item.result_status, ResultStatus::OperationFailed);
    assert_eq!(item.operation, Some(Operation::GetAttributes));
    assert_eq!(item.result_reason, Some(ResultReason::InvalidField));
    assert_eq!(
        item.result_message,
        Some("Attribute Name specified more than once: Object Type".into())
    );
}

#[test]
fn kmip_1_1_testcase_17_1_time_2_get_attributes_request() {
    let use_case_request = RequestMessage(
        RequestHeader(
            request::ProtocolVersion(ProtocolVersionMajor(1), ProtocolVersionMinor(1)),
            Option::<MaximumResponseSize>::None,
            Option::<Authentication>::None,
            BatchCount(1),
        ),
        vec![BatchItem(
            Operation::GetAttributes,
            Option::<UniqueBatchItemID>::None,
            RequestPayload::GetAttributes(
                Some(UniqueIdentifier(KEY_ID.into())),
                Some(vec![AttributeName("Object Type".into())]),
            ),
        )],
    );

    let use_case_request_hex = concat!(
        "42007801000000A84200770100000038420069010000002042006A0200000004000000010000000042006B02000000040",
        "00000010000000042000D0200000004000000010000000042000F010000006042005C05000000040000000B0000000042",
        "00790100000048420094070000002432386337626164312D626339622D343164662D623433392D3162613034613666643",
        "938320000000042000A070000000B4F626A65637420547970650000000000",
    );
    let actual_request_hex = hex::encode_upper(to_vec(&use_case_request).unwrap());

    assert_eq!(
        use_case_request_hex, actual_request_hex,
        "expected hex (left) differs to the generated hex (right)"
    );
}

#[test]
fn kmip_1_1_testcase_17_1_time_2_get_attributes_response() {
    let use_case_response_hex = concat!(
        "42007B01000000E042007A0100000048420069010000002042006A0200000004000000010000000042006B02000000040",
        "0000001000000004200920900000008000000004F9A557442000D0200000004000000010000000042000F010000008842",
        "005C05000000040000000B0000000042007F0500000004000000000000000042007C01000000604200940700000024323",
        "86337626164312D626339622D343164662D623433392D3162613034613666643938320000000042000801000000284200",
        "0A070000000B4F626A6563742054797065000000000042000B05000000040000000200000000",
    );
    let ttlv_wire = hex::decode(use_case_response_hex).unwrap();
    let res: ResponseMessage = from_slice(ttlv_wire.as_ref()).unwrap();

    assert_eq!(res.header.protocol_version.major, 1);
    assert_eq!(res.header.protocol_version.minor, 1);
    assert_eq!(res.header.timestamp, 0x000000004F9A5574);
    assert_eq!(res.header.batch_count, 1);
    assert_eq!(res.batch_items.len(), 1);

    let item = &res.batch_items[0];
    assert_eq!(item.result_status, ResultStatus::Success);
    assert_eq!(item.operation, Some(Operation::GetAttributes));
    assert!(matches!(&item.payload, Some(ResponsePayload::GetAttributes(_))));

    if let Some(ResponsePayload::GetAttributes(payload)) = item.payload.as_ref() {
        assert_eq!(&payload.unique_identifier, KEY_ID);
        assert!(payload.attributes.is_some());
        if let Some(attributes) = &payload.attributes {
            assert_eq!(attributes.len(), 1);
            assert_eq!(&attributes[0].name, "Object Type");
            assert_eq!(
                attributes[0].value,
                AttributeValue::ObjectType(ObjectType::SymmetricKey)
            );
        }
    }
}

#[test]
fn kmip_1_1_testcase_17_1_time_3_modify_attribute_request() {
    let use_case_request = RequestMessage(
        RequestHeader(
            request::ProtocolVersion(ProtocolVersionMajor(1), ProtocolVersionMinor(1)),
            Option::<MaximumResponseSize>::None,
            Option::<Authentication>::None,
            BatchCount(1),
        ),
        vec![BatchItem(
            Operation::ModifyAttribute,
            Option::<UniqueBatchItemID>::None,
            RequestPayload::ModifyAttribute(
                Some(UniqueIdentifier(KEY_ID.into())),
                Attribute(
                    AttributeName("Contact Information".into()),
                    Some(AttributeIndex(0)),
                    AttributeValue::TextString("donald@localhost".into()),
                ),
            ),
        )],
    );

    let use_case_request_hex = concat!(
        "42007801000000E04200770100000038420069010000002042006A0200000004000000010000000042006B02000000040",
        "00000010000000042000D0200000004000000010000000042000F010000009842005C05000000040000000E0000000042",
        "00790100000080420094070000002432386337626164312D626339622D343164662D623433392D3162613034613666643",
        "9383200000000420008010000004842000A0700000013436F6E7461637420496E666F726D6174696F6E00000000004200",
        "090200000004000000000000000042000B0700000010646F6E616C64406C6F63616C686F7374",
    );
    let actual_request_hex = hex::encode_upper(to_vec(&use_case_request).unwrap());

    assert_eq!(
        use_case_request_hex, actual_request_hex,
        "expected hex (left) differs to the generated hex (right)"
    );
}

#[test]
fn kmip_1_1_testcase_17_1_time_3_modify_attribute_response() {
    let use_case_response_hex = concat!(
        "42007B01000000F042007A0100000048420069010000002042006A0200000004000000010000000042006B02000000040",
        "0000001000000004200920900000008000000004F9A557442000D0200000004000000010000000042000F010000009842",
        "005C05000000040000000E0000000042007F0500000004000000000000000042007C01000000704200940700000024323",
        "86337626164312D626339622D343164662D623433392D3162613034613666643938320000000042000801000000384200",
        "0A0700000013436F6E7461637420496E666F726D6174696F6E000000000042000B0700000010646F6E616C64406C6F636",
        "16C686F7374",
    );
    let ttlv_wire = hex::decode(use_case_response_hex).unwrap();
    let res: ResponseMessage = from_slice(ttlv_wire.as_ref()).unwrap();

    assert_eq!(res.header.protocol_version.major, 1);
    assert_eq!(res.header.protocol_version.minor, 1);
    assert_eq!(res.header.timestamp, 0x000000004F9A5574);
    assert_eq!(res.header.batch_count, 1);
    assert_eq!(res.batch_items.len(), 1);

    let item = &res.batch_items[0];
    assert_eq!(item.result_status, ResultStatus::Success);
    assert_eq!(item.operation, Some(Operation::ModifyAttribute));
    assert!(matches!(&item.payload, Some(ResponsePayload::ModifyAttribute(_))));

    if let Some(ResponsePayload::ModifyAttribute(payload)) = item.payload.as_ref() {
        assert_eq!(&payload.unique_identifier, KEY_ID);
        assert_eq!(&payload.attribute.name, "Contact Information");
        assert_eq!(
            payload.attribute.value,
            AttributeValue::ContactInformation("donald@localhost".into())
        );
    }
}

#[test]
fn kmip_1_1_testcase_17_1_time_4_delete_attribute_request() {
    let use_case_request = RequestMessage(
        RequestHeader(
            request::ProtocolVersion(ProtocolVersionMajor(1), ProtocolVersionMinor(1)),
            Option::<MaximumResponseSize>::None,
            Option::<Authentication>::None,
            BatchCount(1),
        ),
        vec![BatchItem(
            Operation::DeleteAttribute,
            Option::<UniqueBatchItemID>::None,
            RequestPayload::DeleteAttribute(
                Some(UniqueIdentifier(KEY_ID.into())),
                AttributeName("Name".into()),
                Option::<AttributeIndex>::None,
            ),
        )],
    );

    let use_case_request_hex = concat!(
        "42007801000000A04200770100000038420069010000002042006A0200000004000000010000000042006B02000000040",
        "00000010000000042000D0200000004000000010000000042000F010000005842005C05000000040000000F0000000042",
        "00790100000040420094070000002432386337626164312D626339622D343164662D623433392D3162613034613666643",
        "938320000000042000A07000000044E616D6500000000",
    );
    let actual_request_hex = hex::encode_upper(to_vec(&use_case_request).unwrap());

    assert_eq!(
        use_case_request_hex, actual_request_hex,
        "expected hex (left) differs to the generated hex (right)"
    );
}

#[test]
fn kmip_1_1_testcase_17_1_time_4_delete_attribute_response() {
    let use_case_response_hex = concat!(
        "42007B01000000F842007A0100000048420069010000002042006A0200000004000000010000000042006B02000000040",
        "0000001000000004200920900000008000000004F9A557442000D0200000004000000010000000042000F01000000A042",
        "005C05000000040000000F0000000042007F0500000004000000000000000042007C01000000784200940700000024323",
        "86337626164312D626339622D343164662D623433392D3162613034613666643938320000000042000801000000404200",
        "0A07000000044E616D650000000042000B0100000028420055070000000D4669727374546573744E616D6500000042005",
        "405000000040000000100000000",
    );
    let ttlv_wire = hex::decode(use_case_response_hex).unwrap();
    let res: ResponseMessage = from_slice(ttlv_wire.as_ref()).unwrap();

    assert_eq!(res.header.protocol_version.major, 1);
    assert_eq!(res.header.protocol_version.minor, 1);
    assert_eq!(res.header.timestamp, 0x000000004F9A5574);
    assert_eq!(res.header.batch_count, 1);
    assert_eq!(res.batch_items.len(), 1);

    let item = &res.batch_items[0];
    assert_eq!(item.result_status, ResultStatus::Success);
    assert_eq!(item.operation, Some(Operation::DeleteAttribute));
    assert!(matches!(&item.payload, Some(ResponsePayload::DeleteAttribute(_))));

    if let Some(ResponsePayload::DeleteAttribute(payload)) = item.payload.as_ref() {
        assert_eq!(&payload.unique_identifier, KEY_ID);
        assert_eq!(&payload.attribute.name, "Name");
        assert_eq!(
            payload.attribute.value,
            AttributeValue::Name(NameValue("FirstTestName".into()), NameType::UninterpretedTextString)
        );
    }
}

#[test]
fn kmip_1_1_testcase_17_1_time_5_destroy_request() {
    let use_case_request = RequestMessage(
        RequestHeader(
            request::ProtocolVersion(ProtocolVersionMajor(1), ProtocolVersionMinor(1)),
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
        "00000010000000042000D0200000004000000010000000042000F010000004842005C0500000004000000140000000042",
        "00790100000030420094070000002432386337626164312D626339622D343164662D623433392D3162613034613666643",
        "9383200000000",
    );
    let actual_request_hex = hex::encode_upper(to_vec(&use_case_request).unwrap());

    assert_eq!(
        use_case_request_hex, actual_request_hex,
        "expected hex (left) differs to the generated hex (right)"
    );
}

#[test]
fn kmip_1_1_testcase_17_1_time_5_destroy_response() {
    let use_case_response_hex = concat!(
        "42007B01000000B042007A0100000048420069010000002042006A0200000004000000010000000042006B02000000040",
        "0000001000000004200920900000008000000004F9A557442000D0200000004000000010000000042000F010000005842",
        "005C0500000004000000140000000042007F0500000004000000000000000042007C01000000304200940700000024323",
        "86337626164312D626339622D343164662D623433392D31626130346136666439383200000000",
    );
    let ttlv_wire = hex::decode(use_case_response_hex).unwrap();
    let res: ResponseMessage = from_slice(ttlv_wire.as_ref()).unwrap();

    assert_eq!(res.header.protocol_version.major, 1);
    assert_eq!(res.header.protocol_version.minor, 1);
    assert_eq!(res.header.timestamp, 0x000000004F9A5574);
    assert_eq!(res.header.batch_count, 1);
    assert_eq!(res.batch_items.len(), 1);

    let item = &res.batch_items[0];
    assert_eq!(item.result_status, ResultStatus::Success);
    assert_eq!(item.operation, Some(Operation::Destroy));
    assert!(matches!(&item.payload, Some(ResponsePayload::Destroy(_))));

    if let Some(ResponsePayload::Destroy(payload)) = item.payload.as_ref() {
        assert_eq!(&payload.unique_identifier, KEY_ID);
    }
}
