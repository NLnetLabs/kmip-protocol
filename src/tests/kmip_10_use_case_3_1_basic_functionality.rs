//! See: http://docs.oasis-open.org/kmip/usecases/v1.0/cs01/kmip-usecases-1.0-cs-01.html#_Toc262822054

#[allow(unused_imports)]
use pretty_assertions::{assert_eq, assert_ne};

use krill_kmip_ttlv::ser::to_vec;

use crate::types::{
    common::{
        ApplicationData, ApplicationNamespace, AttributeName, AttributeValue, ObjectType, Operation, UniqueBatchItemID,
    },
    request::{
        self, Attribute, Authentication, BatchCount, BatchItem, ManagedObject, MaximumResponseSize,
        ProtocolVersionMajor, ProtocolVersionMinor, RequestHeader, RequestMessage, RequestPayload, Template,
        TemplateAttribute,
    },
};

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
