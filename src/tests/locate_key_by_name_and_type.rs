#[allow(unused_imports)]
use pretty_assertions::{assert_eq, assert_ne};

use kmip_ttlv::ser::to_vec;

use crate::response::from_slice;
use crate::types::common::{ObjectType, Operation, UniqueBatchItemID};
use crate::types::request::{
    self, Attribute, Authentication, BatchCount, BatchItem, MaximumResponseSize, ProtocolVersionMajor,
    ProtocolVersionMinor, RequestHeader, RequestMessage, RequestPayload,
};
use crate::types::response::ResponseMessage;

#[test]
fn locate_request_public_key_by_name_only_serializes_without_error() {
    let request = RequestMessage(
        RequestHeader(
            request::ProtocolVersion(ProtocolVersionMajor(1), ProtocolVersionMinor(0)),
            Option::<MaximumResponseSize>::None,
            Option::<Authentication>::None,
            BatchCount(1),
        ),
        vec![BatchItem(
            Operation::Locate,
            Option::<UniqueBatchItemID>::None,
            RequestPayload::Locate(vec![Attribute::Name("Some Public Key Name".into())]),
        )],
    );
    assert!(to_vec(&request).is_ok());
}

#[test]
fn locate_request_public_key_by_name_and_type_serializes_without_error() {
    let request = RequestMessage(
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
                Attribute::ObjectType(ObjectType::PublicKey),
                Attribute::Name("Some Public Key Name".into()),
            ]),
        )],
    );
    assert!(to_vec(&request).is_ok());
}

#[test]
fn locate_request_private_key_by_name_only_serializes_without_error() {
    let request = RequestMessage(
        RequestHeader(
            request::ProtocolVersion(ProtocolVersionMajor(1), ProtocolVersionMinor(0)),
            Option::<MaximumResponseSize>::None,
            Option::<Authentication>::None,
            BatchCount(1),
        ),
        vec![BatchItem(
            Operation::Locate,
            Option::<UniqueBatchItemID>::None,
            RequestPayload::Locate(vec![Attribute::Name("Some Private Key Name".into())]),
        )],
    );
    assert!(to_vec(&request).is_ok());
}

#[test]
fn locate_request_private_key_by_name_and_type_serializes_without_error() {
    let request = RequestMessage(
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
                Attribute::ObjectType(ObjectType::PrivateKey),
                Attribute::Name("Some Private Key Name".into()),
            ]),
        )],
    );
    assert!(to_vec(&request).is_ok());
}

/// See: https://github.com/NLnetLabs/kmip-protocol/issues/30
#[test]
fn locate_empty_response_deserializes_without_error() {
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
    let use_case_response_hex = concat!(
        "42007B 01 00000080",
        "  42007A 01 00000048",
        "    420069 01 00000020",
        "      42006A 02 00000004 00000001 00000000",
        "      42006B 02 00000004 00000000 00000000",
        "    420092 09 00000008 00000000 4AFBED2B",
        "    42000D 02 00000004 00000001 00000000",
        "  42000F 01 00000028",
        "    42005C 05 00000004 00000008 00000000",
        "    42007F 05 00000004 00000000 00000000",
        "    42007C 01 00000000",
    )
    .replace(" ", "");
    let ttlv_wire = hex::decode(use_case_response_hex).unwrap();
    // The unwrap() on the next line panics if deserialization isn't configured correctly to handle 42007C0100000000
    // (tag 0x42007C is the "Response Payload" tag, 0x01 says it is a TTLV Structure and 0x00000000 says it has zero
    // length).
    let _: ResponseMessage = from_slice(ttlv_wire.as_ref()).unwrap();
}
