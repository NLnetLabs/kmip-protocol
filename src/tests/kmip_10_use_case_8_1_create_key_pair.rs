//! See: https://docs.oasis-open.org/kmip/usecases/v1.0/cs01/kmip-usecases-1.0-cs-01.html#_Toc262822069

#[allow(unused_imports)]
use pretty_assertions::{assert_eq, assert_ne};

use krill_kmip_ttlv::ser::to_vec;

use crate::{
    response::from_slice,
    types::{
        common::{
            CryptographicAlgorithm, CryptographicUsageMask, LinkType, LinkedObjectIdentifier, ObjectType, Operation,
            UniqueBatchItemID, UniqueIdentifier,
        },
        request::{
            self, Attribute, Authentication, BatchCount, BatchItem, CommonTemplateAttribute, MaximumResponseSize,
            PrivateKeyTemplateAttribute, ProtocolVersionMajor, ProtocolVersionMinor, PublicKeyTemplateAttribute,
            RequestHeader, RequestMessage, RequestPayload,
        },
        response::{ResponseMessage, ResponsePayload, ResultStatus},
    },
};

#[test]
fn create_key_pair_request_rsa_1024() {
    let use_case_request = RequestMessage(
        RequestHeader(
            request::ProtocolVersion(ProtocolVersionMajor(1), ProtocolVersionMinor(0)),
            Option::<MaximumResponseSize>::None,
            Option::<Authentication>::None,
            BatchCount(1),
        ),
        vec![BatchItem(
            Operation::CreateKeyPair,
            Option::<UniqueBatchItemID>::None,
            RequestPayload::CreateKeyPair(
                Some(CommonTemplateAttribute::unnamed(vec![
                    Attribute::CryptographicAlgorithm(CryptographicAlgorithm::RSA),
                    Attribute::CryptographicLength(1024),
                ])),
                Some(PrivateKeyTemplateAttribute::unnamed(vec![
                    Attribute::Name("PrivateKey1".into()),
                    Attribute::CryptographicUsageMask(CryptographicUsageMask::Sign),
                ])),
                Some(PublicKeyTemplateAttribute::unnamed(vec![
                    Attribute::Name("PublicKey1".into()),
                    Attribute::CryptographicUsageMask(CryptographicUsageMask::Verify),
                ])),
            ),
        )],
    );

    let use_case_request_hex = concat!(
        "42007801000001E84200770100000038420069010000002042006A0200000004000000010000000042006B02000000040",
        "00000000000000042000D0200000004000000010000000042000F01000001A042005C0500000004000000020000000042",
        "0079010000018842001F0100000070420008010000003042000A070000001743727970746F6772617068696320416C676",
        "F726974686D0042000B05000000040000000400000000420008010000003042000A070000001443727970746F67726170",
        "686963204C656E6774680000000042000B020000000400000400000000004200650100000080420008010000004042000",
        "A07000000044E616D650000000042000B0100000028420055070000000B507269766174654B6579310000000000420054",
        "05000000040000000100000000420008010000003042000A070000001843727970746F677261706869632055736167652",
        "04D61736B42000B0200000004000000010000000042006E0100000080420008010000004042000A07000000044E616D65",
        "0000000042000B0100000028420055070000000A5075626C69634B6579310000000000004200540500000004000000010",
        "0000000420008010000003042000A070000001843727970746F67726170686963205573616765204D61736B42000B0200",
        "0000040000000200000000"
    );
    let actual_request_hex = hex::encode_upper(to_vec(&use_case_request).unwrap());

    assert_eq!(
        use_case_request_hex, actual_request_hex,
        "expected hex (left) differs to the generated hex (right)"
    );
}

#[test]
fn create_key_pair_response() {
    let use_case_response_hex = concat!(
        "42007B01000000E042007A0100000048420069010000002042006A0200000004000000010000000042006B02000000040",
        "0000000000000004200920900000008000000004B73C13A42000D0200000004000000010000000042000F010000008842",
        "005C0500000004000000020000000042007F0500000004000000000000000042007C01000000604200940700000024383",
        "93566373263322D623230612D343964382D393530342D3664633231313563633034320000000042009407000000246132",
        "3432666361342D656266302D343339382D616336352D38373962616234393032353900000000"
    );
    let ttlv_wire = hex::decode(use_case_response_hex).unwrap();
    let res: ResponseMessage = from_slice(ttlv_wire.as_ref()).unwrap();

    assert_eq!(res.header.protocol_version.major, 1);
    assert_eq!(res.header.protocol_version.minor, 0);
    assert_eq!(res.header.timestamp, 0x000000004B73C13A);
    assert_eq!(res.header.batch_count, 1);
    assert_eq!(res.batch_items.len(), 1);

    let item = &res.batch_items[0];
    assert!(matches!(item.result_status, ResultStatus::Success));
    assert!(matches!(item.operation, Some(Operation::CreateKeyPair)));
    assert!(matches!(&item.payload, Some(ResponsePayload::CreateKeyPair(_))));

    if let Some(ResponsePayload::CreateKeyPair(payload)) = item.payload.as_ref() {
        assert_eq!(
            &payload.private_key_unique_identifier,
            "895f72c2-b20a-49d8-9504-6dc2115cc042"
        );
        assert_eq!(
            &payload.public_key_unique_identifier,
            "a242fca4-ebf0-4398-ac65-879bab490259"
        );
    } else {
        panic!("Wrong payload");
    }
}

#[test]
fn locate_request_public_key() {
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
                Attribute::ObjectType(ObjectType::PublicKey),
                Attribute::Link(
                    LinkType::PrivateKeyLink,
                    LinkedObjectIdentifier("a242fca4-ebf0-4398-ac65-879bab490259".into()),
                ),
            ]),
        )],
    );

    let use_case_request_hex = concat!(
        "42007801000000F04200770100000038420069010000002042006A0200000004000000010000000042006B02000000040",
        "00000000000000042000D0200000004000000010000000042000F01000000A842005C0500000004000000080000000042",
        "00790100000090420008010000002842000A070000000B4F626A6563742054797065000000000042000B0500000004000",
        "0000300000000420008010000005842000A07000000044C696E6B0000000042000B010000004042004B05000000040000",
        "01030000000042004C070000002461323432666361342D656266302D343339382D616336352D383739626162343930323",
        "53900000000"
    );
    let actual_request_hex = hex::encode_upper(to_vec(&use_case_request).unwrap());

    assert_eq!(
        use_case_request_hex, actual_request_hex,
        "expected hex (left) differs to the generated hex (right)"
    );
}

#[test]
fn locate_response_public_key() {
    let use_case_response_hex = concat!(
        "42007B01000000B042007A0100000048420069010000002042006A0200000004000000010000000042006B02000000040",
        "0000000000000004200920900000008000000004B73C13B42000D0200000004000000010000000042000F010000005842",
        "005C0500000004000000080000000042007F0500000004000000000000000042007C01000000304200940700000024383",
        "93566373263322D623230612D343964382D393530342D36646332313135636330343200000000",
    );
    let ttlv_wire = hex::decode(use_case_response_hex).unwrap();
    let res: ResponseMessage = from_slice(ttlv_wire.as_ref()).unwrap();

    assert_eq!(res.header.protocol_version.major, 1);
    assert_eq!(res.header.protocol_version.minor, 0);
    assert_eq!(res.header.timestamp, 0x000000004B73C13B);
    assert_eq!(res.header.batch_count, 1);
    assert_eq!(res.batch_items.len(), 1);

    let item = &res.batch_items[0];
    assert!(matches!(item.result_status, ResultStatus::Success));
    assert!(matches!(item.operation, Some(Operation::Locate)));
    assert!(matches!(&item.payload, Some(ResponsePayload::Locate(_))));

    if let Some(ResponsePayload::Locate(payload)) = item.payload.as_ref() {
        assert_eq!(payload.unique_identifiers.len(), 1);

        let identifier = &payload.unique_identifiers[0];
        assert_eq!(identifier, "895f72c2-b20a-49d8-9504-6dc2115cc042");
    } else {
        panic!("Wrong payload");
    }
}

#[test]
fn locate_request_private_key() {
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
                Attribute::ObjectType(ObjectType::PrivateKey),
                Attribute::Link(
                    LinkType::PublicKeyLink,
                    LinkedObjectIdentifier("895f72c2-b20a-49d8-9504-6dc2115cc042".into()),
                ),
            ]),
        )],
    );

    let use_case_request_hex = concat!(
        "42007801000000F04200770100000038420069010000002042006A0200000004000000010000000042006B02000000040",
        "00000000000000042000D0200000004000000010000000042000F01000000A842005C0500000004000000080000000042",
        "00790100000090420008010000002842000A070000000B4F626A6563742054797065000000000042000B0500000004000",
        "0000400000000420008010000005842000A07000000044C696E6B0000000042000B010000004042004B05000000040000",
        "01020000000042004C070000002438393566373263322D623230612D343964382D393530342D366463323131356363303",
        "43200000000"
    );
    let actual_request_hex = hex::encode_upper(to_vec(&use_case_request).unwrap());

    assert_eq!(
        use_case_request_hex, actual_request_hex,
        "expected hex (left) differs to the generated hex (right)"
    );
}

#[test]
fn locate_response_private_key() {
    let use_case_response_hex = concat!(
        "42007B01000000B042007A0100000048420069010000002042006A0200000004000000010000000042006B02000000040",
        "0000000000000004200920900000008000000004B73C13B42000D0200000004000000010000000042000F010000005842",
        "005C0500000004000000080000000042007F0500000004000000000000000042007C01000000304200940700000024613",
        "23432666361342D656266302D343339382D616336352D38373962616234393032353900000000",
    );
    let ttlv_wire = hex::decode(use_case_response_hex).unwrap();
    let res: ResponseMessage = from_slice(ttlv_wire.as_ref()).unwrap();

    assert_eq!(res.header.protocol_version.major, 1);
    assert_eq!(res.header.protocol_version.minor, 0);
    assert_eq!(res.header.timestamp, 0x000000004B73C13B);
    assert_eq!(res.header.batch_count, 1);
    assert_eq!(res.batch_items.len(), 1);

    let item = &res.batch_items[0];
    assert!(matches!(item.result_status, ResultStatus::Success));
    assert!(matches!(item.operation, Some(Operation::Locate)));
    assert!(matches!(&item.payload, Some(ResponsePayload::Locate(_))));

    if let Some(ResponsePayload::Locate(payload)) = item.payload.as_ref() {
        assert_eq!(payload.unique_identifiers.len(), 1);

        let identifier = &payload.unique_identifiers[0];
        assert_eq!(identifier, "a242fca4-ebf0-4398-ac65-879bab490259");
    } else {
        panic!("Wrong payload");
    }
}

#[test]
fn destroy_request_private_key() {
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
            RequestPayload::Destroy(Some(UniqueIdentifier("a242fca4-ebf0-4398-ac65-879bab490259".into()))),
        )],
    );

    let use_case_request_hex = concat!(
        "42007801000000904200770100000038420069010000002042006A0200000004000000010000000042006B02000000040",
        "00000000000000042000D0200000004000000010000000042000F010000004842005C0500000004000000140000000042",
        "00790100000030420094070000002461323432666361342D656266302D343339382D616336352D3837396261623439303",
        "2353900000000"
    );
    let actual_request_hex = hex::encode_upper(to_vec(&use_case_request).unwrap());

    assert_eq!(
        use_case_request_hex, actual_request_hex,
        "expected hex (left) differs to the generated hex (right)"
    );
}

#[test]
fn destroy_response_private_key() {
    let use_case_response_hex = concat!(
        "42007B01000000B042007A0100000048420069010000002042006A0200000004000000010000000042006B02000000040",
        "0000000000000004200920900000008000000004B73C13B42000D0200000004000000010000000042000F010000005842",
        "005C0500000004000000140000000042007F0500000004000000000000000042007C01000000304200940700000024613",
        "23432666361342D656266302D343339382D616336352D38373962616234393032353900000000"
    );
    let ttlv_wire = hex::decode(use_case_response_hex).unwrap();
    let res: ResponseMessage = from_slice(ttlv_wire.as_ref()).unwrap();

    assert_eq!(res.header.protocol_version.major, 1);
    assert_eq!(res.header.protocol_version.minor, 0);
    assert_eq!(res.header.timestamp, 0x000000004B73C13B);
    assert_eq!(res.header.batch_count, 1);
    assert_eq!(res.batch_items.len(), 1);

    let item = &res.batch_items[0];
    assert!(matches!(item.result_status, ResultStatus::Success));
    assert!(matches!(item.operation, Some(Operation::Destroy)));
    assert!(matches!(&item.payload, Some(ResponsePayload::Destroy(_))));

    if let Some(ResponsePayload::Destroy(payload)) = item.payload.as_ref() {
        assert_eq!(&payload.unique_identifier, "a242fca4-ebf0-4398-ac65-879bab490259");
    } else {
        panic!("Wrong payload");
    }
}

#[test]
fn destroy_request_public_key() {
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
            RequestPayload::Destroy(Some(UniqueIdentifier("895f72c2-b20a-49d8-9504-6dc2115cc042".into()))),
        )],
    );

    let use_case_request_hex = concat!(
        "42007801000000904200770100000038420069010000002042006A0200000004000000010000000042006B02000000040",
        "00000000000000042000D0200000004000000010000000042000F010000004842005C0500000004000000140000000042",
        "00790100000030420094070000002438393566373263322D623230612D343964382D393530342D3664633231313563633",
        "0343200000000"
    );
    let actual_request_hex = hex::encode_upper(to_vec(&use_case_request).unwrap());

    assert_eq!(
        use_case_request_hex, actual_request_hex,
        "expected hex (left) differs to the generated hex (right)"
    );
}

#[test]
fn destroy_response_public_key() {
    let use_case_response_hex = concat!(
        "42007B01000000B042007A0100000048420069010000002042006A0200000004000000010000000042006B02000000040",
        "0000000000000004200920900000008000000004B73C13B42000D0200000004000000010000000042000F010000005842",
        "005C0500000004000000140000000042007F0500000004000000000000000042007C01000000304200940700000024383",
        "93566373263322D623230612D343964382D393530342D36646332313135636330343200000000",
    );
    let ttlv_wire = hex::decode(use_case_response_hex).unwrap();
    let res: ResponseMessage = from_slice(ttlv_wire.as_ref()).unwrap();

    assert_eq!(res.header.protocol_version.major, 1);
    assert_eq!(res.header.protocol_version.minor, 0);
    assert_eq!(res.header.timestamp, 0x000000004B73C13B);
    assert_eq!(res.header.batch_count, 1);
    assert_eq!(res.batch_items.len(), 1);

    let item = &res.batch_items[0];
    assert!(matches!(item.result_status, ResultStatus::Success));
    assert!(matches!(item.operation, Some(Operation::Destroy)));
    assert!(matches!(&item.payload, Some(ResponsePayload::Destroy(_))));

    if let Some(ResponsePayload::Destroy(payload)) = item.payload.as_ref() {
        assert_eq!(&payload.unique_identifier, "895f72c2-b20a-49d8-9504-6dc2115cc042");
    } else {
        panic!("Wrong payload");
    }
}
