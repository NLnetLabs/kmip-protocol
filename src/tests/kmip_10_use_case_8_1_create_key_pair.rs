//! See: https://docs.oasis-open.org/kmip/usecases/v1.0/cs01/kmip-usecases-1.0-cs-01.html#_Toc262822082

use krill_kmip_ttlv::ser::to_vec;

use crate::{
    response::from_slice,
    types::{
        common::{
            Attribute, CommonTemplateAttribute, CryptographicAlgorithm, CryptographicUsageMask, Operation,
            PrivateKeyTemplateAttribute, PublicKeyTemplateAttribute,
        },
        request::{
            self, Authentication, BatchCount, BatchItem, MaximumResponseSize, ProtocolVersionMajor,
            ProtocolVersionMinor, RequestHeader, RequestMessage, RequestPayload,
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
            RequestPayload::CreateKeyPair(
                CommonTemplateAttribute::unnamed(vec![
                    Attribute::CryptographicAlgorithm(CryptographicAlgorithm::RSA),
                    Attribute::CryptographicLength(1024),
                ]),
                PrivateKeyTemplateAttribute::unnamed(vec![
                    Attribute::Name("PrivateKey1".into()),
                    Attribute::CryptographicUsageMask(CryptographicUsageMask::Sign),
                ]),
                PublicKeyTemplateAttribute::unnamed(vec![
                    Attribute::Name("PublicKey1".into()),
                    Attribute::CryptographicUsageMask(CryptographicUsageMask::Verify),
                ]),
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

    assert_eq!(use_case_request_hex, actual_request_hex);
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
