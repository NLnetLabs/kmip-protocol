//! See: https://docs.oasis-open.org/kmip/usecases/v1.0/cs01/kmip-usecases-1.0-cs-01.html#_Toc262822082

use krill_kmip_ttlv::ser::to_vec;

use crate::types::{
    common::{
        Attribute, CommonTemplateAttribute, CryptographicAlgorithm, CryptographicUsageMask, Operation,
        PrivateKeyTemplateAttribute, PublicKeyTemplateAttribute,
    },
    request::{
        self, Authentication, BatchCount, BatchItem, MaximumResponseSize, ProtocolVersionMajor, ProtocolVersionMinor,
        RequestHeader, RequestMessage, RequestPayload,
    },
};

#[test]
fn create_key_pair_rsa_1024() {
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
