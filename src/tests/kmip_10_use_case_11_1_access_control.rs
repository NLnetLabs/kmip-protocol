//! See: https://docs.oasis-open.org/kmip/usecases/v1.0/kmip-usecases-1.0.html#_Toc262822080

#[allow(unused_imports)]
use pretty_assertions::{assert_eq, assert_ne};

use krill_kmip_ttlv::ser::to_vec;

use crate::{
    auth::{self, CredentialType},
    types::{
        common::{
            BlockCipherMode, CryptographicAlgorithm, CryptographicParameters, CryptographicUsageMask, HashingAlgorithm,
            ObjectType, Operation, PaddingMethod, UniqueBatchItemID,
        },
        request::{
            self, Attribute, Authentication, BatchCount, BatchItem, MaximumResponseSize, ProtocolVersionMajor,
            ProtocolVersionMinor, RequestHeader, RequestMessage, RequestPayload, TemplateAttribute,
        },
    },
};

/// -------------------------------------------------------------------------------------------------------------------
/// 11.1 Use-case: Credential, Operation Policy, Destroy Date
/// -------------------------------------------------------------------------------------------------------------------

#[test]
fn kmip_1_0_usecase_11_1_step_1_client_a_create_request_symmetric_key() {
    let credential = Some(CredentialType::UsernameAndPassword(
        auth::UsernameAndPasswordCredential::new("Fred".to_string(), Some("password1".to_string())),
    ));

    let use_case_request = RequestMessage(
        RequestHeader(
            request::ProtocolVersion(ProtocolVersionMajor(1), ProtocolVersionMinor(0)),
            Option::<MaximumResponseSize>::None,
            credential.map(Authentication::build),
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
                    Attribute::CryptographicUsageMask(
                        CryptographicUsageMask::Encrypt | CryptographicUsageMask::Decrypt,
                    ),
                    Attribute::Name("PolicyKey".into()),
                    Attribute::OperationPolicyName("default".into()),
                    Attribute::CryptographicParameters(
                        CryptographicParameters::default()
                            .with_block_cipher_mode(BlockCipherMode::CBC)
                            .with_padding_method(PaddingMethod::PKCS5)
                            .with_hashing_algorithm(HashingAlgorithm::SHA1),
                    ),
                ]),
            ),
        )],
    );

    let use_case_request_hex = concat!(
        "42007801000002504200770100000088420069010000002042006A0200000004000000010000000042006B02000000040",
        "00000000000000042000C0100000048420023010000004042002405000000040000000100000000420025010000002842",
        "0099070000000446726564000000004200A1070000000970617373776F7264310000000000000042000D0200000004000",
        "000010000000042000F01000001B842005C0500000004000000010000000042007901000001A042005705000000040000",
        "0002000000004200910100000188420008010000003042000A070000001743727970746F6772617068696320416C676F7",
        "26974686D0042000B05000000040000000300000000420008010000003042000A070000001443727970746F6772617068",
        "6963204C656E6774680000000042000B02000000040000008000000000420008010000003042000A07000000184372797",
        "0746F67726170686963205573616765204D61736B42000B02000000040000000C00000000420008010000004042000A07",
        "000000044E616D650000000042000B01000000284200550700000009506F6C6963794B657900000000000000420054050",
        "00000040000000100000000420008010000003042000A07000000154F7065726174696F6E20506F6C696379204E616D65",
        "00000042000B070000000764656661756C7400420008010000005842000A070000001843727970746F677261706869632",
        "0506172616D657465727342000B01000000304200110500000004000000010000000042005F0500000004000000030000",
        "000042003805000000040000000400000000",
    );
    let actual_request_hex = hex::encode_upper(to_vec(&use_case_request).unwrap());

    assert_eq!(
        use_case_request_hex, actual_request_hex,
        "expected hex (left) differs to the generated hex (right)"
    );
}
