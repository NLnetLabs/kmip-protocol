//! See: https://docs.oasis-open.org/kmip/usecases/v1.0/kmip-usecases-1.0.html#_Toc262822080

#[allow(unused_imports)]
use pretty_assertions::{assert_eq, assert_ne};

use crate::{
    tests::util::assert_req_ser_de,
    types::{
        common::{
            BlockCipherMode, CryptographicAlgorithm, CryptographicParameters, CryptographicUsageMask, HashingAlgorithm,
            ObjectType, Operation, PaddingMethod, UniqueBatchItemID,
        },
        request::{
            self, Attribute, Authentication, BatchCount, BatchItem, CredentialValue, MaximumResponseSize, Password,
            ProtocolVersionMajor, ProtocolVersionMinor, RequestHeader, RequestMessage, RequestPayload,
            TemplateAttribute, Username,
        },
    },
};

/// -------------------------------------------------------------------------------------------------------------------
/// 11.1 Use-case: Credential, Operation Policy, Destroy Date
/// -------------------------------------------------------------------------------------------------------------------

#[test]
#[ignore = "Operational Policy Name attribute is not supported"]
fn kmip_1_0_usecase_11_1_step_1_client_a_create_request_symmetric_key() {
    let credential = Some(CredentialValue::UsernameAndPassword(
        Username("Fred".to_string()),
        Some(Password("password1".to_string())),
    ));

    let use_case_request = RequestMessage(
        RequestHeader(
            request::ProtocolVersion(ProtocolVersionMajor(1), ProtocolVersionMinor(0)),
            Option::<MaximumResponseSize>::None,
            credential.map(Authentication::build),
            None,
            None,
            BatchCount(1),
        ),
        vec![BatchItem(
            Operation::Create,
            Option::<UniqueBatchItemID>::None,
            RequestPayload::Create(
                ObjectType::SymmetricKey,
                TemplateAttribute::new(vec![
                    Attribute::CryptographicAlgorithm(CryptographicAlgorithm::AES),
                    Attribute::CryptographicLength(128),
                    Attribute::CryptographicUsageMask(
                        CryptographicUsageMask::Encrypt | CryptographicUsageMask::Decrypt,
                    ),
                    Attribute::Name("PolicyKey".into()),
                    // Attribute::OperationPolicyName("default".into()),
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

    // Tag: Request Message (0x420078), Type: Structure (0x01), Data:
    //   Tag: Request Header (0x420077), Type: Structure (0x01), Data:
    //     Tag: Protocol Version (0x420069), Type: Structure (0x01), Data:
    //       Tag: Protocol Version Major (0x42006A), Type: Integer (0x02), Data: 0x000001 (1)
    //       Tag: Protocol Version Minor (0x42006B), Type: Integer (0x02), Data: 0x000000 (0)
    //     Tag: Authentication (0x42000C), Type: Structure (0x01), Data:
    //       Tag: Credential (0x420023), Type: Structure (0x01), Data:
    //         Tag: Credential Type (0x420024), Type: Enumeration (0x05), Data: 0x000001 (1 = ??)
    //         Tag: Credential Value (0x420025), Type: Structure (0x01), Data:
    //           Tag: Username (0x420099), Type: TextString (0x07), Data: "Fred"
    //           Tag: Password (0x4200A1), Type: TextString (0x07), Data: "password1"
    //     Tag: Batch Count (0x42000D), Type: Integer (0x02), Data: 0x000001 (1)
    //   Tag: Batch Item (0x42000F), Type: Structure (0x01), Data:
    //     Tag: Operation (0x42005C), Type: Enumeration (0x05), Data: 0x000001 (1 = Create)
    //     Tag: Request Payload (0x420079), Type: Structure (0x01), Data:
    //     Tag: Object Type (0x420057), Type: Enumeration (0x05), Data: 0x000002 (2 = Symmetric Key)
    //     Tag: Template-Attribute (0x420091), Type: Structure (0x01), Data:
    //       Tag: Attribute (0x420008), Type: Structure (0x01), Data:
    //         Tag: Attribute Name (0x42000A), Type: TextString (0x07), Data: "Cryptographic Algorithm"
    //         Tag: Attribute Value (0x42000B), Type: Enumeration (0x05), Data: 0x000003 (3 = ??)
    //       Tag: Attribute (0x420008), Type: Structure (0x01), Data:
    //         Tag: Attribute Name (0x42000A), Type: TextString (0x07), Data: "Cryptographic Length"
    //         Tag: Attribute Value (0x42000B), Type: Integer (0x02), Data: 0x000080 (128)
    //       Tag: Attribute (0x420008), Type: Structure (0x01), Data:
    //         Tag: Attribute Name (0x42000A), Type: TextString (0x07), Data: "Cryptographic Usage Mask"
    //         Tag: Attribute Value (0x42000B), Type: Integer (0x02), Data: 0x00000C (12)
    //       Tag: Attribute (0x420008), Type: Structure (0x01), Data:
    //         Tag: Attribute Name (0x42000A), Type: TextString (0x07), Data: "Name"
    //         Tag: Attribute Value (0x42000B), Type: Structure (0x01), Data:
    //           Tag: Name Value (0x420055), Type: TextString (0x07), Data: "PolicyKey"
    //           Tag: Name Type (0x420054), Type: Enumeration (0x05), Data: 0x000001 (1 = Uninterpreted Text String)
    //       Tag: Attribute (0x420008), Type: Structure (0x01), Data:
    //         Tag: Attribute Name (0x42000A), Type: TextString (0x07), Data: "Operation Policy Name"
    //         Tag: Attribute Value (0x42000B), Type: TextString (0x07), Data: "default"
    //       Tag: Attribute (0x420008), Type: Structure (0x01), Data:
    //         Tag: Attribute Name (0x42000A), Type: TextString (0x07), Data: "Cryptographic Parameters"
    //         Tag: Attribute Value (0x42000B), Type: Structure (0x01), Data:
    //           Tag: Block Cipher Mode (0x420011), Type: Enumeration (0x05), Data: 0x000001 (1 = ??)
    //           Tag: Padding Method (0x42005F), Type: Enumeration (0x05), Data: 0x000003 (3 = ??)
    //           Tag: Hashing Algorithm (0x420038), Type: Enumeration (0x05), Data: 0x000004 (4 = ??)
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

    assert_req_ser_de(use_case_request, use_case_request_hex);
}
