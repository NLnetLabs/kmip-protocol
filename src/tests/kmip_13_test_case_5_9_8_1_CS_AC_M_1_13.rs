//! See: https://docs.oasis-open.org/kmip/profiles/v1.3/os/test-cases/kmip-v1.3/mandatory/CS-AC-M-1-13.xml
//! See: https://docs.oasis-open.org/kmip/profiles/v1.3/cs01/kmip-profiles-v1.3-cs01.html#_Toc459802023

#[allow(unused_imports)]
use pretty_assertions::{assert_eq, assert_ne};

use krill_kmip_ttlv::ser::to_vec;

use crate::types::{
    common::{
        AttributeName, AttributeValue, CryptographicAlgorithm, CryptographicLength, CryptographicParameters,
        CryptographicUsageMask, HashingAlgorithm, KeyCompressionType, KeyFormatType, KeyMaterial, ObjectType,
        Operation, PaddingMethod, UniqueBatchItemID,
    },
    request::{
        self, Attribute, Authentication, BatchCount, BatchItem, KeyBlock, KeyValue, KeyWrappingData, ManagedObject,
        MaximumResponseSize, PrivateKey, ProtocolVersionMajor, ProtocolVersionMinor, RequestHeader, RequestMessage,
        RequestPayload, TemplateAttribute,
    },
};

#[test]
fn register_request() {
    // To get more insight into failed tests use a log implementation, e.g.:
    // SimpleLogger::new().init().unwrap();

    let use_case_key_material_hex = concat!(
        "308204a50201000282010100ab7f161c0042496ccd6c6d4dadb919973435357776003acf54b7af1e440afb80b64a8755f",
        "8002cfeba6b184540a2d66086d74648346d75b8d71812b205387c0f6583bc4d7dc7ec114f3b176b7957c422e7d03fc626",
        "7fa2a6f89b9bee9e60a1d7c2d833e5a5f4bb0b1434f4e795a41100f8aa214900df8b65089f98135b1c67b701675abdbc7",
        "d5721aac9d14a7f081fcec80b64e8a0ecc8295353c795328abf70e1b42e7bb8b7f4e8ac8c810cdb66e3d21126eba8da7d",
        "0ca34142cb76f91f013da809e9c1b7ae64c54130fbc21d80e9c2cb06c5c8d7cce8946a9ac99b1c2815c3612a29a82d73a",
        "1f99374fe30e54951662a6eda29c6fc411335d5dc7426b0f6050203010001028201003b12455d53c1816516c518493f63",
        "98aafa72b17dfa894db888a7d48c0a47f62579a4e644f86da711fec850cdd9dbbd17f69a443d2ec1dd60d3c618fa74cde",
        "5fdafabd6baa26eb0a3adb4def6480fb1218cd3b083e252e885b6f0729f98b2144d2b72293e1b11d73393bc41f75b15ee",
        "3d7569b4995ed1a14425da4319b7b26b0e8fef17c37542ae5c6d5849f87209567f3925a47b016d564859717bc57fcb452",
        "2d0aa49ce816e5be7b3088193236ec9efff140858045b73c5d79baf38f7c67f04c5dcf0e3806ad982d1259058c3473e84",
        "7179a878f2c6b3bd968fb99ea46e9185892f3676e78965c2aed4877ba3917df07c5e927474f19e764ba61dc38d63bf290",
        "2818100d5c69c8c3cdc2464744a793713dafb9f1dbc799ff96423fecd3cba794286bce920f4b5c183f99ee9028db6212c",
        "6277c4c8297fcfbce7f7c24ca4c51fc7182fb8f4019fb1d5659674c5cbe6d5fa992051341760cd00735729a070a9e54d3",
        "42beba8ef47ee82d3a01b04cec4a00d4ddb41e35116fc221e854b43a696c0e6419b1b02818100cd5ea7702789064b6735",
        "40cbff09356ad80bc3d592812eba47610b9fac6aecefe22acae438459cda74e59653d88c04189d34399bf5b14b920e34e",
        "f38a7d09fe69593396e8fe735e6f0a6ae4990401041d8a406b6fd86a1161e45f95a3eaa5c1012e6662e44f15f335ac971",
        "e1766b2bb9c985109974141b44d37e1e319820a55f02818100b2871237bf9fad38c3316ab7877a6a868063e542a7186d4",
        "31e8d27c19ac0414584033942e9ff6e2973bb7b2d8b0e94ad1ee82158108fbc8664517a5a467fb963014bd5dcc2b4fb08",
        "7c23039d11920dbe22fd9f16b4d89e23225cd455adbaf32ef43f185864a36d630309d6853f7714b39aae1ebee3938f87c",
        "2707e178c739f9f028181009690bed14b2afaa26d986d592231ee27d71d49065bd2ba1f78157e20229881fd9d23227d0f",
        "8479eaefa922fd75d5b16b1a561fa6680b040ca0bdce650b23b917a4b1bb7983a74fad70e1c305cbec2bff1a85a726a1d",
        "90260e4f1084f518234dcd3fe770b9520215bd543bb6a4117718754676a34171666a79f26e79c149c5aa102818100a0c9",
        "85a0a0a791a659f99731134c44f37b2e520a2cea35800ad27241ed360dfde6e8ca614f12047fd08b76ac4d13c056a0699",
        "e2f98a1cac91011294d71208f4abab33ba87aa0517f415baca88d6bac006088fa601d349417e1f0c9b23affa4d496618d",
        "bc024986ed690bbb7b025768ff9df8ac15416f489f8129c32341a8b44f"
    )
    .to_uppercase();

    let use_case_key_material_bytes = hex::decode(&use_case_key_material_hex).unwrap();

    let use_case_request = RequestMessage(
        RequestHeader(
            request::ProtocolVersion(ProtocolVersionMajor(1), ProtocolVersionMinor(3)),
            Option::<MaximumResponseSize>::None,
            Option::<Authentication>::None,
            BatchCount(1),
        ),
        vec![BatchItem(
            Operation::Register,
            Option::<UniqueBatchItemID>::None,
            RequestPayload::Register(
                ObjectType::PrivateKey,
                TemplateAttribute::unnamed(vec![
                    Attribute::CryptographicUsageMask(CryptographicUsageMask::Sign),
                    Attribute::CryptographicParameters(
                        CryptographicParameters::default()
                            .with_padding_method(PaddingMethod::PSS)
                            .with_hashing_algorithm(HashingAlgorithm::SHA256)
                            .with_cryptographic_algorithm(CryptographicAlgorithm::RSA),
                    ),
                    Attribute(
                        AttributeName("x-ID".into()),
                        AttributeValue::TextString("CS-AC-M-1-13-prikey1".into()),
                    ),
                    Attribute::ActivationDate(0x000000004B7918AA),
                ]),
                Some(ManagedObject::PrivateKey(PrivateKey(KeyBlock(
                    KeyFormatType::PKCS1,
                    Option::<KeyCompressionType>::None,
                    Some(KeyValue(
                        KeyMaterial::Bytes(use_case_key_material_bytes),
                        Option::<Vec<Attribute>>::None,
                    )),
                    Some(CryptographicAlgorithm::RSA),
                    Some(CryptographicLength(2048)),
                    Option::<KeyWrappingData>::None,
                )))),
            ),
        )],
    );

    // Note: This hex was created by hand as the official KMIP test case includes only an XML representation of the
    // request. Lengths are represented by <X> placeholders as their values are calculated and replaced below.
    let expected_request_hex = concat!(
        "420078 01 00000678",                         // Request Message, Structure (0x01)
        "  420077 01 00000038",                       // Request Header, Structure (0x01)
        "    420069 01 00000020",                     // Protocol Version, Structure (0x01)
        "      42006A 02 00000004 00000001 00000000", // Protocol Version Major, Integer (0x02), Data: 1 (+ 4 pad bytes)
        "      42006B 02 00000004 00000003 00000000", // Protocol Version Minor, Integer (0x02), Data: 3 (+ 4 pad bytes)
        "    42000D 02 00000004 00000001 00000000",   // Batch Count, Integer (0x02), Data: 0x01 (+ 4 pad bytes)
        "  42000F 01 00000630",                       // Batch Item, Structure (0x01)
        "    42005C 05 00000004 00000003 00000000", // Operation, Enumeration (0x05), Data: 0x03 (Register + 4 pad bytes)
        "    420079 01 00000618",                   // Request Payload, Structure (0x01)
        "      420057 05 00000004 00000004 00000000", // Object Type, Enumeration (0x05), Data: 0x04 (Private Key + 4 pad bytes)
        "      420091 01 00000100",                   // Template-Attribute, Structure (0x01)
        "        420008 01 00000030",                 // Attribute, Structure (0x01)
        "          42000A 07 00000018 43727970746F67726170686963205573616765204D61736B", // Attribute Name, Text String (0x07), Data: Cryptographic Usage Mask
        "          42000B 02 00000004 00000001 00000000", // Attribute Value, Enumeration (0x05), Data: 0x01 (Sign + 4 pad bytes)
        "        420008 01 00000058",                     // Attribute, Structure (0x01)
        "          42000A 07 00000018 43727970746F6772617068696320506172616D6574657273", // Atribute Name, Text String (0x07), Data: Cryptographic Parameters
        "          42000B 01 00000030", // Attribute Value, Structure (0x01)
        "            42005F 05 00000004 0000000A 00000000", // Padding Method, Enumeration (0x05), Data: 0x0A (PSS + 4 pad bytes)
        "            420038 05 00000004 00000006 00000000", // Hashing Algorithm, Enumeration (0x05), Data: 0x06 (SHA256 + 4 pad bytes)
        "            420028 05 00000004 00000004 00000000", // Cryptographic Algorithm, Enumeration (0x05), Data: 0x04 (RSA + 4 pad bytes)
        "        420008 01 00000030",                       // Attribute, Structure (0x01)
        "          42000A 07 00000004 782D4944 00000000", // Attribute Name, Text String (0x07), Data: x-ID (+ 4 pad bytes)
        "          42000B 07 00000014 43532D41432D4D2D312D31332D7072696B65793100000000", // Attribute Value, Text String (0x07), Data: CS-AC-M-1-13-prikey1 (+ 4 pad bytes)
        "        420008 01 00000028",                                                    // Attribute, Structure (0x01)
        "          42000A 07 0000000F 41637469766174696F6E204461746500", // Attribute Name, Text String (0x07), Data: Activation Date
        "          42000B 09 00000008 000000004B7918AA", // Attribute Value, Date-Time (0x09), Data: 04B7918AA
        "      420064 01 000004F8",                      // Private Key, Structure (0x01)
        "        420040 01 000004F0",                    // Key Block, Structure (0x01)
        "          420042 05 00000004 00000003 00000000", // Key Format Type, Enumeration (0x05), Data: 3 (PKCS1 + 4 pad bytes)
        "          420045 01 000004B8",                   // Key Value, Structure (0x01)
        "            420043 08 000004A9 <KEY_MATERIAL_BYTES>00000000000000", // Key Material, Byte String (0x08), Data: 0x4A9 (1193) bytes of key data (+ 7 pad bytes)
        "            420028 05 00000004 00000004 00000000", // Cryptographic Algorithm, Enumeration (0x05), Data: 0x04 (RSA + 4 pad bytes)
        "            42002A 02 00000004 00000800 00000000", // Cryptgraphic Length, Integer (0x02), Data: 0x800 (2048 + 4 pad bytes)
    );
    let expected_request_hex = expected_request_hex.replace(" ", "");
    let expected_request_hex = expected_request_hex.replace("<KEY_MATERIAL_BYTES>", &use_case_key_material_hex);

    let actual_request_hex = hex::encode_upper(to_vec(&use_case_request).unwrap());

    assert_eq!(
        expected_request_hex, actual_request_hex,
        "expected hex (left) differs to the generated hex (right)"
    );
}
