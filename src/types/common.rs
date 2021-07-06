use serde_derive::Deserialize;
use serde_derive::Serialize;

use enum_display_derive::Display;
use std::fmt::Display;

// KMIP spec 1.0 section 2.1.1 Attribute
// See: http://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581155
#[derive(Serialize)]
#[serde(rename = "0x420008")]
pub struct Attribute(AttributeName, AttributeValue);

// KMIP spec 1.0 section 2.1.1 Attribute
// See: http://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581155
#[derive(Serialize)]
#[serde(rename = "0x42000A")]
pub struct AttributeName(&'static str);

// KMIP spec 1.0 section 2.1.1 Attribute
// See: http://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581155
#[derive(Serialize, Display)]
#[serde(rename = "0x42000B")]
#[non_exhaustive]
pub enum AttributeValue {
    Integer(i32),
    Enumeration(u32),
}

// KMIP spec 1.0 section 2.1.8 Template-Attribute Structures
// See: http://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581162
#[derive(Serialize)]
#[serde(rename = "0x420091")]
pub struct TemplateAttribute(Vec<Attribute>);

// KMIP spec 1.0 section 3.1 Unique Identifier
// See: http://docs.oasis-open.org/kmip/spec/v1.2/os/kmip-spec-v1.2-os.html#_Toc409613482
#[derive(Deserialize, Serialize)]
#[serde(rename = "0x420094")]
pub struct UniqueIdentifier(String);

// KMIP spec 1.0 section 3.3 Object Type
// See: http://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581175
#[derive(Deserialize, Serialize, Display, PartialEq)]
#[serde(rename = "0x420057")]
#[non_exhaustive]
pub enum ObjectType {
    // KMIP spec 1.0 and 1.1 variants
    #[serde(rename = "0x00000001")]
    Certificate,

    #[serde(rename = "0x00000002")]
    SymmetricKey,

    #[serde(rename = "0x00000003")]
    PublicKey,

    #[serde(rename = "0x00000004")]
    PrivateKey,

    #[serde(rename = "0x00000005")]
    SplitKey,

    #[serde(rename = "0x00000006")]
    Template,

    #[serde(rename = "0x00000007")]
    SecretData,

    #[serde(rename = "0x00000008")]
    OpaqueObject,

    // KMIP spec 1.2 variants
    #[serde(rename = "0x00000009")]
    PGPKey,
}

// KMIP spec 1.0 section 3.4 Cryptographic Algorithm
// See: http://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581176
#[derive(Deserialize, Serialize, Display, PartialEq)]
#[serde(rename = "0x420028")]
#[non_exhaustive]
pub enum CryptographicAlgorithm {
    AES = 0x00000003,
}

// KMIP spec 1.0 section 3.6 Cryptographic Parameters
// See: http://docs.oasis-open.org/kmip/spec/v1.2/os/kmip-spec-v1.2-os.html#_Toc409613487
#[derive(Deserialize, Serialize)]
#[serde(rename = "0x420094")]
pub struct CryptographicParameters(CryptographicAlgorithm);

// KMIP spec 1.0 section 6.2 Operation
// See: http://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581240
#[derive(Deserialize, Serialize, Display, PartialEq)]
#[serde(rename = "0x42005C")]
#[non_exhaustive]
pub enum Operation {
    // KMIP spec 1.0 operations
    #[serde(rename = "0x00000001")]
    Create,

    #[serde(rename = "0x00000002")]
    CreateKeyPair,

    #[serde(rename = "0x00000003")]
    Register,

    #[serde(rename = "0x00000004")]
    Rekey,

    #[serde(rename = "0x00000005")]
    DeriveKey,

    #[serde(rename = "0x00000006")]
    Certify,

    #[serde(rename = "0x00000007")]
    Recertify,

    #[serde(rename = "0x00000008")]
    Locate,

    #[serde(rename = "0x00000009")]
    Check,

    #[serde(rename = "0x0000000A")]
    Get,

    #[serde(rename = "0x0000000B")]
    GetAttributes,

    #[serde(rename = "0x0000000C")]
    GetAttributeList,

    #[serde(rename = "0x0000000D")]
    AddAttribute,

    #[serde(rename = "0x0000000E")]
    ModifyAttribute,

    #[serde(rename = "0x0000000F")]
    DeleteAttribute,

    #[serde(rename = "0x00000010")]
    ObtainLease,

    #[serde(rename = "0x00000011")]
    GetUsageAllocation,

    #[serde(rename = "0x00000012")]
    Activate,

    #[serde(rename = "0x00000013")]
    Revoke,

    #[serde(rename = "0x00000014")]
    Destroy,

    #[serde(rename = "0x00000015")]
    Archive,

    #[serde(rename = "0x00000016")]
    Recover,

    #[serde(rename = "0x00000017")]
    Validate,

    #[serde(rename = "0x00000018")]
    Query,

    #[serde(rename = "0x00000019")]
    Cancel,

    #[serde(rename = "0x0000001A")]
    Poll,

    #[serde(rename = "0x0000001B")]
    Notify,

    #[serde(rename = "0x0000001C")]
    Put,

    // KMIP spec 1.1 operations
    #[serde(rename = "0x0000001D")]
    RekeyKeyPair,

    #[serde(rename = "0x0000001E")]
    DiscoverVersions,

    // KMIP spec 1.2 operations
    #[serde(rename = "0x0000001F")]
    Encrypt,

    #[serde(rename = "0x00000020")]
    Decrypt,

    #[serde(rename = "0x00000021")]
    Sign,

    #[serde(rename = "0x00000022")]
    SignatureVerify,

    #[serde(rename = "0x00000023")]
    MAC,

    #[serde(rename = "0x00000024")]
    MACVerify,

    #[serde(rename = "0x00000025")]
    RNGRetrieve,

    #[serde(rename = "0x00000026")]
    RNGSeed,

    #[serde(rename = "0x00000027")]
    Hash,

    #[serde(rename = "0x00000028")]
    CreateSplitKey,

    #[serde(rename = "0x00000029")]
    JoinSplitKey,
}

#[cfg(test)]
mod test {
    use super::Operation;

    #[test]
    fn test_operation_display() {
        assert_ne!("WrongName", &format!("{}", Operation::Create));
        assert_eq!("Create", &format!("{}", Operation::Create));
        assert_eq!("CreateKeyPair", &format!("{}", Operation::CreateKeyPair));
        assert_eq!("Register", &format!("{}", Operation::Register));
    }
}
