use serde_derive::Deserialize;
use serde_derive::Serialize;

use enum_display_derive::Display;
use enumflags2::bitflags;
use std::fmt::Display;

// KMIP spec 1.0 section 2.1.1 Attribute
// See: https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581155
#[derive(Serialize)]
#[serde(rename = "0x420008")]
pub struct Attribute(pub AttributeName, pub AttributeValue);

// KMIP spec 1.0 section 2.1.1 Attribute
// See: https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581155
#[derive(Serialize)]
#[serde(rename = "0x42000A")]
pub struct AttributeName(pub &'static str);

// KMIP spec 1.0 section 2.1.1 Attribute
// See: https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581155
#[derive(Serialize)]
#[serde(rename = "0x42000B")]
#[non_exhaustive]
pub enum AttributeValue {
    CryptographicAlgorithm(CryptographicAlgorithm),
    Integer(i32),
    Name(NameValue, NameType),
    ObjectType(ObjectType),
    TextString(String),
}

/// Helper functions to simplifying including KMIP TemplateAttributes in requests.
///
/// The set of possible attributes and their textual names are specified by the KMIP 1.0 spec in Section 3 Attributes.
/// We offer various Attribute constructor functions that avoid the need for the caller to couple the right
/// AttributeName and AttributeValue pairs together and to use the correct AttributeName text value and instead just Do
/// The Right Thing for them.
impl Attribute {
    /// KMIP spec 1.0 Section 3.1 Unique Identifier
    #[allow(non_snake_case)]
    pub fn UniqueIdentifier(value: String) -> Self {
        Attribute(AttributeName("Unique Identifier"), AttributeValue::TextString(value))
    }

    /// KMIP spec 1.0 Section 3.2 Name
    #[allow(non_snake_case)]
    pub fn Name(value: String) -> Self {
        Attribute(
            AttributeName("Name"),
            AttributeValue::Name(NameValue(value), NameType::UninterpretedTextString),
        )
    }

    /// KMIP spec 1.0 Section 3.2 Name
    #[allow(non_snake_case)]
    pub fn URI(value: String) -> Self {
        Attribute(
            AttributeName("Name"),
            AttributeValue::Name(NameValue(value), NameType::URI),
        )
    }

    /// KMIP spec 1.0 Section 3.3 Object Type
    #[allow(non_snake_case)]
    pub fn ObjectType(value: ObjectType) -> Self {
        Attribute(AttributeName("Object Type"), AttributeValue::ObjectType(value))
    }

    /// KMIP spec 1.0 Section 3.4 Cryptographic Algorithm
    #[allow(non_snake_case)]
    pub fn CryptographicAlgorithm(value: CryptographicAlgorithm) -> Self {
        Attribute(
            AttributeName("Cryptographic Algorithm"),
            AttributeValue::CryptographicAlgorithm(value),
        )
    }

    /// KMIP spec 1.0 Section 3.5 Cryptographic Length
    #[allow(non_snake_case)]
    pub fn CryptographicLength(value: i32) -> Self {
        Attribute(AttributeName("Cryptographic Length"), AttributeValue::Integer(value))
    }

    /// KMIP spec 1.0 Section 3.14 Cryptographic Usage Mask
    #[allow(non_snake_case)]
    pub fn CryptographicUsageMask(value: CryptographicUsageMask) -> Self {
        Attribute(
            AttributeName("Cryptographic Usage Mask"),
            AttributeValue::Integer(value as i32),
        )
    }
}

macro_rules! impl_template_attribute_flavour {
    ($RustType:ident, $TtlvTag:literal) => {
        #[derive(Serialize)]
        #[serde(rename = $TtlvTag)]
        pub struct $RustType(
            #[serde(skip_serializing_if = "Option::is_none")] pub Option<Vec<Name>>,
            #[serde(skip_serializing_if = "Option::is_none")] pub Option<Vec<Attribute>>,
        );
        impl $RustType {
            pub fn unnamed(attributes: Vec<Attribute>) -> Option<Self> {
                Some(Self(Option::<Vec<Name>>::None, Some(attributes)))
            }
        }
    };
}

// KMIP spec 1.0 section 2.1.8 Template-Attribute Structures
// See: https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581162
impl_template_attribute_flavour!(TemplateAttribute, "0x420091");

// KMIP spec 1.0 section 2.1.8 Template-Attribute Structures
// See: https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581162
impl_template_attribute_flavour!(CommonTemplateAttribute, "0x42001F");

// KMIP spec 1.0 section 2.1.8 Template-Attribute Structures
// See: https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581162
impl_template_attribute_flavour!(PrivateKeyTemplateAttribute, "0x420065");

// KMIP spec 1.0 section 2.1.8 Template-Attribute Structures
// See: https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581162
impl_template_attribute_flavour!(PublicKeyTemplateAttribute, "0x42006E");

// KMIP spec 1.0 section 3.2 Name
// See: https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581174
#[derive(Serialize)]
#[serde(rename = "0x420053")]
pub struct Name(NameValue, NameType);

impl std::fmt::Display for Name {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_fmt(format_args!("{}", self.0))
    }
}

// KMIP spec 1.0 section 3.2 Name
// See: https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581174
#[derive(Serialize)]
#[serde(rename = "0x420055")]
pub struct NameValue(String);

impl std::fmt::Display for NameValue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

// KMIP spec 1.0 section 3.1 Unique Identifier
// See: https://docs.oasis-open.org/kmip/spec/v1.2/os/kmip-spec-v1.2-os.html#_Toc409613482
#[derive(Deserialize, Serialize)]
#[serde(rename = "0x420094")]
pub struct UniqueIdentifier(String);

// KMIP spec 1.0 section 3.3 Object Type
// See: https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581175
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

// KMIP spec 1.0 section 3.4 Cryptographic Algorithm Enumeration
// See: https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581176
#[derive(Deserialize, Serialize, Display, PartialEq)]
#[serde(rename = "0x420028")]
#[non_exhaustive]
#[allow(non_camel_case_types)]
pub enum CryptographicAlgorithm {
    #[serde(rename = "0x00000001")]
    DES,

    #[serde(rename = "0x00000002")]
    TRIPLE_DES,

    #[serde(rename = "0x00000003")]
    AES,

    #[serde(rename = "0x00000004")]
    RSA,
}

// KMIP spec 1.0 section 3.6 Cryptographic Parameters
// See: https://docs.oasis-open.org/kmip/spec/v1.2/os/kmip-spec-v1.2-os.html#_Toc409613487
#[derive(Deserialize, Serialize)]
#[serde(rename = "0x420094")]
pub struct CryptographicParameters(CryptographicAlgorithm);

// KMIP spec 1.0 section 3.14 Cryptographic Usage Mask
// See: https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581188
// Note: This enum value is stored in a u32 but is serialized as an i32.
#[bitflags]
#[repr(u32)]
#[derive(Copy, Clone, PartialEq, Debug)]
#[rustfmt::skip]
pub enum CryptographicUsageMask {
    Sign                            = 0x00000001,
    Verify                          = 0x00000002,
    Encrypt                         = 0x00000004,
    Decrypt                         = 0x00000008,
    WrapKey                         = 0x00000010,
    UnwrapKey                       = 0x00000020,
    Export                          = 0x00000040,
    MacGenerate                     = 0x00000080,
    MacVerify                       = 0x00000100,
    DeriveKey                       = 0x00000200,
    ContentCommitmentNonRepudiation = 0x00000400,
    KeyAgreement                    = 0x00000800,
    CertificateSign                 = 0x00001000,
    CrlSign                         = 0x00002000,
    GenerateCryptogram              = 0x00004000,
    ValidateCryptogram              = 0x00008000,
    TranslateEncrypt                = 0x00010000,
    TranslateDecrypt                = 0x00020000,
    TranslateWrap                   = 0x00040000,
    TranslateUnwrap                 = 0x00080000,
}

// KMIP spec 1.0 section 9.1.3.2.10 Name Type Enumeration
// See: https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262582060
#[derive(Serialize)]
#[serde(rename = "0x420054")]
pub enum NameType {
    #[serde(rename = "0x00000001")]
    UninterpretedTextString,

    #[serde(rename = "0x00000002")]
    URI,
}

// KMIP spec 1.0 section 9.1.3.2.26 Operation Enumeration
// See: https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262582076
#[derive(Deserialize, Serialize, Display, PartialEq)]
#[serde(rename = "0x42005C")]
#[non_exhaustive]
pub enum Operation {
    // KMIP spec 1.0 operations
    #[serde(rename = "0x00000001")]
    Create = 1,

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
