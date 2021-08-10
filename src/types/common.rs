use serde_derive::Deserialize;
use serde_derive::Serialize;

use enum_display_derive::Display;
use enum_flags::EnumFlags;
use std::fmt::Display;

// KMIP spec 1.0 section 2.1.1 Attribute
// See: https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581155
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename = "Transparent:0x42000A")]
pub struct AttributeName(pub String);

impl std::cmp::PartialEq<str> for AttributeName {
    fn eq(&self, other: &str) -> bool {
        self.0 == other
    }
}

// KMIP spec 1.0 section 2.1.1 Attribute
// See: https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581155
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
#[serde(rename = "0x42000B")]
#[non_exhaustive]
pub enum AttributeValue {
    #[serde(rename(deserialize = "if 0x42000A==Cryptographic Algorithm"))]
    #[serde(rename(serialize = "Transparent"))]
    CryptographicAlgorithm(CryptographicAlgorithm),

    #[serde(rename = "if 0x42000A==Cryptographic Parameters")]
    CryptographicParameters(
        #[serde(skip_serializing_if = "Option::is_none")] Option<BlockCipherMode>,
        #[serde(skip_serializing_if = "Option::is_none")] Option<PaddingMethod>,
        #[serde(skip_serializing_if = "Option::is_none")] Option<HashingAlgorithm>,
        #[serde(skip_serializing_if = "Option::is_none")] Option<KeyRoleType>,
    ),

    #[serde(rename(deserialize = "if 0x42000A==Linked Object Identifier"))]
    Link(LinkType, LinkedObjectIdentifier),

    #[serde(rename(deserialize = "if 0x42000A==Name"))]
    Name(NameValue, NameType),

    #[serde(rename(deserialize = "if 0x42000A==Object Type"))]
    #[serde(rename(serialize = "Transparent"))]
    ObjectType(ObjectType),

    #[serde(rename(deserialize = "if 0x42000A==State"))]
    #[serde(rename(serialize = "Transparent"))]
    State(State),

    // KMIP spec 1.0 section 3.33 Custom Attribute:
    //   "Any data type or structure. If a structure, then the structure SHALL NOT include sub structures"
    // See: https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581207

    // TODO: Will this support arbitrary structures?
    #[serde(rename(deserialize = "if type==Structure"))]
    Structure(Vec<AttributeValue>),

    #[serde(rename(deserialize = "if type==Integer"))]
    #[serde(rename(serialize = "Transparent"))]
    Integer(i32),

    #[serde(rename(deserialize = "if type==LongInteger"))]
    LongInteger(i64),

    // TODO
    // #[serde(rename = "if type==BigInteger")]
    // BigInteger(??)
    #[serde(rename(deserialize = "if type==Enumeration"))]
    #[serde(rename(serialize = "Transparent"))]
    Enumeration(u32),

    #[serde(rename(deserialize = "if type==Boolean"))]
    #[serde(rename(serialize = "Transparent"))]
    Boolean(bool),

    #[serde(rename(deserialize = "if type==TextString"))]
    #[serde(rename(serialize = "Transparent"))]
    TextString(String),

    #[serde(rename(deserialize = "if type==ByteString"))]
    #[serde(with = "serde_bytes")]
    ByteString(Vec<u8>),

    #[serde(rename(deserialize = "if type==DateTime"))]
    #[serde(rename(serialize = "Transparent"))]
    DateTime(i64),
    // TODO
    // #[serde(rename = "if type==Interval")]
    // Interval(??),
}

// KMIP spec 1.2 section 2.1.10 Data
// See: https://docs.oasis-open.org/kmip/spec/v1.2/os/kmip-spec-v1.2-os.html#_Toc395776391
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename = "0x4200C2")]
pub struct Data(#[serde(with = "serde_bytes")] pub Vec<u8>);

// KMIP spec 1.2 section 2.1.11 Data Length
// See: https://docs.oasis-open.org/kmip/spec/v1.2/os/kmip-spec-v1.2-os.html#_Toc409613467
#[derive(Clone, Copy, Debug, Serialize, PartialEq, Eq)]
#[serde(rename = "Transparent:0x4200C4")]
pub struct DataLength(pub i32);

// KMIP spec 1.0 section 3.1 Unique Identifier
// See: https://docs.oasis-open.org/kmip/spec/v1.2/os/kmip-spec-v1.2-os.html#_Toc409613482
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename = "Transparent:0x420094")]
pub struct UniqueIdentifier(pub String);

impl std::ops::Deref for UniqueIdentifier {
    type Target = String;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl std::cmp::PartialEq<str> for UniqueIdentifier {
    fn eq(&self, other: &str) -> bool {
        self.0 == other
    }
}

// KMIP spec 1.0 section 3.2 Name
// See: https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581174
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename = "Transparent:0x420055")]
pub struct NameValue(pub String);

impl std::fmt::Display for NameValue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

// KMIP spec 1.0 section 3.3 Object Type
// See: https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581175
#[derive(Clone, Copy, Debug, Deserialize, Serialize, Display, PartialEq, Eq)]
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
#[derive(Clone, Copy, Debug, Deserialize, Serialize, Display, PartialEq, Eq)]
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
#[derive(Clone, Deserialize, Serialize, PartialEq)]
#[serde(rename = "0x420094")]
pub struct CryptographicParameters(CryptographicAlgorithm);

// KMIP spec 1.0 section 3.14 Cryptographic Usage Mask
// See: https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581188
// Note: This enum value is stored in a u32 but is serialized as an i32.
#[repr(u32)]
#[derive(EnumFlags, Clone, Copy, Deserialize, Serialize, Display, PartialEq, Eq)]
#[rustfmt::skip]
#[non_exhaustive]
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

// KMIP spec 1.0 section 3.24 Compromise Occurrence Date
// See: https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581198
#[derive(Clone, Copy, Debug, Serialize, PartialEq, Eq)]
#[serde(rename = "Transparent:0x420021")]
pub struct CompromiseOccurrenceDate(pub u64);

// KMIP spec 1.0 section 3.26 Revocation Reason
// See: https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581200
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
#[serde(rename = "Transparent:0x420080")]
pub struct RevocationMessage(pub String);

// KMIP spec 1.0 section 3.29 Linked Object Identifier
// See: https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581203
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename = "Transparent:0x42004C")]
pub struct LinkedObjectIdentifier(pub String);

// KMIP spec 1.0 section 6.4 Unique Batch Item ID
// See: https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581242
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename(serialize = "Transparent:0x420093"))]
pub struct UniqueBatchItemID(#[serde(with = "serde_bytes")] pub Vec<u8>);

impl PartialEq<Vec<u8>> for &UniqueBatchItemID {
    fn eq(&self, other: &Vec<u8>) -> bool {
        &self.0 == other
    }
}

// KMIP spec 1.0 section 9.1.3.2.2 Key Compression Type Enumeration
// See: https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Ref241603856
#[derive(Clone, Copy, Debug, Deserialize, Serialize, Display, PartialEq, Eq)]
#[serde(rename = "0x420041")]
#[non_exhaustive]
pub enum KeyCompressionType {
    #[serde(rename = "0x00000001")]
    ECPUblicKeyTypeUncompressed,

    #[serde(rename = "0x00000002")]
    ECPUblicKeyTypeX962CompressedPrime,

    #[serde(rename = "0x00000003")]
    ECPUblicKeyTypeX962CompressedChar2,

    #[serde(rename = "0x00000004")]
    ECPUblicKeyTypeX962Hybrid,
}

// KMIP spec 1.0 section 9.1.3.2.3 Key Format Type Enumeration
// See: https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Ref241992670
#[derive(Clone, Copy, Debug, Deserialize, Serialize, Display, PartialEq, Eq)]
#[serde(rename = "0x420042")]
#[non_exhaustive]
pub enum KeyFormatType {
    #[serde(rename = "0x00000001")]
    Raw,

    #[serde(rename = "0x00000002")]
    Opaque,

    #[serde(rename = "0x00000003")]
    PKCS1,

    #[serde(rename = "0x00000004")]
    PKCS8,

    #[serde(rename = "0x00000005")]
    X509,

    #[serde(rename = "0x00000006")]
    ECPrivateKey,

    #[serde(rename = "0x00000007")]
    TransparentSymmetricKey,

    #[serde(rename = "0x00000008")]
    TransparentDSAPrivateKey,

    #[serde(rename = "0x00000009")]
    TransparentDSAPublicKey,

    #[serde(rename = "0x0000000A")]
    TransparentRSAPrivateKey,

    #[serde(rename = "0x0000000B")]
    TransparentRSAPublicKey,

    #[serde(rename = "0x0000000C")]
    TransparentDHPrivateKey,

    #[serde(rename = "0x0000000D")]
    TransparentDHPublicKey,

    #[serde(rename = "0x0000000E")]
    TransparentECDSAPrivateKey,

    #[serde(rename = "0x0000000F")]
    TransparentECDSAPublicKey,

    #[serde(rename = "0x00000010")]
    TransparentECHDPrivateKey,

    #[serde(rename = "0x00000011")]
    TransparentECDHPublicKey,

    #[serde(rename = "0x00000012")]
    TransparentECMQVPrivateKey,

    #[serde(rename = "0x00000013")]
    TransparentECMQVPublicKey,
}

// KMIP spec 1.0 section 9.1.3.2.6 Certificate Type Enumeration
// See: https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Ref241994296
#[derive(Clone, Copy, Debug, Deserialize, Serialize, Display, PartialEq, Eq)]
#[serde(rename = "0x42001D")]
#[non_exhaustive]
pub enum CertificateType {
    #[serde(rename = "0x00000001")]
    X509,

    #[serde(rename = "0x00000002")]
    PGP,
}

// KMIP spec 1.0 section 9.1.3.2.10 Name Type Enumeration
// See: https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262582060
#[derive(Clone, Copy, Debug, Deserialize, Serialize, Display, PartialEq, Eq)]
#[serde(rename = "0x420054")]
#[non_exhaustive]
pub enum NameType {
    #[serde(rename = "0x00000001")]
    UninterpretedTextString,

    #[serde(rename = "0x00000002")]
    URI,
}

// KMIP spec 1.0 section 9.1.3.2.13 Block Cipher Mode Enumeration
// See: https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc236497881
#[derive(Clone, Copy, Debug, Deserialize, Serialize, Display, PartialEq, Eq)]
#[serde(rename = "0x420011")]
#[non_exhaustive]
#[allow(non_camel_case_types)]
pub enum BlockCipherMode {
    #[serde(rename = "0x00000001")]
    CBC,

    #[serde(rename = "0x00000002")]
    ECB,

    #[serde(rename = "0x00000003")]
    PCBC,

    #[serde(rename = "0x00000004")]
    CFB,

    #[serde(rename = "0x00000005")]
    OFB,

    #[serde(rename = "0x00000006")]
    CTR,

    #[serde(rename = "0x00000007")]
    CMAC,

    #[serde(rename = "0x00000008")]
    CCM,

    #[serde(rename = "0x00000009")]
    GCM,

    #[serde(rename = "0x0000000A")]
    CBC_MAC,

    #[serde(rename = "0x0000000B")]
    XTS,

    #[serde(rename = "0x0000000C")]
    AESKeyWrapPadding,

    #[serde(rename = "0x0000000D")]
    NISTKeyWrap,

    #[serde(rename = "0x0000000E")]
    X9_102_AESKW,

    #[serde(rename = "0x0000000F")]
    X9_102_TDKW,

    #[serde(rename = "0x00000010")]
    X9_102_AKW1,

    #[serde(rename = "0x00000011")]
    X9_102_AKW2,
}

// KMIP spec 1.0 section 9.1.3.2.14 Padding Method Enumeration
// See: https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc236497882
#[derive(Clone, Copy, Debug, Deserialize, Serialize, Display, PartialEq, Eq)]
#[serde(rename = "0x42005F")]
#[non_exhaustive]
#[allow(non_camel_case_types)]
pub enum PaddingMethod {
    #[serde(rename = "0x00000001")]
    None,

    #[serde(rename = "0x00000002")]
    OAEP,

    #[serde(rename = "0x00000003")]
    PKCS5,

    #[serde(rename = "0x00000004")]
    SSL3,

    #[serde(rename = "0x00000005")]
    Zeros,

    #[serde(rename = "0x00000006")]
    ANSI_X9_23,

    #[serde(rename = "0x00000007")]
    ISO_10126,

    #[serde(rename = "0x00000008")]
    PKCS1_v1_5,

    #[serde(rename = "0x00000009")]
    X9_31,

    #[serde(rename = "0x0000000A")]
    PSS,
}

// KMIP spec 1.0 section 9.1.3.2.15 Hashing Algorithm Enumeration
// See: https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc236497883
#[derive(Clone, Copy, Debug, Deserialize, Serialize, Display, PartialEq, Eq)]
#[serde(rename = "0x420038")]
#[non_exhaustive]
#[allow(non_camel_case_types)]
pub enum HashingAlgorithm {
    #[serde(rename = "0x00000001")]
    MD2,

    #[serde(rename = "0x00000002")]
    MD4,

    #[serde(rename = "0x00000003")]
    MD5,

    #[serde(rename = "0x00000004")]
    SHA1,

    #[serde(rename = "0x00000005")]
    SHA224,

    #[serde(rename = "0x00000006")]
    SHA256,

    #[serde(rename = "0x00000007")]
    SHA384,

    #[serde(rename = "0x00000008")]
    SHA512,

    #[serde(rename = "0x00000009")]
    RIPEMD160,

    #[serde(rename = "0x0000000A")]
    Tiger,

    #[serde(rename = "0x0000000B")]
    Whirlpool,
}

// KMIP spec 1.0 section 9.1.3.2.15 Key Role TypeEnumeration
// See: https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc236497884
#[derive(Clone, Copy, Debug, Deserialize, Serialize, Display, PartialEq, Eq)]
#[serde(rename = "0x420083")]
#[non_exhaustive]
#[allow(non_camel_case_types)]
pub enum KeyRoleType {
    #[serde(rename = "0x00000001")]
    BDK,

    #[serde(rename = "0x00000002")]
    CVK,

    #[serde(rename = "0x00000003")]
    DEK,

    #[serde(rename = "0x00000004")]
    MKAC,

    #[serde(rename = "0x00000005")]
    MKSMC,

    #[serde(rename = "0x00000006")]
    MKSMI,

    #[serde(rename = "0x00000007")]
    MKDAC,

    #[serde(rename = "0x00000008")]
    MKDN,

    #[serde(rename = "0x00000009")]
    MKCP,

    #[serde(rename = "0x0000000A")]
    MKOTH,

    #[serde(rename = "0x0000000B")]
    KEK,

    #[serde(rename = "0x0000000C")]
    MAC16609,

    #[serde(rename = "0x0000000D")]
    MAC97971,

    #[serde(rename = "0x0000000E")]
    MAC97972,

    #[serde(rename = "0x0000000F")]
    MAC97973,

    #[serde(rename = "0x00000010")]
    MAC97974,

    #[serde(rename = "0x00000011")]
    MAC97975,

    #[serde(rename = "0x00000012")]
    ZPK,

    #[serde(rename = "0x00000013")]
    PVKIBM,

    #[serde(rename = "0x00000014")]
    PVKPVV,

    #[serde(rename = "0x00000015")]
    PVKOTH,
}

// KMIP spec 1.0 section 9.1.3.2.17 State
// See: https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262582066
#[derive(Clone, Copy, Debug, Deserialize, Serialize, Display, PartialEq, Eq)]
#[serde(rename = "0x42008D")]
#[non_exhaustive]
pub enum State {
    #[serde(rename = "0x00000001")]
    PreActive,

    #[serde(rename = "0x00000002")]
    Active,

    #[serde(rename = "0x00000003")]
    Deactivated,

    #[serde(rename = "0x00000004")]
    Compromised,

    #[serde(rename = "0x00000005")]
    Destroyed,

    #[serde(rename = "0x00000006")]
    DestroyedCompromised,
}

// KMIP spec 1.0 section 9.1.3.2.18 Revocation Reason Code
// See: https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Ref241996204
#[derive(Clone, Copy, Debug, Deserialize, Serialize, Display, PartialEq, Eq)]
#[serde(rename = "0x420082")]
#[non_exhaustive]
pub enum RevocationReasonCode {
    #[serde(rename = "0x00000001")]
    Unspecified,

    #[serde(rename = "0x00000002")]
    KeyCompromise,

    #[serde(rename = "0x00000003")]
    CACompromise,

    #[serde(rename = "0x00000004")]
    AffiliationChanged,

    #[serde(rename = "0x00000005")]
    Superseded,

    #[serde(rename = "0x00000006")]
    CessationOfOperation,

    #[serde(rename = "0x00000007")]
    PrivilegeWithdrawn,
}

// KMIP spec 1.0 section 9.1.3.2.19 Link Type Enumeration
// See: https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262582069
#[derive(Clone, Copy, Debug, Deserialize, Serialize, Display, PartialEq, Eq)]
#[serde(rename = "0x42004B")]
#[non_exhaustive]
pub enum LinkType {
    #[serde(rename = "0x00000101")]
    CertificateLink,

    #[serde(rename = "0x00000102")]
    PublicKeyLink,

    #[serde(rename = "0x00000103")]
    PrivateKeyLink,

    #[serde(rename = "0x00000104")]
    DerivationBaseObjectLink,

    #[serde(rename = "0x00000105")]
    DerivedKeyLink,

    #[serde(rename = "0x00000106")]
    ReplacementObjectLink,

    #[serde(rename = "0x00000107")]
    ReplacedObjectLink,
}

// KMIP spec 1.0 section 9.1.3.2.26 Operation Enumeration
// See: https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262582076
#[derive(Clone, Copy, Debug, Deserialize, Serialize, Display, PartialEq, Eq)]
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
