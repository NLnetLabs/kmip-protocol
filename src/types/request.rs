use serde_derive::Serialize;

use super::common::{
    AttributeName, AttributeValue, CompromiseOccurrenceDate, CryptographicAlgorithm, CryptographicUsageMask,
    DataLength, KeyCompressionType, KeyFormatType, LinkType, LinkedObjectIdentifier, NameType, NameValue, ObjectType,
    Operation, RevocationMessage, RevocationReasonCode, UniqueIdentifier,
};

// KMIP spec 1.0 section 2.1.1 Attribute
// See: https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581155
#[derive(Serialize)]
#[serde(rename = "0x420008")]
pub struct Attribute(pub AttributeName, pub AttributeValue);

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
        Attribute(
            AttributeName("Unique Identifier".into()),
            AttributeValue::TextString(value),
        )
    }

    /// KMIP spec 1.0 Section 3.2 Name
    #[allow(non_snake_case)]
    pub fn Name(value: String) -> Self {
        Attribute(
            AttributeName("Name".into()),
            AttributeValue::Name(NameValue(value), NameType::UninterpretedTextString),
        )
    }

    /// KMIP spec 1.0 Section 3.2 Name
    #[allow(non_snake_case)]
    pub fn URI(value: String) -> Self {
        Attribute(
            AttributeName("Name".into()),
            AttributeValue::Name(NameValue(value), NameType::URI),
        )
    }

    /// KMIP spec 1.0 Section 3.3 Object Type
    #[allow(non_snake_case)]
    pub fn ObjectType(value: ObjectType) -> Self {
        Attribute(AttributeName("Object Type".into()), AttributeValue::ObjectType(value))
    }

    /// KMIP spec 1.0 Section 3.4 Cryptographic Algorithm
    #[allow(non_snake_case)]
    pub fn CryptographicAlgorithm(value: CryptographicAlgorithm) -> Self {
        Attribute(
            AttributeName("Cryptographic Algorithm".into()),
            AttributeValue::CryptographicAlgorithm(value),
        )
    }

    /// KMIP spec 1.0 Section 3.5 Cryptographic Length
    #[allow(non_snake_case)]
    pub fn CryptographicLength(value: i32) -> Self {
        Attribute(
            AttributeName("Cryptographic Length".into()),
            AttributeValue::Integer(value),
        )
    }

    /// KMIP spec 1.0 Section 3.14 Cryptographic Usage Mask
    #[allow(non_snake_case)]
    pub fn CryptographicUsageMask(value: CryptographicUsageMask) -> Self {
        Attribute(
            AttributeName("Cryptographic Usage Mask".into()),
            AttributeValue::Integer(value as i32),
        )
    }

    /// KMIP spec 1.0 Section 3.29 Link
    #[allow(non_snake_case)]
    pub fn Link(link_type: LinkType, linked_object_identifier: LinkedObjectIdentifier) -> Self {
        Attribute(
            AttributeName("Link".into()),
            AttributeValue::Link(link_type, linked_object_identifier),
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

// KMIP spec 1.0 section 2.1.2 Credential
// See: https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581156
#[derive(Serialize)]
#[serde(rename = "0x420023")]
pub struct Credential(pub CredentialType, pub CredentialValue);

#[derive(Serialize)]
#[serde(rename = "0x420024")]
#[non_exhaustive]
pub enum CredentialType {
    #[serde(rename = "0x00000001")]
    UsernameAndPassword,
}

#[derive(Serialize)]
#[serde(rename = "0x420025")]
#[non_exhaustive]
pub enum CredentialValue {
    UsernameAndPassword(UsernameAndPasswordCredential),
}

#[derive(Serialize)]
pub struct UsernameAndPasswordCredential(pub Username, pub Option<Password>);

#[derive(Serialize)]
#[serde(rename = "0x420099")]
pub struct Username(pub String);

#[derive(Serialize)]
#[serde(rename = "0x4200A1")]
pub struct Password(pub String);

// KMIP spec 1.0 section 2.1.6 Key Wrapping Specification
// See: https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581160
#[derive(Serialize)]
#[serde(rename = "0x420047")]
pub struct KeyWrappingSpecification(pub WrappingMethod); // ... TODO

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

// KMIP spec 1.0 section 3.26 Revocation Reason
// See: https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581200
#[derive(Serialize)]
#[serde(rename = "0x420081")]
pub struct RevocationReason(
    pub RevocationReasonCode,
    #[serde(skip_serializing_if = "Option::is_none")] pub Option<RevocationMessage>,
);

// KMIP spec 1.0 section 6.1 Protocol Version
// See: https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581239
#[derive(Serialize)]
#[serde(rename = "0x420069")]
pub struct ProtocolVersion(pub ProtocolVersionMajor, pub ProtocolVersionMinor);

#[derive(Serialize)]
#[serde(rename = "0x42006A")]
pub struct ProtocolVersionMajor(pub i32);

#[derive(Serialize)]
#[serde(rename = "0x42006B")]
pub struct ProtocolVersionMinor(pub i32);

// KMIP spec 1.0 section 6.3 Maximum Response Size
// See: https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581241
#[derive(Serialize)]
#[serde(rename = "0x420050")]
pub struct MaximumResponseSize(pub i32);

// KMIP spec 1.0 section 6.4 Unique Batch Item ID
// See: https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581242
#[derive(Serialize)]
#[serde(rename = "0x420093")]
pub struct UniqueBatchItemID(#[serde(with = "serde_bytes")] pub Vec<u8>);

// KMIP spec 1.0 section 6.6 Authentication
// See: https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581244
#[derive(Serialize)]
#[serde(rename = "0x42000C")]
pub struct Authentication(pub Credential);

// KMIP spec 1.0 section 6.14 Batch Count
// See: https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581252
#[derive(Serialize)]
#[serde(rename = "0x42000D")]
pub struct BatchCount(pub i32);

// KMIP spec 1.0 section 6.15 Batch Item
// See: https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581253
#[derive(Serialize)]
#[serde(rename = "0x42000F")]
pub struct BatchItem(
    pub Operation,
    #[serde(skip_serializing_if = "Option::is_none")] pub Option<UniqueBatchItemID>,
    pub RequestPayload,
);

// KMIP spec 1.0 section 7.1 Message Format
// See: https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581256
#[derive(Serialize)]
#[serde(rename = "0x420078")]
pub struct RequestMessage(pub RequestHeader, pub Vec<BatchItem>);

// KMIP spec 1.0 section 7.2 Operations
// See: https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581257
#[derive(Serialize)]
#[serde(rename = "0x420077")]
pub struct RequestHeader(
    pub ProtocolVersion,
    #[serde(skip_serializing_if = "Option::is_none")] pub Option<MaximumResponseSize>,
    #[serde(skip_serializing_if = "Option::is_none")] pub Option<Authentication>,
    pub BatchCount,
);

#[derive(Serialize)]
#[serde(rename = "0x420079")]
#[non_exhaustive]
pub enum RequestPayload {
    // KMIP spec 1.0 section 4.1 Create
    // See: https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581209
    Create(ObjectType, TemplateAttribute),

    // KMIP spec 1.0 section 4.2 Create Key Pair
    // See: https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581210
    CreateKeyPair(
        #[serde(skip_serializing_if = "Option::is_none")] Option<CommonTemplateAttribute>,
        #[serde(skip_serializing_if = "Option::is_none")] Option<PrivateKeyTemplateAttribute>,
        #[serde(skip_serializing_if = "Option::is_none")] Option<PublicKeyTemplateAttribute>,
    ),

    // KMIP spec 1.0 section 4.8 Locate
    // See: https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581216
    Locate(Vec<Attribute>), // TODO: Add MaximumItems and StorageStatusMask optional request payload fields

    // KMIP spec 1.0 section 4.10 Get
    // See: https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581218
    Get(
        #[serde(skip_serializing_if = "Option::is_none")] Option<UniqueIdentifier>,
        #[serde(skip_serializing_if = "Option::is_none")] Option<KeyFormatType>,
        #[serde(skip_serializing_if = "Option::is_none")] Option<KeyCompressionType>,
        #[serde(skip_serializing_if = "Option::is_none")] Option<KeyWrappingSpecification>,
    ),

    // KMIP spec 1.0 section 4.11 Get Attributes
    // See: https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581219
    GetAttributes(
        #[serde(skip_serializing_if = "Option::is_none")] Option<UniqueIdentifier>,
        #[serde(skip_serializing_if = "Option::is_none")] Option<Vec<AttributeName>>,
    ),

    // KMIP spec 1.0 section 4.12 Get Attribute List
    // See: https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581220
    GetAttributeList(#[serde(skip_serializing_if = "Option::is_none")] Option<UniqueIdentifier>),

    // KMIP spec 1.0 section 4.13 Add Attribute
    // See: https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581221
    AddAttribute(
        #[serde(skip_serializing_if = "Option::is_none")] Option<UniqueIdentifier>,
        Attribute,
    ),

    // KMIP spec 1.0 section 4.18 Activate
    // See: https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581226
    Activate(#[serde(skip_serializing_if = "Option::is_none")] Option<UniqueIdentifier>),

    // KMIP spec 1.0 section 4.19 Revoke
    // See: https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581227
    Revoke(
        #[serde(skip_serializing_if = "Option::is_none")] Option<UniqueIdentifier>,
        RevocationReason,
        #[serde(skip_serializing_if = "Option::is_none")] Option<CompromiseOccurrenceDate>,
    ),

    // KMIP spec 1.0 section 4.20 Destroy
    // See: https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581228
    Destroy(#[serde(skip_serializing_if = "Option::is_none")] Option<UniqueIdentifier>),

    // KMIP spec 1.0 section 4.24 Query
    // See: https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581232
    Query(Vec<QueryFunction>),

    // KMIP spec 1.1 section 4.26 Discover Versions
    // See: https://docs.oasis-open.org/kmip/spec/v1.1/cs01/kmip-spec-v1.1-cs01.html#_Toc332787652
    DiscoverVersions(Vec<ProtocolVersion>),

    // KMIP spec 1.2 section 4.31 Sign
    // See: https://docs.oasis-open.org/kmip/spec/v1.2/os/kmip-spec-v1.2-os.html#_Toc409613558
    Sign,

    // KMIP spec 1.2 section 4.35 RNG Retrieve
    // See: https://docs.oasis-open.org/kmip/spec/v1.2/os/kmip-spec-v1.2-os.html#_Toc409613562
    RNGRetrieve(DataLength),
}

// KMIP spec 1.0 section 9.1.3.2.4 Wrapping Method Enumeration
// See: https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Ref241993348
#[derive(Serialize)]
#[serde(rename = "0x42009E")]
#[non_exhaustive]
pub enum WrappingMethod {
    #[serde(rename = "0x00000001")]
    Encrypt,

    #[serde(rename = "0x00000002")]
    MACSign,

    #[serde(rename = "0x00000003")]
    EncryptThenMACSign,

    #[serde(rename = "0x00000004")]
    MACSignThenEncrypt,

    #[serde(rename = "0x00000005")]
    TR31,
}

// KMIP spec 1.0 section 9.1.3.2.23 Query Function Enumeration
// See: https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Ref242030554
#[derive(Serialize)]
#[serde(rename = "0x420074")]
#[non_exhaustive]
pub enum QueryFunction {
    #[serde(rename = "0x00000001")]
    QueryOperations,

    #[serde(rename = "0x00000002")]
    QueryObjects,

    #[serde(rename = "0x00000003")]
    QueryServerInformation,
    // Note: This set of enum variants is deliberately limited to those that we currently support.
}
