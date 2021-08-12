use enum_display_derive::Display;
use serde_derive::Serialize;
use std::fmt::Display;

use super::common::{
    ApplicationData, ApplicationNamespace, AttributeName, AttributeValue, CompromiseOccurrenceDate,
    CryptographicAlgorithm, CryptographicLength, CryptographicParameters, CryptographicUsageMask, DataLength,
    KeyCompressionType, KeyFormatType, KeyMaterial, LinkType, LinkedObjectIdentifier, NameType, NameValue, ObjectType,
    Operation, RevocationMessage, RevocationReasonCode, UniqueBatchItemID, UniqueIdentifier,
};

// KMIP spec 1.0 section 2.1.1 Attribute
// See: https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581155
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
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

    /// KMIP spec 1.0 Section 3.6 Cryptographic Parameters
    #[allow(non_snake_case)]
    pub fn CryptographicParameters(cryptographic_parameters: CryptographicParameters) -> Self {
        Attribute(
            AttributeName("Cryptographic Parameters".into()),
            cryptographic_parameters.into(),
        )
    }

    /// KMIP spec 1.0 Section 3.13 Operation Policy Name
    #[allow(non_snake_case)]
    pub fn OperationPolicyName(value: String) -> Self {
        Attribute(
            AttributeName("Operation Policy Name".into()),
            AttributeValue::TextString(value),
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

    /// KMIP spec 1.0 Section 3.24 Activation Date
    #[allow(non_snake_case)]
    pub fn ActivationDate(value: u64) -> Self {
        Attribute(AttributeName("Activation Date".into()), AttributeValue::DateTime(value))
    }

    /// KMIP spec 1.0 Section 3.28 Object Group
    #[allow(non_snake_case)]
    pub fn ObjectGroup(value: String) -> Self {
        Attribute(AttributeName("Object Group".into()), AttributeValue::TextString(value))
    }

    /// KMIP spec 1.0 Section 3.29 Link
    #[allow(non_snake_case)]
    pub fn Link(link_type: LinkType, linked_object_identifier: LinkedObjectIdentifier) -> Self {
        Attribute(
            AttributeName("Link".into()),
            AttributeValue::Link(link_type, linked_object_identifier),
        )
    }

    /// KMIP spec 1.0 Section 3.30 Application Specific Information
    #[allow(non_snake_case)]
    pub fn ApplicationSpecificInformation(
        application_namespace: ApplicationNamespace,
        application_data: ApplicationData,
    ) -> Self {
        Attribute(
            AttributeName("Application Specific Information".into()),
            AttributeValue::ApplicationSpecificInformation(application_namespace, application_data),
        )
    }

    /// KMIP spec 1.0 Section 3.31 Contact Information
    #[allow(non_snake_case)]
    pub fn ContactInformation(value: String) -> Self {
        Attribute(
            AttributeName("Contact Information".into()),
            AttributeValue::ContactInformation(value),
        )
    }
}

macro_rules! impl_template_attribute_flavour {
    ($RustType:ident, $TtlvTag:literal) => {
        #[derive(Clone, Debug, Serialize, PartialEq, Eq)]
        #[serde(rename = $TtlvTag)]
        pub struct $RustType(
            #[serde(skip_serializing_if = "Option::is_none")] pub Option<Vec<Name>>,
            #[serde(skip_serializing_if = "Option::is_none")] pub Option<Vec<Attribute>>,
        );
        impl $RustType {
            pub fn unnamed(attributes: Vec<Attribute>) -> Self {
                Self(Option::<Vec<Name>>::None, Some(attributes))
            }

            pub fn named(name: String, attributes: Vec<Attribute>) -> Self {
                Self(
                    Some(vec![Name(NameValue(name), NameType::UninterpretedTextString)]),
                    Some(attributes),
                )
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
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
#[serde(rename = "0x420023")]
pub struct Credential(pub CredentialType, pub CredentialValue);

#[derive(Clone, Copy, Debug, Serialize, Display, PartialEq, Eq)]
#[serde(rename = "0x420024")]
#[non_exhaustive]
pub enum CredentialType {
    #[serde(rename = "0x00000001")]
    UsernameAndPassword,
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
#[serde(rename = "0x420025")]
#[non_exhaustive]
pub enum CredentialValue {
    UsernameAndPassword(
        Username,
        #[serde(skip_serializing_if = "Option::is_none")] Option<Password>,
    ),
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
#[serde(rename = "Transparent:0x420099")]
pub struct Username(pub String);

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
#[serde(rename = "Transparent:0x4200A1")]
pub struct Password(pub String);

// KMIP spec 1.0 section 2.1.3 Key Block
// See: https://docs.oasis-open.org/kmip/spec/v1.2/os/kmip-spec-v1.2-os.html#_Toc409613459
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
#[serde(rename = "0x420040")]
pub struct KeyBlock(
    pub KeyFormatType,
    #[serde(skip_serializing_if = "Option::is_none")] pub Option<KeyCompressionType>,
    #[serde(skip_serializing_if = "Option::is_none")] pub Option<KeyValue>,
    #[serde(skip_serializing_if = "Option::is_none")] pub Option<CryptographicAlgorithm>,
    #[serde(skip_serializing_if = "Option::is_none")] pub Option<CryptographicLength>,
    #[serde(skip_serializing_if = "Option::is_none")] pub Option<KeyWrappingData>,
);

// KMIP spec 1.0 section 2.1.4 Key Value
// See: https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581158
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
#[serde(rename = "0x420045")]
pub struct KeyValue(
    pub KeyMaterial,
    #[serde(skip_serializing_if = "Option::is_none")] pub Option<Vec<Attribute>>,
);

// KMIP spec 1.0 section 2.1.5 Key Wrapping Data
// See: https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581159
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
#[serde(rename = "0x420046")]
pub struct KeyWrappingData(
    pub WrappingMethod,
    #[serde(skip_serializing_if = "Option::is_none")] pub Option<EncryptionKeyInformation>,
    #[serde(skip_serializing_if = "Option::is_none")] pub Option<MACOrSignatureKeyInformation>,
    #[serde(skip_serializing_if = "Option::is_none")] pub Option<MACOrSignature>,
    #[serde(skip_serializing_if = "Option::is_none")] pub Option<IVOrCounterOrNonce>,
    #[serde(skip_serializing_if = "Option::is_none")] pub Option<Vec<Attribute>>,
);

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
#[serde(rename = "Transparent:0x42004D")]
pub struct MACOrSignature(#[serde(with = "serde_bytes")] Vec<u8>);

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
#[serde(rename = "Transparent:0x42003D")]
pub struct IVOrCounterOrNonce(#[serde(with = "serde_bytes")] Vec<u8>);

// KMIP spec 1.0 section 2.1.5 Encryption Key Information
// See: https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581159
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
#[serde(rename = "0x420036")]
pub struct EncryptionKeyInformation(
    pub UniqueIdentifier,
    #[serde(skip_serializing_if = "Option::is_none")] pub Option<CryptographicParameters>,
);

// KMIP spec 1.0 section 2.1.5 MAC/Signature Key Information
// See: https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581159
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
#[serde(rename = "0x42004E")]
pub struct MACOrSignatureKeyInformation(
    pub UniqueIdentifier,
    #[serde(skip_serializing_if = "Option::is_none")] pub Option<CryptographicParameters>,
);

// KMIP spec 1.0 section 2.1.6 Key Wrapping Specification
// See: https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581160
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
#[serde(rename = "Transparent:0x420047")]
pub struct KeyWrappingSpecification(
    pub WrappingMethod,
    #[serde(skip_serializing_if = "Option::is_none")] pub Option<EncryptionKeyInformation>,
    #[serde(skip_serializing_if = "Option::is_none")] pub Option<MACOrSignatureKeyInformation>,
    #[serde(skip_serializing_if = "Option::is_none")] pub Option<Vec<Attribute>>,
);

// KMIP spec 1.0 section 2.2 Managed Objects
// See: https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581163
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
#[serde(untagged)]
#[non_exhaustive]
pub enum ManagedObject {
    // Certificate(Certificate),
    // Not implemented

    // SymmetricKey(SymmetricKey),
    // Not implemented

    // PublicKey(PublicKey),
    // Not implemented
    PrivateKey(PrivateKey),

    // SplitKey(SplitKey),
    // Not implemented
    Template(Template),
    // SecretData(SecretData),
    // Not implemented

    // OpaqueObject(OpaqueObject),
    // Not implemented
}

// KMIP spec 1.0 section 2.2.4 Private Key
// See: https://docs.oasis-open.org/kmip/spec/v1.2/os/kmip-spec-v1.2-os.html#_Toc409613475
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
#[serde(rename = "0x420064")]
pub struct PrivateKey(pub KeyBlock);

// KMIP spec 1.0 section 2.2.6 Template
// See: https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581169
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
#[serde(rename = "0x420090")]
pub struct Template(pub Vec<Attribute>);

// KMIP spec 1.0 section 3.2 Name
// See: https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581174
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
#[serde(rename = "0x420053")]
pub struct Name(pub NameValue, pub NameType);

impl std::fmt::Display for Name {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_fmt(format_args!("{}", self.0))
    }
}

// KMIP spec 1.0 section 3.26 Revocation Reason
// See: https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581200
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
#[serde(rename = "0x420081")]
pub struct RevocationReason(
    pub RevocationReasonCode,
    #[serde(skip_serializing_if = "Option::is_none")] pub Option<RevocationMessage>,
);

// KMIP spec 1.0 section 6.1 Protocol Version
// See: https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581239
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
#[serde(rename = "0x420069")]
pub struct ProtocolVersion(pub ProtocolVersionMajor, pub ProtocolVersionMinor);

#[derive(Clone, Copy, Debug, Serialize, PartialEq, Eq)]
#[serde(rename = "Transparent:0x42006A")]
pub struct ProtocolVersionMajor(pub i32);

#[derive(Clone, Copy, Debug, Serialize, PartialEq, Eq)]
#[serde(rename = "Transparent:0x42006B")]
pub struct ProtocolVersionMinor(pub i32);

// KMIP spec 1.0 section 6.3 Maximum Response Size
// See: https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581241
#[derive(Clone, Copy, Debug, Serialize, PartialEq, Eq)]
#[serde(rename = "Transparent:0x420050")]
pub struct MaximumResponseSize(pub i32);

// KMIP spec 1.0 section 6.6 Authentication
// See: https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581244
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
#[serde(rename = "0x42000C")]
pub struct Authentication(pub Credential);

// KMIP spec 1.0 section 6.14 Batch Count
// See: https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581252
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
#[serde(rename = "Transparent:0x42000D")]
pub struct BatchCount(pub i32);

// KMIP spec 1.0 section 6.15 Batch Item
// See: https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581253
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
#[serde(rename = "0x42000F")]
pub struct BatchItem(
    pub Operation,
    #[serde(skip_serializing_if = "Option::is_none")] pub Option<UniqueBatchItemID>,
    pub RequestPayload,
);

// KMIP spec 1.0 section 7.1 Message Format
// See: https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581256
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
#[serde(rename = "0x420078")]
pub struct RequestMessage(pub RequestHeader, pub Vec<BatchItem>);

// KMIP spec 1.0 section 7.2 Operations
// See: https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581257
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
#[serde(rename = "0x420077")]
pub struct RequestHeader(
    pub ProtocolVersion,
    #[serde(skip_serializing_if = "Option::is_none")] pub Option<MaximumResponseSize>,
    #[serde(skip_serializing_if = "Option::is_none")] pub Option<Authentication>,
    pub BatchCount,
);

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
#[serde(rename = "0x420079")]
#[non_exhaustive]
#[allow(clippy::large_enum_variant)]
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

    // KMIP spec 1.0 section 4.3 Register
    // See: https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581211
    Register(
        ObjectType,
        TemplateAttribute,
        #[serde(skip_serializing_if = "Option::is_none")] Option<ManagedObject>,
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

    // KMIP spec 1.0 section 4.14 Modify Attribute
    // See: https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581222
    ModifyAttribute(
        #[serde(skip_serializing_if = "Option::is_none")] Option<UniqueIdentifier>,
        Attribute,
    ),

    // KMIP spec 1.0 section 4.15 Delete Attribute
    // See: https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581223
    DeleteAttribute(
        #[serde(skip_serializing_if = "Option::is_none")] Option<UniqueIdentifier>,
        AttributeName,
        #[serde(skip_serializing_if = "Option::is_none")] Option<i32>,
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

impl RequestPayload {
    pub fn operation(&self) -> Operation {
        match self {
            RequestPayload::Create(..) => Operation::Create,
            RequestPayload::CreateKeyPair(..) => Operation::CreateKeyPair,
            RequestPayload::Register(..) => Operation::Register,
            // Not implemented: Re-key (KMIP 1.0)
            // Not implemented: Re-key Key Pair (KMIP 1.1)
            // Not implemented: Derive Key (KMIP 1.0)
            // Not implemented: Certify (KMIP 1.0)
            // Not implemented: Re-certify (KMIP 1.0)
            RequestPayload::Locate(..) => Operation::Locate,
            // Not implemented: Check (KMIP 1.0)
            RequestPayload::Get(..) => Operation::Get,
            RequestPayload::GetAttributes(..) => Operation::GetAttributes,
            RequestPayload::GetAttributeList(..) => Operation::GetAttributeList,
            RequestPayload::AddAttribute(..) => Operation::AddAttribute,
            RequestPayload::ModifyAttribute(..) => Operation::ModifyAttribute,
            RequestPayload::DeleteAttribute(..) => Operation::DeleteAttribute,
            // Not implemented: Obtain Lease (KMIP 1.0)
            // Not implemented: Get Usage Allocation (KMIP 1.0)
            RequestPayload::Activate(..) => Operation::Activate,
            RequestPayload::Revoke(..) => Operation::Revoke,
            RequestPayload::Destroy(..) => Operation::Destroy,
            // Not implemented: Archive (KMIP 1.0)
            // Not implemented: Recover (KMIP 1.0)
            // Not implemented: Validate (KMIP 1.0)
            RequestPayload::Query(..) => Operation::Query,
            RequestPayload::DiscoverVersions(..) => Operation::DiscoverVersions,
            // Not implemented: Cancel (KMIP 1.0)
            // Not implemented: Poll (KMIP 1.0)
            // Not implemented: Encrypt (KMIP 1.2)
            // Not implemented: Decrypt (KMIP 1.2)
            RequestPayload::Sign => Operation::Sign,
            // Not implemented: Signature Verify (KMIP 1.2)
            // Not implemented: MAC (KMIP 1.2)
            // Not implemented: MAC Verify (KMIP 1.2)
            RequestPayload::RNGRetrieve(..) => Operation::RNGRetrieve,
            // Not implemented: RNG Seed (KMIP 1.2)
            // Not implemented: Hash (KMIP 1.2)
            // Not implemented: Create Split Key (KMIP 1.2)
            // Not implemented: Join Split Key (KMIP 1.2)
        }
    }

    pub fn protocol_version(&self) -> ProtocolVersion {
        match self {
            RequestPayload::Create(..)
            | RequestPayload::CreateKeyPair(..)
            | RequestPayload::Register(..)
            | RequestPayload::Locate(..)
            | RequestPayload::Get(..)
            | RequestPayload::GetAttributes(..)
            | RequestPayload::GetAttributeList(..)
            | RequestPayload::AddAttribute(..)
            | RequestPayload::ModifyAttribute(..)
            | RequestPayload::DeleteAttribute(..)
            | RequestPayload::Activate(..)
            | RequestPayload::Revoke(..)
            | RequestPayload::Destroy(..)
            | RequestPayload::Query(..)
            | RequestPayload::DiscoverVersions(..) => ProtocolVersion(ProtocolVersionMajor(1), ProtocolVersionMinor(0)),
            RequestPayload::Sign | RequestPayload::RNGRetrieve(..) => {
                ProtocolVersion(ProtocolVersionMajor(1), ProtocolVersionMinor(2))
            }
        }
    }
}

// KMIP spec 1.0 section 9.1.3.2.4 Wrapping Method Enumeration
// See: https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Ref241993348
#[derive(Clone, Copy, Debug, Serialize, Display, PartialEq, Eq)]
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
#[derive(Clone, Copy, Debug, Serialize, Display, PartialEq, Eq)]
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
