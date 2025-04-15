//! Rust types for sserializing KMIP requests.
use enum_display_derive::Display;
use serde_derive::{Deserialize, Serialize};
use std::fmt::Display;

use super::common::{
    ApplicationData, ApplicationNamespace, AttributeIndex, AttributeName, AttributeValue, CompromiseOccurrenceDate,
    CryptographicAlgorithm, CryptographicLength, CryptographicParameters, CryptographicUsageMask, Data, DataLength,
    KeyCompressionType, KeyFormatType, KeyMaterial, LinkType, LinkedObjectIdentifier, NameType, NameValue, ObjectType,
    Operation, RevocationMessage, RevocationReasonCode, UniqueBatchItemID, UniqueIdentifier,
};

///  See KMIP 1.0 section 2.1.1 [Attribute](https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581155).
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename = "0x420008(0x42000A,0x420009,0x42000B)")]
pub struct Attribute(
    pub AttributeName,
    #[serde(skip_serializing_if = "Option::is_none")] pub Option<AttributeIndex>,
    pub AttributeValue,
);

/// Helper functions to simplifying including KMIP TemplateAttributes in requests.
///
/// The set of possible attributes and their textual names are specified by the KMIP 1.0 spec in Section 3 Attributes.
/// We offer various Attribute constructor functions that avoid the need for the caller to couple the right
/// AttributeName and AttributeValue pairs together and to use the correct AttributeName text value and instead just Do
/// The Right Thing for them.
impl Attribute {
    ///  See KMIP 1.0 section 3.1 Unique Identifier.
    #[allow(non_snake_case)]
    pub fn UniqueIdentifier(value: String) -> Self {
        Attribute(
            AttributeName("Unique Identifier".into()),
            Option::<AttributeIndex>::None,
            AttributeValue::TextString(value),
        )
    }

    ///  See KMIP 1.0 section 3.2 Name.
    #[allow(non_snake_case)]
    pub fn Name(value: String) -> Self {
        Attribute(
            AttributeName("Name".into()),
            Option::<AttributeIndex>::None,
            AttributeValue::Name(NameValue(value), NameType::UninterpretedTextString),
        )
    }

    ///  See KMIP 1.0 section 3.2 Name.
    #[allow(non_snake_case)]
    pub fn URI(value: String) -> Self {
        Attribute(
            AttributeName("Name".into()),
            Option::<AttributeIndex>::None,
            AttributeValue::Name(NameValue(value), NameType::URI),
        )
    }

    ///  See KMIP 1.0 section 3.3 Object Type.
    #[allow(non_snake_case)]
    pub fn ObjectType(value: ObjectType) -> Self {
        Attribute(
            AttributeName("Object Type".into()),
            Option::<AttributeIndex>::None,
            AttributeValue::ObjectType(value),
        )
    }

    ///  See KMIP 1.0 section 3.4 Cryptographic Algorithm.
    #[allow(non_snake_case)]
    pub fn CryptographicAlgorithm(value: CryptographicAlgorithm) -> Self {
        Attribute(
            AttributeName("Cryptographic Algorithm".into()),
            Option::<AttributeIndex>::None,
            AttributeValue::CryptographicAlgorithm(value),
        )
    }

    ///  See KMIP 1.0 section 3.5 Cryptographic Length.
    #[allow(non_snake_case)]
    pub fn CryptographicLength(value: i32) -> Self {
        Attribute(
            AttributeName("Cryptographic Length".into()),
            Option::<AttributeIndex>::None,
            AttributeValue::Integer(value),
        )
    }

    ///  See KMIP 1.0 section 3.6 Cryptographic Parameters.
    #[allow(non_snake_case)]
    pub fn CryptographicParameters(cryptographic_parameters: CryptographicParameters) -> Self {
        Attribute(
            AttributeName("Cryptographic Parameters".into()),
            Option::<AttributeIndex>::None,
            cryptographic_parameters.into(),
        )
    }

    ///  See KMIP 1.0 section 3.13 Operation Policy Name.
    #[allow(non_snake_case)]
    pub fn OperationPolicyName(value: String) -> Self {
        Attribute(
            AttributeName("Operation Policy Name".into()),
            Option::<AttributeIndex>::None,
            AttributeValue::TextString(value),
        )
    }

    ///  See KMIP 1.0 section 3.14 Cryptographic Usage Mask.
    #[allow(non_snake_case)]
    pub fn CryptographicUsageMask(value: CryptographicUsageMask) -> Self {
        Attribute(
            AttributeName("Cryptographic Usage Mask".into()),
            Option::<AttributeIndex>::None,
            AttributeValue::Integer(value as i32),
        )
    }

    ///  See KMIP 1.0 section 3.24 Activation Date.
    #[allow(non_snake_case)]
    pub fn ActivationDate(value: u64) -> Self {
        Attribute(
            AttributeName("Activation Date".into()),
            Option::<AttributeIndex>::None,
            AttributeValue::DateTime(value),
        )
    }

    ///  See KMIP 1.0 section 3.28 Object Group.
    #[allow(non_snake_case)]
    pub fn ObjectGroup(value: String) -> Self {
        Attribute(
            AttributeName("Object Group".into()),
            Option::<AttributeIndex>::None,
            AttributeValue::TextString(value),
        )
    }

    ///  See KMIP 1.0 section 3.29 Link.
    #[allow(non_snake_case)]
    pub fn Link(link_type: LinkType, linked_object_identifier: LinkedObjectIdentifier) -> Self {
        Attribute(
            AttributeName("Link".into()),
            Option::<AttributeIndex>::None,
            AttributeValue::Link(link_type, linked_object_identifier),
        )
    }

    ///  See KMIP 1.0 section 3.30 Application Specific Information.
    #[allow(non_snake_case)]
    pub fn ApplicationSpecificInformation(
        application_namespace: ApplicationNamespace,
        application_data: ApplicationData,
    ) -> Self {
        Attribute(
            AttributeName("Application Specific Information".into()),
            Option::<AttributeIndex>::None,
            AttributeValue::ApplicationSpecificInformation(application_namespace, application_data),
        )
    }

    ///  See KMIP 1.0 section 3.31 Contact Information.
    #[allow(non_snake_case)]
    pub fn ContactInformation(value: String) -> Self {
        Attribute(
            AttributeName("Contact Information".into()),
            Option::<AttributeIndex>::None,
            AttributeValue::ContactInformation(value),
        )
    }
}

macro_rules! impl_template_attribute_flavour {
    ($RustType:ident, $TtlvTag:literal) => {
        ///  See KMIP 1.0 section 2.1.8 [Template-Attribute Structures](https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581162).
        #[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
        #[serde(rename = "$TtlvTag(0x420053,0x420008)")]
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

impl_template_attribute_flavour!(TemplateAttribute, 0x420091);
impl_template_attribute_flavour!(CommonTemplateAttribute, 0x42001F);
impl_template_attribute_flavour!(PrivateKeyTemplateAttribute, 0x420065);
impl_template_attribute_flavour!(PublicKeyTemplateAttribute, 0x42006E);

///  See KMIP 1.0 section 2.1.2 [Credential](https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581156).
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename = "0x420023(0x420024,0x420025)")]
pub struct Credential(pub CredentialType, pub CredentialValue);

///  See KMIP 1.0 section 2.1.2 [Credential](https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581156).
#[derive(Clone, Copy, Debug, Deserialize, Serialize, Display, PartialEq, Eq)]
#[serde(rename = "0x420024")]
#[non_exhaustive]
pub enum CredentialType {
    #[serde(rename = "0x00000001")]
    UsernameAndPassword,
}

///  See KMIP 1.0 section 2.1.2 [Credential](https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581156).
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename = "0x420025")]
#[non_exhaustive]
pub enum CredentialValue {
    UsernameAndPassword(
        Username,
        #[serde(skip_serializing_if = "Option::is_none")] Option<Password>,
    ),
}

///  See KMIP 1.0 section 2.1.2 [Credential](https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581156).
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename = "Transparent:0x420099")]
pub struct Username(pub String);

///  See KMIP 1.0 section 2.1.2 [Credential](https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581156).
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename = "Transparent:0x4200A1")]
pub struct Password(pub String);

///  See KMIP 1.0 section 2.1.3 [Key Block](https://docs.oasis-open.org/kmip/spec/v1.2/os/kmip-spec-v1.2-os.html#_Toc409613459).
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename = "0x420040(0x420041,0x420045,0x420028,0x42002A,0x420046)")]
pub struct KeyBlock(
    pub KeyFormatType,
    #[serde(skip_serializing_if = "Option::is_none")] pub Option<KeyCompressionType>,
    #[serde(skip_serializing_if = "Option::is_none")] pub Option<KeyValue>,
    #[serde(skip_serializing_if = "Option::is_none")] pub Option<CryptographicAlgorithm>,
    #[serde(skip_serializing_if = "Option::is_none")] pub Option<CryptographicLength>,
    #[serde(skip_serializing_if = "Option::is_none")] pub Option<KeyWrappingData>,
);

///  See KMIP 1.0 section 2.1.4 [Key Value](https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581158).
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename = "0x420045(0x420043,0x420008)")]
pub struct KeyValue(
    pub KeyMaterial,
    #[serde(skip_serializing_if = "Option::is_none")] pub Option<Vec<Attribute>>,
);

///  See KMIP 1.0 section 2.1.5 [Key Wrapping Data](https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581159).
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename = "0x420046(0x420036,0x42004E,0x42004D,0x42003D,0x420008)")]
pub struct KeyWrappingData(
    pub WrappingMethod,
    #[serde(skip_serializing_if = "Option::is_none")] pub Option<EncryptionKeyInformation>,
    #[serde(skip_serializing_if = "Option::is_none")] pub Option<MACOrSignatureKeyInformation>,
    #[serde(skip_serializing_if = "Option::is_none")] pub Option<MACOrSignature>,
    #[serde(skip_serializing_if = "Option::is_none")] pub Option<IVOrCounterOrNonce>,
    #[serde(skip_serializing_if = "Option::is_none")] pub Option<Vec<Attribute>>,
);

///  See KMIP 1.0 section 2.1.5 [Key Wrapping Data](https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581159).
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename = "Transparent:0x42004D")]
pub struct MACOrSignature(#[serde(with = "serde_bytes")] Vec<u8>);

///  See KMIP 1.0 section 2.1.5 [Key Wrapping Data](https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581159).
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename = "Transparent:0x42003D")]
pub struct IVOrCounterOrNonce(#[serde(with = "serde_bytes")] Vec<u8>);

///  See KMIP 1.0 section 2.1.5 [Key Wrapping Data](https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581159).
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename = "0x420036(0x420094,0x42002B)")]
pub struct EncryptionKeyInformation(
    pub UniqueIdentifier,
    #[serde(skip_serializing_if = "Option::is_none")] pub Option<CryptographicParameters>,
);

///  See KMIP 1.0 section 2.1.5 [Key Wrapping Data](https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581159).
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename = "0x42004E(0x420094,0x420028)")]
pub struct MACOrSignatureKeyInformation(
    pub UniqueIdentifier,
    #[serde(skip_serializing_if = "Option::is_none")] pub Option<CryptographicParameters>,
);

///  See KMIP 1.0 section 2.1.6 [Key Wrapping Specification](https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581160).
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename = "Transparent:0x420047(0x42009E,0x420036,0x42004E,0x420008)")]
pub struct KeyWrappingSpecification(
    pub WrappingMethod,
    #[serde(skip_serializing_if = "Option::is_none")] pub Option<EncryptionKeyInformation>,
    #[serde(skip_serializing_if = "Option::is_none")] pub Option<MACOrSignatureKeyInformation>,
    #[serde(skip_serializing_if = "Option::is_none")] pub Option<Vec<Attribute>>,
);

///  See KMIP 1.0 section 2.2 [Managed Objects](https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581163).
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(untagged)]
#[non_exhaustive]
pub enum ManagedObject {
    // Certificate(Certificate),
    // Not implemented
    SymmetricKey(SymmetricKey),

    PublicKey(PublicKey),

    PrivateKey(PrivateKey),

    // SplitKey(SplitKey),
    // Not implemented
    Template(Template),
    // SecretData(SecretData),
    // Not implemented

    // OpaqueObject(OpaqueObject),
    // Not implemented
}

///  See KMIP 1.0 section 2.2.2 [Symmetric Key](https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581165).
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename = "0x42008F")]
pub struct SymmetricKey(pub KeyBlock);

///  See KMIP 1.0 section 2.2.3 [Public Key](https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581166).
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename = "0x42006D")]
pub struct PublicKey(pub KeyBlock);

///  See KMIP 1.0 section 2.2.4 [Private Key](https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581167).
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename = "0x420064")]
pub struct PrivateKey(pub KeyBlock);

///  See KMIP 1.0 section 2.2.6 [Template](https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581169).
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename = "0x420090")]
pub struct Template(pub Vec<Attribute>);

///  See KMIP 1.0 section 3.2 [Name](https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581174).
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename = "0x420053(0x420055,0x420054)")]
pub struct Name(pub NameValue, pub NameType);

impl std::fmt::Display for Name {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_fmt(format_args!("{}", self.0))
    }
}

///  See KMIP 1.0 section 3.26 [Revocation Reason](https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581200).
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename = "0x420081(0x420082,0x420080)")]
pub struct RevocationReason(
    pub RevocationReasonCode,
    #[serde(skip_serializing_if = "Option::is_none")] pub Option<RevocationMessage>,
);

///  See KMIP 1.0 section 6.1 [Protocol Version](https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581239).
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename = "0x420069(0x42006A,0x42006B)")]
pub struct ProtocolVersion(pub ProtocolVersionMajor, pub ProtocolVersionMinor);

///  See KMIP 1.0 section 6.1 [Protocol Version](https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581239).
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename = "Transparent:0x42006A")]
pub struct ProtocolVersionMajor(pub i32);

///  See KMIP 1.0 section 6.1 [Protocol Version](https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581239).
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename = "Transparent:0x42006B")]
pub struct ProtocolVersionMinor(pub i32);

///  See KMIP 1.0 section 6.3 [Maximum Response Size](https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581241).
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename = "Transparent:0x420050")]
pub struct MaximumResponseSize(pub i32);

///  See KMIP 1.0 section 6.6 [Authentication](https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581244).
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename = "0x42000C")]
pub struct Authentication(pub Credential);

///  See KMIP 1.0 section 6.14 [Batch Count](https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581252).
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename = "Transparent:0x42000D")]
pub struct BatchCount(pub i32);

///  See KMIP 1.0 section 6.15 [Batch Item](https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581253).
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename = "0x42000F(0x42005C,0x420093,0x420079)")]
pub struct BatchItem(
    pub Operation, // TODO: set this somehow automatically to RequestPayload::operation()
    #[serde(skip_serializing_if = "Option::is_none")] pub Option<UniqueBatchItemID>,
    pub RequestPayload,
);

impl BatchItem {
    pub fn operation(&self) -> &Operation {
        &self.0
    }

    pub fn unique_batch_item_id(&self) -> Option<&UniqueBatchItemID> {
        self.1.as_ref()
    }

    pub fn request_payload(&self) -> &RequestPayload {
        &self.2
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename = "0x420078(0x420077,0x42000F)")]
pub struct RequestMessage(pub RequestHeader, pub Vec<BatchItem>);

impl RequestMessage {
    pub fn header(&self) -> &RequestHeader {
        &self.0
    }

    pub fn batch_items(&self) -> &[BatchItem] {
        &self.1
    }
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename = "0x420077(0x420069,0x420050,0x42000C,0x42000D)")]
pub struct RequestHeader(
    pub ProtocolVersion,
    #[serde(skip_serializing_if = "Option::is_none")] pub Option<MaximumResponseSize>,
    #[serde(skip_serializing_if = "Option::is_none")] pub Option<Authentication>,
    pub BatchCount,
);

impl RequestHeader {
    pub fn protocol_version(&self) -> &ProtocolVersion {
        &self.0
    }

    pub fn max_response_size(&self) -> Option<&MaximumResponseSize> {
        self.1.as_ref()
    }

    pub fn authentication(&self) -> Option<&Authentication> {
        self.2.as_ref()
    }

    pub fn batch_count(&self) -> &BatchCount {
        &self.3
    }
}
#[serde(rename = "WithTtlHeader:0x420079")]
#[non_exhaustive]
#[allow(clippy::large_enum_variant)]
pub enum RequestPayload {
    #[serde(rename = "if 0x42005C==0x00000001")]
    Create(ObjectType, TemplateAttribute),

    #[serde(rename = "if 0x42005C==0x00000002")]
    CreateKeyPair(
        #[serde(skip_serializing_if = "Option::is_none")] Option<CommonTemplateAttribute>,
        #[serde(skip_serializing_if = "Option::is_none")] Option<PrivateKeyTemplateAttribute>,
        #[serde(skip_serializing_if = "Option::is_none")] Option<PublicKeyTemplateAttribute>,
    ),

    #[serde(rename = "if 0x42005C==0x00000003")]
    Register(
        ObjectType,
        TemplateAttribute,
        #[serde(skip_serializing_if = "Option::is_none")] Option<ManagedObject>,
    ),

    #[serde(rename = "if 0x42005C==0x00000008")]
    Locate(Vec<Attribute>), // TODO: Add MaximumItems and StorageStatusMask optional request payload fields

    #[serde(rename = "if 0x42005C==0x0000000A")]
    Get(
        #[serde(skip_serializing_if = "Option::is_none")] Option<UniqueIdentifier>,
        #[serde(skip_serializing_if = "Option::is_none")] Option<KeyFormatType>,
        #[serde(skip_serializing_if = "Option::is_none")] Option<KeyCompressionType>,
        #[serde(skip_serializing_if = "Option::is_none")] Option<KeyWrappingSpecification>,
    ),

    #[serde(rename = "if 0x42005C==0x0000000B")]
    GetAttributes(
        #[serde(skip_serializing_if = "Option::is_none")] Option<UniqueIdentifier>,
        #[serde(skip_serializing_if = "Option::is_none")] Option<Vec<AttributeName>>,
    ),

    #[serde(rename = "if 0x42005C==0x0000000C")]
    GetAttributeList(#[serde(skip_serializing_if = "Option::is_none")] Option<UniqueIdentifier>),

    #[serde(rename = "if 0x42005C==0x0000000D")]
    AddAttribute(
        #[serde(skip_serializing_if = "Option::is_none")] Option<UniqueIdentifier>,
        Attribute,
    ),

    #[serde(rename = "if 0x42005C==0x0000000E")]
    ModifyAttribute(
        #[serde(skip_serializing_if = "Option::is_none")] Option<UniqueIdentifier>,
        Attribute,
    ),

    #[serde(rename = "if 0x42005C==0x0000000F")]
    DeleteAttribute(
        #[serde(skip_serializing_if = "Option::is_none")] Option<UniqueIdentifier>,
        AttributeName,
        #[serde(skip_serializing_if = "Option::is_none")] Option<AttributeIndex>,
    ),

    #[serde(rename = "if 0x42005C==0x00000012")]
    Activate(#[serde(skip_serializing_if = "Option::is_none")] Option<UniqueIdentifier>),

    #[serde(rename = "if 0x42005C==0x00000013")]
    Revoke(
        #[serde(skip_serializing_if = "Option::is_none")] Option<UniqueIdentifier>,
        RevocationReason,
        #[serde(skip_serializing_if = "Option::is_none")] Option<CompromiseOccurrenceDate>,
    ),

    #[serde(rename = "if 0x42005C==0x00000014")]
    Destroy(#[serde(skip_serializing_if = "Option::is_none")] Option<UniqueIdentifier>),

    #[serde(rename = "if 0x42005C==0x00000018")]
    Query(Vec<QueryFunction>),

    #[serde(rename = "if 0x42005C==0x0000001E")]
    DiscoverVersions(Vec<ProtocolVersion>),

    #[serde(rename = "if 0x42005C==0x00000021")]
    Sign(
        #[serde(skip_serializing_if = "Option::is_none")] Option<UniqueIdentifier>,
        #[serde(skip_serializing_if = "Option::is_none")] Option<CryptographicParameters>,
        Data,
    ),

    #[serde(rename = "if 0x42005C==0x00000025")]
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
            RequestPayload::Sign(..) => Operation::Sign,
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
            | RequestPayload::Destroy(..) => {
                // These KMIP operations are defined in the KMIP 1.0 specification
                ProtocolVersion(ProtocolVersionMajor(1), ProtocolVersionMinor(0))
            }
            RequestPayload::DiscoverVersions(..) => {
                // These KMIP operations are defined in the KMIP 1.1 specification
                ProtocolVersion(ProtocolVersionMajor(1), ProtocolVersionMinor(1))
            }
            RequestPayload::Sign(..) | RequestPayload::RNGRetrieve(..) => {
                // These KMIP operations are defined in the KMIP 1.2 specification
                ProtocolVersion(ProtocolVersionMajor(1), ProtocolVersionMinor(2))
            }
            RequestPayload::Query(..) => {
                // TODO: Although query is defined in the KMIP 1.0 specification, KMIP servers that support KMIP >1.0
                // are required by the specification to "support backward compatibility with versions of the protocol
                // with the same major version". A KMIP 1.2 server cannot respond to a Query request with KMIP tag
                // numbers representing KMIP Operations that were only defined in a KMIP specification >1.0. Presumably
                // therefore we must pass the highest version number that both we and the server support. Currently
                // this is just dumb and passes the highest version number that we support, we should actually base
                // it on the result of a previous attempt to use the KMIP 1.1 Discover Versions request.
                ProtocolVersion(ProtocolVersionMajor(1), ProtocolVersionMinor(2))
            }
        }
    }
}

///  See KMIP 1.0 section 9.1.3.2.4 [Wrapping Method Enumeration](https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Ref241993348).
#[derive(Clone, Copy, Debug, Deserialize, Serialize, Display, PartialEq, Eq)]
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

///  See KMIP 1.0 section 9.1.3.2.23 [Query Function Enumeration](https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Ref242030554).
#[derive(Clone, Copy, Debug, Deserialize, Serialize, Display, PartialEq, Eq)]
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
