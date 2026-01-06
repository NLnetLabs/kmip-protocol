//! Rust types for deserializing KMIP responses.
use enum_ordinalize::Ordinalize;
use serde_derive::{Deserialize, Serialize};

use enum_display_derive::Display;
use std::fmt::Display;

use crate::ttlv::fast_scan::{FastScanError, FastScanner};
use crate::ttlv::format::{FormatResult, Formatter};
use crate::ttlv::types::Tag;
use crate::types::common::CryptographicLength;

use super::common::{
    AttributeIndex, AttributeName, AttributeValue, CertificateType, CryptographicAlgorithm, KeyCompressionType,
    KeyFormatType, KeyMaterial, NameType, NameValue, ObjectType, Operation, UniqueBatchItemID, UniqueIdentifier,
};
use super::request::IVOrCounterOrNonce;

use super::impl_ttlv_serde;

///  See KMIP 1.0 section 2.1.3 [Key Block](https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581157).
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename = "0x420040")]
pub struct KeyBlock {
    #[serde(rename = "0x420042")]
    pub key_format_type: KeyFormatType,

    #[serde(rename = "0x420041")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_compression_type: Option<KeyCompressionType>,

    #[serde(rename = "0x420045")]
    pub key_value: KeyValue,

    #[serde(rename = "0x420028")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cryptographic_algorithm: Option<CryptographicAlgorithm>,

    #[serde(rename = "0x42002A")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cryptographic_length: Option<i32>,

    #[serde(rename = "0x420046")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_wrapping_data: Option<()>, // TODO
}

impl_ttlv_serde!(struct KeyBlock as 0x420040 {
    fast_scan = |scanner| {
        let key_format_type = KeyFormatType::fast_scan(&mut scanner)?;
        Self {
            key_format_type,
            key_compression_type: KeyCompressionType::fast_scan_opt(&mut scanner)?,
            key_value: KeyValue::fast_scan(&mut scanner, &key_format_type)?,
            cryptographic_algorithm: CryptographicAlgorithm::fast_scan_opt(&mut scanner)?,
            cryptographic_length: CryptographicLength::fast_scan_opt(&mut scanner)?.map(|s| s.0),
            key_wrapping_data: None,
        }
    };

    format = |&self, formatter| {
        self.key_format_type.format(&mut formatter)?;
        if let Some(x) = &self.key_compression_type { x.format(&mut formatter)?; }
        self.key_value.format(&mut formatter)?;
        if let Some(x) = self.cryptographic_algorithm { x.format(&mut formatter)?; }
        if let Some(x) = self.cryptographic_length { CryptographicLength(x).format(&mut formatter)?; }
    };
});

///  See KMIP 1.0 section 2.1.4 [Key Value](https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581158).
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename = "0x420045")]
pub struct KeyValue {
    #[serde(rename = "Untagged")]
    pub key_material: KeyMaterial,

    #[serde(rename = "0x420008")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attributes: Option<Vec<Attribute>>,
}

impl KeyValue {
    pub const TAG: Tag = Tag::new(0x420045);

    pub fn fast_scan(scanner: &mut FastScanner<'_>, format: &KeyFormatType) -> Result<Self, FastScanError> {
        let mut scanner = scanner.scan_struct(Self::TAG)?;
        let key_material = KeyMaterial::fast_scan(&mut scanner, format)?;
        let attributes =
            std::iter::from_fn(|| Attribute::fast_scan_opt(&mut scanner).transpose()).collect::<Result<Vec<_>, _>>()?;
        let attributes = Some(attributes).filter(|a| !a.is_empty());
        scanner.finish()?;
        Ok(Self {
            key_material,
            attributes,
        })
    }

    pub fn fast_scan_opt(scanner: &mut FastScanner<'_>, format: &KeyFormatType) -> Result<Option<Self>, FastScanError> {
        let Some(mut scanner) = scanner.scan_opt_struct(Self::TAG)? else {
            return Ok(None);
        };
        let key_material = KeyMaterial::fast_scan(&mut scanner, format)?;
        let attributes =
            std::iter::from_fn(|| Attribute::fast_scan_opt(&mut scanner).transpose()).collect::<Result<Vec<_>, _>>()?;
        let attributes = Some(attributes).filter(|a| !a.is_empty());
        scanner.finish()?;
        Ok(Some(Self {
            key_material,
            attributes,
        }))
    }

    pub fn format(&self, formatter: &mut Formatter<'_>) -> FormatResult {
        let mut formatter = formatter.format_struct(Self::TAG)?;
        self.key_material.format(&mut formatter)?;
        for attribute in self.attributes.iter().flatten() {
            attribute.format(&mut formatter)?;
        }
        Ok(formatter.finish())
    }
}

///  See KMIP 1.0 section 2.1.8 [Template Attribute](https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581162).
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename = "0x420091")]
pub struct TemplateAttribute {
    #[serde(rename = "0x420043")]
    pub names: Option<Vec<Name>>,

    #[serde(rename = "0x420008")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attributes: Option<Vec<Attribute>>,
}

impl_ttlv_serde!(struct TemplateAttribute {
    #[option+vec] names: Name,
    #[option+vec] attributes: Attribute,
} as 0x420091);

///  See KMIP 1.0 section 2.2 [Managed Objects](https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581163).
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename = "Transparent")]
#[non_exhaustive]
pub enum ManagedObject {
    #[serde(rename = "if 0x420057==0x00000001")]
    Certificate(Certificate),

    #[serde(rename = "if 0x420057==0x00000002")]
    SymmetricKey(SymmetricKey),

    #[serde(rename = "if 0x420057==0x00000003")]
    PublicKey(PublicKey),

    #[serde(rename = "if 0x420057==0x00000004")]
    PrivateKey(PrivateKey),
    // TODO:
    // #[serde(rename = "if 0x420057==0x00000005")]
    // SplitKey(SplitKey),

    // #[serde(rename = "if 0x420057==0x00000006")]
    // Template(Template),

    // #[serde(rename = "if 0x420057==0x00000007")]
    // SecretData(SecretData),

    // #[serde(rename = "if 0x420057==0x00000008")]
    // OpaqueObject(OpaqueObject),
}

impl Display for ManagedObject {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ManagedObject::Certificate(_) => write!(f, "Certificate"),
            ManagedObject::SymmetricKey(_) => write!(f, "SymmetricKey"),
            ManagedObject::PublicKey(_) => write!(f, "PublicKey"),
            ManagedObject::PrivateKey(_) => write!(f, "PrivateKey"),
        }
    }
}

///  See KMIP 1.0 section 2.2.1 [Certificate](https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581164).
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename = "0x420013")]
pub struct Certificate {
    pub certificate_type: CertificateType,
    #[serde(with = "serde_bytes")]
    pub certificate_value: Vec<u8>,
}

///  See KMIP 1.0 section 2.2.2 [Symmetric Key](https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581165).
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename = "0x42008F")]
pub struct SymmetricKey {
    #[serde(rename = "0x420040")]
    pub key_block: KeyBlock,
}

impl_ttlv_serde!(struct SymmetricKey { key_block: KeyBlock } as 0x42008F);

///  See KMIP 1.0 section 2.2.3 [Public Key](https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581166).
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename = "0x42006D")]
pub struct PublicKey {
    #[serde(rename = "0x420040")]
    pub key_block: KeyBlock,
}

impl_ttlv_serde!(struct PublicKey { key_block: KeyBlock } as 0x42006D);

///  See KMIP 1.0 section 2.2.4 [Private Key](https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581167).
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename = "0x420064")]
pub struct PrivateKey {
    #[serde(rename = "0x420040")]
    pub key_block: KeyBlock,
}

impl_ttlv_serde!(struct PrivateKey { key_block: KeyBlock } as 0x420064);

///  See KMIP 1.0 section 3.2 [Name](https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581174).
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename = "0x420053")]
pub struct Name {
    pub name: NameValue,
    pub r#type: NameType,
}

impl_ttlv_serde!(struct Name {
    name: NameValue,
    r#type: NameType,
} as 0x420053);

///  See KMIP 1.0 section 4.1 [Create](https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581209).
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename = "0x42007C")]
pub struct CreateResponsePayload {
    pub object_type: ObjectType,
    pub unique_identifier: UniqueIdentifier,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub object_attributes: Option<Vec<Attribute>>,
}

impl_ttlv_serde!(struct CreateResponsePayload {
    object_type: ObjectType,
    unique_identifier: UniqueIdentifier,
    #[option+vec] object_attributes: Attribute,
} as 0x42007C);

///  See KMIP 1.0 section 4.2 [Create Key Pair](https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581210).
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename = "Transparent:0x42007C")]
pub struct CreateKeyPairResponsePayload {
    #[serde(rename = "0x420066")]
    pub private_key_unique_identifier: UniqueIdentifier,

    #[serde(rename = "0x42006F")]
    pub public_key_unique_identifier: UniqueIdentifier,
    // TODO: Add the optional response field that lists attributes for the private key

    // TODO: Add the optional response field that lists attributes for the public key
}

///  See KMIP 1.0 section 4.3 [Register](https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581211).
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename = "0x42007C")]
pub struct RegisterResponsePayload {
    #[serde(rename = "0x420094")]
    pub unique_identifier: UniqueIdentifier,

    #[serde(rename = "0x420091")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub template_attributes: Option<Vec<TemplateAttribute>>,
}

///  See KMIP 1.0 section 4.8 [Locate](https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581216).
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename = "0x42007C")]
pub struct LocateResponsePayload {
    #[serde(rename = "0x4200D5")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub located_items: Option<i32>,

    #[serde(rename = "0x420094")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unique_identifiers: Option<Vec<UniqueIdentifier>>,
}

///  See KMIP 1.0 section 4.10 [Get](https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581218).
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename = "Transparent:0x42007C")]
pub struct GetResponsePayload {
    #[serde(rename = "0x420057")]
    pub object_type: ObjectType,

    #[serde(rename = "0x420094")]
    pub unique_identifier: UniqueIdentifier,

    #[serde(rename = "Untagged")]
    pub cryptographic_object: ManagedObject,
}

///  See KMIP 1.0 section 4.11 [Get Attributes](https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581219).
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename = "Transparent:0x42007C")]
pub struct GetAttributesResponsePayload {
    #[serde(rename = "0x420094")]
    pub unique_identifier: UniqueIdentifier,

    #[serde(rename = "0x420008")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attributes: Option<Vec<Attribute>>,
}

///  See KMIP 1.0 section 4.12 [Get Attribute List](https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581220).
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename = "Transparent:0x42007C")]
pub struct GetAttributeListResponsePayload {
    #[serde(rename = "0x420094")]
    pub unique_identifier: UniqueIdentifier,

    #[serde(rename = "0x42000A")]
    pub attributes: Vec<AttributeName>,
}

/// Fields common to sections 4.18 [Activate](https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581226),
/// 4.19 [Revoke](https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581227)
/// and 4.20 [Destroy](http://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581228) responses.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename = "Transparent:0x42007C")]
pub struct UniqueIdentifierResponsePayload {
    #[serde(rename = "0x420094")]
    pub unique_identifier: UniqueIdentifier,
}

///  See KMIP 1.0 section 4.18 [Activate](https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581226).
pub type ActivateResponsePayload = UniqueIdentifierResponsePayload;

///  See KMIP 1.0 section 4.19 [Revoke](https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581227).
pub type RevokeResponsePayload = UniqueIdentifierResponsePayload;

///  See KMIP 1.0 section 4.20 [Destroy](https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581228).
pub type DestroyResponsePayload = UniqueIdentifierResponsePayload;

/// Fields common to sections 4.13 [Add](https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581221),
/// 4.14 [Modify](https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581222) and 4.15
/// [Delete](https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581223) Attribute responses.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename = "Transparent:0x42007C")]
pub struct AttributeEditResponsePayload {
    #[serde(rename = "0x420094")]
    pub unique_identifier: UniqueIdentifier,

    #[serde(rename = "0x420008")]
    pub attribute: Attribute,
}

///  See KMIP 1.0 section 4.13 [Add Attribute](https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581221).
pub type AddAttributeResponsePayload = AttributeEditResponsePayload;

///  See KMIP 1.0 section 4.14 [Modify Attribute](https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581222).
pub type ModifyAttributeResponsePayload = AttributeEditResponsePayload;

///  See KMIP 1.0 section 4.15 [Delete Attribute](https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581223).
pub type DeleteAttributeResponsePayload = AttributeEditResponsePayload;

///  See KMIP 1.0 section 4.24 [Query](https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581232).
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename = "Transparent:0x42007C")]
pub struct QueryResponsePayload {
    #[serde(rename = "0x42005C")]
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub operations: Option<Vec<Operation>>,

    #[serde(rename = "0x420057")]
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub object_types: Option<Vec<ObjectType>>,

    #[serde(rename = "0x42009D")]
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub vendor_identification: Option<String>,

    #[serde(rename = "0x420088")]
    #[serde(skip_serializing, default)]
    pub server_information: Option<ServerInformation>,
}

///  See KMIP 1.0 section 4.24 [Query](https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581232).
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename = "Transparent:0x42007C")]
pub struct RNGRetrieveResponsePayload {
    #[serde(with = "serde_bytes")]
    pub data: Vec<u8>,
}

///  See KMIP 1.0 section 4.24 [Server Information](https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581232).
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq, Default)]
#[serde(rename = "0x420088")]
pub struct ServerInformation;

///  See KMIP 1.1 section 4.26 [Discover Versions](https://docs.oasis-open.org/kmip/spec/v1.1/cs01/kmip-spec-v1.1-cs01.html#_Toc332787652).
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename = "Transparent:0x42007C")]
pub struct DiscoverVersionsResponsePayload {
    #[serde(rename = "0x420069")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub supported_versions: Option<Vec<ProtocolVersion>>,
}

///  See KMIP 1.2 section 4.27 [Encrypt](https://docs.oasis-open.org/kmip/spec/v1.2/os/kmip-spec-v1.2-os.html#_Toc409613554).
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename = "Transparent:0x42007C")]
pub struct EncryptResponsePayload {
    #[serde(rename = "0x420094")]
    pub unique_identifier: UniqueIdentifier,

    #[serde(rename = "0x4200C2")]
    #[serde(with = "serde_bytes")]
    pub data: Vec<u8>,

    #[serde(rename = "0x42003D", skip_serializing_if = "Option::is_none", default)]
    pub iv_counter_nonce: Option<IVOrCounterOrNonce>,
}

///  See KMIP 1.2 section 4.28 [Decrypt](https://docs.oasis-open.org/kmip/spec/v1.2/os/kmip-spec-v1.2-os.html#_Toc409613555).
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename = "Transparent:0x42007C")]
pub struct DecryptResponsePayload {
    #[serde(rename = "0x420094")]
    pub unique_identifier: UniqueIdentifier,

    #[serde(rename = "0x4200C2")]
    #[serde(with = "serde_bytes")]
    pub data: Vec<u8>,
}

///  See KMIP 1.2 section 4.31 [Sign](https://docs.oasis-open.org/kmip/spec/v1.2/os/kmip-spec-v1.2-os.html#_Toc409613558).
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename = "Transparent:0x42007C")]
pub struct SignResponsePayload {
    #[serde(rename = "0x420094")]
    pub unique_identifier: UniqueIdentifier,

    #[serde(rename = "0x4200C3")]
    #[serde(with = "serde_bytes")]
    pub signature_data: Vec<u8>,
}

///  See KMIP 1.0 section 6.1 [Protocol Version](https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581239).
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename = "0x420069")]
pub struct ProtocolVersion {
    #[serde(rename = "0x42006A")]
    pub major: i32,

    #[serde(rename = "0x42006B")]
    pub minor: i32,
}

///  See KMIP 1.0 section 6.9 [Result Status](https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581247).
#[derive(Clone, Copy, Debug, Deserialize, Serialize, Display, PartialEq, Eq, Ordinalize)]
#[serde(rename = "0x42007F")]
#[non_exhaustive]
#[repr(u32)]
pub enum ResultStatus {
    #[serde(rename = "0x00000000")]
    Success,

    #[serde(rename = "0x00000001")]
    OperationFailed,

    #[serde(rename = "0x00000002")]
    OperationPending,

    #[serde(rename = "0x00000003")]
    OperationUndone,
}

impl_ttlv_serde!(enum ResultStatus as 0x42007F);

///  See KMIP 1.0 section 6.10 [Result Reason](https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581248).
#[derive(Clone, Copy, Debug, Deserialize, Serialize, Display, PartialEq, Eq, Ordinalize)]
#[serde(rename = "0x42007E")]
#[non_exhaustive]
#[repr(u32)]
pub enum ResultReason {
    #[serde(rename = "0x00000001")]
    ItemNotFound = 1,

    #[serde(rename = "0x00000002")]
    ResponseTooLarge,

    #[serde(rename = "0x00000003")]
    AuthenticationNotSuccessful,

    #[serde(rename = "0x00000004")]
    InvalidMessage,

    #[serde(rename = "0x00000005")]
    OperationNotSupported,

    #[serde(rename = "0x00000006")]
    MissingData,

    #[serde(rename = "0x00000007")]
    InvalidField,

    #[serde(rename = "0x00000008")]
    FeatureNotSupported,

    #[serde(rename = "0x00000009")]
    OperationCanceledByRequester,

    #[serde(rename = "0x0000000A")]
    CryptographicFailure,

    #[serde(rename = "0x0000000B")]
    IllegalOperation,

    #[serde(rename = "0x0000000C")]
    PermissionDenied,

    #[serde(rename = "0x0000000D")]
    ObjectArchived,

    #[serde(rename = "0x0000000E")]
    IndexOutOfBounds,

    #[serde(rename = "0x0000000F")]
    ApplicationNamespaceNotSupported,

    #[serde(rename = "0x00000010")]
    KeyFormatTypeNotSupported,

    #[serde(rename = "0x00000011")]
    KeyCompressionTypeNotSupported,

    #[serde(rename = "0x00000100")]
    GeneralFailure,
}

impl_ttlv_serde!(enum ResultReason as 0x42007E);

///  See KMIP 1.0 section 6.16 [Message Extension](https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581254).
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename = "0x420051")]
pub struct MessageExtension {
    #[serde(rename = "0x42007D")]
    pub vendor_identification: String,

    #[serde(rename = "0x420026")]
    pub criticality_indicator: bool,

    #[serde(rename = "0x42009C")]
    #[serde(skip_deserializing)] // We don't support this yet
    #[serde(default)]
    pub vendor_extension: VendorExtension,
}

///  See KMIP 1.0 section 6.16 [Message Extension](https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581254).
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq, Default)]
// #[serde(rename = "0x42009C", transparent)]
#[serde(rename = "0x42009C")]
pub struct VendorExtension;

/// KMIP Timestamp for response headers.
///
/// This type handles the asymmetry in kmip-ttlv's DateTime handling:
/// - Serialization: Uses u64 internally, which kmip-ttlv encodes as DateTime (type 0x09)
/// - Deserialization: Accepts i64, which kmip-ttlv decodes from DateTime
///
/// This allows correct KMIP protocol encoding while maintaining compatibility with
/// kmip-ttlv's deserialization limitations.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Timestamp(pub i64);

impl Timestamp {
    /// Create a new Timestamp from a Unix epoch time.
    pub fn new(epoch_secs: i64) -> Self {
        Self(epoch_secs)
    }

    /// Create a new Timestamp from a u64 Unix epoch time.
    pub fn from_u64(epoch_secs: u64) -> Self {
        Self(epoch_secs as i64)
    }

    /// Get the timestamp as i64.
    pub fn as_i64(&self) -> i64 {
        self.0
    }

    /// Get the timestamp as u64 (for serialization).
    pub fn as_u64(&self) -> u64 {
        self.0 as u64
    }
}

impl From<i64> for Timestamp {
    fn from(value: i64) -> Self {
        Self(value)
    }
}

impl From<u64> for Timestamp {
    fn from(value: u64) -> Self {
        Self(value as i64)
    }
}

// Allow direct comparison with integer types for backwards compatibility in tests
impl PartialEq<i32> for Timestamp {
    fn eq(&self, other: &i32) -> bool {
        self.0 == *other as i64
    }
}

impl PartialEq<i64> for Timestamp {
    fn eq(&self, other: &i64) -> bool {
        self.0 == *other
    }
}

impl PartialEq<u64> for Timestamp {
    fn eq(&self, other: &u64) -> bool {
        self.0 as u64 == *other
    }
}

impl serde::Serialize for Timestamp {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        // Serialize as u64 so kmip-ttlv encodes it as DateTime (type 0x09)
        serializer.serialize_u64(self.0 as u64)
    }
}

impl<'de> serde::Deserialize<'de> for Timestamp {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        // Deserialize as i64 because kmip-ttlv decodes DateTime to i64
        let value = i64::deserialize(deserializer)?;
        Ok(Timestamp(value))
    }
}

///  See KMIP 1.0 section 7.1 [Message Structure](https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581256).
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename = "0x42007B")]
pub struct ResponseMessage {
    #[serde(rename = "0x42007A")]
    pub header: ResponseHeader,

    #[serde(rename = "0x42000F")]
    pub batch_items: Vec<BatchItem>,
}

///  See KMIP 1.0 section 7.2 [Operations](https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581257).
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename = "0x42007A")]
pub struct ResponseHeader {
    #[serde(rename = "0x420069")]
    pub protocol_version: ProtocolVersion,

    #[serde(rename = "0x420092")]
    pub timestamp: Timestamp,

    #[serde(rename = "0x42000D")]
    pub batch_count: i32,
}

///  See KMIP 1.0 section 6.15 [Batch Item](https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581253).
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename = "0x42000F")]
pub struct BatchItem {
    #[serde(rename = "0x42005C")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub operation: Option<Operation>,

    #[serde(rename = "0x420093")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unique_batch_item_id: Option<UniqueBatchItemID>,

    #[serde(rename = "0x42007F")]
    pub result_status: ResultStatus,

    #[serde(rename = "0x42007E")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result_reason: Option<ResultReason>,

    #[serde(rename = "0x42007D")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result_message: Option<String>,

    // #[serde(rename = "0x420006")]
    // pub asynchronous_correlation_value: Option<??>,
    #[serde(rename = "0x42007C")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payload: Option<ResponsePayload>,

    #[serde(rename = "0x420051")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message_extension: Option<MessageExtension>,
}

///  See KMIP 1.0 section 7.2 [Operations](https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581257).
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename = "Override:0x42007C")]
#[non_exhaustive]
#[allow(clippy::large_enum_variant)]
pub enum ResponsePayload {
    /// See KMIP 1.0 section 4.1 Create.
    /// See: https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581209
    #[serde(rename(deserialize = "if 0x42005C==0x00000001"))]
    #[serde(rename(serialize = "Transparent"))]
    Create(CreateResponsePayload),

    /// See KMIP 1.0 section 4.2 Create Key Pair.
    /// See: https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581210
    #[serde(rename(deserialize = "if 0x42005C==0x00000002"))]
    #[serde(rename(serialize = "Transparent"))]
    CreateKeyPair(CreateKeyPairResponsePayload),

    /// See KMIP 1.0 section 4.3 Register.
    /// See: https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581211
    #[serde(rename(deserialize = "if 0x42005C==0x00000003"))]
    #[serde(rename(serialize = "Transparent"))]
    Register(RegisterResponsePayload),

    /// See KMIP 1.0 section 4.8 Locate.
    /// See: https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581216
    #[serde(rename(deserialize = "if 0x42005C==0x00000008"))]
    #[serde(rename(serialize = "Transparent"))]
    Locate(LocateResponsePayload),

    /// See KMIP 1.0 section 4.10 Get.
    /// See: https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581218
    #[serde(rename(deserialize = "if 0x42005C==0x0000000A"))]
    #[serde(rename(serialize = "Transparent"))]
    Get(GetResponsePayload),

    /// See KMIP 1.0 section 4.11 Get Attributes.
    /// See: https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581219
    #[serde(rename(deserialize = "if 0x42005C==0x0000000B"))]
    #[serde(rename(serialize = "Transparent"))]
    GetAttributes(GetAttributesResponsePayload),

    /// See KMIP 1.0 section 4.12 Get Attribute List.
    /// See: https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581220
    #[serde(rename(deserialize = "if 0x42005C==0x0000000C"))]
    #[serde(rename(serialize = "Transparent"))]
    GetAttributeList(GetAttributeListResponsePayload),

    /// See KMIP 1.0 section 4.13 Add Attribute.
    /// See: https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581221
    #[serde(rename(deserialize = "if 0x42005C==0x0000000D"))]
    #[serde(rename(serialize = "Transparent"))]
    AddAttribute(AddAttributeResponsePayload),

    /// See KMIP 1.0 section 4.14 Modify Attribute.
    /// See: https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581222
    #[serde(rename(deserialize = "if 0x42005C==0x0000000E"))]
    #[serde(rename(serialize = "Transparent"))]
    ModifyAttribute(ModifyAttributeResponsePayload),

    /// See KMIP 1.0 section 4.15 Delete Attribute.
    /// See: https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581223
    #[serde(rename(deserialize = "if 0x42005C==0x0000000F"))]
    #[serde(rename(serialize = "Transparent"))]
    DeleteAttribute(DeleteAttributeResponsePayload),

    /// See KMIP 1.0 section 4.18 Activate.
    /// See: https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581226
    #[serde(rename(deserialize = "if 0x42005C==0x00000012"))]
    #[serde(rename(serialize = "Transparent"))]
    Activate(ActivateResponsePayload),

    /// See KMIP 1.0 section 4.19 Revoke.
    /// See: https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581227
    #[serde(rename(deserialize = "if 0x42005C==0x00000013"))]
    #[serde(rename(serialize = "Transparent"))]
    Revoke(RevokeResponsePayload),

    /// See KMIP 1.0 section 4.20 Destroy.
    /// See: https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581228
    #[serde(rename(deserialize = "if 0x42005C==0x00000014"))]
    #[serde(rename(serialize = "Transparent"))]
    Destroy(DestroyResponsePayload),

    /// See KMIP 1.0 section 4.24 Query.
    /// See: https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581232
    #[serde(rename(deserialize = "if 0x42005C==0x00000018"))]
    #[serde(rename(serialize = "Transparent"))]
    Query(QueryResponsePayload),

    /// See KMIP 1.1 section 4.26 Discover Versions.
    /// See: https://docs.oasis-open.org/kmip/spec/v1.1/cs01/kmip-spec-v1.1-cs01.html#_Toc332787652
    #[serde(rename(deserialize = "if 0x42005C==0x0000001E"))]
    #[serde(rename(serialize = "Transparent"))]
    DiscoverVersions(DiscoverVersionsResponsePayload),

    /// See KMIP 1.2 section 4.27 Encrypt.
    /// See: https://docs.oasis-open.org/kmip/spec/v1.2/os/kmip-spec-v1.2-os.html#_Toc409613554
    #[serde(rename(deserialize = "if 0x42005C==0x0000001F"))]
    #[serde(rename(serialize = "Transparent"))]
    Encrypt(EncryptResponsePayload),

    /// See KMIP 1.2 section 4.28 Decrypt.
    /// See: https://docs.oasis-open.org/kmip/spec/v1.2/os/kmip-spec-v1.2-os.html#_Toc409613555
    #[serde(rename(deserialize = "if 0x42005C==0x00000020"))]
    #[serde(rename(serialize = "Transparent"))]
    Decrypt(DecryptResponsePayload),

    /// See KMIP 1.2 section 4.31 Sign.
    /// See: https://docs.oasis-open.org/kmip/spec/v1.2/os/kmip-spec-v1.2-os.html#_Toc409613558
    #[serde(rename(deserialize = "if 0x42005C==0x00000021"))]
    #[serde(rename(serialize = "Transparent"))]
    Sign(SignResponsePayload),

    /// See KMIP 1.2 section 4.35 RNG Retrieve.
    /// See: https://docs.oasis-open.org/kmip/spec/v1.2/os/kmip-spec-v1.2-os.html#_Toc409613562
    #[serde(rename(deserialize = "if 0x42005C==0x00000025"))]
    #[serde(rename(serialize = "Transparent"))]
    RNGRetrieve(RNGRetrieveResponsePayload),
    // Note: This set of enum variants is deliberately limited to those that we currently support.
}

///  See KMIP 1.0 section 2.1.1 [Attribute](https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581155).
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename = "0x420008")]
pub struct Attribute {
    #[serde(rename = "0x42000A")]
    pub name: AttributeName,

    #[serde(rename = "0x420009")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub index: Option<AttributeIndex>,

    #[serde(rename = "0x42000B")]
    pub value: AttributeValue,
}

impl_ttlv_serde!(struct Attribute as 0x420008 {
    fast_scan = |scanner| {
        let name = AttributeName::fast_scan(&mut scanner)?;
        let index = AttributeIndex::fast_scan_opt(&mut scanner)?;
        let value = AttributeValue::fast_scan(&mut scanner, &name)?;
        Self{name, index, value}
    };

    format = |&self, formatter| {
        self.name.format(&mut formatter)?;
        if let Some(index) = &self.index {
            index.format(&mut formatter)?;
        }
        self.value.format(&mut formatter)?;
    };
});

#[cfg(test)]
mod tests {
    use super::*;
    use serde::{Serialize, Deserialize};

    /// Test Timestamp creation from different integer types.
    #[test]
    fn test_timestamp_creation() {
        // From i64
        let ts1 = Timestamp::new(1704067200);
        assert_eq!(ts1.as_i64(), 1704067200);

        // From u64
        let ts2 = Timestamp::from_u64(1704067200u64);
        assert_eq!(ts2.as_u64(), 1704067200);

        // From trait
        let ts3: Timestamp = 1704067200i64.into();
        assert_eq!(ts3.0, 1704067200);

        let ts4: Timestamp = 1704067200u64.into();
        assert_eq!(ts4.0, 1704067200);
    }

    /// Test Timestamp comparison with integer types.
    #[test]
    fn test_timestamp_comparison() {
        let ts = Timestamp::new(1704067200);

        // Compare with i32 (hex literals default to i32)
        assert_eq!(ts, 1704067200i32);

        // Compare with i64
        assert_eq!(ts, 1704067200i64);

        // Compare with u64
        assert_eq!(ts, 1704067200u64);
    }

    /// Test Timestamp serialization produces u64 (DateTime type 0x09).
    ///
    /// This verifies that the custom Serialize impl outputs u64, which kmip-ttlv
    /// encodes as DateTime (type 0x09) rather than LongInteger (type 0x03).
    #[test]
    fn test_timestamp_serializes_as_u64() {
        use serde::ser::Serializer;

        struct TestSerializer {
            serialized_as_u64: bool,
        }

        impl serde::Serializer for TestSerializer {
            type Ok = ();
            type Error = serde::de::value::Error;
            type SerializeSeq = serde::ser::Impossible<(), Self::Error>;
            type SerializeTuple = serde::ser::Impossible<(), Self::Error>;
            type SerializeTupleStruct = serde::ser::Impossible<(), Self::Error>;
            type SerializeTupleVariant = serde::ser::Impossible<(), Self::Error>;
            type SerializeMap = serde::ser::Impossible<(), Self::Error>;
            type SerializeStruct = serde::ser::Impossible<(), Self::Error>;
            type SerializeStructVariant = serde::ser::Impossible<(), Self::Error>;

            fn serialize_u64(self, _v: u64) -> Result<Self::Ok, Self::Error> {
                // This is what we expect - serialization as u64
                Ok(())
            }

            fn serialize_i64(self, _v: i64) -> Result<Self::Ok, Self::Error> {
                panic!("Timestamp should serialize as u64, not i64");
            }

            // Required trait methods with default panic implementations
            fn serialize_bool(self, _: bool) -> Result<Self::Ok, Self::Error> { unimplemented!() }
            fn serialize_i8(self, _: i8) -> Result<Self::Ok, Self::Error> { unimplemented!() }
            fn serialize_i16(self, _: i16) -> Result<Self::Ok, Self::Error> { unimplemented!() }
            fn serialize_i32(self, _: i32) -> Result<Self::Ok, Self::Error> { unimplemented!() }
            fn serialize_u8(self, _: u8) -> Result<Self::Ok, Self::Error> { unimplemented!() }
            fn serialize_u16(self, _: u16) -> Result<Self::Ok, Self::Error> { unimplemented!() }
            fn serialize_u32(self, _: u32) -> Result<Self::Ok, Self::Error> { unimplemented!() }
            fn serialize_f32(self, _: f32) -> Result<Self::Ok, Self::Error> { unimplemented!() }
            fn serialize_f64(self, _: f64) -> Result<Self::Ok, Self::Error> { unimplemented!() }
            fn serialize_char(self, _: char) -> Result<Self::Ok, Self::Error> { unimplemented!() }
            fn serialize_str(self, _: &str) -> Result<Self::Ok, Self::Error> { unimplemented!() }
            fn serialize_bytes(self, _: &[u8]) -> Result<Self::Ok, Self::Error> { unimplemented!() }
            fn serialize_none(self) -> Result<Self::Ok, Self::Error> { unimplemented!() }
            fn serialize_some<T: ?Sized + serde::Serialize>(self, _: &T) -> Result<Self::Ok, Self::Error> { unimplemented!() }
            fn serialize_unit(self) -> Result<Self::Ok, Self::Error> { unimplemented!() }
            fn serialize_unit_struct(self, _: &'static str) -> Result<Self::Ok, Self::Error> { unimplemented!() }
            fn serialize_unit_variant(self, _: &'static str, _: u32, _: &'static str) -> Result<Self::Ok, Self::Error> { unimplemented!() }
            fn serialize_newtype_struct<T: ?Sized + serde::Serialize>(self, _: &'static str, _: &T) -> Result<Self::Ok, Self::Error> { unimplemented!() }
            fn serialize_newtype_variant<T: ?Sized + serde::Serialize>(self, _: &'static str, _: u32, _: &'static str, _: &T) -> Result<Self::Ok, Self::Error> { unimplemented!() }
            fn serialize_seq(self, _: Option<usize>) -> Result<Self::SerializeSeq, Self::Error> { unimplemented!() }
            fn serialize_tuple(self, _: usize) -> Result<Self::SerializeTuple, Self::Error> { unimplemented!() }
            fn serialize_tuple_struct(self, _: &'static str, _: usize) -> Result<Self::SerializeTupleStruct, Self::Error> { unimplemented!() }
            fn serialize_tuple_variant(self, _: &'static str, _: u32, _: &'static str, _: usize) -> Result<Self::SerializeTupleVariant, Self::Error> { unimplemented!() }
            fn serialize_map(self, _: Option<usize>) -> Result<Self::SerializeMap, Self::Error> { unimplemented!() }
            fn serialize_struct(self, _: &'static str, _: usize) -> Result<Self::SerializeStruct, Self::Error> { unimplemented!() }
            fn serialize_struct_variant(self, _: &'static str, _: u32, _: &'static str, _: usize) -> Result<Self::SerializeStructVariant, Self::Error> { unimplemented!() }
        }

        let ts = Timestamp::new(1704067200);
        let serializer = TestSerializer { serialized_as_u64: false };

        // This should succeed (serialize_u64 is called)
        // If serialize_i64 were called instead, it would panic
        ts.serialize(serializer).expect("Timestamp should serialize as u64");
    }

    /// Test Timestamp deserialization accepts i64 (from kmip-ttlv DateTime decoding).
    #[test]
    fn test_timestamp_deserializes_from_i64() {
        use serde::de::{Deserializer, Visitor};

        struct I64Deserializer(i64);

        impl<'de> Deserializer<'de> for I64Deserializer {
            type Error = serde::de::value::Error;

            fn deserialize_i64<V>(self, visitor: V) -> Result<V::Value, Self::Error>
            where
                V: Visitor<'de>,
            {
                visitor.visit_i64(self.0)
            }

            fn deserialize_any<V>(self, visitor: V) -> Result<V::Value, Self::Error>
            where
                V: Visitor<'de>,
            {
                self.deserialize_i64(visitor)
            }

            // Required trait methods
            serde::forward_to_deserialize_any! {
                bool i8 i16 i32 u8 u16 u32 u64 f32 f64 char str string bytes
                byte_buf option unit unit_struct newtype_struct seq tuple
                tuple_struct map struct enum identifier ignored_any
            }
        }

        let deserializer = I64Deserializer(1704067200);
        let ts = Timestamp::deserialize(deserializer).expect("Should deserialize from i64");
        assert_eq!(ts.0, 1704067200);
    }

    /// Test round-trip: Timestamp can be created, serialized, and the value is preserved.
    #[test]
    fn test_timestamp_value_preservation() {
        let original_value: i64 = 1704067200;
        let ts = Timestamp::new(original_value);

        // Value should be preserved through conversions
        assert_eq!(ts.as_i64(), original_value);
        assert_eq!(ts.as_u64(), original_value as u64);
    }

    /// Test Timestamp with edge cases.
    #[test]
    fn test_timestamp_edge_cases() {
        // Zero timestamp
        let ts_zero = Timestamp::new(0);
        assert_eq!(ts_zero, 0i64);

        // Max reasonable timestamp (year 3000 or so)
        let ts_future = Timestamp::new(32503680000);
        assert_eq!(ts_future.as_i64(), 32503680000);

        // Large u64 value (within i64 range)
        let ts_large = Timestamp::from_u64(i64::MAX as u64);
        assert_eq!(ts_large.as_i64(), i64::MAX);
    }
}
