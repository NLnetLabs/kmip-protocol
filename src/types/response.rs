//! Rust types for deserializing KMIP responses.
use std::fmt;

use enum_ordinalize::Ordinalize;

use crate::ttlv::fast_scan::{FastScanError, FastScanner};
use crate::ttlv::format::{FormatDone, FormatResult, Formatter, TruncationError};
use crate::ttlv::types::Tag;
use crate::types::common::{CryptographicLength, Data};

use super::common::{
    AttributeIndex, AttributeName, AttributeValue, CertificateType, CryptographicAlgorithm, KeyCompressionType,
    KeyFormatType, KeyMaterial, NameType, NameValue, ObjectType, Operation, UniqueBatchItemID, UniqueIdentifier,
};

use super::impl_ttlv_serde;

pub fn from_slice(buffer: &[u8]) -> Result<ResponseMessage, FastScanError> {
    let (res, rest) = crate::ttlv::from_slice(buffer, ResponseMessage::fast_scan)?;
    if !rest.is_empty() {
        Err(FastScanError::assert())
    } else {
        Ok(res)
    }
}

pub fn to_vec(response: ResponseMessage) -> std::result::Result<Vec<u8>, TruncationError> {
    crate::ttlv::to_vec(|f| response.format(f))
}

///  See KMIP 1.0 section 2.1.3 [Key Block](https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581157).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeyBlock {
    pub key_format_type: KeyFormatType,
    pub key_compression_type: Option<KeyCompressionType>,
    pub key_value: KeyValue,
    pub cryptographic_algorithm: Option<CryptographicAlgorithm>,
    pub cryptographic_length: Option<i32>,
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
            key_wrapping_data: { scanner.skip_opt_struct(Tag::new(0x420046))?; None },
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
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeyValue {
    pub key_material: KeyMaterial,
    pub attributes: Option<Vec<Attribute>>,
}

impl KeyValue {
    pub const TAG: Tag = Tag::new(0x420045);
    pub const KEY_MATERIAL_TAG: Tag = Tag::new(0x420043);

    pub fn fast_scan(scanner: &mut FastScanner<'_>, format: &KeyFormatType) -> Result<Self, FastScanError> {
        // 2.1.4 Key Value
        // The Key Value is used only inside a Key Block and is either a Byte String or a structure (see Table 8):

        // Try first as a byte string.
        let (key_material, attributes) = if let Some(bytes) = scanner.scan_opt_bytes(Self::KEY_MATERIAL_TAG)? {
            (KeyMaterial::Bytes(bytes.to_vec()), None)
        } else {
            let mut scanner = scanner.scan_struct(Self::TAG)?;
            let key_material = KeyMaterial::fast_scan(&mut scanner, format)?;
            let attributes = std::iter::from_fn(|| Attribute::fast_scan_opt(&mut scanner).transpose())
                .collect::<Result<Vec<_>, _>>()?;
            let attributes = Some(attributes).filter(|a| !a.is_empty());
            scanner.finish()?;
            (key_material, attributes)
        };
        Ok(Self {
            key_material,
            attributes,
        })
    }

    pub fn fast_scan_opt(scanner: &mut FastScanner<'_>, format: &KeyFormatType) -> Result<Option<Self>, FastScanError> {
        // 2.1.4 Key Value
        // The Key Value is used only inside a Key Block and is either a Byte String or a structure (see Table 8):

        // Try first as a byte string.
        let (key_material, attributes) = if let Some(bytes) = scanner.scan_opt_bytes(Self::TAG)? {
            (KeyMaterial::Bytes(bytes.to_vec()), None)
        } else if let Some(mut scanner) = scanner.scan_opt_struct(Self::TAG)? {
            let key_material = KeyMaterial::fast_scan(&mut scanner, format)?;
            let attributes = std::iter::from_fn(|| Attribute::fast_scan_opt(&mut scanner).transpose())
                .collect::<Result<Vec<_>, _>>()?;
            let attributes = Some(attributes).filter(|a| !a.is_empty());
            scanner.finish()?;
            (key_material, attributes)
        } else {
            return Ok(None);
        };
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
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TemplateAttribute {
    pub names: Option<Vec<Name>>,
    pub attributes: Option<Vec<Attribute>>,
}

impl_ttlv_serde!(struct TemplateAttribute {
    #[option+vec] names: Name,
    #[option+vec] attributes: Attribute,
} as 0x420091);

///  See KMIP 1.0 section 2.2 [Managed Objects](https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581163).
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum ManagedObject {
    Certificate(Certificate),
    SymmetricKey(SymmetricKey),
    PublicKey(PublicKey),
    PrivateKey(PrivateKey),
    // TODO:
    // SplitKey(SplitKey),
    // Template(Template),
    // SecretData(SecretData),
    // OpaqueObject(OpaqueObject),
}

impl ManagedObject {
    pub fn fast_scan(scanner: &mut FastScanner<'_>, object_type: ObjectType) -> Result<Self, FastScanError> {
        let this = match object_type {
            ObjectType::Certificate => Self::Certificate(Certificate::fast_scan(scanner)?),
            ObjectType::SymmetricKey => Self::SymmetricKey(SymmetricKey::fast_scan(scanner)?),
            ObjectType::PublicKey => Self::PublicKey(PublicKey::fast_scan(scanner)?),
            ObjectType::PrivateKey => Self::PrivateKey(PrivateKey::fast_scan(scanner)?),
            _ => unimplemented!(),
        };
        Ok(this)
    }

    pub fn format(&self, formatter: &mut Formatter<'_>) -> FormatResult {
        match self {
            ManagedObject::Certificate(certificate) => certificate.format(formatter)?,
            ManagedObject::SymmetricKey(symmetric_key) => symmetric_key.format(formatter)?,
            ManagedObject::PublicKey(public_key) => public_key.format(formatter)?,
            ManagedObject::PrivateKey(private_key) => private_key.format(formatter)?,
        };
        Ok(FormatDone::assert())
    }
}

impl fmt::Display for ManagedObject {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ManagedObject::Certificate(_) => write!(f, "Certificate"),
            ManagedObject::SymmetricKey(_) => write!(f, "SymmetricKey"),
            ManagedObject::PublicKey(_) => write!(f, "PublicKey"),
            ManagedObject::PrivateKey(_) => write!(f, "PrivateKey"),
        }
    }
}

///  See KMIP 1.0 section 2.2.1 [Certificate](https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581164).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Certificate {
    pub certificate_type: CertificateType,
    pub certificate_value: Vec<u8>,
}

impl Certificate {
    pub const TAG: Tag = Tag::new(0x420013);
    pub const CERTIFICATE_VALUE_TAG: Tag = Tag::new(0x42001E);

    pub fn fast_scan(scanner: &mut FastScanner<'_>) -> Result<Self, FastScanError> {
        let mut scanner = scanner.scan_struct(Self::TAG)?;
        let this = Self {
            certificate_type: CertificateType::fast_scan(&mut scanner)?,
            certificate_value: scanner.scan_bytes(Self::CERTIFICATE_VALUE_TAG)?.into(),
        };
        scanner.finish()?;
        Ok(this)
    }

    pub fn format(&self, formatter: &mut Formatter<'_>) -> FormatResult {
        let mut formatter = formatter.format_struct(Self::TAG)?;
        self.certificate_type.format(&mut formatter)?;
        formatter.format_bytes(Self::CERTIFICATE_VALUE_TAG, &self.certificate_value)?;
        Ok(formatter.finish())
    }
}

///  See KMIP 1.0 section 2.2.2 [Symmetric Key](https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581165).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SymmetricKey {
    pub key_block: KeyBlock,
}

impl_ttlv_serde!(struct SymmetricKey { key_block: KeyBlock } as 0x42008F);

///  See KMIP 1.0 section 2.2.3 [Public Key](https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581166).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublicKey {
    pub key_block: KeyBlock,
}

impl_ttlv_serde!(struct PublicKey { key_block: KeyBlock } as 0x42006D);

///  See KMIP 1.0 section 2.2.4 [Private Key](https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581167).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PrivateKey {
    pub key_block: KeyBlock,
}

impl_ttlv_serde!(struct PrivateKey { key_block: KeyBlock } as 0x420064);

///  See KMIP 1.0 section 3.2 [Name](https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581174).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Name {
    pub name: NameValue,
    pub r#type: NameType,
}

impl_ttlv_serde!(struct Name {
    name: NameValue,
    r#type: NameType,
} as 0x420053);

///  See KMIP 1.0 section 4.1 [Create](https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581209).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CreateResponsePayload {
    pub object_type: ObjectType,
    pub unique_identifier: UniqueIdentifier,
    pub object_attributes: Option<Vec<Attribute>>,
}

impl_ttlv_serde!(struct CreateResponsePayload {
    object_type: ObjectType,
    unique_identifier: UniqueIdentifier,
    #[option+vec] object_attributes: Attribute,
} as 0x42007C);

///  See KMIP 1.0 section 4.2 [Create Key Pair](https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581210).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CreateKeyPairResponsePayload {
    pub private_key_unique_identifier: UniqueIdentifier,
    pub public_key_unique_identifier: UniqueIdentifier,
    // TODO: Add the optional response field that lists attributes for the private key
    // TODO: Add the optional response field that lists attributes for the public key
}

impl CreateKeyPairResponsePayload {
    pub const TAG: Tag = Tag::new(0x42007C);
    pub const PRIVATE_KEY_IDENTIFICATION_TAG: Tag = Tag::new(0x420066);
    pub const PUBLIC_KEY_IDENTIFICATION_TAG: Tag = Tag::new(0x42006F);

    pub fn fast_scan(scanner: &mut FastScanner<'_>) -> Result<Self, FastScanError> {
        let scanner = scanner.scan_struct(Self::TAG)?;
        Self::fast_scan_inner(scanner)
    }

    pub fn fast_scan_opt(scanner: &mut FastScanner<'_>) -> Result<Option<Self>, FastScanError> {
        if let Some(scanner) = scanner.scan_opt_struct(Self::TAG)? {
            Ok(Some(Self::fast_scan_inner(scanner)?))
        } else {
            Ok(None)
        }
    }

    pub fn format(&self, formatter: &mut Formatter<'_>) -> FormatResult {
        let mut formatter = formatter.format_struct(Self::TAG)?;
        self.private_key_unique_identifier.format(&mut formatter)?;
        self.public_key_unique_identifier.format(&mut formatter)?;
        Ok(formatter.finish())
    }

    fn fast_scan_inner(mut scanner: FastScanner<'_>) -> Result<Self, FastScanError> {
        let private_key_unique_identifier =
            UniqueIdentifier::fast_scan_with(&mut scanner, Self::PRIVATE_KEY_IDENTIFICATION_TAG)?;
        let public_key_unique_identifier =
            UniqueIdentifier::fast_scan_with(&mut scanner, Self::PUBLIC_KEY_IDENTIFICATION_TAG)?;
        Ok(Self {
            private_key_unique_identifier,
            public_key_unique_identifier,
        })
    }
}

///  See KMIP 1.0 section 4.3 [Register](https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581211).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RegisterResponsePayload {
    pub unique_identifier: UniqueIdentifier,
    pub template_attributes: Option<Vec<TemplateAttribute>>,
}

impl_ttlv_serde!(struct RegisterResponsePayload {
    unique_identifier: UniqueIdentifier,
    #[option+vec] template_attributes: TemplateAttribute,
} as 0x42007C);

///  See KMIP 1.0 section 4.8 [Locate](https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581216).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LocateResponsePayload {
    pub unique_identifiers: Vec<UniqueIdentifier>,
}

impl_ttlv_serde!(struct LocateResponsePayload {
    #[vec] unique_identifiers: UniqueIdentifier,
} as 0x42007C);

///  See KMIP 1.0 section 4.10 [Get](https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581218).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GetResponsePayload {
    pub object_type: ObjectType,
    pub unique_identifier: UniqueIdentifier,
    pub cryptographic_object: ManagedObject,
}

impl_ttlv_serde!(struct GetResponsePayload as 0x42007C {
    fast_scan = |scanner| {
        let object_type = ObjectType::fast_scan(&mut scanner)?;
        let unique_identifier = UniqueIdentifier::fast_scan(&mut scanner)?;
        let cryptographic_object = ManagedObject::fast_scan(&mut scanner, object_type)?;
        Self { object_type, unique_identifier, cryptographic_object }
    };

    format = |&self, formatter| {
        self.object_type.format(&mut formatter)?;
        self.unique_identifier.format(&mut formatter)?;
        self.cryptographic_object.format(&mut formatter)?;
    };
});

///  See KMIP 1.0 section 4.11 [Get Attributes](https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581219).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GetAttributesResponsePayload {
    pub unique_identifier: UniqueIdentifier,
    pub attributes: Option<Vec<Attribute>>,
}

impl_ttlv_serde!(struct GetAttributesResponsePayload {
    unique_identifier: UniqueIdentifier,
    #[option+vec] attributes: Attribute,
} as 0x42007C);

///  See KMIP 1.0 section 4.12 [Get Attribute List](https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581220).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GetAttributeListResponsePayload {
    pub unique_identifier: UniqueIdentifier,
    pub attributes: Vec<AttributeName>,
}

impl_ttlv_serde!(struct GetAttributeListResponsePayload {
    unique_identifier: UniqueIdentifier,
    #[vec] attributes: AttributeName,
} as 0x42007C);

/// Fields common to sections 4.18 [Activate](https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581226),
/// 4.19 [Revoke](https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581227)
/// and 4.20 [Destroy](http://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581228) responses.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UniqueIdentifierResponsePayload {
    pub unique_identifier: UniqueIdentifier,
}

impl_ttlv_serde!(struct UniqueIdentifierResponsePayload {
    unique_identifier: UniqueIdentifier,
} as 0x42007C);

///  See KMIP 1.0 section 4.18 [Activate](https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581226).
pub type ActivateResponsePayload = UniqueIdentifierResponsePayload;

///  See KMIP 1.0 section 4.19 [Revoke](https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581227).
pub type RevokeResponsePayload = UniqueIdentifierResponsePayload;

///  See KMIP 1.0 section 4.20 [Destroy](https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581228).
pub type DestroyResponsePayload = UniqueIdentifierResponsePayload;

/// Fields common to sections 4.13 [Add](https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581221),
/// 4.14 [Modify](https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581222) and 4.15
/// [Delete](https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581223) Attribute responses.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AttributeEditResponsePayload {
    pub unique_identifier: UniqueIdentifier,
    pub attribute: Attribute,
}

impl_ttlv_serde!(struct AttributeEditResponsePayload {
    unique_identifier: UniqueIdentifier,
    attribute: Attribute,
} as 0x42007C);

///  See KMIP 1.0 section 4.13 [Add Attribute](https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581221).
pub type AddAttributeResponsePayload = AttributeEditResponsePayload;

///  See KMIP 1.0 section 4.14 [Modify Attribute](https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581222).
pub type ModifyAttributeResponsePayload = AttributeEditResponsePayload;

///  See KMIP 1.0 section 4.15 [Delete Attribute](https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581223).
pub type DeleteAttributeResponsePayload = AttributeEditResponsePayload;

///  See KMIP 1.0 section 4.24 [Query](https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581232).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QueryResponsePayload {
    pub operations: Option<Vec<Operation>>,
    pub object_types: Option<Vec<ObjectType>>,
    pub vendor_identification: Option<String>,
    pub server_information: Option<ServerInformation>,
}

impl QueryResponsePayload {
    pub const TAG: Tag = Tag::new(0x42007C);
    pub const VENDOR_IDENTIFICATION_TAG: Tag = Tag::new(0x42009D);

    pub fn fast_scan(scanner: &mut FastScanner<'_>) -> Result<Self, FastScanError> {
        let scanner = scanner.scan_struct(Self::TAG)?;
        Self::fast_scan_inner(scanner)
    }

    pub fn fast_scan_opt(scanner: &mut FastScanner<'_>) -> Result<Option<Self>, FastScanError> {
        if let Some(scanner) = scanner.scan_opt_struct(Self::TAG)? {
            Ok(Some(Self::fast_scan_inner(scanner)?))
        } else {
            Ok(None)
        }
    }

    pub fn format(&self, formatter: &mut Formatter<'_>) -> FormatResult {
        let mut formatter = formatter.format_struct(Self::TAG)?;
        for operation in self.operations.iter().flatten() {
            operation.format(&mut formatter)?;
        }
        for object_type in self.object_types.iter().flatten() {
            object_type.format(&mut formatter)?;
        }
        if let Some(vendor_identification) = &self.vendor_identification {
            formatter.format_text(Self::VENDOR_IDENTIFICATION_TAG, vendor_identification)?;
        }
        if let Some(server_information) = &self.server_information {
            server_information.format(&mut formatter)?;
        }
        Ok(formatter.finish())
    }

    fn fast_scan_inner(mut scanner: FastScanner<'_>) -> Result<Self, FastScanError> {
        let operations =
            std::iter::from_fn(|| Operation::fast_scan_opt(&mut scanner).transpose()).collect::<Result<Vec<_>, _>>()?;
        let operations = Some(operations).filter(|a| !a.is_empty());
        let object_types = std::iter::from_fn(|| ObjectType::fast_scan_opt(&mut scanner).transpose())
            .collect::<Result<Vec<_>, _>>()?;
        let object_types = Some(object_types).filter(|a| !a.is_empty());
        let vendor_identification = scanner
            .scan_opt_text(Self::VENDOR_IDENTIFICATION_TAG)?
            .map(ToString::to_string);
        let server_information = ServerInformation::fast_scan_opt(&mut scanner)?;
        scanner.finish()?;
        let this = Self {
            operations,
            object_types,
            vendor_identification,
            server_information,
        };
        Ok(this)
    }
}

///  See KMIP 1.0 section 4.24 [Query](https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581232).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RNGRetrieveResponsePayload(pub Data);

impl_ttlv_serde!(struct RNGRetrieveResponsePayload(data: Data) as 0x42007C);

///  See KMIP 1.0 section 4.24 [Server Information](https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581232).
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct ServerInformation;

impl_ttlv_serde!(struct ServerInformation {} as 0x420088);

///  See KMIP 1.1 section 4.26 [Discover Versions](https://docs.oasis-open.org/kmip/spec/v1.1/cs01/kmip-spec-v1.1-cs01.html#_Toc332787652).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DiscoverVersionsResponsePayload {
    pub supported_versions: Option<Vec<ProtocolVersion>>,
}

impl_ttlv_serde!(struct DiscoverVersionsResponsePayload {
    #[option+vec] supported_versions: ProtocolVersion,
} as 0x42007C);

///  See KMIP 1.2 section 4.31 [Sign](https://docs.oasis-open.org/kmip/spec/v1.2/os/kmip-spec-v1.2-os.html#_Toc409613558).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignResponsePayload {
    pub unique_identifier: UniqueIdentifier,
    pub signature_data: Vec<u8>,
}

impl SignResponsePayload {
    pub const TAG: Tag = Tag::new(0x42007C);
    pub const SIGNATURE_DATA_TAG: Tag = Tag::new(0x4200C3);

    pub fn fast_scan(scanner: &mut FastScanner<'_>) -> Result<Self, FastScanError> {
        Self::fast_scan_inner(scanner.scan_struct(Self::TAG)?)
    }

    pub fn fast_scan_opt(scanner: &mut FastScanner<'_>) -> Result<Option<Self>, FastScanError> {
        if let Some(scanner) = scanner.scan_opt_struct(Self::TAG)? {
            Ok(Some(Self::fast_scan_inner(scanner)?))
        } else {
            Ok(None)
        }
    }

    pub fn format(&self, formatter: &mut Formatter<'_>) -> FormatResult {
        let mut formatter = formatter.format_struct(Self::TAG)?;
        self.unique_identifier.format(&mut formatter)?;
        formatter.format_bytes(Self::SIGNATURE_DATA_TAG, &self.signature_data)?;
        Ok(formatter.finish())
    }

    fn fast_scan_inner(mut scanner: FastScanner<'_>) -> Result<Self, FastScanError> {
        let this = Self {
            unique_identifier: UniqueIdentifier::fast_scan(&mut scanner)?,
            signature_data: scanner.scan_bytes(Self::SIGNATURE_DATA_TAG)?.into(),
        };
        scanner.finish()?;
        Ok(this)
    }
}

///  See KMIP 1.0 section 6.1 [Protocol Version](https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581239).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct ProtocolVersion {
    pub major: i32,
    pub minor: i32,
}

impl Default for ProtocolVersion {
    fn default() -> Self {
        Self { major: 1, minor: 0 }
    }
}

impl ProtocolVersion {
    pub const TAG: Tag = Tag::new(0x420069);
    pub const MAJOR_TAG: Tag = Tag::new(0x42006A);
    pub const MINOR_TAG: Tag = Tag::new(0x42006B);

    pub fn fast_scan(scanner: &mut FastScanner<'_>) -> Result<Self, FastScanError> {
        let mut scanner = scanner.scan_struct(Self::TAG)?;
        let major = scanner.scan_int(Self::MAJOR_TAG)?;
        let minor = scanner.scan_int(Self::MINOR_TAG)?;
        scanner.finish()?;
        Ok(Self { major, minor })
    }

    pub fn fast_scan_opt(scanner: &mut FastScanner<'_>) -> Result<Option<Self>, FastScanError> {
        if let Some(mut scanner) = scanner.scan_opt_struct(Self::TAG)? {
            let major = scanner.scan_int(Self::MAJOR_TAG)?;
            let minor = scanner.scan_int(Self::MINOR_TAG)?;
            scanner.finish()?;
            Ok(Some(Self { major, minor }))
        } else {
            Ok(None)
        }
    }

    pub fn format(&self, formatter: &mut Formatter<'_>) -> FormatResult {
        let mut formatter = formatter.format_struct(Self::TAG)?;
        formatter.format_int(Self::MAJOR_TAG, self.major)?;
        formatter.format_int(Self::MINOR_TAG, self.minor)?;
        Ok(formatter.finish())
    }
}

///  See KMIP 1.0 section 6.9 [Result Status](https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581247).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Ordinalize)]
#[non_exhaustive]
#[repr(u32)]
pub enum ResultStatus {
    Success,
    OperationFailed,
    OperationPending,
    OperationUndone,
}

impl_ttlv_serde!(enum ResultStatus as 0x42007F);

impl fmt::Display for ResultStatus {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str(match self {
            Self::Success => "Success",
            Self::OperationFailed => "OperationFailed",
            Self::OperationPending => "OperationPending",
            Self::OperationUndone => "OperationUndone",
        })
    }
}

///  See KMIP 1.0 section 6.10 [Result Reason](https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581248).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Ordinalize)]
#[non_exhaustive]
#[repr(u32)]
pub enum ResultReason {
    ItemNotFound = 1,
    ResponseTooLarge,
    AuthenticationNotSuccessful,
    InvalidMessage,
    OperationNotSupported,
    MissingData,
    InvalidField,
    FeatureNotSupported,
    OperationCanceledByRequester,
    CryptographicFailure,
    IllegalOperation,
    PermissionDenied,
    ObjectArchived,
    IndexOutOfBounds,
    ApplicationNamespaceNotSupported,
    KeyFormatTypeNotSupported,
    KeyCompressionTypeNotSupported,
    GeneralFailure,
}

impl_ttlv_serde!(enum ResultReason as 0x42007E);

impl fmt::Display for ResultReason {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str(match self {
            Self::ItemNotFound => "ItemNotFound",
            Self::ResponseTooLarge => "ResponseTooLarge",
            Self::AuthenticationNotSuccessful => "AuthenticationNotSuccessful",
            Self::InvalidMessage => "InvalidMessage",
            Self::OperationNotSupported => "OperationNotSupported",
            Self::MissingData => "MissingData",
            Self::InvalidField => "InvalidField",
            Self::FeatureNotSupported => "FeatureNotSupported",
            Self::OperationCanceledByRequester => "OperationCanceledByRequester",
            Self::CryptographicFailure => "CryptographicFailure",
            Self::IllegalOperation => "IllegalOperation",
            Self::PermissionDenied => "PermissionDenied",
            Self::ObjectArchived => "ObjectArchived",
            Self::IndexOutOfBounds => "IndexOutOfBounds",
            Self::ApplicationNamespaceNotSupported => "ApplicationNamespaceNotSupported",
            Self::KeyFormatTypeNotSupported => "KeyFormatTypeNotSupported",
            Self::KeyCompressionTypeNotSupported => "KeyCompressionTypeNotSupported",
            Self::GeneralFailure => "GeneralFailure",
        })
    }
}

///  See KMIP 1.0 section 6.16 [Message Extension](https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581254).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MessageExtension {
    pub vendor_identification: String,
    pub criticality_indicator: bool,
    pub vendor_extension: VendorExtension,
}

impl MessageExtension {
    pub const TAG: Tag = Tag::new(0x420051);
    pub const VI_TAG: Tag = Tag::new(0x42007D);
    pub const CI_TAG: Tag = Tag::new(0x420026);
    pub const VE_TAG: Tag = Tag::new(0x42009C);

    pub fn fast_scan(scanner: &mut FastScanner<'_>) -> Result<Self, FastScanError> {
        let mut scanner = scanner.scan_struct(Self::TAG)?;
        let vendor_identification = scanner.scan_text(Self::VI_TAG)?.into();
        let criticality_indicator = scanner.scan_bool(Self::CI_TAG)?;
        let vendor_extension = VendorExtension;
        scanner.skip_struct(Self::VE_TAG)?;
        scanner.finish()?;
        Ok(Self {
            vendor_identification,
            criticality_indicator,
            vendor_extension,
        })
    }

    pub fn fast_scan_opt(scanner: &mut FastScanner<'_>) -> Result<Option<Self>, FastScanError> {
        if let Some(mut scanner) = scanner.scan_opt_struct(Self::TAG)? {
            let vendor_identification = scanner.scan_text(Self::VI_TAG)?.into();
            let criticality_indicator = scanner.scan_bool(Self::CI_TAG)?;
            let vendor_extension = VendorExtension;
            scanner.skip_struct(Self::VE_TAG)?;
            scanner.finish()?;
            Ok(Some(Self {
                vendor_identification,
                criticality_indicator,
                vendor_extension,
            }))
        } else {
            Ok(None)
        }
    }

    pub fn format(&self, formatter: &mut Formatter<'_>) -> FormatResult {
        let mut formatter = formatter.format_struct(Self::TAG)?;
        formatter.format_text(Self::VI_TAG, &self.vendor_identification)?;
        formatter.format_bool(Self::CI_TAG, self.criticality_indicator)?;
        let field_formatter = formatter.format_struct(Self::VE_TAG)?;
        field_formatter.finish();
        Ok(formatter.finish())
    }
}

///  See KMIP 1.0 section 6.16 [Message Extension](https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581254).
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct VendorExtension;

///  See KMIP 1.0 section 7.1 [Message Structure](https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581256).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResponseMessage {
    pub header: ResponseHeader,
    pub batch_items: Vec<BatchItem>,
}

impl_ttlv_serde!(struct ResponseMessage {
    header: ResponseHeader,
    #[vec] batch_items: BatchItem,
} as 0x42007A);

///  See KMIP 1.0 section 7.2 [Operations](https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581257).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ResponseHeader {
    pub protocol_version: ProtocolVersion,
    pub timestamp: i64,
    pub batch_count: i32,
}

impl ResponseHeader {
    pub const TAG: Tag = Tag::new(0x42007A);
    pub const TIMESTAMP_TAG: Tag = Tag::new(0x420092);
    pub const BATCH_COUNT_TAG: Tag = Tag::new(0x42000D);

    pub fn fast_scan(scanner: &mut FastScanner<'_>) -> Result<Self, FastScanError> {
        let mut scanner = scanner.scan_struct(Self::TAG)?;
        let protocol_version = ProtocolVersion::fast_scan(&mut scanner)?;
        let timestamp = scanner.scan_date_time(Self::TIMESTAMP_TAG)?;
        let batch_count = scanner.scan_int(Self::BATCH_COUNT_TAG)?;
        scanner.finish()?;
        Ok(Self {
            protocol_version,
            timestamp,
            batch_count,
        })
    }

    pub fn format(&self, formatter: &mut Formatter<'_>) -> FormatResult {
        let mut formatter = formatter.format_struct(Self::TAG)?;
        self.protocol_version.format(&mut formatter)?;
        formatter.format_date_time(Self::TIMESTAMP_TAG, self.timestamp)?;
        formatter.format_int(Self::BATCH_COUNT_TAG, self.batch_count)?;
        Ok(formatter.finish())
    }
}

///  See KMIP 1.0 section 6.15 [Batch Item](https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581253).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BatchItem {
    pub operation: Option<Operation>,
    pub unique_batch_item_id: Option<UniqueBatchItemID>,
    pub result_status: ResultStatus,
    pub result_reason: Option<ResultReason>,
    pub result_message: Option<String>,
    // pub asynchronous_correlation_value: Option<??>,
    pub payload: Option<ResponsePayload>,
    pub message_extension: Option<MessageExtension>,
}

impl BatchItem {
    pub const TAG: Tag = Tag::new(0x42000F);
    pub const RESULT_MESSAGE_TAG: Tag = Tag::new(0x42007D);

    pub fn fast_scan(scanner: &mut FastScanner<'_>) -> Result<Self, FastScanError> {
        Self::fast_scan_inner(scanner.scan_struct(Self::TAG)?)
    }

    pub fn fast_scan_opt(scanner: &mut FastScanner<'_>) -> Result<Option<Self>, FastScanError> {
        if let Some(scanner) = scanner.scan_opt_struct(Self::TAG)? {
            Self::fast_scan_inner(scanner).map(Some)
        } else {
            Ok(None)
        }
    }

    pub fn format(&self, formatter: &mut Formatter<'_>) -> FormatResult {
        let mut formatter = formatter.format_struct(Self::TAG)?;
        if let Some(operation) = self.operation {
            operation.format(&mut formatter)?;
        }
        // if let Some(unique_batch_item_id) = &self.unique_batch_item_id {
        //     unique_batch_item_id.format(&mut formatter)?;
        // }
        self.result_status.format(&mut formatter)?;
        if let Some(result_reason) = self.result_reason {
            result_reason.format(&mut formatter)?;
        }
        if let Some(result_message) = &self.result_message {
            formatter.format_text(Self::RESULT_MESSAGE_TAG, result_message)?;
        }
        if let Some(payload) = &self.payload {
            payload.format(&mut formatter)?;
        }
        if let Some(message_extension) = &self.message_extension {
            message_extension.format(&mut formatter)?;
        }
        Ok(formatter.finish())
    }

    fn fast_scan_inner(mut scanner: FastScanner<'_>) -> Result<BatchItem, FastScanError> {
        let operation = Operation::fast_scan_opt(&mut scanner)?;
        let unique_batch_item_id = UniqueBatchItemID::fast_scan_opt(&mut scanner)?;
        let result_status = ResultStatus::fast_scan(&mut scanner)?;
        let result_reason = ResultReason::fast_scan_opt(&mut scanner)?;
        let result_message = scanner
            .scan_opt_text(Self::RESULT_MESSAGE_TAG)?
            .map(ToString::to_string);
        let payload = if let Some(operation) = operation {
            ResponsePayload::fast_scan_opt(&mut scanner, operation)?
        } else {
            None
        };
        let message_extension = MessageExtension::fast_scan_opt(&mut scanner)?;
        scanner.finish()?;
        Ok(Self {
            operation,
            unique_batch_item_id,
            result_status,
            result_reason,
            result_message,
            payload,
            message_extension,
        })
    }
}

///  See KMIP 1.0 section 7.2 [Operations](https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581257).
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
#[allow(clippy::large_enum_variant)]
pub enum ResponsePayload {
    /// See KMIP 1.0 section 4.1 Create.
    /// See: https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581209
    Create(CreateResponsePayload),

    /// See KMIP 1.0 section 4.2 Create Key Pair.
    /// See: https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581210
    CreateKeyPair(CreateKeyPairResponsePayload),

    /// See KMIP 1.0 section 4.3 Register.
    /// See: https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581211
    Register(RegisterResponsePayload),

    /// See KMIP 1.0 section 4.8 Locate.
    /// See: https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581216
    Locate(LocateResponsePayload),

    /// See KMIP 1.0 section 4.10 Get.
    /// See: https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581218
    Get(GetResponsePayload),

    /// See KMIP 1.0 section 4.11 Get Attributes.
    /// See: https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581219
    GetAttributes(GetAttributesResponsePayload),

    /// See KMIP 1.0 section 4.12 Get Attribute List.
    /// See: https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581220
    GetAttributeList(GetAttributeListResponsePayload),

    /// See KMIP 1.0 section 4.13 Add Attribute.
    /// See: https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581221
    AddAttribute(AddAttributeResponsePayload),

    /// See KMIP 1.0 section 4.14 Modify Attribute.
    /// See: https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581222
    ModifyAttribute(ModifyAttributeResponsePayload),

    /// See KMIP 1.0 section 4.15 Delete Attribute.
    /// See: https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581223
    DeleteAttribute(DeleteAttributeResponsePayload),

    /// See KMIP 1.0 section 4.18 Activate.
    /// See: https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581226
    Activate(ActivateResponsePayload),

    /// See KMIP 1.0 section 4.19 Revoke.
    /// See: https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581227
    Revoke(RevokeResponsePayload),

    /// See KMIP 1.0 section 4.20 Destroy.
    /// See: https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581228
    Destroy(DestroyResponsePayload),

    /// See KMIP 1.0 section 4.24 Query.
    /// See: https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581232
    Query(QueryResponsePayload),

    /// See KMIP 1.1 section 4.26 Discover Versions.
    /// See: https://docs.oasis-open.org/kmip/spec/v1.1/cs01/kmip-spec-v1.1-cs01.html#_Toc332787652
    DiscoverVersions(DiscoverVersionsResponsePayload),

    /// See KMIP 1.2 section 4.31 Sign.
    /// See: https://docs.oasis-open.org/kmip/spec/v1.2/os/kmip-spec-v1.2-os.html#_Toc409613558
    Sign(SignResponsePayload),

    /// See KMIP 1.2 section 4.35 RNG Retrieve.
    /// See: https://docs.oasis-open.org/kmip/spec/v1.2/os/kmip-spec-v1.2-os.html#_Toc409613562
    RNGRetrieve(RNGRetrieveResponsePayload),
    // Note: This set of enum variants is deliberately limited to those that we currently support.
}

impl ResponsePayload {
    pub fn operation(&self) -> Operation {
        match self {
            ResponsePayload::Create(_) => Operation::Create,
            ResponsePayload::CreateKeyPair(_) => Operation::CreateKeyPair,
            ResponsePayload::Register(_) => Operation::Register,
            ResponsePayload::Locate(_) => Operation::Locate,
            ResponsePayload::Get(_) => Operation::Get,
            ResponsePayload::GetAttributes(_) => Operation::GetAttributes,
            ResponsePayload::GetAttributeList(_) => Operation::GetAttributeList,
            ResponsePayload::AddAttribute(_) => Operation::AddAttribute,
            ResponsePayload::ModifyAttribute(_) => Operation::ModifyAttribute,
            ResponsePayload::DeleteAttribute(_) => Operation::DeleteAttribute,
            ResponsePayload::Activate(_) => Operation::Activate,
            ResponsePayload::Revoke(_) => Operation::Revoke,
            ResponsePayload::Destroy(_) => Operation::Destroy,
            ResponsePayload::Query(_) => Operation::Query,
            ResponsePayload::DiscoverVersions(_) => Operation::DiscoverVersions,
            ResponsePayload::Sign(_) => Operation::Sign,
            ResponsePayload::RNGRetrieve(_) => Operation::RNGRetrieve,
        }
    }

    pub fn protocol_version(&self) -> ProtocolVersion {
        match self {
            ResponsePayload::Create(_)
            | ResponsePayload::CreateKeyPair(_)
            | ResponsePayload::Register(_)
            | ResponsePayload::Locate(_)
            | ResponsePayload::Get(_)
            | ResponsePayload::GetAttributes(_)
            | ResponsePayload::GetAttributeList(_)
            | ResponsePayload::AddAttribute(_)
            | ResponsePayload::ModifyAttribute(_)
            | ResponsePayload::DeleteAttribute(_)
            | ResponsePayload::Activate(_)
            | ResponsePayload::Revoke(_)
            | ResponsePayload::Destroy(_) => ProtocolVersion { major: 1, minor: 0 },
            ResponsePayload::DiscoverVersions(_) => ProtocolVersion { major: 1, minor: 1 },
            ResponsePayload::Sign(_) | ResponsePayload::RNGRetrieve(_) | ResponsePayload::Query(_) => {
                ProtocolVersion { major: 1, minor: 2 }
            }
        }
    }
}

impl ResponsePayload {
    pub fn fast_scan_opt(scanner: &mut FastScanner<'_>, operation: Operation) -> Result<Option<Self>, FastScanError> {
        let this = match operation {
            Operation::Create => CreateResponsePayload::fast_scan_opt(scanner)?.and_then(|v| Some(Self::Create(v))),
            Operation::CreateKeyPair => {
                CreateKeyPairResponsePayload::fast_scan_opt(scanner)?.and_then(|v| Some(Self::CreateKeyPair(v)))
            }
            Operation::Register => {
                RegisterResponsePayload::fast_scan_opt(scanner)?.and_then(|v| Some(Self::Register(v)))
            }
            Operation::Locate => LocateResponsePayload::fast_scan_opt(scanner)?.and_then(|v| Some(Self::Locate(v))),
            Operation::Get => GetResponsePayload::fast_scan_opt(scanner)?.and_then(|v| Some(Self::Get(v))),
            Operation::GetAttributes => {
                GetAttributesResponsePayload::fast_scan_opt(scanner)?.and_then(|v| Some(Self::GetAttributes(v)))
            }
            Operation::GetAttributeList => {
                GetAttributeListResponsePayload::fast_scan_opt(scanner)?.and_then(|v| Some(Self::GetAttributeList(v)))
            }
            Operation::AddAttribute => {
                AddAttributeResponsePayload::fast_scan_opt(scanner)?.and_then(|v| Some(Self::AddAttribute(v)))
            }
            Operation::ModifyAttribute => {
                ModifyAttributeResponsePayload::fast_scan_opt(scanner)?.and_then(|v| Some(Self::ModifyAttribute(v)))
            }
            Operation::DeleteAttribute => {
                DeleteAttributeResponsePayload::fast_scan_opt(scanner)?.and_then(|v| Some(Self::DeleteAttribute(v)))
            }
            Operation::Activate => {
                ActivateResponsePayload::fast_scan_opt(scanner)?.and_then(|v| Some(Self::Activate(v)))
            }
            Operation::Revoke => RevokeResponsePayload::fast_scan_opt(scanner)?.and_then(|v| Some(Self::Revoke(v))),
            Operation::Destroy => DestroyResponsePayload::fast_scan_opt(scanner)?.and_then(|v| Some(Self::Destroy(v))),
            Operation::Query => QueryResponsePayload::fast_scan_opt(scanner)?.and_then(|v| Some(Self::Query(v))),
            Operation::DiscoverVersions => {
                DiscoverVersionsResponsePayload::fast_scan_opt(scanner)?.and_then(|v| Some(Self::DiscoverVersions(v)))
            }
            Operation::Sign => SignResponsePayload::fast_scan_opt(scanner)?.and_then(|v| Some(Self::Sign(v))),
            Operation::RNGRetrieve => {
                RNGRetrieveResponsePayload::fast_scan_opt(scanner)?.and_then(|v| Some(Self::RNGRetrieve(v)))
            }

            _ => unimplemented!(),
        };
        Ok(this)
    }

    pub fn format(&self, formatter: &mut Formatter<'_>) -> FormatResult {
        match self {
            ResponsePayload::Create(payload) => payload.format(formatter),
            ResponsePayload::CreateKeyPair(payload) => payload.format(formatter),
            ResponsePayload::Register(payload) => payload.format(formatter),
            ResponsePayload::Locate(payload) => payload.format(formatter),
            ResponsePayload::Get(payload) => payload.format(formatter),
            ResponsePayload::GetAttributes(payload) => payload.format(formatter),
            ResponsePayload::GetAttributeList(payload) => payload.format(formatter),
            ResponsePayload::AddAttribute(payload) => payload.format(formatter),
            ResponsePayload::ModifyAttribute(payload) => payload.format(formatter),
            ResponsePayload::DeleteAttribute(payload) => payload.format(formatter),
            ResponsePayload::Activate(payload) => payload.format(formatter),
            ResponsePayload::Revoke(payload) => payload.format(formatter),
            ResponsePayload::Destroy(payload) => payload.format(formatter),
            ResponsePayload::Query(payload) => payload.format(formatter),
            ResponsePayload::DiscoverVersions(payload) => payload.format(formatter),
            ResponsePayload::Sign(payload) => payload.format(formatter),
            ResponsePayload::RNGRetrieve(payload) => payload.format(formatter),
        }
    }
}

impl std::fmt::Display for ResponsePayload {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ResponsePayload::Create(_) => f.write_str("Create"),
            ResponsePayload::CreateKeyPair(_) => f.write_str("CreateKeyPair"),
            ResponsePayload::Register(_) => f.write_str("Register"),
            ResponsePayload::Locate(_) => f.write_str("Locate"),
            ResponsePayload::Get(_) => f.write_str("Get"),
            ResponsePayload::GetAttributes(_) => f.write_str("GetAttributes"),
            ResponsePayload::GetAttributeList(_) => f.write_str("GetAttributeList"),
            ResponsePayload::AddAttribute(_) => f.write_str("AddAttribute"),
            ResponsePayload::ModifyAttribute(_) => f.write_str("ModifyAttribute"),
            ResponsePayload::DeleteAttribute(_) => f.write_str("DeleteAttribute"),
            ResponsePayload::Activate(_) => f.write_str("Activate"),
            ResponsePayload::Revoke(_) => f.write_str("Revoke"),
            ResponsePayload::Destroy(_) => f.write_str("Destroy"),
            ResponsePayload::Query(_) => f.write_str("Query"),
            ResponsePayload::DiscoverVersions(_) => f.write_str("DiscoverVersions"),
            ResponsePayload::Sign(_) => f.write_str("Sign"),
            ResponsePayload::RNGRetrieve(_) => f.write_str("RNGRetrieve"),
        }
    }
}

///  See KMIP 1.0 section 2.1.1 [Attribute](https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581155).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Attribute {
    pub name: AttributeName,
    pub index: Option<AttributeIndex>,
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
