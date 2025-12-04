//! Rust types common to both serialization of KMIP requests and deserialization KMIP responses.
use std::fmt::Display;
use std::str::FromStr;

use enum_display_derive::Display;
use enum_ordinalize::Ordinalize;
use serde_derive::Deserialize;
use serde_derive::Serialize;

use crate::ttlv::fast_scan::FastScanError;
use crate::ttlv::fast_scan::FastScanner;
use crate::ttlv::format::FormatResult;
use crate::ttlv::format::Formatter;
use crate::ttlv::types::Tag;

use super::impl_ttlv_serde;

/// See KMIP 1.0 section 2.1.1 [Attribute](https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581155).
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename = "Transparent:0x42000A")]
pub struct AttributeName(pub String);

impl std::cmp::PartialEq<str> for AttributeName {
    fn eq(&self, other: &str) -> bool {
        self.0 == other
    }
}

impl_ttlv_serde!(text AttributeName as 0x42000A);

/// See KMIP 1.0 section 2.1.1 [Attribute](https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581155).
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename = "Transparent:0x420009")]
pub struct AttributeIndex(pub i32);

impl std::cmp::PartialEq<i32> for AttributeIndex {
    fn eq(&self, other: &i32) -> bool {
        &self.0 == other
    }
}

impl_ttlv_serde!(int AttributeIndex as 0x420009);

/// See KMIP 1.0 section 2.1.1 [Attribute](https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581155).
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename(serialize = "Override:0x42000B"))]
#[non_exhaustive]
pub enum AttributeValue {
    /// See KMIP 1.0 section 3.1 Unique Identifier.
    // Not implemented

    /// See KMIP 1.0 section 3.2 Name.
    #[serde(rename(deserialize = "if 0x42000A==Name"))]
    Name(NameValue, NameType),

    /// See KMIP 1.0 section 3.3 Object Type.
    #[serde(rename(deserialize = "if 0x42000A==Object Type"))]
    #[serde(rename(serialize = "Transparent"))]
    ObjectType(ObjectType),

    /// See KMIP 1.0 section 3.4 Cryptographic Algorithm.
    #[serde(rename(deserialize = "if 0x42000A==Cryptographic Algorithm"))]
    #[serde(rename(serialize = "Transparent"))]
    CryptographicAlgorithm(CryptographicAlgorithm),

    /// See KMIP 1.0 section 3.5 Cryptographic Length.
    // Not implemented because the caller should use AttributeValue::Integer.

    /// See KMIP 1.0 section 3.6 Cryptographic Parameters.
    #[serde(rename(deserialize = "if 0x42000A==Cryptographic Parameters"))]
    CryptographicParameters(
        #[serde(skip_serializing_if = "Option::is_none")] Option<BlockCipherMode>,
        #[serde(skip_serializing_if = "Option::is_none")] Option<PaddingMethod>,
        #[serde(skip_serializing_if = "Option::is_none")] Option<HashingAlgorithm>,
        #[serde(skip_serializing_if = "Option::is_none")] Option<KeyRoleType>,
        #[serde(skip_serializing_if = "Option::is_none")] Option<DigitalSignatureAlgorithm>, // KMIP 1.2
        #[serde(skip_serializing_if = "Option::is_none")] Option<CryptographicAlgorithm>,    // KMIP 1.2
        #[serde(skip_serializing_if = "Option::is_none")] Option<RandomIV>,                  // KMIP 1.2
        #[serde(skip_serializing_if = "Option::is_none")] Option<IVLength>,                  // KMIP 1.2
        #[serde(skip_serializing_if = "Option::is_none")] Option<TagLength>,                 // KMIP 1.2
        #[serde(skip_serializing_if = "Option::is_none")] Option<FixedFieldLength>,          // KMIP 1.2
        #[serde(skip_serializing_if = "Option::is_none")] Option<InvocationFieldLength>,     // KMIP 1.2
        #[serde(skip_serializing_if = "Option::is_none")] Option<CounterLength>,             // KMIP 1.2
        #[serde(skip_serializing_if = "Option::is_none")] Option<InitialCounterValue>,       // KMIP 1.2
    ),

    /// See KMIP 1.0 section 3.7 Cryptographic Domain Parameters.
    #[serde(rename(deserialize = "if 0x42000A==Cryptographic Domain Parameters"))]
    CryptographicDomainParameters(
        #[serde(skip_serializing_if = "Option::is_none")] Option<i32>, // Q length
        #[serde(skip_serializing_if = "Option::is_none")] Option<RecommendedCurve>,
    ),

    /// See KMIP 1.0 section 3.8 Certificate Type.
    // Not implemented

    /// See KMIP 1.0 section 3.9 Certificate Identifier.
    // Not implemented

    /// See KMIP 1.0 section 3.10 Certificate Subject.
    // Not implemented

    /// See KMIP 1.0 section 3.11 Certificate Issuer.
    // Not implemented

    /// See KMIP 1.0 section 3.12 Digest.
    // Not implemented

    /// See KMIP 1.0 section 3.13 Operation Policy Name.
    // Not implemented

    /// See KMIP 1.0 section 3.14 Cryptographic Usage Mask.
    // Not implemented

    /// See KMIP 1.0 section 3.15 Lease Time.
    // Not implemented

    /// See KMIP 1.0 section 3.16 Usage Limits.
    // Not implemented

    /// See KMIP 1.0 section 3.17 State.
    #[serde(rename(deserialize = "if 0x42000A==State"))]
    #[serde(rename(serialize = "Transparent"))]
    State(State),

    /// See KMIP 1.0 section 3.18 Initial Date.
    // Not implemented

    /// See KMIP 1.0 section 3.19 Activation Date.
    // Not implemented

    /// See KMIP 1.0 section 3.20 Process Start Date.
    // Not implemented

    /// See KMIP 1.0 section 3.21 Protect Stop Date.
    // Not implemented

    /// See KMIP 1.0 section 3.22 Deactivation Date.
    // Not implemented

    /// See KMIP 1.0 section 3.23 Destroy Date.
    // Not implemented

    /// See KMIP 1.0 section 3.24 Compromise Occurence Date.
    // Not implemented

    /// See KMIP 1.0 section 3.25 Compromise Date.
    // Not implemented

    /// See KMIP 1.0 section 3.26 Revocation Reason.
    // Not implemented

    /// See KMIP 1.0 section 3.27 Archive Date.
    // Not implemented

    /// See KMIP 1.0 section 3.28 Object Group.
    #[serde(rename(deserialize = "if 0x42000A==Object Group"))]
    ObjectGroup(String),

    /// See KMIP 1.0 section 3.29 Link.
    #[serde(rename(deserialize = "if 0x42000A==Linked Object Identifier"))]
    Link(LinkType, LinkedObjectIdentifier),

    /// See KMIP 1.0 section 3.30 Application Specific Information.
    #[serde(rename(deserialize = "if 0x42000A==Application Specific Information"))]
    ApplicationSpecificInformation(ApplicationNamespace, ApplicationData),

    /// See KMIP 1.0 section 3.31 Contact Information.
    #[serde(rename(deserialize = "if 0x42000A==Contact Information"))]
    #[serde(rename(serialize = "Transparent"))]
    ContactInformation(String),

    /// See KMIP 1.0 section 3.32 Last Change Date.
    // Not implemented

    /// See KMIP 1.0 section 3.33 Custom Attribute:.
    //   "Any data type or structure. If a structure, then the structure SHALL NOT include sub structures"
    /// See: https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581207

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
    DateTime(u64),
    // TODO
    // #[serde(rename = "if type==Interval")]
    // Interval(??),
}

impl AttributeValue {
    pub const TAG: Tag = Tag::new(0x42000B);

    pub fn fast_scan(scanner: &mut FastScanner<'_>, name: &AttributeName) -> Result<Self, FastScanError> {
        match name.0.as_str() {
            "Unique Identifier" => scanner.scan_text(Self::TAG).map(|s| Self::TextString(s.into())),
            "Name" => {
                let mut scanner = scanner.scan_struct(Self::TAG)?;
                let name_value = NameValue::fast_scan(&mut scanner)?;
                let name_type = NameType::fast_scan(&mut scanner)?;
                scanner.finish()?;
                Ok(Self::Name(name_value, name_type))
            }
            "Object Type" => ObjectType::fast_scan_with(scanner, Self::TAG).map(Self::ObjectType),
            "Cryptographic Algorithm" => {
                CryptographicAlgorithm::fast_scan_with(scanner, Self::TAG).map(Self::CryptographicAlgorithm)
            }
            "Cryptographic Length" => scanner.scan_int(Self::TAG).map(Self::Integer),
            "Cryptographic Parameters" => CryptographicParameters::fast_scan_with(scanner, Self::TAG).map(|params| {
                Self::CryptographicParameters(
                    params.block_cipher_mode,
                    params.padding_method,
                    params.hashing_algorithm,
                    params.key_role_type,
                    params.digital_signature_algorithm,
                    params.cryptographic_algorithm,
                    params.random_iv,
                    params.iv_length,
                    params.tag_length,
                    params.fixed_field_length,
                    params.invocation_field_length,
                    params.counter_length,
                    params.initial_counter_value,
                )
            }),
            "Operation Policy Name" => scanner.scan_text(Self::TAG).map(|s| Self::TextString(s.into())),
            "Cryptographic Usage Mask" => scanner.scan_int(Self::TAG).map(Self::Integer),
            "Activation Date" => scanner.scan_date_time(Self::TAG).map(|s| Self::DateTime(s as u64)),
            "Object Group" => scanner.scan_text(Self::TAG).map(|s| Self::ObjectGroup(s.into())),
            "Link" => {
                let mut scanner = scanner.scan_struct(Self::TAG)?;
                let link_type = LinkType::fast_scan(&mut scanner)?;
                let linked_object_identifier = LinkedObjectIdentifier::fast_scan(&mut scanner)?;
                scanner.finish()?;
                Ok(Self::Link(link_type, linked_object_identifier))
            }
            "Application Specific Information" => {
                let mut scanner = scanner.scan_struct(Self::TAG)?;
                let application_namespace = ApplicationNamespace::fast_scan(&mut scanner)?;
                let application_data = ApplicationData::fast_scan(&mut scanner)?;
                scanner.finish()?;
                Ok(Self::ApplicationSpecificInformation(
                    application_namespace,
                    application_data,
                ))
            }
            "Contact Information" => scanner.scan_text(Self::TAG).map(|s| Self::ContactInformation(s.into())),
            _ => Err(FastScanError::assert()),
        }
    }

    pub fn format(&self, formatter: &mut Formatter<'_>) -> FormatResult {
        match self {
            AttributeValue::Name(name_value, name_type) => {
                let mut formatter = formatter.format_struct(Self::TAG)?;
                name_value.format(&mut formatter)?;
                name_type.format(&mut formatter)?;
                Ok(formatter.finish())
            }
            AttributeValue::ObjectType(this) => this.format_with(formatter, Self::TAG),
            AttributeValue::CryptographicAlgorithm(this) => this.format_with(formatter, Self::TAG),
            &AttributeValue::CryptographicParameters(
                block_cipher_mode,
                padding_method,
                hashing_algorithm,
                key_role_type,
                digital_signature_algorithm,
                cryptographic_algorithm,
                random_iv,
                iv_length,
                tag_length,
                fixed_field_length,
                invocation_field_length,
                counter_length,
                initial_counter_value,
            ) => CryptographicParameters {
                block_cipher_mode,
                padding_method,
                hashing_algorithm,
                key_role_type,
                digital_signature_algorithm,
                cryptographic_algorithm,
                random_iv,
                iv_length,
                tag_length,
                fixed_field_length,
                invocation_field_length,
                counter_length,
                initial_counter_value,
            }
            .format_with(formatter, Self::TAG),
            &AttributeValue::CryptographicDomainParameters(q_length, recommended_curve) => {
                CryptographicDomainParameters {
                    q_length,
                    recommended_curve,
                }
                .format_with(formatter, Self::TAG)
            }
            AttributeValue::State(this) => this.format_with(formatter, Self::TAG),
            AttributeValue::ObjectGroup(v) => formatter.format_text(Self::TAG, v),
            AttributeValue::Link(link_type, linked_object_identifier) => {
                let mut formatter = formatter.format_struct(Self::TAG)?;
                link_type.format(&mut formatter)?;
                linked_object_identifier.format(&mut formatter)?;
                Ok(formatter.finish())
            }
            AttributeValue::ApplicationSpecificInformation(application_namespace, application_data) => {
                let mut formatter = formatter.format_struct(Self::TAG)?;
                application_namespace.format(&mut formatter)?;
                application_data.format(&mut formatter)?;
                Ok(formatter.finish())
            }
            AttributeValue::ContactInformation(v) => formatter.format_text(Self::TAG, v),

            AttributeValue::Structure(fields) => {
                let mut formatter = formatter.format_struct(Self::TAG)?;
                for field in fields {
                    field.format(&mut formatter)?;
                }
                Ok(formatter.finish())
            }
            &AttributeValue::Integer(v) => formatter.format_int(Self::TAG, v),
            &AttributeValue::LongInteger(v) => formatter.format_long_int(Self::TAG, v),
            &AttributeValue::Enumeration(v) => formatter.format_enum(Self::TAG, v),
            &AttributeValue::Boolean(v) => formatter.format_bool(Self::TAG, v),
            AttributeValue::TextString(v) => formatter.format_text(Self::TAG, v),
            AttributeValue::ByteString(v) => formatter.format_bytes(Self::TAG, v),
            &AttributeValue::DateTime(v) => formatter.format_date_time(Self::TAG, v as i64),
        }
    }
}

/// See KMIP 1.0 section 2.1.4 [Key Value](https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581158).
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
// Use "Transparent" here because we must not write out the TLV of TTLV for
// 0x420043 because Bytes must be written as 42004208..., not 42004301 (i.e.
// as the ByteString type, not the Structure type)... but we do need the
// initial Tag of TTLV to be written out, for which we use TagOnly:0x420043
// below in the case of the Bytes variant as that would otherwise be
// serialized without a tag.
#[serde(rename = "Transparent")]
pub enum KeyMaterial {
    #[serde(rename(deserialize = "if 0x420042 in [0x00000001, 0x00000002, 0x00000003, 0x00000004, 0x00000006]"))] // Raw, Opaque, PKCS1, PKCS8 or ECPrivateKey
    #[serde(rename(serialize = "TagOnly:0x420043"))]
    Bytes(#[serde(with = "serde_bytes")] Vec<u8>),

    #[serde(rename(deserialize = "if 0x420042 == 0x00000007"))]
    TransparentSymmetricKey(TransparentSymmetricKey),

    #[serde(rename(deserialize = "if 0x420042 == 0x00000008"))]
    TransparentDSAPrivateKey(TransparentDSAPrivateKey),

    #[serde(rename(deserialize = "if 0x420042 == 0x00000009"))]
    TransparentDSAPublicKey(TransparentDSAPublicKey),

    #[serde(rename(deserialize = "if 0x420042 == 0x0000000A"))]
    TransparentRSAPrivateKey(TransparentRSAPrivateKey),

    #[serde(rename(deserialize = "if 0x420042 == 0x0000000B"))]
    TransparentRSAPublicKey(TransparentRSAPublicKey),

    #[serde(rename(deserialize = "if 0x420042 == 0x0000000C"))]
    TransparentDHPrivateKey(TransparentDHPrivateKey),

    #[serde(rename(deserialize = "if 0x420042 == 0x0000000D"))]
    TransparentDHPublicKey(TransparentDHPublicKey),

    #[serde(rename(deserialize = "if 0x420042 >= 0x0000000E"))]
    Structure(#[serde(with = "serde_bytes")] Vec<u8>), // All other transparent key types which we don't support yet
}

impl Display for KeyMaterial {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            KeyMaterial::Bytes(_) => write!(f, "Bytes"),
            KeyMaterial::TransparentSymmetricKey(_) => write!(f, "TransparentSymmetricKey"),
            KeyMaterial::TransparentDSAPrivateKey(_) => write!(f, "TransparentDSAPrivateKey"),
            KeyMaterial::TransparentDSAPublicKey(_) => write!(f, "TransparentDSAPublicKey"),
            KeyMaterial::TransparentRSAPrivateKey(_) => write!(f, "TransparentRSAPrivateKey"),
            KeyMaterial::TransparentRSAPublicKey(_) => write!(f, "TransparentRSAPublicKey"),
            KeyMaterial::TransparentDHPrivateKey(_) => write!(f, "TransparentDHPrivateKey"),
            KeyMaterial::TransparentDHPublicKey(_) => write!(f, "TransparentDHPublicKey"),
            KeyMaterial::Structure(_) => write!(f, "Structure"),
        }
    }
}

impl KeyMaterial {
    pub const TAG: Tag = Tag::new(0x420043);

    pub fn fast_scan(scanner: &mut FastScanner<'_>, format: &KeyFormatType) -> Result<Self, FastScanError> {
        match format {
            KeyFormatType::Raw
            | KeyFormatType::Opaque
            | KeyFormatType::PKCS1
            | KeyFormatType::PKCS8
            | KeyFormatType::X509 => scanner.scan_bytes(Self::TAG).map(|s| Self::Bytes(s.into())),

            KeyFormatType::TransparentSymmetricKey => {
                TransparentSymmetricKey::fast_scan(scanner).map(Self::TransparentSymmetricKey)
            }
            KeyFormatType::TransparentDSAPrivateKey => {
                TransparentDSAPrivateKey::fast_scan(scanner).map(Self::TransparentDSAPrivateKey)
            }
            KeyFormatType::TransparentDSAPublicKey => {
                TransparentDSAPublicKey::fast_scan(scanner).map(Self::TransparentDSAPublicKey)
            }
            KeyFormatType::TransparentRSAPrivateKey => {
                TransparentRSAPrivateKey::fast_scan(scanner).map(Self::TransparentRSAPrivateKey)
            }
            KeyFormatType::TransparentRSAPublicKey => {
                TransparentRSAPublicKey::fast_scan(scanner).map(Self::TransparentRSAPublicKey)
            }
            KeyFormatType::TransparentDHPrivateKey => {
                TransparentDHPrivateKey::fast_scan(scanner).map(Self::TransparentDHPrivateKey)
            }
            KeyFormatType::TransparentDHPublicKey => {
                TransparentDHPublicKey::fast_scan(scanner).map(Self::TransparentDHPublicKey)
            }

            _ => todo!(),
        }
    }

    pub fn format(&self, formatter: &mut Formatter<'_>) -> FormatResult {
        match self {
            KeyMaterial::Bytes(v) => formatter.format_bytes(Self::TAG, v),

            KeyMaterial::TransparentSymmetricKey(this) => this.format(formatter),
            KeyMaterial::TransparentDSAPrivateKey(this) => this.format(formatter),
            KeyMaterial::TransparentDSAPublicKey(this) => this.format(formatter),
            KeyMaterial::TransparentRSAPrivateKey(this) => this.format(formatter),
            KeyMaterial::TransparentRSAPublicKey(this) => this.format(formatter),
            KeyMaterial::TransparentDHPrivateKey(this) => this.format(formatter),
            KeyMaterial::TransparentDHPublicKey(this) => this.format(formatter),

            KeyMaterial::Structure(_) => todo!(),
        }
    }
}

/// See KMIP 1.0 section 2.1.7.1 [Transparent Symmetric Key](https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581161).
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename = "0x420043")]
pub struct TransparentSymmetricKey {
    #[serde(with = "serde_bytes")]
    pub key: Vec<u8>,
}

impl TransparentSymmetricKey {
    pub const TAG: Tag = Tag::new(0x420043);
    pub const KEY_TAG: Tag = Tag::new(0x42003F);

    pub fn fast_scan(scanner: &mut FastScanner<'_>) -> Result<Self, FastScanError> {
        let mut scanner = scanner.scan_struct(Self::TAG)?;
        let key = scanner.scan_bytes(Self::KEY_TAG)?.into();
        scanner.finish()?;
        Ok(Self { key })
    }

    pub fn format(&self, formatter: &mut Formatter<'_>) -> FormatResult {
        let mut formatter = formatter.format_struct(Self::TAG)?;
        formatter.format_bytes(Self::KEY_TAG, &self.key)?;
        Ok(formatter.finish())
    }
}

/// See KMIP 1.0 section 2.1.7.2 [Transparent DSA Private Key](https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581161).
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename = "0x420043")]
pub struct TransparentDSAPrivateKey {
    #[serde(with = "serde_bytes")]
    pub p: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub q: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub g: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub x: Vec<u8>,
}

impl TransparentDSAPrivateKey {
    pub const TAG: Tag = Tag::new(0x420043);
    pub const P_TAG: Tag = Tag::new(0x42005E);
    pub const Q_TAG: Tag = Tag::new(0x420071);
    pub const G_TAG: Tag = Tag::new(0x420037);
    pub const X_TAG: Tag = Tag::new(0x42009F);

    pub fn fast_scan(scanner: &mut FastScanner<'_>) -> Result<Self, FastScanError> {
        let mut scanner = scanner.scan_struct(Self::TAG)?;
        let p = scanner.scan_big_int(Self::P_TAG)?.into();
        let q = scanner.scan_big_int(Self::Q_TAG)?.into();
        let g = scanner.scan_big_int(Self::G_TAG)?.into();
        let x = scanner.scan_big_int(Self::X_TAG)?.into();
        scanner.finish()?;
        Ok(Self { p, q, g, x })
    }

    pub fn format(&self, formatter: &mut Formatter<'_>) -> FormatResult {
        let mut formatter = formatter.format_struct(Self::TAG)?;
        formatter.format_big_int(Self::P_TAG, &self.p)?;
        formatter.format_big_int(Self::Q_TAG, &self.q)?;
        formatter.format_big_int(Self::G_TAG, &self.g)?;
        formatter.format_big_int(Self::X_TAG, &self.x)?;
        Ok(formatter.finish())
    }
}

/// See KMIP 1.0 section 2.1.7.3 [Transparent DSA Public Key](https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581161).
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename = "0x420043")]
pub struct TransparentDSAPublicKey {
    #[serde(with = "serde_bytes")]
    pub p: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub q: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub g: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub x: Vec<u8>,
}

impl TransparentDSAPublicKey {
    pub const TAG: Tag = Tag::new(0x420043);
    pub const P_TAG: Tag = Tag::new(0x42005E);
    pub const Q_TAG: Tag = Tag::new(0x420071);
    pub const G_TAG: Tag = Tag::new(0x420037);
    pub const X_TAG: Tag = Tag::new(0x42009F);

    pub fn fast_scan(scanner: &mut FastScanner<'_>) -> Result<Self, FastScanError> {
        let mut scanner = scanner.scan_struct(Self::TAG)?;
        let p = scanner.scan_big_int(Self::P_TAG)?.into();
        let q = scanner.scan_big_int(Self::Q_TAG)?.into();
        let g = scanner.scan_big_int(Self::G_TAG)?.into();
        let x = scanner.scan_big_int(Self::X_TAG)?.into();
        scanner.finish()?;
        Ok(Self { p, q, g, x })
    }

    pub fn format(&self, formatter: &mut Formatter<'_>) -> FormatResult {
        let mut formatter = formatter.format_struct(Self::TAG)?;
        formatter.format_big_int(Self::P_TAG, &self.p)?;
        formatter.format_big_int(Self::Q_TAG, &self.q)?;
        formatter.format_big_int(Self::G_TAG, &self.g)?;
        formatter.format_big_int(Self::X_TAG, &self.x)?;
        Ok(formatter.finish())
    }
}

/// See KMIP 1.0 section 2.1.7.4 [Transparent RSA Private Key](https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581161).
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename = "0x420043")]
pub struct TransparentRSAPrivateKey {
    #[serde(with = "serde_bytes")]
    pub modulus: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub private_exponent: Option<Vec<u8>>,
    #[serde(with = "serde_bytes")]
    pub public_exponent: Option<Vec<u8>>,
    #[serde(with = "serde_bytes")]
    pub p: Option<Vec<u8>>,
    #[serde(with = "serde_bytes")]
    pub q: Option<Vec<u8>>,
    #[serde(with = "serde_bytes")]
    pub prime_exponent_p: Option<Vec<u8>>,
    #[serde(with = "serde_bytes")]
    pub prime_exponent_q: Option<Vec<u8>>,
    #[serde(with = "serde_bytes")]
    pub crt_coefficient: Option<Vec<u8>>,
}

impl TransparentRSAPrivateKey {
    pub const TAG: Tag = Tag::new(0x420043);
    pub const MODULUS_TAG: Tag = Tag::new(0x420052);
    pub const PRIVATE_EXPONENT_TAG: Tag = Tag::new(0x420063);
    pub const PUBLIC_EXPONENT_TAG: Tag = Tag::new(0x42006C);
    pub const P_TAG: Tag = Tag::new(0x42005E);
    pub const Q_TAG: Tag = Tag::new(0x420071);
    pub const PRIME_EXPONENT_P_TAG: Tag = Tag::new(0x420060);
    pub const PRIME_EXPONENT_Q_TAG: Tag = Tag::new(0x420061);
    pub const CRT_COEFFICIENT_TAG: Tag = Tag::new(0x420027);

    pub fn fast_scan(scanner: &mut FastScanner<'_>) -> Result<Self, FastScanError> {
        let mut scanner = scanner.scan_struct(Self::TAG)?;
        let modulus = scanner.scan_big_int(Self::MODULUS_TAG)?.into();
        let private_exponent = scanner.scan_opt_big_int(Self::PRIVATE_EXPONENT_TAG)?.map(Into::into);
        let public_exponent = scanner.scan_opt_big_int(Self::PUBLIC_EXPONENT_TAG)?.map(Into::into);
        let p = scanner.scan_opt_big_int(Self::P_TAG)?.map(Into::into);
        let q = scanner.scan_opt_big_int(Self::Q_TAG)?.map(Into::into);
        let prime_exponent_p = scanner.scan_opt_big_int(Self::PRIME_EXPONENT_P_TAG)?.map(Into::into);
        let prime_exponent_q = scanner.scan_opt_big_int(Self::PRIME_EXPONENT_Q_TAG)?.map(Into::into);
        let crt_coefficient = scanner.scan_opt_big_int(Self::CRT_COEFFICIENT_TAG)?.map(Into::into);
        scanner.finish()?;
        Ok(Self {
            modulus,
            private_exponent,
            public_exponent,
            p,
            q,
            prime_exponent_p,
            prime_exponent_q,
            crt_coefficient,
        })
    }

    pub fn format(&self, formatter: &mut Formatter<'_>) -> FormatResult {
        let mut formatter = formatter.format_struct(Self::TAG)?;
        formatter.format_big_int(Self::MODULUS_TAG, &self.modulus)?;
        if let Some(private_exponent) = &self.private_exponent {
            formatter.format_big_int(Self::PRIVATE_EXPONENT_TAG, private_exponent)?;
        }
        if let Some(public_exponent) = &self.public_exponent {
            formatter.format_big_int(Self::PUBLIC_EXPONENT_TAG, public_exponent)?;
        }
        if let Some(p) = &self.p {
            formatter.format_big_int(Self::P_TAG, p)?;
        }
        if let Some(q) = &self.q {
            formatter.format_big_int(Self::Q_TAG, q)?;
        }
        if let Some(prime_exponent_p) = &self.prime_exponent_p {
            formatter.format_big_int(Self::PRIME_EXPONENT_P_TAG, prime_exponent_p)?;
        }
        if let Some(prime_exponent_q) = &self.prime_exponent_q {
            formatter.format_big_int(Self::PRIME_EXPONENT_Q_TAG, prime_exponent_q)?;
        }
        if let Some(crt_coefficient) = &self.crt_coefficient {
            formatter.format_big_int(Self::CRT_COEFFICIENT_TAG, crt_coefficient)?;
        }
        Ok(formatter.finish())
    }
}

/// See KMIP 1.0 section 2.1.7.5 [Transparent RSA Public Key](https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581161).
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename = "0x420043")]
pub struct TransparentRSAPublicKey {
    #[serde(rename = "0x420052", with = "serde_bytes")]
    pub modulus: Vec<u8>,

    #[serde(rename = "0x42006C", with = "serde_bytes")]
    pub public_exponent: Vec<u8>,
}

impl TransparentRSAPublicKey {
    pub const TAG: Tag = Tag::new(0x420043);
    pub const MODULUS_TAG: Tag = Tag::new(0x420052);
    pub const PUBLIC_EXPONENT_TAG: Tag = Tag::new(0x42006C);

    pub fn fast_scan(scanner: &mut FastScanner<'_>) -> Result<Self, FastScanError> {
        let mut scanner = scanner.scan_struct(Self::TAG)?;
        let modulus = scanner.scan_big_int(Self::MODULUS_TAG)?.into();
        let public_exponent = scanner.scan_big_int(Self::PUBLIC_EXPONENT_TAG)?.into();
        scanner.finish()?;
        Ok(Self {
            modulus,
            public_exponent,
        })
    }

    pub fn format(&self, formatter: &mut Formatter<'_>) -> FormatResult {
        let mut formatter = formatter.format_struct(Self::TAG)?;
        formatter.format_big_int(Self::MODULUS_TAG, &self.modulus)?;
        formatter.format_big_int(Self::PUBLIC_EXPONENT_TAG, &self.public_exponent)?;
        Ok(formatter.finish())
    }
}

/// See KMIP 1.0 section 2.1.7.6 [Transparent DH Private Key](https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581161).
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename = "0x420043")]
pub struct TransparentDHPrivateKey {
    #[serde(with = "serde_bytes")]
    pub p: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub q: Option<Vec<u8>>,
    #[serde(with = "serde_bytes")]
    pub g: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub j: Option<Vec<u8>>,
    #[serde(with = "serde_bytes")]
    pub x: Vec<u8>,
}

impl TransparentDHPrivateKey {
    pub const TAG: Tag = Tag::new(0x420043);
    pub const P_TAG: Tag = Tag::new(0x42005E);
    pub const Q_TAG: Tag = Tag::new(0x420071);
    pub const G_TAG: Tag = Tag::new(0x420037);
    pub const J_TAG: Tag = Tag::new(0x42003E);
    pub const X_TAG: Tag = Tag::new(0x42009F);

    pub fn fast_scan(scanner: &mut FastScanner<'_>) -> Result<Self, FastScanError> {
        let mut scanner = scanner.scan_struct(Self::TAG)?;
        let p = scanner.scan_big_int(Self::P_TAG)?.into();
        let q = scanner.scan_opt_big_int(Self::Q_TAG)?.map(Into::into);
        let g = scanner.scan_big_int(Self::G_TAG)?.into();
        let j = scanner.scan_opt_big_int(Self::J_TAG)?.map(Into::into);
        let x = scanner.scan_big_int(Self::X_TAG)?.into();
        scanner.finish()?;
        Ok(Self { p, q, g, j, x })
    }

    pub fn format(&self, formatter: &mut Formatter<'_>) -> FormatResult {
        let mut formatter = formatter.format_struct(Self::TAG)?;
        formatter.format_big_int(Self::P_TAG, &self.p)?;
        if let Some(q) = &self.q {
            formatter.format_big_int(Self::Q_TAG, q)?;
        }
        formatter.format_big_int(Self::G_TAG, &self.g)?;
        if let Some(j) = &self.j {
            formatter.format_big_int(Self::J_TAG, j)?;
        }
        formatter.format_big_int(Self::X_TAG, &self.x)?;
        Ok(formatter.finish())
    }
}

/// See KMIP 1.0 section 2.1.7.7 [Transparent DH Public Key](https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581161).
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename = "0x420043")]
pub struct TransparentDHPublicKey {
    #[serde(with = "serde_bytes")]
    pub p: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub q: Option<Vec<u8>>,
    #[serde(with = "serde_bytes")]
    pub g: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub j: Option<Vec<u8>>,
    #[serde(with = "serde_bytes")]
    pub y: Vec<u8>,
}

impl TransparentDHPublicKey {
    pub const TAG: Tag = Tag::new(0x420043);
    pub const P_TAG: Tag = Tag::new(0x42005E);
    pub const Q_TAG: Tag = Tag::new(0x420071);
    pub const G_TAG: Tag = Tag::new(0x420037);
    pub const J_TAG: Tag = Tag::new(0x42003E);
    pub const Y_TAG: Tag = Tag::new(0x4200A0);

    pub fn fast_scan(scanner: &mut FastScanner<'_>) -> Result<Self, FastScanError> {
        let mut scanner = scanner.scan_struct(Self::TAG)?;
        let p = scanner.scan_big_int(Self::P_TAG)?.into();
        let q = scanner.scan_opt_big_int(Self::Q_TAG)?.map(Into::into);
        let g = scanner.scan_big_int(Self::G_TAG)?.into();
        let j = scanner.scan_opt_big_int(Self::J_TAG)?.map(Into::into);
        let y = scanner.scan_big_int(Self::Y_TAG)?.into();
        scanner.finish()?;
        Ok(Self { p, q, g, j, y })
    }

    pub fn format(&self, formatter: &mut Formatter<'_>) -> FormatResult {
        let mut formatter = formatter.format_struct(Self::TAG)?;
        formatter.format_big_int(Self::P_TAG, &self.p)?;
        if let Some(q) = &self.q {
            formatter.format_big_int(Self::Q_TAG, q)?;
        }
        formatter.format_big_int(Self::G_TAG, &self.g)?;
        if let Some(j) = &self.j {
            formatter.format_big_int(Self::J_TAG, j)?;
        }
        formatter.format_big_int(Self::Y_TAG, &self.y)?;
        Ok(formatter.finish())
    }
}

/// See KMIP 1.2 section 2.1.10 [Data](https://docs.oasis-open.org/kmip/spec/v1.2/os/kmip-spec-v1.2-os.html#_Toc395776391).
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename = "Transparent:0x4200C2")]
pub struct Data(#[serde(with = "serde_bytes")] pub Vec<u8>);

impl_ttlv_serde!(bytes Data as 0x4200C2);

/// See KMIP 1.2 section 2.1.11 [Data Length](https://docs.oasis-open.org/kmip/spec/v1.2/os/kmip-spec-v1.2-os.html#_Toc409613467).
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename = "Transparent:0x4200C4")]
pub struct DataLength(pub i32);

impl_ttlv_serde!(int DataLength as 0x4200C4);

/// See KMIP 1.0 section 3.1 [Unique Identifier](https://docs.oasis-open.org/kmip/spec/v1.2/os/kmip-spec-v1.2-os.html#_Toc409613482).
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

impl_ttlv_serde!(text UniqueIdentifier as 0x420094);

/// See KMIP 1.0 section 3.2 [Name](https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581174).
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename = "Transparent:0x420055")]
pub struct NameValue(pub String);

impl std::fmt::Display for NameValue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl FromStr for NameValue {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Self(s.to_string()))
    }
}

impl_ttlv_serde!(text NameValue as 0x420055);

/// See KMIP 1.0 section 3.3 [Object Type](https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581175).
#[derive(Clone, Copy, Debug, Deserialize, Serialize, Display, PartialEq, Eq, Ordinalize)]
#[serde(rename = "0x420057")]
#[non_exhaustive]
#[repr(u32)]
pub enum ObjectType {
    // KMIP 1.0 and 1.1 variants
    #[serde(rename = "0x00000001")]
    Certificate = 1,

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

    // KMIP 1.2 variants
    #[serde(rename = "0x00000009")]
    PGPKey,
}

impl_ttlv_serde!(enum ObjectType as 0x420057);

/// See KMIP 1.0 section 3.4 [Cryptographic Algorithm Enumeration](https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581176).
#[derive(Clone, Copy, Debug, Deserialize, Serialize, Display, PartialEq, Eq, Ordinalize)]
#[serde(rename = "0x420028")]
#[non_exhaustive]
#[allow(non_camel_case_types)]
#[repr(u32)]
pub enum CryptographicAlgorithm {
    #[serde(rename = "0x00000001")]
    DES = 1,

    #[serde(rename = "0x00000002")]
    TRIPLE_DES,

    #[serde(rename = "0x00000003")]
    AES,

    #[serde(rename = "0x00000004")]
    RSA,

    #[serde(rename = "0x00000005")]
    DSA,

    #[serde(rename = "0x00000006")]
    ECDSA,

    #[serde(rename = "0x00000007")]
    HMAC_SHA1,

    #[serde(rename = "0x00000008")]
    HMAC_SHA224,

    #[serde(rename = "0x00000009")]
    HMAC_SHA256,

    #[serde(rename = "0x0000000A")]
    HMAC_SHA384,

    #[serde(rename = "0x0000000B")]
    HMAC_SHA512,

    #[serde(rename = "0x0000000C")]
    HMAC_MD5,

    #[serde(rename = "0x0000000D")]
    DH,

    #[serde(rename = "0x0000000E")]
    ECDH,

    #[serde(rename = "0x0000000F")]
    ECMQV,

    #[serde(rename = "0x00000010")]
    Blowfish,

    #[serde(rename = "0x00000011")]
    Camellia,

    #[serde(rename = "0x00000012")]
    CAST5,

    #[serde(rename = "0x00000013")]
    IDEA,

    #[serde(rename = "0x00000014")]
    MARS,

    #[serde(rename = "0x00000015")]
    RC2,

    #[serde(rename = "0x00000016")]
    RC4,

    #[serde(rename = "0x00000017")]
    RC5,

    #[serde(rename = "0x00000018")]
    SKIPJACK,

    #[serde(rename = "0x00000019")]
    Twofish,

    #[serde(rename = "0x0000001A")]
    EC,
}

impl_ttlv_serde!(enum CryptographicAlgorithm as 0x420028);

/// See KMIP 1.0 section 3.5 [Cryptographic Length](https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581177).
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename = "Transparent:0x42002A")]
pub struct CryptographicLength(pub i32);

impl_ttlv_serde!(int CryptographicLength as 0x42002A);

/// See KMIP 1.0 section 3.6 [Cryptographic Parameters](https://docs.oasis-open.org/kmip/spec/v1.2/os/kmip-spec-v1.2-os.html#_Toc409613487).
#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename = "0x42002B")]
#[rustfmt::skip]
pub struct CryptographicParameters {
    #[serde(rename = "0x420011", skip_serializing_if = "Option::is_none")]
    pub block_cipher_mode: Option<BlockCipherMode>,
    
    #[serde(rename = "0x42005F", skip_serializing_if = "Option::is_none")]
    pub padding_method: Option<PaddingMethod>,
    
    #[serde(rename = "0x420038", skip_serializing_if = "Option::is_none")]
    pub hashing_algorithm: Option<HashingAlgorithm>,
    
    #[serde(rename = "0x420083", skip_serializing_if = "Option::is_none")]
    pub key_role_type: Option<KeyRoleType>,
    
    #[serde(rename = "0x4200AE", skip_serializing_if = "Option::is_none")]
    pub digital_signature_algorithm: Option<DigitalSignatureAlgorithm>, // KMIP 1.2
    
    #[serde(rename = "0x420028", skip_serializing_if = "Option::is_none")]
    pub cryptographic_algorithm: Option<CryptographicAlgorithm>, // KMIP 1.2
    
    #[serde(rename = "0x4200C5", skip_serializing_if = "Option::is_none")]
    pub random_iv: Option<RandomIV>, // KMIP 1.2
    
    #[serde(rename = "0x4200CD", skip_serializing_if = "Option::is_none")]
    pub iv_length: Option<IVLength>, // KMIP 1.2
    
    #[serde(rename = "0x4200CE", skip_serializing_if = "Option::is_none")]
    pub tag_length: Option<TagLength>, // KMIP 1.2
    
    #[serde(rename = "0x4200CF", skip_serializing_if = "Option::is_none")]
    pub fixed_field_length: Option<FixedFieldLength>, // KMIP 1.2
    
    #[serde(rename = "0x4200D2", skip_serializing_if = "Option::is_none")]
    pub invocation_field_length: Option<InvocationFieldLength>, // KMIP 1.2
    
    #[serde(rename = "0x4200D0", skip_serializing_if = "Option::is_none")]
    pub counter_length: Option<CounterLength>, // KMIP 1.2
    
    #[serde(rename = "0x4200D1", skip_serializing_if = "Option::is_none")]
    pub initial_counter_value: Option<InitialCounterValue>, // KMIP 1.2
    
}

impl CryptographicParameters {
    pub fn with_block_cipher_mode(self, value: BlockCipherMode) -> Self {
        Self {
            block_cipher_mode: Some(value),
            ..self
        }
    }

    pub fn with_padding_method(self, value: PaddingMethod) -> Self {
        Self {
            padding_method: Some(value),
            ..self
        }
    }

    pub fn with_hashing_algorithm(self, value: HashingAlgorithm) -> Self {
        Self {
            hashing_algorithm: Some(value),
            ..self
        }
    }

    pub fn with_key_role_type(self, value: KeyRoleType) -> Self {
        Self {
            key_role_type: Some(value),
            ..self
        }
    }

    pub fn with_digital_signature_algorithm(self, value: DigitalSignatureAlgorithm) -> Self {
        Self {
            digital_signature_algorithm: Some(value),
            ..self
        }
    }

    pub fn with_cryptographic_algorithm(self, value: CryptographicAlgorithm) -> Self {
        Self {
            cryptographic_algorithm: Some(value),
            ..self
        }
    }

    pub fn with_random_iv(self, value: RandomIV) -> Self {
        Self {
            random_iv: Some(value),
            ..self
        }
    }

    pub fn with_iv_length(self, value: IVLength) -> Self {
        Self {
            iv_length: Some(value),
            ..self
        }
    }

    pub fn with_tag_length(self, value: TagLength) -> Self {
        Self {
            tag_length: Some(value),
            ..self
        }
    }

    pub fn with_fixed_field_length(self, value: FixedFieldLength) -> Self {
        Self {
            fixed_field_length: Some(value),
            ..self
        }
    }

    pub fn with_invocation_field_length(self, value: InvocationFieldLength) -> Self {
        Self {
            invocation_field_length: Some(value),
            ..self
        }
    }

    pub fn with_counter_length(self, value: CounterLength) -> Self {
        Self {
            counter_length: Some(value),
            ..self
        }
    }

    pub fn with_initial_counter_value(self, value: InitialCounterValue) -> Self {
        Self {
            initial_counter_value: Some(value),
            ..self
        }
    }
}

impl_ttlv_serde!(struct CryptographicParameters {
    #[option] block_cipher_mode: BlockCipherMode,    
    #[option] padding_method: PaddingMethod,    
    #[option] hashing_algorithm: HashingAlgorithm,    
    #[option] key_role_type: KeyRoleType,    
    #[option] digital_signature_algorithm: DigitalSignatureAlgorithm,
    #[option] cryptographic_algorithm: CryptographicAlgorithm,
    #[option] random_iv: RandomIV,
    #[option] iv_length: IVLength,
    #[option] tag_length: TagLength,
    #[option] fixed_field_length: FixedFieldLength,
    #[option] invocation_field_length: InvocationFieldLength,
    #[option] counter_length: CounterLength,
    #[option] initial_counter_value: InitialCounterValue,
} as 0x42002B);

impl From<CryptographicParameters> for AttributeValue {
    fn from(params: CryptographicParameters) -> Self {
        AttributeValue::CryptographicParameters(
            params.block_cipher_mode,
            params.padding_method,
            params.hashing_algorithm,
            params.key_role_type,
            params.digital_signature_algorithm,
            params.cryptographic_algorithm,
            params.random_iv,
            params.iv_length,
            params.tag_length,
            params.fixed_field_length,
            params.invocation_field_length,
            params.counter_length,
            params.initial_counter_value,
        )
    }
}

/// See KMIP 1.2 section 3.6 [Cryptographic Parameters](https://docs.oasis-open.org/kmip/spec/v1.2/os/kmip-spec-v1.2-os.html#_Toc409613487).
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename = "Transparent:0x4200C5")]
pub struct RandomIV(pub bool);

impl_ttlv_serde!(bool RandomIV as 0x4200C5);

/// See KMIP 1.2 section 3.6 [Cryptographic Parameters](https://docs.oasis-open.org/kmip/spec/v1.2/os/kmip-spec-v1.2-os.html#_Toc409613487).
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename = "Transparent:0x4200CD")]
pub struct IVLength(pub i32);

impl_ttlv_serde!(int IVLength as 0x4200CD);

/// See KMIP 1.2 section 3.6 [Cryptographic Parameters](https://docs.oasis-open.org/kmip/spec/v1.2/os/kmip-spec-v1.2-os.html#_Toc409613487).
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename = "Transparent:0x4200CE")]
pub struct TagLength(pub i32);

impl_ttlv_serde!(int TagLength as 0x4200CE);

/// See KMIP 1.2 section 3.6 [Cryptographic Parameters](https://docs.oasis-open.org/kmip/spec/v1.2/os/kmip-spec-v1.2-os.html#_Toc409613487).
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename = "Transparent:0x4200CF")]
pub struct FixedFieldLength(pub i32);

impl_ttlv_serde!(int FixedFieldLength as 0x4200CF);

/// See KMIP 1.2 section 3.6 [Cryptographic Parameters](https://docs.oasis-open.org/kmip/spec/v1.2/os/kmip-spec-v1.2-os.html#_Toc409613487).
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename = "Transparent:0x4200D2")]
pub struct InvocationFieldLength(pub i32);

impl_ttlv_serde!(int InvocationFieldLength as 0x4200D2);

/// See KMIP 1.2 section 3.6 [Cryptographic Parameters](https://docs.oasis-open.org/kmip/spec/v1.2/os/kmip-spec-v1.2-os.html#_Toc409613487).
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename = "Transparent:0x4200D0")]
pub struct CounterLength(pub i32);

impl_ttlv_serde!(int CounterLength as 0x4200D0);

/// See KMIP 1.2 section 3.6 [Cryptographic Parameters](https://docs.oasis-open.org/kmip/spec/v1.2/os/kmip-spec-v1.2-os.html#_Toc409613487).
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename = "Transparent:0x4200D1")]
pub struct InitialCounterValue(pub i32);

impl_ttlv_serde!(int InitialCounterValue as 0x4200D1);

/// See KMIP 1.0 section 3.7 [Cryptographic Domain Parameters](https://docs.oasis-open.org/kmip/spec/v1.2/os/kmip-spec-v1.2-os.html#_Toc409613488).
#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename = "0x420029")]
#[rustfmt::skip]
pub struct CryptographicDomainParameters {
    #[serde(skip_serializing_if = "Option::is_none")] pub q_length: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")] pub recommended_curve: Option<RecommendedCurve>,
}

impl CryptographicDomainParameters {
    pub fn with_q_length(self, value: i32) -> Self {
        Self {
            q_length: Some(value),
            ..self
        }
    }

    pub fn with_recommended_curve(self, value: RecommendedCurve) -> Self {
        Self {
            recommended_curve: Some(value),
            ..self
        }
    }
}

impl CryptographicDomainParameters {
    pub const TAG: Tag = Tag::new(0x420029);
    pub const Q_LENGTH_TAG: Tag = Tag::new(0x420073);

    pub fn fast_scan(scanner: &mut FastScanner<'_>) -> Result<Self, FastScanError> {
        Self::fast_scan_with(scanner, Self::TAG)
    }

    pub fn fast_scan_with(scanner: &mut FastScanner<'_>, tag: Tag) -> Result<Self, FastScanError> {
        let mut scanner = scanner.scan_struct(tag)?;
        let q_length = scanner.scan_opt_int(Self::Q_LENGTH_TAG)?;
        let recommended_curve = RecommendedCurve::fast_scan_opt(&mut scanner)?;
        scanner.finish()?;
        Ok(Self {
            q_length,
            recommended_curve,
        })
    }

    pub fn format(&self, formatter: &mut Formatter<'_>) -> FormatResult {
        self.format_with(formatter, Self::TAG)
    }

    pub fn format_with(&self, formatter: &mut Formatter<'_>, tag: Tag) -> FormatResult {
        let mut formatter = formatter.format_struct(tag)?;
        if let Some(q_length) = self.q_length {
            formatter.format_int(Self::Q_LENGTH_TAG, q_length)?;
        }
        if let Some(recommended_curve) = &self.recommended_curve {
            recommended_curve.format(&mut formatter)?;
        }
        Ok(formatter.finish())
    }
}

impl From<CryptographicDomainParameters> for AttributeValue {
    fn from(params: CryptographicDomainParameters) -> Self {
        AttributeValue::CryptographicDomainParameters(params.q_length, params.recommended_curve)
    }
}

bitflags::bitflags! {
    /// See KMIP 1.0 section 3.14 [Cryptographic Usage Mask](https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581188).
    #[derive(Clone, Copy, PartialEq, Eq)]
    pub struct CryptographicUsageMask: i32 {
        const Sign                            = 0x00000001;
        const Verify                          = 0x00000002;
        const Encrypt                         = 0x00000004;
        const Decrypt                         = 0x00000008;
        const WrapKey                         = 0x00000010;
        const UnwrapKey                       = 0x00000020;
        const Export                          = 0x00000040;
        const MacGenerate                     = 0x00000080;
        const MacVerify                       = 0x00000100;
        const DeriveKey                       = 0x00000200;
        const ContentCommitmentNonRepudiation = 0x00000400;
        const KeyAgreement                    = 0x00000800;
        const CertificateSign                 = 0x00001000;
        const CrlSign                         = 0x00002000;
        const GenerateCryptogram              = 0x00004000;
        const ValidateCryptogram              = 0x00008000;
        const TranslateEncrypt                = 0x00010000;
        const TranslateDecrypt                = 0x00020000;
        const TranslateWrap                   = 0x00040000;
        const TranslateUnwrap                 = 0x00080000;

        const _ = !0;
    }
}

impl CryptographicUsageMask {
    pub const TAG: Tag = Tag::new(0x42002C);

    pub fn fast_scan(scanner: &mut FastScanner<'_>) -> Result<Self, FastScanError> {
        Self::fast_scan_with(scanner, Self::TAG)
    }

    pub fn fast_scan_with(scanner: &mut FastScanner<'_>, tag: Tag) -> Result<Self, FastScanError> {
        scanner.scan_int(tag).map(Self::from_bits_retain)
    }

    pub fn fast_scan_opt(scanner: &mut FastScanner<'_>) -> Result<Option<Self>, FastScanError> {
        Self::fast_scan_opt_with(scanner, Self::TAG)
    }

    pub fn fast_scan_opt_with(scanner: &mut FastScanner<'_>, tag: Tag) -> Result<Option<Self>, FastScanError> {
        scanner.scan_opt_int(tag).map(|s| s.map(Self::from_bits_retain))
    }

    pub fn format(&self, formatter: &mut Formatter<'_>) -> FormatResult {
        self.format_with(formatter, Self::TAG)
    }

    pub fn format_with(&self, formatter: &mut Formatter<'_>, tag: Tag) -> FormatResult {
        formatter.format_int(tag, self.bits())
    }
}

/// See KMIP 1.0 section 3.24 [Compromise Occurrence Date](https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581198).
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename = "Transparent:0x420021")]
pub struct CompromiseOccurrenceDate(pub u64);

impl_ttlv_serde!(date_time CompromiseOccurrenceDate as 0x420021);

/// See KMIP 1.0 section 3.26 [Revocation Reason](https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581200).
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename = "Transparent:0x420080")]
pub struct RevocationMessage(pub String);

impl_ttlv_serde!(text RevocationMessage as 0x420080);

/// See KMIP 1.0 section 3.29 [Linked Object Identifier](https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581203).
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename = "Transparent:0x42004C")]
pub struct LinkedObjectIdentifier(pub String);

impl_ttlv_serde!(text LinkedObjectIdentifier as 0x42004C);

/// See KMIP 1.0 section 3.30 [Application Namespace](https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581204).
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename = "Transparent:0x420003")]
pub struct ApplicationNamespace(pub String);

impl_ttlv_serde!(text ApplicationNamespace as 0x420003);

/// See KMIP 1.0 section 3.30 [Application Data](https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581204).
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename = "Transparent:0x420002")]
pub struct ApplicationData(pub String);

impl_ttlv_serde!(text ApplicationData as 0x420002);

/// See KMIP 1.0 section 6.4 [Unique Batch Item ID](https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581242).
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename = "Transparent:0x420093")]
pub struct UniqueBatchItemID(#[serde(with = "serde_bytes")] pub Vec<u8>);

impl PartialEq<Vec<u8>> for &UniqueBatchItemID {
    fn eq(&self, other: &Vec<u8>) -> bool {
        &self.0 == other
    }
}

impl_ttlv_serde!(bytes UniqueBatchItemID as 0x420093);

/// See KMIP 1.0 section 9.1.3.2.2 [Key Compression Type Enumeration](https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Ref241603856).
#[derive(Clone, Copy, Debug, Deserialize, Serialize, Display, PartialEq, Eq, Ordinalize)]
#[serde(rename = "0x420041")]
#[non_exhaustive]
#[repr(u32)]
pub enum KeyCompressionType {
    #[serde(rename = "0x00000001")]
    ECPUblicKeyTypeUncompressed = 1,

    #[serde(rename = "0x00000002")]
    ECPUblicKeyTypeX962CompressedPrime,

    #[serde(rename = "0x00000003")]
    ECPUblicKeyTypeX962CompressedChar2,

    #[serde(rename = "0x00000004")]
    ECPUblicKeyTypeX962Hybrid,
}

impl_ttlv_serde!(enum KeyCompressionType as 0x420041);

/// See KMIP 1.0 section 9.1.3.2.3 [Key Format Type Enumeration](https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Ref241992670).
#[derive(Clone, Copy, Debug, Deserialize, Serialize, Display, PartialEq, Eq, Ordinalize)]
#[serde(rename = "0x420042")]
#[non_exhaustive]
#[repr(u32)]
pub enum KeyFormatType {
    #[serde(rename = "0x00000001")]
    Raw = 1,

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

impl_ttlv_serde!(enum KeyFormatType as 0x420042);

/// See KMIP 1.0 section 9.1.3.2.5 [Padding Method Enumeration](https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc236497874).
#[derive(Clone, Copy, Debug, Deserialize, Serialize, Display, PartialEq, Eq, Ordinalize)]
#[serde(rename = "0x420075")]
#[non_exhaustive]
#[allow(non_camel_case_types)]
#[repr(u32)]
pub enum RecommendedCurve {
    #[serde(rename = "0x00000001")]
    P_192 = 1,

    #[serde(rename = "0x00000002")]
    K_163,

    #[serde(rename = "0x00000003")]
    B_163,

    #[serde(rename = "0x00000004")]
    P_224,

    #[serde(rename = "0x00000005")]
    K_233,

    #[serde(rename = "0x00000006")]
    B_233,

    #[serde(rename = "0x00000007")]
    P_256,

    #[serde(rename = "0x00000008")]
    K_283,

    #[serde(rename = "0x00000009")]
    B_283,

    #[serde(rename = "0x0000000A")]
    P_384,

    #[serde(rename = "0x0000000B")]
    K_409,

    #[serde(rename = "0x0000000C")]
    B_409,

    #[serde(rename = "0x0000000D")]
    P_521,

    #[serde(rename = "0x0000000E")]
    K_571,

    #[serde(rename = "0x0000000F")]
    B_571,
}

impl_ttlv_serde!(enum RecommendedCurve as 0x420075);

/// See KMIP 1.0 section 9.1.3.2.6 [Certificate Type Enumeration](https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Ref241994296).
#[derive(Clone, Copy, Debug, Deserialize, Serialize, Display, PartialEq, Eq, Ordinalize)]
#[serde(rename = "0x42001D")]
#[non_exhaustive]
#[repr(u32)]
pub enum CertificateType {
    #[serde(rename = "0x00000001")]
    X509 = 1,

    #[serde(rename = "0x00000002")]
    PGP,
}

impl_ttlv_serde!(enum CertificateType as 0x42001D);

/// See KMIP 1.2 section 9.1.3.2.7 [Digital Signature Algorithm Enumeration](https://docs.oasis-open.org/kmip/spec/v1.2/os/kmip-spec-v1.2-os.html#_Ref306812211).
#[derive(Clone, Copy, Debug, Deserialize, Serialize, Display, PartialEq, Eq, Ordinalize)]
#[serde(rename = "0x4200AE")]
#[non_exhaustive]
#[allow(non_camel_case_types)]
#[repr(u32)]
pub enum DigitalSignatureAlgorithm {
    #[serde(rename = "0x00000001")]
    MD2WithRSAEncryption_PKCS1_v1_5 = 1,

    #[serde(rename = "0x00000002")]
    MD5WithRSAEncryption_PKCS1_v1_5,

    #[serde(rename = "0x00000003")]
    SHA1WithRSAEncryption_PKCS1_v1_5,

    #[serde(rename = "0x00000004")]
    SHA224WithRSAEncryption_PKCS1_v1_5,

    #[serde(rename = "0x00000005")]
    SHA256WithRSAEncryption_PKCS1_v1_5,

    #[serde(rename = "0x00000006")]
    SHA384WithRSAEncryption_PKCS1_v1_5,

    #[serde(rename = "0x00000007")]
    SHA512WithRSAEncryption_PKCS1_v1_5,

    #[serde(rename = "0x00000008")]
    RSASSA_PSS_PKCS1_v1_5,

    #[serde(rename = "0x00000009")]
    DSAWithSHA1,

    #[serde(rename = "0x0000000A")]
    DSAWithSHA224,

    #[serde(rename = "0x0000000B")]
    DSAWithSHA256,

    #[serde(rename = "0x0000000C")]
    ECDSAWithSHA1,

    #[serde(rename = "0x0000000D")]
    ECDSAWithSHA224,

    #[serde(rename = "0x0000000E")]
    ECDSAWithSHA256,

    #[serde(rename = "0x0000000F")]
    ECDSAWithSHA384,

    #[serde(rename = "0x00000010")]
    ECDSAWithSHA512,
}

impl_ttlv_serde!(enum DigitalSignatureAlgorithm as 0x4200AE);

/// See KMIP 1.0 section 9.1.3.2.10 [Name Type Enumeration](https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262582060).
#[derive(Clone, Copy, Debug, Deserialize, Serialize, Display, PartialEq, Eq, Ordinalize)]
#[serde(rename = "0x420054")]
#[non_exhaustive]
#[repr(u32)]
pub enum NameType {
    #[serde(rename = "0x00000001")]
    UninterpretedTextString = 1,

    #[serde(rename = "0x00000002")]
    URI,
}

impl_ttlv_serde!(enum NameType as 0x420054);

/// See KMIP 1.0 section 9.1.3.2.13 [Block Cipher Mode Enumeration](https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc236497881).
#[derive(Clone, Copy, Debug, Deserialize, Serialize, Display, PartialEq, Eq, Ordinalize)]
#[serde(rename = "0x420011")]
#[non_exhaustive]
#[allow(non_camel_case_types)]
#[repr(u32)]
pub enum BlockCipherMode {
    #[serde(rename = "0x00000001")]
    CBC = 1,

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

impl_ttlv_serde!(enum BlockCipherMode as 0x420011);

/// See KMIP 1.0 section 9.1.3.2.14 [Padding Method Enumeration](https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc236497883).
#[derive(Clone, Copy, Debug, Deserialize, Serialize, Display, PartialEq, Eq, Ordinalize)]
#[serde(rename = "0x42005F")]
#[non_exhaustive]
#[allow(non_camel_case_types)]
#[repr(u32)]
pub enum PaddingMethod {
    #[serde(rename = "0x00000001")]
    None = 1,

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

impl_ttlv_serde!(enum PaddingMethod as 0x42005F);

/// See KMIP 1.0 section 9.1.3.2.15 [Hashing Algorithm Enumeration](https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc236497883).
#[derive(Clone, Copy, Debug, Deserialize, Serialize, Display, PartialEq, Eq, Ordinalize)]
#[serde(rename = "0x420038")]
#[non_exhaustive]
#[allow(non_camel_case_types)]
#[repr(u32)]
pub enum HashingAlgorithm {
    #[serde(rename = "0x00000001")]
    MD2 = 1,

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

impl_ttlv_serde!(enum HashingAlgorithm as 0x420038);

/// See KMIP 1.0 section 9.1.3.2.15 [Key Role Type Enumeration](https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc236497884).
#[derive(Clone, Copy, Debug, Deserialize, Serialize, Display, PartialEq, Eq, Ordinalize)]
#[serde(rename = "0x420083")]
#[non_exhaustive]
#[allow(non_camel_case_types)]
#[repr(u32)]
pub enum KeyRoleType {
    #[serde(rename = "0x00000001")]
    BDK = 1,

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

impl_ttlv_serde!(enum KeyRoleType as 0x420083);

/// See KMIP 1.0 section 9.1.3.2.17 [State Enumeration](https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262582066).
#[derive(Clone, Copy, Debug, Deserialize, Serialize, Display, PartialEq, Eq, Ordinalize)]
#[serde(rename = "0x42008D")]
#[non_exhaustive]
#[repr(u32)]
pub enum State {
    #[serde(rename = "0x00000001")]
    PreActive = 1,

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

impl_ttlv_serde!(enum State as 0x42008D);

/// See KMIP 1.0 section 9.1.3.2.18 [Revocation Reason Code Enumeration](https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Ref241996204).
#[derive(Clone, Copy, Debug, Deserialize, Serialize, Display, PartialEq, Eq, Ordinalize)]
#[serde(rename = "0x420082")]
#[non_exhaustive]
#[repr(u32)]
pub enum RevocationReasonCode {
    #[serde(rename = "0x00000001")]
    Unspecified = 1,

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

impl_ttlv_serde!(enum RevocationReasonCode as 0x420082);

/// See KMIP 1.0 section 9.1.3.2.19 [Link Type Enumeration](https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262582069).
#[derive(Clone, Copy, Debug, Deserialize, Serialize, Display, PartialEq, Eq, Ordinalize)]
#[serde(rename = "0x42004B")]
#[non_exhaustive]
#[repr(u32)]
pub enum LinkType {
    #[serde(rename = "0x00000101")]
    CertificateLink = 0x101,

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

impl_ttlv_serde!(enum LinkType as 0x42004B);

/// See KMIP 1.0 section 9.1.3.2.26 [Operation Enumeration](https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc236497894).
#[derive(Clone, Copy, Debug, Deserialize, Serialize, Display, PartialEq, Eq, Ordinalize)]
#[serde(rename = "0x42005C")]
#[non_exhaustive]
#[repr(u32)]
pub enum Operation {
    // KMIP 1.0 operations
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

    // KMIP 1.1 operations
    #[serde(rename = "0x0000001D")]
    RekeyKeyPair,

    #[serde(rename = "0x0000001E")]
    DiscoverVersions,

    // KMIP 1.2 operations
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

impl_ttlv_serde!(enum Operation as 0x42005C);

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
