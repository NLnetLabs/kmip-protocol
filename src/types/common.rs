//! Rust types common to both serialization of KMIP requests and deserialization KMIP responses.
use std::convert::TryInto;
use std::fmt;
use std::str::FromStr;

use enum_ordinalize::Ordinalize;

use crate::ttlv::fast_scan::{FastScanError, FastScanner};
use crate::ttlv::format::Formatter;
use crate::ttlv::format::{FormatDone, FormatResult};
use crate::ttlv::types::Tag;
use crate::ttlv::{TagType, Type};
use crate::types::request::{Name, RevocationReason};

use super::impl_ttlv_serde;

/// See KMIP 1.0 section 2.1.1 [Attribute](https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581155).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AttributeName(pub String);

impl std::cmp::PartialEq<str> for AttributeName {
    fn eq(&self, other: &str) -> bool {
        self.0 == other
    }
}

impl_ttlv_serde!(text AttributeName as 0x42000A);

/// See KMIP 1.0 section 2.1.1 [Attribute](https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581155).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AttributeIndex(pub i32);

impl std::cmp::PartialEq<i32> for AttributeIndex {
    fn eq(&self, other: &i32) -> bool {
        &self.0 == other
    }
}

impl_ttlv_serde!(int AttributeIndex as 0x420009);

/// See KMIP 1.0 section 2.1.1 [Attribute](https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581155).
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum AttributeValue {
    /// See KMIP 1.0 section 3.1 Unique Identifier.
    UniqueIdentifier(UniqueIdentifier),

    /// See KMIP 1.0 section 3.2 Name.
    Name(Name),

    /// See KMIP 1.0 section 3.3 Object Type.
    ObjectType(ObjectType),

    /// See KMIP 1.0 section 3.4 Cryptographic Algorithm.
    CryptographicAlgorithm(CryptographicAlgorithm),

    /// See KMIP 1.0 section 3.5 Cryptographic Length.
    CryptographicLength(CryptographicLength),

    /// See KMIP 1.0 section 3.6 Cryptographic Parameters.
    CryptographicParameters(CryptographicParameters),

    /// See KMIP 1.0 section 3.7 Cryptographic Domain Parameters.
    CryptographicDomainParameters(CryptographicDomainParameters),

    /// See KMIP 1.0 section 3.8 Certificate Type.
    CertificateType(CertificateType),

    // See KMIP 1.0 section 3.9 Certificate Identifier.
    // Not implemented

    // See KMIP 1.0 section 3.10 Certificate Subject.
    // Not implemented

    // See KMIP 1.0 section 3.11 Certificate Issuer.
    // Not implemented

    // See KMIP 1.0 section 3.12 Digest.
    // Not implemented

    // See KMIP 1.0 section 3.13 Operation Policy Name.
    // Not implemented
    /// See KMIP 1.0 section 3.14 Cryptographic Usage Mask.
    CryptographicUsageMask(CryptographicUsageMask),

    // See KMIP 1.0 section 3.15 Lease Time.
    // Not implemented

    // See KMIP 1.0 section 3.16 Usage Limits.
    // Not implemented
    /// See KMIP 1.0 section 3.17 State.
    State(State),

    /// See KMIP 1.0 section 3.18 Initial Date.
    InitialDate(i64),

    /// See KMIP 1.0 section 3.19 Activation Date.
    ActivationDate(i64),

    // See KMIP 1.0 section 3.20 Process Start Date.
    // Not implemented
    /// See KMIP 1.0 section 3.21 Protect Stop Date.
    // Not implemented

    /// See KMIP 1.0 section 3.22 Deactivation Date.
    DeactivationDate(i64),

    /// See KMIP 1.0 section 3.23 Destroy Date.
    DestroyDate(i64),

    // See KMIP 1.0 section 3.24 Compromise Occurence Date.
    // Not implemented

    // See KMIP 1.0 section 3.25 Compromise Date.
    // Not implemented
    /// See KMIP 1.0 section 3.26 Revocation Reason.
    RevocationReason(RevocationReason),

    // See KMIP 1.0 section 3.27 Archive Date.
    // Not implemented
    /// See KMIP 1.0 section 3.28 Object Group.
    ObjectGroup(String),

    /// See KMIP 1.0 section 3.29 Link.
    Link(LinkType, LinkedObjectIdentifier),

    /// See KMIP 1.0 section 3.30 Application Specific Information.
    ApplicationSpecificInformation(ApplicationNamespace, ApplicationData),

    /// See KMIP 1.0 section 3.31 Contact Information.
    ContactInformation(String),
    // See KMIP 1.0 section 3.32 Last Change Date.
    // Not implemented
    /// See KMIP 1.0 section 3.33 Custom Attribute.
    CustomAttribute,
}

impl AttributeValue {
    pub const TAG: Tag = Tag::new(0x42000B);

    pub fn fast_scan(scanner: &mut FastScanner<'_>, name: &AttributeName) -> Result<Self, FastScanError> {
        match name.0.as_str() {
            "Unique Identifier" => UniqueIdentifier::fast_scan_with(scanner, Self::TAG).map(Self::UniqueIdentifier),

            "Name" => Name::fast_scan_with(scanner, Self::TAG).map(Self::Name),

            "Object Type" => ObjectType::fast_scan_with(scanner, Self::TAG).map(Self::ObjectType),

            "Cryptographic Algorithm" => {
                CryptographicAlgorithm::fast_scan_with(scanner, Self::TAG).map(Self::CryptographicAlgorithm)
            }

            "Cryptographic Length" => {
                CryptographicLength::fast_scan_with(scanner, Self::TAG).map(Self::CryptographicLength)
            }

            "Cryptographic Parameters" => {
                CryptographicParameters::fast_scan_with(scanner, Self::TAG).map(Self::CryptographicParameters)
            }

            "Cryptographic Domain Parameters" => CryptographicDomainParameters::fast_scan_with(scanner, Self::TAG)
                .map(Self::CryptographicDomainParameters),

            "Cryptographic Usage Mask" => {
                CryptographicUsageMask::fast_scan_with(scanner, Self::TAG).map(Self::CryptographicUsageMask)
            }

            "State" => State::fast_scan_with(scanner, Self::TAG).map(Self::State),

            "Initial Date" => scanner.scan_date_time(Self::TAG).map(Self::InitialDate),

            "Activation Date" => scanner.scan_date_time(Self::TAG).map(Self::ActivationDate),

            "Deactivation Date" => scanner.scan_date_time(Self::TAG).map(Self::DeactivationDate),

            "Destroy Date" => scanner.scan_date_time(Self::TAG).map(Self::DestroyDate),

            "Revocation Reason" => RevocationReason::fast_scan_with(scanner, Self::TAG).map(Self::RevocationReason),

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

            custom_attr if custom_attr.starts_with("x-") || custom_attr.starts_with("y-") => {
                let first_ttl = scanner.remaining()[0];
                let tt = TagType::parse(first_ttl[0..4].try_into().unwrap());
                match tt.r#type() {
                    Type::Structure => scanner.skip_struct(tt.tag())?,
                    Type::Integer => scanner.skip_int(tt.tag())?,
                    Type::LongInteger => scanner.skip_long_int(tt.tag())?,
                    Type::BigInteger => scanner.skip_big_int(tt.tag())?,
                    Type::Enumeration => scanner.skip_enum(tt.tag())?,
                    Type::Boolean => scanner.skip_bool(tt.tag())?,
                    Type::TextString => scanner.skip_text(tt.tag())?,
                    Type::ByteString => scanner.skip_bytes(tt.tag())?,
                    Type::DateTime => scanner.skip_date_time(tt.tag())?,
                    Type::Interval => scanner.skip_interval(tt.tag())?,
                }
                Ok(Self::CustomAttribute)
            }

            _ => Err(FastScanError::assert()),
        }
    }

    pub fn format(&self, formatter: &mut Formatter<'_>) -> FormatResult {
        match self {
            AttributeValue::UniqueIdentifier(v) => v.format_with(formatter, Self::TAG),
            AttributeValue::Name(v) => v.format_with(formatter, Self::TAG),
            AttributeValue::ObjectType(v) => v.format_with(formatter, Self::TAG),
            AttributeValue::CryptographicAlgorithm(v) => v.format_with(formatter, Self::TAG),
            AttributeValue::CryptographicLength(v) => v.format_with(formatter, Self::TAG),
            AttributeValue::CryptographicParameters(v) => v.format_with(formatter, Self::TAG),
            AttributeValue::CryptographicDomainParameters(v) => v.format_with(formatter, Self::TAG),
            AttributeValue::CertificateType(v) => v.format_with(formatter, Self::TAG),
            AttributeValue::CryptographicUsageMask(v) => v.format_with(formatter, Self::TAG),
            AttributeValue::State(v) => v.format_with(formatter, Self::TAG),
            AttributeValue::InitialDate(v) => formatter.format_date_time(Self::TAG, *v),
            AttributeValue::ActivationDate(v) => formatter.format_date_time(Self::TAG, *v),
            AttributeValue::DeactivationDate(v) => formatter.format_date_time(Self::TAG, *v),
            AttributeValue::DestroyDate(v) => formatter.format_date_time(Self::TAG, *v),
            AttributeValue::RevocationReason(v) => v.format_with(formatter, Self::TAG),
            AttributeValue::ObjectGroup(v) => formatter.format_text(Self::TAG, v),
            AttributeValue::Link(link_type, linked_object_id) => {
                let mut formatter = formatter.format_struct(Self::TAG)?;
                link_type.format(&mut formatter)?;
                linked_object_id.format(&mut formatter)?;
                Ok(formatter.finish())
            }
            AttributeValue::ApplicationSpecificInformation(namespace, data) => {
                let mut formatter = formatter.format_struct(Self::TAG)?;
                namespace.format(&mut formatter)?;
                data.format(&mut formatter)?;
                Ok(formatter.finish())
            }
            AttributeValue::ContactInformation(v) => formatter.format_text(Self::TAG, v),
            AttributeValue::CustomAttribute => Ok(FormatDone::assert()),
        }
    }
}

/// See KMIP 1.0 section 2.1.4 [Key Value](https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581158).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum KeyMaterial {
    Bytes(Vec<u8>),
    TransparentSymmetricKey(TransparentSymmetricKey),
    TransparentDSAPrivateKey(TransparentDSAPrivateKey),
    TransparentDSAPublicKey(TransparentDSAPublicKey),
    TransparentRSAPrivateKey(TransparentRSAPrivateKey),
    TransparentRSAPublicKey(TransparentRSAPublicKey),
    TransparentDHPrivateKey(TransparentDHPrivateKey),
    TransparentDHPublicKey(TransparentDHPublicKey),
    Structure(Vec<u8>), // All other transparent key types which we don't support yet
}

impl fmt::Display for KeyMaterial {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
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
            | KeyFormatType::X509
            | KeyFormatType::ECPrivateKey => scanner.scan_bytes(Self::TAG).map(|s| Self::Bytes(s.into())),

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
            // TODO: Handle this more elegantly.
            _ => {
                scanner.skip_struct(Self::TAG)?;
                Ok(Self::Structure(Vec::new()))
            }
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

            KeyMaterial::Structure(_) => unimplemented!(),
        }
    }
}

/// See KMIP 1.0 section 2.1.7.1 [Transparent Symmetric Key](https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581161).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TransparentSymmetricKey {
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
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TransparentDSAPrivateKey {
    pub p: Vec<u8>,
    pub q: Vec<u8>,
    pub g: Vec<u8>,
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
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TransparentDSAPublicKey {
    pub p: Vec<u8>,
    pub q: Vec<u8>,
    pub g: Vec<u8>,
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
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TransparentRSAPrivateKey {
    pub modulus: Vec<u8>,
    pub private_exponent: Option<Vec<u8>>,
    pub public_exponent: Option<Vec<u8>>,
    pub p: Option<Vec<u8>>,
    pub q: Option<Vec<u8>>,
    pub prime_exponent_p: Option<Vec<u8>>,
    pub prime_exponent_q: Option<Vec<u8>>,
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
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TransparentRSAPublicKey {
    pub modulus: Vec<u8>,
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
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TransparentDHPrivateKey {
    pub p: Vec<u8>,
    pub q: Option<Vec<u8>>,
    pub g: Vec<u8>,
    pub j: Option<Vec<u8>>,
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
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TransparentDHPublicKey {
    pub p: Vec<u8>,
    pub q: Option<Vec<u8>>,
    pub g: Vec<u8>,
    pub j: Option<Vec<u8>>,
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
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Data(pub Vec<u8>);

impl_ttlv_serde!(bytes Data as 0x4200C2);

/// See KMIP 1.2 section 2.1.11 [Data Length](https://docs.oasis-open.org/kmip/spec/v1.2/os/kmip-spec-v1.2-os.html#_Toc409613467).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DataLength(pub i32);

impl_ttlv_serde!(int DataLength as 0x4200C4);

/// See KMIP 1.0 section 3.1 [Unique Identifier](https://docs.oasis-open.org/kmip/spec/v1.2/os/kmip-spec-v1.2-os.html#_Toc409613482).
#[derive(Clone, Debug, PartialEq, Eq)]
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
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NameValue(pub String);

impl fmt::Display for NameValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
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
#[derive(Clone, Copy, Debug, PartialEq, Eq, Ordinalize)]
#[non_exhaustive]
#[repr(u32)]
pub enum ObjectType {
    // KMIP 1.0 and 1.1 variants
    Certificate = 1,
    SymmetricKey,
    PublicKey,
    PrivateKey,
    SplitKey,
    Template,
    SecretData,
    OpaqueObject,

    // KMIP 1.2 variants
    PGPKey,
}

impl fmt::Display for ObjectType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Certificate => "Certificate",
            Self::SymmetricKey => "SymmetricKey",
            Self::PublicKey => "PublicKey",
            Self::PrivateKey => "PrivateKey",
            Self::SplitKey => "SplitKey",
            Self::Template => "Template",
            Self::SecretData => "SecretData",
            Self::OpaqueObject => "OpaqueObject",
            Self::PGPKey => "PGPKey",
        })
    }
}

impl_ttlv_serde!(enum ObjectType as 0x420057);

/// See KMIP 1.0 section 3.4 [Cryptographic Algorithm Enumeration](https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581176).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Ordinalize)]
#[non_exhaustive]
#[allow(non_camel_case_types)]
#[repr(u32)]
pub enum CryptographicAlgorithm {
    DES = 1,
    TRIPLE_DES,
    AES,
    RSA,
    DSA,
    ECDSA,
    HMAC_SHA1,
    HMAC_SHA224,
    HMAC_SHA256,
    HMAC_SHA384,
    HMAC_SHA512,
    HMAC_MD5,
    DH,
    ECDH,
    ECMQV,
    Blowfish,
    Camellia,
    CAST5,
    IDEA,
    MARS,
    RC2,
    RC4,
    RC5,
    SKIPJACK,
    Twofish,
    EC,
}

impl_ttlv_serde!(enum CryptographicAlgorithm as 0x420028);

impl fmt::Display for CryptographicAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::DES => "DES",
            Self::TRIPLE_DES => "TRIPLE_DES",
            Self::AES => "AES",
            Self::RSA => "RSA",
            Self::DSA => "DSA",
            Self::ECDSA => "ECDSA",
            Self::HMAC_SHA1 => "HMAC_SHA1",
            Self::HMAC_SHA224 => "HMAC_SHA224",
            Self::HMAC_SHA256 => "HMAC_SHA256",
            Self::HMAC_SHA384 => "HMAC_SHA384",
            Self::HMAC_SHA512 => "HMAC_SHA512",
            Self::HMAC_MD5 => "HMAC_MD5",
            Self::DH => "DH",
            Self::ECDH => "ECDH",
            Self::ECMQV => "ECMQV",
            Self::Blowfish => "Blowfish",
            Self::Camellia => "Camellia",
            Self::CAST5 => "CAST5",
            Self::IDEA => "IDEA",
            Self::MARS => "MARS",
            Self::RC2 => "RC2",
            Self::RC4 => "RC4",
            Self::RC5 => "RC5",
            Self::SKIPJACK => "SKIPJACK",
            Self::Twofish => "Twofish",
            Self::EC => "EC",
        })
    }
}

/// See KMIP 1.0 section 3.5 [Cryptographic Length](https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581177).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CryptographicLength(pub i32);

impl_ttlv_serde!(int CryptographicLength as 0x42002A);

/// See KMIP 1.0 section 3.6 [Cryptographic Parameters](https://docs.oasis-open.org/kmip/spec/v1.2/os/kmip-spec-v1.2-os.html#_Toc409613487).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[rustfmt::skip]
pub struct CryptographicParameters {
    pub block_cipher_mode: Option<BlockCipherMode>,
    pub padding_method: Option<PaddingMethod>,
    pub hashing_algorithm: Option<HashingAlgorithm>,
    pub key_role_type: Option<KeyRoleType>,
    pub digital_signature_algorithm: Option<DigitalSignatureAlgorithm>, // KMIP 1.2
    pub cryptographic_algorithm: Option<CryptographicAlgorithm>, // KMIP 1.2
    pub random_iv: Option<RandomIV>, // KMIP 1.2
    pub iv_length: Option<IVLength>, // KMIP 1.2
    pub tag_length: Option<TagLength>, // KMIP 1.2
    pub fixed_field_length: Option<FixedFieldLength>, // KMIP 1.2
    pub invocation_field_length: Option<InvocationFieldLength>, // KMIP 1.2
    pub counter_length: Option<CounterLength>, // KMIP 1.2
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
        AttributeValue::CryptographicParameters(params)
    }
}

/// See KMIP 1.2 section 3.6 [Cryptographic Parameters](https://docs.oasis-open.org/kmip/spec/v1.2/os/kmip-spec-v1.2-os.html#_Toc409613487).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RandomIV(pub bool);

impl_ttlv_serde!(bool RandomIV as 0x4200C5);

/// See KMIP 1.2 section 3.6 [Cryptographic Parameters](https://docs.oasis-open.org/kmip/spec/v1.2/os/kmip-spec-v1.2-os.html#_Toc409613487).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IVLength(pub i32);

impl_ttlv_serde!(int IVLength as 0x4200CD);

/// See KMIP 1.2 section 3.6 [Cryptographic Parameters](https://docs.oasis-open.org/kmip/spec/v1.2/os/kmip-spec-v1.2-os.html#_Toc409613487).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TagLength(pub i32);

impl_ttlv_serde!(int TagLength as 0x4200CE);

/// See KMIP 1.2 section 3.6 [Cryptographic Parameters](https://docs.oasis-open.org/kmip/spec/v1.2/os/kmip-spec-v1.2-os.html#_Toc409613487).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FixedFieldLength(pub i32);

impl_ttlv_serde!(int FixedFieldLength as 0x4200CF);

/// See KMIP 1.2 section 3.6 [Cryptographic Parameters](https://docs.oasis-open.org/kmip/spec/v1.2/os/kmip-spec-v1.2-os.html#_Toc409613487).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InvocationFieldLength(pub i32);

impl_ttlv_serde!(int InvocationFieldLength as 0x4200D2);

/// See KMIP 1.2 section 3.6 [Cryptographic Parameters](https://docs.oasis-open.org/kmip/spec/v1.2/os/kmip-spec-v1.2-os.html#_Toc409613487).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CounterLength(pub i32);

impl_ttlv_serde!(int CounterLength as 0x4200D0);

/// See KMIP 1.2 section 3.6 [Cryptographic Parameters](https://docs.oasis-open.org/kmip/spec/v1.2/os/kmip-spec-v1.2-os.html#_Toc409613487).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InitialCounterValue(pub i32);

impl_ttlv_serde!(int InitialCounterValue as 0x4200D1);

/// See KMIP 1.0 section 3.7 [Cryptographic Domain Parameters](https://docs.oasis-open.org/kmip/spec/v1.2/os/kmip-spec-v1.2-os.html#_Toc409613488).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[rustfmt::skip]
pub struct CryptographicDomainParameters {
    pub q_length: Option<i32>,
    pub recommended_curve: Option<RecommendedCurve>,
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
        AttributeValue::CryptographicDomainParameters(params)
    }
}

bitflags::bitflags! {
    /// See KMIP 1.0 section 3.14 [Cryptographic Usage Mask](https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581188).
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
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
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CompromiseOccurrenceDate(pub u64);

impl_ttlv_serde!(date_time CompromiseOccurrenceDate as 0x420021);

/// See KMIP 1.0 section 3.26 [Revocation Reason](https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581200).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RevocationMessage(pub String);

impl_ttlv_serde!(text RevocationMessage as 0x420080);

/// See KMIP 1.0 section 3.29 [Linked Object Identifier](https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581203).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LinkedObjectIdentifier(pub String);

impl_ttlv_serde!(text LinkedObjectIdentifier as 0x42004C);

/// See KMIP 1.0 section 3.30 [Application Namespace](https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581204).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ApplicationNamespace(pub String);

impl_ttlv_serde!(text ApplicationNamespace as 0x420003);

/// See KMIP 1.0 section 3.30 [Application Data](https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581204).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ApplicationData(pub String);

impl_ttlv_serde!(text ApplicationData as 0x420002);

/// See KMIP 1.0 section 6.4 [Unique Batch Item ID](https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581242).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UniqueBatchItemID(pub Vec<u8>);

impl PartialEq<Vec<u8>> for &UniqueBatchItemID {
    fn eq(&self, other: &Vec<u8>) -> bool {
        &self.0 == other
    }
}

impl_ttlv_serde!(bytes UniqueBatchItemID as 0x420093);

/// See KMIP 1.0 section 9.1.3.2.2 [Key Compression Type Enumeration](https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Ref241603856).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Ordinalize)]
#[non_exhaustive]
#[repr(u32)]
pub enum KeyCompressionType {
    ECPUblicKeyTypeUncompressed = 1,
    ECPUblicKeyTypeX962CompressedPrime,
    ECPUblicKeyTypeX962CompressedChar2,
    ECPUblicKeyTypeX962Hybrid,
}

impl_ttlv_serde!(enum KeyCompressionType as 0x420041);

impl fmt::Display for KeyCompressionType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::ECPUblicKeyTypeUncompressed => "ECPUblicKeyTypeUncompressed",
            Self::ECPUblicKeyTypeX962CompressedPrime => "ECPUblicKeyTypeX962CompressedPrime",
            Self::ECPUblicKeyTypeX962CompressedChar2 => "ECPUblicKeyTypeX962CompressedChar2",
            Self::ECPUblicKeyTypeX962Hybrid => "ECPUblicKeyTypeX962Hybrid",
        })
    }
}

/// See KMIP 1.0 section 9.1.3.2.3 [Key Format Type Enumeration](https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Ref241992670).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Ordinalize)]
#[non_exhaustive]
#[repr(u32)]
pub enum KeyFormatType {
    Raw = 1,
    Opaque,
    PKCS1,
    PKCS8,
    X509,
    ECPrivateKey,
    TransparentSymmetricKey,
    TransparentDSAPrivateKey,
    TransparentDSAPublicKey,
    TransparentRSAPrivateKey,
    TransparentRSAPublicKey,
    TransparentDHPrivateKey,
    TransparentDHPublicKey,
    TransparentECDSAPrivateKey,
    TransparentECDSAPublicKey,
    TransparentECHDPrivateKey,
    TransparentECDHPublicKey,
    TransparentECMQVPrivateKey,
    TransparentECMQVPublicKey,
}

impl_ttlv_serde!(enum KeyFormatType as 0x420042);

impl fmt::Display for KeyFormatType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Raw => "Raw",
            Self::Opaque => "Opaque",
            Self::PKCS1 => "PKCS1",
            Self::PKCS8 => "PKCS8",
            Self::X509 => "X509",
            Self::ECPrivateKey => "ECPrivateKey",
            Self::TransparentSymmetricKey => "TransparentSymmetricKey",
            Self::TransparentDSAPrivateKey => "TransparentDSAPrivateKey",
            Self::TransparentDSAPublicKey => "TransparentDSAPublicKey",
            Self::TransparentRSAPublicKey => "TransparentRSAPublicKey",
            Self::TransparentRSAPrivateKey => "TransparentRSAPrivateKey",
            Self::TransparentDHPrivateKey => "TransparentDHPrivateKey",
            Self::TransparentDHPublicKey => "TransparentDHPublicKey",
            Self::TransparentECDSAPrivateKey => "TransparentECDSAPrivateKey",
            Self::TransparentECDSAPublicKey => "TransparentECDSAPublicKey",
            Self::TransparentECHDPrivateKey => "TransparentECHDPrivateKey",
            Self::TransparentECDHPublicKey => "TransparentECDHPublicKey",
            Self::TransparentECMQVPrivateKey => "TransparentECMQVPrivateKey",
            Self::TransparentECMQVPublicKey => "TransparentECMQVPublicKey",
        })
    }
}

/// See KMIP 1.0 section 9.1.3.2.5 [Recommended Curve Enumeration](https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581179).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Ordinalize)]
#[non_exhaustive]
#[allow(non_camel_case_types)]
#[repr(u32)]
pub enum RecommendedCurve {
    P_192 = 1,
    K_163,
    B_163,
    P_224,
    K_233,
    B_233,
    P_256,
    K_283,
    B_283,
    P_384,
    K_409,
    B_409,
    P_521,
    K_571,
    B_571,
}

impl_ttlv_serde!(enum RecommendedCurve as 0x420075);

impl fmt::Display for RecommendedCurve {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::P_192 => "P_192",
            Self::K_163 => "K_163",
            Self::B_163 => "B_163",
            Self::P_224 => "P_224",
            Self::K_233 => "K_233",
            Self::B_233 => "B_233",
            Self::P_256 => "P_256",
            Self::K_283 => "K_283",
            Self::B_283 => "B_283",
            Self::P_384 => "P_384",
            Self::K_409 => "K_409",
            Self::B_409 => "B_409",
            Self::P_521 => "P_521",
            Self::K_571 => "K_571",
            Self::B_571 => "B_571",
        })
    }
}

/// See KMIP 1.0 section 9.1.3.2.6 [Certificate Type Enumeration](https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Ref241994296).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Ordinalize)]
#[non_exhaustive]
#[repr(u32)]
pub enum CertificateType {
    X509 = 1,
    PGP,
}

impl_ttlv_serde!(enum CertificateType as 0x42001D);

impl fmt::Display for CertificateType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::X509 => "X509",
            Self::PGP => "PGP",
        })
    }
}

/// See KMIP 1.2 section 9.1.3.2.7 [Digital Signature Algorithm Enumeration](https://docs.oasis-open.org/kmip/spec/v1.2/os/kmip-spec-v1.2-os.html#_Ref306812211).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Ordinalize)]
#[non_exhaustive]
#[allow(non_camel_case_types)]
#[repr(u32)]
pub enum DigitalSignatureAlgorithm {
    MD2WithRSAEncryption_PKCS1_v1_5 = 1,
    MD5WithRSAEncryption_PKCS1_v1_5,
    SHA1WithRSAEncryption_PKCS1_v1_5,
    SHA224WithRSAEncryption_PKCS1_v1_5,
    SHA256WithRSAEncryption_PKCS1_v1_5,
    SHA384WithRSAEncryption_PKCS1_v1_5,
    SHA512WithRSAEncryption_PKCS1_v1_5,
    RSASSA_PSS_PKCS1_v1_5,
    DSAWithSHA1,
    DSAWithSHA224,
    DSAWithSHA256,
    ECDSAWithSHA1,
    ECDSAWithSHA224,
    ECDSAWithSHA256,
    ECDSAWithSHA384,
    ECDSAWithSHA512,
}

impl_ttlv_serde!(enum DigitalSignatureAlgorithm as 0x4200AE);

impl fmt::Display for DigitalSignatureAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::MD2WithRSAEncryption_PKCS1_v1_5 => "MD2WithRSAEncryption_PKCS1_v1_5",
            Self::MD5WithRSAEncryption_PKCS1_v1_5 => "MD5WithRSAEncryption_PKCS1_v1_5",
            Self::SHA1WithRSAEncryption_PKCS1_v1_5 => "SHA1WithRSAEncryption_PKCS1_v1_5",
            Self::SHA224WithRSAEncryption_PKCS1_v1_5 => "SHA224WithRSAEncryption_PKCS1_v1_5",
            Self::SHA256WithRSAEncryption_PKCS1_v1_5 => "SHA256WithRSAEncryption_PKCS1_v1_5",
            Self::SHA384WithRSAEncryption_PKCS1_v1_5 => "SHA384WithRSAEncryption_PKCS1_v1_5",
            Self::SHA512WithRSAEncryption_PKCS1_v1_5 => "SHA512WithRSAEncryption_PKCS1_v1_5",
            Self::RSASSA_PSS_PKCS1_v1_5 => "RSASSA_PSS_PKCS1_v1_5",
            Self::DSAWithSHA1 => "DSAWithSHA1",
            Self::DSAWithSHA224 => "DSAWithSHA224",
            Self::DSAWithSHA256 => "DSAWithSHA256",
            Self::ECDSAWithSHA1 => "ECDSAWithSHA1",
            Self::ECDSAWithSHA224 => "ECDSAWithSHA224",
            Self::ECDSAWithSHA256 => "ECDSAWithSHA256",
            Self::ECDSAWithSHA384 => "ECDSAWithSHA384",
            Self::ECDSAWithSHA512 => "ECDSAWithSHA512",
        })
    }
}

/// See KMIP 1.0 section 9.1.3.2.10 [Name Type Enumeration](https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262582060).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Ordinalize)]
#[non_exhaustive]
#[repr(u32)]
pub enum NameType {
    UninterpretedTextString = 1,
    URI,
}

impl_ttlv_serde!(enum NameType as 0x420054);

impl fmt::Display for NameType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::UninterpretedTextString => "UninterpretedTextString",
            Self::URI => "URI",
        })
    }
}

/// See KMIP 1.0 section 9.1.3.2.13 [Block Cipher Mode Enumeration](https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc236497881).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Ordinalize)]
#[non_exhaustive]
#[allow(non_camel_case_types)]
#[repr(u32)]
pub enum BlockCipherMode {
    CBC = 1,
    ECB,
    PCBC,
    CFB,
    OFB,
    CTR,
    CMAC,
    CCM,
    GCM,
    CBC_MAC,
    XTS,
    AESKeyWrapPadding,
    NISTKeyWrap,
    X9_102_AESKW,
    X9_102_TDKW,
    X9_102_AKW1,
    X9_102_AKW2,
}

impl_ttlv_serde!(enum BlockCipherMode as 0x420011);

impl fmt::Display for BlockCipherMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::CBC => "CBC",
            Self::ECB => "ECB",
            Self::PCBC => "PCBC",
            Self::CFB => "CFB",
            Self::OFB => "OFB",
            Self::CTR => "CTR",
            Self::CMAC => "CMAC",
            Self::CCM => "CCM",
            Self::GCM => "GCM",
            Self::CBC_MAC => "CBC_MAC",
            Self::XTS => "XTS",
            Self::AESKeyWrapPadding => "AESKeyWrapPadding",
            Self::NISTKeyWrap => "NISTKeyWrap",
            Self::X9_102_AESKW => "X9_102_AESKW",
            Self::X9_102_TDKW => "X9_102_TDKW",
            Self::X9_102_AKW1 => "X9_102_AKW1",
            Self::X9_102_AKW2 => "X9_102_AKW2",
        })
    }
}

/// See KMIP 1.0 section 9.1.3.2.14 [Padding Method Enumeration](https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc236497883).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Ordinalize)]
#[non_exhaustive]
#[allow(non_camel_case_types)]
#[repr(u32)]
pub enum PaddingMethod {
    None = 1,
    OAEP,
    PKCS5,
    SSL3,
    Zeros,
    ANSI_X9_23,
    ISO_10126,
    PKCS1_v1_5,
    X9_31,
    PSS,
}

impl_ttlv_serde!(enum PaddingMethod as 0x42005F);

impl fmt::Display for PaddingMethod {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::None => "None",
            Self::OAEP => "OAEP",
            Self::PKCS5 => "PKCS5",
            Self::SSL3 => "SSL3",
            Self::Zeros => "Zeros",
            Self::ANSI_X9_23 => "ANSI_X9_23",
            Self::ISO_10126 => "ISO_10126",
            Self::PKCS1_v1_5 => "PKCS1_v1_5",
            Self::X9_31 => "X9_31",
            Self::PSS => "PSS",
        })
    }
}

/// See KMIP 1.0 section 9.1.3.2.15 [Hashing Algorithm Enumeration](https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc236497883).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Ordinalize)]
#[non_exhaustive]
#[allow(non_camel_case_types)]
#[repr(u32)]
pub enum HashingAlgorithm {
    MD2 = 1,
    MD4,
    MD5,
    SHA1,
    SHA224,
    SHA256,
    SHA384,
    SHA512,
    RIPEMD160,
    Tiger,
    Whirlpool,
}

impl_ttlv_serde!(enum HashingAlgorithm as 0x420038);

impl fmt::Display for HashingAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::MD2 => "MD2",
            Self::MD4 => "MD4",
            Self::MD5 => "MD5",
            Self::SHA1 => "SHA1",
            Self::SHA224 => "SHA224",
            Self::SHA256 => "SHA256",
            Self::SHA384 => "SHA384",
            Self::SHA512 => "SHA512",
            Self::RIPEMD160 => "RIPEMD160",
            Self::Tiger => "Tiger",
            Self::Whirlpool => "Whirlpool",
        })
    }
}

/// See KMIP 1.0 section 9.1.3.2.15 [Key Role Type Enumeration](https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc236497884).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Ordinalize)]
#[non_exhaustive]
#[allow(non_camel_case_types)]
#[repr(u32)]
pub enum KeyRoleType {
    BDK = 1,
    CVK,
    DEK,
    MKAC,
    MKSMC,
    MKSMI,
    MKDAC,
    MKDN,
    MKCP,
    MKOTH,
    KEK,
    MAC16609,
    MAC97971,
    MAC97972,
    MAC97973,
    MAC97974,
    MAC97975,
    ZPK,
    PVKIBM,
    PVKPVV,
    PVKOTH,
}

impl_ttlv_serde!(enum KeyRoleType as 0x420083);

impl fmt::Display for KeyRoleType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::BDK => "BDK",
            Self::CVK => "CVK",
            Self::DEK => "DEK",
            Self::MKAC => "MKAC",
            Self::MKSMC => "MKSMC",
            Self::MKSMI => "MKSMI",
            Self::MKDAC => "MKDAC",
            Self::MKDN => "MKDN",
            Self::MKCP => "MKCP",
            Self::MKOTH => "MKOTH",
            Self::KEK => "KEK",
            Self::MAC16609 => "MAC16609",
            Self::MAC97971 => "MAC97971",
            Self::MAC97972 => "MAC97972",
            Self::MAC97973 => "MAC97973",
            Self::MAC97974 => "MAC97974",
            Self::MAC97975 => "MAC97975",
            Self::ZPK => "ZPK",
            Self::PVKIBM => "PVKIBM",
            Self::PVKPVV => "PVKPVV",
            Self::PVKOTH => "PVKOTH",
        })
    }
}

/// See KMIP 1.0 section 9.1.3.2.17 [State Enumeration](https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262582066).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Ordinalize)]
#[non_exhaustive]
#[repr(u32)]
pub enum State {
    PreActive = 1,
    Active,
    Deactivated,
    Compromised,
    Destroyed,
    DestroyedCompromised,
}

impl_ttlv_serde!(enum State as 0x42008D);

impl fmt::Display for State {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::PreActive => "PreActive",
            Self::Active => "Active",
            Self::Deactivated => "Deactivated",
            Self::Compromised => "Compromised",
            Self::Destroyed => "Destroyed",
            Self::DestroyedCompromised => "DestroyedCompromised",
        })
    }
}

/// See KMIP 1.0 section 9.1.3.2.18 [Revocation Reason Code Enumeration](https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Ref241996204).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Ordinalize)]
#[non_exhaustive]
#[repr(u32)]
pub enum RevocationReasonCode {
    Unspecified = 1,
    KeyCompromise,
    CACompromise,
    AffiliationChanged,
    Superseded,
    CessationOfOperation,
    PrivilegeWithdrawn,
}

impl_ttlv_serde!(enum RevocationReasonCode as 0x420082);

impl fmt::Display for RevocationReasonCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Unspecified => "Unspecified",
            Self::KeyCompromise => "KeyCompromise",
            Self::CACompromise => "CACompromise",
            Self::AffiliationChanged => "AffiliationChanged",
            Self::Superseded => "Superseded",
            Self::CessationOfOperation => "CessationOfOperation",
            Self::PrivilegeWithdrawn => "PrivilegeWithdrawn",
        })
    }
}

/// See KMIP 1.0 section 9.1.3.2.19 [Link Type Enumeration](https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262582069).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Ordinalize)]
#[non_exhaustive]
#[repr(u32)]
pub enum LinkType {
    CertificateLink = 0x101,
    PublicKeyLink,
    PrivateKeyLink,
    DerivationBaseObjectLink,
    DerivedKeyLink,
    ReplacementObjectLink,
    ReplacedObjectLink,
}

impl_ttlv_serde!(enum LinkType as 0x42004B);

impl fmt::Display for LinkType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::CertificateLink => "CertificateLink",
            Self::PublicKeyLink => "PublicKeyLink",
            Self::PrivateKeyLink => "PrivateKeyLink",
            Self::DerivationBaseObjectLink => "DerivationBaseObjectLink",
            Self::DerivedKeyLink => "DerivedKeyLink",
            Self::ReplacementObjectLink => "ReplacementObjectLink",
            Self::ReplacedObjectLink => "ReplacedObjectLink",
        })
    }
}

/// See KMIP 1.0 section 9.1.3.2.26 [Operation Enumeration](https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc236497894).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Ordinalize)]
#[non_exhaustive]
#[repr(u32)]
pub enum Operation {
    // KMIP 1.0 operations
    Create = 1,
    CreateKeyPair,
    Register,
    Rekey,
    DeriveKey,
    Certify,
    Recertify,
    Locate,
    Check,
    Get,
    GetAttributes,
    GetAttributeList,
    AddAttribute,
    ModifyAttribute,
    DeleteAttribute,
    ObtainLease,
    GetUsageAllocation,
    Activate,
    Revoke,
    Destroy,
    Archive,
    Recover,
    Validate,
    Query,
    Cancel,
    Poll,
    Notify,
    Put,

    // KMIP 1.1 operations
    RekeyKeyPair,
    DiscoverVersions,

    // KMIP 1.2 operations
    Encrypt,
    Decrypt,
    Sign,
    SignatureVerify,
    MAC,
    MACVerify,
    RNGRetrieve,
    RNGSeed,
    Hash,
    CreateSplitKey,
    JoinSplitKey,
}

impl_ttlv_serde!(enum Operation as 0x42005C);

impl fmt::Display for Operation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Create => "Create",
            Self::CreateKeyPair => "CreateKeyPair",
            Self::Register => "Register",
            Self::Rekey => "Rekey",
            Self::DeriveKey => "DeriveKey",
            Self::Certify => "Certify",
            Self::Recertify => "Recertify",
            Self::Locate => "Locate",
            Self::Check => "Check",
            Self::Get => "Get",
            Self::GetAttributes => "GetAttributes",
            Self::GetAttributeList => "GetAttributeList",
            Self::AddAttribute => "AddAttribute",
            Self::ModifyAttribute => "ModifyAttribute",
            Self::DeleteAttribute => "DeleteAttribute",
            Self::ObtainLease => "ObtainLease",
            Self::GetUsageAllocation => "GetUsageAllocation",
            Self::Activate => "Activate",
            Self::Revoke => "Revoke",
            Self::Destroy => "Destroy",
            Self::Archive => "Archive",
            Self::Recover => "Recover",
            Self::Validate => "Validate",
            Self::Query => "Query",
            Self::Cancel => "Cancel",
            Self::Poll => "Poll",
            Self::Notify => "Notify",
            Self::Put => "Put",
            Self::RekeyKeyPair => "RekeyKeyPair",
            Self::DiscoverVersions => "DiscoverVersions",
            Self::Encrypt => "Encrypt",
            Self::Decrypt => "Decrypt",
            Self::Sign => "Sign",
            Self::SignatureVerify => "SignatureVerify",
            Self::MAC => "MAC",
            Self::MACVerify => "MACVerify",
            Self::RNGRetrieve => "RNGRetrieve",
            Self::RNGSeed => "RNGSeed",
            Self::Hash => "Hash",
            Self::CreateSplitKey => "CreateSplitKey",
            Self::JoinSplitKey => "JoinSplitKey",
        })
    }
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
