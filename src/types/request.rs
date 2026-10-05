//! Rust types for sserializing KMIP requests.
use std::fmt;
use std::{ops::Deref, str::FromStr};

use enum_ordinalize::Ordinalize;

use crate::ttlv::fast_scan::{FastScanError, FastScanner};
use crate::ttlv::format::{FormatResult, Formatter, TruncationError};
use crate::ttlv::types::Tag;

use super::common::{
    ApplicationData, ApplicationNamespace, AttributeIndex, AttributeName, AttributeValue, CompromiseOccurrenceDate,
    CryptographicAlgorithm, CryptographicLength, CryptographicParameters, CryptographicUsageMask, Data, DataLength,
    KeyCompressionType, KeyFormatType, KeyMaterial, LinkType, LinkedObjectIdentifier, NameType, NameValue, ObjectType,
    Operation, RevocationMessage, RevocationReasonCode, UniqueBatchItemID, UniqueIdentifier,
};

use super::impl_ttlv_serde;

pub fn from_slice(buffer: &[u8]) -> std::result::Result<RequestMessage, FastScanError> {
    let (res, rest) = crate::ttlv::from_slice(buffer, RequestMessage::fast_scan)?;
    if !rest.is_empty() {
        Err(FastScanError::assert())
    } else {
        Ok(res)
    }
}

pub fn to_vec(payload: RequestPayload, credential: Option<CredentialValue>) -> Result<Vec<u8>, TruncationError> {
    let operation = payload.operation();

    let request = RequestMessage(
        RequestHeader(
            payload.protocol_version(),
            Option::<MaximumResponseSize>::None,
            credential.map(Authentication::build),
            None,
            None,
            BatchCount(1),
        ),
        vec![BatchItem(operation, Option::<UniqueBatchItemID>::None, payload)],
    );

    crate::ttlv::to_vec(|f| request.format(f))
}

/// See KMIP 1.0 section 2.1.1 [Attribute](https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581155).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Attribute(pub AttributeName, pub Option<AttributeIndex>, pub AttributeValue);

impl Attribute {
    pub fn name(&self) -> &AttributeName {
        &self.0
    }

    pub fn index(&self) -> Option<&AttributeIndex> {
        self.1.as_ref()
    }

    pub fn value(&self) -> &AttributeValue {
        &self.2
    }
}

/// Helper functions to simplifying including KMIP TemplateAttributes in requests.
///
/// The set of possible attributes and their textual names are specified by the KMIP 1.0 spec in Section 3 Attributes.
/// We offer various Attribute constructor functions that avoid the need for the caller to couple the right
/// AttributeName and AttributeValue pairs together and to use the correct AttributeName text value and instead just Do
/// The Right Thing for them.
impl Attribute {
    /// See KMIP 1.0 section 3.1 Unique Identifier.
    #[allow(non_snake_case)]
    pub fn UniqueIdentifier(value: String) -> Self {
        Attribute(
            AttributeName("Unique Identifier".into()),
            Option::<AttributeIndex>::None,
            AttributeValue::UniqueIdentifier(UniqueIdentifier(value)),
        )
    }

    /// See KMIP 1.0 section 3.2 Name.
    #[allow(non_snake_case)]
    pub fn Name(value: String) -> Self {
        Attribute(
            AttributeName("Name".into()),
            Option::<AttributeIndex>::None,
            AttributeValue::Name(Name(NameValue(value), NameType::UninterpretedTextString)),
        )
    }

    /// See KMIP 1.0 section 3.2 Name.
    #[allow(non_snake_case)]
    pub fn URI(value: String) -> Self {
        Attribute(
            AttributeName("Name".into()),
            Option::<AttributeIndex>::None,
            AttributeValue::Name(Name(NameValue(value), NameType::URI)),
        )
    }

    /// See KMIP 1.0 section 3.3 Object Type.
    #[allow(non_snake_case)]
    pub fn ObjectType(value: ObjectType) -> Self {
        Attribute(
            AttributeName("Object Type".into()),
            Option::<AttributeIndex>::None,
            AttributeValue::ObjectType(value),
        )
    }

    /// See KMIP 1.0 section 3.4 Cryptographic Algorithm.
    #[allow(non_snake_case)]
    pub fn CryptographicAlgorithm(value: CryptographicAlgorithm) -> Self {
        Attribute(
            AttributeName("Cryptographic Algorithm".into()),
            Option::<AttributeIndex>::None,
            AttributeValue::CryptographicAlgorithm(value),
        )
    }

    /// See KMIP 1.0 section 3.5 Cryptographic Length.
    #[allow(non_snake_case)]
    pub fn CryptographicLength(value: i32) -> Self {
        Attribute(
            AttributeName("Cryptographic Length".into()),
            Option::<AttributeIndex>::None,
            AttributeValue::CryptographicLength(CryptographicLength(value)),
        )
    }

    /// See KMIP 1.0 section 3.6 Cryptographic Parameters.
    #[allow(non_snake_case)]
    pub fn CryptographicParameters(cryptographic_parameters: CryptographicParameters) -> Self {
        Attribute(
            AttributeName("Cryptographic Parameters".into()),
            Option::<AttributeIndex>::None,
            cryptographic_parameters.into(),
        )
    }

    // See KMIP 1.0 section 3.13 Operation Policy Name.
    // Not implemented.

    /// See KMIP 1.0 section 3.14 Cryptographic Usage Mask.
    #[allow(non_snake_case)]
    pub fn CryptographicUsageMask(value: CryptographicUsageMask) -> Self {
        Attribute(
            AttributeName("Cryptographic Usage Mask".into()),
            Option::<AttributeIndex>::None,
            AttributeValue::CryptographicUsageMask(value),
        )
    }

    /// See KMIP 1.0 section 3.24 Activation Date.
    #[allow(non_snake_case)]
    pub fn ActivationDate(value: i64) -> Self {
        Attribute(
            AttributeName("Activation Date".into()),
            Option::<AttributeIndex>::None,
            AttributeValue::ActivationDate(value),
        )
    }

    /// See KMIP 1.0 section 3.28 Object Group.
    #[allow(non_snake_case)]
    pub fn ObjectGroup(value: String) -> Self {
        Attribute(
            AttributeName("Object Group".into()),
            Option::<AttributeIndex>::None,
            AttributeValue::ObjectGroup(value),
        )
    }

    /// See KMIP 1.0 section 3.29 Link.
    #[allow(non_snake_case)]
    pub fn Link(link_type: LinkType, linked_object_identifier: LinkedObjectIdentifier) -> Self {
        Attribute(
            AttributeName("Link".into()),
            Option::<AttributeIndex>::None,
            AttributeValue::Link(link_type, linked_object_identifier),
        )
    }

    /// See KMIP 1.0 section 3.30 Application Specific Information.
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

    /// See KMIP 1.0 section 3.31 Contact Information.
    #[allow(non_snake_case)]
    pub fn ContactInformation(value: String) -> Self {
        Attribute(
            AttributeName("Contact Information".into()),
            Option::<AttributeIndex>::None,
            AttributeValue::ContactInformation(value),
        )
    }
}

impl_ttlv_serde!(struct Attribute as 0x420008 {
    fast_scan = |scanner| {
        let name = AttributeName::fast_scan(&mut scanner)?;
        let index = AttributeIndex::fast_scan_opt(&mut scanner)?;
        let value = AttributeValue::fast_scan(&mut scanner, &name)?;
        Self(name, index, value)
    };

    format = |&self, formatter| {
        self.0.format(&mut formatter)?;
        if let Some(index) = &self.1 {
            index.format(&mut formatter)?;
        }
        self.2.format(&mut formatter)?;
    };
});

// TODO: Create TemplateAttribute, CommonTemplateAttributes,
// PrivateKeyTemplateAttributes and PublicKeyTemplateAttributes using a macro.

/// See KMIP 1.0 section 2.1.8 [Template-Attribute Structures](https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581162).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TemplateAttribute {
    template_names: Option<Vec<Name>>,
    attributes: Option<Vec<Attribute>>,
}

impl TemplateAttribute {
    pub fn new(attributes: Vec<Attribute>) -> Self {
        Self {
            template_names: None,
            attributes: Some(attributes),
        }
    }

    pub fn new_with_names(attributes: Vec<Attribute>, names: Vec<Name>) -> Self {
        Self {
            template_names: (!names.is_empty()).then_some(names),
            attributes: (!attributes.is_empty()).then_some(attributes),
        }
    }

    pub fn with_template_name(mut self, template_name: &'static str) -> Self {
        // TODO: SAFETY
        let template_name = Name::from_str(template_name).unwrap();
        let mut template_names = self.template_names.unwrap_or_default();
        template_names.push(template_name);
        self.template_names = Some(template_names);
        self
    }

    pub fn template_names(&self) -> &[Name] {
        match &self.template_names {
            Some(template_names) => template_names.as_slice(),
            None => &[],
        }
    }

    pub fn attributes(&self) -> &[Attribute] {
        match &self.attributes {
            Some(attributes) => attributes.as_slice(),
            None => &[],
        }
    }
}

impl_ttlv_serde!(struct TemplateAttribute {
    #[option+vec] template_names: Name,
    #[option+vec] attributes: Attribute,
} as 0x420091);

/// See KMIP 1.0 section 2.1.8 [Template-Attribute Structures](https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581162).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CommonTemplateAttribute {
    template_names: Option<Vec<Name>>,
    attributes: Option<Vec<Attribute>>,
}

impl CommonTemplateAttribute {
    pub fn new(attributes: Vec<Attribute>) -> Self {
        Self {
            template_names: None,
            attributes: Some(attributes),
        }
    }

    pub fn new_with_names(attributes: Vec<Attribute>, names: Vec<Name>) -> Self {
        Self {
            template_names: (!names.is_empty()).then_some(names),
            attributes: (!attributes.is_empty()).then_some(attributes),
        }
    }

    pub fn with_template_name(mut self, template_name: &'static str) -> Self {
        // TODO: SAFETY
        let template_name = Name::from_str(template_name).unwrap();
        let mut template_names = self.template_names.unwrap_or_default();
        template_names.push(template_name);
        self.template_names = Some(template_names);
        self
    }

    pub fn template_names(&self) -> &[Name] {
        match &self.template_names {
            Some(template_names) => template_names.as_slice(),
            None => &[],
        }
    }

    pub fn attributes(&self) -> &[Attribute] {
        match &self.attributes {
            Some(attributes) => attributes.as_slice(),
            None => &[],
        }
    }
}

impl_ttlv_serde!(struct CommonTemplateAttribute as 0x42001F {
    fast_scan = |scanner| {
        let names = std::iter::from_fn(|| Name::fast_scan_opt(&mut scanner).transpose()).collect::<Result<_, _>>()?;
        let attributes =
            std::iter::from_fn(|| Attribute::fast_scan_opt(&mut scanner).transpose()).collect::<Result<_, _>>()?;
        Self::new_with_names(attributes, names)
    };

    format = |&self, formatter| {
        for name in self.template_names() {
            name.format(&mut formatter)?;
        }
        for attribute in self.attributes() {
            attribute.format(&mut formatter)?;
        }
    };
});

/// See KMIP 1.0 section 2.1.8 [Template-Attribute Structures](https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581162).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PrivateKeyTemplateAttribute {
    template_names: Option<Vec<Name>>,
    attributes: Option<Vec<Attribute>>,
}

impl PrivateKeyTemplateAttribute {
    pub fn new(attributes: Vec<Attribute>) -> Self {
        Self {
            template_names: None,
            attributes: Some(attributes),
        }
    }

    pub fn new_with_names(attributes: Vec<Attribute>, names: Vec<Name>) -> Self {
        Self {
            template_names: (!names.is_empty()).then_some(names),
            attributes: (!attributes.is_empty()).then_some(attributes),
        }
    }

    pub fn with_template_name(mut self, template_name: &'static str) -> Self {
        // TODO: SAFETY
        let template_name = Name::from_str(template_name).unwrap();
        let mut template_names = self.template_names.unwrap_or_default();
        template_names.push(template_name);
        self.template_names = Some(template_names);
        self
    }

    pub fn template_names(&self) -> &[Name] {
        match &self.template_names {
            Some(template_names) => template_names.as_slice(),
            None => &[],
        }
    }

    pub fn attributes(&self) -> &[Attribute] {
        match &self.attributes {
            Some(attributes) => attributes.as_slice(),
            None => &[],
        }
    }
}

impl_ttlv_serde!(struct PrivateKeyTemplateAttribute as 0x420065 {
    fast_scan = |scanner| {
        let names = std::iter::from_fn(|| Name::fast_scan_opt(&mut scanner).transpose()).collect::<Result<_, _>>()?;
        let attributes =
            std::iter::from_fn(|| Attribute::fast_scan_opt(&mut scanner).transpose()).collect::<Result<_, _>>()?;
        Self::new_with_names(attributes, names)
    };

    format = |&self, formatter| {
        for name in self.template_names() {
            name.format(&mut formatter)?;
        }
        for attribute in self.attributes() {
            attribute.format(&mut formatter)?;
        }
    };
});

/// See KMIP 1.0 section 2.1.8 [Template-Attribute Structures](https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581162).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublicKeyTemplateAttribute {
    template_names: Option<Vec<Name>>,
    attributes: Option<Vec<Attribute>>,
}

impl PublicKeyTemplateAttribute {
    pub fn new(attributes: Vec<Attribute>) -> Self {
        Self {
            template_names: None,
            attributes: Some(attributes),
        }
    }

    pub fn new_with_names(attributes: Vec<Attribute>, names: Vec<Name>) -> Self {
        Self {
            template_names: (!names.is_empty()).then_some(names),
            attributes: (!attributes.is_empty()).then_some(attributes),
        }
    }

    pub fn with_template_name(mut self, template_name: &'static str) -> Self {
        // TODO: SAFETY
        let template_name = Name::from_str(template_name).unwrap();
        let mut template_names = self.template_names.unwrap_or_default();
        template_names.push(template_name);
        self.template_names = Some(template_names);
        self
    }

    pub fn template_names(&self) -> &[Name] {
        match &self.template_names {
            Some(template_names) => template_names.as_slice(),
            None => &[],
        }
    }

    pub fn attributes(&self) -> &[Attribute] {
        match &self.attributes {
            Some(attributes) => attributes.as_slice(),
            None => &[],
        }
    }
}

impl_ttlv_serde!(struct PublicKeyTemplateAttribute as 0x42006E {
    fast_scan = |scanner| {
        let names = std::iter::from_fn(|| Name::fast_scan_opt(&mut scanner).transpose()).collect::<Result<_, _>>()?;
        let attributes =
            std::iter::from_fn(|| Attribute::fast_scan_opt(&mut scanner).transpose()).collect::<Result<_, _>>()?;
        Self::new_with_names(attributes, names)
    };

    format = |&self, formatter| {
        for name in self.template_names() {
            name.format(&mut formatter)?;
        }
        for attribute in self.attributes() {
            attribute.format(&mut formatter)?;
        }
    };
});

/// See KMIP 1.0 section 2.1.2 [Credential](https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581156).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Credential(pub CredentialType, pub CredentialValue);

impl Credential {
    pub fn credential_type(&self) -> CredentialType {
        self.0
    }

    pub fn credential_value(&self) -> &CredentialValue {
        &self.1
    }
}

impl_ttlv_serde!(struct Credential as 0x420023 {
    fast_scan = |scanner| {
        let r#type = CredentialType::fast_scan(&mut scanner)?;
        let value = CredentialValue::fast_scan(&mut scanner, &r#type)?;
        Self(r#type, value)
    };

    format = |&self, formatter| {
        self.0.format(&mut formatter)?;
        self.1.format(&mut formatter)?;
    };
});

/// See KMIP 1.0 section 2.1.2 [Credential](https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581156).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Ordinalize)]
#[non_exhaustive]
#[repr(u32)]
pub enum CredentialType {
    UsernameAndPassword = 1,
}

impl_ttlv_serde!(enum CredentialType as 0x420024);

impl fmt::Display for CredentialType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str(match self {
            Self::UsernameAndPassword => "UsernameAndPassword",
        })
    }
}

/// See KMIP 1.0 section 2.1.2 [Credential](https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581156).
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum CredentialValue {
    UsernameAndPassword(Username, Option<Password>),
}

impl CredentialValue {
    pub fn username(&self) -> Option<&Username> {
        match self {
            CredentialValue::UsernameAndPassword(username, _password) => Some(username),
        }
    }

    pub fn password(&self) -> Option<&Password> {
        match self {
            CredentialValue::UsernameAndPassword(_username, password) => password.as_ref(),
        }
    }
}

impl CredentialValue {
    pub const TAG: Tag = Tag::new(0x420025);

    pub fn fast_scan(scanner: &mut FastScanner<'_>, r#type: &CredentialType) -> Result<Self, FastScanError> {
        match r#type {
            CredentialType::UsernameAndPassword => {
                let mut scanner = scanner.scan_struct(Self::TAG)?;
                let this = Self::UsernameAndPassword(
                    Username::fast_scan(&mut scanner)?,
                    Password::fast_scan_opt(&mut scanner)?,
                );
                scanner.finish()?;
                Ok(this)
            }
        }
    }

    pub fn format(&self, formatter: &mut Formatter<'_>) -> FormatResult {
        match self {
            CredentialValue::UsernameAndPassword(username, password) => {
                let mut formatter = formatter.format_struct(Self::TAG)?;
                username.format(&mut formatter)?;
                if let Some(password) = password {
                    password.format(&mut formatter)?;
                }
                Ok(formatter.finish())
            }
        }
    }
}

/// See KMIP 1.0 section 2.1.2 [Credential](https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581156).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Username(pub String);

impl Deref for Username {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        self.0.as_str()
    }
}

impl_ttlv_serde!(text Username as 0x420099);

/// See KMIP 1.0 section 2.1.2 [Credential](https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581156).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Password(pub String);

impl Deref for Password {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        self.0.as_str()
    }
}

impl_ttlv_serde!(text Password as 0x4200A1);

/// See KMIP 1.0 section 2.1.3 [Key Block](https://docs.oasis-open.org/kmip/spec/v1.2/os/kmip-spec-v1.2-os.html#_Toc409613459).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeyBlock(
    pub KeyFormatType,
    pub Option<KeyCompressionType>,
    pub Option<KeyValue>,
    pub Option<CryptographicAlgorithm>,
    pub Option<CryptographicLength>,
    pub Option<KeyWrappingData>,
);

impl_ttlv_serde!(struct KeyBlock as 0x420040 {
    fast_scan = |scanner| {
        let format = KeyFormatType::fast_scan(&mut scanner)?;
        Self(
            format,
            KeyCompressionType::fast_scan_opt(&mut scanner)?,
            KeyValue::fast_scan_opt(&mut scanner, &format)?,
            CryptographicAlgorithm::fast_scan_opt(&mut scanner)?,
            CryptographicLength::fast_scan_opt(&mut scanner)?,
            KeyWrappingData::fast_scan_opt(&mut scanner)?,
        )
    };

    format = |&self, formatter| {
        self.0.format(&mut formatter)?;
        if let Some(x) = &self.1 { x.format(&mut formatter)?; }
        if let Some(x) = &self.2 { x.format(&mut formatter)?; }
        if let Some(x) = &self.3 { x.format(&mut formatter)?; }
        if let Some(x) = &self.4 { x.format(&mut formatter)?; }
        if let Some(x) = &self.5 { x.format(&mut formatter)?; }
    };
});

/// See KMIP 1.0 section 2.1.4 [Key Value](https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581158).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeyValue(pub KeyMaterial, pub Option<Vec<Attribute>>);

impl KeyValue {
    pub const TAG: Tag = Tag::new(0x420045);

    pub fn fast_scan_opt(scanner: &mut FastScanner<'_>, format: &KeyFormatType) -> Result<Option<Self>, FastScanError> {
        let Some(mut scanner) = scanner.scan_opt_struct(Self::TAG)? else {
            return Ok(None);
        };
        let material = KeyMaterial::fast_scan(&mut scanner, format)?;
        let attributes =
            std::iter::from_fn(|| Attribute::fast_scan_opt(&mut scanner).transpose()).collect::<Result<Vec<_>, _>>()?;
        let attributes = Some(attributes).filter(|a| !a.is_empty());
        scanner.finish()?;
        Ok(Some(Self(material, attributes)))
    }

    pub fn format(&self, formatter: &mut Formatter<'_>) -> FormatResult {
        let mut formatter = formatter.format_struct(Self::TAG)?;
        self.0.format(&mut formatter)?;
        for attribute in self.1.iter().flatten() {
            attribute.format(&mut formatter)?;
        }
        Ok(formatter.finish())
    }
}

/// See KMIP 1.0 section 2.1.5 [Key Wrapping Data](https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581159).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeyWrappingData(
    pub WrappingMethod,
    pub Option<EncryptionKeyInformation>,
    pub Option<MACOrSignatureKeyInformation>,
    pub Option<MACOrSignature>,
    pub Option<IVOrCounterOrNonce>,
    pub Option<Vec<Attribute>>,
);

impl_ttlv_serde!(struct KeyWrappingData(
    a: WrappingMethod,
    #[option] b: EncryptionKeyInformation,
    #[option] c: MACOrSignatureKeyInformation,
    #[option] d: MACOrSignature,
    #[option] e: IVOrCounterOrNonce,
    #[option+vec] f: Attribute,
) as 0x420046);

/// See KMIP 1.0 section 2.1.5 [Key Wrapping Data](https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581159).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MACOrSignature(Vec<u8>);

impl_ttlv_serde!(bytes MACOrSignature as 0x42004D);

/// See KMIP 1.0 section 2.1.5 [Key Wrapping Data](https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581159).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IVOrCounterOrNonce(Vec<u8>);

impl_ttlv_serde!(bytes IVOrCounterOrNonce as 0x42003D);

/// See KMIP 1.0 section 2.1.5 [Key Wrapping Data](https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581159).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EncryptionKeyInformation(pub UniqueIdentifier, pub Option<CryptographicParameters>);

impl_ttlv_serde!(struct EncryptionKeyInformation(
    id: UniqueIdentifier,
    #[option] params: CryptographicParameters,
) as 0x420036);

/// See KMIP 1.0 section 2.1.5 [Key Wrapping Data](https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581159).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MACOrSignatureKeyInformation(pub UniqueIdentifier, pub Option<CryptographicParameters>);

impl_ttlv_serde!(struct MACOrSignatureKeyInformation(
    id: UniqueIdentifier,
    #[option] params: CryptographicParameters,
) as 0x42004E);

/// See KMIP 1.0 section 2.1.6 [Key Wrapping Specification](https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581160).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeyWrappingSpecification(
    pub WrappingMethod,
    pub Option<EncryptionKeyInformation>,
    pub Option<MACOrSignatureKeyInformation>,
    pub Option<Vec<Attribute>>,
);

impl_ttlv_serde!(struct KeyWrappingSpecification(
    a: WrappingMethod,
    #[option] b: EncryptionKeyInformation,
    #[option] c: MACOrSignatureKeyInformation,
    #[option+vec] d: Attribute,
) as 0x420047);

/// See KMIP 1.0 section 2.2 [Managed Objects](https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581163).
#[derive(Clone, Debug, PartialEq, Eq)]
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

impl ManagedObject {
    pub fn fast_scan(scanner: &mut FastScanner<'_>, r#type: ObjectType) -> Result<Self, FastScanError> {
        match r#type {
            ObjectType::SymmetricKey => SymmetricKey::fast_scan(scanner).map(Self::SymmetricKey),
            ObjectType::PublicKey => PublicKey::fast_scan(scanner).map(Self::PublicKey),
            ObjectType::PrivateKey => PrivateKey::fast_scan(scanner).map(Self::PrivateKey),
            ObjectType::Template => Template::fast_scan(scanner).map(Self::Template),

            ObjectType::Certificate
            | ObjectType::SplitKey
            | ObjectType::SecretData
            | ObjectType::OpaqueObject
            | ObjectType::PGPKey => unimplemented!(),
        }
    }

    pub fn fast_scan_opt(scanner: &mut FastScanner<'_>, r#type: ObjectType) -> Result<Option<Self>, FastScanError> {
        match r#type {
            ObjectType::SymmetricKey => SymmetricKey::fast_scan_opt(scanner).map(|s| s.map(Self::SymmetricKey)),
            ObjectType::PublicKey => PublicKey::fast_scan_opt(scanner).map(|s| s.map(Self::PublicKey)),
            ObjectType::PrivateKey => PrivateKey::fast_scan_opt(scanner).map(|s| s.map(Self::PrivateKey)),
            ObjectType::Template => Template::fast_scan_opt(scanner).map(|s| s.map(Self::Template)),

            ObjectType::Certificate
            | ObjectType::SplitKey
            | ObjectType::SecretData
            | ObjectType::OpaqueObject
            | ObjectType::PGPKey => unimplemented!(),
        }
    }

    pub fn format(&self, formatter: &mut Formatter<'_>) -> FormatResult {
        match self {
            ManagedObject::SymmetricKey(this) => this.format(formatter),
            ManagedObject::PublicKey(this) => this.format(formatter),
            ManagedObject::PrivateKey(this) => this.format(formatter),
            ManagedObject::Template(this) => this.format(formatter),
        }
    }
}

/// See KMIP 1.0 section 2.2.2 [Symmetric Key](https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581165).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SymmetricKey(pub KeyBlock);

impl_ttlv_serde!(struct SymmetricKey(block: KeyBlock) as 0x42008F);

/// See KMIP 1.0 section 2.2.3 [Public Key](https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581166).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublicKey(pub KeyBlock);

impl_ttlv_serde!(struct PublicKey(block: KeyBlock) as 0x42006D);

/// See KMIP 1.0 section 2.2.4 [Private Key](https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581167).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PrivateKey(pub KeyBlock);

impl_ttlv_serde!(struct PrivateKey(block: KeyBlock) as 0x420064);

/// See KMIP 1.0 section 2.2.6 [Template](https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581169).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Template(pub Vec<Attribute>);

impl_ttlv_serde!(struct Template(#[vec] attrs: Attribute) as 0x420090);

/// See KMIP 1.0 section 3.2 [Name](https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581174).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Name(pub NameValue, pub NameType);

impl FromStr for Name {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Self(NameValue::from_str(s)?, NameType::UninterpretedTextString))
    }
}

impl fmt::Display for Name {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_fmt(format_args!("{}", self.0))
    }
}

impl_ttlv_serde!(struct Name(
    value: NameValue,
    r#type: NameType,
) as 0x420053);

/// See KMIP 1.0 section 3.26 [Revocation Reason](https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581200).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RevocationReason(pub RevocationReasonCode, pub Option<RevocationMessage>);

impl_ttlv_serde!(struct RevocationReason(
    code: RevocationReasonCode,
    #[option] message: RevocationMessage,
) as 0x420081);

/// See KMIP 1.0 section 6.1 [Protocol Version](https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581239).
#[derive(Clone, Debug, PartialEq, Eq, Ord, PartialOrd)]
pub struct ProtocolVersion(pub ProtocolVersionMajor, pub ProtocolVersionMinor);

impl_ttlv_serde!(struct ProtocolVersion(
    major: ProtocolVersionMajor,
    minor: ProtocolVersionMinor,
) as 0x420069);

/// See KMIP 1.0 section 6.1 [Protocol Version](https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581239).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Ord, PartialOrd)]
pub struct ProtocolVersionMajor(pub i32);

impl_ttlv_serde!(int ProtocolVersionMajor as 0x42006A);

/// See KMIP 1.0 section 6.1 [Protocol Version](https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581239).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Ord, PartialOrd)]
pub struct ProtocolVersionMinor(pub i32);

impl_ttlv_serde!(int ProtocolVersionMinor as 0x42006B);

/// See KMIP 1.0 section 6.3 [Maximum Response Size](https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581241).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MaximumResponseSize(pub i32);

impl_ttlv_serde!(int MaximumResponseSize as 0x420050);

/// One (or more since KMIP 1.2) credentials to authenticate with.
///
/// In KMIP 1.0 and 1.1 only a single credential was supported.
/// In KMIP 1.2 this was expanded to one or more credentials.
/// In KMIP 2.0 it was specified that if multiple credentials are provided
/// then they must all be satisfied, prior to that it was not specified what
/// the server should require if multiple credentials are supplied.
///
/// See KMIP 1.0 section 6.6 [Authentication](https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581244).
/// See KMIP 1.2 section 6.6 [Authentication](https://docs.oasis-open.org/kmip/spec/v1.2/os/kmip-spec-v1.2-os.html#_Toc409613576).
/// See KMIP 2.0 section 9.4 [Authentication](https://docs.oasis-open.org/kmip/kmip-spec/v2.0/os/kmip-spec-v2.0-os.html#_Toc6497631).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Authentication(pub Vec<Credential>);

impl Authentication {
    pub fn build(credential: CredentialValue) -> Authentication {
        match credential {
            CredentialValue::UsernameAndPassword(username, password) => Authentication(vec![Credential(
                CredentialType::UsernameAndPassword,
                CredentialValue::UsernameAndPassword(username, password),
            )]),
        }
    }

    pub fn credentials(&self) -> &[Credential] {
        &self.0
    }

    pub fn username(&self) -> Option<&Username> {
        self.credentials()
            .iter()
            .find(|c| matches!(c.credential_value(), CredentialValue::UsernameAndPassword(..)))
            .and_then(|c| c.credential_value().username())
    }

    pub fn password(&self) -> Option<&Password> {
        self.credentials()
            .iter()
            .find(|c| matches!(c.credential_value(), CredentialValue::UsernameAndPassword(..)))
            .and_then(|c| c.credential_value().password())
    }
}

impl_ttlv_serde!(struct Authentication(#[vec] credentials: Credential) as 0x42000C);

/// See KMIP 1.0 section 6.14 [Batch Count](https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581252).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct BatchCount(pub i32);

impl_ttlv_serde!(int BatchCount as 0x42000D);

/// See KMIP 1.0 section 6.15 [Batch Item](https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581253).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BatchItem(
    pub Operation, // TODO: set this somehow automatically to RequestPayload::operation()
    pub Option<UniqueBatchItemID>,
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

impl_ttlv_serde!(struct BatchItem as 0x42000F {
    fast_scan = |scanner| {
        let operation = Operation::fast_scan(&mut scanner)?;
        let id = UniqueBatchItemID::fast_scan_opt(&mut scanner)?;
        let payload = RequestPayload::fast_scan(&mut scanner, operation)?;
        Self(operation, id, payload)
    };

    format = |&self, formatter| {
        self.0.format(&mut formatter)?;
        if let Some(x) = &self.1 { x.format(&mut formatter)?; }
        self.2.format(&mut formatter)?;
    };
});

/// See KMIP 1.0 section 7.1 [Message Structure](https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581256).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RequestMessage(pub RequestHeader, pub Vec<BatchItem>);

impl RequestMessage {
    pub fn header(&self) -> &RequestHeader {
        &self.0
    }

    pub fn batch_items(&self) -> &[BatchItem] {
        &self.1
    }
}

impl_ttlv_serde!(struct RequestMessage as 0x420078 {
    fast_scan = |scanner| {
        let header = RequestHeader::fast_scan(&mut scanner)?;
        let BatchCount(count) = header.5;
        let items = (0..count)
            .map(|_| BatchItem::fast_scan(&mut scanner))
            .collect::<Result<Vec<_>, _>>()?;
        Self(header, items)
    };

    format = |&self, formatter| {
        self.0.format(&mut formatter)?;
        for item in &self.1 {
            item.format(&mut formatter)?;
        }
    };
});

/// See KMIP 1.0 section 7.2 [Operations](https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581257).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RequestHeader(
    pub ProtocolVersion,
    pub Option<MaximumResponseSize>,
    pub Option<Authentication>,
    pub Option<BatchErrorContinuationOption>,
    pub Option<bool>, // BatchOrderOption
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
        &self.5
    }
}

impl_ttlv_serde!(struct RequestHeader as 0x420077 {
    fast_scan = |scanner| Self(
        ProtocolVersion::fast_scan(&mut scanner)?,
        MaximumResponseSize::fast_scan_opt(&mut scanner)?,
        Authentication::fast_scan_opt(&mut scanner)?,
        BatchErrorContinuationOption::fast_scan_opt(&mut scanner)?,
        scanner.scan_opt_bool(Tag::new(0x420010))?,
        BatchCount::fast_scan_opt(&mut scanner)?.unwrap_or_default(),
    );

    format = |&self, formatter| {
        self.0.format(&mut formatter)?;
        if let Some(x) = &self.1 { x.format(&mut formatter)?; }
        if let Some(x) = &self.2 { x.format(&mut formatter)?; }
        if let Some(x) = &self.3 { x.format(&mut formatter)?; }
        if let Some(x) = &self.4 { formatter.format_bool(Tag::new(0x420010), *x)?; }
        self.5.format(&mut formatter)?;
    };
});

#[derive(Clone, Copy, Debug, PartialEq, Eq, Ordinalize)]
#[non_exhaustive]
#[repr(u32)]
pub enum BatchErrorContinuationOption {
    Continue = 1,
    Stop,
    Undo,
}

impl_ttlv_serde!(enum BatchErrorContinuationOption as 0x42000E);

/// See KMIP 1.0 section 7.1 [Message Structure](https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581256).
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
#[allow(clippy::large_enum_variant)]
pub enum RequestPayload {
    /// See KMIP 1.0 section 4.1 Create.
    /// See: https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581209
    Create(ObjectType, TemplateAttribute),

    /// See KMIP 1.0 section 4.2 Create Key Pair.
    /// See: https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581210
    CreateKeyPair(
        Option<CommonTemplateAttribute>,
        Option<PrivateKeyTemplateAttribute>,
        Option<PublicKeyTemplateAttribute>,
    ),

    /// See KMIP 1.0 section 4.3 Register.
    /// See: https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581211
    Register(ObjectType, TemplateAttribute, Option<ManagedObject>),

    // TODO? Missing operation code mappings to request payloads
    // Re-key = 4
    // Derive Key = 5
    // Certify = 6
    // Re-certify = 7
    /// See KMIP 1.0 section 4.8 Locate.
    /// See: https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581216
    Locate(Vec<Attribute>), // TODO: Add MaximumItems and StorageStatusMask optional request payload fields

    /// See KMIP 1.0 section 4.10 Get.
    /// See: https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581218
    Get(
        Option<UniqueIdentifier>,
        Option<KeyFormatType>,
        Option<KeyCompressionType>,
        Option<KeyWrappingSpecification>,
    ),

    /// See KMIP 1.0 section 4.11 Get Attributes.
    /// See: https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581219
    GetAttributes(Option<UniqueIdentifier>, Option<Vec<AttributeName>>),

    /// See KMIP 1.0 section 4.12 Get Attribute List.
    /// See: https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581220
    GetAttributeList(Option<UniqueIdentifier>),

    /// See KMIP 1.0 section 4.13 Add Attribute.
    /// See: https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581221
    AddAttribute(Option<UniqueIdentifier>, Attribute),

    /// See KMIP 1.0 section 4.14 Modify Attribute.
    /// See: https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581222
    ModifyAttribute(Option<UniqueIdentifier>, Attribute),

    /// See KMIP 1.0 section 4.15 Delete Attribute.
    /// See: https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581223
    DeleteAttribute(Option<UniqueIdentifier>, AttributeName, Option<AttributeIndex>),

    // TODO? Missing operation code mappings to request payloads
    // Obtain Lease = 10
    // Get Usage Allocation = 11
    /// See KMIP 1.0 section 4.18 Activate.
    /// See: https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581226
    Activate(Option<UniqueIdentifier>),

    /// See KMIP 1.0 section 4.19 Revoke.
    /// See: https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581227
    Revoke(
        Option<UniqueIdentifier>,
        RevocationReason,
        Option<CompromiseOccurrenceDate>,
    ),

    /// See KMIP 1.0 section 4.20 Destroy.
    /// See: https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581228
    Destroy(Option<UniqueIdentifier>),

    // TODO? Missing operation code mappings to request payloads
    // Archive = 15
    // Recover = 16
    // Validate = 17
    /// See KMIP 1.0 section 4.24 Query.
    /// See: https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581232
    Query(Vec<QueryFunction>),

    // TODO? Missing operation code mappings to request payloads
    // Cancel = 19
    // Poll = 1A
    // Notify = 1B
    // Put = 1C
    // Re-key Key Pair = 1D
    /// See KMIP 1.1 section 4.26 Discover Versions.
    /// See: https://docs.oasis-open.org/kmip/spec/v1.1/cs01/kmip-spec-v1.1-cs01.html#_Toc332787652
    DiscoverVersions(Vec<ProtocolVersion>),

    // TODO? Missing operation code mappings to request payloads
    // Encrypt = 1F
    // Decrypt = 20
    /// See KMIP 1.2 section 4.31 Sign.
    /// See: https://docs.oasis-open.org/kmip/spec/v1.2/os/kmip-spec-v1.2-os.html#_Toc409613558
    Sign(Option<UniqueIdentifier>, Option<CryptographicParameters>, Data),

    // TODO? Missing operation code mappings to request payloads
    // Signature Verify = 22
    // MAC = 23
    // MAC Verify = 24
    /// See KMIP 1.2 section 4.35 RNG Retrieve.
    /// See: https://docs.oasis-open.org/kmip/spec/v1.2/os/kmip-spec-v1.2-os.html#_Toc409613562
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

impl RequestPayload {
    pub const TAG: Tag = Tag::new(0x420079);

    pub fn fast_scan(scanner: &mut FastScanner<'_>, operation: Operation) -> Result<Self, FastScanError> {
        let mut scanner = scanner.scan_struct(Self::TAG)?;
        let this = match operation {
            Operation::Create => Self::Create(
                ObjectType::fast_scan(&mut scanner)?,
                TemplateAttribute::fast_scan(&mut scanner)?,
            ),
            Operation::CreateKeyPair => Self::CreateKeyPair(
                CommonTemplateAttribute::fast_scan_opt(&mut scanner)?,
                PrivateKeyTemplateAttribute::fast_scan_opt(&mut scanner)?,
                PublicKeyTemplateAttribute::fast_scan_opt(&mut scanner)?,
            ),
            Operation::Register => {
                let r#type = ObjectType::fast_scan(&mut scanner)?;
                Self::Register(
                    r#type,
                    TemplateAttribute::fast_scan(&mut scanner)?,
                    ManagedObject::fast_scan_opt(&mut scanner, r#type)?,
                )
            }
            Operation::Locate => Self::Locate(
                std::iter::from_fn(|| Attribute::fast_scan_opt(&mut scanner).transpose()).collect::<Result<_, _>>()?,
            ),
            Operation::Get => Self::Get(
                UniqueIdentifier::fast_scan_opt(&mut scanner)?,
                KeyFormatType::fast_scan_opt(&mut scanner)?,
                KeyCompressionType::fast_scan_opt(&mut scanner)?,
                KeyWrappingSpecification::fast_scan_opt(&mut scanner)?,
            ),
            Operation::GetAttributes => Self::GetAttributes(
                UniqueIdentifier::fast_scan_opt(&mut scanner)?,
                std::iter::from_fn(|| AttributeName::fast_scan_opt(&mut scanner).transpose())
                    .collect::<Result<Vec<_>, _>>()
                    .map(Some)?
                    .filter(|s| !s.is_empty()),
            ),
            Operation::GetAttributeList => Self::GetAttributeList(UniqueIdentifier::fast_scan_opt(&mut scanner)?),
            Operation::AddAttribute => Self::AddAttribute(
                UniqueIdentifier::fast_scan_opt(&mut scanner)?,
                Attribute::fast_scan(&mut scanner)?,
            ),
            Operation::ModifyAttribute => Self::ModifyAttribute(
                UniqueIdentifier::fast_scan_opt(&mut scanner)?,
                Attribute::fast_scan(&mut scanner)?,
            ),
            Operation::DeleteAttribute => Self::DeleteAttribute(
                UniqueIdentifier::fast_scan_opt(&mut scanner)?,
                AttributeName::fast_scan(&mut scanner)?,
                AttributeIndex::fast_scan_opt(&mut scanner)?,
            ),
            Operation::Activate => Self::Activate(UniqueIdentifier::fast_scan_opt(&mut scanner)?),
            Operation::Revoke => Self::Revoke(
                UniqueIdentifier::fast_scan_opt(&mut scanner)?,
                RevocationReason::fast_scan(&mut scanner)?,
                CompromiseOccurrenceDate::fast_scan_opt(&mut scanner)?,
            ),
            Operation::Destroy => Self::Destroy(UniqueIdentifier::fast_scan_opt(&mut scanner)?),
            Operation::Query => Self::Query(
                std::iter::from_fn(|| QueryFunction::fast_scan_opt(&mut scanner).transpose())
                    .collect::<Result<_, _>>()?,
            ),
            Operation::DiscoverVersions => Self::DiscoverVersions(
                std::iter::from_fn(|| ProtocolVersion::fast_scan_opt(&mut scanner).transpose())
                    .collect::<Result<_, _>>()?,
            ),
            Operation::Sign => Self::Sign(
                UniqueIdentifier::fast_scan_opt(&mut scanner)?,
                CryptographicParameters::fast_scan_opt(&mut scanner)?,
                Data::fast_scan(&mut scanner)?,
            ),
            Operation::RNGRetrieve => Self::RNGRetrieve(DataLength::fast_scan(&mut scanner)?),

            _ => unimplemented!(),
        };
        scanner.finish()?;
        Ok(this)
    }

    pub fn format(&self, formatter: &mut Formatter<'_>) -> FormatResult {
        let mut formatter = formatter.format_struct(Self::TAG)?;
        match self {
            RequestPayload::Create(object_type, template_attribute) => {
                object_type.format(&mut formatter)?;
                template_attribute.format(&mut formatter)?;
            }
            RequestPayload::CreateKeyPair(
                common_template_attribute,
                private_key_template_attribute,
                public_key_template_attribute,
            ) => {
                if let Some(x) = common_template_attribute {
                    x.format(&mut formatter)?;
                }
                if let Some(x) = private_key_template_attribute {
                    x.format(&mut formatter)?;
                }
                if let Some(x) = public_key_template_attribute {
                    x.format(&mut formatter)?;
                }
            }
            RequestPayload::Register(object_type, template_attribute, managed_object) => {
                object_type.format(&mut formatter)?;
                template_attribute.format(&mut formatter)?;
                if let Some(x) = managed_object {
                    x.format(&mut formatter)?;
                }
            }
            RequestPayload::Locate(attributes) => {
                for x in attributes {
                    x.format(&mut formatter)?;
                }
            }
            RequestPayload::Get(
                unique_identifier,
                key_format_type,
                key_compression_type,
                key_wrapping_specification,
            ) => {
                if let Some(x) = unique_identifier {
                    x.format(&mut formatter)?;
                }
                if let Some(x) = key_format_type {
                    x.format(&mut formatter)?;
                }
                if let Some(x) = key_compression_type {
                    x.format(&mut formatter)?;
                }
                if let Some(x) = key_wrapping_specification {
                    x.format(&mut formatter)?;
                }
            }
            RequestPayload::GetAttributes(unique_identifier, attribute_names) => {
                if let Some(x) = unique_identifier {
                    x.format(&mut formatter)?;
                }
                for x in attribute_names.iter().flatten() {
                    x.format(&mut formatter)?;
                }
            }
            RequestPayload::GetAttributeList(unique_identifier) => {
                if let Some(x) = unique_identifier {
                    x.format(&mut formatter)?;
                }
            }
            RequestPayload::AddAttribute(unique_identifier, attribute) => {
                if let Some(x) = unique_identifier {
                    x.format(&mut formatter)?;
                }
                attribute.format(&mut formatter)?;
            }
            RequestPayload::ModifyAttribute(unique_identifier, attribute) => {
                if let Some(x) = unique_identifier {
                    x.format(&mut formatter)?;
                }
                attribute.format(&mut formatter)?;
            }
            RequestPayload::DeleteAttribute(unique_identifier, attribute_name, attribute_index) => {
                if let Some(x) = unique_identifier {
                    x.format(&mut formatter)?;
                }
                attribute_name.format(&mut formatter)?;
                if let Some(x) = attribute_index {
                    x.format(&mut formatter)?;
                }
            }
            RequestPayload::Activate(unique_identifier) => {
                if let Some(x) = unique_identifier {
                    x.format(&mut formatter)?;
                }
            }
            RequestPayload::Revoke(unique_identifier, revocation_reason, compromise_occurrence_date) => {
                if let Some(x) = unique_identifier {
                    x.format(&mut formatter)?;
                }
                revocation_reason.format(&mut formatter)?;
                if let Some(x) = compromise_occurrence_date {
                    x.format(&mut formatter)?;
                }
            }
            RequestPayload::Destroy(unique_identifier) => {
                if let Some(x) = unique_identifier {
                    x.format(&mut formatter)?;
                }
            }
            RequestPayload::Query(query_functions) => {
                for x in query_functions {
                    x.format(&mut formatter)?;
                }
            }
            RequestPayload::DiscoverVersions(protocol_versions) => {
                for x in protocol_versions {
                    x.format(&mut formatter)?;
                }
            }
            RequestPayload::Sign(unique_identifier, cryptographic_parameters, data) => {
                if let Some(x) = unique_identifier {
                    x.format(&mut formatter)?;
                }
                if let Some(x) = cryptographic_parameters {
                    x.format(&mut formatter)?;
                }
                data.format(&mut formatter)?;
            }
            RequestPayload::RNGRetrieve(data_length) => {
                data_length.format(&mut formatter)?;
            }
        }
        Ok(formatter.finish())
    }
}

/// See KMIP 1.0 section 9.1.3.2.4 [Wrapping Method Enumeration](https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Ref241993348).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Ordinalize)]
#[non_exhaustive]
#[repr(u32)]
pub enum WrappingMethod {
    Encrypt = 1,
    MACSign,
    EncryptThenMACSign,
    MACSignThenEncrypt,
    TR31,
}

impl_ttlv_serde!(enum WrappingMethod as 0x42009E);

impl fmt::Display for WrappingMethod {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str(match self {
            Self::Encrypt => "Encrypt",
            Self::MACSign => "MACSign",
            Self::EncryptThenMACSign => "EncryptThenMACSign",
            Self::MACSignThenEncrypt => "MACSignThenEncrypt",
            Self::TR31 => "TR31",
        })
    }
}

/// See KMIP 1.0 section 9.1.3.2.23 [Query Function Enumeration](https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Ref242030554).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Ordinalize)]
#[non_exhaustive]
#[repr(u32)]
pub enum QueryFunction {
    QueryOperations = 1,
    QueryObjects,
    QueryServerInformation,
    // Note: This set of enum variants is deliberately limited to those that we currently support.
}

impl_ttlv_serde!(enum QueryFunction as 0x420074);

impl fmt::Display for QueryFunction {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str(match self {
            Self::QueryOperations => "QueryOperations",
            Self::QueryObjects => "QueryObjects",
            Self::QueryServerInformation => "QueryServerInformation",
        })
    }
}
