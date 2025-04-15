//! Rust types common to both serialization of KMIP requests and deserialization KMIP responses.
use serde_derive::Deserialize;
use serde_derive::Serialize;

use enum_display_derive::Display;
use enum_flags::EnumFlags;
use std::fmt::Display;

/// See KMIP 1.0 section 2.1.1 [Attribute](https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581155).
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename = "Transparent:0x42000A")]
pub struct AttributeName(pub String);

impl std::cmp::PartialEq<str> for AttributeName {
    fn eq(&self, other: &str) -> bool {
        self.0 == other
    }
}

/// See KMIP 1.0 section 2.1.1 [Attribute](https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581155).
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename = "Transparent:0x420009")]
pub struct AttributeIndex(pub i32);

impl std::cmp::PartialEq<i32> for AttributeIndex {
    fn eq(&self, other: &i32) -> bool {
        &self.0 == other
    }
}

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
    // Not implemented

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
    // Not implemented

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

/// See KMIP 1.0 section 2.1.4 [Key Value](https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581158).
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename = "0x420043")]
pub enum KeyMaterial {
    #[serde(rename(deserialize = "if 0x420042 in [0x00000001, 0x00000002, 0x00000003, 0x00000004, 0x00000006]"))] // Raw, Opaque, PKCS1, PKCS8 or ECPrivateKey
    #[serde(rename(serialize = "Transparent"))]
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

/// See KMIP 1.0 section 2.1.7.1 [Transparent Symmetric Key](https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581161).
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename = "0x420043")]
pub struct TransparentSymmetricKey {
    #[serde(with = "serde_bytes")]
    pub key: Vec<u8>,
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

/// See KMIP 1.0 section 2.1.7.5 [Transparent RSA Public Key](https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581161).
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename = "0x420043")]
pub struct TransparentRSAPublicKey {
    #[serde(with = "serde_bytes")]
    pub modulus: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub public_exponent: Vec<u8>,
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

/// See KMIP 1.2 section 2.1.10 [Data](https://docs.oasis-open.org/kmip/spec/v1.2/os/kmip-spec-v1.2-os.html#_Toc395776391).
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename(deserialize = "0x4200C2"))]
#[serde(rename(serialize = "Transparent:0x4200C2"))]
pub struct Data(#[serde(with = "serde_bytes")] pub Vec<u8>);

/// See KMIP 1.2 section 2.1.11 [Data Length](https://docs.oasis-open.org/kmip/spec/v1.2/os/kmip-spec-v1.2-os.html#_Toc409613467).
#[derive(Clone, Copy, Debug, Serialize, PartialEq, Eq)]
#[serde(rename = "Transparent:0x4200C4")]
pub struct DataLength(pub i32);

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

/// See KMIP 1.0 section 3.2 [Name](https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581174).
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename = "Transparent:0x420055")]
pub struct NameValue(pub String);

impl std::fmt::Display for NameValue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// See KMIP 1.0 section 3.3 [Object Type](https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581175).
#[derive(Clone, Copy, Debug, Deserialize, Serialize, Display, PartialEq, Eq)]
#[serde(rename = "0x420057")]
#[non_exhaustive]
pub enum ObjectType {
    // KMIP 1.0 and 1.1 variants
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

    // KMIP 1.2 variants
    #[serde(rename = "0x00000009")]
    PGPKey,
}

/// See KMIP 1.0 section 3.4 [Cryptographic Algorithm Enumeration](https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581176).
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

/// See KMIP 1.0 section 3.5 [Cryptographic Length](https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581177).
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename = "Transparent:0x42002A")]
pub struct CryptographicLength(pub i32);

/// See KMIP 1.0 section 3.6 [Cryptographic Parameters](https://docs.oasis-open.org/kmip/spec/v1.2/os/kmip-spec-v1.2-os.html#_Toc409613487).
#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename = "0x42002B")]
#[rustfmt::skip]
pub struct CryptographicParameters {
    #[serde(skip_serializing_if = "Option::is_none")] pub block_cipher_mode: Option<BlockCipherMode>,
    #[serde(skip_serializing_if = "Option::is_none")] pub padding_method: Option<PaddingMethod>,
    #[serde(skip_serializing_if = "Option::is_none")] pub hashing_algorithm: Option<HashingAlgorithm>,
    #[serde(skip_serializing_if = "Option::is_none")] pub key_role_type: Option<KeyRoleType>,
    #[serde(skip_serializing_if = "Option::is_none")] pub digital_signature_algorithm: Option<DigitalSignatureAlgorithm>, // KMIP 1.2
    #[serde(skip_serializing_if = "Option::is_none")] pub cryptographic_algorithm: Option<CryptographicAlgorithm>, // KMIP 1.2
    #[serde(skip_serializing_if = "Option::is_none")] pub random_iv: Option<RandomIV>, // KMIP 1.2
    #[serde(skip_serializing_if = "Option::is_none")] pub iv_length: Option<IVLength>, // KMIP 1.2
    #[serde(skip_serializing_if = "Option::is_none")] pub tag_length: Option<TagLength>, // KMIP 1.2
    #[serde(skip_serializing_if = "Option::is_none")] pub fixed_field_length: Option<FixedFieldLength>, // KMIP 1.2
    #[serde(skip_serializing_if = "Option::is_none")] pub invocation_field_length: Option<InvocationFieldLength>, // KMIP 1.2
    #[serde(skip_serializing_if = "Option::is_none")] pub counter_length: Option<CounterLength>, // KMIP 1.2
    #[serde(skip_serializing_if = "Option::is_none")] pub initial_counter_value: Option<InitialCounterValue>, // KMIP 1.2
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

/// See KMIP 1.2 section 3.6 [Cryptographic Parameters](https://docs.oasis-open.org/kmip/spec/v1.2/os/kmip-spec-v1.2-os.html#_Toc409613487).
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename = "Transparent:0x4200CD")]
pub struct IVLength(pub i32);

/// See KMIP 1.2 section 3.6 [Cryptographic Parameters](https://docs.oasis-open.org/kmip/spec/v1.2/os/kmip-spec-v1.2-os.html#_Toc409613487).
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename = "Transparent:0x4200CE")]
pub struct TagLength(pub i32);

/// See KMIP 1.2 section 3.6 [Cryptographic Parameters](https://docs.oasis-open.org/kmip/spec/v1.2/os/kmip-spec-v1.2-os.html#_Toc409613487).
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename = "Transparent:0x4200CF")]
pub struct FixedFieldLength(pub i32);

/// See KMIP 1.2 section 3.6 [Cryptographic Parameters](https://docs.oasis-open.org/kmip/spec/v1.2/os/kmip-spec-v1.2-os.html#_Toc409613487).
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename = "Transparent:0x4200D2")]
pub struct InvocationFieldLength(pub i32);

/// See KMIP 1.2 section 3.6 [Cryptographic Parameters](https://docs.oasis-open.org/kmip/spec/v1.2/os/kmip-spec-v1.2-os.html#_Toc409613487).
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename = "Transparent:0x4200D0")]
pub struct CounterLength(pub i32);

/// See KMIP 1.2 section 3.6 [Cryptographic Parameters](https://docs.oasis-open.org/kmip/spec/v1.2/os/kmip-spec-v1.2-os.html#_Toc409613487).
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename = "Transparent:0x4200D1")]
pub struct InitialCounterValue(pub i32);

/// See KMIP 1.0 section 3.14 [Cryptographic Usage Mask](https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581188).
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

/// See KMIP 1.0 section 3.24 [Compromise Occurrence Date](https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581198).
#[derive(Clone, Copy, Debug, Serialize, PartialEq, Eq)]
#[serde(rename = "Transparent:0x420021")]
pub struct CompromiseOccurrenceDate(pub u64);

/// See KMIP 1.0 section 3.26 [Revocation Reason](https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581200).
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
#[serde(rename = "Transparent:0x420080")]
pub struct RevocationMessage(pub String);

/// See KMIP 1.0 section 3.29 [Linked Object Identifier](https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581203).
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename = "Transparent:0x42004C")]
pub struct LinkedObjectIdentifier(pub String);

/// See KMIP 1.0 section 3.30 [Application Namespace](https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581204).
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename = "Transparent:0x420003")]
pub struct ApplicationNamespace(pub String);

/// See KMIP 1.0 section 3.30 [Application Data](https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581204).
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename = "Transparent:0x420002")]
pub struct ApplicationData(pub String);

/// See KMIP 1.0 section 6.4 [Unique Batch Item ID](https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581242).
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename(serialize = "Transparent:0x420093"))]
pub struct UniqueBatchItemID(#[serde(with = "serde_bytes")] pub Vec<u8>);

impl PartialEq<Vec<u8>> for &UniqueBatchItemID {
    fn eq(&self, other: &Vec<u8>) -> bool {
        &self.0 == other
    }
}

/// See KMIP 1.0 section 9.1.3.2.2 [Key Compression Type Enumeration](https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Ref241603856).
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

/// See KMIP 1.0 section 9.1.3.2.3 [Key Format Type Enumeration](https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Ref241992670).
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

/// See KMIP 1.0 section 9.1.3.2.6 [Certificate Type Enumeration](https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Ref241994296).
#[derive(Clone, Copy, Debug, Deserialize, Serialize, Display, PartialEq, Eq)]
#[serde(rename = "0x42001D")]
#[non_exhaustive]
pub enum CertificateType {
    #[serde(rename = "0x00000001")]
    X509,

    #[serde(rename = "0x00000002")]
    PGP,
}

/// See KMIP 1.2 section 9.1.3.2.7 [Digital Signature Algorithm Enumeration](https://docs.oasis-open.org/kmip/spec/v1.2/os/kmip-spec-v1.2-os.html#_Ref306812211).
#[derive(Clone, Copy, Debug, Deserialize, Serialize, Display, PartialEq, Eq)]
#[serde(rename = "0x4200AE")]
#[non_exhaustive]
#[allow(non_camel_case_types)]
pub enum DigitalSignatureAlgorithm {
    #[serde(rename = "0x00000001")]
    MD2WithRSAEncryption_PKCS1_v1_5,

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

/// See KMIP 1.0 section 9.1.3.2.10 [Name Type Enumeration](https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262582060).
#[derive(Clone, Copy, Debug, Deserialize, Serialize, Display, PartialEq, Eq)]
#[serde(rename = "0x420054")]
#[non_exhaustive]
pub enum NameType {
    #[serde(rename = "0x00000001")]
    UninterpretedTextString,

    #[serde(rename = "0x00000002")]
    URI,
}

/// See KMIP 1.0 section 9.1.3.2.13 [Block Cipher Mode Enumeration](https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc236497881).
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

/// See KMIP 1.0 section 9.1.3.2.14 [Padding Method Enumeration](https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc236497882).
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

/// See KMIP 1.0 section 9.1.3.2.15 [Hashing Algorithm Enumeration](https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc236497883).
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

/// See KMIP 1.0 section 9.1.3.2.15 [Key Role Type Enumeration](https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc236497884).
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

/// See KMIP 1.0 section 9.1.3.2.17 [State Enumeration](https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262582066).
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

/// See KMIP 1.0 section 9.1.3.2.18 [Revocation Reason Code Enumeration](https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Ref241996204).
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

/// See KMIP 1.0 section 9.1.3.2.19 [Link Type Enumeration](https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262582069).
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

/// See KMIP 1.0 section 9.1.3.2.26 [Operation Enumeration](https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc236497894).
#[derive(Clone, Copy, Debug, Deserialize, Serialize, Display, PartialEq, Eq)]
#[serde(rename = "0x42005C")]
#[non_exhaustive]
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
