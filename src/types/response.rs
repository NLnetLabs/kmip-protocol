//! Rust types for deserializing KMIP responses.
use serde_derive::Deserialize;

use enum_display_derive::Display;
use std::fmt::Display;

use super::common::{
    AttributeIndex, AttributeName, AttributeValue, CertificateType, CryptographicAlgorithm, KeyCompressionType,
    KeyFormatType, KeyMaterial, NameType, NameValue, ObjectType, Operation, UniqueBatchItemID, UniqueIdentifier,
};

///  See KMIP 1.0 section 2.1.3 [Key Block](https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581157).
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename = "0x420040")]
pub struct KeyBlock {
    #[serde(rename = "0x420042")]
    pub key_format_type: KeyFormatType,

    #[serde(rename = "0x420041")]
    pub key_compression_type: Option<KeyCompressionType>,

    #[serde(rename = "0x420045")]
    pub key_value: KeyValue,

    #[serde(rename = "0x420028")]
    pub cryptographic_algorithm: Option<CryptographicAlgorithm>,

    #[serde(rename = "0x42002A")]
    pub cryptographic_length: Option<i32>,

    #[serde(rename = "0x420046")]
    pub key_wrapping_data: Option<()>, // TODO
}

///  See KMIP 1.0 section 2.1.4 [Key Value](https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581158).
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename = "0x420045")]
pub struct KeyValue {
    pub key_material: KeyMaterial,
    pub attributes: Option<Vec<Attribute>>,
}

///  See KMIP 1.0 section 2.1.8 [Template Attribute](https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581162).
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename = "0x420091")]
pub struct TemplateAttribute {
    pub name: KeyMaterial,
    pub attributes: Option<Vec<Attribute>>,
}

///  See KMIP 1.0 section 2.2 [Managed Objects](https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581163).
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
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

///  See KMIP 1.0 section 2.2.1 [Certificate](https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581164).
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename = "0x420013")]
pub struct Certificate {
    pub certificate_type: CertificateType,
    #[serde(with = "serde_bytes")]
    pub certificate_value: Vec<u8>,
}

///  See KMIP 1.0 section 2.2.2 [Symmetric Key](https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581165).
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename = "0x42008F")]
pub struct SymmetricKey {
    pub key_block: KeyBlock,
}

///  See KMIP 1.0 section 2.2.3 [Public Key](https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581166).
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename = "0x42006D")]
pub struct PublicKey {
    pub key_block: KeyBlock,
}

///  See KMIP 1.0 section 2.2.4 [Private Key](https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581167).
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename = "0x420064")]
pub struct PrivateKey {
    pub key_block: KeyBlock,
}

///  See KMIP 1.0 section 3.2 [Name](https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581174).
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename = "0x420053")]
pub struct Name {
    pub name: NameValue,
    pub r#type: NameType,
}

///  See KMIP 1.0 section 4.1 [Create](https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581209).
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename = "0x42007C")]
pub struct CreateResponsePayload {
    pub object_type: ObjectType,
    pub unique_identifier: UniqueIdentifier,
    pub object_attributes: Option<Vec<Attribute>>,
}

///  See KMIP 1.0 section 4.2 [Create Key Pair](https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581210).
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename = "0x42007C")]
pub struct CreateKeyPairResponsePayload {
    #[serde(rename = "0x420066")]
    pub private_key_unique_identifier: UniqueIdentifier,

    #[serde(rename = "0x42006F")]
    pub public_key_unique_identifier: UniqueIdentifier,
    // TODO: Add the optional response field that lists attributes for the private key

    // TODO: Add the optional response field that lists attributes for the public key
}

///  See KMIP 1.0 section 4.3 [Register](https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581211).
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename = "0x42007C")]
pub struct RegisterResponsePayload {
    #[serde(rename = "0x420094")]
    pub unique_identifier: UniqueIdentifier,

    #[serde(rename = "0x420091")]
    pub template_attributes: Option<Vec<TemplateAttribute>>,
}

///  See KMIP 1.0 section 4.8 [Locate](https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581216).
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename = "0x42007C")]
pub struct LocateResponsePayload {
    #[serde(rename = "0x420094")]
    pub unique_identifiers: Vec<UniqueIdentifier>,
}

///  See KMIP 1.0 section 4.10 [Get](https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581218).
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename = "0x42007C")]
pub struct GetResponsePayload {
    pub object_type: ObjectType,
    pub unique_identifier: UniqueIdentifier,
    pub cryptographic_object: ManagedObject,
}

///  See KMIP 1.0 section 4.11 [Get Attributes](https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581219).
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename = "0x42007C")]
pub struct GetAttributesResponsePayload {
    #[serde(rename = "0x420094")]
    pub unique_identifier: UniqueIdentifier,

    #[serde(rename = "0x420008")]
    pub attributes: Option<Vec<Attribute>>,
}

///  See KMIP 1.0 section 4.12 [Get Attribute List](https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581220).
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename = "0x42007C")]
pub struct GetAttributeListResponsePayload {
    #[serde(rename = "0x420094")]
    pub unique_identifier: UniqueIdentifier,

    #[serde(rename = "0x42000A")]
    pub attributes: Vec<AttributeName>,
}

/// Fields common to sections 4.18 [Activate](https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581226),
/// 4.19 [Revoke](https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581227)
/// and 4.20 [Destroy](http://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581228) responses.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename = "0x42007C")]
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
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename = "0x42007C")]
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
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename = "0x42007C")]
pub struct QueryResponsePayload {
    #[serde(rename = "0x42005C")]
    pub operations: Option<Vec<Operation>>,

    #[serde(rename = "0x420057")]
    pub object_types: Option<Vec<ObjectType>>,

    #[serde(rename = "0x42009D")]
    pub vendor_identification: Option<String>,

    #[serde(rename = "0x420088")]
    #[serde(skip_deserializing)] // We don't support this yet
    #[serde(default)]
    pub server_information: Option<ServerInformation>,
}

///  See KMIP 1.0 section 4.24 [Query](https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581232).
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename = "0x42007C")]
pub struct RNGRetrieveResponsePayload {
    #[serde(with = "serde_bytes")]
    pub data: Vec<u8>,
}

///  See KMIP 1.0 section 4.24 [Server Information](https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581232).
#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Default)]
#[serde(rename = "0x420088")]
pub struct ServerInformation;

///  See KMIP 1.1 section 4.26 [Discover Versions](https://docs.oasis-open.org/kmip/spec/v1.1/cs01/kmip-spec-v1.1-cs01.html#_Toc332787652).
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename = "0x42007C")]
pub struct DiscoverVersionsResponsePayload {
    #[serde(rename = "0x420069")]
    pub supported_versions: Option<Vec<ProtocolVersion>>,
}

///  See KMIP 1.2 section 4.31 [Sign](https://docs.oasis-open.org/kmip/spec/v1.2/os/kmip-spec-v1.2-os.html#_Toc409613558).
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename = "0x42007C")]
pub struct SignResponsePayload {
    #[serde(rename = "0x420094")]
    pub unique_identifier: UniqueIdentifier,

    #[serde(rename = "0x4200C3")]
    #[serde(with = "serde_bytes")]
    pub signature_data: Vec<u8>,
}

///  See KMIP 1.0 section 6.1 [Protocol Version](https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581239).
#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename = "0x420069")]
pub struct ProtocolVersion {
    #[serde(rename = "0x42006A")]
    pub major: i32,

    #[serde(rename = "0x42006B")]
    pub minor: i32,
}

///  See KMIP 1.0 section 6.9 [Result Status](https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581247).
#[derive(Clone, Copy, Debug, Deserialize, Display, PartialEq, Eq)]
#[non_exhaustive]
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

///  See KMIP 1.0 section 6.10 [Result Reason](https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581248).
#[derive(Clone, Copy, Debug, Deserialize, Display, PartialEq, Eq)]
#[non_exhaustive]
pub enum ResultReason {
    #[serde(rename = "0x00000001")]
    ItemNotFound,

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

///  See KMIP 1.0 section 6.16 [Message Extension](https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581254).
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
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
#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Default)]
// #[serde(rename = "0x42009C", transparent)]
#[serde(rename = "0x42009C")]
pub struct VendorExtension;

///  See KMIP 1.0 section 7.1 [Message Structure](https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581256).
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename = "0x42007B")]
pub struct ResponseMessage {
    #[serde(rename = "0x42007A")]
    pub header: ResponseHeader,

    #[serde(rename = "0x42000F")]
    pub batch_items: Vec<BatchItem>,
}

///  See KMIP 1.0 section 7.2 [Operations](https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581257).
#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename = "0x42007A")]
pub struct ResponseHeader {
    #[serde(rename = "0x420069")]
    pub protocol_version: ProtocolVersion,

    #[serde(rename = "0x420092")]
    pub timestamp: i64,

    #[serde(rename = "0x42000D")]
    pub batch_count: i32,
}

///  See KMIP 1.0 section 6.15 [Batch Item](https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581253).
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename = "0x42000F")]
pub struct BatchItem {
    #[serde(rename = "0x42005C")]
    pub operation: Option<Operation>,

    #[serde(rename = "0x420093")]
    pub unique_batch_item_id: Option<UniqueBatchItemID>,

    #[serde(rename = "0x42007F")]
    pub result_status: ResultStatus,

    #[serde(rename = "0x42007E")]
    pub result_reason: Option<ResultReason>,

    #[serde(rename = "0x42007D")]
    pub result_message: Option<String>,

    // #[serde(rename = "0x420006")]
    // pub asynchronous_correlation_value: Option<??>,
    #[serde(rename = "0x42007C")]
    pub payload: Option<ResponsePayload>,

    #[serde(rename = "0x420051")]
    pub message_extension: Option<MessageExtension>,
}

///  See KMIP 1.0 section 7.2 [Operations](https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581257).
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[non_exhaustive]
#[allow(clippy::large_enum_variant)]
pub enum ResponsePayload {
    // ///  See KMIP 1.0 section 4.1 Create.
    // See: https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581209
    #[serde(rename = "if 0x42005C==0x00000001")]
    Create(CreateResponsePayload),

    // ///  See KMIP 1.0 section 4.2 Create Key Pair.
    // See: https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581210
    #[serde(rename = "if 0x42005C==0x00000002")]
    CreateKeyPair(CreateKeyPairResponsePayload),

    // ///  See KMIP 1.0 section 4.3 Register.
    // See: https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581211
    #[serde(rename = "if 0x42005C==0x00000003")]
    Register(RegisterResponsePayload),

    // ///  See KMIP 1.0 section 4.8 Locate.
    // See: https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581216
    #[serde(rename = "if 0x42005C==0x00000008")]
    Locate(LocateResponsePayload),

    // ///  See KMIP 1.0 section 4.10 Get.
    // See: https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581218
    #[serde(rename = "if 0x42005C==0x0000000A")]
    Get(GetResponsePayload),

    // ///  See KMIP 1.0 section 4.11 Get Attributes.
    // See: https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581219
    #[serde(rename = "if 0x42005C==0x0000000B")]
    GetAttributes(GetAttributesResponsePayload),

    // ///  See KMIP 1.0 section 4.12 Get Attribute List.
    // See: https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581220
    #[serde(rename = "if 0x42005C==0x0000000C")]
    GetAttributeList(GetAttributeListResponsePayload),

    // ///  See KMIP 1.0 section 4.13 Add Attribute.
    // See: https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581221
    #[serde(rename = "if 0x42005C==0x0000000D")]
    AddAttribute(AddAttributeResponsePayload),

    // ///  See KMIP 1.0 section 4.14 Modify Attribute.
    // See: https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581222
    #[serde(rename = "if 0x42005C==0x0000000E")]
    ModifyAttribute(ModifyAttributeResponsePayload),

    // ///  See KMIP 1.0 section 4.15 Delete Attribute.
    // See: https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581223
    #[serde(rename = "if 0x42005C==0x0000000F")]
    DeleteAttribute(DeleteAttributeResponsePayload),

    // ///  See KMIP 1.0 section 4.18 Activate.
    // See: https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581226
    #[serde(rename = "if 0x42005C==0x00000012")]
    Activate(ActivateResponsePayload),

    // ///  See KMIP 1.0 section 4.19 Revoke.
    // See: https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581227
    #[serde(rename = "if 0x42005C==0x00000013")]
    Revoke(RevokeResponsePayload),

    // ///  See KMIP 1.0 section 4.20 Destroy.
    // See: https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581228
    #[serde(rename = "if 0x42005C==0x00000014")]
    Destroy(DestroyResponsePayload),

    // ///  See KMIP 1.0 section 4.24 Query.
    // See: https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581232
    #[serde(rename = "if 0x42005C==0x00000018")]
    Query(QueryResponsePayload),

    // ///  See KMIP 1.1 section 4.26 Discover Versions.
    // See: https://docs.oasis-open.org/kmip/spec/v1.1/cs01/kmip-spec-v1.1-cs01.html#_Toc332787652
    #[serde(rename = "if 0x42005C==0x0000001E")]
    DiscoverVersions(DiscoverVersionsResponsePayload),

    // ///  See KMIP 1.2 section 4.31 Sign.
    // See: https://docs.oasis-open.org/kmip/spec/v1.2/os/kmip-spec-v1.2-os.html#_Toc409613558
    #[serde(rename = "if 0x42005C==0x00000021")]
    Sign(SignResponsePayload),

    // ///  See KMIP 1.2 section 4.35 RNG Retrieve.
    // See: https://docs.oasis-open.org/kmip/spec/v1.2/os/kmip-spec-v1.2-os.html#_Toc409613562
    #[serde(rename = "if 0x42005C==0x00000025")]
    RNGRetrieve(RNGRetrieveResponsePayload),
    // Note: This set of enum variants is deliberately limited to those that we currently support.
}

///  See KMIP 1.0 section 2.1.1 [Attribute](https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581155).
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename = "0x420008")]
pub struct Attribute {
    #[serde(rename = "0x42000A")]
    pub name: AttributeName,

    #[serde(rename = "0x420009")]
    pub index: Option<AttributeIndex>,

    #[serde(rename = "0x42000B")]
    pub value: AttributeValue,
}
