use serde_derive::Deserialize;

use enum_display_derive::Display;
use std::fmt::Display;

use super::common::{Operation, UniqueIdentifier};

// KMIP spec 1.0 section 4.2 Create Key Pair
// See: http://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581210
#[derive(Deserialize)]
pub struct CreateKeyPairResponsePayload {
    #[serde(rename = "0x420066")]
    pub private_key_unique_identifier: String,

    #[serde(rename = "0x42006F")]
    pub public_key_unique_identifier: String,
}

// KMIP spec 1.2 section 4.26 Discover Versions
// See: http://docs.oasis-open.org/kmip/spec/v1.2/os/kmip-spec-v1.2-os.html#_Toc409613553
#[derive(Deserialize)]
pub struct DiscoverVersionsResponsePayload {
    #[serde(rename = "0x420069")]
    pub supported_versions: Vec<ProtocolVersion>,
}

// KMIP spec 1.2 section 4.31 Sign
// See: http://docs.oasis-open.org/kmip/spec/v1.2/os/kmip-spec-v1.2-os.html#_Toc409613558
#[derive(Deserialize)]
pub struct SignResponsePayload {
    #[serde(rename = "0x420094")]
    pub unique_identifier: UniqueIdentifier,

    #[serde(rename = "0x420094")]
    pub signature_data: SignatureData,
}

#[derive(Deserialize)]
pub struct SignatureData(Vec<u8>);

// KMIP spec 1.0 section 6.1 Protocol Version
// See: http://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581239
#[derive(Deserialize)]
pub struct ProtocolVersion {
    #[serde(rename = "0x42006A")]
    pub major: i32,

    #[serde(rename = "0x42006B")]
    pub minor: i32,
}

// KMIP spec 1.0 section 6.9 Result Status
// See: http://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581247
#[derive(Deserialize, Display)]
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

// KMIP spec 1.0 section 6.10 Result Reason
// See: http://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581248
#[derive(Deserialize, Display)]
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

// KMIP spec 1.0 section 6.16 Message Extension
// See: http://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581254
#[derive(Deserialize)]
pub struct MessageExtension {
    #[serde(rename = "0x42007A")]
    pub vendor_identification: String,

    #[serde(rename = "0x42009D")]
    pub criticality_indicator: bool,

    #[serde(rename = "0x42009C")]
    pub vendor_extension: VendorExtension,
}

#[derive(Deserialize)]
pub struct VendorExtension;

// KMIP spec 1.0 section 7.1 Message Format
// See: http://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581256
#[derive(Deserialize)]
#[serde(rename = "0x42007B")]
pub struct ResponseMessage {
    #[serde(rename = "0x42007A")]
    pub header: ResponseHeader,

    #[serde(rename = "0x42000F")]
    pub batch_items: Vec<BatchItem>,
}

// KMIP spec 1.0 section 7.2 Operations
// See: http://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581257
#[derive(Deserialize)]
pub struct ResponseHeader {
    #[serde(rename = "0x420069")]
    pub protocol_version: ProtocolVersion,

    #[serde(rename = "0x420092")]
    pub timestamp: i64,

    #[serde(rename = "0x42000D")]
    pub batch_count: i32,
}

#[derive(Deserialize)]
pub struct BatchItem {
    #[serde(rename = "0x42005C")]
    #[serde(default)]
    pub operation: Option<Operation>,

    // pub unique_batch_item_id: Option<...> // we don't have this field yet because (a) per the spec we don't need it
                                             // because we don't send it in the request, and (b) because it uses the
                                             // TTLV ByteString type which the krill-kmip-ttlv crate doesn't support
                                             // yet.

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
    pub message_extension: Option<MessageExtension>
}

#[derive(Deserialize)]
#[non_exhaustive]
pub enum ResponsePayload {
    // KMIP spec 1.0 operations
    #[serde(rename = "if 0x42005C==0x00000002")]
    CreateKeyPair(CreateKeyPairResponsePayload),

    // KMIP spec 1.1 operations
    #[serde(rename = "if 0x42005C==0x0000001E")]
    DiscoverVersions(DiscoverVersionsResponsePayload),
    
    // KMIP spec 1.2 operations
    #[serde(rename = "if 0x42005C==0x00000021")]
    Sign(SignResponsePayload),

    // Note: This set of enum variants is deliberately limited to those that we currently support.
}
