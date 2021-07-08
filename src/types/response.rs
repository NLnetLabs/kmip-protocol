use serde_derive::Deserialize;

use enum_display_derive::Display;
use std::fmt::Display;

use super::common::{ObjectType, Operation, UniqueIdentifier};

// KMIP spec 1.0 section 4.2 Create Key Pair
// See: https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581210
#[derive(Deserialize)]
#[serde(rename = "0x42007C")]
pub struct CreateKeyPairResponsePayload {
    #[serde(rename = "0x420066")]
    pub private_key_unique_identifier: UniqueIdentifier,

    #[serde(rename = "0x42006F")]
    pub public_key_unique_identifier: UniqueIdentifier,
    // TODO: Add the optional response field that lists attributes for the private key

    // TODO: Add the optional response field that lists attributes for the public key
}

// KMIP spec 1.0 section 4.8 Locate
// See: https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581216
#[derive(Deserialize)]
#[serde(rename = "0x42007C")]
pub struct LocateResponsePayload {
    #[serde(rename = "0x420094")]
    pub unique_identifiers: Vec<UniqueIdentifier>,
}

// KMIP spec 1.0 section 4.8 Locate
// See: https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581228
#[derive(Deserialize)]
#[serde(rename = "0x42007C")]
pub struct DestroyResponsePayload {
    #[serde(rename = "0x420094")]
    pub unique_identifier: UniqueIdentifier,
}

// KMIP spec 1.0 section 4.24 Query
// See: https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581232
#[derive(Deserialize)]
#[serde(rename = "0x42007C")]
pub struct QueryResponsePayload {
    #[serde(rename = "0x42005C")]
    pub operations: Vec<Operation>,

    #[serde(rename = "0x420057")]
    pub object_types: Vec<ObjectType>,

    #[serde(rename = "0x42009D")]
    pub vendor_identification: Option<String>,

    #[serde(rename = "0x420088")]
    pub server_information: Option<ServerInformation>,
}

#[derive(Deserialize)]
#[serde(rename = "0x420088")]
pub struct ServerInformation {}

// KMIP spec 1.1 section 4.26 Discover Versions
// See: https://docs.oasis-open.org/kmip/spec/v1.1/cs01/kmip-spec-v1.1-cs01.html#_Toc332787652
#[derive(Deserialize)]
#[serde(rename = "0x42007C")]
pub struct DiscoverVersionsResponsePayload {
    #[serde(rename = "0x420069")]
    pub supported_versions: Vec<ProtocolVersion>,
}

// KMIP spec 1.2 section 4.31 Sign
// See: https://docs.oasis-open.org/kmip/spec/v1.2/os/kmip-spec-v1.2-os.html#_Toc409613558
#[derive(Deserialize)]
#[serde(rename = "0x42007C")]
pub struct SignResponsePayload {
    #[serde(rename = "0x420094")]
    pub unique_identifier: UniqueIdentifier,

    #[serde(rename = "0x420094")]
    pub signature_data: SignatureData,
}

#[derive(Deserialize)]
pub struct SignatureData(Vec<u8>);

// KMIP spec 1.0 section 6.1 Protocol Version
// See: https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581239
#[derive(Deserialize)]
#[serde(rename = "0x420069")]
pub struct ProtocolVersion {
    #[serde(rename = "0x42006A")]
    pub major: i32,

    #[serde(rename = "0x42006B")]
    pub minor: i32,
}

// KMIP spec 1.0 section 6.9 Result Status
// See: https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581247
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
// See: https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581248
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
// See: https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581254
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
// See: https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581256
#[derive(Deserialize)]
#[serde(rename = "0x42007B")]
pub struct ResponseMessage {
    #[serde(rename = "0x42007A")]
    pub header: ResponseHeader,

    #[serde(rename = "0x42000F")]
    pub batch_items: Vec<BatchItem>,
}

// KMIP spec 1.0 section 7.2 Operations
// See: https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581257
#[derive(Deserialize)]
#[serde(rename = "0x42007A")]
pub struct ResponseHeader {
    #[serde(rename = "0x420069")]
    pub protocol_version: ProtocolVersion,

    #[serde(rename = "0x420092")]
    pub timestamp: i64,

    #[serde(rename = "0x42000D")]
    pub batch_count: i32,
}

#[derive(Deserialize)]
#[serde(rename = "0x42000F")]
pub struct BatchItem {
    #[serde(rename = "0x42005C")]
    #[serde(default)]
    pub operation: Option<Operation>,

    // pub unique_batch_item_id: Option<...> // we don't have this field yet because (a) per the spec we don't need it
    //                                          because we don't send it in the request, and (b) because it uses the
    //                                          TTLV ByteString type which the krill-kmip-ttlv crate doesn't support
    //                                          yet.
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

#[derive(Deserialize)]
#[non_exhaustive]
pub enum ResponsePayload {
    // KMIP spec 1.0 section 4.2 Create Key Pair
    // See: https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581210
    #[serde(rename = "if 0x42005C==0x00000002")]
    CreateKeyPair(CreateKeyPairResponsePayload),

    // KMIP spec 1.0 section 4.8 Locate
    // See: https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581216
    #[serde(rename = "if 0x42005C==0x00000008")]
    Locate(LocateResponsePayload),

    // KMIP spec 1.0 section 4.20 Destroy
    // See: https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581228
    #[serde(rename = "if 0x42005C==0x00000014")]
    Destroy(DestroyResponsePayload),

    // KMIP spec 1.0 section 4.24 Query
    // See: https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581232
    #[serde(rename = "if 0x42005C==0x00000018")]
    Query(QueryResponsePayload),

    // KMIP spec 1.1 section 4.26 Discover Versions
    // See: https://docs.oasis-open.org/kmip/spec/v1.1/cs01/kmip-spec-v1.1-cs01.html#_Toc332787652
    #[serde(rename = "if 0x42005C==0x0000001E")]
    DiscoverVersions(DiscoverVersionsResponsePayload),

    // KMIP spec 1.2 section 4.31 Sign
    // See: https://docs.oasis-open.org/kmip/spec/v1.2/os/kmip-spec-v1.2-os.html#_Toc409613558
    #[serde(rename = "if 0x42005C==0x00000021")]
    Sign(SignResponsePayload),
    // Note: This set of enum variants is deliberately limited to those that we currently support.
}
