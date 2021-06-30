use serde_derive::Deserialize;

use super::common::{ObjectType, Operation, UniqueIdentifier};

// KMIP spec 1.0 section 4.1 Create
// See: http://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581209
#[derive(Deserialize)]
pub struct CreateResponsePayload {
    #[serde(rename = "0x420057")]
    object_type: ObjectType,

    #[serde(rename = "0x420094")]
    unique_id: String,
}

// KMIP spec 1.2 section 4.26 Discover Versions
// See: http://docs.oasis-open.org/kmip/spec/v1.2/os/kmip-spec-v1.2-os.html#_Toc409613553
#[derive(Deserialize)]
pub struct DiscoverVersionsResponsePayload {
    #[serde(rename = "0x420069")]
    supported_versions: Vec<ProtocolVersion>,
}

// KMIP spec 1.2 section 4.31 Sign
// See: http://docs.oasis-open.org/kmip/spec/v1.2/os/kmip-spec-v1.2-os.html#_Toc409613558
#[derive(Deserialize)]
pub struct SignResponsePayload {
    #[serde(rename = "0x420094")]
    unique_identifier: UniqueIdentifier,

    #[serde(rename = "0x420094")]
    signature_data: SignatureData,
}

#[derive(Deserialize)]
pub struct SignatureData(Vec<u8>);

// KMIP spec 1.0 section 6.1 Protocol Version
// See: http://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581239
#[derive(Deserialize)]
pub struct ProtocolVersion {
    #[serde(rename = "0x42006A")]
    major: i32,

    #[serde(rename = "0x42006B")]
    minor: i32,
}

// KMIP spec 1.0 section 6.9 Result Status
// See: http://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581247
#[derive(Deserialize)]
pub enum ResultStatus {
    #[serde(rename = "0x00000000")]
    Success,
}

// KMIP spec 1.0 section 7.1 Message Format
// See: http://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581256
#[derive(Deserialize)]
pub struct ResponseMessage {
    #[serde(rename = "0x42007A")]
    header: ResponseHeader,

    #[serde(rename = "0x42000F")]
    items: Vec<BatchItem>,
}

// KMIP spec 1.0 section 7.2 Operations
// See: http://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581257
#[derive(Deserialize)]
pub struct ResponseHeader {
    #[serde(rename = "0x420069")]
    ver: ProtocolVersion,

    #[serde(rename = "0x420092")]
    timestamp: i64,

    #[serde(rename = "0x42000D")]
    item_count: i32,
}

#[derive(Deserialize)]
pub struct BatchItem {
    #[serde(rename = "0x42005C")]
    operation: Operation,

    #[serde(rename = "0x42007F")]
    status: ResultStatus,

    #[serde(rename = "0x42007C")]
    payload: ResponsePayload,
}

#[derive(Deserialize)]
pub enum ResponsePayload {
    // KMIP spec 1.0 operations
    #[serde(rename = "if 0x42005C==0x00000001")]
    Create(CreateResponsePayload),

    // KMIP spec 1.2 operations
    #[serde(rename = "if 0x42005C==0x0000001E")]
    DiscoverVersions(DiscoverVersionsResponsePayload),

    #[serde(rename = "if 0x42005C==0x00000021")]
    Sign(SignResponsePayload),
}
