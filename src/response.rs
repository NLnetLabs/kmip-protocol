//! Deserialiation of KMIP responses.

use kmip_ttlv::error::Result;
use serde::Deserialize;

use crate::types::common::Operation;
use crate::types::response::{
    BatchItem, ProtocolVersion, ResponseHeader, ResponseMessage, ResponsePayload, ResultReason, ResultStatus,
};

pub fn from_slice<'de, T>(bytes: &'de [u8]) -> Result<T>
where
    T: Deserialize<'de>,
{
    kmip_ttlv::de::from_slice(bytes)
}

pub fn to_vec(
    protocol_version: ProtocolVersion,
    timestamp: i64,
    operation: Operation,
    result_status: ResultStatus,
    result_reason: Option<ResultReason>,
    result_message: Option<String>,
    payload: Option<ResponsePayload>,
) -> Result<Vec<u8>> {
    let request = ResponseMessage {
        header: ResponseHeader {
            protocol_version,
            timestamp,
            batch_count: 1,
        },
        batch_items: vec![BatchItem {
            operation: Some(operation),
            unique_batch_item_id: None,
            result_status,
            result_reason,
            result_message,
            payload,
            message_extension: None,
        }],
    };
    kmip_ttlv::ser::to_vec(&request)
}
