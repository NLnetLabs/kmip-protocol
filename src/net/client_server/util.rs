use std::time::SystemTime;

use crate::{
    net::client_server::error::{NetError, NetResult},
    types::{
        request::{self, Authentication, MaximumResponseSize, RequestHeader, RequestMessage, RequestPayload},
        response::{self, ResponseHeader, ResponseMessage, ResponsePayload, ResultReason, ResultStatus},
    },
};

pub fn batch_items_to_request(
    auth: Option<Authentication>,
    max_response_size: Option<MaximumResponseSize>,
    batch_items: Vec<request::BatchItem>,
) -> NetResult<RequestMessage> {
    if batch_items.is_empty() {
        return Err(NetError::SerializeError("Cannot serialize an empty batch".to_string()));
    }

    if batch_items.len() >= i32::MAX as usize {
        return Err(NetError::SerializeError(format!(
            "Too many batch items: {} > {}",
            batch_items.len(),
            i32::MAX
        )));
    }

    // Construct the request.
    let max_protocol_version = batch_items
        .iter()
        .map(|r| r.request_payload().protocol_version())
        .max()
        .unwrap();

    Ok(RequestMessage(
        RequestHeader(
            max_protocol_version,
            max_response_size,
            auth,
            request::BatchCount(batch_items.len().try_into().unwrap()),
        ),
        batch_items,
    ))
}

pub fn batch_items_to_response(batch_items: Vec<response::BatchItem>) -> NetResult<ResponseMessage> {
    if batch_items.len() >= i32::MAX as usize {
        return Err(NetError::SerializeError(format!(
            "Too many batch items: {} > {}",
            batch_items.len(),
            i32::MAX
        )));
    }

    let timestamp = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs()
        .try_into()
        .unwrap();

    let protocol_version = batch_items
        .iter()
        .filter_map(|item| item.payload.as_ref())
        .map(|payload| payload.protocol_version())
        .max()
        .unwrap_or_default();

    Ok(ResponseMessage {
        header: ResponseHeader {
            protocol_version,
            timestamp,
            batch_count: batch_items.len().try_into().unwrap(),
        },
        batch_items,
    })
}

pub fn payload_to_request(
    auth: Option<Authentication>,
    max_response_size: Option<MaximumResponseSize>,
    payload: RequestPayload,
) -> NetResult<RequestMessage> {
    let batch_items = vec![request::BatchItem(payload.operation(), None, payload)];
    batch_items_to_request(auth, max_response_size, batch_items)
}

pub fn payload_to_response(
    result_status: ResultStatus,
    result_reason: Option<ResultReason>,
    result_message: Option<String>,
    payload: Option<ResponsePayload>,
) -> NetResult<ResponseMessage> {
    let batch_items = vec![response::BatchItem {
        operation: payload.as_ref().map(|p| p.operation()),
        unique_batch_item_id: None,
        result_status,
        result_reason,
        result_message,
        payload,
        message_extension: None,
    }];
    batch_items_to_response(batch_items)
}
