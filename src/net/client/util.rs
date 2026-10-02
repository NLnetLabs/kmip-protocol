use crate::{
    net::client::error::{NetError, NetResult},
    types::{
        request::{self, Authentication, MaximumResponseSize, RequestHeader, RequestMessage, RequestPayload},
        response::{self, ResponsePayload},
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

pub fn payload_to_request(
    auth: Option<Authentication>,
    max_response_size: Option<MaximumResponseSize>,
    payload: RequestPayload,
) -> NetResult<RequestMessage> {
    let batch_items = vec![request::BatchItem(payload.operation(), None, payload)];
    batch_items_to_request(auth, max_response_size, batch_items)
}

/// Extract the first successful operation payload from a KMIP response.
///
/// Useful when invoking [`Client::do_request()`] for cases where only a single
/// batch item is expected in the response.
impl TryFrom<Vec<NetResult<response::BatchItem>>> for ResponsePayload {
    type Error = NetError;

    fn try_from(mut res: Vec<NetResult<response::BatchItem>>) -> NetResult<Self> {
        res.pop()
            .transpose()?
            .ok_or_else(|| NetError::UnexpectedData("No successful response batch item found".into()))
            .and_then(|batch_item| {
                batch_item
                    .payload
                    .ok_or_else(|| NetError::UnexpectedData("No successful response payload found".into()))
            })
    }
}
