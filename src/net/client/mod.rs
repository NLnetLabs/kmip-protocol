//! A high level KMIP "operation" oriented client interface for request/response construction & (de)serialization.
pub mod builder;
pub mod error;
pub mod tests;
pub mod util;

use std::{
    mem::MaybeUninit,
    ops::DerefMut,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
};

use tracing::trace;

#[cfg(feature = "tokio")]
use tokio::sync::Mutex;

#[cfg(not(feature = "tokio"))]
use std::sync::Mutex;

use crate::{
    net::client::{
        error::{NetError, NetResult},
        util::{batch_items_to_request, payload_to_request},
    },
    ttlv::{FastScanError, FastScanner},
    types::{
        common::*,
        request::{
            self, Authentication, BatchItem, CommonTemplateAttribute, KeyWrappingSpecification, MaximumResponseSize,
            PrivateKeyTemplateAttribute, PublicKeyTemplateAttribute, QueryFunction, RequestMessage, RequestPayload,
            RevocationReason,
        },
        response::{
            self, CreateKeyPairResponsePayload, GetResponsePayload, QueryResponsePayload, ResponseMessage,
            ResponsePayload, ResultReason, ResultStatus,
        },
        traits::*,
    },
};

/// A client for serializing KMIP and deserializing KMIP responses to/from an established read/write stream.
///
/// Use the [ClientBuilder] to build a [Client] instance to work with.
#[derive(Debug)]
pub struct Client<T: ReadWrite> {
    auth: Option<Authentication>,
    max_message_size: i32,
    stream: Arc<Mutex<T>>,
    read_buf: Vec<u8>,
    write_buf: Vec<MaybeUninit<u8>>,
    connection_error_count: Arc<AtomicUsize>,
}

//--- High level client interface

impl<T: ReadWrite> Client<T> {
    /// Serialize a KMIP 1.0 [Query](https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581232) request.
    ///
    /// See also: [do_request()](Self::do_request())
    #[maybe_async::maybe_async]
    pub async fn query(&mut self) -> NetResult<QueryResponsePayload> {
        // Setup the request
        let wanted_info = vec![
            QueryFunction::QueryOperations,
            QueryFunction::QueryObjects,
            QueryFunction::QueryServerInformation,
        ];
        let request = RequestPayload::Query(wanted_info);

        // Execute the request and capture the response
        let res = self.do_request_payload(request).await?.try_into()?;

        let ResponsePayload::Query(payload) = res else {
            return Err(NetError::UnexpectedData(format!(
                "Expected Query payload but response has {res}"
            )));
        };

        Ok(payload)
    }

    /// Serialize a KMIP 1.0 [Create Key Pair](https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581269) request to create an RSA key pair.
    ///
    /// See also: [do_request()](Self::do_request())
    ///
    /// Creates an RSA key pair.
    ///
    /// To create keys of other types or with other parameters you must compose the Create Key Pair request manually
    /// and pass it to [do_request()](Self::do_request()) directly.
    #[maybe_async::maybe_async]
    pub async fn create_rsa_key_pair(
        &mut self,
        key_length: i32,
        private_key_name: String,
        public_key_name: String,
    ) -> NetResult<(String, String)> {
        // Setup the request
        let request = RequestPayload::CreateKeyPair(
            Some(CommonTemplateAttribute::new(vec![
                request::Attribute::CryptographicAlgorithm(CryptographicAlgorithm::RSA),
                request::Attribute::CryptographicLength(key_length),
            ])),
            Some(PrivateKeyTemplateAttribute::new(vec![
                request::Attribute::Name(private_key_name),
                request::Attribute::CryptographicUsageMask(CryptographicUsageMask::Sign),
            ])),
            Some(PublicKeyTemplateAttribute::new(vec![
                request::Attribute::Name(public_key_name),
                request::Attribute::CryptographicUsageMask(CryptographicUsageMask::Verify),
            ])),
        );

        // Execute the request and capture the response
        let res = self.do_request_payload(request).await?.try_into()?;

        // Execute the request and capture the response
        let ResponsePayload::CreateKeyPair(payload) = res else {
            return Err(NetError::UnexpectedData(format!(
                "Expected Query payload but response has {res}"
            )));
        };

        let CreateKeyPairResponsePayload {
            private_key_unique_identifier: UniqueIdentifier(prikey),
            public_key_unique_identifier: UniqueIdentifier(pubkey),
        } = payload;

        Ok((prikey, pubkey))
    }

    /// Serialize a KMIP 1.2 [Rng Retrieve](https://docs.oasis-open.org/kmip/spec/v1.2/os/kmip-spec-v1.2-os.html#_Toc409613562)
    /// operation to retrieve a number of random bytes.
    ///
    /// See also: [do_request()](Self::do_request())
    ///
    #[maybe_async::maybe_async]
    pub async fn rng_retrieve(&mut self, num_bytes: i32) -> NetResult<Vec<u8>> {
        let request = RequestPayload::RNGRetrieve(DataLength(num_bytes));

        // Execute the request and capture the response
        let res = self.do_request_payload(request).await?.try_into()?;

        let ResponsePayload::RNGRetrieve(payload) = res else {
            return Err(NetError::UnexpectedData(format!(
                "Expected RNGRetrieve payload but response has {res}"
            )));
        };

        Ok(payload.0.0)
    }

    /// Serialize a KMIP 1.2 [Sign](https://docs.oasis-open.org/kmip/spec/v1.2/os/kmip-spec-v1.2-os.html#_Toc409613558)
    /// operation to sign the given bytes with the given private key ID.
    ///
    /// See also: [do_request()](Self::do_request())
    ///
    #[maybe_async::maybe_async]
    pub async fn sign(&mut self, private_key_id: &str, in_bytes: &[u8]) -> NetResult<Vec<u8>> {
        let request = RequestPayload::Sign(
            Some(UniqueIdentifier(private_key_id.to_owned())),
            Some(
                CryptographicParameters::default()
                    .with_padding_method(PaddingMethod::PKCS1_v1_5)
                    .with_hashing_algorithm(HashingAlgorithm::SHA256)
                    .with_cryptographic_algorithm(CryptographicAlgorithm::RSA),
            ),
            Data(in_bytes.to_vec()),
        );

        // Execute the request and capture the response
        let res = self.do_request_payload(request).await?.try_into()?;

        let ResponsePayload::Sign(payload) = res else {
            return Err(NetError::UnexpectedData(format!(
                "Expected Sign payload but response has {res}"
            )));
        };

        Ok(payload.signature_data)
    }

    /// Serialize a KMIP 1.0 [Activate](https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581226)
    /// operation to activate a given private key ID.
    ///
    /// See also: [do_request()](Self::do_request())
    ///
    /// To activate other kinds of managed object you must compose the Activate request manually and pass it to
    /// [do_request()](Self::do_request()) directly.
    #[maybe_async::maybe_async]
    pub async fn activate_key(&mut self, private_key_id: &str) -> NetResult<()> {
        let request = RequestPayload::Activate(UniqueIdentifier(private_key_id.to_owned()).into());

        // Execute the request and capture the response
        let res = self.do_request_payload(request).await?.try_into()?;

        let ResponsePayload::Activate(_) = res else {
            return Err(NetError::UnexpectedData(format!(
                "Expected Activate payload but response has {res}"
            )));
        };

        Ok(())
    }

    /// Serialize a KMIP 1.0 [Revoke](https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581227)
    /// operation to deactivate a given private key ID.
    ///
    /// See also: [do_request()](Self::do_request())
    ///
    /// To deactivate other kinds of managed object you must compose the Revoke request manually and pass it to
    /// [do_request()](Self::do_request()) directly.
    #[maybe_async::maybe_async]
    pub async fn revoke_key(&mut self, private_key_id: &str) -> NetResult<()> {
        let request = RequestPayload::Revoke(
            Some(UniqueIdentifier(private_key_id.to_owned())),
            RevocationReason(
                RevocationReasonCode::CessationOfOperation,
                Option::<RevocationMessage>::None,
            ),
            Option::<CompromiseOccurrenceDate>::None,
        );

        // Execute the request and capture the response
        let res = self.do_request_payload(request).await?.try_into()?;

        let ResponsePayload::Revoke(_) = res else {
            return Err(NetError::UnexpectedData(format!(
                "Expected Revoke payload but response has {res}"
            )));
        };

        Ok(())
    }

    /// Serialize a KMIP 1.0 [Destroy](https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581228)
    /// operation to destroy a given private key ID.
    ///
    /// See also: [do_request()](Self::do_request())
    ///
    /// To destroy other kinds of managed object you must compose the Destroy request manually and pass it to
    /// [do_request()](Self::do_request()) directly.
    #[maybe_async::maybe_async]
    pub async fn destroy_key(&mut self, key_id: &str) -> NetResult<()> {
        let request = RequestPayload::Destroy(Some(UniqueIdentifier(key_id.to_owned())));

        // Execute the request and capture the response
        let res = self.do_request_payload(request).await?.try_into()?;

        let ResponsePayload::Destroy(_) = res else {
            return Err(NetError::UnexpectedData(format!(
                "Expected Destroy payload but response has {res}"
            )));
        };

        Ok(())
    }

    /// Serialize a KMIP 1.0 [ModifyAttribute](http://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581222)
    /// operation to rename a given key ID.
    ///
    /// See also: [do_request()](Self::do_request())
    ///
    /// To modify other attributes of managed objects you must compose the Modify Attribute request manually and pass
    /// it to [do_request()](Self::do_request()) directly.
    #[maybe_async::maybe_async]
    pub async fn rename_key(&mut self, key_id: &str, new_name: String) -> NetResult<()> {
        // Setup the request
        let request = RequestPayload::ModifyAttribute(
            Some(UniqueIdentifier(key_id.to_string())),
            request::Attribute::Name(new_name),
        );

        // Execute the request and capture the response
        let res = self.do_request_payload(request).await?.try_into()?;

        let ResponsePayload::ModifyAttribute(_) = res else {
            return Err(NetError::UnexpectedData(format!(
                "Expected ModifyAttribute payload but response has {res}"
            )));
        };

        Ok(())
    }

    /// Serialize a KMIP 1.0 [Get](http://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581218)
    /// operation to get the details of a given key ID.
    ///
    /// See also: [do_request()](Self::do_request())
    #[maybe_async::maybe_async]
    pub async fn get_key(&mut self, key_id: &str) -> NetResult<GetResponsePayload> {
        // Setup the request
        let request = RequestPayload::Get(
            Some(UniqueIdentifier(key_id.to_string())),
            Option::<KeyFormatType>::None,
            Option::<KeyCompressionType>::None,
            Option::<KeyWrappingSpecification>::None,
        );

        // Execute the request and capture the response
        let res = self.do_request_payload(request).await?.try_into()?;

        let ResponsePayload::Get(payload) = res else {
            return Err(NetError::UnexpectedData(format!(
                "Expected Get payload but response has {res}"
            )));
        };

        Ok(payload)
    }
}

//--- Lower level client interface
//
// For sending requests and receiving responses.

impl<T: ReadWrite> Client<T> {
    /// Write request bytes to the given stream and read, deserialize and
    /// sanity check the response.
    ///
    /// Tip: For cases when the response is expected to consist of only a
    /// single batch item,`TryInto` can be used to simplify handling of the
    /// result, e.g.:
    ///
    /// ```ignore
    /// // Setup the request.
    /// let wanted_info = vec![
    ///     QueryFunction::QueryOperations,
    ///     QueryFunction::QueryObjects,
    ///     QueryFunction::QueryServerInformation,
    /// ];
    /// let request = RequestPayload::Query(wanted_info);
    ///
    /// // Execute the request and capture the response.
    /// let res = client.do_request_payload(request).await?.try_into()?;
    /// let ResponsePayload::Query(payload) = res else {
    ///     return Err(NetError::UnexpectedData(format!(
    ///         "Expected Query payload but response has {res}"
    ///     )));
    /// };
    /// ```
    ///
    /// Note: Enforcing a timeout on this operation is the responsibility of
    /// the caller.
    #[maybe_async::maybe_async]
    pub async fn do_request(&mut self, request: RequestMessage) -> NetResult<Vec<NetResult<response::BatchItem>>> {
        trace!("Serializing request to KMIP wire bytes");
        let len = self.write_buf.len();
        assert!(len <= i32::MAX as usize);
        let mut len = len as i32;

        let mut stream = Self::get_mut_stream(&self.stream).await?;
        let mut formatter;

        // TODO: Enforce a timeout on sending the request?
        let request_bytes = loop {
            formatter = crate::ttlv::Formatter::new(&mut self.write_buf);
            if request.format(&mut formatter).is_ok() {
                let request_bytes = formatter.filled().as_flattened();
                Self::write_to_stream(&mut stream, request_bytes).await?;
                break request_bytes;
            } else if len >= self.max_message_size {
                // Buffer is already at the maximum possible size.
                return Err(NetError::SerializeError(format!(
                    "Message too large: {len} > {}",
                    self.max_message_size
                )));
            } else {
                // Retry with a larger buffer.
                len = i32::max(self.max_message_size, len.saturating_mul(2));
                self.write_buf.resize(len as usize, MaybeUninit::uninit());
            }
        };

        trace!("Waiting for a response from the server");
        let res = Self::read_message_from_stream(
            &mut stream,
            &mut self.read_buf,
            self.max_message_size,
            ResponseMessage::fast_scan,
            self.connection_error_count.clone(),
        )
        .await?;
        trace!("KMIP server response received");

        Self::post_process_response(res).await.map_err(|mut err| {
            if let NetError::DeserializeError { req, .. } = &mut err {
                *req = request_bytes.into();
            }
            err
        })
    }

    /// Serialize the given request to the stream and deserialize the response.
    ///
    /// Automatically constructs the request message wrapper around the payload including the [RequestHeader] and
    /// [BatchItem].
    ///
    /// Only supports a single batch item.
    ///
    /// Sets the request operation to [RequestPayload::operation()].
    ///
    /// # Errors
    ///
    /// Will fail if there is a problem serializing the request, writing to or reading from the stream, deserializing
    /// the response or if the response does not indicate operation success or contains more than one batch item.
    #[maybe_async::maybe_async]
    pub async fn do_request_payload(
        &mut self,
        payload: RequestPayload,
    ) -> NetResult<Vec<NetResult<response::BatchItem>>> {
        self.do_request(payload_to_request(
            self.auth.clone(),
            Some(MaximumResponseSize(self.max_message_size)),
            payload,
        )?)
        .await
    }

    #[maybe_async::maybe_async]
    pub async fn do_request_batch(
        &mut self,
        batch_items: Vec<BatchItem>,
    ) -> NetResult<Vec<NetResult<response::BatchItem>>> {
        self.do_request(batch_items_to_request(
            self.auth.clone(),
            Some(MaximumResponseSize(self.max_message_size)),
            batch_items,
        )?)
        .await
    }
}

//------------ Internals -----------------------------------------------------

impl<T: ReadWrite> Client<T> {
    #[cfg(feature = "tokio")]
    async fn get_mut_stream(stream: &Mutex<T>) -> NetResult<impl DerefMut<Target = T> + '_> {
        Ok(stream.lock().await)
    }

    #[cfg(not(feature = "tokio"))]
    fn get_mut_stream(stream: &Mutex<T>) -> NetResult<impl DerefMut<Target = T> + '_> {
        Ok(stream.lock()?)
    }

    #[maybe_async::maybe_async]
    async fn post_process_response(mut res: ResponseMessage) -> NetResult<Vec<NetResult<response::BatchItem>>> {
        if res.header.batch_count >= 1 && !res.batch_items.is_empty() {
            let res = res
                .batch_items
                .drain(..)
                .map(|item| match item.result_status {
                    ResultStatus::OperationFailed => {
                        let reason = item.result_message.unwrap_or_else(|| "Reason unknown".to_string());
                        let operation = item
                            .operation
                            .map(|op| op.to_string())
                            .unwrap_or_else(|| "unknown".to_string());
                        let err = format!("Operation {operation} failed: {reason}");
                        if matches!(item.result_reason, Some(ResultReason::ItemNotFound)) {
                            Err(NetError::ItemNotFound(err))
                        } else {
                            Err(NetError::ServerError(err))
                        }
                    }
                    ResultStatus::OperationPending => Err(NetError::InternalError(
                        "Result status 'operation pending' is not supported".into(),
                    )),
                    ResultStatus::OperationUndone => Err(NetError::InternalError(
                        "Result status 'operation undone' is not supported".into(),
                    )),
                    ResultStatus::Success => Ok(item),
                })
                .collect::<Vec<_>>();
            Ok(res)
        } else {
            let err = format!(
                "Expected at least one batch item in response but received {}",
                res.batch_items.len()
            );
            Err(NetError::ServerError(err))
        }
    }

    #[maybe_async::maybe_async]
    async fn read_message_from_stream<F, R>(
        stream: &mut T,
        read_buf: &mut Vec<u8>,
        limit: i32,
        op: F,
        connection_error_count: Arc<AtomicUsize>,
    ) -> NetResult<R>
    where
        F: Fn(&mut FastScanner) -> std::result::Result<R, FastScanError>,
    {
        trace!("Awaiting KMIP server response");
        read_buf.clear();
        loop {
            // Try reading from the buffer.
            let available = read_buf.len();
            let available_rounded = read_buf.len() - available % 8;
            let ttlv_bytes = &read_buf[..available_rounded];
            let mut scanner = FastScanner::new(ttlv_bytes).expect("the provided buffer has a multiple of 8 bytes");
            match scanner.have_next() {
                Ok(()) => {
                    trace!(
                        "Received {available_rounded} bytes from the server: {}",
                        hex::encode_upper(ttlv_bytes)
                    );
                    // A complete TTLV element is available. Try to parse it.
                    return op(&mut scanner).map_err(|err| NetError::DeserializeError {
                        err: err.to_string(),
                        req: Default::default(), // do_requests() will populate this
                        res: read_buf.clone().into(),
                    });
                }
                Err(Some(n)) => {
                    // n more bytes are needed to complete the current message
                    // in the buffer.
                    Self::enlarge_read_buffer_if_needed(read_buf, n as usize, limit)?;
                }
                Err(None) => {
                    // More bytes are needed to complete the current message
                    // in the buffer but we don't know how many so fetch at
                    // least 8 bytes (as TTLV messages are always a multiple
                    // of 8 bytes and thus FastScanner only accepts multiples
                    // of 8 bytes).
                    Self::enlarge_read_buffer_if_needed(read_buf, 8, limit)?;
                }
            }

            // The buffer did not contain enough data, try to read more.

            let write_start_idx = available;
            let updated_buffer_len = read_buf.len();
            let bytes_to_write_into = &mut read_buf[write_start_idx..updated_buffer_len];
            let read_byte_count =
                Self::read_from_stream(stream, bytes_to_write_into, connection_error_count.clone()).await?;

            // Don't pass any extra zeroes in the buffer to the TTLV parser,
            // only give it bytes that we actually read.
            read_buf.truncate(write_start_idx + read_byte_count);
        }
    }

    #[maybe_async::maybe_async]
    async fn write_to_stream(stream: &mut T, bytes: &[u8]) -> NetResult<()> {
        trace!(
            "Writing {} bytes to the server: {}",
            bytes.len(),
            hex::encode_upper(bytes)
        );
        if let Err(err) = stream.write_all(bytes).await {
            return Err(NetError::RequestWriteError(err.to_string()));
        }

        Ok(())
    }

    fn enlarge_read_buffer_if_needed(read_buf: &mut Vec<u8>, extra_bytes_needed: usize, limit: i32) -> NetResult<()> {
        // If the buffer is too small, try to expand it.
        let wanted_buf_size = read_buf.len() + extra_bytes_needed;
        if wanted_buf_size > read_buf.capacity() && wanted_buf_size > limit as usize {
            return Err(NetError::ResponseReadError(format!(
                "Response too large: {wanted_buf_size} bytes > {limit} bytes"
            )));
        }
        read_buf.resize(wanted_buf_size, 0);
        Ok(())
    }

    #[maybe_async::maybe_async]
    async fn read_from_stream(
        stream: &mut T,
        buffer: &mut [u8],
        connection_error_count: Arc<AtomicUsize>,
    ) -> NetResult<usize> {
        trace!("Reading upto {} bytes from the KMIP server", buffer.len());
        match stream.read(buffer).await {
            // The client has closed the connection.
            Ok(0) => Err(NetError::ResponseReadError(
                "Client closed connection with a partial request received".into(),
            )),

            // Some data was received successfully.
            Ok(amt) => {
                trace!("Read {amt} bytes from the KMIP server");
                Ok(amt)
            }

            Err(err) if err.kind() == std::io::ErrorKind::Interrupted => {
                // This is a recoverable error.
                trace!("KMIP server connection interrupted, continuing.");
                Ok(0)
            }

            // An unexpected error has occurred.
            Err(err) => {
                let _ = connection_error_count.fetch_add(1, Ordering::SeqCst);
                // TODO: Categorize the various std::io::ErrorKinds into fatal and
                // non-fatal variants and only abort on fatal errors.
                Err(NetError::ResponseReadError(format!("I/O error: {err}")))
            }
        }
    }
}

impl<T: ReadWrite> Clone for Client<T> {
    fn clone(&self) -> Self {
        Self {
            auth: self.auth.clone(),
            max_message_size: self.max_message_size,
            stream: self.stream.clone(),
            connection_error_count: self.connection_error_count.clone(),
            read_buf: vec![0u8; 8192],
            write_buf: vec![MaybeUninit::uninit(); 8192],
        }
    }
}

impl<T: ReadWrite> Client<T> {
    /// Get the count of connection errors experienced by this Client.
    pub fn connection_error_count(&self) -> usize {
        self.connection_error_count.load(Ordering::SeqCst)
    }
}
