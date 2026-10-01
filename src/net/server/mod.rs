pub mod builder;
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

#[cfg(feature = "tokio")]
use tokio::sync::Mutex;

#[cfg(not(feature = "tokio"))]
use std::sync::Mutex;

use crate::{
    net::{NetError, NetResult, batch_items_to_response, payload_to_response},
    ttlv::{FastScanError, FastScanner},
    types::{
        request::{Authentication, RequestMessage},
        response::{self, ResponseMessage, ResponsePayload, ResultReason, ResultStatus},
        traits::ReadWrite,
    },
};

use tracing::trace;

/// A server for deserializing KMIP requests and serializing KMIP responses
/// from/to an established read/write stream.
///
/// Use the [ServerBuilder] to build a [Server] instance to work with.
#[derive(Debug)]
pub struct Server<T: ReadWrite> {
    auth: Option<Authentication>,
    max_message_size: i32,
    stream: Arc<Mutex<T>>,
    read_buf: Vec<u8>,
    write_buf: Vec<MaybeUninit<u8>>,
    connection_error_count: Arc<AtomicUsize>,
}

//--- Low level server interface
//
// For receiving requests and sending responses.

impl<T: ReadWrite> Server<T> {
    /// Receive a KMIP request from the network.
    ///
    /// Unlike do_request() and do_requests() this function only performs the
    /// receiving half of the message exchange as the caller has to inspect the
    /// received message and determinate an appropriate response.
    #[maybe_async::maybe_async]
    pub async fn receive_request(&mut self) -> NetResult<RequestMessage> {
        trace!("Acquiring stream lock");
        let mut lock = Self::get_mut_stream(&self.stream).await?;
        let stream = lock.deref_mut();

        trace!("Waiting for a request from the client");
        let req = Self::read_message_from_stream(
            stream,
            &mut self.read_buf,
            self.max_message_size,
            RequestMessage::fast_scan,
            self.connection_error_count.clone(),
        )
        .await?;
        drop(lock);

        // Check that the request is correctly authenticated.
        if req.header().authentication() != self.auth.as_ref() {
            return Err(NetError::AuthenticationError);
        }

        Ok(req)
    }

    #[maybe_async::maybe_async]
    pub async fn send_response(&mut self, response: ResponseMessage) -> NetResult<()> {
        trace!("Serializing response to KMIP wire bytes");
        let len = self.write_buf.len();
        assert!(len <= i32::MAX as usize);
        let mut len = len as i32;

        // TODO: Enforce a timeout on sending the response?
        loop {
            let mut formatter = crate::ttlv::Formatter::new(&mut self.write_buf);
            if response.format(&mut formatter).is_ok() {
                let response_bytes = formatter.filled().as_flattened();
                let mut stream = Self::get_mut_stream(&self.stream).await?;
                trace!("Writing {} response bytes to the server", response_bytes.len());
                stream.write_all(response_bytes).await?;
                return Ok(());
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
        }
    }

    #[maybe_async::maybe_async]
    pub async fn send_response_payload(
        &mut self,
        result_status: ResultStatus,
        result_reason: Option<ResultReason>,
        result_message: Option<String>,
        payload: Option<ResponsePayload>,
    ) -> NetResult<()> {
        self.send_response(payload_to_response(
            result_status,
            result_reason,
            result_message,
            payload,
        )?)
        .await
    }

    #[maybe_async::maybe_async]
    pub async fn send_response_batch(&mut self, batch_items: Vec<response::BatchItem>) -> NetResult<()> {
        self.send_response(batch_items_to_response(batch_items)?).await
    }
}

//------------ Internals -----------------------------------------------------

impl<T: ReadWrite> Server<T> {
    #[cfg(feature = "tokio")]
    async fn get_mut_stream(stream: &Mutex<T>) -> NetResult<impl DerefMut<Target = T> + '_> {
        Ok(stream.lock().await)
    }

    #[cfg(not(feature = "tokio"))]
    fn get_mut_stream(stream: &Mutex<T>) -> NetResult<impl DerefMut<Target = T> + '_> {
        Ok(stream.lock()?)
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

    fn enlarge_read_buffer_if_needed(read_buf: &mut Vec<u8>, extra_bytes_needed: usize, limit: i32) -> NetResult<()> {
        // If the buffer is too small, try to expand it.
        let wanted_buf_size = read_buf.len() + extra_bytes_needed;
        if wanted_buf_size > read_buf.capacity() && wanted_buf_size > limit as usize {
            return Err(std::io::Error::new(
                std::io::ErrorKind::FileTooLarge,
                format!("Response too large: {wanted_buf_size} bytes > {limit} bytes"),
            )
            .into());
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
            Ok(0) => Err(NetError::IoError(std::io::ErrorKind::ConnectionAborted.into())),

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
                Err(NetError::IoError(err))
            }
        }
    }
}

impl<T: ReadWrite> Clone for Server<T> {
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

impl<T: ReadWrite> Server<T> {
    /// Get the count of connection errors experienced by this Client.
    pub fn connection_error_count(&self) -> usize {
        self.connection_error_count.load(Ordering::SeqCst)
    }
}
