use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

use tracing::trace;

use crate::{
    net::common::error::{NetError, NetResult},
    ttlv::{FastScanError, FastScanner},
    types::traits::ReadWrite,
};

#[maybe_async::maybe_async]
pub async fn read_message_from_stream<F, R, T>(
    stream: &mut T,
    read_buf: &mut Vec<u8>,
    limit: i32,
    op: F,
    connection_error_count: Arc<AtomicUsize>,
) -> NetResult<R>
where
    F: Fn(&mut FastScanner) -> std::result::Result<R, FastScanError>,
    T: ReadWrite,
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
                enlarge_read_buffer_if_needed(read_buf, n as usize, limit)?;
            }
            Err(None) => {
                // More bytes are needed to complete the current message
                // in the buffer but we don't know how many so fetch at
                // least 8 bytes (as TTLV messages are always a multiple
                // of 8 bytes and thus FastScanner only accepts multiples
                // of 8 bytes).
                enlarge_read_buffer_if_needed(read_buf, 8, limit)?;
            }
        }

        // The buffer did not contain enough data, try to read more.

        let write_start_idx = available;
        let updated_buffer_len = read_buf.len();
        let bytes_to_write_into = &mut read_buf[write_start_idx..updated_buffer_len];
        let read_byte_count = read_from_stream(stream, bytes_to_write_into, connection_error_count.clone()).await?;

        // Don't pass any extra zeroes in the buffer to the TTLV parser,
        // only give it bytes that we actually read.
        read_buf.truncate(write_start_idx + read_byte_count);
    }
}

pub fn enlarge_read_buffer_if_needed(read_buf: &mut Vec<u8>, extra_bytes_needed: usize, limit: i32) -> NetResult<()> {
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
pub async fn read_from_stream<T: ReadWrite>(
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
            Err(err.into())
        }
    }
}
