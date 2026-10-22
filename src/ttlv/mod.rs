//! Low-level TTLV (de)serialization.
//!
//! This module provides a fast TTLV scanner and formatter, without support for
//! how TTLV gets used within the KMIP protocol.

pub mod fast_scan;
pub mod format;
pub mod types;

pub use fast_scan::{FastScanError, FastScanner};
pub use format::{FormatResult, Formatter};
pub use types::{Tag, TagType, Type};

use crate::ttlv::format::TruncationError;

pub fn from_slice<T, F>(buffer: &[u8], op: F) -> std::result::Result<(T, &[u8]), FastScanError>
where
    F: Fn(&mut FastScanner) -> std::result::Result<T, FastScanError>,
{
    let available = buffer.len() - buffer.len() % 8;
    let mut scanner = FastScanner::new(&buffer[..available]).expect("the provided buffer has a multiple of 8 bytes");
    let kmip_type = op(&mut scanner)?;
    let rest = scanner.remaining().as_flattened();
    Ok((kmip_type, rest))
}

pub fn to_vec<F>(op: F) -> std::result::Result<Vec<u8>, TruncationError>
where
    F: Fn(&mut Formatter) -> FormatResult,
{
    // A buffer for writing responses into.
    // 2^32 is the maximum length of a KMIP TTLV structure.
    // See KMIP Specification v1.0 section 9.1.1.3 Item Length.
    let mut len = u16::MAX as usize;

    while len <= u32::MAX as usize {
        let mut buffer = Box::<[u8]>::new_uninit_slice(len);
        let mut formatter = crate::ttlv::Formatter::new(&mut buffer);

        if op(&mut formatter).is_ok() {
            return Ok(formatter.filled().as_flattened().to_vec());
        } else {
            // Retry with a larger buffer.
            len <<= 1;
        }
    }

    Err(TruncationError)
}
