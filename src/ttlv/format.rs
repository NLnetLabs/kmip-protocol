//! Serializing TTLV elements.
//!
//! This module provides low-level TTLV serialization support.  It is entirely
//! manual -- it does not provide a declarative interface.  It is designed for
//! fast, streaming operation.

use core::{
    fmt,
    mem::{MaybeUninit, transmute},
    ops::{Deref, DerefMut},
};

use super::types::{Tag, Type};

//----------- Formatter ------------------------------------------------------

/// A TTLV formatter.
pub struct Formatter<'b> {
    /// The buffer to write into.
    buffer: &'b mut [MaybeUninit<[u8; 8]>],

    /// The current position into the buffer.
    ///
    /// - Invariant `initialized`:
    ///   `self.buffer[..self.position]` is initialized.
    ///
    /// - Invariant `coherent-position`:
    ///   `self.position <= self.buffer.len()`.
    position: usize,
}

impl<'b> Formatter<'b> {
    /// Construct a new [`Formatter`].
    ///
    /// If the input is not a multiple of 8 bytes, the remainder (at most 7
    /// bytes) will be ignored.  The input should ideally be aligned to an
    /// 8-byte boundary.
    pub const fn new(buffer: &'b mut [MaybeUninit<u8>]) -> Self {
        let num_blocks = buffer.len() / 8;
        let ptr = buffer.as_mut_ptr().cast::<MaybeUninit<[u8; 8]>>();
        let buffer = unsafe { core::slice::from_raw_parts_mut(ptr, num_blocks) };

        Self { buffer, position: 0 }
    }

    /// Construct a new [`Formatter`] from its raw parts.
    ///
    /// ## Safety
    ///
    /// `Formatter::from_raw_parts(buffer, position)` is sound if and only if:
    /// - `position <= buffer.len()`.
    /// - `buffer[..position]` is initialized.
    pub const unsafe fn from_raw_parts(buffer: &'b mut [MaybeUninit<[u8; 8]>], position: usize) -> Self {
        debug_assert!(position <= buffer.len());
        Self { buffer, position }
    }

    /// The filled part of the buffer.
    pub fn filled(&self) -> &[[u8; 8]] {
        unsafe {
            let blocks = self.buffer.get_unchecked(..self.position);
            transmute::<&[MaybeUninit<[u8; 8]>], &[[u8; 8]]>(blocks)
        }
    }

    /// The filled part of the buffer, mutably.
    pub fn filled_mut(&mut self) -> &mut [[u8; 8]] {
        unsafe {
            let blocks = self.buffer.get_unchecked_mut(..self.position);
            transmute::<&mut [MaybeUninit<[u8; 8]>], &mut [[u8; 8]]>(blocks)
        }
    }

    /// The remaining part of the buffer.
    pub fn remaining(&mut self) -> &mut [MaybeUninit<[u8; 8]>] {
        unsafe { self.buffer.get_unchecked_mut(self.position..) }
    }

    /// Destructure a [`Formatter`] into its raw parts.
    ///
    /// ## Invariants
    ///
    /// For `(buffer, position) = self.into_raw_parts()`:
    /// - Invariant `coherent-position`: `position <= buffer.len()`.
    /// - Invariant `initialized`: `buffer[..position]` is initialized.
    pub const fn into_raw_parts(self) -> (&'b mut [MaybeUninit<[u8; 8]>], usize) {
        (self.buffer, self.position)
    }
}

impl<'b> Formatter<'b> {
    /// Format a structure.
    ///
    /// The returned sub-formatter should be used to format the fields of the
    /// `struct`; once it is finished, `self` can continue.
    #[inline]
    pub fn format_struct(&mut self, tag: Tag) -> Result<FieldFormatter<'_>, TruncationError> {
        let buffer = &mut self.buffer[self.position..];
        let (header_slot, rest) = buffer.split_first_mut().ok_or(TruncationError)?;

        // Write the field header.
        let header = (tag.with_type(Type::Structure).value() as u64) << 32;
        let header = header_slot.write(header.to_be_bytes());

        Ok(FieldFormatter {
            outer_pos: &mut self.position,
            header,
            inner: Formatter {
                buffer: rest,
                position: 0,
            },
        })
    }

    /// Format an integer.
    #[inline]
    pub fn format_int(&mut self, tag: Tag, value: i32) -> FormatResult {
        let header = (tag.with_type(Type::Integer).value() as u64) << 32 | 4;

        let buffer = &mut self.buffer[self.position..];
        let [header_slot, value_slot, ..] = buffer else {
            return Err(TruncationError);
        };

        header_slot.write(header.to_be_bytes());
        value_slot.write(((value as u32 as u64) << 32).to_be_bytes());
        self.position += 2;
        Ok(FormatDone(()))
    }

    /// Format a long integer.
    #[inline]
    pub fn format_long_int(&mut self, tag: Tag, value: i64) -> FormatResult {
        let header = (tag.with_type(Type::LongInteger).value() as u64) << 32 | 8;

        let buffer = &mut self.buffer[self.position..];
        let [header_slot, value_slot, ..] = buffer else {
            return Err(TruncationError);
        };

        header_slot.write(header.to_be_bytes());
        value_slot.write((value as u64).to_be_bytes());
        self.position += 2;
        Ok(FormatDone(()))
    }

    /// Format a big integer.
    #[inline]
    pub fn format_big_int(&mut self, tag: Tag, value: &[u8]) -> FormatResult {
        let header = tag.with_type(Type::BigInteger).value() as u64;
        let length = u32::try_from(value.len()).unwrap() as u64;
        let length = (length + 7) & !7; // round up to 8 bytes
        let header = header << 32 | length;

        let num_blocks = value.len().div_ceil(8);
        let buffer = &mut self.buffer[self.position..];
        if buffer.len() < 1 + num_blocks {
            return Err(TruncationError);
        }

        buffer[0].write(header.to_be_bytes());
        if let &[first, ..] = value {
            // Fill the first 8 bytes by sign extension.
            //
            // This also ensures all bytes are initialized.
            //
            // On the one hand, we could extract the top bit from 'first' and
            // sign-extend just that.  On the other hand, we know that at least
            // one byte of 'buffer[1]' (which always includes the last byte)
            // will get overwritten by the later copy.
            //
            // This code is likely constant-time, which may be beneficial in
            // case secret data is being serialized.  But we do not provide any
            // public guarantees about constant-time operation.
            let ext = first as i8 as i64;
            buffer[1].write(ext.to_be_bytes());

            // Fill the remaining bytes.
            let ptr = buffer[1..].as_mut_ptr_range().end.cast::<u8>();
            unsafe {
                ptr.sub(value.len())
                    .copy_from_nonoverlapping(value.as_ptr(), value.len())
            };
        } else {
            // The value is empty; we don't write anything.
            //
            // TODO: The spec is a bit ambiguous about whether this is allowed.
            // How do other TTLV implementations parse this?
        }

        self.position += 1 + num_blocks;
        Ok(FormatDone(()))
    }

    /// Format an enumeration.
    #[inline]
    pub fn format_enum(&mut self, tag: Tag, value: u32) -> FormatResult {
        let header = (tag.with_type(Type::Enumeration).value() as u64) << 32 | 4;

        let buffer = &mut self.buffer[self.position..];
        let [header_slot, value_slot, ..] = buffer else {
            return Err(TruncationError);
        };

        header_slot.write(header.to_be_bytes());
        value_slot.write(((value as u64) << 32).to_be_bytes());
        self.position += 2;
        Ok(FormatDone(()))
    }

    /// Format a boolean.
    #[inline]
    pub fn format_bool(&mut self, tag: Tag, value: bool) -> FormatResult {
        let header = (tag.with_type(Type::Boolean).value() as u64) << 32 | 8;

        let buffer = &mut self.buffer[self.position..];
        let [header_slot, value_slot, ..] = buffer else {
            return Err(TruncationError);
        };

        header_slot.write(header.to_be_bytes());
        value_slot.write((value as u64).to_be_bytes());
        self.position += 2;
        Ok(FormatDone(()))
    }

    /// Format a text string.
    #[inline]
    pub fn format_text(&mut self, tag: Tag, value: &str) -> FormatResult {
        let header = tag.with_type(Type::TextString).value() as u64;
        let length = u32::try_from(value.len()).unwrap() as u64;
        let header = header << 32 | length;

        let num_blocks = value.len().div_ceil(8);
        let buffer = &mut self.buffer[self.position..];
        if buffer.len() < 1 + num_blocks {
            return Err(TruncationError);
        }

        buffer[0].write(header.to_be_bytes());
        // Make sure the last block is completely initialized.
        if num_blocks > 0 {
            buffer[num_blocks].write([0; 8]);
        }
        let ptr = buffer[1..].as_mut_ptr().cast::<u8>();
        unsafe { ptr.copy_from_nonoverlapping(value.as_ptr(), value.len()) };

        self.position += 1 + num_blocks;
        Ok(FormatDone(()))
    }

    /// Format a byte string.
    #[inline]
    pub fn format_bytes(&mut self, tag: Tag, value: &[u8]) -> FormatResult {
        let header = tag.with_type(Type::ByteString).value() as u64;
        let length = u32::try_from(value.len()).unwrap() as u64;
        let header = header << 32 | length;

        let num_blocks = value.len().div_ceil(8);
        let buffer = &mut self.buffer[self.position..];
        if buffer.len() < 1 + num_blocks {
            return Err(TruncationError);
        }

        buffer[0].write(header.to_be_bytes());
        // Make sure the last block is completely initialized.
        if num_blocks > 0 {
            buffer[num_blocks].write([0; 8]);
        }
        let ptr = buffer[1..].as_mut_ptr().cast::<u8>();
        unsafe { ptr.copy_from_nonoverlapping(value.as_ptr(), value.len()) };

        self.position += 1 + num_blocks;
        Ok(FormatDone(()))
    }

    /// Format a date-time.
    #[inline]
    pub fn format_date_time(&mut self, tag: Tag, value: i64) -> FormatResult {
        let header = (tag.with_type(Type::DateTime).value() as u64) << 32 | 8;

        let buffer = &mut self.buffer[self.position..];
        let [header_slot, value_slot, ..] = buffer else {
            return Err(TruncationError);
        };

        header_slot.write(header.to_be_bytes());
        value_slot.write((value as u64).to_be_bytes());
        self.position += 2;
        Ok(FormatDone(()))
    }

    /// Format an interval.
    #[inline]
    pub fn format_interval(&mut self, tag: Tag, value: u32) -> FormatResult {
        let header = (tag.with_type(Type::Interval).value() as u64) << 32 | 4;

        let buffer = &mut self.buffer[self.position..];
        let [header_slot, value_slot, ..] = buffer else {
            return Err(TruncationError);
        };

        header_slot.write(header.to_be_bytes());
        value_slot.write(((value as u64) << 32).to_be_bytes());
        self.position += 2;
        Ok(FormatDone(()))
    }
}

//----------- FieldFormatter -------------------------------------------------

/// A [`Formatter`] for filling a particular TTLV field.
///
/// A [`Formatter`] can delegate to a [`FieldFormatter`] to format a TTLV
/// field such as a structure.  This provides an incremental API to fill the
/// field.
#[must_use = "Complete the formatter using `.finish()`"]
pub struct FieldFormatter<'f> {
    /// The position of the outer formatter.
    outer_pos: &'f mut usize,

    /// The header slot.
    ///
    /// The length of the created field will be written here.
    header: &'f mut [u8; 8],

    /// The inner formatter.
    ///
    /// This formatter borrows its buffer from the outer one.
    inner: Formatter<'f>,
}

impl FieldFormatter<'_> {
    /// Successfully finish formatting.
    pub fn finish(self) -> FormatDone {
        // Update the length of the field.
        let length = self.inner.position;
        assert!(length * 8 <= u32::MAX as usize);
        let length = (length * 8) as u32;
        self.header[4..].copy_from_slice(&length.to_be_bytes());

        // Update the position of the outer formatter.
        *self.outer_pos += 1 + self.inner.position;

        FormatDone(())
    }
}

impl<'f> Deref for FieldFormatter<'f> {
    type Target = Formatter<'f>;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl<'f> DerefMut for FieldFormatter<'f> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner
    }
}

//----------- FormatResult ---------------------------------------------------

/// The result of formatting a field.
pub type FormatResult = Result<FormatDone, TruncationError>;

//----------- FormatDone -----------------------------------------------------

/// A token showing that formatting completed successfully.
pub struct FormatDone(());

impl FormatDone {
    /// Manually assert that formatting is complete.
    pub const fn definitely() -> Self {
        Self(())
    }
}

//----------- TruncationError ------------------------------------------------

/// A [`Formatter`] ran out of space to serialize TTLV data.
#[derive(Clone, PartialEq, Eq)]
pub struct TruncationError;

impl std::error::Error for TruncationError {}

impl fmt::Debug for TruncationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

impl fmt::Display for TruncationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ran out of space while serializing TTLV data")
    }
}
