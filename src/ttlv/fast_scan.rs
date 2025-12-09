//! Deserializing TTLV elements quickly.
//!
//! This module provides low-level TTLV deserialization support.  It is entirely
//! manual -- it does not provide a declarative interface.  It is designed for
//! fast, streaming, zero-copy operation.

use core::fmt;

use super::types::Tag;

//----------- FastScanner ----------------------------------------------------

/// A fast TTLV scanner.
///
/// In most cases, errors are highly unlikely.  This scanner optimizes for this
/// by omitting error handling and pinpointing facilities -- it detects errors
/// without tracking any details of them.  In some cases, it will delay errors,
/// returning garbage data instead of [`Err`].  If scanning with [`FastScanner`]
/// fails, a different scanner (e.g. [`crate::de::from_slice()`]) needs to be
/// used to ascertain the position and cause of the error.
//
// TODO: Link to 'SlowScanner' instead, once it exists.
///
/// ## Delayed Errors
///
/// For efficiency, the scanner will sometimes return invalid data, e.g. from
/// [`Self::scan_int()`].  This only occurs if the input is invalid, but it is
/// more efficient than returning an actual [`Err`].  Once invalid data has been
/// returned, at any point, [`Self::is_delayed_error()`] will report `true`.
///
/// The caller should never "trust" the data being returned, e.g. to decide how
/// much memory to allocate.  Any field can return invalid data; the input may
/// be well-formed but contain an unexpected value for a field.
///
/// ## Streaming Operation
///
/// [`FastScanner`] can be used in streaming fashion.  For example, when
/// receiving a stream of serialized items (e.g. KMIP requests), one cannot
/// wait for the end of the stream to parse.  Instead, the user should store the
/// input in a dynamically allocated buffer.  Once some data is in the buffer, a
/// [`FastScanner`] can be initialized over it, and [`Self::has_next()`] can be
/// used to check whether a complete TTLV item is available.  If it is, the item
/// can be parsed; otherwise, more data needs to be buffered.
///
/// Note that [`Self::new()`] should not be used in this scenario; it expects
/// the input to be exhaustive.  Use [`Self::from_partial()`] for the most part,
/// and only use [`Self::new()`] when the stream has terminated.
#[derive(Clone)]
pub struct FastScanner<'a> {
    /// The currently remaining input.
    ///
    /// TTLV elements are always serialized into multiples of 8 bytes.  The
    /// first 8-byte block of each element contains the tag, type, and length;
    /// even if the content is less than 8 bytes, it gets padded.  By tracking
    /// these blocks, we can use 64-bit integer operations to process 8 bytes at
    /// a time, which is far more efficient than byte-by-byte scanning.
    remaining: &'a [[u8; 8]],

    /// A failure word.
    ///
    /// This is non-zero if an error was detected and delayed.
    failure_word: u64,
}

impl<'a> FastScanner<'a> {
    /// Construct a new [`FastScanner`].
    ///
    /// It is expected that the input will be scanned in its entirety.  Use
    /// [`Self::from_partial()`] otherwise.
    ///
    /// ## Errors
    ///
    /// Fails if the input is not a multiple of 8 bytes.  TTLV elements are
    /// always serialized into multiples of 8 bytes, so the presence of a
    /// partial 8-byte block immediately implies the input is invalid.
    pub fn new(input: &'a [u8]) -> Result<Self, FastScanError> {
        let (input, &[]) = input.as_chunks() else {
            // The input contains a partial block.
            return Err(FastScanError::assert());
        };

        Ok(Self::from_blocks(input))
    }

    /// Construct a new [`FastScanner`] from non-exhaustive input.
    ///
    /// This should be preferred over [`Self::new()`] if more input may be
    /// appended in the future (e.g. during streaming operation).  It will
    /// round down the input, ignoring partial data.
    pub const fn from_partial(input: &'a [u8]) -> Self {
        // Ignore a trailing partial 8-byte block.
        let (input, _) = input.as_chunks();

        Self::from_blocks(input)
    }

    /// Construct a new [`FastScanner`] from a slice of 8-byte blocks.
    ///
    /// TTLV elements are always serialized into multiples of 8 bytes.
    /// [`FastScanner`] internally represents its input as slices of 8-byte
    /// blocks so it is easier to process.
    pub const fn from_blocks(input: &'a [[u8; 8]]) -> Self {
        Self {
            remaining: input,
            failure_word: 0,
        }
    }

    /// The remaining input to the scanner.
    pub const fn remaining(&self) -> &'a [[u8; 8]] {
        self.remaining
    }

    /// Whether the scanner is finished.
    pub const fn is_empty(&self) -> bool {
        self.remaining.is_empty()
    }

    /// Whether an error has been delayed.
    ///
    /// This should only be checked if the consistency of the previously
    /// scanned data is important, e.g. if acting on it.  It can be ignored
    /// while parsing.
    pub const fn has_delayed_error(&self) -> bool {
        self.failure_word != 0
    }

    /// Whether an entire TTLV element is available.
    ///
    /// The length of the next element will be checked; if it is entirely loaded
    /// in the buffer, `true` is returned.  Otherwise, or if there is no next
    /// element, `false` is returned.  This can be used for streamed parsing,
    /// to decide whether more data needs to be buffered.
    pub fn have_next(&self) -> bool {
        let [header, rest @ ..] = self.remaining else {
            return false;
        };

        let length = u32::from_be_bytes(header[4..8].try_into().unwrap());
        let available = rest.as_flattened().len();

        if usize::BITS >= u32::BITS {
            // 'usize' is at least as big as 'u32'.
            available >= length as usize
        } else {
            // 'u32' is bigger than 'usize'.
            available as u32 >= length
        }
    }

    /// Finish the scanner.
    ///
    /// If there is remaining input, or an error was delayed, [`Err`] is
    /// returned.  If additional remaining input is allowed, use
    /// [`Self::finish_non_exhaustive()`] instead.
    pub fn finish(self) -> Result<(), FastScanError> {
        if self.is_empty() && !self.has_delayed_error() {
            Ok(())
        } else {
            Err(FastScanError::assert())
        }
    }

    /// Finish the scanner non-exhaustively.
    ///
    /// Additional input is ignored.  [`Err`] is returned only if an error is
    /// delayed.  If additional remaining input is not allowed, use
    /// [`Self::finish()`] instead.
    pub fn finish_non_exhaustive(self) -> Result<(), FastScanError> {
        if !self.has_delayed_error() {
            Ok(())
        } else {
            Err(FastScanError::assert())
        }
    }
}

/// # Scanning Helpers
///
impl<'a> FastScanner<'a> {
    /// Verify that a header has a particular tag, type, and length.
    ///
    /// An incorrect header will result in a delayed error.
    #[inline(always)]
    fn check_ttl(&mut self, header: &[u8; 8], tag: Tag, r#type: u8, length: u32) {
        self.failure_word |= Self::calc_ttl(header, tag, r#type, length);
    }

    /// Test that a header has a particular tag, type, and length.
    ///
    /// Returns `true` if it does.
    #[inline(always)]
    fn test_ttl(&self, header: &[u8; 8], tag: Tag, r#type: u8, length: u32) -> Option<()> {
        let mismatch = Self::calc_ttl(header, tag, r#type, length);
        (mismatch == 0).then_some(())
    }

    #[inline(always)]
    fn calc_ttl(header: &[u8; 8], tag: Tag, r#type: u8, length: u32) -> u64 {
        // Prepare an expected value as a big-endian integer.
        //
        // The compiler should be able to fold this computation into a simple
        // hard-coded 64-bit constant.
        let expected = ((tag.value() as u64) << 40 | (r#type as u64) << 32 | (length as u64)).to_be();

        // Load the header without changing its endianness, so that it and
        // 'expected' have matching byte layouts.
        let actual = u64::from_ne_bytes(*header);

        // Return non-zero if at least one bit in the actual header did not
        // match.
        actual ^ expected
    }

    /// Verify that a header has a particular tag and type, and a length that is
    /// a multiple of 8.
    ///
    /// The length is returned, and is in units of 8-byte blocks.
    ///
    /// An incorrect header will result in a delayed error.
    #[inline(always)]
    fn check_tt_8l(&mut self, header: &[u8; 8], tag: Tag, r#type: u8) -> usize {
        let (mismatch, length) = Self::calc_tt_8l(header, tag, r#type);
        self.failure_word |= mismatch;
        length
    }

    /// Test that a header has a particular tag and type, and a length that is
    /// a multiple of 8.
    ///
    /// If the header matches, a length is returned, in units of 8-byte blocks.
    #[inline(always)]
    fn test_tt_8l(&self, header: &[u8; 8], tag: Tag, r#type: u8) -> Option<usize> {
        let (mismatch, length) = Self::calc_tt_8l(header, tag, r#type);
        (mismatch == 0).then_some(length)
    }

    #[inline(always)]
    fn calc_tt_8l(header: &[u8; 8], tag: Tag, r#type: u8) -> (u64, usize) {
        // Generate a mask for the length.
        //
        // We need to make sure the low 3 bits of the length are zero.
        //
        // We don't need to support lengths that can't fit in 'usize'; such
        // objects wouldn't fit in memory.  If 'usize' is smaller than 'u32',
        // we'll include the non-'usize' bits in the mask, and so ensure that
        // they are zero in the actual header.
        //
        // This is 0xFFFF_0007 on 16-bit, else 0x0000_0007.
        const LENGTH_MASK: u32 = !(usize::MAX as u32) | 0x07;

        // Generate a mask for the whole header.
        //
        // We always check the top 4 bytes (tag and type).
        const MASK: u64 = u64::MAX << 32 | LENGTH_MASK as u64;

        // Prepare an expected value as a native-endian integer.
        //
        // The length field is set to all-zeros; we will check that 'header'
        // contains the same bits, but only for 'LENGTH_MASK'.
        //
        // The compiler should be able to fold this computation into a simple
        // hard-coded 64-bit constant.
        let expected = (tag.value() as u64) << 40 | (r#type as u64) << 32;

        // Load the header into the right endianness, as we need to read out its
        // low 32 bits for the length field.  Note that it and 'expected' have
        // matching byte layouts.
        let actual = u64::from_be_bytes(*header);

        // Return non-zero if at least one bit in the actual header (of the tag,
        // type, or low 3 bits of length) did not match.
        let mismatch = (actual ^ expected) & MASK;

        // Extract and return the length, in units of 8-byte blocks.  We have
        // already checked that it fits in a 'usize', so cast to that.
        //
        // Note that the division by 8 happens after casting; otherwise the top
        // 3 bits of the type would get thrown in here by accident.
        let length = (actual as u32 as usize) / 8;

        (mismatch, length)
    }

    /// Verify that a header has a particular tag and type.
    ///
    /// No restrictions are placed on the length field, which is returned in
    /// units of bytes.
    ///
    /// An incorrect header will result in a delayed error.
    #[inline(always)]
    fn check_tt(&mut self, header: &[u8; 8], tag: Tag, r#type: u8) -> usize {
        let (mismatch, length) = Self::calc_tt(header, tag, r#type);
        self.failure_word |= mismatch;
        length
    }

    #[inline(always)]
    fn test_tt(&self, header: &[u8; 8], tag: Tag, r#type: u8) -> Option<usize> {
        let (mismatch, length) = Self::calc_tt(header, tag, r#type);
        (mismatch == 0).then_some(length)
    }

    #[inline(always)]
    fn calc_tt(header: &[u8; 8], tag: Tag, r#type: u8) -> (u64, usize) {
        // If 'u32' can fit in a 'usize', then the encoded length is always a
        // valid 'usize'.  Load the tag-type half and the length as separate
        // 32-bit words; that way, we only hard-code 32-bit integer constants.
        if usize::BITS >= u32::BITS {
            // Prepare an expected value as a big-endian integer.
            //
            // This only accounts for the tag and type.
            //
            // The compiler should be able to fold this computation into a
            // simple hard-coded 32-bit constant.
            let expected = (tag.value() << 8 | r#type as u32).to_be();

            // Load the tag-type part of the header without changing its
            // endianness, so that it and 'expected' have matching byte layouts.
            //
            // NOTE: This 'unwrap()' is guaranteed to never fail.
            let actual = u32::from_ne_bytes(header[..4].try_into().unwrap());

            // Make the failure word non-zero if at least one bit in the actual
            // header (of the tag or type) did not match.
            let mismatch = (actual ^ expected) as u64;

            // Load the length part of the header into native endianness.
            let length = u32::from_be_bytes(header[4..].try_into().unwrap());

            // We know 'u32' fits in a 'usize', so we can cast directly.
            (mismatch, length as usize)
        } else {
            // Generate a mask for the length.
            //
            // We don't need to support lengths that can't fit in 'usize';
            // such objects wouldn't fit in memory.  If 'usize' is smaller than
            // 'u32', we'll include the non-'usize' bits in the mask, and so
            // ensure that they are zero in the actual header.
            //
            // This is 0xFFFF_0000 on 16-bit.
            const LENGTH_MASK: u32 = !(usize::MAX as u32);

            // Generate a mask for the whole header.
            //
            // We always check the top 4 bytes (tag and type).
            const MASK: u64 = u64::MAX << 32 | LENGTH_MASK as u64;

            // Prepare an expected value as a native-endian integer.
            //
            // The length field is set to all-zeros; we will check that 'header'
            // contains the same bits, but only for 'LENGTH_MASK'.
            //
            // The compiler should be able to fold this computation into a
            // simple hard-coded 64-bit constant.
            let expected = (tag.value() as u64) << 40 | (r#type as u64) << 32;

            // Load the header into the right endianness, as we need to read out
            // its low bits for the length field.  Note that it and 'expected'
            // have matching byte layouts.
            let actual = u64::from_be_bytes(*header);

            // Make the failure word non-zero if at least one bit in the actual
            // header (of the tag, type, or high part of length) did not match.
            let mismatch = (actual ^ expected) & MASK;

            // We have already checked that the length fits in a 'usize', so we
            // can freely truncate the value now.
            (mismatch, actual as u32 as usize)
        }
    }
}

impl<'a> FastScanner<'a> {
    /// Scan an expected structure.
    ///
    /// The returned sub-scanner can be used to scan the fields of the
    /// `struct`; `self` will independently continue from the end of the
    /// `struct`.
    #[must_use = "Use the returned scanner to parse the structure, or use `FastScanner::skip_struct()` to ignore its contents"]
    #[inline]
    pub fn scan_struct(&mut self, tag: Tag) -> Result<Self, FastScanError> {
        let [header, rest @ ..] = self.remaining else {
            return Err(FastScanError::assert());
        };
        let length = self.check_tt_8l(header, tag, 0x01);
        let (body, rest) = rest.split_at_checked(length).ok_or(FastScanError::assert())?;
        self.remaining = rest;

        Ok(Self::from_blocks(body))
    }

    /// Scan an expected structure with a pre-determined length.
    ///
    /// The returned sub-scanner can be used scan the fields of the `struct`;
    /// `self` will independently continue from the end of the `struct`.  If
    /// the length encoded in the input is different from the pre-determined
    /// length, the error will be delayed and both scanners will return
    /// garbage.
    #[must_use = "Use the returned scanner to parse the structure, or use `FastScanner::skip_fixed_struct()` to ignore its contents"]
    #[inline]
    pub fn scan_fixed_struct(&mut self, tag: Tag, length: u32) -> Result<Self, FastScanError> {
        debug_assert!(length.is_multiple_of(8));
        if self.remaining.len() < 1 + length as usize / 8 {
            return Err(FastScanError::assert());
        }
        let (header, rest) = self.remaining.split_first().unwrap();
        self.check_ttl(header, tag, 0x01, length);
        let (body, rest) = rest.split_at(length as usize / 8);
        self.remaining = rest;

        Ok(Self::from_blocks(body))
    }

    /// Scan an expected integer.
    #[must_use = "Use the returned value, or use `FastScanner::skip_int()` to ignore it"]
    #[inline]
    pub fn scan_int(&mut self, tag: Tag) -> Result<i32, FastScanError> {
        let [header, value, rest @ ..] = self.remaining else {
            return Err(FastScanError::assert());
        };
        self.check_ttl(header, tag, 0x02, 4);
        self.remaining = rest;

        Ok(i32::from_be_bytes(value[0..4].try_into().unwrap()))
    }

    /// Scan an expected long integer.
    #[must_use = "Use the returned value, or use `FastScanner::skip_long_int()` to ignore it"]
    #[inline]
    pub fn scan_long_int(&mut self, tag: Tag) -> Result<i64, FastScanError> {
        let [header, value, rest @ ..] = self.remaining else {
            return Err(FastScanError::assert());
        };
        self.check_ttl(header, tag, 0x03, 8);
        self.remaining = rest;

        Ok(i64::from_be_bytes(*value))
    }

    /// Scan an expected big integer.
    #[must_use = "Use the returned value, or use `FastScanner::skip_big_int()` to ignore it"]
    #[inline]
    pub fn scan_big_int(&mut self, tag: Tag) -> Result<&'a [u8], FastScanError> {
        let [header, rest @ ..] = self.remaining else {
            return Err(FastScanError::assert());
        };
        let length = self.check_tt_8l(header, tag, 0x04);
        let (body, rest) = rest.split_at_checked(length).ok_or(FastScanError::assert())?;
        self.remaining = rest;

        Ok(body.as_flattened())
    }

    /// Scan an expected enumeration.
    #[must_use = "Use the returned value, or use `FastScanner::skip_enum()` to ignore it"]
    #[inline]
    pub fn scan_enum(&mut self, tag: Tag) -> Result<u32, FastScanError> {
        let [header, value, rest @ ..] = self.remaining else {
            return Err(FastScanError::assert());
        };
        self.check_ttl(header, tag, 0x05, 4);
        self.remaining = rest;

        Ok(u32::from_be_bytes(value[0..4].try_into().unwrap()))
    }

    /// Scan an expected boolean.
    #[must_use = "Use the returned value, or use `FastScanner::skip_bool()` to ignore it"]
    #[inline]
    pub fn scan_bool(&mut self, tag: Tag) -> Result<bool, FastScanError> {
        let [header, value, rest @ ..] = self.remaining else {
            return Err(FastScanError::assert());
        };
        self.check_ttl(header, tag, 0x06, 8);
        // Load the value without changing its endianness.
        let value = u64::from_ne_bytes(*value);
        // Check that it all bits except the lowest are zero.
        self.failure_word |= value & !u64::from_be(1);
        self.remaining = rest;

        Ok(value != 0)
    }

    /// Scan an expected text string.
    #[must_use = "Use the returned value, or use `FastScanner::skip_text()` to ignore it"]
    #[inline]
    pub fn scan_text(&mut self, tag: Tag) -> Result<&'a str, FastScanError> {
        let [header, rest @ ..] = self.remaining else {
            return Err(FastScanError::assert());
        };
        let length = self.check_tt(header, tag, 0x07);
        let body = rest.as_flattened().get(..length).ok_or(FastScanError::assert())?;
        let body = core::str::from_utf8(body).map_err(|_| FastScanError::assert())?;
        self.remaining = &rest[length.div_ceil(8)..];

        Ok(body)
    }

    /// Scan an expected text string as bytes.
    #[must_use = "Use the returned value, or use `FastScanner::skip_text()` to ignore it"]
    #[inline]
    pub fn scan_text_bytes(&mut self, tag: Tag) -> Result<&'a [u8], FastScanError> {
        let [header, rest @ ..] = self.remaining else {
            return Err(FastScanError::assert());
        };
        let length = self.check_tt(header, tag, 0x07);
        let body = rest.as_flattened().get(..length).ok_or(FastScanError::assert())?;
        self.remaining = &rest[length.div_ceil(8)..];

        Ok(body)
    }

    /// Scan an expected byte string.
    #[must_use = "Use the returned value, or use `FastScanner::skip_bytes()` to ignore it"]
    #[inline]
    pub fn scan_bytes(&mut self, tag: Tag) -> Result<&'a [u8], FastScanError> {
        let [header, rest @ ..] = self.remaining else {
            return Err(FastScanError::assert());
        };
        let length = self.check_tt(header, tag, 0x08);
        let body = rest.as_flattened().get(..length).ok_or(FastScanError::assert())?;
        self.remaining = &rest[length.div_ceil(8)..];

        Ok(body)
    }

    /// Scan an expected date-time.
    #[must_use = "Use the returned value, or use `FastScanner::skip_date_time()` to ignore it"]
    #[inline]
    pub fn scan_date_time(&mut self, tag: Tag) -> Result<i64, FastScanError> {
        let [header, value, rest @ ..] = self.remaining else {
            return Err(FastScanError::assert());
        };
        self.check_ttl(header, tag, 0x09, 8);
        self.remaining = rest;

        Ok(i64::from_be_bytes(*value))
    }

    /// Scan an expected interval.
    #[must_use = "Use the returned value, or use `FastScanner::skip_interval()` to ignore it"]
    #[inline]
    pub fn scan_interval(&mut self, tag: Tag) -> Result<u32, FastScanError> {
        let [header, value, rest @ ..] = self.remaining else {
            return Err(FastScanError::assert());
        };
        self.check_ttl(header, tag, 0x0A, 4);
        self.remaining = rest;

        Ok(u32::from_be_bytes(value[0..4].try_into().unwrap()))
    }
}

impl FastScanner<'_> {
    /// Skip an expected structure.
    #[inline]
    pub fn skip_struct(&mut self, tag: Tag) -> Result<(), FastScanError> {
        let [header, rest @ ..] = self.remaining else {
            return Err(FastScanError::assert());
        };
        let length = self.check_tt_8l(header, tag, 0x01);
        self.remaining = rest.get(length..).ok_or(FastScanError::assert())?;

        Ok(())
    }

    /// Skip an expected structure with a pre-determined length.
    #[inline]
    pub fn skip_fixed_struct(&mut self, tag: Tag, length: u32) -> Result<(), FastScanError> {
        debug_assert!(length.is_multiple_of(8));
        if self.remaining.len() < 1 + length as usize / 8 {
            return Err(FastScanError::assert());
        }
        self.check_ttl(&self.remaining[0], tag, 0x01, length);
        self.remaining = &self.remaining[1 + length as usize / 8..];

        Ok(())
    }

    /// Skip an expected integer.
    #[inline]
    pub fn skip_int(&mut self, tag: Tag) -> Result<(), FastScanError> {
        let [header, _, rest @ ..] = self.remaining else {
            return Err(FastScanError::assert());
        };
        self.check_ttl(header, tag, 0x02, 4);
        self.remaining = rest;

        Ok(())
    }

    /// Skip an expected long integer.
    #[inline]
    pub fn skip_long_int(&mut self, tag: Tag) -> Result<(), FastScanError> {
        let [header, _, rest @ ..] = self.remaining else {
            return Err(FastScanError::assert());
        };
        self.check_ttl(header, tag, 0x03, 8);
        self.remaining = rest;

        Ok(())
    }

    /// Skip an expected big integer.
    #[inline]
    pub fn skip_big_int(&mut self, tag: Tag) -> Result<(), FastScanError> {
        let [header, rest @ ..] = self.remaining else {
            return Err(FastScanError::assert());
        };
        let length = self.check_tt_8l(header, tag, 0x04);
        self.remaining = rest.get(length..).ok_or(FastScanError::assert())?;

        Ok(())
    }

    /// Skip an expected enumeration.
    #[inline]
    pub fn skip_enum(&mut self, tag: Tag) -> Result<(), FastScanError> {
        let [header, _, rest @ ..] = self.remaining else {
            return Err(FastScanError::assert());
        };
        self.check_ttl(header, tag, 0x05, 4);
        self.remaining = rest;

        Ok(())
    }

    /// Skip an expected boolean.
    #[inline]
    pub fn skip_bool(&mut self, tag: Tag) -> Result<(), FastScanError> {
        let [header, _, rest @ ..] = self.remaining else {
            return Err(FastScanError::assert());
        };
        self.check_ttl(header, tag, 0x06, 8);
        self.remaining = rest;

        Ok(())
    }

    /// Skip an expected text string.
    #[inline]
    pub fn skip_text(&mut self, tag: Tag) -> Result<(), FastScanError> {
        let [header, rest @ ..] = self.remaining else {
            return Err(FastScanError::assert());
        };
        let length = self.check_tt(header, tag, 0x07);
        self.remaining = rest.get(length.div_ceil(8)..).ok_or(FastScanError::assert())?;

        Ok(())
    }

    /// Skip an expected byte string.
    #[inline]
    pub fn skip_bytes(&mut self, tag: Tag) -> Result<(), FastScanError> {
        let [header, rest @ ..] = self.remaining else {
            return Err(FastScanError::assert());
        };
        let length = self.check_tt(header, tag, 0x08);
        self.remaining = rest.get(length.div_ceil(8)..).ok_or(FastScanError::assert())?;

        Ok(())
    }

    /// Skip an expected date-time.
    #[inline]
    pub fn skip_date_time(&mut self, tag: Tag) -> Result<(), FastScanError> {
        let [header, _, rest @ ..] = self.remaining else {
            return Err(FastScanError::assert());
        };
        self.check_ttl(header, tag, 0x09, 8);
        self.remaining = rest;

        Ok(())
    }

    /// Skip an expected interval.
    #[inline]
    pub fn skip_interval(&mut self, tag: Tag) -> Result<(), FastScanError> {
        let [header, _, rest @ ..] = self.remaining else {
            return Err(FastScanError::assert());
        };
        self.check_ttl(header, tag, 0x0A, 4);
        self.remaining = rest;

        Ok(())
    }
}

impl<'a> FastScanner<'a> {
    /// Scan an optional structure.
    ///
    /// The returned sub-scanner can be used to scan the fields of the
    /// `struct`; `self` will independently continue from the end of the
    /// `struct`.
    #[must_use = "Use the returned scanner to parse the structure, or use `FastScanner::skip_opt_struct()` to ignore its contents"]
    #[inline]
    pub fn scan_opt_struct(&mut self, tag: Tag) -> Result<Option<Self>, FastScanError> {
        let [header, rest @ ..] = self.remaining else {
            return Ok(None);
        };
        let Some(length) = self.test_tt_8l(header, tag, 0x01) else {
            return Ok(None);
        };
        let (body, rest) = rest.split_at_checked(length).ok_or(FastScanError::assert())?;
        self.remaining = rest;

        Ok(Some(Self::from_blocks(body)))
    }

    /// Scan an optional structure with a pre-determined length.
    ///
    /// The returned sub-scanner can be used to scan the fields of the
    /// `struct`; `self` will independently continue from the end of the
    /// `struct`.  If the length encoded in the input is different from the
    /// pre-determined length, the error will be delayed and both scanners
    /// will return garbage.
    #[must_use = "Use the returned scanner to parse the structure, or use `FastScanner::skip_opt_fixed_struct()` to ignore its contents"]
    #[inline]
    pub fn scan_opt_fixed_struct(&mut self, tag: Tag, length: u32) -> Result<Option<Self>, FastScanError> {
        debug_assert!(length.is_multiple_of(8));

        if self.remaining.len() < 1 + length as usize / 8 {
            return Ok(None);
        }
        let (header, rest) = self.remaining.split_first().unwrap();
        let Some(()) = self.test_ttl(header, tag, 0x01, length) else {
            return Ok(None);
        };
        let (body, rest) = rest.split_at(length as usize / 8);
        self.remaining = rest;

        Ok(Some(Self::from_blocks(body)))
    }

    /// Scan an optional integer.
    #[must_use = "Use the returned value, or use `FastScanner::skip_opt_int()` to ignore it"]
    #[inline]
    pub fn scan_opt_int(&mut self, tag: Tag) -> Result<Option<i32>, FastScanError> {
        let [header, value, rest @ ..] = self.remaining else {
            return Ok(None);
        };
        let Some(()) = self.test_ttl(header, tag, 0x02, 4) else {
            return Ok(None);
        };
        self.remaining = rest;

        Ok(Some(i32::from_be_bytes(value[0..4].try_into().unwrap())))
    }

    /// Scan an optional long integer.
    #[must_use = "Use the returned value, or use `FastScanner::skip_opt_long_int()` to ignore it"]
    #[inline]
    pub fn scan_opt_long_int(&mut self, tag: Tag) -> Result<Option<i64>, FastScanError> {
        let [header, value, rest @ ..] = self.remaining else {
            return Ok(None);
        };
        let Some(()) = self.test_ttl(header, tag, 0x03, 8) else {
            return Ok(None);
        };
        self.remaining = rest;

        Ok(Some(i64::from_be_bytes(*value)))
    }

    /// Scan an optional big integer.
    #[must_use = "Use the returned value, or use `FastScanner::skip_opt_big_int()` to ignore it"]
    #[inline]
    pub fn scan_opt_big_int(&mut self, tag: Tag) -> Result<Option<&'a [u8]>, FastScanError> {
        let [header, rest @ ..] = self.remaining else {
            return Ok(None);
        };
        let Some(length) = self.test_tt_8l(header, tag, 0x04) else {
            return Ok(None);
        };
        let (body, rest) = rest.split_at_checked(length).ok_or(FastScanError::assert())?;
        self.remaining = rest;

        Ok(Some(body.as_flattened()))
    }

    /// Scan an optional enumeration.
    #[must_use = "Use the returned value, or use `FastScanner::skip_opt_enum()` to ignore it"]
    #[inline]
    pub fn scan_opt_enum(&mut self, tag: Tag) -> Result<Option<u32>, FastScanError> {
        let [header, value, rest @ ..] = self.remaining else {
            return Ok(None);
        };
        let Some(()) = self.test_ttl(header, tag, 0x05, 4) else {
            return Ok(None);
        };
        self.remaining = rest;

        Ok(Some(u32::from_be_bytes(value[0..4].try_into().unwrap())))
    }

    /// Scan an optional boolean.
    #[must_use = "Use the returned value, or use `FastScanner::skip_opt_bool()` to ignore it"]
    #[inline]
    pub fn scan_opt_bool(&mut self, tag: Tag) -> Result<Option<bool>, FastScanError> {
        let [header, value, rest @ ..] = self.remaining else {
            return Ok(None);
        };
        let Some(()) = self.test_ttl(header, tag, 0x06, 8) else {
            return Ok(None);
        };
        // Load the value without changing its endianness.
        let value = u64::from_ne_bytes(*value);
        // Check that it all bits except the lowest are zero.
        self.failure_word |= value & !u64::from_be(1);
        self.remaining = rest;

        Ok(Some(value != 0))
    }

    /// Scan an optional text string.
    #[must_use = "Use the returned value, or use `FastScanner::skip_opt_text()` to ignore it"]
    #[inline]
    pub fn scan_opt_text(&mut self, tag: Tag) -> Result<Option<&'a str>, FastScanError> {
        let [header, rest @ ..] = self.remaining else {
            return Ok(None);
        };
        let Some(length) = self.test_tt(header, tag, 0x07) else {
            return Ok(None);
        };
        let body = rest.as_flattened().get(..length).ok_or(FastScanError::assert())?;
        let body = core::str::from_utf8(body).map_err(|_| FastScanError::assert())?;
        self.remaining = &rest[length.div_ceil(8)..];

        Ok(Some(body))
    }

    /// Scan an optional text string as bytes.
    #[must_use = "Use the returned value, or use `FastScanner::skip_opt_text()` to ignore it"]
    #[inline]
    pub fn scan_opt_text_bytes(&mut self, tag: Tag) -> Result<Option<&'a [u8]>, FastScanError> {
        let [header, rest @ ..] = self.remaining else {
            return Ok(None);
        };
        let Some(length) = self.test_tt(header, tag, 0x07) else {
            return Ok(None);
        };
        let body = rest.as_flattened().get(..length).ok_or(FastScanError::assert())?;
        self.remaining = &rest[length.div_ceil(8)..];

        Ok(Some(body))
    }

    /// Scan an optional byte string.
    #[must_use = "Use the returned value, or use `FastScanner::skip_opt_bytes()` to ignore it"]
    #[inline]
    pub fn scan_opt_bytes(&mut self, tag: Tag) -> Result<Option<&'a [u8]>, FastScanError> {
        let [header, rest @ ..] = self.remaining else {
            return Ok(None);
        };
        let Some(length) = self.test_tt(header, tag, 0x08) else {
            return Ok(None);
        };
        let body = rest.as_flattened().get(..length).ok_or(FastScanError::assert())?;
        self.remaining = &rest[length.div_ceil(8)..];

        Ok(Some(body))
    }

    /// Scan an optional date-time.
    #[must_use = "Use the returned value, or use `FastScanner::skip_opt_date_time()` to ignore it"]
    #[inline]
    pub fn scan_opt_date_time(&mut self, tag: Tag) -> Result<Option<i64>, FastScanError> {
        let [header, value, rest @ ..] = self.remaining else {
            return Ok(None);
        };
        let Some(()) = self.test_ttl(header, tag, 0x09, 8) else {
            return Ok(None);
        };
        self.remaining = rest;

        Ok(Some(i64::from_be_bytes(*value)))
    }

    /// Scan an optional interval.
    #[must_use = "Use the returned value, or use `FastScanner::skip_opt_interval()` to ignore it"]
    #[inline]
    pub fn scan_opt_interval(&mut self, tag: Tag) -> Result<Option<u32>, FastScanError> {
        let [header, value, rest @ ..] = self.remaining else {
            return Ok(None);
        };
        let Some(()) = self.test_ttl(header, tag, 0x0A, 4) else {
            return Ok(None);
        };
        self.remaining = rest;

        Ok(Some(u32::from_be_bytes(value[0..4].try_into().unwrap())))
    }
}

impl<'a> FastScanner<'a> {
    /// Skip an optional structure.
    #[inline]
    pub fn skip_opt_struct(&mut self, tag: Tag) -> Result<bool, FastScanError> {
        let [header, rest @ ..] = self.remaining else {
            return Ok(false);
        };
        let Some(length) = self.test_tt_8l(header, tag, 0x01) else {
            return Ok(false);
        };
        self.remaining = rest.get(length..).ok_or(FastScanError::assert())?;

        Ok(true)
    }

    /// Skip an optional structure with a pre-determined length.
    #[inline]
    pub fn skip_opt_fixed_struct(&mut self, tag: Tag, length: u32) -> Result<bool, FastScanError> {
        debug_assert!(length.is_multiple_of(8));
        if self.remaining.len() < 1 + length as usize / 8 {
            return Ok(false);
        }
        let (header, rest) = self.remaining.split_first().unwrap();
        let Some(()) = self.test_ttl(header, tag, 0x01, length) else {
            return Ok(false);
        };
        self.remaining = &rest[length as usize / 8..];

        Ok(true)
    }

    /// Skip an optional integer.
    #[inline]
    pub fn skip_opt_int(&mut self, tag: Tag) -> Result<bool, FastScanError> {
        let [header, _, rest @ ..] = self.remaining else {
            return Ok(false);
        };
        let Some(()) = self.test_ttl(header, tag, 0x02, 4) else {
            return Ok(false);
        };
        self.remaining = rest;

        Ok(true)
    }

    /// Skip an optional long integer.
    #[inline]
    pub fn skip_opt_long_int(&mut self, tag: Tag) -> Result<bool, FastScanError> {
        let [header, _, rest @ ..] = self.remaining else {
            return Ok(false);
        };
        let Some(()) = self.test_ttl(header, tag, 0x03, 8) else {
            return Ok(false);
        };
        self.remaining = rest;

        Ok(true)
    }

    /// Skip an optional big integer.
    #[inline]
    pub fn skip_opt_big_int(&mut self, tag: Tag) -> Result<bool, FastScanError> {
        let [header, rest @ ..] = self.remaining else {
            return Ok(false);
        };
        let Some(length) = self.test_tt_8l(header, tag, 0x04) else {
            return Ok(false);
        };
        self.remaining = rest.get(length..).ok_or(FastScanError::assert())?;

        Ok(true)
    }

    /// Skip an optional enumeration.
    #[inline]
    pub fn skip_opt_enum(&mut self, tag: Tag) -> Result<bool, FastScanError> {
        let [header, _, rest @ ..] = self.remaining else {
            return Ok(false);
        };
        let Some(()) = self.test_ttl(header, tag, 0x05, 4) else {
            return Ok(false);
        };
        self.remaining = rest;

        Ok(true)
    }

    /// Skip an optional boolean.
    #[inline]
    pub fn skip_opt_bool(&mut self, tag: Tag) -> Result<bool, FastScanError> {
        let [header, _, rest @ ..] = self.remaining else {
            return Ok(false);
        };
        let Some(()) = self.test_ttl(header, tag, 0x06, 8) else {
            return Ok(false);
        };
        self.remaining = rest;

        Ok(true)
    }

    /// Skip an optional text string.
    #[inline]
    pub fn skip_opt_text(&mut self, tag: Tag) -> Result<bool, FastScanError> {
        let [header, rest @ ..] = self.remaining else {
            return Ok(false);
        };
        let Some(length) = self.test_tt(header, tag, 0x07) else {
            return Ok(false);
        };
        self.remaining = rest.get(length.div_ceil(8)..).ok_or(FastScanError::assert())?;

        Ok(true)
    }

    /// Skip an optional byte string.
    #[inline]
    pub fn skip_opt_bytes(&mut self, tag: Tag) -> Result<bool, FastScanError> {
        let [header, rest @ ..] = self.remaining else {
            return Ok(false);
        };
        let Some(length) = self.test_tt(header, tag, 0x08) else {
            return Ok(false);
        };
        self.remaining = rest.get(length.div_ceil(8)..).ok_or(FastScanError::assert())?;

        Ok(true)
    }

    /// Skip an optional date-time.
    #[inline]
    pub fn skip_opt_date_time(&mut self, tag: Tag) -> Result<bool, FastScanError> {
        let [header, _, rest @ ..] = self.remaining else {
            return Ok(false);
        };
        let Some(()) = self.test_ttl(header, tag, 0x09, 8) else {
            return Ok(false);
        };
        self.remaining = rest;

        Ok(true)
    }

    /// Skip an optional interval.
    #[inline]
    pub fn skip_opt_interval(&mut self, tag: Tag) -> Result<bool, FastScanError> {
        let [header, _, rest @ ..] = self.remaining else {
            return Ok(false);
        };
        let Some(()) = self.test_ttl(header, tag, 0x0A, 4) else {
            return Ok(false);
        };
        self.remaining = rest;

        Ok(true)
    }
}

//============ Errors ==========================================================

/// An error from a [`FastScanner`].
///
/// [`FastScanner`] deliberately elides information about the error, in order
/// to run more efficiently.  As such, this is a trivial zero-sized type.
///
/// ## Interpretation
///
/// Presumably, the input was received from an external entity.  This error
/// indicates a miscommunication between that entity and the caller.  There
/// are three expected causes of such miscommunication:
///
/// - Incompatibility (e.g. the entity expects the caller to understand more
///   than it does).  This is a persistent error, but may be localized to the
///   particular kind of input message.
///
/// - Transport error (e.g. the input was corrupted during network transfer).
///   This is an ephemeral error.
///
/// - Implementation bug (e.g. in the external entity).  This is a persistent
///   error, but may be localized to the particular kind of input message.
///
/// The caller can distinguish incompatibilities from the lower-level errors
/// by re-parsing the input using a different scanner.  In order to distinguish
/// transport errors from implementation bugs, the caller has to continue
/// operation and detect reoccurring parsing failures.
//
// TODO: Link to 'SlowScanner' once it exists.
///
/// ## Reaction
///
/// The caller can react to this error in a few ways:
///
/// - Assume the error was ephemeral and continue communicating with the
///   external entity as normal.  The caller should remember that the error
///   occurred and switch to a different reaction if it reoccurs.
///
/// - Actively work around the issue by parsing the input differently.  This
///   implies significant implementation burden, and is not recommended.
///
/// - Avoid receiving similar messages from the external entity (e.g. by
///   avoiding making the same kinds of requests to it, or informing it that
///   its message could not be parsed).  This is only feasible if the
///   communication is non-critical functionality for the caller.
///
/// - Crash.  This is ideal if the error prevents the caller from fulfilling
///   critical functionality.
///
/// The caller should re-parse the input using a different scanner; if the error
/// appears to be an incompatibility, it should avoid receiving such messages
/// from the entity.  If this is not possible, it should crash.  If the error
/// appears to be a lower-level bug, the caller should assume it is ephemeral
/// and continue operation.  If the error is persistent, it should avoid
/// receiving similar messages, or crash.
//
// TODO: Link to 'SlowScanner' once it exists.
pub struct FastScanError {
    /// A backtrace.
    #[cfg(debug_assertions)]
    backtrace: std::backtrace::Backtrace,

    /// Force this 'struct' to be private.
    _private: (),
}

impl FastScanError {
    /// Assert an error.
    pub fn assert() -> Self {
        Self {
            #[cfg(debug_assertions)]
            backtrace: std::backtrace::Backtrace::force_capture(),
            _private: (),
        }
    }
}

impl std::error::Error for FastScanError {}

impl fmt::Debug for FastScanError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        #[cfg(debug_assertions)]
        {
            f.debug_struct("FastScanError")
                .field("backtrace", &self.backtrace)
                .finish()
        }

        #[cfg(not(debug_assertions))]
        {
            f.write_str("a fast-scanning error occurred")
        }
    }
}

impl fmt::Display for FastScanError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a fast-scanning error occurred")?;
        #[cfg(debug_assertions)]
        {
            write!(f, "\nBacktrace:\n{}", self.backtrace)?;
        }
        Ok(())
    }
}

impl PartialEq for FastScanError {
    fn eq(&self, _: &Self) -> bool {
        true
    }
}

impl Eq for FastScanError {}
