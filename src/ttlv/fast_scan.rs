//! Scanning TTLV elements really fast.

use core::fmt;

use super::types::Tag;

//----------- FastScanner ----------------------------------------------------

/// A fast TTLV scanner.
///
/// In most cases, errors are highly unlikely.  This scanner optimizes for
/// this by eliding error handling and pinpointing facilities -- it detects
/// errors without tracking any details of them.  In some cases, it will
/// delay errors, returning garbage data instead of [`Err`].  If scanning
/// with [`FastScanner`] fails, a different scanner needs to be used to
/// ascertain the position and cause of the error.
#[derive(Clone)]
#[must_use = "Call 'FastScanner::finish()' to finish scanning"]
pub struct FastScanner<'a> {
    /// The currently remaining input.
    remaining: &'a [[u8; 8]],

    /// A failure word.
    ///
    /// This is non-zero if an error was detected and delayed.
    failure_word: u64,
}

impl<'a> FastScanner<'a> {
    /// Construct a new [`FastScanner`].
    pub fn new(input: &'a [u8]) -> Result<Self, FastScanError> {
        let num_blocks = input.len() / 8;
        if !input.len().is_multiple_of(8) {
            // The input contains a partial block.
            return Err(FastScanError::assert());
        }

        let ptr = input.as_ptr().cast::<[u8; 8]>();
        let input = unsafe { core::slice::from_raw_parts(ptr, num_blocks) };
        Ok(Self::from_blocks(input))
    }

    /// Construct a new [`FastScanner`] from a block slice.
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
    pub const fn delayed_error(&self) -> bool {
        self.failure_word != 0
    }

    /// Whether a whole element is available.
    ///
    /// The length of the next element will be checked; if it is entirely loaded
    /// in the buffer, `true` is returned.  Otherwise, or if there is no next
    /// element, `false` is returned.
    pub fn have_next(&self) -> bool {
        let [head, rest @ ..] = self.remaining else {
            return false;
        };

        let length = u32::from_be_bytes(head[4..8].try_into().unwrap());
        let available = rest.as_flattened().len();

        if usize::MAX as u32 == u32::MAX {
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
        if self.is_empty() && !self.delayed_error() {
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
        if !self.delayed_error() {
            Ok(())
        } else {
            Err(FastScanError::assert())
        }
    }
}

impl<'a> FastScanner<'a> {
    /// Scan an expected structure.
    ///
    /// The returned sub-scanner can be used to scan the fields of the
    /// `struct`; `self` will independently continue from the end of the
    /// `struct`.
    #[inline]
    pub fn scan_struct(&mut self, tag: Tag) -> Result<Self, FastScanError> {
        let expected_header = (tag.value() as u64) << 40 | 0x01_00000000;
        let [header, rest @ ..] = self.remaining else {
            return Err(FastScanError::assert());
        };
        let header = u64::from_be_bytes(*header);
        self.failure_word |= (expected_header ^ header) & 0xFFFFFFFF_00000007;
        let length = header as u32 as usize / 8;
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
    #[inline]
    pub fn scan_fixed_struct(&mut self, tag: Tag, length: u32) -> Result<Self, FastScanError> {
        debug_assert!(length.is_multiple_of(8));
        let expected_header = ((tag.value() as u64) << 40 | 0x01 << 32 | length as u64).to_be();
        if self.remaining.len() < 1 + length as usize / 8 {
            return Err(FastScanError::assert());
        }
        let (header, rest) = self.remaining.split_first().unwrap();
        let header = u64::from_ne_bytes(*header);
        self.failure_word |= expected_header ^ header;
        let (body, rest) = rest.split_at(length as usize / 8);
        self.remaining = rest;

        Ok(Self::from_blocks(body))
    }

    /// Scan an expected integer.
    #[inline]
    pub fn scan_int(&mut self, tag: Tag) -> Result<i32, FastScanError> {
        let expected_header = ((tag.value() as u64) << 40 | 0x02_00000004).to_be();
        let [header, value, rest @ ..] = self.remaining else {
            return Err(FastScanError::assert());
        };
        let header = u64::from_ne_bytes(*header);
        self.failure_word |= expected_header ^ header;
        self.remaining = rest;

        Ok(i32::from_be_bytes(value[0..4].try_into().unwrap()))
    }

    /// Scan an expected long integer.
    #[inline]
    pub fn scan_long_int(&mut self, tag: Tag) -> Result<i64, FastScanError> {
        let expected_header = ((tag.value() as u64) << 40 | 0x03_00000008).to_be();
        let [header, value, rest @ ..] = self.remaining else {
            return Err(FastScanError::assert());
        };
        let header = u64::from_ne_bytes(*header);
        self.failure_word |= expected_header ^ header;
        self.remaining = rest;

        Ok(i64::from_be_bytes(*value))
    }

    /// Scan an expected big integer.
    #[inline]
    pub fn scan_big_int(&mut self, tag: Tag) -> Result<&'a [u8], FastScanError> {
        let expected_header = (tag.value() as u64) << 40 | 0x04_00000000;
        let [header, rest @ ..] = self.remaining else {
            return Err(FastScanError::assert());
        };
        let header = u64::from_be_bytes(*header);
        self.failure_word |= (expected_header ^ header) & 0xFFFFFFFF_00000007;
        let length = header as u32 as usize / 8;
        let (body, rest) = rest.split_at_checked(length).ok_or(FastScanError::assert())?;
        self.remaining = rest;

        Ok(body.as_flattened())
    }

    /// Scan an expected enumeration.
    #[inline]
    pub fn scan_enum(&mut self, tag: Tag) -> Result<u32, FastScanError> {
        let expected_header = ((tag.value() as u64) << 40 | 0x05_00000004).to_be();
        let [header, value, rest @ ..] = self.remaining else {
            return Err(FastScanError::assert());
        };
        let header = u64::from_ne_bytes(*header);
        self.failure_word |= expected_header ^ header;
        self.remaining = rest;

        Ok(u32::from_be_bytes(value[0..4].try_into().unwrap()))
    }

    /// Scan an expected boolean.
    #[inline]
    pub fn scan_bool(&mut self, tag: Tag) -> Result<bool, FastScanError> {
        let expected_header = ((tag.value() as u64) << 40 | 0x06_00000008).to_be();
        let [header, value, rest @ ..] = self.remaining else {
            return Err(FastScanError::assert());
        };
        let header = u64::from_ne_bytes(*header);
        self.failure_word |= expected_header ^ header;
        let value = u64::from_ne_bytes(*value);
        self.failure_word |= value & !u64::from_be(1);
        self.remaining = rest;

        Ok(value != 0)
    }

    /// Scan an expected text string.
    #[inline]
    pub fn scan_text(&mut self, tag: Tag) -> Result<&'a str, FastScanError> {
        let expected_header = (tag.value() << 8 | 0x07).to_be();
        let [header, rest @ ..] = self.remaining else {
            return Err(FastScanError::assert());
        };
        let (header, length) = header.split_at(4);
        let header = u32::from_ne_bytes(header.try_into().unwrap());
        let length = u32::from_be_bytes(length.try_into().unwrap());
        self.failure_word |= (expected_header ^ header) as u64;
        let length = length as usize;
        let body = rest.as_flattened().get(..length).ok_or(FastScanError::assert())?;
        let body = core::str::from_utf8(body).map_err(|_| FastScanError::assert())?;
        self.remaining = &rest[length.div_ceil(8)..];

        Ok(body)
    }

    /// Scan an expected text string as bytes.
    #[inline]
    pub fn scan_text_bytes(&mut self, tag: Tag) -> Result<&'a [u8], FastScanError> {
        let expected_header = (tag.value() << 8 | 0x07).to_be();
        let [header, rest @ ..] = self.remaining else {
            return Err(FastScanError::assert());
        };
        let (header, length) = header.split_at(4);
        let header = u32::from_ne_bytes(header.try_into().unwrap());
        let length = u32::from_be_bytes(length.try_into().unwrap());
        self.failure_word |= (expected_header ^ header) as u64;
        let length = length as usize;
        let body = rest.as_flattened().get(..length).ok_or(FastScanError::assert())?;
        self.remaining = &rest[length.div_ceil(8)..];

        Ok(body)
    }

    /// Scan an expected byte string.
    #[inline]
    pub fn scan_bytes(&mut self, tag: Tag) -> Result<&'a [u8], FastScanError> {
        let expected_header = (tag.value() << 8 | 0x08).to_be();
        let [header, rest @ ..] = self.remaining else {
            return Err(FastScanError::assert());
        };
        let (header, length) = header.split_at(4);
        let header = u32::from_ne_bytes(header.try_into().unwrap());
        let length = u32::from_be_bytes(length.try_into().unwrap());
        self.failure_word |= (expected_header ^ header) as u64;
        let length = length as usize;
        let body = rest.as_flattened().get(..length).ok_or(FastScanError::assert())?;
        self.remaining = &rest[length.div_ceil(8)..];

        Ok(body)
    }

    /// Scan an expected date-time.
    #[inline]
    pub fn scan_date_time(&mut self, tag: Tag) -> Result<i64, FastScanError> {
        let expected_header = ((tag.value() as u64) << 40 | 0x09_00000008).to_be();
        let [header, value, rest @ ..] = self.remaining else {
            return Err(FastScanError::assert());
        };
        let header = u64::from_ne_bytes(*header);
        self.failure_word |= expected_header ^ header;
        self.remaining = rest;

        Ok(i64::from_be_bytes(*value))
    }

    /// Scan an expected interval.
    #[inline]
    pub fn scan_interval(&mut self, tag: Tag) -> Result<u32, FastScanError> {
        let expected_header = ((tag.value() as u64) << 40 | 0x0A_00000004).to_be();
        let [header, value, rest @ ..] = self.remaining else {
            return Err(FastScanError::assert());
        };
        let header = u64::from_ne_bytes(*header);
        self.failure_word |= expected_header ^ header;
        self.remaining = rest;

        Ok(u32::from_be_bytes(value[0..4].try_into().unwrap()))
    }
}

impl FastScanner<'_> {
    /// Skip an expected structure.
    #[inline]
    pub fn skip_struct(&mut self, tag: Tag) -> Result<(), FastScanError> {
        let expected_header = (tag.value() as u64) << 40 | 0x01_00000000;
        let [header, rest @ ..] = self.remaining else {
            return Err(FastScanError::assert());
        };
        let header = u64::from_be_bytes(*header);
        self.failure_word |= (expected_header ^ header) & 0xFFFFFFFF_00000007;
        let length = header as u32 as usize / 8;
        self.remaining = rest.get(length..).ok_or(FastScanError::assert())?;

        Ok(())
    }

    /// Skip an expected structure with a pre-determined length.
    #[inline]
    pub fn skip_fixed_struct(&mut self, tag: Tag, length: u32) -> Result<(), FastScanError> {
        debug_assert!(length.is_multiple_of(8));
        let expected_header = ((tag.value() as u64) << 40 | 0x01 << 32 | length as u64).to_be();
        if self.remaining.len() < 1 + length as usize / 8 {
            return Err(FastScanError::assert());
        }
        let header = u64::from_ne_bytes(self.remaining[0]);
        self.failure_word |= (expected_header ^ header) & 0xFFFFFFFF_00000007;
        self.remaining = &self.remaining[1 + length as usize / 8..];

        Ok(())
    }

    /// Skip an expected integer.
    #[inline]
    pub fn skip_int(&mut self, tag: Tag) -> Result<(), FastScanError> {
        let expected_header = ((tag.value() as u64) << 40 | 0x02_00000004).to_be();
        let [header, _, rest @ ..] = self.remaining else {
            return Err(FastScanError::assert());
        };
        let header = u64::from_ne_bytes(*header);
        self.failure_word |= expected_header ^ header;
        self.remaining = rest;

        Ok(())
    }

    /// Skip an expected long integer.
    #[inline]
    pub fn skip_long_int(&mut self, tag: Tag) -> Result<(), FastScanError> {
        let expected_header = ((tag.value() as u64) << 40 | 0x03_00000008).to_be();
        let [header, _, rest @ ..] = self.remaining else {
            return Err(FastScanError::assert());
        };
        let header = u64::from_ne_bytes(*header);
        self.failure_word |= expected_header ^ header;
        self.remaining = rest;

        Ok(())
    }

    /// Skip an expected big integer.
    #[inline]
    pub fn skip_big_int(&mut self, tag: Tag) -> Result<(), FastScanError> {
        let expected_header = (tag.value() as u64) << 40 | 0x04_00000000;
        let [header, rest @ ..] = self.remaining else {
            return Err(FastScanError::assert());
        };
        let header = u64::from_be_bytes(*header);
        self.failure_word |= (expected_header ^ header) & 0xFFFFFFFF_00000007;
        let length = header as u32 as usize / 8;
        self.remaining = rest.get(length..).ok_or(FastScanError::assert())?;

        Ok(())
    }

    /// Skip an expected enumeration.
    #[inline]
    pub fn skip_enum(&mut self, tag: Tag) -> Result<(), FastScanError> {
        let expected_header = ((tag.value() as u64) << 40 | 0x05_00000004).to_be();
        let [header, _, rest @ ..] = self.remaining else {
            return Err(FastScanError::assert());
        };
        let header = u64::from_ne_bytes(*header);
        self.failure_word |= expected_header ^ header;
        self.remaining = rest;

        Ok(())
    }

    /// Skip an expected boolean.
    #[inline]
    pub fn skip_bool(&mut self, tag: Tag) -> Result<(), FastScanError> {
        let expected_header = ((tag.value() as u64) << 40 | 0x06_00000008).to_be();
        let [header, _, rest @ ..] = self.remaining else {
            return Err(FastScanError::assert());
        };
        let header = u64::from_ne_bytes(*header);
        self.failure_word |= expected_header ^ header;
        self.remaining = rest;

        Ok(())
    }

    /// Skip an expected text string.
    #[inline]
    pub fn skip_text(&mut self, tag: Tag) -> Result<(), FastScanError> {
        let expected_header = (tag.value() << 8 | 0x07).to_be();
        let [header, rest @ ..] = self.remaining else {
            return Err(FastScanError::assert());
        };
        let (header, length) = header.split_at(4);
        let header = u32::from_ne_bytes(header.try_into().unwrap());
        let length = u32::from_be_bytes(length.try_into().unwrap());
        self.failure_word |= (expected_header ^ header) as u64;
        self.remaining = rest
            .get((length as usize).div_ceil(8)..)
            .ok_or(FastScanError::assert())?;

        Ok(())
    }

    /// Skip an expected byte string.
    #[inline]
    pub fn skip_bytes(&mut self, tag: Tag) -> Result<(), FastScanError> {
        let expected_header = (tag.value() << 8 | 0x08).to_be();
        let [header, rest @ ..] = self.remaining else {
            return Err(FastScanError::assert());
        };
        let (header, length) = header.split_at(4);
        let header = u32::from_ne_bytes(header.try_into().unwrap());
        let length = u32::from_be_bytes(length.try_into().unwrap());
        self.failure_word |= (expected_header ^ header) as u64;
        self.remaining = rest
            .get((length as usize).div_ceil(8)..)
            .ok_or(FastScanError::assert())?;

        Ok(())
    }

    /// Skip an expected date-time.
    #[inline]
    pub fn skip_date_time(&mut self, tag: Tag) -> Result<(), FastScanError> {
        let expected_header = ((tag.value() as u64) << 40 | 0x09_00000008).to_be();
        let [header, _, rest @ ..] = self.remaining else {
            return Err(FastScanError::assert());
        };
        let header = u64::from_ne_bytes(*header);
        self.failure_word |= expected_header ^ header;
        self.remaining = rest;

        Ok(())
    }

    /// Skip an expected interval.
    #[inline]
    pub fn skip_interval(&mut self, tag: Tag) -> Result<(), FastScanError> {
        let expected_header = ((tag.value() as u64) << 40 | 0x0A_00000004).to_be();
        let [header, _, rest @ ..] = self.remaining else {
            return Err(FastScanError::assert());
        };
        let header = u64::from_ne_bytes(*header);
        self.failure_word |= expected_header ^ header;
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
    #[inline]
    pub fn scan_opt_struct(&mut self, tag: Tag) -> Result<Option<Self>, FastScanError> {
        let expected_header = (tag.value() as u64) << 40 | 0x01_00000000;
        let [header, rest @ ..] = self.remaining else {
            return Ok(None);
        };
        let header = u64::from_be_bytes(*header);
        if (expected_header ^ header) & 0xFFFFFFFF_00000007 != 0 {
            return Ok(None);
        }
        let length = header as u32 as usize / 8;
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
    #[inline]
    pub fn scan_opt_fixed_struct(&mut self, tag: Tag, length: u32) -> Result<Option<Self>, FastScanError> {
        debug_assert!(length.is_multiple_of(8));
        let expected_header = ((tag.value() as u64) << 40 | 0x01 << 32 | length as u64).to_be();

        if self.remaining.len() < 1 + length as usize / 8 {
            return Ok(None);
        }
        let (header, rest) = self.remaining.split_first().unwrap();
        let header = u64::from_ne_bytes(*header);
        if expected_header != header {
            return Ok(None);
        }
        let length = length as usize / 8;
        let (body, rest) = rest.split_at(length);
        self.remaining = rest;

        Ok(Some(Self::from_blocks(body)))
    }

    /// Scan an optional integer.
    #[inline]
    pub fn scan_opt_int(&mut self, tag: Tag) -> Result<Option<i32>, FastScanError> {
        let expected_header = ((tag.value() as u64) << 40 | 0x02_00000004).to_be();
        let [header, value, rest @ ..] = self.remaining else {
            return Ok(None);
        };
        let header = u64::from_ne_bytes(*header);
        if expected_header != header {
            return Ok(None);
        }
        self.remaining = rest;

        Ok(Some(i32::from_be_bytes(value[0..4].try_into().unwrap())))
    }

    /// Scan an optional long integer.
    #[inline]
    pub fn scan_opt_long_int(&mut self, tag: Tag) -> Result<Option<i64>, FastScanError> {
        let expected_header = ((tag.value() as u64) << 40 | 0x03_00000008).to_be();
        let [header, value, rest @ ..] = self.remaining else {
            return Ok(None);
        };
        let header = u64::from_ne_bytes(*header);
        if expected_header != header {
            return Ok(None);
        }
        self.remaining = rest;

        Ok(Some(i64::from_be_bytes(*value)))
    }

    /// Scan an optional big integer.
    #[inline]
    pub fn scan_opt_big_int(&mut self, tag: Tag) -> Result<Option<&'a [u8]>, FastScanError> {
        let expected_header = (tag.value() as u64) << 40 | 0x04_00000000;
        let [header, rest @ ..] = self.remaining else {
            return Ok(None);
        };
        let header = u64::from_be_bytes(*header);
        if (expected_header ^ header) & 0xFFFFFFFF_00000007 != 0 {
            return Ok(None);
        }
        let length = header as u32 as usize / 8;
        let (body, rest) = rest.split_at_checked(length).ok_or(FastScanError::assert())?;
        self.remaining = rest;

        Ok(Some(body.as_flattened()))
    }

    /// Scan an optional enumeration.
    #[inline]
    pub fn scan_opt_enum(&mut self, tag: Tag) -> Result<Option<u32>, FastScanError> {
        let expected_header = ((tag.value() as u64) << 40 | 0x05_00000004).to_be();
        let [header, value, rest @ ..] = self.remaining else {
            return Ok(None);
        };
        let header = u64::from_ne_bytes(*header);
        if expected_header != header {
            return Ok(None);
        }
        self.remaining = rest;

        Ok(Some(u32::from_be_bytes(value[0..4].try_into().unwrap())))
    }

    /// Scan an optional boolean.
    #[inline]
    pub fn scan_opt_bool(&mut self, tag: Tag) -> Result<Option<bool>, FastScanError> {
        let expected_header = ((tag.value() as u64) << 40 | 0x06_00000008).to_be();
        let [header, value, rest @ ..] = self.remaining else {
            return Ok(None);
        };
        let header = u64::from_ne_bytes(*header);
        if expected_header != header {
            return Ok(None);
        }
        let value = u64::from_ne_bytes(*value);
        self.failure_word |= value & !u64::from_be(1);
        self.remaining = rest;

        Ok(Some(value != 0))
    }

    /// Scan an optional text string.
    #[inline]
    pub fn scan_opt_text(&mut self, tag: Tag) -> Result<Option<&'a str>, FastScanError> {
        let expected_header = (tag.value() << 8 | 0x07).to_be();
        let [header, rest @ ..] = self.remaining else {
            return Ok(None);
        };
        let (header, length) = header.split_at(4);
        let header = u32::from_ne_bytes(header.try_into().unwrap());
        let length = u32::from_be_bytes(length.try_into().unwrap());
        if expected_header != header {
            return Ok(None);
        }
        let length = length as usize;
        let body = rest.as_flattened().get(..length).ok_or(FastScanError::assert())?;
        let body = core::str::from_utf8(body).map_err(|_| FastScanError::assert())?;
        self.remaining = &rest[length.div_ceil(8)..];

        Ok(Some(body))
    }

    /// Scan an optional text string as bytes.
    #[inline]
    pub fn scan_opt_text_bytes(&mut self, tag: Tag) -> Result<Option<&'a [u8]>, FastScanError> {
        let expected_header = (tag.value() << 8 | 0x07).to_be();
        let [header, rest @ ..] = self.remaining else {
            return Ok(None);
        };
        let (header, length) = header.split_at(4);
        let header = u32::from_ne_bytes(header.try_into().unwrap());
        let length = u32::from_be_bytes(length.try_into().unwrap());
        if expected_header != header {
            return Ok(None);
        }
        let length = length as usize;
        let body = rest.as_flattened().get(..length).ok_or(FastScanError::assert())?;
        self.remaining = &rest[length.div_ceil(8)..];

        Ok(Some(body))
    }

    /// Scan an optional byte string.
    #[inline]
    pub fn scan_opt_bytes(&mut self, tag: Tag) -> Result<Option<&'a [u8]>, FastScanError> {
        let expected_header = (tag.value() << 8 | 0x08).to_be();
        let [header, rest @ ..] = self.remaining else {
            return Ok(None);
        };
        let (header, length) = header.split_at(4);
        let header = u32::from_ne_bytes(header.try_into().unwrap());
        let length = u32::from_be_bytes(length.try_into().unwrap());
        if expected_header != header {
            return Ok(None);
        }
        let length = length as usize;
        let body = rest.as_flattened().get(..length).ok_or(FastScanError::assert())?;
        self.remaining = &rest[length.div_ceil(8)..];

        Ok(Some(body))
    }

    /// Scan an optional date-time.
    #[inline]
    pub fn scan_opt_date_time(&mut self, tag: Tag) -> Result<Option<i64>, FastScanError> {
        let expected_header = ((tag.value() as u64) << 40 | 0x09_00000008).to_be();
        let [header, value, rest @ ..] = self.remaining else {
            return Ok(None);
        };
        let header = u64::from_ne_bytes(*header);
        if expected_header != header {
            return Ok(None);
        }
        self.remaining = rest;

        Ok(Some(i64::from_be_bytes(*value)))
    }

    /// Scan an optional interval.
    #[inline]
    pub fn scan_opt_interval(&mut self, tag: Tag) -> Result<Option<u32>, FastScanError> {
        let expected_header = ((tag.value() as u64) << 40 | 0x0A_00000004).to_be();
        let [header, value, rest @ ..] = self.remaining else {
            return Ok(None);
        };
        let header = u64::from_ne_bytes(*header);
        if expected_header != header {
            return Ok(None);
        }
        self.remaining = rest;

        Ok(Some(u32::from_be_bytes(value[0..4].try_into().unwrap())))
    }
}

impl<'a> FastScanner<'a> {
    /// Skip an optional structure.
    #[inline]
    pub fn skip_opt_struct(&mut self, tag: Tag) -> Result<bool, FastScanError> {
        let expected_header = (tag.value() as u64) << 40 | 0x01_00000000;
        let [header, rest @ ..] = self.remaining else {
            return Ok(false);
        };
        let header = u64::from_be_bytes(*header);
        if (expected_header ^ header) & 0xFFFFFFFF_00000007 != 0 {
            return Ok(false);
        }
        let length = header as u32 as usize / 8;
        self.remaining = rest.get(length..).ok_or(FastScanError::assert())?;

        Ok(true)
    }

    /// Skip an optional structure with a pre-determined length.
    #[inline]
    pub fn skip_opt_fixed_struct(&mut self, tag: Tag, length: u32) -> Result<bool, FastScanError> {
        debug_assert!(length.is_multiple_of(8));
        let expected_header = ((tag.value() as u64) << 40 | 0x01 << 32 | length as u64).to_be();
        if self.remaining.len() < 1 + length as usize / 8 {
            return Ok(false);
        }
        let (header, rest) = self.remaining.split_first().unwrap();
        let header = u64::from_ne_bytes(*header);
        if expected_header != header {
            return Ok(false);
        }
        self.remaining = &rest[length as usize / 8..];

        Ok(true)
    }

    /// Skip an optional integer.
    #[inline]
    pub fn skip_opt_int(&mut self, tag: Tag) -> Result<bool, FastScanError> {
        let expected_header = ((tag.value() as u64) << 40 | 0x02_00000004).to_be();
        let [header, _, rest @ ..] = self.remaining else {
            return Ok(false);
        };
        let header = u64::from_ne_bytes(*header);
        if expected_header != header {
            return Ok(false);
        }
        self.remaining = rest;

        Ok(true)
    }

    /// Skip an optional long integer.
    #[inline]
    pub fn skip_opt_long_int(&mut self, tag: Tag) -> Result<bool, FastScanError> {
        let expected_header = ((tag.value() as u64) << 40 | 0x03_00000008).to_be();
        let [header, _, rest @ ..] = self.remaining else {
            return Ok(false);
        };
        let header = u64::from_ne_bytes(*header);
        if expected_header != header {
            return Ok(false);
        }
        self.remaining = rest;

        Ok(true)
    }

    /// Skip an optional big integer.
    #[inline]
    pub fn skip_opt_big_int(&mut self, tag: Tag) -> Result<bool, FastScanError> {
        let expected_header = (tag.value() as u64) << 40 | 0x04_00000000;
        let [header, rest @ ..] = self.remaining else {
            return Ok(false);
        };
        let header = u64::from_be_bytes(*header);
        if (expected_header ^ header) & 0xFFFFFFFF_00000007 != 0 {
            return Ok(false);
        }
        let length = header as u32 as usize / 8;
        self.remaining = rest.get(length..).ok_or(FastScanError::assert())?;

        Ok(true)
    }

    /// Skip an optional enumeration.
    #[inline]
    pub fn skip_opt_enum(&mut self, tag: Tag) -> Result<bool, FastScanError> {
        let expected_header = ((tag.value() as u64) << 40 | 0x05_00000004).to_be();
        let [header, _, rest @ ..] = self.remaining else {
            return Ok(false);
        };
        let header = u64::from_ne_bytes(*header);
        if expected_header != header {
            return Ok(false);
        }
        self.remaining = rest;

        Ok(true)
    }

    /// Skip an optional boolean.
    #[inline]
    pub fn skip_opt_bool(&mut self, tag: Tag) -> Result<bool, FastScanError> {
        let expected_header = ((tag.value() as u64) << 40 | 0x06_00000008).to_be();
        let [header, _, rest @ ..] = self.remaining else {
            return Ok(false);
        };
        let header = u64::from_ne_bytes(*header);
        if expected_header != header {
            return Ok(false);
        }
        self.remaining = rest;

        Ok(true)
    }

    /// Skip an optional text string.
    #[inline]
    pub fn skip_opt_text(&mut self, tag: Tag) -> Result<bool, FastScanError> {
        let expected_header = (tag.value() << 8 | 0x07).to_be();
        let [header, rest @ ..] = self.remaining else {
            return Ok(false);
        };
        let (header, length) = header.split_at(4);
        let header = u32::from_ne_bytes(header.try_into().unwrap());
        let length = u32::from_be_bytes(length.try_into().unwrap());
        if expected_header != header {
            return Ok(false);
        }
        self.remaining = rest
            .get((length as usize).div_ceil(8)..)
            .ok_or(FastScanError::assert())?;

        Ok(true)
    }

    /// Skip an optional byte string.
    #[inline]
    pub fn skip_opt_bytes(&mut self, tag: Tag) -> Result<bool, FastScanError> {
        let expected_header = (tag.value() << 8 | 0x08).to_be();
        let [header, rest @ ..] = self.remaining else {
            return Ok(false);
        };
        let (header, length) = header.split_at(4);
        let header = u32::from_ne_bytes(header.try_into().unwrap());
        let length = u32::from_be_bytes(length.try_into().unwrap());
        if expected_header != header {
            return Ok(false);
        }
        self.remaining = rest
            .get((length as usize).div_ceil(8)..)
            .ok_or(FastScanError::assert())?;

        Ok(true)
    }

    /// Skip an optional date-time.
    #[inline]
    pub fn skip_opt_date_time(&mut self, tag: Tag) -> Result<bool, FastScanError> {
        let expected_header = ((tag.value() as u64) << 40 | 0x09_00000008).to_be();
        let [header, _, rest @ ..] = self.remaining else {
            return Ok(false);
        };
        let header = u64::from_ne_bytes(*header);
        if expected_header != header {
            return Ok(false);
        }
        self.remaining = rest;

        Ok(true)
    }

    /// Skip an optional interval.
    #[inline]
    pub fn skip_opt_interval(&mut self, tag: Tag) -> Result<bool, FastScanError> {
        let expected_header = ((tag.value() as u64) << 40 | 0x0A_00000004).to_be();
        let [header, _, rest @ ..] = self.remaining else {
            return Ok(false);
        };
        let header = u64::from_ne_bytes(*header);
        if expected_header != header {
            return Ok(false);
        }
        self.remaining = rest;

        Ok(true)
    }
}

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
/// by re-parsing the input using [`SlowScanner`].  In order to distinguish
/// transport errors from implementation bugs, the caller has to continue
/// operation and detect reoccurring parsing failures.
///
/// [`SlowScanner`]: crate::slow_scan::SlowScanner
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
/// The caller should re-parse the input using [`SlowScanner`]; if the error
/// appears to be an incompatibility, it should avoid receiving such messages
/// from the entity.  If this is not possible, it should crash.  If the error
/// appears to be a lower-level bug, the caller should assume it is ephemeral
/// and continue operation.  If the error is persistent, it should avoid
/// receiving similar messages, or crash.
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
        f.write_str("a fast-scanning error occurred")
    }
}

impl PartialEq for FastScanError {
    fn eq(&self, _: &Self) -> bool {
        true
    }
}

impl Eq for FastScanError {}
