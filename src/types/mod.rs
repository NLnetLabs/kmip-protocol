//! Rust type definitions for `kmip-ttlv` based (de)serializing of KMIP message objects.
//!
//! These types are used when constructing requests to be sent to, and processing responses received from, a KMIP
//! server. The [Client](crate::client::Client) struct composes the request types into entire KMIP request message type
//! trees for serialization into the binary TTLV format and uses the response types to deserialize the binary KMIP
//! response format into rich Rust types.
//!
//! The attributes on the Rust types are used by the `kmip-ttlv` crate to guide the (de)serialization correctly to/from
//! the KMIP binary TTLV format.

pub mod common;
pub mod request;
pub mod response;
pub mod traits;

macro_rules! impl_ttlv_serde {
    // Implement TTLV (de)serialization for a simple enum.
    (enum $type:ident as $tag:literal) => {
        impl $type {
            pub const TAG: Tag = Tag::new($tag);

            pub fn fast_scan(scanner: &mut FastScanner<'_>) -> Result<Self, FastScanError> {
                Self::fast_scan_with(scanner, Self::TAG)
            }

            pub fn fast_scan_with(scanner: &mut FastScanner<'_>, tag: Tag) -> Result<Self, FastScanError> {
                Self::from_ordinal(scanner.scan_enum(tag)?).ok_or_else(FastScanError::assert)
            }

            pub fn fast_scan_opt(scanner: &mut FastScanner<'_>) -> Result<Option<Self>, FastScanError> {
                Self::fast_scan_opt_with(scanner, Self::TAG)
            }

            pub fn fast_scan_opt_with(scanner: &mut FastScanner<'_>, tag: Tag) -> Result<Option<Self>, FastScanError> {
                scanner
                    .scan_opt_enum(tag)?
                    .map(|d| Self::from_ordinal(d).ok_or_else(FastScanError::assert))
                    .transpose()
            }

            pub fn format(&self, formatter: &mut Formatter<'_>) -> FormatResult {
                self.format_with(formatter, Self::TAG)
            }

            pub fn format_with(&self, formatter: &mut Formatter<'_>, tag: Tag) -> FormatResult {
                formatter.format_enum(tag, self.ordinal())
            }
        }
    };

    // Impl TTLV (de)serialization for a boolean wrapper.
    (bool $type:ident as $tag:literal) => {
        impl $type {
            pub const TAG: Tag = Tag::new($tag);

            pub fn fast_scan(scanner: &mut FastScanner<'_>) -> Result<Self, FastScanError> {
                Self::fast_scan_with(scanner, Self::TAG)
            }

            pub fn fast_scan_with(scanner: &mut FastScanner<'_>, tag: Tag) -> Result<Self, FastScanError> {
                scanner.scan_bool(tag).map(Self)
            }

            pub fn fast_scan_opt(scanner: &mut FastScanner<'_>) -> Result<Option<Self>, FastScanError> {
                Self::fast_scan_opt_with(scanner, Self::TAG)
            }

            pub fn fast_scan_opt_with(scanner: &mut FastScanner<'_>, tag: Tag) -> Result<Option<Self>, FastScanError> {
                scanner.scan_opt_bool(tag).map(|s| s.map(Self))
            }

            pub fn format(&self, formatter: &mut Formatter<'_>) -> FormatResult {
                self.format_with(formatter, Self::TAG)
            }

            pub fn format_with(&self, formatter: &mut Formatter<'_>, tag: Tag) -> FormatResult {
                formatter.format_bool(tag, self.0)
            }
        }
    };

    // Impl TTLV (de)serialization for a string wrapper.
    (text $type:ident as $tag:literal) => {
        impl $type {
            pub const TAG: Tag = Tag::new($tag);

            pub fn fast_scan(scanner: &mut FastScanner<'_>) -> Result<Self, FastScanError> {
                Self::fast_scan_with(scanner, Self::TAG)
            }

            pub fn fast_scan_with(scanner: &mut FastScanner<'_>, tag: Tag) -> Result<Self, FastScanError> {
                scanner.scan_text(tag).map(|s| Self(s.into()))
            }

            pub fn fast_scan_opt(scanner: &mut FastScanner<'_>) -> Result<Option<Self>, FastScanError> {
                Self::fast_scan_opt_with(scanner, Self::TAG)
            }

            pub fn fast_scan_opt_with(scanner: &mut FastScanner<'_>, tag: Tag) -> Result<Option<Self>, FastScanError> {
                scanner.scan_opt_text(tag).map(|s| s.map(|s| Self(s.into())))
            }

            pub fn format(&self, formatter: &mut Formatter<'_>) -> FormatResult {
                self.format_with(formatter, Self::TAG)
            }

            pub fn format_with(&self, formatter: &mut Formatter<'_>, tag: Tag) -> FormatResult {
                formatter.format_text(tag, &self.0)
            }
        }
    };

    // Impl TTLV (de)serialization for a bytes wrapper.
    (bytes $type:ident as $tag:literal) => {
        impl $type {
            pub const TAG: Tag = Tag::new($tag);

            pub fn fast_scan(scanner: &mut FastScanner<'_>) -> Result<Self, FastScanError> {
                Self::fast_scan_with(scanner, Self::TAG)
            }

            pub fn fast_scan_with(scanner: &mut FastScanner<'_>, tag: Tag) -> Result<Self, FastScanError> {
                scanner.scan_bytes(tag).map(|s| Self(s.into()))
            }

            pub fn fast_scan_opt(scanner: &mut FastScanner<'_>) -> Result<Option<Self>, FastScanError> {
                Self::fast_scan_opt_with(scanner, Self::TAG)
            }

            pub fn fast_scan_opt_with(scanner: &mut FastScanner<'_>, tag: Tag) -> Result<Option<Self>, FastScanError> {
                scanner.scan_opt_bytes(tag).map(|s| s.map(|s| Self(s.into())))
            }

            pub fn format(&self, formatter: &mut Formatter<'_>) -> FormatResult {
                self.format_with(formatter, Self::TAG)
            }

            pub fn format_with(&self, formatter: &mut Formatter<'_>, tag: Tag) -> FormatResult {
                formatter.format_bytes(tag, &self.0)
            }
        }
    };

    // Impl TTLV (de)serialization for an integer wrapper.
    (int $type:ident as $tag:literal) => {
        impl $type {
            pub const TAG: Tag = Tag::new($tag);

            pub fn fast_scan(scanner: &mut FastScanner<'_>) -> Result<Self, FastScanError> {
                Self::fast_scan_with(scanner, Self::TAG)
            }

            pub fn fast_scan_with(scanner: &mut FastScanner<'_>, tag: Tag) -> Result<Self, FastScanError> {
                scanner.scan_int(tag).map(Self)
            }

            pub fn fast_scan_opt(scanner: &mut FastScanner<'_>) -> Result<Option<Self>, FastScanError> {
                Self::fast_scan_opt_with(scanner, Self::TAG)
            }

            pub fn fast_scan_opt_with(scanner: &mut FastScanner<'_>, tag: Tag) -> Result<Option<Self>, FastScanError> {
                scanner.scan_opt_int(tag).map(|s| s.map(Self))
            }

            pub fn format(&self, formatter: &mut Formatter<'_>) -> FormatResult {
                self.format_with(formatter, Self::TAG)
            }

            pub fn format_with(&self, formatter: &mut Formatter<'_>, tag: Tag) -> FormatResult {
                formatter.format_int(tag, self.0)
            }
        }
    };

    // Impl TTLV (de)serialization for a date-time wrapper.
    (date_time $type:ident as $tag:literal) => {
        impl $type {
            pub const TAG: Tag = Tag::new($tag);

            pub fn fast_scan(scanner: &mut FastScanner<'_>) -> Result<Self, FastScanError> {
                Self::fast_scan_with(scanner, Self::TAG)
            }

            pub fn fast_scan_with(scanner: &mut FastScanner<'_>, tag: Tag) -> Result<Self, FastScanError> {
                scanner.scan_date_time(tag).map(|s| Self(s as u64))
            }

            pub fn fast_scan_opt(scanner: &mut FastScanner<'_>) -> Result<Option<Self>, FastScanError> {
                Self::fast_scan_opt_with(scanner, Self::TAG)
            }

            pub fn fast_scan_opt_with(scanner: &mut FastScanner<'_>, tag: Tag) -> Result<Option<Self>, FastScanError> {
                scanner.scan_opt_date_time(tag).map(|s| s.map(|s| Self(s as u64)))
            }

            pub fn format(&self, formatter: &mut Formatter<'_>) -> FormatResult {
                self.format_with(formatter, Self::TAG)
            }

            pub fn format_with(&self, formatter: &mut Formatter<'_>, tag: Tag) -> FormatResult {
                formatter.format_date_time(tag, self.0 as i64)
            }
        }
    };
}
use impl_ttlv_serde;
