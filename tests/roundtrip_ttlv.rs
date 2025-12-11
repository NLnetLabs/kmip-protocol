//! A round-tripping test for the low-level scanner and formatter.
//!
//! This test verifies that the scanner and formatter are functional inverses
//! of each other, by generating random TTLV objects and converting them to
//! and from the TTLV format.  It does not test the scanner against invalid
//! inputs.

use kmip_protocol::ttlv::{
    fast_scan::{FastScanError, FastScanner},
    format::{FormatDone, FormatResult, Formatter},
    types::{Tag, Type},
};

use proptest::prelude::*;

/// A dynamic TTLV field.
#[derive(Debug)]
pub struct Field {
    /// The field tag.
    pub tag: Tag,

    /// Whether the field is required.
    pub required: bool,

    /// Whether the field is ignored.
    pub ignored: bool,

    /// The data of the field.
    pub data: FieldData,
}

/// The data for a [`Field`].
#[derive(Debug)]
pub enum FieldData {
    /// A missing object.
    Missing(Type),

    /// A structure.
    Structure(Box<[Field]>),

    /// An integer.
    Integer(i32),

    /// A long integer.
    LongInteger(i64),

    /// A big integer.
    BigInteger(Box<[u8]>),

    /// An enumeration.
    Enumeration(u32),

    /// A boolean.
    Boolean(bool),

    /// A text string.
    TextString(Box<str>),

    /// A byte string.
    ByteString(Box<[u8]>),

    /// A date-time.
    DateTime(i64),

    /// An interval.
    Interval(u32),
}

impl FieldData {
    /// The type of this field.
    const fn r#type(&self) -> Type {
        match *self {
            FieldData::Missing(t) => t,
            FieldData::Structure(_) => Type::Structure,
            FieldData::Integer(_) => Type::Integer,
            FieldData::LongInteger(_) => Type::LongInteger,
            FieldData::BigInteger(_) => Type::BigInteger,
            FieldData::Enumeration(_) => Type::Enumeration,
            FieldData::Boolean(_) => Type::Boolean,
            FieldData::TextString(_) => Type::TextString,
            FieldData::ByteString(_) => Type::ByteString,
            FieldData::DateTime(_) => Type::DateTime,
            FieldData::Interval(_) => Type::Interval,
        }
    }
}

impl Field {
    /// The size of this field when formatted, in blocks.
    fn formatted_size(&self) -> usize {
        match self.data {
            FieldData::Missing(_) => 0,
            FieldData::Structure(ref fields) => 1 + fields.iter().map(|f| f.formatted_size()).sum::<usize>(),
            FieldData::Integer(_) => 2,
            FieldData::LongInteger(_) => 2,
            FieldData::BigInteger(ref v) => 1 + v.len().div_ceil(8),
            FieldData::Enumeration(_) => 2,
            FieldData::Boolean(_) => 2,
            FieldData::TextString(ref v) => 1 + v.len().div_ceil(8),
            FieldData::ByteString(ref v) => 1 + v.len().div_ceil(8),
            FieldData::DateTime(_) => 2,
            FieldData::Interval(_) => 2,
        }
    }

    /// Format this field.
    fn format(&self, formatter: &mut Formatter<'_>) -> FormatResult {
        match self.data {
            FieldData::Missing(_) => Ok(FormatDone::assert()),
            FieldData::Structure(ref fields) => {
                let mut f = formatter.format_struct(self.tag)?;
                for field in fields {
                    field.format(&mut f)?;
                }
                Ok(f.finish())
            }
            FieldData::Integer(v) => formatter.format_int(self.tag, v),
            FieldData::LongInteger(v) => formatter.format_long_int(self.tag, v),
            FieldData::BigInteger(ref v) => formatter.format_big_int(self.tag, v),
            FieldData::Enumeration(v) => formatter.format_enum(self.tag, v),
            FieldData::Boolean(v) => formatter.format_bool(self.tag, v),
            FieldData::TextString(ref v) => formatter.format_text(self.tag, v),
            FieldData::ByteString(ref v) => formatter.format_bytes(self.tag, v),
            FieldData::DateTime(v) => formatter.format_date_time(self.tag, v),
            FieldData::Interval(v) => formatter.format_interval(self.tag, v),
        }
    }

    /// Scan this field.
    fn fast_scan(&self, scanner: &mut FastScanner<'_>) -> Result<(), FastScanError> {
        if self.ignored {
            if self.required {
                match self.data.r#type() {
                    Type::Structure => scanner.skip_struct(self.tag)?,
                    Type::Integer => scanner.skip_int(self.tag)?,
                    Type::LongInteger => scanner.skip_long_int(self.tag)?,
                    Type::BigInteger => scanner.skip_big_int(self.tag)?,
                    Type::Enumeration => scanner.skip_enum(self.tag)?,
                    Type::Boolean => scanner.skip_bool(self.tag)?,
                    Type::TextString => scanner.skip_text(self.tag)?,
                    Type::ByteString => scanner.skip_bytes(self.tag)?,
                    Type::DateTime => scanner.skip_date_time(self.tag)?,
                    Type::Interval => scanner.skip_interval(self.tag)?,
                }
                Ok(())
            } else {
                let found = match self.data.r#type() {
                    Type::Structure => scanner.skip_opt_struct(self.tag)?,
                    Type::Integer => scanner.skip_opt_int(self.tag)?,
                    Type::LongInteger => scanner.skip_opt_long_int(self.tag)?,
                    Type::BigInteger => scanner.skip_opt_big_int(self.tag)?,
                    Type::Enumeration => scanner.skip_opt_enum(self.tag)?,
                    Type::Boolean => scanner.skip_opt_bool(self.tag)?,
                    Type::TextString => scanner.skip_opt_text(self.tag)?,
                    Type::ByteString => scanner.skip_opt_bytes(self.tag)?,
                    Type::DateTime => scanner.skip_opt_date_time(self.tag)?,
                    Type::Interval => scanner.skip_opt_interval(self.tag)?,
                };

                if found == matches!(self.data, FieldData::Missing(_)) {
                    return Err(FastScanError::assert());
                }
                Ok(())
            }
        } else if self.required {
            match self.data {
                FieldData::Missing(_) => unreachable!(),
                FieldData::Structure(ref fields) => {
                    let mut s = scanner.scan_struct(self.tag)?;
                    for field in fields {
                        field.fast_scan(&mut s)?;
                    }
                    s.finish()?;
                }
                FieldData::Integer(v) => {
                    if scanner.scan_int(self.tag)? != v {
                        return Err(FastScanError::assert());
                    }
                }
                FieldData::LongInteger(v) => {
                    if scanner.scan_long_int(self.tag)? != v {
                        return Err(FastScanError::assert());
                    }
                }
                FieldData::BigInteger(ref v) => {
                    let p = scanner.scan_big_int(self.tag)?;
                    if strip_sign_ext(p) != strip_sign_ext(v) {
                        return Err(FastScanError::assert());
                    }
                }
                FieldData::Enumeration(v) => {
                    if scanner.scan_enum(self.tag)? != v {
                        return Err(FastScanError::assert());
                    }
                }
                FieldData::Boolean(v) => {
                    if scanner.scan_bool(self.tag)? != v {
                        return Err(FastScanError::assert());
                    }
                }
                FieldData::TextString(ref v) => {
                    if scanner.scan_text(self.tag)? != &**v {
                        return Err(FastScanError::assert());
                    }
                }
                FieldData::ByteString(ref v) => {
                    if scanner.scan_bytes(self.tag)? != &**v {
                        return Err(FastScanError::assert());
                    }
                }
                FieldData::DateTime(v) => {
                    if scanner.scan_date_time(self.tag)? != v {
                        return Err(FastScanError::assert());
                    }
                }
                FieldData::Interval(v) => {
                    if scanner.scan_interval(self.tag)? != v {
                        return Err(FastScanError::assert());
                    }
                }
            }
            Ok(())
        } else {
            match self.data {
                FieldData::Missing(Type::Structure) => {
                    if scanner.scan_opt_struct(self.tag)?.is_some() {
                        return Err(FastScanError::assert());
                    }
                }
                FieldData::Missing(Type::Integer) => {
                    if scanner.scan_opt_int(self.tag)?.is_some() {
                        return Err(FastScanError::assert());
                    }
                }
                FieldData::Missing(Type::LongInteger) => {
                    if scanner.scan_opt_long_int(self.tag)?.is_some() {
                        return Err(FastScanError::assert());
                    }
                }
                FieldData::Missing(Type::BigInteger) => {
                    if scanner.scan_opt_big_int(self.tag)?.is_some() {
                        return Err(FastScanError::assert());
                    }
                }
                FieldData::Missing(Type::Enumeration) => {
                    if scanner.scan_opt_enum(self.tag)?.is_some() {
                        return Err(FastScanError::assert());
                    }
                }
                FieldData::Missing(Type::Boolean) => {
                    if scanner.scan_opt_bool(self.tag)?.is_some() {
                        return Err(FastScanError::assert());
                    }
                }
                FieldData::Missing(Type::TextString) => {
                    if scanner.scan_opt_text(self.tag)?.is_some() {
                        return Err(FastScanError::assert());
                    }
                }
                FieldData::Missing(Type::ByteString) => {
                    if scanner.scan_opt_bytes(self.tag)?.is_some() {
                        return Err(FastScanError::assert());
                    }
                }
                FieldData::Missing(Type::DateTime) => {
                    if scanner.scan_opt_date_time(self.tag)?.is_some() {
                        return Err(FastScanError::assert());
                    }
                }
                FieldData::Missing(Type::Interval) => {
                    if scanner.scan_opt_interval(self.tag)?.is_some() {
                        return Err(FastScanError::assert());
                    }
                }

                FieldData::Structure(ref fields) => {
                    let mut s = scanner.scan_opt_struct(self.tag)?.ok_or(FastScanError::assert())?;
                    for field in fields {
                        field.fast_scan(&mut s)?;
                    }
                    s.finish()?;
                }
                FieldData::Integer(v) => {
                    if scanner.scan_opt_int(self.tag)? != Some(v) {
                        return Err(FastScanError::assert());
                    }
                }
                FieldData::LongInteger(v) => {
                    if scanner.scan_opt_long_int(self.tag)? != Some(v) {
                        return Err(FastScanError::assert());
                    }
                }
                FieldData::BigInteger(ref v) => {
                    let p = scanner.scan_opt_big_int(self.tag)?;
                    if p.map(strip_sign_ext) != Some(strip_sign_ext(v)) {
                        return Err(FastScanError::assert());
                    }
                }
                FieldData::Enumeration(v) => {
                    if scanner.scan_opt_enum(self.tag)? != Some(v) {
                        return Err(FastScanError::assert());
                    }
                }
                FieldData::Boolean(v) => {
                    if scanner.scan_opt_bool(self.tag)? != Some(v) {
                        return Err(FastScanError::assert());
                    }
                }
                FieldData::TextString(ref v) => {
                    if scanner.scan_opt_text(self.tag)? != Some(v) {
                        return Err(FastScanError::assert());
                    }
                }
                FieldData::ByteString(ref v) => {
                    if scanner.scan_opt_bytes(self.tag)? != Some(v) {
                        return Err(FastScanError::assert());
                    }
                }
                FieldData::DateTime(v) => {
                    if scanner.scan_opt_date_time(self.tag)? != Some(v) {
                        return Err(FastScanError::assert());
                    }
                }
                FieldData::Interval(v) => {
                    if scanner.scan_opt_interval(self.tag)? != Some(v) {
                        return Err(FastScanError::assert());
                    }
                }
            }
            Ok(())
        }
    }
}

/// Strip leading sign-extension bytes from a big integer.
fn strip_sign_ext(int: &[u8]) -> &[u8] {
    if let [ext @ (0x00 | 0xFF), ..] = int {
        let len = int.iter().position(|x| x != ext).unwrap_or(int.len());
        &int[len..]
    } else {
        int
    }
}

fn arb_field() -> impl Strategy<Value = Field> {
    fn field(data: impl Strategy<Value = FieldData>) -> impl Strategy<Value = Field> {
        (any::<Tag>(), prop::bool::weighted(0.8), prop::bool::weighted(0.1), data).prop_map(
            |(tag, required, ignored, data)| Field {
                tag,
                required: !matches!(data, FieldData::Missing(_)) && required,
                ignored,
                data,
            },
        )
    }

    let leaf_data = prop_oneof![
        any::<Type>().prop_map(FieldData::Missing),
        any::<i32>().prop_map(FieldData::Integer),
        any::<i64>().prop_map(FieldData::LongInteger),
        any::<Box<[u8]>>().prop_map(FieldData::BigInteger),
        any::<u32>().prop_map(FieldData::Enumeration),
        any::<bool>().prop_map(FieldData::Boolean),
        any::<Box<str>>().prop_map(FieldData::TextString),
        any::<Box<[u8]>>().prop_map(FieldData::ByteString),
        any::<i64>().prop_map(FieldData::DateTime),
        any::<u32>().prop_map(FieldData::Interval),
    ];

    // These parameters bound recursive generation.  They are quite arbitrary,
    // but should be large enough to cover any kind of error we expect.  Making
    // them too large would hurt testing speed.
    field(leaf_data.prop_recursive(3, 27, 3, |inner| {
        prop::collection::vec(field(inner), 0..10).prop_map(|fields| FieldData::Structure(fields.into_boxed_slice()))
    }))
}

proptest! {
    #[test]
    fn roundtrip(field in arb_field()) {
        // Format the field.
        let formatted_size = field.formatted_size() * 8;
        let mut buffer = Box::<[u8]>::new_uninit_slice(formatted_size);
        let mut formatter = Formatter::new(&mut buffer);
        field.format(&mut formatter)?;
        prop_assert!(formatter.remaining().is_empty());
        let buffer = formatter.filled().as_flattened();

        // Scan the field.
        let mut scanner = FastScanner::new(buffer)?;
        field.fast_scan(&mut scanner)?;
        scanner.finish()?;
    }
}

#[test]
#[ignore = "must find a way to disallow ambiguous schemas"]
fn ambiguous_schema() {
    let field = Field {
        tag: Tag::new(0),
        required: true,
        ignored: false,
        data: FieldData::Structure(Box::new([
            Field {
                tag: Tag::new(0),
                required: false,
                ignored: false,
                data: FieldData::Missing(Type::Integer),
            },
            Field {
                tag: Tag::new(0),
                required: true,
                ignored: false,
                data: FieldData::Integer(2),
            },
        ])),
    };

    // Format the field.
    let formatted_size = field.formatted_size() * 8;
    let mut buffer = Box::<[u8]>::new_uninit_slice(formatted_size);
    let mut formatter = Formatter::new(&mut buffer);
    assert!(field.format(&mut formatter).is_ok());
    assert!(formatter.remaining().is_empty());
    let buffer = formatter.filled().as_flattened();

    // Scan the field.
    let scanner = FastScanner::new(buffer);
    assert!(scanner.is_ok());
    let mut scanner = scanner.unwrap();
    assert!(field.fast_scan(&mut scanner).is_ok());
    assert!(scanner.finish().is_ok());
}
