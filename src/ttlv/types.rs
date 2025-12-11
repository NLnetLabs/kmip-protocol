use core::fmt;

//----------- Tag ------------------------------------------------------------

/// A TTLV tag.
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Tag(u32);

impl Tag {
    /// Construct a new [`Tag`].
    ///
    /// ## Panics
    ///
    /// Panics if the value does not fit within 24 bits.
    pub const fn new(value: u32) -> Self {
        assert!(value < (1u32 << 24));
        Self(value << 8)
    }

    /// The value of this tag.
    pub const fn value(self) -> u32 {
        self.0 >> 8
    }

    /// The wire-format bytes of this tag.
    pub const fn bytes(self) -> [u8; 3] {
        let [a, b, c, _] = self.0.to_be_bytes();
        [a, b, c]
    }

    /// Attach a type to this tag.
    pub const fn with_type(self, r#type: Type) -> TagType {
        TagType::new(self, r#type)
    }
}

impl From<TagType> for Tag {
    fn from(value: TagType) -> Self {
        value.tag()
    }
}

impl fmt::Display for Tag {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "0x{:06X}", self.value())
    }
}

impl fmt::Debug for Tag {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Tag(0x{:06X})", self.value())
    }
}

//----------- Type -----------------------------------------------------------

/// A TTLV type.
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u8)]
pub enum Type {
    /// A TTLV structure.
    ///
    /// This corresponds to a user-defined [`struct`].
    Structure = 0x01,

    /// A TTLV integer.
    ///
    /// This corresponds to [`i32`].
    Integer = 0x02,

    /// A TTLV long integer.
    ///
    /// This corresponds to [`i64`].
    LongInteger = 0x03,

    /// A TTLV big integer.
    ///
    /// This is a variable-length signed integer type.
    BigInteger = 0x04,

    /// A TTLV enumeration.
    ///
    /// This corresponds to [`u32`], but in practice it may be represented by
    /// a user-defined [`enum`].
    Enumeration = 0x05,

    /// A TTLV boolean.
    ///
    /// This corresponds to [`bool`].
    Boolean = 0x06,

    /// A TTLV text string.
    ///
    /// This corresponds to [`str`].
    TextString = 0x07,

    /// A TTLV byte string.
    ///
    /// This corresponds to `[u8]` -- a slice of bytes.
    ByteString = 0x08,

    /// A TTLV date-time.
    ///
    /// This is a 64-bit signed UNIX time value, in units of seconds.
    DateTime = 0x09,

    /// A TTLV interval.
    ///
    /// This corresponds to [`Duration`], but has a limited range and a
    /// granularity of seconds.
    ///
    /// [`Duration`]: std::time::Duration
    Interval = 0x0A,
}

impl From<TagType> for Type {
    fn from(value: TagType) -> Self {
        value.r#type()
    }
}

impl fmt::Display for Type {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Type::Structure => "Structure",
            Type::Integer => "Integer",
            Type::LongInteger => "LongInteger",
            Type::BigInteger => "BigInteger",
            Type::Enumeration => "Enumeration",
            Type::Boolean => "Boolean",
            Type::TextString => "TextString",
            Type::ByteString => "ByteString",
            Type::DateTime => "DateTime",
            Type::Interval => "Interval",
        })
    }
}

impl fmt::Debug for Type {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

//----------- TagType --------------------------------------------------------

/// A TTLV tag-type pair.
#[derive(Copy, Clone, PartialEq, Eq, Hash)]
pub struct TagType(u32);

impl TagType {
    /// Construct a new [`TagType`].
    pub const fn new(tag: Tag, r#type: Type) -> Self {
        Self(tag.0 | r#type as u32)
    }

    /// Split this into a tag-type tuple.
    pub const fn split(self) -> (Tag, Type) {
        (self.tag(), self.r#type())
    }

    /// The contained tag.
    pub const fn tag(self) -> Tag {
        Tag(self.0 & 0xFFFFFF00)
    }

    /// The contained type.
    pub const fn r#type(self) -> Type {
        // SAFETY: 'self.0' always contains a valid tag and type.
        unsafe { core::mem::transmute(self.0 as u8) }
    }

    /// The value of this pair as a native-endian integer.
    pub const fn value(self) -> u32 {
        self.0
    }

    /// The wire-format bytes of this tag-type pair.
    pub const fn bytes(self) -> [u8; 4] {
        self.0.to_be_bytes()
    }

    /// Parse a tag-type pair from bytes.
    pub const fn parse(bytes: [u8; 4]) -> Self {
        Self(u32::from_be_bytes(bytes))
    }
}

impl From<(Tag, Type)> for TagType {
    fn from((tag, r#type): (Tag, Type)) -> Self {
        Self::new(tag, r#type)
    }
}

impl From<TagType> for (Tag, Type) {
    fn from(value: TagType) -> Self {
        value.split()
    }
}

impl fmt::Display for TagType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {}", self.r#type(), self.tag())
    }
}

impl fmt::Debug for TagType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "TagType({:?}, {:?})", self.tag(), self.r#type())
    }
}

//============ Property-based Testing ========================================

#[cfg(feature = "proptest")]
mod proptest {
    use std::ops::Range;

    use proptest::prelude::*;

    use super::{Tag, Type};

    impl Arbitrary for Tag {
        type Parameters = ();
        type Strategy = prop::strategy::Map<Range<u32>, fn(u32) -> Tag>;

        fn arbitrary_with((): Self::Parameters) -> Self::Strategy {
            (0..1 << 24).prop_map(Tag::new)
        }
    }

    impl Arbitrary for Type {
        type Parameters = ();
        type Strategy = prop::strategy::Map<Range<u8>, fn(u8) -> Type>;

        fn arbitrary_with((): Self::Parameters) -> Self::Strategy {
            (0x01..0x0B).prop_map(|x| unsafe { core::mem::transmute(x) })
        }
    }
}
