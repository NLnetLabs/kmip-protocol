//! Useful functionality separate but related to (de)serialization.
use std::collections::HashMap;

use enum_ordinalize::Ordinalize;
use kmip_protocol::ttlv::{FastScanError, FastScanner, Tag, TagType, Type};

/// Facilities for pretty printing TTLV bytes to text format.
#[derive(Clone, Debug, Default)]
pub struct PrettyPrinter {
    tag_prefix: String,
    tag_map: HashMap<Tag, &'static str>,
    enum_map: HashMap<(Tag, u32), &'static str>,
}

impl PrettyPrinter {
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the pretty printer's tag prefix.
    ///
    /// This can be used both to strip common tag prefixes from the output produced by [PrettyPrinter::to_diag_string()]
    /// to make it shorter, and to restore them when using [PrettyPrinter::from_diag_string()].
    pub fn with_tag_prefix(mut self, tag_prefix: String) -> Self {
        self.tag_prefix = tag_prefix;
        self
    }

    /// Set the pretty printer's tag map.
    ///
    /// The tag map is used to render a meaningful name for hexadecimal tag identifiers in pretty printed output by
    /// looking up the human friendly name associated with the tag in the given map.
    pub fn with_tag_map(mut self, tag_map: HashMap<Tag, &'static str>) -> Self {
        self.tag_map = tag_map;
        self
    }

    /// Set the pretty printer's enum map.
    ///
    /// The enum map is used to render a meaningful name for numeric enum values in pretty printed output by
    /// looking up the human friendly name associated with the enum for the current tag in the given map.
    pub fn with_enum_map(mut self, enum_map: HashMap<(Tag, u32), &'static str>) -> Self {
        self.enum_map = enum_map;
        self
    }

    /// Interpret the given byte slice as TTLV as much as possible and render it to a String in human readable form.
    ///
    /// An example string for a successful KMIP 1.0 create symmetric key response could look like this:
    ///
    /// ```text
    /// Tag: 0x42007B, Type: Structure (0x01), Data:
    ///   Tag: 0x42007A, Type: Structure (0x01), Data:
    ///     Tag: 0x420069, Type: Structure (0x01), Data:
    ///       Tag: 0x42006A, Type: Integer (0x02), Data: 0x000001 (1)
    ///       Tag: 0x42006B, Type: Integer (0x02), Data: 0x000000 (0)
    ///     Tag: 0x420092, Type: DateTime (0x09), Data: 0x4AFBE7C2
    ///     Tag: 0x42000D, Type: Integer (0x02), Data: 0x000001 (1)
    ///   Tag: 0x42000F, Type: Structure (0x01), Data:
    ///     Tag: 0x42005C, Type: Enumeration (0x05), Data: 0x000001 (1)
    ///     Tag: 0x42007F, Type: Enumeration (0x05), Data: 0x000000 (0)
    ///     Tag: 0x42007C, Type: Structure (0x01), Data:
    ///       Tag: 0x420057, Type: Enumeration (0x05), Data: 0x000002 (2)
    ///       Tag: 0x420094, Type: TextString (0x07), Data: fc8833de-70d2-4ece-b063-fede3a3c59fe
    /// ```
    ///
    /// If configured using [PrettyPrinter::with_tag_map()] the hexadecimal tag identifiers will be prefixed by their
    /// mapped human readable name.
    ///
    /// For a more compact form that omits sensitive details see [PrettyPrinter::to_diag_string()].
    pub fn to_string(&self, bytes: &[u8]) -> String {
        let available = bytes.len() - bytes.len() % 8;
        let scanner = FastScanner::new(&bytes[..available]).unwrap();
        self.scanner_to_string(scanner, 0)
    }

    pub fn scanner_to_string(&self, mut scanner: FastScanner, mut indent: usize) -> String {
        const EMPTY_STRING: String = String::new();

        // Expect the start of a structure.
        if scanner.is_empty() {
            return EMPTY_STRING;
        }

        let first_ttl = scanner.remaining()[0];
        let tt = TagType::parse(first_ttl[0..4].try_into().unwrap());

        if tt.r#type() != Type::Structure {
            return format!(
                "Error: Expected a TTLV structure but found tag {} type {}",
                tt.tag(),
                tt.r#type()
            );
        }

        let Ok(scanner) = scanner.scan_struct(tt.tag()) else {
            return format!("Error: Invalid structure format for tag {}", tt.tag());
        };

        let is_attribute = tt.tag().value() == 0x420008;
        let mut report = self.tag_with_data_to_string(tt, "", indent);

        indent += 2;

        // Process each element in this struct. Recurse on any sub-structs
        // encountered.
        let mut rest = scanner.remaining().as_flattened();
        let mut attr_name = is_attribute.then_some(String::new());
        while let Some((scanner, next_rest)) = FastScanner::next_element(rest) {
            let first_ttl = scanner.remaining()[0];
            let tt = TagType::parse(first_ttl[0..4].try_into().unwrap());

            if tt.r#type() == Type::Structure {
                report += &self.scanner_to_string(scanner, indent);
            } else {
                let Ok(fragment) = self.element_to_string(tt, scanner, indent, &mut attr_name) else {
                    return report + &format!("Invalid TTLV bytes at tag {} of type {}", tt.tag(), tt.r#type());
                };
                report += &fragment;
            }

            rest = next_rest;
        }

        report
    }

    fn element_to_string(
        &self,
        tt: TagType,
        mut scanner: FastScanner,
        indent: usize,
        attr_name: &mut Option<String>,
    ) -> Result<String, FastScanError> {
        // Special cases:
        //
        // Handle data structures such as:
        //     Tag: Attribute (0x420008), Type: Structure (0x01), Data:
        //       Tag: Attribute Name (0x42000A), Type: TextString (0x07), Data: "Cryptographic Algorithm"
        //       Tag: Attribute Value (0x42000B), Type: Enumeration (0x05), Data: 0x000004 (4 = RSA)
        //
        // Where we need to know that we are in an attribute structure, and
        // that the Attribute Name determines which text string we map the
        // enumeration value to.
        //
        // Also handle data structures such as:
        //     Tag: Attribute (0x420008), Type: Structure (0x01), Data:
        //       Tag: Attribute Name (0x42000A), Type: TextString (0x07), Data: "Cryptographic Usage Mask"
        //       Tag: Attribute Value (0x42000B), Type: Integer (0x02), Data: 0x000001 (1 = Sign)
        //
        // Where we need to know that we are in an attribute structure, and
        // that the Attribute Name determines that we must treat the value as
        // a bit mask consisting of potentially many different bit matches and
        // their mapped string names.
        #[rustfmt::skip]
            let data = match tt.r#type() {
                Type::Structure   => { unreachable!() }
                Type::Integer     => {
                    let data = scanner.scan_int(tt.tag())?;
                    let mut is_mask = false;
                    let enum_tag = match attr_name.as_mut().map(|v| v.as_str()) {
                        Some("Cryptographic Usage Mask") => { is_mask = true; Tag::new(0x42002C) },
                        _ => tt.tag(),
                    };
                    if is_mask {
                        let mut values: Vec<&'static str> = vec![];
                        for n in Self::bit_mask_values() {
                            let data = data as u32;
                            if data & n != 0 {
                                values.push(self.enum_map.get(&(enum_tag, n)).unwrap_or(&"??"));
                            }
                        }
                        format!(" {:#08X} ({} = {})", data, data, values.join("|"))
                    } else {
                    format!(" {data:#08X} ({data})")
                    }
                }
                Type::LongInteger => { format!(" {data:#08X} ({data})", data = scanner.scan_long_int(tt.tag())?) }
                Type::BigInteger  => { format!(" {data}", data = hex::encode_upper(scanner.scan_big_int(tt.tag())?)) }
                Type::Enumeration => {
                    let data = scanner.scan_enum(tt.tag())?;
                    let enum_tag = match attr_name.as_mut().map(|v| v.as_str()) {
                        Some("Cryptographic Algorithm") => Tag::new(0x420028),
                        Some("Key Format Type") => Tag::new(0x420042),
                        Some("Name Type") => Tag::new(0x420054),
                        Some("Object Type") => Tag::new(0x420042),
                        _ => tt.tag(),
                    };
                    format!(" {:#08X} ({} = {})", data, data, self.enum_map.get(&(enum_tag, data)).unwrap_or(&"??"))
                }
                Type::Boolean     => { format!(" {data}", data = scanner.scan_bool(tt.tag())?) }
                Type::TextString  => { let data = scanner.scan_text(tt.tag())?;
                    if let Some(attr_name) = attr_name {
                        *attr_name = data.to_string();
                    }
                    format!(" \"{}\"", data)
                }
                Type::ByteString  => { format!(" {data}", data = hex::encode_upper(scanner.scan_bytes(tt.tag())?)) }
                Type::DateTime    => { format!(" {data:#08X}", data = scanner.scan_date_time(tt.tag())?) }
                Type::Interval => todo!(),
            };

        Ok(self.tag_with_data_to_string(tt, &data, indent))
    }

    fn tag_with_data_to_string(&self, tt: TagType, data: &str, indent: usize) -> String {
        if let Some(tag_name) = self.tag_map.get(&tt.tag()) {
            format!(
                "{:>indent$}Tag: {} ({:#08X}), Type: {} ({:#04X}), Data:{data}\n",
                "",
                tag_name,
                tt.tag().value(),
                tt.r#type(),
                tt.r#type().ordinal(),
            )
        } else {
            format!(
                "{:>indent$}Tag: {:#08X}, Type: {} ({:#04X}), Data:{data}\n",
                "",
                tt.tag().value(),
                tt.r#type(),
                tt.r#type().ordinal(),
            )
        }
    }

    fn bit_mask_values() -> impl std::iter::Iterator<Item = u32> {
        let mut n = 0u32;
        std::iter::from_fn(move || {
            if n == 0 {
                n = 1;
            } else if n == 0x80000000 {
                return None;
            }
            let ret_val = Some(n);
            n <<= 1;
            ret_val
        })
    }
}
