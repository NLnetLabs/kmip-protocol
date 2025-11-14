use std::{
    convert::TryFrom,
    io::{self, Cursor},
};

use enum_ordinalize::Ordinalize;

use kmip_ttlv::types::{
    SerializableTtlvType, TtlvEnumeration, TtlvInteger, TtlvLength, TtlvTag, TtlvTextString, TtlvType,
};

use crate::types::{
    common::{AttributeIndex, AttributeName, AttributeValue, NameValue, Operation},
    request::{
        Attribute, BatchCount, BatchItem, CommonTemplateAttribute, MaximumResponseSize, Name,
        PrivateKeyTemplateAttribute, ProtocolVersion, ProtocolVersionMajor, ProtocolVersionMinor,
        PublicKeyTemplateAttribute, RequestHeader, RequestMessage, RequestPayload,
    },
};

//============ KMIP request parsing functions ================================

pub fn parse(data: &[u8]) -> Result<Option<RequestMessage>, ExtendedTtlvError> {
    let mut cursor = io::Cursor::new(data);
    enter_optional_tag(&mut cursor, 0x420078, TtlvType::Structure, request_message, ())
}

// https://docs.oasis-open.org/kmip/spec/v1.2/os/kmip-spec-v1.2-os.html#_Toc409613588
// 7 Message Contents
// 7.1 Message Structure
//   Request Message
//     Request Header
//     Batch Item
fn request_message(
    input: &mut Cursor<&[u8]>,
    _tag: i32,
    _tag_type: TtlvType,
    _context: (),
) -> Result<RequestMessage, ExtendedTtlvError> {
    let len = TtlvLength::read(input)?;
    if *len > 1024 {
        return Err(io::Error::from(io::ErrorKind::FileTooLarge).into());
    }
    let header = enter_tag(input, 0x420077, TtlvType::Structure, request_header, ())?;
    let num_batch_items = header.batch_count().0 as usize;
    let mut batch_items = Vec::with_capacity(num_batch_items);
    for _ in 0..num_batch_items {
        batch_items.push(enter_tag(input, 0x42000F, TtlvType::Structure, batch_item, ())?);
    }
    Ok(RequestMessage(header, batch_items))
}

// https://docs.oasis-open.org/kmip/spec/v1.2/os/kmip-spec-v1.2-os.html#_Toc409613590
// 7.2 Operations
//   Request Header
//     Field                            Required             Tag
//     --------------------------------------------------------------
//     Protocol Version                 Yes                  0x420069
//     Maximum Response Size            No                   0x420050
//     Asynchronous Indicator           No                   0x420007
//     Attestation Capable Indicator    No                   0x4200D3
//     Attestation Type                 No, MAY be repeated  0x4200C7
//     Authentication                   No                   0x42000C
//     Batch Error Continuation Option  No                   0x42000E
//     Batch Order Option               No                   0x420010
//     Time Stamp                       No                   0x420092
//     Batch Count                      Yes                  0x42000D
//
// Tags can be found here: https://docs.oasis-open.org/kmip/spec/v1.2/os/kmip-spec-v1.2-os.html#_Toc409613596
fn request_header(
    input: &mut Cursor<&[u8]>,
    _tag: i32,
    _tag_type: TtlvType,
    _context: (),
) -> Result<RequestHeader, ExtendedTtlvError> {
    let _ = TtlvLength::read(input)?;
    let protocol_version = enter_tag(input, 0x420069, TtlvType::Structure, protocol_version, ())?;
    let max_response_size = enter_optional_tag(input, 0x420050, TtlvType::Integer, max_response_size, ())?;
    let _ = enter_optional_tag(input, 0x420007, TtlvType::Structure, unsupported_tag, ())?;
    let _ = enter_optional_tag(input, 0x420003, TtlvType::Structure, unsupported_tag, ())?;
    while enter_optional_tag(input, 0x4200C7, TtlvType::Structure, unsupported_tag, ())?.is_some() {}
    let authentication = enter_optional_tag(input, 0x42000C, TtlvType::Structure, unsupported_typed_tag, ())?;
    let _ = enter_optional_tag(input, 0x42000E, TtlvType::Structure, unsupported_tag, ())?;
    let _ = enter_optional_tag(input, 0x420010, TtlvType::Structure, unsupported_tag, ())?;
    let _ = enter_optional_tag(input, 0x420092, TtlvType::Structure, unsupported_tag, ())?;
    let batch_count = enter_tag(input, 0x42000D, TtlvType::Integer, batch_count, ())?;
    Ok(RequestHeader(
        protocol_version,
        max_response_size,
        authentication,
        batch_count,
    ))
}

fn protocol_version(
    input: &mut Cursor<&[u8]>,
    _tag: i32,
    _tag_type: TtlvType,
    _context: (),
) -> Result<ProtocolVersion, ExtendedTtlvError> {
    let _ = TtlvLength::read(input)?;
    let major = protocol_version_major(input)?;
    let minor = protocol_version_minor(input)?;
    Ok(ProtocolVersion(major, minor))
}

fn protocol_version_minor(input: &mut Cursor<&[u8]>) -> Result<ProtocolVersionMinor, ExtendedTtlvError> {
    let val: TtlvInteger = expect_ttlv(input, 0x42006B, TtlvType::Integer)?;
    Ok(ProtocolVersionMinor(val.0))
}

fn protocol_version_major(input: &mut Cursor<&[u8]>) -> Result<ProtocolVersionMajor, ExtendedTtlvError> {
    let val: TtlvInteger = expect_ttlv(input, 0x42006A, TtlvType::Integer)?;
    Ok(ProtocolVersionMajor(val.0))
}

fn max_response_size(
    mut input: &mut Cursor<&[u8]>,
    _tag: i32,
    _tag_type: TtlvType,
    _context: (),
) -> Result<MaximumResponseSize, ExtendedTtlvError> {
    let val = TtlvInteger::read(&mut input)?;
    Ok(MaximumResponseSize(*val))
}

fn batch_count(
    input: &mut Cursor<&[u8]>,
    _tag: i32,
    _tag_type: TtlvType,
    _context: (),
) -> Result<BatchCount, ExtendedTtlvError> {
    Ok(BatchCount(*TtlvInteger::read(input)?))
}

fn batch_item(
    input: &mut Cursor<&[u8]>,
    _tag: i32,
    _tag_type: TtlvType,
    _context: (),
) -> Result<BatchItem, ExtendedTtlvError> {
    let _ = TtlvLength::read(input)?;
    let operation = enter_tag(input, 0x42005C, TtlvType::Enumeration, ttlv_enum_to_rust_type, ())?;
    let unique_batch_item_id = enter_optional_tag(input, 0x420093, TtlvType::Integer, unsupported_typed_tag, ())?;
    let request_payload = enter_tag(input, 0x420079, TtlvType::Structure, request_payload, operation)?;
    let _: Option<()> = enter_optional_tag(input, 0x420051, TtlvType::Structure, unsupported_tag, ())?;
    Ok(BatchItem(operation, unique_batch_item_id, request_payload))
}

fn request_payload(
    input: &mut Cursor<&[u8]>,
    tag: i32,
    tag_type: TtlvType,
    operation: Operation,
) -> Result<RequestPayload, ExtendedTtlvError> {
    match operation {
        Operation::CreateKeyPair => create_key_pair(input, tag, tag_type, ()),
        _ => Err(ExtendedTtlvError::UnsupportedVariant(tag, operation.ordinal())),
    }
}

//------------ KMIP Operation parser: Create Key Pair ------------------------

// https://docs.oasis-open.org/kmip/spec/v1.2/os/kmip-spec-v1.2-os.html#_Toc409613529
// 4.2 Create Key Pair
fn create_key_pair(
    input: &mut Cursor<&[u8]>,
    tag: i32,
    tag_type: TtlvType,
    _context: (),
) -> Result<RequestPayload, ExtendedTtlvError> {
    let _ = TtlvLength::read(input)?;
    let common_template_attribute =
        enter_optional_tag(input, 0x42001F, TtlvType::Structure, common_template_attribute, ())?;
    let private_key_template_attribute =
        enter_optional_tag(input, 0x420065, TtlvType::Structure, private_key_template_attribute, ())?;
    let public_key_template_attribute =
        enter_optional_tag(input, 0x42006E, TtlvType::Structure, public_key_template_attribute, ())?;
    Ok(RequestPayload::CreateKeyPair(
        common_template_attribute,
        private_key_template_attribute,
        public_key_template_attribute,
    ))
}

fn common_template_attribute(
    input: &mut Cursor<&[u8]>,
    tag: i32,
    tag_type: TtlvType,
    _context: (),
) -> Result<CommonTemplateAttribute, ExtendedTtlvError> {
    let _ = TtlvLength::read(input)?;
    let (names, attributes) = template_attribute(input, tag, tag_type, ())?;
    Ok(CommonTemplateAttribute::new_with_names(attributes, names))
}

fn private_key_template_attribute(
    input: &mut Cursor<&[u8]>,
    tag: i32,
    tag_type: TtlvType,
    _context: (),
) -> Result<PrivateKeyTemplateAttribute, ExtendedTtlvError> {
    let _ = TtlvLength::read(input)?;
    let (names, attributes) = template_attribute(input, tag, tag_type, ())?;
    Ok(PrivateKeyTemplateAttribute::new_with_names(attributes, names))
}

fn public_key_template_attribute(
    input: &mut Cursor<&[u8]>,
    tag: i32,
    tag_type: TtlvType,
    _context: (),
) -> Result<PublicKeyTemplateAttribute, ExtendedTtlvError> {
    let _ = TtlvLength::read(input)?;
    let (names, attributes) = template_attribute(input, tag, tag_type, ())?;
    Ok(PublicKeyTemplateAttribute::new_with_names(attributes, names))
}

fn template_attribute(
    input: &mut Cursor<&[u8]>,
    tag: i32,
    tag_type: TtlvType,
    _context: (),
) -> Result<(Vec<Name>, Vec<Attribute>), ExtendedTtlvError> {
    let mut names = vec![];
    let mut attributes = vec![];

    while let Some(name) = enter_optional_tag(input, 0x4200C7, TtlvType::Structure, name, ())? {
        names.push(name);
    }

    while let Some(attribute) = enter_optional_tag(input, 0x420008, TtlvType::Structure, attribute, ())? {
        attributes.push(attribute);
    }

    Ok((names, attributes))
}

fn name(input: &mut Cursor<&[u8]>, tag: i32, tag_type: TtlvType, _context: ()) -> Result<Name, ExtendedTtlvError> {
    let _ = TtlvLength::read(input)?;
    let name_value = enter_tag(input, 0x420055, TtlvType::TextString, name_value, ())?;
    let name_type = enter_tag(input, 0x420054, TtlvType::Enumeration, ttlv_enum_to_rust_type, ())?;
    Ok(Name(name_value, name_type))
}

fn name_value(
    mut input: &mut Cursor<&[u8]>,
    _tag: i32,
    _tag_type: TtlvType,
    _context: (),
) -> Result<NameValue, ExtendedTtlvError> {
    let val = TtlvTextString::read(&mut input)?;
    Ok(NameValue((*val).clone()))
}

fn attribute(
    input: &mut Cursor<&[u8]>,
    tag: i32,
    tag_type: TtlvType,
    _context: (),
) -> Result<Attribute, ExtendedTtlvError> {
    let _ = TtlvLength::read(input)?;
    let attribute_name = enter_tag(input, 0x42000A, TtlvType::TextString, attribute_name, ())?;
    let attribute_index = enter_optional_tag(input, 0x420009, TtlvType::Integer, attribute_index, ())?;
    let attribute_value = match attribute_name.0.as_str() {
        "Cryptographic Algorithm" => {
            AttributeValue::CryptographicAlgorithm(ttlv_enum_to_rust_type(input, tag, tag_type, context)?)
        }
        _ => todo!(),
    };
    Ok(Attribute(attribute_name, attribute_index, attribute_value))
}

fn attribute_name(
    mut input: &mut Cursor<&[u8]>,
    _tag: i32,
    _tag_type: TtlvType,
    _context: (),
) -> Result<AttributeName, ExtendedTtlvError> {
    let val = TtlvTextString::read(&mut input)?;
    Ok(AttributeName((*val).clone()))
}

fn attribute_index(
    mut input: &mut Cursor<&[u8]>,
    _tag: i32,
    _tag_type: TtlvType,
    _context: (),
) -> Result<AttributeIndex, ExtendedTtlvError> {
    let val = TtlvInteger::read(&mut input)?;
    Ok(AttributeIndex(*val))
}

//------------ High level parsing helper functions ---------------------------

/// A handler function for use with [`enter_tag()`] and
/// [`enter_optional_tag()`] that fails with an error that the specified tag
/// is not yet supportd by the parser.
fn unsupported_tag(
    _input: &mut Cursor<&[u8]>,
    tag: i32,
    _tag_type: TtlvType,
    _context: (),
) -> Result<(), ExtendedTtlvError> {
    Err(ExtendedTtlvError::UnsupportedTag(tag))
}

/// A handler function for use with [`enter_tag()`] and
/// [`enter_optional_tag()`] that fails with an error that the specified
/// tag is not yet supportd by the parser, but whose type we do need to
/// be able to specify, e.g. Authentication for when we need to store
/// Option::<Authentication>::None even if we don't support the tag yet.
fn unsupported_typed_tag<T>(
    _input: &mut Cursor<&[u8]>,
    tag: i32,
    _tag_type: TtlvType,
    _context: (),
) -> Result<T, ExtendedTtlvError> {
    Err(ExtendedTtlvError::UnsupportedTag(tag))
}

/// Parse a numeric KMIP TTLV enumeration from the input into a Rust type that
/// implements the Ordinalize trait.
fn ttlv_enum_to_rust_type<T: Ordinalize>(
    input: &mut Cursor<&[u8]>,
    tag: i32,
    _tag_type: TtlvType,
    _context: (),
) -> Result<T, ExtendedTtlvError>
where
    <T as Ordinalize>::VariantType: From<u32>,
{
    let discriminant: u32 = *TtlvEnumeration::read(input)?;
    let variant: <T as Ordinalize>::VariantType = discriminant.into();
    match T::from_ordinal(variant) {
        Some(res) => Ok(res),
        None => Err(ExtendedTtlvError::UnsupportedVariant(tag, discriminant)),
    }
}

// Parse the next KMIP TTLV record in `T`.
//
// A thin wrapper around [`Self::enter_optional_tag()`] returning only `Ok(T)`
// or Err, i.e. the next T_ag and T_ype in the input stream MUST be the
// expected ones.
fn enter_tag<F, T, C>(
    input: &mut Cursor<&[u8]>,
    tag: i32,
    tag_type: TtlvType,
    handler: F,
    handler_context: C,
) -> Result<T, ExtendedTtlvError>
where
    F: Fn(&mut Cursor<&[u8]>, i32, TtlvType, C) -> Result<T, ExtendedTtlvError>,
{
    match enter_optional_tag(input, tag, tag_type, handler, handler_context)? {
        Some(res) => Ok(res),
        None => panic!("Missing tag {:06X} of type {}", tag, tag_type),
    }
}

/// Parse the next KMIP TTLV record into `T`, if present.
///
/// Returns Ok(None) if the next T_ag or T_ype do not match the specified tag
/// and tag_type.
///
/// Otherwise invokes the provided `handler()` function passing to it the
/// input remaiing after the T_ag and T_type, i.e. L_ength and V_alue..., plus
/// the KMIP numeric tag number, KMIP type and any provided context.
///
/// The tag and type can be used to write generic handler functions that vary
/// their behaviour based on the tag and type encountered.
///
/// The context can be used to write handler functions that expect different
/// input based on some value, e.g. a previously read enum. One example of
/// this is parsing the KMIP Request Payload which is a KMIP Structure whose
/// contents depend on the previously seen Operation enum value.
fn enter_optional_tag<F, T, C>(
    input: &mut Cursor<&[u8]>,
    tag: i32,
    tag_type: TtlvType,
    handler: F,
    handler_context: C,
) -> Result<Option<T>, ExtendedTtlvError>
where
    F: Fn(&mut Cursor<&[u8]>, i32, TtlvType, C) -> Result<T, ExtendedTtlvError>,
{
    diag(input);
    let found = if_tt(input, tag, tag_type)?;
    if found {
        match handler(input, tag, tag_type, handler_context) {
            Ok(res) => Ok(Some(res)),
            Err(ExtendedTtlvError::UnsupportedTag(_)) => {
                // We don't support this data yet so read its length and skip it.
                let len = *TtlvLength::read(input)? as u64;
                input.set_position(input.position() + len);
                Ok(None)
            }
            Err(err) => Err(err),
        }
    } else {
        Ok(None)
    }
}

//------------ Low-level parsing helper functions ----------------------------

fn expect_tt(
    mut input: &mut Cursor<&[u8]>,
    expected_tag: u32,
    expected_type: TtlvType,
) -> Result<(), kmip_ttlv::types::Error> {
    diag(input);
    let expected_tag = TtlvTag::from(<[u8; 3]>::try_from(&expected_tag.to_be_bytes()[1..4]).unwrap());
    let tag = TtlvTag::read(&mut input)?;
    if tag != expected_tag {
        return Err(kmip_ttlv::types::Error::InvalidTtlvTag(format!(
            "Expected {expected_tag}, found {tag}"
        )));
    }
    let typ = TtlvType::read(&mut input)?;
    if typ != expected_type {
        return Err(kmip_ttlv::types::Error::UnsupportedTtlvType(expected_type as u8));
    }
    Ok(())
}

#[allow(dead_code)]
fn expect_ttl(
    mut input: &mut Cursor<&[u8]>,
    expected_tag: u32,
    expected_type: TtlvType,
) -> Result<TtlvLength, kmip_ttlv::types::Error> {
    expect_tt(input, expected_tag, expected_type)?;
    let len = TtlvLength::read(&mut input)?;
    Ok(len)
}

fn expect_ttlv<T: SerializableTtlvType>(
    mut input: &mut Cursor<&[u8]>,
    expected_tag: u32,
    expected_type: TtlvType,
) -> Result<T, kmip_ttlv::types::Error> {
    expect_tt(input, expected_tag, expected_type)?;
    let val = T::read(&mut input)?;
    Ok(val)
}

fn if_tt(
    mut input: &mut Cursor<&[u8]>,
    expected_tag: i32,
    expected_type: TtlvType,
) -> Result<bool, kmip_ttlv::types::Error> {
    let saved_pos = input.position();
    let expected_tag = TtlvTag::from(<[u8; 3]>::try_from(&expected_tag.to_be_bytes()[1..4]).unwrap());
    let tag = TtlvTag::read(&mut input)?;
    if tag != expected_tag {
        input.set_position(saved_pos);
        return Ok(false);
    }
    let typ = TtlvType::read(&mut input)?;
    if typ != expected_type {
        return Err(kmip_ttlv::types::Error::UnsupportedTtlvType(expected_type as u8));
    }
    Ok(true)
}

fn diag(input: &Cursor<&[u8]>) {
    let pos = input.position() as usize;
    eprintln!("Dbg: {}.. @ {pos}", hex::encode_upper(&input.get_ref()[pos..pos + 8]));
}

//------------ Error types ---------------------------------------------------

#[derive(Debug)]
pub enum ExtendedTtlvError {
    TtlvError(kmip_ttlv::types::Error),
    UnsupportedTag(i32),
    UnsupportedVariant(i32, u32),
}

impl From<kmip_ttlv::types::Error> for ExtendedTtlvError {
    fn from(err: kmip_ttlv::types::Error) -> Self {
        ExtendedTtlvError::TtlvError(err)
    }
}

impl From<std::io::Error> for ExtendedTtlvError {
    fn from(err: std::io::Error) -> Self {
        ExtendedTtlvError::TtlvError(err.into())
    }
}

impl std::fmt::Display for ExtendedTtlvError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ExtendedTtlvError::TtlvError(err) => write!(f, "KMIP TTLV parsing error: {err:?}"),
            ExtendedTtlvError::UnsupportedTag(tag) => write!(f, "KMIP TTLV tag 0x{tag:06X} not supported"),
            ExtendedTtlvError::UnsupportedVariant(tag, variant) => {
                write!(f, "KMIP TTLV tag 0x{tag:06X} variant {variant:0X} not supported")
            }
        }
    }
}

//============ Tests =========================================================

#[cfg(test)]
mod tests {
    use crate::types::response::ResultStatus;

    use super::*;

    #[test]
    fn kmip_1_0_usecase_8_1_step_1_create_rsa_1024_key_pair_request() {
        let use_case_request_hex = concat!(
            "42007801000001E84200770100000038420069010000002042006A0200000004000000010000000042006B02000000040",
            "00000000000000042000D0200000004000000010000000042000F01000001A042005C0500000004000000020000000042",
            "0079010000018842001F0100000070420008010000003042000A070000001743727970746F6772617068696320416C676",
            "F726974686D0042000B05000000040000000400000000420008010000003042000A070000001443727970746F67726170",
            "686963204C656E6774680000000042000B020000000400000400000000004200650100000080420008010000004042000",
            "A07000000044E616D650000000042000B0100000028420055070000000B507269766174654B6579310000000000420054",
            "05000000040000000100000000420008010000003042000A070000001843727970746F677261706869632055736167652",
            "04D61736B42000B0200000004000000010000000042006E0100000080420008010000004042000A07000000044E616D65",
            "0000000042000B0100000028420055070000000A5075626C69634B6579310000000000004200540500000004000000010",
            "0000000420008010000003042000A070000001843727970746F67726170686963205573616765204D61736B42000B0200",
            "0000040000000200000000"
        );
        let ttlv_wire = hex::decode(use_case_request_hex).unwrap();
        let res: Result<Option<RequestMessage>, ExtendedTtlvError> = parse(ttlv_wire.as_ref());
        let Ok(res) = res else {
            panic!("KMIP TTLV parsing failed: {}", res.unwrap_err());
        };
        let Some(res) = res else {
            panic!("No KMIP TTLV request found");
        };

        assert_eq!(
            res.0 .0,
            ProtocolVersion(ProtocolVersionMajor(1), ProtocolVersionMinor(0))
        );
        assert_eq!(res.header().batch_count().0, 1);
        assert_eq!(res.batch_items().len(), 1);

        let item = &res.batch_items()[0];
        assert!(matches!(item.0, Operation::CreateKeyPair));
        dbg!(item);
    }
}
