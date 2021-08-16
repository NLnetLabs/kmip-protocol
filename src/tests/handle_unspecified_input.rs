use crate::{
    response::from_slice,
    types::response::{BatchItem, MessageExtension, QueryResponsePayload, ServerInformation, VendorExtension},
};

/// The server information response field is vendor specific and thus could contain anything.
/// We don't attempt to make sense of it, but we shouldn't fail to deserialize this kind of response either.
#[test]
fn test_deserialize_arbitrary_server_information() {
    let fragment_hex = concat!(
        "42007C 01 00000028", // (Query) Response Payload with only the Server Information (0x420088) optional structure
        "  420088 01 00000020", // present and consisting of unknown tags (0x123456, 0x999999) and arbitrary data types
        "    123456 07 00000003 00010200 00000000", // a string (type 0x07)
        "    999999 02 00000004 00000099 00000000", // an integer (type 0x02)
    );
    let fragment_hex = fragment_hex.replace(" ", "");
    let ttlv_wire = hex::decode(fragment_hex).unwrap();
    let res: QueryResponsePayload = from_slice(ttlv_wire.as_ref()).unwrap();
    assert_eq!(
        res.server_information,
        Some(ServerInformation(Some(
            hex::decode("1234560700000003000102000000000099999902000000040000009900000000").unwrap()
        )))
    );
}

/// Any KMIP Batch Item may include a vendor specific message extension which could contain anything.
/// We don't attempt to make sense of it, but we shouldn't fail to deserialize this kind of response either.
#[test]
fn test_batch_item_vendor_extensions() {
    let fragment_hex = concat!(
        "42000F 01 00000048", // Batch Item (0x42000F) with a failed result status (0x42007F, enum type 0x05), all other
        "  42007F 05 00000004 00000001 00000000", // optional fields missing except the message extension structure (0x420051).
        "  420051 01 00000030",                   //
        "    42007D 07 00000003 01020300 00000000", // Vendor Identification (0x042007D, string type 0x07)
        "    420026 06 00000008 00000000 00000001", // Criticality Indicator (0x420026, bool type 0x06)
        "    42009C 02 00000004 00000005 00000000", // Vendor Extension (0x42009C, arbitrary type but treated as bytes)
    );
    let fragment_hex = fragment_hex.replace(" ", "");
    let ttlv_wire = hex::decode(fragment_hex).unwrap();
    let res: BatchItem = from_slice(ttlv_wire.as_ref()).unwrap();
    assert!(matches!(res.message_extension, Some(MessageExtension { .. })));
    let me = res.message_extension.unwrap();
    assert_eq!(me.vendor_identification, "\u{01}\u{02}\u{03}");
    assert_eq!(me.criticality_indicator, true);
    assert_eq!(me.vendor_extension, VendorExtension(Some(vec![0u8, 0u8, 0u8, 5u8])));
}
