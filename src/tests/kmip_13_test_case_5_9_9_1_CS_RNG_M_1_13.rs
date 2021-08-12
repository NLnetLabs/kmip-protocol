//! See: https://docs.oasis-open.org/kmip/profiles/v1.3/os/test-cases/kmip-v1.3/mandatory/CS-RNG-M-1-13.xml
//! See: https://docs.oasis-open.org/kmip/profiles/v1.3/cs01/kmip-profiles-v1.3-cs01.html#_Toc459802032

#[allow(unused_imports)]
use pretty_assertions::{assert_eq, assert_ne};

use krill_kmip_ttlv::{de::from_slice, ser::to_vec};

use crate::types::{
    common::{DataLength, Operation, UniqueBatchItemID},
    request::{
        self, Authentication, BatchCount, BatchItem, MaximumResponseSize, ProtocolVersionMajor, ProtocolVersionMinor,
        RequestHeader, RequestMessage, RequestPayload,
    },
    response::{ResponseMessage, ResponsePayload, ResultStatus},
};

#[test]
fn rng_retrieve_request() {
    let use_case_request = RequestMessage(
        RequestHeader(
            request::ProtocolVersion(ProtocolVersionMajor(1), ProtocolVersionMinor(3)),
            Option::<MaximumResponseSize>::None,
            Option::<Authentication>::None,
            BatchCount(1),
        ),
        vec![BatchItem(
            Operation::RNGRetrieve,
            Option::<UniqueBatchItemID>::None,
            RequestPayload::RNGRetrieve(DataLength(32)),
        )],
    );

    // Note: This hex was based on a working request sent to a Kryptus KMIP server. It was adjusted by hand to exactly
    // match the official test case request as that is only given in XML form, not binary TTLV form.
    let use_case_request_hex = concat!(
        "42007801000000704200770100000038420069010000002042006A0200000004000000010000000042006B02000000040",
        "00000030000000042000D0200000004000000010000000042000F010000002842005C0500000004000000250000000042",
        "007901000000104200C402000000040000002000000000",
    );
    let actual_request_hex = hex::encode_upper(to_vec(&use_case_request).unwrap());

    assert_eq!(
        use_case_request_hex, actual_request_hex,
        "expected hex (left) differs to the generated hex (right)"
    );
}

#[test]
fn rng_retrieve_response() {
    let use_case_generated_random_bytes_hex = "9c0bcd79d775998ddc52457bbbcfce2d4a194b039e20a3adacb63fb6561ba545";

    // Note: This hex was based on a successful response from a Kryptus KMIP server. It was adjusted by hand to exactly
    // match the official test case response as that is only given in XML form, not binary TTLV form.
    let use_case_response_hex = concat!(
        "42007B01000000A842007A0100000048420069010000002042006A0200000004000000010000000042006B02000000040",
        "0000003000000004200920900000008000000004ED73ED742000D0200000004000000010000000042000F010000005042",
        "005C0500000004000000250000000042007F0500000004000000000000000042007C01000000284200C208000000209c0",
        "BCD79D775998DDC52457BBBCFCE2D4A194B039E20A3ADACB63FB6561BA545",
    );
    let ttlv_wire = hex::decode(use_case_response_hex).unwrap();
    let res: ResponseMessage = from_slice(ttlv_wire.as_ref()).unwrap();

    assert_eq!(res.header.protocol_version.major, 1);
    assert_eq!(res.header.protocol_version.minor, 3);
    assert_eq!(res.header.timestamp, 0x000000004ED73ED7);
    assert_eq!(res.header.batch_count, 1);
    assert_eq!(res.batch_items.len(), 1);

    let item = &res.batch_items[0];
    assert!(matches!(item.result_status, ResultStatus::Success));
    assert!(matches!(item.operation, Some(Operation::RNGRetrieve)));
    assert!(matches!(&item.payload, Some(ResponsePayload::RNGRetrieve(_))));

    if let Some(ResponsePayload::RNGRetrieve(payload)) = item.payload.as_ref() {
        assert_eq!(payload.data, hex::decode(use_case_generated_random_bytes_hex).unwrap());
    } else {
        panic!("Wrong payload");
    }
}
