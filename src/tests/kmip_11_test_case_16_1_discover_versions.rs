//! See: http://docs.oasis-open.org/kmip/testcases/v1.1/cn01/kmip-testcases-v1.1-cn01.html#_Toc333488818

#[allow(unused_imports)]
use pretty_assertions::{assert_eq, assert_ne};

use krill_kmip_ttlv::ser::to_vec;

use crate::types::{
    common::Operation,
    request::{
        self, Authentication, BatchCount, BatchItem, MaximumResponseSize, ProtocolVersionMajor, ProtocolVersionMinor,
        RequestHeader, RequestMessage, RequestPayload,
    },
};

#[test]
fn discover_versions_request_no_versions_provided() {
    let use_case_request = RequestMessage(
        RequestHeader(
            request::ProtocolVersion(ProtocolVersionMajor(1), ProtocolVersionMinor(1)),
            Option::<MaximumResponseSize>::None,
            Option::<Authentication>::None,
            BatchCount(1),
        ),
        vec![BatchItem(
            Operation::DiscoverVersions,
            RequestPayload::DiscoverVersions(vec![]),
        )],
    );

    let use_case_request_hex = concat!(
        "42007801000000604200770100000038420069010000002042006A0200000004000000010000000042006B02000000040",
        "00000010000000042000D0200000004000000010000000042000F010000001842005C05000000040000001E0000000042",
        "00790100000000",
    );
    let actual_request_hex = hex::encode_upper(to_vec(&use_case_request).unwrap());

    assert_eq!(use_case_request_hex, actual_request_hex);
}
