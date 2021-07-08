//! See: http://docs.oasis-open.org/kmip/testcases/v1.1/cn01/kmip-testcases-v1.1-cn01.html#_Toc333488818

#[allow(unused_imports)]
use pretty_assertions::{assert_eq, assert_ne};

use krill_kmip_ttlv::{de::from_slice, ser::to_vec};

use crate::types::{
    common::Operation,
    request::{
        self, Authentication, BatchCount, BatchItem, MaximumResponseSize, ProtocolVersionMajor, ProtocolVersionMinor,
        RequestHeader, RequestMessage, RequestPayload,
    },
    response::{ProtocolVersion, ResponseMessage, ResponsePayload, ResultStatus},
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

#[test]
fn discover_versions_response_v11_v10() {
    let use_case_response_hex = concat!(
        "42007B01000000D042007A0100000048420069010000002042006A0200000004000000010000000042006B02000000040",
        "0000001000000004200920900000008000000004ED73ED742000D0200000004000000010000000042000F010000007842",
        "005C05000000040000001E0000000042007F0500000004000000000000000042007C01000000504200690100000020420",
        "06A0200000004000000010000000042006B02000000040000000100000000420069010000002042006A02000000040000",
        "00010000000042006B02000000040000000000000000",
    );
    let ttlv_wire = hex::decode(use_case_response_hex).unwrap();
    let res: ResponseMessage = from_slice(ttlv_wire.as_ref()).unwrap();

    assert_eq!(res.header.protocol_version.major, 1);
    assert_eq!(res.header.protocol_version.minor, 1);
    assert_eq!(res.header.timestamp, 0x000000004ED73ED7);
    assert_eq!(res.header.batch_count, 1);
    assert_eq!(res.batch_items.len(), 1);

    let item = &res.batch_items[0];
    assert!(matches!(item.result_status, ResultStatus::Success));
    assert!(matches!(item.operation, Some(Operation::DiscoverVersions)));
    assert!(matches!(&item.payload, Some(ResponsePayload::DiscoverVersions(_))));

    if let Some(ResponsePayload::DiscoverVersions(payload)) = item.payload.as_ref() {
        if let Some(versions) = &payload.supported_versions {
            assert_eq!(versions.len(), 2);
            assert_eq!(versions[0], ProtocolVersion { major: 1, minor: 1 });
            assert_eq!(versions[1], ProtocolVersion { major: 1, minor: 0 });
        } else {
            panic!("Supported versions response should not be None");
        }
    } else {
        panic!("Wrong payload");
    }
}

#[test]
fn discover_versions_request_with_v10() {
    let use_case_request = RequestMessage(
        RequestHeader(
            request::ProtocolVersion(ProtocolVersionMajor(1), ProtocolVersionMinor(1)),
            Option::<MaximumResponseSize>::None,
            Option::<Authentication>::None,
            BatchCount(1),
        ),
        vec![BatchItem(
            Operation::DiscoverVersions,
            RequestPayload::DiscoverVersions(vec![request::ProtocolVersion(
                ProtocolVersionMajor(1),
                ProtocolVersionMinor(0),
            )]),
        )],
    );

    let use_case_request_hex = concat!(
        "42007801000000884200770100000038420069010000002042006A0200000004000000010000000042006B02000000040",
        "00000010000000042000D0200000004000000010000000042000F010000004042005C05000000040000001E0000000042",
        "00790100000028420069010000002042006A0200000004000000010000000042006B02000000040000000000000000",
    );
    let actual_request_hex = hex::encode_upper(to_vec(&use_case_request).unwrap());

    assert_eq!(use_case_request_hex, actual_request_hex);
}

#[test]
fn discover_versions_response_v10() {
    let use_case_response_hex = concat!(
        "42007B01000000A842007A0100000048420069010000002042006A0200000004000000010000000042006B02000000040",
        "0000001000000004200920900000008000000004E04888242000D0200000004000000010000000042000F010000005042",
        "005C05000000040000001E0000000042007F0500000004000000000000000042007C01000000284200690100000020420",
        "06A0200000004000000010000000042006B02000000040000000000000000"
    );
    let ttlv_wire = hex::decode(use_case_response_hex).unwrap();
    let res: ResponseMessage = from_slice(ttlv_wire.as_ref()).unwrap();

    assert_eq!(res.header.protocol_version.major, 1);
    assert_eq!(res.header.protocol_version.minor, 1);
    assert_eq!(res.header.timestamp, 0x000000004E048882);
    assert_eq!(res.header.batch_count, 1);
    assert_eq!(res.batch_items.len(), 1);

    let item = &res.batch_items[0];
    assert!(matches!(item.result_status, ResultStatus::Success));
    assert!(matches!(item.operation, Some(Operation::DiscoverVersions)));
    assert!(matches!(&item.payload, Some(ResponsePayload::DiscoverVersions(_))));

    if let Some(ResponsePayload::DiscoverVersions(payload)) = item.payload.as_ref() {
        if let Some(versions) = &payload.supported_versions {
            assert_eq!(versions.len(), 1);
            assert_eq!(versions[0], ProtocolVersion { major: 1, minor: 0 });
        } else {
            panic!("Supported versions response should not be None");
        }
    } else {
        panic!("Wrong payload");
    }
}

#[test]
fn discover_versions_request_with_v11() {
    let use_case_request = RequestMessage(
        RequestHeader(
            request::ProtocolVersion(ProtocolVersionMajor(1), ProtocolVersionMinor(1)),
            Option::<MaximumResponseSize>::None,
            Option::<Authentication>::None,
            BatchCount(1),
        ),
        vec![BatchItem(
            Operation::DiscoverVersions,
            RequestPayload::DiscoverVersions(vec![request::ProtocolVersion(
                ProtocolVersionMajor(1),
                ProtocolVersionMinor(1),
            )]),
        )],
    );

    let use_case_request_hex = concat!(
        "42007801000000884200770100000038420069010000002042006A0200000004000000010000000042006B02000000040",
        "00000010000000042000D0200000004000000010000000042000F010000004042005C05000000040000001E0000000042",
        "00790100000028420069010000002042006A0200000004000000010000000042006B02000000040000000100000000",
    );
    let actual_request_hex = hex::encode_upper(to_vec(&use_case_request).unwrap());

    assert_eq!(use_case_request_hex, actual_request_hex);
}

#[test]
fn discover_versions_response_v11() {
    let use_case_response_hex = concat!(
        "42007B01000000A842007A0100000048420069010000002042006A0200000004000000010000000042006B02000000040",
        "0000001000000004200920900000008000000004ED73ED742000D0200000004000000010000000042000F010000005042",
        "005C05000000040000001E0000000042007F0500000004000000000000000042007C01000000284200690100000020420",
        "06A0200000004000000010000000042006B02000000040000000100000000",
    );
    let ttlv_wire = hex::decode(use_case_response_hex).unwrap();
    let res: ResponseMessage = from_slice(ttlv_wire.as_ref()).unwrap();

    assert_eq!(res.header.protocol_version.major, 1);
    assert_eq!(res.header.protocol_version.minor, 1);
    assert_eq!(res.header.timestamp, 0x000000004ED73ED7);
    assert_eq!(res.header.batch_count, 1);
    assert_eq!(res.batch_items.len(), 1);

    let item = &res.batch_items[0];
    assert!(matches!(item.result_status, ResultStatus::Success));
    assert!(matches!(item.operation, Some(Operation::DiscoverVersions)));
    assert!(matches!(&item.payload, Some(ResponsePayload::DiscoverVersions(_))));

    if let Some(ResponsePayload::DiscoverVersions(payload)) = item.payload.as_ref() {
        if let Some(versions) = &payload.supported_versions {
            assert_eq!(versions.len(), 1);
            assert_eq!(versions[0], ProtocolVersion { major: 1, minor: 1 });
        } else {
            panic!("Supported versions response should not be None");
        }
    } else {
        panic!("Wrong payload");
    }
}

#[test]
fn discover_versions_request_with_v931() {
    let use_case_request = RequestMessage(
        RequestHeader(
            request::ProtocolVersion(ProtocolVersionMajor(1), ProtocolVersionMinor(1)),
            Option::<MaximumResponseSize>::None,
            Option::<Authentication>::None,
            BatchCount(1),
        ),
        vec![BatchItem(
            Operation::DiscoverVersions,
            RequestPayload::DiscoverVersions(vec![request::ProtocolVersion(
                ProtocolVersionMajor(9),
                ProtocolVersionMinor(31),
            )]),
        )],
    );

    let use_case_request_hex = concat!(
        "42007801000000884200770100000038420069010000002042006A0200000004000000010000000042006B02000000040",
        "00000010000000042000D0200000004000000010000000042000F010000004042005C05000000040000001E0000000042",
        "00790100000028420069010000002042006A0200000004000000090000000042006B02000000040000001F00000000",
    );
    let actual_request_hex = hex::encode_upper(to_vec(&use_case_request).unwrap());

    assert_eq!(use_case_request_hex, actual_request_hex);
}

#[test]
fn discover_versions_response_no_versions() {
    let use_case_response_hex = concat!(
        "42007B010000008042007A0100000048420069010000002042006A0200000004000000010000000042006B02000000040",
        "0000001000000004200920900000008000000004ED73ED742000D0200000004000000010000000042000F010000002842",
        "005C05000000040000001E0000000042007F0500000004000000000000000042007C0100000000",
    );
    let ttlv_wire = hex::decode(use_case_response_hex).unwrap();
    let res: ResponseMessage = from_slice(ttlv_wire.as_ref()).unwrap();

    assert_eq!(res.header.protocol_version.major, 1);
    assert_eq!(res.header.protocol_version.minor, 1);
    assert_eq!(res.header.timestamp, 0x000000004ED73ED7);
    assert_eq!(res.header.batch_count, 1);
    assert_eq!(res.batch_items.len(), 1);

    let item = &res.batch_items[0];
    assert!(matches!(item.result_status, ResultStatus::Success));
    assert!(matches!(item.operation, Some(Operation::DiscoverVersions)));
    assert!(matches!(&item.payload, Some(ResponsePayload::DiscoverVersions(_))));

    if let Some(ResponsePayload::DiscoverVersions(payload)) = item.payload.as_ref() {
        assert!(payload.supported_versions.is_none());
    } else {
        panic!("Wrong payload");
    }
}
