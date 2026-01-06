/// Tests for TimeStamp support in KMIP request headers.
///
/// OpenBao sends TimeStamp (tag 0x420092, DateTime type 0x09) in request headers.
/// These tests verify that requests with and without TimeStamp parse correctly.

use crate::ttlv::fast_scan::FastScanner;
use crate::types::request::TimeStamp;

/// Test that TimeStamp struct can hold a value and be accessed.
#[test]
fn test_timestamp_struct() {
    let ts = TimeStamp(1704067200);
    assert_eq!(ts.0, 1704067200);
}

/// Test TimeStamp parsing from raw DateTime TTLV bytes.
#[test]
fn test_timestamp_fast_scan_from_bytes() {
    // TTLV encoding:
    // Tag: 0x420092 (TimeStamp)
    // Type: 0x09 (DateTime)
    // Length: 0x00000008 (8 bytes)
    // Value: 0x0000000065000000 (example timestamp)
    let timestamp_ttlv: &[u8] = &[
        0x42, 0x00, 0x92, // Tag
        0x09,             // Type: DateTime
        0x00, 0x00, 0x00, 0x08, // Length
        0x00, 0x00, 0x00, 0x00, 0x65, 0x00, 0x00, 0x00, // Value
    ];

    let mut scanner = FastScanner::new(timestamp_ttlv).unwrap();
    let ts = TimeStamp::fast_scan(&mut scanner).unwrap();

    assert_eq!(ts.0, 0x65000000);
}

/// Test that TimeStamp is optional in RequestHeader (can be None).
#[test]
fn test_timestamp_optional_scan() {
    // Empty case - scanning should return None for optional
    let empty: &[u8] = &[
        0x42, 0x00, 0x0D, // Tag: BatchCount (not TimeStamp)
        0x02,             // Type: Integer
        0x00, 0x00, 0x00, 0x04, // Length
        0x00, 0x00, 0x00, 0x01, // Value: 1
        0x00, 0x00, 0x00, 0x00, // Padding
    ];

    let mut scanner = FastScanner::new(empty).unwrap();
    let ts = TimeStamp::fast_scan_opt(&mut scanner).unwrap();

    assert!(ts.is_none());
}

/// Test that TimeStamp present in bytes is correctly parsed as Some.
#[test]
fn test_timestamp_present_scan() {
    let with_timestamp: &[u8] = &[
        0x42, 0x00, 0x92, // Tag: TimeStamp
        0x09,             // Type: DateTime
        0x00, 0x00, 0x00, 0x08, // Length
        0x00, 0x00, 0x00, 0x00, 0x12, 0x34, 0x56, 0x78, // Value
    ];

    let mut scanner = FastScanner::new(with_timestamp).unwrap();
    let ts = TimeStamp::fast_scan_opt(&mut scanner).unwrap();

    assert!(ts.is_some());
    assert_eq!(ts.unwrap().0, 0x12345678);
}
