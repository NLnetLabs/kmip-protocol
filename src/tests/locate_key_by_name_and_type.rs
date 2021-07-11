#[allow(unused_imports)]
use pretty_assertions::{assert_eq, assert_ne};

use krill_kmip_ttlv::ser::to_vec;

use crate::types::common::{ObjectType, Operation};
use crate::types::request::{
    self, Attribute, Authentication, BatchCount, BatchItem, MaximumResponseSize, ProtocolVersionMajor,
    ProtocolVersionMinor, RequestHeader, RequestMessage, RequestPayload,
};

#[test]
fn locate_request_public_key_by_name_only_serializes_without_error() {
    let request = RequestMessage(
        RequestHeader(
            request::ProtocolVersion(ProtocolVersionMajor(1), ProtocolVersionMinor(0)),
            Option::<MaximumResponseSize>::None,
            Option::<Authentication>::None,
            BatchCount(1),
        ),
        vec![BatchItem(
            Operation::Locate,
            RequestPayload::Locate(vec![Attribute::Name("Some Public Key Name".into())]),
        )],
    );
    assert!(to_vec(&request).is_ok());
}

#[test]
fn locate_request_public_key_by_name_and_type_serializes_without_error() {
    let request = RequestMessage(
        RequestHeader(
            request::ProtocolVersion(ProtocolVersionMajor(1), ProtocolVersionMinor(0)),
            Option::<MaximumResponseSize>::None,
            Option::<Authentication>::None,
            BatchCount(1),
        ),
        vec![BatchItem(
            Operation::Locate,
            RequestPayload::Locate(vec![
                Attribute::ObjectType(ObjectType::PublicKey),
                Attribute::Name("Some Public Key Name".into()),
            ]),
        )],
    );
    assert!(to_vec(&request).is_ok());
}

#[test]
fn locate_request_private_key_by_name_only_serializes_without_error() {
    let request = RequestMessage(
        RequestHeader(
            request::ProtocolVersion(ProtocolVersionMajor(1), ProtocolVersionMinor(0)),
            Option::<MaximumResponseSize>::None,
            Option::<Authentication>::None,
            BatchCount(1),
        ),
        vec![BatchItem(
            Operation::Locate,
            RequestPayload::Locate(vec![Attribute::Name("Some Private Key Name".into())]),
        )],
    );
    assert!(to_vec(&request).is_ok());
}

#[test]
fn locate_request_private_key_by_name_and_type_serializes_without_error() {
    let request = RequestMessage(
        RequestHeader(
            request::ProtocolVersion(ProtocolVersionMajor(1), ProtocolVersionMinor(0)),
            Option::<MaximumResponseSize>::None,
            Option::<Authentication>::None,
            BatchCount(1),
        ),
        vec![BatchItem(
            Operation::Locate,
            RequestPayload::Locate(vec![
                Attribute::ObjectType(ObjectType::PrivateKey),
                Attribute::Name("Some Private Key Name".into()),
            ]),
        )],
    );
    assert!(to_vec(&request).is_ok());
}
