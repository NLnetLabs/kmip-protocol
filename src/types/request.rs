use serde_derive::Serialize;

use super::common::{CryptographicParameters, ObjectType, Operation, TemplateAttribute, UniqueIdentifier};

// KMIP spec 1.0 section 2.1.2 Credential
// See: http://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581156
#[derive(Serialize)]
#[serde(rename = "0x420023")]
pub struct Credential(pub CredentialType, pub CredentialValue);

#[derive(Serialize)]
#[serde(rename = "0x420024")]
#[non_exhaustive]
pub enum CredentialType {
    #[serde(rename = "0x00000001")]
    UsernameAndPassword,
}

#[derive(Serialize)]
#[serde(rename = "0x420025")]
#[non_exhaustive]
pub enum CredentialValue {
    UsernameAndPassword(UsernameAndPasswordCredential),
}

#[derive(Serialize)]
pub struct UsernameAndPasswordCredential(pub Username, pub Option<Password>);

#[derive(Serialize)]
#[serde(rename = "0x420099")]
pub struct Username(pub String);

#[derive(Serialize)]
#[serde(rename = "0x4200A1")]
pub struct Password(pub String);

// KMIP spec 1.0 section 6.1 Protocol Version
// See: http://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581239
#[derive(Serialize)]
#[serde(rename = "0x420069")]
pub struct ProtocolVersion(pub ProtocolVersionMajor, pub ProtocolVersionMinor);

#[derive(Serialize)]
#[serde(rename = "0x42006A")]
pub struct ProtocolVersionMajor(pub i32);

#[derive(Serialize)]
#[serde(rename = "0x42006B")]
pub struct ProtocolVersionMinor(pub i32);

// KMIP spec 1.0 section 6.3 Maximum Response Size
// See: http://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581241
#[derive(Serialize)]
#[serde(rename = "0x420050")]
pub struct MaximumResponseSize(pub i32);

// KMIP spec 1.0 section 6.6 Authentication
// See: http://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581244
#[derive(Serialize)]
#[serde(rename = "0x42000C")]
pub struct Authentication(pub Credential);

// KMIP spec 1.0 section 6.14 Batch Count
// See: http://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581252
#[derive(Serialize)]
#[serde(rename = "0x42000D")]
pub struct BatchCount(pub i32);

// KMIP spec 1.0 section 6.15 Batch Item
// See: http://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581253
#[derive(Serialize)]
#[serde(rename = "0x42000F")]
pub struct BatchItem(pub Operation, pub RequestPayload);

// KMIP spec 1.0 section 7.1 Message Format
// See: http://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581256
#[derive(Serialize)]
#[serde(rename = "0x420078")]
pub struct RequestMessage(pub RequestHeader, pub Vec<BatchItem>);

// KMIP spec 1.0 section 7.2 Operations
// See: http://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581257
#[derive(Serialize)]
#[serde(rename = "0x420077")]
pub struct RequestHeader(
    pub ProtocolVersion,
    #[serde(skip_serializing_if = "Option::is_none")] pub Option<MaximumResponseSize>,
    #[serde(skip_serializing_if = "Option::is_none")] pub Option<Authentication>,
    pub BatchCount,
);

#[derive(Serialize)]
#[serde(rename = "0x420079")]
#[non_exhaustive]
pub enum RequestPayload {
    Create(CreateRequestPayload),
    Query(Vec<QueryFunction>),
    DiscoverVersions(DiscoverVersionsRequestPayload),
    Sign(SignRequestPayload),
}

// KMIP spec 1.0 section 4.1 Create
// See: http://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581209
#[derive(Serialize)]
pub struct CreateRequestPayload(pub ObjectType, pub TemplateAttribute);

// KMIP spec 1.0 section 9.1.3.2.23 Query Function Enumeration
// See: http://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Ref242030554
#[derive(Serialize)]
#[serde(rename = "0x420074")]
#[non_exhaustive]
pub enum QueryFunction {
    #[serde(rename = "0x00000001")]
    QueryOperations,

    #[serde(rename = "0x00000002")]
    QueryObjects,

    #[serde(rename = "0x00000003")]
    QueryServerInformation,
    // Note: This set of enum variants is deliberately limited to those that we currently support.
}

// KMIP spec 1.2 section 4.26 Discover Versions
// See: http://docs.oasis-open.org/kmip/spec/v1.2/os/kmip-spec-v1.2-os.html#_Toc409613553
#[derive(Serialize)]
pub struct DiscoverVersionsRequestPayload();

// KMIP spec 1.2 section 4.31 Sign
// See: http://docs.oasis-open.org/kmip/spec/v1.2/os/kmip-spec-v1.2-os.html#_Toc409613558
#[derive(Serialize)]
pub struct SignRequestPayload(
    #[serde(skip_serializing_if = "Option::is_none")] pub Option<UniqueIdentifier>,
    #[serde(skip_serializing_if = "Option::is_none")] pub Option<CryptographicParameters>,
);
