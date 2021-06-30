use serde_derive::Deserialize;
use serde_derive::Serialize;

// KMIP spec 1.0 section 2.1.1 Attribute
// See: http://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581155
#[derive(Serialize)]
#[serde(rename = "0x420008")]
pub struct Attribute(AttributeName, AttributeValue);

// KMIP spec 1.0 section 2.1.1 Attribute
// See: http://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581155
#[derive(Serialize)]
#[serde(rename = "0x42000A")]
pub struct AttributeName(&'static str);

// KMIP spec 1.0 section 2.1.1 Attribute
// See: http://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581155
#[derive(Serialize)]
#[serde(rename = "0x42000B")]
pub enum AttributeValue {
    Integer(i32),
    Enumeration(u32),
}

// KMIP spec 1.0 section 2.1.8 Template-Attribute Structures
// See: http://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581162
#[derive(Serialize)]
#[serde(rename = "0x420091")]
pub struct TemplateAttribute(Vec<Attribute>);

// KMIP spec 1.0 section 3.1 Unique Identifier
// See: http://docs.oasis-open.org/kmip/spec/v1.2/os/kmip-spec-v1.2-os.html#_Toc409613482
#[derive(Deserialize, Serialize)]
#[serde(rename = "0x420094")]
pub struct UniqueIdentifier(String);

// KMIP spec 1.0 section 3.3 Object Type
// See: http://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581175
#[derive(Deserialize, Serialize)]
#[serde(rename = "0x420057")]
pub enum ObjectType {
    #[serde(rename = "0x00000002")]
    SymmetricKey,
}

// KMIP spec 1.0 section 3.4 Cryptographic Algorithm
// See: http://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581176
#[derive(Deserialize, Serialize)]
#[serde(rename = "0x420028")]
pub enum CryptographicAlgorithm {
    AES = 0x00000003,
}

// KMIP spec 1.0 section 3.6 Cryptographic Parameters
// See: http://docs.oasis-open.org/kmip/spec/v1.2/os/kmip-spec-v1.2-os.html#_Toc409613487
#[derive(Deserialize, Serialize)]
#[serde(rename = "0x420094")]
pub struct CryptographicParameters(CryptographicAlgorithm);

// KMIP spec 1.0 section 6.2 Operation
// See: http://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581240
#[derive(Deserialize, Serialize)]
pub enum Operation {
    // KMIP spec 1.0 operations
    #[serde(rename = "0x00000001")]
    Create,

    #[serde(rename = "0x00000018")]
    Query,

    // KMIP spec 1.2 operations
    #[serde(rename = "0x0000001E")]
    DiscoverVersions,

    #[serde(rename = "0x00000021")]
    Sign,
}
