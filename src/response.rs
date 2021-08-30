//! Deserialiation of KMIP responses.

use serde::Deserialize;

use kmip_ttlv::error::Result;

pub fn from_slice<'de, T>(bytes: &'de [u8]) -> Result<T>
where
    T: Deserialize<'de>,
{
    kmip_ttlv::de::from_slice(bytes)
}
