use serde::Deserialize;

use krill_kmip_ttlv::error::Result;

pub fn from_slice<'de, T>(bytes: &'de [u8]) -> Result<T>
where
    T: Deserialize<'de>,
{
    krill_kmip_ttlv::de::from_slice(bytes)
}
