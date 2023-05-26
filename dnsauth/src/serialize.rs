//! Helper types for de-/serializing data.

use serde::de::Error as _;
use serde::ser::Error as _;
use serde::{Deserializer, Serializer};
use serde_with::base64::{Base64, Standard};
use serde_with::{Bytes, DeserializeAs, SerializeAs};
use trust_dns_proto::serialize::binary::{BinDecodable, BinEncodable};

pub(crate) struct DnsWireFormatB64;

impl<T> SerializeAs<T> for DnsWireFormatB64
where
    T: BinEncodable,
{
    fn serialize_as<S>(value: &T, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let bytes = value.to_bytes().map_err(S::Error::custom)?;
        if serializer.is_human_readable() {
            Base64::<Standard>::serialize_as(&bytes, serializer)
        } else {
            Bytes::serialize_as(&bytes, serializer)
        }
    }
}

impl<'de, T> DeserializeAs<'de, T> for DnsWireFormatB64
where
    T: for<'r> BinDecodable<'r>,
{
    fn deserialize_as<D>(deserializer: D) -> Result<T, D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes: Vec<u8> = if deserializer.is_human_readable() {
            Base64::<Standard>::deserialize_as(deserializer)?
        } else {
            Bytes::deserialize_as(deserializer)?
        };
        T::from_bytes(&bytes).map_err(D::Error::custom)
    }
}

pub(crate) struct BytesOrBase64;

impl SerializeAs<Vec<u8>> for BytesOrBase64 {
    fn serialize_as<S>(bytes: &Vec<u8>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        if serializer.is_human_readable() {
            Base64::<Standard>::serialize_as(bytes, serializer)
        } else {
            Bytes::serialize_as(bytes, serializer)
        }
    }
}

impl<'de> DeserializeAs<'de, Vec<u8>> for BytesOrBase64 {
    fn deserialize_as<D>(deserializer: D) -> Result<Vec<u8>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes: Vec<u8> = if deserializer.is_human_readable() {
            Base64::<Standard>::deserialize_as(deserializer)?
        } else {
            Bytes::deserialize_as(deserializer)?
        };
        Ok(bytes)
    }
}
