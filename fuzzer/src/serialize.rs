use serde_with::{DeserializeAs, SerializeAs};
use std::marker::PhantomData;
use tokio::sync::{Mutex, RwLock};

/// Requires that the sync function is run using `block_in_place` or `spawn_blocking`.
pub(crate) struct SerializableMutex<T>(PhantomData<T>);

impl<T, TAs> SerializeAs<Mutex<T>> for SerializableMutex<TAs>
where
    TAs: SerializeAs<T>,
{
    fn serialize_as<S>(src: &Mutex<T>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let handle = tokio::runtime::Handle::current();
        handle.block_on(async {
            let src = src.lock().await;
            TAs::serialize_as(&src, serializer)
        })
    }
}

impl<'de, T, TAs> DeserializeAs<'de, Mutex<T>> for SerializableMutex<TAs>
where
    TAs: DeserializeAs<'de, T>,
{
    fn deserialize_as<D>(deserializer: D) -> Result<Mutex<T>, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let src = TAs::deserialize_as(deserializer)?;
        Ok(Mutex::new(src))
    }
}

/// Requires that the sync function is run using `block_in_place` or `spawn_blocking`.
pub(crate) struct SerializableRwLock<T>(PhantomData<T>);

impl<T, TAs> SerializeAs<RwLock<T>> for SerializableRwLock<TAs>
where
    TAs: SerializeAs<T>,
{
    fn serialize_as<S>(src: &RwLock<T>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let handle = tokio::runtime::Handle::current();
        handle.block_on(async {
            let src = src.read().await;
            TAs::serialize_as(&src, serializer)
        })
    }
}

impl<'de, T, TAs> DeserializeAs<'de, RwLock<T>> for SerializableRwLock<TAs>
where
    TAs: DeserializeAs<'de, T>,
{
    fn deserialize_as<D>(deserializer: D) -> Result<RwLock<T>, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let src = TAs::deserialize_as(deserializer)?;
        Ok(RwLock::new(src))
    }
}
