use super::{DiffVisitable, KeyValueCollector};
use crate::atom::{Atom, Natsorted};
use color_eyre::eyre::Result;
use std::collections::{BTreeMap, HashMap};
use std::fmt;
use std::marker::PhantomData;
use std::ops::Index;

/// Key-Value map representing another object.
///
/// A value of this type can be created for any type implementing [`DiffVisitable`].
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(crate) struct ValueMap {
    map: HashMap<Atom, Value, nohash_hasher::BuildNoHashHasher<u32>>,
}

impl ValueMap {
    /// Create a new `ValueMap` based on a value implementing [`DiffVisitable`].
    pub(crate) fn from(dv: &impl DiffVisitable) -> Result<Self> {
        let mut map = HashMap::default();
        let mut visitor = KeyValueCollector::new(&mut map);
        dv.visit(&mut visitor)?;
        Ok(Self { map })
    }

    // /// Create a copy of this map, but only keeping the keys selected by `filter`.
    // ///
    // /// If `filter` returns `true` for a key, the key is kept in the new map.
    // pub(crate) fn filter_keys(&self, filter: impl Fn(&str) -> bool) -> Self {
    //     let map = self
    //         .map
    //         .iter()
    //         .filter(|(k, _)| filter(k.as_ref()))
    //         .map(|(k, v)| (k.clone(), v.clone()))
    //         .collect();
    //     Self { map }
    // }

    fn get(&self, key: &Atom) -> Option<&Value> {
        self.map.get(key)
    }

    /// Return the same data, but sorted based on the key
    pub(crate) fn as_sorted(&self) -> BTreeMap<Natsorted, &Value> {
        self.map
            .iter()
            .map(|(k, v)| (Natsorted(k.clone()), v))
            .collect()
    }
}

impl Index<String> for ValueMap {
    type Output = Value;

    fn index(&self, key: String) -> &Self::Output {
        self.get(&Atom::from(key)).unwrap_or(&Value::Missing)
    }
}

impl Index<Atom> for ValueMap {
    type Output = Value;

    fn index(&self, key: Atom) -> &Self::Output {
        self.get(&key).unwrap_or(&Value::Missing)
    }
}

impl Index<&Atom> for ValueMap {
    type Output = Value;

    fn index(&self, key: &Atom) -> &Self::Output {
        self.get(key).unwrap_or(&Value::Missing)
    }
}

impl Index<Natsorted> for ValueMap {
    type Output = Value;

    fn index(&self, key: Natsorted) -> &Self::Output {
        self.get(&key.0).unwrap_or(&Value::Missing)
    }
}

impl Index<&Natsorted> for ValueMap {
    type Output = Value;

    fn index(&self, key: &Natsorted) -> &Self::Output {
        self.get(&key.0).unwrap_or(&Value::Missing)
    }
}

impl<'a> IntoIterator for &'a ValueMap {
    type Item = (&'a Atom, &'a Value);
    type IntoIter = std::collections::hash_map::Iter<'a, Atom, Value>;

    fn into_iter(self) -> Self::IntoIter {
        self.map.iter()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) enum Value {
    String(Atom),
    Integer(i64),
    Boolean(bool),
    Missing,
}

impl Value {
    pub(crate) fn as_str(&self) -> Option<&str> {
        match self {
            Value::String(s) => Some(s.as_ref()),
            _ => None,
        }
    }

    pub(crate) fn as_i64(&self) -> Option<i64> {
        match self {
            Value::Integer(i) => Some(*i),
            _ => None,
        }
    }

    // pub(crate) fn as_bool(&self) -> Option<bool> {
    //     match self {
    //         Value::Boolean(b) => Some(*b),
    //         _ => None,
    //     }
    // }

    pub(crate) fn is_missing(&self) -> bool {
        matches!(self, Value::Missing)
    }

    // pub(crate) fn is_present(&self) -> bool {
    //     !self.is_missing()
    // }
}

impl fmt::Display for Value {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Value::String(s) => s.fmt(f),
            Value::Integer(i) => i.fmt(f),
            Value::Boolean(b) => b.fmt(f),
            Value::Missing => "<missing>".fmt(f),
        }
    }
}

impl PartialEq<str> for Value {
    fn eq(&self, other: &str) -> bool {
        match self {
            Value::String(s) => s == other,
            _ => false,
        }
    }
}

impl PartialEq<&str> for Value {
    fn eq(&self, other: &&str) -> bool {
        match self {
            Value::String(s) => s == *other,
            _ => false,
        }
    }
}

impl PartialEq<Atom> for Value {
    fn eq(&self, other: &Atom) -> bool {
        match self {
            Value::String(s) => s == other,
            _ => false,
        }
    }
}

impl PartialEq<&Atom> for Value {
    fn eq(&self, other: &&Atom) -> bool {
        match self {
            Value::String(s) => s == *other,
            _ => false,
        }
    }
}

impl PartialEq<i64> for Value {
    fn eq(&self, other: &i64) -> bool {
        match self {
            Value::Integer(i) => *i == *other,
            _ => false,
        }
    }
}

impl PartialEq<bool> for Value {
    fn eq(&self, other: &bool) -> bool {
        match self {
            Value::Boolean(b) => *b == *other,
            _ => false,
        }
    }
}

impl PartialOrd<i64> for Value {
    fn partial_cmp(&self, other: &i64) -> Option<std::cmp::Ordering> {
        match *self {
            Value::Integer(i) => i.partial_cmp(other),
            _ => None,
        }
    }
}

impl serde::Serialize for Value {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        if serializer.is_human_readable() {
            match self {
                Value::String(s) => s.serialize(serializer),
                Value::Integer(i) => i.serialize(serializer),
                Value::Boolean(b) => b.serialize(serializer),
                Value::Missing => serializer.serialize_none(),
            }
        } else {
            match self {
                Value::String(s) => {
                    serializer.serialize_newtype_variant("Value", 0u32, "String", s)
                }
                Value::Integer(i) => {
                    serializer.serialize_newtype_variant("Value", 1u32, "Integer", i)
                }
                Value::Boolean(b) => {
                    serializer.serialize_newtype_variant("Value", 2u32, "Boolean", b)
                }
                Value::Missing => serializer.serialize_unit_variant("Value", 3u32, "Missing"),
            }
        }
    }
}

impl<'de> serde::Deserialize<'de> for Value {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct ValueEnumVisitor<'de> {
            lifetime: PhantomData<&'de ()>,
        }
        impl<'de> serde::de::Visitor<'de> for ValueEnumVisitor<'de> {
            type Value = Value;
            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("enum Value")
            }
            fn visit_enum<A>(self, data: A) -> Result<Self::Value, A::Error>
            where
                A: serde::de::EnumAccess<'de>,
            {
                use serde::de::VariantAccess;

                #[derive(serde::Deserialize)]
                #[serde(field_identifier)]
                enum Field {
                    String,
                    Integer,
                    Boolean,
                    Missing,
                }

                match serde::de::EnumAccess::variant(data)? {
                    (Field::String, variant) => variant.newtype_variant().map(Value::String),
                    (Field::Integer, variant) => variant.newtype_variant().map(Value::Integer),
                    (Field::Boolean, variant) => variant.newtype_variant().map(Value::Boolean),
                    (Field::Missing, variant) => variant.unit_variant().map(|()| Value::Missing),
                }
            }
        }
        const VARIANTS: &[&str] = &["String", "Integer", "Boolean", "Missing"];

        struct ValueUntaggedVisitor;

        impl<'de> serde::de::Visitor<'de> for ValueUntaggedVisitor {
            type Value = Value;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a string, integer, boolean, or null")
            }

            fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                Ok(Value::Integer(value))
            }

            fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                Ok(Value::Integer(value as i64))
            }

            fn visit_bool<E>(self, value: bool) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                Ok(Value::Boolean(value))
            }

            fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                Ok(Value::String(Atom::from(value)))
            }

            fn visit_string<E>(self, value: String) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                Ok(Value::String(Atom::from(value)))
            }

            fn visit_none<E>(self) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                Ok(Value::Missing)
            }

            fn visit_unit<E>(self) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                Ok(Value::Missing)
            }
        }

        if deserializer.is_human_readable() {
            deserializer.deserialize_any(ValueUntaggedVisitor)
        } else {
            deserializer.deserialize_enum(
                "Value",
                VARIANTS,
                ValueEnumVisitor {
                    lifetime: PhantomData,
                },
            )
        }
    }
}
