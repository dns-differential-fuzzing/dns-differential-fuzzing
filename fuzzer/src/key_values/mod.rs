//! Provide types and implementations for the [`ValueMap`].
//!
//! This module contains all code to create and manipulate [`ValueMap`]s.
//! One part is the [`ValueMap`] itself and the matching [`Value`] type.
//! The other part is the [`DiffVisitable`] trait, which is the trait that allows the conversion.

mod valuemap;
mod visit_impls;

use crate::atom::Atom;
use color_eyre::eyre::Result;
use std::collections::HashMap;
use std::fmt::Display;
pub(crate) use valuemap::{Value, ValueMap};

/// Implemented by the collector.
///
/// Types will call either [`visit_value`] or [`visit_scope`] depending on if the type is a primitive or multiple sub-values are possible.
pub(crate) trait Visitor {
    type ScopeVisitor: Visitor;

    fn visit_string(&mut self, value: impl AsRef<str>) -> Result<()>;
    fn visit_integer(&mut self, value: impl Into<i64>) -> Result<()>;
    fn visit_bool(&mut self, value: bool) -> Result<()>;

    fn visit_scope<S, V>(&mut self, scope: &S, value: &V) -> Result<()>
    where
        S: Display + ?Sized,
        V: DiffVisitable + ?Sized;
}

/// Implemented by a type and determines which values are collected.
///
/// A struct should usually call [`Visitor::visit_scope`] for each field of the struct.
/// Simple types like [`i32`] or [`String`] should use [`Visitor::visit_value`] to emit themself as a value.
pub(crate) trait DiffVisitable {
    fn visit<V>(&self, visitor: &mut V) -> Result<()>
    where
        V: Visitor + ?Sized;
}

/// Simple collector gathering all key-values pairs in order
///
/// Keys are generated dot separated like `.bar.baz`.
struct KeyValueCollector<'a> {
    scope: String,
    values: &'a mut HashMap<Atom, Value, nohash_hasher::BuildNoHashHasher<u32>>,
}

impl<'a> KeyValueCollector<'a> {
    pub(crate) fn new(
        map: &'a mut HashMap<Atom, Value, nohash_hasher::BuildNoHashHasher<u32>>,
    ) -> Self {
        Self {
            scope: String::new(),
            values: map,
        }
    }
}

impl Visitor for KeyValueCollector<'_> {
    type ScopeVisitor = Self;

    fn visit_string(&mut self, value: impl AsRef<str>) -> Result<()> {
        self.values.insert(
            Atom::from(&*self.scope),
            Value::String(Atom::from(value.as_ref())),
        );
        Ok(())
    }

    fn visit_integer(&mut self, value: impl Into<i64>) -> Result<()> {
        self.values
            .insert(Atom::from(&*self.scope), Value::Integer(value.into()));
        Ok(())
    }

    fn visit_bool(&mut self, value: bool) -> Result<()> {
        self.values
            .insert(Atom::from(&*self.scope), Value::Boolean(value));
        Ok(())
    }

    fn visit_scope<S, V>(&mut self, scope: &S, value: &V) -> Result<()>
    where
        S: Display + ?Sized,
        V: DiffVisitable + ?Sized,
    {
        let mut subvisitor = KeyValueCollector {
            scope: format!("{}.{}", self.scope, scope),
            values: self.values,
        };
        value.visit(&mut subvisitor)?;

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use pretty_assertions::assert_eq;

    struct Foo {
        a: i32,
        b: bool,
        s: String,
        bar: Bar,
    }

    struct Bar {
        c: i32,
        v: Vec<i32>,
    }

    impl DiffVisitable for Foo {
        fn visit<V>(&self, visitor: &mut V) -> Result<()>
        where
            V: Visitor + ?Sized,
        {
            let Self { a, b, s, bar } = self;
            super::visit_impls::visit_fields!(visitor, a b s bar);
            Ok(())
        }
    }

    impl DiffVisitable for Bar {
        fn visit<V>(&self, visitor: &mut V) -> Result<()>
        where
            V: Visitor + ?Sized,
        {
            let Self { c, v } = self;
            super::visit_impls::visit_fields!(visitor,c v);
            Ok(())
        }
    }

    #[test]
    fn test_key_value_collecting() {
        let mut expected = HashMap::default();
        expected.extend(
            [
                (".a", Value::Integer(1)),
                (".b", Value::Boolean(true)),
                (".s", Value::String(Atom::from("hello"))),
                (".bar.c", Value::Integer(2)),
                (".bar.v.#count", Value::Integer(3)),
                (".bar.v.0", Value::Integer(3)),
                (".bar.v.1", Value::Integer(4)),
                (".bar.v.2", Value::Integer(5)),
            ]
            .into_iter()
            .map(|(k, v)| (Atom::from(k), v)),
        );

        let foo = Foo {
            a: 1,
            b: true,
            s: "hello".to_string(),
            bar: Bar {
                c: 2,
                v: vec![3, 4, 5],
            },
        };
        let mut key_values = HashMap::default();
        let mut visitor = KeyValueCollector::new(&mut key_values);
        foo.visit(&mut visitor).unwrap();

        assert_eq!(expected, key_values);
    }
}
