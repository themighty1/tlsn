use std::ops::{Index, Range};

use spansy::{Span, Spanned};
use tlsn_core::{transcript::TranscriptSubsequence, Direction};
use utils::range::{RangeDifference, RangeSet};

use crate::GenericSubsequence;

/// A JSON value.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum JsonValue {
    /// A null value.
    Null(Null),
    /// A boolean value.
    Bool(Bool),
    /// A number value.
    Number(Number),
    /// A string value.
    String(String),
    /// An array value.
    Array(Array),
    /// An object value.
    Object(Object),
}

impl JsonValue {
    pub(crate) fn from_spansy(value: spansy::json::JsonValue, direction: Direction) -> Self {
        match value {
            spansy::json::JsonValue::Null(v) => JsonValue::Null(Null {
                span: v.span().clone(),
                direction,
            }),
            spansy::json::JsonValue::Bool(v) => JsonValue::Bool(Bool {
                span: v.span().clone(),
                direction,
            }),
            spansy::json::JsonValue::Number(v) => JsonValue::Number(Number {
                span: v.span().clone(),
                direction,
            }),
            spansy::json::JsonValue::String(v) => JsonValue::String(String {
                span: v.span().clone(),
                direction,
            }),
            spansy::json::JsonValue::Array(v) => JsonValue::Array(Array {
                span: v.span().clone(),
                direction,
                elems: v
                    .elems
                    .into_iter()
                    .map(|v| JsonValue::from_spansy(v, direction))
                    .collect(),
            }),
            spansy::json::JsonValue::Object(v) => JsonValue::Object(Object {
                span: v.span().clone(),
                direction,
                pairs: v
                    .elems
                    .into_iter()
                    .map(|kv| KeyValue::from_spansy(kv, direction))
                    .collect(),
            }),
        }
    }

    /// Returns the value as a string.
    pub fn as_str(&self) -> &str {
        match self {
            JsonValue::Null(v) => v.span.as_ref(),
            JsonValue::Bool(v) => v.span.as_ref(),
            JsonValue::Number(v) => v.span.as_ref(),
            JsonValue::String(v) => v.span.as_ref(),
            JsonValue::Array(v) => v.span.as_ref(),
            JsonValue::Object(v) => v.span.as_ref(),
        }
    }

    /// Returns the range in the transcript corresponding to the value.
    pub fn range(&self) -> Range<usize> {
        match self {
            JsonValue::Null(v) => v.span.range(),
            JsonValue::Bool(v) => v.span.range(),
            JsonValue::Number(v) => v.span.range(),
            JsonValue::String(v) => v.span.range(),
            JsonValue::Array(v) => v.span.range(),
            JsonValue::Object(v) => v.span.range(),
        }
    }

    /// Get a reference to the value using the given path.
    pub fn path(&self, path: &str) -> Option<&JsonValue> {
        match self {
            JsonValue::Null(_) => None,
            JsonValue::Bool(_) => None,
            JsonValue::Number(_) => None,
            JsonValue::String(_) => None,
            JsonValue::Array(v) => v.path(path),
            JsonValue::Object(v) => v.path(path),
        }
    }
}

impl AsRef<str> for JsonValue {
    fn as_ref(&self) -> &str {
        match self {
            JsonValue::Null(v) => v.span.as_ref(),
            JsonValue::Bool(v) => v.span.as_ref(),
            JsonValue::Number(v) => v.span.as_ref(),
            JsonValue::String(v) => v.span.as_ref(),
            JsonValue::Array(v) => v.span.as_ref(),
            JsonValue::Object(v) => v.span.as_ref(),
        }
    }
}

impl TranscriptSubsequence for JsonValue {
    fn direction(&self) -> Direction {
        match self {
            JsonValue::Null(v) => v.direction,
            JsonValue::Bool(v) => v.direction,
            JsonValue::Number(v) => v.direction,
            JsonValue::String(v) => v.direction,
            JsonValue::Array(v) => v.direction,
            JsonValue::Object(v) => v.direction,
        }
    }

    fn ranges(&self) -> utils::range::RangeSet<usize> {
        match self {
            JsonValue::Null(v) => v.ranges(),
            JsonValue::Bool(v) => v.ranges(),
            JsonValue::Number(v) => v.ranges(),
            JsonValue::String(v) => v.ranges(),
            JsonValue::Array(v) => v.ranges(),
            JsonValue::Object(v) => v.ranges(),
        }
    }
}

/// A JSON object.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Object {
    pub(crate) span: Span<str>,
    pub(crate) direction: Direction,

    /// The key-value pairs of the object.
    pub pairs: Vec<KeyValue>,
}

impl Object {
    /// Returns the key value pair with the provided key.
    pub fn get(&self, key: &str) -> Option<&KeyValue> {
        self.pairs.iter().find(|kv| kv.key.span == key)
    }

    /// Get a reference to the value using the given path.
    pub fn path(&self, path: &str) -> Option<&JsonValue> {
        let mut path_iter = path.split('.');

        let key = path_iter.next()?;

        let KeyValue { value, .. } = self.pairs.iter().find(|kv| kv.key.span == key)?;

        if path_iter.next().is_some() {
            value.path(&path[key.len() + 1..])
        } else {
            Some(value)
        }
    }

    /// Returns the object without any key value pairs.
    pub fn without_pairs(&self) -> GenericSubsequence {
        let mut ranges: RangeSet<usize> = self.span.range().into();
        for kv in &self.pairs {
            ranges = ranges.difference(&kv.span.range());
        }

        GenericSubsequence {
            direction: self.direction,
            ranges,
        }
    }
}

impl TranscriptSubsequence for Object {
    fn direction(&self) -> Direction {
        self.direction
    }

    fn ranges(&self) -> utils::range::RangeSet<usize> {
        self.span.range().into()
    }
}

/// A JSON array.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Array {
    pub(crate) span: Span<str>,
    pub(crate) direction: Direction,

    /// The elements of the array.
    pub elems: Vec<JsonValue>,
}

impl Array {
    /// Returns the value at the given index of the array.
    pub fn get(&self, index: usize) -> Option<&JsonValue> {
        self.elems.get(index)
    }

    /// Get a reference to the value using the given path.
    pub fn path(&self, path: &str) -> Option<&JsonValue> {
        let mut path_iter = path.split('.');

        let key = path_iter.next()?;
        let idx = key.parse::<usize>().ok()?;

        let value = self.elems.get(idx)?;

        if path_iter.next().is_some() {
            value.path(&path[key.len() + 1..])
        } else {
            Some(value)
        }
    }

    /// Returns the array without any values.
    pub fn without_values(&self) -> GenericSubsequence {
        let mut ranges: RangeSet<usize> = self.span.range().into();
        for elem in &self.elems {
            ranges = ranges.difference(&elem.range());
        }

        GenericSubsequence {
            direction: self.direction,
            ranges,
        }
    }
}

impl Index<usize> for Array {
    type Output = JsonValue;

    /// Returns the value at the given index of the array.
    ///
    /// # Panics
    ///
    /// Panics if the index is out of bounds.
    fn index(&self, index: usize) -> &Self::Output {
        self.elems.get(index).expect("index is in bounds")
    }
}

impl TranscriptSubsequence for Array {
    fn direction(&self) -> Direction {
        self.direction
    }

    fn ranges(&self) -> utils::range::RangeSet<usize> {
        self.span.range().into()
    }
}

/// A JSON key-value pair.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct KeyValue {
    pub(crate) span: Span<str>,
    pub(crate) direction: Direction,

    /// The key of the pair.
    pub key: JsonKey,
    /// The value of the pair.
    pub value: JsonValue,
}

impl KeyValue {
    pub(crate) fn from_spansy(kv: spansy::json::KeyValue, direction: Direction) -> Self {
        Self {
            span: kv.span().clone(),
            direction,
            key: JsonKey {
                span: kv.key.span().clone(),
                direction,
            },
            value: JsonValue::from_spansy(kv.value, direction),
        }
    }

    /// Returns the key value pair without the value.
    pub fn without_value(&self) -> GenericSubsequence {
        let mut ranges: RangeSet<usize> = self.span.range().into();
        ranges = ranges.difference(&self.value.range());

        GenericSubsequence {
            direction: self.direction,
            ranges,
        }
    }
}

impl TranscriptSubsequence for KeyValue {
    fn direction(&self) -> Direction {
        self.direction
    }

    fn ranges(&self) -> utils::range::RangeSet<usize> {
        self.span.range().into()
    }
}

/// A JSON key.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct JsonKey {
    pub(crate) span: Span<str>,
    pub(crate) direction: Direction,
}

impl TranscriptSubsequence for JsonKey {
    fn direction(&self) -> Direction {
        self.direction
    }

    fn ranges(&self) -> utils::range::RangeSet<usize> {
        self.span.range().into()
    }
}

/// A null value.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Null {
    pub(crate) span: Span<str>,
    pub(crate) direction: Direction,
}

impl TranscriptSubsequence for Null {
    fn direction(&self) -> Direction {
        self.direction
    }

    fn ranges(&self) -> utils::range::RangeSet<usize> {
        self.span.range().into()
    }
}

/// A boolean value.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Bool {
    pub(crate) span: Span<str>,
    pub(crate) direction: Direction,
}

impl TranscriptSubsequence for Bool {
    fn direction(&self) -> Direction {
        self.direction
    }

    fn ranges(&self) -> utils::range::RangeSet<usize> {
        self.span.range().into()
    }
}

/// A number value.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Number {
    pub(crate) span: Span<str>,
    pub(crate) direction: Direction,
}

impl TranscriptSubsequence for Number {
    fn direction(&self) -> Direction {
        self.direction
    }

    fn ranges(&self) -> utils::range::RangeSet<usize> {
        self.span.range().into()
    }
}

/// A string value.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct String {
    pub(crate) span: Span<str>,
    pub(crate) direction: Direction,
}

impl TranscriptSubsequence for String {
    fn direction(&self) -> Direction {
        self.direction
    }

    fn ranges(&self) -> utils::range::RangeSet<usize> {
        self.span.range().into()
    }
}
