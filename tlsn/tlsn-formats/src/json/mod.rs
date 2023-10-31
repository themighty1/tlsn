//! Tooling for working with JSON data.

mod commit;
mod types;

pub use commit::{JsonCommitmentError, JsonCommitter};
pub use types::{Array, Bool, JsonKey, JsonValue, KeyValue, Null, Number, Object, String};

/// A visitor for JSON values.
pub trait JsonVisit {
    /// Visit a key-value pair in a JSON object.
    fn visit_key_value(&mut self, node: &KeyValue) {
        self.visit_key(&node.key);
        self.visit_value(&node.value);
    }

    /// Visit a key in a JSON object.
    fn visit_key(&mut self, _node: &JsonKey) {}

    /// Visit a JSON value.
    fn visit_value(&mut self, node: &JsonValue) {
        match node {
            JsonValue::Null(value) => self.visit_null(value),
            JsonValue::Bool(value) => self.visit_bool(value),
            JsonValue::Number(value) => self.visit_number(value),
            JsonValue::String(value) => self.visit_string(value),
            JsonValue::Array(value) => self.visit_array(value),
            JsonValue::Object(value) => self.visit_object(value),
        }
    }

    /// Visit an array value.
    fn visit_array(&mut self, node: &Array) {
        for elem in &node.elems {
            self.visit_value(elem);
        }
    }

    /// Visit an object value.
    fn visit_object(&mut self, node: &Object) {
        for kv in &node.pairs {
            self.visit_key_value(kv);
        }
    }

    /// Visit a null value.
    fn visit_null(&mut self, _node: &Null) {}

    /// Visit a boolean value.
    fn visit_bool(&mut self, _node: &Bool) {}

    /// Visit a number value.
    fn visit_number(&mut self, _node: &Number) {}

    /// Visit a string value.
    fn visit_string(&mut self, _node: &String) {}
}
