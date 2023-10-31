use tlsn_core::{
    commitment::{TranscriptCommit, TranscriptCommitmentBuilder, TranscriptCommitmentBuilderError},
    transcript::TranscriptSubsequence,
};

use crate::json::{Array, Bool, JsonValue, JsonVisit, Null, Number, Object, String};

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum JsonCommitmentError {
    #[error(transparent)]
    Commitment(#[from] TranscriptCommitmentBuilderError),
}

/// Default committer for JSON values.
#[derive(Debug)]
pub struct JsonCommitter {}

#[allow(clippy::derivable_impls)]
impl Default for JsonCommitter {
    fn default() -> Self {
        Self {}
    }
}

impl TranscriptCommit<JsonValue> for JsonCommitter {
    type Error = JsonCommitmentError;

    fn commit(
        &mut self,
        builder: &mut TranscriptCommitmentBuilder,
        value: &JsonValue,
    ) -> Result<(), Self::Error> {
        let mut vis = CommitVisitor { builder, err: None };

        vis.visit_value(value);

        if let Some(err) = vis.err {
            err
        } else {
            Ok(())
        }
    }
}

struct CommitVisitor<'a> {
    builder: &'a mut TranscriptCommitmentBuilder,
    err: Option<Result<(), JsonCommitmentError>>,
}

impl<'a> CommitVisitor<'a> {
    fn commit(&mut self, value: &dyn TranscriptSubsequence) {
        if self.err.is_some() {
            return;
        }

        let res = self.builder.commit(value);

        if res.is_err() {
            println!("commit error: {:?}", value.ranges());
            self.err = Some(res.map(|_| ()).map_err(From::from));
        }
    }
}

impl<'a> JsonVisit for CommitVisitor<'a> {
    fn visit_object(&mut self, node: &Object) {
        self.commit(node);

        if node.pairs.is_empty() {
            return;
        }

        self.commit(&node.without_pairs());
        for pair in &node.pairs {
            self.commit(pair);
            self.commit(&pair.without_value());
            self.visit_value(&pair.value);
        }
    }

    fn visit_array(&mut self, node: &Array) {
        self.commit(node);

        if node.elems.is_empty() {
            return;
        }

        self.commit(&node.without_values());
        for elem in &node.elems {
            self.visit_value(elem);
        }
    }

    fn visit_bool(&mut self, node: &Bool) {
        self.commit(node);
    }

    fn visit_null(&mut self, node: &Null) {
        self.commit(node);
    }

    fn visit_number(&mut self, node: &Number) {
        self.commit(node);
    }

    fn visit_string(&mut self, node: &String) {
        self.commit(node);
    }
}
