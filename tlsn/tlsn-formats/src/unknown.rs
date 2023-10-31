use std::ops::Range;

use bytes::Bytes;

use tlsn_core::{
    commitment::{TranscriptCommit, TranscriptCommitmentBuilder, TranscriptCommitmentBuilderError},
    transcript::TranscriptSubsequence,
    Direction,
};
use utils::range::RangeSet;

#[derive(Debug, thiserror::Error)]
pub enum UnknownCommitterError {
    #[error(transparent)]
    Commitment(#[from] TranscriptCommitmentBuilderError),
}

/// A span within the transcript with an unknown format.
#[derive(Debug)]
pub struct UnknownSpan {
    pub(crate) data: Bytes,
    pub(crate) range: Range<usize>,
    pub(crate) direction: Direction,
}

impl UnknownSpan {
    pub(crate) fn new(data: Bytes, range: Range<usize>, direction: Direction) -> Self {
        Self {
            data,
            range,
            direction,
        }
    }
}

impl TranscriptSubsequence for UnknownSpan {
    fn direction(&self) -> Direction {
        self.direction
    }

    fn ranges(&self) -> RangeSet<usize> {
        self.range.clone().into()
    }
}

/// Default committer for unknown spans.
#[derive(Debug)]
pub struct UnknownCommitter {}

#[allow(clippy::derivable_impls)]
impl Default for UnknownCommitter {
    fn default() -> Self {
        Self {}
    }
}

impl TranscriptCommit<UnknownSpan> for UnknownCommitter {
    type Error = UnknownCommitterError;

    fn commit(
        &mut self,
        builder: &mut TranscriptCommitmentBuilder,
        value: &UnknownSpan,
    ) -> Result<(), Self::Error> {
        // Simply commits the entire span.
        builder.commit(value).map(|_| ()).map_err(From::from)
    }
}
