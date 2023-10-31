//! Tools for selective disclosure of various formats.
//!
//! # Warning
//!
//! This library is not yet ready for production use, and should *NOT* be considered secure.
//!
//! At present, this library does not verify that redacted data does not contain control characters which can
//! be used by a malicious prover to cheat.

//#![deny(missing_docs, unreachable_pub, unused_must_use)]
#![deny(clippy::all)]
#![forbid(unsafe_code)]

use tlsn_core::{transcript::TranscriptSubsequence, Direction};
use utils::range::RangeSet;

pub mod http;
pub mod json;
mod unknown;

/// A generic subsequence of a transcript not specific to any format.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GenericSubsequence {
    direction: Direction,
    ranges: RangeSet<usize>,
}

impl GenericSubsequence {
    /// Create a new generic subsequence.
    pub fn new(direction: Direction, ranges: RangeSet<usize>) -> Self {
        Self { direction, ranges }
    }
}

impl TranscriptSubsequence for GenericSubsequence {
    fn direction(&self) -> Direction {
        self.direction
    }

    fn ranges(&self) -> RangeSet<usize> {
        self.ranges.clone()
    }
}
