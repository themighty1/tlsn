//! Convenience types for running AuthDecode over data contained in a single range.

use core::ops::Range;
use serde::{Deserialize, Serialize};
use std::mem;

use authdecode_core::{
    backend::{
        halo2::Bn256F,
        traits::{Field, ProverBackend},
    },
    encodings::EncodingProvider as BitEncodingProvider,
    id::{Id, IdCollection},
    msgs::{Commit, Message, Proofs},
    prover::{
        commitment::CommitmentData,
        error::ProverError,
        state::{Committed, Initialized, ProofGenerated},
    },
    Prover as AuthDecodeProver,
};

use itybity::{FromBitIterator, ToBits};

use tlsn_core::{
    hash::{Blinder, HashAlgId},
    request::Request,
    transcript::{
        authdecode::{AuthdecodeInputs, AuthdecodeInputsWithAlg},
        encoding::EncodingProvider,
        Direction, Idx, Transcript,
    },
    Secrets,
};

#[derive(Clone, PartialEq, Serialize, Deserialize)]
/// A single byterange of data with a corresponding direction.
pub struct SingleRange {
    /// The direction in which the data was transmitted.
    direction: Direction,
    /// A range of bytes.
    range: Range<usize>,
}

impl Default for SingleRange {
    fn default() -> Self {
        Self {
            direction: Direction::Sent,
            range: Range::default(),
        }
    }
}

impl IdCollection for SingleRange {
    fn drain_front(&mut self, count: usize) -> Self {
        debug_assert!(count % 8 == 0);
        let byte_count = count / 8;

        let drain_count = if byte_count >= self.range.len() {
            self.range.len()
        } else {
            byte_count
        };

        let drained = self.range.start..self.range.start + drain_count;
        let remaining = self.range.start + drain_count..self.range.end;

        self.range = remaining;

        Self {
            direction: self.direction,
            range: drained,
        }
    }

    fn id(&self, index: usize) -> authdecode_core::id::Id {
        self.encode_bit_id(index)
    }

    fn ids(&self) -> Vec<Id> {
        (0..self.range.len())
            .map(|idx| self.id(idx))
            .collect::<Vec<_>>()
    }

    fn is_empty(&self) -> bool {
        self.len() == 0
    }

    fn len(&self) -> usize {
        self.range.len()
    }

    fn new_from_iter<I: IntoIterator<Item = Self>>(iter: I) -> Self {
        unimplemented!()
    }
}

impl SingleRange {
    /// Encodes the direction and the bit's `offset` in the transcript into an id.
    ///
    /// # Panics
    ///
    /// Panics if `offset` > 2^32.
    fn encode_bit_id(&self, offset: usize) -> Id {
        // All values are encoded in MSB-first order.
        // The first bit encodes the direction, the remaining bits encode the offset.
        let mut id = vec![false; 64];
        let encoded_direction = if self.direction == Direction::Sent {
            [false]
        } else {
            [true]
        };

        assert!(offset < (1 << 32));

        let encoded_offset = (offset as u32).to_be_bytes().to_msb0_vec();

        id[0..1].copy_from_slice(&encoded_direction);
        id[1 + (63 - encoded_offset.len())..].copy_from_slice(&encoded_offset);

        Id(u64::from_be_bytes(
            boolvec_to_u8vec(&id).try_into().unwrap(),
        ))
    }
}

/// Converts bits in MSB-first order into BE bytes. The bits will be internally left-padded
/// with zeroes to the nearest multiple of 8.
fn boolvec_to_u8vec(bv: &[bool]) -> Vec<u8> {
    // Reverse to lsb0 since `itybity` can only pad the rightmost bits.
    let mut b = Vec::<u8>::from_lsb0_iter(bv.iter().rev().copied());
    // Reverse to get big endian byte order.
    b.reverse();
    b
}
