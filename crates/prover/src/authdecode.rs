//! Docs
//!
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

use mpz_garble_core::ChaChaEncoder;
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

/// Returns a concrete AuthDecode prover based on the hashing algorithm used in commitments.
pub(crate) fn authdecode_prover(
    request: &Request,
    secrets: &Secrets,
    encoding_provider: &(dyn EncodingProvider + Send + Sync),
    transcript: &Transcript,
) -> impl TranscriptProver {
    let inputs: AuthdecodeInputsWithAlg = (request, secrets, encoding_provider, transcript)
        .try_into()
        .unwrap();

    match inputs.alg {
        HashAlgId::POSEIDON_CIRCOMLIB => PoseidonCircomlibProver::new(inputs.inputs),
        _ => unimplemented!(),
    }
}

/// An AuthDecode prover which proves a single range of a transcript.
pub(crate) trait TranscriptProver {
    /// Creates a new prover with the given commitment data.
    fn new(inputs: AuthdecodeInputs) -> Self;

    /// Commits to the commitment data which the prover was instantiated with.
    fn commit(&mut self) -> Result<impl serio::Serialize, ProverError>;

    /// Creates a proof based on the encodings from the seed.
    fn prove(&mut self, seed: [u8; 32]) -> Result<Proofs, ProverError>;
}

/// The prover in the AuthDecode protocol which uses
pub(crate) struct PoseidonCircomlibProver {
    commitment_data: Option<CommitmentSetWithSalt<SingleRangeIdx, Bn256F>>,
    initialized: Option<AuthDecodeProver<SingleRangeIdx, Initialized, Bn256F>>,
    committed: Option<AuthDecodeProver<SingleRangeIdx, Committed<SingleRangeIdx, Bn256F>, Bn256F>>,
    proof_generated:
        Option<AuthDecodeProver<SingleRangeIdx, ProofGenerated<SingleRangeIdx, Bn256F>, Bn256F>>,
}

impl TranscriptProver for PoseidonCircomlibProver {
    fn new(inputs: AuthdecodeInputs) -> Self {
        let prover = AuthDecodeProver::new(Box::new(
            authdecode_core::backend::halo2::prover::Prover::new(),
        ));

        Self {
            initialized: Some(prover),
            committed: None,
            proof_generated: None,
            commitment_data: Some(inputs.into()),
        }
    }

    fn commit(&mut self) -> Result<impl serio::Serialize, ProverError> {
        let prover = mem::take(&mut self.initialized).unwrap();
        let commitment = mem::take(&mut self.commitment_data).unwrap();

        let (prover, msg) = prover.commit_with_salt(commitment.into()).unwrap();

        self.committed = Some(prover);
        Ok(msg)
    }

    // TODO, ideally the return value should be Result<impl Serialize, ProverError>
    // but when I tried that, I was getting weird errors. So I punted this for later.
    fn prove(&mut self, seed: [u8; 32]) -> Result<Proofs, ProverError> {
        let encoding_provider = TranscriptEncoder::new(seed);

        let prover = mem::take(&mut self.committed).unwrap();

        let (prover, msg) = prover.prove(&encoding_provider).unwrap();
        self.proof_generated = Some(prover);

        Ok(msg)
    }
}

/// Docs.
pub(crate) struct TranscriptEncoder {
    encoder: ChaChaEncoder,
}

impl TranscriptEncoder {
    /// Docs
    pub(crate) fn new(seed: [u8; 32]) -> Self {
        Self {
            encoder: ChaChaEncoder::new(seed),
        }
    }
}

#[derive(Default)]
/// A set of commitment data with salts.
pub(crate) struct CommitmentSetWithSalt<I, F>
where
    I: IdCollection,
    F: Field,
{
    data: Vec<CommitmentData<I>>,
    salt: Vec<Vec<F>>,
}

impl<I, F> From<AuthdecodeInputs> for CommitmentSetWithSalt<I, F>
where
    I: IdCollection,
    F: Field,
{
    fn from(value: AuthdecodeInputs) -> Self {
        CommitmentSetWithSalt {
            data: vec![CommitmentData::default()],
            salt: vec![vec![F::zero()]],
        }
    }
}

#[allow(clippy::from_over_into)]
impl<I, F> Into<Vec<(CommitmentData<I>, Vec<F>)>> for CommitmentSetWithSalt<I, F>
where
    I: IdCollection,
    F: Field,
{
    fn into(self) -> Vec<(CommitmentData<I>, Vec<F>)> {
        vec![(CommitmentData::default(), vec![F::zero()])]
    }
}

impl<I> BitEncodingProvider<I> for TranscriptEncoder
where
    I: IdCollection,
{
    fn get_by_ids(
        &self,
        ids: &I,
    ) -> Result<
        authdecode_core::encodings::FullEncodings<I>,
        authdecode_core::encodings::EncodingProviderError,
    > {
        unimplemented!()
    }
}

#[derive(Clone, PartialEq, Serialize, Deserialize)]
/// An transcript index consisting of a single range.
pub(crate) struct SingleRangeIdx {
    direction: Direction,
    // A range of bytes.
    range: Range<usize>,
}

impl Default for SingleRangeIdx {
    fn default() -> Self {
        Self {
            direction: Direction::Sent,
            range: Range::default(),
        }
    }
}

impl IdCollection for SingleRangeIdx {
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

impl SingleRangeIdx {
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

#[derive(Debug, thiserror::Error)]
/// Docs
pub(crate) enum AuthdecodeError {
    #[error(transparent)]
    /// Docs
    ProtocolError(#[from] authdecode_core::prover::error::ProverError),
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
