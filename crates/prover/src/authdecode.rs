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

use authdecode_single_range::SingleRange;

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
    fn prove(&mut self, seed: [u8; 32]) -> Result<impl serio::Serialize, ProverError>;
}

/// The prover in the AuthDecode protocol which uses
pub(crate) struct PoseidonCircomlibProver {
    commitment_data: Option<CommitmentSetWithSalt<SingleRange, Bn256F>>,
    initialized: Option<AuthDecodeProver<SingleRange, Initialized, Bn256F>>,
    committed: Option<AuthDecodeProver<SingleRange, Committed<SingleRange, Bn256F>, Bn256F>>,
    proof_generated:
        Option<AuthDecodeProver<SingleRange, ProofGenerated<SingleRange, Bn256F>, Bn256F>>,
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

    // TODO, I was getting errors when using `impl serde::Serialize`, so I had to use
    // `impl serio::Serialize`
    fn prove(&mut self, seed: [u8; 32]) -> Result<impl serio::Serialize, ProverError> {
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

#[derive(Debug, thiserror::Error)]
/// Docs
pub(crate) enum AuthdecodeError {
    #[error(transparent)]
    /// Docs
    ProtocolError(#[from] authdecode_core::prover::error::ProverError),
}
