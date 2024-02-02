use crate::{prover::error::ProverError, Proof, ProofInput};
use num::{BigInt, BigUint};

/// A trait for zk proof generation backend.
pub trait Backend {
    /// Creates a commitment to the plaintext, padding it if needed.
    /// Creates a commitment to the sum of encodings.
    /// Commitments are salted.
    /// Returns the commitment to the plaintext, the commitment to the sum and the salt (one salt
    /// is used in both commitments).
    ///
    /// TODO using the same salt is a micro-optimization not worth pursuing,
    /// we should use separate salts for each commitment. This requires modifying the circuit.
    ///
    fn commit(
        &self,
        plaintext: Vec<bool>,
        encodings_sum: BigUint,
    ) -> Result<(BigUint, BigUint, BigUint), ProverError>;

    /// Given the `input` to the AuthDecode zk circuit, generates and returns `Proof`(s)
    fn prove(&self, input: Vec<ProofInput>) -> Result<Vec<Proof>, ProverError>;

    /// How many bits of [Plaintext] can fit into one [Chunk]. This does not
    /// include the [Salt] of the hash - which takes up the remaining least bits
    /// of the last field element of each chunk.
    fn chunk_size(&self) -> usize;
}
