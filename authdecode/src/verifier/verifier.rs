use crate::{
    encodings::FullEncodings,
    prover::{prover::CommitmentDetails, InitData, VerificationData},
    verifier::{backend::Backend, error::VerifierError, state},
    Delta, Proof,
};

use crate::prover::ToInitData;
use mpz_core::utils::blake3;
use num::{BigInt, BigUint};
use std::ops::Shr;

/// Public inputs and a zk proof that needs to be verified.
#[derive(Default, Clone)]
pub struct VerificationInput {
    pub plaintext_hash: BigUint,
    pub encoding_sum_hash: BigUint,
    pub zero_sum: BigUint,
    pub deltas: Vec<Delta>,
}

/// Verifier in the AuthDecode protocol.
pub struct Verifier<T: state::VerifierState> {
    backend: Box<dyn Backend>,
    state: T,
}

impl Verifier<state::Initialized> {
    /// Creates a new verifier.
    pub fn new(backend: Box<dyn Backend>) -> Self {
        Verifier {
            backend,
            state: state::Initialized {},
        }
    }

    // TODO CommitmentDetails must be converted into their public form before sending
    //
    /// Receives the commitments and returns the data needed by the prover to check the authenticity
    /// of the encodings.
    pub fn receive_commitments(
        self,
        commitments: Vec<CommitmentDetails>,
        // Full encodings for each commitment.
        full_encodings_sets: Vec<FullEncodings>,
        // initialization data to be sent to the prover to initialize the encoding verifier
        init_data: InitData,
    ) -> Result<(Verifier<state::CommitmentReceived>, VerificationData), VerifierError> {
        if commitments.len() != full_encodings_sets.len() {
            // TODO proper error, count mismatch
            return Err(VerifierError::InternalError);
        }

        Ok((
            Verifier {
                backend: self.backend,
                state: state::CommitmentReceived {
                    commitments,
                    full_encodings_sets: full_encodings_sets.clone(),
                },
            },
            VerificationData {
                // TODO passing encodings is unnecessary
                full_encodings_sets,
                init_data,
            },
        ))

        // TODO return GC/OT randomness to the Prover
    }
}

impl Verifier<state::CommitmentReceived> {
    /// Verifies proofs corresponding to the commitments received earlier.
    /// The ordering of `proofs` and `self.state.encoding_pairs_sets` must match.
    pub fn verify(
        self,
        // Zk proofs. Their ordering corresponds to the ordering of the commitments.
        proof_sets: Vec<Proof>,
    ) -> Result<Verifier<state::VerifiedSuccessfully>, VerifierError> {
        // Get encodings for each chunk
        let chunk_encodings = self
            .state
            .full_encodings_sets
            .iter()
            .map(|set| set.clone().into_chunks(self.backend.chunk_size()))
            .flatten()
            .collect::<Vec<_>>();

        // Get commitments for each chunk
        let chunk_commitments = self
            .state
            .commitments
            .iter()
            .map(|c| c.chunk_commitments.clone())
            .flatten()
            .collect::<Vec<_>>();

        if chunk_commitments.len() != chunk_encodings.len() {
            // TODO proper error, count mismatch
            return Err(VerifierError::CustomError(
                "if chunk_com.len() != chunk_data.len() {".to_string(),
            ));
        }

        // Compute public inputs for each chunk of plaintext
        let public_inputs = chunk_commitments
            .iter()
            .zip(chunk_encodings.iter())
            .map(|(com, enc)| {
                self.create_verification_input(
                    enc.compute_deltas(),
                    enc.compute_zero_sum(),
                    com.plaintext_hash.clone(),
                    com.encoding_sum_hash.clone(),
                )
            })
            .collect::<Vec<_>>();

        // For now the halo2 backend only knows how to verify one chunk against one proof,
        // Commenting the line below and instead verifying the chunks one by one.
        // self.backend.verify(public_inputs, proof_sets)?;
        assert!(public_inputs.len() == proof_sets.len());
        self.backend.verify(public_inputs, proof_sets)?;

        Ok(Verifier {
            backend: self.backend,
            state: state::VerifiedSuccessfully {
                commitments: self.state.commitments,
            },
        })
    }

    fn break_correlation(&self, encodings: Vec<[u128; 2]>) -> Vec<[u128; 2]> {
        // Hash the encoding if it encodes bit 1, otherwise keep the encoding.
        encodings
            .iter()
            .map(|pair| {
                let mut bytes = [0u8; 16];
                bytes.copy_from_slice(&blake3(&pair[1].to_be_bytes())[0..16]);
                let one_encoding = u128::from_be_bytes(bytes);
                [pair[0], one_encoding]
            })
            .collect()
    }

    /// Truncates each encoding to the 40 bit length. Returns truncated encodings.
    ///
    /// This is an optimization. 40-bit encodings provide 40 bits of statistical security
    /// for the AuthDecode protocol.
    fn truncate(&self, encodings: Vec<[u128; 2]>) -> Vec<[u128; 2]> {
        encodings
            .iter()
            .map(|enc| [enc[0].shr(128 - 40), enc[1].shr(128 - 40)])
            .collect()
    }

    /// Computes the arithmetic sum of the 0 bit encodings.
    fn compute_zero_sum(&self, encodings: &[[u128; 2]]) -> BigUint {
        encodings
            .iter()
            .fold(BigUint::from(0u128), |acc, &x| acc + BigUint::from(x[0]))
    }

    /// Computes the arithmetic difference between a pair of encodings.
    fn compute_deltas(&self, encodings: &[[u128; 2]]) -> Vec<BigInt> {
        encodings
            .iter()
            .map(|pair| BigInt::from(pair[1]) - BigInt::from(pair[0]))
            .collect()
    }

    /// Construct public inputs for the zk circuit for each [Chunk].
    fn create_verification_input(
        &self,
        mut deltas: Vec<BigInt>,
        zero_sum: BigUint,
        pt_hash: BigUint,
        enc_hash: BigUint,
    ) -> VerificationInput {
        // For now the halo2 backend expects deltas to be padded by us. In the future we will
        // input unpadded deltas and have the backend pad them.

        // Pad the deltas with 0s to the size of the chunk
        deltas.extend(vec![0u8.into(); self.backend.chunk_size() - deltas.len()]);

        VerificationInput {
            plaintext_hash: pt_hash,
            encoding_sum_hash: enc_hash,
            zero_sum,
            deltas,
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        verifier::{
            backend::Backend,
            verifier::{VerificationInput, VerifierError},
        },
        Proof,
    };
    use num::BigUint;

    /// The verifier who implements `Verify` with the correct values
    struct CorrectTestVerifier {}
    impl Backend for CorrectTestVerifier {
        fn verify(
            &self,
            inputs: Vec<VerificationInput>,
            proofs: Vec<Proof>,
        ) -> Result<(), VerifierError> {
            Ok(())
        }

        fn chunk_size(&self) -> usize {
            3670
        }
    }
}
