use std::ops::{Shl, Shr};

use crate::{
    prover::{backend::Backend, error, error::ProverError, state},
    utils::u8vec_to_boolvec,
    Delta, LabelSumHash, PlaintextHash, Salt, ZeroSum,
};

use mpz_core::utils::blake3;
use num::{BigInt, BigUint};

use super::EncodingsVerifier;

/// Details pertaining to an AuthDecode commitment to a single chunk of the plaintext.
#[derive(Clone, Default)]
pub struct ChunkCommitmentDetails {
    /// The chunk of plaintext to commit to.
    pub plaintext: Vec<bool>,
    pub plaintext_hash: BigUint,
    pub plaintext_salt: BigUint,

    // The uncorrelated and truncated encodings to commit to.
    pub encodings: Vec<u128>,
    pub encodings_sum: BigUint,
    pub encodings_sum_hash: BigUint,
    pub encodings_sum_salt: BigUint,
}

/// Details pertaining to an AuthDecode commitment to plaintext of arbitrary length.
#[derive(Clone, Default)]
pub struct CommitmentDetails {
    /// Commitments to each chunk of the plaintext
    pub chunk_commitments: Vec<ChunkCommitmentDetails>,
}

// Public and private inputs to the zk circuit
#[derive(Clone, Default)]
pub struct ProofInput {
    // Public
    pub plaintext_hash: PlaintextHash,
    pub label_sum_hash: LabelSumHash,
    pub sum_of_zero_labels: ZeroSum,
    pub deltas: Vec<Delta>,

    // Private
    pub plaintext: Vec<bool>,
    pub salt: Salt,
}

/// Prover in the AuthDecode protocol.
pub struct Prover<T: state::ProverState> {
    backend: Box<dyn Backend>,
    pub state: T,
}

impl Prover<state::Initialized> {
    /// Creates a new prover.
    pub fn new(backend: Box<dyn Backend>) -> Self {
        Prover {
            backend,
            state: state::Initialized {},
        }
    }

    /// Creates a commitment to (potentially multiple sets of) the `plaintext` and a commitment
    /// to the `encodings` of the `plaintext` bits.
    pub fn commit(
        self,
        plaintext_and_encodings: Vec<(Vec<u8>, Vec<u128>)>,
    ) -> Result<Prover<state::Committed>, ProverError> {
        let commitments = plaintext_and_encodings
            .iter()
            .map(|set| {
                let plaintext = set.0.clone();
                let encodings = set.1.clone();
                if plaintext.is_empty() {
                    return Err(ProverError::EmptyPlaintext);
                }

                let plaintext = u8vec_to_boolvec(&plaintext);

                if plaintext.len() != encodings.len() {
                    return Err(ProverError::Mismatch);
                }

                // Chunk up the plaintext and encodings and commit to them.
                // Returning the hash and the salt.
                let chunk_commitments = plaintext
                    .chunks(self.backend.chunk_size())
                    .zip(encodings.chunks(self.backend.chunk_size()))
                    .map(|(plaintext, encodings)| {
                        // Break encoding correlation, truncate them and compute their sum.
                        let encodings =
                            self.break_correlation(encodings.to_vec(), plaintext.to_vec());
                        let encodings = self.truncate(encodings);
                        let sum = self.compute_encoding_sum(encodings.to_vec());

                        let (plaintext_hash, encodings_hash, salt) =
                            self.backend.commit(plaintext.to_vec(), sum.clone())?;
                        Ok(ChunkCommitmentDetails {
                            plaintext: plaintext.to_vec(),
                            plaintext_hash,
                            plaintext_salt: salt.clone(),
                            encodings,
                            encodings_sum: sum,
                            encodings_sum_hash: encodings_hash,
                            encodings_sum_salt: salt,
                        })
                    })
                    .collect::<Result<Vec<ChunkCommitmentDetails>, ProverError>>()?;
                Ok(CommitmentDetails { chunk_commitments })
            })
            .collect::<Result<Vec<CommitmentDetails>, ProverError>>()?;

        Ok(Prover {
            backend: self.backend,
            state: state::Committed { commitments },
        })
    }

    /// Breaks the correlation which each bit encoding has with its complementary encoding.
    /// Returns uncorrelated encodings.
    ///
    /// In half-gates garbling scheme, each pair of bit encodings is correlated by a global delta.
    /// It is essential for the security of the AuthDecode protocol that this correlation is removed.   
    fn break_correlation(&self, encodings: Vec<u128>, plaintext: Vec<bool>) -> Vec<u128> {
        // Hash the encoding if it encodes bit 1, otherwise keep the encoding.
        encodings
            .iter()
            .zip(plaintext.iter())
            .map(|(encoding, bit)| {
                if *bit {
                    let mut bytes = [0u8; 16];
                    bytes.copy_from_slice(&blake3(&encoding.to_be_bytes())[0..16]);
                    u128::from_be_bytes(bytes)
                } else {
                    *encoding
                }
            })
            .collect()
    }

    /// Truncates each encoding to the 40 bit length. Returns truncated encodings.
    ///
    /// This is an optimization. 40-bit encodings provide 40 bits of statistical security
    /// for the AuthDecode protocol.
    fn truncate(&self, encodings: Vec<u128>) -> Vec<u128> {
        encodings.iter().map(|enc| enc.shr(128 - 40)).collect()
    }

    /// Computes the arithmetic sum of the encodings.
    fn compute_encoding_sum(&self, encodings: Vec<u128>) -> BigUint {
        encodings
            .iter()
            .fold(BigUint::from(0u128), |acc, &x| acc + BigUint::from(x))
    }
}

impl Prover<state::Committed> {
    /// Checks the authenticity of the peer's encodings used to create commitments.
    ///
    /// The verifier encodings must be in the same order in which the commitments were made.

    pub fn check(
        self,
        peer_encodings: Vec<[u128; 2]>,
        verifier: impl EncodingsVerifier,
    ) -> Result<Prover<state::Checked>, ProverError> {
        // Verify that the encodings are authentic.
        verifier.verify(peer_encodings.clone())?;

        // Collect all plaintext and all encodings from all commitments.
        let mut plaintext: Vec<bool> = Vec::new();
        let mut encodings: Vec<u128> = Vec::new();
        for comm in &self.state.commitments {
            for chunk in &comm.chunk_commitments {
                plaintext.extend(chunk.plaintext.clone());
                encodings.extend(chunk.encodings.clone());
            }
        }

        if encodings.len() != peer_encodings.len() {
            // TODO proper error
            return Err(ProverError::InternalError);
        }

        let verifier_encodings = self.break_correlation(peer_encodings);
        let verifier_encodings = self.truncate(verifier_encodings);

        let selected: Vec<u128> = crate::utils::choose(&verifier_encodings, &plaintext);

        if selected != encodings {
            // TODO proper error, check failed
            return Err(ProverError::InternalError);
        }

        Ok(Prover {
            backend: self.backend,
            state: state::Checked {
                commitments: self.state.commitments,
                encoding_pairs: verifier_encodings,
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
                [pair[0], u128::from_be_bytes(bytes)]
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
}

impl Prover<state::Checked> {
    /// Generates a zk proof(s).
    pub fn prove(self) -> Result<Prover<state::ProofCreated>, ProverError> {
        let commitments = self.state.commitments.clone();
        let mut pairs = self.state.encoding_pairs.clone();

        let all_inputs: Vec<ProofInput> = commitments
            .iter()
            .flat_map(|commitment| {
                // Compute circuit inputs: deltas and zero_sum for each chunk
                let inputs: Vec<ProofInput> = commitment
                    .chunk_commitments
                    .iter()
                    .map(|com| {
                        let cloned = pairs.clone();
                        let (split, remaining) = cloned.split_at(com.plaintext.len());

                        pairs = remaining.to_vec();

                        let zero_sum = self.compute_zero_sum(&split);
                        let mut deltas = self.compute_deltas(&split);
                        // Pad deltas to the size of the chunk
                        // TODO: this should be the backend's job
                        deltas.extend(vec![
                            BigInt::from(0u8);
                            self.backend.chunk_size() - deltas.len()
                        ]);

                        ProofInput {
                            deltas,
                            plaintext_hash: com.plaintext_hash.clone(),
                            label_sum_hash: com.encodings_sum_hash.clone(),
                            sum_of_zero_labels: zero_sum,
                            plaintext: com.plaintext.clone(),
                            salt: com.plaintext_salt.clone(),
                        }
                    })
                    .collect();

                inputs
            })
            .collect();

        // Call prove on all chunks at the same time, let the backend decide on the
        // strategy for the circuit composition.
        // The verifier will choose the same strategy when verifying.
        let proofs = self.backend.prove(all_inputs)?;

        Ok(Prover {
            backend: self.backend,
            state: state::ProofCreated {
                commitments,
                proofs,
            },
        })
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
}

#[cfg(test)]
mod tests {
    use crate::{
        prover::{
            backend::Backend as ProverBackend,
            error::ProverError,
            prover::{ProofInput, Prover},
        },
        Proof,
    };
    use num::BigUint;

    /// The prover who implements `Prove` with the correct values
    struct CorrectTestProver {}
    impl ProverBackend for CorrectTestProver {
        fn prove(&self, _: Vec<ProofInput>) -> Result<Vec<Proof>, ProverError> {
            Ok(vec![Proof::default()])
        }

        fn chunk_size(&self) -> usize {
            3670
        }

        fn commit(
            &self,
            _plaintext: Vec<bool>,
            _encodings_sum: BigUint,
        ) -> Result<(BigUint, BigUint, BigUint), ProverError> {
            Ok((BigUint::default(), BigUint::default(), BigUint::default()))
        }
    }

    #[test]
    /// Inputs empty plaintext and triggers [ProverError::EmptyPlaintext]
    fn test_error_empty_plaintext() {
        let lsp = Prover::new(Box::new(CorrectTestProver {}));

        let pt: Vec<u8> = Vec::new();
        let res = lsp.commit(vec![(pt, vec![1u128])]);
        assert_eq!(res.err().unwrap(), ProverError::EmptyPlaintext);
    }
}
