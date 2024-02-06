use crate::{
    prover::{backend::Backend as ProverBackend, error::ProverError},
    utils::boolvec_to_u8vec,
    verifier::backend::Backend as VerifierBackend,
    Proof, ProofInput,
};
use blake3::Hasher;
use num::{BigInt, BigUint};
use rand::{thread_rng, Rng};

/// Mock prover backend.
pub struct MockProverBackend {}

impl ProverBackend for MockProverBackend {
    // Note that we need to model real-life hashing, i.e. we want different
    // hash digests for different inputs.
    fn commit(
        &self,
        plaintext: Vec<bool>,
        encodings_sum: BigUint,
    ) -> Result<(BigUint, BigUint, BigUint), ProverError> {
        if plaintext.len() > self.chunk_size() {
            // TODO proper error
            return Err(ProverError::InternalError);
        }
        // Generate random salt and add it to the plaintext.
        let mut rng = thread_rng();
        let salt: u128 = rng.gen();
        let salt = salt.to_be_bytes();

        let mut plaintext = boolvec_to_u8vec(&plaintext);
        plaintext.extend(salt);
        let plaintext_hash = BigUint::from_bytes_be(&hash(&plaintext));

        let mut enc_sum = encodings_sum.to_bytes_be();
        enc_sum.extend(salt);
        let enc_sum_hash = BigUint::from_bytes_be(&hash(&enc_sum));

        Ok((plaintext_hash, enc_sum_hash, BigUint::from_bytes_be(&salt)))
    }

    fn chunk_size(&self) -> usize {
        1234
    }

    fn prove(&self, input: Vec<ProofInput>) -> Result<Vec<Proof>, ProverError> {
        Ok(vec![vec![1u8; 128]])
    }
}

fn hash(bytes: &[u8]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(bytes);
    hasher.finalize().into()
}
