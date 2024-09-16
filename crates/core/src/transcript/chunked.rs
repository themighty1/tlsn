use serde::{Deserialize, Serialize};

use crate::{
    attestation::FieldId,
    hash::{
        impl_domain_separator, Blinded, Blinder, HashAlgorithmExt, HashProvider, HashProviderError,
        TypedHash,
    },
    transcript::{Direction, Idx, InvalidSubsequence, Subsequence},
};

/// A hash commitment to each individual chunk of the plaintext in the transcript.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct ChunkedPlaintextHash {
    /// Direction of the plaintext.
    pub direction: Direction,
    /// Index of plaintext.
    pub idx: Idx,
    /// The hash of each chunk of the plaintext.
    pub hash: Vec<TypedHash>,
}

impl_domain_separator!(ChunkedPlaintextHash);

/// Secret data for a chunked plaintext hash commitment.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct ChunkedPlaintextHashSecret {
    pub(crate) direction: Direction,
    pub(crate) idx: Idx,
    pub(crate) commitment: FieldId,
    /// A blinder for each chunk of the hash commitment.
    pub(crate) blinder: Vec<Blinder>,
}

/// Proof of the chunked plaintext of a hash.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct ChunkedPlaintextHashProof {
    /// Blinded chunks of the plaintext.
    chunks: Vec<Blinded<Vec<u8>>>,
    commitment: FieldId,
}

impl ChunkedPlaintextHashProof {
    pub(crate) fn new(chunks: Vec<Blinded<Vec<u8>>>, commitment: FieldId) -> Self {
        Self { chunks, commitment }
    }
}

impl ChunkedPlaintextHashProof {
    /// Returns the field id of the commitment this opening corresponds to.
    pub(crate) fn commitment_id(&self) -> &FieldId {
        &self.commitment
    }

    /// Verifies the proof, returning the subsequence of plaintext.
    ///
    /// # Arguments
    ///
    /// * `commitment` - The commitment attested to by a Notary.
    pub(crate) fn verify(
        self,
        provider: &HashProvider,
        commitment: &ChunkedPlaintextHash,
    ) -> Result<(Direction, Subsequence), ChunkedPlaintextHashProofError> {
        let alg = provider.get(&commitment.hash[0].alg)?;

        debug_assert!(commitment.hash.len() == self.chunks.len());

        let mut data = Vec::new();

        for (chunk_hash, chunk) in commitment.hash.iter().zip(self.chunks) {
            if chunk_hash.value != alg.hash_canonical(&chunk) {
                return Err(ChunkedPlaintextHashProofError::new(
                    "hash does not match commitment",
                ));
            }

            data.extend(chunk.into_parts().0);
        }

        Ok((
            commitment.direction,
            Subsequence::new(commitment.idx.clone(), data)?,
        ))
    }
}

/// Error for [`ChunkedPlaintextHashProof`].
#[derive(Debug, thiserror::Error)]
#[error("invalid chunked plaintext hash proof: {0}")]
pub(crate) struct ChunkedPlaintextHashProofError(String);

impl ChunkedPlaintextHashProofError {
    fn new<T: Into<String>>(msg: T) -> Self {
        Self(msg.into())
    }
}

impl From<HashProviderError> for ChunkedPlaintextHashProofError {
    fn from(err: HashProviderError) -> Self {
        Self(err.to_string())
    }
}

impl From<InvalidSubsequence> for ChunkedPlaintextHashProofError {
    fn from(err: InvalidSubsequence) -> Self {
        Self(err.to_string())
    }
}
