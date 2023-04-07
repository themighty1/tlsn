//! Commitment protocols

use rand::{thread_rng, Rng};
use serde::{Deserialize, Serialize};

/// Error associated with commitments
#[derive(Debug, thiserror::Error)]
pub enum CommitmentError {
    #[error("Invalid commitment opening")]
    InvalidCommitment,
    #[error(transparent)]
    SerializationError(#[from] bincode::Error),
}

/// A trait for committing to arbitrary data which implements `serde::Serialize`
pub trait Commit
where
    Self: serde::Serialize + Sized,
{
    /// Creates a hash commitment to self
    fn commit(self) -> Result<(Opening<Self>, HashCommitment), CommitmentError> {
        let opening = Opening::new(self);

        let mut bytes = opening.key.0.to_vec();
        bytes.extend(bincode::serialize(&opening.data)?);

        let commit = HashCommitment::new(&bytes);

        Ok((opening, commit))
    }
}

impl<T> Commit for T where T: serde::Serialize {}

/// Opening information for a commitment
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Opening<T>
where
    T: Serialize,
{
    pub(crate) key: CommitmentKey,
    pub(crate) data: T,
}

impl<T> Opening<T>
where
    T: Serialize,
{
    /// Creates a new commitment opening
    pub fn new(data: T) -> Self {
        Self {
            key: CommitmentKey::random(),
            data,
        }
    }

    /// Creates a commitment
    pub fn commit(&self) -> Result<HashCommitment, CommitmentError> {
        let mut bytes = self.key.0.to_vec();
        bytes.extend(bincode::serialize(&self.data)?);

        Ok(HashCommitment::new(&bytes))
    }

    /// Verifies that the provided commitment corresponds to this
    /// opening
    pub fn verify(&self, commitment: &HashCommitment) -> Result<(), CommitmentError> {
        let expected = self.commit()?;

        if commitment == &expected {
            Ok(())
        } else {
            Err(CommitmentError::InvalidCommitment)
        }
    }

    /// Returns the commitment key
    pub fn key(&self) -> &CommitmentKey {
        &self.key
    }

    /// Returns the data
    pub fn data(&self) -> &T {
        &self.data
    }

    /// Returns the data
    pub fn to_inner(self) -> T {
        self.data
    }
}

/// A commitment of the form H(key || message) using Blake3
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct HashCommitment(pub(crate) [u8; 32]);

impl HashCommitment {
    pub(crate) fn new(message: &[u8]) -> Self {
        let mut hasher = blake3::Hasher::new();
        hasher.update(message);
        Self(hasher.finalize().into())
    }
}

/// A randomly generated 32 byte key
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct CommitmentKey(pub(crate) [u8; 32]);

impl CommitmentKey {
    /// Creates a random 32 byte key
    pub fn random() -> Self {
        Self(thread_rng().gen())
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_commitment_pass() {
        let message = [0, 1, 2, 3u8];
        let (opening, commitment) = message.commit().unwrap();

        opening.verify(&commitment).unwrap();
    }

    #[test]
    fn test_commitment_invalid_key() {
        let message = [0, 1, 2, 3u8];
        let (mut opening, commitment) = message.commit().unwrap();

        opening.key.0[0] = opening.key.0[0] - 1;

        let err = opening.verify(&commitment).unwrap_err();

        assert!(matches!(err, CommitmentError::InvalidCommitment));
    }

    #[test]
    fn test_commitment_invalid_data() {
        let message = [0, 1, 2, 3u8];
        let (mut opening, commitment) = message.commit().unwrap();

        opening.data[0] = opening.data[0] + 1;

        let err = opening.verify(&commitment).unwrap_err();

        assert!(matches!(err, CommitmentError::InvalidCommitment));
    }
}
