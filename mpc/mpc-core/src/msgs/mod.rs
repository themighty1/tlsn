use serde::{Deserialize, Serialize};

use crate::commit;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HashCommitment(pub [u8; 32]);

impl From<commit::HashCommitment> for HashCommitment {
    fn from(c: commit::HashCommitment) -> Self {
        Self(c.0)
    }
}

impl From<HashCommitment> for commit::HashCommitment {
    fn from(c: HashCommitment) -> Self {
        Self(c.0)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommitmentKey(pub [u8; 32]);

impl From<commit::CommitmentKey> for CommitmentKey {
    fn from(key: commit::CommitmentKey) -> Self {
        Self(key.0)
    }
}

impl From<CommitmentKey> for commit::CommitmentKey {
    fn from(key: CommitmentKey) -> Self {
        Self(key.0)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommitmentOpening<T> {
    pub key: CommitmentKey,
    pub data: T,
}

impl<T> From<commit::Opening<T>> for CommitmentOpening<T>
where
    T: serde::Serialize,
{
    fn from(opening: commit::Opening<T>) -> Self {
        Self {
            key: opening.key.into(),
            data: opening.data,
        }
    }
}

impl<T> From<CommitmentOpening<T>> for commit::Opening<T>
where
    T: serde::Serialize,
{
    fn from(opening: CommitmentOpening<T>) -> Self {
        Self {
            key: opening.key.into(),
            data: opening.data,
        }
    }
}
