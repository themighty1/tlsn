use std::ops::Index;

use mpc_circuits::Circuit;
use mpc_core::Block;
use serde::{Deserialize, Serialize};

use crate::{label_state, Delta, EncodedValue, Generator, GeneratorError};

#[derive(Debug, thiserror::Error)]
pub enum GarbledCircuitError {
    #[error(transparent)]
    GeneratorError(#[from] GeneratorError),
    #[error("invalid garbled circuit digest")]
    InvalidDigest,
}

/// Encrypted gate truth table
///
/// For the half-gate garbling scheme a truth table will typically have 2 rows, except for in
/// privacy-free garbling mode where it will be reduced to 1
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EncryptedGate(#[serde(with = "serde_arrays")] pub(crate) [Block; 2]);

impl EncryptedGate {
    pub(crate) fn new(inner: [Block; 2]) -> Self {
        Self(inner)
    }

    pub(crate) fn to_be_bytes(&self) -> [u8; 32] {
        let mut bytes = [0u8; 32];
        bytes[..16].copy_from_slice(&self.0[0].to_be_bytes());
        bytes[16..].copy_from_slice(&self.0[1].to_be_bytes());
        bytes
    }
}

impl Index<usize> for EncryptedGate {
    type Output = Block;

    fn index(&self, index: usize) -> &Self::Output {
        &self.0[index]
    }
}

/// Garbled circuit digest
#[derive(Debug, Clone, PartialEq)]
pub struct GarbledCircuitDigest(pub(crate) [u8; 32]);

impl GarbledCircuitDigest {
    /// Verifies that the given circuit and inputs produce the same digest as this one
    pub fn verify(
        &self,
        circ: &Circuit,
        delta: Delta,
        inputs: &[EncodedValue<label_state::Full>],
    ) -> Result<(), GarbledCircuitError> {
        let mut gen = Generator::new(circ, delta, &inputs, true)?;
        // drain the generator, dropping the gates
        while let Some(_) = gen.next() {}
        let digest = gen.digest().expect("digest should be available");

        if digest.0 == self.0 {
            Ok(())
        } else {
            Err(GarbledCircuitError::InvalidDigest)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gc_digest() {}
}
