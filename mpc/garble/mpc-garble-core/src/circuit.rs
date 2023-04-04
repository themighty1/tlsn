use std::{ops::Index, sync::Arc};

use cipher::{consts::U16, BlockCipher, BlockEncrypt};
use mpc_circuits::Circuit;
use mpc_core::{utils::blake3, Block};

use crate::{generator::GeneratorError, label_state, EncodedValue};

/// Encrypted gate truth table
///
/// For the half-gate garbling scheme a truth table will typically have 2 rows, except for in
/// privacy-free garbling mode where it will be reduced to 1
#[derive(Debug, Clone, PartialEq)]
pub struct EncryptedGate(pub(crate) [Block; 2]);

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

#[derive(Debug, Clone)]
pub struct GarbledCircuit {
    circ: Arc<Circuit>,
    gates: Vec<EncryptedGate>,
}

// impl GarbledCircuit {
//     pub fn generate<C: BlockCipher<BlockSize = U16> + BlockEncrypt>(
//         cipher: &C,
//         circ: Arc<Circuit>,
//         inputs: &[EncodedValue<label_state::Full>],
//     ) -> Result<(Self, Vec<EncodedValue<label_state::Full>>), GarbleError> {
//         let (outputs, gates) = garble(cipher, &circ, inputs[0].delta(), inputs)?;

//         Ok((Self { circ, gates }, outputs))
//     }

//     pub fn circuit(&self) -> &Circuit {
//         &self.circ
//     }

//     pub fn gates(&self) -> &[EncryptedGate] {
//         &self.gates
//     }
// }
