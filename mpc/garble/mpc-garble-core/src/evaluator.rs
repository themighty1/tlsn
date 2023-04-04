use std::iter::Peekable;

use aes::{Aes128, NewBlockCipher};
use blake3::Hasher;
use cipher::{consts::U16, BlockCipher, BlockEncrypt};

use crate::{
    circuit::{EncryptedGate, GarbledCircuitDigest},
    label::{state, EncodedValue, Label},
    CIPHER_FIXED_KEY,
};
use mpc_circuits::{types::TypeError, Circuit, CircuitError, Gate, GateType};
use mpc_core::Block;

#[derive(Debug, thiserror::Error)]
pub enum EvaluatorError {
    #[error(transparent)]
    TypeError(#[from] TypeError),
    #[error(transparent)]
    CircuitError(#[from] CircuitError),
    #[error("evaluator not finished")]
    NotFinished,
}

/// Evaluates half-gate garbled AND gate
#[inline]
pub(crate) fn and_gate<C: BlockCipher<BlockSize = U16> + BlockEncrypt>(
    cipher: &C,
    x: &Label,
    y: &Label,
    encrypted_gate: &EncryptedGate,
    gid: usize,
) -> Label {
    let x = x.into_inner();
    let y = y.into_inner();

    let s_a = x.lsb();
    let s_b = y.lsb();

    let j = gid;
    let k = gid + 1;

    let hx = x.hash_tweak(cipher, j);
    let hy = y.hash_tweak(cipher, k);

    let w_g = hx ^ (encrypted_gate[0] & Block::SELECT_MASK[s_a]);
    let w_e = hy ^ (Block::SELECT_MASK[s_b] & (encrypted_gate[1] ^ x));

    Label::new(w_g ^ w_e)
}

pub struct Evaluator<'a> {
    cipher: Aes128,
    circ: &'a Circuit,
    gates_iter: Peekable<std::slice::Iter<'a, Gate>>,
    active_labels: Vec<Option<Label>>,
    gid: usize,
    complete: bool,
    hasher: Option<Hasher>,
}

impl<'a> Evaluator<'a> {
    pub fn new(
        circ: &'a Circuit,
        inputs: &[EncodedValue<state::Active>],
        digest: bool,
    ) -> Result<Self, EvaluatorError> {
        if inputs.len() != circ.inputs().len() {
            return Err(CircuitError::InvalidInputCount(
                circ.inputs().len(),
                inputs.len(),
            ))?;
        }

        let mut active_labels: Vec<Option<Label>> = vec![None; circ.feed_count()];
        for (encoded, input) in inputs.iter().zip(circ.inputs()) {
            if encoded.value_type() != input.value_type() {
                return Err(TypeError::UnexpectedType {
                    expected: input.value_type(),
                    actual: encoded.value_type(),
                })?;
            }

            for (label, node) in encoded.iter().zip(input.iter()) {
                active_labels[node.id()] = Some(label.clone());
            }
        }

        Ok(Self {
            cipher: Aes128::new_from_slice(&CIPHER_FIXED_KEY).expect("cipher should initialize"),
            circ,
            gates_iter: circ.gates().iter().peekable(),
            active_labels,
            gid: 1,
            complete: false,
            hasher: if digest { Some(Hasher::new()) } else { None },
        })
    }

    /// Evaluates the next batch of encrypted gates.
    #[inline]
    pub fn evaluate(&mut self, encrypted_gates: impl IntoIterator<Item = EncryptedGate>) {
        let mut encrypted_gates = encrypted_gates.into_iter().peekable();
        let labels = &mut self.active_labels;

        // Process gates until we run out of encrypted gates
        while let Some(gate) = self.gates_iter.next() {
            match gate {
                Gate::Inv {
                    x: node_x,
                    z: node_z,
                } => {
                    let x = labels[node_x.id()].expect("feed should be initialized");
                    labels[node_z.id()] = Some(x);
                }
                Gate::Xor {
                    x: node_x,
                    y: node_y,
                    z: node_z,
                } => {
                    let x = labels[node_x.id()].expect("feed should be initialized");
                    let y = labels[node_y.id()].expect("feed should be initialized");
                    labels[node_z.id()] = Some(x ^ y);
                }
                Gate::And {
                    x: node_x,
                    y: node_y,
                    z: node_z,
                } => {
                    let encrypted_gate = encrypted_gates.next().expect("gate should be available");

                    if let Some(hasher) = &mut self.hasher {
                        hasher.update(&encrypted_gate.to_be_bytes());
                    }

                    let x = labels[node_x.id()].expect("feed should be initialized");
                    let y = labels[node_y.id()].expect("feed should be initialized");
                    let z = and_gate(&self.cipher, &x, &y, &encrypted_gate, self.gid);
                    labels[node_z.id()] = Some(z);
                    self.gid += 2;
                }
            }

            // If the next gate is an AND gate and we've run out of encrypted gates
            // then we return and wait for the next batch
            if let Some(next_gate) = self.gates_iter.peek() {
                if next_gate.gate_type() == GateType::And && encrypted_gates.peek().is_none() {
                    return;
                }
            }
        }

        self.complete = true;
    }

    pub fn is_complete(&self) -> bool {
        self.complete
    }

    pub fn outputs(&self) -> Result<Vec<EncodedValue<state::Active>>, EvaluatorError> {
        if !self.is_complete() {
            return Err(EvaluatorError::NotFinished);
        }

        Ok(self
            .circ
            .outputs()
            .iter()
            .map(|output| {
                let labels: Vec<Label> = output
                    .iter()
                    .map(|node| self.active_labels[node.id()].expect("feed should be initialized"))
                    .collect();

                EncodedValue::<state::Active>::from_labels(output.value_type(), &labels)
                    .expect("encoding should be correct")
            })
            .collect())
    }

    /// Returns the digest of the encrypted gates evaluated by this evaluator.
    pub fn digest(&self) -> Option<GarbledCircuitDigest> {
        self.hasher
            .as_ref()
            .map(|hasher| GarbledCircuitDigest(hasher.finalize().into()))
    }
}
