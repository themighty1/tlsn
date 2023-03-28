use cipher::{consts::U16, BlockCipher, BlockEncrypt};

use crate::{
    circuit::EncryptedGate,
    label::{state, Delta, EncodedValue, Label, LabelPair},
};
use mpc_circuits::{types::TypeError, Circuit, Gate};
use mpc_core::Block;

#[derive(Debug, thiserror::Error)]
pub enum EvaluationError {
    #[error(transparent)]
    TypeError(#[from] TypeError),
}

/// Evaluates half-gate garbled AND gate
#[inline]
pub(crate) fn and_gate<C: BlockCipher<BlockSize = U16> + BlockEncrypt>(
    cipher: &C,
    x: &Label,
    y: &Label,
    encrypted_gate: &[Block; 2],
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

/// Evaluates half-gate garbled XOR gate
#[inline]
pub(crate) fn xor_gate(x: &Label, y: &Label) -> Label {
    *x ^ *y
}

/// Evaluates a garbled circuit.
pub fn evaluate<C: BlockCipher<BlockSize = U16> + BlockEncrypt>(
    cipher: &C,
    circ: &Circuit,
    inputs: &[EncodedValue<state::Active>],
    encrypted_gates: &[EncryptedGate],
) -> Result<Vec<EncodedValue<state::Active>>, EvaluationError> {
    let mut labels: Vec<Option<Label>> = vec![None; circ.feed_count()];

    for (encoded, input) in inputs.iter().zip(circ.inputs()) {
        if encoded.value_type() != input.value_type() {
            return Err(TypeError::UnexpectedType {
                expected: input.value_type(),
                actual: encoded.value_type(),
            })?;
        }

        for (label, node) in encoded.iter().zip(input.iter()) {
            labels[node.id()] = Some(label.clone());
        }
    }

    let mut tid = 0;
    let mut gid = 1;
    for gate in circ.gates() {
        match *gate {
            Gate::Inv {
                x: node_x,
                z: node_z,
                ..
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
                let z = xor_gate(&x, &y);
                labels[node_z.id()] = Some(z);
            }
            Gate::And {
                x: node_x,
                y: node_y,
                z: node_z,
            } => {
                let x = labels[node_x.id()].expect("feed should be initialized");
                let y = labels[node_y.id()].expect("feed should be initialized");
                let z = and_gate(cipher, &x, &y, encrypted_gates[tid].as_ref(), gid);
                labels[node_z.id()] = Some(z);
                tid += 1;
                gid += 2;
            }
        };
    }

    let outputs = circ
        .outputs()
        .iter()
        .map(|output| {
            let labels: Vec<Label> = output
                .iter()
                .map(|node| labels[node.id()].expect("feed should be initialized"))
                .collect();

            EncodedValue::<state::Active>::from_labels(output.value_type(), &labels)
                .expect("encoding should be correct")
        })
        .collect();

    Ok(outputs)
}
