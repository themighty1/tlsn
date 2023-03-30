use cipher::{consts::U16, BlockCipher, BlockEncrypt};

use crate::{
    circuit::EncryptedGate,
    label::{state, Delta, EncodedValue, Label, LabelPair},
};
use mpc_circuits::{types::TypeError, Circuit, Gate};
use mpc_core::Block;

#[derive(Debug, thiserror::Error)]
pub enum GarbleError {
    #[error(transparent)]
    TypeError(#[from] TypeError),
}

/// Computes half-gate garbled AND gate
#[inline]
pub(crate) fn and_gate<C: BlockCipher<BlockSize = U16> + BlockEncrypt>(
    c: &C,
    x_0: &Label,
    y_0: &Label,
    delta: &Delta,
    gid: usize,
) -> (Label, EncryptedGate) {
    let delta = delta.into_inner();
    let x_0 = x_0.into_inner();
    let x_1 = x_0 ^ delta;
    let y_0 = y_0.into_inner();
    let y_1 = y_0 ^ delta;

    let p_a = x_0.lsb();
    let p_b = y_0.lsb();
    let j = gid;
    let k = gid + 1;

    let hx_0 = x_0.hash_tweak(c, j);
    let hy_0 = y_0.hash_tweak(c, k);

    // Garbled row of generator half-gate
    let t_g = hx_0 ^ x_1.hash_tweak(c, j) ^ (Block::SELECT_MASK[p_b] & delta);
    let w_g = hx_0 ^ (Block::SELECT_MASK[p_a] & t_g);

    // Garbled row of evaluator half-gate
    let t_e = hy_0 ^ y_1.hash_tweak(c, k) ^ x_0;
    let w_e = hy_0 ^ (Block::SELECT_MASK[p_b] & (t_e ^ x_0));

    let z_0 = Label::new(w_g ^ w_e);

    (z_0, EncryptedGate::new([t_g, t_e]))
}

/// Computes half-gate garbled XOR gate
#[inline]
pub(crate) fn xor_gate(x_0: &Label, y_0: &Label, delta: Delta) -> Label {
    *x_0 ^ *y_0
}

/// Garbles a circuit using the provided input labels and delta
pub fn garble<C: BlockCipher<BlockSize = U16> + BlockEncrypt>(
    cipher: &C,
    circ: &Circuit,
    delta: Delta,
    inputs: &[EncodedValue<state::Full>],
) -> Result<(Vec<EncodedValue<state::Full>>, Vec<EncryptedGate>), GarbleError> {
    let mut encrypted_gates: Vec<EncryptedGate> = Vec::with_capacity(circ.and_count());
    // Every wire label pair for the circuit
    let mut low_labels: Vec<Option<Label>> = vec![None; circ.feed_count()];

    for (encoded, input) in inputs.iter().zip(circ.inputs()) {
        if encoded.value_type() != input.value_type() {
            return Err(TypeError::UnexpectedType {
                expected: input.value_type(),
                actual: encoded.value_type(),
            })?;
        }

        for (label, node) in encoded.iter().zip(input.iter()) {
            low_labels[node.id()] = Some(label.clone());
        }
    }

    let mut gid = 1;
    for gate in circ.gates() {
        match *gate {
            Gate::Inv {
                x: node_x,
                z: node_z,
            } => {
                let x_0 = low_labels[node_x.id()].expect("feed should be initialized");
                low_labels[node_z.id()] = Some(x_0 ^ delta);
            }
            Gate::Xor {
                x: node_x,
                y: node_y,
                z: node_z,
            } => {
                let x_0 = low_labels[node_x.id()].expect("feed should be initialized");
                let y_0 = low_labels[node_y.id()].expect("feed should be initialized");
                let z_0 = xor_gate(&x_0, &y_0, delta);
                low_labels[node_z.id()] = Some(z_0);
            }
            Gate::And {
                x: node_x,
                y: node_y,
                z: node_z,
            } => {
                if node_x.id() == 0 {
                    let z_0 = low_labels[node_y.id()].expect("feed should be initialized");
                }
                let x_0 = low_labels[node_x.id()].expect("feed should be initialized");
                let y_0 = low_labels[node_y.id()].expect("feed should be initialized");
                let (z_0, t) = and_gate(cipher, &x_0, &y_0, &delta, gid);
                encrypted_gates.push(t);
                low_labels[node_z.id()] = Some(z_0);
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
                .map(|node| low_labels[node.id()].expect("feed should be initialized"))
                .collect();

            EncodedValue::<state::Full>::from_labels(output.value_type(), delta, &labels)
                .expect("encoding should be correct")
        })
        .collect();

    Ok((outputs, encrypted_gates))
}
