//! Core components used to implement garbled circuit protocols
//!
//! This module implements "half-gate" garbled circuits from the [Two Halves Make a Whole [ZRE15]](https://eprint.iacr.org/2014/756) paper.
//!
//! Additionally, it provides various [execution modes](exec) which can be selected depending on protocol requirements.

pub(crate) mod circuit;
mod error;
mod evaluator;
//pub mod exec;
mod generator;
pub(crate) mod label;
//pub mod msgs;

//pub use circuit::{state as gc_state, CircuitOpening, GarbledCircuit};
//pub use error::{EncodingError, Error, InputError};
//pub use label::{
//     state as label_state, ActiveEncodedInput, ActiveEncodedOutput, ActiveInputSet, ActiveLabels,
//     ActiveOutputSet, ChaChaEncoder, Delta, Encoded, EncodedSet, Encoder, EncoderRng,
//     FullEncodedInput, FullEncodedOutput, FullInputSet, FullLabels, FullOutputSet,
//     GroupDecodingInfo, Label, LabelPair, Labels, LabelsDigest,
// };

#[cfg(test)]
mod tests {
    use crate::label::{Delta, Label};

    use super::{evaluator as ev, generator as gen};
    use aes::{
        cipher::{generic_array::GenericArray, NewBlockCipher},
        Aes128,
    };
    use rand::SeedableRng;
    use rand_chacha::ChaCha12Rng;

    //use mpc_circuits::AES_128;

    #[test]
    fn test_and_gate() {
        let mut rng = ChaCha12Rng::from_entropy();
        let mut cipher = Aes128::new(GenericArray::from_slice(&[0u8; 16]));

        let delta = Delta::random(&mut rng);
        let x_0 = Label::random(&mut rng);
        let x_1 = x_0 ^ delta;
        let y_0 = Label::random(&mut rng);
        let y_1 = y_0 ^ delta;
        let gid: usize = 1;

        let (z_0, encrypted_gate) = gen::and_gate(&cipher, &x_0, &y_0, &delta, gid);
        let z_1 = z_0 ^ delta;

        assert_eq!(
            ev::and_gate(&mut cipher, &x_0, &y_1, encrypted_gate.as_ref(), gid),
            z_0
        );
        assert_eq!(
            ev::and_gate(&mut cipher, &x_0, &y_1, encrypted_gate.as_ref(), gid),
            z_0
        );
        assert_eq!(
            ev::and_gate(&mut cipher, &x_1, &y_0, encrypted_gate.as_ref(), gid),
            z_0
        );
        assert_eq!(
            ev::and_gate(&mut cipher, &x_1, &y_1, encrypted_gate.as_ref(), gid),
            z_1
        );
    }

    #[test]
    fn test_xor_gate() {
        let mut rng = ChaCha12Rng::from_entropy();

        let delta = Delta::random(&mut rng);
        let x_0 = Label::random(&mut rng);
        let x_1 = x_0 ^ delta;
        let y_0 = Label::random(&mut rng);
        let y_1 = y_0 ^ delta;

        let z_0 = gen::xor_gate(&x_0, &y_0, delta);
        let z_1 = z_0 ^ delta;

        assert_eq!(ev::xor_gate(&x_0, &y_0), z_0);
        assert_eq!(ev::xor_gate(&x_0, &y_1), z_1);
        assert_eq!(ev::xor_gate(&x_1, &y_0), z_1,);
        assert_eq!(ev::xor_gate(&x_1, &y_1), z_0);
    }

    // #[test]
    // fn test_aes_128() {
    //     let mut rng = ChaCha12Rng::from_entropy();
    //     let cipher = Aes128::new(GenericArray::from_slice(&[0u8; 16]));
    //     let circ = AES_128.clone();

    //     let input_labels = FullInputSet::generate(&mut rng, &circ, None);

    //     // Generator provides key
    //     let gen_input = circ.input(0).unwrap().to_value(vec![0x32; 16]).unwrap();
    //     // Evaluator provides message
    //     let ev_input = circ.input(1).unwrap().to_value(vec![0x11; 16]).unwrap();

    //     let gc = GarbledCircuit::generate(&cipher, circ.clone(), input_labels.clone()).unwrap();

    //     let gc = gc.get_partial(true, false).unwrap();

    //     let gen_input_labels = input_labels[0].select(gen_input.value()).unwrap();
    //     // Evaluator typically receives these using OT
    //     let ev_input_labels = input_labels[1].select(ev_input.value()).unwrap();

    //     let evaluated_gc = gc
    //         .evaluate(
    //             &cipher,
    //             ActiveInputSet::new(vec![gen_input_labels, ev_input_labels]).unwrap(),
    //         )
    //         .unwrap();
    //     let output = evaluated_gc.decode().unwrap();

    //     let expected = circ.evaluate(&[gen_input, ev_input]).unwrap();

    //     assert_eq!(output[0], expected[0]);
    // }
}
