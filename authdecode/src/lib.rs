//! Implementation of the AuthDecode protocol.
//! The protocol performs authenticated decoding of encodings in zero knowledge.
//!
//! The purpose of AuthDecode is to allow the GC evaluator to produce a zk-friendly
//! hash commitment to the GC output. Computing a zk-friendly hash directly inside
//! the GC is too expensive, hence the need for this protocol.
//!
//! The high-level overview of Authdecode is:
//! - The Verifier first reveals all of his secret inputs to the GC
//! - The Prover computes the expected output of GC ("the plaintext") in the
//! clear and commits to it
//! - The Verifier sends the GC but withholds the output decoding information
//! - The Prover evaluates the circuit and commits to his active output labels
//! - The Verifier reveals all the output labels of the circuit
//! - The Prover, without revealing the plaintext, creates a zero-knowledge proof
//! that the plaintext he committed to earlier is the true output of the GC evaluation
//!
//! Authdecode assumes a privacy-free setting for the garbler, i.e. the protocol
//! MUST ONLY start AFTER the garbler reveals all his secret GC inputs.
//! Specifically, in the context of the TLSNotary protocol, AuthDecode MUST ONLY
//! start AFTER the Notary (who is the garbler) has revealed all of his TLS session
//! keys' shares.
//!
//! See ../authdecode_diagram.pdf for a diagram of the whole protocol

pub mod backend;
pub mod encodings;
pub mod prover;
pub mod utils;
pub mod verifier;

use crate::prover::prover::ProofInput;
use num::{BigInt, BigUint};

/// An arithmetic difference between the arithmetic label "one" and the
/// arithmetic label "zero".
type Delta = BigInt;

/// An opaque proof of the AuthDecode circuit.
type Proof = Vec<u8>;

/// A zk proof with the corresponding public inputs.
struct ProofProperties {
    proof: Proof,
    public_inputs: ProofInput,
}

#[cfg(test)]
mod tests {
    use crate::{
        backend::mock::{MockProverBackend, MockVerifierBackend},
        encodings::{ActiveEncodings, Encoding, ToActiveEncodings},
        prover::{
            backend::Backend as ProverBackend,
            error::ProverError,
            prover::{ProofInput, Prover},
            InitData, ToInitData,
        },
        utils::{choose, u8vec_to_boolvec},
        verifier::verifier::Verifier,
        Proof,
    };
    use num::BigUint;
    use rand::{Rng, SeedableRng};
    use rand_chacha::ChaCha12Rng;

    /// The size of plaintext in bytes;
    const PLAINTEXT_SIZE: usize = 2000;

    // A dummy encodings verifier.
    struct DummyEncodingsVerifier {}
    impl crate::prover::EncodingVerifier for DummyEncodingsVerifier {
        fn init(&self, init_data: impl ToInitData) {}

        fn verify(
            &self,
            _encodings: Vec<[u128; 2]>,
        ) -> Result<(), crate::prover::EncodingVerifierError> {
            Ok(())
        }
    }

    // Dummy initialization data for the encoding verifier.
    struct DummyInitData {}
    impl ToInitData for DummyInitData {
        fn to_init_data(&self) -> InitData {
            InitData::new(vec![0u8])
        }
    }

    #[test]
    fn test_authdecode() {
        let mut rng = ChaCha12Rng::from_seed([0; 32]);

        // Generate random plaintext.
        let plaintext: Vec<u8> = core::iter::repeat_with(|| rng.gen::<u8>())
            .take(PLAINTEXT_SIZE)
            .collect();

        // Generate Verifier's full encodings for each bit of the plaintext.
        let full_encodings: Vec<[u128; 2]> = core::iter::repeat_with(|| rng.gen::<[u128; 2]>())
            .take(PLAINTEXT_SIZE * 8)
            .collect();

        // Prover's active encodings.
        let active_encodings = choose(&full_encodings, &u8vec_to_boolvec(&plaintext));
        pub struct ActiveEncodingsProvider(Vec<u128>);
        impl ActiveEncodingsProvider {
            pub fn new(encodings: Vec<u128>) -> Self {
                Self(encodings)
            }
        }
        impl ToActiveEncodings for ActiveEncodingsProvider {
            fn to_active_encodings(&self) -> crate::encodings::ActiveEncodings {
                let encodings = self
                    .0
                    .iter()
                    .map(|x| Encoding::new(BigUint::from(*x)))
                    .collect::<Vec<_>>();
                ActiveEncodings::new(encodings)
            }
        }

        let prover = Prover::new(Box::new(MockProverBackend::new()));
        let verifier = Verifier::new(Box::new(MockVerifierBackend::new()));

        let (prover, commitments) = prover
            .commit(vec![(
                plaintext,
                ActiveEncodingsProvider::new(active_encodings),
            )])
            .unwrap();

        let (verifier, verification_data) = verifier
            .receive_commitments(commitments, vec![full_encodings.clone()], DummyInitData {})
            .unwrap();

        let prover = prover
            .check(verification_data, DummyEncodingsVerifier {})
            .unwrap();

        let (prover, proof_sets) = prover.prove().unwrap();

        let verifier = verifier.verify(proof_sets).unwrap();
    }
}
