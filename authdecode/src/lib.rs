//! This module implements the protocol for zero-knowledge authenticated
//! decoding (aka AuthDecode) of output labels from a garbled circuit (GC)
//! evaluation.
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

pub mod halo2_backend;
mod label;
pub mod prover;
mod utils;
pub mod verifier;

use crate::prover::prover::ProofInput;
use num::{BigInt, BigUint};

/// Before hashing a [Chunk], it is salted by shifting its last element to the
/// left by [Prove::salt_size] and placing the salt into the low bits.
/// This same salt is also used to salt the sum of all the labels corresponding
/// to the [Chunk].
/// Without the salt, a hash of plaintext with low entropy could be brute-forced.
type Salt = BigUint;

/// A Poseidon hash digest of a [Salt]ed [Chunk]. This is an EC field element.
type PlaintextHash = BigUint;

/// A Poseidon hash digest of a [Salt]ed arithmetic sum of arithmetic labels
/// corresponding to the [Chunk]. This is an EC field element.
type LabelSumHash = BigUint;

/// An arithmetic sum of all "zero" arithmetic labels ( those are the labels
/// which encode the bit value 0) corresponding to one [Chunk].
type ZeroSum = BigUint;

/// An arithmetic difference between the arithmetic label "one" and the
/// arithmetic label "zero".
type Delta = BigInt;

/// An opaque proof proving that:
/// the encodings are authentic and that they decode into
/// plaintext which hashes to a certain Poseidon hash.
type Proof = Vec<u8>;

/// A zk proof with the corresponding public inputs.
struct ProofProperties {
    proof: Proof,
    public_inputs: ProofInput,
}

#[cfg(test)]
mod tests {
    use crate::{
        prover::{backend::Backend as ProverBackend, prover::Prover, state::ProofCreated},
        utils::*,
        verifier::{
            backend::Backend as VerifierBackend, error::VerifierError, state::CommitmentReceived,
            verifier::Verifier,
        },
        Proof,
    };
    use rand::{thread_rng, Rng};

    /// Accepts a concrete Prover and Verifier and runs the whole AuthDecode
    /// protocol end-to-end.
    ///
    /// Corrupts the proof if `will_corrupt_proof` is `true` and expects the
    /// verification to fail.
    pub fn e2e_test(
        prover: Box<dyn ProverBackend>,
        verifier: Box<dyn VerifierBackend>,
        will_corrupt_proof: bool,
    ) {
        let (prover, verifier) = run_until_proofs_are_generated(prover, verifier);

        if !will_corrupt_proof {
            // Verifier verifies a good proof.
            assert!(verifier.verify(prover.state.proofs).is_ok());
        } else {
            // corrupt one byte in each proof
            let corrupted_proofs: Vec<Proof> = prover
                .state
                .proofs
                .iter()
                .map(|p| {
                    let old_byte = p[p.len() / 2];
                    let new_byte = old_byte.checked_add(1).unwrap_or_default();
                    let mut new_proof = p.clone();
                    let p_len = new_proof.len();
                    new_proof[p_len / 2] = new_byte;
                    new_proof
                })
                .collect();
            // Notary tries to verify a corrupted proof
            let res = verifier.verify(corrupted_proofs);
            assert_eq!(res.err().unwrap(), VerifierError::VerificationFailed);
        }
    }

    /// Runs the protocol until the moment when Prover returns generated proofs.
    ///
    /// Returns the proofs, the salts, and the verifier in the next expected state.
    pub fn run_until_proofs_are_generated(
        prover: Box<dyn ProverBackend>,
        verifier: Box<dyn VerifierBackend>,
    ) -> (Prover<ProofCreated>, Verifier<CommitmentReceived>) {
        let mut rng = thread_rng();

        // generate random plaintext of random size up to 300 bytes
        let plaintext: Vec<u8> = core::iter::repeat_with(|| rng.gen::<u8>())
            .take(thread_rng().gen_range(1..1000))
            .collect();

        // Normally, the Prover is expected to obtain her binary labels by
        // evaluating the garbled circuit.
        // To keep this test simple, we don't evaluate the gc, but we generate
        // all labels of the Verifier and give the Prover her active labels.
        let bit_size = plaintext.len() * 8;
        let mut all_binary_labels: Vec<[u128; 2]> = Vec::with_capacity(bit_size);
        let mut delta: u128 = rng.gen();
        // set the last bit
        delta |= 1;
        for _ in 0..bit_size {
            let label_zero: u128 = rng.gen();
            all_binary_labels.push([label_zero, label_zero ^ delta]);
        }
        let prover_labels = crate::utils::choose(&all_binary_labels, &u8vec_to_boolvec(&plaintext));

        let verifier = Verifier::new(verifier);

        let prover = Prover::new(prover);

        // Commitment to the plaintext is sent to the Verifier
        let prover = prover.commit(vec![(plaintext, prover_labels)]).unwrap();
        let commitments = prover.state.commitments.clone();

        // Verifier receives the commitment and reveals its randomness
        let verifier = verifier
            .receive_commitments(commitments, vec![all_binary_labels.clone()])
            .unwrap();

        // A verifier of encodings obtained from the DEAP protocol.
        struct DEAPEncodingsVerifier {}
        impl crate::prover::EncodingsVerifier for DEAPEncodingsVerifier {
            fn verify(
                &self,
                _encodings: Vec<[u128; 2]>,
            ) -> Result<(), crate::prover::EncodingsVerifierError> {
                // Check garbled circuits consistency.
                // Check OT consistency.
                Ok(())
            }
        }
        let enc_verifier = DEAPEncodingsVerifier {};

        let prover = prover.check(all_binary_labels, enc_verifier).unwrap();

        // Create proofs
        let prover = prover.prove().unwrap();

        (prover, verifier)
    }
}
