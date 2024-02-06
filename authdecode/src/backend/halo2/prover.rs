use super::{
    circuit::{AuthDecodeCircuit, SALT_SIZE, TOTAL_FIELD_ELEMENTS},
    poseidon::{poseidon_1, poseidon_15},
    utils::{biguint_to_f, deltas_to_matrices, f_to_biguint},
    CHUNK_SIZE, USEFUL_BITS,
};
use crate::{
    prover::{backend::Backend, error::ProverError, prover::ProofInput},
    utils::{bits_to_biguint, u8vec_to_boolvec},
    Delta, LabelSumHash, PlaintextHash, Proof, Salt, ZeroSum,
};
use halo2_proofs::{
    plonk,
    plonk::ProvingKey,
    poly::commitment::Params,
    transcript::{Blake2bWrite, Challenge255},
};
use num::BigUint;
use pasta_curves::{pallas::Base as F, EqAffine};
use rand::{thread_rng, Rng};

#[derive(Clone, Default)]
// Public and private inputs to the zk circuit
pub struct ProofInputHalo2 {
    // Public
    pub plaintext_hash: PlaintextHash,
    pub label_sum_hash: LabelSumHash,
    pub sum_of_zero_labels: ZeroSum,
    // deltas in the CHUNK_SIZE quantity
    pub deltas: Vec<Delta>,

    // Private
    pub plaintext: Vec<BigUint>,
    pub salt: Salt,
}

/// halo2's native ProvingKey can't be used without params, so we wrap
/// them in one struct.
#[derive(Clone)]
pub struct PK {
    pub key: ProvingKey<EqAffine>,
    pub params: Params<EqAffine>,
}

/// Implements the Prover in the authdecode protocol using halo2
/// proof system.
pub struct Prover {
    proving_key: PK,
}

impl Backend for Prover {
    fn chunk_size(&self) -> usize {
        CHUNK_SIZE
    }

    fn commit(
        &self,
        plaintext: Vec<bool>,
        encodings_sum: BigUint,
    ) -> Result<(BigUint, BigUint, BigUint), ProverError> {
        commit(plaintext, encodings_sum)
    }

    fn prove(&self, inputs: Vec<ProofInput>) -> Result<Vec<Proof>, ProverError> {
        // TODO: here we decide on the strategy how to compose multiple inputs.
        // Each input proves an AuthDecode commitment to one chunk of the plaintext.
        // Depending on future benchmarks, we may want to compose multiple inputs in one circuit.

        // Pad plaintext to the size of the chunk and convert it into BigUints
        let new_inputs = inputs
            .iter()
            .map(|input| {
                let mut plaintext = input.plaintext.clone();
                plaintext.extend(vec![false; self.chunk_size() - plaintext.len()]);
                let plaintext = plaintext
                    .chunks(self.useful_bits())
                    .map(bits_to_biguint)
                    .collect::<Vec<_>>();
                ProofInputHalo2 {
                    deltas: input.deltas.clone(),
                    label_sum_hash: input.label_sum_hash.clone(),
                    plaintext_hash: input.plaintext_hash.clone(),
                    sum_of_zero_labels: input.sum_of_zero_labels.clone(),
                    plaintext,
                    salt: input.salt.clone(),
                }
            })
            .collect::<Vec<_>>();

        // For now, we use the default "one input per one circuit" strategy
        let proofs = new_inputs
            .iter()
            .map(|input| self.do_prove(input.clone()))
            .collect::<Result<Vec<Proof>, ProverError>>()?;
        Ok(proofs)
    }
}

impl Prover {
    pub fn new(pk: PK) -> Self {
        Self { proving_key: pk }
    }

    fn useful_bits(&self) -> usize {
        USEFUL_BITS
    }

    fn do_prove(&self, input: ProofInputHalo2) -> Result<Proof, ProverError> {
        if input.deltas.len() != self.chunk_size() || input.plaintext.len() != TOTAL_FIELD_ELEMENTS
        {
            // this can only be caused by an error in
            // `crate::prover::AuthDecodeProver` logic
            return Err(ProverError::InternalError);
        }

        // convert into matrices
        let (deltas_as_rows, deltas_as_columns) =
            deltas_to_matrices(&input.deltas, self.useful_bits());

        // convert plaintext into F type
        let plaintext: [F; TOTAL_FIELD_ELEMENTS] = input
            .plaintext
            .iter()
            .map(biguint_to_f)
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();

        // arrange into the format which halo2 expects
        let mut all_inputs: Vec<&[F]> = deltas_as_columns.iter().map(|v| v.as_slice()).collect();

        // add another column with public inputs
        let tmp = &[
            biguint_to_f(&input.plaintext_hash),
            biguint_to_f(&input.label_sum_hash),
            biguint_to_f(&input.sum_of_zero_labels),
        ];
        all_inputs.push(tmp);

        // prepare the proving system and generate the proof:

        let circuit = AuthDecodeCircuit::new(plaintext, biguint_to_f(&input.salt), deltas_as_rows);

        let params = &self.proving_key.params;
        let pk = &self.proving_key.key;

        let mut transcript = Blake2bWrite::<_, _, Challenge255<_>>::init(vec![]);

        let mut rng = thread_rng();

        // let now = Instant::now();

        let res = plonk::create_proof(
            params,
            pk,
            &[circuit],
            &[all_inputs.as_slice()],
            &mut rng,
            &mut transcript,
        );
        if res.is_err() {
            return Err(ProverError::ProvingBackendError);
        }

        // println!("Proof created [{:?}]", now.elapsed());
        let proof = transcript.finalize();
        // println!("Proof size [{} kB]", proof.len() as f64 / 1024.0);
        Ok(proof)
    }
}

/// Hashes `inputs` with Poseidon and returns the digest as `BigUint`.
fn hash_internal(inputs: &[BigUint]) -> Result<BigUint, ProverError> {
    let digest = match inputs.len() {
        15 => {
            // hash with rate-15 Poseidon
            let fes: [F; 15] = inputs
                .iter()
                .map(biguint_to_f)
                .collect::<Vec<_>>()
                .try_into()
                .unwrap();
            poseidon_15(&fes)
        }
        1 => {
            // hash with rate-1 Poseidon
            let fes: [F; 1] = inputs
                .iter()
                .map(biguint_to_f)
                .collect::<Vec<_>>()
                .try_into()
                .unwrap();
            poseidon_1(&fes)
        }
        _ => return Err(ProverError::WrongPoseidonInput),
    };
    Ok(f_to_biguint(&digest))
}

fn commit(
    plaintext: Vec<bool>,
    encodings_sum: BigUint,
) -> Result<(BigUint, BigUint, BigUint), ProverError> {
    let mut plaintext = plaintext.clone();
    if plaintext.len() > CHUNK_SIZE {
        // TODO proper error
        return Err(ProverError::InternalError);
    }

    // Pad the plaintext to the size of the chunk.
    plaintext.extend(vec![false; CHUNK_SIZE - plaintext.len()]);

    // Generate random salt and add it to the plaintext.
    let mut rng = thread_rng();
    let salt: Vec<bool> = core::iter::repeat_with(|| rng.gen::<bool>())
        .take(SALT_SIZE)
        .collect::<Vec<_>>();

    plaintext.extend(salt.clone());

    // Convert bits into field elements and hash them.
    let field_elements: Vec<BigUint> = plaintext.chunks(USEFUL_BITS).map(bits_to_biguint).collect();

    let pt_digest = hash_internal(&field_elements)?;

    // Commit to encodings

    let enc_sum_bits = u8vec_to_boolvec(&encodings_sum.to_bytes_be());

    if (enc_sum_bits.len() + SALT_SIZE) > USEFUL_BITS {
        // TODO proper error, no room for salt
        return Err(ProverError::InternalError);
    }

    // Pack sum and salt into a single field element.
    // The high 128 bits are for the sum, the low 125 bits are for the salt.
    let mut field_element = vec![false; USEFUL_BITS];
    field_element[128 - enc_sum_bits.len()..128].copy_from_slice(&enc_sum_bits);
    field_element[USEFUL_BITS - SALT_SIZE..].copy_from_slice(&salt);

    let enc_digest = hash_internal(&[bits_to_biguint(&field_element)])?;

    Ok((pt_digest, enc_digest, bits_to_biguint(&salt)))
}

/// Puts salt into the low bits of the last field element of the chunk.
/// Returns the salted chunk.
// fn salt_chunk(&self, chunk: &Chunk, salt: &Salt) -> Result<Chunk, ProverError> {
//     let len = chunk.len();
//     let last_fe = chunk[len - 1].clone();

//     if last_fe.bits() as usize > self.prover.useful_bits() - self.prover.salt_size() {
//         // can only happen if there is a logic error in this code
//         return Err(ProverError::WrongLastFieldElementBitCount);
//     }

//     let mut salted_chunk = chunk.clone();
//     salted_chunk[len - 1] = last_fe.shl(self.prover.salt_size()) + salt;
//     Ok(salted_chunk)
// }

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        backend::halo2::{
            circuit::{CELLS_PER_ROW, K},
            utils::bigint_to_256bits,
            Curve,
        },
        prover::{backend::Backend as ProverBackend, error::ProverError, prover::ProofInput},
        tests::run_until_proofs_are_generated,
        verifier::{
            backend::Backend as VerifierBackend, error::VerifierError, verifier::VerificationInput,
        },
        Proof,
    };
    use halo2_proofs::dev::MockProver;
    use num::BigUint;

    /// TestHalo2Prover is a test prover. It is the same as [Prover] except:
    /// - it doesn't require a proving key
    /// - it uses a `MockProver` inside `prove()`
    ///
    /// This allows us to test the circuit with the correct inputs from the authdecode
    /// protocol execution. Also allows us to corrupt each of the circuit inputs and
    /// expect a failure.
    struct TestHalo2Prover {}
    impl ProverBackend for TestHalo2Prover {
        fn prove(&self, inputs: Vec<ProofInput>) -> Result<Vec<Proof>, ProverError> {
            // Pad plaintext to the size of the chunk and convert bits into BigUints
            let new_inputs = inputs
                .iter()
                .map(|input| {
                    let mut plaintext = input.plaintext.clone();
                    plaintext.extend(vec![false; self.chunk_size() - plaintext.len()]);
                    let plaintext = plaintext
                        .chunks(self.useful_bits())
                        .map(bits_to_biguint)
                        .collect::<Vec<_>>();
                    ProofInputHalo2 {
                        deltas: input.deltas.clone(),
                        label_sum_hash: input.label_sum_hash.clone(),
                        plaintext_hash: input.plaintext_hash.clone(),
                        sum_of_zero_labels: input.sum_of_zero_labels.clone(),
                        plaintext,
                        salt: input.salt.clone(),
                    }
                })
                .collect::<Vec<_>>();

            let input = new_inputs[0].clone();

            // convert into matrices
            let (deltas_as_rows, deltas_as_columns) =
                deltas_to_matrices(&input.deltas, self.useful_bits());

            // convert plaintext into F type
            let good_plaintext: [F; TOTAL_FIELD_ELEMENTS] = input
                .plaintext
                .iter()
                .map(biguint_to_f)
                .collect::<Vec<_>>()
                .try_into()
                .unwrap();

            // arrange into the format which halo2 expects
            let mut good_inputs: Vec<Vec<F>> =
                deltas_as_columns.iter().map(|v| v.to_vec()).collect();

            // add another column with public inputs
            let tmp = vec![
                biguint_to_f(&input.plaintext_hash),
                biguint_to_f(&input.label_sum_hash),
                biguint_to_f(&input.sum_of_zero_labels),
            ];
            good_inputs.push(tmp);

            let circuit =
                AuthDecodeCircuit::new(good_plaintext, biguint_to_f(&input.salt), deltas_as_rows);

            // Test with the correct inputs.
            // Expect successful verification.

            let prover = MockProver::run(K, &circuit, good_inputs.clone()).unwrap();
            let res = prover.verify();
            if res.is_err() {
                println!("ERROR: {:?}", res);
            }
            assert!(res.is_ok());

            // Find one delta which corresponds to plaintext bit 1 and corrupt
            // the delta:

            // Find the first bit 1 in plaintext
            let bits = bigint_to_256bits(input.plaintext[0].clone());
            let mut offset: i32 = -1;
            for (i, b) in bits.iter().enumerate() {
                if *b {
                    offset = i as i32;
                    break;
                }
            }
            // first field element of the plaintext is not expected to have all
            // bits set to zero.
            assert!(offset != -1);
            let offset = offset as usize;

            // Find the position of the corresponding delta. The position is
            // row/column in the halo2 table
            let col = offset % CELLS_PER_ROW;
            let row = offset / CELLS_PER_ROW;

            // Corrupt the delta
            let mut bad_input1 = good_inputs.clone();
            bad_input1[col][row] = F::from(123);

            let prover = MockProver::run(K, &circuit, bad_input1.clone()).unwrap();
            assert!(prover.verify().is_err());

            // One-by-one corrupt the plaintext hash, the label sum hash, the zero sum.
            // Expect verification error.

            for i in 0..3 {
                let mut bad_public_input = good_inputs.clone();
                bad_public_input[CELLS_PER_ROW][i] = F::from(123);
                let prover = MockProver::run(K, &circuit, bad_public_input.clone()).unwrap();
                assert!(prover.verify().is_err());
            }

            // Corrupt only the plaintext.
            // Expect verification error.

            let mut bad_plaintext = good_plaintext;
            bad_plaintext[0] = F::from(123);
            let circuit =
                AuthDecodeCircuit::new(bad_plaintext, biguint_to_f(&input.salt), deltas_as_rows);
            let prover = MockProver::run(K, &circuit, good_inputs.clone()).unwrap();
            assert!(prover.verify().is_err());

            // Corrupt only the salt.
            // Expect verification error.

            let bad_salt = BigUint::from(123u8);
            let circuit =
                AuthDecodeCircuit::new(good_plaintext, biguint_to_f(&bad_salt), deltas_as_rows);
            let prover = MockProver::run(K, &circuit, good_inputs.clone()).unwrap();
            assert!(prover.verify().is_err());

            Ok(vec![Default::default()])
        }

        fn chunk_size(&self) -> usize {
            CHUNK_SIZE
        }

        fn commit(
            &self,
            plaintext: Vec<bool>,
            encodings_sum: BigUint,
        ) -> Result<(BigUint, BigUint, BigUint), ProverError> {
            commit(plaintext, encodings_sum)
        }
    }

    impl TestHalo2Prover {
        pub fn new() -> Self {
            Self {}
        }

        fn useful_bits(&self) -> usize {
            USEFUL_BITS
        }
    }

    /// This verifier is the same as [crate::halo2_backend::verifier::Verifier] except:
    /// - it doesn't require a verifying key
    /// - it does not verify since `MockProver` does that already
    struct TestHalo2Verifier {
        curve: Curve,
    }

    impl TestHalo2Verifier {
        pub fn new(curve: Curve) -> Self {
            Self { curve }
        }
    }

    impl VerifierBackend for TestHalo2Verifier {
        fn verify(
            &self,
            inputs: Vec<VerificationInput>,
            proofs: Vec<Proof>,
        ) -> Result<(), VerifierError> {
            Ok(())
        }

        fn chunk_size(&self) -> usize {
            CHUNK_SIZE
        }
    }

    #[test]
    // As of Oct 2022 there appears to be a bug in halo2 which causes the prove
    // times with MockProver be as long as with a real prover. Marking this test
    // as expensive.
    // #[ignore = "expensive"]
    /// Tests the circuit with the correct inputs as well as wrong inputs. The logic is
    /// in [TestHalo2Prover]'s prove()
    fn test_circuit() {
        let prover = Box::new(TestHalo2Prover::new());
        let verifier = Box::new(TestHalo2Verifier::new(Curve::Pallas));
        let _ = run_until_proofs_are_generated(prover, verifier);
    }
}
