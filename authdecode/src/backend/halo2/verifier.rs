use super::{
    utils::{biguint_to_f, deltas_to_matrices},
    Curve, CHUNK_SIZE, USEFUL_BITS,
};
use crate::{
    verifier::{backend::Backend, error::VerifierError, verifier::VerificationInput},
    Proof,
};
use halo2_proofs::{
    plonk,
    plonk::{SingleVerifier, VerifyingKey},
    poly::commitment::Params,
    transcript::{Blake2bRead, Challenge255},
};
use pasta_curves::{pallas::Base as F, EqAffine};

/// halo2's native [halo2::VerifyingKey] can't be used without params, so we wrap
/// them in one struct.
#[derive(Clone)]
pub struct VK {
    pub key: VerifyingKey<EqAffine>,
    pub params: Params<EqAffine>,
}

/// Implements the Verifier in the authdecode protocol.
pub struct Verifier {
    verification_key: VK,
    curve: Curve,
}
impl Verifier {
    pub fn new(vk: VK, curve: Curve) -> Self {
        Self {
            verification_key: vk,
            curve,
        }
    }

    fn field_size(&self) -> usize {
        match self.curve {
            Curve::Pallas => 255,
            Curve::BN254 => 254,
        }
    }

    fn useful_bits(&self) -> usize {
        USEFUL_BITS
    }
}

impl Backend for Verifier {
    fn verify(
        &self,
        inputs: Vec<VerificationInput>,
        proofs: Vec<Proof>,
    ) -> Result<(), VerifierError> {
        // depending on the proof generation strategy used by the prover
        // we match chunk_inputs to proofs and verify

        // For now we assume there is only one chunk and only one proof for it.
        let proof = proofs[0].clone();
        let input = &inputs[0];

        let params = &self.verification_key.params;
        let vk = &self.verification_key.key;

        let strategy = SingleVerifier::new(params);
        let mut transcript = Blake2bRead::<_, _, Challenge255<_>>::init(&proof[..]);

        // convert deltas into a matrix which halo2 expects
        let (_, deltas_as_columns) = deltas_to_matrices(&input.deltas, self.useful_bits());

        let mut all_inputs: Vec<&[F]> = deltas_as_columns.iter().map(|v| v.as_slice()).collect();

        // add another column with public inputs
        let tmp = &[
            biguint_to_f(&input.plaintext_hash),
            biguint_to_f(&input.label_sum_hash),
            biguint_to_f(&input.sum_of_zero_labels),
        ];
        all_inputs.push(tmp);

        // let now = Instant::now();
        // perform the actual verification
        let res = plonk::verify_proof(
            params,
            vk,
            strategy,
            &[all_inputs.as_slice()],
            &mut transcript,
        );
        // println!("Proof verified [{:?}]", now.elapsed());
        if res.is_err() {
            Err(VerifierError::VerificationFailed)
        } else {
            Ok(())
        }
    }

    fn chunk_size(&self) -> usize {
        CHUNK_SIZE
    }
}
