//! Types for the AuthDecode protocol.

use core::ops::Range;

use crate::{
    hash::HashAlgId,
    request::Request,
    transcript::{
        encoding::{new_encoder, EncodingProvider},
        Transcript,
    },
    Secrets,
};

/// The list of hash algorithms compatible with AuthDecode.
const COMPATIBLE_ALGS: &[HashAlgId] = &[HashAlgId::POSEIDON_CIRCOMLIB];

/// Docs
pub struct AuthdecodeInputsWithAlg {
    /// Docs
    pub inputs: AuthdecodeInputs,
    /// Docs
    pub alg: HashAlgId,
}

/// Docs
/// The motivation for this type is not to expose core types and their non-public methods
/// to the prover crate.  
pub struct AuthdecodeInputs(Vec<AuthdecodeInput>);

struct AuthdecodeInput {
    salt: [u8; 16],
    plaintext: Vec<u8>,
    encodings: Vec<Vec<u8>>,
    range: Range<usize>,
}

impl
    TryFrom<(
        &Request,
        &Secrets,
        &(dyn EncodingProvider + Send + Sync),
        &Transcript,
    )> for AuthdecodeInputsWithAlg
{
    type Error = &'static str;

    fn try_from(
        tuple: (
            &Request,
            &Secrets,
            &(dyn EncodingProvider + Send + Sync),
            &Transcript,
        ),
    ) -> Result<Self, Self::Error> {
        let (request, secrets, encoding_provider, transcript) = tuple;

        let mut hash_alg: Option<HashAlgId> = None;

        let inputs: Vec<AuthdecodeInput> = request
            .plaintext_hashes
            .iter()
            .filter(|hash| COMPATIBLE_ALGS.contains(&hash.data.hash.alg))
            .map(|hash| {
                if hash_alg.is_none() {
                    hash_alg = Some(hash.data.hash.alg);
                } else if hash_alg != Some(hash.data.hash.alg) {
                    return Err(
                        "Only one AuthDecode-compatible hash algorithm is allowed in commitments",
                    );
                }
                let blinder = secrets
                    .plaintext_hashes
                    .get_by_transcript_idx(&hash.data.idx)
                    .unwrap()
                    .blinder
                    .clone();
                let subsequence = transcript.get(hash.data.direction, &hash.data.idx).unwrap();
                let plaintext = subsequence.data().to_vec();
                let encodings: Vec<Vec<u8>> = encoding_provider
                    .provide_encoding(hash.data.direction, &hash.data.idx)
                    .unwrap()
                    .chunks(encoding_provider.bit_encoding_len())
                    .map(|chunk| chunk.to_vec())
                    .collect::<Vec<_>>();

                let range = hash.data.idx.iter_ranges().next().unwrap();

                Ok(AuthdecodeInput {
                    encodings,
                    plaintext,
                    range,
                    salt: *blinder.as_inner(),
                })
            })
            .collect::<Result<Vec<_>, Self::Error>>()?;

        if inputs.is_empty() {
            return Err("At least one AuthDecode-compatible hash commitment is expected");
        }

        // It is safe to `.unwrap()` since if at least one commitment is present, `hash_alg` must
        // have been set.
        Ok(AuthdecodeInputsWithAlg {
            inputs: AuthdecodeInputs(inputs),
            alg: hash_alg.unwrap(),
        })
    }
}
