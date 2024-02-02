pub mod backend;
pub mod error;
pub mod prover;
pub mod state;

#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum EncodingsVerifierError {
    #[error("Verification failed")]
    VerificationFailed,
}

pub trait EncodingsVerifier {
    /// Verifies the authenticity of the provided full encodings.
    fn verify(&self, encodings: Vec<[u128; 2]>) -> Result<(), EncodingsVerifierError>;
}
