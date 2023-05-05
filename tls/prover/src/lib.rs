mod prover;

pub use crate::prover::Prover;

use self::prover::ProverError;

pub trait Prove {
    fn make_request<T: Into<Vec<u8>>>(&self, request: T) -> Result<(), ProverError>;
    fn get_response(&self) -> Result<Vec<u8>, ProverError>;
}
