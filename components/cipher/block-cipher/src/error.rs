use std::error::Error;

/// Errors that can occur when using the block cipher
#[derive(Debug, thiserror::Error)]
#[allow(missing_docs)]
pub enum BlockCipherError {
    #[error("MPC backend error: {0:?}")]
    Mpc(Box<dyn Error + Send>),
    #[error("Cipher key not set")]
    KeyNotSet,
    #[error("Input does not match block length: expected {0}, got {1}")]
    InvalidInputLength(usize, usize),
}

impl From<mpz_garble::MemoryError> for BlockCipherError {
    fn from(err: mpz_garble::MemoryError) -> Self {
        BlockCipherError::Mpc(Box::new(err))
    }
}

impl From<mpz_garble::LoadError> for BlockCipherError {
    fn from(err: mpz_garble::LoadError) -> Self {
        BlockCipherError::Mpc(Box::new(err))
    }
}

impl From<mpz_garble::ExecutionError> for BlockCipherError {
    fn from(err: mpz_garble::ExecutionError) -> Self {
        BlockCipherError::Mpc(Box::new(err))
    }
}

impl From<mpz_garble::DecodeError> for BlockCipherError {
    fn from(err: mpz_garble::DecodeError) -> Self {
        BlockCipherError::Mpc(Box::new(err))
    }
}
