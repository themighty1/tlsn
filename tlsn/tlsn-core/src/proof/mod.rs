//! Different types of proofs used in the TLSNotary protocol.

mod substrings;
mod tls;

pub use substrings::{
    SubstringProve, SubstringsProof, SubstringsProofBuilder, SubstringsProofBuilderError,
    SubstringsProofError,
};
pub use tls::{SessionProof, TlsProof};
