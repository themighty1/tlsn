//! HTTP Prover.
//!
//! An HTTP prover can be created from a TLS [`Prover`](crate::tls::Prover), after the TLS connection has been closed, by calling the
//! [`to_http`](crate::tls::Prover::to_http) method.
//!
//! The [`HttpProver`] provides higher-level APIs for committing and proving data communicated during an HTTP connection.

pub mod state;

use tlsn_core::commitment::TranscriptCommit;
use tlsn_formats::http::{
    parse_requests, parse_responses, HttpCommitmentError, HttpCommitter, HttpTranscript, ParseError,
};

use crate::tls::{state as prover_state, Prover, ProverError};

pub use tlsn_formats::http::NotarizedHttpSession;

/// HTTP prover error.
#[derive(Debug, thiserror::Error)]
pub enum HttpProverError {
    /// An error originated from the TLS prover.
    #[error(transparent)]
    Prover(#[from] ProverError),
    /// An error occurred while parsing the HTTP data.
    #[error(transparent)]
    Parse(#[from] ParseError),
}

/// An HTTP prover.
pub struct HttpProver<S: state::State> {
    state: S,
}

impl HttpProver<state::Closed> {
    /// Creates a new HTTP prover.
    pub fn new(prover: Prover<prover_state::Closed>) -> Result<Self, HttpProverError> {
        let requests = parse_requests(prover.sent_transcript().data().clone())?;
        let responses = parse_responses(prover.recv_transcript().data().clone())?;

        Ok(Self {
            state: state::Closed {
                prover,
                transcript: HttpTranscript {
                    requests,
                    responses,
                },
            },
        })
    }

    /// Starts notarization of the HTTP session.
    ///
    /// If the verifier is a Notary, this function will transition the prover to the next state
    /// where it can generate commitments to the transcript prior to finalization.
    pub fn start_notarize(self) -> HttpProver<state::Notarize> {
        HttpProver {
            state: state::Notarize {
                prover: self.state.prover.start_notarize(),
                transcript: self.state.transcript,
            },
        }
    }
}

impl HttpProver<state::Notarize> {
    /// Generates commitments to the HTTP session using the provided committer.
    pub fn commit_with<C: TranscriptCommit<HttpTranscript>>(
        &mut self,
        committer: &mut C,
    ) -> Result<(), C::Error> {
        committer.commit(
            self.state.prover.commitment_builder(),
            &self.state.transcript,
        )
    }

    /// Generates commitments to the HTTP session using the default committer.
    pub fn commit(&mut self) -> Result<(), HttpCommitmentError> {
        HttpCommitter::default().commit(
            self.state.prover.commitment_builder(),
            &self.state.transcript,
        )
    }

    /// Finalizes the HTTP session.
    pub async fn finalize(self) -> Result<NotarizedHttpSession, HttpProverError> {
        Ok(NotarizedHttpSession::new(
            self.state.prover.finalize().await?,
            self.state.transcript,
        ))
    }
}
