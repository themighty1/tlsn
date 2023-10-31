use std::error::Error;

use tlsn_core::commitment::{
    TranscriptCommit, TranscriptCommitmentBuilder, TranscriptCommitmentBuilderError,
};

use crate::{
    http::{Body, Request, Response},
    json::JsonCommitter,
    unknown::UnknownCommitter,
};

use super::HttpTranscript;

#[derive(Debug, thiserror::Error)]
pub enum HttpCommitmentError {
    #[error("request commitment error: index {0}, error: {1}")]
    Request(usize, TranscriptCommitmentBuilderError),
    #[error("response commitment error: index {0}, error: {1}")]
    Response(usize, TranscriptCommitmentBuilderError),
    #[error("body commitment error: {0}")]
    Body(Box<dyn Error + Send + 'static>),
}

/// Default committer for HTTP transcripts.
#[derive(Debug)]
pub struct HttpCommitter {}

#[allow(clippy::derivable_impls)]
impl Default for HttpCommitter {
    fn default() -> Self {
        Self {}
    }
}

impl HttpCommitter {
    fn commit_request(
        &mut self,
        builder: &mut TranscriptCommitmentBuilder,
        idx: usize,
        request: &Request,
    ) -> Result<(), HttpCommitmentError> {
        builder
            .commit(&request.without_data())
            .map_err(|e| HttpCommitmentError::Request(idx, e))?;
        builder
            .commit(&request.request.path)
            .map_err(|e| HttpCommitmentError::Request(idx, e))?;

        for header in &request.headers {
            builder
                .commit(header)
                .map_err(|e| HttpCommitmentError::Request(idx, e))?;

            builder
                .commit(&header.without_value())
                .map_err(|e| HttpCommitmentError::Request(idx, e))?;
        }

        if let Some(body) = &request.body {
            self.commit_body(builder, body)?;
        }

        Ok(())
    }

    fn commit_response(
        &mut self,
        builder: &mut TranscriptCommitmentBuilder,
        idx: usize,
        response: &Response,
    ) -> Result<(), HttpCommitmentError> {
        builder
            .commit(&response.without_data())
            .map_err(|e| HttpCommitmentError::Response(idx, e))?;

        for header in &response.headers {
            builder
                .commit(header)
                .map_err(|e| HttpCommitmentError::Response(idx, e))?;

            builder
                .commit(&header.without_value())
                .map_err(|e| HttpCommitmentError::Response(idx, e))?;
        }

        if let Some(body) = &response.body {
            self.commit_body(builder, body)?;
        }

        Ok(())
    }

    fn commit_body(
        &mut self,
        builder: &mut TranscriptCommitmentBuilder,
        body: &Body,
    ) -> Result<(), HttpCommitmentError> {
        match body {
            Body::Json(body) => {
                JsonCommitter::default()
                    .commit(builder, body)
                    .map_err(|e| HttpCommitmentError::Body(Box::new(e)))?;
            }
            Body::Unknown(body) => {
                UnknownCommitter::default()
                    .commit(builder, body)
                    .map_err(|e| HttpCommitmentError::Body(Box::new(e)))?;
            }
        }

        Ok(())
    }
}

impl TranscriptCommit<HttpTranscript> for HttpCommitter {
    type Error = HttpCommitmentError;

    fn commit(
        &mut self,
        builder: &mut TranscriptCommitmentBuilder,
        transcript: &HttpTranscript,
    ) -> Result<(), HttpCommitmentError> {
        for (idx, request) in transcript.requests.iter().enumerate() {
            self.commit_request(builder, idx, request)?;
        }

        for (idx, response) in transcript.responses.iter().enumerate() {
            self.commit_response(builder, idx, response)?;
        }

        Ok(())
    }
}
