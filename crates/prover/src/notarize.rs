//! This module handles the notarization phase of the prover.
//!
//! The prover deals with a TLS verifier that is only a notary.

use crate::authdecode::{authdecode_prover, CommitmentSetWithSalt, TranscriptEncoder};

use super::{state::Notarize, Prover, ProverError};
use crate::authdecode::TranscriptProver;
use authdecode_core::{
    backend::{
        halo2::Bn256F,
        traits::{Field, ProverBackend},
    },
    id::IdCollection,
    msgs::Commit,
    prover::{commitment::CommitmentData, state::Committed},
    Prover as AuthDecodeProver,
};
use mpz_ot::VerifiableOTReceiver;
use serde::Serialize;
use serio::{stream::IoStreamExt as _, SinkExt as _};
use tlsn_core::{
    attestation::Attestation,
    hash::HashAlgId,
    request::{Request, RequestConfig},
    transcript::{
        authdecode::{AuthdecodeInputs, AuthdecodeInputsWithAlg},
        encoding::EncodingTree,
        Transcript, TranscriptCommitConfig,
    },
    Secrets,
};
use tracing::{debug, instrument};

impl Prover<Notarize> {
    /// Returns the transcript.
    pub fn transcript(&self) -> &Transcript {
        &self.state.transcript
    }

    /// Configures transcript commitments.
    pub fn transcript_commit(&mut self, config: TranscriptCommitConfig) {
        self.state.transcript_commit_config = Some(config);
    }

    /// Finalizes the notarization.
    #[instrument(parent = &self.span, level = "debug", skip_all, err)]
    pub async fn finalize(
        self,
        config: &RequestConfig,
    ) -> Result<(Attestation, Secrets), ProverError> {
        let Notarize {
            mut io,
            mux_ctrl,
            mut mux_fut,
            mut vm,
            mut ot_recv,
            mut ctx,
            connection_info,
            server_cert_data,
            transcript,
            encoding_provider,
            transcript_commit_config,
        } = self.state;

        let provider = self.config.crypto_provider();

        let hasher = provider.hash.get(config.hash_alg()).unwrap();

        let mut builder = Request::builder(config);

        builder
            .server_name(self.config.server_name().clone())
            .server_cert_data(server_cert_data)
            .transcript(transcript.clone());

        if let Some(config) = transcript_commit_config {
            if config.has_encoding() {
                builder.encoding_tree(
                    EncodingTree::new(
                        hasher,
                        config.iter_encoding(),
                        &*encoding_provider,
                        &connection_info.transcript_length,
                    )
                    .unwrap(),
                );
            }
        }

        let (request, secrets) = builder.build(provider).map_err(ProverError::attestation)?;

        let is_authdecode = true;

        let prover = match is_authdecode {
            true => Some(authdecode_prover(
                &request,
                &secrets,
                &*encoding_provider,
                &transcript,
            )),
            false => None,
        };
        let mut prover = prover.unwrap();

        let attestation = mux_fut
            .poll_with(async {
                debug!("starting finalization");

                io.send(request.clone()).await?;

                //if let Some(mut prover) = prover {
                let msg = prover.commit().unwrap();
                io.send(msg).await?;
                debug!("sent Authdecode commitment");
                //}

                ot_recv.accept_reveal(&mut ctx).await?;

                debug!("received OT secret");

                let seed = vm
                    .finalize()
                    .await?
                    .expect("The seed should be returned to the follower");

                //if let Some(mut prover) = prover {
                // Now that the full encodings were authenticated, it is safe to proceed to the
                // proof generation phase of the AuthDecode protocol.
                let msg = prover.prove(seed).unwrap();
                io.send(msg).await?;
                debug!("sent Authdecode proof");
                //}

                let attestation: Attestation = io.expect_next().await?;

                Ok::<_, ProverError>(attestation)
            })
            .await?;

        // Wait for the notary to correctly close the connection.
        if !mux_fut.is_complete() {
            mux_ctrl.mux().close();
            mux_fut.await?;
        }

        // Check the attestation is consistent with the Prover's view.
        request
            .validate(&attestation)
            .map_err(ProverError::attestation)?;

        Ok((attestation, secrets))
    }
}
