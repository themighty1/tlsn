use futures::{Sink, SinkExt};
use mpc_circuits::Circuit;
use mpc_garble_core::{
    label_state, msg::GarbleMessage, Delta, EncodedValue, Generator as GeneratorCore,
    GeneratorError as CoreError,
};
use mpc_ot::{
    config::{OTSenderConfig, OTSenderConfigBuilder},
    OTFactoryError, ObliviousSend,
};
use utils_aio::factory::AsyncFactory;

use crate::DEFAULT_BATCH_SIZE;

#[derive(Debug, thiserror::Error)]
pub enum GeneratorError {
    #[error(transparent)]
    CoreError(#[from] CoreError),
    #[error(transparent)]
    IOError(#[from] std::io::Error),
}

#[derive(Debug)]
pub struct Generator {
    batch_size: usize,
}

impl Default for Generator {
    fn default() -> Self {
        Self {
            batch_size: DEFAULT_BATCH_SIZE,
        }
    }
}

impl Generator {
    /// Asynchronously generate a garbled circuit, streaming the encrypted gates to
    /// the evaluator in batches.
    ///
    /// # Arguments
    ///
    /// * `circ` - The circuit to garble
    /// * `delta` - The delta value to use for the garbling
    /// * `inputs` - The inputs to use for the garbling
    pub async fn generate<S: Sink<GarbleMessage, Error = std::io::Error> + Unpin>(
        &mut self,
        circ: &Circuit,
        delta: Delta,
        inputs: &[EncodedValue<label_state::Full>],
        sink: &mut S,
    ) -> Result<Vec<EncodedValue<label_state::Full>>, GeneratorError> {
        let mut gen = GeneratorCore::new(circ, delta, inputs, false)?;

        while !gen.is_complete() {
            let mut batch = Vec::with_capacity(self.batch_size);
            while let Some(enc_gate) = gen.next() {
                batch.push(enc_gate);
                if batch.len() == self.batch_size {
                    break;
                }
            }
            sink.send(GarbleMessage::EncryptedGates(batch)).await?;
        }

        Ok(gen.outputs()?)
    }
}

pub(crate) async fn setup_generator_inputs<S, F, OTS>(
    ot_sender_factory: &mut F,
    sink: &mut S,
    ot_id: String,
    ot_send: Vec<EncodedValue<label_state::Full>>,
    direct_send: Vec<EncodedValue<label_state::Active>>,
) -> Result<(), GeneratorError>
where
    S: Sink<GarbleMessage, Error = std::io::Error> + Unpin,
    F: AsyncFactory<OTS, Config = OTSenderConfig, Error = OTFactoryError>,
    OTS: ObliviousSend<EncodedValue<label_state::Full>>,
{
    let ot_send_count = ot_send.iter().map(|v| v.value_type().len()).sum();
    let ot_config = OTSenderConfigBuilder::default()
        .count(ot_send_count)
        .build()
        .unwrap();
    let mut ot_sender = ot_sender_factory.create(ot_id, ot_config).await.unwrap();

    ot_sender.send(ot_send).await.unwrap();

    sink.send(GarbleMessage::ActiveValues(direct_send))
        .await
        .unwrap();

    Ok(())
}
