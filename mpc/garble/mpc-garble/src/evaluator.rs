use std::collections::HashMap;

use futures::{Stream, StreamExt};
use mpc_circuits::{
    types::{TypeError, Value, ValueType},
    Circuit,
};
use mpc_garble_core::{
    label_state, msg::GarbleMessage, EncodedValue, Evaluator as EvaluatorCore,
    EvaluatorError as CoreError, GarbledCircuitDigest,
};
use mpc_ot::{
    config::{OTReceiverConfig, OTReceiverConfigBuilder},
    OTFactoryError, ObliviousReceive,
};
use utils_aio::{expect_msg_or_err, factory::AsyncFactory};

use crate::{types::ValueId, DEFAULT_BATCH_SIZE};

#[derive(Debug, thiserror::Error)]
pub enum EvaluatorError {
    #[error(transparent)]
    CoreError(#[from] CoreError),
    #[error(transparent)]
    IOError(#[from] std::io::Error),
    #[error("Unexpected message: {0:?}")]
    UnexpectedMessage(GarbleMessage),
    #[error(transparent)]
    TypeError(#[from] mpc_circuits::types::TypeError),
}

#[derive(Debug)]
pub struct Evaluator {
    batch_size: usize,
}

impl Default for Evaluator {
    fn default() -> Self {
        Self {
            batch_size: DEFAULT_BATCH_SIZE,
        }
    }
}

impl Evaluator {
    /// Asynchronously evaluate a garbled circuit, streaming the encrypted gates in batches.
    ///
    /// # Arguments
    ///
    /// * `circ` - The circuit to evaluate
    /// * `inputs` - The inputs to use for the evaluation
    /// * `stream` - The stream of encrypted gates
    ///
    /// # Returns
    ///
    /// The outputs of the garbled circuit
    pub async fn evaluate<S: Stream<Item = GarbleMessage> + Unpin>(
        &mut self,
        circ: &Circuit,
        inputs: &[EncodedValue<label_state::Active>],
        stream: &mut S,
    ) -> Result<Vec<EncodedValue<label_state::Active>>, EvaluatorError> {
        let ev = self.evaluate_internal(circ, inputs, stream, false).await?;
        Ok(ev.outputs()?)
    }

    /// Asynchronously evaluate a garbled circuit, streaming the encrypted gates in batches.
    ///
    /// This method also returns the digest of the garbled circuit.
    ///
    /// # Arguments
    ///
    /// * `circ` - The circuit to evaluate
    /// * `inputs` - The inputs to use for the evaluation
    /// * `stream` - The stream of encrypted gates
    ///
    /// # Returns
    ///
    /// The outputs and the digest of the garbled circuit
    pub async fn evaluate_and_digest<S: Stream<Item = GarbleMessage> + Unpin>(
        &mut self,
        circ: &Circuit,
        inputs: &[EncodedValue<label_state::Active>],
        stream: &mut S,
    ) -> Result<(Vec<EncodedValue<label_state::Active>>, GarbledCircuitDigest), EvaluatorError>
    {
        let ev = self.evaluate_internal(circ, inputs, stream, true).await?;
        let digest = ev.digest().expect("digest should be present");

        Ok((ev.outputs()?, digest))
    }

    async fn evaluate_internal<'a, S: Stream<Item = GarbleMessage> + Unpin>(
        &mut self,
        circ: &'a Circuit,
        inputs: &[EncodedValue<label_state::Active>],
        stream: &mut S,
        digest: bool,
    ) -> Result<EvaluatorCore<'a>, EvaluatorError> {
        let mut ev = EvaluatorCore::new(circ, inputs, digest)?;

        while !ev.is_complete() {
            let encrypted_gates = expect_msg_or_err!(
                stream.next().await,
                GarbleMessage::EncryptedGates,
                EvaluatorError::UnexpectedMessage
            )?;

            for batch in encrypted_gates.chunks(self.batch_size) {
                ev.evaluate(batch.iter());
            }
        }

        Ok(ev)
    }
}

pub(crate) async fn setup_evaluator_inputs<S, F, R>(
    ot_receiver_factory: &mut F,
    stream: &mut S,
    ot_id: String,
    ot_receive: HashMap<ValueId, Value>,
    direct_receive: HashMap<ValueId, ValueType>,
) -> Result<HashMap<ValueId, EncodedValue<label_state::Active>>, EvaluatorError>
where
    S: Stream<Item = GarbleMessage> + Unpin,
    F: AsyncFactory<R, Config = OTReceiverConfig, Error = OTFactoryError>,
    R: ObliviousReceive<Value, EncodedValue<label_state::Active>>,
{
    let ot_receive_count = ot_receive.values().map(|v| v.value_type().len()).sum();
    let ot_config = OTReceiverConfigBuilder::default()
        .count(ot_receive_count)
        .build()
        .unwrap();
    let mut ot_receiver = ot_receiver_factory.create(ot_id, ot_config).await.unwrap();

    let ot_received_encoded = ot_receiver
        .receive(ot_receive.values().cloned().collect())
        .await
        .unwrap();

    let direct_received = expect_msg_or_err!(
        stream.next().await,
        GarbleMessage::ActiveValues,
        EvaluatorError::UnexpectedMessage
    )
    .unwrap();

    let mut inputs = HashMap::new();

    for (received, (id, _)) in ot_received_encoded.into_iter().zip(ot_receive.into_iter()) {
        inputs.insert(id.clone(), received);
    }

    for (received, (id, expected_type)) in
        direct_received.into_iter().zip(direct_receive.into_iter())
    {
        if received.value_type() != expected_type {
            return Err(TypeError::UnexpectedType {
                expected: expected_type.clone(),
                actual: received.value_type().clone(),
            })?;
        }
        inputs.insert(id, received);
    }

    Ok(inputs)
}
