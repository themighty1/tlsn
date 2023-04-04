use futures::{SinkExt, StreamExt};
use mpc_circuits::Circuit;
use mpc_garble_core::{
    label_state, msg::GarbleMessage, Delta, EncodedValue, Evaluator, EvaluatorError as CoreError,
};
use utils_aio::{expect_msg_or_err, Channel};

#[derive(Debug, thiserror::Error)]
pub enum EvaluatorError {
    #[error(transparent)]
    CoreError(#[from] CoreError),
    #[error(transparent)]
    IOError(#[from] std::io::Error),
    #[error("Unexpected message: {0:?}")]
    UnexpectedMessage(GarbleMessage),
}

/// Asynchronously evaluate a garbled circuit, streaming the encrypted gates in batches.
///
/// # Arguments
///
/// * `circ` - The circuit to evaluate
/// * `inputs` - The inputs to use for the evaluation
/// * `channel` - The channel to use for streaming the encrypted gates
///
/// # Returns
///
/// The outputs of the circuit
pub async fn evaluate<C: Channel<GarbleMessage, Error = std::io::Error>>(
    circ: &Circuit,
    inputs: &[EncodedValue<label_state::Active>],
    channel: &mut C,
) -> Result<Vec<EncodedValue<label_state::Active>>, EvaluatorError> {
    let mut ev = Evaluator::new(circ, inputs, false)?;

    while !ev.is_complete() {
        let batch = expect_msg_or_err!(
            channel.next().await,
            GarbleMessage::EncryptedGates,
            EvaluatorError::UnexpectedMessage
        )?;

        ev.evaluate(batch);
    }

    Ok(ev.outputs()?)
}
