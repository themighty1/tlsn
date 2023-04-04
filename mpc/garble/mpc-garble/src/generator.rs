use futures::SinkExt;
use mpc_circuits::Circuit;
use mpc_garble_core::{
    label_state, msg::GarbleMessage, Delta, EncodedValue, Generator, GeneratorError as CoreError,
};
use utils_aio::Channel;

static BATCH_SIZE: usize = 1000;

#[derive(Debug, thiserror::Error)]
pub enum GeneratorError {
    #[error(transparent)]
    CoreError(#[from] CoreError),
    #[error(transparent)]
    IOError(#[from] std::io::Error),
}

/// Asynchronously generate a garbled circuit, streaming the encrypted gates in batches.
///
/// # Arguments
///
/// * `circ` - The circuit to garble
/// * `delta` - The delta value to use for the garbling
/// * `inputs` - The inputs to use for the garbling
/// * `channel` - The channel to use for streaming the encrypted gates
pub async fn generate<C: Channel<GarbleMessage, Error = std::io::Error>>(
    circ: &Circuit,
    delta: Delta,
    inputs: &[EncodedValue<label_state::Full>],
    channel: &mut C,
) -> Result<(), GeneratorError> {
    let mut gen = Generator::new(circ, delta, inputs)?;

    while !gen.is_complete() {
        let mut batch = Vec::with_capacity(BATCH_SIZE);
        while let Some(enc_gate) = gen.next() {
            batch.push(enc_gate);
            if batch.len() == BATCH_SIZE {
                break;
            }
        }
        channel.send(GarbleMessage::EncryptedGates(batch)).await?;
    }

    Ok(())
}
