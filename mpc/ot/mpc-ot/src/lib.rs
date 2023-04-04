pub mod kos;
#[cfg(feature = "mock")]
pub mod mock;

use async_trait::async_trait;
use futures::channel::oneshot::Canceled;
use mpc_circuits::types::Value;
use mpc_core::Block;
use mpc_garble_core::{label_state, EncodedValue, Label};
use mpc_ot_core::{
    msgs::{OTFactoryMessage, OTMessage},
    CommittedOTError, ExtReceiverCoreError, ExtSenderCoreError, ReceiverCoreError, SenderCoreError,
};
use utils::bits::ToBitsIter;
use utils_aio::{mux::MuxerError, Channel};

pub use mpc_ot_core::config;

type OTChannel = Box<dyn Channel<OTMessage, Error = std::io::Error>>;

#[derive(Debug, thiserror::Error)]
pub enum OTError {
    #[error("OT sender core error: {0}")]
    SenderCoreError(#[from] SenderCoreError),
    #[error("OT receiver core error: {0}")]
    ReceiverCoreError(#[from] ReceiverCoreError),
    #[error("OT sender core error: {0}")]
    ExtSenderCoreError(#[from] ExtSenderCoreError),
    #[error("OT receiver core error: {0}")]
    ExtReceiverCoreError(#[from] ExtReceiverCoreError),
    #[error(transparent)]
    ValueError(#[from] mpc_garble_core::ValueError),
    #[error("IO error")]
    IOError(#[from] std::io::Error),
    #[error("CommittedOT Error: {0}")]
    CommittedOT(#[from] CommittedOTError),
    #[error("Received unexpected message: {0:?}")]
    Unexpected(OTMessage),
    #[error("Received ciphertext with wrong length: expected {0}, got {1}")]
    InvalidCiphertextLength(usize, usize),
    #[error("Encountered error in backend")]
    Backend(#[from] Canceled),
}

#[derive(Debug, thiserror::Error)]
pub enum OTFactoryError {
    #[error("muxer error")]
    MuxerError(#[from] MuxerError),
    #[error("ot error")]
    OTError(#[from] OTError),
    #[error("io error")]
    IOError(#[from] std::io::Error),
    #[error("unexpected message")]
    UnexpectedMessage(OTFactoryMessage),
    #[error("{0} Sender expects {1} OTs, Receiver expects {2}")]
    SplitMismatch(String, usize, usize),
    #[error("other: {0}")]
    Other(String),
}

#[async_trait]
pub trait ObliviousSend<T> {
    async fn send(&mut self, inputs: Vec<T>) -> Result<(), OTError>;
}

#[async_trait]
pub trait ObliviousReceive<T, U> {
    async fn receive(&mut self, choices: Vec<T>) -> Result<Vec<U>, OTError>;
}

#[async_trait]
pub trait ObliviousCommit {
    /// Sends a commitment to the OT seed
    async fn commit(&mut self) -> Result<(), OTError>;
}

#[async_trait]
pub trait ObliviousReveal {
    /// Reveals the OT seed
    async fn reveal(mut self) -> Result<(), OTError>;
}

#[async_trait]
pub trait ObliviousAcceptCommit {
    /// Receives and stores a commitment to the OT seed
    async fn accept_commit(&mut self) -> Result<(), OTError>;
}

#[async_trait]
pub trait ObliviousVerify<T> {
    /// Verifies the correctness of the revealed OT seed
    async fn verify(self, input: Vec<T>) -> Result<(), OTError>;
}

#[async_trait]
impl<T> ObliviousSend<EncodedValue<label_state::Full>> for T
where
    T: Send + ObliviousSend<[Block; 2]>,
{
    async fn send(&mut self, inputs: Vec<EncodedValue<label_state::Full>>) -> Result<(), OTError> {
        self.send(
            inputs
                .iter()
                .flat_map(|value| value.iter_blocks())
                .collect::<Vec<[Block; 2]>>(),
        )
        .await
    }
}

#[async_trait]
impl<T> ObliviousReceive<Value, EncodedValue<label_state::Active>> for T
where
    T: Send + ObliviousReceive<bool, Block>,
{
    async fn receive(
        &mut self,
        choices: Vec<Value>,
    ) -> Result<Vec<EncodedValue<label_state::Active>>, OTError> {
        let types = choices
            .iter()
            .map(|value| value.value_type())
            .collect::<Vec<_>>();
        let choice_bits = choices
            .into_iter()
            .flat_map(|value| value.into_lsb0_iter())
            .collect::<Vec<bool>>();

        let mut blocks = self.receive(choice_bits).await?;

        Ok(types
            .into_iter()
            .map(|typ| {
                let labels = blocks
                    .drain(..typ.len())
                    .map(|block| Label::new(block))
                    .collect::<Vec<_>>();
                EncodedValue::<label_state::Active>::from_labels(typ, &labels)
            })
            .collect::<Result<Vec<_>, _>>()?)
    }
}

#[async_trait]
impl<T> ObliviousVerify<EncodedValue<label_state::Full>> for T
where
    T: Send + ObliviousVerify<[Block; 2]>,
{
    async fn verify(self, input: Vec<EncodedValue<label_state::Full>>) -> Result<(), OTError> {
        self.verify(input.iter().flat_map(|value| value.iter_blocks()).collect())
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mock::mock_ot_pair;
    use mpc_circuits::circuits::AES128;
    use mpc_garble_core::{ChaChaEncoder, Encoder};

    #[tokio::test]
    async fn test_encoded_value_transfer() {
        let (mut sender, mut receiver) = mock_ot_pair::<Block>();
        let mut encoder = ChaChaEncoder::new([0u8; 32]);
        let encoded_values = AES128
            .inputs()
            .iter()
            .map(|value| encoder.encode_by_type(0, value.value_type()))
            .collect::<Vec<_>>();

        let encoded_value = encoded_values[0].clone();
        let decoding = encoded_value.decoding();
        sender.send(vec![encoded_value]).await.unwrap();

        let value: Value = [69u8; 16].into();
        let received = receiver.receive(vec![value.clone()]).await.unwrap();

        let received_value = received[0].decode(&decoding).unwrap();

        assert_eq!(received_value, value);
    }
}
