use std::{collections::HashMap, sync::Arc};

use futures::{lock::Mutex, task::Spawn, SinkExt, StreamExt};
use mpc_circuits::{
    types::{Value, ValueType},
    Circuit,
};
use mpc_garble_core::{
    label_state, msg::GarbleMessage, ChaChaEncoder, EncodedValue, Encoder, GarbledCircuitDigest,
    Generator,
};
use mpc_ot::{
    config::{OTReceiverConfig, OTSenderConfig},
    OTFactoryError, ObliviousReceive, ObliviousSend,
};
use utils_aio::{expect_msg_or_err, factory::AsyncFactory, mux::MuxChannelControl, Channel};

use crate::{evaluator::evaluate, generator::generate};

type ChannelFactory = Box<dyn MuxChannelControl<GarbleMessage> + Send + 'static>;
type GarbleChannel = Box<dyn Channel<GarbleMessage, Error = std::io::Error>>;

#[derive(Debug, Clone, PartialEq)]
pub struct RefValue(ValueId, ValueType);

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ValueId(String);

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ThreadId(String);

pub enum Visibility {
    /// A value known to all parties
    Public,
    /// A value known by one party
    Private,
    /// A value known by all parties, but not known to be the same
    Secret,
}

#[derive(Default)]
struct Memory {
    full_encoded: HashMap<ValueId, EncodedValue<label_state::Full>>,
    active_encoded: HashMap<ValueId, EncodedValue<label_state::Active>>,
    values: HashMap<ValueId, Value>,
}

#[derive(Debug, Default)]
struct GarbleLog(Vec<GarbledCircuitDigest>);

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Role {
    Leader,
    Follower,
}

pub struct DEAPVm<OTS, OTR> {
    role: Role,
    spawner: Arc<dyn Spawn + Send>,
    channel_factory: ChannelFactory,
    ot_sender: OTS,
    ot_receiver: OTR,

    encoder: Arc<Mutex<ChaChaEncoder>>,
    memory: Arc<Mutex<Memory>>,
    log: Arc<Mutex<GarbleLog>>,
}

impl<OTS, OTR> DEAPVm<OTS, OTR>
where
    OTS: ObliviousSend<EncodedValue<label_state::Full>> + Clone + Send + 'static,
    OTR: ObliviousReceive<Value, EncodedValue<label_state::Active>> + Clone + Send + 'static,
{
    pub fn new(
        role: Role,
        spawner: Arc<dyn Spawn + Send>,
        channel_factory: ChannelFactory,
        ot_sender: OTS,
        ot_receiver: OTR,
    ) -> Self {
        Self {
            role,
            spawner,
            channel_factory,
            ot_sender,
            ot_receiver,
            encoder: Arc::new(Mutex::new(ChaChaEncoder::new([0; 32]))),
            memory: Arc::new(Mutex::new(Memory::default())),
            log: Arc::new(Mutex::new(GarbleLog::default())),
        }
    }

    pub async fn new_thread(&mut self, id: ThreadId) -> DEAPThread<OTS, OTR> {
        let encoder = self.encoder.clone();
        let global_memory = self.memory.clone();
        let log = self.log.clone();
        let ot_sender = self.ot_sender.clone();
        let ot_receiver = self.ot_receiver.clone();

        let generator_channel = self
            .channel_factory
            .get_channel(format!("{}_gen", &id.0))
            .await
            .unwrap();
        let evaluator_channel = self
            .channel_factory
            .get_channel(format!("{}_ev", &id.0))
            .await
            .unwrap();

        DEAPThread::new(
            id,
            self.role,
            encoder,
            global_memory,
            log,
            generator_channel,
            evaluator_channel,
            ot_sender,
            ot_receiver,
        )
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ThreadError {
    #[error(transparent)]
    IOError(#[from] std::io::Error),
    #[error("value error: {0}")]
    ValueError(String),
    #[error("unexpected message: {0:?}")]
    UnexpectedMessage(GarbleMessage),
}

struct BufferedValue {
    domain: u32,
    value: Option<Value>,
    value_type: ValueType,
    visibility: Visibility,
}

pub struct DEAPThread<OTS, OTR> {
    id: ThreadId,
    role: Role,

    encoder: Arc<Mutex<ChaChaEncoder>>,
    global_memory: Arc<Mutex<Memory>>,
    value_buffer: HashMap<ValueId, BufferedValue>,
    log: Arc<Mutex<GarbleLog>>,

    generator_channel: GarbleChannel,
    evaluator_channel: GarbleChannel,

    ot_sender: OTS,
    ot_receiver: OTR,
}

impl<OTS, OTR> DEAPThread<OTS, OTR>
where
    OTS: ObliviousSend<EncodedValue<label_state::Full>> + Clone + Send + 'static,
    OTR: ObliviousReceive<Value, EncodedValue<label_state::Active>> + Clone + Send + 'static,
{
    fn new(
        id: ThreadId,
        role: Role,
        encoder: Arc<Mutex<ChaChaEncoder>>,
        global_memory: Arc<Mutex<Memory>>,
        log: Arc<Mutex<GarbleLog>>,
        generator_channel: GarbleChannel,
        evaluator_channel: GarbleChannel,
        ot_sender: OTS,
        ot_receiver: OTR,
    ) -> Self {
        Self {
            id,
            role,
            encoder,
            global_memory,
            value_buffer: HashMap::new(),
            log,
            generator_channel,
            evaluator_channel,
            ot_sender,
            ot_receiver,
        }
    }

    /// Synchronizes the thread state with all parties.
    pub async fn sync(&mut self) -> Result<(), ThreadError> {
        for (id, buffered_value) in self.value_buffer.drain() {
            let BufferedValue {
                domain,
                value,
                value_type,
                visibility,
            } = buffered_value;

            match visibility {
                Visibility::Public => {
                    let value = value.unwrap();

                    let encoded_full = self.encoder.lock().await.encode_by_type(domain, value_type);
                    let encoded_active = encoded_full.select(value).unwrap();

                    self.generator_channel
                        .send(GarbleMessage::ActiveValue(encoded_active))
                        .await
                        .unwrap();

                    let peer_encoded_active = expect_msg_or_err!(
                        self.evaluator_channel.next().await,
                        GarbleMessage::ActiveValue,
                        ThreadError::UnexpectedMessage
                    )
                    .unwrap();

                    // Insert into global memory
                    let mut mem = self.global_memory.lock().await;
                    mem.full_encoded.insert(id.clone(), encoded_full);
                    mem.active_encoded.insert(id.clone(), peer_encoded_active);
                }
                Visibility::Private => {
                    if let Some(value) = value {
                        let encoded_full =
                            self.encoder.lock().await.encode_by_type(domain, value_type);
                        let encoded_active = encoded_full.select(value.clone()).unwrap();

                        self.generator_channel
                            .send(GarbleMessage::ActiveValue(encoded_active))
                            .await
                            .unwrap();

                        let peer_encoded_active = self
                            .ot_receiver
                            .receive(vec![value])
                            .await
                            .unwrap()
                            .pop()
                            .unwrap();

                        // Insert into global memory
                        let mut mem = self.global_memory.lock().await;
                        mem.full_encoded.insert(id.clone(), encoded_full);
                        mem.active_encoded.insert(id.clone(), peer_encoded_active);
                    } else {
                        let encoded_full =
                            self.encoder.lock().await.encode_by_type(domain, value_type);

                        self.ot_sender
                            .send(vec![encoded_full.clone()])
                            .await
                            .unwrap();

                        let peer_encoded_active = expect_msg_or_err!(
                            self.evaluator_channel.next().await,
                            GarbleMessage::ActiveValue,
                            ThreadError::UnexpectedMessage
                        )
                        .unwrap();

                        // Insert into global memory
                        let mut mem = self.global_memory.lock().await;
                        mem.full_encoded.insert(id.clone(), encoded_full);
                        mem.active_encoded.insert(id.clone(), peer_encoded_active);
                    }
                }
                Visibility::Secret => {
                    let value = value.unwrap();

                    let encoded_full = self.encoder.lock().await.encode_by_type(domain, value_type);
                    let encoded_active = encoded_full.select(value).unwrap();

                    self.generator_channel
                        .send(GarbleMessage::ActiveValue(encoded_active))
                        .await
                        .unwrap();

                    let peer_encoded_active = expect_msg_or_err!(
                        self.evaluator_channel.next().await,
                        GarbleMessage::ActiveValue,
                        ThreadError::UnexpectedMessage
                    )
                    .unwrap();

                    // Insert into global memory
                    let mut mem = self.global_memory.lock().await;
                    mem.full_encoded.insert(id.clone(), encoded_full);
                    mem.active_encoded.insert(id.clone(), peer_encoded_active);
                }
            }
        }

        Ok(())
    }

    pub async fn new_value(
        &mut self,
        domain: u32,
        id: &str,
        value: Option<impl Into<Value>>,
        value_type: ValueType,
        visibility: Visibility,
    ) -> Result<ValueId, ThreadError> {
        let id = ValueId(id.to_string());

        self.value_buffer.insert(
            id.clone(),
            BufferedValue {
                domain,
                value: value.map(|v| v.into()),
                value_type,
                visibility,
            },
        );

        Ok(id)
    }

    pub async fn execute(&mut self, circ: &Circuit, inputs: &[ValueId]) -> Result<(), ThreadError> {
        self.sync().await?;

        let mem = self.global_memory.lock().await;

        let delta = self.encoder.lock().await.get_delta();
        let gen_inputs = inputs
            .iter()
            .map(|id| mem.full_encoded.get(id).unwrap().clone())
            .collect::<Vec<_>>();

        let gen_fut = generate(circ, delta, &gen_inputs, &mut self.generator_channel);

        let ev_inputs = inputs
            .iter()
            .map(|id| mem.active_encoded.get(id).unwrap().clone())
            .collect::<Vec<_>>();

        let ev_fut = evaluate(circ, &ev_inputs, &mut self.evaluator_channel);

        drop(mem);

        let (gen_result, ev_result) = futures::join!(gen_fut, ev_fut);

        gen_result.unwrap();
        let _ = ev_result.unwrap();

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use async_executors::TokioTpBuilder;
    use mpc_ot::mock::mock_ot_pair;
    use utils_aio::mux::mock::MockMuxChannelFactory;

    #[tokio::test]
    async fn test_vm() {
        let mux_factory = MockMuxChannelFactory::new();
        let (leader_sender, follower_receiver) = mock_ot_pair();
        let (follower_sender, leader_receiver) = mock_ot_pair();
        let exec = Arc::new(TokioTpBuilder::new().build().unwrap());
        let mut leader = DEAPVm::new(
            Role::Leader,
            exec,
            Box::new(mux_factory),
            leader_sender,
            leader_receiver,
        );
    }
}
