use std::{
    collections::HashMap,
    marker::PhantomData,
    ops::{Deref, DerefMut},
    sync::{Arc, Mutex},
};

use futures::{
    stream::{SplitSink, SplitStream},
    task::Spawn,
    SinkExt, StreamExt,
};
use mpc_circuits::{
    types::{Value, ValueType},
    Circuit,
};
use mpc_core::commit::{Commit, HashCommitment, Opening};
use mpc_garble_core::{
    label_state,
    msg::{GarbleMessage, VmMessage},
    ChaChaEncoder, Delta, EncodedValue, Encoder, EqualityCheck, GarbledCircuitDigest,
};
use mpc_ot::{
    config::{OTReceiverConfig, OTReceiverConfigBuilder, OTSenderConfig, OTSenderConfigBuilder},
    OTFactoryError, ObliviousReceive, ObliviousSend,
};
use utils_aio::{expect_msg_or_err, factory::AsyncFactory, mux::MuxChannelControl, Channel};

use crate::{
    config::{Role, ValueConfig, ValueConfigBuilder, Visibility},
    evaluator::{setup_evaluator_inputs, Evaluator},
    generator::{setup_generator_inputs, Generator},
    types::{OperationId, ThreadId, ThreadName, ValueId, ValueRef},
};

type ChannelFactory = Box<dyn MuxChannelControl<GarbleMessage> + Send + 'static>;
type GarbleChannel = Box<dyn Channel<GarbleMessage, Error = std::io::Error>>;

type OTSender = Box<dyn ObliviousSend<EncodedValue<label_state::Full>> + Send + 'static>;
type OTReceiver =
    Box<dyn ObliviousReceive<Value, EncodedValue<label_state::Active>> + Send + 'static>;

#[derive(Default)]
struct Memory {
    full_encoded: HashMap<ValueId, EncodedValue<label_state::Full>>,
    active_encoded: HashMap<ValueId, EncodedValue<label_state::Active>>,
    values: HashMap<ValueId, Value>,
}

struct Globals<SF, RF, S, R> {
    encoder: ChaChaEncoder,
    memory: Memory,
    threads: HashMap<ThreadId, DEAPThread<SF, RF, S, R>>,
    log: HashMap<ThreadId, DEAPThreadFinalizer>,
}

impl<SF, RF, S, R> Default for Globals<SF, RF, S, R> {
    fn default() -> Self {
        Self {
            encoder: Default::default(),
            memory: Default::default(),
            threads: Default::default(),
            log: Default::default(),
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum VmError {
    #[error("thread {0} already in use")]
    ThreadAlreadyInUse(usize),
    #[error(transparent)]
    IOError(#[from] std::io::Error),
    #[error("unexpected message: {0:?}")]
    UnexpectedMessage(GarbleMessage),
}

pub struct DEAPVm<SF, RF, S, R> {
    role: Role,

    channel_factory: ChannelFactory,
    ot_sender_factory: SF,
    ot_receiver_factory: RF,

    channel: GarbleChannel,
    globals: Arc<Mutex<Globals<SF, RF, S, R>>>,
    thread_count: usize,

    _ot_sender: PhantomData<S>,
    _ot_receiver: PhantomData<R>,
}

impl<SF, RF, S, R> DEAPVm<SF, RF, S, R>
where
    SF: AsyncFactory<S, Config = OTSenderConfig, Error = OTFactoryError> + Clone + Send + 'static,
    RF: AsyncFactory<R, Config = OTReceiverConfig, Error = OTFactoryError> + Clone + Send + 'static,
    S: ObliviousSend<EncodedValue<label_state::Full>> + Send + 'static,
    R: ObliviousReceive<Value, EncodedValue<label_state::Active>> + Send + 'static,
{
    pub fn new(
        role: Role,
        channel: GarbleChannel,
        channel_factory: ChannelFactory,
        ot_sender_factory: SF,
        ot_receiver_factory: RF,
        thread_count: usize,
    ) -> Self {
        Self {
            role,
            channel_factory,
            ot_sender_factory,
            ot_receiver_factory,
            channel,
            globals: Arc::new(Mutex::new(Globals::default())),
            thread_count,
            _ot_sender: PhantomData::<S>,
            _ot_receiver: PhantomData::<R>,
        }
    }

    pub async fn setup(&mut self) -> Result<(), VmError> {
        for id in 0..self.thread_count {
            let id = ThreadId::new(id);
            self.new_thread(id).await;
        }

        Ok(())
    }

    async fn new_thread(&mut self, id: ThreadId) -> Result<(), VmError> {
        let channel = self
            .channel_factory
            .get_channel(format!("vm/{}", id.as_ref()))
            .await
            .unwrap();

        self.globals
            .lock()
            .expect("lock should not be poisoned")
            .threads
            .insert(
                id,
                DEAPThread::new(
                    id,
                    self.role,
                    self.globals.clone(),
                    channel,
                    self.ot_sender_factory.clone(),
                    self.ot_receiver_factory.clone(),
                ),
            );

        Ok(())
    }

    pub fn get_thread(&mut self, id: usize) -> Result<DEAPThreadHandle<SF, RF, S, R>, VmError> {
        let id = ThreadId::new(id);

        Ok(DEAPThreadHandle {
            thread: Some(
                self.globals
                    .lock()
                    .expect("lock should not be poisoned")
                    .threads
                    .remove(&id)
                    .ok_or(VmError::ThreadAlreadyInUse(*id.as_ref()))?,
            ),
        })
    }

    pub async fn finalize(&mut self) -> Result<(), VmError> {
        let mut globals = self.globals.lock().unwrap();

        // match self.role {
        //     Role::Leader => {
        //         let delta = expect_msg_or_err!(
        //             self.channel.next().await,
        //             GarbleMessage::Delta,
        //             VmError::UnexpectedMessage
        //         )
        //         .unwrap();

        //         for finalizer in globals.log.values_mut() {
        //             finalizer.finalize_circuits(delta).unwrap();
        //         }

        //         for (_, mut finalizer) in globals.log.drain() {
        //             finalizer.finalize_equality_checks().await.unwrap();
        //         }
        //     }
        //     Role::Follower => {
        //         let delta = globals.encoder.get_delta();

        //         self.channel.send(GarbleMessage::Delta(delta)).await?;

        //         for (_, mut finalizer) in globals.log.drain() {
        //             finalizer.finalize_equality_checks().await.unwrap();
        //         }
        //     }
        // }

        Ok(())
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

struct DEAPThreadFinalizer {
    role: Role,
    channel: GarbleChannel,
    logs: Vec<ThreadLog>,
    eq_openings: Vec<Opening<EqualityCheck>>,
    eq_commitments: Vec<HashCommitment>,
}

struct ThreadLog {
    circ: Arc<Circuit>,
    inputs: Vec<EncodedValue<label_state::Active>>,
    digest: GarbledCircuitDigest,
}

impl DEAPThreadFinalizer {
    fn finalize_circuits(&mut self, delta: Delta) -> Result<(), ThreadError> {
        // for log in self.logs.drain(..) {
        //     let ThreadLog {
        //         circ,
        //         inputs,
        //         digest,
        //     } = log;

        //     digest.verify(&circ, delta, &inputs).unwrap();
        // }

        Ok(())
    }

    async fn finalize_equality_checks(&mut self) -> Result<(), ThreadError> {
        match self.role {
            Role::Leader => {
                let openings = self.eq_openings.drain(..).collect();
                self.channel
                    .send(GarbleMessage::EqualityCheckOpenings(openings))
                    .await?;
            }
            Role::Follower => {
                let openings = expect_msg_or_err!(
                    self.channel.next().await,
                    GarbleMessage::EqualityCheckOpenings,
                    ThreadError::UnexpectedMessage
                )
                .unwrap();

                for (commitment, opening) in self.eq_commitments.drain(..).zip(openings) {
                    opening.verify(&commitment).unwrap();
                }
            }
        }

        Ok(())
    }
}

pub struct DEAPThreadHandle<SF, RF, S, R> {
    thread: Option<DEAPThread<SF, RF, S, R>>,
}

impl<SF, RF, S, R> Drop for DEAPThreadHandle<SF, RF, S, R> {
    fn drop(&mut self) {
        if let Some(thread) = self.thread.take() {
            let globals = thread.globals.clone();

            globals
                .lock()
                .expect("lock should not be poisoned")
                .threads
                .insert(thread.id, thread);
        }
    }
}

impl<SF, RF, S, R> Deref for DEAPThreadHandle<SF, RF, S, R> {
    type Target = DEAPThread<SF, RF, S, R>;

    fn deref(&self) -> &Self::Target {
        self.thread.as_ref().unwrap()
    }
}

impl<SF, RF, S, R> DerefMut for DEAPThreadHandle<SF, RF, S, R> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.thread.as_mut().unwrap()
    }
}

pub struct DEAPThread<SF, RF, S, R> {
    id: ThreadId,
    role: Role,
    operation_id: OperationId,

    globals: Arc<Mutex<Globals<SF, RF, S, R>>>,
    local_memory: Memory,
    logs: Vec<ThreadLog>,
    eq_openings: Vec<Opening<EqualityCheck>>,
    eq_commitments: Vec<HashCommitment>,
    value_buffer: Vec<(Option<Value>, ValueConfig)>,

    gen: Generator,
    ev: Evaluator,

    sink: SplitSink<GarbleChannel, GarbleMessage>,
    stream: SplitStream<GarbleChannel>,

    ot_sender_factory: SF,
    ot_receiver_factory: RF,
    _ot_sender: PhantomData<S>,
    _ot_receiver: PhantomData<R>,
}

impl<SF, RF, S, R> DEAPThread<SF, RF, S, R>
where
    SF: AsyncFactory<S, Config = OTSenderConfig, Error = OTFactoryError> + Send + 'static,
    RF: AsyncFactory<R, Config = OTReceiverConfig, Error = OTFactoryError> + Send + 'static,
    S: ObliviousSend<EncodedValue<label_state::Full>> + Send + 'static,
    R: ObliviousReceive<Value, EncodedValue<label_state::Active>> + Send + 'static,
{
    fn new(
        id: ThreadId,
        role: Role,
        globals: Arc<Mutex<Globals<SF, RF, S, R>>>,
        channel: GarbleChannel,
        ot_sender_factory: SF,
        ot_receiver_factory: RF,
    ) -> Self {
        println!("new thread: {:?}, role: {:?}", &id.as_ref(), &role);
        let (sink, stream) = channel.split();
        Self {
            id,
            role,
            operation_id: OperationId::default(),
            globals,
            local_memory: Memory::default(),
            logs: Vec::new(),
            eq_openings: Vec::new(),
            eq_commitments: Vec::new(),
            value_buffer: Vec::new(),
            gen: Generator::default(),
            ev: Evaluator::default(),
            sink,
            stream,
            ot_sender_factory,
            ot_receiver_factory,
            _ot_sender: PhantomData::<S>,
            _ot_receiver: PhantomData::<R>,
        }
    }

    fn collect_generator_inputs(
        &mut self,
        values: &[(Option<Value>, ValueConfig)],
    ) -> Result<
        (
            HashMap<ValueId, EncodedValue<label_state::Full>>,
            HashMap<ValueId, EncodedValue<label_state::Active>>,
        ),
        ThreadError,
    > {
        let mut ot_send_encoded = HashMap::new();
        let mut direct_send_encoded = HashMap::new();
        for (value, config) in values {
            let ValueConfig {
                domain,
                id,
                value_type,
                visibility,
                ..
            } = config;

            let encoded_full = self
                .globals
                .lock()
                .unwrap()
                .encoder
                .encode_by_type(*domain, value_type.clone());
            self.local_memory
                .full_encoded
                .insert(id.clone(), encoded_full.clone());

            match (value, visibility) {
                (Some(value), Visibility::Public) => {
                    direct_send_encoded
                        .insert(id.clone(), encoded_full.select(value.clone()).unwrap());
                }
                (Some(value), Visibility::Private) => {
                    direct_send_encoded
                        .insert(id.clone(), encoded_full.select(value.clone()).unwrap());
                }
                (None, Visibility::Private) => {
                    ot_send_encoded.insert(id.clone(), encoded_full);
                }
                _ => panic!(),
            }
        }

        Ok((ot_send_encoded, direct_send_encoded))
    }

    fn collect_evaluator_inputs(
        &mut self,
        values: &[(Option<Value>, ValueConfig)],
    ) -> Result<(HashMap<ValueId, Value>, HashMap<ValueId, ValueType>), ThreadError> {
        let mut ot_receive_values = HashMap::new();
        let mut direct_receive_encoded = HashMap::new();
        for (value, config) in values {
            let ValueConfig {
                domain,
                id,
                value_type,
                visibility,
                ..
            } = config;

            match (value, visibility) {
                (Some(value), Visibility::Public) => {
                    direct_receive_encoded.insert(*id, value_type.clone());
                }
                (Some(value), Visibility::Private) => {
                    ot_receive_values.insert(*id, value.clone());
                }
                (None, Visibility::Private) => {
                    direct_receive_encoded.insert(*id, value_type.clone());
                }
                _ => panic!(),
            }
        }

        Ok((ot_receive_values, direct_receive_encoded))
    }

    pub async fn setup_dual_inputs(&mut self) -> Result<(), ThreadError> {
        let mut value_buffer = self.value_buffer.drain(..).collect::<Vec<_>>();
        value_buffer.sort_by_key(|(_, config)| config.id.clone());

        let (ot_send_encoded, direct_send_encoded) =
            self.collect_generator_inputs(&value_buffer)?;
        let (ot_receive_values, direct_receive_encoded) =
            self.collect_evaluator_inputs(&value_buffer)?;

        let (ots_id, otr_id) = {
            let id_0 = format!("{}/{}/ot/0", self.id.as_ref(), self.operation_id.as_ref());
            let id_1 = format!("{}/{}/ot/1", self.id.as_ref(), self.operation_id.as_ref());

            match self.role {
                Role::Leader => (id_0, id_1),
                Role::Follower => (id_1, id_0),
            }
        };

        setup_generator_inputs(
            &mut self.ot_sender_factory,
            &mut self.sink,
            ots_id,
            ot_send_encoded.values().cloned().collect(),
            direct_send_encoded.values().cloned().collect(),
        )
        .await
        .unwrap();

        println!("role: {:?}, ot send done", &self.role);

        let active_encoded = setup_evaluator_inputs(
            &mut self.ot_receiver_factory,
            &mut self.stream,
            otr_id,
            ot_receive_values.clone(),
            direct_receive_encoded.clone(),
        )
        .await
        .unwrap();

        active_encoded.into_iter().for_each(|(id, encoded)| {
            self.local_memory.active_encoded.insert(id, encoded);
        });

        println!("Thread {}, role {:?}, synced", self.id.as_ref(), self.role);

        Ok(())
    }

    pub fn new_value(
        &mut self,
        value: Option<Value>,
        config: ValueConfig,
    ) -> Result<ValueRef, ThreadError> {
        let id = config.id.clone();
        let value_type = config.value_type.clone();
        self.value_buffer.push((value, config));

        Ok(ValueRef::new(id, value_type))
    }

    pub async fn execute(
        &mut self,
        circ: Arc<Circuit>,
        inputs: &[ValueRef],
        outputs: &[&str],
    ) -> Result<Vec<ValueRef>, ThreadError> {
        self.setup_dual_inputs().await?;

        let delta = self.globals.lock().unwrap().encoder.get_delta();
        let gen_inputs = inputs
            .iter()
            .map(|input| {
                self.local_memory
                    .full_encoded
                    .get(input.id())
                    .unwrap()
                    .clone()
            })
            .collect::<Vec<_>>();

        let gen_fut = self.gen.generate(&circ, delta, &gen_inputs, &mut self.sink);

        let ev_inputs = inputs
            .iter()
            .map(|input| {
                self.local_memory
                    .active_encoded
                    .get(input.id())
                    .unwrap()
                    .clone()
            })
            .collect::<Vec<_>>();

        let ev_fut = self
            .ev
            .evaluate_and_digest(&circ, &ev_inputs, &mut self.stream);

        let (gen_result, ev_result) = futures::join!(gen_fut, ev_fut);

        let full_encoded = gen_result.unwrap();
        let (active_encoded, digest) = ev_result.unwrap();

        if let Role::Leader = self.role {
            self.logs.push(ThreadLog {
                circ,
                inputs: ev_inputs,
                digest,
            })
        };

        let outputs = outputs
            .iter()
            .zip(full_encoded.into_iter())
            .zip(active_encoded.into_iter())
            .map(|((id, full), active)| {
                let id = ValueId::new(id).unwrap();
                let value_ref = ValueRef::new(id, active.value_type());

                // Store the encoded values in the local memory.
                self.local_memory.full_encoded.insert(id, full);
                self.local_memory.active_encoded.insert(id, active);

                value_ref
            })
            .collect();

        Ok(outputs)
    }

    /// Decodes the given values.
    ///
    /// Note that all parties must call this function with the same set of values,
    /// in the same order.
    pub async fn decode(&mut self, refs: &[ValueRef]) -> Result<Vec<Value>, ThreadError> {
        let full = refs
            .iter()
            .map(|value| {
                self.local_memory
                    .full_encoded
                    .get(value.id())
                    .unwrap()
                    .clone()
            })
            .collect::<Vec<_>>();

        let decodings = full.iter().map(|full| full.decoding()).collect::<Vec<_>>();

        self.sink
            .send(GarbleMessage::ValueDecodings(decodings.clone()))
            .await
            .unwrap();

        let peer_decodings = expect_msg_or_err!(
            self.stream.next().await,
            GarbleMessage::ValueDecodings,
            ThreadError::UnexpectedMessage
        )
        .unwrap();

        let active = refs
            .iter()
            .map(|value| {
                self.local_memory
                    .active_encoded
                    .get(value.id())
                    .unwrap()
                    .clone()
            })
            .collect::<Vec<_>>();

        let purported_values = active
            .iter()
            .zip(peer_decodings.into_iter())
            .map(|(active, decoding)| active.decode(&decoding).unwrap())
            .collect::<Vec<_>>();

        let eq_check = EqualityCheck::new(
            &full,
            &active,
            &purported_values,
            match self.role {
                Role::Leader => false,
                Role::Follower => true,
            },
        );

        let outputs = match self.role {
            Role::Leader => {
                let (opening, commit) = eq_check.commit().unwrap();
                self.eq_openings.push(opening);

                self.sink
                    .send(GarbleMessage::HashCommitment(commit.into()))
                    .await
                    .unwrap();

                let active = expect_msg_or_err!(
                    self.stream.next().await,
                    GarbleMessage::ActiveValues,
                    ThreadError::UnexpectedMessage
                )
                .unwrap();

                let values = active
                    .into_iter()
                    .zip(full)
                    .zip(decodings)
                    .map(|((active, full), decoding)| {
                        full.verify(&active).unwrap();
                        active.decode(&decoding).unwrap()
                    })
                    .collect();

                values
            }
            Role::Follower => {
                let commit = expect_msg_or_err!(
                    self.stream.next().await,
                    GarbleMessage::HashCommitment,
                    ThreadError::UnexpectedMessage
                )
                .unwrap();

                self.eq_commitments.push(commit.into());

                self.sink
                    .send(GarbleMessage::ActiveValues(active))
                    .await
                    .unwrap();

                purported_values
            }
        };

        Ok(outputs)
    }

    pub async fn prove(&mut self, circ: &Circuit, inputs: &[ValueRef]) -> Result<(), ThreadError> {
        todo!()
    }

    pub async fn verify(
        &mut self,
        circ: &Circuit,
        inputs: &[ValueRef],
        expected_outputs: &[Value],
    ) -> Result<(), ThreadError> {
        todo!()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use mpc_circuits::circuits::AES128;

    use mpc_core::Block;
    use mpc_ot::mock::{MockOTFactory, MockOTReceiver, MockOTSender};
    use utils_aio::mux::mock::MockMuxChannelFactory;

    async fn create_vm_pair() -> (
        DEAPVm<
            MockOTFactory<Block>,
            MockOTFactory<Block>,
            MockOTSender<Block>,
            MockOTReceiver<Block>,
        >,
        DEAPVm<
            MockOTFactory<Block>,
            MockOTFactory<Block>,
            MockOTSender<Block>,
            MockOTReceiver<Block>,
        >,
    ) {
        let mut mux_factory = MockMuxChannelFactory::new();
        let leader_ot_sender_factory = MockOTFactory::<Block>::new();
        let follower_ot_receiver_factory = leader_ot_sender_factory.clone();
        let leader_ot_receiver_factory = MockOTFactory::<Block>::new();
        let follower_ot_sender_factory = leader_ot_receiver_factory.clone();

        let leader_channel = mux_factory
            .get_channel("mock/vm".to_string())
            .await
            .unwrap();
        let follower_channel = mux_factory
            .get_channel("mock/vm".to_string())
            .await
            .unwrap();

        let mut leader = DEAPVm::new(
            Role::Leader,
            leader_channel,
            Box::new(mux_factory.clone()),
            leader_ot_sender_factory,
            leader_ot_receiver_factory,
            8,
        );

        let mut follower = DEAPVm::new(
            Role::Follower,
            follower_channel,
            Box::new(mux_factory),
            follower_ot_sender_factory,
            follower_ot_receiver_factory,
            8,
        );

        futures::try_join!(leader.setup(), follower.setup()).unwrap();

        (leader, follower)
    }

    #[tokio::test]
    async fn test_vm() {
        let (mut leader, mut follower) = create_vm_pair().await;

        let mut leader_thread = leader.get_thread(0).unwrap();
        let mut follower_thread = follower.get_thread(0).unwrap();

        let leader_fut = {
            let key = leader_thread
                .new_value(
                    Some([0u8; 16].into()),
                    ValueConfigBuilder::default()
                        .id("key")
                        .value_type(ValueType::new::<[u8; 16]>())
                        .build()
                        .unwrap(),
                )
                .unwrap();
            let msg = leader_thread
                .new_value(
                    None,
                    ValueConfigBuilder::default()
                        .id("msg")
                        .value_type(ValueType::new::<[u8; 16]>())
                        .build()
                        .unwrap(),
                )
                .unwrap();

            async move {
                let refs = leader_thread
                    .execute(AES128.clone(), &[key, msg], &["ciphertext"])
                    .await
                    .unwrap();
                let output = leader_thread.decode(&refs).await.unwrap();

                output
            }
        };

        let follower_fut = {
            let key = follower_thread
                .new_value(
                    None,
                    ValueConfigBuilder::default()
                        .id("key")
                        .value_type(ValueType::new::<[u8; 16]>())
                        .build()
                        .unwrap(),
                )
                .unwrap();
            let msg = follower_thread
                .new_value(
                    Some([42u8; 16].into()),
                    ValueConfigBuilder::default()
                        .id("msg")
                        .value_type(ValueType::new::<[u8; 16]>())
                        .build()
                        .unwrap(),
                )
                .unwrap();

            async move {
                let refs = follower_thread
                    .execute(AES128.clone(), &[key, msg], &["ciphertext"])
                    .await
                    .unwrap();
                let output = follower_thread.decode(&refs).await.unwrap();

                output
            }
        };

        let (leader_values, follower_values) = futures::join!(leader_fut, follower_fut);

        assert_eq!(leader_values, follower_values);

        futures::try_join!(leader.finalize(), follower.finalize()).unwrap();
    }
}
