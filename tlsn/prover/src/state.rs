use futures::{
    channel::oneshot::{Receiver, Sender},
    Future,
};
use std::pin::Pin;
use tlsn_core::transcript::TranscriptSet;

pub struct Initialized {
    pub(crate) run_future: Option<Pin<Box<dyn Future<Output = ()> + Send + 'static>>>,
    pub(crate) transcript_receiver: Receiver<TranscriptSet>,
    pub(crate) close_tls_sender: Sender<()>,
}

#[derive(Debug)]
pub struct Running {
    pub(crate) transcript_receiver: Receiver<TranscriptSet>,
    pub(crate) close_tls_sender: Sender<()>,
}

#[derive(Debug)]
pub struct Finalized {
    pub(crate) transcript: TranscriptSet,
}

pub trait ProverState: sealed::Sealed {}

impl ProverState for Initialized {}
impl ProverState for Running {}
impl ProverState for Finalized {}

mod sealed {
    pub trait Sealed {}
    impl Sealed for super::Initialized {}
    impl Sealed for super::Running {}
    impl Sealed for super::Finalized {}
}
