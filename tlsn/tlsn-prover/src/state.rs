use crate::ReadWrite;
use bytes::Bytes;
use futures::channel::{
    mpsc::{Receiver, Sender},
    oneshot::{Receiver as OneshotReceiver, Sender as OneshotSender},
};
use std::io::Error as IOError;
use tls_client::ClientConnection;
use tlsn_core::transcript::TranscriptSet;

pub struct Initialized<S> {
    pub(crate) request_receiver: Receiver<Bytes>,
    pub(crate) response_sender: Sender<Result<Bytes, IOError>>,
    pub(crate) close_tls_receiver: OneshotReceiver<()>,
    pub(crate) tls_client: ClientConnection,
    pub(crate) socket: S,
    pub(crate) transcript_channel: (OneshotSender<TranscriptSet>, OneshotReceiver<TranscriptSet>),
}

#[derive(Debug)]
pub struct Notarizing {
    pub(crate) transcript: TranscriptSet,
}

#[derive(Debug)]
pub struct Finalized {}

pub trait ProverState: sealed::Sealed {}

impl ProverState for Initialized {}
impl ProverState for Notarizing {}
impl ProverState for Finalized {}

mod sealed {
    pub trait Sealed {}
    impl Sealed for super::Initialized {}
    impl Sealed for super::Notarizing {}
    impl Sealed for super::Finalized {}
}
