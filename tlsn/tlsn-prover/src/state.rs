use bytes::Bytes;
use futures::channel::{
    mpsc::{Receiver, Sender},
    oneshot,
};
use std::io::Error as IOError;
use tls_client::ClientConnection;
use tlsn_core::Transcript;

pub struct Initialized<S> {
    pub(crate) tx_receiver: Receiver<Bytes>,
    pub(crate) rx_sender: Sender<Result<Bytes, IOError>>,
    pub(crate) close_tls_receiver: oneshot::Receiver<()>,
    pub(crate) client: ClientConnection,
    pub(crate) server_socket: S,
    pub(crate) transcript_tx: Transcript,
    pub(crate) transcript_rx: Transcript,
}

#[derive(Debug)]
pub struct Notarizing {
    pub(crate) transcript_tx: Transcript,
    pub(crate) transcript_rx: Transcript,
}

#[derive(Debug)]
pub struct Finalized {}

pub trait ProverState: sealed::Sealed {}

impl<S> ProverState for Initialized<S> {}
impl ProverState for Notarizing {}
impl ProverState for Finalized {}

mod sealed {
    pub trait Sealed {}
    impl<S> Sealed for super::Initialized<S> {}
    impl Sealed for super::Notarizing {}
    impl Sealed for super::Finalized {}
}
