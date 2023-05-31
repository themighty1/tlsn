use bytes::Bytes;
use futures::channel::{
    mpsc::{Receiver, Sender},
    oneshot,
};

use tls_core::dns::ServerName;
use tlsn_core::Transcript;
use uid_mux::{UidYamux, UidYamuxControl};
use utils_aio::codec::BincodeMux;

pub struct Initialized<S, T> {
    pub(crate) server_name: ServerName,

    pub(crate) server_socket: S,
    pub(crate) muxer: UidYamux<T>,
    pub(crate) mux: BincodeMux<UidYamuxControl>,

    pub(crate) tx_receiver: Receiver<Bytes>,
    pub(crate) rx_sender: Sender<Result<Bytes, std::io::Error>>,
    pub(crate) close_tls_receiver: oneshot::Receiver<()>,

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

impl<S, T> ProverState for Initialized<S, T> {}
impl ProverState for Notarizing {}
impl ProverState for Finalized {}

mod sealed {
    pub trait Sealed {}
    impl<S, T> Sealed for super::Initialized<S, T> {}
    impl Sealed for super::Notarizing {}
    impl Sealed for super::Finalized {}
}
