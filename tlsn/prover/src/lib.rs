use bytes::Bytes;
use futures::{
    channel::{self, oneshot::Canceled},
    select, FutureExt, SinkExt, StreamExt,
};
use std::{
    io::{Read, Write},
    sync::Arc,
};
use tls_client::{client::InvalidDnsNameError, Backend, ClientConnection, ServerName};
use tlsn_core::transcript::{Transcript, TranscriptSet};

mod config;
mod state;
mod tls_conn;

pub use config::ProverConfig;
pub use tls_conn::TLSConnection;

use state::{Initialized, Notarizing, ProverState};

#[derive(Debug)]
pub struct Prover<T: ProverState = Initialized>(T);

impl Prover<Initialized> {
    pub fn new(
        config: ProverConfig,
        url: String,
        // TODO: Not pass into constructor, but method needed to construct this
        backend: Box<dyn Backend + Send + 'static>,
        socket: Box<dyn ReadWrite + Send + 'static>,
    ) -> Result<(Self, TLSConnection), ProverError> {
        let (request_sender, request_receiver) = channel::mpsc::channel::<Bytes>(10);
        let (response_sender, response_receiver) =
            channel::mpsc::channel::<Result<Bytes, std::io::Error>>(10);
        let (close_tls_sender, close_tls_receiver) = channel::oneshot::channel::<()>();
        // let (transcript_sender, transcript_receiver) = channel::oneshot::channel::<TranscriptSet>();

        let tls_conn = TLSConnection::new(request_sender, response_receiver, close_tls_sender);

        let server_name = ServerName::try_from(url.as_str())?;
        let client_config = Arc::new(config.client_config);
        let tls_client = ClientConnection::new(client_config, backend, server_name)?;

        Ok((
            Self(Initialized {
                request_receiver,
                response_sender,
                close_tls_receiver,
                tls_client,
                socket,
            }),
            tls_conn,
        ))
    }

    // Caller needs to run future on executor
    pub async fn run(mut self) -> Result<Prover<Notarizing>, ProverError> {
        let mut sent_data: Vec<u8> = Vec::new();
        let mut received_data: Vec<u8> = Vec::new();

        let mut request_receiver = self.0.request_receiver;
        let mut response_sender = self.0.response_sender;

        let mut tls_client = self.0.tls_client;
        tls_client.start().await.unwrap();

        loop {
            select! {
                request = request_receiver.select_next_some() => {
                    let written = sent_data.write(request.as_ref()).unwrap();
              tls_client.write_all_plaintext(&sent_data[sent_data.len() - written..]).await.unwrap();
                },
                _ = futures::future::ready(()).fuse() =>  {
                    if tls_client.wants_write() {
                        match tls_client.write_tls(&mut self.0.socket) {
                            Ok(_) => (),
                            Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => (),
                            Err(err) => panic!("{}", err)
                        }
                    }

                    if tls_client.wants_read() {
                        match tls_client.read_tls(&mut self.0.socket) {
                            Ok(_) => (),
                            Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => (),
                            Err(err) => panic!("{}", err)
                        }
                        tls_client.process_new_packets().await.unwrap();
                    }
                },
                _ = futures::future::ready(()).fuse() =>  {
                    // TODO: It is not so easy to get the length of the data that was read
                    // so we do it by checking the length before and afterwards
                    let received_data_len_before_read = received_data.len();
                    match tls_client.reader().read_to_end(&mut received_data) {
                            Ok(_) => (),
                            Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => (),
                            Err(err) => panic!("{}", err)
                        }
                    let read = received_data.len() - received_data_len_before_read;
                    // TODO: If we replace the condition with  if `read >= 0`, we are unable to
                    // close the connection. I would be interested why that happens.
                    if read > 0 {
                        let response = received_data.split_at(received_data_len_before_read).1.to_vec();
                        response_sender.send(Ok(response.into())).await.unwrap();
                    }
                }
                _ = &mut self.0.close_tls_receiver => {
                    // TODO: This is some internal wrong handling of close_notify in `tls_client/src/backend/standard.rs` line 436
                    // We should not treat close_notify alert as an error since we use it in our protocol to force
                    // closing the connection
                    tls_client.send_close_notify().await.unwrap();
                    match tls_client.complete_io(&mut self.0.socket).await {
                        Ok(_) => (),
                        Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => (),
                        Err(err) => panic!("{}", err)
                    }
                    let transcript_received = Transcript::new("rx", received_data);
                    let transcript_sent = Transcript::new("tx", sent_data);

                    let _transcript_set = TranscriptSet::new(&[transcript_sent, transcript_received]);
                    // TODO Get transcript out of future loop
                    break;
                }

            }
        }

        Ok(Prover(Notarizing {
            transcript: TranscriptSet::new(&[]),
        }))
    }
}

impl Prover<Notarizing> {
    pub fn transcript(&self) -> &TranscriptSet {
        &self.0.transcript
    }

    pub fn send_commitments(&mut self) -> Result<(), ProverError> {
        todo!()
    }
}

pub trait ReadWrite: Read + Write + Send + Unpin + 'static {}
impl<T: Read + Write + Send + Unpin + 'static> ReadWrite for T {}

#[derive(Debug, thiserror::Error)]
pub enum ProverError {
    #[error(transparent)]
    TlsClientError(#[from] tls_client::Error),
    #[error(transparent)]
    IOError(#[from] std::io::Error),
    #[error(transparent)]
    InvalidSeverName(#[from] InvalidDnsNameError),
    #[error("Prover is already running")]
    AlreadyRunning,
    #[error("Unable to close TLS connection")]
    CloseTlsConnection,
    #[error("Prover has already been shutdown")]
    AlreadyShutdown,
    #[error("Unable to receive transcripts: {0}")]
    TranscriptError(#[from] Canceled),
}
