use bytes::Bytes;
use futures::{
    channel::{self, oneshot::Canceled},
    select, SinkExt, StreamExt,
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
        let (transcript_sender, transcript_receiver) = channel::oneshot::channel::<TranscriptSet>();

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
                transcript_channel: (transcript_sender, transcript_receiver),
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

        let transcript_receiver = self.0.transcript_channel.1;

        let mut tls_client = self.0.tls_client;
        tls_client.start().await.unwrap();

        loop {
            select! {
                request = request_receiver.select_next_some() => {
                    let written = sent_data.write(request.as_ref()).unwrap();
              tls_client.write_all_plaintext(&sent_data[sent_data.len() - written..]).await.unwrap();
                },
                _ = &mut self.0.close_tls_receiver => {
                    // TODO: Handle this correctly
                    _ = tls_client.send_close_notify().await;
                    match tls_client.complete_io(&mut self.0.socket).await {
                        Ok(_) => (),
                        Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => (),
                        Err(err) => panic!("{}", err)
                    }
                    let transcript_received = Transcript::new("rx", received_data);
                    let transcript_sent = Transcript::new("tx", sent_data);

                    let transcript_set = TranscriptSet::new(&[transcript_sent, transcript_received]);
                    self.0.transcript_channel.0.send(transcript_set).unwrap();
                    break;
                },
                default => {
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

                    let received_data_len_before_read = received_data.len();
                    match tls_client.reader().read_to_end(&mut received_data) {
                            Ok(_) => (),
                            Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => (),
                            Err(err) => panic!("{}", err)
                        }
                    let response = received_data.split_at(received_data_len_before_read).1.to_vec();
                        response_sender.send(Ok(response.into())).await.unwrap();
                }
            }
        }
        let transcript = transcript_receiver.await.unwrap();
        Ok(Prover(Notarizing { transcript }))
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
