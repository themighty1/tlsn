use bytes::Bytes;
use futures::{
    channel::{self, oneshot::Canceled},
    select, Future, FutureExt, SinkExt, StreamExt,
};
use std::{
    io::{Read, Write},
    pin::Pin,
    sync::Arc,
};
use tls_client::{client::InvalidDnsNameError, Backend, ClientConnection, ServerName};
use tlsn_core::transcript::{Transcript, TranscriptSet};
use tokio::sync::Mutex;

mod config;
mod socket;
mod state;

pub use config::ProverConfig;
pub use socket::Socket;

use state::{Finalized, Initialized, ProverState, Running};

#[derive(Debug)]
pub struct Prover<T: ProverState = Initialized>(T);

impl Prover<Initialized> {
    pub fn new(
        config: ProverConfig,
        url: String,
        backend: Box<dyn Backend>,
        mut tls_socket: Box<dyn ReadWrite + Send>,
    ) -> Result<(Self, Socket), ProverError> {
        let (request_sender, mut request_receiver) = channel::mpsc::channel::<Bytes>(10);
        let (mut response_sender, response_receiver) =
            channel::mpsc::channel::<Result<Bytes, std::io::Error>>(10);
        let (close_tls_sender, mut close_tls_receiver) = channel::oneshot::channel::<()>();
        let (transcript_sender, transcript_receiver) = channel::oneshot::channel::<TranscriptSet>();

        let socket = Socket::new(request_sender, response_receiver);

        let server_name = ServerName::try_from(url.as_str())?;
        let client_config = Arc::new(config.client_config);
        let tls_conn = Mutex::new(ClientConnection::new(client_config, backend, server_name)?);

        let run_future = async move {
            let mut sent_data: Vec<u8> = Vec::new();
            let mut received_data: Vec<u8> = Vec::new();

            tls_conn.lock().await.start().await.unwrap();
            loop {
                select! {
                    request = request_receiver.select_next_some() => {
                        let mut tls_conn = tls_conn.lock().await;
                        let written = sent_data.write(request.as_ref()).unwrap();
                        tls_conn.write_all_plaintext(&sent_data[sent_data.len() - written..]).await.unwrap();
                    },
                    mut tls_conn = tls_conn.lock().fuse() =>  {
                        if tls_conn.wants_write() {
                            match tls_conn.write_tls(&mut tls_socket) {
                                Ok(_) => (),
                                Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => (),
                                Err(err) => panic!("{}", err)
                            }
                        }

                        if tls_conn.wants_read() {
                            match tls_conn.read_tls(&mut tls_socket) {
                                Ok(_) => (),
                                Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => (),
                                Err(err) => panic!("{}", err)
                            }
                            tls_conn.process_new_packets().await.unwrap();
                        }
                    },
                    mut tls_conn = tls_conn.lock().fuse() =>  {
                        // TODO: It is not so easy to get the length of the data that was read
                        // so we do it by checking the length before and afterwards
                        let received_data_len_before_read = received_data.len();
                        match tls_conn.reader().read_to_end(&mut received_data) {
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
                    _ = close_tls_receiver => {
                        let mut tls_conn = tls_conn.lock().await;
                        // TODO: This is some internal wrong handling of close_notify in `tls_client/src/backend/standard.rs` line 436
                        // We should not treat close_notify alert as an error since we use it in our protocol to force
                        // closing the connection
                        tls_conn.send_close_notify().await.unwrap_err();
                        match tls_conn.complete_io(&mut tls_socket).await {
                            Ok(_) => (),
                            Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => (),
                            Err(err) => panic!("{}", err)
                        }
                        let transcript_received = Transcript::new("tx", received_data);
                        let transcript_sent = Transcript::new("rx", sent_data);

                        let transcript_set = TranscriptSet::new(&[transcript_sent, transcript_received]);
                        transcript_sender.send(transcript_set).unwrap();
                        break;
                    }

                }
            }
        };

        let prover = Self(Initialized {
            run_future: Some(Box::pin(run_future)),
            transcript_receiver,
            close_tls_sender,
        });

        Ok((prover, socket))
    }

    // Caller needs to run future on executor
    pub fn run(
        mut self,
    ) -> Result<
        (
            Prover<Running>,
            Pin<Box<dyn Future<Output = ()> + Send + 'static>>,
        ),
        ProverError,
    > {
        let prover = Prover(Running {
            transcript_receiver: self.0.transcript_receiver,
            close_tls_sender: self.0.close_tls_sender,
        });
        let future = self
            .0
            .run_future
            .take()
            .ok_or(ProverError::AlreadyRunning)?;
        Ok((prover, Box::pin(future)))
    }
}

impl Prover<Running> {
    pub async fn finalize(self) -> Result<Prover<Finalized>, ProverError> {
        self.0
            .close_tls_sender
            .send(())
            .map_err(|_| ProverError::CloseTlsConnection)?;
        let transcript = self.0.transcript_receiver.await?;

        Ok(Prover(Finalized { transcript }))
    }
}

impl Prover<Finalized> {
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
