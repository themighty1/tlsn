use bytes::Bytes;
use futures::{channel, select, Future, FutureExt, SinkExt, StreamExt};
use std::{
    io::{Read, Write},
    pin::Pin,
    sync::Arc,
};
use tls_client::{client::InvalidDnsNameError, Backend, ClientConnection, ServerName};
use tlsn_core::transcript::TranscriptSet;
use tokio::sync::Mutex;

mod config;
mod socket;
mod state;

pub use config::ProverConfig;
pub use socket::Socket;

use state::{Finalized, Initialized, ProverState, Running};

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

        let socket = Socket::new(request_sender, response_receiver, close_tls_sender);

        let server_name = ServerName::try_from(url.as_str())?;
        let client_config = Arc::new(config.client_config);
        let tls_conn = Mutex::new(ClientConnection::new(client_config, backend, server_name)?);

        let run_future = async move {
            tls_conn.lock().await.start().await.unwrap();
            loop {
                select! {
                    request = request_receiver.select_next_some() => {
                        let mut tls_conn = tls_conn.lock().await;
                        tls_conn.write_all_plaintext(request.as_ref()).await.unwrap();
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
                        let mut response = Vec::new();
                        match tls_conn.reader().read_to_end(&mut response) {
                                Ok(_) => (),
                                Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => (),
                                Err(err) => panic!("{}", err)
                            }
                        if !response.is_empty() {
                            response_sender.send(Ok(response.into())).await.unwrap();
                        }
                    }
                    _ = close_tls_receiver => {
                        let mut tls_conn = tls_conn.lock().await;
                        tls_conn.send_close_notify().await.unwrap();
                        match tls_conn.complete_io(&mut tls_socket).await {
                            Ok(_) => (),
                            Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => (),
                            Err(err) => panic!("{}", err)
                        }
                        break;
                    }

                }
            }
        };

        let prover = Self(Initialized {
            run_future: Some(Box::pin(run_future)),
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
        let prover = Prover(Running);
        let future = self
            .0
            .run_future
            .take()
            .ok_or(ProverError::AlreadyRunning)?;
        Ok((prover, Box::pin(future)))
    }
}

impl Prover<Running> {
    pub fn close(self) -> Result<Prover<Finalized>, ProverError> {
        // TODO: Need to get transcripts after shutting down running future
        todo!()
    }
}

impl Prover<Finalized> {
    pub fn get_transcripts(&self) -> Result<TranscriptSet, ProverError> {
        todo!()
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
}
