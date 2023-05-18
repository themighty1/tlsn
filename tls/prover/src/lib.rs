use bytes::Bytes;
use futures::{
    task::{Spawn, SpawnExt},
    Future, SinkExt, StreamExt,
};
use std::{
    io::{Read, Write},
    pin::Pin,
    sync::Arc,
};
use tls_client::{client::InvalidDnsNameError, Backend, ClientConnection, ServerName};

mod config;
mod socket;

pub use config::ProverConfig;

use self::socket::AsyncSocket;

pub trait ReadWrite: Read + Write + Unpin + Send {}
impl<T> ReadWrite for T where T: Read + Write + Unpin + Send {}

pub struct Prover {
    run_future: Option<Pin<Box<dyn Future<Output = ()> + Send + 'static>>>,
}

impl Prover {
    pub fn new(
        config: ProverConfig,
        url: String,
        backend: Box<dyn Backend>,
        mut socket: Box<dyn ReadWrite>,
    ) -> Result<(Self, AsyncSocket), ProverError> {
        let (request_sender, mut request_receiver) = futures::channel::mpsc::channel::<Bytes>(10);
        let (mut response_sender, response_receiver) =
            futures::channel::mpsc::channel::<Result<Bytes, std::io::Error>>(10);

        let async_socket = AsyncSocket::new(request_sender, response_receiver);

        let server_name = ServerName::try_from(url.as_str())?;
        let client_config = Arc::new(config.client_config);
        let mut tls_conn = ClientConnection::new(client_config, backend, server_name)?;

        let run_future = async move {
            // Handshake
            tls_conn.start().await.unwrap();

            // Accept requests and write them to the tls connection
            if let Some(request) = request_receiver.next().await {
                tls_conn
                    .write_all_plaintext(request.as_ref())
                    .await
                    .unwrap();
            }

            // Write the encrypted tls traffic into the socket
            if tls_conn.wants_write() {
                tls_conn.write_tls(&mut socket).unwrap();
            }

            // Read the encrypted tls traffic from the socket
            if tls_conn.wants_read() {
                tls_conn.read_tls(&mut socket).unwrap();
                tls_conn.process_new_packets().await.unwrap();
            }

            // Decrypt the tls traffic and send it to the response channel
            let mut response = Vec::new();
            tls_conn.reader().read_to_end(&mut response).unwrap();
            if !response.is_empty() {
                response_sender.send(Ok(response.into())).await.unwrap();
            }
        };

        let prover = Prover {
            run_future: Some(Box::pin(run_future)),
        };

        Ok((prover, async_socket))
    }

    // Caller needs to run future on executor
    pub fn run(&mut self, executor: &dyn Spawn) -> Result<(), ProverError> {
        let run_future = self.run_future.take().ok_or(ProverError::AlreadyRunning)?;
        executor.spawn(run_future).map_err(ProverError::Spawn)
    }
}

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
    #[error(transparent)]
    Spawn(#[from] futures::task::SpawnError),
}
