use futures::{
    channel::mpsc::{Receiver, Sender},
    task::{Spawn, SpawnExt},
    AsyncRead, AsyncWrite, Future, SinkExt, StreamExt,
};
use std::{
    io::{ErrorKind, Read},
    net::TcpStream,
    sync::Arc,
};
use tls_client::{client::InvalidDnsNameError, Backend, ClientConnection, ServerName};
use tokio::sync::Mutex;

mod config;
mod socket;

pub use config::ProverConfig;

use self::socket::AsyncSocket;

pub trait AsyncReadWrite: AsyncRead + AsyncWrite + Unpin + Send + Sync {}
impl<T> AsyncReadWrite for T where T: AsyncRead + AsyncWrite + Unpin + Send + Sync {}

pub struct Prover {
    run_future: FnOnce() -> impl Future<Output = ()>,
}

impl Prover {
    fn new(
        config: ProverConfig,
        url: String,
        backend: Box<dyn Backend>,
        socket: Box<dyn AsyncReadWrite>,
    ) -> Result<(Self, AsyncSocket), ProverError> {
        let (request_sender, request_receiver) = futures::channel::mpsc::channel(10);
        let (response_sender, response_receiver) = futures::channel::mpsc::channel(10);

        let async_socket = AsyncSocket::new(request_sender, response_receiver);

        let server_name = ServerName::try_from(url.as_str())?;
        let client_config = Arc::new(config.client_config);
        let tls_connection = ClientConnection::new(client_config, backend, server_name)?;

        self.run_future = async {};

        Ok((prover, async_socket))
    }

    // Caller needs to run future on executor
    pub fn run(mut self, executor: impl Spawn) {
        let response_sender = self
            .response_sender
            .take()
            .expect("Prover is already running");
        let request_receiver = self
            .request_receiver
            .take()
            .expect("Prover is already running");
        let prover = Arc::new(self);

        executor.spawn(prover.clone().handshake()).unwrap();
        executor
            .spawn(prover.clone().write(request_receiver))
            .unwrap();
        executor.spawn(prover.clone().write_tls()).unwrap();
        executor
            .spawn(prover.clone().read(response_sender))
            .unwrap();
        executor.spawn(prover.clone().read_tls()).unwrap();
    }

    async fn handshake(self: Arc<Self>) {
        self.tls_connection.lock().await.start().await.unwrap()
    }

    async fn write(self: Arc<Self>, mut request_receiver: Receiver<Vec<u8>>) {
        loop {
            if let Some(request) = request_receiver.next().await {
                self.tls_connection
                    .lock()
                    .await
                    .write_all_plaintext(request.into().as_slice())
                    .await
                    .unwrap();
            }
        }
    }

    async fn write_tls(self: Arc<Self>) {
        loop {
            let mut tls_connection = self.tls_connection.lock().await;
            let mut socket = self.socket.lock().await;
            if tls_connection.wants_write() {
                tls_connection.write_tls(&mut *socket).unwrap();
            }
        }
    }

    async fn read(self: Arc<Self>, mut response_sender: Sender<T>) {
        loop {
            let mut response = Vec::new();
            match self
                .tls_connection
                .lock()
                .await
                .reader()
                .read_to_end(&mut response)
            {
                Ok(_) => {}
                Err(e) if e.kind() == ErrorKind::WouldBlock => {}
                err => panic!("{:?}", err),
            }
            if !response.is_empty() {
                response_sender.send(response.into()).await.unwrap();
            }
        }
    }

    async fn read_tls(self: Arc<Self>) {
        loop {
            let mut tls_connection = self.tls_connection.lock().await;
            let mut socket = self.socket.lock().await;
            if tls_connection.wants_read() {
                match tls_connection.read_tls(&mut *socket) {
                    Ok(_) => {}
                    Err(e) if e.kind() == ErrorKind::WouldBlock => {}
                    err => panic!("{:?}", err),
                }
                tls_connection.process_new_packets().await.unwrap();
            }
        }
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
}
