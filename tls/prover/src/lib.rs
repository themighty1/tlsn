use bytes::Bytes;
use futures::{
    select,
    task::{Spawn, SpawnExt},
    Future, FutureExt, SinkExt, StreamExt,
};
use std::{
    io::{Read, Write},
    pin::Pin,
    sync::Arc,
};
use tls_client::{client::InvalidDnsNameError, Backend, ClientConnection, ServerName};
use tokio::sync::Mutex;

mod config;
mod socket;

pub use config::ProverConfig;
pub use socket::AsyncSocket;

pub struct Prover {
    run_futures: Option<Vec<Pin<Box<dyn Future<Output = ()> + Send + 'static>>>>,
}

pub trait ReadWrite: Read + Write + Send + Unpin + 'static {}
impl<T: Read + Write + Send + Unpin + 'static> ReadWrite for T {}

impl Prover {
    pub fn new(
        config: ProverConfig,
        url: String,
        backend: Box<dyn Backend>,
        mut socket: Box<dyn ReadWrite + Send>,
    ) -> Result<(Self, AsyncSocket), ProverError> {
        let (request_sender, mut request_receiver) = futures::channel::mpsc::channel::<Bytes>(10);
        let (mut response_sender, response_receiver) =
            futures::channel::mpsc::channel::<Result<Bytes, std::io::Error>>(10);

        let async_socket = AsyncSocket::new(request_sender, response_receiver);

        let server_name = ServerName::try_from(url.as_str())?;
        let client_config = Arc::new(config.client_config);
        let tls_conn = Box::new(Mutex::new(ClientConnection::new(
            client_config,
            backend,
            server_name,
        )?));
        let tls_conn_ref: &'static Mutex<ClientConnection> = Box::leak(tls_conn);

        let start_future = async move {
            tls_conn_ref.lock().await.start().await.unwrap();
        };

        let read_write_tls_future = async move {
            loop {
                let mut tls_conn = tls_conn_ref.lock().await;
                if tls_conn.wants_read() {
                    match tls_conn.read_tls(&mut socket) {
                        Ok(_) => (),
                        Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => (),
                        Err(err) => panic!("{}", err),
                    }
                    tls_conn.process_new_packets().await.unwrap();
                }
                if tls_conn.wants_write() {
                    match tls_conn.write_tls(&mut socket) {
                        Ok(_) => (),
                        Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => (),
                        Err(err) => panic!("{}", err),
                    }
                }
            }
        };

        let request_future = async move {
            loop {
                let request = request_receiver.next().await;
                if let Some(request) = request {
                    let mut tls_conn = tls_conn_ref.lock().await;
                    tls_conn
                        .write_all_plaintext(request.as_ref())
                        .await
                        .unwrap();
                }
            }
        };

        let response_future = async move {
            loop {
                let mut tls_conn = tls_conn_ref.lock().await;
                let mut response = Vec::new();
                match tls_conn.reader().read_to_end(&mut response) {
                    Ok(_) => (),
                    Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => (),
                    Err(err) => panic!("{}", err),
                }
                if !response.is_empty() {
                    response_sender.send(Ok(response.into())).await.unwrap();
                }
            }
        };

        let prover = Prover {
            run_futures: Some(vec![
                Box::pin(start_future),
                Box::pin(read_write_tls_future),
                Box::pin(request_future),
                Box::pin(response_future),
            ]),
        };

        Ok((prover, async_socket))
    }

    // Caller needs to run future on executor
    pub fn run(&mut self, executor: impl Spawn) -> Result<(), ProverError> {
        let run_futures = self.run_futures.take().ok_or(ProverError::AlreadyRunning)?;
        for future in run_futures {
            executor.spawn(future).map_err(ProverError::Spawn)?;
        }
        Ok(())
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
