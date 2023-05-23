use bytes::Bytes;
use futures::{
    channel, select,
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
mod handle;

pub use config::ProverConfig;
pub use handle::ProverHandle;

pub struct Prover {
    run_future: Option<Pin<Box<dyn Future<Output = ()> + Send + 'static>>>,
}

pub trait ReadWrite: Read + Write + Send + Unpin + 'static {}
impl<T: Read + Write + Send + Unpin + 'static> ReadWrite for T {}

impl Prover {
    pub fn new(
        config: ProverConfig,
        url: String,
        backend: Box<dyn Backend>,
        mut socket: Box<dyn ReadWrite + Send>,
    ) -> Result<(Self, ProverHandle), ProverError> {
        let (request_sender, mut request_receiver) = channel::mpsc::channel::<Bytes>(10);
        let (mut response_sender, response_receiver) =
            channel::mpsc::channel::<Result<Bytes, std::io::Error>>(10);
        let (close_tls_sender, mut close_tls_receiver) = channel::oneshot::channel::<()>();

        let handle = ProverHandle::new(request_sender, response_receiver, close_tls_sender);

        let server_name = ServerName::try_from(url.as_str())?;
        let client_config = Arc::new(config.client_config);
        let tls_conn = Box::new(Mutex::new(ClientConnection::new(
            client_config,
            backend,
            server_name,
        )?));

        let tls_conn_ref: &'static Mutex<ClientConnection> = Box::leak(tls_conn);
        let run_future = async move {
            tls_conn_ref.lock().await.start().await.unwrap();
            loop {
                select! {
                    request = request_receiver.select_next_some() => {
                        let mut tls_conn = tls_conn_ref.lock().await;
                        tls_conn.write_all_plaintext(request.as_ref()).await.unwrap();
                    },
                    mut tls_conn = tls_conn_ref.lock().fuse() =>  {
                        if tls_conn.wants_write() {
                            match tls_conn.write_tls(&mut socket) {
                                Ok(_) => (),
                                Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => (),
                                Err(err) => panic!("{}", err)
                            }
                        }

                        if tls_conn.wants_read() {
                            match tls_conn.read_tls(&mut socket) {
                                Ok(_) => (),
                                Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => (),
                                Err(err) => panic!("{}", err)
                            }
                            tls_conn.process_new_packets().await.unwrap();
                        }
                    },
                    mut tls_conn = tls_conn_ref.lock().fuse() =>  {
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
                        let mut tls_conn = tls_conn_ref.lock().await;
                        tls_conn.send_close_notify().await.unwrap();
                        _ = unsafe { Box::from_raw(tls_conn_ref as *const Mutex<ClientConnection>
                                                                  as *mut Mutex<ClientConnection>) };
                        break;
                    }

                }
            }
        };

        let prover = Prover {
            run_future: Some(Box::pin(run_future)),
        };

        Ok((prover, handle))
    }

    // Caller needs to run future on executor
    pub fn run(&mut self, executor: impl Spawn) -> Result<(), ProverError> {
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
    #[error("Unable to close TLS connection")]
    CloseTlsConnection,
    #[error("Prover has already been shutdown")]
    AlreadyShutdown,
}
