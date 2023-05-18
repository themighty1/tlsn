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
    pub run_future: Option<Pin<Box<dyn Future<Output = ()> + Send + 'static>>>,
}

impl Prover {
    pub fn new(
        config: ProverConfig,
        url: String,
        backend: Box<dyn Backend>,
        (mut read_socket, mut write_socket): (Box<dyn Read + Send>, Box<dyn Write + Send>),
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

        println!("tls_conn_ref created = {:?}", tls_conn_ref);
        let run_future = async move {
            println!("run_future started!!!");
            tls_conn_ref.lock().await.start().await.unwrap();
            loop {
                select! {
                    request = request_receiver.next().fuse() => {
                        println!("request = {:?}", request);
                        let mut tls_conn = tls_conn_ref.lock().await;
                        if let Some(request) = request {
                            tls_conn.write_all_plaintext(request.as_ref()).await.unwrap();
                        }
                    },
                    _write_tls = async {
                        println!("write_tls");
                        let mut tls_conn = tls_conn_ref.lock().await;
                        if tls_conn.wants_write() {
                            tls_conn.write_tls(&mut write_socket).unwrap();
                        }
                    }.fuse() => (),
                    _read_tls = async {
                        println!("read_tls");
                        let mut tls_conn = tls_conn_ref.lock().await;
                        if tls_conn.wants_read() {
                            tls_conn.read_tls(&mut read_socket).unwrap();
                            tls_conn.process_new_packets().await.unwrap();
                        }
                    }.fuse() => (),
                    _response = async {
                        println!("response");
                        let mut tls_conn = tls_conn_ref.lock().await;
                        let mut response = Vec::new();
                        tls_conn.reader().read_to_end(&mut response).unwrap();
                        if !response.is_empty() {
                            response_sender.send(Ok(response.into())).await.unwrap();
                        }
                    }.fuse() => (),
                }
            }
        };

        let prover = Prover {
            run_future: Some(Box::pin(run_future)),
        };

        Ok((prover, async_socket))
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
}
