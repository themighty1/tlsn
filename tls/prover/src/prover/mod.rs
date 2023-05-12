use config::ProverConfig;
use futures::{
    channel::mpsc::{Receiver, Sender},
    task::{Spawn, SpawnExt},
    try_join, SinkExt, StreamExt,
};
use std::{
    io::{ErrorKind, Read},
    net::TcpStream,
    sync::Arc,
};
use tls_client::{client::InvalidDnsNameError, Backend, ClientConnection, ServerName};
use tokio::sync::Mutex;

mod config;

pub struct Prover<T>
where
    T: From<Vec<u8>> + Into<Vec<u8>>,
{
    tls_connection: ClientConnection,
    socket: TcpStream,
    request_receiver: Option<Receiver<T>>,
    response_sender: Option<Sender<T>>,
}

impl<T> Prover<T>
where
    T: From<Vec<u8>> + Into<Vec<u8>> + std::fmt::Debug + Send + 'static,
{
    pub fn new(
        config: ProverConfig,
        url: String,
        socket: TcpStream,
    ) -> Result<(Self, Sender<T>, Receiver<T>), ProverError> {
        let backend = Box::new(tls_client::TLSNBackend {});
        Self::new_with(config, url, backend, socket)
    }

    #[cfg(feature = "standard")]
    pub fn new_with_standard(
        config: ProverConfig,
        url: String,
        socket: TcpStream,
    ) -> Result<(Self, Sender<T>, Receiver<T>), ProverError> {
        let backend = Box::new(tls_client::RustCryptoBackend::new());
        Self::new_with(config, url, backend, socket)
    }

    fn new_with(
        config: ProverConfig,
        url: String,
        backend: Box<dyn Backend>,
        socket: TcpStream,
    ) -> Result<(Self, Sender<T>, Receiver<T>), ProverError> {
        let (request_sender, request_receiver) = futures::channel::mpsc::channel(10);
        let (response_sender, response_receiver) = futures::channel::mpsc::channel(10);

        let server_name = ServerName::try_from(url.as_str())?;
        let client_config = Arc::new(config.client_config);
        let tls_connection = ClientConnection::new(client_config, backend, server_name)?;

        let prover = Self {
            tls_connection,
            socket,
            request_receiver: Some(request_receiver),
            response_sender: Some(response_sender),
        };
        Ok((prover, request_sender, response_receiver))
    }

    // Caller needs to run future on executor
    pub fn run(mut self, executor: impl Spawn) {
        let mut sender = self.response_sender.take().unwrap();
        let mut receiver = self.request_receiver.take().unwrap();
        let prover_mutex = Arc::new(Mutex::new(self));
        let prover_mutex2 = Arc::clone(&prover_mutex);
        let prover_mutex3 = Arc::clone(&prover_mutex);
        let prover_mutex4 = Arc::clone(&prover_mutex);
        let prover_mutex5 = Arc::clone(&prover_mutex);

        let write_fut = async move {
            loop {
                {
                    if let Some(request) = receiver.next().await {
                        let mut prover = prover_mutex.lock().await;
                        prover
                            .tls_connection
                            .write_all_plaintext(request.into().as_slice())
                            .await?;
                        println!("Wrote into tls backend");
                    }
                }
            }
            Ok::<(), ProverError>(())
        };

        let write_tls_fut = async move {
            loop {
                {
                    let mut prover = prover_mutex2.lock().await;
                    let mut socket = prover.socket.try_clone()?;
                    socket.set_nonblocking(true)?;
                    if prover.tls_connection.wants_write() {
                        prover.tls_connection.write_tls(&mut socket)?;
                        println!("Wrote into socket");
                    }
                }
            }
            Ok::<(), ProverError>(())
        };

        let read_fut = async move {
            loop {
                {
                    let mut prover = prover_mutex3.lock().await;
                    let mut response = Vec::new();
                    match prover.tls_connection.reader().read_to_end(&mut response) {
                        Ok(_) => {
                            println!("Read from tls backend")
                        }
                        Err(e) if e.kind() == ErrorKind::WouldBlock => {}
                        Err(e) => return Err(e.into()),
                    }
                    if !response.is_empty() {
                        sender.send(response.into()).await?;
                    }
                }
            }
            Ok::<(), ProverError>(())
        };

        let read_tls_fut = async move {
            loop {
                {
                    let mut prover = prover_mutex4.lock().await;
                    let mut socket = prover.socket.try_clone()?;
                    socket.set_nonblocking(true)?;
                    if prover.tls_connection.wants_read() {
                        match prover.tls_connection.read_tls(&mut socket) {
                            Ok(_) => {
                                println!("Read from socket")
                            }
                            Err(e) if e.kind() == ErrorKind::WouldBlock => {}
                            Err(e) => return Err(e.into()),
                        }
                        prover.tls_connection.process_new_packets().await?;
                    }
                }
            }

            Ok::<(), ProverError>(())
        };

        let start_fut = async move { prover_mutex5.lock().await.tls_connection.start().await };

        executor.spawn(async { start_fut.await.unwrap() }).unwrap();
        executor.spawn(async { write_fut.await.unwrap() }).unwrap();
        executor
            .spawn(async { write_tls_fut.await.unwrap() })
            .unwrap();
        executor.spawn(async { read_fut.await.unwrap() }).unwrap();
        executor
            .spawn(async { read_tls_fut.await.unwrap() })
            .unwrap();
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ProverError {
    #[error("TLS client error: {0}")]
    TlsClientError(#[from] tls_client::Error),
    #[error("IO error: {0}")]
    IOError(#[from] std::io::Error),
    #[error("Unable to deliver response")]
    ResponseError(#[from] futures::channel::mpsc::SendError),
    #[error("Unable to parse URL: {0}")]
    InvalidSeverName(#[from] InvalidDnsNameError),
    #[error("SpawnError: {0}")]
    SpawnError(#[from] futures::task::SpawnError),
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::runtime::Handle;
    use utils_aio::executor::SpawnCompatExt;

    #[tokio::test]
    async fn test_prover_run_tls_notary() {
        let rt = Handle::current();

        let tcp_stream = std::net::TcpStream::connect("tlsnotary.org:443").unwrap();

        let (prover, mut request_channel, mut response_channel) =
            Prover::<Vec<u8>>::new_with_standard(
                ProverConfig::default(),
                String::from("tlsnotary.org"),
                tcp_stream,
            )
            .unwrap();
        prover.run(rt.compat());

        request_channel
            .send(
                b"GET / HTTP/1.1\r\n\
                Host: tlsnotary.org\r\n\
                User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/112.0\r\n\
                Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8\r\n\
                Accept-Language: en-US,en;q=0.5\r\n\
                Accept-Encoding: identity\r\n\r\n"
                .to_vec()).await.unwrap();
        loop {
            let response = response_channel.select_next_some().await;
            println!("Got response: {}", String::from_utf8_lossy(&response));
        }
        assert!(false)
    }
}
