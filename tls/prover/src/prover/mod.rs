use config::ProverConfig;
use futures::{
    channel::mpsc::{Receiver, Sender},
    lock::Mutex,
    task::{Spawn, SpawnExt},
    try_join, SinkExt, StreamExt,
};
use std::{io::Read, net::TcpStream, sync::Arc};
use tls_client::{client::InvalidDnsNameError, Backend, ClientConnection, ServerName};

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
        // TODO Currently two problems:
        // 1. The `request_receiver.next()` call blocks if there is no request
        // 2. For some reason `tls_connection.wants_write()` is always `false

        // TODO There should be a better option than using an await mutex
        let mut sender = self.response_sender.take().unwrap();
        let mut receiver = self.request_receiver.take().unwrap();
        let prover_mutex = Arc::new(Mutex::new(self));
        let prover_mutex2 = Arc::clone(&prover_mutex);
        let prover_mutex3 = Arc::clone(&prover_mutex);
        let prover_mutex4 = Arc::clone(&prover_mutex);
        println!("At beginning of prover run");

        let write_fut = async move {
            loop {
                {
                    println!("in write loop");
                    let mut prover = prover_mutex.lock().await;
                    // Push requests into the TCP stream
                    if let Some(request) = receiver.next().await {
                        prover
                            .tls_connection
                            .write_all_plaintext(request.into().as_slice())
                            .await?;
                    }
                }
                println!("end of write loop");
            }
            Ok::<(), ProverError>(())
        };

        let write_tls_fut = async move {
            loop {
                {
                    println!("in write tls loop");
                    let mut prover = prover_mutex2.lock().await;
                    let mut socket = prover.socket.try_clone()?;
                    if prover.tls_connection.wants_write() {
                        prover.tls_connection.write_tls(&mut socket)?;
                    }
                }
                println!("end of write tls loop");
            }
            Ok::<(), ProverError>(())
        };

        let read_fut = async move {
            loop {
                {
                    println!("in read loop");
                    let mut prover = prover_mutex3.lock().await;
                    let mut response = Vec::new();
                    prover.tls_connection.reader().read_to_end(&mut response)?;
                    if !response.is_empty() {
                        sender.send(response.into()).await?;
                    }
                }
                println!("end of read loop");
            }
            Ok::<(), ProverError>(())
        };

        let read_tls_fut = async move {
            loop {
                {
                    println!("in read tls loop");
                    let mut prover = prover_mutex4.lock().await;
                    let mut socket = prover.socket.try_clone()?;
                    // Pull responses from the TCP stream
                    if prover.tls_connection.wants_read() {
                        prover.tls_connection.read_tls(&mut socket)?;
                        prover.tls_connection.process_new_packets().await?;
                    }
                }
                println!("end of read tls loop");
            }

            Ok::<(), ProverError>(())
        };
        let fut = async {
            try_join!(write_fut, write_tls_fut, read_fut, read_tls_fut).unwrap();
        };
        executor.spawn(fut).unwrap();
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
    async fn test_prover_run() {
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
        println!("Started prover run loop");

        request_channel.send(
            b"
                GET / HTTP/2
                Host: tlsnotary.org
                User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/112.0
                Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
                Accept-Language: en-US,en;q=0.5
                Accept-Encoding: gzip, deflate, br
                DNT: 1
                Upgrade-Insecure-Requests: 1
                Connection: keep-alive
                Sec-Fetch-Dest: document
                Sec-Fetch-Mode: navigate
                Sec-Fetch-Site: none
                Sec-Fetch-User: ?1
                "
            .to_vec(),
        ).await.unwrap();
        println!("Sent request");
        let response = response_channel.select_next_some().await;
        println!("Got response: {:?}", response);
        assert!(false)
    }
}
