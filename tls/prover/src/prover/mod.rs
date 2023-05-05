use config::ProverConfig;
use futures::{
    channel::mpsc::{Receiver, Sender},
    SinkExt, StreamExt,
};
use std::{future::Future, io::Read, net::TcpStream};
use tls_client::ClientConnection;

mod config;

pub struct Prover<T>
where
    T: From<Vec<u8>> + Into<Vec<u8>>,
{
    tls_connection: ClientConnection,
    tcp_stream: TcpStream,
    request_sender: Option<Sender<T>>,
    request_receiver: Receiver<T>,
    response_sender: Sender<T>,
    response_receiver: Option<Receiver<T>>,
}

impl<T> Prover<T>
where
    T: From<Vec<u8>> + Into<Vec<u8>>,
{
    pub fn new(_config: ProverConfig) -> Self {
        let (request_sender, request_receiver) = futures::channel::mpsc::channel(10);
        let (response_sender, response_receiver) = futures::channel::mpsc::channel(10);
        Self {
            tls_connection: todo!(),
            tcp_stream: todo!(),
            request_sender: Some(request_sender),
            request_receiver,
            response_sender,
            response_receiver: Some(response_receiver),
        }
    }

    pub fn take_channels(&mut self) -> Result<(Sender<T>, Receiver<T>), ProverError> {
        let request_channel = self
            .request_sender
            .take()
            .ok_or(ProverError::NoChannelsAvailable)?;
        let response_channel = self
            .response_receiver
            .take()
            .ok_or(ProverError::NoChannelsAvailable)?;

        Ok((request_channel, response_channel))
    }

    // Caller needs to run future on executor
    pub fn run(&mut self) -> impl Future<Output = Result<(), ProverError>> + '_ {
        async move {
            loop {
                // Push requests into the TCP stream
                if let Some(request) = self.request_receiver.next().await {
                    self.tls_connection
                        .write_all_plaintext(request.into().as_slice())
                        .await?;
                    self.tls_connection.write_tls(&mut self.tcp_stream)?;
                }

                // Pull responses from the TCP stream
                let mut response = Vec::new();
                self.tls_connection.read_tls(&mut self.tcp_stream)?;
                self.tls_connection.process_new_packets().await?;
                self.tls_connection.reader().read_to_end(&mut response)?;
                if !response.is_empty() {
                    self.response_sender.send(response.into()).await?;
                }
            }
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ProverError {
    #[error("TLS client error: {0}")]
    TlsClientError(#[from] tls_client::Error),
    #[error("IO error: {0}")]
    IOError(#[from] std::io::Error),
    #[error("Channels for sending requests and receiving responses have already been assigned")]
    NoChannelsAvailable,
    #[error("Unable to deliver response")]
    ResponseError(#[from] futures::channel::mpsc::SendError),
}
