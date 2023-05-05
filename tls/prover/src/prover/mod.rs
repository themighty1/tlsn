use config::ProverConfig;
use futures::{
    channel::mpsc::{Receiver, Sender},
    SinkExt, StreamExt,
};
use std::{
    io::{Read, Write},
    net::TcpStream,
    sync::Arc,
};
use tls_client::{client::InvalidDnsNameError, Backend, ClientConnection, ServerName};

mod config;

pub struct Prover<T>
where
    T: From<Vec<u8>> + Into<Vec<u8>>,
{
    tls_connection: ClientConnection,
    socket: TcpStream,
    request_sender: Option<Sender<T>>,
    request_receiver: Receiver<T>,
    response_sender: Sender<T>,
    response_receiver: Option<Receiver<T>>,
}

impl<T> Prover<T>
where
    T: From<Vec<u8>> + Into<Vec<u8>>,
{
    pub fn new(config: ProverConfig, url: String, socket: TcpStream) -> Result<Self, ProverError> {
        let backend = Box::new(tls_client::TLSNBackend {});
        Self::new_with(config, url, backend, socket)
    }

    #[cfg(feature = "standard")]
    pub fn new_with_standard(
        config: ProverConfig,
        url: String,
        socket: TcpStream,
    ) -> Result<Self, ProverError> {
        let backend = Box::new(tls_client::RustCryptoBackend::new());
        Self::new_with(config, url, backend, socket)
    }

    fn new_with(
        config: ProverConfig,
        url: String,
        backend: Box<dyn Backend>,
        socket: TcpStream,
    ) -> Result<Self, ProverError> {
        let (request_sender, request_receiver) = futures::channel::mpsc::channel(10);
        let (response_sender, response_receiver) = futures::channel::mpsc::channel(10);

        let server_name = ServerName::try_from(url.as_str())?;
        let client_config = Arc::new(config.client_config);
        let tls_connection = ClientConnection::new(client_config, backend, server_name)?;

        let prover = Self {
            tls_connection,
            socket,
            request_sender: Some(request_sender),
            request_receiver,
            response_sender,
            response_receiver: Some(response_receiver),
        };
        Ok(prover)
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
    pub async fn run(mut self) -> Result<(), ProverError> {
        loop {
            // Push requests into the TCP stream
            if let Some(request) = self.request_receiver.next().await {
                self.tls_connection
                    .write_all_plaintext(request.into().as_slice())
                    .await?;
                self.tls_connection.write_tls(&mut self.socket)?;
            }

            // Pull responses from the TCP stream
            let mut response = Vec::new();
            self.tls_connection.read_tls(&mut self.socket)?;
            self.tls_connection.process_new_packets().await?;
            self.tls_connection.reader().read_to_end(&mut response)?;
            if !response.is_empty() {
                self.response_sender.send(response.into()).await?;
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
    #[error("Unable to parse URL: {0}")]
    InvalidSeverName(#[from] InvalidDnsNameError),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_prover_run() {
        let prover = Prover::<Vec<u8>>::new_with_standard(
            ProverConfig::default(),
            "tlsnotary.org".to_string(),
            std::net::TcpStream::connect("tlsnotary.org:443").unwrap(),
        )
        .unwrap();
        let (request_channel, response_channel) = prover.take_channels().unwrap();
        tokio::spawn(async move {
            prover.run().await.unwrap();
        });
        request_channel.send(
            br#"
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
                "#
            .to_vec(),
        );
    }
}
