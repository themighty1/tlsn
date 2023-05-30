use bytes::Bytes;
use futures::{
    channel::{self, oneshot::Canceled},
    select, AsyncRead, AsyncWrite, SinkExt, StreamExt,
};
use std::{io::Read, sync::Arc};
use tls_client::{client::InvalidDnsNameError, Backend, ClientConnection, ServerName};
use tlsn_core::transcript::{Transcript, TranscriptSet};

mod config;
mod state;
mod tls_conn;

pub use config::ProverConfig;
pub use tls_conn::TLSConnection;

pub use state::{Initialized, Notarizing, ProverState};

#[derive(Debug)]
pub struct Prover<T: ProverState>(T);

impl<S> Prover<Initialized<S>>
where
    S: AsyncWrite + AsyncRead + Send + Unpin + 'static,
{
    pub fn new(
        config: ProverConfig,
        url: String,
        // TODO: Not pass into constructor, but method needed to construct this
        backend: Box<dyn Backend + Send + 'static>,
        server_socket: S,
    ) -> Result<(Self, TLSConnection), ProverError> {
        let (request_sender, request_receiver) = channel::mpsc::channel::<Bytes>(10);
        let (response_sender, response_receiver) =
            channel::mpsc::channel::<Result<Bytes, std::io::Error>>(10);
        let (close_tls_sender, close_tls_receiver) = channel::oneshot::channel::<()>();
        let (transcript_sender, transcript_receiver) = channel::oneshot::channel::<TranscriptSet>();

        let tls_conn = TLSConnection::new(request_sender, response_receiver, close_tls_sender);

        let server_name = ServerName::try_from(url.as_str())?;
        let client_config = Arc::new(config.client_config);
        let tls_client = ClientConnection::new(client_config, backend, server_name)?;

        Ok((
            Self(Initialized {
                request_receiver,
                response_sender,
                close_tls_receiver,
                tls_client,
                server_socket,
                transcript_channel: (transcript_sender, transcript_receiver),
            }),
            tls_conn,
        ))
    }

    // Caller needs to run future on executor
    pub async fn run(mut self) -> Result<Prover<Notarizing>, ProverError> {
        let mut sent_data: Vec<u8> = Vec::new();
        let mut received_data: Vec<u8> = Vec::new();

        let mut request_receiver = self.0.request_receiver;
        let mut response_sender = self.0.response_sender;

        let transcript_receiver = self.0.transcript_channel.1;

        let mut tls_client = self.0.tls_client;
        tls_client.start().await.unwrap();

        loop {
            select! {
                request = request_receiver.select_next_some() => {
                    sent_data.extend_from_slice(&request);
              tls_client.write_all_plaintext(&sent_data[sent_data.len() - request.len()..]).await.unwrap();
                },
                _ = &mut self.0.close_tls_receiver => {
                    // TODO: Handle this correctly
                    _ = tls_client.send_close_notify().await;
                    match tls_client.complete_io(&mut self.0.server_socket).await {
                        Ok(_) => (),
                        Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => (),
                        Err(err) => panic!("{}", err)
                    }
                    let transcript_received = Transcript::new("rx", received_data);
                    let transcript_sent = Transcript::new("tx", sent_data);

                    let transcript_set = TranscriptSet::new(&[transcript_sent, transcript_received]);
                    self.0.transcript_channel.0.send(transcript_set).unwrap();
                    break;
                },
                default => {
                    if tls_client.is_handshaking() {
                        tls_client.complete_io(&mut self.0.server_socket).await?;
                    }

                    if tls_client.wants_write() {
                        tls_client.write_tls_async(&mut self.0.server_socket).await?;
                    }

                    while tls_client.wants_read() {
                        if tls_client.complete_io(&mut self.0.server_socket).await?.0 == 0 {
                            break;
                        }
                    }

                    let mut buf = [0u8; 512];
                    if let Ok(n) = tls_client.reader().read(&mut buf) {
                        if n > 0 {
                            received_data.extend_from_slice(&buf[..n]);
                            response_sender.send(Ok(Bytes::copy_from_slice(&buf[..n]))).await.unwrap();
                        }
                    }
                }
            }
        }
        let transcript = transcript_receiver.await.unwrap();
        Ok(Prover(Notarizing { transcript }))
    }
}

impl Prover<Notarizing> {
    pub fn transcript(&self) -> &TranscriptSet {
        &self.0.transcript
    }

    pub fn send_commitments(&mut self) -> Result<(), ProverError> {
        todo!()
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
    #[error("Unable to close TLS connection")]
    CloseTlsConnection,
    #[error("Prover has already been shutdown")]
    AlreadyShutdown,
    #[error("Unable to receive transcripts: {0}")]
    TranscriptError(#[from] Canceled),
}
