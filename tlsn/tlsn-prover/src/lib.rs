use bytes::Bytes;
use futures::{
    channel::{self, oneshot::Canceled},
    select, AsyncRead, AsyncWrite, SinkExt, StreamExt,
};
use std::{io::Read, sync::Arc};
use tls_client::{client::InvalidDnsNameError, Backend, ClientConnection, ServerName};
use tlsn_core::transcript::Transcript;

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
        let (tx_sender, tx_receiver) = channel::mpsc::channel::<Bytes>(10);
        let (rx_sender, rx_receiver) = channel::mpsc::channel::<Result<Bytes, std::io::Error>>(10);
        let (close_tls_sender, close_tls_receiver) = channel::oneshot::channel::<()>();

        let tls_conn = TLSConnection::new(tx_sender, rx_receiver, close_tls_sender);

        let server_name = ServerName::try_from(url.as_str())?;
        let client_config = Arc::new(config.client_config);
        let tls_client = ClientConnection::new(client_config, backend, server_name)?;

        Ok((
            Self(Initialized {
                tx_receiver,
                rx_sender,
                close_tls_receiver,
                tls_client,
                server_socket,
                transcript_tx: Transcript::new("tx", vec![]),
                transcript_rx: Transcript::new("rx", vec![]),
            }),
            tls_conn,
        ))
    }

    // Caller needs to run future on executor
    pub async fn run(self) -> Result<Prover<Notarizing>, ProverError> {
        let Initialized {
            mut tx_receiver,
            mut rx_sender,
            mut close_tls_receiver,
            mut tls_client,
            mut server_socket,
            mut transcript_tx,
            mut transcript_rx,
        } = self.0;

        tls_client.start().await?;

        let mut rx_buf = [0u8; 512];
        loop {
            select! {
                data = tx_receiver.select_next_some() => {
                    transcript_tx.extend(&data);
                    tls_client
                        .write_all_plaintext(&data)
                        .await?;
                },
                _ = &mut close_tls_receiver => {
                    tls_client.send_close_notify().await?;

                    // Drain any remaining data from the connection
                    loop {
                        match tls_client.complete_io(&mut server_socket).await {
                            Ok(_) => {},
                            // Not all servers correctly close the connection with a close_notify,
                            // if this happens we must abort because we can't reveal the MAC key
                            // to the Notary.
                            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                                return Err(ProverError::ServerNoCloseNotify)
                            },
                            Err(e) => return Err(e)?,
                        }

                        if let Ok(n) = tls_client.reader().read(&mut rx_buf) {
                            if n > 0 {
                                transcript_rx.extend(&rx_buf[..n]);
                                rx_sender.send(Ok(Bytes::copy_from_slice(&rx_buf[..n]))).await.unwrap();
                            } else {
                                // Drain until EOF, ie Ok(0)
                                break;
                            }
                        }
                    }

                    break;
                },
                default => {
                    if tls_client.is_handshaking() {
                        tls_client.complete_io(&mut server_socket).await?;
                    }

                    if tls_client.wants_write() {
                        tls_client.write_tls_async(&mut server_socket).await?;
                    }

                    while tls_client.wants_read() {
                        if tls_client.complete_io(&mut server_socket).await?.0 == 0 {
                            break;
                        }
                    }

                    if let Ok(n) = tls_client.reader().read(&mut rx_buf) {
                        if n > 0 {
                            transcript_rx.extend(&rx_buf[..n]);
                            rx_sender.send(Ok(Bytes::copy_from_slice(&rx_buf[..n]))).await.unwrap();
                        }
                    }
                }
            }
        }

        Ok(Prover(Notarizing {
            transcript_tx,
            transcript_rx,
        }))
    }
}

impl Prover<Notarizing> {
    pub fn sent_transcript(&self) -> &Transcript {
        &self.0.transcript_tx
    }

    pub fn recv_transcript(&self) -> &Transcript {
        &self.0.transcript_rx
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
    InvalidServerName(#[from] InvalidDnsNameError),
    #[error("Prover is already running")]
    AlreadyRunning,
    #[error("Unable to close TLS connection")]
    CloseTlsConnection,
    #[error("server did not send a close_notify")]
    ServerNoCloseNotify,
    #[error("Prover has already been shutdown")]
    AlreadyShutdown,
    #[error("Unable to receive transcripts: {0}")]
    TranscriptError(#[from] Canceled),
}
