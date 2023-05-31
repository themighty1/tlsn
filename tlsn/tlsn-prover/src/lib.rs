use bytes::Bytes;
use futures::{
    channel::{self, oneshot::Canceled},
    select_biased, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, FutureExt, SinkExt,
    StreamExt,
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

const RX_TLS_BUF_SIZE: usize = 2 << 13; // 8 KiB
const RX_BUF_SIZE: usize = 2 << 13; // 8 KiB

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
        let client = ClientConnection::new(client_config, backend, server_name)?;

        Ok((
            Self(Initialized {
                tx_receiver,
                rx_sender,
                close_tls_receiver,
                client,
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
            tx_receiver,
            rx_sender,
            close_tls_receiver,
            client,
            server_socket,
            mut transcript_tx,
            mut transcript_rx,
        } = self.0;

        run_client(
            client,
            server_socket,
            &mut transcript_tx,
            &mut transcript_rx,
            tx_receiver,
            rx_sender,
            close_tls_receiver,
        )
        .await?;

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

/// Runs the TLS session to completion, returning the session transcripts.
async fn run_client<T: AsyncWrite + AsyncRead + Unpin>(
    mut client: ClientConnection,
    server_socket: T,
    transcript_tx: &mut Transcript,
    transcript_rx: &mut Transcript,
    mut tx_receiver: channel::mpsc::Receiver<Bytes>,
    mut rx_sender: channel::mpsc::Sender<Result<Bytes, std::io::Error>>,
    mut close_tls_receiver: channel::oneshot::Receiver<()>,
) -> Result<(), ProverError> {
    client.start().await?;

    let (mut server_rx, mut server_tx) = server_socket.split();

    let mut rx_tls_buf = [0u8; RX_TLS_BUF_SIZE];
    let mut rx_buf = [0u8; RX_BUF_SIZE];

    let mut client_closed = false;
    let mut server_closed = false;

    let mut rx_tls_fut = server_rx.read(&mut rx_tls_buf).fuse();
    loop {
        select_biased! {
            read_res = &mut rx_tls_fut => {
                let received = read_res?;

                // Loop until we've processed all the data we received in this read.
                let mut processed = 0;
                while processed < received {
                    processed += client.read_tls(&mut &rx_tls_buf[processed..received])?;
                    match client.process_new_packets().await {
                        Ok(_) => {}
                        Err(e) => {
                            // In case we have an alert to send describing this error,
                            // try a last-gasp write -- but don't predate the primary
                            // error.
                            let _ignored = client.write_tls_async(&mut server_tx).await;

                            return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
                        }
                    }
                }

                if received == 0 {
                    server_closed = true;
                }

                // Reset the read future so next iteration we can read again.
                rx_tls_fut = server_rx.read(&mut rx_tls_buf).fuse();
            }
            data = tx_receiver.select_next_some() => {
                transcript_tx.extend(&data);
                client
                    .write_all_plaintext(&data)
                    .await?;
            },
            _ = &mut close_tls_receiver => {
                client_closed = true;

                client.send_close_notify().await?;

                // Flush all remaining plaintext
                while client.wants_write() {
                    client.write_tls_async(&mut server_tx).await?;
                }
                server_tx.flush().await?;
                server_tx.close().await?;
            },
        }

        while client.wants_write() && !client_closed {
            client.write_tls_async(&mut server_tx).await?;
        }

        // Flush all remaining plaintext to the server
        // otherwise this loop could hang forever as the server
        // waits for more data before responding.
        server_tx.flush().await?;

        // Forward all plaintext to the TLSConnection
        loop {
            let n = match client.reader().read(&mut rx_buf) {
                Ok(n) => n,
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                // Some servers will not send a close_notify, in which case we need to
                // error because we can't reveal the MAC key to the Notary.
                Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                    return Err(ProverError::ServerNoCloseNotify)
                }
                Err(e) => return Err(e)?,
            };

            if n > 0 {
                transcript_rx.extend(&rx_buf[..n]);
                rx_sender
                    .send(Ok(Bytes::copy_from_slice(&rx_buf[..n])))
                    .await
                    .unwrap();
            } else {
                break;
            }
        }

        if client_closed && server_closed {
            break;
        }
    }

    // Extra guard to guarantee that the server sent a close_notify.
    //
    // DO NOT REMOVE!
    //
    // This is necessary, as our protocol reveals the MAC key to the Notary afterwards
    // which could be used to authenticate modified TLS records if the Notary is
    // in the middle of the connection.
    if !client.received_close_notify() {
        return Err(ProverError::ServerNoCloseNotify);
    }

    Ok(())
}
