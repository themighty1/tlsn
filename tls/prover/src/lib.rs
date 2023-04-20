use buffer::{RequestBuffer, ResponseBuffer};
use config::ProverConfig;
use futures::{AsyncRead, AsyncWrite};
use std::{
    io::{Error, Read},
    net::TcpStream,
    pin::Pin,
    task::{Context, Poll},
};
use tls_client::ClientConnection;

mod buffer;
mod config;

pub struct Prover {
    request_buffer: RequestBuffer,
    response_buffer: ResponseBuffer,
    tls_connection: ClientConnection,
    tcp_stream: TcpStream,
}

impl Prover {
    pub fn new(config: ProverConfig) -> Self {
        todo!();
    }

    pub async fn run(&mut self) -> Result<(), ProverError> {
        loop {
            // Pull requests from the request buffer
            self.tls_connection.read_tls(&mut self.tcp_stream)?;
            self.tls_connection
                .reader()
                .read_to_end(&mut self.response_buffer.0)?;
            self.tls_connection.process_new_packets().await?;

            // Push responses into the response buffer
            self.tls_connection
                .write_all_plaintext(&self.request_buffer.0)
                .await?;
            self.tls_connection.write_tls(&mut self.tcp_stream)?;
        }
    }
}

impl AsyncRead for Prover {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<Result<usize, Error>> {
        Pin::new(&mut self.response_buffer).poll_read(cx, buf)
    }
}

impl AsyncWrite for Prover {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, Error>> {
        Pin::new(&mut self.request_buffer).poll_write(cx, buf)
    }

    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
        Pin::new(&mut self.request_buffer).poll_close(cx)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
        Pin::new(&mut self.request_buffer).poll_flush(cx)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ProverError {
    #[error("TLS client error: {0}")]
    TlsClientError(#[from] tls_client::Error),
    #[error("IO error: {0}")]
    IOError(#[from] std::io::Error),
}
