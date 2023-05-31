use bytes::Bytes;
use futures::{
    channel::{
        mpsc::{Receiver, SendError, Sender},
        oneshot::Sender as OneshotSender,
    },
    sink::SinkMapErr,
    AsyncRead, AsyncWrite, SinkExt,
};
use std::{
    pin::Pin,
    task::{Context, Poll},
};
use tokio_util::{
    compat::{Compat, TokioAsyncReadCompatExt, TokioAsyncWriteCompatExt},
    io::{CopyToBytes, SinkWriter, StreamReader},
};

pub struct TLSConnection {
    sink_writer:
        Compat<SinkWriter<CopyToBytes<SinkMapErr<Sender<Bytes>, fn(SendError) -> std::io::Error>>>>,
    stream_reader: Compat<StreamReader<Receiver<Result<Bytes, std::io::Error>>, Bytes>>,
    close_tls_sender: Option<OneshotSender<()>>,
}

impl TLSConnection {
    pub fn new(
        request_sender: Sender<Bytes>,
        response_receiver: Receiver<Result<Bytes, std::io::Error>>,
        close_tls_sender: OneshotSender<()>,
    ) -> Self {
        fn convert_error(err: SendError) -> std::io::Error {
            std::io::Error::new(std::io::ErrorKind::Other, err)
        }

        Self {
            sink_writer: SinkWriter::new(CopyToBytes::new(
                request_sender.sink_map_err(convert_error as fn(SendError) -> std::io::Error),
            ))
            .compat_write(),
            stream_reader: StreamReader::new(response_receiver).compat(),
            close_tls_sender: Some(close_tls_sender),
        }
    }

    pub async fn close_tls(&mut self) -> Result<(), std::io::Error> {
        let close_tls_sender = self.close_tls_sender.take().ok_or(std::io::Error::new(
            std::io::ErrorKind::Other,
            "TLSConnection already closed",
        ))?;
        close_tls_sender.send(()).map_err(|_| {
            std::io::Error::new(std::io::ErrorKind::Other, "Unable to close TLSConnection")
        })
    }
}

impl AsyncRead for TLSConnection {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<Result<usize, std::io::Error>> {
        Pin::new(&mut self.stream_reader).poll_read(cx, buf)
    }
}

impl AsyncWrite for TLSConnection {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, std::io::Error>> {
        Pin::new(&mut self.sink_writer).poll_write(cx, buf)
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        Pin::new(&mut self.sink_writer).poll_flush(cx)
    }

    fn poll_close(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        Pin::new(&mut self.sink_writer).poll_close(cx)
    }
}
