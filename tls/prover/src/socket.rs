use bytes::Bytes;
use futures::{sink::SinkMapErr, SinkExt};
use std::{
    pin::Pin,
    task::{Context, Poll},
};
use tokio::{
    io::{AsyncRead as TokioAsyncRead, AsyncWrite as TokioAsyncWrite, ReadBuf},
    sync::mpsc::{Receiver, Sender},
};
use tokio_stream::wrappers::ReceiverStream;
use tokio_util::{
    io::{CopyToBytes, SinkWriter, StreamReader},
    sync::{PollSendError, PollSender},
};

pub struct AsyncSocket {
    sink_writer: SinkWriter<
        CopyToBytes<SinkMapErr<PollSender<Bytes>, fn(PollSendError<Bytes>) -> std::io::Error>>,
    >,
    stream_reader: StreamReader<ReceiverStream<Result<Bytes, std::io::Error>>, Bytes>,
}

impl AsyncSocket {
    pub fn new(
        request_sender: Sender<Bytes>,
        response_receiver: Receiver<Result<Bytes, std::io::Error>>,
    ) -> Self {
        Self {
            sink_writer: SinkWriter::new(CopyToBytes::new(
                PollSender::new(request_sender)
                    .sink_map_err(|err| std::io::Error::new(std::io::ErrorKind::Other, err)),
            )),
            stream_reader: StreamReader::new(ReceiverStream::new(response_receiver)),
        }
    }
}

impl TokioAsyncRead for AsyncSocket {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf,
    ) -> Poll<Result<(), std::io::Error>> {
        Pin::new(&mut self.stream_reader).poll_read(cx, buf)
    }
}

impl TokioAsyncWrite for AsyncSocket {
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

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        Pin::new(&mut self.sink_writer).poll_shutdown(cx)
    }
}
