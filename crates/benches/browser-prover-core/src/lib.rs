use async_io_stream;
use bytes::{Bytes, BytesMut};
use futures::{SinkExt, TryStream};
use serio::{
    codec::{Bincode, Framed},
    stream::IoStreamExt,
    Deserializer, IoDuplex, IoSink, IoStream, Serializer, Sink, SinkExt as _, Stream,
    StreamExt as _,
};
use std::{
    io::{Error, ErrorKind},
    marker::PhantomData,
    pin::Pin,
    task::{ready, Context, Poll},
};
use tokio::io::{duplex, AsyncRead, AsyncWrite, DuplexStream};
use tokio_util::{
    codec::LengthDelimitedCodec,
    compat::{Compat, TokioAsyncReadCompatExt},
};
use ws_stream_wasm::*;

/// A sink/stream for serializable types with a framed transport.
pub struct FramedIo<T>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    inner: serio::Framed<tokio_util::codec::Framed<T, LengthDelimitedCodec>, Bincode>,
}

impl<T> FramedIo<T>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    /// Creates a new `FramedIo` from the given async `io`.
    pub fn new(io: T) -> Self {
        let io = LengthDelimitedCodec::builder().new_framed(io);
        Self {
            inner: Framed::new(io, Bincode::default()),
        }
    }
}

impl<T> Sink for FramedIo<T>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    type Error = Error;

    fn poll_ready(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Pin::new(&mut self.inner).poll_ready(cx)
    }

    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Pin::new(&mut self.inner).poll_close(cx)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn start_send<Item: serio::Serialize>(
        mut self: Pin<&mut Self>,
        item: Item,
    ) -> std::result::Result<(), Self::Error> {
        Pin::new(&mut self.inner).start_send(item)
    }
}

impl<T> Stream for FramedIo<T>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    type Error = Error;

    fn poll_next<Item: serio::Deserialize>(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Item, Error>>> {
        Pin::new(&mut self.inner).poll_next(cx)
    }
}

/// Messages exchanged by the native and the browser components of the browser prover.
pub mod msg {
    use serde::{Deserialize, Serialize};

    #[derive(Serialize, Deserialize, PartialEq)]
    /// Sent by the browser component when it is expecting a config.
    pub struct ExpectingConfig {}

    #[derive(Serialize, Deserialize, PartialEq)]
    /// The config sent to the browser component.
    pub struct Config {
        pub upload_size: usize,
        pub download_size: usize,
        pub defer_decryption: bool,
    }

    #[derive(Serialize, Deserialize, PartialEq)]
    /// Sent by the browser component when proving process is finished. Contains total runtime
    /// in seconds.
    pub struct Runtime(pub u64);
}
