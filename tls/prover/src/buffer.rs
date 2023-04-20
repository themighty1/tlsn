use futures::io::{AsyncRead, AsyncWrite};
use std::{
    io::Error,
    net::TcpStream,
    pin::Pin,
    task::{Context, Poll},
};

pub struct RequestBuffer(pub Vec<u8>);

impl AsyncWrite for RequestBuffer {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, Error>> {
        todo!()
    }

    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
        todo!()
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
        todo!()
    }
}

pub struct ResponseBuffer(pub Vec<u8>);

impl AsyncRead for ResponseBuffer {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<Result<usize, Error>> {
        todo!()
    }
}
