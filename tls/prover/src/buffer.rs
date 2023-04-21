use std::{
    io::Error,
    pin::Pin,
    sync::{atomic::AtomicUsize, Arc, Mutex},
    task::{Context, Poll},
};

use futures::{AsyncRead, AsyncWrite};

pub struct ExchangeBuffer {
    request_buffer: Arc<Mutex<Vec<u8>>>,
    response_buffer: Arc<Mutex<Vec<u8>>>,
}

impl ExchangeBuffer {
    pub fn new(size: usize) -> Self {
        Self {
            request_buffer: Arc::new(Mutex::new(vec![0; size])),
            response_buffer: Arc::new(Mutex::new(vec![0; size])),
        }
    }

    pub fn request_buffer(&self) -> RequestBuffer {
        RequestBuffer(self.request_buffer.clone())
    }

    pub async fn write_request(&mut self) -> Result<(), Error> {
        todo!();
    }

    pub async fn read_request(&mut self) -> Result<(), Error> {
        todo!();
    }
}

impl AsyncWrite for RequestBuffer {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, Error>> {
        Pin::new(&mut self.as_mut().0).poll_write(cx, buf)
    }

    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
        Pin::new(&mut self.as_mut().0).poll_close(cx)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
        Pin::new(&mut self.as_mut().0).poll_flush(cx)
    }
}

pub struct ResponseBuffer(pub Vec<u8>);

impl AsyncRead for ResponseBuffer {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<Result<usize, Error>> {
        Pin::new(&mut self.0.as_slice()).poll_read(cx, buf)
    }
}
