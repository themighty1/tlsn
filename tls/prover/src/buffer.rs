use futures::{AsyncRead, AsyncWrite};
use std::{
    io::Error,
    pin::Pin,
    sync::atomic::AtomicUsize,
    task::{Context, Poll, Waker},
};

pub struct ExchangeBuffer {
    request_buffer: ByteBuffer,
    response_buffer: ByteBuffer,
}

impl ExchangeBuffer {
    pub fn new() -> Self {
        Self {
            request_buffer: ByteBuffer::new(4096),
            response_buffer: ByteBuffer::new(4096),
        }
    }

    pub async fn make_request<T: Into<Vec<u8>>>(request: T) -> Result<(), BufferError> {
        let bytes: Vec<u8> = request.into();
        let mut buffer = self.request_buffer.lock().unwrap();
        buffer.write_all(&bytes).await?;
        Ok(())
    }

    pub async fn receive_response<T: From<&[u8]>>() -> Result<T, BufferError> {
        let mut buffer = self.response_buffer.lock().unwrap();
        let mut bytes = vec![0; 4096];
        buffer.read_exact(&mut bytes).await?;
        Ok(T::from(&bytes))
    }
}

struct ByteBuffer {
    buffer: Vec<u8>,
    read_mark: AtomicUsize,
    write_mark: AtomicUsize,
    read_waker: Option<Waker>,
    write_waker: Option<Waker>,
}

impl ByteBuffer {
    fn new(size: usize) -> Self {
        Self {
            buffer: vec![0; size],
            read_mark: AtomicUsize::new(0),
            write_mark: AtomicUsize::new(0),
            read_waker: None,
            write_waker: None,
        }
    }

    fn increment_read_mark(&self) -> Result<(usize, usize), BufferError> {
        let out = self.increment_mark(self.read_mark, self.write_mark);
        if out.is_ok() {
            if let Some(waker) = self.write_waker.take() {
                waker.wake();
            }
        }
        out
    }

    fn increment_read_mark_by(&self, data_len: usize) -> Result<usize, BufferError> {
        self.increment_mark_by(self.read_mark, self.write_mark, data_len)
    }

    fn increment_write_mark(&self) -> Result<(usize, usize), BufferError> {
        let out = self.increment_mark(self.write_mark, self.read_mark);
        if out.is_ok() {
            if let Some(waker) = self.read_waker.take() {
                waker.wake();
            }
        }
        out
    }

    fn increment_write_mark_by(&self, data_len: usize) -> Result<usize, BufferError> {
        self.increment_mark_by(self.write_mark, self.read_mark, data_len)
    }

    fn increment_mark(
        &self,
        mark_to_increment: AtomicUsize,
        mark: AtomicUsize,
    ) -> Result<(usize, usize), BufferError> {
        let m = mark.load(std::sync::atomic::Ordering::Relaxed);
        let mti = mark_to_increment.load(std::sync::atomic::Ordering::Acquire);

        match mark_to_increment.compare_exchange_weak(
            mti,
            m,
            std::sync::atomic::Ordering::Release,
            std::sync::atomic::Ordering::Relaxed,
        ) {
            Ok(old_mark) => {
                if old_mark < m {
                    Ok((old_mark, m - old_mark))
                } else {
                    Ok((old_mark, m + self.buffer.len() - old_mark))
                }
            }
            Err(_) => Err(BufferError::Nope),
        }
    }

    fn increment_mark_by(
        &self,
        mark_to_increment: AtomicUsize,
        mark: AtomicUsize,
        data_len: usize,
    ) -> Result<usize, BufferError> {
        if data_len > self.buffer.len() {
            return Err(BufferError::Nope);
        }

        let m = mark.load(std::sync::atomic::Ordering::Relaxed);
        let mti = mark_to_increment.load(std::sync::atomic::Ordering::Acquire);
        let new_potential_mti = mti + data_len;

        let inc_mark = |mark, new_mark| {
            mark_to_increment.compare_exchange_weak(
                mark,
                new_mark,
                std::sync::atomic::Ordering::Release,
                std::sync::atomic::Ordering::Relaxed,
            )
        };

        if mti < m {
            if new_potential_mti < m {
                inc_mark(mti, new_potential_mti)
            } else {
                Err(mti)
            }
        } else {
            if new_potential_mti < self.buffer.len() {
                inc_mark(mti, new_potential_mti)
            } else {
                if new_potential_mti < m {
                    inc_mark(mti, new_potential_mti - self.buffer.len())
                } else {
                    Err(mti)
                }
            }
        }
        .map_err(|_| BufferError::Nope)
    }
}

impl AsyncWrite for ByteBuffer {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, Error>> {
        Pin::new(&mut self.as_mut().buffer).poll_write(cx, buf)
    }

    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
        Pin::new(&mut self.as_mut().buffer).poll_close(cx)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
        Pin::new(&mut self.as_mut().buffer).poll_flush(cx)
    }
}

impl AsyncRead for ByteBuffer {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<Result<usize, Error>> {
        match self.increment_read_mark() {
            Ok((mark, len)) => {
                let mut buffer = self.buffer.clone();
                let mut read_buffer = buffer.split_off(mark);
                read_buffer.truncate(len);
            }
            Err(_) => {
                self.read_waker = Some(cx.waker().clone());
                Poll::Pending
            }
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum BufferError {
    #[error("Nope")]
    Nope,
}
