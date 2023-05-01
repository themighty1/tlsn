use futures::{
    task::{AtomicWaker, Context, Poll},
    AsyncRead, AsyncWrite,
};
use std::{
    io::{Error, Read, Write},
    pin::Pin,
    sync::atomic::{AtomicBool, AtomicUsize},
};

#[derive(Debug)]
pub struct RingBuffer {
    buffer: Vec<u8>,
    read_mark: AtomicUsize,
    write_mark: AtomicUsize,
    can_write: AtomicBool,
    read_waker: AtomicWaker,
    write_waker: AtomicWaker,
}

impl RingBuffer {
    pub fn new(size: usize) -> Self {
        let optimized_size = size.next_power_of_two();
        Self {
            buffer: vec![0; optimized_size],
            read_mark: AtomicUsize::new(0),
            write_mark: AtomicUsize::new(0),
            can_write: AtomicBool::new(true),
            read_waker: AtomicWaker::new(),
            write_waker: AtomicWaker::new(),
        }
    }

    unsafe fn raw_mut(&self) -> &mut [u8] {
        unsafe {
            let slice_start = self.buffer.as_ptr() as *mut u8;
            std::slice::from_raw_parts_mut(slice_start, self.buffer.len())
        }
    }

    fn increment_read_mark(&self, max: usize) -> Result<(usize, usize), BufferError> {
        let read_mark = self.read_mark.load(std::sync::atomic::Ordering::Acquire);
        let write_mark = self.write_mark.load(std::sync::atomic::Ordering::Relaxed);

        if read_mark == write_mark {
            if !self.can_write.load(std::sync::atomic::Ordering::Acquire) {
                if max >= self.buffer.len() {
                    return Ok((read_mark, self.buffer.len()));
                }
            } else {
                return Err(BufferError::NoProgress);
            }
        }

        let distance = self.compute_distance(read_mark, write_mark, max);
        let new_mark = (read_mark + distance) & (self.buffer.len() - 1);

        match self.read_mark.compare_exchange_weak(
            read_mark,
            new_mark,
            std::sync::atomic::Ordering::Release,
            std::sync::atomic::Ordering::Relaxed,
        ) {
            Ok(old_mark) => Ok((old_mark, distance)),
            Err(_) => Err(BufferError::NoProgress),
        }
    }

    fn increment_write_mark(&self, max: usize) -> Result<(usize, usize), BufferError> {
        let write_mark = self.write_mark.load(std::sync::atomic::Ordering::Acquire);
        let read_mark = self.read_mark.load(std::sync::atomic::Ordering::Relaxed);

        if write_mark == read_mark {
            if self.can_write.load(std::sync::atomic::Ordering::Acquire) {
                if max >= self.buffer.len() {
                    return Ok((write_mark, self.buffer.len()));
                }
            } else {
                return Err(BufferError::NoProgress);
            }
        }

        let distance = self.compute_distance(write_mark, read_mark, max);
        let new_mark = (write_mark + distance) & (self.buffer.len() - 1);

        match self.write_mark.compare_exchange_weak(
            write_mark,
            new_mark,
            std::sync::atomic::Ordering::Release,
            std::sync::atomic::Ordering::Relaxed,
        ) {
            Ok(old_mark) => Ok((old_mark, distance)),
            Err(_) => Err(BufferError::NoProgress),
        }
    }

    fn compute_distance(&self, mark_to_increment: usize, until_mark: usize, max: usize) -> usize {
        let mut distance = mark_to_increment.abs_diff(until_mark);
        if until_mark <= mark_to_increment {
            distance = self.buffer.len() - distance;
        }
        std::cmp::min(distance, max)
    }
}

impl AsyncWrite for &RingBuffer {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, Error>> {
        let byte_buffer = Pin::into_inner(self);
        match Write::write(byte_buffer, buf) {
            Ok(len) => {
                byte_buffer.read_waker.wake();
                Poll::Ready(Ok(len))
            }
            Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                byte_buffer.write_waker.register(cx.waker());
                Poll::Pending
            }
            _ => unreachable!(),
        }
    }

    fn poll_close(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
        Poll::Ready(Ok(()))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for RingBuffer {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, Error>> {
        Pin::new(&mut (&*self)).poll_write(cx, buf)
    }

    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
        Pin::new(&mut (&*self)).poll_close(cx)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
        Pin::new(&mut (&*self)).poll_flush(cx)
    }
}

impl Write for &RingBuffer {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        match self.increment_write_mark(buf.len()) {
            Ok((mark, len)) => {
                let buffer = unsafe { self.raw_mut() };
                let buffer_len = buffer.len();
                if mark + len <= buffer_len {
                    _ = (&mut buffer[mark..mark + len]).write(buf);
                } else {
                    _ = (&mut buffer[mark..]).write(buf);
                    _ = (&mut buffer[..len - (buffer_len - mark)]).write(buf);
                }
                self.can_write
                    .store(false, std::sync::atomic::Ordering::Release);
                Ok(len)
            }
            Err(BufferError::NoProgress) => Err(std::io::Error::new(
                std::io::ErrorKind::WouldBlock,
                "No progress was made",
            )),
        }
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl Write for RingBuffer {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        (&*self).write(buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl AsyncRead for &RingBuffer {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<Result<usize, Error>> {
        let byte_buffer = Pin::into_inner(self);
        match Read::read(byte_buffer, buf) {
            Ok(len) => {
                byte_buffer.write_waker.wake();
                Poll::Ready(Ok(len))
            }
            Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                byte_buffer.read_waker.register(cx.waker());
                Poll::Pending
            }
            _ => unreachable!(),
        }
    }
}

impl AsyncRead for RingBuffer {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<Result<usize, Error>> {
        Pin::new(&mut (&*self)).poll_read(cx, buf)
    }
}

impl Read for &RingBuffer {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let buffer = &self.buffer;
        match self.increment_read_mark(buf.len()) {
            Ok((mark, len)) => {
                if mark + len <= buffer.len() {
                    _ = (&buffer[mark..mark + len]).read(buf);
                } else {
                    _ = (&buffer[mark..]).read(buf);
                    _ = (&buffer[..len - (buffer.len() - mark)]).read(buf);
                }
                self.can_write
                    .store(true, std::sync::atomic::Ordering::Release);
                Ok(len)
            }
            Err(BufferError::NoProgress) => Err(std::io::Error::new(
                std::io::ErrorKind::WouldBlock,
                "No progress was made",
            )),
        }
    }
}

impl Read for RingBuffer {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        (&*self).read(buf)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum BufferError {
    #[error("No progress was made")]
    NoProgress,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::Ordering;

    #[test]
    fn test_ring_buffer_write_longer_buffer() {
        let mut buffer = RingBuffer::new(256);
        let input = vec![1; 512];
        let result = buffer.write(&input);

        assert_eq!(buffer.read_mark.load(Ordering::SeqCst), 0);
        assert_eq!(buffer.write_mark.load(Ordering::SeqCst), 0);
        assert_eq!(buffer.buffer, vec![1; 256]);
        assert!(matches!(result, Ok(256)));
    }

    #[test]
    fn test_ring_buffer_write_shorter_buffer() {
        let mut buffer = RingBuffer::new(256);
        let input = vec![1; 30];
        let result = buffer.write(&input);

        assert_eq!(buffer.read_mark.load(Ordering::SeqCst), 0);
        assert_eq!(buffer.write_mark.load(Ordering::SeqCst), 30);
        assert_eq!(buffer.buffer, [vec![1; 30], vec![0; 226]].concat().to_vec());
        assert!(matches!(result, Ok(30)));
    }

    #[test]
    fn test_ring_buffer_read_longer_buffer() {
        let mut buffer = RingBuffer::new(256);
        buffer.buffer = vec![1; 256];
        buffer.can_write.store(false, Ordering::SeqCst);

        let mut output = vec![0; 512];
        let result = buffer.read(&mut output);

        assert_eq!(buffer.read_mark.load(Ordering::SeqCst), 0);
        assert_eq!(buffer.write_mark.load(Ordering::SeqCst), 0);
        assert_eq!(output, [vec![1; 256], vec![0; 256]].concat().to_vec());
        assert!(matches!(result, Ok(256)));
    }

    #[test]
    fn test_ring_buffer_read_shorter_buffer() {
        let mut buffer = RingBuffer::new(256);
        buffer.buffer = vec![1; 256];
        buffer.can_write.store(false, Ordering::SeqCst);

        let mut output = vec![0; 30];
        let result = buffer.read(&mut output);

        assert_eq!(buffer.read_mark.load(Ordering::SeqCst), 30);
        assert_eq!(buffer.write_mark.load(Ordering::SeqCst), 0);
        assert_eq!(output, vec![1; 30]);
        assert!(matches!(result, Ok(30)));
    }

    #[test]
    fn test_ring_buffer_read_write_short_repeated() {
        let input = (0..128).collect::<Vec<u8>>();
        let mut output = vec![0; 128];

        let buffer = RingBuffer::new(16);

        let mut read_mark = 0;
        let mut write_mark = 0;
        loop {
            write_mark += (&buffer).write(&input[write_mark..]).unwrap();
            read_mark += (&buffer).read(&mut output[read_mark..]).unwrap();
            if write_mark == input.len() {
                break;
            }
        }
        assert_eq!(input, output);
    }

    #[test]
    fn test_ring_buffer_read_write_long_repeated() {
        let input = (0..128).collect::<Vec<u8>>();
        let mut output = vec![0; 128];

        let buffer = RingBuffer::new(256);

        let mut read_mark = 0;
        let mut write_mark = 0;
        loop {
            write_mark += (&buffer).write(&input[write_mark..]).unwrap();
            read_mark += (&buffer).read(&mut output[read_mark..]).unwrap();
            if write_mark == input.len() {
                break;
            }
        }
        assert_eq!(input, output);
    }

    #[test]
    fn test_ring_buffer_multi_thread_short() {
        let input = (0..128).collect::<Vec<u8>>();
        let mut output = vec![0; 128];
        let buffer = RingBuffer::new(32);

        std::thread::scope(|s| {
            s.spawn(|| {
                let mut write_mark = 0;
                loop {
                    match (&buffer).write(&input[write_mark..]) {
                        Ok(len) => write_mark += len,
                        Err(_) => continue,
                    }
                    if write_mark == input.len() {
                        break;
                    }
                }
            });
            s.spawn(|| {
                let mut read_mark = 0;
                loop {
                    match (&buffer).read(&mut output[read_mark..]) {
                        Ok(len) => read_mark += len,
                        Err(_) => continue,
                    }
                    if read_mark == output.len() {
                        break;
                    }
                }
            });
        });
        assert_eq!(input, output);
    }

    #[test]
    fn test_ring_buffer_multi_thread_long() {
        let input = (0..128).collect::<Vec<u8>>();
        let mut output = vec![0; 128];
        let buffer = RingBuffer::new(256);

        std::thread::scope(|s| {
            s.spawn(|| {
                let mut write_mark = 0;
                loop {
                    match (&buffer).write(&input[write_mark..]) {
                        Ok(len) => write_mark += len,
                        Err(_) => continue,
                    }
                    if write_mark == input.len() {
                        break;
                    }
                }
            });
            s.spawn(|| {
                let mut read_mark = 0;
                loop {
                    match (&buffer).read(&mut output[read_mark..]) {
                        Ok(len) => read_mark += len,
                        Err(_) => continue,
                    }
                    if read_mark == output.len() {
                        break;
                    }
                }
            });
        });
        assert_eq!(input, output);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_ring_buffer_async() {
        let input = (0..128).collect::<Vec<u8>>();
        let mut output = vec![0; 128];
        let mut buffer = RingBuffer::new(256);
        let mut pin_buffer = Pin::new(&mut buffer);

        let fut_write = tokio::spawn(async move {
            let mut write_mark = 0;
            loop {
                match futures::AsyncWriteExt::write(&mut pin_buffer, &input[write_mark..]).await {
                    Ok(len) => write_mark += len,
                    Err(_) => continue,
                }
                if write_mark == input.len() {
                    break input;
                }
            }
        });
        let fut_read = tokio::spawn(async move {
            let mut read_mark = 0;
            loop {
                match futures::AsyncReadExt::read(&mut pin_buffer, &mut output[read_mark..]).await {
                    Ok(len) => read_mark += len,
                    Err(_) => continue,
                }
                if read_mark == output.len() {
                    break output;
                }
            }
        });
        let (input, output) = tokio::try_join!(fut_write, fut_read).unwrap();
        assert_eq!(input, output);
    }
}
