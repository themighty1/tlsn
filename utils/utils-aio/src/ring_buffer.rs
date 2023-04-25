use futures::{
    task::{AtomicWaker, Context, Poll},
    AsyncRead, AsyncWrite,
};
use std::{
    io::{Error, Read, Write},
    pin::Pin,
    sync::atomic::AtomicUsize,
};

pub struct AtomicByteBuffer {
    buffer: Vec<u8>,
    read_mark: AtomicUsize,
    write_mark: AtomicUsize,
    read_waker: AtomicWaker,
    write_waker: AtomicWaker,
    bit_mask: usize,
}

impl AtomicByteBuffer {
    pub fn new(size: usize) -> Self {
        let optimized_size = size.next_power_of_two();
        let bit_mask = optimized_size - 1;
        Self {
            buffer: vec![0; optimized_size],
            read_mark: AtomicUsize::new(bit_mask - 1),
            write_mark: AtomicUsize::new(bit_mask),
            read_waker: AtomicWaker::new(),
            write_waker: AtomicWaker::new(),
            bit_mask,
        }
    }

    unsafe fn raw_mut(&self) -> &mut [u8] {
        unsafe {
            let slice_start = self.buffer.as_ptr() as *mut u8;
            std::slice::from_raw_parts_mut(slice_start, self.buffer.len())
        }
    }

    fn increment_read_mark(&self, max: usize) -> Result<(usize, usize), BufferError> {
        let out = self.increment_mark(&self.read_mark, &self.write_mark, max);
        if out.is_ok() {
            self.write_waker.wake();
        }
        out
    }

    fn increment_write_mark(&self, max: usize) -> Result<(usize, usize), BufferError> {
        let out = self.increment_mark(&self.write_mark, &self.read_mark, max);
        if out.is_ok() {
            self.read_waker.wake();
        }
        out
    }

    fn increment_mark(
        &self,
        mark_to_increment: &AtomicUsize,
        until_mark: &AtomicUsize,
        max: usize,
    ) -> Result<(usize, usize), BufferError> {
        let mti = mark_to_increment.load(std::sync::atomic::Ordering::Acquire);
        let um = until_mark.load(std::sync::atomic::Ordering::Relaxed);

        let mut moved = mti.abs_diff(um) - 1;
        if um < mti {
            moved = self.buffer.len() - moved - 2;
        }
        moved = std::cmp::min(moved, max);

        let new_mark = (mti + moved) & self.bit_mask;

        match mark_to_increment.compare_exchange_weak(
            mti,
            new_mark,
            std::sync::atomic::Ordering::Release,
            std::sync::atomic::Ordering::Relaxed,
        ) {
            Ok(old_mark) => Ok(((old_mark + 1) & self.bit_mask, moved)),
            Err(_) => Err(BufferError::NoProgress),
        }
    }
}

impl AsyncWrite for &AtomicByteBuffer {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, Error>> {
        let atomic_byte_buffer = Pin::into_inner(self);
        match Write::write(atomic_byte_buffer, buf) {
            Ok(len) => Poll::Ready(Ok(len)),
            Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                atomic_byte_buffer.write_waker.register(cx.waker());
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

impl AsyncWrite for AtomicByteBuffer {
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

impl Write for &AtomicByteBuffer {
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

impl Write for AtomicByteBuffer {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        (&*self).write(buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl AsyncRead for &AtomicByteBuffer {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<Result<usize, Error>> {
        let atomic_byte_buffer = Pin::into_inner(self);
        match Read::read(atomic_byte_buffer, buf) {
            Ok(len) => Poll::Ready(Ok(len)),
            Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                atomic_byte_buffer.read_waker.register(cx.waker());
                Poll::Pending
            }
            _ => unreachable!(),
        }
    }
}

impl AsyncRead for AtomicByteBuffer {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<Result<usize, Error>> {
        Pin::new(&mut (&*self)).poll_read(cx, buf)
    }
}

impl Read for &AtomicByteBuffer {
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
                Ok(len)
            }
            Err(BufferError::NoProgress) => Err(std::io::Error::new(
                std::io::ErrorKind::WouldBlock,
                "No progress was made",
            )),
        }
    }
}

impl Read for AtomicByteBuffer {
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
        let mut buffer = AtomicByteBuffer::new(255);
        let input = vec![1; 512];
        let result = buffer.write(&input);

        assert_eq!(buffer.read_mark.load(Ordering::SeqCst), 254);
        assert_eq!(buffer.write_mark.load(Ordering::SeqCst), 253);
        assert_eq!(buffer.buffer, [vec![1; 254], vec![0; 2]].concat().to_vec());
        assert!(matches!(result, Ok(254)));
    }

    #[test]
    fn test_ring_buffer_write_shorter_buffer() {
        let mut buffer = AtomicByteBuffer::new(255);
        let input = vec![1; 30];
        let result = buffer.write(&input);

        assert_eq!(buffer.read_mark.load(Ordering::SeqCst), 254);
        assert_eq!(buffer.write_mark.load(Ordering::SeqCst), 29);
        assert_eq!(buffer.buffer, [vec![1; 30], vec![0; 226]].concat().to_vec());
        assert!(matches!(result, Ok(30)));
    }

    #[test]
    fn test_ring_buffer_read_longer_buffer() {
        let mut buffer = AtomicByteBuffer::new(255);
        buffer.buffer = vec![1; 256];
        buffer.read_mark.store(255, Ordering::SeqCst);
        buffer.write_mark.store(254, Ordering::SeqCst);

        let mut output = vec![0; 512];
        let result = buffer.read(&mut output);

        assert_eq!(buffer.read_mark.load(Ordering::SeqCst), 253);
        assert_eq!(buffer.write_mark.load(Ordering::SeqCst), 254);
        assert_eq!(output, [vec![1; 254], vec![0; 258]].concat().to_vec());
        assert!(matches!(result, Ok(254)));
    }

    #[test]
    fn test_ring_buffer_read_shorter_buffer() {
        let mut buffer = AtomicByteBuffer::new(255);
        buffer.buffer = vec![1; 256];
        buffer.read_mark.store(255, Ordering::SeqCst);
        buffer.write_mark.store(254, Ordering::SeqCst);

        let mut output = vec![0; 30];
        let result = buffer.read(&mut output);

        assert_eq!(buffer.read_mark.load(Ordering::SeqCst), 29);
        assert_eq!(buffer.write_mark.load(Ordering::SeqCst), 254);
        assert_eq!(output, vec![1; 30]);
        assert!(matches!(result, Ok(30)));
    }
}
