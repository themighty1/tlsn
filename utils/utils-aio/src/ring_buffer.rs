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
    bit_mask: usize,
}

impl RingBuffer {
    pub fn new(size: usize) -> Self {
        let optimized_size = size.next_power_of_two();
        let bit_mask = optimized_size - 1;
        Self {
            buffer: vec![0; optimized_size],
            read_mark: AtomicUsize::new(0),
            write_mark: AtomicUsize::new(0),
            can_write: AtomicBool::new(true),
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
        let (mark, mut len) = self.increment_mark(&self.read_mark, &self.write_mark, max)?;
        if len == self.buffer.len()
            && self
                .can_write
                .swap(true, std::sync::atomic::Ordering::AcqRel)
        {
            len = 0;
        }
        self.read_waker.wake();
        Ok((mark, len))
    }

    fn increment_write_mark(&self, max: usize) -> Result<(usize, usize), BufferError> {
        let (mark, mut len) = self.increment_mark(&self.write_mark, &self.read_mark, max)?;
        if len == self.buffer.len()
            && !self
                .can_write
                .swap(false, std::sync::atomic::Ordering::AcqRel)
        {
            len = 0;
        }
        self.read_waker.wake();
        Ok((mark, len))
    }

    fn increment_mark(
        &self,
        mark_to_increment: &AtomicUsize,
        until_mark: &AtomicUsize,
        max: usize,
    ) -> Result<(usize, usize), BufferError> {
        let mti = mark_to_increment.load(std::sync::atomic::Ordering::Acquire);
        let um = until_mark.load(std::sync::atomic::Ordering::Relaxed);

        let mut distance = mti.abs_diff(um);
        if um <= mti {
            distance = self.buffer.len() - distance;
        }
        distance = std::cmp::min(distance, max);
        if distance == self.bit_mask + 1 {
            return Ok((mti, distance));
        }

        let new_mark = (mti + distance) & self.bit_mask;

        match mark_to_increment.compare_exchange_weak(
            mti,
            new_mark,
            std::sync::atomic::Ordering::Release,
            std::sync::atomic::Ordering::Relaxed,
        ) {
            Ok(old_mark) => Ok((old_mark, distance)),
            Err(_) => Err(BufferError::NoProgress),
        }
    }
}

impl AsyncWrite for &RingBuffer {
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

        assert_eq!(buffer.read_mark.load(Ordering::SeqCst), 254);
        assert_eq!(buffer.write_mark.load(Ordering::SeqCst), 253);
        assert_eq!(buffer.buffer, [vec![1; 254], vec![0; 2]].concat().to_vec());
        assert!(matches!(result, Ok(254)));
    }

    #[test]
    fn test_ring_buffer_write_shorter_buffer() {
        let mut buffer = RingBuffer::new(256);
        let input = vec![1; 30];
        let result = buffer.write(&input);

        assert_eq!(buffer.read_mark.load(Ordering::SeqCst), 254);
        assert_eq!(buffer.write_mark.load(Ordering::SeqCst), 29);
        assert_eq!(buffer.buffer, [vec![1; 30], vec![0; 226]].concat().to_vec());
        assert!(matches!(result, Ok(30)));
    }

    #[test]
    fn test_ring_buffer_read_longer_buffer() {
        let mut buffer = RingBuffer::new(256);
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
        let mut buffer = RingBuffer::new(256);
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

    #[test]
    fn test_ring_buffer_read_write() {
        let input = (0..128).collect::<Vec<u8>>();
        let mut output = vec![0; 128];

        let buffer = RingBuffer::new(16);

        let mut read_mark = 0;
        let mut write_mark = 0;
        loop {
            println!("After read: {:#?}", &buffer);
            read_mark += (&buffer).write(&input[read_mark..]).unwrap();
            println!("After write: {:#?}", &buffer);
            write_mark += (&buffer).read(&mut output[write_mark..]).unwrap();
            if write_mark == input.len() {
                break;
            }
        }
        assert_eq!(input, output);
    }
}
