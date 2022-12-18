use futures::{channel::mpsc, Sink, Stream};
use std::{
    future::Future,
    io::{Error, ErrorKind},
    pin::Pin,
    task::Poll,
    time::Duration,
};
use tokio::time::{sleep, Instant, Sleep};

#[derive(Debug)]
struct Wrapper<T>(T, Instant);

impl<T> Wrapper<T> {
    fn new(item: T, millis: u64) -> Self {
        Self(item, Instant::now() + Duration::from_millis(millis))
    }
}

pub struct DuplexChannelLatency<T> {
    millis: u64,
    sink: mpsc::UnboundedSender<Wrapper<T>>,
    stream: mpsc::UnboundedReceiver<Wrapper<T>>,
    pending: Option<T>,
    sleep: Pin<Box<Sleep>>,
}

//impl<T> super::Channel<T> for DuplexChannelLatency<T> where T: Send + 'static {}

impl<T> DuplexChannelLatency<T>
where
    T: Send + Unpin + 'static,
{
    pub fn new(millis: u64) -> (Self, Self) {
        let (sender, receiver) = mpsc::unbounded::<Wrapper<T>>();
        let (sender_2, receiver_2) = mpsc::unbounded::<Wrapper<T>>();

        (
            Self {
                millis,
                sink: sender,
                stream: receiver_2,
                pending: None,
                sleep: Box::pin(sleep(Duration::from_millis(0))),
            },
            Self {
                millis,
                sink: sender_2,
                stream: receiver,
                pending: None,
                sleep: Box::pin(sleep(Duration::from_millis(0))),
            },
        )
    }
}

impl<T> Sink<T> for DuplexChannelLatency<T>
where
    T: Send + Unpin + 'static,
{
    type Error = std::io::Error;

    fn poll_ready(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        Pin::new(&mut self.sink)
            .poll_ready(cx)
            .map_err(|_| Error::new(ErrorKind::ConnectionAborted, "channel died"))
    }

    fn start_send(mut self: std::pin::Pin<&mut Self>, item: T) -> Result<(), Self::Error> {
        let millis = self.millis;
        Pin::new(&mut self.sink)
            .start_send(Wrapper::new(item, millis))
            .map_err(|_| Error::new(ErrorKind::ConnectionAborted, "channel died"))
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        Pin::new(&mut self.sink)
            .poll_flush(cx)
            .map_err(|_| Error::new(ErrorKind::ConnectionAborted, "channel died"))
    }

    fn poll_close(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        Pin::new(&mut self.sink)
            .poll_close(cx)
            .map_err(|_| Error::new(ErrorKind::ConnectionAborted, "channel died"))
    }
}

impl<T> Stream for DuplexChannelLatency<T>
where
    T: Send + Unpin + 'static,
{
    type Item = T;

    fn poll_next(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<Option<Self::Item>> {
        let pending = self.pending.take();

        if let Some(item) = pending {
            if let Poll::Ready(_) = self.sleep.as_mut().poll(cx) {
                // If pending item is ready return immediately
                return Poll::Ready(Some(item));
            } else {
                // Otherwise we reinsert it back into self.pending
                self.pending = Some(item);
            }
        } else {
            // If nothing is pending we pull from the stream
            if let Poll::Ready(item) = Pin::new(&mut self.stream).poll_next(cx) {
                // If the stream yields `None` then the stream is closed
                // and we return immediately
                let Some(item) = item else {
                    return Poll::Ready(None);
                };

                // If item is already ready when we pull it return it immediately
                if Instant::now() >= item.1 {
                    return Poll::Ready(Some(item.0));
                }

                // Otherwise we set the sleep future
                self.sleep.as_mut().reset(item.1);

                // Then we must poll the future before returning so it knows to wake
                // up this task
                if let Poll::Ready(_) = self.sleep.as_mut().poll(cx) {
                    return Poll::Ready(Some(item.0));
                } else {
                    self.pending = Some(item.0);
                }
            }
        }

        Poll::Pending
    }
}

#[cfg(test)]
mod test {
    use async_std::stream::StreamExt;
    use futures::SinkExt;

    use super::*;

    struct Message;

    #[tokio::test]
    async fn test_latency() {
        let latency = 10;
        let count = 10;

        let (mut a, mut b) = DuplexChannelLatency::<Message>::new(latency as u64);

        let mut samples = Vec::with_capacity(count);
        for _ in 0..count {
            let now = Instant::now();
            a.send(Message).await.unwrap();
            b.next().await.unwrap();
            let elapsed = now.elapsed().as_millis();
            samples.push(elapsed);
        }

        let mean = samples.iter().sum::<u128>() as f32 / samples.len() as f32;

        assert!((mean - latency as f32).abs() < 2.5 as f32);
    }
}
