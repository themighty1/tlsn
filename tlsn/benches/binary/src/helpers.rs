#[cfg(feature = "browser-bench")]
/// Wraps a Stream/Sink object into an AsyncRead/Write object.
pub struct WebSocketStreamToAsyncReadWrite<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    //sink: SplitSink<WebSocketStream<S>, Message>,
    //stream: SplitStream<WebSocketStream<S>>,
    inner: Mutex<WebSocketStream<S>>,
}

#[cfg(any(feature = "browser-bench", feature = "wstest"))]
impl<S> WebSocketStreamToAsyncReadWrite<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    pub fn new(inner: WebSocketStream<S>) -> Self {
        Self {
            inner: Mutex::new(inner),
        }
    }
}

#[cfg(any(feature = "browser-bench", feature = "wstest"))]
impl<S> AsyncRead for WebSocketStreamToAsyncReadWrite<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    #[inline]
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context2<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<Result<(), IoError>> {
        Pin::new(self.get_mut().inner.lock().unwrap().get_mut()).poll_read(cx, buf)
    }
}

#[cfg(any(feature = "browser-bench", feature = "wstest"))]
impl<S> AsyncWrite for WebSocketStreamToAsyncReadWrite<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    #[inline]
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context2<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, IoError>> {
        Pin::new(self.get_mut().inner.lock().unwrap().get_mut()).poll_write(cx, buf)
    }

    #[inline]
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context2<'_>) -> Poll<Result<(), IoError>> {
        Pin::new(self.get_mut().inner.lock().unwrap().get_mut()).poll_flush(cx)
    }

    #[inline]
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context2<'_>) -> Poll<Result<(), IoError>> {
        Pin::new(self.get_mut().inner.lock().unwrap().get_mut()).poll_shutdown(cx)
    }
}
