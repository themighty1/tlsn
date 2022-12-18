pub mod adaptive_barrier;
#[cfg(feature = "codec")]
pub mod codec;
#[cfg(feature = "duplex")]
pub mod duplex;
#[cfg(feature = "duplex_latency")]
pub mod duplex_latency;
pub mod expect_msg;
#[cfg(feature = "mux")]
pub mod mux;

pub trait Channel<T>: futures::Stream<Item = T> + futures::Sink<T> + Send + Unpin {}
