use futures::{
    channel::mpsc::{Receiver, Sender},
    AsyncRead,
};
use tokio_util::io::{SinkWriter, StreamReader};

pub struct AsyncSocket {
    sink_writer: SinkWriter<Sender<Vec<u8>>>,
    stream_reader: StreamReader<Receiver<Result<&'static [u8], std::io::Error>>, &'static [u8]>,
}

impl AsyncSocket {
    pub fn new(
        request_sender: Sender<Vec<u8>>,
        response_receiver: Receiver<Result<&'static [u8], std::io::Error>>,
    ) -> Self {
        Self {
            sink_writer: SinkWriter::new(request_sender),
            stream_reader: StreamReader::new(response_receiver),
        }
    }
}
