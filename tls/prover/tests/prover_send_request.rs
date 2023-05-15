use std::io::Write;

use futures::{SinkExt, StreamExt};
use prover::{Prover, ProverConfig};
use tokio::runtime::Handle;
use utils_aio::executor::SpawnCompatExt;

#[tokio::test]
async fn test_prover_run_parse_respone_headers() {
    let rt = Handle::current();

    let tcp_stream = std::net::TcpStream::connect("tlsnotary.org:443").unwrap();

    let (prover, mut request_channel, mut response_channel) = Prover::<Vec<u8>>::new_with_standard(
        ProverConfig::default(),
        String::from("tlsnotary.org"),
        tcp_stream,
    )
    .unwrap();
    prover.run(rt.compat());

    request_channel
            .send(
                b"GET / HTTP/1.1\r\n\
                Host: tlsnotary.org\r\n\
                User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/112.0\r\n\
                Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8\r\n\
                Accept-Language: en-US,en;q=0.5\r\n\
                Accept-Encoding: identity\r\n\r\n"
                .to_vec()).await.unwrap();

    let mut response_header = Vec::new();
    let headers_end_marker = b"\r\n\r\n";

    loop {
        let next_bytes = response_channel.select_next_some().await;
        response_header.write(&next_bytes).unwrap();

        if let Some(_) = response_header
            .windows(headers_end_marker.len())
            .position(|window| window == headers_end_marker)
        {
            break;
        }
    }

    let parsed_headers = String::from_utf8(response_header).unwrap();
    assert!(parsed_headers.contains("HTTP/1.1 200 OK\r\n"));
}
