use futures::{
    channel::mpsc::{Receiver, Sender},
    SinkExt, StreamExt,
};
use prover::{Prover, ProverConfig};
use std::io::Write;
use tokio::runtime::Handle;
use utils_aio::executor::SpawnCompatExt;

#[tokio::test]
async fn test_prover_run_parse_response_headers() {
    let (mut request_channel, mut response_channel) = tlsn_run(Handle::current(), "tlsnotary.org");

    request_channel
            .send(
                b"GET / HTTP/1.1\r\n\
                Host: tlsnotary.org\r\n\
                User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/112.0\r\n\
                Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8\r\n\
                Accept-Language: en-US,en;q=0.5\r\n\
                Accept-Encoding: identity\r\n\r\n"
                .to_vec()).await.unwrap();

    let response_headers = parse_response_headers(&mut response_channel).await;
    let parsed_headers = String::from_utf8(response_headers).unwrap();

    assert!(parsed_headers.contains("HTTP/1.1 200 OK\r\n"));
}

#[tokio::test]
async fn test_prover_run_parse_response_body() {
    let (mut request_channel, mut response_channel) = tlsn_run(Handle::current(), "tlsnotary.org");

    // First we need to parse the response header again
    request_channel
            .send(
                b"GET / HTTP/1.1\r\n\
                Host: tlsnotary.org\r\n\
                User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/112.0\r\n\
                Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8\r\n\
                Accept-Language: en-US,en;q=0.5\r\n\
                Accept-Encoding: identity\r\n\r\n"
                .to_vec()).await.unwrap();

    let response_headers = parse_response_headers(&mut response_channel).await;
    let mut parsed_headers = String::from_utf8(response_headers).unwrap();

    // Extract content length from response headers
    let content_length_header: &str = "Content-Length: ";
    let content_length_start =
        parsed_headers.find(content_length_header).unwrap() + content_length_header.len();
    let content_length_len = parsed_headers[content_length_start..].find("\r\n").unwrap();

    // Now parse content length to usize
    let mut content_length = parsed_headers
        [content_length_start..content_length_start + content_length_len]
        .parse::<usize>()
        .unwrap();

    // Parse response body until content length is reached
    //
    // We need subtract the body part which is already in the parsed headers from content length to
    // get the remaining body length
    let body_start = parsed_headers.find("\r\n\r\n").unwrap() + 4;
    content_length -= parsed_headers.len() - body_start;
    let mut response_body = Vec::new();

    while content_length > 0 {
        let next_bytes = response_channel.select_next_some().await;
        response_body.write_all(&next_bytes).unwrap();
        content_length -= next_bytes.len();
    }

    // Convert parsed bytes to utf8 and also add the header part which did include some body parts
    let parsed_body =
        parsed_headers.split_off(body_start) + &String::from_utf8(response_body).unwrap();

    assert!(parsed_body.contains("<!DOCTYPE html>"));
    assert!(parsed_body.contains("TLSNotary is a public good"));
    assert!(parsed_body.contains("</html>"));
}

fn tlsn_run(handle: Handle, address: &str) -> (Sender<Vec<u8>>, Receiver<Vec<u8>>) {
    let tcp_stream = std::net::TcpStream::connect(&format!("{}:{}", address, "443")).unwrap();

    let (prover, request_channel, response_channel) = Prover::<Vec<u8>>::new_with_standard(
        ProverConfig::default(),
        address.to_owned(),
        tcp_stream,
    )
    .unwrap();
    prover.run(handle.compat());

    (request_channel, response_channel)
}

async fn parse_response_headers(response_channel: &mut Receiver<Vec<u8>>) -> Vec<u8> {
    let headers_end_marker = b"\r\n\r\n";
    let mut response_headers = Vec::new();

    loop {
        let next_bytes = response_channel.select_next_some().await;
        response_headers.write_all(&next_bytes).unwrap();

        if let Some(_) = response_headers
            .windows(headers_end_marker.len())
            .position(|window| window == headers_end_marker)
        {
            break;
        }
    }

    response_headers
}
