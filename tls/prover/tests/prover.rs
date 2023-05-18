use std::io::{Read, Write};

use futures::{AsyncReadExt, AsyncWriteExt};
use prover::{AsyncSocket, Prover, ProverConfig};
use tls_client::{Backend, RustCryptoBackend};
use tokio::runtime::Handle;
use utils_aio::executor::SpawnCompatExt;

#[tokio::test]
async fn test_prover_run_parse_response_headers() {
    let (mut prover, mut async_socket) = tlsn_new("tlsnotary.org");
    prover.run(Handle::current().compat()).unwrap();

    async_socket
            .write_all(
                    b"GET / HTTP/1.1\r\n\
                    Host: tlsnotary.org\r\n\
                    User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/112.0\r\n\
                    Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8\r\n\
                    Accept-Language: en-US,en;q=0.5\r\n\
                    Accept-Encoding: identity\r\n\r\n"
                ).await.unwrap();

    let response_headers = parse_response_headers(&mut async_socket).await;
    let parsed_headers = String::from_utf8(response_headers).unwrap();

    assert!(parsed_headers.contains("HTTP/1.1 200 OK\r\n"));
}

#[tokio::test]
async fn test_prover_run_parse_response_body() {
    let (mut prover, mut async_socket) = tlsn_new("tlsnotary.org");
    prover.run(Handle::current().compat()).unwrap();

    // First we need to parse the response header again
    async_socket
            .write_all(
                    b"GET / HTTP/1.1\r\n\
                    Host: tlsnotary.org\r\n\
                    User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/112.0\r\n\
                    Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8\r\n\
                    Accept-Language: en-US,en;q=0.5\r\n\
                    Accept-Encoding: identity\r\n\r\n"
                ).await.unwrap();

    let response_headers = parse_response_headers(&mut async_socket).await;
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
        let bytes_read = async_socket.read(&mut response_body).await.unwrap();
        content_length -= bytes_read;
    }

    // Convert parsed bytes to utf8 and also add the header part which did include some body parts
    let parsed_body =
        parsed_headers.split_off(body_start) + &String::from_utf8(response_body).unwrap();

    assert!(parsed_body.contains("<!DOCTYPE html>"));
    assert!(parsed_body.contains("TLSNotary is a public good"));
    assert!(parsed_body.contains("</html>"));
}

#[tokio::test]
async fn smoke_test() {
    let (mut prover, _async_socket) = tlsn_new("tlsnotary.org");
    prover.run(Handle::current().compat()).unwrap();
    loop {}
}

fn tlsn_new(address: &str) -> (Prover, AsyncSocket) {
    let tcp_stream = std::net::TcpStream::connect(&format!("{}:{}", address, "443")).unwrap();

    let (prover, async_socket) = Prover::new(
        ProverConfig::default(),
        address.to_owned(),
        Box::new(RustCryptoBackend::new()) as Box<dyn Backend>,
        (
            Box::new(tcp_stream.try_clone().unwrap()) as Box<dyn Read + Send>,
            Box::new(tcp_stream) as Box<dyn Write + Send>,
        ),
    )
    .unwrap();

    (prover, async_socket)
}

async fn parse_response_headers(async_socket: &mut AsyncSocket) -> Vec<u8> {
    let headers_end_marker = b"\r\n\r\n";
    let mut response_headers = Vec::new();

    loop {
        async_socket.read(&mut response_headers).await.unwrap();

        if let Some(_) = response_headers
            .windows(headers_end_marker.len())
            .position(|window| window == headers_end_marker)
        {
            break;
        }
    }

    response_headers
}
