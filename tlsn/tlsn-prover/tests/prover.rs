use futures::{AsyncReadExt, AsyncWriteExt};
use tlsn_prover::{Prover, ProverConfig,  TLSConnection, Initialized, ProverError};
use tls_client::{Backend, RustCryptoBackend};
use tokio::runtime::Handle;
use tokio_util::compat::{TokioAsyncReadCompatExt, Compat};

const TLSN_TEST_REQUEST: &[u8] = 
                    b"GET / HTTP/1.1\r\n\
                    Host: tlsnotary.org\r\n\
                    User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/112.0\r\n\
                    Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8\r\n\
                    Accept-Language: en-US,en;q=0.5\r\n\
                    Accept-Encoding: identity\r\n\r\n";

#[tokio::test]
async fn test_prover_parse_headers() {
    _ = Handle::current().enter();

    let (prover, mut tls_connection) = tlsn_new("tlsnotary.org").await;
    _ = tokio::spawn(prover.run());

    tls_connection
            .write_all(TLSN_TEST_REQUEST).await.unwrap();

    let (response_headers, _) = tokio::spawn(parse_response_headers(tls_connection))
        .await
        .unwrap();

    let parsed_headers = String::from_utf8(response_headers).unwrap();

    assert!(parsed_headers.contains("HTTP/1.1 200 OK\r\n"));
}

#[tokio::test]
async fn test_prover_parse_body() {
    _ = Handle::current().enter();

    let (prover, mut tls_connection) = tlsn_new("tlsnotary.org").await;
    _ = tokio::spawn(prover.run());

    tls_connection
            .write_all(TLSN_TEST_REQUEST).await.unwrap();


    let (response_headers, tls_connection) = tokio::spawn(parse_response_headers(tls_connection))
        .await
        .unwrap();
    let (_, response_body, _) = tokio::spawn(parse_response_body_and_adapt_headers(tls_connection, response_headers)).await.unwrap();

    let parsed_body = String::from_utf8(response_body).unwrap();
   

    assert!(parsed_body.contains("<!DOCTYPE html>"));
    assert!(parsed_body.contains("TLSNotary is a public good"));
    assert!(parsed_body.contains("</html>"));
}

#[tokio::test]
async fn test_prover_close_notify() {
    _ = Handle::current().enter();

    let (prover, mut tls_connection) = tlsn_new("tlsnotary.org").await;
    let join_handle = tokio::spawn(prover.run());

    tls_connection
            .write_all(TLSN_TEST_REQUEST).await.unwrap();

    tls_connection.close_tls().await.unwrap();
    let close_notify = join_handle.await.unwrap().unwrap_err();

    // This should fail, since we closed the tls connection
    let expected_error = tls_connection
            .write_all(TLSN_TEST_REQUEST).await;


    assert!(matches!(close_notify, ProverError::ServerNoCloseNotify));
    assert!(matches!(expected_error, Err(std::io::Error { .. })));
}

#[tokio::test]
async fn test_prover_transcript() {
    _ = Handle::current().enter();

    let (prover, mut tls_connection) = tlsn_new("tlsnotary.org").await;
    let join_handle = tokio::spawn(async {
        let res = prover.run().await; println!("run err: {:?}", &res.is_err()); res});

    tls_connection
            .write_all(TLSN_TEST_REQUEST).await.unwrap();


    let (response_headers, tls_connection) = tokio::spawn(parse_response_headers(tls_connection))
        .await
        .unwrap();
    let (response_headers, mut response_body, mut tls_connection) =
        tokio::spawn(parse_response_body_and_adapt_headers(tls_connection,
                                                           response_headers)).await.unwrap();

    tls_connection.close_tls().await.unwrap();
    let prover = join_handle.await.unwrap().unwrap();

    let parsed_headers = String::from_utf8(response_headers).unwrap();
    let parsed_body = String::from_utf8(response_body).unwrap();

    let expected_transcript_sent = prover.sent_transcript().data();
    let expected_transcript_received = prover.recv_transcript().data(); 

    assert_eq!(expected_transcript_sent, TLSN_TEST_REQUEST);
    assert_eq!(expected_transcript_received, (parsed_headers + parsed_body.as_str()).as_bytes());
}

async fn tlsn_new(address: &str) -> (Prover<Initialized<Compat<tokio::net::TcpStream>>>, TLSConnection) {
    let tcp_stream = tokio::net::TcpStream::connect(format!("{}:{}", address, "443")).await.unwrap();

    let (prover, tls_connection) = Prover::new(
        ProverConfig::default(),
        address.to_owned(),
        Box::new(RustCryptoBackend::new()) as Box<dyn Backend + Send>,
        tcp_stream.compat(),
    )
    .unwrap();

    (prover, tls_connection)
}

async fn parse_response_headers(mut tls_connection: TLSConnection) -> (Vec<u8>, TLSConnection) {
    let headers_end_marker = b"\r\n\r\n";
    let mut response_headers = vec![0; 1024];
    let mut read_bytes = 0;

    loop {
        read_bytes += tls_connection
            .read(&mut response_headers[read_bytes..])
            .await
            .unwrap();

        if read_bytes >= response_headers.len() {
            response_headers.resize(response_headers.len() * 2, 0);
        }

        if response_headers
            .windows(headers_end_marker.len())
            .any(|window| window == headers_end_marker)
        {
            break;
        }
    }
    response_headers.resize(read_bytes, 0);

    (response_headers, tls_connection)
}

async fn parse_response_body_and_adapt_headers(mut tls_connection: TLSConnection, mut parsed_headers: Vec<u8>) -> (Vec<u8>, Vec<u8>, TLSConnection) {
    // Extract content length from response headers
    let content_length_header: &[u8] = b"Content-Length: ";
    let content_length_start = parsed_headers
        .windows(content_length_header.len())
        .position(|window| window == content_length_header).unwrap() + content_length_header.len();
    let content_length_len = parsed_headers[content_length_start..].windows(2).position(|window| window == b"\r\n").unwrap();

    // Now parse content length to usize
    let mut content_length = std::str::from_utf8(&parsed_headers
        [content_length_start..content_length_start + content_length_len])
        .unwrap()
        .parse::<usize>()
        .unwrap();

    // Parse response body until content length is reached
    //
    // We need subtract the body part which is already in the parsed headers from content length to
    // get the remaining body length
    let body_start = parsed_headers.windows(4).position(|window| window == b"\r\n\r\n").unwrap() + 4;
    content_length -= parsed_headers.len() - body_start;

    let mut response_body: Vec<u8> = vec![0; content_length];
    tls_connection.read_exact(&mut response_body).await.unwrap();

    // Convert parsed bytes to utf8 and also add the header part which did include some body parts
    let mut parsed_body = parsed_headers.split_off(body_start);
    parsed_body.extend_from_slice(&response_body);


    (parsed_headers, parsed_body, tls_connection)
}
