//! Tooling for working with HTTP data.

mod commit;
mod parse;
mod session;
mod types;

pub use commit::{HttpCommitmentError, HttpCommitter};
pub use parse::{parse_body, parse_requests, parse_responses, ParseError};
pub use session::NotarizedHttpSession;
pub use types::{
    Body, Code, Header, HeaderName, HeaderValue, Method, Path, Reason, Request, RequestLine,
    Response, Status,
};

/// An HTTP transcript.
#[derive(Debug)]
pub struct HttpTranscript {
    /// The requests sent to the server.
    pub requests: Vec<Request>,
    /// The responses received from the server.
    pub responses: Vec<Response>,
}

#[cfg(test)]
mod tests {
    use super::*;

    use bytes::Bytes;
    use tlsn_core::{
        commitment::{CommitmentKind, TranscriptCommit, TranscriptCommitmentBuilder},
        fixtures,
        proof::SubstringsProofBuilder,
        Direction, Transcript,
    };

    use crate::json::JsonValue;

    static TX: &[u8] = b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n\
    POST /hello HTTP/1.1\r\nHost: localhost\r\nContent-Length: 44\r\nContent-Type: application/json\r\n\r\n\
    {\"foo\": \"bar\", \"bazz\": 123, \"buzz\": [1,\"5\"]}";
    static RX: &[u8] =
        b"HTTP/1.1 200 OK\r\nCookie: very-secret-cookie\r\nContent-Length: 14\r\nContent-Type: application/json\r\n\r\n\
    {\"foo\": \"bar\"}\r\n\
    HTTP/1.1 200 OK\r\nContent-Length: 14\r\nContent-Type: text/plain\r\n\r\n\
    Hello World!!!";

    #[test]
    fn test_http_commit() {
        let mut builder = TranscriptCommitmentBuilder::new(
            fixtures::encoding_provider(TX, RX),
            TX.len(),
            RX.len(),
        );

        let requests = parse_requests(Bytes::copy_from_slice(TX)).unwrap();
        let responses = parse_responses(Bytes::copy_from_slice(RX)).unwrap();

        let transcript = HttpTranscript {
            requests,
            responses,
        };

        HttpCommitter::default()
            .commit(&mut builder, &transcript)
            .unwrap();

        let commitments = builder.build().unwrap();

        // Path
        assert!(commitments
            .get_id_by_info(CommitmentKind::Blake3, (4..5).into(), Direction::Sent)
            .is_some());

        // Host header
        assert!(commitments
            .get_id_by_info(CommitmentKind::Blake3, (16..33).into(), Direction::Sent)
            .is_some());
        // foo value
        assert!(commitments
            .get_id_by_info(CommitmentKind::Blake3, (137..140).into(), Direction::Sent)
            .is_some());

        // Cookie header
        assert!(commitments
            .get_id_by_info(CommitmentKind::Blake3, (17..45).into(), Direction::Received)
            .is_some());
        // Body
        assert!(commitments
            .get_id_by_info(
                CommitmentKind::Blake3,
                (180..194).into(),
                Direction::Received
            )
            .is_some());
    }

    #[test]
    fn test_http_prove() {
        let transcript_tx = Transcript::new(TX);
        let transcript_rx = Transcript::new(RX);

        let mut builder = TranscriptCommitmentBuilder::new(
            fixtures::encoding_provider(TX, RX),
            TX.len(),
            RX.len(),
        );

        let requests = parse_requests(Bytes::copy_from_slice(TX)).unwrap();
        let responses = parse_responses(Bytes::copy_from_slice(RX)).unwrap();

        let transcript = HttpTranscript {
            requests,
            responses,
        };

        HttpCommitter::default()
            .commit(&mut builder, &transcript)
            .unwrap();

        let commitments = builder.build().unwrap();

        let mut builder = SubstringsProofBuilder::new(&commitments, &transcript_tx, &transcript_rx);

        let req_0 = &transcript.requests[0];
        let req_1 = &transcript.requests[1];
        let Body::Json(JsonValue::Object(req_1_body)) = req_1.body.as_ref().unwrap() else {
            unreachable!();
        };
        let resp_0 = &transcript.responses[0];
        let resp_1 = &transcript.responses[1];

        builder
            .reveal(&req_0.without_data(), CommitmentKind::Blake3)
            .unwrap()
            .reveal(&req_0.request.path, CommitmentKind::Blake3)
            .unwrap()
            .reveal(
                req_0.headers_with_name("host").next().unwrap(),
                CommitmentKind::Blake3,
            )
            .unwrap();

        builder
            .reveal(&req_1.without_data(), CommitmentKind::Blake3)
            .unwrap()
            .reveal(&req_1_body.without_pairs(), CommitmentKind::Blake3)
            .unwrap()
            .reveal(req_1_body.get("bazz").unwrap(), CommitmentKind::Blake3)
            .unwrap();

        builder
            .reveal(&resp_0.without_data(), CommitmentKind::Blake3)
            .unwrap()
            .reveal(
                resp_0.headers_with_name("cookie").next().unwrap(),
                CommitmentKind::Blake3,
            )
            .unwrap();

        builder
            .reveal(&resp_1.without_data(), CommitmentKind::Blake3)
            .unwrap()
            .reveal(resp_1.body.as_ref().unwrap(), CommitmentKind::Blake3)
            .unwrap();

        let proof = builder.build().unwrap();

        let header = fixtures::session_header(commitments.merkle_root(), TX.len(), RX.len());

        let (sent, recv) = proof.verify(&header).unwrap();

        assert_eq!(&sent.data()[4..5], b"/");
        assert_eq!(&sent.data()[22..31], b"localhost");
        assert_eq!(&sent.data()[151..154], b"123");

        assert_eq!(&recv.data()[25..43], b"very-secret-cookie");
        assert_eq!(&recv.data()[180..194], b"Hello World!!!");
    }
}
