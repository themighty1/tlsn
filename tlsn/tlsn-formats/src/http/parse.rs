use bytes::Bytes;
use spansy::{
    http::{Requests, Responses},
    json::{self},
    Spanned,
};
use tlsn_core::Direction;

use crate::{
    http::{Body, Code, Header, Method, Path, Reason, Request, RequestLine, Response, Status},
    json::JsonValue,
    unknown::UnknownSpan,
};

/// An HTTP transcript parse error
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ParseError {
    /// Failed to parse request
    #[error("failed to parse request at index {index}: {reason}")]
    Request {
        /// The index of the request
        index: usize,
        /// The reason for the error
        reason: String,
    },
    /// Failed to parse response
    #[error("failed to parse response at index {index}: {reason}")]
    Response {
        /// The index of the response
        index: usize,
        /// The reason for the error
        reason: String,
    },
    /// Failed to parse JSON body
    #[error("failed to parse JSON at index {index}: {reason}")]
    Json {
        /// The index of the request or response
        index: usize,
        /// The reason for the error
        reason: String,
    },
}

/// Parses a body of an HTTP request or response
///
/// # Arguments
///
/// * `index` - The index of the request or response
/// * `content_type` - The content type of the body
/// * `body` - The body data
/// * `offset` - The offset of the body from the start of the transcript
///
/// # Panics
///
/// Panics if the range and body length do not match.
pub fn parse_body(
    index: usize,
    direction: Direction,
    content_type: &[u8],
    body: Bytes,
    offset: usize,
) -> Result<Body, ParseError> {
    if content_type.get(..16) == Some(b"application/json".as_slice()) {
        let mut body = json::parse(body).map_err(|e| ParseError::Json {
            index,
            reason: e.to_string(),
        })?;

        body.offset(offset);

        Ok(Body::Json(JsonValue::from_spansy(body, direction)))
    } else {
        let len = body.len();
        Ok(Body::Unknown(UnknownSpan::new(
            body,
            offset..offset + len,
            direction,
        )))
    }
}

/// Parses the requests of an HTTP transcript.
///
/// # Arguments
///
/// * `data` - The HTTP transcript data
pub fn parse_requests(data: Bytes) -> Result<Vec<Request>, ParseError> {
    let mut requests = Vec::new();
    for (index, request) in Requests::new(data.clone()).enumerate() {
        let request = request.map_err(|e| ParseError::Request {
            index,
            reason: e.to_string(),
        })?;

        let body = if let Some(ref body) = request.body {
            let range = body.span().range();
            let body = data.slice(range.clone());

            let body = if let Some(content_type) = request.headers_with_name("content-type").next()
            {
                parse_body(
                    index,
                    Direction::Sent,
                    content_type.value.span().as_bytes(),
                    body,
                    range.start,
                )?
            } else {
                Body::Unknown(UnknownSpan::new(body, range, Direction::Sent))
            };

            Some(body)
        } else {
            None
        };

        let span = request.span().clone();
        let spansy::http::Request {
            request: request_line,
            headers,
            ..
        } = request;

        requests.push(Request {
            span,
            request: RequestLine {
                span: request_line.span().clone(),
                method: Method(request_line.method),
                path: Path(request_line.path),
            },
            headers: headers
                .into_iter()
                .map(|h| Header::from_spansy(h, Direction::Sent))
                .collect(),
            body,
        });
    }

    Ok(requests)
}

/// Parses the responses of an HTTP transcript.
///
/// # Arguments
///
/// * `data` - The HTTP transcript data
pub fn parse_responses(data: Bytes) -> Result<Vec<Response>, ParseError> {
    let mut responses = Vec::new();
    for (index, response) in Responses::new(data.clone()).enumerate() {
        let response = response.map_err(|e| ParseError::Response {
            index,
            reason: e.to_string(),
        })?;

        let body = if let Some(ref body) = response.body {
            let range = body.span().range();
            let body = data.slice(range.clone());

            let body = if let Some(content_type) = response.headers_with_name("content-type").next()
            {
                parse_body(
                    index,
                    Direction::Received,
                    content_type.value.span().as_bytes(),
                    body,
                    range.start,
                )?
            } else {
                Body::Unknown(UnknownSpan::new(body, range, Direction::Received))
            };

            Some(body)
        } else {
            None
        };

        let span = response.span().clone();
        let spansy::http::Response {
            status, headers, ..
        } = response;

        responses.push(Response {
            span,
            status: Status {
                span: status.span().clone(),
                code: Code(status.code),
                reason: Reason(status.reason),
            },
            headers: headers
                .into_iter()
                .map(|h| Header::from_spansy(h, Direction::Received))
                .collect(),
            body,
        });
    }

    Ok(responses)
}

#[cfg(test)]
mod tests {
    use super::*;

    use bytes::Bytes;

    #[test]
    fn test_parse_body_json() {
        let body = b"{\"foo\": \"bar\"}";

        let body = parse_body(
            0,
            Direction::Sent,
            b"application/json",
            Bytes::copy_from_slice(body),
            0,
        )
        .unwrap();

        let Body::Json(body) = body else {
            unreachable!();
        };

        let range = body.range();

        assert_eq!(range.start, 0);
        assert_eq!(range.end, 14);
        assert_eq!(body.as_str(), "{\"foo\": \"bar\"}");

        let foo = body.path("foo").unwrap();
        let range = foo.range();

        assert_eq!(range.start, 9);
        assert_eq!(range.end, 12);
        assert_eq!(foo.as_str(), "bar");
    }

    #[test]
    fn test_parse_body_json_offset() {
        let body = b"    {\"foo\": \"bar\"}";

        let body = parse_body(
            0,
            Direction::Sent,
            b"application/json",
            Bytes::copy_from_slice(&body[4..]),
            4,
        )
        .unwrap();

        let Body::Json(body) = body else {
            unreachable!();
        };

        let range = body.range();

        assert_eq!(range.start, 4);
        assert_eq!(range.end, 18);
        assert_eq!(body.as_str(), "{\"foo\": \"bar\"}");

        let foo = body.path("foo").unwrap();
        let range = foo.range();

        assert_eq!(range.start, 13);
        assert_eq!(range.end, 16);
        assert_eq!(foo.as_str(), "bar");
    }

    #[test]
    fn test_parse_body_unknown() {
        let body = b"foo";

        let body = parse_body(
            0,
            Direction::Sent,
            b"text/plain",
            Bytes::copy_from_slice(body),
            0,
        )
        .unwrap();

        assert!(matches!(body, Body::Unknown(_)));
    }

    #[test]
    fn test_parse_requests() {
        let reqs = b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n\
        POST /hello HTTP/1.1\r\nHost: localhost\r\nContent-Length: 14\r\nContent-Type: application/json\r\n\r\n\
        {\"foo\": \"bar\"}";

        let requests = parse_requests(Bytes::copy_from_slice(reqs)).unwrap();

        assert_eq!(requests.len(), 2);
        assert!(requests[0].body.is_none());
        assert!(requests[1].body.is_some());

        let Body::Json(body) = requests[1].body.as_ref().unwrap() else {
            unreachable!();
        };

        let foo = body.path("foo").unwrap();
        let range = foo.range();

        assert_eq!(range.start, 137);
        assert_eq!(range.end, 140);
    }

    #[test]
    fn test_parse_responses() {
        let resps =
            b"HTTP/1.1 200 OK\r\nContent-Length: 14\r\nContent-Type: application/json\r\n\r\n\
        {\"foo\": \"bar\"}\r\n\
        HTTP/1.1 200 OK\r\nContent-Length: 14\r\nContent-Type: text/plain\r\n\r\n\
        Hello World!!!";

        let responses = parse_responses(Bytes::copy_from_slice(resps)).unwrap();

        assert_eq!(responses.len(), 2);
        assert!(responses[0].body.is_some());
        assert!(responses[1].body.is_some());
        assert!(matches!(responses[0].body.as_ref().unwrap(), Body::Json(_)));
        assert!(matches!(
            responses[1].body.as_ref().unwrap(),
            Body::Unknown(_)
        ));
    }
}
