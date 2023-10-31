use spansy::{Span, Spanned};
use tlsn_core::{transcript::TranscriptSubsequence, Direction};
use utils::range::{RangeDifference, RangeSet};

use crate::{json::JsonValue, unknown::UnknownSpan, GenericSubsequence};

/// An HTTP request.
#[derive(Debug)]
pub struct Request {
    pub(crate) span: Span,

    /// Request line.
    pub request: RequestLine,
    /// Request headers.
    pub headers: Vec<Header>,
    /// Request body.
    pub body: Option<Body>,
}

impl Request {
    /// Returns the request headers with the given name (case-insensitive).
    pub fn headers_with_name<'a>(&'a self, name: &'a str) -> impl Iterator<Item = &'a Header> + 'a {
        self.headers
            .iter()
            .filter(|h| h.name.as_str().eq_ignore_ascii_case(name))
    }

    /// Returns the request excluding the path, headers and body.
    pub fn without_data(&self) -> GenericSubsequence {
        let mut ranges: RangeSet<usize> = self.span.range().into();
        ranges = ranges.difference(&self.request.path.ranges());
        for header in &self.headers {
            ranges = ranges.difference(&header.span.range());
        }
        if let Some(body) = &self.body {
            ranges = ranges.difference(&body.ranges());
        }
        GenericSubsequence {
            direction: Direction::Sent,
            ranges,
        }
    }
}

impl TranscriptSubsequence for Request {
    fn direction(&self) -> Direction {
        Direction::Sent
    }

    fn ranges(&self) -> RangeSet<usize> {
        self.span.range().into()
    }
}

/// An HTTP request line.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct RequestLine {
    pub(crate) span: Span<str>,

    /// The request method.
    pub method: Method,
    /// The request path.
    pub path: Path,
}

impl RequestLine {
    /// Returns the request line without the path.
    pub fn without_path(&self) -> GenericSubsequence {
        let mut ranges: RangeSet<usize> = self.span.range().into();
        ranges = ranges.difference(&self.path.0.range());
        GenericSubsequence {
            direction: Direction::Sent,
            ranges,
        }
    }
}

impl TranscriptSubsequence for RequestLine {
    fn direction(&self) -> Direction {
        Direction::Sent
    }

    fn ranges(&self) -> RangeSet<usize> {
        self.span.range().into()
    }
}

/// An HTTP request method.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Method(pub(crate) Span<str>);

impl TranscriptSubsequence for Method {
    fn direction(&self) -> Direction {
        Direction::Sent
    }

    fn ranges(&self) -> RangeSet<usize> {
        self.0.range().into()
    }
}

/// An HTTP request path.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Path(pub(crate) Span<str>);

impl TranscriptSubsequence for Path {
    fn direction(&self) -> Direction {
        Direction::Sent
    }

    fn ranges(&self) -> RangeSet<usize> {
        self.0.range().into()
    }
}

/// An HTTP response.
#[derive(Debug)]
pub struct Response {
    pub(crate) span: Span,

    /// The response status.
    pub status: Status,
    /// Response headers.
    pub headers: Vec<Header>,
    /// Response body.
    pub body: Option<Body>,
}

impl Response {
    /// Returns the response headers with the given name (case-insensitive).
    pub fn headers_with_name<'a>(&'a self, name: &'a str) -> impl Iterator<Item = &'a Header> + 'a {
        self.headers
            .iter()
            .filter(|h| h.name.as_str().eq_ignore_ascii_case(name))
    }

    /// Returns the response excluding the headers and body.
    pub fn without_data(&self) -> GenericSubsequence {
        let mut ranges: RangeSet<usize> = self.span.range().into();
        for header in &self.headers {
            ranges = ranges.difference(&header.span.range());
        }
        if let Some(body) = &self.body {
            ranges = ranges.difference(&body.ranges());
        }
        GenericSubsequence {
            direction: Direction::Received,
            ranges,
        }
    }
}

impl TranscriptSubsequence for Response {
    fn direction(&self) -> Direction {
        Direction::Received
    }

    fn ranges(&self) -> RangeSet<usize> {
        self.span.range().into()
    }
}

/// An HTTP response status.
#[derive(Debug)]
pub struct Status {
    pub(crate) span: Span<str>,

    /// The response code.
    pub code: Code,
    /// The response reason.
    pub reason: Reason,
}

impl TranscriptSubsequence for Status {
    fn direction(&self) -> Direction {
        Direction::Received
    }

    fn ranges(&self) -> RangeSet<usize> {
        self.span.range().into()
    }
}

/// An HTTP response code.
#[derive(Debug)]
pub struct Code(pub(crate) Span<str>);

impl TranscriptSubsequence for Code {
    fn direction(&self) -> Direction {
        Direction::Received
    }

    fn ranges(&self) -> RangeSet<usize> {
        self.0.range().into()
    }
}

/// An HTTP response reason.
#[derive(Debug)]
pub struct Reason(pub(crate) Span<str>);

impl TranscriptSubsequence for Reason {
    fn direction(&self) -> Direction {
        Direction::Received
    }

    fn ranges(&self) -> RangeSet<usize> {
        self.0.range().into()
    }
}

/// An HTTP header.
#[derive(Debug)]
pub struct Header {
    pub(crate) span: Span,
    pub(crate) direction: Direction,

    /// The header name.
    pub name: HeaderName,
    /// The header value.
    pub value: Option<HeaderValue>,
}

impl Header {
    pub(crate) fn from_spansy(value: spansy::http::Header, direction: Direction) -> Self {
        let span = value.span().clone();
        let spansy::http::Header { name, value, .. } = value;

        Self {
            span: span.clone(),
            direction,
            name: HeaderName::from_spansy(name, direction),
            value: if value.span().is_empty() {
                None
            } else {
                Some(HeaderValue::from_spansy(value, direction))
            },
        }
    }

    /// Returns the header without the value.
    pub fn without_value(&self) -> GenericSubsequence {
        let mut ranges: RangeSet<usize> = self.span.range().into();
        if let Some(value) = &self.value {
            ranges = ranges.difference(&value.span.range());
        }
        GenericSubsequence {
            direction: self.direction,
            ranges,
        }
    }
}

impl TranscriptSubsequence for Header {
    fn direction(&self) -> Direction {
        self.direction
    }

    fn ranges(&self) -> RangeSet<usize> {
        self.span.range().into()
    }
}

/// An HTTP header name.
#[derive(Debug)]
pub struct HeaderName {
    pub(crate) span: Span<str>,
    pub(crate) direction: Direction,
}

impl HeaderName {
    pub(crate) fn from_spansy(value: spansy::http::HeaderName, direction: Direction) -> Self {
        Self {
            span: value.span().clone(),
            direction,
        }
    }

    /// Returns the header name as a string.
    pub fn as_str(&self) -> &str {
        self.span.as_str()
    }
}

impl TranscriptSubsequence for HeaderName {
    fn direction(&self) -> Direction {
        self.direction
    }

    fn ranges(&self) -> RangeSet<usize> {
        self.span.range().into()
    }
}

/// Names of HTTP headers.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct HeaderNames {
    pub(crate) ranges: RangeSet<usize>,
    pub(crate) direction: Direction,
}

impl TranscriptSubsequence for HeaderNames {
    fn direction(&self) -> Direction {
        self.direction
    }

    fn ranges(&self) -> RangeSet<usize> {
        self.ranges.clone()
    }
}

/// An HTTP header value.
#[derive(Debug)]
pub struct HeaderValue {
    pub(crate) span: Span,
    pub(crate) direction: Direction,
}

impl HeaderValue {
    pub(crate) fn from_spansy(value: spansy::http::HeaderValue, direction: Direction) -> Self {
        Self {
            span: value.span().clone(),
            direction,
        }
    }
}

impl TranscriptSubsequence for HeaderValue {
    fn direction(&self) -> Direction {
        self.direction
    }

    fn ranges(&self) -> RangeSet<usize> {
        self.span.range().into()
    }
}

/// A body of an HTTP request or response
#[derive(Debug)]
#[non_exhaustive]
pub enum Body {
    /// A JSON body
    Json(JsonValue),
    /// A body with an unsupported content type
    Unknown(UnknownSpan),
}

impl TranscriptSubsequence for Body {
    fn direction(&self) -> Direction {
        match self {
            Body::Json(body) => body.direction(),
            Body::Unknown(body) => body.direction(),
        }
    }

    fn ranges(&self) -> RangeSet<usize> {
        match self {
            Body::Json(body) => body.ranges(),
            Body::Unknown(body) => body.ranges(),
        }
    }
}
