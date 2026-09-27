//! A small, bounded HTTP/1.1 server for Encompute's services (control
//! plane, evaluator, key broker, SecAgg coordinator).
//!
//! Every limit is enforced before a request reaches the service:
//!
//! - a fixed pool of connection threads, and a bounded queue of accepted
//!   connections; beyond it a connection gets `503` at once;
//! - the request head (request line and headers) must arrive within
//!   [`Limits::head_timeout`] and fit [`Limits::max_head_bytes`];
//! - the body must declare its length (`Content-Length`; chunked bodies are
//!   refused with `411`), stay within the service's limit for that route
//!   (refused with `413` *before* reading it), and arrive within
//!   [`Limits::body_timeout`] plus its length at [`Limits::min_body_rate`],
//!   with no silence longer than [`Limits::idle_timeout`];
//! - one request per connection (`Connection: close`).
//!
//! A slow or stalled client therefore holds one connection thread for a
//! bounded time, never the whole server; other clients keep being served.

use std::io::{self, Read, Write};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream, ToSocketAddrs};
use std::sync::mpsc::{self, Receiver, SyncSender, TrySendError};
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Server limits. The defaults suit an internal JSON API.
#[derive(Clone, Debug)]
pub struct Limits {
    /// Connection threads (each serves one connection at a time).
    pub threads: usize,
    /// Accepted connections waiting for a thread; beyond this: `503`.
    pub queue: usize,
    /// Request line and headers together.
    pub max_head_bytes: usize,
    pub max_headers: usize,
    /// The whole request head must arrive within this.
    pub head_timeout: Duration,
    /// Longest silence while reading a body.
    pub idle_timeout: Duration,
    /// Time allowed for a body, plus its length at `min_body_rate`.
    pub body_timeout: Duration,
    /// Bytes per second a body is given (on top of `body_timeout`).
    pub min_body_rate: u64,
    /// Writing the response.
    pub write_timeout: Duration,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            threads: 16,
            queue: 64,
            max_head_bytes: 64 << 10,
            max_headers: 64,
            head_timeout: Duration::from_secs(10),
            idle_timeout: Duration::from_secs(10),
            body_timeout: Duration::from_secs(30),
            min_body_rate: 256 << 10,
            write_timeout: Duration::from_secs(30),
        }
    }
}

/// A request, read completely.
#[derive(Clone, Debug)]
pub struct Request {
    pub method: String,
    /// The request target as sent: path and query, e.g. `/v1/audit?after=10`.
    pub url: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
    pub remote: Option<SocketAddr>,
}

impl Request {
    /// The first header named `name` (case-insensitive).
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    /// The path, without the query.
    pub fn path(&self) -> &str {
        self.url.split('?').next().unwrap_or("")
    }
}

/// A response.
#[derive(Clone, Debug)]
pub struct Response {
    pub status: u16,
    pub content_type: String,
    /// Extra headers (names and values must not contain CR or LF).
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl Response {
    pub fn new(status: u16, content_type: &str, body: Vec<u8>) -> Self {
        Self {
            status,
            content_type: content_type.into(),
            headers: vec![],
            body,
        }
    }

    pub fn json(status: u16, v: &serde_json::Value) -> Self {
        Self::new(status, "application/json", v.to_string().into_bytes())
    }

    pub fn with_header(mut self, name: &str, value: &str) -> Self {
        self.headers.push((name.into(), value.into()));
        self
    }
}

/// Why a request was refused before it reached the service.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refused {
    /// The declared body is above the route's limit (`413`).
    TooLarge { limit: usize },
    /// The head or body did not arrive in time (`408`).
    Timeout,
    /// Not a well-formed HTTP/1.x request (`400`).
    Malformed(&'static str),
    /// The request head is above the limit (`431`).
    HeadTooLarge,
    /// A chunked (or otherwise encoded) body: send `Content-Length` (`411`).
    LengthRequired,
    /// Every connection thread is busy and the queue is full (`503`).
    Busy,
}

impl Refused {
    pub fn status(self) -> u16 {
        match self {
            Refused::TooLarge { .. } => 413,
            Refused::Timeout => 408,
            Refused::Malformed(_) => 400,
            Refused::HeadTooLarge => 431,
            Refused::LengthRequired => 411,
            Refused::Busy => 503,
        }
    }

    pub fn message(self) -> String {
        match self {
            Refused::TooLarge { limit } => format!("request body above the {limit}-byte limit"),
            Refused::Timeout => "the request did not arrive in time".into(),
            Refused::Malformed(m) => format!("malformed request: {m}"),
            Refused::HeadTooLarge => "request headers too large".into(),
            Refused::LengthRequired => {
                "request bodies need Content-Length (no chunked transfer)".into()
            }
            Refused::Busy => "the server is busy; retry later".into(),
        }
    }

    /// The default response: `{"code", "message"}` (ENC1102 for a client
    /// error, ENC1701 when the server is busy).
    pub fn response(self) -> Response {
        let code = if self == Refused::Busy {
            "ENC1701"
        } else {
            "ENC1102"
        };
        Response::json(
            self.status(),
            &serde_json::json!({"code": code, "message": self.message()}),
        )
    }
}

/// What a service implements.
pub trait Handler: Sync {
    /// The largest body accepted for this request (its head only: `body`
    /// is empty). Checked against `Content-Length` before reading.
    fn body_limit(&self, head: &Request) -> usize;
    /// Handles a complete request.
    fn handle(&self, req: Request) -> Response;
    /// The response to a request refused before [`Handler::handle`].
    fn refused(&self, why: Refused) -> Response {
        why.response()
    }
}

/// A listening server; [`Server::serve`] runs it.
pub struct Server {
    listener: TcpListener,
    limits: Limits,
}

impl Server {
    /// Listens on `addr` (e.g. `127.0.0.1:0`) with the default limits.
    pub fn http(addr: impl ToSocketAddrs) -> io::Result<Self> {
        Ok(Self {
            listener: TcpListener::bind(addr)?,
            limits: Limits::default(),
        })
    }

    pub fn with_limits(mut self, limits: Limits) -> Self {
        self.limits = limits;
        self
    }

    pub fn limits(&self) -> &Limits {
        &self.limits
    }

    /// The bound address (the port chosen for `:0`).
    pub fn server_addr(&self) -> SocketAddr {
        self.listener
            .local_addr()
            .expect("a bound listener has an address")
    }

    /// Serves `handler` until the process exits.
    pub fn serve<H: Handler>(self, handler: &H) {
        let limits = self.limits.clone();
        let (tx, rx): (SyncSender<TcpStream>, Receiver<TcpStream>) =
            mpsc::sync_channel(limits.queue.max(1));
        let rx = Mutex::new(rx);
        std::thread::scope(|s| {
            for _ in 0..limits.threads.max(1) {
                s.spawn(|| loop {
                    let next = rx.lock().unwrap_or_else(|p| p.into_inner()).recv();
                    match next {
                        Ok(stream) => connection(stream, handler, &limits),
                        Err(_) => return,
                    }
                });
            }
            for stream in self.listener.incoming() {
                match stream {
                    Ok(stream) => match tx.try_send(stream) {
                        Ok(()) => {}
                        Err(TrySendError::Full(stream)) => {
                            let _ = stream.set_write_timeout(Some(Duration::from_secs(1)));
                            finish(stream, &handler.refused(Refused::Busy), &limits);
                        }
                        Err(TrySendError::Disconnected(_)) => return,
                    },
                    // Out of descriptors, or the peer gave up: keep accepting.
                    Err(_) => std::thread::sleep(Duration::from_millis(10)),
                }
            }
        });
    }
}

fn timed_out() -> io::Error {
    io::Error::new(io::ErrorKind::TimedOut, "deadline")
}

/// One read, bounded by `deadline` and `idle`.
fn read_some(
    s: &mut TcpStream,
    buf: &mut [u8],
    deadline: Instant,
    idle: Duration,
) -> io::Result<usize> {
    let now = Instant::now();
    if now >= deadline {
        return Err(timed_out());
    }
    let wait = (deadline - now).min(idle).max(Duration::from_millis(1));
    s.set_read_timeout(Some(wait))?;
    match s.read(buf) {
        Err(e)
            if matches!(
                e.kind(),
                io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
            ) =>
        {
            Err(timed_out())
        }
        r => r,
    }
}

fn find_head_end(b: &[u8]) -> Option<usize> {
    b.windows(4).position(|w| w == b"\r\n\r\n")
}

fn is_token(s: &str) -> bool {
    !s.is_empty()
        && s.bytes()
            .all(|c| c.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&c))
}

/// A parsed request head: (method, target, headers).
type Head = (String, String, Vec<(String, String)>);

/// Parses the head.
fn parse_head(
    head: &[u8],
    max_headers: usize,
) -> Result<Head, Refused> {
    let text = std::str::from_utf8(head).map_err(|_| Refused::Malformed("non-UTF-8 head"))?;
    let mut lines = text.split("\r\n");
    let line = lines.next().unwrap_or("");
    let mut parts = line.split(' ');
    let (Some(method), Some(target), Some(version), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(Refused::Malformed("request line"));
    };
    if !is_token(method) {
        return Err(Refused::Malformed("method"));
    }
    if !target.starts_with('/') || target.bytes().any(|c| c <= b' ' || c == 0x7f) {
        return Err(Refused::Malformed("request target"));
    }
    if version != "HTTP/1.1" && version != "HTTP/1.0" {
        return Err(Refused::Malformed("HTTP version"));
    }
    let mut headers = vec![];
    for l in lines {
        if headers.len() >= max_headers {
            return Err(Refused::HeadTooLarge);
        }
        let (name, value) = l.split_once(':').ok_or(Refused::Malformed("header line"))?;
        if !is_token(name) {
            return Err(Refused::Malformed("header name"));
        }
        let value = value.trim_matches(|c| c == ' ' || c == '\t');
        if value.bytes().any(|c| (c < b' ' && c != b'\t') || c == 0x7f) {
            return Err(Refused::Malformed("header value"));
        }
        headers.push((name.to_owned(), value.to_owned()));
    }
    Ok((method.to_owned(), target.to_owned(), headers))
}

/// The declared body length (0 without one).
fn content_length(headers: &[(String, String)]) -> Result<usize, Refused> {
    if headers
        .iter()
        .any(|(k, _)| k.eq_ignore_ascii_case("Transfer-Encoding"))
    {
        return Err(Refused::LengthRequired);
    }
    let mut len: Option<usize> = None;
    for (_, v) in headers
        .iter()
        .filter(|(k, _)| k.eq_ignore_ascii_case("Content-Length"))
    {
        if v.is_empty() || !v.bytes().all(|c| c.is_ascii_digit()) {
            return Err(Refused::Malformed("Content-Length"));
        }
        // Too many digits for usize: certainly above any limit.
        let n = v.parse::<usize>().unwrap_or(usize::MAX);
        if len.is_some_and(|l| l != n) {
            return Err(Refused::Malformed("conflicting Content-Length"));
        }
        len = Some(n);
    }
    Ok(len.unwrap_or(0))
}

fn reason(status: u16) -> &'static str {
    match status {
        100 => "Continue",
        200 => "OK",
        201 => "Created",
        204 => "No Content",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        408 => "Request Timeout",
        409 => "Conflict",
        410 => "Gone",
        411 => "Length Required",
        413 => "Content Too Large",
        422 => "Unprocessable Content",
        425 => "Too Early",
        429 => "Too Many Requests",
        431 => "Request Header Fields Too Large",
        500 => "Internal Server Error",
        503 => "Service Unavailable",
        _ => "Status",
    }
}

fn clean(s: &str) -> String {
    s.chars().filter(|c| *c != '\r' && *c != '\n').collect()
}

fn write_response(s: &mut TcpStream, r: &Response) -> io::Result<()> {
    let mut head = format!(
        "HTTP/1.1 {} {}\r\nContent-Type: {}\r\nContent-Length: {}\r\nConnection: close\r\n",
        r.status,
        reason(r.status),
        clean(&r.content_type),
        r.body.len()
    );
    for (k, v) in &r.headers {
        head.push_str(&format!("{}: {}\r\n", clean(k), clean(v)));
    }
    head.push_str("\r\n");
    s.write_all(head.as_bytes())?;
    s.write_all(&r.body)?;
    s.flush()
}

/// Writes `r` and closes, reading (and discarding) what the client is
/// still sending (e.g. a refused body) so the response is not lost to a
/// reset. Bounded: 2 s, 250 ms of silence, 16 MiB.
fn finish(mut s: TcpStream, r: &Response, limits: &Limits) {
    let _ = s.set_write_timeout(Some(limits.write_timeout));
    if write_response(&mut s, r).is_err() {
        return;
    }
    let _ = s.shutdown(Shutdown::Write);
    let deadline = Instant::now() + Duration::from_secs(2);
    let mut buf = [0u8; 16 << 10];
    let mut drained = 0usize;
    while drained < (16 << 20) {
        match read_some(&mut s, &mut buf, deadline, Duration::from_millis(250)) {
            Ok(0) | Err(_) => break,
            Ok(n) => drained += n,
        }
    }
}

fn connection<H: Handler>(mut s: TcpStream, handler: &H, limits: &Limits) {
    let remote = s.peer_addr().ok();
    let _ = s.set_nodelay(true);
    match read_request(&mut s, handler, limits, remote) {
        Ok(req) => {
            let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| handler.handle(req)))
                .unwrap_or_else(|_| {
                    Response::json(
                        500,
                        &serde_json::json!({"code": "ENC1701", "message": "internal error"}),
                    )
                });
            finish(s, &r, limits);
        }
        Err(Some(why)) => finish(s, &handler.refused(why), limits),
        // The client went away: nothing to answer.
        Err(None) => {}
    }
}

/// Reads one complete request within the limits. `Err(None)`: the
/// connection closed or failed without a request.
fn read_request<H: Handler>(
    s: &mut TcpStream,
    handler: &H,
    limits: &Limits,
    remote: Option<SocketAddr>,
) -> Result<Request, Option<Refused>> {
    let head_deadline = Instant::now() + limits.head_timeout;
    let mut buf: Vec<u8> = Vec::with_capacity(4096);
    let mut chunk = [0u8; 16 << 10];
    let end = loop {
        if let Some(i) = find_head_end(&buf) {
            break i;
        }
        if buf.len() > limits.max_head_bytes {
            return Err(Some(Refused::HeadTooLarge));
        }
        match read_some(s, &mut chunk, head_deadline, limits.head_timeout) {
            Ok(0) if buf.is_empty() => return Err(None),
            Ok(0) => return Err(Some(Refused::Malformed("incomplete head"))),
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
            Err(e) if e.kind() == io::ErrorKind::TimedOut => return Err(Some(Refused::Timeout)),
            Err(_) => return Err(None),
        }
    };
    if end > limits.max_head_bytes {
        return Err(Some(Refused::HeadTooLarge));
    }
    let (method, url, headers) = parse_head(&buf[..end], limits.max_headers).map_err(Some)?;
    let len = content_length(&headers).map_err(Some)?;
    let mut req = Request {
        method,
        url,
        headers,
        body: vec![],
        remote,
    };
    let limit = handler.body_limit(&req);
    if len > limit {
        return Err(Some(Refused::TooLarge { limit }));
    }
    let mut body: Vec<u8> = buf[end + 4..].to_vec();
    if body.len() > len {
        // Bytes beyond the declared body: a pipelined or smuggled request.
        return Err(Some(Refused::Malformed("bytes beyond the declared body")));
    }
    if body.len() < len
        && req
            .header("Expect")
            .is_some_and(|v| v.eq_ignore_ascii_case("100-continue"))
    {
        let _ = s.set_write_timeout(Some(limits.write_timeout));
        if s.write_all(b"HTTP/1.1 100 Continue\r\n\r\n").is_err() {
            return Err(None);
        }
    }
    let allowance = Duration::from_secs(len as u64 / limits.min_body_rate.max(1));
    let body_deadline = Instant::now() + limits.body_timeout + allowance;
    body.reserve(len.saturating_sub(body.len()).min(1 << 20));
    while body.len() < len {
        let want = (len - body.len()).min(chunk.len());
        match read_some(s, &mut chunk[..want], body_deadline, limits.idle_timeout) {
            Ok(0) => return Err(Some(Refused::Malformed("incomplete body"))),
            Ok(n) => body.extend_from_slice(&chunk[..n]),
            Err(e) if e.kind() == io::ErrorKind::TimedOut => return Err(Some(Refused::Timeout)),
            Err(_) => return Err(None),
        }
    }
    req.body = body;
    Ok(req)
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Echo;

    impl Handler for Echo {
        fn body_limit(&self, _: &Request) -> usize {
            1024
        }
        fn handle(&self, req: Request) -> Response {
            if req.path() == "/panic" {
                panic!("handler panicked");
            }
            Response::new(200, "text/plain", req.body)
        }
    }

    fn start(limits: Limits) -> SocketAddr {
        let s = Server::http("127.0.0.1:0").unwrap().with_limits(limits);
        let a = s.server_addr();
        std::thread::spawn(move || s.serve(&Echo));
        a
    }

    fn raw(addr: SocketAddr, bytes: &[u8]) -> String {
        let mut c = TcpStream::connect(addr).unwrap();
        c.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
        c.write_all(bytes).unwrap();
        let mut out = String::new();
        let _ = c.read_to_string(&mut out);
        out
    }

    #[test]
    fn parses_and_refuses() {
        let a = start(Limits::default());
        let ok = raw(a, b"POST /x HTTP/1.1\r\nContent-Length: 5\r\n\r\nhello");
        assert!(ok.starts_with("HTTP/1.1 200 OK\r\n"), "{ok}");
        assert!(ok.ends_with("\r\n\r\nhello"), "{ok}");
        let status = |b: &[u8]| raw(a, b)[9..12].to_owned();
        assert_eq!(
            status(b"POST /x HTTP/1.1\r\nContent-Length: 2000\r\n\r\n"),
            "413"
        );
        assert_eq!(
            status(b"POST /x HTTP/1.1\r\nContent-Length: 99999999999999999999999\r\n\r\n"),
            "413"
        );
        assert_eq!(
            status(
                b"POST /x HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n"
            ),
            "411"
        );
        assert_eq!(
            status(b"POST /x HTTP/1.1\r\nContent-Length: 1\r\nContent-Length: 2\r\n\r\nab"),
            "400"
        );
        assert_eq!(
            status(b"POST /x HTTP/1.1\r\nContent-Length: 1\r\n\r\nab"),
            "400"
        );
        assert_eq!(status(b"GET x HTTP/1.1\r\n\r\n"), "400");
        assert_eq!(status(b"GET /x HTTP/2.0\r\n\r\n"), "400");
        assert_eq!(status(b"GET /x HTTP/1.1\r\nBad Header\r\n\r\n"), "400");
        assert_eq!(status(b"GET /panic HTTP/1.1\r\n\r\n"), "500");
        let mut big = b"GET /x HTTP/1.1\r\nX: ".to_vec();
        big.extend(vec![b'a'; 70 << 10]);
        big.extend_from_slice(b"\r\n\r\n");
        assert_eq!(status(&big), "431");
    }

    #[test]
    fn slow_clients_time_out_without_blocking_others() {
        let a = start(Limits {
            threads: 4,
            head_timeout: Duration::from_millis(500),
            idle_timeout: Duration::from_millis(500),
            body_timeout: Duration::from_millis(500),
            ..Limits::default()
        });
        let t = Instant::now();
        // A head that never finishes, and a body that never arrives.
        let mut slow_head = TcpStream::connect(a).unwrap();
        slow_head.write_all(b"GET /x HTTP/1.1\r\nX-Slow: ").unwrap();
        let mut slow_body = TcpStream::connect(a).unwrap();
        slow_body
            .write_all(b"POST /x HTTP/1.1\r\nContent-Length: 1000\r\n\r\nabc")
            .unwrap();
        let ok = raw(a, b"GET /x HTTP/1.1\r\n\r\n");
        assert!(ok.starts_with("HTTP/1.1 200"), "{ok}");
        for mut c in [slow_head, slow_body] {
            c.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
            let mut out = String::new();
            let _ = c.read_to_string(&mut out);
            assert!(out.starts_with("HTTP/1.1 408"), "{out}");
        }
        assert!(t.elapsed() < Duration::from_secs(5));
    }

    #[test]
    fn a_full_queue_answers_busy() {
        let a = start(Limits {
            threads: 1,
            queue: 1,
            head_timeout: Duration::from_secs(3),
            ..Limits::default()
        });
        let mut held = vec![];
        for _ in 0..2 {
            let mut c = TcpStream::connect(a).unwrap();
            c.write_all(b"GET /x HTTP/1.1\r\n").unwrap();
            held.push(c);
            std::thread::sleep(Duration::from_millis(100));
        }
        let busy = raw(a, b"GET /x HTTP/1.1\r\n\r\n");
        assert!(busy.starts_with("HTTP/1.1 503"), "{busy}");
        assert!(busy.contains("ENC1701"), "{busy}");
    }
}
