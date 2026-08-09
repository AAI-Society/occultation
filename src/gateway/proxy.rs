use crate::gateway::config::GatewayConfig;
use http_body_util::{combinators::BoxBody, BodyExt, Full, Limited};
use hyper::body::{Bytes, Incoming};
use hyper::{Request, Response};
use std::panic::AssertUnwindSafe;
use std::sync::Arc;
use std::time::Duration;

#[derive(Debug, thiserror::Error)]
pub enum ProxyError {
    #[error("could not bind {addr}: {source}")]
    Bind {
        addr: std::net::SocketAddr,
        #[source]
        source: std::io::Error,
    },
    #[error("upstream {upstream} {reason}")]
    InvalidUpstream {
        upstream: hyper::Uri,
        reason: &'static str,
    },
}

/// What a hook sees: an owned copy of the head, never the live request.
///
/// Owned so the hook can run *after* the forward, which relocates the hook's
/// cost rather than removing it — see [`Hooks`]. The body is deliberately
/// absent: no measurement in this design needs it.
#[derive(Clone, Debug)]
pub struct RequestHead {
    pub method: hyper::Method,
    pub path_and_query: String,
    pub headers: hyper::HeaderMap,
}

impl RequestHead {
    /// Capture what a hook needs before `forward` consumes the request.
    fn snapshot(req: &Request<Incoming>) -> Self {
        RequestHead {
            method: req.method().clone(),
            path_and_query: req
                .uri()
                .path_and_query()
                .map(|pq| pq.as_str().to_string())
                .unwrap_or_else(|| "/".to_string()),
            headers: req.headers().clone(),
        }
    }
}

/// What the proxy calls alongside forwarding. Boxed closures rather than a
/// trait object over the meter, so `proxy.rs` never depends on the verifier
/// or the meter and can be tested with neither.
///
/// The hook runs *after* the forward (see `handle`), on an owned snapshot,
/// never the live request. That ordering **relocates** the cost of a slow
/// hook; it does not eliminate it. hyper does not write the response until
/// the service future resolves, and the hook runs inside that future, so
/// anything slow here still adds to time-to-first-byte and still occupies a
/// worker for as long as it runs. What the reorder buys is that the hook's
/// cost is paid after the upstream has already answered rather than before
/// it is asked — and, because the snapshot is owned, that the hook cannot
/// hold the live request open.
///
/// This is the premise the rest of the design rests on, not a caveat to it.
/// It is why `collateral::refresh` may not be called from a hook, why
/// `refresh.rs` exists to keep the fetch on a background task, and why
/// `RefreshQueue::schedule` is a `try_send` that cannot block.
/// `tests/gateway_failopen.rs`'s hanging-verifier case asserts the
/// consequence directly: the client waits out the hook's 120 ms.
///
/// Hook state must itself tolerate being observed mid-panic: `catch_unwind`
/// in `handle` stops a panic from dropping the connection, but it does not
/// un-poison anything the hook was holding when it panicked. In particular,
/// do not guard hook state with `std::sync::Mutex` — a panic while the lock
/// is held poisons it, and every later request's hook then itself panics on
/// `.lock().unwrap()` (a panic `catch_unwind` also catches, but the finding
/// is lost on every request from then on, not just the one that panicked).
/// Prefer a lock that does not poison, or an atomics-based design.
#[allow(clippy::type_complexity)]
pub struct Hooks {
    pub on_request: Box<dyn Fn(&RequestHead) + Send + Sync>,
}

impl Hooks {
    pub fn noop() -> Self {
        Hooks {
            on_request: Box::new(|_| {}),
        }
    }
}

/// Forward first, measure second, and never let the second affect the first.
///
/// The hook runs after `forward` resolves, on an owned `RequestHead`
/// snapshotted before the request was consumed — never on the live request,
/// and never ahead of the forward.
///
/// `catch_unwind` bounds the panic. Nothing here bounds the *time*: hyper
/// does not write the response until this future resolves, so a slow hook is
/// still time-to-first-byte the client pays, just paid after the upstream
/// has answered instead of before it is asked. Keeping hook work cheap is
/// therefore a live constraint on every caller — see [`Hooks`] and
/// `refresh.rs`, which exists because of it.
async fn handle(
    req: Request<Incoming>,
    upstream: hyper::Uri,
    hooks: Arc<Hooks>,
) -> Result<Response<BoxBody<Bytes, hyper::Error>>, std::convert::Infallible> {
    let head = RequestHead::snapshot(&req);
    let resp = forward(req, upstream).await; // FIRST
    if std::panic::catch_unwind(AssertUnwindSafe(|| (hooks.on_request)(&head))).is_err() {
        log::error!("gateway hook panicked; request already forwarded, no finding recorded");
    }
    resp
}

use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::client::legacy::Client;
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use std::sync::OnceLock;
use tokio::net::TcpListener;
use tokio::sync::Semaphore;

/// Cap the request body. A proxy that buffers on an attacker's say-so is a
/// denial-of-service primitive.
pub const MAX_REQUEST_BODY: usize = 8 * 1024 * 1024;

/// How long a connection may take to finish sending its request headers.
///
/// This is hyper's own default, restated here because hyper's is unreachable
/// without a timer: `http1::Builder` defaults `h1_header_read_timeout` to
/// `Some(30s)`, but the check is performed through an installed
/// `hyper::rt::Timer` and silently degrades to *no timeout at all* when none
/// is installed. hyper emits a `warn!` about that, and hyper's `tracing`
/// feature is not enabled here, so the warning is a no-op too. The result is
/// a header-read timeout that looks configured, is documented upstream as
/// on-by-default, and does nothing.
///
/// What that costs is not theoretical. One socket per connection, one
/// truncated request line, and nothing sent afterwards, holds a file
/// descriptor and a task indefinitely: at the process file-descriptor limit
/// the accept loop then logs `Too many open files` for every subsequent
/// connection and the fronted API is unreachable until the attacker
/// disconnects. No attestation, no valid request, and no upstream traffic is
/// needed. See `a_half_open_connection_is_closed_by_the_header_read_timeout`.
pub const DEFAULT_HEADER_READ_TIMEOUT: Duration = Duration::from_secs(30);

/// The shortest header-read timeout an operator may configure.
///
/// Zero is the value that matters: `header_read_timeout(Duration::ZERO)`
/// closes every connection the instant it arrives, which is the outage this
/// whole setting exists to prevent, arrived at from the other direction. A
/// second is the same shape of floor `refresh::MIN_SALT_ROTATION` is — the
/// smallest value the argument for it actually supports, not a guess about
/// anyone's network.
pub const MIN_HEADER_READ_TIMEOUT: Duration = Duration::from_secs(1);

/// How many connections the proxy serves at once.
///
/// A bound rather than a rate limit: rate limiting is a stated non-goal, and
/// this does not refuse anything. Past the cap the accept loop simply stops
/// accepting, so further connections wait in the kernel's listen backlog and
/// are served as earlier ones finish.
///
/// Its job is to keep the process's descriptor use *bounded and knowable*
/// rather than unbounded. Be honest about what it does not do: each proxied
/// connection costs one descriptor here and one more to the upstream, so a
/// burst that fills this cap wants roughly 2,100 descriptors, and on a host
/// left at the common `ulimit -n 1024` the accept loop still reaches `Too
/// many open files` at about half the cap. That is strictly better than the
/// unbounded case — the ceiling is finite, and it recovers, because
/// [`DEFAULT_HEADER_READ_TIMEOUT`] means held connections drain — but this
/// number alone does not guarantee the error never appears.
///
/// 1024 is a judgement call and not derived. It cannot be derived here: the
/// process's real limit is `RLIMIT_NOFILE`, which this crate cannot read
/// without a `libc` dependency it does not have and would not take under
/// `#![forbid(unsafe_code)]`. An operator who knows their limit should set
/// `--max-connections` to somewhat under half of it; the README says so.
pub const DEFAULT_MAX_CONNECTIONS: usize = 1024;

/// What the accept loop enforces per connection.
///
/// Both fields are bounds on *resources*, never on who may talk to the
/// gateway: nothing here can produce a rejected request. Neither is checked
/// by this struct — [`serve`] takes them from [`GatewayConfig`] and
/// `src/bin/gateway.rs` validates the command line, exactly as
/// `refresh::spawn` validates the rotation interval its own `spawn_with` does
/// not.
#[derive(Clone, Copy, Debug)]
pub struct ConnectionLimits {
    /// Passed to `http1::Builder::header_read_timeout`, with a timer
    /// installed so that it is actually enforced.
    pub header_read_timeout: Duration,
    /// The number of connections served concurrently.
    pub max_connections: usize,
}

impl Default for ConnectionLimits {
    fn default() -> Self {
        ConnectionLimits {
            header_read_timeout: DEFAULT_HEADER_READ_TIMEOUT,
            max_connections: DEFAULT_MAX_CONNECTIONS,
        }
    }
}

/// A header-read timeout of zero closes every connection on arrival.
#[derive(Debug, thiserror::Error)]
#[error(
    "a header-read timeout of {}ms is shorter than the {}ms minimum; the \
     gateway would close connections before a client could finish sending \
     its request headers, which is the outage this timeout exists to prevent",
    .timeout.as_millis(),
    .minimum.as_millis()
)]
pub struct HeaderReadTimeoutTooShort {
    pub timeout: Duration,
    pub minimum: Duration,
}

/// Refuse a header-read timeout short enough to close healthy connections.
///
/// The same shape as [`validate_upstream`] and `refresh::validate_rotation`:
/// a configuration mistake that would take the fronted API down is caught at
/// startup, where an operator reads the error.
pub fn validate_header_read_timeout(timeout: Duration) -> Result<(), HeaderReadTimeoutTooShort> {
    if timeout < MIN_HEADER_READ_TIMEOUT {
        return Err(HeaderReadTimeoutTooShort {
            timeout,
            minimum: MIN_HEADER_READ_TIMEOUT,
        });
    }
    Ok(())
}

/// A single client, shared across every forwarded request. Cheap to clone in
/// spirit (it is just a connection pool handle), so it is built once and
/// reused rather than stood up per request.
fn client() -> &'static Client<HttpConnector, Full<Bytes>> {
    static CLIENT: OnceLock<Client<HttpConnector, Full<Bytes>>> = OnceLock::new();
    CLIENT.get_or_init(|| Client::builder(TokioExecutor::new()).build(HttpConnector::new()))
}

fn bad_gateway(msg: &str) -> Response<BoxBody<Bytes, hyper::Error>> {
    let body = Full::new(Bytes::from(msg.to_string()))
        .map_err(|never| match never {})
        .boxed();
    Response::builder()
        .status(hyper::StatusCode::BAD_GATEWAY)
        .body(body)
        .expect("a response built from a fixed status and an owned body cannot fail")
}

/// RFC 9110 §7.6.1 hop-by-hop headers, stripped in both directions. Copying
/// these wholesale while re-framing the body is the canonical
/// request-smuggling shape: a client-supplied `Transfer-Encoding` surviving
/// alongside the `Content-Length` this proxy's re-framing produces is
/// exactly that shape. Anything named in a `Connection` header is hop-by-hop
/// too, by definition, and is stripped along with it.
fn strip_hop_by_hop_headers(headers: &mut hyper::HeaderMap) {
    use hyper::header::{
        HeaderName, CONNECTION, PROXY_AUTHENTICATE, PROXY_AUTHORIZATION, TE, TRAILER,
        TRANSFER_ENCODING, UPGRADE,
    };

    let mut named = Vec::new();
    for value in headers.get_all(CONNECTION).iter() {
        let Ok(value) = value.to_str() else {
            continue;
        };
        for token in value.split(',') {
            let token = token.trim();
            if token.is_empty() {
                continue;
            }
            if let Ok(name) = HeaderName::from_bytes(token.as_bytes()) {
                named.push(name);
            }
        }
    }
    for name in named {
        headers.remove(name);
    }

    for name in [
        CONNECTION,
        PROXY_AUTHENTICATE,
        PROXY_AUTHORIZATION,
        TE,
        TRAILER,
        TRANSFER_ENCODING,
        UPGRADE,
    ] {
        headers.remove(name);
    }
    headers.remove(HeaderName::from_static("keep-alive"));
}

/// Send the request on to `upstream`, copying method, path, headers and
/// body, and returning the upstream's status, headers and body.
///
/// The response body passes through unbuffered (`.boxed()`, no `collect()`),
/// so a streamed response — SSE, tokens as they are generated — reaches the
/// client as it arrives rather than after the whole stream has ended. The
/// request body is capped at `MAX_REQUEST_BODY`; over-cap becomes a 502,
/// the same as every other failure in this function.
///
/// This cannot return `Err` — the compiler enforces it, not a comment.
async fn forward(
    req: Request<Incoming>,
    upstream: hyper::Uri,
) -> Result<Response<BoxBody<Bytes, hyper::Error>>, std::convert::Infallible> {
    let method = req.method().clone();
    let mut headers = req.headers().clone();
    strip_hop_by_hop_headers(&mut headers);
    // Not hop-by-hop, but the outgoing request is re-addressed to a
    // different authority, so the client's Host would be wrong there;
    // dropping it lets the client set its own from the target URI.
    headers.remove(hyper::header::HOST);
    let path_and_query = req
        .uri()
        .path_and_query()
        .map(|pq| pq.as_str().to_string())
        .unwrap_or_else(|| "/".to_string());

    let mut target_parts = upstream.into_parts();
    target_parts.path_and_query = match path_and_query.parse() {
        Ok(pq) => Some(pq),
        Err(_) => return Ok(bad_gateway("could not build upstream path")),
    };
    let target = match hyper::Uri::from_parts(target_parts) {
        Ok(uri) => uri,
        Err(_) => return Ok(bad_gateway("could not build upstream uri")),
    };

    let body_bytes = match Limited::new(req.into_body(), MAX_REQUEST_BODY)
        .collect()
        .await
    {
        Ok(collected) => collected.to_bytes(),
        Err(_) => return Ok(bad_gateway("request body unreadable or too large")),
    };

    let mut builder = Request::builder().method(method).uri(target);
    if let Some(map) = builder.headers_mut() {
        *map = headers;
    }
    let outgoing = match builder.body(Full::new(body_bytes)) {
        Ok(req) => req,
        Err(_) => return Ok(bad_gateway("could not build upstream request")),
    };

    let response = match client().request(outgoing).await {
        Ok(response) => response,
        Err(_) => return Ok(bad_gateway("upstream unreachable")),
    };
    let status = response.status();
    let mut response_headers = response.headers().clone();
    strip_hop_by_hop_headers(&mut response_headers);

    let mut builder = Response::builder().status(status);
    if let Some(map) = builder.headers_mut() {
        *map = response_headers;
    }
    Ok(builder
        .body(response.into_body().boxed())
        .unwrap_or_else(|_| bad_gateway("could not build response")))
}

/// Accept connections until the process exits. A connection-level error
/// (the peer resetting mid-request, a malformed HTTP/1.1 stream, ...) is
/// logged and only ever affects that one connection; the accept loop itself
/// never stops, because one bad connection must not touch any other.
///
/// # Why the cap cannot become the outage it prevents
///
/// A connection refused at the accept loop and a request that fails to
/// forward are different things, and only the second would break fail-open.
/// Five properties keep the semaphore on the right side of that line, and
/// each is here rather than in a design note because each is one edit away
/// from being false:
///
/// 1. The permit is taken **before** `accept()`, so an over-cap connection is
///    left in the kernel's listen backlog rather than accepted and then
///    closed. Nothing in this function ever refuses, resets or rejects a
///    connection; the worst it does is serve one later.
/// 2. The permit is moved into the connection task and dropped when that task
///    ends — on a clean close, on a connection error, and on an unwind, since
///    a panicking task still drops its locals. There is no path that leaks
///    one, which is what would turn a temporary cap into a permanent one.
/// 3. [`ConnectionLimits::header_read_timeout`] bounds how long a permit can
///    be held by a connection that never sends anything, which is what stops
///    the cap being pinnable by idle sockets. The timeout and the cap are one
///    mechanism: without the timeout the cap is a slower denial of service,
///    and `the_connection_cap_delays_a_new_connection_rather_than_refusing_it`
///    fails if either half is removed.
/// 4. `max_connections` is clamped to at least one. A zero-permit semaphore
///    would park the accept loop forever and serve nobody — the exact outage
///    — and it is reachable from a programmatic caller even though the
///    command line refuses it.
/// 5. `acquire_owned` can only fail on a closed semaphore, which cannot
///    happen (this loop owns the only handle and never closes it). The `Err`
///    arm nonetheless carries on serving *without* a permit rather than
///    returning: if the impossible happens, the failure direction is
///    unlimited connections, never no connections.
///
/// None of this touches the request path. `handle` and `forward` still return
/// `Result<_, Infallible>`, and nothing here introduces a `?` on the way to a
/// response.
async fn run(
    listener: TcpListener,
    upstream: hyper::Uri,
    hooks: Arc<Hooks>,
    limits: ConnectionLimits,
) {
    // Property 4 above. `Semaphore::new(0)` never yields a permit.
    let connections = Arc::new(Semaphore::new(limits.max_connections.max(1)));
    // Property 3's companion: `Duration::ZERO` would close every connection
    // on arrival. The command line refuses anything under
    // `MIN_HEADER_READ_TIMEOUT`; this is the floor a programmatic caller
    // cannot get under, and it is a millisecond rather than a second only so
    // that this module's own tests can pin the behaviour without sleeping.
    let header_read_timeout = limits.header_read_timeout.max(Duration::from_millis(1));
    loop {
        let permit = match Arc::clone(&connections).acquire_owned().await {
            Ok(permit) => Some(permit),
            Err(_) => {
                log::error!(
                    "the gateway's connection semaphore was closed, which should be \
                     unreachable; serving this connection without a concurrency limit \
                     rather than refusing it"
                );
                None
            }
        };
        let (stream, _peer) = match listener.accept().await {
            Ok(pair) => pair,
            Err(err) => {
                log::error!("gateway accept failed: {err}");
                continue;
            }
        };
        let upstream = upstream.clone();
        let hooks = Arc::clone(&hooks);
        tokio::spawn(async move {
            // Held for exactly as long as the connection is, and released by
            // this binding going out of scope on every exit path.
            let _permit = permit;
            let io = TokioIo::new(stream);
            let service = service_fn(move |req| handle(req, upstream.clone(), Arc::clone(&hooks)));
            if let Err(err) = http1::Builder::new()
                // Without a timer hyper's own default header-read timeout is
                // silently inert; see `DEFAULT_HEADER_READ_TIMEOUT`.
                .timer(TokioTimer::new())
                .header_read_timeout(header_read_timeout)
                .serve_connection(io, service)
                .await
            {
                log::error!("gateway connection error: {err}");
            }
        });
    }
}

/// `HttpConnector` is plaintext-only. Without this check, `--upstream
/// https://api.internal` starts cleanly and then answers every single
/// request with a synthesised 502 — fail-open in the narrow sense, and the
/// fronted API completely unreachable in the sense that actually matters.
/// Caught here, at startup, instead of discovered request by request.
fn validate_upstream(upstream: &hyper::Uri) -> Result<(), ProxyError> {
    if upstream.authority().is_none() {
        return Err(ProxyError::InvalidUpstream {
            upstream: upstream.clone(),
            reason: "has no host",
        });
    }
    if upstream.scheme_str() != Some("http") {
        return Err(ProxyError::InvalidUpstream {
            upstream: upstream.clone(),
            reason: "must use the http scheme; HttpConnector cannot speak TLS",
        });
    }
    Ok(())
}

/// Bind `cfg.listen`, after validating `cfg.upstream`, and run the accept
/// loop, passing a shared `Hooks` into every connection.
pub async fn serve(cfg: GatewayConfig, hooks: Hooks) -> Result<(), ProxyError> {
    validate_upstream(&cfg.upstream)?;
    let limits = ConnectionLimits {
        header_read_timeout: cfg.header_read_timeout,
        max_connections: cfg.max_connections,
    };
    let listener = TcpListener::bind(cfg.listen)
        .await
        .map_err(|source| ProxyError::Bind {
            addr: cfg.listen,
            source,
        })?;
    serve_on_with(listener, cfg.upstream, hooks, limits).await
}

/// The part of `serve` that runs once a listener already exists. Split out
/// so tests can bind an ephemeral port, read it back with `local_addr()`,
/// and still exercise exactly the code `serve` runs, rather than a
/// test-only stand-in.
///
/// Public because Task 7's fail-open suite lives in `tests/`, outside the
/// crate, and has to bind an ephemeral port to know where to send requests.
/// It re-runs `validate_upstream` rather than trusting the caller to have
/// done it: `serve`'s check happens before the bind so an operator learns
/// about an `https://` upstream at startup, and that ordering is the only
/// reason the check is not here in the first place — an entry point that
/// skipped it entirely would let a caller stand up a proxy that answers every
/// request with a synthesised 502.
pub async fn serve_on(
    listener: TcpListener,
    upstream: hyper::Uri,
    hooks: Hooks,
) -> Result<(), ProxyError> {
    serve_on_with(listener, upstream, hooks, ConnectionLimits::default()).await
}

/// [`serve_on`] with the per-connection resource bounds supplied rather than
/// defaulted.
///
/// `serve_on` is the entry point every caller outside this crate uses, and it
/// applies [`ConnectionLimits::default`] — so the header-read timeout and the
/// connection cap are on for everybody, and cannot be lost by a caller
/// forgetting to pass them. This variant exists for the two callers that need
/// to choose: [`serve`], which reads an operator's configuration, and this
/// module's own tests, which need a timeout short enough to assert against
/// without sleeping for [`DEFAULT_HEADER_READ_TIMEOUT`].
///
/// It does not validate `limits`, for the same reason `refresh::spawn_with`
/// does not validate its rotation: the checked entry point is the command
/// line. What it does do is clamp, in `run`, the two values that would be an
/// outage rather than a mistake — a zero cap and a zero timeout.
pub async fn serve_on_with(
    listener: TcpListener,
    upstream: hyper::Uri,
    hooks: Hooks,
    limits: ConnectionLimits,
) -> Result<(), ProxyError> {
    validate_upstream(&upstream)?;
    run(listener, upstream, Arc::new(hooks), limits).await;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddr;

    async fn spawn_echo_upstream() -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind echo upstream");
        let addr = listener.local_addr().expect("echo upstream local addr");
        tokio::spawn(async move {
            loop {
                let (stream, _peer) = match listener.accept().await {
                    Ok(pair) => pair,
                    Err(_) => continue,
                };
                tokio::spawn(async move {
                    let io = TokioIo::new(stream);
                    let service = service_fn(|req: Request<Incoming>| async move {
                        let path = req.uri().path().to_string();
                        Ok::<_, std::convert::Infallible>(Response::new(Full::new(Bytes::from(
                            format!("echo:{path}"),
                        ))))
                    });
                    let _ = http1::Builder::new().serve_connection(io, service).await;
                });
            }
        });
        addr
    }

    async fn spawn_status_upstream(status: u16, body: &'static str) -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind status upstream");
        let addr = listener.local_addr().expect("status upstream local addr");
        tokio::spawn(async move {
            loop {
                let (stream, _peer) = match listener.accept().await {
                    Ok(pair) => pair,
                    Err(_) => continue,
                };
                tokio::spawn(async move {
                    let io = TokioIo::new(stream);
                    let service = service_fn(move |_req: Request<Incoming>| async move {
                        let response = Response::builder()
                            .status(status)
                            .body(Full::new(Bytes::from(body)))
                            .expect("a fixed test status and body cannot fail to build");
                        Ok::<_, std::convert::Infallible>(response)
                    });
                    let _ = http1::Builder::new().serve_connection(io, service).await;
                });
            }
        });
        addr
    }

    /// Echoes the method, the `x-agent` header (if present), the body
    /// length, and the *names* of every other header it saw, back in the
    /// response body — so a test can assert on all of "method, a specific
    /// header's value, body length, which header names arrived" at once.
    ///
    /// `Host` and `Content-Length` are excluded from the name list: both are
    /// added unconditionally by any HTTP/1.1 client sending a body, not
    /// something a caller intentionally set, and `content-length` contains
    /// `te` as a substring — left in, it would make a `body.contains("te")`
    /// assertion pass even when the real `TE` header was correctly stripped.
    async fn spawn_reflecting_upstream() -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind reflecting upstream");
        let addr = listener
            .local_addr()
            .expect("reflecting upstream local addr");
        tokio::spawn(async move {
            loop {
                let (stream, _peer) = match listener.accept().await {
                    Ok(pair) => pair,
                    Err(_) => continue,
                };
                tokio::spawn(async move {
                    let io = TokioIo::new(stream);
                    let service = service_fn(|req: Request<Incoming>| async move {
                        let method = req.method().to_string();
                        let agent_header = req
                            .headers()
                            .get("x-agent")
                            .and_then(|v| v.to_str().ok())
                            .map(|v| format!("x-agent={v}"))
                            .unwrap_or_default();
                        let mut names: Vec<&str> = req
                            .headers()
                            .keys()
                            .map(|name| name.as_str())
                            .filter(|name| *name != "host" && *name != "content-length")
                            .collect();
                        names.sort_unstable();
                        names.dedup();
                        let names = names.join(",");
                        let body_len = req
                            .into_body()
                            .collect()
                            .await
                            .map(|c| c.to_bytes().len())
                            .unwrap_or(0);
                        let reflection =
                            format!("{method} names=[{names}] {agent_header} len={body_len}");
                        Ok::<_, std::convert::Infallible>(Response::new(Full::new(Bytes::from(
                            reflection,
                        ))))
                    });
                    let _ = http1::Builder::new().serve_connection(io, service).await;
                });
            }
        });
        addr
    }

    /// Always answers with the one fixed header, so a test can check that a
    /// response header (`Content-Type`, `Set-Cookie`, a CORS header, ...)
    /// survives the round trip.
    async fn spawn_upstream_with_header(name: &'static str, value: &'static str) -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind header upstream");
        let addr = listener.local_addr().expect("header upstream local addr");
        tokio::spawn(async move {
            loop {
                let (stream, _peer) = match listener.accept().await {
                    Ok(pair) => pair,
                    Err(_) => continue,
                };
                tokio::spawn(async move {
                    let io = TokioIo::new(stream);
                    let service = service_fn(move |_req: Request<Incoming>| async move {
                        let response = Response::builder()
                            .header(name, value)
                            .body(Full::new(Bytes::from("ok")))
                            .expect("a fixed test header and body cannot fail to build");
                        Ok::<_, std::convert::Infallible>(response)
                    });
                    let _ = http1::Builder::new().serve_connection(io, service).await;
                });
            }
        });
        addr
    }

    /// Answers with every header in `headers`, so a test can check that a
    /// set of response headers — including hop-by-hop ones that should be
    /// stripped — is handled correctly all at once.
    async fn spawn_upstream_with_headers(headers: &[(&str, &str)]) -> SocketAddr {
        let headers: Vec<(String, String)> = headers
            .iter()
            .map(|(name, value)| (name.to_string(), value.to_string()))
            .collect();
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind headers upstream");
        let addr = listener.local_addr().expect("headers upstream local addr");
        tokio::spawn(async move {
            loop {
                let (stream, _peer) = match listener.accept().await {
                    Ok(pair) => pair,
                    Err(_) => continue,
                };
                let headers = headers.clone();
                tokio::spawn(async move {
                    let io = TokioIo::new(stream);
                    let service = service_fn(move |_req: Request<Incoming>| {
                        let headers = headers.clone();
                        async move {
                            let mut builder = Response::builder();
                            for (name, value) in &headers {
                                builder = builder.header(name.as_str(), value.as_str());
                            }
                            let response = builder
                                .body(Full::new(Bytes::from("ok")))
                                .expect("fixed test headers and body cannot fail to build");
                            Ok::<_, std::convert::Infallible>(response)
                        }
                    });
                    let _ = http1::Builder::new().serve_connection(io, service).await;
                });
            }
        });
        addr
    }

    async fn spawn_gateway(upstream: SocketAddr, hooks: Hooks) -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind gateway");
        let addr = listener.local_addr().expect("gateway local addr");
        let upstream_uri: hyper::Uri = format!("http://{upstream}")
            .parse()
            .expect("a loopback socket address is always a valid uri authority");
        // Exercises the same code `serve` runs post-bind, not a test-only
        // stand-in: `serve` itself only adds `validate_upstream` plus the
        // bind call ahead of this.
        tokio::spawn(serve_on(listener, upstream_uri, hooks));
        addr
    }

    /// [`spawn_gateway`] with the resource bounds chosen. Goes through
    /// `serve_on_with`, which is what `serve_on` and `serve` both bottom out
    /// in — the only thing either adds is where the limits come from.
    async fn spawn_gateway_with_limits(
        upstream: SocketAddr,
        hooks: Hooks,
        limits: ConnectionLimits,
    ) -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind gateway");
        let addr = listener.local_addr().expect("gateway local addr");
        let upstream_uri: hyper::Uri = format!("http://{upstream}")
            .parse()
            .expect("a loopback socket address is always a valid uri authority");
        tokio::spawn(serve_on_with(listener, upstream_uri, hooks, limits));
        addr
    }

    /// Connect, send a request line and one header, and never terminate the
    /// header block — the cheapest denial of service there is against an
    /// HTTP/1.1 server with no header-read timeout. One socket, twenty-five
    /// bytes, nothing afterwards.
    async fn half_open(gw: SocketAddr) -> tokio::net::TcpStream {
        use tokio::io::AsyncWriteExt as _;
        let mut stream = tokio::net::TcpStream::connect(gw)
            .await
            .expect("connect to the gateway");
        stream
            .write_all(b"GET / HTTP/1.1\r\nHost: x\r\n")
            .await
            .expect("write a partial header block");
        stream.flush().await.expect("flush the partial headers");
        stream
    }

    async fn get_full(gw: &SocketAddr, path: &str) -> anyhow::Result<(u16, String)> {
        let uri: hyper::Uri = format!("http://{gw}{path}").parse()?;
        let req = Request::builder()
            .method(hyper::Method::GET)
            .uri(uri)
            .body(Full::new(Bytes::new()))?;
        let response = client().request(req).await?;
        let status = response.status().as_u16();
        let body_bytes = response.into_body().collect().await?.to_bytes();
        let body = String::from_utf8(body_bytes.to_vec())?;
        Ok((status, body))
    }

    async fn get(gw: &SocketAddr, path: &str) -> anyhow::Result<String> {
        get_full(gw, path).await.map(|(_, body)| body)
    }

    async fn post(
        gw: &SocketAddr,
        path: &str,
        headers: &[(&str, &str)],
        body: &[u8],
    ) -> anyhow::Result<String> {
        let uri: hyper::Uri = format!("http://{gw}{path}").parse()?;
        let mut builder = Request::builder().method(hyper::Method::POST).uri(uri);
        for (name, value) in headers {
            builder = builder.header(*name, *value);
        }
        let req = builder.body(Full::new(Bytes::from(body.to_vec())))?;
        let response = client().request(req).await?;
        let body_bytes = response.into_body().collect().await?.to_bytes();
        Ok(String::from_utf8(body_bytes.to_vec())?)
    }

    async fn header_of(gw: &SocketAddr, path: &str, name: &str) -> anyhow::Result<String> {
        let uri: hyper::Uri = format!("http://{gw}{path}").parse()?;
        let req = Request::builder()
            .method(hyper::Method::GET)
            .uri(uri)
            .body(Full::new(Bytes::new()))?;
        let response = client().request(req).await?;
        let value = response
            .headers()
            .get(name)
            .ok_or_else(|| anyhow::anyhow!("missing header {name}"))?
            .to_str()?
            .to_string();
        Ok(value)
    }

    /// The whole design rests on this: a hook that panics must not stop the
    /// request. If this test ever fails, the gateway can take down the API it
    /// fronts, which is the one thing it must never do.
    #[tokio::test]
    async fn a_panicking_hook_still_forwards_the_request() {
        let upstream = spawn_echo_upstream().await;
        let hooks = Hooks {
            on_request: Box::new(|_| panic!("hook exploded")),
        };
        let gw = spawn_gateway(upstream, hooks).await;

        let body = get(&gw, "/hello").await.expect("the request must complete");
        assert_eq!(body, "echo:/hello");
    }

    #[tokio::test]
    async fn a_request_with_no_attestation_is_forwarded_unchanged() {
        let upstream = spawn_echo_upstream().await;
        let gw = spawn_gateway(upstream, Hooks::noop()).await;
        assert_eq!(get(&gw, "/plain").await.unwrap(), "echo:/plain");
    }

    #[tokio::test]
    async fn the_upstreams_status_and_body_are_preserved() {
        let upstream = spawn_status_upstream(503, "upstream sad").await;
        let gw = spawn_gateway(upstream, Hooks::noop()).await;
        let (status, body) = get_full(&gw, "/x").await.unwrap();
        assert_eq!(
            status, 503,
            "the gateway must not rewrite upstream failures"
        );
        assert_eq!(body, "upstream sad");
    }

    #[tokio::test]
    async fn method_headers_and_body_all_reach_the_upstream() {
        // `..._is_forwarded_unchanged` above asserts only the path. This
        // asserts the rest of "unchanged", and kills the mutations that
        // drop the request headers, hard-code GET, or send an empty body.
        let upstream = spawn_reflecting_upstream().await; // echoes method, a header, body len
        let gw = spawn_gateway(upstream, Hooks::noop()).await;
        let body = post(&gw, "/x", &[("x-agent", "acme")], b"hello")
            .await
            .unwrap();
        assert!(body.contains("POST"), "{body}");
        assert!(body.contains("x-agent=acme"), "{body}");
        assert!(body.contains("len=5"), "{body}");
    }

    #[tokio::test]
    async fn upstream_response_headers_reach_the_client() {
        // Deleting the response header copy silently strips Content-Type,
        // Set-Cookie and CORS off every response, and nothing else notices.
        let upstream = spawn_upstream_with_header("content-type", "application/json").await;
        let gw = spawn_gateway(upstream, Hooks::noop()).await;
        assert_eq!(
            header_of(&gw, "/x", "content-type").await.unwrap(),
            "application/json"
        );
    }

    #[tokio::test]
    async fn hop_by_hop_request_headers_do_not_reach_the_upstream() {
        // Without this, a client sending Transfer-Encoding produces an upstream
        // request carrying both Transfer-Encoding and Content-Length — the
        // request-smuggling shape, and the reason this function exists.
        let upstream = spawn_reflecting_upstream().await; // must echo the header names it saw
        let gw = spawn_gateway(upstream, Hooks::noop()).await;
        let seen = post(
            &gw,
            "/x",
            &[
                ("connection", "x-custom"),
                ("te", "trailers"),
                ("x-custom", "drop-me"),
                ("x-keep", "keep-me"),
            ],
            b"hi",
        )
        .await
        .unwrap();
        for gone in ["connection", "te", "x-custom"] {
            assert!(!seen.contains(gone), "{gone} reached the upstream: {seen}");
        }
        assert!(
            seen.contains("x-keep"),
            "an ordinary header was stripped: {seen}"
        );
    }

    #[tokio::test]
    async fn hop_by_hop_response_headers_do_not_reach_the_client() {
        let upstream = spawn_upstream_with_headers(&[
            ("connection", "x-secret"),
            ("x-secret", "leak"),
            ("content-type", "application/json"),
        ])
        .await;
        let gw = spawn_gateway(upstream, Hooks::noop()).await;
        assert!(header_of(&gw, "/x", "connection").await.is_err());
        assert!(
            header_of(&gw, "/x", "x-secret").await.is_err(),
            "a Connection-named header leaked"
        );
        assert_eq!(
            header_of(&gw, "/x", "content-type").await.unwrap(),
            "application/json"
        );
    }

    #[tokio::test]
    async fn serve_rejects_a_non_http_upstream_before_binding() {
        // `validate_upstream` runs before the bind, so this needs no port at
        // all — a real bind would mean `serve` tried to stand up a proxy in
        // front of an upstream it can never successfully speak to.
        let cfg = GatewayConfig {
            listen: "127.0.0.1:0".parse().unwrap(),
            upstream: "https://api.internal".parse().unwrap(),
            salt_rotation: Duration::from_secs(3600),
            pccs_url: "http://example.invalid".to_string(),
            header_read_timeout: DEFAULT_HEADER_READ_TIMEOUT,
            max_connections: DEFAULT_MAX_CONNECTIONS,
        };
        let result = serve(cfg, Hooks::noop()).await;
        assert!(
            matches!(result, Err(ProxyError::InvalidUpstream { .. })),
            "{result:?}"
        );
    }

    /// `serve_on` is a public entry point now, so the upstream check has to
    /// hold there too — otherwise a caller who binds their own listener gets
    /// a proxy that 502s every request and never learns why.
    #[tokio::test]
    async fn serve_on_rejects_a_non_http_upstream_too() {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind for serve_on check");
        let result = serve_on(
            listener,
            "https://api.internal".parse().unwrap(),
            Hooks::noop(),
        )
        .await;
        assert!(
            matches!(result, Err(ProxyError::InvalidUpstream { .. })),
            "{result:?}"
        );
    }

    /// The one that was demonstrated against the built binary, and the
    /// reason `DEFAULT_HEADER_READ_TIMEOUT` exists.
    ///
    /// hyper's two behaviours here are not the same, and which one this test
    /// catches is worth stating precisely, because the first draft of this
    /// comment got it backwards.
    ///
    /// - `Dur::Default(Some(30s))` with no timer installed — that is,
    ///   *neither* `.timer(..)` nor `.header_read_timeout(..)` called, which
    ///   is what `http1::Builder::new()` alone gives you — logs a `warn!` and
    ///   silently enforces nothing. The `warn!` is `tracing`-gated and
    ///   `Cargo.toml` enables only `["server", "client", "http1"]`, so there
    ///   is no output either. **This is the condition that shipped, and the
    ///   condition this test catches:** revert `run` to a bare
    ///   `http1::Builder::new()` and the read below never completes, failing
    ///   on the outer timeout in 5s.
    /// - `Dur::Configured(Some(_))` with no timer *panics*
    ///   (`common/time.rs`: "timeout `header_read_timeout` set, but no timer
    ///   set"). So deleting only the `.timer(..)` line does not reproduce the
    ///   defect at all — it makes every connection task panic, which this
    ///   test is the one connection-level proxy test to *survive* (the
    ///   unwind closes the socket, so the read returns and the assertion
    ///   holds). Ten others fail loudly instead. Measured, not assumed.
    ///
    /// The outer timeout is twenty-five times the configured one, so it
    /// cannot fail for scheduling reasons — the two are not close.
    #[tokio::test]
    async fn a_half_open_connection_is_closed_by_the_header_read_timeout() {
        use tokio::io::AsyncReadExt as _;

        let upstream = spawn_echo_upstream().await;
        let limits = ConnectionLimits {
            header_read_timeout: Duration::from_millis(200),
            ..ConnectionLimits::default()
        };
        let gw = spawn_gateway_with_limits(upstream, Hooks::noop(), limits).await;

        let mut idle = half_open(gw).await;
        // hyper answers a header-read timeout with a 408 and then closes, so
        // this reads whatever it chose to send and then sees EOF. Either a
        // response or an immediate close satisfies "the connection did not
        // survive"; what must not happen is the read hanging.
        let mut seen = Vec::new();
        let closed =
            tokio::time::timeout(Duration::from_secs(5), idle.read_to_end(&mut seen)).await;
        assert!(
            closed.is_ok(),
            "the gateway held a half-open connection past its 200ms \
             header-read timeout. One socket per connection and no further \
             bytes is then enough to exhaust the process's file descriptors, \
             after which the accept loop logs `Too many open files` and the \
             fronted API is unreachable"
        );
    }

    /// The cap holds, and the cap is not an outage.
    ///
    /// Both halves in one test on purpose, because each alone is satisfiable
    /// by the wrong thing: "the second connection was served" passes for a
    /// gateway with no cap at all, and "the second connection was delayed"
    /// passes for a gateway that refused it. What is asserted is that it
    /// waited *and* was served, with the same body an uncapped gateway would
    /// have returned.
    ///
    /// It is also the test that pins the timeout and the cap as one
    /// mechanism, in the sense that both are needed for it to pass — though
    /// not for the reason the first version of this comment gave.
    ///
    /// - Remove the semaphore and the second connection is served
    ///   immediately (measured: 3.7 ms), failing the wait assertion.
    /// - Remove the `.timer(..)` and hyper panics on the configured timeout
    ///   before the idle connection is ever read from. That does **not**
    ///   wedge the permit — the unwind drops it at once, which is property 2
    ///   of `run`'s doc comment working exactly as written — so this fails
    ///   fast rather than hanging, on the queued connection being reset by
    ///   its own panicking task.
    ///
    /// The condition that actually shipped, a bare `http1::Builder::new()`
    /// with no timer and no configured timeout, is caught by
    /// `a_half_open_connection_is_closed_by_the_header_read_timeout`: the
    /// idle connection then really does hold its permit forever and this
    /// test fails on its ten-second outer timeout.
    #[tokio::test]
    async fn the_connection_cap_delays_a_new_connection_rather_than_refusing_it() {
        let upstream = spawn_echo_upstream().await;
        let limits = ConnectionLimits {
            header_read_timeout: Duration::from_millis(800),
            max_connections: 1,
        };
        let gw = spawn_gateway_with_limits(upstream, Hooks::noop(), limits).await;

        // Takes the single permit and holds it until its header-read timeout
        // expires. Kept bound so the socket is not closed early by a drop.
        let _idle = half_open(gw).await;
        // Long enough that the accept loop has certainly taken the idle
        // connection rather than racing the one below for the permit.
        tokio::time::sleep(Duration::from_millis(200)).await;

        let started = std::time::Instant::now();
        let body = tokio::time::timeout(Duration::from_secs(10), get(&gw, "/queued"))
            .await
            .expect("the capped gateway never served the queued connection")
            .expect("a connection over the cap must be served late, never refused");
        let waited = started.elapsed();

        assert_eq!(
            body, "echo:/queued",
            "a connection served from behind the cap must be forwarded like any other"
        );
        assert!(
            waited >= Duration::from_millis(300),
            "the second connection was served in {waited:?}, so the cap of one \
             was not enforced at all"
        );
    }

    /// A cap of zero would park the accept loop on a semaphore that never
    /// yields, which is the outage the cap exists to prevent. The command
    /// line refuses it; this pins the clamp that a programmatic caller
    /// cannot get under.
    #[tokio::test]
    async fn a_zero_connection_cap_still_serves() {
        let upstream = spawn_echo_upstream().await;
        let limits = ConnectionLimits {
            max_connections: 0,
            ..ConnectionLimits::default()
        };
        let gw = spawn_gateway_with_limits(upstream, Hooks::noop(), limits).await;
        let body = tokio::time::timeout(Duration::from_secs(5), get(&gw, "/zero"))
            .await
            .expect("a zero cap parked the accept loop forever")
            .expect("a zero cap must be clamped, not honoured");
        assert_eq!(body, "echo:/zero");
    }

    /// A zero header-read timeout would close every connection on arrival —
    /// the same outage from the other direction. Clamped in `run` for a
    /// programmatic caller, and refused outright at the command line.
    #[tokio::test]
    async fn a_zero_header_read_timeout_still_serves_a_prompt_request() {
        let upstream = spawn_echo_upstream().await;
        let limits = ConnectionLimits {
            header_read_timeout: Duration::ZERO,
            ..ConnectionLimits::default()
        };
        let gw = spawn_gateway_with_limits(upstream, Hooks::noop(), limits).await;
        let body = tokio::time::timeout(Duration::from_secs(5), get(&gw, "/zero-timeout"))
            .await
            .expect("a zero header-read timeout closed a healthy connection")
            .expect("a zero header-read timeout must be clamped, not honoured");
        assert_eq!(body, "echo:/zero-timeout");
    }

    /// The floor, at its boundary and in absolute terms. Written against
    /// literals as well as against the constant, because assertions phrased
    /// only in terms of `MIN_HEADER_READ_TIMEOUT` hold for any value of it
    /// and would let the floor drift anywhere.
    #[test]
    fn a_header_read_timeout_short_enough_to_close_healthy_connections_is_refused() {
        assert!(validate_header_read_timeout(Duration::ZERO).is_err());
        assert!(validate_header_read_timeout(Duration::from_millis(999)).is_err());
        assert!(validate_header_read_timeout(Duration::from_secs(1)).is_ok());
        assert!(validate_header_read_timeout(Duration::from_secs(30)).is_ok());
        assert!(
            validate_header_read_timeout(MIN_HEADER_READ_TIMEOUT - Duration::from_nanos(1))
                .is_err(),
            "one tick under the floor is still under it"
        );

        let err =
            validate_header_read_timeout(Duration::ZERO).expect_err("zero is under the floor");
        let rendered = err.to_string();
        // An operator reads this and has to be able to act on it.
        assert!(rendered.contains("0ms"), "{rendered}");
        assert!(rendered.contains("1000ms minimum"), "{rendered}");
    }

    /// The defaults are the ones that ship, and both are load-bearing: a
    /// `None`/zero timeout is the denial of service this commit closes, and
    /// hyper's own 30s is the value the missing timer made unreachable.
    #[test]
    fn the_shipped_defaults_are_bounded() {
        let limits = ConnectionLimits::default();
        assert_eq!(limits.header_read_timeout, DEFAULT_HEADER_READ_TIMEOUT);
        assert_eq!(limits.max_connections, DEFAULT_MAX_CONNECTIONS);
        assert!(
            validate_header_read_timeout(limits.header_read_timeout).is_ok(),
            "the shipped default is under the floor the command line enforces"
        );
        assert!(limits.max_connections >= 1);
    }

    /// Task 1's Important #2, which came back twice.
    ///
    /// A slow hook *does* delay the response — hyper writes nothing until the
    /// service future resolves — and `refresh.rs`, `collateral.rs` and
    /// `tests/gateway_failopen.rs` have always said so, the last of them by
    /// asserting the client waits out 120 ms of hook work. This module said
    /// the opposite in two doc comments and the README said it in a third,
    /// and each round of review fixed the surface it was looking at while
    /// the others carried on contradicting it.
    ///
    /// A lexical guard, because that is the shape of the recurrence: nobody
    /// has ever got the *behaviour* wrong, only the sentence describing it,
    /// and no behavioural test can fail on a sentence. Scoped to the
    /// non-test half so this test may quote the phrases it forbids.
    #[test]
    fn no_surface_claims_the_hook_is_off_the_response_path() {
        const MARKER: &str = "#[cfg(test)]\nmod tests {";
        let src = include_str!("proxy.rs");
        assert_eq!(src.matches(MARKER).count(), 1, "ambiguous test module");
        let non_test = src.split(MARKER).next().expect("split yields a head");
        assert!(
            non_test.contains("async fn handle") && non_test.contains("pub struct Hooks"),
            "the scanned region does not reach the two doc comments this \
             guard exists to hold"
        );

        let readme = include_str!("../../README.md");
        for (surface, text) in [("proxy.rs", non_test), ("README.md", readme)] {
            for claim in ["cannot stall", "cannot delay", "unable to delay"] {
                assert!(
                    !text.contains(claim),
                    "{surface} says a hook `{claim}` a response. It can: hyper \
                     does not write the response until the service future \
                     resolves, and tests/gateway_failopen.rs asserts the client \
                     waits out the hook's 120ms. This is the third time"
                );
            }
        }
        // The positive half. Without it, deleting both doc comments outright
        // would satisfy every assertion above.
        assert!(
            non_test.contains("does not write the response until"),
            "the doc comments no longer state what the reorder actually buys, \
             so the next reader has nothing to correct the intuition with"
        );
        assert!(
            readme.contains("*after* the forward"),
            "the README no longer distinguishes the forward from the response"
        );
    }

    #[test]
    fn an_upstream_without_a_host_is_rejected() {
        let uri: hyper::Uri = "/just-a-path".parse().unwrap();
        assert!(validate_upstream(&uri).is_err());
    }

    #[test]
    fn a_non_http_upstream_is_rejected() {
        let uri: hyper::Uri = "https://api.internal".parse().unwrap();
        assert!(validate_upstream(&uri).is_err());
    }

    #[test]
    fn a_plain_http_upstream_with_a_host_is_accepted() {
        let uri: hyper::Uri = "http://127.0.0.1:9999".parse().unwrap();
        assert!(validate_upstream(&uri).is_ok());
    }
}
