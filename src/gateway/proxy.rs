use crate::gateway::config::GatewayConfig;
use http_body_util::{combinators::BoxBody, BodyExt, Full, Limited};
use hyper::body::{Bytes, Incoming};
use hyper::{Request, Response};
use std::panic::AssertUnwindSafe;
use std::sync::Arc;

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
/// Owned so the hook can run *after* the forward, which is what makes a slow
/// hook unable to delay a response. The body is deliberately absent — no
/// measurement in this design needs it.
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
/// never the live request — a hook is not on the path to the response, so a
/// slow or blocking hook (a PCCS fetch, say) cannot stall one.
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
/// and never ahead of the forward. `catch_unwind` bounds the panic; running
/// the hook after the response is what bounds the *time* a slow or blocking
/// hook can cost the request.
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
use hyper_util::rt::{TokioExecutor, TokioIo};
use std::sync::OnceLock;
use tokio::net::TcpListener;

/// Cap the request body. A proxy that buffers on an attacker's say-so is a
/// denial-of-service primitive.
pub const MAX_REQUEST_BODY: usize = 8 * 1024 * 1024;

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
async fn run(listener: TcpListener, upstream: hyper::Uri, hooks: Arc<Hooks>) {
    loop {
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
            let io = TokioIo::new(stream);
            let service = service_fn(move |req| handle(req, upstream.clone(), Arc::clone(&hooks)));
            if let Err(err) = http1::Builder::new().serve_connection(io, service).await {
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
    let listener = TcpListener::bind(cfg.listen)
        .await
        .map_err(|source| ProxyError::Bind {
            addr: cfg.listen,
            source,
        })?;
    serve_on(listener, cfg.upstream, hooks).await
}

/// The part of `serve` that runs once a listener already exists. Split out
/// so tests can bind an ephemeral port, read it back with `local_addr()`,
/// and still exercise exactly the code `serve` runs, rather than a
/// test-only stand-in.
async fn serve_on(
    listener: TcpListener,
    upstream: hyper::Uri,
    hooks: Hooks,
) -> Result<(), ProxyError> {
    run(listener, upstream, Arc::new(hooks)).await;
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

    /// Echoes the method, the `x-agent` header (if present) and the body
    /// length back in the response body, so a test can assert on all three
    /// at once without inventing a bespoke protocol per assertion.
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
                        let body_len = req
                            .into_body()
                            .collect()
                            .await
                            .map(|c| c.to_bytes().len())
                            .unwrap_or(0);
                        let reflection = format!("{method} {agent_header} len={body_len}");
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
