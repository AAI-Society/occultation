use crate::gateway::config::GatewayConfig;
use http_body_util::{BodyExt, Full};
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
}

/// What the proxy calls alongside forwarding. Boxed closures rather than a
/// trait object over the meter, so `proxy.rs` never depends on the verifier
/// or the meter and can be tested with neither.
#[allow(clippy::type_complexity)]
pub struct Hooks {
    pub on_request: Box<dyn Fn(&Request<Incoming>) + Send + Sync>,
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
/// `catch_unwind` is deliberate. A hook is the only place gateway logic runs
/// on the request path, and a panic there must degrade to "no finding for
/// this request" rather than to a dropped connection. The unwind is recorded
/// so the operator learns the hook is broken.
async fn handle(
    req: Request<Incoming>,
    upstream: hyper::Uri,
    hooks: Arc<Hooks>,
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    if std::panic::catch_unwind(AssertUnwindSafe(|| (hooks.on_request)(&req))).is_err() {
        log::error!("gateway hook panicked; request forwarded, no finding recorded");
    }
    forward(req, upstream).await
}

use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::client::legacy::Client;
use hyper_util::rt::{TokioExecutor, TokioIo};
use std::sync::OnceLock;
use tokio::net::TcpListener;

/// A single client, shared across every forwarded request. Cheap to clone in
/// spirit (it is just a connection pool handle), so it is built once and
/// reused rather than stood up per request.
fn client() -> &'static Client<HttpConnector, Full<Bytes>> {
    static CLIENT: OnceLock<Client<HttpConnector, Full<Bytes>>> = OnceLock::new();
    CLIENT.get_or_init(|| Client::builder(TokioExecutor::new()).build(HttpConnector::new()))
}

fn bad_gateway(msg: &str) -> Response<Full<Bytes>> {
    Response::builder()
        .status(hyper::StatusCode::BAD_GATEWAY)
        .body(Full::new(Bytes::from(msg.to_string())))
        .expect("a response built from a fixed status and an owned body cannot fail")
}

/// Send the request on to `upstream`, copying method, path, headers and
/// body, and returning the upstream's status and body verbatim.
///
/// This never returns `Err`. If the upstream cannot be reached, or the
/// exchange with it fails, that is reported to the client as a synthesised
/// 502 rather than by dropping the connection — dropping the connection is
/// exactly what this proxy exists not to do.
async fn forward(
    req: Request<Incoming>,
    upstream: hyper::Uri,
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    let method = req.method().clone();
    let headers = req.headers().clone();
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

    let body_bytes = match req.into_body().collect().await {
        Ok(collected) => collected.to_bytes(),
        Err(_) => return Ok(bad_gateway("could not read request body")),
    };

    let mut builder = Request::builder().method(method).uri(target);
    if let Some(map) = builder.headers_mut() {
        *map = headers;
        map.remove(hyper::header::HOST);
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
    response_headers.remove(hyper::header::TRANSFER_ENCODING);
    let body = match response.into_body().collect().await {
        Ok(collected) => collected.to_bytes(),
        Err(_) => return Ok(bad_gateway("could not read upstream response body")),
    };

    let mut builder = Response::builder().status(status);
    if let Some(map) = builder.headers_mut() {
        *map = response_headers;
    }
    Ok(builder
        .body(Full::new(body))
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

/// Bind `cfg.listen` and run the accept loop, passing a shared `Hooks` into
/// every connection.
pub async fn serve(cfg: GatewayConfig, hooks: Hooks) -> Result<(), ProxyError> {
    let listener = TcpListener::bind(cfg.listen)
        .await
        .map_err(|source| ProxyError::Bind {
            addr: cfg.listen,
            source,
        })?;
    run(listener, cfg.upstream, Arc::new(hooks)).await;
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

    async fn spawn_gateway(upstream: SocketAddr, hooks: Hooks) -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind gateway");
        let addr = listener.local_addr().expect("gateway local addr");
        let upstream_uri: hyper::Uri = format!("http://{upstream}")
            .parse()
            .expect("a loopback socket address is always a valid uri authority");
        tokio::spawn(run(listener, upstream_uri, Arc::new(hooks)));
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
}
