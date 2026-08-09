//! The scrape endpoint, on a listener of its own.
//!
//! Task 6 registered three counters and Task 7 records to them. Nothing ever
//! read them: the plan specified a scrape endpoint in no task, so for the
//! whole of phase 1 the metrics were write-only and Task 6's
//! label-cardinality argument was unobservable. This module is where they
//! become observable.
//!
//! # Why this is not a route on the proxy
//!
//! `proxy::forward` forwards **every** request unconditionally — that is the
//! fail-open guarantee, and it is enforced at the type level (`handle` and
//! `forward` return `Result<_, Infallible>`). A `/metrics` route on the proxy
//! port would have to be one of two things, and both are wrong:
//!
//! - a branch *ahead* of the forward, which carves `/metrics` out of the
//!   upstream's URL space — the fronted API can no longer serve its own
//!   `/metrics`, and a gateway that silently steals a path from the API it
//!   fronts has broken it;
//! - a branch *after* the forward, which never runs, because the forward
//!   already answered.
//!
//! A separate listener is the only shape that preserves "every request
//! forwards". `the_proxy_port_still_forwards_a_metrics_request` and
//! `the_metrics_listener_answers_on_its_own_port` in `tests/gateway_hostile.rs`
//! assert both halves — either alone is satisfiable by a gateway that got
//! this wrong.
//!
//! # Fail-open
//!
//! This listener must never be able to take down the proxy. It shares no
//! task, no listener and no lock with the request path: it holds an
//! `Arc<Registry>` and reads it. `src/bin/gateway.rs` treats a failure to
//! bind as a **startup** decision — logged loudly and then run without a
//! scrape endpoint — rather than as a reason to refuse to front somebody's
//! API. That is the same direction every other decision in this crate takes:
//! the gateway's job is being up.

use http_body_util::{combinators::BoxBody, BodyExt, Full};
use hyper::body::{Bytes, Incoming};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response};
use hyper_util::rt::TokioIo;
use prometheus_client::registry::Registry;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::TcpListener;

/// The one path this listener answers on. Anything else is a 404 — this is a
/// scrape endpoint, not a second proxy.
pub const METRICS_PATH: &str = "/metrics";

/// Loopback by default. These counters describe a fleet's TCB diversity;
/// Task 6 bounded their label cardinality but that is an argument about
/// storage, not about who may read them. An operator who wants them off-host
/// says so explicitly.
pub const DEFAULT_METRICS_LISTEN: &str = "127.0.0.1:9469";

/// The OpenMetrics text content type `prometheus_client`'s text encoder
/// actually produces — it emits `# EOF`, which the older
/// `text/plain; version=0.0.4` exposition format does not have.
const CONTENT_TYPE: &str = "application/openmetrics-text; version=1.0.0; charset=utf-8";

fn respond(status: hyper::StatusCode, body: String) -> Response<BoxBody<Bytes, hyper::Error>> {
    let content_type = if status == hyper::StatusCode::OK {
        CONTENT_TYPE
    } else {
        "text/plain; charset=utf-8"
    };
    let body = Full::new(Bytes::from(body))
        .map_err(|never| match never {})
        .boxed();
    Response::builder()
        .status(status)
        .header(hyper::header::CONTENT_TYPE, content_type)
        .body(body)
        .expect("a response built from a fixed status, header and owned body cannot fail")
}

/// The whole endpoint, as a pure function of a method, a path and a registry.
///
/// Split out from the async plumbing so it can be exercised without a socket:
/// every decision this module makes is here, and none of it is `async`.
fn answer(
    method: &hyper::Method,
    path: &str,
    registry: &Registry,
) -> Response<BoxBody<Bytes, hyper::Error>> {
    if path != METRICS_PATH {
        return respond(
            hyper::StatusCode::NOT_FOUND,
            format!("this is the gateway's metrics listener; it serves {METRICS_PATH} only\n"),
        );
    }
    if method != hyper::Method::GET && method != hyper::Method::HEAD {
        return respond(
            hyper::StatusCode::METHOD_NOT_ALLOWED,
            format!("{METRICS_PATH} is read-only\n"),
        );
    }
    let mut buf = String::new();
    match prometheus_client::encoding::text::encode(&mut buf, registry) {
        // Cannot fail today — the encoder writes into a `String`, whose
        // `fmt::Write` is infallible. Handled rather than `.expect`ed anyway,
        // because a scrape endpoint that panics is a scrape endpoint that
        // drops the connection, and an operator then cannot tell "the gateway
        // is down" from "the exporter is broken".
        Ok(()) => respond(hyper::StatusCode::OK, buf),
        Err(_) => respond(
            hyper::StatusCode::INTERNAL_SERVER_ERROR,
            "encoding the metrics registry failed\n".to_string(),
        ),
    }
}

async fn handle(
    req: Request<Incoming>,
    registry: Arc<Registry>,
) -> Result<Response<BoxBody<Bytes, hyper::Error>>, std::convert::Infallible> {
    // `Infallible`, deliberately, for the same reason `proxy::handle` is: no
    // `?` and no `Err` can compile on this path.
    Ok(answer(req.method(), req.uri().path(), &registry))
}

/// Bind the scrape listener. Separated from [`serve_on`] so a caller can
/// decide what a bind failure means — `src/bin/gateway.rs` logs it and
/// carries on, and a test can read the ephemeral port back before serving.
pub async fn bind(addr: SocketAddr) -> std::io::Result<TcpListener> {
    TcpListener::bind(addr).await
}

/// Accept scrapes until the process exits.
///
/// One bad connection never affects another, and the accept loop never stops
/// — the same shape as `proxy::run`, for the same reason.
pub async fn serve_on(listener: TcpListener, registry: Arc<Registry>) {
    loop {
        let (stream, _peer) = match listener.accept().await {
            Ok(pair) => pair,
            Err(err) => {
                log::error!("metrics listener accept failed: {err}");
                continue;
            }
        };
        let registry = Arc::clone(&registry);
        tokio::spawn(async move {
            let io = TokioIo::new(stream);
            let service = service_fn(move |req| handle(req, Arc::clone(&registry)));
            if let Err(err) = http1::Builder::new().serve_connection(io, service).await {
                log::debug!("metrics listener connection error: {err}");
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gateway::finding::{Finding, Metrics};
    use crate::gateway::source::SessionBinding;
    use crate::gateway::verify::{Platform, QuoteVerdict, TcbConfig};

    async fn body_of(response: Response<BoxBody<Bytes, hyper::Error>>) -> (u16, String) {
        let status = response.status().as_u16();
        let bytes = response
            .into_body()
            .collect()
            .await
            .expect("an owned body collects")
            .to_bytes();
        (status, String::from_utf8_lossy(&bytes).into_owned())
    }

    /// A registry with one recorded finding in it, so a scrape has something
    /// to show. Without a recorded finding every assertion below would be
    /// satisfied by an endpoint that returned the empty string.
    fn registry_with_one_verified_request() -> Registry {
        let mut registry = Registry::default();
        let metrics = Metrics::new(&mut registry);
        metrics.record(&Finding {
            verdict: QuoteVerdict::Verified {
                platform: Platform::TdxV10,
                tcb_status: "UpToDate".to_string(),
                advisories: vec![],
                config: TcbConfig::for_test(&[("fmspc", "b0c06f000000")]),
            },
            binding: SessionBinding::Bound,
            observation: None,
        });
        registry
    }

    #[tokio::test]
    async fn a_scrape_returns_the_registered_counters() {
        let registry = registry_with_one_verified_request();
        let response = answer(&hyper::Method::GET, METRICS_PATH, &registry);
        // The content type a Prometheus scraper negotiates on. Wrong here and
        // the endpoint answers 200 with a body the scraper discards, which no
        // assertion about the body would notice.
        assert_eq!(
            response
                .headers()
                .get(hyper::header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok()),
            Some(CONTENT_TYPE)
        );
        let (status, body) = body_of(response).await;
        assert_eq!(status, 200);
        // The three counters Task 6 registered, by their exposed names. A
        // scrape that returned 200 and an empty body would satisfy the status
        // assertion alone.
        assert!(
            body.contains("gateway_requests_total{verdict=\"verified\"} 1"),
            "{body}"
        );
        assert!(
            body.contains("gateway_quotes_total{platform=\"tdx_v10\",tcb_status=\"up_to_date\"} 1"),
            "{body}"
        );
        assert!(body.contains("# EOF"), "the OpenMetrics trailer: {body}");
        // ...and Task 6's whole argument, made observable: no TCB value ever
        // reaches a label, so a scrape cannot rebuild the dossier the meter
        // refuses to keep.
        assert!(
            !body.contains("b0c06f000000"),
            "an FMSPC reached the scrape output: {body}"
        );
    }

    /// This is a scrape endpoint, not a second proxy. A listener that
    /// answered every path would be one `--metrics-listen 0.0.0.0:9469` away
    /// from being an open relay onto whatever it happened to serve.
    #[tokio::test]
    async fn every_other_path_is_a_404() {
        let registry = registry_with_one_verified_request();
        for path in ["/", "/healthz", "/metrics/", "/metrics/extra", "/Metrics"] {
            let (status, body) = body_of(answer(&hyper::Method::GET, path, &registry)).await;
            assert_eq!(status, 404, "path {path} was served: {body}");
            assert!(
                !body.contains("gateway_requests_total"),
                "path {path} leaked the metrics: {body}"
            );
        }
    }

    #[tokio::test]
    async fn a_write_method_is_refused_rather_than_served() {
        let registry = registry_with_one_verified_request();
        for method in [
            hyper::Method::POST,
            hyper::Method::PUT,
            hyper::Method::DELETE,
        ] {
            let (status, _) = body_of(answer(&method, METRICS_PATH, &registry)).await;
            assert_eq!(status, 405, "{method} was accepted on {METRICS_PATH}");
        }
        // HEAD is a scrape a monitoring system really does send.
        let (status, _) = body_of(answer(&hyper::Method::HEAD, METRICS_PATH, &registry)).await;
        assert_eq!(status, 200);
    }

    /// The default must be loopback. `0.0.0.0` here would publish a fleet's
    /// TCB-diversity counters to anything that can reach the host, and it is
    /// a one-token edit that no behavioural test would notice.
    #[test]
    fn the_default_listen_address_is_loopback() {
        let addr: SocketAddr = DEFAULT_METRICS_LISTEN
            .parse()
            .expect("the default metrics address parses");
        assert!(
            addr.ip().is_loopback(),
            "{DEFAULT_METRICS_LISTEN} is not a loopback address"
        );
        assert_ne!(addr.port(), 0, "a zero port would be a fresh port per run");
    }

    /// `verify.rs`'s formatter ban, applied here for the same reason
    /// `refresh.rs` adopted it: this module writes a response body an
    /// operator scrapes, and a `{value:?}` on some future field is how
    /// something that should not be exposed gets exposed. There is nothing to
    /// leak today — the registry is the only thing this module reads — so the
    /// guard is free.
    #[test]
    fn nothing_in_the_non_test_module_reaches_a_debug_formatter() {
        let src = include_str!("scrape.rs");
        const MARKER: &str = "#[cfg(test)]\nmod tests {";
        assert_eq!(
            src.matches(MARKER).count(),
            1,
            "ambiguous test module boundary"
        );
        let non_test = src.split(MARKER).next().expect("split yields a head");
        assert!(
            non_test.contains("fn answer") && non_test.contains("pub async fn serve_on"),
            "the scanned region does not reach the implementation, so this \
             guard would pass against a truncated string"
        );
        assert!(
            !non_test.contains("/*"),
            "block comments would let banned code hide from this guard"
        );
        let code: String = non_test
            .lines()
            .filter(|l| !l.trim_start().starts_with("//"))
            .collect::<Vec<_>>()
            .join("\n");
        for banned in ["?}", ":?", "println!", "eprintln!", "dbg!"] {
            assert!(
                !code.contains(banned),
                "`{banned}` appears in the scrape endpoint's non-test code"
            );
        }
    }
}
