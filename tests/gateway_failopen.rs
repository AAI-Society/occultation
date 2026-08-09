//! Fail-open under fault injection: the gateway's one hard guarantee.
//!
//! This proxy sits in front of somebody else's revenue API. Every internal
//! error, every verification failure, every meter or rendering fault and
//! every panic must still forward the request, and the finding must record
//! what was skipped. Task 1 built the outer guarantee at the type level
//! (`forward` and `handle` return `Result<_, Infallible>`, so no `?` and no
//! `Err` can compile on the request path) and wrapped the hook in
//! `catch_unwind`. Task 7 wires six modules behind that hook, and this file
//! is where the whole assembly is attacked.
//!
//! # Two ways a fault-injection suite can prove nothing
//!
//! **The fault never fires.** A stub source that returns `None` means the
//! verifier is never called, so `Fault::VerifierPanics` against a request
//! with no attestation header exercises nothing at all and passes. Every
//! fault here therefore increments a shared counter at the moment it fires,
//! and every test asserts the counter moved. The non-faulty stages are
//! permissive on purpose — `AlwaysQuoteSource` and `AlwaysVerified` exist so
//! the request reaches the stage under test.
//!
//! **The assertion is satisfied by something other than the guard.** Task 1's
//! `catch_unwind` alone makes every request in `every_stage_fails_open`
//! succeed, so "the body came back" says nothing about whether the finding
//! survived. `each_fault_still_records_a_finding_naming_what_it_skipped` is
//! the test that holds the per-stage guards in place, and it is separate for
//! that reason.

use base64::{engine::general_purpose::STANDARD, Engine};
use http_body_util::{BodyExt, Full};
use hyper::body::{Bytes, Incoming};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response};
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::client::legacy::Client;
use hyper_util::rt::{TokioExecutor, TokioIo};
use occultation::gateway::collateral::CollateralCache;
use occultation::gateway::finding::Metrics;
use occultation::gateway::meter::{LinkabilityMeter, Observation};
use occultation::gateway::pipeline::{
    FindingSink, Measure, Measured, Pipeline, RecordMetrics, VerifyQuote, STAGE_METER,
    STAGE_METRICS, STAGE_SOURCE, STAGE_VERIFIER,
};
use occultation::gateway::proxy::{serve_on, Hooks, RequestHead};
use occultation::gateway::refresh::{self, RefreshQueue};
use occultation::gateway::source::{
    AttestationSource, HeaderSource, RawAttestation, SessionBinding, SourceError,
};
use occultation::gateway::verify::{Platform, QuoteVerdict, QuoteVerifier, TcbConfig};
use prometheus_client::registry::Registry;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

/// The vendored TDX quote (Phala Network, MIT — `tests/fixtures/PROVENANCE.txt`).
///
/// A real quote rather than a junk buffer, and the difference matters: a
/// hand-built buffer fails `Quote::parse` before any code that could reach a
/// provisioning service runs, so a timing test built on one would pass with
/// the collateral fetch wired straight into the request path.
const REAL_TDX_QUOTE: &[u8] = include_bytes!("fixtures/tdx-quote.bin");

/// The attestation header name the pipeline is configured with here.
const ATTESTATION_HEADER: &str = "x-attestation";

// ---------------------------------------------------------------------
// Faults
// ---------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Fault {
    SourcePanics,
    SourceErrors,
    VerifierPanics,
    VerifierHangsThenErrors,
    MeterPanics,
    MeterLockPoisoned,
    SinkPanics,
    MetricsPanic,
}

/// How long `Fault::VerifierHangsThenErrors` occupies the worker for.
///
/// Long enough that a response written before the hook ran would be
/// distinguishable from one written after it, short enough that the suite
/// still finishes. The hook runs *after* the forward, so this is time added
/// to time-to-first-byte, which is precisely the cost `refresh.rs` exists to
/// keep a network round trip from adding.
const HANG: Duration = Duration::from_millis(120);

struct PanickingSource(Arc<AtomicUsize>);

impl AttestationSource for PanickingSource {
    fn extract(&self, _head: &RequestHead) -> Result<Option<RawAttestation>, SourceError> {
        self.0.fetch_add(1, Ordering::SeqCst);
        panic!("injected fault: the attestation source panicked");
    }
    fn session_binding(&self) -> SessionBinding {
        SessionBinding::Unbound { why: "injected" }
    }
    fn name(&self) -> &'static str {
        "panicking"
    }
}

struct ErroringSource(Arc<AtomicUsize>);

impl AttestationSource for ErroringSource {
    fn extract(&self, _head: &RequestHead) -> Result<Option<RawAttestation>, SourceError> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Err(SourceError::NotUtf8)
    }
    fn session_binding(&self) -> SessionBinding {
        SessionBinding::Unbound { why: "injected" }
    }
    fn name(&self) -> &'static str {
        "erroring"
    }
}

/// Hands the pipeline a quote whatever the request looked like, so a fault
/// planted downstream is actually reached. Without this, a request carrying
/// no attestation header stops at the source and every later fault is
/// untested.
struct AlwaysQuoteSource;

impl AttestationSource for AlwaysQuoteSource {
    fn extract(&self, _head: &RequestHead) -> Result<Option<RawAttestation>, SourceError> {
        Ok(Some(RawAttestation {
            bytes: vec![0xab; 16],
        }))
    }
    fn session_binding(&self) -> SessionBinding {
        SessionBinding::Unbound {
            why: "a stub transport binds nothing",
        }
    }
    fn name(&self) -> &'static str {
        "always-quote"
    }
}

struct PanickingVerifier(Arc<AtomicUsize>);

impl VerifyQuote for PanickingVerifier {
    fn verify(&self, _raw: &RawAttestation) -> QuoteVerdict {
        self.0.fetch_add(1, Ordering::SeqCst);
        panic!("injected fault: the quote verifier panicked");
    }
}

/// Blocks the worker, then fails. Models a verifier that has picked up
/// something synchronous and slow — the shape a collateral fetch would have
/// if it were ever wired inline.
struct HangingVerifier(Arc<AtomicUsize>);

impl VerifyQuote for HangingVerifier {
    fn verify(&self, _raw: &RawAttestation) -> QuoteVerdict {
        self.0.fetch_add(1, Ordering::SeqCst);
        std::thread::sleep(HANG);
        QuoteVerdict::Unverified {
            why: "injected fault: the verifier gave up after hanging".to_string(),
        }
    }
}

/// A verdict good enough to reach the meter with.
struct AlwaysVerified;

impl VerifyQuote for AlwaysVerified {
    fn verify(&self, _raw: &RawAttestation) -> QuoteVerdict {
        QuoteVerdict::Verified {
            platform: Platform::TdxV10,
            tcb_status: "UpToDate".to_string(),
            advisories: vec![],
            config: TcbConfig {
                attributes: [("fmspc".to_string(), "b0c06f000000".to_string())]
                    .into_iter()
                    .collect(),
            },
        }
    }
}

struct PanickingMeter(Arc<AtomicUsize>);

impl Measure for PanickingMeter {
    fn observe(&self, _config: &TcbConfig) -> Observation {
        self.0.fetch_add(1, Ordering::SeqCst);
        panic!("injected fault: the linkability meter panicked");
    }
}

/// Panics on its first call **while holding a write lock**, leaving that lock
/// poisoned for every later request, then delegates to a real
/// [`LinkabilityMeter`].
///
/// The distinction from [`PanickingMeter`] is the state left behind. A bare
/// panic costs one request its measurement; a panic under a lock is how one
/// bad request becomes a permanently broken gateway, because the obvious
/// `.lock().expect(...)` on the recovery path panics again on every request
/// from then on and the finding is lost forever rather than once. This type
/// recovers the poisoned guard the way `meter.rs`'s and `collateral.rs`'s
/// `recover` do, so `a_poisoned_meter_lock_does_not_wedge_every_later_request`
/// can assert the thing that actually matters: requests two through five get
/// *real measurements*, not merely a response body.
struct PoisoningMeter {
    hits: Arc<AtomicUsize>,
    gate: RwLock<u64>,
    inner: LinkabilityMeter,
}

impl PoisoningMeter {
    fn new(hits: Arc<AtomicUsize>) -> PoisoningMeter {
        PoisoningMeter {
            hits,
            gate: RwLock::new(0),
            inner: LinkabilityMeter::new(Duration::from_secs(3600), 7),
        }
    }
}

impl Measure for PoisoningMeter {
    fn observe(&self, config: &TcbConfig) -> Observation {
        self.hits.fetch_add(1, Ordering::SeqCst);
        let mut calls = match self.gate.write() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        *calls += 1;
        let first = *calls == 1;
        if first {
            // Unwinds with the guard still held, which is what poisons it.
            panic!("injected fault: the meter panicked while holding its write lock");
        }
        drop(calls);
        self.inner.observe(config)
    }
}

struct PanickingMetrics(Arc<AtomicUsize>);

impl RecordMetrics for PanickingMetrics {
    fn record(&self, _finding: &occultation::gateway::finding::Finding) {
        self.0.fetch_add(1, Ordering::SeqCst);
        panic!("injected fault: the metrics recorder panicked");
    }
}

/// What the sink saw. `Finding` derives neither `Debug` nor `Clone` by
/// design, so the pieces a test needs are copied out at emit time.
#[derive(Clone, Debug)]
struct Recorded {
    rendered: String,
    skipped: Vec<&'static str>,
    has_observation: bool,
}

struct RecordingSink {
    seen: Mutex<Vec<Recorded>>,
    panic_after_recording: bool,
    hits: Arc<AtomicUsize>,
}

impl RecordingSink {
    fn new(panic_after_recording: bool, hits: Arc<AtomicUsize>) -> Arc<RecordingSink> {
        Arc::new(RecordingSink {
            seen: Mutex::new(Vec::new()),
            panic_after_recording,
            hits,
        })
    }

    fn entries(&self) -> Vec<Recorded> {
        match self.seen.lock() {
            Ok(seen) => seen.clone(),
            Err(poisoned) => poisoned.into_inner().clone(),
        }
    }
}

impl FindingSink for RecordingSink {
    fn emit(&self, measured: &Measured) {
        // Recorded *before* the injected panic, so "the sink came apart" and
        // "the sink was never called" stay distinguishable.
        let entry = Recorded {
            rendered: measured.render(),
            skipped: measured.skipped.clone(),
            has_observation: measured.finding.observation.is_some(),
        };
        match self.seen.lock() {
            Ok(mut seen) => seen.push(entry),
            Err(poisoned) => poisoned.into_inner().push(entry),
        }
        if self.panic_after_recording {
            self.hits.fetch_add(1, Ordering::SeqCst);
            panic!("injected fault: the finding sink panicked");
        }
    }
}

// ---------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------

/// A running gateway, plus the two things a test needs to know about what
/// happened behind it.
struct Gw {
    addr: SocketAddr,
    sink: Arc<RecordingSink>,
    /// Incremented by the injected fault, and by nothing else. A test that
    /// does not check this cannot tell a survived fault from an unreached one.
    hits: Arc<AtomicUsize>,
}

impl Gw {
    fn fault_fired(&self) -> usize {
        self.hits.load(Ordering::SeqCst)
    }
}

async fn spawn_echo_upstream() -> SocketAddr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind echo upstream");
    let addr = listener.local_addr().expect("echo upstream local addr");
    tokio::spawn(async move {
        loop {
            let Ok((stream, _peer)) = listener.accept().await else {
                continue;
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

/// A "provisioning service" that completes the TCP handshake and then never
/// says anything.
///
/// `http://127.0.0.1:1` — the obvious choice — is refused instantly on
/// loopback, so an inline collateral fetch against it would return in under a
/// millisecond and a timing assertion built on it would pass whether the
/// fetch was on the request path or not. A black hole is the only address
/// that makes the timing test capable of failing.
///
/// The returned counter is how `an_unreachable_pccs_does_not_slow_the_request_path`
/// proves a fetch was genuinely attempted; without it, a pipeline that simply
/// never scheduled anything would satisfy the timing assertion trivially.
async fn spawn_black_hole_pccs() -> (SocketAddr, Arc<AtomicUsize>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind black hole");
    let addr = listener.local_addr().expect("black hole local addr");
    let connections = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&connections);
    tokio::spawn(async move {
        // Held rather than dropped: a closed socket would turn the black hole
        // into a fast failure, which is the case this fixture exists to avoid.
        let mut held = Vec::new();
        loop {
            match listener.accept().await {
                Ok((stream, _peer)) => {
                    counter.fetch_add(1, Ordering::SeqCst);
                    held.push(stream);
                }
                Err(_) => continue,
            }
        }
    });
    (addr, connections)
}

async fn serve_pipeline(upstream: SocketAddr, pipeline: Pipeline) -> SocketAddr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind gateway");
    let addr = listener.local_addr().expect("gateway local addr");
    let upstream_uri: hyper::Uri = format!("http://{upstream}")
        .parse()
        .expect("a loopback socket address is a valid uri authority");
    tokio::spawn(serve_on(
        listener,
        upstream_uri,
        Hooks::from_pipeline(Arc::new(pipeline)),
    ));
    addr
}

async fn spawn_gateway_with_fault(upstream: SocketAddr, fault: Fault) -> Gw {
    let hits = Arc::new(AtomicUsize::new(0));
    let sink = RecordingSink::new(fault == Fault::SinkPanics, Arc::clone(&hits));

    let source: Arc<dyn AttestationSource> = match fault {
        Fault::SourcePanics => Arc::new(PanickingSource(Arc::clone(&hits))),
        Fault::SourceErrors => Arc::new(ErroringSource(Arc::clone(&hits))),
        _ => Arc::new(AlwaysQuoteSource),
    };
    let verifier: Arc<dyn VerifyQuote> = match fault {
        Fault::VerifierPanics => Arc::new(PanickingVerifier(Arc::clone(&hits))),
        Fault::VerifierHangsThenErrors => Arc::new(HangingVerifier(Arc::clone(&hits))),
        _ => Arc::new(AlwaysVerified),
    };
    let meter: Arc<dyn Measure> = match fault {
        Fault::MeterPanics => Arc::new(PanickingMeter(Arc::clone(&hits))),
        Fault::MeterLockPoisoned => Arc::new(PoisoningMeter::new(Arc::clone(&hits))),
        _ => Arc::new(LinkabilityMeter::new(Duration::from_secs(3600), 7)),
    };
    let metrics: Arc<dyn RecordMetrics> = match fault {
        Fault::MetricsPanic => Arc::new(PanickingMetrics(Arc::clone(&hits))),
        _ => Arc::new(Metrics::new(&mut Registry::default())),
    };

    let addr = serve_pipeline(
        upstream,
        Pipeline {
            source,
            verifier,
            meter,
            metrics,
            sink: Arc::clone(&sink) as Arc<dyn FindingSink>,
            refresh: RefreshQueue::never_refreshes(),
        },
    )
    .await;
    Gw { addr, sink, hits }
}

/// The whole real pipeline, pointed at a provisioning service of the caller's
/// choosing. Nothing is stubbed: the real header source, the real verifier
/// over a real (cold) collateral cache, the real meter, the real counters,
/// and the real background refresher.
async fn spawn_gateway_with_pccs(upstream: SocketAddr, pccs_url: &str) -> Gw {
    let hits = Arc::new(AtomicUsize::new(0));
    let sink = RecordingSink::new(false, Arc::clone(&hits));
    let cache = Arc::new(CollateralCache::new(
        pccs_url.to_string(),
        Duration::from_secs(3600),
    ));
    let meter = Arc::new(LinkabilityMeter::new(Duration::from_secs(3600), 7));
    let queue = refresh::spawn(Arc::clone(&cache), Arc::clone(&meter))
        .expect("an hour is well above the minimum salt rotation");

    let addr = serve_pipeline(
        upstream,
        Pipeline {
            source: Arc::new(HeaderSource::new(ATTESTATION_HEADER)),
            verifier: Arc::new(QuoteVerifier::new(cache)),
            meter,
            metrics: Arc::new(Metrics::new(&mut Registry::default())),
            sink: Arc::clone(&sink) as Arc<dyn FindingSink>,
            refresh: queue,
        },
    )
    .await;
    Gw { addr, sink, hits }
}

/// A fresh client per request.
///
/// `proxy.rs` shares one process-wide client because production forwards to
/// one upstream forever; a test binary runs each `#[tokio::test]` on its own
/// runtime, and a pooled connection whose driver task belongs to a runtime
/// that has since shut down is a flake waiting to happen.
fn client() -> Client<HttpConnector, Full<Bytes>> {
    Client::builder(TokioExecutor::new()).build(HttpConnector::new())
}

async fn send(gw: &Gw, path: &str, attestation: Option<&[u8]>) -> anyhow::Result<String> {
    let uri: hyper::Uri = format!("http://{}{path}", gw.addr).parse()?;
    let mut builder = Request::builder().method(hyper::Method::GET).uri(uri);
    if let Some(quote) = attestation {
        builder = builder.header(ATTESTATION_HEADER, STANDARD.encode(quote));
    }
    let response = client()
        .request(builder.body(Full::new(Bytes::new()))?)
        .await?;
    let body = response.into_body().collect().await?.to_bytes();
    Ok(String::from_utf8(body.to_vec())?)
}

async fn get(gw: &Gw, path: &str) -> anyhow::Result<String> {
    send(gw, path, None).await
}

async fn get_with_attestation(gw: &Gw, path: &str, quote: &[u8]) -> anyhow::Result<String> {
    send(gw, path, Some(quote)).await
}

/// Poll until `condition` holds or `limit` elapses. Used instead of a fixed
/// sleep so a slow machine does not make a test flaky and a fast one does not
/// make it slow.
async fn wait_for(limit: Duration, condition: impl Fn() -> bool) -> bool {
    let deadline = Instant::now() + limit;
    while Instant::now() < deadline {
        if condition() {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    condition()
}

const ALL_FAULTS: [Fault; 8] = [
    Fault::SourcePanics,
    Fault::SourceErrors,
    Fault::VerifierPanics,
    Fault::VerifierHangsThenErrors,
    Fault::MeterPanics,
    Fault::MeterLockPoisoned,
    Fault::SinkPanics,
    Fault::MetricsPanic,
];

// ---------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------

/// Fail-open is the gateway's one hard guarantee: it sits in front of
/// somebody else's revenue API. Each case injects a fault at a different
/// stage and asserts the request still reaches the upstream unchanged.
///
/// The `fault_fired` assertion is not decoration. Without it, a fault planted
/// behind a stage that never runs would pass this test while proving nothing
/// — which is what happens to `VerifierPanics`, `MeterPanics` and
/// `MeterLockPoisoned` the moment the request stops carrying something the
/// source will hand onward.
///
/// The `VerifierHangsThenErrors` case additionally pins the premise the whole
/// of `refresh.rs` is built on: **hyper does not write the response until the
/// service future resolves**, so anything slow in the hook is
/// time-to-first-byte the client pays, even though the hook runs after the
/// forward. If that ever stopped being true, moving collateral fetches off
/// the request path would be unnecessary.
///
/// Be precise about what this assertion does and does not catch. It
/// distinguishes *a hook awaited on the service future* from *a hook running
/// off it* — spawn the hook, or write the response before it finishes, and
/// `elapsed` collapses to sub-millisecond and this fails. It says nothing
/// about the hook's **ordering** relative to the forward: a hook moved back
/// ahead of the forward, but still awaited inline, costs the same
/// `elapsed >= HANG` and passes here unchanged. That ordering is `proxy.rs`'s
/// property to pin, not this test's.
///
/// **Multi-threaded on purpose**, and the only test here that is. On a
/// current-thread runtime `HangingVerifier`'s `thread::sleep` blocks the one
/// worker, so the client cannot be served early *whatever* the hook's
/// position relative to the response write — the timing assertion would hold
/// for the wrong reason and a mutation that spawned the hook off the service
/// future would still pass it. With four workers the response could be
/// written by another thread the moment `handle` stopped waiting, so
/// `elapsed >= HANG` only holds if hyper genuinely waits for the service
/// future. This is also the flavour `#[tokio::main]` gives the real binary.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn every_stage_fails_open() {
    // The multi-threaded flavour is load-bearing, and an attribute is not an
    // assertion: `worker_threads = 1` silently reinstates the current-thread
    // false positive this test was rewritten to remove.
    assert!(
        tokio::runtime::Handle::current().metrics().num_workers() > 1,
        "this test needs more than one worker, or a blocking hook stalls the \
         client's connection driver too and the timing assertion below holds \
         wherever the hook sits"
    );

    // Set inside the timing branch below. Dropping VerifierHangsThenErrors
    // from ALL_FAULTS would otherwise leave the whole timing fix unexercised
    // and the suite green.
    let mut timing_checked = false;

    for fault in ALL_FAULTS {
        let upstream = spawn_echo_upstream().await;
        let gw = spawn_gateway_with_fault(upstream, fault).await;
        let started = Instant::now();
        let body = get(&gw, "/still-works")
            .await
            .unwrap_or_else(|e| panic!("{fault:?} took down the proxy: {e}"));
        let elapsed = started.elapsed();
        assert_eq!(body, "echo:/still-works", "{fault:?} altered the response");
        assert!(
            gw.fault_fired() >= 1,
            "{fault:?} never actually fired, so this case proves nothing"
        );
        if fault == Fault::VerifierHangsThenErrors {
            timing_checked = true;
            // Both halves, because `elapsed >= HANG` alone is vacuous for a
            // small enough `HANG` — at `Duration::ZERO` it can never fail,
            // and the fixture would be decorative again.
            assert!(
                HANG >= Duration::from_millis(50),
                "HANG is too short to be distinguishable from scheduling noise, \
                 so the assertion below proves nothing"
            );
            assert!(
                elapsed >= HANG,
                "the client saw its response in {elapsed:?}, before the hook's \
                 {HANG:?} of work finished. Hook cost is supposed to be \
                 time-to-first-byte cost — that premise is the entire reason \
                 collateral refresh lives off the request path"
            );
        }
    }

    assert!(
        timing_checked,
        "the sweep never ran the hanging verifier, so nothing here pins that \
         hook cost is time-to-first-byte cost"
    );
}

/// The other half of fail-open, and the half `catch_unwind` alone does not
/// give: a stage that comes apart must cost its own contribution and nothing
/// else. Without a guard *inside* the measure path, one panic unwinds past
/// every later stage and the operator is told nothing at all.
#[tokio::test]
async fn each_fault_still_records_a_finding_naming_what_it_skipped() {
    for fault in ALL_FAULTS {
        let upstream = spawn_echo_upstream().await;
        let gw = spawn_gateway_with_fault(upstream, fault).await;
        assert_eq!(get(&gw, "/measured").await.unwrap(), "echo:/measured");
        assert!(gw.fault_fired() >= 1, "{fault:?} never fired");

        let found = gw.sink.entries();
        assert_eq!(
            found.len(),
            1,
            "{fault:?} cost the request its finding entirely"
        );
        let record = &found[0];

        // The verdict word as well as the skip list. Without it, a mutation
        // that folded the source's `Err` arm into its `Ok(None)` arm — a
        // malformed quote reported as no quote at all, the agent's fault
        // rebadged as ours — would leave every other assertion here green.
        let expected_verdict = match fault {
            Fault::SourceErrors => "INVALID",
            Fault::SourcePanics | Fault::VerifierPanics | Fault::VerifierHangsThenErrors => {
                "UNVERIFIED"
            }
            Fault::MeterPanics
            | Fault::MeterLockPoisoned
            | Fault::SinkPanics
            | Fault::MetricsPanic => "VERIFIED",
        };
        let first_line = record
            .rendered
            .lines()
            .next()
            .expect("a rendering always has a first line");
        assert!(
            first_line.contains(expected_verdict)
                // "VERIFIED" is a substring of "UNVERIFIED", so the positive
                // case has to exclude the negative one explicitly.
                && (expected_verdict != "VERIFIED" || !first_line.contains("UNVERIFIED")),
            "{fault:?} rendered the wrong verdict; expected {expected_verdict}: {first_line}"
        );

        let expected: Vec<&'static str> = match fault {
            Fault::SourcePanics => vec![STAGE_SOURCE],
            // An error is not a panic: the source worked and said no.
            Fault::SourceErrors => vec![],
            Fault::VerifierPanics => vec![STAGE_VERIFIER],
            // Slow is not broken.
            Fault::VerifierHangsThenErrors => vec![],
            Fault::MeterPanics | Fault::MeterLockPoisoned => vec![STAGE_METER],
            Fault::MetricsPanic => vec![STAGE_METRICS],
            // The sink is last; nothing after it observes its panic, so the
            // skip list is empty and the evidence is that a record exists.
            Fault::SinkPanics => vec![],
        };
        assert_eq!(
            record.skipped, expected,
            "{fault:?} recorded the wrong skip list: {}",
            record.rendered
        );
        for stage in &expected {
            assert!(
                record.rendered.contains(stage),
                "{fault:?}: the rendered finding does not name the stage it lost: {}",
                record.rendered
            );
        }

        // A number with no provenance is worse than no number. The meter is
        // only reached when the source yielded a quote *and* the verifier
        // returned `Verified`, which is these two faults and no others.
        let meter_ran = matches!(fault, Fault::SinkPanics | Fault::MetricsPanic);
        assert_eq!(
            record.has_observation, meter_ran,
            "{fault:?} disagreed about whether a measurement happened: {}",
            record.rendered
        );
        assert_eq!(
            record.rendered.contains("anonymity set"),
            meter_ran,
            "{fault:?} rendered the wrong anonymity block: {}",
            record.rendered
        );
    }
}

/// A panic while holding the lock must not turn one bad request into a
/// permanently broken gateway.
///
/// The response assertions are the brief's; on their own Task 1's
/// `catch_unwind` satisfies them, so they cannot distinguish a recovered
/// gateway from one that survives while measuring nothing ever again. The
/// finding assertions are what give this test teeth: the first request loses
/// its measurement, and every request after it gets a real one.
#[tokio::test]
async fn a_poisoned_meter_lock_does_not_wedge_every_later_request() {
    let upstream = spawn_echo_upstream().await;
    let gw = spawn_gateway_with_fault(upstream, Fault::MeterLockPoisoned).await;
    for _ in 0..5 {
        assert_eq!(get(&gw, "/after").await.unwrap(), "echo:/after");
    }

    let found = gw.sink.entries();
    assert_eq!(found.len(), 5, "findings stopped after the poison");
    assert_eq!(
        found[0].skipped,
        vec![STAGE_METER],
        "the request that panicked must say so: {}",
        found[0].rendered
    );
    assert!(!found[0].has_observation);
    for (i, record) in found.iter().enumerate().skip(1) {
        assert!(
            record.skipped.is_empty(),
            "request {i} was still degraded by the earlier poison: {:?}",
            record.skipped
        );
        assert!(
            record.has_observation,
            "request {i} forwarded but measured nothing; the gateway is wedged: {}",
            record.rendered
        );
        assert!(
            record.rendered.contains("anonymity set"),
            "request {i}: {}",
            record.rendered
        );
    }
    // Four surviving observations of one configuration: the meter kept
    // counting across the poison rather than restarting.
    assert!(
        found[4].rendered.contains("4 of 4"),
        "the recovered meter lost its history: {}",
        found[4].rendered
    );
}

/// Collateral refresh is off the request path. If it were not, this would
/// block until the provisioning service answered — which, against a socket
/// that accepts and then says nothing, is never.
///
/// Two deviations from the obvious version of this test, both load-bearing.
/// The target is a black hole rather than `127.0.0.1:1`, because a refused
/// port on loopback fails in microseconds and an inline fetch against it
/// would satisfy any timing bound. And the attestation is the real vendored
/// quote rather than a junk buffer, because `CollateralCache::refresh`
/// rejects an unparseable quote *before* it reads the PCCS URL at all — a
/// junk buffer never reaches the network from either the foreground or the
/// background, so the timing assertion would hold no matter where the fetch
/// was wired.
#[tokio::test]
async fn an_unreachable_pccs_does_not_slow_the_request_path() {
    let upstream = spawn_echo_upstream().await;
    let (pccs, pccs_connections) = spawn_black_hole_pccs().await;
    let gw = spawn_gateway_with_pccs(upstream, &format!("http://{pccs}")).await;

    let t = std::time::Instant::now();
    let body = get_with_attestation(&gw, "/x", REAL_TDX_QUOTE)
        .await
        .unwrap();
    let elapsed = t.elapsed();

    assert_eq!(body, "echo:/x");
    assert!(elapsed < Duration::from_millis(500), "took {elapsed:?}");

    // The request path did the work it was supposed to: a cold cache is our
    // gap, not the agent's, so the verdict is Unverified and names it.
    let found = gw.sink.entries();
    assert_eq!(found.len(), 1);
    assert!(
        found[0].rendered.contains("UNVERIFIED")
            && found[0].rendered.contains("no collateral cached"),
        "{}",
        found[0].rendered
    );
    assert!(
        !found[0].rendered.contains("anonymity set"),
        "an unverified quote must carry no set size: {}",
        found[0].rendered
    );

    // ...and the refresh really was attempted, somewhere else. Without this
    // the timing assertion is satisfied by a gateway that never schedules
    // anything at all.
    assert!(
        wait_for(Duration::from_secs(5), || pccs_connections
            .load(Ordering::SeqCst)
            >= 1)
        .await,
        "the background refresher never reached the provisioning service, so \
         the timing assertion above proves nothing"
    );
}
