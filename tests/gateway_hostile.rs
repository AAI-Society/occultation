//! The hostile agent: an agent that misbehaves in every way the gateway must
//! survive, and the scrape endpoint that makes the measurement visible.
//!
//! In the spirit of `transit`'s hostile server. Every case here asserts the
//! same property first — **the request still reaches the upstream** — and only
//! then asserts what the finding recorded. Fail-open is not a best-effort
//! behaviour that degrades under attack; it is the thing this proxy exists to
//! guarantee, and a hostile agent is exactly who would test it.
//!
//! # How deep each case actually goes, and how that is known
//!
//! Two rewrites on this branch were caused by hostile inputs that failed
//! earlier than their author thought: `[0u8; 64]` dies in `Quote::parse`
//! before anything touches a network, and `127.0.0.1:1` is refused in
//! microseconds on loopback. A hostile case that stops short of the code it
//! meant to attack proves nothing while looking thorough.
//!
//! So every case here names the stage it reaches, and the assertion *pins*
//! that stage rather than trusting the comment. `QuoteVerifier` hands out a
//! different message per stage, which makes the depth observable from the
//! finding alone:
//!
//! | message | how far the input got |
//! | --- | --- |
//! | `the attestation could not be decoded: …` | stopped in `HeaderSource`; the verifier never ran |
//! | `not a DCAP quote: …` | stopped in `Quote::parse` or `quote_fmspc` |
//! | `no collateral cached for FMSPC <hex>` | **parsed**, FMSPC extracted, cache consulted |
//!
//! An FMSPC in the message is the load-bearing signal: it can only be there
//! if `Quote::parse` and `intel::quote_fmspc` both succeeded on the agent's
//! bytes. Cases that must get past the parser assert on the FMSPC, and
//! [`Hostile::verifier_calls`] separately distinguishes "the source rejected
//! it" from "the verifier rejected it".
//!
//! # The ceiling on how deep any of this can go
//!
//! No test in this file reaches `dcap_qvl::verify::verify`, and none can.
//! Warming the collateral cache needs a live provisioning service — the only
//! other route, `CollateralCache::insert_for_test`, is `#[cfg(test)]
//! pub(crate)` and invisible from an integration test — so every quote here
//! bottoms out at `Unverified { why: "no collateral cached …" }` by
//! construction. The chain check against hostile bytes is therefore pinned
//! *in-crate*, where the clock can be held inside the vendored collateral's
//! validity window: see `verify.rs`'s
//! `a_tampered_quote_fails_the_chain_inside_the_collateral_window`, which
//! tampers with five distinct signed structures, and its truncation sweep.
//! This file covers everything on either side of that call.

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
use occultation::gateway::finding::{Metrics, MIN_MEANINGFUL_SESSIONS};
use occultation::gateway::meter::LinkabilityMeter;
use occultation::gateway::pipeline::{FindingSink, Measured, Pipeline, VerifyQuote};
use occultation::gateway::proxy::{serve_on, Hooks, RequestHead};
use occultation::gateway::refresh::RefreshQueue;
use occultation::gateway::scrape::{self, METRICS_PATH};
use occultation::gateway::source::{HeaderSource, RawAttestation, MAX_ATTESTATION_B64};
use occultation::gateway::verify::{Platform, QuoteVerdict, QuoteVerifier, TcbConfig};
use prometheus_client::registry::Registry;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// The vendored TDX quote (Phala Network, MIT — `tests/fixtures/README.md`).
const REAL_TDX_QUOTE: &[u8] = include_bytes!("fixtures/tdx-quote.bin");

/// A real quote from a *different* platform: SGX rather than TDX, and a
/// different FMSPC. See `tests/fixtures/README.md`.
const REAL_SGX_QUOTE: &[u8] = include_bytes!("fixtures/sgx-quote.bin");

/// The FMSPCs the two fixtures carry, pinned so a case that claims to have
/// reached the FMSPC extraction has to name the right one. `verify.rs` pins
/// the TDX value independently under `REAL_FMSPC_HEX`.
const TDX_FMSPC: &str = "b0c06f000000";
const SGX_FMSPC: &str = "00a067110000";

const ATTESTATION_HEADER: &str = "x-attestation";

// ---------------------------------------------------------------------
// What the hostile agent sends
// ---------------------------------------------------------------------

/// One way for an agent to misbehave.
///
/// Every variant is a *header value* (or its absence) — that is the whole
/// attack surface phase 1's transport gives an agent, and being explicit
/// about that is part of the point: with header transport there is nothing
/// else for the gateway to check.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Misbehaviour {
    /// A captured quote, sent again. Indistinguishable from the first use.
    ReplayedQuote,
    /// Well-formed base64 over bytes that are not a quote.
    MalformedQuote,
    /// A header that is not base64 at all.
    UndecodableHeader,
    /// No attestation whatsoever.
    NoAttestation,
    /// A genuine quote, from a platform this gateway holds no collateral for.
    QuoteForAnotherPlatform,
    /// A header past the decode cap, which must be refused before it is
    /// turned into bytes.
    OversizedHeader,
}

const ALL_MISBEHAVIOURS: [Misbehaviour; 6] = [
    Misbehaviour::ReplayedQuote,
    Misbehaviour::MalformedQuote,
    Misbehaviour::UndecodableHeader,
    Misbehaviour::NoAttestation,
    Misbehaviour::QuoteForAnotherPlatform,
    Misbehaviour::OversizedHeader,
];

/// Bytes that are well-formed base64 and are not a quote.
///
/// Deterministic rather than random, and quote-sized rather than eight bytes:
/// a short buffer fails the length check before the version check, which is a
/// different code path with the same verdict. Generated by an LCG so a
/// failure is reproducible.
fn random_looking_bytes(len: usize) -> Vec<u8> {
    let mut state: u64 = 0x1234_5678_9abc_def0;
    (0..len)
        .map(|_| {
            state = state
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            (state >> 33) as u8
        })
        .collect()
}

impl Misbehaviour {
    /// The header value this misbehaviour puts on the wire, or `None` for a
    /// request that carries no attestation header at all.
    fn header_value(self) -> Option<String> {
        match self {
            Misbehaviour::ReplayedQuote => Some(STANDARD.encode(REAL_TDX_QUOTE)),
            Misbehaviour::MalformedQuote => Some(STANDARD.encode(random_looking_bytes(4096))),
            // `!` is outside the base64 alphabet, so this cannot decode.
            Misbehaviour::UndecodableHeader => Some("not!base64!at!all".to_string()),
            Misbehaviour::NoAttestation => None,
            Misbehaviour::QuoteForAnotherPlatform => Some(STANDARD.encode(REAL_SGX_QUOTE)),
            // One byte past the cap, and valid base64 throughout, so the only
            // thing that can refuse it is the cap itself.
            Misbehaviour::OversizedHeader => Some("A".repeat(MAX_ATTESTATION_B64 + 1)),
        }
    }
}

// ---------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------

/// What the sink saw. `Finding` derives neither `Debug` nor `Clone` by
/// design, so the pieces a test needs are copied out at emit time.
#[derive(Clone, Debug)]
struct Recorded {
    rendered: String,
    json: serde_json::Value,
    has_observation: bool,
}

#[derive(Default)]
struct RecordingSink {
    seen: Mutex<Vec<Recorded>>,
}

impl FindingSink for RecordingSink {
    fn emit(&self, measured: &Measured) {
        let entry = Recorded {
            rendered: measured.render(),
            json: measured.finding.to_json(),
            has_observation: measured.finding.observation.is_some(),
        };
        match self.seen.lock() {
            Ok(mut seen) => seen.push(entry),
            Err(poisoned) => poisoned.into_inner().push(entry),
        }
    }
}

impl RecordingSink {
    fn entries(&self) -> Vec<Recorded> {
        match self.seen.lock() {
            Ok(seen) => seen.clone(),
            Err(poisoned) => poisoned.into_inner().clone(),
        }
    }
}

/// The real [`QuoteVerifier`], with a tally of what it was asked to verify.
///
/// The tally is not decoration. "The source rejected the header" and "the
/// verifier rejected the quote" produce different findings but the same
/// forwarded response, and several cases below are only meaningful if the
/// verifier was — or was definitely *not* — reached. It also records the
/// bytes, which is how the replay case proves the same quote really was
/// verified twice rather than cached, deduplicated or skipped.
struct CountingVerifier {
    inner: QuoteVerifier,
    seen: Mutex<Vec<Vec<u8>>>,
}

impl VerifyQuote for CountingVerifier {
    fn verify(&self, raw: &RawAttestation) -> QuoteVerdict {
        match self.seen.lock() {
            Ok(mut seen) => seen.push(raw.bytes.clone()),
            Err(poisoned) => poisoned.into_inner().push(raw.bytes.clone()),
        }
        self.inner.verify(raw)
    }
}

impl CountingVerifier {
    fn quotes(&self) -> Vec<Vec<u8>> {
        match self.seen.lock() {
            Ok(seen) => seen.clone(),
            Err(poisoned) => poisoned.into_inner().clone(),
        }
    }
}

/// A running gateway with the whole real pipeline behind it, plus a scrape
/// endpoint on a second listener over the same registry.
///
/// Nothing is stubbed: the real `HeaderSource`, the real `QuoteVerifier` over
/// a real (cold) `CollateralCache`, the real `LinkabilityMeter`, the real
/// counters. The refresh queue is [`RefreshQueue::never_refreshes`] so a
/// hostile quote cannot turn this suite into traffic aimed at a real
/// provisioning service — every `Unverified` verdict schedules a refresh, and
/// six of these cases produce one.
struct Hostile {
    proxy: SocketAddr,
    metrics: SocketAddr,
    sink: Arc<RecordingSink>,
    verifier: Arc<CountingVerifier>,
}

impl Hostile {
    fn verifier_calls(&self) -> usize {
        self.verifier.quotes().len()
    }
    fn findings(&self) -> Vec<Recorded> {
        self.sink.entries()
    }
    fn only_finding(&self) -> Recorded {
        let found = self.findings();
        assert_eq!(found.len(), 1, "expected exactly one finding");
        found.into_iter().next().expect("one finding")
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

/// Assemble the pipeline the hostile cases run against, and serve it, along
/// with a scrape endpoint on its own ephemeral port.
async fn spawn_hostile_gateway() -> Hostile {
    spawn_hostile_gateway_with(|verifier| verifier).await
}

/// [`spawn_hostile_gateway`], with the option to substitute the verifier.
///
/// Only the two "crafted configuration" cases use the substitution, and they
/// say why: the real verifier cannot return `Verified` from an integration
/// test (see the module docs), so a case about what the *meter* does with an
/// agent's chosen configuration has to hand it one.
async fn spawn_hostile_gateway_with(
    swap: impl FnOnce(Arc<CountingVerifier>) -> Arc<dyn VerifyQuote>,
) -> Hostile {
    let upstream = spawn_echo_upstream().await;
    let sink = Arc::new(RecordingSink::default());
    let cache = Arc::new(CollateralCache::new(
        "http://127.0.0.1:1".to_string(),
        Duration::from_secs(3600),
    ));
    let verifier = Arc::new(CountingVerifier {
        inner: QuoteVerifier::new(cache),
        seen: Mutex::new(Vec::new()),
    });

    let mut registry = Registry::default();
    let metrics = Arc::new(Metrics::new(&mut registry));
    let registry = Arc::new(registry);

    let pipeline = Pipeline {
        source: Arc::new(HeaderSource::new(ATTESTATION_HEADER)),
        verifier: swap(Arc::clone(&verifier)),
        meter: Arc::new(LinkabilityMeter::new(Duration::from_secs(3600), 7)),
        metrics,
        sink: Arc::clone(&sink) as Arc<dyn FindingSink>,
        refresh: RefreshQueue::never_refreshes(),
    };

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind gateway");
    let proxy = listener.local_addr().expect("gateway local addr");
    let upstream_uri: hyper::Uri = format!("http://{upstream}")
        .parse()
        .expect("a loopback socket address is a valid uri authority");
    tokio::spawn(serve_on(
        listener,
        upstream_uri,
        Hooks::from_pipeline(Arc::new(pipeline)),
    ));

    // The scrape endpoint, on its own listener. `bind` then `serve_on` is
    // exactly what `src/bin/gateway.rs` does; the split exists so the
    // ephemeral port can be read back before serving starts.
    let metrics_listener = scrape::bind("127.0.0.1:0".parse().expect("a literal addr parses"))
        .await
        .expect("bind metrics listener");
    let metrics_addr = metrics_listener.local_addr().expect("metrics local addr");
    tokio::spawn(scrape::serve_on(metrics_listener, registry));

    Hostile {
        proxy,
        metrics: metrics_addr,
        sink,
        verifier,
    }
}

/// A fresh client per request, for the reason Task 7's suite gives: each
/// `#[tokio::test]` runs on its own runtime, and a pooled connection whose
/// driver belongs to a shut-down runtime is a flake waiting to happen.
fn client() -> Client<HttpConnector, Full<Bytes>> {
    Client::builder(TokioExecutor::new()).build(HttpConnector::new())
}

/// Send one misbehaving request and return the upstream's response body.
async fn misbehave(gw: &Hostile, path: &str, how: Misbehaviour) -> anyhow::Result<String> {
    let uri: hyper::Uri = format!("http://{}{path}", gw.proxy).parse()?;
    let mut builder = Request::builder().method(hyper::Method::GET).uri(uri);
    if let Some(value) = how.header_value() {
        builder = builder.header(ATTESTATION_HEADER, value);
    }
    let response = client()
        .request(builder.body(Full::new(Bytes::new()))?)
        .await?;
    let body = response.into_body().collect().await?.to_bytes();
    Ok(String::from_utf8(body.to_vec())?)
}

async fn get(addr: &SocketAddr, path: &str) -> anyhow::Result<(u16, String)> {
    let uri: hyper::Uri = format!("http://{addr}{path}").parse()?;
    let response = client()
        .request(
            Request::builder()
                .method(hyper::Method::GET)
                .uri(uri)
                .body(Full::new(Bytes::new()))?,
        )
        .await?;
    let status = response.status().as_u16();
    let body = response.into_body().collect().await?.to_bytes();
    Ok((status, String::from_utf8_lossy(&body).into_owned()))
}

/// The first line of a rendered finding — where the verdict word and its
/// reason live, and the only place a `contains` over the whole rendering
/// could be satisfied by a footnote.
fn first_line(record: &Recorded) -> &str {
    record
        .rendered
        .lines()
        .next()
        .expect("a rendering always has a first line")
}

// ---------------------------------------------------------------------
// The property every hostile case shares
// ---------------------------------------------------------------------

/// The one guarantee. Whatever the agent sends, the API behind the gateway
/// answers it — unchanged, and with the gateway's own opinion nowhere in the
/// response.
///
/// Swept over every misbehaviour rather than asserted case by case, so a new
/// variant added to [`ALL_MISBEHAVIOURS`] inherits the property automatically
/// instead of relying on whoever adds it to remember.
#[tokio::test]
async fn every_hostile_request_still_reaches_the_upstream_unchanged() {
    for how in ALL_MISBEHAVIOURS {
        let gw = spawn_hostile_gateway().await;
        let body = misbehave(&gw, "/agent/act", how)
            .await
            .unwrap_or_else(|e| panic!("{how:?} took down the proxy: {e}"));
        assert_eq!(body, "echo:/agent/act", "{how:?} altered the response");

        // ...and it was measured. A gateway that forwarded perfectly and
        // measured nothing would satisfy the assertion above for every case
        // here, which is the failure mode this whole suite exists to detect.
        let found = gw.findings();
        assert_eq!(
            found.len(),
            1,
            "{how:?} was forwarded but produced no finding"
        );
        // No hostile input may produce a pass. Nothing in this file can reach
        // a genuine `Verified` (see the module docs), so this is a guard
        // against a verdict fabricated somewhere on the way.
        assert!(
            !first_line(&found[0]).contains("VERIFIED")
                || first_line(&found[0]).contains("UNVERIFIED"),
            "{how:?} produced a pass: {}",
            found[0].rendered
        );
    }
}

// ---------------------------------------------------------------------
// The individual misbehaviours
// ---------------------------------------------------------------------

/// A captured quote, replayed.
///
/// **Detecting this requires RA-TLS, and RA-TLS is phase 1b.** With header
/// transport nothing ties a quote to the TLS session it arrived on, so the
/// second presentation is byte-identical to the first and the gateway has no
/// signal at all to distinguish them. This test therefore pins *today's
/// honest behaviour* rather than pretending otherwise: the quote is verified
/// again, from scratch, the second finding is indistinguishable from the
/// first, and the session-binding line says why. When `RaTlsSource` lands,
/// this test should fail, and the fix is to change it.
///
/// The identical-rendering assertion is the sharp end. Asserting only that
/// both requests forwarded would hold for a gateway that silently dropped the
/// second finding, and asserting only that the binding line says "NONE" would
/// hold for a gateway that had somehow flagged the replay elsewhere in the
/// finding. Byte-equality of the two renderings says exactly one thing: there
/// is nothing in the output that distinguishes a replay from a first use.
#[tokio::test]
async fn a_replayed_quote_is_verified_again_because_nothing_binds_it_to_a_session() {
    let gw = spawn_hostile_gateway().await;
    for _ in 0..2 {
        assert_eq!(
            misbehave(&gw, "/replay", Misbehaviour::ReplayedQuote)
                .await
                .unwrap(),
            "echo:/replay"
        );
    }

    // The verifier really ran twice, on the same bytes. Without this, a
    // gateway that cached the first verdict by quote digest — which would be
    // a *different* design with different properties — would pass everything
    // below.
    let quotes = gw.verifier.quotes();
    assert_eq!(quotes.len(), 2, "the quote was not verified twice");
    assert_eq!(quotes[0], quotes[1], "the two quotes differed");
    assert_eq!(quotes[0], REAL_TDX_QUOTE, "the quote was altered in flight");

    let found = gw.findings();
    assert_eq!(found.len(), 2);
    assert_eq!(
        found[0].rendered, found[1].rendered,
        "a replay renders differently from a first use, which would mean the \
         gateway can detect one — it cannot, and this test is what says so"
    );
    assert_eq!(found[0].json, found[1].json, "the JSON forms differ");

    // The gap is stated on the finding, not left to the reader.
    assert!(
        found[1].rendered.contains("session binding   NONE"),
        "{}",
        found[1].rendered
    );
    assert!(
        found[1].rendered.contains("replayable"),
        "the finding must say a captured quote is replayable: {}",
        found[1].rendered
    );
    assert_eq!(found[1].json["binding"]["kind"], "unbound");

    // Depth: an FMSPC in the message can only come from a successful
    // `Quote::parse` plus `intel::quote_fmspc`, so this case really did get
    // past the parser and into the cache lookup — it is not a replay of
    // something the gateway rejected on sight.
    assert!(
        first_line(&found[1]).contains(TDX_FMSPC),
        "the replay never reached FMSPC extraction: {}",
        found[1].rendered
    );
}

/// Well-formed base64 over bytes that are not a quote.
///
/// This one *is* meant to die in `Quote::parse` — that is the stage under
/// test — and the assertion pins that it died there rather than somewhere
/// convenient. The distinction from [`Misbehaviour::UndecodableHeader`] below
/// is the whole point: this reaches the verifier, that one does not.
#[tokio::test]
async fn a_malformed_quote_is_invalid_and_never_a_panic() {
    let gw = spawn_hostile_gateway().await;
    assert_eq!(
        misbehave(&gw, "/junk", Misbehaviour::MalformedQuote)
            .await
            .unwrap(),
        "echo:/junk"
    );

    assert_eq!(
        gw.verifier_calls(),
        1,
        "the bytes decoded, so the verifier must have been asked about them"
    );
    let found = gw.only_finding();
    let line = first_line(&found);
    assert!(line.contains("INVALID"), "{line}");
    assert!(
        line.contains("not a DCAP quote"),
        "the verifier must say the bytes are not a quote: {line}"
    );
    // The agent's fault, not ours — and so not in the counter an operator
    // alerts on for their own collateral pipeline.
    assert!(!line.contains("UNVERIFIED"), "{line}");
    assert_eq!(found.json["verdict"]["verdict"], "invalid");
    assert!(!found.has_observation, "an invalid quote measures nothing");
}

/// A header that is not base64 at all.
///
/// Stops in `HeaderSource`, one stage earlier than the case above, and the
/// zero verifier-call count is what proves it. Still the *agent's* fault, so
/// still `Invalid` — reporting a garbled header as `Unverified` would blame
/// the gateway's own collateral pipeline for a malformed request.
#[tokio::test]
async fn an_undecodable_header_is_the_agents_fault_and_never_reaches_the_verifier() {
    let gw = spawn_hostile_gateway().await;
    assert_eq!(
        misbehave(&gw, "/garbled", Misbehaviour::UndecodableHeader)
            .await
            .unwrap(),
        "echo:/garbled"
    );

    assert_eq!(
        gw.verifier_calls(),
        0,
        "an undecodable header must be refused before the verifier is asked"
    );
    let line = first_line(&gw.only_finding()).to_string();
    assert!(line.contains("INVALID"), "{line}");
    assert!(
        line.contains("could not be decoded"),
        "the finding must name the decode failure: {line}"
    );
}

/// No attestation at all.
///
/// A legitimate state the gateway reports on, not a malformed request — and
/// the commonest one in a real deployment, since nothing forces an agent to
/// send anything. `Unverified`, because we could not check; never `Invalid`,
/// because the agent did nothing wrong; and never a pass.
#[tokio::test]
async fn a_request_with_no_attestation_is_unverified_and_says_what_is_missing() {
    let gw = spawn_hostile_gateway().await;
    assert_eq!(
        misbehave(&gw, "/bare", Misbehaviour::NoAttestation)
            .await
            .unwrap(),
        "echo:/bare"
    );

    assert_eq!(gw.verifier_calls(), 0, "there was nothing to verify");
    let found = gw.only_finding();
    let line = first_line(&found);
    assert!(line.contains("UNVERIFIED"), "{line}");
    assert!(
        line.contains("no attestation accompanied this request"),
        "{line}"
    );
    assert!(
        !line.contains('\u{2713}'),
        "a checkmark next to a request that carried no attestation: {line}"
    );
    assert!(!found.has_observation);
    assert_eq!(found.json["verdict"]["verdict"], "unverified");
    assert!(found.json["observation"].is_null());
}

/// A genuine quote from a platform this gateway holds no collateral for.
///
/// `Unverified`, not `Invalid`: the quote is real and well-formed, and the
/// gap is ours. Calling it `Invalid` would blame a counterparty for a
/// provisioning gap on our side, and would skip the collateral refresh that
/// `Unverified` schedules — so the platform would stay unverifiable forever.
///
/// The SGX fixture is what makes this a genuinely different platform rather
/// than a relabelled version of the cold-cache case: it parses through a
/// different `Report` variant and carries a different FMSPC, and the
/// assertion below requires the message to name *that* FMSPC and not the TDX
/// one. A gateway that had failed to parse it could not produce either.
#[tokio::test]
async fn a_quote_for_another_platform_is_unverified_rather_than_invalid() {
    let gw = spawn_hostile_gateway().await;
    assert_eq!(
        misbehave(
            &gw,
            "/other-platform",
            Misbehaviour::QuoteForAnotherPlatform
        )
        .await
        .unwrap(),
        "echo:/other-platform"
    );

    assert_eq!(gw.verifier_calls(), 1);
    let found = gw.only_finding();
    let line = first_line(&found);
    assert!(line.contains("UNVERIFIED"), "{line}");
    assert!(
        !line.contains("INVALID"),
        "a real quote for an unprovisioned platform is our gap, not the \
         agent's fault: {line}"
    );
    assert!(
        line.contains(SGX_FMSPC),
        "the finding must name the platform whose collateral is missing, and \
         it must be the SGX fixture's: {line}"
    );
    assert!(
        !line.contains(TDX_FMSPC),
        "the finding names the wrong platform, so the FMSPC did not come out \
         of the quote that was actually sent: {line}"
    );
    assert!(
        !found.has_observation,
        "an unverified quote yields no trustworthy configuration to measure"
    );
}

/// A header past the decode cap.
///
/// Refused *before* it is decoded — that is the property, and the reason the
/// cap exists at all: decoding is an allocation on an attacker's say-so, and
/// a proxy that allocates on demand is a denial-of-service primitive. The
/// zero verifier-call count is the observable, since a cap enforced after the
/// decode would produce the same verdict having already done the work.
#[tokio::test]
async fn an_oversized_attestation_header_is_refused_before_it_is_decoded() {
    let gw = spawn_hostile_gateway().await;
    assert_eq!(
        misbehave(&gw, "/huge", Misbehaviour::OversizedHeader)
            .await
            .unwrap(),
        "echo:/huge"
    );

    assert_eq!(
        gw.verifier_calls(),
        0,
        "the oversized header reached the verifier, so it was decoded first"
    );
    let line = first_line(&gw.only_finding()).to_string();
    assert!(line.contains("INVALID"), "{line}");
    assert!(
        line.contains(&MAX_ATTESTATION_B64.to_string()),
        "the finding must name the cap that refused it: {line}"
    );
}

// ---------------------------------------------------------------------
// Crafted configurations: what an agent can do to the meter
// ---------------------------------------------------------------------

/// A verifier that accepts whatever the agent sent and reports the TCB
/// configuration the agent's bytes describe.
///
/// This is a stub, and it is here for a reason the module docs give: no
/// integration test can obtain a genuine `Verified` verdict, so a case about
/// what the *meter* does with an agent-chosen configuration has to hand it
/// one. What it models is not a broken verifier — it is an agent on hardware
/// that genuinely attests, varying the fields that are not platform-fixed.
/// `meter.rs` names those explicitly: `td_attributes` and `xfam` are set at
/// TD creation, so a counterparty who can launch TDs can mint distinct
/// verified configurations at will. Every attribute name below is one Task
/// 4's verifier really produces for TDX 1.0.
struct CraftingVerifier;

impl VerifyQuote for CraftingVerifier {
    fn verify(&self, raw: &RawAttestation) -> QuoteVerdict {
        QuoteVerdict::Verified {
            platform: Platform::TdxV10,
            tcb_status: "UpToDate".to_string(),
            advisories: vec![],
            config: TcbConfig {
                attributes: [
                    ("fmspc".to_string(), TDX_FMSPC.to_string()),
                    ("tee_tcb_svn".to_string(), "0".repeat(32)),
                    // The one field the agent controls, taken from its own
                    // bytes so distinct requests are distinct configurations.
                    (
                        "td_attributes".to_string(),
                        String::from_utf8_lossy(&raw.bytes).into_owned(),
                    ),
                    ("xfam".to_string(), "0".repeat(16)),
                ]
                .into_iter()
                .collect(),
            },
        }
    }
}

/// Build the same pipeline `spawn_hostile_gateway` builds, but off-socket, so
/// a ten-thousand-request sweep does not become ten thousand TCP round trips.
///
/// This is the real `Pipeline`, the real `HeaderSource`, the real
/// `LinkabilityMeter`, the real counters and the real `Finding` rendering —
/// only the listener is absent. The hook is what the sweep is measuring, and
/// Task 7 established that hook cost *is* time-to-first-byte cost, so
/// measuring it directly measures the thing that matters.
/// `a_crafted_configuration_still_forwards` covers the socket half.
fn offline_pipeline(sink: Arc<RecordingSink>) -> Pipeline {
    Pipeline {
        source: Arc::new(HeaderSource::new(ATTESTATION_HEADER)),
        verifier: Arc::new(CraftingVerifier),
        meter: Arc::new(LinkabilityMeter::new(Duration::from_secs(3600), 7)),
        metrics: Arc::new(Metrics::new(&mut Registry::default())),
        sink: sink as Arc<dyn FindingSink>,
        refresh: RefreshQueue::never_refreshes(),
    }
}

fn head_carrying(value: &str) -> RequestHead {
    let mut headers = hyper::HeaderMap::new();
    headers.insert(
        hyper::header::HeaderName::from_static("x-attestation"),
        hyper::header::HeaderValue::from_str(value).expect("base64 is a valid header value"),
    );
    RequestHead {
        method: hyper::Method::GET,
        path_and_query: "/agent/act".to_string(),
        headers,
    }
}

/// Ten thousand distinct crafted configurations, and what the meter does with
/// them.
///
/// Two properties, and it is worth being exact about which one is being
/// claimed, because the obvious phrasing — "the meter's memory stays bounded"
/// — is **false** and `meter.rs` says so: between rotations `counts` and
/// `marginals` grow without bound, and the rotation interval is the only
/// ceiling the module offers. Asserting boundedness here would be asserting
/// something the design does not provide.
///
/// What is true, and what this pins:
///
/// 1. **Growth is linear in distinct configurations and nothing is retained
///    per session.** Ten thousand distinct configurations produce ten
///    thousand entries; ten thousand repeats of *one* configuration produce
///    one. The store counts, and does not remember who.
/// 2. **No request degrades as the store fills.** A per-observation cost that
///    grew with the number of stored configurations would make the hook — and
///    therefore time-to-first-byte — a function of how long the gateway had
///    been up, with an agent holding the dial.
///
/// The second property is measured in two places on purpose, because the
/// obvious single measurement does not work and the numbers say why.
///
/// A decile-ratio check *over the whole pipeline* is worthless here. Measured
/// on this host, an `observe` deliberately mutated to scan the entire store on
/// every call — genuinely superlinear, exactly the regression worth catching —
/// moves the pipeline's last-decile/first-decile ratio from 0.97 to 0.97,
/// because the meter is a few microseconds of a ~46 µs request and the fixed
/// costs (base64, rendering, JSON, the sink) swamp it. That mutation passed a
/// ten-times-the-first-decile assertion without blinking. The same ratio taken
/// **against the meter alone** moves from 0.9 to 9.1, so that is where it is
/// taken, at a threshold of three: three times the clean ratio, three times
/// under the mutated one.
///
/// The absolute ceiling is a percentile rather than a maximum, and that is not
/// a dodge. Mean cost here is ~4.6 µs and the p99.9 is tens of microseconds,
/// but the single worst sample in ten thousand is ~3.4 ms — a 700× outlier
/// that is the operating system descheduling the thread, not the gateway doing
/// work. Asserting on that one sample would be asserting on the CI runner's
/// load. So the crate's 15 ms per-action budget is held against the p99.9,
/// where it has three orders of magnitude of margin and any systematic
/// degradation shows up immediately, and a separate, looser ceiling catches
/// what a maximum is actually for: a request that *stalls*, which is what an
/// inline collateral fetch would look like.
#[test]
fn ten_thousand_crafted_configurations_grow_linearly_and_never_slow_a_request() {
    const N: usize = 10_000;
    /// The crate's per-action budget, the same 15 ms `bench --composed` is
    /// measured against.
    const BUDGET: Duration = Duration::from_millis(15);
    /// What a *stall* looks like: a network round trip that found its way onto
    /// the request path. Nothing in the measure path may take this long even
    /// once, however loaded the host.
    const STALL: Duration = Duration::from_millis(250);

    let sink = Arc::new(RecordingSink::default());
    let pipeline = offline_pipeline(Arc::clone(&sink));

    let mut costs: Vec<Duration> = Vec::with_capacity(N);
    for i in 0..N {
        // Distinct per request, and a valid header value.
        let head = head_carrying(&STANDARD.encode(format!("craft-{i:08}")));
        let started = Instant::now();
        pipeline.measure(&head);
        costs.push(started.elapsed());
    }

    let worst = *costs.iter().max().expect("N > 0");
    assert!(
        worst < STALL,
        "one request's measurement stalled for {worst:?}; nothing in the \
         measure path may block, and hook cost is time-to-first-byte cost"
    );
    costs.sort_unstable();
    let p999 = costs[N - N / 1000];
    assert!(
        p999 < BUDGET,
        "the 99.9th-percentile measurement cost {p999:?}, over the crate's \
         {BUDGET:?} per-action budget — an agent can make the hook expensive"
    );

    // The anti-superlinearity check, against the meter alone. See this test's
    // doc comment for why it cannot be taken over the whole pipeline: the
    // mutation it exists to catch survives that version.
    let meter = LinkabilityMeter::new(Duration::from_secs(3600), 7);
    let mut first_decile = Duration::ZERO;
    let mut last_decile = Duration::ZERO;
    for i in 0..N {
        let config = TcbConfig {
            attributes: [("td_attributes".to_string(), format!("{i:016x}"))]
                .into_iter()
                .collect(),
        };
        let started = Instant::now();
        meter.observe(&config);
        let took = started.elapsed();
        if i < N / 10 {
            first_decile += took;
        } else if i >= N - N / 10 {
            last_decile += took;
        }
    }
    assert!(
        last_decile < first_decile * 3,
        "the meter's per-observation cost grows with its store: the first {} \
         observations took {first_decile:?} and the last {} took \
         {last_decile:?}. An agent minting distinct configurations can then \
         drive the hook's cost, and hook cost is time-to-first-byte cost",
        N / 10,
        N / 10
    );

    let found = sink.entries();
    assert_eq!(found.len(), N, "every request must produce a finding");

    // Linear in distinct configurations, exactly — every crafted request is
    // its own set of one, which is the honest reading of a fleet where every
    // agent runs a different configuration.
    let last = found.last().expect("N > 0");
    assert_eq!(
        last.json["observation"]["distinct_configs"], N,
        "the meter must have seen {N} distinct configurations: {}",
        last.rendered
    );
    assert_eq!(
        last.json["observation"]["set_size"], 1,
        "a configuration nobody else shares is a set of one"
    );
    assert_eq!(last.json["observation"]["total_sessions"], N);

    // ...and nothing per session. The same configuration ten thousand times
    // over adds one entry, not ten thousand: the store cannot answer "has
    // this agent been here before", and this is what that refusal looks like
    // from outside the crate.
    let repeat_sink = Arc::new(RecordingSink::default());
    let repeat = offline_pipeline(Arc::clone(&repeat_sink));
    let same = head_carrying(&STANDARD.encode("craft-identical"));
    for _ in 0..N {
        repeat.measure(&same);
    }
    let found = repeat_sink.entries();
    let last = found.last().expect("N > 0");
    assert_eq!(
        last.json["observation"]["distinct_configs"], 1,
        "repeating one configuration must not grow the store per session"
    );
    assert_eq!(last.json["observation"]["set_size"], N);
}

/// The crafted-configuration case over a real socket, so the sweep above is
/// not the only thing standing behind it.
#[tokio::test]
async fn a_crafted_configuration_still_forwards_and_is_measured() {
    let gw = spawn_hostile_gateway_with(|_real| Arc::new(CraftingVerifier)).await;
    assert_eq!(
        misbehave(&gw, "/crafted", Misbehaviour::ReplayedQuote)
            .await
            .unwrap(),
        "echo:/crafted"
    );
    let found = gw.only_finding();
    assert!(
        first_line(&found).contains("VERIFIED"),
        "{}",
        found.rendered
    );
    assert!(found.has_observation, "{}", found.rendered);
}

/// **The finding this suite exists to surface.** An agent that replays one
/// configuration manufactures its own anonymity set.
///
/// `set_size` counts *sessions* on a configuration, not agents — the meter
/// has no notion of an agent and refuses to acquire one, which is the whole
/// design. So a single counterparty presenting the same attestation twelve
/// times is reported exactly as twelve agents sharing a configuration would
/// be, and once the corpus passes [`MIN_MEANINGFUL_SESSIONS`] the
/// `NOT EVIDENCE` caveat — the one defence that could have flagged it —
/// switches itself off.
///
/// This is not a bug in the meter; it is the cost of refusing to correlate,
/// and it is the reason `README.md` says a set size is an upper bound on
/// anonymity rather than a measurement of it. The test pins the behaviour so
/// that anyone who "fixes" it has to confront what they would be building:
/// distinguishing these two cases means telling sessions apart, which is the
/// dossier this tool exists to warn about.
#[test]
fn one_agent_replaying_one_configuration_manufactures_its_own_anonymity_set() {
    // The literal, not only the constant. Everything below is phrased in terms
    // of `MIN_MEANINGFUL_SESSIONS`, and assertions phrased that way hold for
    // *any* value of it — lowering the threshold to 2 leaves every one of them
    // green while making this test's own claim about README.md false.
    // (`finding.rs`'s `the_caveat_boundary_is_exact` catches that mutation
    // too; this is here so the failure names the document that goes stale.)
    assert_eq!(
        MIN_MEANINGFUL_SESSIONS, 10,
        "README.md's gateway section quotes this threshold; update it too"
    );
    let sessions = MIN_MEANINGFUL_SESSIONS + 2;
    let sink = Arc::new(RecordingSink::default());
    let pipeline = offline_pipeline(Arc::clone(&sink));
    let same = head_carrying(&STANDARD.encode("one-agent-many-sessions"));
    for _ in 0..sessions {
        pipeline.measure(&same);
    }

    let found = sink.entries();
    let last = found.last().expect("at least one finding");
    assert_eq!(last.json["observation"]["set_size"], sessions);
    assert_eq!(last.json["observation"]["distinct_configs"], 1);
    assert!(
        last.rendered
            .contains(&format!("{sessions} of {sessions} sessions")),
        "{}",
        last.rendered
    );
    // The caveat is gone, because the corpus is "big enough" — and the corpus
    // is one agent.
    assert!(
        !last.rendered.contains("NOT EVIDENCE"),
        "the caveat is expected to have switched off here; if it has not, \
         MIN_MEANINGFUL_SESSIONS changed and README.md's account of this is \
         now wrong: {}",
        last.rendered
    );
    // The boundary itself, so this test keeps meaning what it says: below the
    // threshold the caveat is present, which is the only thing that makes its
    // absence above the threshold a statement.
    let below = &found[(MIN_MEANINGFUL_SESSIONS - 2) as usize];
    assert!(
        below.rendered.contains("NOT EVIDENCE"),
        "the caveat must be present below the threshold, or its absence \
         above the threshold says nothing: {}",
        below.rendered
    );
}

// ---------------------------------------------------------------------
// The scrape endpoint
// ---------------------------------------------------------------------

/// Half one: the metrics listener answers, and what it answers with is the
/// counters Task 6 registered and Task 7 records to.
///
/// Before this task nothing ever read them. They were registered, incremented
/// on every request, and exposed to nobody for the whole of phase 1 — so
/// Task 6's label-cardinality argument and Task 7's `WhyKind` classification
/// were both unobservable claims. This is the test that makes them
/// observable.
#[tokio::test]
async fn the_metrics_listener_answers_on_its_own_port() {
    let gw = spawn_hostile_gateway().await;
    // Three different verdict classes, so the scrape has something to
    // distinguish: an agent's malformed quote, a missing attestation, and a
    // real quote we hold no collateral for.
    for how in [
        Misbehaviour::MalformedQuote,
        Misbehaviour::NoAttestation,
        Misbehaviour::ReplayedQuote,
    ] {
        misbehave(&gw, "/x", how).await.unwrap();
    }

    let (status, body) = get(&gw.metrics, METRICS_PATH).await.unwrap();
    assert_eq!(status, 200, "{body}");

    // Every verdict class reached the counter, under its own label.
    assert!(
        body.contains("gateway_requests_total{verdict=\"invalid\"} 1"),
        "{body}"
    );
    assert!(
        body.contains("gateway_requests_total{verdict=\"unverified\"} 2"),
        "the missing attestation and the uncached platform are both \
         `unverified`: {body}"
    );
    // Task 7's classification, visible at last: "no attestation" is a gateway
    // gap that is none of the four named causes, and the cold cache is.
    assert!(
        body.contains("gateway_unverified_total{why_kind=\"collateral_absent\"} 1"),
        "{body}"
    );
    assert!(
        body.contains("gateway_unverified_total{why_kind=\"other\"} 1"),
        "{body}"
    );

    // Task 6's cardinality argument, made checkable rather than asserted.
    // Neither the FMSPC the finding carries nor any free text may appear.
    assert!(
        !body.contains(TDX_FMSPC),
        "an FMSPC reached the scrape output: {body}"
    );
    assert!(
        !body.contains("no collateral cached"),
        "a free-text reason reached the scrape output: {body}"
    );
}

/// Half two, and the half that is easy to lose: `/metrics` on the **proxy**
/// port is still just a request, and the upstream still answers it.
///
/// A `/metrics` route on the proxy port would carve that path out of the
/// upstream's URL space — an API that served its own `/metrics` would find
/// the gateway had silently taken it. Asserting only that the metrics
/// listener answers would leave that regression completely invisible, which
/// is why both halves exist.
#[tokio::test]
async fn the_proxy_port_still_forwards_a_metrics_request() {
    let gw = spawn_hostile_gateway().await;
    let (status, body) = get(&gw.proxy, METRICS_PATH).await.unwrap();
    assert_eq!(status, 200);
    assert_eq!(
        body, "echo:/metrics",
        "the proxy answered /metrics itself instead of forwarding it; the \
         upstream can no longer serve its own metrics"
    );
    // And it was measured like any other request, rather than special-cased
    // out of the pipeline.
    assert_eq!(gw.findings().len(), 1);
}

/// The scrape listener is a scrape listener, not a second way into the
/// upstream. A metrics port that forwarded would be an unauthenticated proxy
/// on a port nobody thinks of as one.
#[tokio::test]
async fn the_metrics_listener_never_forwards_to_the_upstream() {
    let gw = spawn_hostile_gateway().await;
    for path in ["/", "/agent/act", "/metrics/../agent"] {
        let (status, body) = get(&gw.metrics, path).await.unwrap();
        assert_eq!(status, 404, "path {path} was served: {body}");
        assert!(
            !body.starts_with("echo:"),
            "the metrics listener forwarded {path} to the upstream: {body}"
        );
    }
    assert!(
        gw.findings().is_empty(),
        "a scrape was measured as though it were an agent request"
    );
}

/// The scrape endpoint cannot take the proxy down, and the proxy does not
/// need it. Both directions, because "separate listeners" is only a claim
/// until something depends on one of them being gone.
#[tokio::test]
async fn the_proxy_serves_whether_or_not_anything_scrapes_it() {
    let gw = spawn_hostile_gateway().await;
    // Never scraped: the proxy works.
    assert_eq!(
        misbehave(&gw, "/before", Misbehaviour::NoAttestation)
            .await
            .unwrap(),
        "echo:/before"
    );
    // Scraped, including on paths it refuses: the proxy still works.
    for path in [METRICS_PATH, "/nope"] {
        let _ = get(&gw.metrics, path).await;
    }
    assert_eq!(
        misbehave(&gw, "/after", Misbehaviour::MalformedQuote)
            .await
            .unwrap(),
        "echo:/after"
    );
    assert_eq!(gw.findings().len(), 2);
}

// ---------------------------------------------------------------------
// The PPID, from outside the crate — and the honest limit on that
// ---------------------------------------------------------------------

/// Every *non-verified* finding this suite can produce, checked across all
/// three output channels for a hardware identifier. Named for exactly that,
/// because the general claim is not one this test can make.
///
/// The earlier name — "no hostile input puts a hardware identifier into any
/// output" — promised more than the harness delivers, and review was right to
/// call it. `spawn_hostile_gateway` builds the real verifier over a cold cache
/// pointed at a dead port with `never_refreshes`, and no integration test can
/// reach `dcap_qvl::verify::verify` at all (see the module docs). **No
/// verified report is ever constructed here, so there is no hardware
/// identifier in existence to leak.** `verified_verdict` could be mutated to
/// copy the serial into every TCB attribute and this test would stay green.
///
/// What it does hold is still worth holding, and nothing else holds it: the
/// six hostile inputs drive the `Invalid` and `Unverified` renderings — free
/// text from `SourceError`, from `Quote::parse` and from the collateral
/// lookup, all of it derived from bytes an agent chose — through `render`,
/// `to_json` and the scrape encoder. That is a regression check on the
/// output layer for the verdicts this harness can actually produce.
///
/// The verified path is out of reach from here and is pinned in-crate, where
/// the clock can be held inside the collateral's validity window, by
/// `verify.rs`'s `a_real_verified_report_leaks_none_of_its_hardware_identifier`
/// — which runs a genuine verification, recovers the real serial from the
/// report at runtime, and asserts it appears in neither output form in any of
/// seven byte shapes. **Do not "strengthen" this test by handing it a
/// fabricated report.** A serial invented by a stub proves nothing about the
/// one real hardware hands over, and the honest name is worth more than the
/// false coverage.
#[tokio::test]
async fn no_unverified_finding_carries_a_hardware_identifier_in_any_output_channel() {
    let gw = spawn_hostile_gateway().await;
    for how in ALL_MISBEHAVIOURS {
        misbehave(&gw, "/leak-check", how).await.unwrap();
    }

    for record in gw.findings() {
        let rendered = record.rendered.to_lowercase();
        assert!(!rendered.contains("ppid"), "{rendered}");
        assert!(
            !rendered.contains("fingerprint"),
            "a per-counterparty key reached a rendered finding: {rendered}"
        );
        let json = serde_json::to_string(&record.json)
            .expect("a finding's JSON serializes")
            .to_lowercase();
        assert!(!json.contains("ppid"), "{json}");
        assert!(!json.contains("fingerprint"), "{json}");
    }

    let (_, body) = get(&gw.metrics, METRICS_PATH).await.unwrap();
    assert!(!body.to_lowercase().contains("ppid"), "{body}");
}
