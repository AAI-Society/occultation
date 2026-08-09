//! Where six modules become a running gateway — and where fail-open stops
//! being a property of each of them and starts being a property of the whole.
//!
//! # Fail-open is absolute, and it is enforced stage by stage
//!
//! Task 1 established the outer half at the type level: `proxy::handle` and
//! `proxy::forward` return `Result<_, std::convert::Infallible>`, so no `?`
//! and no `Err` can compile on the request path, and the hook is additionally
//! wrapped in `catch_unwind`. That outer guard is the last resort, and on its
//! own it is not enough: a panic anywhere in the measure path would unwind
//! straight past every later stage, so one panicking component would cost the
//! request its whole finding — the request still forwarded, but the operator
//! told nothing at all about why nothing was measured.
//!
//! So every stage here runs inside its own [`stage`] guard. A panicking
//! source still yields a finding; a panicking verifier still yields a
//! finding; a panicking meter still yields a finding, with the anonymity
//! block absent and the meter named in [`Measured::skipped`]; a panicking
//! metrics recorder still lets the finding reach the sink. This is the
//! "check inside the function, not just at its entrance" lesson from Task 5's
//! review, applied to a pipeline: the entrance is guarded by Task 1, and the
//! body has to be guarded too.
//!
//! `measure` therefore returns `()`. There is nothing for a caller to handle,
//! because by construction nothing here can fail in a way a caller could act
//! on — the request was forwarded before this code ran at all.
//!
//! # An unverified quote yields no observation, structurally
//!
//! [`Finding`]'s fields are `pub`, so `Finding { verdict: Unverified { .. },
//! observation: Some(..) }` compiles. Task 6 defends against that at the
//! rendering end by conjoining the anonymity gate. This module defends
//! against it at the *producing* end: the observation is computed inside the
//! `QuoteVerdict::Verified` arm of a `match` on the verdict and nowhere else,
//! so there is no code path on which an unverified verdict has an
//! `Observation` to attach. See
//! `no_verdict_but_verified_can_carry_an_observation`.
//!
//! # Nothing slow, nothing async, and no cache on the request path
//!
//! `Hooks::on_request` is a synchronous `Fn`, so there is no `.await` here
//! for a network call to hide in. Beyond that, this module never names
//! `CollateralCache`: the only collateral-shaped thing it holds is a
//! [`RefreshQueue`], which can schedule and cannot fetch. `refresh.rs` owns
//! the cache handle that fetches, on a background task.
//! `the_request_path_cannot_name_the_cache_or_await_anything` pins that the
//! non-test source of this file contains none of the tokens that would let
//! that change quietly — including `rotate_if_due`, which belongs on a timer
//! and not on a request (Task 5's review: a per-request rotation whose clock
//! reset regressed would report `set_size: 1` forever, the failure direction
//! that overstates anonymity).
//!
//! # The PPID
//!
//! Nothing here obtains a `dcap_qvl` report. This module sees
//! [`QuoteVerdict`], [`SessionBinding`] and [`Observation`], all three of
//! which Task 4's boundary and Task 5's meter already hand over with the
//! hardware serial destroyed. There is no field on any of them that could
//! carry one, and `the_pipeline_hands_nothing_to_a_debug_formatter` keeps the
//! non-test code free of the `{:?}` family that made the leak reachable in
//! `verify.rs`'s first draft.

use crate::gateway::finding::{Finding, Metrics};
use crate::gateway::meter::{LinkabilityMeter, Observation};
use crate::gateway::proxy::{Hooks, RequestHead};
use crate::gateway::refresh::RefreshQueue;
use crate::gateway::source::{AttestationSource, RawAttestation, SessionBinding};
use crate::gateway::verify::{QuoteVerdict, QuoteVerifier, TcbConfig};
use std::fmt::Write as _;
use std::panic::AssertUnwindSafe;
use std::sync::Arc;

/// The five stages, named once. These strings reach an operator (in
/// [`Measured::skipped`] and in the log line a panicking stage writes), and
/// the integration suite asserts on them, so they are constants rather than
/// literals repeated at each site.
pub const STAGE_SOURCE: &str = "attestation source";
/// See [`STAGE_SOURCE`].
pub const STAGE_VERIFIER: &str = "quote verifier";
/// See [`STAGE_SOURCE`].
pub const STAGE_METER: &str = "linkability meter";
/// See [`STAGE_SOURCE`].
pub const STAGE_METRICS: &str = "metrics";
/// See [`STAGE_SOURCE`].
pub const STAGE_SINK: &str = "finding sink";

/// The `why` a finding carries when the source itself came apart. Deliberately
/// avoids the vocabulary [`crate::gateway::finding`]'s `WhyKind::classify`
/// keys on — this is not a collateral problem and not a provisioning-service
/// problem, and mislabelling it would send an operator to fix the wrong thing.
pub(crate) const SOURCE_PANICKED: &str =
    "the attestation source panicked before a quote could be read, so this \
     request was forwarded without being measured";

/// See [`SOURCE_PANICKED`]: with the source gone, its own claim about session
/// binding is gone too, and `Bound` must never be the fallback.
pub(crate) const BINDING_UNKNOWN: &str =
    "the attestation source panicked, so nothing is known about whether a \
     quote was bound to this session";

pub(crate) const NO_ATTESTATION: &str =
    "no attestation accompanied this request, so there was nothing to verify";

pub(crate) const VERIFIER_PANICKED: &str =
    "the quote verifier panicked, so this request was forwarded without a verdict";

/// Verify a quote. The seam Task 4's [`QuoteVerifier`] plugs into, and the one
/// a fault-injection suite substitutes for.
pub trait VerifyQuote: Send + Sync {
    fn verify(&self, raw: &RawAttestation) -> QuoteVerdict;
}

impl VerifyQuote for QuoteVerifier {
    fn verify(&self, raw: &RawAttestation) -> QuoteVerdict {
        QuoteVerifier::verify(self, raw)
    }
}

/// Count one session against a configuration. Task 5's
/// [`LinkabilityMeter`] plugs in here.
pub trait Measure: Send + Sync {
    fn observe(&self, config: &TcbConfig) -> Observation;
}

impl Measure for LinkabilityMeter {
    fn observe(&self, config: &TcbConfig) -> Observation {
        LinkabilityMeter::observe(self, config)
    }
}

/// Increment the bounded counters. Task 6's [`Metrics`] plugs in here.
pub trait RecordMetrics: Send + Sync {
    fn record(&self, finding: &Finding);
}

impl RecordMetrics for Metrics {
    fn record(&self, finding: &Finding) {
        Metrics::record(self, finding)
    }
}

/// Where a finished measurement goes.
///
/// The rendering stage as well as the delivery one: a sink is handed the
/// [`Measured`] and decides what to do with it, so [`Finding::render`] runs
/// inside the sink's [`stage`] guard rather than outside it. A rendering
/// fault is therefore a sink fault, guarded like every other stage and
/// exercised by the same injected fault.
pub trait FindingSink: Send + Sync {
    fn emit(&self, measured: &Measured);
}

/// One request's measurement: the finding, plus the stages that panicked on
/// the way to producing it.
///
/// `skipped` exists because a `Finding` alone cannot say "the meter came
/// apart". A verified quote whose meter panicked renders exactly like a
/// verified quote nobody asked to measure — no anonymity block in either case
/// — and an operator has to be able to tell those apart. Rather than widen
/// Task 6's deliberately narrow `Finding` (three fields, hand-written
/// renderers, no blanket derives), the skip list travels alongside it.
pub struct Measured {
    pub finding: Finding,
    /// Stage names, in pipeline order. Empty on a clean request.
    pub skipped: Vec<&'static str>,
}

impl Measured {
    /// The operator-facing rendering: Task 6's finding, plus a line naming
    /// anything that was skipped. Never panics — `Finding::render` is a fixed
    /// set of format strings over data this crate owns, and the join below is
    /// over `&'static str`.
    pub fn render(&self) -> String {
        let mut out = self.finding.render();
        if !self.skipped.is_empty() {
            let _ = writeln!(out, "  skipped           {}", self.skipped.join(", "));
        }
        out
    }
}

/// The level [`LogSink`] emits at.
///
/// Exported because with no metrics endpoint yet, the log is the gateway's
/// *only* output channel, and a default log filter below this level is the
/// difference between a gateway that reports findings and one that reports
/// nothing at all. `src/bin/gateway.rs` derives its default filter from this
/// constant rather than repeating a level literal that could drift from it.
pub const SINK_LOG_LEVEL: log::Level = log::Level::Info;

/// The default sink: write the finding to the log.
pub struct LogSink;

impl FindingSink for LogSink {
    fn emit(&self, measured: &Measured) {
        log::log!(SINK_LOG_LEVEL, "{}", measured.render().trim_end());
    }
}

/// Run one pipeline stage, turning a panic into `None`.
///
/// This is the inner half of the fail-open guarantee. Task 1's `catch_unwind`
/// around the whole hook keeps a panic from dropping the connection; this one
/// keeps a panic from costing the request every stage that had not run yet.
fn stage<T>(name: &'static str, f: impl FnOnce() -> T) -> Option<T> {
    match std::panic::catch_unwind(AssertUnwindSafe(f)) {
        Ok(value) => Some(value),
        Err(_) => {
            log::error!(
                "gateway pipeline stage `{name}` panicked; the request was already \
                 forwarded, and the finding records the stage as skipped"
            );
            None
        }
    }
}

/// The assembled gateway: the five components, plus the one non-blocking
/// handle onto work that happens somewhere else.
///
/// Fields are trait objects and `pub` so the composition root (and a
/// fault-injection suite) can substitute any of them. Nothing here is
/// `async`, and nothing here owns a network client.
pub struct Pipeline {
    pub source: Arc<dyn AttestationSource>,
    pub verifier: Arc<dyn VerifyQuote>,
    pub meter: Arc<dyn Measure>,
    pub metrics: Arc<dyn RecordMetrics>,
    pub sink: Arc<dyn FindingSink>,
    /// Schedules collateral fetches; cannot perform one. See `refresh.rs`.
    pub refresh: RefreshQueue,
}

impl Pipeline {
    /// Measure one already-forwarded request.
    ///
    /// Order: extract, verify, observe, record, emit. `record` runs before
    /// `emit` so that the [`Measured`] the sink receives can name *every*
    /// stage that was skipped — with the sink first, a metrics panic could
    /// only ever be logged, never reported to the thing whose job is
    /// reporting. The rendering the sink performs is the "render" step; it
    /// runs inside the sink's guard, so a rendering fault is caught like any
    /// other.
    ///
    /// Returns nothing, and can return nothing: there is no failure here that
    /// a caller could act on, because the response has already gone.
    pub fn measure(&self, head: &RequestHead) {
        let mut skipped: Vec<&'static str> = Vec::new();

        // Extract. `session_binding` shares this stage's guard because it is
        // the same object's claim about the same transport: a source that
        // panics on `extract` cannot be trusted to answer the other question
        // either, and the fallback below is `Unbound`, never `Bound`.
        let extracted = stage(STAGE_SOURCE, || {
            (self.source.extract(head), self.source.session_binding())
        });

        let (verdict, binding) = match extracted {
            None => {
                skipped.push(STAGE_SOURCE);
                (
                    QuoteVerdict::Unverified {
                        why: SOURCE_PANICKED.to_string(),
                    },
                    SessionBinding::Unbound {
                        why: BINDING_UNKNOWN,
                    },
                )
            }
            // The agent's fault: a header that is there but is not a quote.
            Some((Err(err), binding)) => (
                QuoteVerdict::Invalid {
                    reason: format!("the attestation could not be decoded: {err}"),
                },
                binding,
            ),
            Some((Ok(None), binding)) => (
                QuoteVerdict::Unverified {
                    why: NO_ATTESTATION.to_string(),
                },
                binding,
            ),
            Some((Ok(Some(raw)), binding)) => {
                let verdict = match stage(STAGE_VERIFIER, || self.verifier.verify(&raw)) {
                    Some(verdict) => verdict,
                    None => {
                        skipped.push(STAGE_VERIFIER);
                        QuoteVerdict::Unverified {
                            why: VERIFIER_PANICKED.to_string(),
                        }
                    }
                };
                // `Unverified` is *our* gap, and the commonest cause of it is
                // a cold or aged collateral cache. Queue this platform so the
                // next request for it can be checked. Scheduling is a
                // `try_send`; this request does not wait for the fetch, and
                // never learns whether it happened.
                //
                // Only `Unverified`. A `Verified` quote needs nothing, and an
                // `Invalid` one is either not a quote at all or has failed the
                // chain against collateral we already hold — fetching more of
                // it would be an agent-triggered request amplifier pointed at
                // the provisioning service.
                if matches!(verdict, QuoteVerdict::Unverified { .. }) {
                    self.refresh.schedule(raw.bytes);
                }
                (verdict, binding)
            }
        };

        // Observe — inside the `Verified` arm and nowhere else. An unverified
        // quote yields no trustworthy configuration, so it must yield no
        // observation; this `match` is why no other combination exists to
        // construct.
        let observation = match &verdict {
            QuoteVerdict::Verified { config, .. } => {
                match stage(STAGE_METER, || self.meter.observe(config)) {
                    Some(observation) => Some(observation),
                    None => {
                        skipped.push(STAGE_METER);
                        None
                    }
                }
            }
            QuoteVerdict::Invalid { .. } | QuoteVerdict::Unverified { .. } => None,
        };

        let finding = Finding {
            verdict,
            binding,
            observation,
        };

        if stage(STAGE_METRICS, || self.metrics.record(&finding)).is_none() {
            skipped.push(STAGE_METRICS);
        }

        let measured = Measured { finding, skipped };
        if stage(STAGE_SINK, || self.sink.emit(&measured)).is_none() {
            log::error!(
                "the finding sink panicked; this request's finding was lost, but the \
                 request itself was forwarded before any of this ran"
            );
        }
    }
}

impl Hooks {
    /// Wire a pipeline into the proxy's measurement hook.
    ///
    /// `proxy.rs` still knows nothing about the verifier or the meter — it
    /// sees a boxed `Fn(&RequestHead)`, exactly as Task 1 defined it. The
    /// dependency runs the other way: this module knows about `Hooks`.
    pub fn from_pipeline(pipeline: Arc<Pipeline>) -> Hooks {
        Hooks {
            on_request: Box::new(move |head| pipeline.measure(head)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gateway::source::SourceError;
    use crate::gateway::verify::Platform;
    use hyper::HeaderMap;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Mutex;

    fn head() -> RequestHead {
        RequestHead {
            method: hyper::Method::GET,
            path_and_query: "/x".to_string(),
            headers: HeaderMap::new(),
        }
    }

    fn a_config() -> TcbConfig {
        TcbConfig {
            attributes: [("fmspc".to_string(), "b0c06f000000".to_string())]
                .into_iter()
                .collect(),
        }
    }

    fn verified() -> QuoteVerdict {
        QuoteVerdict::Verified {
            platform: Platform::TdxV10,
            tcb_status: "UpToDate".to_string(),
            advisories: vec![],
            config: a_config(),
        }
    }

    // --- stub components -------------------------------------------------

    /// A source that answers however the test says, and counts its calls.
    struct StubSource {
        answer: fn() -> Result<Option<RawAttestation>, SourceError>,
        calls: AtomicUsize,
    }

    impl StubSource {
        fn new(answer: fn() -> Result<Option<RawAttestation>, SourceError>) -> Arc<StubSource> {
            Arc::new(StubSource {
                answer,
                calls: AtomicUsize::new(0),
            })
        }
    }

    impl AttestationSource for StubSource {
        fn extract(&self, _head: &RequestHead) -> Result<Option<RawAttestation>, SourceError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            (self.answer)()
        }
        fn session_binding(&self) -> SessionBinding {
            SessionBinding::Unbound { why: "stub" }
        }
        fn name(&self) -> &'static str {
            "stub"
        }
    }

    fn quote_bytes() -> Result<Option<RawAttestation>, SourceError> {
        Ok(Some(RawAttestation {
            bytes: vec![0xab; 16],
        }))
    }

    struct StubVerifier {
        answer: fn() -> QuoteVerdict,
        calls: AtomicUsize,
    }

    impl VerifyQuote for StubVerifier {
        fn verify(&self, _raw: &RawAttestation) -> QuoteVerdict {
            self.calls.fetch_add(1, Ordering::SeqCst);
            (self.answer)()
        }
    }

    fn stub_verifier(answer: fn() -> QuoteVerdict) -> Arc<StubVerifier> {
        Arc::new(StubVerifier {
            answer,
            calls: AtomicUsize::new(0),
        })
    }

    struct StubMeter {
        panics: bool,
        calls: AtomicUsize,
    }

    impl Measure for StubMeter {
        fn observe(&self, _config: &TcbConfig) -> Observation {
            self.calls.fetch_add(1, Ordering::SeqCst);
            assert!(!self.panics, "injected meter panic");
            Observation {
                set_size: 1,
                total_sessions: 1,
                distinct_configs: 1,
                varying_attributes: vec![],
            }
        }
    }

    fn stub_meter(panics: bool) -> Arc<StubMeter> {
        Arc::new(StubMeter {
            panics,
            calls: AtomicUsize::new(0),
        })
    }

    struct StubMetrics {
        panics: bool,
        calls: AtomicUsize,
    }

    impl RecordMetrics for StubMetrics {
        fn record(&self, _finding: &Finding) {
            self.calls.fetch_add(1, Ordering::SeqCst);
            assert!(!self.panics, "injected metrics panic");
        }
    }

    fn stub_metrics(panics: bool) -> Arc<StubMetrics> {
        Arc::new(StubMetrics {
            panics,
            calls: AtomicUsize::new(0),
        })
    }

    /// Records the rendering, the skip list and whether an anonymity number
    /// was carried — then optionally panics, so "the sink came apart" and
    /// "the sink saw nothing" are distinguishable.
    struct RecordingSink {
        seen: Mutex<Vec<(String, Vec<&'static str>, bool)>>,
        panic_after_recording: bool,
    }

    impl FindingSink for RecordingSink {
        fn emit(&self, measured: &Measured) {
            let entry = (
                measured.render(),
                measured.skipped.clone(),
                measured.finding.observation.is_some(),
            );
            if let Ok(mut seen) = self.seen.lock() {
                seen.push(entry);
            }
            assert!(!self.panic_after_recording, "injected sink panic");
        }
    }

    impl RecordingSink {
        fn new(panic_after_recording: bool) -> Arc<RecordingSink> {
            Arc::new(RecordingSink {
                seen: Mutex::new(Vec::new()),
                panic_after_recording,
            })
        }
        fn only(&self) -> (String, Vec<&'static str>, bool) {
            let seen = self.seen.lock().expect("the recording sink lock is sound");
            assert_eq!(seen.len(), 1, "expected exactly one finding");
            seen[0].clone()
        }
    }

    /// Assemble a pipeline from parts, defaulting everything the caller does
    /// not care about to a working stub.
    struct Parts {
        source: Arc<dyn AttestationSource>,
        verifier: Arc<dyn VerifyQuote>,
        meter: Arc<dyn Measure>,
        metrics: Arc<dyn RecordMetrics>,
        sink: Arc<RecordingSink>,
    }

    impl Parts {
        fn new() -> Parts {
            Parts {
                source: StubSource::new(quote_bytes),
                verifier: stub_verifier(verified),
                meter: stub_meter(false),
                metrics: stub_metrics(false),
                sink: RecordingSink::new(false),
            }
        }
        fn build(&self) -> Pipeline {
            Pipeline {
                source: Arc::clone(&self.source),
                verifier: Arc::clone(&self.verifier),
                meter: Arc::clone(&self.meter),
                metrics: Arc::clone(&self.metrics),
                sink: Arc::clone(&self.sink) as Arc<dyn FindingSink>,
                refresh: RefreshQueue::never_refreshes(),
            }
        }
    }

    #[test]
    fn a_clean_request_skips_nothing_and_carries_an_anonymity_number() {
        let parts = Parts::new();
        parts.build().measure(&head());
        let (rendered, skipped, has_observation) = parts.sink.only();
        assert!(skipped.is_empty(), "{skipped:?}");
        assert!(has_observation);
        assert!(rendered.contains("VERIFIED"), "{rendered}");
        assert!(rendered.contains("anonymity set"), "{rendered}");
        assert!(
            !rendered.contains("skipped"),
            "a clean request must not claim anything was skipped: {rendered}"
        );
    }

    #[test]
    fn a_panicking_source_still_produces_a_finding_that_names_it() {
        let mut parts = Parts::new();
        parts.source = StubSource::new(|| panic!("injected source panic"));
        parts.build().measure(&head());
        let (rendered, skipped, has_observation) = parts.sink.only();
        assert_eq!(skipped, vec![STAGE_SOURCE]);
        assert!(!has_observation);
        assert!(rendered.contains("UNVERIFIED"), "{rendered}");
        assert!(rendered.contains(STAGE_SOURCE), "{rendered}");
        // The fallback must not claim the transport bound anything.
        assert!(rendered.contains("session binding   NONE"), "{rendered}");
    }

    /// A header that is present but undecodable is the *agent's* problem, not
    /// ours. Reporting it as `Unverified` would blame the gateway's own
    /// collateral pipeline for a malformed request, and would land in the
    /// `gateway_unverified_total` counter an operator alerts on.
    #[test]
    fn a_source_error_is_the_agents_fault_and_renders_as_invalid() {
        let mut parts = Parts::new();
        parts.source = StubSource::new(|| Err(SourceError::NotUtf8));
        parts.build().measure(&head());
        let (rendered, skipped, _) = parts.sink.only();
        assert!(skipped.is_empty(), "an error is not a panic: {skipped:?}");
        assert!(rendered.contains("INVALID"), "{rendered}");
        assert!(!rendered.contains("UNVERIFIED"), "{rendered}");
    }

    #[test]
    fn a_request_with_no_attestation_is_unverified_and_says_so() {
        let mut parts = Parts::new();
        parts.source = StubSource::new(|| Ok(None));
        parts.build().measure(&head());
        let (rendered, skipped, has_observation) = parts.sink.only();
        assert!(skipped.is_empty());
        assert!(!has_observation);
        assert!(rendered.contains("UNVERIFIED"), "{rendered}");
        assert!(rendered.contains("no attestation"), "{rendered}");
    }

    #[test]
    fn a_panicking_verifier_still_produces_a_finding_that_names_it() {
        let mut parts = Parts::new();
        parts.verifier = stub_verifier(|| panic!("injected verifier panic"));
        parts.build().measure(&head());
        let (rendered, skipped, has_observation) = parts.sink.only();
        assert_eq!(skipped, vec![STAGE_VERIFIER]);
        assert!(!has_observation, "a panicked verifier verifies nothing");
        assert!(rendered.contains("UNVERIFIED"), "{rendered}");
        assert!(rendered.contains(STAGE_VERIFIER), "{rendered}");
    }

    /// The one that only an inner guard catches. With the meter's panic
    /// caught only by Task 1's outer `catch_unwind`, the unwind takes the
    /// metrics increment and the sink with it and the operator hears nothing.
    #[test]
    fn a_panicking_meter_costs_the_number_and_nothing_else() {
        let parts_metrics = stub_metrics(false);
        let mut parts = Parts::new();
        parts.meter = stub_meter(true);
        parts.metrics = Arc::clone(&parts_metrics) as Arc<dyn RecordMetrics>;
        parts.build().measure(&head());
        let (rendered, skipped, has_observation) = parts.sink.only();
        assert_eq!(skipped, vec![STAGE_METER]);
        assert!(!has_observation);
        // The verdict survives: the quote really was verified, and saying
        // otherwise would misreport a working verifier as a broken one.
        assert!(rendered.contains("VERIFIED"), "{rendered}");
        assert!(!rendered.contains("anonymity set"), "{rendered}");
        assert!(rendered.contains(STAGE_METER), "{rendered}");
        assert_eq!(
            parts_metrics.calls.load(Ordering::SeqCst),
            1,
            "the stages after the meter must still run"
        );
    }

    #[test]
    fn a_panicking_metrics_recorder_still_lets_the_finding_reach_the_sink() {
        let mut parts = Parts::new();
        parts.metrics = stub_metrics(true);
        parts.build().measure(&head());
        let (rendered, skipped, _) = parts.sink.only();
        assert_eq!(skipped, vec![STAGE_METRICS]);
        assert!(
            rendered.contains(STAGE_METRICS),
            "the sink must be told which stage was lost: {rendered}"
        );
    }

    /// The last stage has nothing after it to observe the panic, so this
    /// asserts the only thing left: `measure` returns normally rather than
    /// unwinding into Task 1's outer guard.
    #[test]
    fn a_panicking_sink_does_not_unwind_out_of_measure() {
        let mut parts = Parts::new();
        parts.sink = RecordingSink::new(true);
        parts.build().measure(&head());
        let (_, skipped, _) = parts.sink.only();
        assert!(skipped.is_empty(), "nothing before the sink failed");
    }

    /// Every stage broken at once. Individually-guarded stages could still be
    /// wired so that the *first* failure short-circuits the rest; this pins
    /// that a request whose every component is broken still produces a
    /// finding, and that the skip list is in pipeline order.
    #[test]
    fn every_stage_broken_at_once_still_produces_one_finding() {
        let mut parts = Parts::new();
        parts.source = StubSource::new(|| panic!("injected source panic"));
        parts.verifier = stub_verifier(|| panic!("injected verifier panic"));
        parts.meter = stub_meter(true);
        parts.metrics = stub_metrics(true);
        parts.build().measure(&head());
        let (rendered, skipped, has_observation) = parts.sink.only();
        assert_eq!(
            skipped,
            vec![STAGE_SOURCE, STAGE_METRICS],
            "the verifier and meter are unreachable once the source is gone: {rendered}"
        );
        assert!(!has_observation);
    }

    /// [`Finding`]'s fields are `pub`, so the combination this asserts against
    /// is constructible; the point is that no path through `measure` produces
    /// it. Exercised across all three verdicts with a meter that would
    /// happily hand back an observation if it were ever asked.
    #[test]
    fn no_verdict_but_verified_can_carry_an_observation() {
        let cases: [fn() -> QuoteVerdict; 2] = [
            || QuoteVerdict::Unverified {
                why: "no collateral cached for FMSPC b0c06f000000 yet".to_string(),
            },
            || QuoteVerdict::Invalid {
                reason: "signature check failed".to_string(),
            },
        ];
        for answer in cases {
            let meter = stub_meter(false);
            let mut parts = Parts::new();
            parts.verifier = stub_verifier(answer);
            parts.meter = Arc::clone(&meter) as Arc<dyn Measure>;
            parts.build().measure(&head());
            let (rendered, _, has_observation) = parts.sink.only();
            assert!(!has_observation, "{rendered}");
            assert_eq!(
                meter.calls.load(Ordering::SeqCst),
                0,
                "the meter must not even be consulted without a verdict to \
                 partition on: {rendered}"
            );
        }
    }

    /// A cold cache must schedule a fetch; a good quote and a malformed one
    /// must not. Without the `Unverified`-only gate, an agent replaying junk
    /// turns every request into a call to the provisioning service.
    ///
    /// Uses a real, live queue rather than [`RefreshQueue::never_refreshes`], so the
    /// assertion is about what was sent and not about what was swallowed.
    #[tokio::test]
    async fn only_an_unverified_verdict_schedules_a_collateral_fetch() {
        use tokio::sync::mpsc;

        let cases: [(fn() -> QuoteVerdict, usize); 3] = [
            (
                || QuoteVerdict::Unverified {
                    why: "no collateral cached for FMSPC b0c06f000000 yet".to_string(),
                },
                1,
            ),
            (verified, 0),
            (
                || QuoteVerdict::Invalid {
                    reason: "not a DCAP quote".to_string(),
                },
                0,
            ),
        ];

        for (answer, expected) in cases {
            let (tx, mut rx) = mpsc::channel::<Vec<u8>>(8);
            let parts = Parts::new();
            let pipeline = Pipeline {
                source: Arc::clone(&parts.source),
                verifier: stub_verifier(answer),
                meter: Arc::clone(&parts.meter),
                metrics: Arc::clone(&parts.metrics),
                sink: Arc::clone(&parts.sink) as Arc<dyn FindingSink>,
                refresh: crate::gateway::refresh::queue_for_test(tx),
            };
            pipeline.measure(&head());
            drop(pipeline);

            let mut scheduled = Vec::new();
            while let Ok(quote) = rx.try_recv() {
                scheduled.push(quote);
            }
            assert_eq!(scheduled.len(), expected, "scheduling was wrong");
            if expected == 1 {
                assert_eq!(
                    scheduled[0],
                    vec![0xab; 16],
                    "the whole quote must reach the refresher, not a digest of it"
                );
            }
        }
    }

    /// A source that never yields a quote must never schedule a fetch — there
    /// is nothing to fetch *for*, and the refresher would only parse-fail.
    #[tokio::test]
    async fn a_request_with_no_quote_schedules_nothing() {
        use tokio::sync::mpsc;
        let (tx, mut rx) = mpsc::channel::<Vec<u8>>(8);
        let parts = Parts::new();
        let pipeline = Pipeline {
            source: StubSource::new(|| Ok(None)),
            verifier: Arc::clone(&parts.verifier),
            meter: Arc::clone(&parts.meter),
            metrics: Arc::clone(&parts.metrics),
            sink: Arc::clone(&parts.sink) as Arc<dyn FindingSink>,
            refresh: crate::gateway::refresh::queue_for_test(tx),
        };
        pipeline.measure(&head());
        drop(pipeline);
        assert!(rx.try_recv().is_err());
    }

    /// `Hooks::from_pipeline` has to actually call `measure`. A hook that
    /// silently did nothing would leave every fail-open test in the
    /// integration suite passing for the wrong reason.
    #[test]
    fn from_pipeline_produces_a_hook_that_measures() {
        let parts = Parts::new();
        let hooks = Hooks::from_pipeline(Arc::new(parts.build()));
        (hooks.on_request)(&head());
        let (rendered, _, _) = parts.sink.only();
        assert!(rendered.contains("VERIFIED"), "{rendered}");
    }

    /// The production sink, which no fault-injection test can substitute for
    /// (it *is* the thing they substitute). Fail-open binds it like
    /// everything else: `Finding::render` runs inside it, so a panic here on
    /// some verdict shape would be a rendering fault reaching a real
    /// deployment. Every verdict, with and without a skip list.
    #[test]
    fn the_log_sink_renders_every_verdict_shape_without_panicking() {
        let verdicts = [
            verified(),
            QuoteVerdict::Unverified { why: String::new() },
            QuoteVerdict::Invalid {
                reason: "\u{0}\u{2713}".to_string(),
            },
        ];
        for verdict in verdicts {
            for skipped in [vec![], vec![STAGE_METER, STAGE_METRICS]] {
                let measured = Measured {
                    finding: Finding {
                        verdict: match &verdict {
                            QuoteVerdict::Verified { .. } => verified(),
                            QuoteVerdict::Unverified { why } => {
                                QuoteVerdict::Unverified { why: why.clone() }
                            }
                            QuoteVerdict::Invalid { reason } => QuoteVerdict::Invalid {
                                reason: reason.clone(),
                            },
                        },
                        binding: SessionBinding::Bound,
                        observation: None,
                    },
                    skipped: skipped.clone(),
                };
                // The rendering the sink is about to log, checked first so a
                // failure names the shape rather than just unwinding.
                let rendered = measured.render();
                assert_eq!(
                    rendered.contains("skipped"),
                    !skipped.is_empty(),
                    "{rendered}"
                );
                LogSink.emit(&measured);
            }
        }
    }

    // --- structural guards ----------------------------------------------

    /// The non-test half of this file, comments stripped. Shared by the two
    /// guards below, and loud rather than silent if the split ever misses:
    /// an unsplit file would carry this module's own banned-token array and
    /// trip every check in it.
    fn non_test_code() -> String {
        let src = include_str!("pipeline.rs");
        const MARKER: &str = "#[cfg(test)]\nmod tests {";
        assert_eq!(
            src.matches(MARKER).count(),
            1,
            "ambiguous test module boundary"
        );
        let non_test = src.split(MARKER).next().expect("split yields a head");
        assert!(
            non_test.contains("pub fn measure") && non_test.contains("fn from_pipeline"),
            "the scanned region does not reach the implementation, so these \
             guards would pass against a truncated string"
        );
        let tail = src.split(MARKER).nth(1).expect("split yields a tail");
        let after: Vec<&str> = tail
            .lines()
            .filter(|l| !l.is_empty() && !l.starts_with(char::is_whitespace))
            .collect();
        assert_eq!(
            after,
            ["}"],
            "code appears after the test module, where these guards cannot see it"
        );
        assert!(
            !non_test.contains("/*"),
            "block comments would let banned code hide from these guards"
        );
        non_test
            .lines()
            .filter(|l| !l.trim_start().starts_with("//"))
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// The structural version of "refresh runs off the request path".
    ///
    /// Documenting it is what `collateral.rs` already does; this makes an
    /// inline fetch something you cannot reach from here without first
    /// importing a type this module does not have. There is no `.await` to
    /// hide a fetch in either — `Hooks::on_request` is a synchronous `Fn` —
    /// so the remaining route is to build a nested runtime and block on it,
    /// which is what the last three tokens are for.
    ///
    /// `rotate_if_due` is in the same list for a different reason: Task 5's
    /// review established that a per-request rotation is the dangerous
    /// wiring, because a regression in the rotation clock's reset would then
    /// clear the store before every observation and report maximum anonymity
    /// forever. It belongs on the timer in `refresh.rs`.
    #[test]
    fn the_request_path_cannot_name_the_cache_or_await_anything() {
        let code = non_test_code();
        for banned in [
            "CollateralCache",
            ".refresh(",
            "rotate_if_due",
            ".await",
            "block_on",
            "Runtime",
        ] {
            assert!(
                !code.contains(banned),
                "`{banned}` appears in the pipeline's non-test code; the request \
                 path must not be able to fetch collateral, rotate the salt, or \
                 wait on anything"
            );
        }
        // A positive control: the guard has to be looking at code that really
        // does schedule, or it proves only that an empty string is clean.
        assert!(
            code.contains("self.refresh.schedule"),
            "the scanned region does not contain the scheduling call"
        );
    }

    /// `verify.rs`'s formatter ban, applied one module downstream. Nothing
    /// here can hold a hardware serial, but the cheapest way for that to stop
    /// being true is a `{:?}` on some future field, and this module's
    /// non-test code has no legitimate need for one today.
    #[test]
    fn the_pipeline_hands_nothing_to_a_debug_formatter() {
        let code = non_test_code();
        for banned in ["?}", ":?", "println!", "eprintln!", "dbg!"] {
            assert!(
                !code.contains(banned),
                "`{banned}` appears in the pipeline's non-test code"
            );
        }
    }
}
