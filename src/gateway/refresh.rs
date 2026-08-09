//! Collateral refresh, driven from a background task and never from a
//! request.
//!
//! Task 3 split the collateral module in two on purpose: `get` is a
//! synchronous, offline, lock-only lookup a verifier may call inline, and
//! `refresh` is an async network round trip to a provisioning service that
//! must never run on the request path. Task 1's reorder — hook after forward,
//! on an owned snapshot — relocates hook cost but does not eliminate it:
//! hyper does not write the response until the service future resolves, so a
//! slow hook still adds to time-to-first-byte and still occupies a worker.
//!
//! This module is where that separation is *enforced* rather than described.
//! It owns the only handle to a [`CollateralCache`] that ever calls
//! `refresh`, and it hands the request path a [`RefreshQueue`] — a
//! non-blocking, bounded, fire-and-forget sender and nothing else. A pipeline
//! holding a `RefreshQueue` has no way to name the cache, no way to name
//! `refresh`, and no way to await anything: `Hooks::on_request` is a
//! synchronous `Fn`, so there is no `.await` for a network call to hide in.
//! `pipeline.rs`'s own
//! `the_request_path_cannot_name_the_cache_or_await_anything` guard pins that
//! its non-test source contains none of those tokens.
//!
//! The same task also drives [`LinkabilityMeter::rotate_if_due`]. That call
//! deliberately does **not** live on the request path: Task 5's review found
//! that a per-request `rotate_if_due` whose clock reset was ever broken would
//! clear the store before every observation landed and report `set_size: 1,
//! distinct_configs: 1` forever — the tool whose job is flagging low
//! diversity silently claiming maximum anonymity. A timer is the only caller
//! here, so "how often does rotation happen" is a property of the configured
//! interval rather than of how much traffic the gateway happens to see.

use crate::gateway::collateral::{fmspc_to_hex, CollateralCache};
use crate::gateway::meter::LinkabilityMeter;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::mpsc::{self, Sender};

/// How many quotes may be waiting for a background refresh at once.
///
/// Bounded because the request path pushes into this queue on an agent's
/// say-so. Past the cap, [`RefreshQueue::schedule`] drops rather than waits —
/// a dropped refresh costs one more `Unverified` verdict for that platform,
/// which is the same thing that would have happened anyway.
pub const QUEUE_DEPTH: usize = 64;

/// Don't ask the provisioning service about the same platform more often than
/// this. Every request for an uncached platform schedules a refresh, so
/// without a cooldown a single agent retrying in a loop becomes a request
/// amplifier pointed at the PCCS.
pub const RETRY_AFTER: Duration = Duration::from_secs(60);

/// A hard bound on how long one fetch may occupy the refresher.
///
/// The provisioning service is not under this gateway's control, and
/// `CollateralClient` offers no guarantee about its own timeout. Without this,
/// a PCCS that accepts a connection and then says nothing stalls every later
/// refresh forever. It cannot stall a *request* — that is what this whole
/// module is for — but a permanently wedged refresher means every platform
/// stays `Unverified`, which is a silent failure worth bounding.
pub const FETCH_TIMEOUT: Duration = Duration::from_secs(10);

/// How many platforms the cooldown map remembers before it is emptied.
///
/// The FMSPC is read out of a PCK certificate the gateway has not validated
/// at the point this map is keyed, so a hostile agent can in principle mint
/// distinct keys. Clearing wholesale (rather than evicting) keeps this to one
/// bounded allocation and only ever costs a redundant fetch.
const MAX_TRACKED_PLATFORMS: usize = 512;

/// The shortest salt rotation this gateway will start with.
///
/// Not an arbitrary tidiness bound. `LinkabilityMeter::rotate_if_due` clears
/// the whole store once `rotation` has elapsed, and this module's timer asks
/// it four times per interval. With `rotation` at or below the interval
/// between requests, the store is cleared between every pair of
/// observations, and *every* request comes back `set_size: 1,
/// total_sessions: 1, distinct_configs: 1` — a tool whose job is flagging
/// low diversity silently reporting maximum anonymity, on a diverse
/// population, forever. `--salt-rotation 0s` is the extreme (rotate on every
/// tick, roughly a thousand times a second); anything sub-second fails the
/// same way and less visibly.
///
/// A minute is well below any interval an operator would choose on purpose —
/// the default is an hour — and well above any traffic rate at which the
/// collapse is possible. See
/// `a_sub_second_rotation_is_the_collapse_this_floor_exists_to_refuse`, which
/// demonstrates the harm rather than describing it.
pub const MIN_SALT_ROTATION: Duration = Duration::from_secs(60);

/// A salt rotation short enough to make the meter report maximum anonymity.
#[derive(Debug, thiserror::Error)]
#[error(
    "a salt rotation of {rotation:?} is shorter than the {minimum:?} minimum; \
     the meter would clear its store between observations and report every \
     request as an anonymity set of one"
)]
pub struct RotationTooShort {
    pub rotation: Duration,
    pub minimum: Duration,
}

/// Refuse a rotation interval that would collapse every anonymity set to one.
///
/// The same shape as `proxy::validate_upstream`: a configuration mistake is
/// caught at startup, where an operator reads the error, rather than
/// discovered later as a suspiciously flattering number.
pub fn validate_rotation(rotation: Duration) -> Result<(), RotationTooShort> {
    if rotation < MIN_SALT_ROTATION {
        return Err(RotationTooShort {
            rotation,
            minimum: MIN_SALT_ROTATION,
        });
    }
    Ok(())
}

/// The request path's only handle on collateral refresh: schedule, never
/// wait, never fetch.
///
/// Deliberately exposes no cache, no URL and no future. `schedule` is
/// synchronous and cannot block — it is a `try_send` into a bounded channel
/// and nothing else — so a hook that calls it pays a lock acquisition and a
/// move, not a network round trip.
#[derive(Clone)]
pub struct RefreshQueue {
    /// `None` for a [`never_refreshes`](RefreshQueue::never_refreshes) queue.
    tx: Option<Sender<Vec<u8>>>,
}

impl RefreshQueue {
    /// Ask for `quote`'s platform to be refreshed, eventually. Returns
    /// immediately in every case, including when the queue is full or the
    /// refresher has stopped.
    pub fn schedule(&self, quote: Vec<u8>) {
        let Some(tx) = self.tx.as_ref() else {
            return;
        };
        if tx.try_send(quote).is_err() {
            // Full or closed. Either way this is a measurement we will not
            // take, never a request we will not forward.
            log::debug!(
                "collateral refresh queue is full or closed; this platform stays uncached for now"
            );
        }
    }

    /// A queue that discards everything and can never fetch anything.
    ///
    /// Named for its consequence rather than for its mechanism, because the
    /// consequence is silent: a pipeline built on one reports `Unverified`
    /// for every platform for the life of the process, with nothing louder
    /// than a `debug!` line. That is the safe direction — it can never
    /// manufacture a `Verified` — but it is not a degraded [`spawn`], and it
    /// is not what a production gateway wants. It exists for pipelines
    /// assembled for reasons other than collateral (most of this crate's
    /// tests) and for a caller populating the cache some other way.
    pub fn never_refreshes() -> RefreshQueue {
        RefreshQueue { tx: None }
    }
}

/// Start the two background tasks — collateral refresh and salt rotation —
/// and hand back the request path's end of the refresh queue.
///
/// Two tasks rather than one `select!` loop: a fetch against an unresponsive
/// provisioning service would otherwise sit in the same loop as the rotation
/// timer and stop the salt rotating, which is a correlation-window failure
/// caused by an unrelated network problem.
///
/// Fallible only for [`validate_rotation`]'s sake, and deliberately so: the
/// timer here is the *only* caller of `rotate_if_due` in the process, so
/// gating the timer is what makes an unsafe rotation interval unstartable
/// rather than merely discouraged. A `LinkabilityMeter` built with a short
/// rotation but never driven simply keeps correlating, which is the safe
/// direction.
pub fn spawn(
    cache: Arc<CollateralCache>,
    meter: Arc<LinkabilityMeter>,
    rotation: Duration,
) -> Result<RefreshQueue, RotationTooShort> {
    validate_rotation(rotation)?;
    Ok(spawn_with(cache, meter, rotation))
}

/// [`spawn`] without the interval check, so this module's own tests can drive
/// a rotation faster than [`MIN_SALT_ROTATION`] without waiting a minute for
/// it. Private: the checked entry point is the only way in from outside.
fn spawn_with(
    cache: Arc<CollateralCache>,
    meter: Arc<LinkabilityMeter>,
    rotation: Duration,
) -> RefreshQueue {
    let (tx, rx) = mpsc::channel::<Vec<u8>>(QUEUE_DEPTH);
    tokio::spawn(drive_refresh(cache, rx));
    tokio::spawn(drive_rotation(meter, rotation));
    RefreshQueue { tx: Some(tx) }
}

/// How often the rotation task wakes to ask whether a rotation is due.
///
/// A quarter of the interval, not the interval itself: `rotate_if_due` is a
/// no-op unless `rotation` has fully elapsed, so a timer of exactly
/// `rotation` that fires a hair early skips that rotation entirely and the
/// salt then lives for two intervals. Polling four times per interval bounds
/// the real lifetime at 1.25 intervals. Floored above zero because
/// `tokio::time::interval` panics on a zero period, and `rotation` comes from
/// an operator's command line.
fn poll_period(rotation: Duration) -> Duration {
    (rotation / 4).max(Duration::from_millis(1))
}

async fn drive_rotation(meter: Arc<LinkabilityMeter>, rotation: Duration) {
    let mut ticker = tokio::time::interval(poll_period(rotation));
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        ticker.tick().await;
        meter.rotate_if_due();
    }
}

/// How the refresher reads a platform out of a quote. A function pointer only
/// so this module's own tests can substitute one that panics — production has
/// exactly one implementation, [`fmspc_of`].
type FmspcParse = fn(&[u8]) -> Option<String>;

async fn drive_refresh(cache: Arc<CollateralCache>, rx: mpsc::Receiver<Vec<u8>>) {
    drive_refresh_with(cache, rx, fmspc_of).await
}

async fn drive_refresh_with(
    cache: Arc<CollateralCache>,
    mut rx: mpsc::Receiver<Vec<u8>>,
    parse: FmspcParse,
) {
    let mut attempted: HashMap<String, Instant> = HashMap::new();
    while let Some(quote) = rx.recv().await {
        refresh_one_within(&cache, &mut attempted, quote, FETCH_TIMEOUT, parse).await;
    }
}

/// Read the platform out of a quote, the one way the crate reads it.
///
/// `Quote::parse` then `intel::quote_fmspc` then [`fmspc_to_hex`] — the same
/// route `CollateralCache::refresh` itself takes, so the key this function
/// dedupes on is the key that fetch will write under.
fn fmspc_of(quote: &[u8]) -> Option<String> {
    let parsed = dcap_qvl::quote::Quote::parse(quote).ok()?;
    let fmspc = dcap_qvl::intel::quote_fmspc(&parsed).ok()?;
    Some(fmspc_to_hex(&fmspc))
}

/// [`fmspc_of`] with a panic guard around it.
///
/// The parse behind this reads a DER-encoded PCK certificate and an Intel
/// extension out of bytes an agent chose, in a third-party crate. It runs
/// directly in the refresher's loop, so a panic in it unwinds out of
/// `while let`, drops the receiver, and turns every later `schedule` into a
/// `debug!` line — the gateway then reports `Unverified` for every platform
/// for the rest of the process with nothing louder than that to say so.
/// Requests still forward, so fail-open holds; the measurement product is
/// what dies, silently, which for this tool is most of the point.
///
/// `catch_unwind` is possible here precisely because the parse is
/// synchronous: it sits before the first `.await` in `refresh_one_within`,
/// which is also why the *fetch* needs the separate child-task isolation
/// below rather than this.
fn fmspc_of_guarded(parse: FmspcParse, quote: &[u8]) -> Option<String> {
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| parse(quote))) {
        Ok(key) => key,
        Err(_) => {
            log::error!(
                "reading a platform out of a quote panicked; dropping this refresh and \
                 continuing. The refresher is still running and later platforms will \
                 still be cached"
            );
            None
        }
    }
}

/// Decide whether `key` is due for another attempt, and record the attempt if
/// it is. Pure bookkeeping, separated from the I/O so it can be tested
/// without a provisioning service.
fn claim_attempt(attempted: &mut HashMap<String, Instant>, key: &str, now: Instant) -> bool {
    if let Some(last) = attempted.get(key) {
        if now.saturating_duration_since(*last) < RETRY_AFTER {
            return false;
        }
    }
    if attempted.len() >= MAX_TRACKED_PLATFORMS {
        attempted.clear();
    }
    attempted.insert(key.to_string(), now);
    true
}

/// One refresh, with the fetch bound and the parser injected so a test can
/// pin the timeout without waiting [`FETCH_TIMEOUT`] for it and can make the
/// parse panic. Production always passes `FETCH_TIMEOUT` and [`fmspc_of`].
async fn refresh_one_within(
    cache: &Arc<CollateralCache>,
    attempted: &mut HashMap<String, Instant>,
    quote: Vec<u8>,
    bound: Duration,
    parse: FmspcParse,
) {
    let Some(key) = fmspc_of_guarded(parse, &quote) else {
        // Not a DCAP quote, or a certification type this crate cannot read a
        // platform out of. Nothing to fetch, and the verifier has already
        // reported it.
        return;
    };
    if !claim_attempt(attempted, &key, Instant::now()) {
        return;
    }

    // Fetched inside a child task so a panic anywhere under `refresh` kills
    // that fetch and not the refresher: this loop is the only thing that ever
    // populates the cache, and a task that unwinds out of `while let` stops
    // every platform being cached from then on, silently and forever.
    let cache = Arc::clone(cache);
    let child =
        tokio::spawn(async move { tokio::time::timeout(bound, cache.refresh(&quote)).await });
    match child.await {
        Ok(Ok(Ok(()))) => log::info!("cached collateral for FMSPC {key}"),
        Ok(Ok(Err(err))) => log::warn!("could not refresh collateral for FMSPC {key}: {err}"),
        Ok(Err(_elapsed)) => log::warn!(
            "the provisioning service did not answer within {}ms for FMSPC {key}; giving up on this attempt",
            bound.as_millis()
        ),
        Err(join) => log::error!(
            "the collateral fetch for FMSPC {key} ended abnormally ({}); the refresher is still running",
            if join.is_panic() { "panicked" } else { "cancelled" }
        ),
    }
}

/// A live queue over a caller-supplied sender, so `pipeline.rs`'s tests can
/// assert on what the request path scheduled without standing up a
/// provisioning service. Test-only: production queues come from [`spawn`],
/// which is the only thing that also starts something to drain them.
#[cfg(test)]
pub(crate) fn queue_for_test(tx: Sender<Vec<u8>>) -> RefreshQueue {
    RefreshQueue { tx: Some(tx) }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn real_tdx_quote() -> Vec<u8> {
        include_bytes!("../../tests/fixtures/tdx-quote.bin").to_vec()
    }

    /// The fixture's platform, as `verify.rs` and `finding.rs` both pin it.
    const REAL_FMSPC_HEX: &str = "b0c06f000000";

    /// The dedupe key has to be the *cache's* key, or a refresh writes under
    /// one spelling and every later `get` reads another — a miss that
    /// degrades to `Unverified` forever with nothing failing loudly.
    #[test]
    fn the_dedupe_key_is_the_same_hex_the_cache_stores_under() {
        assert_eq!(fmspc_of(&real_tdx_quote()).as_deref(), Some(REAL_FMSPC_HEX));
    }

    #[test]
    fn a_quote_with_no_platform_is_skipped_rather_than_fetched() {
        assert_eq!(fmspc_of(&[0u8; 8]), None);
        assert_eq!(fmspc_of(&[]), None);
    }

    /// A parser that comes apart on one input and works on every other, so a
    /// test can distinguish "the refresher survived a hostile quote" from
    /// "the refresher never saw one".
    fn parse_that_panics_on_boom(quote: &[u8]) -> Option<String> {
        assert!(quote != b"boom", "injected parser panic on a hostile quote");
        fmspc_of(quote)
    }

    /// The guard around the parse, at the unit level: a panic becomes `None`
    /// rather than an unwind.
    #[test]
    fn a_panicking_parse_becomes_a_skipped_refresh_not_an_unwind() {
        assert_eq!(fmspc_of_guarded(parse_that_panics_on_boom, b"boom"), None);
        // ...and the guard is not simply swallowing everything.
        assert_eq!(
            fmspc_of_guarded(parse_that_panics_on_boom, &real_tdx_quote()).as_deref(),
            Some(REAL_FMSPC_HEX)
        );
    }

    /// The cooldown, pinned at its exact boundary. Without it every request
    /// for an uncached platform is a request to the provisioning service,
    /// which turns one retrying agent into a request amplifier.
    ///
    /// `now` is a parameter for the same reason `CollateralCache::lookup_at`'s
    /// is: with a real clock the elapsed time is never exactly `RETRY_AFTER`,
    /// so `<` and `<=` are indistinguishable to the test and the boundary
    /// goes unpinned.
    #[test]
    fn a_platform_is_not_re_attempted_until_the_cooldown_has_elapsed() {
        let mut attempted = HashMap::new();
        let t0 = Instant::now();
        assert!(claim_attempt(&mut attempted, "aaaaaaaaaaaa", t0));
        assert!(!claim_attempt(&mut attempted, "aaaaaaaaaaaa", t0));
        assert!(
            !claim_attempt(
                &mut attempted,
                "aaaaaaaaaaaa",
                t0 + RETRY_AFTER - Duration::from_nanos(1)
            ),
            "one tick short of the cooldown is still inside it"
        );
        assert!(
            claim_attempt(&mut attempted, "aaaaaaaaaaaa", t0 + RETRY_AFTER),
            "the cooldown has fully elapsed at exactly RETRY_AFTER"
        );
        // ...and the successful claim reset the clock, so the next one is
        // held back again rather than the platform staying permanently due.
        assert!(!claim_attempt(
            &mut attempted,
            "aaaaaaaaaaaa",
            t0 + RETRY_AFTER
        ));
        // A different platform is never held back by another's cooldown.
        assert!(claim_attempt(&mut attempted, "bbbbbbbbbbbb", t0));
    }

    /// The map is keyed on attacker-influenced data, so it must not grow
    /// without bound between rotations.
    #[test]
    fn the_cooldown_map_is_bounded() {
        let mut attempted = HashMap::new();
        let t0 = Instant::now();
        for i in 0..(MAX_TRACKED_PLATFORMS * 2) {
            claim_attempt(&mut attempted, &format!("{i:012x}"), t0);
        }
        assert!(
            attempted.len() <= MAX_TRACKED_PLATFORMS,
            "the cooldown map grew to {}",
            attempted.len()
        );
    }

    /// `tokio::time::interval` panics on a zero period, and `rotation` is an
    /// operator-supplied command-line value. A gateway that aborts at startup
    /// on `--salt-rotation 0s` is a gateway that is not fronting anyone's API.
    #[test]
    fn the_rotation_poll_period_is_never_zero_and_is_shorter_than_the_interval() {
        assert!(poll_period(Duration::ZERO) > Duration::ZERO);
        assert!(poll_period(Duration::from_nanos(1)) > Duration::ZERO);
        let hour = Duration::from_secs(3600);
        assert!(
            poll_period(hour) < hour,
            "polling at exactly the interval skips rotations that fire a hair early"
        );
        assert_eq!(poll_period(hour), Duration::from_secs(900));
    }

    /// A never-refreshing queue must be inert in the strong sense: it holds
    /// nothing that could fetch, so scheduling against it is a no-op rather
    /// than a deferred surprise.
    #[test]
    fn a_never_refreshing_queue_swallows_everything_without_a_runtime() {
        let q = RefreshQueue::never_refreshes();
        q.schedule(real_tdx_quote());
        q.schedule(vec![0u8; 8]);
    }

    /// `schedule` is called from a synchronous hook on the request path, so
    /// it must never block and never panic — including once the queue is
    /// full, which is exactly when a blocking send would stall a request.
    #[tokio::test]
    async fn scheduling_past_the_queue_depth_drops_rather_than_blocks() {
        let (tx, _rx) = mpsc::channel::<Vec<u8>>(QUEUE_DEPTH);
        let q = RefreshQueue { tx: Some(tx) };
        let start = Instant::now();
        for _ in 0..(QUEUE_DEPTH * 4) {
            q.schedule(vec![0u8; 8]);
        }
        assert!(
            start.elapsed() < Duration::from_millis(200),
            "schedule blocked once the queue filled: {:?}",
            start.elapsed()
        );
    }

    /// A closed refresher must not turn into a panicking `schedule` on the
    /// request path.
    #[tokio::test]
    async fn scheduling_into_a_dropped_refresher_is_a_no_op() {
        let (tx, rx) = mpsc::channel::<Vec<u8>>(QUEUE_DEPTH);
        drop(rx);
        RefreshQueue { tx: Some(tx) }.schedule(real_tdx_quote());
    }

    /// A socket that accepts and then says nothing, plus a count of how many
    /// connections it took. `127.0.0.1:1` is refused instantly on loopback
    /// and so cannot stand in for an unresponsive provisioning service.
    async fn black_hole() -> (std::net::SocketAddr, Arc<AtomicUsize>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind black hole");
        let addr = listener.local_addr().expect("black hole addr");
        let connections = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&connections);
        tokio::spawn(async move {
            // Held rather than dropped: a closed socket is a fast failure,
            // which is the case this fixture exists to avoid.
            let mut held = Vec::new();
            while let Ok((stream, _)) = listener.accept().await {
                counter.fetch_add(1, Ordering::SeqCst);
                held.push(stream);
            }
        });
        (addr, connections)
    }

    /// The fetch bound, against a provisioning service that never answers.
    ///
    /// Without it, one such service stops every later platform being cached
    /// — forever, silently, and with every quote reported `Unverified` as a
    /// result. Nothing else in this file exercises `refresh_one`'s timeout,
    /// so deleting it would leave the suite green.
    #[tokio::test]
    async fn an_unresponsive_provisioning_service_does_not_wedge_the_refresher() {
        let (addr, _) = black_hole().await;
        let cache = Arc::new(CollateralCache::new(
            format!("http://{addr}"),
            Duration::from_secs(3600),
        ));
        let mut attempted = HashMap::new();
        let started = Instant::now();
        refresh_one_within(
            &cache,
            &mut attempted,
            real_tdx_quote(),
            Duration::from_millis(100),
            fmspc_of,
        )
        .await;
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "the fetch was not bounded: {:?}",
            started.elapsed()
        );
        // The attempt was recorded even though it failed, so a retry loop
        // still respects the cooldown.
        assert!(attempted.contains_key(REAL_FMSPC_HEX));
    }

    /// The whole point of Important 1: one hostile quote must not be the last
    /// quote this gateway ever measures.
    ///
    /// Feeds the refresher a quote whose parse panics, then a legitimate one,
    /// and asserts the legitimate one still reaches the provisioning service.
    /// With the parse unguarded, the first message unwinds out of `while
    /// let`, the receiver drops, and the second `schedule` goes to a closed
    /// channel — the black hole is never contacted and the gateway reports
    /// `Unverified` for every platform for the rest of the process.
    #[tokio::test]
    async fn a_quote_that_panics_the_parser_does_not_kill_the_refresher() {
        let (addr, connections) = black_hole().await;
        let cache = Arc::new(CollateralCache::new(
            format!("http://{addr}"),
            Duration::from_secs(3600),
        ));
        let (tx, rx) = mpsc::channel::<Vec<u8>>(QUEUE_DEPTH);
        tokio::spawn(drive_refresh_with(cache, rx, parse_that_panics_on_boom));

        let queue = RefreshQueue { tx: Some(tx) };
        queue.schedule(b"boom".to_vec());
        queue.schedule(real_tdx_quote());

        let deadline = Instant::now() + Duration::from_secs(5);
        while connections.load(Ordering::SeqCst) == 0 {
            assert!(
                Instant::now() < deadline,
                "the refresher died on the hostile quote; every later platform \
                 stays uncached for the life of the process"
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }

    /// The floor, at its boundary, and the harm it exists to refuse.
    #[test]
    fn a_sub_second_rotation_is_the_collapse_this_floor_exists_to_refuse() {
        use crate::gateway::verify::TcbConfig;

        fn cfg(n: u32) -> TcbConfig {
            TcbConfig {
                attributes: [("tee_tcb_svn".to_string(), format!("{n:032x}"))]
                    .into_iter()
                    .collect(),
            }
        }

        // The harm, demonstrated rather than described. A meter whose
        // rotation is shorter than the gap between observations is cleared
        // between each one, so a population of five genuinely distinct
        // configurations reports as one set of one, five times over.
        let collapsed = LinkabilityMeter::new(Duration::ZERO, 7);
        for n in 0..5 {
            collapsed.rotate_if_due();
            let o = collapsed.observe(&cfg(n));
            assert_eq!(o.set_size, 1);
            assert_eq!(
                o.distinct_configs, 1,
                "five distinct platforms reported as one — this is the failure"
            );
            assert_eq!(o.total_sessions, 1);
        }

        // The same population under a rotation the floor allows: the leak is
        // reported honestly.
        let honest = LinkabilityMeter::new(MIN_SALT_ROTATION, 7);
        let mut last = None;
        for n in 0..5 {
            honest.rotate_if_due();
            last = Some(honest.observe(&cfg(n)));
        }
        let last = last.expect("five observations happened");
        assert_eq!(last.distinct_configs, 5);
        assert_eq!(last.total_sessions, 5);

        // And the boundary itself.
        assert!(validate_rotation(Duration::ZERO).is_err());
        assert!(validate_rotation(Duration::from_millis(999)).is_err());
        assert!(
            validate_rotation(MIN_SALT_ROTATION - Duration::from_nanos(1)).is_err(),
            "one tick under the floor is still under it"
        );
        assert!(validate_rotation(MIN_SALT_ROTATION).is_ok());
        assert!(validate_rotation(Duration::from_secs(3600)).is_ok());
    }

    /// The floor has to be enforced where the rotation timer is started, not
    /// merely offered as a function nobody calls. `spawn` is the only way to
    /// obtain a live queue from outside this module, and the timer it starts
    /// is the only caller of `rotate_if_due` in the process.
    #[tokio::test]
    async fn spawn_refuses_a_rotation_short_enough_to_collapse_every_set() {
        let cache = Arc::new(CollateralCache::new(
            "http://127.0.0.1:1".to_string(),
            Duration::from_secs(3600),
        ));
        let meter = Arc::new(LinkabilityMeter::new(Duration::from_secs(3600), 7));

        let err = match spawn(Arc::clone(&cache), Arc::clone(&meter), Duration::ZERO) {
            Ok(_) => panic!("a zero rotation must not start a gateway"),
            Err(err) => err,
        };
        assert_eq!(err.minimum, MIN_SALT_ROTATION);
        // The operator reads this; it has to say what to do about it.
        let rendered = err.to_string();
        assert!(rendered.contains("anonymity set of one"), "{rendered}");

        assert!(spawn(cache, meter, MIN_SALT_ROTATION).is_ok());
    }

    /// `spawn` has to actually drive rotation. Nothing else here would notice
    /// `drive_rotation` being dropped from it: the request path deliberately
    /// never calls `rotate_if_due`, so if the timer does not, nothing ever
    /// does and the salt lives forever.
    ///
    /// Goes through `spawn_with` rather than `spawn` so the rotation can be
    /// 40 ms instead of [`MIN_SALT_ROTATION`]; `spawn` adds only the interval
    /// check, which
    /// `spawn_refuses_a_rotation_short_enough_to_collapse_every_set` covers.
    #[tokio::test]
    async fn the_background_task_rotates_the_salt_when_it_comes_due() {
        let cache = Arc::new(CollateralCache::new(
            "http://127.0.0.1:1".to_string(),
            Duration::from_secs(3600),
        ));
        let meter = Arc::new(LinkabilityMeter::new(Duration::from_millis(40), 7));
        let config = crate::gateway::verify::TcbConfig {
            attributes: [("fmspc".to_string(), "b0c06f000000".to_string())]
                .into_iter()
                .collect(),
        };
        meter.observe(&config);
        assert_eq!(meter.observe(&config).set_size, 2);

        let _queue = spawn_with(cache, Arc::clone(&meter), Duration::from_millis(40));

        // Poll rather than sleep a fixed amount: the timer polls at a quarter
        // of the interval, so the rotation lands somewhere inside 1.25 of it.
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            if meter.observe(&config).set_size == 1 {
                return;
            }
            assert!(
                Instant::now() < deadline,
                "the background task never rotated the salt"
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }
}
