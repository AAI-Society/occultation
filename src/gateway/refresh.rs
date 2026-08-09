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

/// The request path's only handle on collateral refresh: schedule, never
/// wait, never fetch.
///
/// Deliberately exposes no cache, no URL and no future. `schedule` is
/// synchronous and cannot block — it is a `try_send` into a bounded channel
/// and nothing else — so a hook that calls it pays a lock acquisition and a
/// move, not a network round trip.
#[derive(Clone)]
pub struct RefreshQueue {
    /// `None` for an [`inert`](RefreshQueue::inert) queue.
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

    /// A queue that discards everything, for a pipeline assembled without a
    /// refresher (tests that are not about collateral, and any caller that
    /// deliberately runs with a cache it populates some other way).
    ///
    /// Not a degraded `spawn`: it holds no cache and starts no task, so it
    /// cannot fetch anything even by accident.
    pub fn inert() -> RefreshQueue {
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
pub fn spawn(
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

async fn drive_refresh(cache: Arc<CollateralCache>, mut rx: mpsc::Receiver<Vec<u8>>) {
    let mut attempted: HashMap<String, Instant> = HashMap::new();
    while let Some(quote) = rx.recv().await {
        refresh_one(&cache, &mut attempted, quote).await;
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

async fn refresh_one(
    cache: &Arc<CollateralCache>,
    attempted: &mut HashMap<String, Instant>,
    quote: Vec<u8>,
) {
    refresh_one_within(cache, attempted, quote, FETCH_TIMEOUT).await
}

/// [`refresh_one`] with the fetch bound injected, so a test can pin the
/// timeout without waiting [`FETCH_TIMEOUT`] for it. Production always passes
/// `FETCH_TIMEOUT`.
async fn refresh_one_within(
    cache: &Arc<CollateralCache>,
    attempted: &mut HashMap<String, Instant>,
    quote: Vec<u8>,
    bound: Duration,
) {
    let Some(key) = fmspc_of(&quote) else {
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

    /// An inert queue must be inert in the strong sense: it holds nothing
    /// that could fetch, so scheduling against it is a no-op rather than a
    /// deferred surprise.
    #[test]
    fn an_inert_queue_swallows_everything_without_a_runtime() {
        let q = RefreshQueue::inert();
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

    /// A socket that accepts and then says nothing. `127.0.0.1:1` is refused
    /// instantly on loopback and so cannot stand in for an unresponsive
    /// provisioning service.
    async fn black_hole() -> std::net::SocketAddr {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind black hole");
        let addr = listener.local_addr().expect("black hole addr");
        tokio::spawn(async move {
            let mut held = Vec::new();
            while let Ok((stream, _)) = listener.accept().await {
                held.push(stream);
            }
        });
        addr
    }

    /// The fetch bound, against a provisioning service that never answers.
    ///
    /// Without it, one such service stops every later platform being cached
    /// — forever, silently, and with every quote reported `Unverified` as a
    /// result. Nothing else in this file exercises `refresh_one`'s timeout,
    /// so deleting it would leave the suite green.
    #[tokio::test]
    async fn an_unresponsive_provisioning_service_does_not_wedge_the_refresher() {
        let addr = black_hole().await;
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

    /// `spawn` has to actually drive rotation. Nothing else here would notice
    /// `drive_rotation` being dropped from it: the request path deliberately
    /// never calls `rotate_if_due`, so if the timer does not, nothing ever
    /// does and the salt lives forever.
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

        let _queue = spawn(cache, Arc::clone(&meter), Duration::from_millis(40));

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
