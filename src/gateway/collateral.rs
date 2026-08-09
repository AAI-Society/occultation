//! Collateral cache: fetched off the request path, read synchronously on it.
//!
//! `dcap_qvl::verify::verify` is synchronous and offline — it takes
//! collateral as an argument and does no I/O. Fetching that collateral is an
//! async network call to a provisioning service (PCCS). Keeping the two
//! apart is the only reason a PCS round trip never lands on a live request:
//! [`CollateralCache::get`] is a synchronous, lock-only lookup a verifier can
//! call inline; [`CollateralCache::refresh`] is the async network call that
//! populates what `get` reads, and it must never run on the request path.

use dcap_qvl::collateral::CollateralClient;
use dcap_qvl::quote::Quote;
use dcap_qvl::{Fmspc, QuoteCollateralV3};
use std::collections::HashMap;
use std::sync::{Arc, PoisonError, RwLock};
use std::time::{Duration, Instant};

#[derive(Debug, thiserror::Error)]
pub enum CollateralError {
    #[error("could not reach the provisioning service at {url}: {source}")]
    Unreachable {
        url: String,
        #[source]
        source: anyhow::Error,
    },
    #[error("quote does not carry an FMSPC; it may not be a DCAP quote")]
    NoFmspc,
}

#[derive(Debug)]
pub enum CacheLookup {
    Fresh(Arc<QuoteCollateralV3>),
    /// Present but past its TTL. Structurally distinct from `Fresh` — a
    /// verifier that matches on this enum cannot mistake one for the other.
    /// The verifier turns this into `Unverified`, never into a verification
    /// against expired TCB data: an aged entry might describe a platform
    /// that Intel has since revoked, so treating it as current would report
    /// a revoked platform as up to date.
    Stale {
        age: Duration,
    },
    Absent,
}

struct Entry {
    collateral: Arc<QuoteCollateralV3>,
    fetched: Instant,
}

/// Canonicalize an FMSPC string so the same platform always hashes to the
/// same cache slot regardless of how the caller spelled it.
///
/// Applied uniformly at the one point every lookup and every insert funnels
/// through ([`CollateralCache::lookup_at_key`]), whether the caller entered
/// through the production `&Fmspc` seam (already-canonical hex out of
/// [`fmspc_to_hex`]) or the test-only `&str` seam (unconstrained). Canonical
/// on both sides is what keeps a `refresh` and a later `get` for the same
/// platform from silently missing each other — a miss here degrades to
/// `Absent`/`Unverified`, never loudly.
fn canonical_fmspc(fmspc: &str) -> String {
    fmspc.trim().to_ascii_lowercase()
}

/// Lowercase, zero-padded, big-endian hex — the crate's *only* byte-to-hex
/// rendering.
///
/// [`fmspc_to_hex`] is a thin wrapper over this, and Task 4's verifier
/// renders TCB report fields (8, 16 and 48 bytes wide, which `fmspc_to_hex`
/// cannot take) through it directly. Sharing one function rather than one
/// convention is deliberate: while two renderers agreed only by test, a
/// reviewer had to check that they still agreed, and swapping one call site
/// for the other was a silent no-op that no test could distinguish.
pub(crate) fn hex_lower(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Render a raw FMSPC as the lowercase hex string used as the cache key.
///
/// Public because Task 4's verifier needs the same rendering for
/// operator-facing messages (e.g. "collateral for FMSPC {hex} is 900s
/// old…") — a second, independent renderer anywhere in the codebase would
/// reintroduce exactly the two-spellings-of-one-platform risk this module
/// exists to close.
pub fn fmspc_to_hex(fmspc: &Fmspc) -> String {
    hex_lower(fmspc)
}

/// Recover a lock guard even if a prior holder panicked while holding it.
///
/// Fail-open binds this module absolutely: no lock state may panic it. Both
/// critical sections here are a *single* `HashMap` operation (one read, one
/// insert) — there is no multi-step mutation with an observable
/// intermediate state, so there is no torn state to recover into. The worst
/// a recovered map can produce is a missing or stale-by-the-clock entry,
/// which resolves to `Absent`/`Stale` → `Unverified`; it cannot manufacture
/// a `Fresh` result with the wrong collateral. A poisoned lock is still
/// worth knowing about operationally, so recovery logs rather than staying
/// silent — without paying the permanent-panic cost `.expect(...)` would.
fn recover<T>(result: Result<T, PoisonError<T>>) -> T {
    result.unwrap_or_else(|poisoned| {
        log::warn!(
            "collateral cache lock was poisoned by a prior panic; recovering the guard rather than propagating"
        );
        poisoned.into_inner()
    })
}

/// Collateral, fetched off the request path and cached by FMSPC.
///
/// `dcap_qvl::verify::verify` is synchronous and takes collateral as an
/// argument; fetching it is an async network call. Keeping the two apart is
/// what stops a PCS round trip landing on a request.
pub struct CollateralCache {
    pccs_url: String,
    ttl: Duration,
    entries: RwLock<HashMap<String, Entry>>,
}

impl CollateralCache {
    pub fn new(pccs_url: String, ttl: Duration) -> Self {
        CollateralCache {
            pccs_url,
            ttl,
            entries: RwLock::new(HashMap::new()),
        }
    }

    /// The one place a key is looked up, given the final hex key and the
    /// instant to measure age against. Parameterized on `now` so tests can
    /// pin the TTL boundary exactly instead of racing a real clock — the
    /// production entry points below always pass `Instant::now()`.
    fn lookup_at_key(&self, key: &str, now: Instant) -> CacheLookup {
        let key = canonical_fmspc(key);
        let guard = recover(self.entries.read());
        match guard.get(&key) {
            None => CacheLookup::Absent,
            Some(e) => {
                // Saturating, not subtracting: `now` is caller-supplied in
                // tests and could in principle precede `e.fetched`; this
                // must still never panic, only ever under-report age.
                let age = now.saturating_duration_since(e.fetched);
                if age > self.ttl {
                    CacheLookup::Stale { age }
                } else {
                    CacheLookup::Fresh(Arc::clone(&e.collateral))
                }
            }
        }
    }

    fn lookup_at(&self, fmspc: &Fmspc, now: Instant) -> CacheLookup {
        self.lookup_at_key(&fmspc_to_hex(fmspc), now)
    }

    /// Synchronous, lock-only lookup. Safe to call inline on the request
    /// path — it does no I/O and cannot block on anything but this cache's
    /// own (briefly held, panic-tolerant) lock.
    ///
    /// Takes the raw `Fmspc` — the same type `dcap_qvl::intel::quote_fmspc`
    /// hands a verifier — rather than a string, so there is exactly one
    /// place ([`fmspc_to_hex`]) that turns it into the cache key. A `&str`
    /// entry point here would let a caller supply an already-rendered
    /// spelling that this module never validated, reopening the
    /// two-spellings-of-one-platform risk `fmspc_to_hex` exists to close.
    pub fn get(&self, fmspc: &Fmspc) -> CacheLookup {
        self.lookup_at(fmspc, Instant::now())
    }

    /// Fetch collateral for `quote`'s platform from the PCCS and cache it
    /// under its FMSPC.
    ///
    /// This does a real network round trip and offers no bound on its own
    /// latency beyond the HTTP client's timeout. It is **not** safe to call
    /// from the request path — Task 1's measurement hook already runs after
    /// the response has been forwarded, on an owned snapshot, precisely so a
    /// slow hook cannot delay a reply; but hyper still does not write that
    /// response until the hook's future resolves, so anything slow here adds
    /// straight to time-to-first-byte and occupies a worker for as long as
    /// it runs. `refresh` is the named reason that constraint exists: it
    /// must only ever be driven off-path (a background task, a periodic
    /// sweep) — this module does not wire that up, and nothing here calls
    /// `refresh` for you.
    ///
    /// FMSPC derivation here goes through `intel::quote_fmspc`, which reads
    /// the FMSPC out of a PCK certificate embedded in (or referenced by) the
    /// quote's certification data and only handles cert types 4 and 5.
    /// `CollateralClient::fetch` is more permissive — it also resolves cert
    /// types 2/3 (encrypted PPID) by asking the PCCS for the PCK cert first.
    /// So a cert-type-3 quote fails FMSPC derivation here (`NoFmspc`) and
    /// `refresh` never attempts a fetch that `fetch` alone could have
    /// completed. This is fail-safe in direction — permanent `Absent` →
    /// `Unverified`, never a spurious `Verified` — and TDX in practice uses
    /// cert type 5, but it is a real narrowing worth having on record.
    pub async fn refresh(&self, quote: &[u8]) -> Result<(), CollateralError> {
        let parsed = Quote::parse(quote).map_err(|_| CollateralError::NoFmspc)?;
        let fmspc = dcap_qvl::intel::quote_fmspc(&parsed).map_err(|_| CollateralError::NoFmspc)?;
        let key = fmspc_to_hex(&fmspc);

        let client = CollateralClient::with_default_http(self.pccs_url.clone()).map_err(|e| {
            CollateralError::Unreachable {
                url: self.pccs_url.clone(),
                source: e,
            }
        })?;
        let collateral = client
            .fetch(quote)
            .await
            .map_err(|e| CollateralError::Unreachable {
                url: self.pccs_url.clone(),
                source: e,
            })?;

        let mut guard = recover(self.entries.write());
        guard.insert(
            canonical_fmspc(&key),
            Entry {
                collateral: Arc::new(collateral),
                fetched: Instant::now(),
            },
        );
        Ok(())
    }

    /// Test-only `&str` entry point, kept so the existing case/whitespace
    /// tests can exercise canonicalization directly without fabricating a
    /// `Fmspc` for every spelling under test. Shares [`lookup_at_key`] with
    /// the production path, so it cannot drift from `get`'s behavior.
    #[cfg(test)]
    fn get_by_str(&self, fmspc: &str) -> CacheLookup {
        self.lookup_at_key(fmspc, Instant::now())
    }

    #[cfg(test)]
    pub(crate) fn insert_for_test(
        &self,
        fmspc: &str,
        collateral: QuoteCollateralV3,
        fetched: Instant,
    ) {
        let key = canonical_fmspc(fmspc);
        let mut guard = recover(self.entries.write());
        guard.insert(
            key,
            Entry {
                collateral: Arc::new(collateral),
                fetched,
            },
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A platform with a leading zero byte and no repeated bytes, so a
    /// mutated hex renderer (dropped zero-padding, reversed byte order)
    /// cannot coincidentally reproduce the correct string.
    const SAMPLE_FMSPC: Fmspc = [0x00, 0x80, 0x6f, 0x05, 0x00, 0x00];

    fn fake_collateral() -> QuoteCollateralV3 {
        QuoteCollateralV3 {
            pck_crl_issuer_chain: String::new(),
            root_ca_crl: Vec::new(),
            pck_crl: Vec::new(),
            tcb_info_issuer_chain: String::new(),
            tcb_info: String::new(),
            tcb_info_signature: Vec::new(),
            qe_identity_issuer_chain: String::new(),
            qe_identity: String::new(),
            qe_identity_signature: Vec::new(),
            pck_certificate_chain: None,
        }
    }

    /// The only function that produces a real cache key from a real FMSPC.
    /// Every other test enters through the `&str` seam with hand-written
    /// hex, so nothing else in this suite would notice a broken renderer —
    /// dropped zero-padding or a reversed byte order would each still leave
    /// every other test green while `refresh` silently wrote a key `get`
    /// would never read.
    #[test]
    fn fmspc_to_hex_renders_zero_padded_lowercase_in_byte_order() {
        assert_eq!(fmspc_to_hex(&SAMPLE_FMSPC), "00806f050000");
    }

    #[test]
    fn an_empty_cache_reports_absent_not_an_error() {
        let c = CollateralCache::new("https://pccs.invalid".into(), Duration::from_secs(3600));
        assert!(matches!(c.get_by_str("00806f050000"), CacheLookup::Absent));
    }

    #[test]
    fn a_fresh_entry_is_returned() {
        let c = CollateralCache::new("https://pccs.invalid".into(), Duration::from_secs(3600));
        c.insert_for_test("00806f050000", fake_collateral(), Instant::now());
        assert!(matches!(
            c.get_by_str("00806f050000"),
            CacheLookup::Fresh(_)
        ));
    }

    /// The constraint that matters: age must degrade to Stale, and Stale must
    /// be a distinct state the verifier turns into `Unverified`. If this ever
    /// returned Fresh, the gateway would verify against expired TCB data and
    /// report a revoked platform as up to date.
    ///
    /// Ages the entry by advancing the `now` passed to `lookup_at` rather
    /// than sleeping or subtracting from `Instant::now()`: no real time
    /// needs to pass (no flake surface), and `t0 + duration` only ever moves
    /// forward, so there is no underflow path regardless of host uptime —
    /// unlike `Instant::now() - Duration::from_secs(N)`, which can panic on
    /// `CLOCK_MONOTONIC` hosts that booted more recently than N seconds ago.
    #[test]
    fn an_aged_entry_is_stale_and_never_fresh() {
        let ttl = Duration::from_secs(60);
        let c = CollateralCache::new("https://pccs.invalid".into(), ttl);
        let t0 = Instant::now();
        c.insert_for_test(&fmspc_to_hex(&SAMPLE_FMSPC), fake_collateral(), t0);

        match c.lookup_at(&SAMPLE_FMSPC, t0 + Duration::from_secs(61)) {
            CacheLookup::Stale { age } => assert!(age > ttl),
            other => panic!("expired collateral must be Stale, got {other:?}"),
        }
    }

    /// Pins the TTL boundary exactly: fresh for the full TTL, stale the
    /// instant after. Only possible because `lookup_at` takes `now` as a
    /// parameter — with a real clock, `age` measured at call time is never
    /// exactly equal to a `ttl` fixed at insertion (some real time always
    /// passes), so `>` and `>=` are indistinguishable to any test built on
    /// `Instant::now()`. Injecting `now` makes `age == ttl` reproducible and
    /// closes that gap: `>=` would report `Stale` at exactly the boundary,
    /// failing the first assertion below.
    #[test]
    fn an_entry_is_fresh_at_the_ttl_boundary_and_stale_one_tick_past_it() {
        let ttl = Duration::from_secs(60);
        let c = CollateralCache::new("https://pccs.invalid".into(), ttl);
        let t0 = Instant::now();
        c.insert_for_test(&fmspc_to_hex(&SAMPLE_FMSPC), fake_collateral(), t0);

        assert!(matches!(
            c.lookup_at(&SAMPLE_FMSPC, t0 + ttl),
            CacheLookup::Fresh(_)
        ));
        match c.lookup_at(&SAMPLE_FMSPC, t0 + ttl + Duration::from_nanos(1)) {
            CacheLookup::Stale { age } => assert_eq!(age, ttl + Duration::from_nanos(1)),
            other => panic!("one tick past the ttl must be Stale, got {other:?}"),
        }
    }

    #[test]
    fn entries_for_different_fmspc_do_not_collide() {
        let c = CollateralCache::new("https://pccs.invalid".into(), Duration::from_secs(3600));
        c.insert_for_test("aaaaaaaaaaaa", fake_collateral(), Instant::now());
        assert!(matches!(c.get_by_str("bbbbbbbbbbbb"), CacheLookup::Absent));
    }

    /// The FMSPC is the cache key. If `insert` and `get` ever canonicalized
    /// differently — or not at all — a `refresh` for one spelling and a
    /// `get` for another spelling of the *same* platform would silently miss
    /// and the gateway would report `Unverified` forever with nothing
    /// failing loudly. Pins both directions: inserted-lower/looked-up-upper
    /// and inserted-upper/looked-up-lower.
    #[test]
    fn two_spellings_of_the_same_fmspc_resolve_to_the_same_entry() {
        let c = CollateralCache::new("https://pccs.invalid".into(), Duration::from_secs(3600));
        c.insert_for_test("00806f050000", fake_collateral(), Instant::now());
        assert!(matches!(
            c.get_by_str("00806F050000"),
            CacheLookup::Fresh(_)
        ));

        let c2 = CollateralCache::new("https://pccs.invalid".into(), Duration::from_secs(3600));
        c2.insert_for_test("00806F050000", fake_collateral(), Instant::now());
        assert!(matches!(
            c2.get_by_str("00806f050000"),
            CacheLookup::Fresh(_)
        ));
    }

    /// Incidental whitespace around an FMSPC must not create a distinct key
    /// from the trimmed spelling — same reasoning as the case test above.
    #[test]
    fn an_fmspc_with_incidental_whitespace_matches_the_trimmed_spelling() {
        let c = CollateralCache::new("https://pccs.invalid".into(), Duration::from_secs(3600));
        c.insert_for_test(" 00806f050000 ", fake_collateral(), Instant::now());
        assert!(matches!(
            c.get_by_str("00806f050000"),
            CacheLookup::Fresh(_)
        ));
    }

    /// Fail-open binds this module absolutely: no lock state may panic it.
    /// Poison the lock deliberately (a panic while holding the *write*
    /// lock) and confirm both a read and a subsequent write still go
    /// through instead of panicking on the poison — a poison test that only
    /// reads afterward would leave `recover`'s use on the write path
    /// (`refresh`, `insert_for_test`) unheld, since `.expect(...)` there
    /// would only be exercised by a write that happens after the poison.
    #[test]
    fn get_survives_a_lock_poisoned_by_a_prior_panic() {
        let c = CollateralCache::new("https://pccs.invalid".into(), Duration::from_secs(3600));
        c.insert_for_test("00806f050000", fake_collateral(), Instant::now());

        let poisoned = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _guard = c.entries.write().expect("lock is not yet poisoned");
            panic!("simulated panic while holding the write lock");
        }));
        assert!(poisoned.is_err());

        assert!(matches!(
            c.get_by_str("00806f050000"),
            CacheLookup::Fresh(_)
        ));

        // Write recovery: an insert after the poison must still land.
        c.insert_for_test("bbbbbbbbbbbb", fake_collateral(), Instant::now());
        assert!(matches!(
            c.get_by_str("bbbbbbbbbbbb"),
            CacheLookup::Fresh(_)
        ));
    }

    /// `get` must hand back a shared handle to the cached collateral, not a
    /// copy — the whole point of `Arc` here. A deep-copying substitution
    /// (`Arc::new((*e.collateral).clone())`) would still satisfy every other
    /// test in this suite (the returned value is equal, just not the same
    /// allocation) while cloning the full collateral bundle on every
    /// request-path lookup.
    #[test]
    fn get_returns_a_shared_handle_not_a_clone() {
        let c = CollateralCache::new("https://pccs.invalid".into(), Duration::from_secs(3600));
        c.insert_for_test("00806f050000", fake_collateral(), Instant::now());

        let (CacheLookup::Fresh(a), CacheLookup::Fresh(b)) =
            (c.get_by_str("00806f050000"), c.get_by_str("00806f050000"))
        else {
            panic!("expected two Fresh lookups");
        };
        assert!(Arc::ptr_eq(&a, &b));
    }

    /// `refresh` must fail cleanly rather than panic on a quote too short to
    /// decode — and it does, but at the parsing step, before any network
    /// I/O: `Quote::parse` (and, redundantly, `CollateralClient::fetch`'s
    /// own internal `Quote::decode`) rejects an 8-byte buffer long before
    /// `pccs_url` is ever read, since a `Quote` header alone is 48 bytes.
    /// The target address (127.0.0.1:1, nothing listening) is deliberately
    /// unreachable too, so this test cannot start passing for a networking
    /// reason instead of a parsing one.
    //
    // TODO(task 4/7): add a companion test asserting `CollateralError::
    // Unreachable` against a genuinely unreachable PCCS. That needs a
    // byte-valid DCAP quote fixture — one that survives `Quote::decode`
    // (correct SCALE encoding of `Header` + a report + `AuthData`) — which
    // does not exist in this repo and is out of this task's scope to build.
    #[tokio::test]
    async fn refresh_on_an_undecodable_quote_errors_rather_than_panicking() {
        let c = CollateralCache::new("http://127.0.0.1:1".into(), Duration::from_secs(60));
        let err = c.refresh(&[0u8; 8]).await.unwrap_err();
        assert!(matches!(err, CollateralError::NoFmspc));
    }
}
