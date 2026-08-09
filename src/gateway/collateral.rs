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
/// `dcap_qvl::intel::quote_fmspc` returns a raw `[u8; 6]`, not a string —
/// this module is what turns it into hex, via [`fmspc_to_hex`], and that
/// path always emits lowercase with no separators. But `get`'s `fmspc: &str`
/// parameter is a public seam: nothing stops a caller (or a future verifier)
/// from passing a differently-cased or padded spelling of the same FMSPC.
/// Canonicalizing on every `insert` and every `get` is what keeps a
/// `refresh` and a later `get` for the same platform from silently missing
/// each other — a miss here degrades to `Absent`/`Unverified`, never loudly.
fn canonical_fmspc(fmspc: &str) -> String {
    fmspc.trim().to_ascii_lowercase()
}

/// Render a raw FMSPC as the lowercase hex string used as the cache key.
fn fmspc_to_hex(fmspc: &Fmspc) -> String {
    fmspc.iter().map(|b| format!("{b:02x}")).collect()
}

/// Recover a lock guard even if a prior holder panicked while holding it.
///
/// Fail-open binds this module absolutely: no lock state may panic it. The
/// critical sections here (a `HashMap` read or insert, a `Duration`
/// comparison) do not themselves panic in ordinary operation, but *if* one
/// ever did, poisoning the lock, every subsequent `get` — on the hot request
/// path — must still return an answer rather than panic on the poison. The
/// map's own invariants survive a panicked writer (`HashMap::insert` is
/// exception-safe), so recovering the guard is sound, not merely convenient.
fn recover<T>(result: Result<T, PoisonError<T>>) -> T {
    result.unwrap_or_else(PoisonError::into_inner)
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

    /// Synchronous, lock-only lookup. Safe to call inline on the request
    /// path — it does no I/O and cannot block on anything but this cache's
    /// own (briefly held, panic-tolerant) lock.
    pub fn get(&self, fmspc: &str) -> CacheLookup {
        let key = canonical_fmspc(fmspc);
        let guard = recover(self.entries.read());
        match guard.get(&key) {
            None => CacheLookup::Absent,
            Some(e) => {
                let age = e.fetched.elapsed();
                if age > self.ttl {
                    CacheLookup::Stale { age }
                } else {
                    CacheLookup::Fresh(Arc::clone(&e.collateral))
                }
            }
        }
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
    pub async fn refresh(&self, quote: &[u8]) -> Result<(), CollateralError> {
        let parsed = Quote::parse(quote).map_err(|_| CollateralError::NoFmspc)?;
        let fmspc = dcap_qvl::intel::quote_fmspc(&parsed).map_err(|_| CollateralError::NoFmspc)?;
        let key = canonical_fmspc(&fmspc_to_hex(&fmspc));

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
            key,
            Entry {
                collateral: Arc::new(collateral),
                fetched: Instant::now(),
            },
        );
        Ok(())
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

    #[test]
    fn an_empty_cache_reports_absent_not_an_error() {
        let c = CollateralCache::new("https://pccs.invalid".into(), Duration::from_secs(3600));
        assert!(matches!(c.get("00806f050000"), CacheLookup::Absent));
    }

    #[test]
    fn a_fresh_entry_is_returned() {
        let c = CollateralCache::new("https://pccs.invalid".into(), Duration::from_secs(3600));
        c.insert_for_test("00806f050000", fake_collateral(), Instant::now());
        assert!(matches!(c.get("00806f050000"), CacheLookup::Fresh(_)));
    }

    /// The constraint that matters: age must degrade to Stale, and Stale must
    /// be a distinct state the verifier turns into `Unverified`. If this ever
    /// returned Fresh, the gateway would verify against expired TCB data and
    /// report a revoked platform as up to date.
    ///
    /// Ages the entry with a real sleep rather than `Instant::now() -
    /// Duration::from_secs(N)`: on Linux `Instant` is `CLOCK_MONOTONIC` (time
    /// since boot), so subtracting from `now()` underflows and panics on any
    /// host that booted more recently than N seconds ago. Sleeping instead
    /// can only make the measured age larger than the TTL, never risk going
    /// negative.
    #[test]
    fn an_aged_entry_is_stale_and_never_fresh() {
        let ttl = Duration::from_millis(20);
        let c = CollateralCache::new("https://pccs.invalid".into(), ttl);
        c.insert_for_test("00806f050000", fake_collateral(), Instant::now());
        std::thread::sleep(Duration::from_millis(100));
        match c.get("00806f050000") {
            CacheLookup::Stale { age } => assert!(age > ttl),
            other => panic!("expired collateral must be Stale, got {other:?}"),
        }
    }

    #[test]
    fn entries_for_different_fmspc_do_not_collide() {
        let c = CollateralCache::new("https://pccs.invalid".into(), Duration::from_secs(3600));
        c.insert_for_test("aaaaaaaaaaaa", fake_collateral(), Instant::now());
        assert!(matches!(c.get("bbbbbbbbbbbb"), CacheLookup::Absent));
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
        assert!(matches!(c.get("00806F050000"), CacheLookup::Fresh(_)));

        let c2 = CollateralCache::new("https://pccs.invalid".into(), Duration::from_secs(3600));
        c2.insert_for_test("00806F050000", fake_collateral(), Instant::now());
        assert!(matches!(c2.get("00806f050000"), CacheLookup::Fresh(_)));
    }

    /// Incidental whitespace around an FMSPC must not create a distinct key
    /// from the trimmed spelling — same reasoning as the case test above.
    #[test]
    fn an_fmspc_with_incidental_whitespace_matches_the_trimmed_spelling() {
        let c = CollateralCache::new("https://pccs.invalid".into(), Duration::from_secs(3600));
        c.insert_for_test(" 00806f050000 ", fake_collateral(), Instant::now());
        assert!(matches!(c.get("00806f050000"), CacheLookup::Fresh(_)));
    }

    /// Fail-open binds this module absolutely: no lock state may panic it.
    /// Poison the write lock deliberately (a panic while holding it) and
    /// confirm `get` still answers instead of panicking on the poison. This
    /// is what justifies `recover`'s `unwrap_or_else(PoisonError::into_inner)`
    /// over the more common `.expect(...)` — with `.expect`, this test would
    /// panic instead of asserting.
    #[test]
    fn get_survives_a_lock_poisoned_by_a_prior_panic() {
        let c = CollateralCache::new("https://pccs.invalid".into(), Duration::from_secs(3600));
        c.insert_for_test("00806f050000", fake_collateral(), Instant::now());

        let poisoned = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _guard = c.entries.write().expect("lock is not yet poisoned");
            panic!("simulated panic while holding the write lock");
        }));
        assert!(poisoned.is_err());

        assert!(matches!(c.get("00806f050000"), CacheLookup::Fresh(_)));
    }

    #[tokio::test]
    async fn an_unreachable_pccs_is_an_error_not_a_panic() {
        let c = CollateralCache::new("http://127.0.0.1:1".into(), Duration::from_secs(60));
        assert!(c.refresh(&[0u8; 8]).await.is_err());
    }
}
