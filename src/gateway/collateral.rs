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
use std::time::{Duration, Instant, UNIX_EPOCH};

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

/// Why an entry is no longer usable. Two genuinely different failures, and
/// an operator has to be able to tell them apart: the first is a knob they
/// chose, the second is Intel's clock.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StaleReason {
    /// Older than the configured [`CollateralCache`] TTL.
    PastOurTtl,
    /// Inside our TTL, but past the validity window the collateral itself
    /// declares. Carries the `nextUpdate` it declared, in Unix seconds.
    PastDeclaredValidity { next_update: u64 },
}

#[derive(Debug)]
pub enum CacheLookup {
    Fresh(Arc<QuoteCollateralV3>),
    /// Present but no longer usable. Structurally distinct from `Fresh` — a
    /// verifier that matches on this enum cannot mistake one for the other.
    /// The verifier turns this into `Unverified`, never into a verification
    /// against expired TCB data: an aged entry might describe a platform
    /// that Intel has since revoked, so treating it as current would report
    /// a revoked platform as up to date.
    Stale {
        age: Duration,
        reason: StaleReason,
    },
    Absent,
}

struct Entry {
    collateral: Arc<QuoteCollateralV3>,
    fetched: Instant,
    /// The `nextUpdate` the collateral declares for itself, in Unix
    /// seconds — see [`declared_expiry`]. `None` when neither document
    /// carried a readable one.
    declared_expiry: Option<u64>,
}

/// Read a `nextUpdate` out of one of the collateral's two JSON documents.
///
/// Both are carried as raw JSON strings on [`QuoteCollateralV3`] (that is
/// what the signature is computed over), so this parses generically rather
/// than through `dcap_qvl`'s own `TcbInfo`/`QeIdentity` structs: a document
/// this crate cannot fully model must still yield its expiry, and a future
/// upstream field addition must not turn into a parse failure here.
///
/// Intel writes these as RFC 3339 with a `Z` offset and no fractional part
/// (`2025-07-19T10:16:03Z`), which is exactly what `humantime` accepts —
/// and `humantime` is already a dependency, so reading the window costs no
/// new one.
fn next_update_secs(document: &str) -> Option<u64> {
    let parsed: serde_json::Value = serde_json::from_str(document).ok()?;
    let text = parsed.get("nextUpdate")?.as_str()?;
    humantime::parse_rfc3339(text)
        .ok()?
        .duration_since(UNIX_EPOCH)
        .ok()
        .map(|d| d.as_secs())
}

/// The DER tags this module reads. `SEQUENCE` is constructed, both time
/// types are primitive; nothing else is inspected.
const DER_SEQUENCE: u8 = 0x30;
const DER_UTC_TIME: u8 = 0x17;
const DER_GENERALIZED_TIME: u8 = 0x18;

/// Split one DER tag-length-value off the front of `bytes`, returning the
/// tag, its contents, and whatever follows.
///
/// Deliberately not a DER parser. It reads a tag byte, a definite length,
/// and a body, and it refuses everything else — indefinite length (which DER
/// forbids anyway) and lengths wider than four bytes both come back `None`.
/// Every slice is taken through a checked accessor, so a truncated or
/// hostile encoding is a `None` and never a panic; `crl_next_update_secs`
/// turns `None` into "no declared window", which is the behaviour that
/// shipped.
fn der_tlv(bytes: &[u8]) -> Option<(u8, &[u8], &[u8])> {
    let (&tag, rest) = bytes.split_first()?;
    let (&first_length_byte, rest) = rest.split_first()?;
    let (length, rest) = if first_length_byte < 0x80 {
        (usize::from(first_length_byte), rest)
    } else {
        let width = usize::from(first_length_byte & 0x7f);
        if width == 0 || width > 4 {
            return None;
        }
        let (length_bytes, rest) = rest.split_at_checked(width)?;
        let length = length_bytes
            .iter()
            .fold(0usize, |acc, byte| (acc << 8) | usize::from(*byte));
        (length, rest)
    };
    let (value, rest) = rest.split_at_checked(length)?;
    Some((tag, value, rest))
}

/// Turn a DER `UTCTime` or `GeneralizedTime` into Unix seconds.
///
/// Reformatted into RFC 3339 and handed to `humantime` rather than converted
/// here: there is no calendar arithmetic in this crate and this is not the
/// place to introduce some. The two-digit-year rule is RFC 5280 §4.1.2.5.1's
/// — `00..=49` is 20xx, `50..=99` is 19xx.
fn der_time_to_unix_secs(tag: u8, value: &[u8]) -> Option<u64> {
    let text = std::str::from_utf8(value).ok()?;
    let digits = text.strip_suffix('Z')?;
    let (year, rest) = match tag {
        DER_UTC_TIME => {
            let (yy, rest) = digits.split_at_checked(2)?;
            let yy: u32 = yy.parse().ok()?;
            (if yy < 50 { 2000 + yy } else { 1900 + yy }, rest)
        }
        DER_GENERALIZED_TIME => {
            let (yyyy, rest) = digits.split_at_checked(4)?;
            (yyyy.parse().ok()?, rest)
        }
        _ => return None,
    };
    // MMDDHHMMSS, and DER requires the seconds and the `Z` this has already
    // stripped, so anything else is not a DER time.
    if rest.len() != 10 || !rest.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let rfc3339 = format!(
        "{year:04}-{}-{}T{}:{}:{}Z",
        &rest[0..2],
        &rest[2..4],
        &rest[4..6],
        &rest[6..8],
        &rest[8..10]
    );
    humantime::parse_rfc3339(&rfc3339)
        .ok()?
        .duration_since(UNIX_EPOCH)
        .ok()
        .map(|d| d.as_secs())
}

/// Read a CRL's `nextUpdate`, in Unix seconds.
///
/// `CertificateList ::= SEQUENCE { tbsCertList, signatureAlgorithm,
/// signatureValue }`, and `TBSCertList ::= SEQUENCE { version INTEGER
/// OPTIONAL, signature SEQUENCE, issuer SEQUENCE, thisUpdate Time,
/// nextUpdate Time OPTIONAL, ... }`. So the two `Time`s at the top level of
/// `tbsCertList` are `thisUpdate` and `nextUpdate` in that order, and
/// nothing before or after them at that level is a `Time` — the fields
/// ahead are an INTEGER and two SEQUENCEs, and those behind are the revoked
/// list (a SEQUENCE) and a `[0]` extensions block. Taking the *second* time
/// is therefore exact rather than heuristic, and a CRL with no `nextUpdate`
/// yields `None` because there is no second one to find.
fn crl_next_update_secs(der: &[u8]) -> Option<u64> {
    let (tag, certificate_list, _) = der_tlv(der)?;
    if tag != DER_SEQUENCE {
        return None;
    }
    let (tag, tbs_cert_list, _) = der_tlv(certificate_list)?;
    if tag != DER_SEQUENCE {
        return None;
    }

    let mut rest = tbs_cert_list;
    let mut seen_this_update = false;
    while let Some((tag, value, next)) = der_tlv(rest) {
        if tag == DER_UTC_TIME || tag == DER_GENERALIZED_TIME {
            if seen_this_update {
                return der_time_to_unix_secs(tag, value);
            }
            seen_this_update = true;
        }
        rest = next;
    }
    None
}

/// The earliest moment this bundle stops being usable, according to the
/// bundle itself.
///
/// This is the fix for a misattribution, not a hardening measure, and the
/// direction is the whole point. `dcap_qvl::verify::verify` enforces both of
/// these as hard errors (`bail!("TCBInfo expired")`,
/// `bail!("QE Identity expired")`), and `verify_at` maps every `Err` to
/// [`crate::gateway::verify::QuoteVerdict::Invalid`] — the *counterparty's*
/// fault. So without this, collateral fetched at T and still inside our own
/// six-hour TTL at T+Δ starts reporting every genuine quote from every
/// legitimate agent as `INVALID` the instant Intel's window closes, counts
/// them in the counter an operator watches for hostile agents, and — because
/// the verdict is `Invalid` and not `Unverified` — schedules no refresh, so
/// it persists until our TTL runs out. Reading the window here turns that
/// into `Stale` → `Unverified` → a scheduled refresh, which is what
/// `collateral_or_unverified`'s own doc has always said an aged cache is.
///
/// `None` when neither document parses. That is the pre-existing behaviour
/// (our TTL alone), not a new hole: a bundle whose `nextUpdate` this cannot
/// read is one `dcap_qvl` cannot read either, so it fails there for a
/// parsing reason rather than an expiry one.
///
/// Four of Intel's eight validity sources, and the four that bind in
/// practice: the TCB info's and the QE identity's `nextUpdate`, and the PCK
/// and root CA CRLs'.
///
/// The two CRLs are here because leaving them out was measurably not enough.
/// The vendored bundle's PCK CRL expires **928 seconds before** its TCB info
/// does, and inside that window `dcap_qvl` fails the certificate chain and
/// `verify_at` reports `Invalid` — the same misattribution, fifteen minutes
/// wide per collateral cycle instead of six hours.
/// `expired_collateral_is_our_gap_and_never_the_agents_fault` could not even
/// state its control until they were included: at the TCB info's own
/// `nextUpdate` the fixture no longer verifies.
///
/// **What this still does not cover, stated rather than implied.** The other
/// four sources are `notBefore`/`notAfter` on the PCK certificate chain, the
/// PCK CRL issuer chain, the TCB info issuer chain and the QE identity
/// issuer chain. Those are certificate validity periods measured in years
/// rather than in days, so they are not the piece that turns over inside a
/// TTL — but a bundle whose issuer chain expires while cached would still
/// produce the original misattribution, and nothing here would catch it.
/// Reading them means walking four PEM chains and a certificate structure
/// rather than a CRL header, which is where this stopped.
fn declared_expiry(collateral: &QuoteCollateralV3) -> Option<u64> {
    [
        next_update_secs(&collateral.tcb_info),
        next_update_secs(&collateral.qe_identity),
        crl_next_update_secs(&collateral.pck_crl),
        crl_next_update_secs(&collateral.root_ca_crl),
    ]
    .into_iter()
    .flatten()
    .min()
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

    /// The one place a key is looked up, given the final hex key, the
    /// instant to measure age against, and the wall clock to measure the
    /// collateral's own declared validity against.
    ///
    /// Two clocks, deliberately. Our TTL is an interval since a fetch, so it
    /// belongs on the monotonic clock and is immune to the wall clock being
    /// stepped. The collateral's `nextUpdate` is an absolute Unix timestamp
    /// Intel wrote down, so it can only be compared against a wall clock.
    /// Both are parameters so a test can pin either boundary exactly instead
    /// of racing a real clock; the production entry point passes
    /// `Instant::now()` and the same `now_secs` the verifier hands to
    /// `dcap_qvl`.
    ///
    /// The TTL is checked first, so an entry past both reports the reason an
    /// operator can act on: our TTL is a knob they set.
    ///
    /// `>=`, not `>`, and the second matters. The four windows
    /// [`declared_expiry`] reads are enforced downstream by two different
    /// comparisons: `dcap_qvl`'s JSON check bails when `now > next_update`,
    /// while webpki treats a CRL as expired at `now >= next_update` — the
    /// vendored fixture verifies at its PCK CRL's `nextUpdate` minus one
    /// second and fails at the `nextUpdate` itself, measured by bisection
    /// rather than assumed. Taking the stricter of the two here is what
    /// leaves *no* second in which this cache says `Fresh` and the verifier
    /// says expired. The cost is at most one second of early `Unverified`
    /// per collateral cycle on the two JSON windows, which is the direction
    /// that fails safe.
    fn lookup_at_key(&self, key: &str, now: Instant, now_secs: u64) -> CacheLookup {
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
                    CacheLookup::Stale {
                        age,
                        reason: StaleReason::PastOurTtl,
                    }
                } else if let Some(next_update) = e.declared_expiry.filter(|next| now_secs >= *next)
                {
                    CacheLookup::Stale {
                        age,
                        reason: StaleReason::PastDeclaredValidity { next_update },
                    }
                } else {
                    CacheLookup::Fresh(Arc::clone(&e.collateral))
                }
            }
        }
    }

    fn lookup_at(&self, fmspc: &Fmspc, now: Instant, now_secs: u64) -> CacheLookup {
        self.lookup_at_key(&fmspc_to_hex(fmspc), now, now_secs)
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
    ///
    /// `now_secs` is the wall clock in Unix seconds, and must be the same
    /// one the caller is about to hand `dcap_qvl::verify::verify`: it is
    /// what the collateral's own declared validity is measured against, and
    /// two different clocks either side of that call would reopen the gap
    /// [`declared_expiry`] closes.
    pub fn get(&self, fmspc: &Fmspc, now_secs: u64) -> CacheLookup {
        self.lookup_at(fmspc, Instant::now(), now_secs)
    }

    /// Fetch collateral for `quote`'s platform from the PCCS and cache it
    /// under its FMSPC.
    ///
    /// This does a real network round trip and offers no bound on its own
    /// latency beyond the HTTP client's timeout. It is **not** safe to call
    /// from the request path — Task 1's measurement hook already runs after
    /// the response has been forwarded, on an owned snapshot, precisely so a
    /// slow hook is not also a slow *upstream*; but that only relocates the
    /// cost, because hyper still does not write that
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

        self.insert(&key, collateral, Instant::now());
        Ok(())
    }

    /// The one place an entry is built, so the declared validity window is
    /// read on every insertion path rather than on whichever one somebody
    /// remembered. Parsing here rather than at lookup also keeps the cost
    /// off the request path: `get` stays a lock and two comparisons.
    fn insert(&self, fmspc: &str, collateral: QuoteCollateralV3, fetched: Instant) {
        let declared_expiry = declared_expiry(&collateral);
        if declared_expiry.is_none() {
            log::warn!(
                "collateral for FMSPC {fmspc} declares no readable validity window, so \
                 only this gateway's own TTL bounds it; a quote against it will be \
                 reported Invalid rather than Unverified once Intel's window closes"
            );
        }
        let mut guard = recover(self.entries.write());
        guard.insert(
            canonical_fmspc(fmspc),
            Entry {
                collateral: Arc::new(collateral),
                fetched,
                declared_expiry,
            },
        );
    }

    /// Test-only `&str` entry point, kept so the existing case/whitespace
    /// tests can exercise canonicalization directly without fabricating a
    /// `Fmspc` for every spelling under test. Shares [`lookup_at_key`] with
    /// the production path, so it cannot drift from `get`'s behavior.
    ///
    /// The wall clock it passes is the epoch, which no declared window can
    /// be behind — so these tests exercise the key and the TTL and never
    /// accidentally trip the validity check. The declared window has tests
    /// of its own below, which pass a real one.
    #[cfg(test)]
    fn get_by_str(&self, fmspc: &str) -> CacheLookup {
        self.lookup_at_key(fmspc, Instant::now(), 0)
    }

    /// Shares [`CollateralCache::insert`] with `refresh`, so a test entry
    /// carries the same declared validity a fetched one does. An insert that
    /// skipped the parse would let every test below assert against an entry
    /// shape production never produces.
    #[cfg(test)]
    pub(crate) fn insert_for_test(
        &self,
        fmspc: &str,
        collateral: QuoteCollateralV3,
        fetched: Instant,
    ) {
        self.insert(fmspc, collateral, fetched);
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

        match c.lookup_at(&SAMPLE_FMSPC, t0 + Duration::from_secs(61), 0) {
            CacheLookup::Stale { age, reason } => {
                assert!(age > ttl);
                assert_eq!(reason, StaleReason::PastOurTtl);
            }
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
            c.lookup_at(&SAMPLE_FMSPC, t0 + ttl, 0),
            CacheLookup::Fresh(_)
        ));
        match c.lookup_at(&SAMPLE_FMSPC, t0 + ttl + Duration::from_nanos(1), 0) {
            CacheLookup::Stale { age, reason } => {
                assert_eq!(age, ttl + Duration::from_nanos(1));
                assert_eq!(reason, StaleReason::PastOurTtl);
            }
            other => panic!("one tick past the ttl must be Stale, got {other:?}"),
        }
    }

    /// The vendored bundle Intel actually issued, so the two window tests
    /// below are about real dates rather than about a fixture's.
    fn real_collateral() -> QuoteCollateralV3 {
        serde_json::from_slice(include_bytes!(
            "../../tests/fixtures/tdx-quote-collateral.json"
        ))
        .expect("the vendored collateral fixture decodes")
    }

    /// The bundle's own dates, written out rather than computed, so a
    /// mutated parser cannot quietly agree with itself. Both are RFC 3339
    /// `Z` timestamps in the fixture's JSON:
    /// `tcbInfo.nextUpdate = 2025-07-19T10:16:03Z` and
    /// `enclaveIdentity.nextUpdate = 2025-07-19T10:32:27Z`.
    const REAL_TCB_INFO_NEXT_UPDATE: u64 = 1_752_920_163;
    const REAL_QE_IDENTITY_NEXT_UPDATE: u64 = 1_752_921_147;
    /// `Jul 19 10:00:35 2025 GMT`, per `openssl crl -nextupdate`. **The
    /// earliest of the four**, and by 928 seconds — which is why leaving the
    /// CRLs out of [`declared_expiry`] left the reported defect live for
    /// fifteen minutes per collateral cycle rather than closing it.
    const REAL_PCK_CRL_NEXT_UPDATE: u64 = 1_752_919_235;
    /// `Apr  3 11:21:57 2026 GMT`, and a `GeneralizedTime` rather than a
    /// `UTCTime`, so the two DER time encodings are both exercised by the
    /// fixture rather than only by hand-written bytes.
    const REAL_ROOT_CA_CRL_NEXT_UPDATE: u64 = 1_775_215_317;

    /// The parse, pinned against the real bundle and against the *earliest*
    /// of its four sources.
    ///
    /// Every part of this is load-bearing. Without the absolute values, a
    /// parser returning `Some(0)` would satisfy every behavioural test below
    /// by making everything permanently stale. Without the four separate
    /// assertions, three of the four could return `None` and the `min` would
    /// still look right. And without the PCK CRL in particular the window is
    /// 928 seconds too late, which is not a rounding error: it is the
    /// interval in which `dcap_qvl` fails the chain and every genuine quote
    /// from every legitimate agent is reported `INVALID`.
    #[test]
    fn the_declared_expiry_is_the_earliest_of_the_four_sources_it_reads() {
        let c = real_collateral();
        assert_eq!(
            next_update_secs(&c.tcb_info),
            Some(REAL_TCB_INFO_NEXT_UPDATE)
        );
        assert_eq!(
            next_update_secs(&c.qe_identity),
            Some(REAL_QE_IDENTITY_NEXT_UPDATE)
        );
        assert_eq!(
            crl_next_update_secs(&c.pck_crl),
            Some(REAL_PCK_CRL_NEXT_UPDATE)
        );
        assert_eq!(
            crl_next_update_secs(&c.root_ca_crl),
            Some(REAL_ROOT_CA_CRL_NEXT_UPDATE)
        );

        let earliest = REAL_PCK_CRL_NEXT_UPDATE;
        assert!(earliest < REAL_TCB_INFO_NEXT_UPDATE);
        assert!(earliest < REAL_QE_IDENTITY_NEXT_UPDATE);
        assert!(earliest < REAL_ROOT_CA_CRL_NEXT_UPDATE);
        assert_eq!(declared_expiry(&c), Some(earliest));
    }

    /// The DER reader, against inputs the fixture cannot supply.
    ///
    /// The fixture exercises the happy path for both time encodings; this
    /// covers what a hostile or truncated provisioning service could send.
    /// None of it may panic — this runs at insert time on bytes the gateway
    /// did not author, and a panic here poisons the refresher's loop.
    #[test]
    fn the_der_reader_refuses_malformed_input_rather_than_panicking() {
        let real = real_collateral();
        for truncation in [0, 1, 2, 3, 7, 40, 200, real.pck_crl.len() - 1] {
            // No assertion on the value: most truncations simply have no
            // readable nextUpdate. The property is that none of them panics.
            let _ = crl_next_update_secs(&real.pck_crl[..truncation]);
        }
        assert_eq!(crl_next_update_secs(&[]), None);
        assert_eq!(crl_next_update_secs(&[0x30]), None);
        // A SEQUENCE whose length runs past the buffer.
        assert_eq!(crl_next_update_secs(&[0x30, 0x7f, 0x00]), None);
        // Indefinite length: legal BER, forbidden in DER, refused here.
        assert_eq!(crl_next_update_secs(&[0x30, 0x80, 0x00, 0x00]), None);
        // A well-formed CRL shape with only one time in it — `thisUpdate`
        // and no `nextUpdate` — must not report `thisUpdate` as the window.
        assert_eq!(
            der_time_to_unix_secs(DER_UTC_TIME, b"250719100035Z"),
            Some(REAL_PCK_CRL_NEXT_UPDATE)
        );
        assert_eq!(
            der_time_to_unix_secs(DER_GENERALIZED_TIME, b"20260403112157Z"),
            Some(REAL_ROOT_CA_CRL_NEXT_UPDATE)
        );
        // RFC 5280's two-digit-year pivot, from both sides. `70` is 1970 and
        // `49` is 2049; reading either as the other century is a ~100-year
        // error in an expiry, which is exactly the kind of thing that either
        // never expires or expired before it was issued.
        assert_eq!(
            der_time_to_unix_secs(DER_UTC_TIME, b"700101000000Z"),
            Some(0),
            "a two-digit year of 70 is 1970, which is the epoch"
        );
        assert_eq!(
            der_time_to_unix_secs(DER_UTC_TIME, b"490101000000Z"),
            humantime::parse_rfc3339("2049-01-01T00:00:00Z")
                .ok()
                .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
                .map(|d| d.as_secs()),
            "a two-digit year of 49 is 2049, not 1949"
        );
        // ...and rejections.
        assert_eq!(der_time_to_unix_secs(DER_UTC_TIME, b"250719100035"), None);
        assert_eq!(der_time_to_unix_secs(DER_UTC_TIME, b"2507191000Z"), None);
        assert_eq!(der_time_to_unix_secs(DER_UTC_TIME, b"25071910xx35Z"), None);
        assert_eq!(der_time_to_unix_secs(DER_SEQUENCE, b"250719100035Z"), None);
    }

    /// An unreadable window degrades to "our TTL only", which is the
    /// behaviour that shipped, rather than to a permanently stale entry.
    /// A bundle this cannot read is one `dcap_qvl` cannot read either.
    #[test]
    fn collateral_with_no_readable_window_falls_back_to_the_ttl_alone() {
        assert_eq!(declared_expiry(&fake_collateral()), None);
        assert_eq!(next_update_secs("not json at all"), None);
        assert_eq!(
            next_update_secs(r#"{"issueDate":"2025-06-19T10:16:03Z"}"#),
            None
        );
        assert_eq!(
            next_update_secs(r#"{"nextUpdate":"not a timestamp"}"#),
            None
        );
        // Present and readable: the positive control, so the three `None`s
        // above are not simply what this function always returns.
        assert_eq!(
            next_update_secs(r#"{"nextUpdate":"2025-07-19T10:16:03Z"}"#),
            Some(REAL_TCB_INFO_NEXT_UPDATE)
        );

        // ...and an entry built from it is Fresh well past Intel's window,
        // exactly as it was before this check existed.
        let c = CollateralCache::new("https://pccs.invalid".into(), Duration::from_secs(3600));
        let t0 = Instant::now();
        c.insert_for_test(&fmspc_to_hex(&SAMPLE_FMSPC), fake_collateral(), t0);
        assert!(matches!(
            c.lookup_at(&SAMPLE_FMSPC, t0, REAL_QE_IDENTITY_NEXT_UPDATE + 1),
            CacheLookup::Fresh(_)
        ));
    }

    /// The defect, at the cache layer and at its exact boundary.
    ///
    /// A six-hour TTL and an entry fetched a moment ago: by the TTL alone
    /// this is as fresh as collateral gets, and that is precisely the state
    /// in which `dcap_qvl` starts bailing with `TCBInfo expired` and the
    /// gateway starts reporting every honest agent `INVALID`.
    ///
    /// The boundary is pinned in both directions because `>` and `>=` are
    /// otherwise indistinguishable, and only one of them agrees with
    /// `dcap_qvl`'s own comparison. `>=` would call the collateral stale a
    /// second before the verifier would call it expired — harmless — but a
    /// `<` would leave a one-second window in which the verifier says
    /// `Invalid` and this says `Fresh`, which is the whole defect in
    /// miniature.
    #[test]
    fn an_entry_inside_our_ttl_goes_stale_when_its_own_window_closes() {
        let ttl = Duration::from_secs(6 * 3600);
        let c = CollateralCache::new("https://pccs.invalid".into(), ttl);
        let t0 = Instant::now();
        c.insert_for_test(&fmspc_to_hex(&SAMPLE_FMSPC), real_collateral(), t0);

        assert!(
            matches!(
                c.lookup_at(&SAMPLE_FMSPC, t0, REAL_PCK_CRL_NEXT_UPDATE - 1),
                CacheLookup::Fresh(_)
            ),
            "one second before its earliest nextUpdate the collateral still \
             verifies — measured, not assumed — so refusing here would report \
             Unverified for collateral that works"
        );

        match c.lookup_at(&SAMPLE_FMSPC, t0, REAL_PCK_CRL_NEXT_UPDATE) {
            CacheLookup::Stale { age, reason } => {
                assert_eq!(
                    reason,
                    StaleReason::PastDeclaredValidity {
                        next_update: REAL_PCK_CRL_NEXT_UPDATE
                    },
                    "an entry inside our TTL is not stale because of our TTL"
                );
                assert!(
                    age < ttl,
                    "the entry is comfortably inside the configured TTL, which \
                     is what makes this a defect rather than an expiry"
                );
            }
            other => panic!(
                "at its own declared window, collateral must be Stale — the \
                 chain check fails from this second on and every genuine quote \
                 is then reported as the agent's fault. Got {other:?}"
            ),
        }
    }

    /// Our TTL wins the report when both have passed, because an operator
    /// can act on the TTL and cannot act on Intel's clock.
    #[test]
    fn an_entry_past_both_reports_the_ttl_the_operator_configured() {
        let ttl = Duration::from_secs(60);
        let c = CollateralCache::new("https://pccs.invalid".into(), ttl);
        let t0 = Instant::now();
        c.insert_for_test(&fmspc_to_hex(&SAMPLE_FMSPC), real_collateral(), t0);
        match c.lookup_at(
            &SAMPLE_FMSPC,
            t0 + ttl + Duration::from_secs(1),
            REAL_QE_IDENTITY_NEXT_UPDATE + 1,
        ) {
            CacheLookup::Stale { reason, .. } => assert_eq!(reason, StaleReason::PastOurTtl),
            other => panic!("expected Stale, got {other:?}"),
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
