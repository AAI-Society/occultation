use crate::bbs::proof::ProofScalars;
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::{HashSet, VecDeque};
use std::time::Duration;

/// Above this many simulated requests the run is refused rather than
/// allocated. A burst description that implies billions of actions is a typo,
/// and turning it into an out-of-memory kill helps nobody.
const MAX_REQUESTS: usize = 20_000_000;

#[derive(Debug, thiserror::Error)]
pub enum PoolError {
    #[error("a pool needs capacity of at least 1, got {0}")]
    ZeroCapacity(usize),
    #[error("burst rate must be a positive number of requests per second, got {0}")]
    BadBurstRate(f64),
    #[error("refill cost must be greater than zero")]
    ZeroRefillCost,
    #[error("that burst implies {0} requests, above the {MAX_REQUESTS} limit; shorten --duration or lower --burst")]
    TooManyRequests(u128),
}

/// One pre-computed presentation's worth of blinding.
///
/// **Not `Clone` and not `Copy`, deliberately.** `consume` takes `self` by
/// value, lends the scalars for exactly one call and drops them.
///
/// **What that does and does not buy, stated precisely**, because this is the
/// claim a reader of P05 will rely on:
///
/// * Accidental reuse is impossible. No pooled item can be presented twice by
///   holding it, copying it, or re-acquiring it: the fields are private, the
///   type has no `Clone`, and `acquire` never returns an item to the queue.
/// * Deliberate reuse is **not** prevented. `consume` places no bound on its
///   return type and `ProofScalars` is `Clone` with public fields, so
///   `item.consume(|s| s.clone())` yields an owned copy that outlives the
///   item, and `prove_with_scalars` is public. What the design buys is that
///   any such reuse is a single conspicuous, greppable `.clone()` at the call
///   site rather than an emergent property of pool exhaustion — which is the
///   failure mode P05 actually asks about.
///
/// Reuse silently voids the unlinkability property the whole of P05 is about,
/// and it also hands an observer of two transcripts the signature scalar and
/// every undisclosed attribute. See
/// `reusing_one_set_of_scalars_leaks_the_signature_and_every_hidden_attribute`,
/// which performs the extraction.
pub struct PoolItem {
    scalars: ProofScalars,
    serial: u64,
}

impl PoolItem {
    /// Use this item, once.
    pub fn consume<R>(self, f: impl FnOnce(&ProofScalars) -> R) -> R {
        f(&self.scalars)
    }

    /// A stable identifier for the item's blinding, for the uniqueness audit.
    ///
    /// Covers **every** scalar in the item, not just `r1`. The audit's whole
    /// job is to notice a repeat, and a fingerprint derived from one of six
    /// fields would pass while five of them were being reused — a partial
    /// derivation is invisible in a passing test. Domain-separated and
    /// length-prefixed for the same reason `octets` is.
    pub fn fingerprint(&self) -> [u8; 32] {
        let mut parts: Vec<Vec<u8>> = vec![
            self.scalars.r1.to_bytes_be().to_vec(),
            self.scalars.r2.to_bytes_be().to_vec(),
            self.scalars.e_tilde.to_bytes_be().to_vec(),
            self.scalars.r1_tilde.to_bytes_be().to_vec(),
            self.scalars.r3_tilde.to_bytes_be().to_vec(),
        ];
        for m in &self.scalars.m_tilde {
            parts.push(m.to_bytes_be().to_vec());
        }
        let refs: Vec<&[u8]> = parts.iter().map(|p| p.as_slice()).collect();
        Sha256::digest(crate::bls::octets(&refs)).into()
    }

    pub fn serial(&self) -> u64 {
        self.serial
    }

    /// Build an item from known scalars, so the fingerprint derivation can be
    /// mutation-tested. Test-only: outside tests, the pool is the only source
    /// of items.
    #[cfg(test)]
    pub(crate) fn for_test(scalars: ProofScalars) -> Self {
        PoolItem::for_test_with_serial(scalars, 0)
    }

    #[cfg(test)]
    pub(crate) fn for_test_with_serial(scalars: ProofScalars, serial: u64) -> Self {
        PoolItem { scalars, serial }
    }
}

/// A pool of pre-computed blinding, refilled by an idle-time worker.
///
/// On exhaustion `acquire` returns `None`. The caller stalls. It never returns
/// a previously issued item, and there is no configuration under which it
/// would.
pub struct PrecomputationPool {
    capacity: usize,
    items: VecDeque<PoolItem>,
    rng: ChaCha20Rng,
    undisclosed: usize,
    next_serial: u64,
    produced: u64,
    issued: u64,
    exhaustions: u64,
}

impl PrecomputationPool {
    pub fn try_new(capacity: usize, undisclosed: usize, seed: u64) -> Result<Self, PoolError> {
        if capacity == 0 {
            return Err(PoolError::ZeroCapacity(capacity));
        }
        Ok(PrecomputationPool {
            capacity,
            items: VecDeque::with_capacity(capacity),
            rng: ChaCha20Rng::seed_from_u64(seed),
            undisclosed,
            next_serial: 0,
            produced: 0,
            issued: 0,
            exhaustions: 0,
        })
    }

    /// Convenience for tests and callers that have already validated capacity.
    pub fn new(capacity: usize, undisclosed: usize, seed: u64) -> Self {
        Self::try_new(capacity, undisclosed, seed).expect("capacity >= 1")
    }

    /// Produce one item. Returns false when the pool is already full.
    pub fn refill_one(&mut self) -> bool {
        if self.items.len() >= self.capacity {
            return false;
        }
        let scalars = ProofScalars::random(&mut self.rng, self.undisclosed);
        self.items.push_back(PoolItem {
            scalars,
            serial: self.next_serial,
        });
        self.next_serial += 1;
        self.produced += 1;
        true
    }

    pub fn fill(&mut self) {
        while self.refill_one() {}
    }

    /// Take an item, or `None` if there are none.
    ///
    /// `None` means stall. It does not mean "reuse the last one".
    pub fn acquire(&mut self) -> Option<PoolItem> {
        match self.items.pop_front() {
            Some(item) => {
                self.issued += 1;
                Some(item)
            }
            None => {
                self.exhaustions += 1;
                None
            }
        }
    }

    pub fn len(&self) -> usize {
        self.items.len()
    }

    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }

    pub fn capacity(&self) -> usize {
        self.capacity
    }

    pub fn produced(&self) -> u64 {
        self.produced
    }

    pub fn issued(&self) -> u64 {
        self.issued
    }

    pub fn exhaustions(&self) -> u64 {
        self.exhaustions
    }
}

#[derive(Clone, Debug)]
pub struct BurstConfig {
    pub capacity: usize,
    /// Wall-clock cost of pre-computing one item inside the TEE.
    pub refill_cost: Duration,
    /// Wall-clock cost of finishing a presentation once an item is in hand.
    pub online_cost: Duration,
    pub burst_rate_hz: f64,
    pub duration: Duration,
    pub seed: u64,
}

#[derive(Clone, Debug, Serialize)]
pub struct BurstReport {
    pub requests: usize,
    pub served_immediately: usize,
    pub stalled: usize,
    pub exhausted: bool,
    pub refill_rate_hz: f64,
    pub burst_rate_hz: f64,
    pub stall_total: Duration,
    pub stall_max: Duration,
    pub latency_p50: Duration,
    pub latency_p95: Duration,
    pub latency_p99: Duration,
    pub latency_max: Duration,
    /// `latency_max / online_cost`: how far the busiest response departs from
    /// an idle one, which is the size of the timing side channel.
    ///
    /// The denominator is the **unstalled** cost, deliberately. An earlier
    /// version divided by `latency_p50`, which is wrong for the case that
    /// matters: under a sustained burst the queue grows linearly, so the
    /// median stall is about half the maximum and the ratio saturates near
    /// 2.0 however bad the backlog gets. A metric that reports 2.0 whether
    /// the worst response is 2 ms or 6 s does not measure a side channel.
    ///
    /// **It grows linearly with `duration`.** The queue is unstable under
    /// sustained overload, so there is no steady state: this is the peak over
    /// the observation window, not a property of the pool. On the shipped
    /// burst, 1 s gives ~59,000x and 8 s gives ~479,000x. Quote it with its
    /// duration, and quote `growth_per_request` beside it as the invariant.
    pub amplification: f64,
    pub distinct_blinding_factors: usize,
    /// Always zero. Present so the report says so out loud, and computed from
    /// the issued fingerprints rather than asserted, so it would catch a pool
    /// that started handing items out twice.
    pub reuse_events: usize,
    /// How many times `acquire` returned `None` — the real pool's exhaustion
    /// count, not the fluid model's. Reported so the stall claim is made
    /// against a pool that genuinely ran dry.
    pub pool_exhaustions: u64,
    /// Requests per second by which arrivals outrun refill, as a ratio.
    /// Duration-invariant: it says whether a channel exists at all.
    pub overload_factor: f64,
    /// How many idle-responses of extra delay each successive request pays
    /// relative to the one before it, once the pool is dry:
    /// `(1/refill_rate - 1/burst_rate) / online_cost`.
    ///
    /// This is the duration-invariant companion to `amplification`, and it is
    /// the figure to quote as a system property. `amplification` is the peak
    /// observed over `duration` and grows linearly with it — 2 s of this burst
    /// gives ~119,000x and 8 s gives ~479,000x — so it characterises the
    /// observation window as much as the pool.
    pub growth_per_request: f64,
    /// The request index at which the buffer ran dry, if it did. How briefly
    /// an adversary must sustain a burst before the channel opens — and the
    /// figure `capacity` actually moves.
    pub onset_request: Option<usize>,
}

/// Run a burst against a pool.
///
/// Refill is modelled as one worker producing at `1/refill_cost`, capped at
/// `capacity`, using a fluid approximation of the queue level. Item issuance
/// is not approximated: every served request takes a real `PoolItem` with real
/// scalars, so the uniqueness audit measures the actual pool rather than the
/// model of it.
pub fn simulate_burst(cfg: &BurstConfig) -> Result<BurstReport, PoolError> {
    if !cfg.burst_rate_hz.is_finite() || cfg.burst_rate_hz <= 0.0 {
        return Err(PoolError::BadBurstRate(cfg.burst_rate_hz));
    }
    if cfg.refill_cost.is_zero() {
        return Err(PoolError::ZeroRefillCost);
    }
    let implied = (cfg.duration.as_secs_f64() * cfg.burst_rate_hz).ceil();
    if !implied.is_finite() || implied > MAX_REQUESTS as f64 {
        return Err(PoolError::TooManyRequests(implied as u128));
    }
    let requests = implied as usize;

    let mut pool = PrecomputationPool::try_new(cfg.capacity, 8, cfg.seed)?;
    pool.fill();

    let refill_rate = 1.0 / cfg.refill_cost.as_secs_f64();
    let interval = 1.0 / cfg.burst_rate_hz;
    let capacity = cfg.capacity as f64;

    // Items available, as a real number. Starts full. It goes *negative*
    // once arrivals outrun refill, which is deliberate: the negative part is
    // the backlog, and it is what makes each successive stall longer than the
    // last. An unthrottled burst above the refill rate does not settle at a
    // constant penalty — the delay grows without bound for as long as the
    // burst lasts, which is the shape of the side channel.
    let mut level = capacity;
    let mut last_t = 0.0f64;

    let mut latencies: Vec<Duration> = Vec::with_capacity(requests);
    let mut stalls: Vec<Duration> = Vec::with_capacity(requests);
    let mut fingerprints: HashSet<[u8; 32]> = HashSet::with_capacity(requests);
    let mut served_immediately = 0usize;
    let mut stalled = 0usize;
    let mut onset_request: Option<usize> = None;

    for k in 0..requests {
        let t = k as f64 * interval;
        level = (level + (t - last_t) * refill_rate).min(capacity);
        last_t = t;

        let stall_secs = if level >= 1.0 {
            level -= 1.0;
            served_immediately += 1;
            0.0
        } else {
            // Wait for the worker to finish the item in progress.
            let wait = (1.0 - level) / refill_rate;
            level = 0.0;
            last_t = t + wait;
            stalled += 1;
            onset_request.get_or_insert(k);
            wait
        };

        // Drive the real pool from the model rather than topping it up before
        // every acquire. Refilling to capacity each iteration would mean
        // `acquire` never returned `None`, `exhaustions()` were provably zero,
        // and the "stall, never reuse" assertion would be made against a pool
        // that never stalled — asserting only that ChaCha20 does not repeat.
        let due = (level.max(0.0).floor() as usize).saturating_sub(pool.len());
        for _ in 0..due {
            pool.refill_one();
        }
        let item = match pool.acquire() {
            Some(item) => item,
            None => {
                // The model says this request waited for the worker to finish
                // an item; produce that item and take it. `acquire` returning
                // `None` here is the exhaustion path, and it is the only way
                // a caller ever learns the pool is empty.
                pool.refill_one();
                pool.acquire().expect("the worker just produced one")
            }
        };
        fingerprints.insert(item.fingerprint());

        let stall = Duration::from_secs_f64(stall_secs);
        stalls.push(stall);
        latencies.push(cfg.online_cost + stall);
    }

    latencies.sort_unstable();
    let pick = |q: f64| -> Duration {
        if latencies.is_empty() {
            Duration::ZERO
        } else {
            latencies[(((latencies.len() - 1) as f64) * q).round() as usize]
        }
    };
    let p50 = pick(0.50);
    let latency_max = latencies.last().copied().unwrap_or_default();

    Ok(BurstReport {
        requests,
        served_immediately,
        stalled,
        exhausted: stalled > 0,
        refill_rate_hz: refill_rate,
        burst_rate_hz: cfg.burst_rate_hz,
        stall_total: stalls.iter().sum(),
        stall_max: stalls.iter().copied().max().unwrap_or_default(),
        latency_p50: p50,
        latency_p95: pick(0.95),
        latency_p99: pick(0.99),
        latency_max,
        // A zero idle cost means any stall at all is infinitely amplified.
        // Reporting 1.0 — "no side channel" — for a run with six-second
        // stalls would invert the metric's meaning.
        amplification: match (cfg.online_cost.is_zero(), latency_max.is_zero()) {
            (_, true) => 1.0,
            (true, false) => f64::INFINITY,
            (false, false) => latency_max.as_secs_f64() / cfg.online_cost.as_secs_f64(),
        },
        distinct_blinding_factors: fingerprints.len(),
        reuse_events: requests - fingerprints.len(),
        pool_exhaustions: pool.exhaustions(),
        overload_factor: cfg.burst_rate_hz / refill_rate,
        growth_per_request: if cfg.online_cost.is_zero() {
            f64::INFINITY
        } else {
            ((1.0 / refill_rate) - interval).max(0.0) / cfg.online_cost.as_secs_f64()
        },
        onset_request,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bbs::keys::KeyPair;
    use crate::bbs::proof::{prove_with_scalars, verify_proof};
    use crate::bbs::sign::{message_to_scalar, sign};
    use crate::bls::Generators;
    use blstrs::Scalar;
    use ff::Field;
    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng;
    use std::collections::HashSet;
    use std::time::Duration;

    /// Compile-time guard: `PoolItem` must never gain `Clone`.
    ///
    /// Autoref specialization — the by-value impl needs one autoref and the
    /// `&Probe<T>` impl needs two, so Rust picks the first when `T: Clone` and
    /// falls back otherwise. If this becomes a maintenance burden, delete it
    /// and keep the behavioural tests below, but do not delete it *and* add
    /// `#[derive(Clone)]`.
    mod clone_probe {
        use std::marker::PhantomData;
        pub struct Probe<T>(pub PhantomData<T>);
        pub trait IsClone {
            fn probe(&self) -> bool;
        }
        impl<T: Clone> IsClone for Probe<T> {
            fn probe(&self) -> bool {
                true
            }
        }
        pub trait NotClone {
            fn probe(&self) -> bool;
        }
        impl<T> NotClone for &Probe<T> {
            fn probe(&self) -> bool {
                false
            }
        }
    }

    #[test]
    // The `&` before every `.probe()` call below is load-bearing: it is what
    // selects the zero-autoref candidate the specialization trick depends on.
    // Removing it, as clippy suggests, would change which impl gets picked
    // and silently break the probe.
    #[allow(clippy::needless_borrow)]
    fn pool_items_are_not_clonable() {
        use clone_probe::{IsClone, NotClone};
        use std::marker::PhantomData;
        let item = clone_probe::Probe::<PoolItem>(PhantomData);
        assert!(
            !(&item).probe(),
            "PoolItem gained Clone; blinding reuse is now representable"
        );
        // Control: the probe does detect Clone when it is present.
        let control = clone_probe::Probe::<u64>(PhantomData);
        assert!((&control).probe());
    }

    #[test]
    fn an_empty_pool_hands_back_nothing_rather_than_something_old() {
        let mut p = PrecomputationPool::new(2, 3, 7);
        p.fill();
        assert!(p.acquire().is_some());
        assert!(p.acquire().is_some());
        assert!(
            p.acquire().is_none(),
            "an exhausted pool must yield None, never a used item"
        );
        assert_eq!(p.exhaustions(), 1);
    }

    #[test]
    fn every_item_a_pool_ever_issues_is_distinct() {
        let mut p = PrecomputationPool::new(8, 3, 7);
        let mut seen: HashSet<[u8; 32]> = HashSet::new();
        for _ in 0..500 {
            p.fill();
            let item = p.acquire().expect("just filled");
            assert!(
                seen.insert(item.fingerprint()),
                "a blinding factor was issued twice"
            );
        }
        assert_eq!(seen.len(), 500);
        assert_eq!(p.issued(), 500);
    }

    /// The identity-derivation check. A fingerprint that ignored a field
    /// would let the uniqueness audit pass while that field was reused.
    #[test]
    fn a_change_in_any_single_scalar_changes_the_fingerprint() {
        let base = ProofScalars::random(&mut ChaCha20Rng::seed_from_u64(1), 3);
        let item = PoolItem::for_test(base.clone());
        let reference = item.fingerprint();

        // Semantically identical input must compare equal.
        assert_eq!(PoolItem::for_test(base.clone()).fingerprint(), reference);

        // And every contributing field must be able to break that equality.
        let bump = Scalar::from(7u64);
        let mutations: Vec<(&str, ProofScalars)> = vec![
            (
                "r1",
                ProofScalars {
                    r1: base.r1 + bump,
                    ..base.clone()
                },
            ),
            (
                "r2",
                ProofScalars {
                    r2: base.r2 + bump,
                    ..base.clone()
                },
            ),
            (
                "e_tilde",
                ProofScalars {
                    e_tilde: base.e_tilde + bump,
                    ..base.clone()
                },
            ),
            (
                "r1_tilde",
                ProofScalars {
                    r1_tilde: base.r1_tilde + bump,
                    ..base.clone()
                },
            ),
            (
                "r3_tilde",
                ProofScalars {
                    r3_tilde: base.r3_tilde + bump,
                    ..base.clone()
                },
            ),
            ("m_tilde[0]", {
                let mut s = base.clone();
                s.m_tilde[0] += bump;
                s
            }),
            ("m_tilde[2]", {
                let mut s = base.clone();
                s.m_tilde[2] += bump;
                s
            }),
        ];
        for (field, mutated) in mutations {
            assert_ne!(
                PoolItem::for_test(mutated).fingerprint(),
                reference,
                "the fingerprint ignores `{field}`, so the reuse audit cannot see it change"
            );
        }
    }

    /// The other direction of the identity constraint, and it is not
    /// decorative: adding `parts.push(self.serial.to_be_bytes().to_vec())` to
    /// the fingerprint is a one-line change that leaves every other test in
    /// this module green — and it would make every fingerprint unique by
    /// construction, so `reuse_events` would be permanently 0 and the audit
    /// would be silently dead.
    #[test]
    fn the_serial_is_excluded_from_the_fingerprint() {
        let s = ProofScalars::random(&mut ChaCha20Rng::seed_from_u64(3), 2);
        let a = PoolItem::for_test_with_serial(s.clone(), 0);
        let b = PoolItem::for_test_with_serial(s, 9_999);
        assert_ne!(a.serial(), b.serial());
        assert_eq!(
            a.fingerprint(),
            b.fingerprint(),
            "the serial must not enter the fingerprint, or the reuse audit is dead"
        );
    }

    #[test]
    fn refilling_a_full_pool_produces_nothing() {
        let mut p = PrecomputationPool::new(3, 1, 7);
        p.fill();
        assert_eq!(p.len(), 3);
        assert!(!p.refill_one(), "a full pool must not grow past capacity");
        assert_eq!(p.produced(), 3);
    }

    #[test]
    fn a_zero_capacity_pool_is_an_error_not_a_permanent_stall() {
        assert!(PrecomputationPool::try_new(0, 1, 7).is_err());
    }

    /// The demonstration. This is what the type system prevents, shown by
    /// bypassing the pool and calling the low-level prover twice with one set
    /// of scalars.
    #[test]
    fn reusing_one_set_of_scalars_leaks_the_signature_and_every_hidden_attribute() {
        let kp = KeyPair::generate(7);
        let gens = Generators::create(4);
        let msgs: Vec<Scalar> = (0..4)
            .map(|i| message_to_scalar(format!("attribute-{i}").as_bytes()).unwrap())
            .collect();
        let sig = sign(&kp.sk, &kp.pk, &gens, b"h", &msgs).unwrap();
        let disclosed = [0usize];
        let pairs: Vec<(usize, Scalar)> = vec![(0, msgs[0])];

        // One set of scalars, two presentations to two relying parties.
        let s = ProofScalars::random(&mut ChaCha20Rng::seed_from_u64(99), 3);
        let p1 = prove_with_scalars(&kp.pk, &gens, b"h", b"rp-one", &sig, &msgs, &disclosed, &s)
            .unwrap();
        let p2 = prove_with_scalars(&kp.pk, &gens, b"h", b"rp-two", &sig, &msgs, &disclosed, &s)
            .unwrap();

        // Both are individually valid, so neither relying party sees a problem.
        assert!(verify_proof(&kp.pk, &gens, b"h", b"rp-one", &pairs, &p1).unwrap());
        assert!(verify_proof(&kp.pk, &gens, b"h", b"rp-two", &pairs, &p2).unwrap());

        // Linkage, on sight.
        assert_eq!(
            p1.a_bar, p2.a_bar,
            "reuse makes two showings trivially linkable"
        );
        assert_eq!(p1.d, p2.d);

        // And the witness falls out by subtraction.
        let dc = Option::<Scalar>::from((p1.challenge - p2.challenge).invert()).unwrap();
        let recovered_e = (p1.e_hat - p2.e_hat) * dc;
        assert_eq!(recovered_e, sig.e, "the signature scalar is recoverable");

        // Undisclosed attributes 1, 2 and 3, in order.
        for (k, j) in [1usize, 2, 3].into_iter().enumerate() {
            let recovered = (p1.m_hat[k] - p2.m_hat[k]) * dc;
            assert_eq!(recovered, msgs[j], "hidden attribute {j} is recoverable");
        }
    }

    #[test]
    fn a_burst_below_the_refill_rate_never_stalls() {
        let cfg = BurstConfig {
            capacity: 32,
            refill_cost: Duration::from_micros(1_000), // 1000 items/s
            online_cost: Duration::from_micros(50),
            burst_rate_hz: 100.0, // well under refill
            duration: Duration::from_secs(2),
            seed: 7,
        };
        let r = simulate_burst(&cfg).unwrap();
        assert!(
            !r.exhausted,
            "a pool refilling faster than it drains cannot exhaust"
        );
        assert_eq!(r.stalled, 0);
        assert_eq!(r.stall_max, Duration::ZERO);
        assert_eq!(r.stall_total, Duration::ZERO);
        assert_eq!(r.served_immediately, r.requests);
        assert_eq!(r.pool_exhaustions, 0, "a pool that never ran dry");
        assert!(r.onset_request.is_none());
        assert!(
            r.overload_factor < 1.0,
            "arrivals must be below refill here"
        );
        // No stall means no side channel: every response costs the same.
        assert!(
            (r.amplification - 1.0).abs() < 1e-9,
            "amplification {}",
            r.amplification
        );
    }

    #[test]
    fn a_burst_above_the_refill_rate_exhausts_and_stalls() {
        let cfg = BurstConfig {
            capacity: 32,
            refill_cost: Duration::from_micros(1_000), // 1000 items/s
            online_cost: Duration::from_micros(50),
            burst_rate_hz: 4_000.0, // four times refill
            duration: Duration::from_secs(2),
            seed: 7,
        };
        let r = simulate_burst(&cfg).unwrap();
        assert!(r.exhausted);
        assert!(r.stalled > 0);
        assert!(r.stall_max > Duration::ZERO);
        assert_eq!(r.reuse_events, 0, "the pool must stall, never reuse");
        assert_eq!(
            r.distinct_blinding_factors, r.requests,
            "every request got a fresh item"
        );
        // Against a pool that genuinely ran dry, not one topped up before
        // every acquire: `acquire` returned None, and that is the only way a
        // caller learns the pool is empty.
        assert!(
            r.pool_exhaustions > 0,
            "the real pool never exhausted, so this proves nothing"
        );
        assert_eq!(r.served_immediately + r.stalled, r.requests);
        assert!(r.stall_total > Duration::ZERO);
    }

    #[test]
    fn the_duration_invariant_metrics_do_not_move_with_the_window() {
        // amplification is a peak over the observation window and scales with
        // it; growth_per_request, overload_factor and onset are properties of
        // the pool and must not.
        let base = BurstConfig {
            capacity: 32,
            refill_cost: Duration::from_micros(1_000),
            online_cost: Duration::from_micros(50),
            burst_rate_hz: 4_000.0,
            duration: Duration::from_secs(1),
            seed: 7,
        };
        let short = simulate_burst(&base).unwrap();
        let long = simulate_burst(&BurstConfig {
            duration: Duration::from_secs(4),
            ..base.clone()
        })
        .unwrap();

        assert!((short.growth_per_request - long.growth_per_request).abs() < 1e-9);
        assert!((short.overload_factor - long.overload_factor).abs() < 1e-9);
        assert_eq!(short.onset_request, long.onset_request);

        // (1/1000 - 1/4000) / 50e-6 = 0.00075 / 0.00005 = 15
        assert!(
            (short.growth_per_request - 15.0).abs() < 1e-6,
            "{}",
            short.growth_per_request
        );
        assert!((short.overload_factor - 4.0).abs() < 1e-9);

        // And the peak does move, roughly in proportion to the window.
        assert!(long.amplification > short.amplification * 3.0);
    }

    #[test]
    fn the_stall_grows_through_a_sustained_burst() {
        // The side channel: latency is not merely worse under load, it climbs
        // for as long as the burst lasts, so an observer can read the agent's
        // load — and the burst's duration — off response times alone.
        let cfg = BurstConfig {
            capacity: 32,
            refill_cost: Duration::from_micros(1_000),
            online_cost: Duration::from_micros(50),
            burst_rate_hz: 4_000.0,
            duration: Duration::from_secs(2),
            seed: 7,
        };
        let r = simulate_burst(&cfg).unwrap();

        // Growth, not merely a constant penalty: the median request waits far
        // less than the last one. In a queue whose backlog grows linearly the
        // median lands near half the maximum, so this ratio is bounded by
        // about 2 by construction — assert the growth, but do not treat this
        // ratio as the side-channel measure.
        assert!(
            r.latency_max > r.latency_p50,
            "the stall must grow, not plateau"
        );
        assert!(r.latency_p99 > r.latency_p50);

        // The side channel itself, measured against an idle response rather
        // than a median that is already stalled.
        assert!(
            r.amplification > 100.0,
            "the worst response was only {:.1}x an idle one",
            r.amplification
        );
        assert!(
            r.stall_max > Duration::from_millis(100),
            "stall_max {:?}",
            r.stall_max
        );
    }

    #[test]
    fn the_simulation_is_deterministic() {
        let cfg = BurstConfig {
            capacity: 16,
            refill_cost: Duration::from_micros(800),
            online_cost: Duration::from_micros(40),
            burst_rate_hz: 3_000.0,
            duration: Duration::from_secs(1),
            seed: 7,
        };
        let a = simulate_burst(&cfg).unwrap();
        let b = simulate_burst(&cfg).unwrap();
        assert_eq!(a.requests, b.requests);
        assert_eq!(a.stalled, b.stalled);
        assert_eq!(a.stall_total, b.stall_total);
        assert_eq!(a.latency_p99, b.latency_p99);
    }

    #[test]
    fn a_nonpositive_burst_rate_is_an_error_not_an_infinite_loop() {
        let base = BurstConfig {
            capacity: 8,
            refill_cost: Duration::from_micros(1_000),
            online_cost: Duration::from_micros(50),
            burst_rate_hz: 0.0,
            duration: Duration::from_secs(1),
            seed: 7,
        };
        assert!(simulate_burst(&base).is_err());
        assert!(simulate_burst(&BurstConfig {
            burst_rate_hz: -5.0,
            ..base.clone()
        })
        .is_err());
        assert!(simulate_burst(&BurstConfig {
            burst_rate_hz: f64::NAN,
            ..base.clone()
        })
        .is_err());
        assert!(simulate_burst(&BurstConfig {
            refill_cost: Duration::ZERO,
            ..base.clone()
        })
        .is_err());
    }

    #[test]
    fn an_absurd_request_count_is_refused_rather_than_allocated() {
        let cfg = BurstConfig {
            capacity: 8,
            refill_cost: Duration::from_micros(1_000),
            online_cost: Duration::from_micros(50),
            burst_rate_hz: 1e9,
            duration: Duration::from_secs(3_600),
            seed: 7,
        };
        assert!(
            simulate_burst(&cfg).is_err(),
            "3.6e12 requests must not be attempted"
        );
    }
}
