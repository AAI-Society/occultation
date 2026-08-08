use occultation::bench::{composed_report, run_bench, BenchOptions};
use occultation::cost::{judge, BudgetVerdict, BUDGET};
use std::time::Duration;

/// Acceptance test 1, part 1 — the paper's headline correction.
///
/// Asserted against the desk study's published figures rather than this host's
/// wall clock, because the claim is about a composition error and must
/// reproduce identically on any machine. See the plan's Task 8 for why a
/// measured-wall-clock form of this assertion would be host-dependent and, on
/// current hardware, false.
#[test]
fn the_composed_path_misses_the_budget_without_pre_computation() {
    let costs = run_bench(&BenchOptions {
        iters: 5,
        ..Default::default()
    })
    .unwrap();
    let report = composed_report(&costs);

    let naive = &report.desk_study[0];
    assert!(naive.origin.is_published());
    assert_eq!(naive.composed.present, Duration::from_micros(13_800));
    assert_eq!(naive.composed.verify, Duration::from_micros(4_200));
    assert_eq!(naive.composed.total, Duration::from_micros(18_000));
    assert!(
        naive.composed.total > BUDGET,
        "18 ms must exceed the 15 ms budget"
    );
    assert_eq!(
        naive.composed.verdict,
        BudgetVerdict::Misses {
            over: Duration::from_millis(3)
        }
    );
}

/// Acceptance test 1, part 2 — with pre-computation it fits.
#[test]
fn the_composed_path_fits_the_budget_with_pre_computation() {
    let costs = run_bench(&BenchOptions {
        iters: 5,
        ..Default::default()
    })
    .unwrap();
    let report = composed_report(&costs);

    let pooled = &report.desk_study[2];
    assert_eq!(pooled.composed.total, Duration::from_micros(3_900));
    assert!(pooled.composed.total < BUDGET);
    assert_eq!(
        pooled.composed.verdict,
        BudgetVerdict::Fits {
            headroom: Duration::from_micros(11_100)
        }
    );
}

/// The half-measure in between, and the reason `Marginal` exists. Cached
/// pairings alone bring the sum to 14.9 ms: under the limit, with 100 us
/// left, which is not headroom.
#[test]
fn cached_pairings_alone_are_marginal_rather_than_a_pass() {
    let costs = run_bench(&BenchOptions {
        iters: 5,
        ..Default::default()
    })
    .unwrap();
    let report = composed_report(&costs);
    let cached = &report.desk_study[1];
    assert_eq!(cached.composed.total, Duration::from_micros(14_900));
    assert_eq!(
        cached.composed.verdict,
        BudgetVerdict::Marginal {
            headroom: Duration::from_micros(100)
        }
    );
}

/// The property that must hold for measured numbers too, on any host: the
/// budget is applied to a sum, never to a half.
///
/// `assert_eq!(total, present + verify)` alone is a tautology — `compose`
/// defines `total` that way — and worse, it does not test what this test's
/// name claims. A row judged on one half would not show up as a broken sum;
/// it would show up as `compose(present, ZERO)`, and the tautology would pass.
/// The last assertion is the one that bites: on the desk study's naive row,
/// `judge(present)` is `Fits` while `judge(total)` is `Misses`.
#[test]
fn no_verdict_is_ever_issued_against_half_a_path() {
    let costs = run_bench(&BenchOptions {
        iters: 5,
        ..Default::default()
    })
    .unwrap();
    let report = composed_report(&costs);
    for row in report.desk_study.iter().chain(report.measured.iter()) {
        assert_eq!(
            row.composed.total,
            row.composed.present + row.composed.verify
        );
        assert!(
            row.composed.present > Duration::ZERO && row.composed.verify > Duration::ZERO,
            "{}: a half-path row would have a zero half",
            row.label
        );
        assert_eq!(row.composed.verdict, judge(row.composed.total));
        assert_ne!(
            row.composed.verdict,
            judge(row.composed.present),
            "{}: the verdict matches a verdict on the presentation alone",
            row.label
        );
    }
}

use occultation::bbs::keys::KeyPair;
use occultation::bbs::proof::{prove_with_scalars, verify_proof};
use occultation::bbs::sign::{message_to_scalar, sign};
use occultation::bls::Generators;
use occultation::pool::{simulate_burst, BurstConfig, PrecomputationPool};
use std::collections::HashSet;

/// Acceptance test 2 — the pool exhausts under burst, and stalls rather than
/// reusing.
#[test]
fn a_burst_above_the_refill_rate_exhausts_and_stalls_without_reusing() {
    let cfg = BurstConfig {
        capacity: 64,
        refill_cost: Duration::from_micros(700), // ~1430 items/s
        online_cost: Duration::from_micros(60),
        burst_rate_hz: 5_000.0, // well above refill
        duration: Duration::from_secs(2),
        seed: 7,
    };
    let r = simulate_burst(&cfg).unwrap();

    assert!(
        r.exhausted,
        "5000/s against ~1430/s refill must exhaust the pool"
    );
    assert!(r.stalled > 0, "exhaustion must produce stalls");
    assert!(r.stall_max > Duration::ZERO);
    // Against a pool that genuinely ran dry, not just the fluid model's
    // `exhausted` flag: `acquire` must actually have returned `None`, since
    // that is the only way a real caller ever learns the pool is empty.
    assert!(
        r.pool_exhaustions > 0,
        "the real pool never exhausted, so this proves nothing"
    );

    // The invariant. Not a preference, not a tuning choice.
    assert_eq!(r.reuse_events, 0, "the pool reused a blinding factor");
    assert_eq!(
        r.distinct_blinding_factors, r.requests,
        "every one of {} requests must have had its own blinding",
        r.requests
    );

    // And the cost of stalling, which is the finding: latency under load is a
    // side channel, not merely a slowdown.
    assert!(
        r.amplification > 100.0,
        "the busiest response was only {:.1}x an idle one",
        r.amplification
    );
}

/// The invariant again, at the level of the pool itself rather than the
/// simulation: an exhausted pool yields nothing rather than something used.
#[test]
fn an_exhausted_pool_yields_nothing_rather_than_a_used_item() {
    let mut pool = PrecomputationPool::new(4, 3, 7);
    pool.fill();
    let mut seen: HashSet<[u8; 32]> = HashSet::new();
    for _ in 0..4 {
        seen.insert(pool.acquire().expect("pool was filled").fingerprint());
    }
    assert_eq!(seen.len(), 4);
    assert!(
        pool.acquire().is_none(),
        "an exhausted pool must stall its caller"
    );
    assert_eq!(pool.exhaustions(), 1);
}

/// Why the invariant is an invariant. Reuse is not a degradation of
/// unlinkability; it discloses the credential.
#[test]
fn reuse_would_hand_over_the_signature_and_every_hidden_attribute() {
    use blstrs::Scalar;
    use ff::Field;
    use occultation::bbs::proof::ProofScalars;
    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng;

    let kp = KeyPair::generate(7);
    let gens = Generators::create(4);
    let msgs: Vec<Scalar> = (0..4)
        .map(|i| message_to_scalar(format!("attribute-{i}").as_bytes()).unwrap())
        .collect();
    let sig = sign(&kp.sk, &kp.pk, &gens, b"h", &msgs).unwrap();
    let pairs = vec![(0usize, msgs[0])];

    let s = ProofScalars::random(&mut ChaCha20Rng::seed_from_u64(99), 3);
    let p1 = prove_with_scalars(&kp.pk, &gens, b"h", b"rp-one", &sig, &msgs, &[0], &s).unwrap();
    let p2 = prove_with_scalars(&kp.pk, &gens, b"h", b"rp-two", &sig, &msgs, &[0], &s).unwrap();

    assert!(verify_proof(&kp.pk, &gens, b"h", b"rp-one", &pairs, &p1).unwrap());
    assert!(verify_proof(&kp.pk, &gens, b"h", b"rp-two", &pairs, &p2).unwrap());

    let dc = Option::<Scalar>::from((p1.challenge - p2.challenge).invert()).unwrap();
    assert_eq!((p1.e_hat - p2.e_hat) * dc, sig.e);
    for (k, j) in [1usize, 2, 3].into_iter().enumerate() {
        assert_eq!((p1.m_hat[k] - p2.m_hat[k]) * dc, msgs[j]);
    }
}
