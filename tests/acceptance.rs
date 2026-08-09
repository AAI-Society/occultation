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

use occultation::anonymity::{partition, Fleet};
use std::path::Path;

/// Acceptance test 3 — a single-TCB fleet is one anonymity set the size of the
/// fleet; a drifted fleet reports its partition sizes.
#[test]
fn a_single_tcb_fleet_has_an_anonymity_set_equal_to_the_fleet() {
    let f = Fleet::load(Path::new("examples/fleet-uniform.toml")).unwrap();
    let r = partition(&f).unwrap();
    assert_eq!(r.fleet_size, 120);
    assert_eq!(r.partitions.len(), 1);
    assert_eq!(r.partitions[0].size, r.fleet_size);
    assert_eq!(r.min_set, 120);
    assert_eq!(r.singletons, 0);
    assert!((r.effective_set - 120.0).abs() < 1e-9);
    assert!(
        r.entropy_bits.abs() < 1e-12,
        "a uniform fleet leaks no bits"
    );
}

#[test]
fn a_fleet_with_tcb_drift_reports_its_partition_sizes() {
    let f = Fleet::load(Path::new("examples/fleet-drifted.toml")).unwrap();
    let r = partition(&f).unwrap();

    assert_eq!(r.fleet_size, 120, "the same 120 hosts as the uniform fleet");
    let sizes: Vec<usize> = r.partitions.iter().map(|p| p.size).collect();
    assert_eq!(sizes, vec![71, 34, 11, 3, 1]);

    // The finding: identical hardware, six weeks of ordinary drift, and the
    // largest anonymity set is now 71 rather than 120 — with one host alone.
    assert_eq!(r.min_set, 1);
    assert_eq!(r.max_set, 71);
    assert_eq!(r.singletons, 1);
    // Pinned to the value, not to a bound. `> 1.0` is cleared by a natural-log
    // substitution at 1.019 — a 1.9% margin — so the paper's "1.470 bits" and
    // the word "bits" itself would be a figure no test could notice changing.
    assert!(
        (r.effective_set - 6328.0 / 120.0).abs() < 1e-9,
        "effective set {} (expected sum(n^2)/N = 52.7333)",
        r.effective_set
    );
    assert!(
        (r.entropy_bits - 1.470_103_8).abs() < 1e-6,
        "entropy {} bits (expected 1.4701038; log2, not ln)",
        r.entropy_bits
    );

    // And it must say which attributes did it, or an operator cannot act.
    assert!(r
        .distinguishing_attributes
        .contains(&"microcode".to_string()));
    assert!(r.distinguishing_attributes.contains(&"pce_svn".to_string()));
}

/// The uniform fleet is the paper's control, so its report must not claim
/// anything about singletons. `singletons > 0` -> `>= 0` survives the rest of
/// the suite and makes that report say "0 host(s) are alone on their TCB
/// configuration ... no credential scheme can help them", which is
/// categorically false about the fleet the whole comparison rests on.
#[test]
fn a_uniform_fleets_report_makes_no_claim_about_singletons() {
    let f = Fleet::load(Path::new("examples/fleet-uniform.toml")).unwrap();
    let out = partition(&f).unwrap().render();
    assert!(
        !out.contains("alone on their TCB configuration"),
        "a fleet with no singletons must not claim it has some:\n{out}"
    );
    assert!(
        out.contains("No TCB attribute varies"),
        "and it must say why:\n{out}"
    );

    // The converse, so neither sentence can simply be deleted.
    let d = Fleet::load(Path::new("examples/fleet-drifted.toml")).unwrap();
    let drifted = partition(&d).unwrap().render();
    assert!(drifted.contains("alone on their TCB configuration"));
    assert!(!drifted.contains("No TCB attribute varies"));
}

/// The policy exit code, so the check drops into a CI pipeline.
#[test]
fn a_minimum_set_size_policy_is_enforceable() {
    let f = Fleet::load(Path::new("examples/fleet-drifted.toml")).unwrap();
    assert!(
        partition(&f).unwrap().min_set < 10,
        "the CLI must exit 1 for --min-set 10"
    );
}

use std::process::Command;

fn occultation() -> Command {
    Command::new(env!("CARGO_BIN_EXE_occultation"))
}

/// Acceptance test 4 — a stub refuses to run without an explicit opt-in.
#[test]
fn a_modelled_component_refuses_to_run_without_allow_modelled() {
    let out = occultation()
        .args(["bench", "--composed", "--with-escrow", "--iters", "3"])
        .output()
        .expect("the binary runs");

    assert_eq!(
        out.status.code(),
        Some(3),
        "requesting a stub without the flag must exit 3"
    );

    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("--allow-modelled"),
        "must name the flag: {stderr}"
    );
    assert!(
        stderr.contains("no security"),
        "must say why the flag exists: {stderr}"
    );
}

#[test]
fn the_same_command_succeeds_with_allow_modelled_and_warns_loudly() {
    let out = occultation()
        .args([
            "bench",
            "--composed",
            "--with-escrow",
            "--allow-modelled",
            "--iters",
            "3",
        ])
        .output()
        .expect("the binary runs");

    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("MODELLED"),
        "the warning must reach stderr: {stderr}"
    );
    assert!(stderr.contains("no security"));

    // The flag's actual EFFECT, not just its acknowledgement. Both stderr
    // assertions above come from the MODELLED_WARNING banner, which any
    // --allow-modelled run prints whether or not escrow was requested — so
    // without this, replacing the escrow threading with `None` leaves the
    // whole suite green and the flag is silently inert.
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("+ MODELLED escrow tag"),
        "the composed rows must show the escrow tag was folded in: {stdout}"
    );
}

/// And the converse: without `--with-escrow` the escrow tag must NOT be in
/// the composed path, and the rows must say what they exclude.
#[test]
fn without_with_escrow_the_composed_path_says_what_it_leaves_out() {
    let out = occultation()
        .args(["bench", "--composed", "--iters", "3"])
        .output()
        .expect("the binary runs");
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(!stdout.contains("+ MODELLED escrow tag"));
    assert!(
        stdout.contains("excludes the escrow tag"),
        "a composed path missing a third of its presentation cost must say so: {stdout}"
    );
    // And the estimated row must keep its own caveat rather than having it
    // overwritten by the escrow note.
    assert!(
        stdout.contains("almost certainly too low"),
        "the estimated row's caveat must survive: {stdout}"
    );
}

#[test]
fn a_plain_bench_never_touches_a_stub_and_says_so() {
    let out = occultation()
        .args(["bench", "--iters", "3"])
        .output()
        .expect("runs");
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        !stdout.contains("MODELLED"),
        "no modelled rows without the flag"
    );
    assert!(
        stdout.contains("--allow-modelled"),
        "must explain what is missing: {stdout}"
    );
}

#[test]
fn bench_with_allow_modelled_labels_every_stub_row() {
    let out = occultation()
        .args(["bench", "--allow-modelled", "--iters", "3"])
        .output()
        .expect("runs");
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("ECDAA"));
    assert!(stdout.contains("escrow"));
    // Both stub rows plus the footer.
    assert!(stdout.matches("MODELLED").count() >= 3, "{stdout}");
}

/// The policy exit codes, end to end, so all four commands drop into CI.
#[test]
fn policy_violations_exit_one_and_bad_input_exits_two() {
    let violation = occultation()
        .args([
            "anonymity",
            "--fleet",
            "examples/fleet-drifted.toml",
            "--min-set",
            "10",
        ])
        .output()
        .expect("runs");
    assert_eq!(violation.status.code(), Some(1));

    let bad_input = occultation()
        .args(["anonymity", "--fleet", "examples/does-not-exist.toml"])
        .output()
        .expect("runs");
    assert_eq!(bad_input.status.code(), Some(2));
}

// ---------------------------------------------------------------------
// The results contract: byte-stability of results/deterministic/
// ---------------------------------------------------------------------

/// Every writer that feeds `results/` emits sorted keys, over the *real*
/// inputs `scripts/regen-results.sh` uses.
///
/// `results/deterministic/`'s stated guarantee is that it is byte-identical
/// on any host, and CI enforces it by regenerating and diffing. That
/// guarantee was never actually held by anything: `serde_json::Map` happened
/// to be a `BTreeMap`, so objects came out sorted for free — until `dcap-qvl`
/// arrived for the gateway's quote verification, declaring `serde_json` with
/// `preserve_order`. Cargo unifies features graph-wide, the map became an
/// `IndexMap`, and every one of these files changed its bytes with nothing in
/// this repository touched. Values were identical throughout; only key order
/// moved. Nobody noticed for five commits, because nobody ran the regen.
///
/// So the real guarantee was "byte-identical given this lockfile".
/// `report::canonical_json` is what makes it the advertised one instead, and
/// this is the test that stops it being deleted as redundant — which it looks
/// like, and which it was, right up until it wasn't.
///
/// Deliberately driven from `examples/fleet-drifted.toml` and the same burst
/// parameters the regen script passes, not from a synthetic fixture: the
/// claim is about the committed files, so the test should exercise what
/// produces them.
#[test]
fn every_writer_that_feeds_results_emits_sorted_keys() {
    fn keys_are_sorted(value: &serde_json::Value) -> bool {
        match value {
            serde_json::Value::Object(map) => {
                let keys: Vec<&String> = map.keys().collect();
                keys.windows(2).all(|w| w[0] <= w[1]) && map.values().all(keys_are_sorted)
            }
            serde_json::Value::Array(items) => items.iter().all(keys_are_sorted),
            _ => true,
        }
    }

    // results/deterministic/anonymity-drifted.json
    let fleet =
        occultation::anonymity::Fleet::load(std::path::Path::new("examples/fleet-drifted.toml"))
            .expect("the committed drifted fleet loads");
    let anonymity = occultation::anonymity::partition(&fleet).expect("the fleet partitions");
    assert!(
        keys_are_sorted(&anonymity.to_json()),
        "AnonymityReport::to_json is not sorted; results/deterministic/ \
         would change bytes on any host whose dependency graph differs"
    );

    // results/deterministic/pool-burst-5000.json, the regen script's own
    // parameters.
    let burst = simulate_burst(&BurstConfig {
        burst_rate_hz: 5000.0,
        duration: Duration::from_secs(2),
        capacity: 64,
        refill_cost: Duration::from_micros(700),
        online_cost: Duration::from_micros(60),
        seed: 7,
    })
    .expect("the regen script's burst parameters simulate");
    assert!(
        keys_are_sorted(&burst.to_json()),
        "BurstReport::to_json is not sorted"
    );

    // results/measured/. Not diffed by CI — wall-clock timing cannot be —
    // but held to the same rule, because "our output does not depend on a
    // transitive dependency's feature flags" is not a property worth having
    // in half the files.
    let costs = run_bench(&BenchOptions {
        iters: 1,
        ..Default::default()
    })
    .expect("a one-iteration bench runs");
    assert!(
        keys_are_sorted(&composed_report(&costs).to_json()),
        "ComposedReport::to_json is not sorted"
    );

    // The non-vacuity check, mirroring `report.rs`'s own. If insertion order
    // does not survive in this build, every assertion above is true for free.
    let out_of_order = serde_json::json!({ "b": 1, "a": 2 });
    let preserve_order_active = out_of_order
        .as_object()
        .expect("an object")
        .keys()
        .next()
        .map(String::as_str)
        == Some("b");
    if !preserve_order_active {
        // Not a failure — it is the regime this crate used to be in, and the
        // sort is still correct. But the assertions above proved nothing
        // about it, and that should be visible rather than assumed.
        eprintln!(
            "note: serde_json is compiled without `preserve_order`, so every \
             object sorts itself and this test cannot distinguish a working \
             canonical_json from a missing one. Check `cargo tree -e features` \
             before trusting it."
        );
    }
}
