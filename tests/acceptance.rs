use occultation::bench::{composed_report, run_bench, BenchOptions};
use occultation::cost::{BudgetVerdict, BUDGET};
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
    assert!(naive.published);
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
    }
}
