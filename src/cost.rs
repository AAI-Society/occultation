use serde::Serialize;
use std::time::Duration;

/// The per-action latency budget from P05 and the desk study.
pub const BUDGET: Duration = Duration::from_millis(15);

/// Headroom below this fraction of the budget is reported as `Marginal`.
/// 5% of 15 ms is 750 µs. The desk study's cached-pairing composition leaves
/// 100 µs, and calling that a pass is the second half of its arithmetic error.
const MARGINAL_FRACTION: u32 = 20;

/// Where a number came from. Every `Measurement` carries one, because the
/// desk study's central failure was presenting figures from published
/// benchmarks of other people's hardware as if they characterised this stack.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Source {
    /// Timed on this host, in this process, by `harness::measure`.
    MeasuredHere { iters: u32 },
    /// Read from a publication. Never measured here.
    Published { citation: &'static str },
}

impl std::fmt::Display for Source {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Source::MeasuredHere { iters } => write!(f, "measured here (n={iters})"),
            Source::Published { citation } => {
                write!(f, "PUBLISHED — {citation}; not measured on this stack")
            }
        }
    }
}

/// A cost, its label, and where it came from. There is no other constructor,
/// so a number cannot enter the tool anonymously.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Measurement {
    pub label: String,
    pub cost: Duration,
    pub source: Source,
}

impl Measurement {
    pub fn new(label: impl Into<String>, cost: Duration, source: Source) -> Self {
        Measurement {
            label: label.into(),
            cost,
            source,
        }
    }

    pub fn is_published(&self) -> bool {
        matches!(self.source, Source::Published { .. })
    }

    pub fn citation(&self) -> Option<&'static str> {
        match self.source {
            Source::Published { citation } => Some(citation),
            Source::MeasuredHere { .. } => None,
        }
    }
}

/// The verdict on a latency against the budget.
///
/// `Marginal` is the variant that earns its keep. Without it, 14.9 ms against
/// a 15 ms budget reports as a pass, which is what the desk study concluded
/// and is the claim this tool exists to correct.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "verdict", rename_all = "snake_case")]
pub enum BudgetVerdict {
    Misses { over: Duration },
    Marginal { headroom: Duration },
    Fits { headroom: Duration },
}

impl std::fmt::Display for BudgetVerdict {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BudgetVerdict::Misses { over } => write!(f, "MISSES by {}", fmt_ms(*over)),
            BudgetVerdict::Marginal { headroom } => {
                write!(
                    f,
                    "MARGINAL — {} spare, which is not headroom",
                    fmt_ms(*headroom)
                )
            }
            BudgetVerdict::Fits { headroom } => write!(f, "fits, {} spare", fmt_ms(*headroom)),
        }
    }
}

/// Render a duration in milliseconds, which is the unit the 15 ms budget is
/// quoted in and therefore the unit every verdict should read in.
pub fn fmt_ms(d: Duration) -> String {
    format!("{:.2} ms", d.as_secs_f64() * 1e3)
}

pub fn judge(total: Duration) -> BudgetVerdict {
    if total > BUDGET {
        return BudgetVerdict::Misses {
            over: total - BUDGET,
        };
    }
    let headroom = BUDGET - total;
    if headroom <= BUDGET / MARGINAL_FRACTION {
        BudgetVerdict::Marginal { headroom }
    } else {
        BudgetVerdict::Fits { headroom }
    }
}

/// A present-and-verify path judged as one path.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Composed {
    pub present: Duration,
    pub verify: Duration,
    pub total: Duration,
    pub budget: Duration,
    pub verdict: BudgetVerdict,
}

/// Sum the two halves and judge the sum. The desk study judged the halves.
pub fn compose(present: Duration, verify: Duration) -> Composed {
    let total = present + verify;
    Composed {
        present,
        verify,
        total,
        budget: BUDGET,
        verdict: judge(total),
    }
}

const DESK: &str = "research/Accountable Unlinkable Agent Identity.md, \
                    \"Empirical Overhead and Execution Latency at Agent Action Rates\"";

/// A set of costs for one profile of the construction.
#[derive(Clone, Debug, Serialize)]
pub struct CostProfile {
    pub name: &'static str,
    pub ed25519_sign: Measurement,
    pub ed25519_verify: Measurement,
    pub present_naive: Measurement,
    pub present_pooled: Measurement,
    pub verify_naive: Measurement,
    pub verify_cached: Measurement,
}

impl CostProfile {
    /// The desk study's published figures, verbatim. Not measured here, and
    /// every entry says so. Reproducing this profile's arithmetic on any host
    /// is what makes the headline correction checkable by a third party.
    pub fn desk_study() -> Self {
        let p = |label: &str, micros: u64| {
            Measurement::new(
                label,
                Duration::from_micros(micros),
                Source::Published { citation: DESK },
            )
        };
        CostProfile {
            name: "desk-study (published)",
            ed25519_sign: p("Ed25519 sign", 97),
            ed25519_verify: p("Ed25519 verify", 162),
            present_naive: p("BBS+ presentation", 13_800),
            present_pooled: p("BBS+ presentation, pre-computed pool", 2_800),
            verify_naive: p("BBS+ verification", 4_200),
            verify_cached: p("BBS+ verification, cached pairings", 1_100),
        }
    }

    pub fn all(&self) -> Vec<&Measurement> {
        vec![
            &self.ed25519_sign,
            &self.ed25519_verify,
            &self.present_naive,
            &self.present_pooled,
            &self.verify_naive,
            &self.verify_cached,
        ]
    }

    /// Sign plus verify, the like-for-like comparison against a composed
    /// BBS+ path.
    pub fn baseline_round_trip(&self) -> Duration {
        self.ed25519_sign.cost + self.ed25519_verify.cost
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ms(n: u64) -> Duration {
        Duration::from_millis(n)
    }

    #[test]
    fn a_measurement_always_carries_a_source() {
        let m = Measurement::new("x", ms(1), Source::MeasuredHere { iters: 100 });
        assert!(matches!(m.source, Source::MeasuredHere { iters: 100 }));
        let p = Measurement::new(
            "y",
            ms(1),
            Source::Published {
                citation: "somewhere",
            },
        );
        assert!(p.is_published(), "a published figure must announce itself");
    }

    #[test]
    fn a_published_figure_renders_the_word_published() {
        let p = Measurement::new(
            "BBS+ presentation",
            Duration::from_micros(13_800),
            Source::Published {
                citation: "desk study",
            },
        );
        let rendered = format!("{}", p.source);
        assert!(rendered.contains("PUBLISHED"), "got {rendered}");
        assert!(rendered.contains("desk study"), "the citation must survive");
    }

    /// The headline correction. The desk study assessed 13.8 ms and 4.2 ms
    /// separately against a 15 ms budget and called each acceptable. Summed,
    /// it misses by 3 ms.
    #[test]
    fn the_desk_study_naive_composition_misses_the_budget() {
        let p = CostProfile::desk_study();
        let c = compose(p.present_naive.cost, p.verify_naive.cost);
        assert_eq!(c.total, Duration::from_micros(18_000));
        assert_eq!(c.verdict, BudgetVerdict::Misses { over: ms(3) });
    }

    /// Each half, taken alone, fits — which is exactly how the error was made.
    #[test]
    fn each_half_alone_fits_which_is_how_the_error_happened() {
        let p = CostProfile::desk_study();
        assert!(matches!(
            judge(p.present_naive.cost),
            BudgetVerdict::Fits { .. } | BudgetVerdict::Marginal { .. }
        ));
        assert!(matches!(
            judge(p.verify_naive.cost),
            BudgetVerdict::Fits { .. }
        ));
    }

    /// With cached pairings the sum is 14.9 ms: under the limit with 100 µs
    /// left, which is not headroom. `Marginal` exists so the tool cannot
    /// report that as a pass.
    #[test]
    fn cached_pairings_alone_are_marginal_not_a_pass() {
        let p = CostProfile::desk_study();
        let c = compose(p.present_naive.cost, p.verify_cached.cost);
        assert_eq!(c.total, Duration::from_micros(14_900));
        assert_eq!(
            c.verdict,
            BudgetVerdict::Marginal {
                headroom: Duration::from_micros(100)
            }
        );
    }

    #[test]
    fn the_pool_plus_cached_pairings_fits_with_room() {
        let p = CostProfile::desk_study();
        let c = compose(p.present_pooled.cost, p.verify_cached.cost);
        assert_eq!(c.total, Duration::from_micros(3_900));
        assert_eq!(
            c.verdict,
            BudgetVerdict::Fits {
                headroom: Duration::from_micros(11_100)
            }
        );
    }

    #[test]
    fn the_marginal_band_is_five_percent_of_the_budget() {
        // 750 µs headroom is the edge: inside is Marginal, outside is Fits.
        assert!(matches!(
            judge(BUDGET - Duration::from_micros(750)),
            BudgetVerdict::Marginal { .. }
        ));
        assert!(matches!(
            judge(BUDGET - Duration::from_micros(751)),
            BudgetVerdict::Fits { .. }
        ));
    }

    #[test]
    fn exactly_on_the_budget_is_marginal_not_a_miss() {
        assert_eq!(
            judge(BUDGET),
            BudgetVerdict::Marginal {
                headroom: Duration::ZERO
            }
        );
    }

    #[test]
    fn every_desk_study_figure_is_published_not_measured() {
        let p = CostProfile::desk_study();
        for m in p.all() {
            assert!(m.is_published(), "{} claims to be measured here", m.label);
            assert!(!m.citation().unwrap().is_empty());
        }
    }
}
