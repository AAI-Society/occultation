use crate::cost::{Measurement, Source};
use serde::Serialize;
use std::time::{Duration, Instant};

#[derive(Debug, thiserror::Error)]
pub enum HarnessError {
    #[error("cannot measure `{label}` with {iters} iterations; need at least 1")]
    NoIterations { label: String, iters: u32 },
    #[error(
        "`{label}` recorded {got} timings for {expected} iterations; \
         a timing that is not one of the requested iterations must never reach a Sample"
    )]
    SampleCountMismatch {
        label: String,
        expected: u32,
        got: usize,
    },
}

/// One timed closure: the distribution, not just a mean.
///
/// The median is the reported cost. A mean over a run that hit a scheduler
/// preemption is not the cost of the operation, and p99 is carried separately
/// so the pool's stall analysis has a tail to talk about.
#[derive(Clone, Debug, Serialize)]
pub struct Sample {
    pub label: String,
    pub iters: u32,
    pub min: Duration,
    pub median: Duration,
    pub mean: Duration,
    pub p95: Duration,
    pub p99: Duration,
}

impl Sample {
    pub fn measurement(&self) -> Measurement {
        Measurement::new(
            self.label.clone(),
            self.median,
            Source::MeasuredHere { iters: self.iters },
        )
    }
}

/// The quantile at `q` of an already-sorted slice, by nearest-rank.
///
/// Split out from `summarize` so it can be checked against hand-built vectors.
/// An off-by-one here would silently report the wrong tail, and Task 10 quotes
/// p95 and p99 as the size of a timing side channel.
///
/// `sorted` must be non-empty and ascending; `q` is clamped to `[0, 1]`.
pub fn percentile(sorted: &[Duration], q: f64) -> Duration {
    debug_assert!(!sorted.is_empty(), "percentile of an empty slice");
    if sorted.is_empty() {
        return Duration::ZERO;
    }
    let q = q.clamp(0.0, 1.0);
    let i = ((sorted.len() as f64 - 1.0) * q).round() as usize;
    sorted[i.min(sorted.len() - 1)]
}

/// Turn a vector of timings into a `Sample`.
///
/// Errors when `times.len()` disagrees with `iters`. That guard is the reason
/// this is a separate function: if the warmup loop's timings ever reached the
/// measured vector, every number this tool prints would be inflated by the
/// warmup fraction, and no stopwatch test could see it. Here it is a hard
/// error, checked against hand-built vectors.
pub fn summarize(
    label: &str,
    iters: u32,
    mut times: Vec<Duration>,
) -> Result<Sample, HarnessError> {
    if iters == 0 {
        return Err(HarnessError::NoIterations {
            label: label.to_string(),
            iters,
        });
    }
    if times.len() != iters as usize {
        return Err(HarnessError::SampleCountMismatch {
            label: label.to_string(),
            expected: iters,
            got: times.len(),
        });
    }
    times.sort_unstable();
    let total: Duration = times.iter().sum();
    Ok(Sample {
        label: label.to_string(),
        iters,
        min: times[0],
        median: percentile(&times, 0.50),
        mean: total / iters,
        p95: percentile(&times, 0.95),
        p99: percentile(&times, 0.99),
    })
}

/// Warm up, then time `iters` individual invocations.
///
/// Panics via `expect` only where the iteration count is a compile-time
/// constant in this crate. Anywhere the count can come from outside — a CLI
/// flag, a config file — call `try_measure` and propagate the error.
pub fn measure<T>(label: &str, iters: u32, f: impl FnMut() -> T) -> Sample {
    try_measure(label, iters, f).expect("iters > 0 and the sample count matches")
}

pub fn try_measure<T>(
    label: &str,
    iters: u32,
    mut f: impl FnMut() -> T,
) -> Result<Sample, HarnessError> {
    if iters == 0 {
        return Err(HarnessError::NoIterations {
            label: label.to_string(),
            iters,
        });
    }

    // Warm up caches, branch predictors and any lazily initialised tables in
    // blst. Ten percent of the run, capped, and never zero. These timings are
    // deliberately not recorded — `summarize` errors if any of them leak in.
    let warmup = (iters / 10).clamp(1, 50);
    for _ in 0..warmup {
        std::hint::black_box(f());
    }

    let mut times: Vec<Duration> = Vec::with_capacity(iters as usize);
    for _ in 0..iters {
        let t = Instant::now();
        std::hint::black_box(f());
        times.push(t.elapsed());
    }
    summarize(label, iters, times)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn measure_reports_the_iteration_count_it_actually_ran() {
        let s = measure("noop", 50, || std::hint::black_box(1u64 + 1));
        assert_eq!(s.iters, 50);
        assert_eq!(s.label, "noop");
    }

    #[test]
    fn the_percentiles_are_ordered() {
        let s = measure("noop", 200, || std::hint::black_box(1u64 + 1));
        assert!(s.min <= s.median, "min {:?} > median {:?}", s.min, s.median);
        assert!(s.median <= s.p95);
        assert!(s.p95 <= s.p99);
    }

    #[test]
    fn a_measurable_cost_is_reported_as_nonzero() {
        // 2 ms of real sleeping, in four samples, cannot median to zero.
        let s = measure("sleep", 4, || {
            std::thread::sleep(Duration::from_micros(500))
        });
        assert!(s.median >= Duration::from_micros(400), "got {:?}", s.median);
    }

    #[test]
    fn a_sample_converts_to_a_measured_here_measurement() {
        let s = measure("noop", 10, || std::hint::black_box(1u64 + 1));
        let m = s.measurement();
        assert!(
            !m.is_published(),
            "a timed sample is never a published figure"
        );
        assert_eq!(m.cost, s.median, "the reported cost is the median");
        assert!(matches!(m.source, Source::MeasuredHere { iters: 10 }));
    }

    #[test]
    fn zero_iterations_is_an_error_not_a_divide_by_zero() {
        assert!(try_measure("noop", 0, || ()).is_err());
    }

    // --- the two derivations that a stopwatch cannot check ---

    fn ms(n: u64) -> Duration {
        Duration::from_millis(n)
    }

    #[test]
    fn percentile_picks_the_documented_index() {
        // Ten values, so the index is `round(9 * q)` and every pick is
        // unambiguous. A test that only asserted p50 <= p95 <= p99 would pass
        // against an implementation that returned the maximum for every
        // quantile, which is the mutation this pins.
        let v: Vec<Duration> = (1..=10).map(ms).collect();
        assert_eq!(percentile(&v, 0.0), ms(1));
        assert_eq!(
            percentile(&v, 0.50),
            ms(6),
            "round(9*0.50) = 5 -> the 6th value"
        );
        assert_eq!(
            percentile(&v, 0.95),
            ms(10),
            "round(9*0.95) = 9 -> the 10th value"
        );
        assert_eq!(percentile(&v, 1.0), ms(10));
    }

    #[test]
    fn percentile_does_not_collapse_to_the_maximum() {
        // Twenty values: p50 and p99 must differ, so returning `last()` for
        // every quantile fails here.
        let v: Vec<Duration> = (1..=20).map(ms).collect();
        assert_ne!(percentile(&v, 0.50), percentile(&v, 0.99));
        assert_eq!(
            percentile(&v, 0.50),
            ms(11),
            "round(19*0.5) = 10 -> the 11th value"
        );
        assert_eq!(percentile(&v, 0.99), ms(20));
    }

    #[test]
    fn percentile_of_a_single_value_is_that_value() {
        assert_eq!(percentile(&[ms(7)], 0.99), ms(7));
    }

    #[test]
    fn summarize_computes_the_statistics_from_the_vector_it_is_given() {
        let s = summarize("x", 4, vec![ms(1), ms(2), ms(3), ms(10)]).unwrap();
        assert_eq!(s.min, ms(1));
        assert_eq!(s.median, ms(3), "round(3*0.5) = 2 -> the 3rd value");
        assert_eq!(s.mean, ms(4), "(1+2+3+10)/4");
        assert_eq!(s.p99, ms(10));
        assert_eq!(s.iters, 4);
    }

    #[test]
    fn summarize_sorts_before_it_picks() {
        let ordered = summarize("x", 3, vec![ms(1), ms(2), ms(9)]).unwrap();
        let shuffled = summarize("x", 3, vec![ms(9), ms(1), ms(2)]).unwrap();
        assert_eq!(
            ordered.median, shuffled.median,
            "order of arrival must not matter"
        );
        assert_eq!(shuffled.min, ms(1));
    }

    /// The guard that makes warmup contamination impossible to miss.
    ///
    /// If the warmup loop's timings were ever recorded alongside the measured
    /// ones, the vector would be longer than the iteration count and every
    /// number this tool prints would be inflated. No stopwatch test can see
    /// that; this one turns it into a hard error.
    #[test]
    fn summarize_rejects_a_sample_count_that_disagrees_with_the_iteration_count() {
        assert!(
            summarize("x", 3, vec![ms(1), ms(2), ms(3), ms(4)]).is_err(),
            "too many"
        );
        assert!(summarize("x", 3, vec![ms(1), ms(2)]).is_err(), "too few");
        assert!(summarize("x", 3, vec![]).is_err());
        assert!(summarize("x", 3, vec![ms(1), ms(2), ms(3)]).is_ok());
    }

    #[test]
    fn measure_records_exactly_as_many_timings_as_it_was_asked_for() {
        // Reaches `summarize`'s guard through the real timing path: a warmup
        // leak would make this error rather than return a Sample.
        for iters in [1u32, 7, 40, 120] {
            let s = try_measure("noop", iters, || std::hint::black_box(1u64 + 1))
                .unwrap_or_else(|e| panic!("iters={iters}: {e}"));
            assert_eq!(s.iters, iters);
        }
    }
}
