use crate::cost::{Measurement, Source};
use serde::Serialize;
use std::time::{Duration, Instant};

#[derive(Debug, thiserror::Error)]
pub enum HarnessError {
    #[error("cannot measure `{label}` with {iters} iterations; need at least 1")]
    NoIterations { label: String, iters: u32 },
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

/// Warm up, then time `iters` individual invocations.
///
/// Panics only via `expect` on a programmer error (zero iterations); prefer
/// `try_measure` where the count comes from user input.
pub fn measure<T>(label: &str, iters: u32, f: impl FnMut() -> T) -> Sample {
    try_measure(label, iters, f).expect("iters > 0")
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
    // blst. Ten percent of the run, capped, and never zero.
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
    times.sort_unstable();

    let pick = |q: f64| -> Duration {
        let i = ((times.len() as f64 - 1.0) * q).round() as usize;
        times[i]
    };
    let total: Duration = times.iter().sum();

    Ok(Sample {
        label: label.to_string(),
        iters,
        min: times[0],
        median: pick(0.50),
        mean: total / iters,
        p95: pick(0.95),
        p99: pick(0.99),
    })
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
}
