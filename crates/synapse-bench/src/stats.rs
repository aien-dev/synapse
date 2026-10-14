//! Latency percentiles (nearest-rank) and across-repetition spreads.

use serde::{Deserialize, Serialize};

/// Minimum sample count for reporting a p95 value (smaller samples report `null`).
pub const MIN_SAMPLES_P95: usize = 20;
/// Minimum sample count for reporting a p99 value (smaller samples report `null`).
pub const MIN_SAMPLES_P99: usize = 100;

/// Per-cell latency summary in milliseconds (three decimals, microsecond resolution).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LatencySummary {
    pub n: usize,
    pub min_ms: f64,
    pub p50_ms: f64,
    /// `None` when `n < MIN_SAMPLES_P95`.
    pub p95_ms: Option<f64>,
    /// `None` when `n < MIN_SAMPLES_P99`.
    pub p99_ms: Option<f64>,
    pub max_ms: f64,
    pub mean_ms: f64,
}

/// Nearest-rank percentile over an ascending slice: the value at 1-based rank
/// `ceil(q * n)`. Returns `None` for an empty slice or `q` outside `(0, 1]`.
pub fn nearest_rank(sorted: &[u64], q: f64) -> Option<u64> {
    if sorted.is_empty() || !(q > 0.0 && q <= 1.0) {
        return None;
    }
    let rank = (q * sorted.len() as f64).ceil() as usize;
    Some(sorted[rank.clamp(1, sorted.len()) - 1])
}

/// Round to three decimals.
pub fn round3(x: f64) -> f64 {
    (x * 1000.0).round() / 1000.0
}

fn us_to_ms(us: u64) -> f64 {
    round3(us as f64 / 1000.0)
}

/// Summarize microsecond samples. Returns `None` when there are no samples.
pub fn summarize_us(samples_us: &[u64]) -> Option<LatencySummary> {
    if samples_us.is_empty() {
        return None;
    }
    let mut s = samples_us.to_vec();
    s.sort_unstable();
    let n = s.len();
    let sum: u128 = s.iter().map(|&v| u128::from(v)).sum();
    Some(LatencySummary {
        n,
        min_ms: us_to_ms(s[0]),
        p50_ms: us_to_ms(nearest_rank(&s, 0.50)?),
        p95_ms: if n >= MIN_SAMPLES_P95 {
            nearest_rank(&s, 0.95).map(us_to_ms)
        } else {
            None
        },
        p99_ms: if n >= MIN_SAMPLES_P99 {
            nearest_rank(&s, 0.99).map(us_to_ms)
        } else {
            None
        },
        max_ms: us_to_ms(s[n - 1]),
        mean_ms: round3(sum as f64 / n as f64 / 1000.0),
    })
}

/// Median, minimum, and maximum of one metric across repetitions.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Spread {
    pub median: f64,
    pub min: f64,
    pub max: f64,
    /// Number of repetitions that contributed a value.
    pub reps: usize,
}

/// Spread over finite values (median of an even count is the mean of the two middle values).
pub fn spread(values: &[f64]) -> Option<Spread> {
    let mut v: Vec<f64> = values.iter().copied().filter(|x| x.is_finite()).collect();
    if v.is_empty() {
        return None;
    }
    v.sort_by(|a, b| a.total_cmp(b));
    let n = v.len();
    let median = if n % 2 == 1 {
        v[n / 2]
    } else {
        (v[n / 2 - 1] + v[n / 2]) / 2.0
    };
    Some(Spread {
        median: round3(median),
        min: round3(v[0]),
        max: round3(v[n - 1]),
        reps: n,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nearest_rank_matches_definition() {
        let s: Vec<u64> = (1..=100).collect();
        assert_eq!(nearest_rank(&s, 0.50), Some(50));
        assert_eq!(nearest_rank(&s, 0.95), Some(95));
        assert_eq!(nearest_rank(&s, 0.99), Some(99));
        assert_eq!(nearest_rank(&s, 1.0), Some(100));
        assert_eq!(nearest_rank(&[7], 0.5), Some(7));
        assert_eq!(nearest_rank(&[], 0.5), None);
        assert_eq!(nearest_rank(&s, 0.0), None);
    }

    #[test]
    fn summary_withholds_tail_percentiles_for_small_samples() {
        let small: Vec<u64> = (1..=19).map(|v| v * 1000).collect();
        let sum = summarize_us(&small).unwrap();
        assert_eq!(sum.n, 19);
        assert_eq!(sum.p95_ms, None);
        assert_eq!(sum.p99_ms, None);
        assert_eq!(sum.p50_ms, 10.0);

        let big: Vec<u64> = (1..=100).map(|v| v * 1000).collect();
        let sum = summarize_us(&big).unwrap();
        assert_eq!(sum.p95_ms, Some(95.0));
        assert_eq!(sum.p99_ms, Some(99.0));
        assert_eq!(sum.mean_ms, 50.5);
        assert!(summarize_us(&[]).is_none());
    }

    #[test]
    fn spread_reports_median_min_max() {
        let s = spread(&[3.0, 1.0, 2.0]).unwrap();
        assert_eq!((s.median, s.min, s.max, s.reps), (2.0, 1.0, 3.0, 3));
        let s = spread(&[4.0, 1.0]).unwrap();
        assert_eq!(s.median, 2.5);
        assert!(spread(&[f64::NAN]).is_none());
    }
}
