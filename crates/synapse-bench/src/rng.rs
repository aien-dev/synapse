//! Deterministic SplitMix64 generator used for reproducible workloads, sample
//! selection, and cell ordering (no external `rand` dependency).

/// SplitMix64 pseudo-random generator (Steele, Lea, and Flood, 2014).
/// The same seed always yields the same sequence on every host.
#[derive(Debug, Clone)]
pub struct SplitMix64 {
    state: u64,
}

impl SplitMix64 {
    pub fn new(seed: u64) -> Self {
        Self { state: seed }
    }

    /// Derive an independent stream from `seed` and an ordered list of labels
    /// (for example `[rep, agents, agent, index]`).
    pub fn derive(seed: u64, labels: &[u64]) -> Self {
        let mut mixed = Self::new(seed).next_u64();
        for &label in labels {
            mixed = Self::new(mixed ^ label.wrapping_mul(0x9E37_79B9_7F4A_7C15)).next_u64();
        }
        Self::new(mixed)
    }

    pub fn next_u64(&mut self) -> u64 {
        self.state = self.state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    /// Uniform index in `0..n` via a 128-bit multiply-shift. Returns 0 when `n == 0`.
    pub fn below(&mut self, n: usize) -> usize {
        if n == 0 {
            return 0;
        }
        ((u128::from(self.next_u64()) * n as u128) >> 64) as usize
    }

    /// Inclusive range `lo..=hi` (returns `lo` when `hi < lo`).
    pub fn range(&mut self, lo: usize, hi: usize) -> usize {
        if hi <= lo {
            return lo;
        }
        lo + self.below(hi - lo + 1)
    }

    /// Fisher-Yates shuffle.
    pub fn shuffle<T>(&mut self, items: &mut [T]) {
        for i in (1..items.len()).rev() {
            let j = self.below(i + 1);
            items.swap(i, j);
        }
    }

    /// Sixteen lowercase hex characters from the next output.
    pub fn hex16(&mut self) -> String {
        format!("{:016x}", self.next_u64())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn same_seed_same_sequence_and_derive_is_label_sensitive() {
        let mut a = SplitMix64::new(42);
        let mut b = SplitMix64::new(42);
        for _ in 0..16 {
            assert_eq!(a.next_u64(), b.next_u64());
        }
        let x = SplitMix64::derive(7, &[1, 2, 3]).next_u64();
        let y = SplitMix64::derive(7, &[1, 2, 3]).next_u64();
        let z = SplitMix64::derive(7, &[1, 2, 4]).next_u64();
        assert_eq!(x, y);
        assert_ne!(x, z);
    }

    #[test]
    fn below_stays_in_bounds_and_shuffle_is_permutation() {
        let mut g = SplitMix64::new(1);
        for n in 1..50 {
            assert!(g.below(n) < n);
        }
        assert_eq!(g.below(0), 0);
        let mut v: Vec<u32> = (0..100).collect();
        g.shuffle(&mut v);
        let mut sorted = v.clone();
        sorted.sort_unstable();
        assert_eq!(sorted, (0..100).collect::<Vec<u32>>());
    }
}
