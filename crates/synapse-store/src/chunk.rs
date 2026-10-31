//! Content-defined chunking (ADR 0003 step G2, section 5.9, experiment X6).
//!
//! A blob above [`ChunkParams::threshold_bytes`] is cut into content-defined chunks by a
//! FastCDC-style gear chunker with normalized chunking [S20], and each chunk is stored once
//! per [`ChunkDigest`] inside the segments. A chunk is a storage and transfer unit only: a
//! blob's identity stays its `BlobDigest` over the whole content, so the parameters can
//! change without changing any identity (a store opened with other parameters only
//! deduplicates less against what is already stored).
//!
//! The chunker, the candidates, and the rule that chose the default parameters are fixed in
//! `evidence/g2-content-defined-chunking/x6/RULE.md` (committed before the X6 runs).

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fmt;
use synapse_core::BlobDigest;

/// Domain tag of [`ChunkDigest`].
pub const DOMAIN_CHUNK_V1: &[u8] = b"SYNAPSE_CHUNK_V1\0";

/// Seed of the SplitMix64 sequence that fills [`GEAR`] (ASCII `SYNAPSE1`).
pub const GEAR_SEED: u64 = 0x5359_4E41_5053_4531;

/// Digest of one content-defined chunk of a large blob (CONTEXT.md `ChunkDigest`):
/// `SHA-256("SYNAPSE_CHUNK_V1\0" || u64 LE length || bytes)`.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ChunkDigest(pub [u8; 32]);

impl ChunkDigest {
    pub fn compute(bytes: &[u8]) -> Self {
        let mut h = Sha256::new();
        h.update(DOMAIN_CHUNK_V1);
        h.update((bytes.len() as u64).to_le_bytes());
        h.update(bytes);
        Self(h.finalize().into())
    }

    pub fn to_hex(self) -> String {
        hex::encode(self.0)
    }
}

impl fmt::Debug for ChunkDigest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ChunkDigest({})", self.to_hex())
    }
}

impl fmt::Display for ChunkDigest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex())
    }
}

const fn splitmix64_table(seed: u64) -> [u64; 256] {
    let mut t = [0u64; 256];
    let mut state = seed;
    let mut i = 0;
    while i < 256 {
        state = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        t[i] = z ^ (z >> 31);
        i += 1;
    }
    t
}

/// Gear table: the first 256 outputs of SplitMix64 seeded with [`GEAR_SEED`].
pub const GEAR: [u64; 256] = splitmix64_table(GEAR_SEED);

/// Chunking parameters of a store. `min`, `avg`, `max` are chunk sizes in bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChunkParams {
    /// A blob of at most this many bytes is stored whole; a longer one is chunked.
    /// `u64::MAX` turns chunking off.
    pub threshold_bytes: u64,
    pub min_bytes: u32,
    /// Target average chunk size; a power of two.
    pub avg_bytes: u32,
    pub max_bytes: u32,
}

impl Default for ChunkParams {
    /// The X6 outcome (see `evidence/g2-content-defined-chunking/x6/OUTCOME.md`).
    fn default() -> Self {
        Self::X6_DEFAULT
    }
}

impl ChunkParams {
    /// Chunking off: every blob is stored whole (the A2 behaviour, X6 control C0).
    pub const OFF: Self = Self {
        threshold_bytes: u64::MAX,
        min_bytes: 4 * 1024,
        avg_bytes: 16 * 1024,
        max_bytes: 64 * 1024,
    };

    /// Parameters chosen by experiment X6 under its pre-registered rule: candidate K1
    /// (T = 16 KiB, min 1 KiB, avg 4 KiB, max 16 KiB), the only eligible candidate
    /// (`evidence/g2-content-defined-chunking/x6/RESULTS.md`).
    pub const X6_DEFAULT: Self = Self::candidate(16 * 1024, 4 * 1024);

    /// Candidate with `min = avg / 4` and `max = 4 * avg` (the X6 shape).
    pub const fn candidate(threshold_bytes: u64, avg_bytes: u32) -> Self {
        Self {
            threshold_bytes,
            min_bytes: avg_bytes / 4,
            avg_bytes,
            max_bytes: avg_bytes * 4,
        }
    }

    /// True when a blob of `len` bytes is chunked.
    pub fn is_chunked(&self, len: usize) -> bool {
        len as u64 > self.threshold_bytes
    }

    /// Parameters the chunker accepts: `64 <= min < avg < max`, `avg` a power of two
    /// with at least 2^4, and `max` at most 16 MiB.
    pub fn validate(&self) -> Result<(), String> {
        let ok = self.min_bytes >= 64
            && self.min_bytes < self.avg_bytes
            && self.avg_bytes < self.max_bytes
            && self.avg_bytes.is_power_of_two()
            && self.avg_bytes >= 16
            && self.max_bytes <= 16 * 1024 * 1024;
        if ok {
            Ok(())
        } else {
            Err(format!("invalid chunk parameters {self:?}"))
        }
    }
}

/// Length of the first chunk of `src` (the cut rule of the X6 rule, section 1).
pub fn cut(src: &[u8], p: &ChunkParams) -> usize {
    let min = p.min_bytes as usize;
    if src.len() <= min {
        return src.len();
    }
    let n = src.len().min(p.max_bytes as usize);
    let normal = n.min(p.avg_bytes as usize);
    let bits = p.avg_bytes.trailing_zeros();
    let mask_s = !0u64 << (64 - (bits + 2));
    let mask_l = !0u64 << (64 - (bits - 2));
    let mut h = 0u64;
    let mut i = min;
    while i < normal {
        h = (h << 1).wrapping_add(GEAR[src[i] as usize]);
        if h & mask_s == 0 {
            return i + 1;
        }
        i += 1;
    }
    while i < n {
        h = (h << 1).wrapping_add(GEAR[src[i] as usize]);
        if h & mask_l == 0 {
            return i + 1;
        }
        i += 1;
    }
    n
}

/// Byte ranges of the chunks of `data`, in order; they cover `data` exactly.
pub fn chunk_ranges(data: &[u8], p: &ChunkParams) -> Vec<std::ops::Range<usize>> {
    let mut out = Vec::with_capacity(data.len() / p.avg_bytes.max(1) as usize + 1);
    let mut at = 0;
    while at < data.len() {
        let len = cut(&data[at..], p);
        out.push(at..at + len);
        at += len;
    }
    out
}

/// One chunked blob: its identity, length, and its chunks in order (digest, length).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChunkManifest {
    pub blob: BlobDigest,
    pub len: u64,
    pub chunks: Vec<(ChunkDigest, u32)>,
}

/// A blob cut into chunks before it is encoded: its manifest plus the distinct chunks in
/// first-occurrence order with their byte ranges inside the blob.
#[derive(Debug, Clone)]
pub(crate) struct ChunkedBlob {
    pub manifest: ChunkManifest,
    pub distinct: Vec<(ChunkDigest, std::ops::Range<usize>)>,
}

/// Cut `data` (whose digest is `blob`) and digest every chunk.
pub(crate) fn chunk_blob(blob: BlobDigest, data: &[u8], p: &ChunkParams) -> ChunkedBlob {
    let ranges = chunk_ranges(data, p);
    let mut chunks = Vec::with_capacity(ranges.len());
    let mut distinct: Vec<(ChunkDigest, std::ops::Range<usize>)> = Vec::new();
    let mut seen = std::collections::BTreeSet::new();
    for r in ranges {
        let d = ChunkDigest::compute(&data[r.clone()]);
        chunks.push((d, r.len() as u32));
        if seen.insert(d) {
            distinct.push((d, r));
        }
    }
    ChunkedBlob {
        manifest: ChunkManifest {
            blob,
            len: data.len() as u64,
            chunks,
        },
        distinct,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gear_table_is_splitmix64_of_the_seed() {
        // First SplitMix64 outputs for the seed, computed step by step.
        let mut state = GEAR_SEED;
        let mut next = || {
            state = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
            let mut z = state;
            z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
            z ^ (z >> 31)
        };
        for (i, g) in GEAR.iter().enumerate() {
            assert_eq!(*g, next(), "gear entry {i}");
        }
        let distinct: std::collections::BTreeSet<_> = GEAR.iter().collect();
        assert_eq!(distinct.len(), 256);
    }

    #[test]
    fn chunk_ranges_cover_the_data_and_respect_min_and_max() {
        let p = ChunkParams::candidate(16 * 1024, 4 * 1024);
        p.validate().unwrap();
        let mut x = 0x1234_5678u32;
        let data: Vec<u8> = (0..300_000)
            .map(|_| {
                x ^= x << 13;
                x ^= x >> 17;
                x ^= x << 5;
                x as u8
            })
            .collect();
        let ranges = chunk_ranges(&data, &p);
        let mut at = 0;
        for (i, r) in ranges.iter().enumerate() {
            assert_eq!(r.start, at);
            assert!(r.len() <= p.max_bytes as usize);
            if i + 1 < ranges.len() {
                assert!(r.len() > p.min_bytes as usize, "chunk {i} below min");
            }
            at = r.end;
        }
        assert_eq!(at, data.len());
        // Content-defined: the average is near the target on random data.
        let mean = data.len() / ranges.len();
        assert!(mean > 2 * 1024 && mean < 8 * 1024, "mean chunk {mean}");
        // All-zero data never matches the masks: every chunk is max long.
        let zeros = vec![0u8; 100_000];
        let z = chunk_ranges(&zeros, &p);
        assert!(z[..z.len() - 1]
            .iter()
            .all(|r| r.len() == p.max_bytes as usize));
        assert!(chunk_ranges(&[], &p).is_empty());
    }

    #[test]
    fn invalid_parameters_are_refused() {
        assert!(ChunkParams::candidate(16 * 1024, 3000).validate().is_err());
        assert!(ChunkParams {
            min_bytes: 8,
            ..ChunkParams::candidate(1, 64)
        }
        .validate()
        .is_err());
        assert!(ChunkParams::OFF.validate().is_ok());
    }
}
