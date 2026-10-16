//! Coverage probes for the frame decoder.
//!
//! The decoder is generic over a [`Probe`]. Production code passes [`NoProbe`], whose
//! methods are empty and inline away, so the decoder carries no instrumentation cost. The
//! in-repository fuzzer ([`crate::fuzz`]) passes an [`EdgeProbe`], which records every
//! transition between instrumented decoder states (an AFL-style edge map: the edge index is
//! `prev ^ cur` over hashed site ids) and the highest input offset the decoder touched.
//!
//! A site id is the source line of the probe call (`line!()`), so every instrumented branch
//! of `frame.rs` is a distinct state.

/// Receives decoder state transitions and input reads.
pub trait Probe {
    /// The decoder reached instrumented state `site`.
    fn site(&mut self, site: u32);
    /// The decoder read input bytes up to (not including) absolute offset `end`.
    fn touched(&mut self, end: usize);
}

/// The production probe: records nothing.
#[derive(Debug, Default, Clone, Copy)]
pub struct NoProbe;

impl Probe for NoProbe {
    #[inline(always)]
    fn site(&mut self, _site: u32) {}
    #[inline(always)]
    fn touched(&mut self, _end: usize) {}
}

/// Size of the edge map (a power of two).
pub const EDGE_MAP_LEN: usize = 1 << 16;

/// Most distinct edges one execution records in the touched list before falling back
/// to a full scan of the map.
pub const TOUCHED_CAP: usize = 4096;

/// Source lines tracked for site reach (sites on later lines share slots modulo this).
pub const SITE_LINES: usize = 1 << 13;

/// Edge-coverage probe used by the fuzzer.
#[derive(Clone)]
pub struct EdgeProbe {
    prev: u32,
    /// Hit count per edge index (saturating).
    pub map: Box<[u8]>,
    /// Indices of the edges hit in this execution (preallocated, never grows), unless
    /// `overflow` is set.
    touched: Vec<u32>,
    overflow: bool,
    /// Every site id (source line) reached since creation; not cleared by `reset`.
    pub sites_seen: Box<[bool]>,
    /// Highest absolute input offset read (exclusive end).
    pub high_water: usize,
}

impl Default for EdgeProbe {
    fn default() -> Self {
        Self::new()
    }
}

impl EdgeProbe {
    pub fn new() -> Self {
        Self {
            prev: 0,
            map: vec![0u8; EDGE_MAP_LEN].into_boxed_slice(),
            touched: Vec::with_capacity(TOUCHED_CAP),
            overflow: false,
            sites_seen: vec![false; SITE_LINES].into_boxed_slice(),
            high_water: 0,
        }
    }

    /// Clear the map and high-water mark for the next execution (no allocation).
    pub fn reset(&mut self) {
        self.prev = 0;
        if self.overflow {
            self.map.fill(0);
        } else {
            for &i in &self.touched {
                self.map[i as usize] = 0;
            }
        }
        self.touched.clear();
        self.overflow = false;
        self.high_water = 0;
    }

    /// Call `f(index, count)` for every edge hit in this execution.
    pub fn for_each_hit(&self, mut f: impl FnMut(usize, u8)) {
        if self.overflow {
            for (i, &c) in self.map.iter().enumerate() {
                if c != 0 {
                    f(i, c);
                }
            }
        } else {
            for &i in &self.touched {
                f(i as usize, self.map[i as usize]);
            }
        }
    }
}

/// Spread a site id over the edge map (Fibonacci hashing).
fn hash_site(site: u32) -> u32 {
    (site.wrapping_mul(0x9E37_79B1) >> 16) & (EDGE_MAP_LEN as u32 - 1)
}

impl Probe for EdgeProbe {
    fn site(&mut self, site: u32) {
        self.sites_seen[site as usize & (SITE_LINES - 1)] = true;
        let cur = hash_site(site);
        let idx = ((self.prev ^ cur) as usize) & (EDGE_MAP_LEN - 1);
        if self.map[idx] == 0 {
            if self.touched.len() < TOUCHED_CAP {
                self.touched.push(idx as u32);
            } else {
                self.overflow = true;
            }
        }
        self.map[idx] = self.map[idx].saturating_add(1);
        self.prev = cur >> 1;
    }

    fn touched(&mut self, end: usize) {
        self.high_water = self.high_water.max(end);
    }
}

/// AFL-style hit-count bucket of one edge (bit per bucket), so a loop that runs more often
/// counts as new behaviour without every extra iteration counting.
pub fn bucket(count: u8) -> u8 {
    match count {
        0 => 0,
        1 => 1,
        2 => 2,
        3 => 4,
        4..=7 => 8,
        8..=15 => 16,
        16..=31 => 32,
        32..=127 => 64,
        _ => 128,
    }
}

/// Source lines of `frame.rs` that hold an instrumented site (`cov!` or
/// `probe.site(line!())`), so a run can report which sites it never reached.
pub fn instrumented_lines() -> Vec<u32> {
    include_str!("frame.rs")
        .lines()
        .enumerate()
        .filter(|(_, l)| {
            let t = l.trim_start();
            !t.starts_with("//")
                && !t.starts_with("$r.")
                && (t.starts_with("cov!(") || t.starts_with("probe.site(line!())"))
        })
        .map(|(i, _)| i as u32 + 1)
        .collect()
}
