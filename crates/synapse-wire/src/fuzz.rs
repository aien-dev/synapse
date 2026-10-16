//! In-repository coverage-guided fuzzer for the untrusted frame decoder (step G1).
//!
//! What it is, plainly: a deterministic mutation loop with edge-coverage feedback. The
//! decoder in `frame.rs` is compiled with an [`EdgeProbe`] at every branch (AFL-style edge
//! map over source-line sites); an input that reaches a new edge, or an edge a new number of
//! times (hit-count bucket), joins the corpus and is mutated further. It is not libFuzzer or
//! AFL: there is no compiler instrumentation, so coverage is exactly the instrumented
//! decoder states of `frame.rs` (the capability chain decoder of `synapse-auth` and the
//! envelope decoder of `synapse-store::codec` run, and are checked, but are not
//! instrumented). The budget (executions or seconds) and the seed are fixed before a run.
//!
//! The target is what a server does with untrusted bytes: [`decode_frame`] on the input,
//! then, for a `Submit` frame, `decode_envelope` on its payload. Every execution checks:
//! * no panic (`catch_unwind`);
//! * no read past the frame: the probe's high-water mark never exceeds the declared frame
//!   end, and decoding the input followed by different trailing bytes gives the same answer
//!   whenever the input already held the whole declared frame;
//! * no allocation above the cap: the largest single allocation during the decode is at
//!   most `max_frame_body` (needs [`CountingAlloc`] as the global allocator);
//! * a frame that decodes re-encodes to exactly the bytes it was decoded from, and a
//!   payload that decodes as an envelope re-encodes to exactly the payload;
//! * everything else is a typed [`WireRefusal`] (or a typed `CodecRefusal` for a payload).

use crate::frame::{
    decode_frame, decode_frame_probed, encode_frame, Frame, FrameBody, WireLimits, WireRefusal,
    FRAME_HEADER_LEN,
};
use crate::probe::{bucket, EdgeProbe, EDGE_MAP_LEN};
use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::collections::BTreeMap;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::time::Instant;
use synapse_store::codec::{decode_envelope, encode_envelope};
use synapse_store::CodecRefusal;

// ---------------------------------------------------------------------------------------
// Allocation accounting
// ---------------------------------------------------------------------------------------

thread_local! {
    static TRACK: Cell<bool> = const { Cell::new(false) };
    static PEAK: Cell<usize> = const { Cell::new(0) };
    static TOTAL: Cell<usize> = const { Cell::new(0) };
}

fn note(size: usize) {
    let _ = TRACK.try_with(|t| {
        if t.get() {
            let _ = PEAK.try_with(|p| p.set(p.get().max(size)));
            let _ = TOTAL.try_with(|p| p.set(p.get().saturating_add(size)));
        }
    });
}

/// Global allocator that records, per thread and only while a measurement is open, the
/// largest single allocation and the total bytes allocated. Install it in the binary or
/// test that runs the fuzzer: `#[global_allocator] static A: CountingAlloc = CountingAlloc;`
pub struct CountingAlloc;

// SAFETY: every method forwards to `System` with the same arguments; the bookkeeping only
// touches thread-local `Cell`s through `try_with`, which never allocates.
unsafe impl GlobalAlloc for CountingAlloc {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        note(layout.size());
        System.alloc(layout)
    }
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        note(layout.size());
        System.alloc_zeroed(layout)
    }
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        note(new_size);
        System.realloc(ptr, layout, new_size)
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        System.dealloc(ptr, layout)
    }
}

thread_local! {
    static QUIET_PANICS: Cell<bool> = const { Cell::new(false) };
}

/// Silence the panic message of expected (caught) panics on this thread only, leaving the
/// process panic hook in place for every other thread (test harness threads included).
fn quiet_panics_on_this_thread() {
    static INSTALL: std::sync::Once = std::sync::Once::new();
    INSTALL.call_once(|| {
        let previous = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |info| {
            if !QUIET_PANICS.try_with(|q| q.get()).unwrap_or(false) {
                previous(info);
            }
        }));
    });
    QUIET_PANICS.with(|q| q.set(true));
}
/// Run `f`, returning its result (or panic) with (largest single allocation, total bytes).
pub fn measured<T>(f: impl FnOnce() -> T) -> (std::thread::Result<T>, usize, usize) {
    PEAK.with(|p| p.set(0));
    TOTAL.with(|p| p.set(0));
    TRACK.with(|t| t.set(true));
    let r = catch_unwind(AssertUnwindSafe(f));
    TRACK.with(|t| t.set(false));
    (r, PEAK.with(|p| p.get()), TOTAL.with(|p| p.get()))
}

/// True when [`CountingAlloc`] is the global allocator (a probe allocation is seen).
pub fn alloc_tracking_installed() -> bool {
    let (_, peak, _) = measured(|| std::hint::black_box(vec![0u8; 4321]));
    peak >= 4321
}

// ---------------------------------------------------------------------------------------
// Target
// ---------------------------------------------------------------------------------------

/// What the server-side decode of one input produced.
#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(clippy::large_enum_variant)] // built once per execution; boxing buys nothing here
pub enum TargetOutcome {
    /// A frame of `consumed` bytes; for a `Submit`, the payload's envelope decode result.
    Accepted {
        frame: Frame,
        consumed: usize,
        payload: Option<Result<synapse_core::ChangesetEnvelope, CodecRefusal>>,
    },
    Refused(WireRefusal),
}

fn target_with<P: crate::probe::Probe>(
    input: &[u8],
    limits: &WireLimits,
    probe: &mut P,
) -> TargetOutcome {
    match decode_frame_probed(input, limits, probe) {
        Ok((frame, consumed)) => {
            let payload = match &frame.body {
                FrameBody::Submit(req) => Some(decode_envelope(
                    &req.payload,
                    u64::from(limits.max_frame_body),
                )),
                _ => None,
            };
            TargetOutcome::Accepted {
                frame,
                consumed,
                payload,
            }
        }
        Err(r) => TargetOutcome::Refused(r),
    }
}

/// A fuzz target: decode untrusted `input` under `limits`, reporting to the probe.
pub type Target = fn(&[u8], &WireLimits, &mut EdgeProbe) -> TargetOutcome;

/// The real target: [`decode_frame_probed`], then `decode_envelope` on a `Submit` payload.
pub fn server_decode(input: &[u8], limits: &WireLimits, probe: &mut EdgeProbe) -> TargetOutcome {
    target_with(input, limits, probe)
}

/// The real target without instrumentation.
pub fn target(input: &[u8], limits: &WireLimits) -> TargetOutcome {
    target_with(input, limits, &mut crate::probe::NoProbe)
}

/// Declared end of the frame at the start of `input` (header length plus `body_len`), or
/// the header length when the header is incomplete.
fn declared_end(input: &[u8]) -> usize {
    if input.len() < FRAME_HEADER_LEN {
        return FRAME_HEADER_LEN;
    }
    let n = u32::from_le_bytes(input[12..16].try_into().expect("4 bytes"));
    FRAME_HEADER_LEN + n as usize
}

// ---------------------------------------------------------------------------------------
// Engine
// ---------------------------------------------------------------------------------------

/// Deterministic PRNG (SplitMix64).
#[derive(Debug, Clone)]
pub struct SplitMix64(pub u64);

impl SplitMix64 {
    pub fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
    pub fn below(&mut self, n: usize) -> usize {
        if n == 0 {
            0
        } else {
            (self.next_u64() % n as u64) as usize
        }
    }
    fn chance(&mut self, num: usize, den: usize) -> bool {
        self.below(den) < num
    }
}

/// When the run stops; fixed before the run.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Budget {
    Execs(u64),
    Seconds(f64),
}

#[derive(Debug, Clone)]
pub struct FuzzConfig {
    pub seed: u64,
    pub budget: Budget,
    pub limits: WireLimits,
    /// Corpus size limit (new-coverage inputs beyond it are counted, not kept).
    pub max_corpus: usize,
}

/// One broken invariant, with the input that broke it.
#[derive(Debug, Clone)]
pub struct Violation {
    pub kind: &'static str,
    pub detail: String,
    pub input: Vec<u8>,
}

#[derive(Debug, Clone, Default)]
pub struct FuzzReport {
    pub execs: u64,
    pub elapsed_s: f64,
    pub seeds: usize,
    /// Distinct edges reached.
    pub edges: usize,
    /// Inputs that reached new coverage (seeds first), in discovery order.
    pub corpus: Vec<Vec<u8>>,
    /// Executions at which each non-seed corpus entry was found.
    pub corpus_found_at: Vec<u64>,
    /// Count per outcome class: `accepted:<kind>`, `refused:<kind>`,
    /// `payload_accepted`, `payload_refused:<kind>`.
    pub outcomes: BTreeMap<String, u64>,
    pub violation_counts: BTreeMap<&'static str, u64>,
    /// First violations of each kind (at most 4 each).
    pub violations: Vec<Violation>,
    /// Largest single allocation in any decode, bytes.
    pub peak_alloc: usize,
    /// Largest total bytes allocated by one decode.
    pub peak_alloc_total: usize,
    pub alloc_tracking: bool,
    pub largest_input: usize,
    /// Instrumented decoder sites (source lines of `frame.rs`) in total, and those never
    /// reached during the run.
    pub sites_total: usize,
    pub sites_unreached: Vec<u32>,
}

impl FuzzReport {
    pub fn violation_total(&self) -> u64 {
        self.violation_counts.values().sum()
    }

    fn violate(&mut self, kind: &'static str, detail: String, input: &[u8]) {
        let n = self.violation_counts.entry(kind).or_insert(0);
        *n += 1;
        if *n <= 4 {
            self.violations.push(Violation {
                kind,
                detail,
                input: input.to_vec(),
            });
        }
    }
}

fn classify(out: &TargetOutcome, outcomes: &mut BTreeMap<String, u64>) {
    let mut add = |k: String| *outcomes.entry(k).or_insert(0) += 1;
    match out {
        TargetOutcome::Accepted { frame, payload, .. } => {
            add(format!("accepted:{}", frame.body.kind().name()));
            match payload {
                Some(Ok(_)) => add("payload_accepted".into()),
                Some(Err(r)) => add(format!("payload_refused:{}", r.kind())),
                None => {}
            }
        }
        TargetOutcome::Refused(r) => add(format!("refused:{}", r.kind())),
    }
}

/// Invariant checks on one execution's outcome. Returns the violations found.
fn check_outcome(
    input: &[u8],
    out: &TargetOutcome,
    limits: &WireLimits,
) -> Vec<(&'static str, String)> {
    let mut v = Vec::new();
    if let TargetOutcome::Accepted {
        frame,
        consumed,
        payload,
    } = out
    {
        match encode_frame(frame) {
            Ok(bytes) if bytes.as_slice() == &input[..*consumed] => {}
            Ok(bytes) => v.push((
                "non_canonical_accept",
                format!("re-encoded {} bytes differ from {consumed}", bytes.len()),
            )),
            Err(e) => v.push(("non_canonical_accept", format!("re-encode refused: {e}"))),
        }
        if let (Some(Ok(env)), FrameBody::Submit(req)) = (payload, &frame.body) {
            match encode_envelope(env) {
                Ok(b) if b == req.payload => {}
                _ => v.push((
                    "payload_non_canonical",
                    "payload envelope does not re-encode to its bytes".into(),
                )),
            }
        }
        if *consumed > input.len() || *consumed != declared_end(input) {
            v.push((
                "read_past_frame",
                format!("consumed {consumed} of declared {}", declared_end(input)),
            ));
        }
    }
    let _ = limits;
    v
}

struct Engine {
    target: Target,
    scratch: EdgeProbe,
    cfg: FuzzConfig,
    rng: SplitMix64,
    virgin: Vec<u8>,
    probe: EdgeProbe,
    report: FuzzReport,
}

const INTERESTING_U8: [u8; 12] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 0x7F, 0x80, 0xFF];

impl Engine {
    fn interesting_u32(&mut self, v: &[u8], off: usize) -> u32 {
        let cap = self.cfg.limits.max_frame_body;
        let remaining = v.len().saturating_sub(off + 4) as u32;
        let choices = [
            0,
            1,
            2,
            3,
            4,
            16,
            32,
            33,
            64,
            cap.saturating_sub(1),
            cap,
            cap.saturating_add(1),
            remaining,
            remaining.saturating_add(1),
            remaining.saturating_sub(1),
            remaining / 32,
            remaining / 32 + 1,
            v.len() as u32,
            0x7FFF_FFFF,
            u32::MAX,
        ];
        choices[self.rng.below(choices.len())]
    }

    fn mutate(&mut self, base: &[u8]) -> Vec<u8> {
        let mut v = base.to_vec();
        let rounds = 1 + self.rng.below(4);
        for _ in 0..rounds {
            let len = v.len();
            match self.rng.below(12) {
                0 if len > 0 => {
                    let i = self.rng.below(len);
                    v[i] ^= 1 << self.rng.below(8);
                }
                1 if len > 0 => {
                    let i = self.rng.below(len);
                    v[i] = self.rng.next_u64() as u8;
                }
                2 if len > 0 => {
                    let i = self.rng.below(len);
                    v[i] = INTERESTING_U8[self.rng.below(INTERESTING_U8.len())];
                }
                3 if len >= 4 => {
                    let off = self.rng.below(len - 3);
                    let x = self.interesting_u32(&v, off);
                    v[off..off + 4].copy_from_slice(&x.to_le_bytes());
                }
                4 => {
                    let n = self.rng.below(len + 1);
                    v.truncate(n);
                }
                5 => {
                    let at = self.rng.below(len + 1);
                    let n = 1 + self.rng.below(16);
                    let ins: Vec<u8> = (0..n).map(|_| self.rng.next_u64() as u8).collect();
                    v.splice(at..at, ins);
                }
                6 if len > 0 => {
                    let a = self.rng.below(len);
                    let b = (a + 1 + self.rng.below(32)).min(len);
                    v.drain(a..b);
                }
                7 if len > 0 => {
                    let a = self.rng.below(len);
                    let b = (a + 1 + self.rng.below(64)).min(len);
                    let piece = v[a..b].to_vec();
                    let at = self.rng.below(len + 1);
                    v.splice(at..at, piece);
                }
                8 if !self.report.corpus.is_empty() => {
                    let other =
                        self.report.corpus[self.rng.below(self.report.corpus.len())].clone();
                    let cut = self.rng.below(len + 1);
                    let from = self.rng.below(other.len() + 1);
                    v.truncate(cut);
                    v.extend_from_slice(&other[from..]);
                }
                9 if len >= 64 => {
                    // Swap two 32-byte runs (reorders digests and keys).
                    let a = self.rng.below(len - 31);
                    let b = self.rng.below(len - 31);
                    let (x, y) = (v[a..a + 32].to_vec(), v[b..b + 32].to_vec());
                    v[a..a + 32].copy_from_slice(&y);
                    v[b..b + 32].copy_from_slice(&x);
                }
                10 if len >= 6 => {
                    v[5] = self.rng.below(9) as u8;
                }
                11 if len >= 4 => {
                    // Rewrite an aligned u32 near a random position to the bytes left.
                    let off = self.rng.below(len - 3);
                    let rem = (len - off - 4) as u32;
                    v[off..off + 4].copy_from_slice(&rem.to_le_bytes());
                }
                _ => {}
            }
        }
        // Half the time keep the declared body length honest so mutations reach the body.
        if v.len() >= FRAME_HEADER_LEN && self.rng.chance(1, 2) {
            let body = (v.len() - FRAME_HEADER_LEN) as u32;
            v[12..16].copy_from_slice(&body.to_le_bytes());
        }
        v.truncate(self.cfg.limits.max_frame_body as usize + 2 * FRAME_HEADER_LEN);
        v
    }

    /// Run one input; returns true when it reached new coverage.
    fn exec(&mut self, input: &[u8]) -> bool {
        self.report.execs += 1;
        self.report.largest_input = self.report.largest_input.max(input.len());
        self.probe.reset();
        let limits = self.cfg.limits;
        let probe = &mut self.probe;
        let t = self.target;
        let (res, peak, total) = measured(|| t(input, &limits, probe));
        let out = match res {
            Ok(o) => o,
            Err(p) => {
                let msg = p
                    .downcast_ref::<&str>()
                    .map(|s| s.to_string())
                    .or_else(|| p.downcast_ref::<String>().cloned())
                    .unwrap_or_default();
                self.report.violate("panic", msg, input);
                return self.update_coverage();
            }
        };
        self.report.peak_alloc = self.report.peak_alloc.max(peak);
        self.report.peak_alloc_total = self.report.peak_alloc_total.max(total);
        if peak as u64 > u64::from(limits.max_frame_body) {
            self.report.violate(
                "alloc_over_cap",
                format!(
                    "allocation of {peak} bytes over cap {}",
                    limits.max_frame_body
                ),
                input,
            );
        }
        let end = declared_end(input).min(input.len());
        if self.probe.high_water > end {
            self.report.violate(
                "read_past_frame",
                format!("read to {} past frame end {end}", self.probe.high_water),
                input,
            );
        }
        for (kind, detail) in check_outcome(input, &out, &limits) {
            self.report.violate(kind, detail, input);
        }
        // Trailing-bytes differential: a decision made on a complete frame (or a refusal
        // other than truncation) must not depend on what follows the frame.
        let truncated = matches!(out, TargetOutcome::Refused(WireRefusal::Truncated { .. }));
        if !truncated {
            let mut longer = input.to_vec();
            let n = 1 + self.rng.below(48);
            longer.extend((0..n).map(|_| self.rng.next_u64() as u8));
            self.scratch.reset();
            let out2 = (self.target)(&longer, &limits, &mut self.scratch);
            if out2 != out {
                self.report.violate(
                    "read_past_frame",
                    "outcome changed when bytes were appended after the frame".into(),
                    input,
                );
            }
        }
        classify(&out, &mut self.report.outcomes);
        self.update_coverage()
    }

    fn update_coverage(&mut self) -> bool {
        let mut new = false;
        let (virgin, edges) = (&mut self.virgin, &mut self.report.edges);
        self.probe.for_each_hit(|i, c| {
            let b = bucket(c);
            if virgin[i] & b != b {
                if virgin[i] == 0 {
                    *edges += 1;
                }
                virgin[i] |= b;
                new = true;
            }
        });
        new
    }
}

/// Run the fuzzer from `seeds` (valid frames) under `cfg`.
pub fn run(cfg: FuzzConfig, seeds: &[Vec<u8>]) -> FuzzReport {
    run_target(cfg, seeds, server_decode)
}

/// Run the fuzzer on another target (negative controls: decoders with planted bugs).
pub fn run_target(cfg: FuzzConfig, seeds: &[Vec<u8>], target: Target) -> FuzzReport {
    let mut e = Engine {
        target,
        scratch: EdgeProbe::new(),
        rng: SplitMix64(cfg.seed),
        virgin: vec![0u8; EDGE_MAP_LEN],
        probe: EdgeProbe::new(),
        report: FuzzReport {
            alloc_tracking: alloc_tracking_installed(),
            seeds: seeds.len(),
            ..Default::default()
        },
        cfg,
    };
    quiet_panics_on_this_thread();
    let start = Instant::now();
    for s in seeds {
        e.exec(s);
        e.report.corpus.push(s.clone());
    }
    loop {
        let stop = match e.cfg.budget {
            Budget::Execs(n) => e.report.execs >= n,
            Budget::Seconds(s) => {
                e.report.execs.is_multiple_of(256) && start.elapsed().as_secs_f64() >= s
            }
        };
        if stop {
            break;
        }
        let base = e.report.corpus[e.rng.below(e.report.corpus.len())].clone();
        let input = e.mutate(&base);
        if e.exec(&input) && e.report.corpus.len() < e.cfg.max_corpus {
            e.report.corpus.push(input);
            e.report.corpus_found_at.push(e.report.execs);
        }
    }
    e.report.elapsed_s = start.elapsed().as_secs_f64();
    let lines = crate::probe::instrumented_lines();
    e.report.sites_total = lines.len();
    e.report.sites_unreached = lines
        .into_iter()
        .filter(|l| !e.probe.sites_seen[*l as usize & (crate::probe::SITE_LINES - 1)])
        .collect();
    QUIET_PANICS.with(|q| q.set(false));
    e.report
}

/// Replay of a saved corpus without instrumentation.
#[derive(Debug, Clone, Default)]
pub struct CorpusReplay {
    pub entries: usize,
    /// Entries that decoded and re-encoded to identical bytes (well-formed frames).
    pub accepted_canonical: usize,
    /// Malformed entries, by typed refusal kind.
    pub refused: BTreeMap<String, usize>,
    /// Entries that panicked, decoded non-canonically, or allocated over the cap.
    pub violations: Vec<(usize, String)>,
    pub peak_alloc: usize,
}

/// Decode every corpus entry: each must be a canonical frame or a typed refusal.
pub fn replay_corpus(corpus: &[Vec<u8>], limits: &WireLimits) -> CorpusReplay {
    let mut out = CorpusReplay {
        entries: corpus.len(),
        ..Default::default()
    };
    quiet_panics_on_this_thread();
    for (i, input) in corpus.iter().enumerate() {
        let (res, peak, _) = measured(|| target(input, limits));
        out.peak_alloc = out.peak_alloc.max(peak);
        if peak as u64 > u64::from(limits.max_frame_body) {
            out.violations
                .push((i, format!("allocation {peak} over cap")));
        }
        match res {
            Err(_) => out.violations.push((i, "panic".into())),
            Ok(o) => {
                let v = check_outcome(input, &o, limits);
                if !v.is_empty() {
                    out.violations.push((i, format!("{v:?}")));
                } else {
                    match &o {
                        TargetOutcome::Accepted { .. } => out.accepted_canonical += 1,
                        TargetOutcome::Refused(r) => {
                            *out.refused.entry(r.kind().to_string()).or_insert(0) += 1
                        }
                    }
                }
            }
        }
    }
    QUIET_PANICS.with(|q| q.set(false));
    out
}

/// Serialise a corpus as `u32 count | (u32 len | bytes)*` (little endian).
pub fn corpus_to_bytes(corpus: &[Vec<u8>]) -> Vec<u8> {
    let mut b = Vec::new();
    b.extend_from_slice(&(corpus.len() as u32).to_le_bytes());
    for c in corpus {
        b.extend_from_slice(&(c.len() as u32).to_le_bytes());
        b.extend_from_slice(c);
    }
    b
}

/// Parse [`corpus_to_bytes`] output; `None` if malformed.
pub fn corpus_from_bytes(b: &[u8]) -> Option<Vec<Vec<u8>>> {
    let take4 = |at: usize| -> Option<usize> {
        Some(u32::from_le_bytes(b.get(at..at + 4)?.try_into().ok()?) as usize)
    };
    let n = take4(0)?;
    let mut at = 4;
    let mut out = Vec::new();
    for _ in 0..n {
        let len = take4(at)?;
        at += 4;
        out.push(b.get(at..at + len)?.to_vec());
        at += len;
    }
    (at == b.len()).then_some(out)
}

/// Encoded seed frames ([`crate::testkit::sample_frames`]) that fit `limits`.
pub fn seed_corpus(limits: &WireLimits) -> Vec<Vec<u8>> {
    crate::testkit::sample_frames()
        .iter()
        .map(|f| encode_frame(f).expect("sample frames encode"))
        .filter(|b| b.len() - FRAME_HEADER_LEN <= limits.max_frame_body as usize)
        .collect()
}

/// Malformed frames derived from every seed: wrong magic, version, kind (0 and 8), flags,
/// reserved byte, declared length one over the cap, one byte short, and one trailing byte
/// inside the declared body. Every one must be refused; they join the corpus as seeds.
pub fn malformed_seed_corpus(limits: &WireLimits) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    for good in seed_corpus(limits) {
        let with = |i: usize, v: u8| {
            let mut b = good.clone();
            b[i] = v;
            b
        };
        out.push(with(0, b'X'));
        out.push(with(4, 2));
        out.push(with(5, 0));
        out.push(with(5, 8));
        out.push(with(6, 1));
        out.push(with(7, 0x80));
        let mut over = good.clone();
        over[12..16].copy_from_slice(&(limits.max_frame_body.saturating_add(1)).to_le_bytes());
        out.push(over);
        out.push(good[..good.len() - 1].to_vec());
        let mut trailing = good.clone();
        trailing.push(0);
        let n = (trailing.len() - FRAME_HEADER_LEN) as u32;
        trailing[12..16].copy_from_slice(&n.to_le_bytes());
        out.push(trailing);
    }
    out
}

/// Decode check used by tests: decode `bytes` fully.
pub fn decode_exact(bytes: &[u8], limits: &WireLimits) -> Result<Frame, WireRefusal> {
    let (f, n) = decode_frame(bytes, limits)?;
    if n != bytes.len() {
        return Err(WireRefusal::TrailingBytes {
            at: n,
            count: bytes.len() - n,
        });
    }
    Ok(f)
}
