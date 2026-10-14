//! Host bound probes: ADR 0003 section 9 step A0 (experiment X0, section 6.4).
//!
//! Measures the host inputs of the section 6.2 bounds: memory bandwidth (every core
//! streaming a read and a copy), device read and write bandwidth (sequential
//! `O_DIRECT` on the store's filesystem; writes are timed through `fdatasync`),
//! all-core SHA-256 throughput (the `sha2` crate Synapse uses, and the CPU's SHA-2
//! instructions), and all-core Ed25519 verification throughput (`ed25519-dalek`, the
//! implementation Synapse uses). The flush time is not measured again: it is taken from
//! W1's sealed `floor.json` (Phase 5), pinned by its SHA-256 in the protocol.
//!
//! Evidence discipline:
//! - `protocol.json` fixes the repetitions, the central, spread, and bound statistics,
//!   and every probe size before the run. The raw data carries the protocol's SHA-256,
//!   and every run must have exactly the work the protocol fixed.
//! - `raw.json` holds integers only (nanoseconds, work units, microjoule counter
//!   readings), so `report.json` is a pure function of the protocol and raw bytes, and
//!   [`verify_evidence`] recomputes it byte for byte and checks every file listed in
//!   `SHA256SUMS`. That proves consistency only; authenticity comes from
//!   the git history and review of the sealing commit.
//! - A repetition marked `error` is excluded and counted in the report; protocol v1
//!   allows none, so any excluded repetition refuses the report.
//! - Rates measured here are labelled achieved (a lower bound on the hardware's
//!   capability), never the bound itself; see [`BoundInputKind`].
//! - Energy preflight runs before anything else: without a working `aien_spbm` meter
//!   the run refuses with `INSTRUMENT_UNAVAILABLE` and writes nothing.
//!
//! The figures are measurements, not targets; no test asserts a speed.

use crate::energy::{Spbm, COUNTER_WRAP_UJ, MAX_SAMPLE_GAP, SAMPLE_PERIOD, SENSOR_PERIOD_S};
use crate::floor::FloorReport;
use crate::host::{collect_host_info, HostInfo};
use crate::stats::LatencySummary;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::hint::black_box;
use std::io::Write;
use std::os::unix::fs::{FileExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Barrier, Mutex};
use std::time::{Duration, Instant};

/// Refusal code when the energy meter is missing or not counting (ADR 0003 section 6.2).
pub const INSTRUMENT_UNAVAILABLE: &str = "INSTRUMENT_UNAVAILABLE";
pub const PROTOCOL_SCHEMA: &str = "synapse-bench/a0-host-bounds-protocol/v1";
pub const RAW_SCHEMA: &str = "synapse-bench/a0-host-bounds-raw/v1";
pub const REPORT_SCHEMA: &str = "synapse-bench/a0-host-bounds-report/v2";
/// A range needs at least three repetitions to say anything about spread.
pub const MIN_REPETITIONS: u32 = 3;
pub const PROTOCOL_FILE: &str = "protocol.json";
pub const RAW_FILE: &str = "raw.json";
pub const REPORT_FILE: &str = "report.json";
/// Checksums of the sealed files, in the `sha256sum` format.
pub const SUMS_FILE: &str = "SHA256SUMS";
/// Repetitions a protocol v1 run may exclude (runs marked `error`). v1 has no
/// allowance field, so none: any errored repetition refuses the report.
pub const MAX_EXCLUDED_REPETITIONS: u32 = 0;

const ENERGY_LABELS: [&str; 3] = ["pkg", "cpu_e", "cpu_p"];
const DIRECT_IO_ALIGN: usize = 4096;
const ED25519_ITEMS_PER_THREAD: usize = 16;

// ---------------------------------------------------------------------------------
// Refusals and verification errors
// ---------------------------------------------------------------------------------

/// Why a run refused to produce figures.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BoundsRefusal {
    InstrumentUnavailable(String),
    ProtocolInvalid(String),
    HostMismatch(String),
    W1SourceMismatch(String),
    EvidenceExists(String),
    Io(String),
}

impl BoundsRefusal {
    pub fn code(&self) -> &'static str {
        match self {
            Self::InstrumentUnavailable(_) => INSTRUMENT_UNAVAILABLE,
            Self::ProtocolInvalid(_) => "PROTOCOL_INVALID",
            Self::HostMismatch(_) => "HOST_MISMATCH",
            Self::W1SourceMismatch(_) => "W1_SOURCE_MISMATCH",
            Self::EvidenceExists(_) => "EVIDENCE_EXISTS",
            Self::Io(_) => "IO_FAILURE",
        }
    }

    pub fn detail(&self) -> &str {
        match self {
            Self::InstrumentUnavailable(d)
            | Self::ProtocolInvalid(d)
            | Self::HostMismatch(d)
            | Self::W1SourceMismatch(d)
            | Self::EvidenceExists(d)
            | Self::Io(d) => d,
        }
    }
}

impl fmt::Display for BoundsRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.code(), self.detail())
    }
}

/// Why sealed evidence failed verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerifyError {
    Io(String),
    Parse(String),
    ProtocolInvalid(String),
    ProtocolDigestMismatch { protocol: String, raw_names: String },
    RepetitionMismatch(String),
    WorkMismatch(String),
    ReportMismatch { first_difference_at: usize },
    ExcludedRepetitions(String),
    ChecksumsMissing(String),
    ChecksumMismatch(String),
}

impl fmt::Display for VerifyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(d) => write!(f, "IO_FAILURE: {d}"),
            Self::Parse(d) => write!(f, "PARSE_FAILURE: {d}"),
            Self::ProtocolInvalid(d) => write!(f, "PROTOCOL_INVALID: {d}"),
            Self::ProtocolDigestMismatch {
                protocol,
                raw_names,
            } => write!(
                f,
                "PROTOCOL_DIGEST_MISMATCH: protocol.json is {protocol}, raw.json names {raw_names}"
            ),
            Self::RepetitionMismatch(d) => write!(f, "REPETITION_MISMATCH: {d}"),
            Self::WorkMismatch(d) => write!(f, "WORK_MISMATCH: {d}"),
            Self::ReportMismatch {
                first_difference_at,
            } => write!(
                f,
                "REPORT_MISMATCH: recomputed report differs from report.json at byte {first_difference_at}"
            ),
            Self::ExcludedRepetitions(d) => write!(f, "EXCLUDED_REPETITIONS: {d}"),
            Self::ChecksumsMissing(d) => write!(f, "CHECKSUMS_MISSING: {d}"),
            Self::ChecksumMismatch(d) => write!(f, "CHECKSUM_MISMATCH: {d}"),
        }
    }
}

// ---------------------------------------------------------------------------------
// Protocol (fixed before the runs)
// ---------------------------------------------------------------------------------

/// Central statistic across repetitions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CentralStatistic {
    /// Middle value; mean of the two middle values for an even count.
    Median,
}

/// Spread statistic across repetitions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SpreadStatistic {
    /// Minimum and maximum.
    Range,
}

/// Which repetition value becomes the bound input.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BoundStatistic {
    /// The highest rate any repetition reached: the host demonstrably did at least that.
    MaxRate,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MemoryParams {
    pub bytes_per_thread: u64,
    pub passes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeviceParams {
    pub file_bytes: u64,
    pub chunk_bytes: u64,
    pub threads: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HashParams {
    pub block_bytes: u64,
    pub blocks_per_thread: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerifyParams {
    pub message_bytes: u64,
    pub verifications_per_thread: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PreflightParams {
    pub observe_ms: u64,
    pub min_counter_changes: u32,
}

/// W1's sealed flush measurement, pinned by digest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct W1Source {
    /// Path relative to the repository root.
    pub path: String,
    /// Lowercase hex SHA-256 of the file.
    pub sha256: String,
    /// `floor.json` storage probe names to carry into the report.
    pub probes: Vec<String>,
}

/// Everything fixed before the runs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Protocol {
    pub schema: String,
    pub repetitions: u32,
    pub central_statistic: CentralStatistic,
    pub spread_statistic: SpreadStatistic,
    pub bound_statistic: BoundStatistic,
    /// Threads for the memory, hashing, and verification probes (one per CPU).
    pub threads: u32,
    pub idle_ms: u64,
    pub memory: MemoryParams,
    pub device: DeviceParams,
    pub sha256: HashParams,
    pub ed25519: VerifyParams,
    pub energy_preflight: PreflightParams,
    pub w1_flush: W1Source,
}

impl Protocol {
    /// Parse and validate protocol bytes.
    pub fn parse(bytes: &[u8]) -> Result<Self, String> {
        let p: Protocol = serde_json::from_slice(bytes).map_err(|e| format!("parse: {e}"))?;
        p.validate()?;
        Ok(p)
    }

    pub fn validate(&self) -> Result<(), String> {
        let fail = |why: &str| Err(why.to_string());
        if self.schema != PROTOCOL_SCHEMA {
            return Err(format!(
                "schema {:?}, expected {PROTOCOL_SCHEMA:?}",
                self.schema
            ));
        }
        if self.repetitions < MIN_REPETITIONS {
            return Err(format!(
                "{} repetitions; a range needs at least {MIN_REPETITIONS}",
                self.repetitions
            ));
        }
        if self.threads == 0 || self.device.threads == 0 {
            return fail("thread counts must be positive");
        }
        if self.idle_ms == 0 {
            return fail("idle_ms must be positive");
        }
        let m = &self.memory;
        if m.bytes_per_thread == 0 || !m.bytes_per_thread.is_multiple_of(8) || m.passes == 0 {
            return fail(
                "memory: bytes_per_thread must be a positive multiple of 8 and passes positive",
            );
        }
        let d = &self.device;
        if d.chunk_bytes == 0 || !d.chunk_bytes.is_multiple_of(DIRECT_IO_ALIGN as u64) {
            return fail("device: chunk_bytes must be a positive multiple of 4096 (O_DIRECT)");
        }
        if d.file_bytes == 0
            || !d
                .file_bytes
                .is_multiple_of(d.chunk_bytes * u64::from(d.threads))
        {
            return fail(
                "device: file_bytes must be a positive multiple of chunk_bytes times threads",
            );
        }
        if self.sha256.block_bytes == 0 || self.sha256.blocks_per_thread == 0 {
            return fail("sha256: block_bytes and blocks_per_thread must be positive");
        }
        if self.ed25519.message_bytes == 0 || self.ed25519.verifications_per_thread == 0 {
            return fail("ed25519: message_bytes and verifications_per_thread must be positive");
        }
        let e = &self.energy_preflight;
        if e.observe_ms == 0 || e.min_counter_changes == 0 {
            return fail("energy_preflight: observe_ms and min_counter_changes must be positive");
        }
        let w = &self.w1_flush;
        let hex64 = w.sha256.len() == 64
            && w.sha256
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b));
        if w.path.is_empty() || !hex64 || w.probes.is_empty() {
            return fail(
                "w1_flush: path, a lowercase hex SHA-256, and at least one probe are required",
            );
        }
        Ok(())
    }

    /// Work units every run of `probe` must report (fixed by the protocol).
    pub fn expected_units(&self, probe: ProbeKind) -> u64 {
        let t = u64::from(self.threads);
        match probe {
            ProbeKind::Idle => 0,
            ProbeKind::MemoryRead => t * self.memory.bytes_per_thread * self.memory.passes,
            ProbeKind::MemoryCopy => 2 * t * self.memory.bytes_per_thread * self.memory.passes,
            ProbeKind::DeviceWrite | ProbeKind::DeviceRead => self.device.file_bytes,
            ProbeKind::Sha256Sha2Crate | ProbeKind::Sha256ArmInstructions => {
                t * self.sha256.block_bytes * self.sha256.blocks_per_thread
            }
            ProbeKind::Ed25519Verify => t * self.ed25519.verifications_per_thread,
        }
    }

    /// Threads every run of `probe` must use.
    pub fn expected_threads(&self, probe: ProbeKind) -> u32 {
        match probe {
            ProbeKind::Idle => 0,
            ProbeKind::DeviceWrite | ProbeKind::DeviceRead => self.device.threads,
            _ => self.threads,
        }
    }
}

// ---------------------------------------------------------------------------------
// Probes
// ---------------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProbeKind {
    Idle,
    MemoryRead,
    MemoryCopy,
    DeviceWrite,
    DeviceRead,
    Sha256Sha2Crate,
    Sha256ArmInstructions,
    Ed25519Verify,
}

/// Order of probes inside every repetition.
pub const PROBE_ORDER: [ProbeKind; 8] = [
    ProbeKind::Idle,
    ProbeKind::MemoryRead,
    ProbeKind::MemoryCopy,
    ProbeKind::DeviceWrite,
    ProbeKind::DeviceRead,
    ProbeKind::Sha256Sha2Crate,
    ProbeKind::Sha256ArmInstructions,
    ProbeKind::Ed25519Verify,
];

impl ProbeKind {
    pub fn unit(self) -> &'static str {
        match self {
            Self::Idle => "none",
            Self::Ed25519Verify => "verification",
            _ => "byte",
        }
    }

    pub fn description(self) -> &'static str {
        match self {
            Self::Idle => "harness sleeps; other tenants keep running (idle baseline power)",
            Self::MemoryRead => "every thread sums its own buffer of u64 words, one thread pinned per CPU",
            Self::MemoryCopy => "every thread copies its own buffer into a second one; units count bytes read plus bytes written",
            Self::DeviceWrite => "sequential O_DIRECT overwrite of an already written file, one region per thread, each thread ends with fdatasync",
            Self::DeviceRead => "sequential O_DIRECT read of the same file, one region per thread, read-back pattern checked",
            Self::Sha256Sha2Crate => "every thread hashes one block repeatedly with the sha2 crate as Synapse builds it",
            Self::Sha256ArmInstructions => "every thread hashes one block repeatedly with the CPU's SHA-2 instructions (checked against the sha2 crate first)",
            Self::Ed25519Verify => "every thread verifies prepared Ed25519 signatures with ed25519-dalek as Synapse builds it",
        }
    }
}

/// Elapsed wall time and work units of one timed probe.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Timed {
    pub elapsed_ns: u64,
    pub units: u64,
}

fn pin_current_thread(cpu: usize) {
    // SAFETY: `set` is a zeroed cpu_set_t; CPU_SET and sched_setaffinity(0, ...) only
    // touch it and the calling thread's affinity. Failure leaves the thread unpinned.
    unsafe {
        let mut set: libc::cpu_set_t = std::mem::zeroed();
        libc::CPU_SET(cpu, &mut set);
        let _ = libc::sched_setaffinity(0, std::mem::size_of::<libc::cpu_set_t>(), &set);
    }
}

/// Run `work` on one thread per state, all released together; time from release until
/// the last thread finishes. Each thread is pinned to CPU `index % online CPUs`.
pub fn timed_parallel<S: Send>(
    states: &mut [S],
    work: impl Fn(usize, &mut S) -> Result<u64, String> + Sync,
) -> Result<Timed, String> {
    let n = states.len();
    let cpus = std::thread::available_parallelism().map_or(1, |c| c.get());
    let start = Barrier::new(n + 1);
    let end = Barrier::new(n + 1);
    let (elapsed, results) = std::thread::scope(|s| {
        let handles: Vec<_> = states
            .iter_mut()
            .enumerate()
            .map(|(i, st)| {
                let (start, end, work) = (&start, &end, &work);
                s.spawn(move || {
                    pin_current_thread(i % cpus);
                    start.wait();
                    let r = work(i, st);
                    end.wait();
                    r
                })
            })
            .collect();
        start.wait();
        let t = Instant::now();
        end.wait();
        let elapsed = t.elapsed();
        let results: Vec<Result<u64, String>> = handles
            .into_iter()
            .map(|h| {
                h.join()
                    .unwrap_or_else(|_| Err("probe thread panicked".into()))
            })
            .collect();
        (elapsed, results)
    });
    let mut units = 0u64;
    for r in results {
        units += r?;
    }
    Ok(Timed {
        elapsed_ns: elapsed.as_nanos() as u64,
        units,
    })
}

/// Per-thread buffer for the memory read probe.
pub struct ReadState {
    pub words: Vec<u64>,
    pub checksum: u64,
}

/// Buffers of `bytes_per_thread` bytes, word `j` of thread `t` holding `t * 2^32 + j`.
pub fn memory_read_states(threads: u32, bytes_per_thread: u64) -> Vec<ReadState> {
    (0..u64::from(threads))
        .map(|t| ReadState {
            words: (0..bytes_per_thread / 8).map(|j| (t << 32) + j).collect(),
            checksum: 0,
        })
        .collect()
}

/// Every thread sums its buffer `passes` times (wrapping); the sum is kept for checking.
pub fn memory_read(states: &mut [ReadState], passes: u64) -> Result<Timed, String> {
    timed_parallel(states, |_, st| {
        let mut acc = 0u64;
        for _ in 0..passes {
            let words = black_box(st.words.as_slice());
            acc = acc.wrapping_add(words.iter().fold(0u64, |a, &w| a.wrapping_add(w)));
        }
        st.checksum = black_box(acc);
        Ok(passes * st.words.len() as u64 * 8)
    })
}

/// Per-thread buffers for the memory copy probe.
pub struct CopyState {
    pub src: Vec<u64>,
    pub dst: Vec<u64>,
}

pub fn memory_copy_states(threads: u32, bytes_per_thread: u64) -> Vec<CopyState> {
    let words = (bytes_per_thread / 8) as usize;
    (0..u64::from(threads))
        .map(|t| CopyState {
            src: (0..words as u64)
                .map(|j| (t << 32) ^ j.wrapping_mul(31))
                .collect(),
            dst: vec![u64::MAX; words],
        })
        .collect()
}

/// Every thread copies `src` into `dst` `passes` times; units are bytes read plus written.
pub fn memory_copy(states: &mut [CopyState], passes: u64) -> Result<Timed, String> {
    timed_parallel(states, |_, st| {
        for _ in 0..passes {
            let src = black_box(st.src.as_slice());
            st.dst.copy_from_slice(src);
            black_box(st.dst.as_mut_ptr());
        }
        Ok(2 * passes * st.src.len() as u64 * 8)
    })
}

/// A heap buffer whose usable slice starts on a 4096-byte boundary (for `O_DIRECT`).
pub struct AlignedBytes {
    storage: Vec<u8>,
    offset: usize,
    len: usize,
}

impl AlignedBytes {
    pub fn new(len: usize, fill: u8) -> Result<Self, String> {
        let storage = vec![fill; len + DIRECT_IO_ALIGN];
        let offset = storage.as_ptr().align_offset(DIRECT_IO_ALIGN);
        if offset > DIRECT_IO_ALIGN {
            return Err("cannot align buffer for O_DIRECT".into());
        }
        Ok(Self {
            storage,
            offset,
            len,
        })
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.storage[self.offset..self.offset + self.len]
    }

    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.storage[self.offset..self.offset + self.len]
    }
}

fn io<T>(r: std::io::Result<T>, what: &str) -> Result<T, String> {
    r.map_err(|e| format!("{what}: {e}"))
}

/// Write `bytes` of zeros to `path` and fsync, so later probes overwrite allocated blocks.
pub fn prepare_device_file(path: &Path, bytes: u64) -> Result<(), String> {
    let mut f = io(File::create(path), "create device file")?;
    let chunk = vec![0u8; 4 << 20];
    let mut left = bytes;
    while left > 0 {
        let n = left.min(chunk.len() as u64) as usize;
        io(f.write_all(&chunk[..n]), "prewrite device file")?;
        left -= n as u64;
    }
    io(f.sync_all(), "fsync device file")
}

/// One thread's region of the device file.
pub struct DeviceState {
    file: File,
    buf: AlignedBytes,
    offset: u64,
    chunks: u64,
}

fn device_states(
    path: &Path,
    p: &DeviceParams,
    write: bool,
    fill: u8,
) -> Result<Vec<DeviceState>, String> {
    let region = p.file_bytes / u64::from(p.threads);
    (0..u64::from(p.threads))
        .map(|t| {
            let mut o = OpenOptions::new();
            if write {
                o.write(true);
            } else {
                o.read(true);
            }
            let file = io(
                o.custom_flags(libc::O_DIRECT).open(path),
                "open device file O_DIRECT",
            )?;
            Ok(DeviceState {
                file,
                buf: AlignedBytes::new(p.chunk_bytes as usize, fill)?,
                offset: t * region,
                chunks: region / p.chunk_bytes,
            })
        })
        .collect()
}

/// Overwrite the whole file with `pattern` (each thread its region), each thread
/// ending with `fdatasync`; the time includes the flushes.
pub fn device_write(path: &Path, p: &DeviceParams, pattern: u8) -> Result<Timed, String> {
    let mut states = device_states(path, p, true, pattern)?;
    timed_parallel(&mut states, |_, st| {
        let len = st.buf.as_slice().len() as u64;
        for k in 0..st.chunks {
            io(
                st.file.write_all_at(st.buf.as_slice(), st.offset + k * len),
                "O_DIRECT write",
            )?;
        }
        io(st.file.sync_data(), "fdatasync")?;
        Ok(st.chunks * len)
    })
}

/// Read the whole file (each thread its region) and check that every chunk starts and
/// ends with `pattern`.
pub fn device_read(path: &Path, p: &DeviceParams, pattern: u8) -> Result<Timed, String> {
    let mut states = device_states(path, p, false, !pattern)?;
    timed_parallel(&mut states, |_, st| {
        let len = st.buf.as_slice().len() as u64;
        for k in 0..st.chunks {
            let off = st.offset + k * len;
            io(
                st.file.read_exact_at(st.buf.as_mut_slice(), off),
                "O_DIRECT read",
            )?;
            let b = st.buf.as_slice();
            if b[0] != pattern || b[b.len() - 1] != pattern {
                return Err(format!("read-back mismatch at offset {off}"));
            }
        }
        Ok(st.chunks * len)
    })
}

/// Per-thread block for the hashing probes.
pub struct HashState {
    pub block: Vec<u8>,
    pub last: [u8; 32],
}

pub fn hash_states(threads: u32, block_bytes: u64) -> Vec<HashState> {
    (0..threads)
        .map(|t| HashState {
            block: (0..block_bytes)
                .map(|j| (j as u8).wrapping_mul(13) ^ t as u8)
                .collect(),
            last: [0u8; 32],
        })
        .collect()
}

/// Every thread hashes its block `blocks` times with the `sha2` crate.
pub fn sha256_sha2_crate(states: &mut [HashState], blocks: u64) -> Result<Timed, String> {
    timed_parallel(states, |_, st| {
        for _ in 0..blocks {
            st.last = Sha256::digest(black_box(st.block.as_slice())).into();
        }
        Ok(blocks * st.block.len() as u64)
    })
}

/// Every thread hashes its block `blocks` times with the CPU's SHA-2 instructions, after
/// checking that they give the `sha2` crate's digest for that block.
pub fn sha256_arm_instructions(states: &mut [HashState], blocks: u64) -> Result<Timed, String> {
    for st in states.iter() {
        let want: [u8; 32] = Sha256::digest(&st.block).into();
        match sha256_arm(&st.block) {
            None => return Err("CPU SHA-2 instructions not available".into()),
            Some(d) if d != want => {
                return Err("SHA-2 instruction digest differs from the sha2 crate".into())
            }
            Some(_) => {}
        }
    }
    timed_parallel(states, |_, st| {
        for _ in 0..blocks {
            st.last = sha256_arm(black_box(st.block.as_slice())).unwrap_or([0u8; 32]);
        }
        Ok(blocks * st.block.len() as u64)
    })
}

/// Prepared signatures for one verification thread.
pub struct VerifyState {
    pub items: Vec<(VerifyingKey, Vec<u8>, Signature)>,
}

pub fn verify_states(threads: u32, message_bytes: u64) -> Vec<VerifyState> {
    (0..threads)
        .map(|t| VerifyState {
            items: (0..ED25519_ITEMS_PER_THREAD)
                .map(|i| {
                    let mut seed = [0u8; 32];
                    seed[0] = t as u8;
                    seed[1] = i as u8;
                    seed[2] = 0xa0;
                    let key = SigningKey::from_bytes(&seed);
                    let msg: Vec<u8> = (0..message_bytes).map(|j| (j as u8) ^ i as u8).collect();
                    let sig = key.sign(&msg);
                    (key.verifying_key(), msg, sig)
                })
                .collect(),
        })
        .collect()
}

/// Every thread verifies `per_thread` signatures; any failed verification is an error.
pub fn ed25519_verify(states: &mut [VerifyState], per_thread: u64) -> Result<Timed, String> {
    timed_parallel(states, |t, st| {
        for i in 0..per_thread {
            let (key, msg, sig) = &st.items[i as usize % st.items.len()];
            key.verify(black_box(msg), sig)
                .map_err(|_| format!("thread {t}: verification {i} failed"))?;
        }
        Ok(per_thread)
    })
}

// ---------------------------------------------------------------------------------
// SHA-256 with the Armv8 SHA-2 instructions
// ---------------------------------------------------------------------------------

/// SHA-256 with the CPU's SHA-2 instructions; `None` when the CPU lacks them.
pub fn sha256_arm(data: &[u8]) -> Option<[u8; 32]> {
    #[cfg(target_arch = "aarch64")]
    {
        if std::arch::is_aarch64_feature_detected!("sha2") {
            // SAFETY: the `sha2` feature was detected at run time.
            return Some(unsafe { arm::sha256(data) });
        }
    }
    let _ = data;
    None
}

#[cfg(target_arch = "aarch64")]
mod arm {
    use core::arch::aarch64::*;

    const K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
        0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
        0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
        0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
        0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
        0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
        0xc67178f2,
    ];

    const H0: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];

    /// Compress whole 64-byte blocks into `state`.
    #[target_feature(enable = "sha2")]
    unsafe fn compress(state: &mut [u32; 8], data: &[u8]) {
        let mut abcd = vld1q_u32(state.as_ptr());
        let mut efgh = vld1q_u32(state.as_ptr().add(4));
        for block in data.as_chunks::<64>().0 {
            let (abcd0, efgh0) = (abcd, efgh);
            let p = block.as_ptr();
            let load = |o: usize| vreinterpretq_u32_u8(vrev32q_u8(vld1q_u8(p.add(o))));
            let mut w = [load(0), load(16), load(32), load(48)];
            for i in 0..16 {
                let wk = vaddq_u32(w[i % 4], vld1q_u32(K.as_ptr().add(4 * i)));
                let prev = abcd;
                abcd = vsha256hq_u32(abcd, efgh, wk);
                efgh = vsha256h2q_u32(efgh, prev, wk);
                if i < 12 {
                    w[i % 4] = vsha256su1q_u32(
                        vsha256su0q_u32(w[i % 4], w[(i + 1) % 4]),
                        w[(i + 2) % 4],
                        w[(i + 3) % 4],
                    );
                }
            }
            abcd = vaddq_u32(abcd, abcd0);
            efgh = vaddq_u32(efgh, efgh0);
        }
        vst1q_u32(state.as_mut_ptr(), abcd);
        vst1q_u32(state.as_mut_ptr().add(4), efgh);
    }

    /// # Safety
    /// The CPU must support the Armv8 `sha2` feature.
    #[target_feature(enable = "sha2")]
    pub unsafe fn sha256(data: &[u8]) -> [u8; 32] {
        let mut state = H0;
        let full = data.len() / 64 * 64;
        compress(&mut state, &data[..full]);
        let rest = &data[full..];
        let mut tail = [0u8; 128];
        tail[..rest.len()].copy_from_slice(rest);
        tail[rest.len()] = 0x80;
        let tail_len = if rest.len() < 56 { 64 } else { 128 };
        let bits = (data.len() as u64).wrapping_mul(8);
        tail[tail_len - 8..tail_len].copy_from_slice(&bits.to_be_bytes());
        compress(&mut state, &tail[..tail_len]);
        let mut out = [0u8; 32];
        for (i, word) in state.iter().enumerate() {
            out[4 * i..4 * i + 4].copy_from_slice(&word.to_be_bytes());
        }
        out
    }
}

// ---------------------------------------------------------------------------------
// Energy: preflight and raw sampling
// ---------------------------------------------------------------------------------

/// Check the energy meter before any probe runs: the `aien_spbm` device must exist
/// under `hwmon_root`, the `pkg`, `cpu_e`, and `cpu_p` counters must be readable with
/// clear overflow flags, and `pkg` must change at least `min_counter_changes` times in
/// `observe_ms` without decreasing. Otherwise the run refuses with
/// `INSTRUMENT_UNAVAILABLE` and no figure is produced.
pub fn energy_preflight(hwmon_root: &Path, p: &PreflightParams) -> Result<Spbm, BoundsRefusal> {
    let refuse = |why: String| BoundsRefusal::InstrumentUnavailable(why);
    let spbm = Spbm::find_in(hwmon_root).ok_or_else(|| {
        refuse(format!(
            "no aien_spbm hwmon device under {}",
            hwmon_root.display()
        ))
    })?;
    for label in ENERGY_LABELS {
        if spbm.energy_uj(label).is_none() {
            return Err(refuse(format!("energy channel {label} unreadable")));
        }
        match spbm.overflow_raw(label) {
            Some(0) => {}
            Some(v) => return Err(refuse(format!("overflow flag {v} set on {label}"))),
            None => return Err(refuse(format!("overflow flag of {label} unreadable"))),
        }
    }
    let mut last = spbm
        .energy_uj("pkg")
        .ok_or_else(|| refuse("pkg became unreadable".into()))?;
    let mut changes = 0u32;
    let start = Instant::now();
    while start.elapsed() < Duration::from_millis(p.observe_ms) {
        std::thread::sleep(Duration::from_millis(1));
        let v = spbm
            .energy_uj("pkg")
            .ok_or_else(|| refuse("pkg became unreadable".into()))?;
        if v < last {
            return Err(refuse("pkg counter decreased during preflight".into()));
        }
        if v != last {
            changes += 1;
            last = v;
        }
    }
    if changes < p.min_counter_changes {
        return Err(refuse(format!(
            "pkg counter changed {changes} times in {} ms; the protocol needs {}",
            p.observe_ms, p.min_counter_changes
        )));
    }
    Ok(spbm)
}

/// One meter reading: nanoseconds since the window opened and raw counters in microjoules.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct RawEnergySample {
    pub t_ns: u64,
    pub pkg_uj: Option<u64>,
    pub cpu_e_uj: Option<u64>,
    pub cpu_p_uj: Option<u64>,
}

/// Every meter reading of one window, with the overflow flags at both edges.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RawEnergy {
    pub overflow_at_start: bool,
    pub overflow_at_end: bool,
    pub samples: Vec<RawEnergySample>,
}

fn any_overflow(s: &Spbm) -> bool {
    ENERGY_LABELS
        .iter()
        .any(|l| s.overflow_raw(l).is_none_or(|v| v != 0))
}

fn read_sample(s: &Spbm, t0: Instant) -> RawEnergySample {
    RawEnergySample {
        t_ns: t0.elapsed().as_nanos() as u64,
        pkg_uj: s.energy_uj("pkg"),
        cpu_e_uj: s.energy_uj("cpu_e"),
        cpu_p_uj: s.energy_uj("cpu_p"),
    }
}

/// A 10 Hz sampler recording raw counters (no arithmetic happens while sampling).
struct Sampler {
    spbm: Spbm,
    t0: Instant,
    overflow_at_start: bool,
    first: RawEnergySample,
    stop: Arc<AtomicBool>,
    samples: Arc<Mutex<Vec<RawEnergySample>>>,
    handle: Option<std::thread::JoinHandle<()>>,
}

impl Sampler {
    fn start(spbm: &Spbm) -> Self {
        let t0 = Instant::now();
        let overflow_at_start = any_overflow(spbm);
        let first = read_sample(spbm, t0);
        let stop = Arc::new(AtomicBool::new(false));
        let samples = Arc::new(Mutex::new(Vec::new()));
        let handle = {
            let (s, stop, samples) = (spbm.clone(), stop.clone(), samples.clone());
            std::thread::spawn(move || {
                let mut next = t0 + SAMPLE_PERIOD;
                while !stop.load(Ordering::Relaxed) {
                    let now = Instant::now();
                    if now < next {
                        std::thread::sleep((next - now).min(Duration::from_millis(5)));
                        continue;
                    }
                    let sm = read_sample(&s, t0);
                    if let Ok(mut v) = samples.lock() {
                        v.push(sm);
                    }
                    next += SAMPLE_PERIOD;
                }
            })
        };
        Self {
            spbm: spbm.clone(),
            t0,
            overflow_at_start,
            first,
            stop,
            samples,
            handle: Some(handle),
        }
    }

    fn finish(mut self) -> RawEnergy {
        let last = read_sample(&self.spbm, self.t0);
        self.stop.store(true, Ordering::Relaxed);
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
        let mut samples = vec![self.first];
        samples.extend(self.samples.lock().map(|v| v.clone()).unwrap_or_default());
        samples.push(last);
        RawEnergy {
            overflow_at_start: self.overflow_at_start,
            overflow_at_end: any_overflow(&self.spbm),
            samples,
        }
    }
}

// ---------------------------------------------------------------------------------
// Raw evidence
// ---------------------------------------------------------------------------------

/// Instruments and their resolution.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Instruments {
    pub clock: String,
    pub clock_resolution_ns: u64,
    pub energy_sensor: String,
    /// Smallest energy step the counter reports, microjoules.
    pub energy_step_uj: u64,
    /// Firmware update period assumed for the edge uncertainty, milliseconds.
    pub energy_update_period_ms: u64,
    pub energy_sample_period_ms: u64,
}

/// One storage probe carried over from W1's `floor.json`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct W1FlushProbe {
    pub name: String,
    pub description: String,
    pub latency: LatencySummary,
}

/// W1's flush measurement as sealed in Phase 5.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct W1Flush {
    pub path: String,
    pub sha256: String,
    pub probes: Vec<W1FlushProbe>,
}

/// One probe run: integers only.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RawRun {
    pub probe: ProbeKind,
    pub rep: u32,
    pub threads: u32,
    pub work_units: u64,
    pub elapsed_ns: u64,
    pub error: Option<String>,
    pub energy: RawEnergy,
    /// `/proc/loadavg` as read at the start and end of the run (other tenants are a confounder).
    pub loadavg_start: Option<String>,
    pub loadavg_end: Option<String>,
}

/// Everything `report.json` is computed from.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RawEvidence {
    pub schema: String,
    pub protocol_sha256: String,
    pub source_rev: String,
    pub started_utc: String,
    pub host: HostInfo,
    pub instruments: Instruments,
    pub w1_flush: W1Flush,
    pub runs: Vec<RawRun>,
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

/// Load W1's `floor.json` from `repo_root`, check its digest, and copy the named probes.
pub fn load_w1_flush(repo_root: &Path, src: &W1Source) -> Result<W1Flush, BoundsRefusal> {
    let path = repo_root.join(&src.path);
    let bytes = fs::read(&path)
        .map_err(|e| BoundsRefusal::W1SourceMismatch(format!("read {}: {e}", path.display())))?;
    let found = sha256_hex(&bytes);
    if found != src.sha256 {
        return Err(BoundsRefusal::W1SourceMismatch(format!(
            "{} has SHA-256 {found}; the protocol pins {}",
            src.path, src.sha256
        )));
    }
    let floor: FloorReport = serde_json::from_slice(&bytes)
        .map_err(|e| BoundsRefusal::W1SourceMismatch(format!("parse {}: {e}", src.path)))?;
    let probes = src
        .probes
        .iter()
        .map(|name| {
            floor
                .storage
                .iter()
                .find(|p| &p.name == name)
                .and_then(|p| {
                    p.latency.clone().map(|latency| W1FlushProbe {
                        name: p.name.clone(),
                        description: p.description.clone(),
                        latency,
                    })
                })
                .ok_or_else(|| {
                    BoundsRefusal::W1SourceMismatch(format!(
                        "probe {name} missing or without latency in {}",
                        src.path
                    ))
                })
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(W1Flush {
        path: src.path.clone(),
        sha256: src.sha256.clone(),
        probes,
    })
}

fn clock_resolution_ns() -> u64 {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: `ts` is a valid, exclusively borrowed timespec.
    let rc = unsafe { libc::clock_getres(libc::CLOCK_MONOTONIC, &mut ts) };
    if rc != 0 {
        return 0;
    }
    ts.tv_sec as u64 * 1_000_000_000 + ts.tv_nsec as u64
}

// ---------------------------------------------------------------------------------
// Running
// ---------------------------------------------------------------------------------

/// Where a run reads its protocol and writes its evidence.
#[derive(Debug, Clone)]
pub struct BoundsConfig {
    /// Holds `protocol.json`; `raw.json` and `report.json` are written here.
    pub evidence_dir: PathBuf,
    /// Scratch directory on the store's filesystem (device probes write here).
    pub work_dir: PathBuf,
    /// Root that `protocol.w1_flush.path` is relative to.
    pub repo_root: PathBuf,
    /// Where hwmon devices are listed (normally [`crate::energy::HWMON_ROOT`]).
    pub hwmon_root: PathBuf,
    pub source_rev: String,
}

fn measured(
    spbm: &Spbm,
    probe: ProbeKind,
    rep: u32,
    threads: u32,
    work: impl FnOnce() -> Result<Timed, String>,
) -> RawRun {
    let loadavg_start = loadavg_line();
    let sampler = Sampler::start(spbm);
    let result = work();
    let energy = sampler.finish();
    let loadavg_end = loadavg_line();
    let (work_units, elapsed_ns, error) = match result {
        Ok(t) => (t.units, t.elapsed_ns, None),
        Err(e) => (0, 0, Some(e)),
    };
    RawRun {
        probe,
        rep,
        threads,
        work_units,
        elapsed_ns,
        error,
        energy,
        loadavg_start,
        loadavg_end,
    }
}

fn loadavg_line() -> Option<String> {
    fs::read_to_string("/proc/loadavg")
        .ok()
        .map(|s| s.trim().to_string())
}

fn device_pattern(rep: u32) -> u8 {
    0x41 + (rep % 64) as u8
}

fn run_probe(spbm: &Spbm, p: &Protocol, probe: ProbeKind, rep: u32, device_file: &Path) -> RawRun {
    let threads = p.expected_threads(probe);
    match probe {
        ProbeKind::Idle => measured(spbm, probe, rep, threads, || {
            let t = Instant::now();
            std::thread::sleep(Duration::from_millis(p.idle_ms));
            Ok(Timed {
                elapsed_ns: t.elapsed().as_nanos() as u64,
                units: 0,
            })
        }),
        ProbeKind::MemoryRead => {
            let mut st = memory_read_states(p.threads, p.memory.bytes_per_thread);
            measured(spbm, probe, rep, threads, || {
                memory_read(&mut st, p.memory.passes)
            })
        }
        ProbeKind::MemoryCopy => {
            let mut st = memory_copy_states(p.threads, p.memory.bytes_per_thread);
            measured(spbm, probe, rep, threads, || {
                memory_copy(&mut st, p.memory.passes)
            })
        }
        ProbeKind::DeviceWrite => measured(spbm, probe, rep, threads, || {
            device_write(device_file, &p.device, device_pattern(rep))
        }),
        ProbeKind::DeviceRead => measured(spbm, probe, rep, threads, || {
            device_read(device_file, &p.device, device_pattern(rep))
        }),
        ProbeKind::Sha256Sha2Crate => {
            let mut st = hash_states(p.threads, p.sha256.block_bytes);
            measured(spbm, probe, rep, threads, || {
                sha256_sha2_crate(&mut st, p.sha256.blocks_per_thread)
            })
        }
        ProbeKind::Sha256ArmInstructions => {
            let mut st = hash_states(p.threads, p.sha256.block_bytes);
            measured(spbm, probe, rep, threads, || {
                sha256_arm_instructions(&mut st, p.sha256.blocks_per_thread)
            })
        }
        ProbeKind::Ed25519Verify => {
            let mut st = verify_states(p.threads, p.ed25519.message_bytes);
            measured(spbm, probe, rep, threads, || {
                ed25519_verify(&mut st, p.ed25519.verifications_per_thread)
            })
        }
    }
}

/// Run every probe `repetitions` times (probe order fixed by [`PROBE_ORDER`]), write
/// `raw.json`, then compute `report.json` from the bytes just written.
///
/// Refuses before touching the work or evidence directory when the protocol is invalid
/// or the energy meter is unavailable (`INSTRUMENT_UNAVAILABLE`).
pub fn run_bounds(cfg: &BoundsConfig) -> Result<Report, BoundsRefusal> {
    let protocol_bytes = fs::read(cfg.evidence_dir.join(PROTOCOL_FILE))
        .map_err(|e| BoundsRefusal::Io(format!("read {PROTOCOL_FILE}: {e}")))?;
    let protocol = Protocol::parse(&protocol_bytes).map_err(BoundsRefusal::ProtocolInvalid)?;
    let spbm = energy_preflight(&cfg.hwmon_root, &protocol.energy_preflight)?;
    for name in [RAW_FILE, REPORT_FILE, SUMS_FILE] {
        if cfg.evidence_dir.join(name).exists() {
            return Err(BoundsRefusal::EvidenceExists(format!(
                "{name} already exists; sealed evidence is never overwritten"
            )));
        }
    }
    let cpus = std::thread::available_parallelism().map_or(1, |c| c.get());
    if protocol.threads as usize > cpus {
        return Err(BoundsRefusal::HostMismatch(format!(
            "protocol fixes {} threads; this host has {cpus} CPUs",
            protocol.threads
        )));
    }
    let w1_flush = load_w1_flush(&cfg.repo_root, &protocol.w1_flush)?;
    let work = cfg
        .work_dir
        .join(format!("synapse-a0-bounds-{}", std::process::id()));
    fs::create_dir_all(&work)
        .map_err(|e| BoundsRefusal::Io(format!("mkdir {}: {e}", work.display())))?;
    let host = collect_host_info(&work);
    let started_utc = crate::utc_timestamp();
    let device_file = work.join("device.dat");
    let prepared = prepare_device_file(&device_file, protocol.device.file_bytes);
    let mut runs = Vec::new();
    for rep in 0..protocol.repetitions {
        for probe in PROBE_ORDER {
            let run = match (&prepared, probe) {
                (Err(e), ProbeKind::DeviceWrite | ProbeKind::DeviceRead) => RawRun {
                    probe,
                    rep,
                    threads: protocol.expected_threads(probe),
                    work_units: 0,
                    elapsed_ns: 0,
                    error: Some(e.clone()),
                    energy: RawEnergy::default(),
                    loadavg_start: None,
                    loadavg_end: None,
                },
                _ => run_probe(&spbm, &protocol, probe, rep, &device_file),
            };
            runs.push(run);
        }
    }
    let _ = fs::remove_dir_all(&work);
    let raw = RawEvidence {
        schema: RAW_SCHEMA.into(),
        protocol_sha256: sha256_hex(&protocol_bytes),
        source_rev: cfg.source_rev.clone(),
        started_utc,
        host,
        instruments: Instruments {
            clock: "CLOCK_MONOTONIC (std::time::Instant)".into(),
            clock_resolution_ns: clock_resolution_ns(),
            energy_sensor: "aien_spbm hwmon, SoC package only (GB10 SPBM firmware counters; \
                            pkg, cpu_e, cpu_p; no published accuracy; not compared with an \
                            external meter; NVMe drive energy outside it, UNMEASURED)"
                .into(),
            energy_step_uj: 1000,
            energy_update_period_ms: (SENSOR_PERIOD_S * 1000.0) as u64,
            energy_sample_period_ms: SAMPLE_PERIOD.as_millis() as u64,
        },
        w1_flush,
        runs,
    };
    let raw_bytes = serde_json::to_vec_pretty(&raw)
        .map_err(|e| BoundsRefusal::Io(format!("serialize raw: {e}")))?;
    fs::write(cfg.evidence_dir.join(RAW_FILE), &raw_bytes)
        .map_err(|e| BoundsRefusal::Io(format!("write {RAW_FILE}: {e}")))?;
    let raw_bytes = fs::read(cfg.evidence_dir.join(RAW_FILE))
        .map_err(|e| BoundsRefusal::Io(format!("reread {RAW_FILE}: {e}")))?;
    let report = compute_report(&protocol_bytes, &raw_bytes)
        .map_err(|e| BoundsRefusal::Io(format!("compute report: {e}")))?;
    fs::write(cfg.evidence_dir.join(REPORT_FILE), report_bytes(&report)?)
        .map_err(|e| BoundsRefusal::Io(format!("write {REPORT_FILE}: {e}")))?;
    let sums = sha256sums(&cfg.evidence_dir, &[PROTOCOL_FILE, RAW_FILE, REPORT_FILE])
        .map_err(|e| BoundsRefusal::Io(format!("checksum sealed files: {e}")))?;
    fs::write(cfg.evidence_dir.join(SUMS_FILE), sums)
        .map_err(|e| BoundsRefusal::Io(format!("write {SUMS_FILE}: {e}")))?;
    Ok(report)
}

// ---------------------------------------------------------------------------------
// Report: a pure function of the protocol and raw bytes
// ---------------------------------------------------------------------------------

/// Energy figures of one window, derived from raw counters only.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct EnergyFigures {
    pub valid: bool,
    pub refusal: Option<String>,
    pub samples: usize,
    pub window_s: Option<f64>,
    pub largest_gap_ms: Option<f64>,
    pub pkg_j: Option<f64>,
    pub cpu_p_j: Option<f64>,
    pub cpu_e_j: Option<f64>,
    pub pkg_mean_w: Option<f64>,
    /// `pkg_mean_w * 0.1 s * sqrt(2/3)`: the analytic edge uncertainty, joules.
    pub pkg_edge_sd_j: Option<f64>,
    pub pkg_j_per_unit: Option<f64>,
    /// `(pkg_j - idle W * window_s) / units`, idle W from the same repetition's idle run.
    pub pkg_j_per_unit_above_idle: Option<f64>,
}

/// Apply the energy refusal rules of [`crate::energy`] to raw counters: refuse when an
/// overflow flag is set at an edge, a gap between samples exceeds 300 ms, fewer than
/// 90% of the expected samples arrived, a counter is unreadable or decreased, or the
/// counter is within one window of the 32-bit wrap.
pub fn energy_figures(raw: &RawEnergy, work_units: u64, idle_w: Option<f64>) -> EnergyFigures {
    let s = &raw.samples;
    let mut f = EnergyFigures {
        samples: s.len(),
        ..Default::default()
    };
    if s.len() < 2 {
        f.refusal = Some("fewer than two samples".into());
        return f;
    }
    let window_ns = s[s.len() - 1].t_ns.saturating_sub(s[0].t_ns);
    let window_s = window_ns as f64 / 1e9;
    f.window_s = Some(window_s);
    let largest_gap = s
        .windows(2)
        .map(|w| w[1].t_ns.saturating_sub(w[0].t_ns))
        .max()
        .unwrap_or(0);
    f.largest_gap_ms = Some(largest_gap as f64 / 1e6);
    let expected = window_ns / SAMPLE_PERIOD.as_nanos() as u64;
    let delta = |get: fn(&RawEnergySample) -> Option<u64>| -> Result<u64, String> {
        let mut prev: Option<u64> = None;
        for x in s {
            let v = get(x).ok_or("counter read failed (overflow or missing)")?;
            if prev.is_some_and(|p| v < p) {
                return Err("energy counter decreased".into());
            }
            prev = Some(v);
        }
        let (a, b) = (get(&s[0]).unwrap_or(0), get(&s[s.len() - 1]).unwrap_or(0));
        if COUNTER_WRAP_UJ.saturating_sub(b) <= b - a {
            return Err("counter within one window of the 32-bit wrap".into());
        }
        Ok(b - a)
    };
    let refusal = if raw.overflow_at_start || raw.overflow_at_end {
        Some("overflow flag set at a window edge".to_string())
    } else if largest_gap > MAX_SAMPLE_GAP.as_nanos() as u64 {
        Some("gap between consecutive samples above 300 ms".into())
    } else if (s.len() as u64 - 2) * 10 < expected * 9 {
        Some(format!(
            "fewer than 90% of expected samples ({} of {expected})",
            s.len() - 2
        ))
    } else {
        None
    };
    if let Some(why) = refusal {
        f.refusal = Some(why);
        return f;
    }
    let (pkg, cpu_p, cpu_e) = match (
        delta(|x| x.pkg_uj),
        delta(|x| x.cpu_p_uj),
        delta(|x| x.cpu_e_uj),
    ) {
        (Ok(a), Ok(b), Ok(c)) => (a, b, c),
        (a, b, c) => {
            f.refusal = [a.err(), b.err(), c.err()].into_iter().flatten().next();
            return f;
        }
    };
    let pkg_j = pkg as f64 / 1e6;
    f.valid = true;
    f.pkg_j = Some(pkg_j);
    f.cpu_p_j = Some(cpu_p as f64 / 1e6);
    f.cpu_e_j = Some(cpu_e as f64 / 1e6);
    if window_ns > 0 {
        let w = pkg_j / window_s;
        f.pkg_mean_w = Some(w);
        f.pkg_edge_sd_j = Some(w * SENSOR_PERIOD_S * (2.0f64 / 3.0).sqrt());
    }
    if work_units > 0 {
        f.pkg_j_per_unit = Some(pkg_j / work_units as f64);
        f.pkg_j_per_unit_above_idle = idle_w.map(|w| (pkg_j - w * window_s) / work_units as f64);
    }
    f
}

/// Median, minimum, and maximum across repetitions (no rounding).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Stat {
    pub median: f64,
    pub min: f64,
    pub max: f64,
    pub n: usize,
}

pub fn stat(values: &[f64]) -> Option<Stat> {
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
    Some(Stat {
        median,
        min: v[0],
        max: v[n - 1],
        n,
    })
}

/// Figures of one probe run.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RepFigures {
    pub rep: u32,
    pub work_units: u64,
    pub elapsed_s: f64,
    /// `work_units / elapsed_s`.
    pub rate_per_s: Option<f64>,
    pub error: Option<String>,
    pub energy: EnergyFigures,
}

/// One probe across all repetitions.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ProbeSummary {
    pub probe: ProbeKind,
    pub unit: String,
    pub description: String,
    pub threads: u32,
    pub errors: u32,
    pub valid_energy_reps: u32,
    pub rate_per_s: Option<Stat>,
    pub pkg_mean_w: Option<Stat>,
    pub pkg_j_per_unit: Option<Stat>,
    pub pkg_j_per_unit_above_idle: Option<Stat>,
    pub reps: Vec<RepFigures>,
}

/// What a measured bound input is allowed to claim. A rate measured on this host is
/// never the hardware's capability: a better workload can exceed it. So a hardware
/// rate is only ever `Achieved` (a lower bound on capability; the physical bound comes
/// from the vendor's published figure or the link, outside this run). Where no
/// closed-form limit exists, section 6.2 makes the best all-core implementation the
/// reference, replaced whenever a later measurement beats it. There is no third label.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BoundInputKind {
    #[serde(rename = "achieved (lower bound on capability)")]
    Achieved,
    #[serde(rename = "implementation reference (section 6.2 replacement rule)")]
    ImplementationReference,
}

impl fmt::Display for BoundInputKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Achieved => "achieved (lower bound on capability)",
            Self::ImplementationReference => {
                "implementation reference (section 6.2 replacement rule)"
            }
        })
    }
}

/// One section 6.2 bound input.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BoundInput {
    pub name: String,
    pub value: f64,
    pub unit: String,
    pub probe: ProbeKind,
    pub statistic: BoundStatistic,
    pub kind: BoundInputKind,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Report {
    pub schema: String,
    pub protocol_sha256: String,
    pub raw_sha256: String,
    pub source_rev: String,
    pub repetitions: u32,
    pub central_statistic: CentralStatistic,
    pub spread_statistic: SpreadStatistic,
    pub bound_statistic: BoundStatistic,
    /// Repetitions marked `error` (they skip their work). At most
    /// [`MAX_EXCLUDED_REPETITIONS`]; reported even when zero.
    pub excluded_repetitions: u32,
    pub instruments: Instruments,
    pub w1_flush: W1Flush,
    pub bound_inputs: Vec<BoundInput>,
    pub probes: Vec<ProbeSummary>,
}

fn report_bytes(r: &Report) -> Result<Vec<u8>, BoundsRefusal> {
    serde_json::to_vec_pretty(r).map_err(|e| BoundsRefusal::Io(format!("serialize report: {e}")))
}

/// Checks the runs against the protocol and returns how many repetitions are excluded
/// (marked `error`). Refuses when that exceeds [`MAX_EXCLUDED_REPETITIONS`].
fn check_runs(p: &Protocol, raw: &RawEvidence) -> Result<u32, VerifyError> {
    let want = PROBE_ORDER.len() * p.repetitions as usize;
    if raw.runs.len() != want {
        return Err(VerifyError::RepetitionMismatch(format!(
            "{} runs; the protocol fixes {} probes x {} repetitions = {want}",
            raw.runs.len(),
            PROBE_ORDER.len(),
            p.repetitions
        )));
    }
    for probe in PROBE_ORDER {
        let mut reps: Vec<u32> = raw
            .runs
            .iter()
            .filter(|r| r.probe == probe)
            .map(|r| r.rep)
            .collect();
        reps.sort_unstable();
        if reps != (0..p.repetitions).collect::<Vec<_>>() {
            return Err(VerifyError::RepetitionMismatch(format!(
                "{probe:?} has repetitions {reps:?}; the protocol fixes 0..{}",
                p.repetitions
            )));
        }
    }
    for r in &raw.runs {
        if r.threads != p.expected_threads(r.probe) {
            return Err(VerifyError::WorkMismatch(format!(
                "{:?} rep {} used {} threads; the protocol fixes {}",
                r.probe,
                r.rep,
                r.threads,
                p.expected_threads(r.probe)
            )));
        }
        if r.error.is_none() && r.work_units != p.expected_units(r.probe) {
            return Err(VerifyError::WorkMismatch(format!(
                "{:?} rep {} did {} units; the protocol fixes {}",
                r.probe,
                r.rep,
                r.work_units,
                p.expected_units(r.probe)
            )));
        }
    }
    let excluded: Vec<String> = raw
        .runs
        .iter()
        .filter_map(|r| {
            r.error
                .as_ref()
                .map(|e| format!("{:?} rep {} ({e})", r.probe, r.rep))
        })
        .collect();
    if excluded.len() as u32 > MAX_EXCLUDED_REPETITIONS {
        return Err(VerifyError::ExcludedRepetitions(format!(
            "{} repetition(s) marked error, protocol v1 allows {MAX_EXCLUDED_REPETITIONS}: {}",
            excluded.len(),
            excluded.join(", ")
        )));
    }
    Ok(excluded.len() as u32)
}

fn bound_inputs(probes: &[ProbeSummary]) -> Vec<BoundInput> {
    let max_of = |k: ProbeKind| {
        probes
            .iter()
            .find(|s| s.probe == k)
            .and_then(|s| s.rate_per_s.as_ref())
            .map(|s| s.max)
    };
    let mut out = Vec::new();
    let mut push =
        |name: &str, unit: &str, kind: BoundInputKind, probe: ProbeKind, value: Option<f64>| {
            if let Some(value) = value {
                out.push(BoundInput {
                    name: name.into(),
                    value,
                    unit: unit.into(),
                    probe,
                    statistic: BoundStatistic::MaxRate,
                    kind,
                });
            }
        };
    let hw = BoundInputKind::Achieved;
    let imp = BoundInputKind::ImplementationReference;
    for (name, unit, probe) in [
        ("memory_read_bandwidth", "B/s", ProbeKind::MemoryRead),
        (
            "memory_copy_bandwidth",
            "B/s (read plus written)",
            ProbeKind::MemoryCopy,
        ),
        (
            "device_write_bandwidth",
            "B/s (through fdatasync)",
            ProbeKind::DeviceWrite,
        ),
        ("device_read_bandwidth", "B/s", ProbeKind::DeviceRead),
    ] {
        push(name, unit, hw, probe, max_of(probe));
    }
    let sha = [ProbeKind::Sha256Sha2Crate, ProbeKind::Sha256ArmInstructions]
        .into_iter()
        .filter_map(|k| max_of(k).map(|v| (k, v)))
        .max_by(|a, b| a.1.total_cmp(&b.1));
    if let Some((k, v)) = sha {
        push("sha256_all_core_throughput", "B/s", imp, k, Some(v));
    }
    push(
        "ed25519_verify_all_core_throughput",
        "verifications/s",
        imp,
        ProbeKind::Ed25519Verify,
        max_of(ProbeKind::Ed25519Verify),
    );
    out
}

/// Compute the report from the exact protocol and raw bytes. Checks that the raw data
/// names this protocol's digest and has exactly the repetitions and work it fixed.
pub fn compute_report(protocol_bytes: &[u8], raw_bytes: &[u8]) -> Result<Report, VerifyError> {
    let protocol = Protocol::parse(protocol_bytes).map_err(VerifyError::ProtocolInvalid)?;
    let raw: RawEvidence =
        serde_json::from_slice(raw_bytes).map_err(|e| VerifyError::Parse(format!("raw: {e}")))?;
    if raw.schema != RAW_SCHEMA {
        return Err(VerifyError::Parse(format!("raw schema {:?}", raw.schema)));
    }
    let protocol_sha256 = sha256_hex(protocol_bytes);
    if raw.protocol_sha256 != protocol_sha256 {
        return Err(VerifyError::ProtocolDigestMismatch {
            protocol: protocol_sha256,
            raw_names: raw.protocol_sha256,
        });
    }
    let excluded_repetitions = check_runs(&protocol, &raw)?;
    let idle_w = |rep: u32| {
        raw.runs
            .iter()
            .find(|r| r.probe == ProbeKind::Idle && r.rep == rep && r.error.is_none())
            .and_then(|r| energy_figures(&r.energy, 0, None).pkg_mean_w)
    };
    let probes: Vec<ProbeSummary> = PROBE_ORDER
        .iter()
        .map(|&probe| {
            let mut runs: Vec<&RawRun> = raw.runs.iter().filter(|r| r.probe == probe).collect();
            runs.sort_by_key(|r| r.rep);
            let reps: Vec<RepFigures> = runs
                .iter()
                .map(|r| {
                    let ok = r.error.is_none();
                    let elapsed_s = r.elapsed_ns as f64 / 1e9;
                    RepFigures {
                        rep: r.rep,
                        work_units: r.work_units,
                        elapsed_s,
                        rate_per_s: (ok && r.work_units > 0 && r.elapsed_ns > 0)
                            .then(|| r.work_units as f64 * 1e9 / r.elapsed_ns as f64),
                        error: r.error.clone(),
                        energy: if ok {
                            energy_figures(&r.energy, r.work_units, idle_w(r.rep))
                        } else {
                            EnergyFigures {
                                refusal: Some("probe failed".into()),
                                ..Default::default()
                            }
                        },
                    }
                })
                .collect();
            let col = |f: fn(&RepFigures) -> Option<f64>| {
                stat(&reps.iter().filter_map(f).collect::<Vec<_>>())
            };
            ProbeSummary {
                probe,
                unit: probe.unit().into(),
                description: probe.description().into(),
                threads: protocol.expected_threads(probe),
                errors: reps.iter().filter(|r| r.error.is_some()).count() as u32,
                valid_energy_reps: reps.iter().filter(|r| r.energy.valid).count() as u32,
                rate_per_s: col(|r| r.rate_per_s),
                pkg_mean_w: col(|r| r.energy.pkg_mean_w),
                pkg_j_per_unit: col(|r| r.energy.pkg_j_per_unit),
                pkg_j_per_unit_above_idle: col(|r| r.energy.pkg_j_per_unit_above_idle),
                reps,
            }
        })
        .collect();
    Ok(Report {
        schema: REPORT_SCHEMA.into(),
        protocol_sha256,
        raw_sha256: sha256_hex(raw_bytes),
        source_rev: raw.source_rev,
        repetitions: protocol.repetitions,
        central_statistic: protocol.central_statistic,
        spread_statistic: protocol.spread_statistic,
        bound_statistic: protocol.bound_statistic,
        excluded_repetitions,
        instruments: raw.instruments,
        w1_flush: raw.w1_flush,
        bound_inputs: bound_inputs(&probes),
        probes,
    })
}

/// `SHA256SUMS` text in the `sha256sum` format over `names` in `dir`.
pub fn sha256sums(dir: &Path, names: &[&str]) -> std::io::Result<String> {
    let mut out = String::new();
    for name in names {
        out.push_str(&format!(
            "{}  {name}\n",
            sha256_hex(&fs::read(dir.join(name))?)
        ));
    }
    Ok(out)
}

/// Checks every file `SHA256SUMS` lists against its digest, and requires the three
/// sealed files to be listed.
fn verify_sums(dir: &Path) -> Result<(), VerifyError> {
    let text = fs::read_to_string(dir.join(SUMS_FILE))
        .map_err(|e| VerifyError::ChecksumsMissing(format!("read {SUMS_FILE}: {e}")))?;
    let mut listed = Vec::new();
    for (i, line) in text.lines().enumerate() {
        let (digest, name) = line
            .split_once("  ")
            .filter(|(d, n)| d.len() == 64 && !n.is_empty())
            .ok_or_else(|| VerifyError::Parse(format!("{SUMS_FILE} line {}: {line:?}", i + 1)))?;
        let bytes = fs::read(dir.join(name)).map_err(|e| {
            VerifyError::ChecksumMismatch(format!("{name} listed but unreadable: {e}"))
        })?;
        let actual = sha256_hex(&bytes);
        if actual != digest {
            return Err(VerifyError::ChecksumMismatch(format!(
                "{name} is {actual}, {SUMS_FILE} lists {digest}"
            )));
        }
        listed.push(name);
    }
    let missing: Vec<&str> = [PROTOCOL_FILE, RAW_FILE, REPORT_FILE]
        .into_iter()
        .filter(|n| !listed.contains(n))
        .collect();
    if !missing.is_empty() {
        return Err(VerifyError::ChecksumsMissing(format!(
            "{SUMS_FILE} does not list {}",
            missing.join(", ")
        )));
    }
    Ok(())
}

/// Recompute `report.json` from `protocol.json` and `raw.json` in `dir`, require the
/// result to match byte for byte, then check every file `SHA256SUMS` lists.
///
/// This proves consistency (the report is what the raw data implies) and that the
/// files are the ones that were checksummed. It does not prove authenticity: anyone
/// can edit `raw.json` and regenerate both files. Authenticity comes from the git
/// history and review of the commit that sealed them.
pub fn verify_evidence(dir: &Path) -> Result<Report, VerifyError> {
    let read = |name: &str| {
        fs::read(dir.join(name)).map_err(|e| VerifyError::Io(format!("read {name}: {e}")))
    };
    let (protocol, raw, sealed) = (read(PROTOCOL_FILE)?, read(RAW_FILE)?, read(REPORT_FILE)?);
    let report = compute_report(&protocol, &raw)?;
    let again = serde_json::to_vec_pretty(&report)
        .map_err(|e| VerifyError::Parse(format!("serialize report: {e}")))?;
    if again != sealed {
        let first_difference_at = again
            .iter()
            .zip(&sealed)
            .position(|(a, b)| a != b)
            .unwrap_or(again.len().min(sealed.len()));
        return Err(VerifyError::ReportMismatch {
            first_difference_at,
        });
    }
    verify_sums(dir)?;
    Ok(report)
}

#[cfg(test)]
mod tests;
