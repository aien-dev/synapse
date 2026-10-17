//! ADR 0003 A2 measurement: seconds and joules per accepted change of the segment store,
//! against the section 6.2 flush bound.
//!
//! Each cell opens a fresh store with `FsyncPolicy::GROUP_COMMIT_DEFAULT` through
//! [`SharedStore`], starts `agents` threads that submit signed one-file changesets of
//! `blob_bytes` each, and records every change's time from `submit` to durable
//! acknowledgement. Small segments make the run rotate (new segment file, pre-write,
//! directory flush) inside the timed window, and a checkpoint runs every
//! `checkpoint_every` accepted changes (blobs stay in the segments). The whole cell is one
//! energy window of the `aien_spbm` package meter; a missing meter leaves joules `None`
//! with the reason (`INSTRUMENT_UNAVAILABLE`), never a substitute.
//!
//! Bounds (fraction of bound reached = bound / measured, at most 1):
//! * latency of one change: one flush plus the change's bytes moved once at memory
//!   bandwidth;
//! * steady-state interval per accepted change: the largest of flush / agents (all
//!   agents' changes sharing one flush), bytes / device write bandwidth, bytes / memory
//!   bandwidth, and the change's SHA-256 plus one Ed25519 verification at all-core rates;
//! * package joules per change: the idle package power for the interval bound (the
//!   package draws at least that while the work runs). A floor model, not physics; NVMe
//!   energy is UNMEASURED on this host.
//!
//! The flush time is the cheapest `overwrite_*_fdatasync` p50 of a `floor.json` measured
//! on the same filesystem (`synapse-bench floor`).

use crate::energy::{idle_window, EnergyReading, EnergyWindow};
use crate::floor::FloorReport;
use crate::stats::{summarize_us, LatencySummary};
use ed25519_dalek::SigningKey;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Barrier, Mutex};
use std::time::{Duration, Instant};
use synapse_core::{
    BlobDigest, ChangesetEnvelope, FileMode, GitOid, IdempotencyKey, MutationOp, PathMutation,
    RepoId, SYNAPSE_ENVELOPE_VERSION,
};
use synapse_core::{RefusalCode, SynapseError};
use synapse_store::blockdev::BlockDevice;
use synapse_store::{
    BlockDeviceConfig, FormatPolicy, FsyncPolicy, IngestOutcome, RecoveryPolicy, SharedStore,
    StoreLimits,
};

/// Memory bandwidth, bytes per second: NVIDIA DGX Spark specification, 273 GB/s (A0).
pub const MEMORY_BW_BPS: f64 = 273e9;
/// Device write bandwidth bound, bytes per second: the drive's PCIe link (A0).
pub const DEVICE_BW_BPS: f64 = 15.754e9;
/// All-core SHA-256 implementation reference, bytes per second (J3).
pub const SHA256_ALLCORE_BPS: f64 = 39.46e9;
/// All-core Ed25519 verification implementation reference, per second (J3).
pub const ED25519_ALLCORE_PER_S: f64 = 397_560.0;

/// Run configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SegmentsConfig {
    pub agents: Vec<usize>,
    pub changes: usize,
    pub reps: usize,
    pub blob_bytes: usize,
    pub segment_bytes: u64,
    pub checkpoint_every: usize,
    pub idle_window_s: u64,
    /// R1 (issue #47): run every cell on a raw block store device at this absolute path
    /// instead of a store directory. The path must not exist: for each cell the bench
    /// creates a regular file there (preallocated, `block_device_bytes`), formats it,
    /// and removes it afterwards. It never writes to a file it did not create.
    #[serde(default)]
    pub block_device: Option<String>,
    /// Size of that device file.
    #[serde(default = "default_block_device_bytes")]
    pub block_device_bytes: u64,
    /// Metadata region size of that device.
    #[serde(default = "default_block_meta_bytes")]
    pub block_meta_bytes: u64,
}

/// One measured cell (raw samples).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CellRaw {
    pub agents: usize,
    pub rep: usize,
    pub accepted: usize,
    /// Wall time of the cell from the barrier release to the last acknowledgement.
    pub elapsed_ns: u64,
    /// Every accepted change's time from `submit` to durable acknowledgement.
    pub latency_ns: Vec<u64>,
    /// Duration of every checkpoint run during the cell.
    pub checkpoint_ns: Vec<u64>,
    pub batches: u64,
    pub segment_files: usize,
    pub blob_files: usize,
    pub energy: EnergyReading,
}

/// Figures of one cell against the bound.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CellReport {
    pub agents: usize,
    pub rep: usize,
    pub latency: Option<LatencySummary>,
    pub interval_s: f64,
    pub interval_bound_s: f64,
    pub interval_fraction: f64,
    pub latency_p50_s: f64,
    pub latency_bound_s: f64,
    pub latency_fraction: f64,
    pub mean_batch: f64,
    pub pkg_j_per_change: Option<f64>,
    pub pkg_j_per_change_above_idle: Option<f64>,
    pub pkg_mean_w: Option<f64>,
    pub energy_bound_j: Option<f64>,
    pub energy_fraction: Option<f64>,
    pub energy_refusal: Option<String>,
}

/// Bound inputs used for the report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BoundInputs {
    pub flush_s: f64,
    pub flush_probe: String,
    pub blob_bytes: usize,
    pub memory_bw_bps: f64,
    pub device_bw_bps: f64,
    pub sha256_allcore_bps: f64,
    pub ed25519_allcore_per_s: f64,
    pub idle_pkg_w: Option<f64>,
}

/// Raw output of a run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SegmentsRaw {
    pub config: SegmentsConfig,
    pub store_dir: String,
    pub idle: EnergyReading,
    pub cells: Vec<CellRaw>,
}

/// Flush time: the cheapest overwrite-plus-`fdatasync` p50 in the floor report.
pub fn flush_from_floor(floor: &FloorReport) -> Result<(f64, String), String> {
    floor
        .storage
        .iter()
        .filter(|p| p.name.starts_with("overwrite_") && p.name.ends_with("_fdatasync"))
        .filter_map(|p| p.latency.as_ref().map(|l| (l.p50_ms / 1e3, p.name.clone())))
        .min_by(|a, b| a.0.total_cmp(&b.0))
        .ok_or_else(|| "floor report has no overwrite_*_fdatasync probe".to_string())
}

/// Interval bound per accepted change at `agents` concurrent agents.
pub fn interval_bound_s(b: &BoundInputs, agents: usize) -> f64 {
    let bytes = b.blob_bytes as f64;
    let crypto = bytes / b.sha256_allcore_bps + 1.0 / b.ed25519_allcore_per_s;
    (b.flush_s / agents.max(1) as f64)
        .max(bytes / b.device_bw_bps)
        .max(bytes / b.memory_bw_bps)
        .max(crypto)
}

/// Latency bound of one change: one flush plus its bytes moved once at memory bandwidth.
pub fn latency_bound_s(b: &BoundInputs) -> f64 {
    b.flush_s + b.blob_bytes as f64 / b.memory_bw_bps
}

/// Compute the report of one cell (pure function of the raw cell and bound inputs).
pub fn cell_report(c: &CellRaw, b: &BoundInputs, idle: &EnergyReading) -> CellReport {
    let n = c.accepted.max(1) as f64;
    let interval_s = c.elapsed_ns as f64 / 1e9 / n;
    let us: Vec<u64> = c.latency_ns.iter().map(|v| v / 1000).collect();
    let latency = summarize_us(&us);
    let mut sorted = c.latency_ns.clone();
    sorted.sort_unstable();
    let p50_ns = crate::stats::nearest_rank(&sorted, 0.5).unwrap_or(0);
    let latency_p50_s = p50_ns as f64 / 1e9;
    let interval_bound = interval_bound_s(b, c.agents);
    let latency_bound = latency_bound_s(b);
    let pkg_j_per_change = c.energy.pkg_j.map(|j| j / n);
    let energy_bound_j = b.idle_pkg_w.map(|w| w * interval_bound);
    CellReport {
        agents: c.agents,
        rep: c.rep,
        latency,
        interval_s,
        interval_bound_s: interval_bound,
        interval_fraction: interval_bound / interval_s,
        latency_p50_s,
        latency_bound_s: latency_bound,
        latency_fraction: if latency_p50_s > 0.0 {
            latency_bound / latency_p50_s
        } else {
            0.0
        },
        mean_batch: c.accepted as f64 / c.batches.max(1) as f64,
        pkg_j_per_change,
        pkg_j_per_change_above_idle: c.energy.pkg_above_idle_j(idle).map(|j| j / n),
        pkg_mean_w: c.energy.pkg_mean_w,
        energy_bound_j,
        energy_fraction: match (energy_bound_j, pkg_j_per_change) {
            (Some(bound), Some(m)) if m > 0.0 => Some(bound / m),
            _ => None,
        },
        energy_refusal: c.energy.refusal.clone().or_else(|| {
            c.energy
                .pkg_j
                .is_none()
                .then(|| format!("INSTRUMENT_UNAVAILABLE: {}", c.energy.sensor))
        }),
    }
}

fn changeset(
    key: &SigningKey,
    label: &str,
    blob_bytes: usize,
) -> (ChangesetEnvelope, Vec<(BlobDigest, Vec<u8>)>) {
    let mut content = format!("// {label}\n").into_bytes();
    let mut x: u32 = label.bytes().fold(2_166_136_261u32, |a, b| {
        (a ^ u32::from(b)).wrapping_mul(16_777_619)
    });
    while content.len() < blob_bytes {
        x ^= x << 13;
        x ^= x >> 17;
        x ^= x << 5;
        content.push(b"abcdefghijklmnopqrstuvwxyz \n(){};"[(x % 33) as usize]);
    }
    let digest = BlobDigest::compute(&content);
    let path = format!("src/{label}.rs");
    let mut env = ChangesetEnvelope {
        version: SYNAPSE_ENVELOPE_VERSION,
        repo_id: RepoId::new("aien-spark/synapse").expect("repo id"),
        base_git_oid: GitOid::compute_blob(b"base"),
        parent_changesets: vec![],
        author_did: String::new(),
        idempotency_key: IdempotencyKey::from_label(label),
        created_at_ms: 1000,
        intent_summary: format!("Update {path}"),
        mutations: vec![PathMutation {
            path,
            op: MutationOp::Upsert {
                mode: FileMode::Regular644,
                blob_digest: digest,
                size_bytes: content.len() as u64,
            },
        }],
        evidence_receipts: vec![],
        signature: vec![],
    };
    env.sign(key);
    (env, vec![(digest, content)])
}

fn count_files(dir: &Path, pred: &dyn Fn(&str) -> bool) -> usize {
    let Ok(rd) = std::fs::read_dir(dir) else {
        return 0;
    };
    rd.filter_map(Result::ok)
        .map(|e| {
            if e.file_type().map(|t| t.is_dir()).unwrap_or(false) {
                count_files(&e.path(), pred)
            } else {
                usize::from(pred(&e.file_name().to_string_lossy()))
            }
        })
        .sum()
}

/// Default size of the device file the bench creates for each R1 cell.
pub const DEFAULT_BLOCK_DEVICE_BYTES: u64 = 512 << 20;
/// Default metadata region size of that device.
pub const DEFAULT_BLOCK_META_BYTES: u64 = 64 << 20;

fn default_block_device_bytes() -> u64 {
    DEFAULT_BLOCK_DEVICE_BYTES
}

fn default_block_meta_bytes() -> u64 {
    DEFAULT_BLOCK_META_BYTES
}

/// The R1 device of one cell: a regular file the bench creates itself at the configured
/// path, preallocated with zeros, and removes after the cell. The bench formats only
/// a file it created: an existing path (a file, a symbolic link, anything) is refused
/// before a byte is written, and it never opens a block device.
struct BenchDevice {
    path: PathBuf,
    dev: u64,
    ino: u64,
}

impl BenchDevice {
    fn create(path: &str, bytes: u64) -> Result<Self, String> {
        use std::os::unix::fs::{FileExt, MetadataExt, OpenOptionsExt};
        let p = PathBuf::from(path);
        if !p.is_absolute() {
            return Err(format!("--block-device {path}: must be an absolute path"));
        }
        if bytes == 0 || !bytes.is_multiple_of(4096) {
            return Err(format!(
                "block device size {bytes} is not a positive multiple of 4096"
            ));
        }
        // create_new (O_CREAT | O_EXCL) fails on any existing path, a dangling symbolic
        // link included; O_NOFOLLOW as well.
        let f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&p)
            .map_err(|e| match e.kind() {
                std::io::ErrorKind::AlreadyExists => format!(
                    "--block-device {path}: refusing, it already exists; the bench formats \
                     only a device file it creates itself (name a path that does not exist)"
                ),
                _ => format!("create {path}: {e}"),
            })?;
        let m = f.metadata().map_err(|e| format!("stat {path}: {e}"))?;
        let device = Self {
            path: p,
            dev: m.dev(),
            ino: m.ino(),
        };
        // Preallocate: every block written once (no sparse holes), then synced.
        let zeros = vec![0u8; 1 << 20];
        let mut at = 0u64;
        while at < bytes {
            let n = (bytes - at).min(zeros.len() as u64) as usize;
            f.write_all_at(&zeros[..n], at)
                .map_err(|e| format!("preallocate {path}: {e}"))?;
            at += n as u64;
        }
        f.sync_all().map_err(|e| format!("sync {path}: {e}"))?;
        Ok(device)
    }
}

impl Drop for BenchDevice {
    /// Remove the device file, only if the path still is the file this bench created.
    fn drop(&mut self) {
        use std::os::unix::fs::MetadataExt;
        if let Ok(m) = std::fs::symlink_metadata(&self.path) {
            if m.file_type().is_file() && m.dev() == self.dev && m.ino() == self.ino {
                let _ = std::fs::remove_file(&self.path);
            }
        }
    }
}

fn run_cell(
    dir: &Path,
    cfg: &SegmentsConfig,
    agents: usize,
    rep: usize,
) -> Result<CellRaw, String> {
    let _ = std::fs::remove_dir_all(dir);
    std::fs::create_dir_all(dir).map_err(|e| format!("create {}: {e}", dir.display()))?;
    let limits = StoreLimits {
        segment_bytes: cfg.segment_bytes,
        ..Default::default()
    };
    let device = match cfg.block_device.as_deref() {
        Some(p) => Some(BenchDevice::create(p, cfg.block_device_bytes)?),
        None => None,
    };
    let block = device.as_ref().map(|d| BlockDeviceConfig {
        path: d.path.clone(),
        format: FormatPolicy::FormatIfBlank,
        meta_region_bytes: cfg.block_meta_bytes,
        allow_foreign_signature: false,
    });
    let shared = match &block {
        Some(bc) => SharedStore::open_block_device(
            bc,
            FsyncPolicy::GROUP_COMMIT_DEFAULT,
            RecoveryPolicy::StrictFailClosed,
            limits,
        ),
        None => SharedStore::open(
            dir,
            FsyncPolicy::GROUP_COMMIT_DEFAULT,
            RecoveryPolicy::StrictFailClosed,
            limits,
        ),
    }
    .map_err(|e| format!("open store: {e:?}"))?;
    // Prepare every agent's changesets before timing (signing is the agent's own work).
    let per_agent = cfg.changes.div_ceil(agents);
    let work: Vec<Vec<_>> = (0..agents)
        .map(|a| {
            let key = SigningKey::from_bytes(&[(a as u8).wrapping_add(1); 32]);
            (0..per_agent)
                .map(|i| changeset(&key, &format!("a{a}-r{rep}-c{i}"), cfg.blob_bytes))
                .collect()
        })
        .collect();
    let accepted = AtomicUsize::new(0);
    // Agents that finished every submission and any checkpoint they triggered.
    let agents_done = AtomicUsize::new(0);
    let latencies = Mutex::new(Vec::with_capacity(cfg.changes));
    let checkpoints = Mutex::new(Vec::new());
    let errors = Mutex::new(Vec::<String>::new());
    let barrier = Barrier::new(agents + 1);
    let batches_before = shared.stats().batches;
    let (elapsed, energy) = std::thread::scope(|s| {
        for w in &work {
            let (shared, accepted, agents_done, latencies, checkpoints, errors, barrier) = (
                &shared,
                &accepted,
                &agents_done,
                &latencies,
                &checkpoints,
                &errors,
                &barrier,
            );
            s.spawn(move || {
                barrier.wait();
                for (env, blobs) in w {
                    let t = Instant::now();
                    match shared.submit(env.clone(), blobs) {
                        Ok(IngestOutcome::Committed { .. }) => {
                            let ns = t.elapsed().as_nanos() as u64;
                            latencies.lock().unwrap().push(ns);
                            let n = accepted.fetch_add(1, Ordering::SeqCst) + 1;
                            if cfg.checkpoint_every > 0 && n % cfg.checkpoint_every == 0 {
                                let t = Instant::now();
                                match shared.with_exclusive(|st| st.checkpoint_and_compact(1000)) {
                                    Ok(_) => checkpoints
                                        .lock()
                                        .unwrap()
                                        .push(t.elapsed().as_nanos() as u64),
                                    Err(e) => {
                                        errors.lock().unwrap().push(format!("checkpoint: {e:?}"))
                                    }
                                }
                            }
                        }
                        Ok(other) => errors
                            .lock()
                            .unwrap()
                            .push(format!("not committed: {other:?}")),
                        Err(e) => errors.lock().unwrap().push(format!("submit: {e:?}")),
                    }
                }
                agents_done.fetch_add(1, Ordering::SeqCst);
            });
        }
        let window = EnergyWindow::start();
        let t0 = Instant::now();
        barrier.wait();
        // The scope joins the agents when this closure returns; time them here instead,
        // up to the end of the last checkpoint an agent ran.
        while agents_done.load(Ordering::SeqCst) < agents {
            std::thread::sleep(Duration::from_micros(200));
        }
        (t0.elapsed(), window.finish())
    });
    let errors = errors.into_inner().unwrap();
    if !errors.is_empty() {
        return Err(format!(
            "{} failed submissions, first: {}",
            errors.len(),
            errors[0]
        ));
    }
    let batches = shared.stats().batches - batches_before;
    drop(shared);
    let segment_files = match &block {
        Some(bc) => {
            let cfg = BlockDeviceConfig {
                format: FormatPolicy::OpenExisting,
                ..bc.clone()
            };
            BlockDevice::open_path(&cfg, 0)
                .and_then(|d| {
                    d.list_segments()
                        .map_err(|e| SynapseError::new(RefusalCode::IoFailure, e.to_string()))
                })
                .map_err(|e| format!("reopen device: {e:?}"))?
                .len()
        }
        None => count_files(dir, &|n| {
            synapse_store::segment::parse_segment_file_name(n).is_some()
        }),
    };
    let blob_files = count_files(&dir.join("blobs"), &|_| true);
    Ok(CellRaw {
        agents,
        rep,
        accepted: accepted.into_inner(),
        elapsed_ns: elapsed.as_nanos() as u64,
        latency_ns: latencies.into_inner().unwrap(),
        checkpoint_ns: checkpoints.into_inner().unwrap(),
        batches,
        segment_files,
        blob_files,
        energy,
    })
}

/// Run every cell (agents x reps, agent counts interleaved inside each repetition).
pub fn run_segments(store_dir: &Path, cfg: &SegmentsConfig) -> Result<SegmentsRaw, String> {
    let idle = idle_window(Duration::from_secs(cfg.idle_window_s));
    let mut cells = Vec::new();
    for rep in 0..cfg.reps {
        for &agents in &cfg.agents {
            let dir: PathBuf = store_dir.join(format!("cell-{agents}-{rep}"));
            let cell = run_cell(&dir, cfg, agents, rep)?;
            let _ = std::fs::remove_dir_all(&dir);
            eprintln!(
                "agents {agents} rep {rep}: {} accepted in {:.3} s, {} batches, {} segment files",
                cell.accepted,
                cell.elapsed_ns as f64 / 1e9,
                cell.batches,
                cell.segment_files
            );
            cells.push(cell);
        }
    }
    Ok(SegmentsRaw {
        config: cfg.clone(),
        store_dir: store_dir.display().to_string(),
        idle,
        cells,
    })
}

/// Report of a run: bound inputs and every cell's figures.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SegmentsReport {
    pub bounds: BoundInputs,
    pub cells: Vec<CellReport>,
}

/// Recompute the report from the raw run and the floor report.
pub fn segments_report(raw: &SegmentsRaw, floor: &FloorReport) -> Result<SegmentsReport, String> {
    let (flush_s, flush_probe) = flush_from_floor(floor)?;
    let bounds = BoundInputs {
        flush_s,
        flush_probe,
        blob_bytes: raw.config.blob_bytes,
        memory_bw_bps: MEMORY_BW_BPS,
        device_bw_bps: DEVICE_BW_BPS,
        sha256_allcore_bps: SHA256_ALLCORE_BPS,
        ed25519_allcore_per_s: ED25519_ALLCORE_PER_S,
        idle_pkg_w: raw.idle.pkg_mean_w,
    };
    let cells = raw
        .cells
        .iter()
        .map(|c| cell_report(c, &bounds, &raw.idle))
        .collect();
    Ok(SegmentsReport { bounds, cells })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn inputs() -> BoundInputs {
        BoundInputs {
            flush_s: 0.0008,
            flush_probe: "overwrite_1m_fdatasync".into(),
            blob_bytes: 11_949,
            memory_bw_bps: MEMORY_BW_BPS,
            device_bw_bps: DEVICE_BW_BPS,
            sha256_allcore_bps: SHA256_ALLCORE_BPS,
            ed25519_allcore_per_s: ED25519_ALLCORE_PER_S,
            idle_pkg_w: Some(20.0),
        }
    }

    /// B1 (review of PR #103): `--block-device` never writes to a file the bench did not
    /// create itself, and never follows a symbolic link to one.
    #[test]
    fn block_device_bench_never_writes_to_a_file_it_did_not_create() {
        let dir = crate::fixture::test_support::temp_dir("r1-bench-victim");
        let victim = dir.join("victim.img");
        let mut bytes: Vec<u8> = (0..4u32 << 20).map(|i| (i % 251) as u8).collect();
        bytes[1080..1082].copy_from_slice(&[0x53, 0xEF]);
        std::fs::write(&victim, &bytes).unwrap();
        let link = dir.join("link.img");
        std::os::unix::fs::symlink(&victim, &link).unwrap();
        for target in [&victim, &link] {
            let cfg = SegmentsConfig {
                agents: vec![1],
                changes: 4,
                reps: 1,
                blob_bytes: 64,
                segment_bytes: 1 << 20,
                checkpoint_every: 2,
                idle_window_s: 0,
                block_device: Some(target.display().to_string()),
                block_device_bytes: 8 << 20,
                block_meta_bytes: 1 << 20,
            };
            assert!(
                run_cell(&dir.join("store"), &cfg, 1, 0).is_err(),
                "{}",
                target.display()
            );
            assert_eq!(
                std::fs::read(&victim).unwrap(),
                bytes,
                "{}: victim changed",
                target.display()
            );
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The bench creates its own device file for a cell, formats it, and removes it.
    #[test]
    fn block_device_bench_creates_formats_and_removes_its_own_device() {
        let dir = crate::fixture::test_support::temp_dir("r1-bench-own");
        let path = dir.join("device.img");
        let cfg = SegmentsConfig {
            agents: vec![2],
            changes: 6,
            reps: 1,
            blob_bytes: 64,
            segment_bytes: 1 << 20,
            checkpoint_every: 3,
            idle_window_s: 0,
            block_device: Some(path.display().to_string()),
            block_device_bytes: 8 << 20,
            block_meta_bytes: 1 << 20,
        };
        let cell = run_cell(&dir.join("store"), &cfg, 2, 0).unwrap();
        assert_eq!(cell.accepted, 6);
        assert_eq!(cell.segment_files, 1);
        assert!(
            !path.exists(),
            "the bench removes the device file it created"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn interval_bound_is_flush_shared_by_agents_until_crypto_dominates() {
        let b = inputs();
        assert_eq!(interval_bound_s(&b, 1), 0.0008);
        assert_eq!(interval_bound_s(&b, 8), 0.0001);
        // 1000 agents: the flush share (0.8 us) is below one change's crypto (2.82 us).
        let crypto = 11_949.0 / SHA256_ALLCORE_BPS + 1.0 / ED25519_ALLCORE_PER_S;
        assert_eq!(interval_bound_s(&b, 1000), crypto);
        assert!(latency_bound_s(&b) > 0.0008);
    }

    #[test]
    fn fractions_are_bound_over_measured_and_refused_energy_stays_none() {
        let b = inputs();
        let cell = CellRaw {
            agents: 1,
            rep: 0,
            accepted: 4,
            elapsed_ns: 8_000_000,
            latency_ns: vec![1_600_000; 4],
            checkpoint_ns: vec![],
            batches: 4,
            segment_files: 1,
            blob_files: 0,
            energy: EnergyReading {
                refusal: Some("INSTRUMENT_UNAVAILABLE: no aien_spbm device".into()),
                ..Default::default()
            },
        };
        let r = cell_report(&cell, &b, &EnergyReading::default());
        assert_eq!(r.interval_s, 0.002);
        assert!((r.interval_fraction - 0.4).abs() < 1e-12);
        assert!(r.pkg_j_per_change.is_none() && r.energy_fraction.is_none());
        assert!(r
            .energy_refusal
            .unwrap()
            .starts_with("INSTRUMENT_UNAVAILABLE"));
    }
}
