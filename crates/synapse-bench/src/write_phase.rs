//! Write-phase measurement cell: `agents` concurrent agents each submit their proposals
//! through one arm, starting together on a `std::sync::Barrier`.
//!
//! Per-operation latency starts when the agent begins submitting an already generated
//! proposal and ends when the arm acknowledges it:
//! * Synapse arms: envelope and request signing, JSON encode, JSON decode, waiting for
//!   the single-writer service lock (queue wait, also recorded separately), and `submit`.
//! * Git arms: every file write and `git` process for that proposal.
//!
//! Throughput is acknowledged operations divided by the wall time from barrier release
//! to the last acknowledgement (for S2 this includes one final `sync_wal`).

use crate::fixture::{self, BaseTree, EditableFile};
use crate::git_arm::{self, PlumbingAgent, FSYNC_ALL_CONFIG};
use crate::rusage::{CpuUsage, RusageWindow};
use crate::stats::{round3, summarize_us, LatencySummary};
use crate::synapse_arm::{self, AgentIdentity};
use crate::workload::{generate_write_workload, Proposal};
use crate::write_jsonl;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::sync::{Barrier, Mutex};
use std::time::Instant;
use synapse_api::{SubmitChangesetPayload, SynapseService};
use synapse_auth::AuthenticatedRequest;
use synapse_core::{GitOid, RepoId};
use synapse_store::{DurabilityGuarantee, FsyncPolicy, IngestOutcome, RecoveryPolicy};

/// Measured arm.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum ArmKind {
    S1,
    S2,
    G1,
    G2,
    G3,
    G3F,
}

impl ArmKind {
    pub const ALL: [ArmKind; 6] = [
        ArmKind::S1,
        ArmKind::S2,
        ArmKind::G1,
        ArmKind::G2,
        ArmKind::G3,
        ArmKind::G3F,
    ];

    pub fn code(self) -> &'static str {
        match self {
            Self::S1 => "S1",
            Self::S2 => "S2",
            Self::G1 => "G1",
            Self::G2 => "G2",
            Self::G3 => "G3",
            Self::G3F => "G3F",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|a| a.code().eq_ignore_ascii_case(s))
    }

    pub fn is_synapse(self) -> bool {
        matches!(self, Self::S1 | Self::S2)
    }

    pub fn description(self) -> &'static str {
        match self {
            Self::S1 => "Synapse submit, FsyncPolicy::EveryCommit (blob files, shard dirs, and WAL fsynced before ack)",
            Self::S2 => "Synapse submit, FsyncPolicy::BatchWindow (WAL fsync every N records, blobs never fsynced; final sync_wal inside timing)",
            Self::G1 => "Git: fresh `git worktree add -b` checkout per proposal, then add + commit (today's hive practice)",
            Self::G2 => "Git: one persistent worktree per agent; `checkout -B` to base, edit, add, commit per proposal",
            Self::G3 => "Git plumbing without checkout: per-agent temporary index, hash-object, update-index, write-tree, commit-tree, update-ref",
            Self::G3F => "G3 with `-c core.fsync=all -c core.fsyncMethod=fsync` on every git command",
        }
    }

    pub fn durability(self) -> &'static str {
        match self {
            Self::S1 => "fsync before ack (blobs, shard directories, WAL)",
            Self::S2 => "process-crash durable only (page cache) between WAL syncs",
            Self::G1 | Self::G2 | Self::G3 => {
                "git default core.fsync (git-config(1): committed,-loose-object), loose objects and refs not fsynced"
            }
            Self::G3F => "core.fsync=all, core.fsyncMethod=fsync (objects, index, refs fsynced)",
        }
    }
}

/// Input for one write cell (serialized to the child process).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WriteCellSpec {
    pub arm: ArmKind,
    pub agents: usize,
    pub ops_per_agent: usize,
    pub rep: usize,
    pub seed: u64,
    pub clone_dir: PathBuf,
    pub base_commit: String,
    pub cell_dir: PathBuf,
    pub trace_path: PathBuf,
    pub batch_window_records: u32,
}

/// One timed operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpTrace {
    pub arm: String,
    pub agents: usize,
    pub rep: usize,
    pub agent: usize,
    pub index: usize,
    pub files: usize,
    pub content_bytes: u64,
    /// Start offset from barrier release, microseconds.
    pub start_us: u64,
    pub latency_us: u64,
    /// Synapse only: time spent waiting for the single-writer service lock.
    pub queue_wait_us: Option<u64>,
    /// Synapse only: JSON-encoded request size.
    pub wire_bytes: Option<u64>,
    /// Synapse only: durability class reported in the commit receipt.
    pub durability: Option<String>,
    pub ok: bool,
    pub error: Option<String>,
}

/// Setup cost (excluded from per-operation latency).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SetupSummary {
    pub description: String,
    pub units: usize,
    pub total_ms: f64,
    pub per_unit: Option<LatencySummary>,
}

/// `du` reading over the arm's directories.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize)]
pub struct StorageSample {
    pub apparent_bytes: u64,
    pub allocated_bytes: u64,
}

/// Storage growth attributable to the arm.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageDelta {
    pub measured_paths: Vec<String>,
    pub before_setup: StorageSample,
    pub after_setup: StorageSample,
    pub after_ops: StorageSample,
    pub setup_apparent_bytes: i64,
    pub ops_apparent_bytes: i64,
    pub ops_allocated_bytes: i64,
    pub total_apparent_bytes: i64,
    pub total_allocated_bytes: i64,
    pub ops_apparent_bytes_per_op: f64,
    pub ops_allocated_bytes_per_op: f64,
}

/// Result of one write cell.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WriteCellResult {
    pub arm: ArmKind,
    pub agents: usize,
    pub ops_per_agent: usize,
    pub rep: usize,
    pub ops_attempted: usize,
    pub ops_ok: usize,
    pub ops_failed: usize,
    pub wall_ms: f64,
    pub throughput_ops_per_s: f64,
    pub latency: Option<LatencySummary>,
    pub queue_wait: Option<LatencySummary>,
    pub mean_wire_bytes: Option<f64>,
    pub mean_content_bytes: f64,
    pub setup: SetupSummary,
    pub final_sync_ms: Option<f64>,
    pub cpu: CpuUsage,
    pub cpu_ms_per_op: Option<f64>,
    pub storage: StorageDelta,
    pub durability_receipts: Vec<(String, usize)>,
    pub first_errors: Vec<String>,
}

/// `du -s -c` (apparent with `-b`, allocated with `-B1`) over `paths`; returns the total.
pub fn du_total(paths: &[PathBuf]) -> Result<StorageSample, String> {
    let existing: Vec<&PathBuf> = paths.iter().filter(|p| p.exists()).collect();
    if existing.is_empty() {
        return Ok(StorageSample::default());
    }
    let run = |flag: &str| -> Result<u64, String> {
        let mut cmd = std::process::Command::new("du");
        cmd.arg("-s").arg("-c").arg(flag);
        for p in &existing {
            cmd.arg(p);
        }
        let out = cmd.output().map_err(|e| format!("spawn du: {e}"))?;
        if !out.status.success() {
            return Err(format!(
                "du {flag} failed: {}",
                String::from_utf8_lossy(&out.stderr).trim()
            ));
        }
        let text = String::from_utf8_lossy(&out.stdout);
        let total_line = text
            .lines()
            .rev()
            .find(|l| l.trim_end().ends_with("total"))
            .ok_or("du output has no total line")?;
        total_line
            .split_whitespace()
            .next()
            .and_then(|v| v.parse().ok())
            .ok_or_else(|| format!("unparsable du total: {total_line}"))
    };
    Ok(StorageSample {
        apparent_bytes: run("-b")?,
        allocated_bytes: run("-B1")?,
    })
}

fn storage_delta(
    paths: &[PathBuf],
    before: StorageSample,
    after_setup: StorageSample,
    after_ops: StorageSample,
    ops_ok: usize,
) -> StorageDelta {
    let d = |a: u64, b: u64| a as i64 - b as i64;
    let ops_apparent = d(after_ops.apparent_bytes, after_setup.apparent_bytes);
    let ops_allocated = d(after_ops.allocated_bytes, after_setup.allocated_bytes);
    let per = |v: i64| {
        if ops_ok == 0 {
            0.0
        } else {
            round3(v as f64 / ops_ok as f64)
        }
    };
    StorageDelta {
        measured_paths: paths.iter().map(|p| p.display().to_string()).collect(),
        before_setup: before,
        after_setup,
        after_ops,
        setup_apparent_bytes: d(after_setup.apparent_bytes, before.apparent_bytes),
        ops_apparent_bytes: ops_apparent,
        ops_allocated_bytes: ops_allocated,
        total_apparent_bytes: d(after_ops.apparent_bytes, before.apparent_bytes),
        total_allocated_bytes: d(after_ops.allocated_bytes, before.allocated_bytes),
        ops_apparent_bytes_per_op: per(ops_apparent),
        ops_allocated_bytes_per_op: per(ops_allocated),
    }
}

fn durability_name(d: DurabilityGuarantee) -> &'static str {
    match d {
        DurabilityGuarantee::FsyncBeforeAck => "FsyncBeforeAck",
        DurabilityGuarantee::ProcessCrashPageCacheOnly => "ProcessCrashPageCacheOnly",
    }
}

fn base_trace(spec: &WriteCellSpec, p: &Proposal) -> OpTrace {
    OpTrace {
        arm: spec.arm.code().to_string(),
        agents: spec.agents,
        rep: spec.rep,
        agent: p.agent,
        index: p.index,
        files: p.edits.len(),
        content_bytes: p.content_bytes(),
        start_us: 0,
        latency_us: 0,
        queue_wait_us: None,
        wire_bytes: None,
        durability: None,
        ok: false,
        error: None,
    }
}

struct SynapseSubmitOk {
    queue_wait_us: u64,
    wire_bytes: usize,
    durability: Option<DurabilityGuarantee>,
}

/// One Synapse submit through the wire approximation and the shared service lock.
pub fn synapse_submit(
    service: &Mutex<SynapseService>,
    agent: &AgentIdentity,
    repo_id: &RepoId,
    base_oid: GitOid,
    p: &Proposal,
    label: &str,
) -> Result<(u64, usize, Option<DurabilityGuarantee>), String> {
    let now = crate::unix_now_ms();
    let req = synapse_arm::build_submit_request(agent, repo_id, base_oid, p, label, now)?;
    let (decoded, wire_bytes): (AuthenticatedRequest<SubmitChangesetPayload>, usize) =
        synapse_arm::wire_roundtrip(&req)?;
    let wait_start = Instant::now();
    let mut guard = service
        .lock()
        .map_err(|_| "synapse service mutex poisoned".to_string())?;
    let queue_wait_us = wait_start.elapsed().as_micros() as u64;
    let outcome = guard.submit(&decoded, now).map_err(|e| e.to_string())?;
    drop(guard);
    let durability = match outcome {
        IngestOutcome::Committed { durability, .. } => Some(durability),
        IngestOutcome::IdempotentDuplicate { .. } => None,
    };
    Ok((queue_wait_us, wire_bytes, durability))
}

#[allow(clippy::too_many_arguments)]
fn run_synapse_agent(
    spec: &WriteCellSpec,
    service: &Mutex<SynapseService>,
    agent: &AgentIdentity,
    repo_id: &RepoId,
    base_oid: GitOid,
    proposals: &[Proposal],
    barrier: &Barrier,
    epoch: Instant,
) -> Vec<OpTrace> {
    barrier.wait();
    let mut traces = Vec::with_capacity(proposals.len());
    for p in proposals {
        let mut t = base_trace(spec, p);
        let label = format!(
            "gate4/{}/r{}/n{}/a{}/p{}",
            spec.arm.code(),
            spec.rep,
            spec.agents,
            p.agent,
            p.index
        );
        let start = Instant::now();
        let res = synapse_submit(service, agent, repo_id, base_oid, p, &label).map(
            |(queue_wait_us, wire_bytes, durability)| SynapseSubmitOk {
                queue_wait_us,
                wire_bytes,
                durability,
            },
        );
        t.latency_us = start.elapsed().as_micros() as u64;
        t.start_us = start.duration_since(epoch).as_micros() as u64;
        match res {
            Ok(ok) => {
                t.ok = true;
                t.queue_wait_us = Some(ok.queue_wait_us);
                t.wire_bytes = Some(ok.wire_bytes as u64);
                t.durability = ok.durability.map(|d| durability_name(d).to_string());
            }
            Err(e) => t.error = Some(e),
        }
        traces.push(t);
    }
    traces
}

enum GitAgentState {
    G1 { wt_root: PathBuf },
    G2 { wt: PathBuf },
    G3 { plumbing: PlumbingAgent },
}

fn run_git_agent(
    spec: &WriteCellSpec,
    state: &GitAgentState,
    proposals: &[Proposal],
    barrier: &Barrier,
    epoch: Instant,
) -> Vec<OpTrace> {
    barrier.wait();
    let clone = spec.clone_dir.as_path();
    let base = spec.base_commit.as_str();
    let config: &[(&str, &str)] = if spec.arm == ArmKind::G3F {
        FSYNC_ALL_CONFIG
    } else {
        &[]
    };
    let mut traces = Vec::with_capacity(proposals.len());
    for p in proposals {
        let mut t = base_trace(spec, p);
        let start = Instant::now();
        let res = match state {
            GitAgentState::G1 { wt_root } => git_arm::g1_op(clone, base, wt_root, p).map(|_| ()),
            GitAgentState::G2 { wt } => git_arm::g2_op(wt, base, p),
            GitAgentState::G3 { plumbing } => {
                git_arm::g3_op(clone, base, plumbing, p, config).map(|_| ())
            }
        };
        t.latency_us = start.elapsed().as_micros() as u64;
        t.start_us = start.duration_since(epoch).as_micros() as u64;
        match res {
            Ok(()) => t.ok = true,
            Err(e) => t.error = Some(e),
        }
        traces.push(t);
    }
    traces
}

fn time_units<T>(
    n: usize,
    mut f: impl FnMut(usize) -> Result<T, String>,
) -> Result<(Vec<T>, Vec<u64>, f64), String> {
    let total = Instant::now();
    let mut out = Vec::with_capacity(n);
    let mut samples = Vec::with_capacity(n);
    for i in 0..n {
        let t = Instant::now();
        out.push(f(i)?);
        samples.push(t.elapsed().as_micros() as u64);
    }
    Ok((out, samples, round3(total.elapsed().as_secs_f64() * 1000.0)))
}

/// Run one write cell end to end (setup, timed phase, storage, traces, cleanup).
pub fn run_write_cell(spec: &WriteCellSpec) -> Result<WriteCellResult, String> {
    std::fs::create_dir_all(&spec.cell_dir)
        .map_err(|e| format!("mkdir {}: {e}", spec.cell_dir.display()))?;
    let clone = spec.clone_dir.as_path();
    let base: BaseTree = fixture::list_base_tree(clone, &spec.base_commit)?;

    // Proposal content needs only the editable files; Synapse also needs the full base
    // because `SynapseService` holds the base tree in memory.
    let (files, full_base): (Vec<EditableFile>, Option<Vec<_>>) = if spec.arm.is_synapse() {
        let full = fixture::load_full_base(clone, &base)?;
        (fixture::editable_from_full_base(&base, &full), Some(full))
    } else {
        (fixture::load_editable_files(clone, &base)?, None)
    };
    let workload =
        generate_write_workload(spec.seed, spec.rep, spec.agents, spec.ops_per_agent, &files);
    drop(files);

    let store_dir = spec.cell_dir.join("synapse-store");
    let wt_root = spec.cell_dir.join("worktrees");
    let plumbing_root = spec.cell_dir.join("plumbing");
    let measured: Vec<PathBuf> = if spec.arm.is_synapse() {
        vec![store_dir.clone()]
    } else {
        vec![clone.join(".git"), wt_root.clone(), plumbing_root.clone()]
    };
    let before = du_total(&measured)?;

    let barrier = Barrier::new(spec.agents + 1);
    let mut final_sync_ms = None;
    let (setup, after_setup, traces, wall_ms, cpu) = if spec.arm.is_synapse() {
        let setup_start = Instant::now();
        let ids = synapse_arm::issue_identities(spec.seed, spec.agents, crate::unix_now_ms())?;
        let fsync = if spec.arm == ArmKind::S1 {
            FsyncPolicy::EveryCommit
        } else {
            FsyncPolicy::BatchWindow {
                max_records: spec.batch_window_records,
            }
        };
        let mut svc =
            synapse_arm::open_service(&store_dir, &ids, fsync, RecoveryPolicy::StrictFailClosed)?;
        let base_oid = synapse_arm::register_base(
            &mut svc,
            &spec.base_commit,
            full_base.ok_or("full base missing for Synapse arm")?,
        )?;
        let setup = SetupSummary {
            description: "open SynapseService, register the base tree held in memory, issue grants"
                .into(),
            units: 1,
            total_ms: round3(setup_start.elapsed().as_secs_f64() * 1000.0),
            per_unit: None,
        };
        let service = Mutex::new(svc);
        let after_setup = du_total(&measured)?;
        let window = RusageWindow::start()?;
        let epoch = Instant::now();
        let traces: Vec<OpTrace> = std::thread::scope(|s| {
            let handles: Vec<_> = ids
                .agents
                .iter()
                .zip(workload.iter())
                .map(|(agent, props)| {
                    let (service, barrier, repo_id) = (&service, &barrier, &ids.repo_id);
                    s.spawn(move || {
                        run_synapse_agent(
                            spec, service, agent, repo_id, base_oid, props, barrier, epoch,
                        )
                    })
                })
                .collect();
            barrier.wait();
            handles
                .into_iter()
                .map(|h| h.join().map_err(|_| "agent thread panicked".to_string()))
                .collect::<Result<Vec<Vec<OpTrace>>, String>>()
        })?
        .into_iter()
        .flatten()
        .collect();
        if spec.arm == ArmKind::S2 {
            let t = Instant::now();
            service
                .lock()
                .map_err(|_| "synapse service mutex poisoned")?
                .store_mut()
                .sync_wal()
                .map_err(|e| e.to_string())?;
            final_sync_ms = Some(round3(t.elapsed().as_secs_f64() * 1000.0));
        }
        let wall_ms = epoch.elapsed().as_secs_f64() * 1000.0;
        let cpu = window.finish()?;
        (setup, after_setup, traces, wall_ms, cpu)
    } else {
        let config: &[(&str, &str)] = if spec.arm == ArmKind::G3F {
            FSYNC_ALL_CONFIG
        } else {
            &[]
        };
        std::fs::create_dir_all(&wt_root).map_err(|e| format!("mkdir worktrees: {e}"))?;
        std::fs::create_dir_all(&plumbing_root).map_err(|e| format!("mkdir plumbing: {e}"))?;
        let (states, samples, total_ms, description) = match spec.arm {
            ArmKind::G1 => (
                (0..spec.agents)
                    .map(|_| GitAgentState::G1 {
                        wt_root: wt_root.clone(),
                    })
                    .collect(),
                Vec::new(),
                0.0,
                "none (each operation creates its own worktree)".to_string(),
            ),
            ArmKind::G2 => {
                let (wts, samples, total) = time_units(spec.agents, |a| {
                    git_arm::g2_setup_agent(clone, &spec.base_commit, &wt_root, a)
                })?;
                (
                    wts.into_iter()
                        .map(|wt| GitAgentState::G2 { wt })
                        .collect::<Vec<_>>(),
                    samples,
                    total,
                    "one `git worktree add --detach` per agent (sequential)".to_string(),
                )
            }
            _ => {
                let (agents, samples, total) = time_units(spec.agents, |a| {
                    git_arm::g3_setup_agent(clone, &spec.base_commit, &plumbing_root, a, config)
                })?;
                (
                    agents
                        .into_iter()
                        .map(|plumbing| GitAgentState::G3 { plumbing })
                        .collect::<Vec<_>>(),
                    samples,
                    total,
                    "one `git read-tree` into a per-agent base index (sequential)".to_string(),
                )
            }
        };
        let setup = SetupSummary {
            description,
            units: samples.len(),
            total_ms,
            per_unit: summarize_us(&samples),
        };
        let after_setup = du_total(&measured)?;
        let window = RusageWindow::start()?;
        let epoch = Instant::now();
        let traces: Vec<OpTrace> = std::thread::scope(|s| {
            let handles: Vec<_> = states
                .iter()
                .zip(workload.iter())
                .map(|(state, props)| {
                    let barrier = &barrier;
                    s.spawn(move || run_git_agent(spec, state, props, barrier, epoch))
                })
                .collect();
            barrier.wait();
            handles
                .into_iter()
                .map(|h| h.join().map_err(|_| "agent thread panicked".to_string()))
                .collect::<Result<Vec<Vec<OpTrace>>, String>>()
        })?
        .into_iter()
        .flatten()
        .collect();
        let wall_ms = epoch.elapsed().as_secs_f64() * 1000.0;
        let cpu = window.finish()?;
        (setup, after_setup, traces, wall_ms, cpu)
    };

    let after_ops = du_total(&measured)?;
    let ops_ok = traces.iter().filter(|t| t.ok).count();
    let storage = storage_delta(&measured, before, after_setup, after_ops, ops_ok);

    write_jsonl(&spec.trace_path, &traces)?;

    if matches!(spec.arm, ArmKind::G1 | ArmKind::G2) {
        git_arm::remove_worktrees(clone, &wt_root)?;
    }

    let ok_lat: Vec<u64> = traces
        .iter()
        .filter(|t| t.ok)
        .map(|t| t.latency_us)
        .collect();
    let queue: Vec<u64> = traces
        .iter()
        .filter(|t| t.ok)
        .filter_map(|t| t.queue_wait_us)
        .collect();
    let wire: Vec<u64> = traces
        .iter()
        .filter(|t| t.ok)
        .filter_map(|t| t.wire_bytes)
        .collect();
    let mut receipts: Vec<(String, usize)> = Vec::new();
    for t in traces.iter().filter_map(|t| t.durability.as_ref()) {
        match receipts.iter_mut().find(|(k, _)| k == t) {
            Some((_, c)) => *c += 1,
            None => receipts.push((t.clone(), 1)),
        }
    }
    let first_errors: Vec<String> = traces
        .iter()
        .filter_map(|t| t.error.clone())
        .take(5)
        .collect();
    let ops_attempted = traces.len();
    let content_total: u64 = traces.iter().map(|t| t.content_bytes).sum();
    Ok(WriteCellResult {
        arm: spec.arm,
        agents: spec.agents,
        ops_per_agent: spec.ops_per_agent,
        rep: spec.rep,
        ops_attempted,
        ops_ok,
        ops_failed: ops_attempted - ops_ok,
        wall_ms: round3(wall_ms),
        throughput_ops_per_s: if wall_ms > 0.0 {
            round3(ops_ok as f64 / (wall_ms / 1000.0))
        } else {
            0.0
        },
        latency: summarize_us(&ok_lat),
        queue_wait: summarize_us(&queue),
        mean_wire_bytes: if wire.is_empty() {
            None
        } else {
            Some(round3(wire.iter().sum::<u64>() as f64 / wire.len() as f64))
        },
        mean_content_bytes: if ops_attempted == 0 {
            0.0
        } else {
            round3(content_total as f64 / ops_attempted as f64)
        },
        setup,
        final_sync_ms,
        cpu_ms_per_op: if ops_ok == 0 {
            None
        } else {
            Some(round3(cpu.total_cpu_ms / ops_ok as f64))
        },
        cpu,
        storage,
        durability_receipts: receipts,
        first_errors,
    })
}
