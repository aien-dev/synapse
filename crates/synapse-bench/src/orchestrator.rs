//! Run orchestration: preflight, isolated fixture clones, one child process per cell,
//! and the aggregated `report.json` and `manifest.json`.
//!
//! The original fixture repository is only read: it is cloned once with
//! `git clone --no-checkout --no-hardlinks` into the work directory (no shared inodes),
//! and every cell then clones that master copy. A digest of the original's refs and
//! `HEAD` is recorded before and after the run.

use crate::conflict::{run_conflict_cell, ConflictResult, ConflictSpec};
use crate::conformance::{run_suite, CaseOutcome, SuiteResult};
use crate::fixture::{self, clone_no_checkout, configure_bench_clone};
use crate::gitcmd::{git_line, git_ok};
use crate::host::{self, FsyncProbe, GitConfigValue, HostInfo, UNKNOWN};
use crate::query::{run_query_cell, QueryCellResult, QuerySpec};
use crate::recovery::{
    run_import_probe, run_recovery_cell, ImportProbeResult, ImportProbeSpec, RecoveryResult,
    RecoverySpec,
};
use crate::rng::SplitMix64;
use crate::stats::{round3, spread, Spread};
use crate::write_phase::{du_total, run_write_cell, ArmKind, WriteCellResult, WriteCellSpec};
use crate::{path_str, read_json, utc_timestamp, write_json};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Instant;

/// Report schema identifier.
pub const REPORT_SCHEMA: &str = "synapse-gate4-qualification-report/v1";
/// Manifest schema identifier.
pub const MANIFEST_SCHEMA: &str = "synapse-gate4-qualification-manifest/v1";
/// Default master seed (recorded in the manifest).
pub const DEFAULT_SEED: u64 = 0x6A7E_4000_2026_1014;

/// Full run configuration (recorded verbatim in the manifest).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunConfig {
    pub fixture_repo: PathBuf,
    pub fixture_rev: String,
    pub out_dir: PathBuf,
    pub work_dir: PathBuf,
    pub reps: usize,
    pub tiers: Vec<usize>,
    pub arms: Vec<ArmKind>,
    pub seed: u64,
    /// Minimum operations per write cell for every arm except G1.
    pub ops_floor: usize,
    pub min_ops_per_agent: usize,
    /// G1 creates one full checkout per operation; its cells are capped at
    /// `max(2, ceil(g1_ops_cap / agents))` operations per agent.
    pub g1_ops_cap: usize,
    pub batch_window_records: u32,
    pub query_agents: usize,
    pub query_ops_per_agent: usize,
    pub query_samples: usize,
    pub recovery_sizes: Vec<usize>,
    pub recovery_reopen_reps: usize,
    pub radicle_repo: Option<PathBuf>,
    pub source_rev: String,
    pub source_dirty: String,
    pub source_digest: String,
    pub smoke: bool,
    pub command_line: Vec<String>,
}

impl RunConfig {
    /// Full-run defaults.
    pub fn new(
        fixture_repo: PathBuf,
        fixture_rev: String,
        out_dir: PathBuf,
        work_dir: PathBuf,
    ) -> Self {
        Self {
            fixture_repo,
            fixture_rev,
            out_dir,
            work_dir,
            reps: 3,
            tiers: vec![1, 4, 8, 32],
            arms: ArmKind::ALL.to_vec(),
            seed: DEFAULT_SEED,
            ops_floor: 400,
            min_ops_per_agent: 8,
            g1_ops_cap: 32,
            batch_window_records: 64,
            query_agents: 8,
            query_ops_per_agent: 50,
            query_samples: 400,
            recovery_sizes: vec![100, 1_000, 10_000],
            recovery_reopen_reps: 3,
            radicle_repo: None,
            source_rev: UNKNOWN.into(),
            source_dirty: UNKNOWN.into(),
            source_digest: UNKNOWN.into(),
            smoke: false,
            command_line: Vec::new(),
        }
    }

    /// Shrink every dimension for a quick end-to-end check of the harness.
    pub fn apply_smoke(&mut self) {
        self.smoke = true;
        self.reps = 1;
        self.tiers = vec![1, 4];
        self.ops_floor = 16;
        self.min_ops_per_agent = 4;
        self.g1_ops_cap = 4;
        self.query_agents = 2;
        self.query_ops_per_agent = 8;
        self.query_samples = 20;
        self.recovery_sizes = vec![50];
        self.recovery_reopen_reps = 2;
    }

    /// Operations per agent for `arm` at `agents` concurrency.
    pub fn ops_per_agent(&self, arm: ArmKind, agents: usize) -> usize {
        let agents = agents.max(1);
        if arm == ArmKind::G1 {
            self.g1_ops_cap.div_ceil(agents).max(2)
        } else {
            self.ops_floor.div_ceil(agents).max(self.min_ops_per_agent)
        }
    }
}

/// Input for the conformance child.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConformanceSpec {
    pub suites: Vec<String>,
    pub work_dir: PathBuf,
    pub radicle_repo: Option<PathBuf>,
}

/// One planned cell, in execution order.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CellPlanEntry {
    pub order: usize,
    pub label: String,
    pub kind: String,
    pub arm: Option<ArmKind>,
    pub agents: Option<usize>,
    pub ops_per_agent: Option<usize>,
    pub rep: Option<usize>,
}

/// A cell that did not produce a result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CellFailure {
    pub label: String,
    pub kind: String,
    pub error: String,
}

/// Wall time of one executed cell (including its clone, excluded from measurements).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CellTiming {
    pub label: String,
    pub clone_ms: f64,
    pub child_wall_ms: f64,
    pub ok: bool,
}

/// Arm metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArmInfo {
    pub code: String,
    pub description: String,
    pub durability: String,
}

/// Aggregate of one arm at one concurrency tier across repetitions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArmTierSummary {
    pub arm: ArmKind,
    pub agents: usize,
    pub ops_per_agent: usize,
    pub reps: usize,
    pub ops_ok_total: usize,
    pub ops_failed_total: usize,
    pub latency_n_per_rep: Vec<usize>,
    pub throughput_ops_per_s: Option<Spread>,
    pub latency_p50_ms: Option<Spread>,
    /// Present only when every repetition had at least 20 samples.
    pub latency_p95_ms: Option<Spread>,
    /// Present only when every repetition had at least 100 samples.
    pub latency_p99_ms: Option<Spread>,
    pub latency_max_ms: Option<Spread>,
    pub queue_wait_p50_ms: Option<Spread>,
    pub cpu_ms_per_op: Option<Spread>,
    pub peak_rss_arm_process_kib: Option<Spread>,
    pub peak_rss_largest_git_child_kib: Option<Spread>,
    pub setup_description: String,
    pub setup_units: usize,
    pub setup_ms_per_unit: Option<Spread>,
    pub storage_setup_apparent_bytes: Option<Spread>,
    pub storage_ops_apparent_bytes_per_op: Option<Spread>,
    pub storage_ops_allocated_bytes_per_op: Option<Spread>,
    pub mean_wire_bytes: Option<Spread>,
    pub final_sync_ms: Option<Spread>,
}

/// Compact headline row (medians across repetitions).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeadlineRow {
    pub agents: usize,
    pub arm: ArmKind,
    pub ops_per_cell: usize,
    pub throughput_ops_per_s_median: Option<f64>,
    pub write_p50_ms_median: Option<f64>,
    pub write_p99_ms_median: Option<f64>,
}

/// Aggregate of one query method across repetitions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuerySummaryRow {
    pub query: String,
    pub system: String,
    pub method: String,
    pub n_per_rep: Vec<usize>,
    pub failures_total: usize,
    pub p50_ms: Option<Spread>,
    pub p95_ms: Option<Spread>,
    pub p99_ms: Option<Spread>,
    pub api_only_p50_ms: Option<Spread>,
    pub mean_pages: Option<Spread>,
    pub mean_response_bytes: Option<Spread>,
}

/// Conformance outcome per suite across runs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConformanceSummary {
    pub suite: String,
    pub runs: usize,
    pub cases: usize,
    pub passed_per_run: Vec<usize>,
    pub failed_per_run: Vec<usize>,
    pub skipped_per_run: Vec<usize>,
    /// Every case had the same outcome in every run.
    pub outcomes_identical_across_runs: bool,
}

/// `report.json`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Report {
    pub schema: String,
    pub smoke: bool,
    pub generated_at_utc: String,
    pub arms: Vec<ArmInfo>,
    pub headline: Vec<HeadlineRow>,
    pub write_summary: Vec<ArmTierSummary>,
    pub write_cells: Vec<WriteCellResult>,
    pub query_summary: Vec<QuerySummaryRow>,
    pub query_cells: Vec<QueryCellResult>,
    pub conflict: Option<ConflictResult>,
    pub conformance_summary: Vec<ConformanceSummary>,
    pub conformance_runs: Vec<Vec<SuiteResult>>,
    pub recovery: Option<RecoveryResult>,
    pub import_probe: Option<ImportProbeResult>,
    pub failures: Vec<CellFailure>,
    pub scope_notes: Vec<String>,
}

/// Fixture identity and read-only evidence for the original repository.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FixtureInfo {
    pub original_repo: String,
    pub requested_rev: String,
    pub commit: String,
    pub tree: String,
    pub files: usize,
    pub total_bytes: u64,
    pub largest_file_bytes: u64,
    pub skipped_entries: usize,
    pub editable_files: usize,
    pub master_clone_method: String,
    pub master_clone_git_dir_apparent_bytes: u64,
    pub original_head_before: String,
    pub original_head_after: String,
    pub original_refs_sha256_before: String,
    pub original_refs_sha256_after: String,
}

/// Disk preflight.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiskPlan {
    pub free_bytes_at_start: Option<u64>,
    pub estimated_peak_cell_bytes: u64,
    pub required_free_bytes: u64,
    pub min_free_bytes_observed: Option<u64>,
}

/// Source tree identity supplied by the run script.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SourceInfo {
    pub rev: String,
    pub dirty: String,
    pub digest: String,
}

/// `manifest.json`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Manifest {
    pub schema: String,
    pub smoke: bool,
    pub started_at_utc: String,
    pub finished_at_utc: String,
    pub total_run_s: f64,
    pub command_line: Vec<String>,
    pub config: RunConfig,
    pub host: HostInfo,
    pub fixture: FixtureInfo,
    pub bench_clone_config: Vec<(String, String)>,
    pub git_config: Vec<GitConfigValue>,
    pub git_config_listing: Vec<String>,
    pub fsync_probe: FsyncProbe,
    pub disk: DiskPlan,
    pub source: SourceInfo,
    pub cell_order_seed: u64,
    pub cell_order: Vec<CellPlanEntry>,
    pub cell_timings: Vec<CellTiming>,
    pub trace_files: Vec<String>,
}

fn ms_since(t: Instant) -> f64 {
    round3(t.elapsed().as_secs_f64() * 1000.0)
}

fn tail(bytes: &[u8], max: usize) -> String {
    let s = String::from_utf8_lossy(bytes);
    let start = s.len().saturating_sub(max);
    let mut idx = start;
    while !s.is_char_boundary(idx) {
        idx += 1;
    }
    s[idx..].trim().to_string()
}

/// Run one child cell: `<exe> child --kind <kind> --spec <file> --result <file>`.
fn run_child<S: Serialize, R: DeserializeOwned>(
    exe: &Path,
    ctl: &Path,
    kind: &str,
    label: &str,
    spec: &S,
) -> Result<R, String> {
    let spec_path = ctl.join(format!("{label}.spec.json"));
    let result_path = ctl.join(format!("{label}.result.json"));
    write_json(&spec_path, spec)?;
    let out = Command::new(exe)
        .args([
            "child",
            "--kind",
            kind,
            "--spec",
            path_str(&spec_path)?,
            "--result",
            path_str(&result_path)?,
        ])
        .stdin(Stdio::null())
        .output()
        .map_err(|e| format!("spawn child {label}: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "child {label} exited {:?}: {}",
            out.status.code(),
            tail(&out.stderr, 2000)
        ));
    }
    read_json(&result_path)
}

/// Child entry point: run one cell from a spec file and write its result.
pub fn child_main(kind: &str, spec: &Path, result: &Path) -> Result<(), String> {
    match kind {
        "write" => {
            let s: WriteCellSpec = read_json(spec)?;
            write_json(result, &run_write_cell(&s)?)
        }
        "query" => {
            let s: QuerySpec = read_json(spec)?;
            write_json(result, &run_query_cell(&s)?)
        }
        "conflict" => {
            let s: ConflictSpec = read_json(spec)?;
            write_json(result, &run_conflict_cell(&s)?)
        }
        "conformance" => {
            let s: ConformanceSpec = read_json(spec)?;
            let suites = s
                .suites
                .iter()
                .map(|name| run_suite(name, &s.work_dir.join(name), s.radicle_repo.as_deref()))
                .collect::<Result<Vec<_>, String>>()?;
            write_json(result, &suites)
        }
        "recovery" => {
            let s: RecoverySpec = read_json(spec)?;
            write_json(result, &run_recovery_cell(&s)?)
        }
        "import-probe" => {
            let s: ImportProbeSpec = read_json(spec)?;
            write_json(result, &run_import_probe(&s)?)
        }
        other => Err(format!("unknown child kind {other}")),
    }
}

/// `HEAD` and a SHA-256 over `git for-each-ref` of a repository (read-only commands).
fn refs_fingerprint(repo: &Path) -> Result<(String, String), String> {
    let head = git_line(repo, &["rev-parse", "HEAD"])?;
    let refs = git_ok(
        repo,
        &[],
        &[],
        &["for-each-ref", "--format=%(objectname) %(refname)"],
        None,
    )?;
    let mut h = Sha256::new();
    h.update(head.as_bytes());
    h.update(b"\n");
    h.update(&refs);
    Ok((head, hex::encode(h.finalize())))
}

fn opt_all(values: &[Option<f64>]) -> Option<Spread> {
    if values.is_empty() || values.iter().any(Option::is_none) {
        return None;
    }
    let v: Vec<f64> = values.iter().flatten().copied().collect();
    spread(&v)
}

fn summarize_write(
    cells: &[WriteCellResult],
    arms: &[ArmKind],
    tiers: &[usize],
) -> Vec<ArmTierSummary> {
    let mut out = Vec::new();
    for &agents in tiers {
        for &arm in arms {
            let reps: Vec<&WriteCellResult> = cells
                .iter()
                .filter(|c| c.arm == arm && c.agents == agents)
                .collect();
            if reps.is_empty() {
                continue;
            }
            let f = |g: &dyn Fn(&WriteCellResult) -> Option<f64>| -> Option<Spread> {
                opt_all(&reps.iter().map(|c| g(c)).collect::<Vec<_>>())
            };
            out.push(ArmTierSummary {
                arm,
                agents,
                ops_per_agent: reps[0].ops_per_agent,
                reps: reps.len(),
                ops_ok_total: reps.iter().map(|c| c.ops_ok).sum(),
                ops_failed_total: reps.iter().map(|c| c.ops_failed).sum(),
                latency_n_per_rep: reps
                    .iter()
                    .map(|c| c.latency.as_ref().map_or(0, |l| l.n))
                    .collect(),
                throughput_ops_per_s: f(&|c| Some(c.throughput_ops_per_s)),
                latency_p50_ms: f(&|c| c.latency.as_ref().map(|l| l.p50_ms)),
                latency_p95_ms: f(&|c| c.latency.as_ref().and_then(|l| l.p95_ms)),
                latency_p99_ms: f(&|c| c.latency.as_ref().and_then(|l| l.p99_ms)),
                latency_max_ms: f(&|c| c.latency.as_ref().map(|l| l.max_ms)),
                queue_wait_p50_ms: f(&|c| c.queue_wait.as_ref().map(|l| l.p50_ms)),
                cpu_ms_per_op: f(&|c| c.cpu_ms_per_op),
                peak_rss_arm_process_kib: f(&|c| Some(c.cpu.peak_rss_self_kib as f64)),
                peak_rss_largest_git_child_kib: f(&|c| {
                    (!c.arm.is_synapse()).then_some(c.cpu.peak_rss_largest_child_kib as f64)
                }),
                setup_description: reps[0].setup.description.clone(),
                setup_units: reps[0].setup.units,
                setup_ms_per_unit: f(&|c| {
                    (c.setup.units > 0).then(|| c.setup.total_ms / c.setup.units as f64)
                }),
                storage_setup_apparent_bytes: f(&|c| Some(c.storage.setup_apparent_bytes as f64)),
                storage_ops_apparent_bytes_per_op: f(&|c| {
                    Some(c.storage.ops_apparent_bytes_per_op)
                }),
                storage_ops_allocated_bytes_per_op: f(&|c| {
                    Some(c.storage.ops_allocated_bytes_per_op)
                }),
                mean_wire_bytes: f(&|c| c.mean_wire_bytes),
                final_sync_ms: f(&|c| c.final_sync_ms),
            });
        }
    }
    out
}

fn headline(summary: &[ArmTierSummary]) -> Vec<HeadlineRow> {
    summary
        .iter()
        .map(|s| HeadlineRow {
            agents: s.agents,
            arm: s.arm,
            ops_per_cell: s.agents * s.ops_per_agent,
            throughput_ops_per_s_median: s.throughput_ops_per_s.as_ref().map(|x| x.median),
            write_p50_ms_median: s.latency_p50_ms.as_ref().map(|x| x.median),
            write_p99_ms_median: s.latency_p99_ms.as_ref().map(|x| x.median),
        })
        .collect()
}

fn summarize_queries(cells: &[QueryCellResult]) -> Vec<QuerySummaryRow> {
    let mut keys: Vec<(String, String, String)> = Vec::new();
    for c in cells {
        for q in &c.queries {
            let k = (q.query.clone(), q.system.clone(), q.method.clone());
            if !keys.contains(&k) {
                keys.push(k);
            }
        }
    }
    keys.into_iter()
        .map(|(query, system, method)| {
            let rows: Vec<_> = cells
                .iter()
                .filter_map(|c| {
                    c.queries
                        .iter()
                        .find(|q| q.query == query && q.system == system && q.method == method)
                })
                .collect();
            let f = |g: &dyn Fn(&crate::query::QueryKindResult) -> Option<f64>| {
                opt_all(&rows.iter().map(|r| g(r)).collect::<Vec<_>>())
            };
            QuerySummaryRow {
                n_per_rep: rows
                    .iter()
                    .map(|r| r.latency.as_ref().map_or(0, |l| l.n))
                    .collect(),
                failures_total: rows.iter().map(|r| r.failures).sum(),
                p50_ms: f(&|r| r.latency.as_ref().map(|l| l.p50_ms)),
                p95_ms: f(&|r| r.latency.as_ref().and_then(|l| l.p95_ms)),
                p99_ms: f(&|r| r.latency.as_ref().and_then(|l| l.p99_ms)),
                api_only_p50_ms: f(&|r| r.api_only.as_ref().map(|l| l.p50_ms)),
                mean_pages: f(&|r| r.mean_pages),
                mean_response_bytes: f(&|r| r.mean_response_bytes),
                query,
                system,
                method,
            }
        })
        .collect()
}

fn summarize_conformance(runs: &[Vec<SuiteResult>]) -> Vec<ConformanceSummary> {
    let mut names: Vec<String> = Vec::new();
    for run in runs {
        for s in run {
            if !names.contains(&s.suite) {
                names.push(s.suite.clone());
            }
        }
    }
    names
        .into_iter()
        .map(|suite| {
            let per_run: Vec<&SuiteResult> = runs
                .iter()
                .filter_map(|r| r.iter().find(|s| s.suite == suite))
                .collect();
            let outcomes: Vec<Vec<(String, CaseOutcome)>> = per_run
                .iter()
                .map(|s| {
                    s.cases
                        .iter()
                        .map(|c| (c.case.clone(), c.outcome))
                        .collect()
                })
                .collect();
            ConformanceSummary {
                runs: per_run.len(),
                cases: per_run.first().map_or(0, |s| s.cases.len()),
                passed_per_run: per_run.iter().map(|s| s.passed).collect(),
                failed_per_run: per_run.iter().map(|s| s.failed).collect(),
                skipped_per_run: per_run.iter().map(|s| s.skipped).collect(),
                outcomes_identical_across_runs: outcomes.windows(2).all(|w| w[0] == w[1]),
                suite,
            }
        })
        .collect()
}

fn scope_notes() -> Vec<String> {
    [
        "Synapse arms call SynapseService in-process; the JSON encode/decode of each request is included as a transport approximation. No socket, daemon, or network stack is measured.",
        "Single host, single filesystem; every cell starts from a fresh clone, but the page cache is warm (no cache drop between cells).",
        "Edits are synthetic (generated hunks, added and deleted files on the real fixture tree); no compiler, tests, or agent reasoning time is included.",
        "Synapse arms hold the full base tree in memory (registered during setup, excluded from per-operation latency).",
        "Transfer sizes are estimates: Synapse JSON request bytes versus git thin-pack bytes against the base; neither is a measured network transfer.",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect()
}

struct Planned {
    entry: CellPlanEntry,
    work: Work,
}

enum Work {
    Write(WriteCellSpec),
    Query(QuerySpec),
    Conformance(ConformanceSpec),
    Conflict(ConflictSpec),
    Recovery(RecoverySpec),
    ImportProbe(ImportProbeSpec),
}

impl Work {
    fn kind(&self) -> &'static str {
        match self {
            Work::Write(_) => "write",
            Work::Query(_) => "query",
            Work::Conformance(_) => "conformance",
            Work::Conflict(_) => "conflict",
            Work::Recovery(_) => "recovery",
            Work::ImportProbe(_) => "import-probe",
        }
    }

    /// Clone directory the parent prepares before the child runs, if any.
    fn clone_dir(&self) -> Option<&Path> {
        match self {
            Work::Write(s) => Some(&s.clone_dir),
            Work::Query(s) => Some(&s.clone_dir),
            Work::Conflict(s) => Some(&s.clone_dir),
            Work::Recovery(s) => Some(&s.clone_dir),
            Work::ImportProbe(s) => Some(&s.clone_dir),
            Work::Conformance(_) => None,
        }
    }
}

/// Execute a full qualification run and write `report.json` and `manifest.json`.
pub fn run_qualification(cfg: &RunConfig) -> Result<(), String> {
    let started = Instant::now();
    let started_at = utc_timestamp();
    let exe = std::env::current_exe().map_err(|e| format!("current_exe: {e}"))?;
    let work = cfg.work_dir.clone();
    let traces = cfg.out_dir.join("traces");
    let ctl = work.join("ctl");
    let cells_root = work.join("cells");
    for d in [&work, &traces, &ctl, &cells_root] {
        std::fs::create_dir_all(d).map_err(|e| format!("mkdir {}: {e}", d.display()))?;
    }
    let host_info = host::collect_host_info(&work);

    // Original repository: read-only fingerprint, then one isolated master clone.
    let (head_before, refs_before) = refs_fingerprint(&cfg.fixture_repo)?;
    let master = work.join("master");
    git_ok(
        &work,
        &[],
        &[],
        &[
            "clone",
            "--no-checkout",
            "--no-hardlinks",
            "--quiet",
            path_str(&cfg.fixture_repo)?,
            path_str(&master)?,
        ],
        None,
    )?;
    configure_bench_clone(&master)?;
    let commit = git_line(
        &master,
        &[
            "rev-parse",
            "--verify",
            &format!("{}^{{commit}}", cfg.fixture_rev),
        ],
    )?;
    git_ok(
        &master,
        &[],
        &[],
        &["update-ref", "refs/heads/gate4-base", &commit],
        None,
    )?;
    let base = fixture::list_base_tree(&master, &commit)?;
    let editable = fixture::load_editable_files(&master, &base)?.len();
    let master_git = du_total(&[master.join(".git")])?;

    // Disk preflight: the largest cell is G1 (one checkout per op) or G2 (one per agent).
    let max_tier = cfg.tiers.iter().copied().max().unwrap_or(1);
    let mut checkouts = 0usize;
    for &t in &cfg.tiers {
        if cfg.arms.contains(&ArmKind::G1) {
            checkouts = checkouts.max(t * cfg.ops_per_agent(ArmKind::G1, t));
        }
    }
    if cfg.arms.contains(&ArmKind::G2) {
        checkouts = checkouts.max(max_tier);
    }
    let estimated_peak =
        (checkouts as u64 + 2) * base.total_bytes() + 2 * master_git.apparent_bytes + (2u64 << 30);
    let required_free = estimated_peak.saturating_mul(3);
    let free_at_start = host::free_bytes(&work);
    if free_at_start.is_some_and(|f| f < required_free) {
        return Err(format!(
            "insufficient free disk: {:?} bytes free, {required_free} required",
            free_at_start
        ));
    }

    let git_config: Vec<GitConfigValue> = [
        "core.fsync",
        "core.fsyncMethod",
        "core.fsyncObjectFiles",
        "gc.auto",
        "maintenance.auto",
    ]
    .iter()
    .map(|k| git_config_or_unknown(&master, k))
    .collect();
    let git_listing =
        host::git_config_listing(&master).unwrap_or_else(|e| vec![format!("error: {e}")]);
    let fsync_probe = host::probe_git_fsync(&work.join("fsync-probe"));

    // Plan cells: each repetition is a shuffled block of write cells plus that
    // repetition's query and conformance cells; single cells follow.
    let order_seed = SplitMix64::derive(cfg.seed, &[0x0DE5]).next_u64();
    let mut planned: Vec<Planned> = Vec::new();
    for rep in 0..cfg.reps {
        let mut block: Vec<Planned> = Vec::new();
        for &agents in &cfg.tiers {
            for &arm in &cfg.arms {
                let ops = cfg.ops_per_agent(arm, agents);
                let label = format!("write-{}-a{agents:02}-r{rep}", arm.code());
                let root = cells_root.join(&label);
                block.push(Planned {
                    entry: CellPlanEntry {
                        order: 0,
                        label: label.clone(),
                        kind: "write".into(),
                        arm: Some(arm),
                        agents: Some(agents),
                        ops_per_agent: Some(ops),
                        rep: Some(rep),
                    },
                    work: Work::Write(WriteCellSpec {
                        arm,
                        agents,
                        ops_per_agent: ops,
                        rep,
                        seed: cfg.seed,
                        clone_dir: root.join("clone"),
                        base_commit: commit.clone(),
                        cell_dir: root.join("cell"),
                        trace_path: traces.join(format!("{label}.jsonl")),
                        batch_window_records: cfg.batch_window_records,
                    }),
                });
            }
        }
        let label = format!("query-r{rep}");
        let root = cells_root.join(&label);
        block.push(Planned {
            entry: CellPlanEntry {
                order: 0,
                label: label.clone(),
                kind: "query".into(),
                arm: None,
                agents: Some(cfg.query_agents),
                ops_per_agent: Some(cfg.query_ops_per_agent),
                rep: Some(rep),
            },
            work: Work::Query(QuerySpec {
                rep,
                seed: cfg.seed,
                agents: cfg.query_agents,
                ops_per_agent: cfg.query_ops_per_agent,
                samples: cfg.query_samples,
                clone_dir: root.join("clone"),
                base_commit: commit.clone(),
                cell_dir: root.join("cell"),
                trace_path: traces.join(format!("{label}.jsonl")),
            }),
        });
        let label = format!("conformance-r{rep}");
        block.push(Planned {
            entry: CellPlanEntry {
                order: 0,
                label: label.clone(),
                kind: "conformance".into(),
                arm: None,
                agents: None,
                ops_per_agent: None,
                rep: Some(rep),
            },
            work: Work::Conformance(ConformanceSpec {
                suites: vec!["wal".into(), "git".into(), "radicle".into()],
                work_dir: cells_root.join(&label),
                radicle_repo: cfg.radicle_repo.clone(),
            }),
        });
        let mut rng = SplitMix64::derive(order_seed, &[rep as u64]);
        rng.shuffle(&mut block);
        planned.extend(block);
    }
    let singles: [(&str, &str); 3] = [
        ("conflict", "conflict"),
        ("recovery", "recovery"),
        ("import-probe", "import-probe"),
    ];
    for (label, kind) in singles {
        let root = cells_root.join(label);
        let work_item = match kind {
            "conflict" => Work::Conflict(ConflictSpec {
                seed: cfg.seed,
                clone_dir: root.join("clone"),
                base_commit: commit.clone(),
                cell_dir: root.join("cell"),
                trace_path: traces.join("conflict.jsonl"),
            }),
            "recovery" => Work::Recovery(RecoverySpec {
                seed: cfg.seed,
                sizes: cfg.recovery_sizes.clone(),
                reopen_reps: cfg.recovery_reopen_reps,
                clone_dir: root.join("clone"),
                base_commit: commit.clone(),
                cell_dir: root.join("cell"),
                trace_path: traces.join("recovery.jsonl"),
            }),
            _ => Work::ImportProbe(ImportProbeSpec {
                seed: cfg.seed,
                clone_dir: root.join("clone"),
                base_commit: commit.clone(),
                cell_dir: root.join("cell"),
            }),
        };
        planned.push(Planned {
            entry: CellPlanEntry {
                order: 0,
                label: label.to_string(),
                kind: kind.to_string(),
                arm: None,
                agents: None,
                ops_per_agent: None,
                rep: None,
            },
            work: work_item,
        });
    }
    for (i, p) in planned.iter_mut().enumerate() {
        p.entry.order = i;
    }

    // Execute.
    let total = planned.len();
    let mut write_cells = Vec::new();
    let mut query_cells = Vec::new();
    let mut conformance_runs = Vec::new();
    let mut conflict = None;
    let mut recovery = None;
    let mut import_probe = None;
    let mut failures = Vec::new();
    let mut timings = Vec::new();
    let mut min_free = free_at_start;
    for p in &planned {
        let label = p.entry.label.as_str();
        let kind = p.work.kind();
        let free = host::free_bytes(&work);
        min_free = match (min_free, free) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (a, b) => a.or(b),
        };
        if free.is_some_and(|f| f < estimated_peak) {
            failures.push(CellFailure {
                label: label.into(),
                kind: kind.into(),
                error: format!("skipped: free disk {free:?} below estimated peak {estimated_peak}"),
            });
            continue;
        }
        let cell_root = cells_root.join(label);
        let t_clone = Instant::now();
        let mut clone_err = None;
        if let Some(clone) = p.work.clone_dir() {
            if let Err(e) =
                clone_no_checkout(&master, clone).and_then(|_| configure_bench_clone(clone))
            {
                clone_err = Some(e);
            }
        }
        let clone_ms = ms_since(t_clone);
        let t_child = Instant::now();
        let outcome: Result<(), String> = match clone_err {
            Some(e) => Err(format!("clone failed: {e}")),
            None => match &p.work {
                Work::Write(s) => {
                    run_child(&exe, &ctl, kind, label, s).map(|r| write_cells.push(r))
                }
                Work::Query(s) => {
                    run_child(&exe, &ctl, kind, label, s).map(|r| query_cells.push(r))
                }
                Work::Conformance(s) => {
                    run_child(&exe, &ctl, kind, label, s).map(|r| conformance_runs.push(r))
                }
                Work::Conflict(s) => {
                    run_child(&exe, &ctl, kind, label, s).map(|r| conflict = Some(r))
                }
                Work::Recovery(s) => {
                    run_child(&exe, &ctl, kind, label, s).map(|r| recovery = Some(r))
                }
                Work::ImportProbe(s) => {
                    run_child(&exe, &ctl, kind, label, s).map(|r| import_probe = Some(r))
                }
            },
        };
        let child_ms = ms_since(t_child);
        let ok = outcome.is_ok();
        if let Err(e) = outcome {
            failures.push(CellFailure {
                label: label.into(),
                kind: kind.into(),
                error: e,
            });
        }
        let _ = std::fs::remove_dir_all(&cell_root);
        eprintln!(
            "[{}/{total}] {label} {} clone {:.1}s cell {:.1}s (elapsed {:.0}s)",
            p.entry.order + 1,
            if ok { "ok" } else { "FAILED" },
            clone_ms / 1000.0,
            child_ms / 1000.0,
            started.elapsed().as_secs_f64()
        );
        timings.push(CellTiming {
            label: label.into(),
            clone_ms,
            child_wall_ms: child_ms,
            ok,
        });
    }

    let write_summary = summarize_write(&write_cells, &cfg.arms, &cfg.tiers);
    let report = Report {
        schema: REPORT_SCHEMA.into(),
        smoke: cfg.smoke,
        generated_at_utc: utc_timestamp(),
        arms: cfg
            .arms
            .iter()
            .map(|a| ArmInfo {
                code: a.code().into(),
                description: a.description().into(),
                durability: a.durability().into(),
            })
            .collect(),
        headline: headline(&write_summary),
        write_summary,
        write_cells,
        query_summary: summarize_queries(&query_cells),
        query_cells,
        conflict,
        conformance_summary: summarize_conformance(&conformance_runs),
        conformance_runs,
        recovery,
        import_probe,
        failures,
        scope_notes: scope_notes(),
    };
    write_json(&cfg.out_dir.join("report.json"), &report)?;

    let (head_after, refs_after) = refs_fingerprint(&cfg.fixture_repo)?;
    let mut trace_files: Vec<String> = std::fs::read_dir(&traces)
        .map_err(|e| format!("read_dir traces: {e}"))?
        .flatten()
        .map(|e| format!("traces/{}", e.file_name().to_string_lossy()))
        .collect();
    trace_files.sort();
    let largest = base.entries.iter().map(|e| e.size_bytes).max().unwrap_or(0);
    let manifest = Manifest {
        schema: MANIFEST_SCHEMA.into(),
        smoke: cfg.smoke,
        started_at_utc: started_at,
        finished_at_utc: utc_timestamp(),
        total_run_s: round3(started.elapsed().as_secs_f64()),
        command_line: cfg.command_line.clone(),
        config: cfg.clone(),
        host: host_info,
        fixture: FixtureInfo {
            original_repo: cfg.fixture_repo.display().to_string(),
            requested_rev: cfg.fixture_rev.clone(),
            commit: base.commit_hex.clone(),
            tree: base.tree_hex.clone(),
            files: base.entries.len(),
            total_bytes: base.total_bytes(),
            largest_file_bytes: largest,
            skipped_entries: base.skipped_entries,
            editable_files: editable,
            master_clone_method: "git clone --no-checkout --no-hardlinks (once); each cell: git clone --no-checkout --local of the master clone".into(),
            master_clone_git_dir_apparent_bytes: master_git.apparent_bytes,
            original_head_before: head_before,
            original_head_after: head_after,
            original_refs_sha256_before: refs_before,
            original_refs_sha256_after: refs_after,
        },
        bench_clone_config: fixture::BENCH_CLONE_CONFIG
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect(),
        git_config,
        git_config_listing: git_listing,
        fsync_probe,
        disk: DiskPlan {
            free_bytes_at_start: free_at_start,
            estimated_peak_cell_bytes: estimated_peak,
            required_free_bytes: required_free,
            min_free_bytes_observed: min_free,
        },
        source: SourceInfo {
            rev: cfg.source_rev.clone(),
            dirty: cfg.source_dirty.clone(),
            digest: cfg.source_digest.clone(),
        },
        cell_order_seed: order_seed,
        cell_order: planned.into_iter().map(|p| p.entry).collect(),
        cell_timings: timings,
        trace_files,
    };
    write_json(&cfg.out_dir.join("manifest.json"), &manifest)?;
    let _ = std::fs::remove_dir_all(&master);
    Ok(())
}

fn git_config_or_unknown(repo: &Path, key: &str) -> GitConfigValue {
    host::git_config_value(repo, key).unwrap_or_else(|e| GitConfigValue {
        key: key.to_string(),
        values_with_origin: vec![format!("error: {e}")],
        set: false,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ops_per_agent_respects_floor_and_g1_cap() {
        let cfg = RunConfig::new("a".into(), "b".into(), "c".into(), "d".into());
        assert_eq!(cfg.ops_per_agent(ArmKind::S1, 1), 400);
        assert_eq!(cfg.ops_per_agent(ArmKind::G3, 32), 13);
        assert_eq!(cfg.ops_per_agent(ArmKind::G2, 8), 50);
        assert_eq!(cfg.ops_per_agent(ArmKind::G1, 1), 32);
        assert_eq!(cfg.ops_per_agent(ArmKind::G1, 32), 2);
        for t in [1usize, 4, 8, 32] {
            for a in ArmKind::ALL {
                if a != ArmKind::G1 {
                    assert!(t * cfg.ops_per_agent(a, t) >= 400);
                }
            }
        }
    }

    #[test]
    fn opt_all_requires_every_rep() {
        assert!(opt_all(&[Some(1.0), None]).is_none());
        assert_eq!(
            opt_all(&[Some(1.0), Some(3.0), Some(2.0)]).unwrap().median,
            2.0
        );
    }
}
