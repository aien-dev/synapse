//! C1 measurement (ADR 0003 section 9 step 4): the shared Merkle tree on the Gate 4 query load.
//!
//! One process, one reader thread, no concurrent writers. The population is the Gate 4 query
//! cell's (`generate_write_workload(seed, 10_000 + rep, agents, ops_per_agent, ..)`, the same
//! proposals committed to Git through the plumbing path). Then, in order:
//!
//! 1. Parity: the base tree and every changeset's tree and diff from the signed `tree` and
//!    `diff` APIs, per entry and in order, against `git ls-tree -r` and `git diff-tree -r`.
//! 2. The tree cache is replaced by an empty one bounded by `cache_bytes` (base pinned).
//! 3. Cold (build): every changeset root once, in a seeded shuffled order, timed around
//!    `tree_digest` (the build reads the upserted blobs for their Git ids, edits the base tree
//!    along the touched paths, encodes and hashes the new nodes). Bound: (upserted blob bytes
//!    read plus new node bytes written) / memory bandwidth.
//! 4. Warm (paging): `samples` full listings of random changesets in pages of 256, timed at
//!    the engine (`tree_page`) and separately at the API (`tree`, authorization included,
//!    request signing and encoding excluded, as Gate 4's `api_only`). Bound: encoded bytes
//!    of the tree's distinct nodes / memory bandwidth.
//! 5. Diff (warm): `samples` engine diffs base to changeset, timed; no bound is derived.
//!
//! The memory bound used is the physical 273 GB/s (A0, `docs/A0_HOST_BOUNDS.md`). Each sample
//! records whether it built a tree, so a cold rebuild after eviction is never counted as warm.

use crate::energy::{EnergyReading, EnergyWindow};
use crate::fixture;
use crate::rng::SplitMix64;
use crate::rusage::sample_self;
use crate::stats::{round3, summarize_us, LatencySummary};
use crate::synapse_arm;
use crate::tree_parity::{first_mismatch, ParityPair};
use crate::workload::{generate_write_workload, EditOp, Proposal};
use crate::{write_json, write_jsonl};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::time::Instant;
use synapse_api::{
    PageRequest, TreeCacheConfig, TreeQueryPayload, TreeStoreStats, TreeTarget,
    DEFAULT_MAX_PAGE_SIZE,
};
use synapse_core::ChangesetId;

/// Physical memory bandwidth of the host, bytes per second (A0: NVIDIA DGX Spark, 273 GB/s).
pub const MEMORY_BANDWIDTH_BPS: f64 = 273e9;

/// Input of one C1 measurement.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct C1Spec {
    pub clone_dir: PathBuf,
    pub base_commit: String,
    pub seed: u64,
    pub rep: usize,
    pub agents: usize,
    pub ops_per_agent: usize,
    pub samples: usize,
    pub cache_bytes: usize,
    pub work_dir: PathBuf,
    pub out_dir: PathBuf,
    /// Skip the parity pass (a second run on the same population need not repeat it).
    pub skip_parity: bool,
}

/// One timed sample.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct C1Trace {
    pub phase: String,
    pub sample: usize,
    pub changeset_index: usize,
    pub latency_ns: u64,
    /// Bytes the bound charges for this sample (see the module documentation).
    pub bound_bytes: Option<u64>,
    pub bound_ns: Option<f64>,
    /// bound / measured.
    pub fraction_of_bound: Option<f64>,
    /// Changeset roots built during the sample (0 = warm).
    pub root_builds: u64,
    pub new_nodes: u64,
    pub pages: Option<usize>,
    pub entries: Option<u64>,
}

/// Summary of one phase.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct C1PhaseSummary {
    pub phase: String,
    pub method: String,
    pub samples: usize,
    pub latency: Option<LatencySummary>,
    pub samples_that_built: usize,
    pub bound_bytes_p50: Option<u64>,
    pub bound_ms_p50: Option<f64>,
    /// Median of the per-sample fractions of the bound.
    pub fraction_of_bound_p50: Option<f64>,
    pub energy: Option<EnergyReading>,
}

/// Parity result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct C1Parity {
    pub check: String,
    pub compared_trees: usize,
    pub compared_entries: usize,
    pub mismatched_trees: usize,
    pub first_mismatch: Option<String>,
}

/// C1 report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct C1Report {
    pub spec: C1Spec,
    pub base_files: usize,
    pub base_tree_encoded_bytes: u64,
    pub base_tree_nodes: u64,
    pub population_changesets: usize,
    pub populate_s: f64,
    pub parity: Vec<C1Parity>,
    pub memory_bandwidth_bps: f64,
    pub phases: Vec<C1PhaseSummary>,
    pub cache_after: TreeStoreStats,
    pub cache_bound_held: bool,
    pub peak_rss_self_kib: u64,
    pub loadavg_start: Option<[f64; 3]>,
    pub loadavg_end: Option<[f64; 3]>,
    pub notes: Vec<String>,
}

fn upserted_bytes(p: &Proposal) -> u64 {
    p.edits
        .iter()
        .map(|e| match &e.op {
            EditOp::Upsert { content, .. } => content.len() as u64,
            EditOp::Delete => 0,
        })
        .sum()
}

/// (bound in ns, bound / measured) for `bytes` at the memory bandwidth.
fn bound(bytes: u64, latency_ns: u64) -> (Option<f64>, Option<f64>) {
    let bound_ns = bytes as f64 / MEMORY_BANDWIDTH_BPS * 1e9;
    let frac = (latency_ns > 0).then(|| bound_ns / latency_ns as f64);
    (Some(bound_ns), frac)
}

fn median_u64(mut v: Vec<u64>) -> Option<u64> {
    v.sort_unstable();
    crate::stats::nearest_rank(&v, 0.5)
}

fn median_f64(mut v: Vec<f64>) -> Option<f64> {
    if v.is_empty() {
        return None;
    }
    v.sort_by(|a, b| a.total_cmp(b));
    Some(v[(v.len() - 1) / 2])
}

fn summarize(
    phase: &str,
    method: &str,
    rows: &[C1Trace],
    energy: Option<EnergyReading>,
) -> C1PhaseSummary {
    let lat_us: Vec<u64> = rows.iter().map(|r| r.latency_ns / 1000).collect();
    let bytes: Vec<u64> = rows.iter().filter_map(|r| r.bound_bytes).collect();
    let fractions: Vec<f64> = rows.iter().filter_map(|r| r.fraction_of_bound).collect();
    let bytes_p50 = median_u64(bytes);
    C1PhaseSummary {
        phase: phase.to_string(),
        method: method.to_string(),
        samples: rows.len(),
        latency: summarize_us(&lat_us),
        samples_that_built: rows.iter().filter(|r| r.root_builds > 0).count(),
        bound_bytes_p50: bytes_p50,
        bound_ms_p50: bytes_p50.map(|b| b as f64 / MEMORY_BANDWIDTH_BPS * 1e3),
        fraction_of_bound_p50: median_f64(fractions),
        energy,
    }
}

fn trace(phase: &str, sample: usize, idx: usize, latency_ns: u64) -> C1Trace {
    C1Trace {
        phase: phase.to_string(),
        sample,
        changeset_index: idx,
        latency_ns,
        bound_bytes: None,
        bound_ns: None,
        fraction_of_bound: None,
        root_builds: 0,
        new_nodes: 0,
        pages: None,
        entries: None,
    }
}

fn phase_rows(rows: &[C1Trace], phase: &str) -> Vec<C1Trace> {
    rows.iter().filter(|r| r.phase == phase).cloned().collect()
}

fn new_parity(check: &str) -> C1Parity {
    C1Parity {
        check: check.to_string(),
        compared_trees: 0,
        compared_entries: 0,
        mismatched_trees: 0,
        first_mismatch: None,
    }
}

fn record_parity(p: &mut C1Parity, k: usize, git: &[String], syn: &[String]) {
    p.compared_trees += 1;
    p.compared_entries += git.len();
    if let Some(m) = first_mismatch(git, syn) {
        p.mismatched_trees += 1;
        p.first_mismatch.get_or_insert(format!("target {k}: {m:?}"));
    }
}

/// Run the C1 measurement and write `report.json` plus `traces.jsonl` under `out_dir`.
pub fn run_c1(spec: &C1Spec) -> Result<C1Report, String> {
    std::fs::create_dir_all(&spec.work_dir).map_err(|e| format!("mkdir work: {e}"))?;
    let loadavg_start = crate::energy::loadavg();
    let clone = spec.clone_dir.as_path();
    let t = Instant::now();
    let mut pair = ParityPair::open(
        clone,
        &spec.base_commit,
        &spec.work_dir,
        spec.seed,
        spec.agents,
    )?;
    let base_target = TreeTarget::BaseGitCommit(pair.base_oid);
    let listed = fixture::list_base_tree(clone, &spec.base_commit)?;
    let base_files = listed.entries.len();
    let files = {
        let full = fixture::load_full_base(clone, &listed)?;
        fixture::editable_from_full_base(&listed, &full)
    };
    let workload = generate_write_workload(
        spec.seed,
        10_000 + spec.rep,
        spec.agents,
        spec.ops_per_agent,
        &files,
    );
    drop(files);
    let mut pop: Vec<(ChangesetId, String, Proposal)> = Vec::new();
    for p in workload.iter().flatten() {
        let (cs, commit) = pair.apply(p)?;
        pop.push((cs, commit, p.clone()));
    }
    pair.svc.store_mut().sync_wal().map_err(|e| e.to_string())?;
    let populate_s = round3(t.elapsed().as_secs_f64());
    let n = pop.len();
    if n == 0 {
        return Err("empty population".into());
    }

    // 1. Parity, per entry, the base tree and every changeset.
    let mut parity = Vec::new();
    if !spec.skip_parity {
        let mut tree = new_parity(
            "tree entries (mode, type, object id, path, order) vs git ls-tree -r --full-tree",
        );
        let mut diff = new_parity(
            "diff entries (modes, object ids, status, path, order) vs git diff-tree -r --raw --no-renames, base to changeset",
        );
        let (git, syn) = pair.tree_pair(base_target, &spec.base_commit)?;
        record_parity(&mut tree, 0, &git, &syn);
        for (k, (cs, commit, _)) in pop.iter().enumerate() {
            let target = TreeTarget::Changeset(*cs);
            let (git, syn) = pair.tree_pair(target, commit)?;
            record_parity(&mut tree, k + 1, &git, &syn);
            let (git, syn) = pair.diff_pair(target, commit)?;
            record_parity(&mut diff, k + 1, &git, &syn);
        }
        parity.push(tree);
        parity.push(diff);
    }

    // 2. Fresh bounded cache (base pinned, no changeset root memoized).
    pair.svc
        .set_tree_cache_config(TreeCacheConfig {
            max_bytes: spec.cache_bytes,
        })
        .map_err(|e| e.to_string())?;
    let (base_bytes, base_nodes) = pair
        .svc
        .tree_encoded_bytes(base_target, None)
        .map_err(|e| e.to_string())?;
    let mut rng = SplitMix64::derive(spec.seed, &[spec.rep as u64, 0xC1]);
    let mut rows: Vec<C1Trace> = Vec::new();
    let mut phases = Vec::new();
    let mut bound_held = true;
    let check_bound = |pair: &ParityPair, held: &mut bool| {
        if pair.svc.tree_store().stats().total_bytes > spec.cache_bytes {
            *held = false;
        }
    };

    // 3. Cold: every changeset root once, shuffled.
    let mut order: Vec<usize> = (0..n).collect();
    for i in (1..n).rev() {
        order.swap(i, rng.below(i + 1));
    }
    let window = EnergyWindow::start();
    for (s, &i) in order.iter().enumerate() {
        let before = pair.svc.tree_store().stats();
        let start = Instant::now();
        pair.svc
            .tree_digest(TreeTarget::Changeset(pop[i].0), None)
            .map_err(|e| e.to_string())?;
        let ns = start.elapsed().as_nanos() as u64;
        let after = pair.svc.tree_store().stats();
        check_bound(&pair, &mut bound_held);
        let mut r = trace("cold_build", s, i, ns);
        r.root_builds = after.root_builds - before.root_builds;
        r.new_nodes = after.nodes_inserted - before.nodes_inserted;
        let bytes = upserted_bytes(&pop[i].2)
            + (after.encoded_bytes_inserted - before.encoded_bytes_inserted);
        r.bound_bytes = Some(bytes);
        (r.bound_ns, r.fraction_of_bound) = bound(bytes, ns);
        rows.push(r);
    }
    let energy = window.finish();
    phases.push(summarize(
        "cold_build",
        "SynapseService::tree_digest on a changeset whose root is not memoized (engine only): read upserted blobs for Git ids, edit the touched paths, encode and SHA-256 the new nodes",
        &phase_rows(&rows, "cold_build"),
        Some(energy),
    ));

    // 4a. Warm paging at the engine.
    let picks: Vec<usize> = (0..spec.samples).map(|_| rng.below(n)).collect();
    let window = EnergyWindow::start();
    for (s, &i) in picks.iter().enumerate() {
        let target = TreeTarget::Changeset(pop[i].0);
        let (bytes, _) = pair
            .svc
            .tree_encoded_bytes(target, None)
            .map_err(|e| e.to_string())?;
        let before = pair.svc.tree_store().stats();
        let start = Instant::now();
        let (total, first) = pair
            .svc
            .tree_page(target, "", 0, DEFAULT_MAX_PAGE_SIZE, None)
            .map_err(|e| e.to_string())?;
        let mut seen = first.len() as u64;
        let mut pages = 1;
        while seen < total {
            let (_, page) = pair
                .svc
                .tree_page(target, "", seen, DEFAULT_MAX_PAGE_SIZE, None)
                .map_err(|e| e.to_string())?;
            seen += page.len() as u64;
            pages += 1;
        }
        let ns = start.elapsed().as_nanos() as u64;
        let after = pair.svc.tree_store().stats();
        check_bound(&pair, &mut bound_held);
        let mut r = trace("warm_page_engine", s, i, ns);
        r.root_builds = after.root_builds - before.root_builds;
        r.new_nodes = after.nodes_inserted - before.nodes_inserted;
        r.pages = Some(pages);
        r.entries = Some(seen);
        r.bound_bytes = Some(bytes);
        (r.bound_ns, r.fraction_of_bound) = bound(bytes, ns);
        rows.push(r);
    }
    let energy = window.finish();
    phases.push(summarize(
        "warm_page_engine",
        "SynapseService::tree_page, every page of 256 entries of a changeset tree (engine only)",
        &phase_rows(&rows, "warm_page_engine"),
        Some(energy),
    ));

    // 4b. Warm paging at the API (authorization included; signing excluded).
    let reader = pair.ids.agents[0].clone();
    let repo_id = pair.ids.repo_id.clone();
    let mut counter = 0u64;
    for (s, &i) in picks.iter().enumerate() {
        let target = TreeTarget::Changeset(pop[i].0);
        let (bytes, _) = pair
            .svc
            .tree_encoded_bytes(target, None)
            .map_err(|e| e.to_string())?;
        let before = pair.svc.tree_store().stats();
        let (mut cursor, mut snapshot) = (None, None);
        let (mut ns, mut pages, mut entries) = (0u64, 0usize, 0u64);
        loop {
            counter += 1;
            let now = crate::unix_now_ms();
            let payload = TreeQueryPayload {
                target,
                path_prefix: None,
                page: PageRequest {
                    cursor: cursor.clone(),
                    limit: DEFAULT_MAX_PAGE_SIZE,
                    min_visible_seq: None,
                    snapshot_seq: snapshot,
                },
            };
            let req = synapse_arm::build_read_request(
                &reader,
                &repo_id,
                payload,
                &format!("c1/warm-api/{counter}"),
                now,
            )?;
            let start = Instant::now();
            let resp = pair.svc.tree(&req, now).map_err(|e| e.to_string())?;
            ns += start.elapsed().as_nanos() as u64;
            pages += 1;
            entries += resp.items.len() as u64;
            snapshot = Some(resp.snapshot_seq);
            match resp.next_cursor {
                Some(c) => cursor = Some(c),
                None => break,
            }
        }
        let after = pair.svc.tree_store().stats();
        check_bound(&pair, &mut bound_held);
        let mut r = trace("warm_page_api", s, i, ns);
        r.root_builds = after.root_builds - before.root_builds;
        r.new_nodes = after.nodes_inserted - before.nodes_inserted;
        r.pages = Some(pages);
        r.entries = Some(entries);
        r.bound_bytes = Some(bytes);
        (r.bound_ns, r.fraction_of_bound) = bound(bytes, ns);
        rows.push(r);
    }
    phases.push(summarize(
        "warm_page_api",
        "SynapseService::tree, every page (request authorization plus engine; client signing and wire encoding excluded, as Gate 4 api_only)",
        &phase_rows(&rows, "warm_page_api"),
        None,
    ));

    // 5. Warm diff at the engine (no bound derived).
    let diff_picks: Vec<usize> = (0..spec.samples).map(|_| rng.below(n)).collect();
    for (s, &i) in diff_picks.iter().enumerate() {
        let before = pair.svc.tree_store().stats();
        let start = Instant::now();
        let d = pair
            .svc
            .diff_trees(base_target, TreeTarget::Changeset(pop[i].0), None)
            .map_err(|e| e.to_string())?;
        let ns = start.elapsed().as_nanos() as u64;
        let after = pair.svc.tree_store().stats();
        check_bound(&pair, &mut bound_held);
        let mut r = trace("warm_diff_engine", s, i, ns);
        r.root_builds = after.root_builds - before.root_builds;
        r.new_nodes = after.nodes_inserted - before.nodes_inserted;
        r.entries = Some(d.len() as u64);
        rows.push(r);
    }
    phases.push(summarize(
        "warm_diff_engine",
        "SynapseService::diff_trees base to changeset (engine only; skips equal subtrees)",
        &phase_rows(&rows, "warm_diff_engine"),
        None,
    ));

    let cache_after = pair.svc.tree_store().stats();
    if cache_after.high_water_bytes > spec.cache_bytes {
        bound_held = false;
    }
    let report = C1Report {
        spec: spec.clone(),
        base_files,
        base_tree_encoded_bytes: base_bytes,
        base_tree_nodes: base_nodes,
        population_changesets: n,
        populate_s,
        parity,
        memory_bandwidth_bps: MEMORY_BANDWIDTH_BPS,
        phases,
        cache_after,
        cache_bound_held: bound_held,
        peak_rss_self_kib: sample_self()?.maxrss_kib,
        loadavg_start,
        loadavg_end: crate::energy::loadavg(),
        notes: vec![
            "Bound: physical memory bandwidth 273 GB/s (A0). Cold: (upserted blob bytes + new node encoded bytes) / bandwidth. Warm: encoded bytes of the tree's distinct nodes / bandwidth. fraction_of_bound = bound / measured.".into(),
            "Energy windows are whole-phase SPBM readings (provisional, uncalibrated, 10 Hz; see energy.rs refusal rules); no idle baseline is subtracted. A refused window reports no joules.".into(),
            "peak_rss_self_kib covers the whole process: the loaded base blobs, the store, the parity pass, and Git plumbing buffers, not the tree cache alone.".into(),
        ],
    };
    write_jsonl(&spec.out_dir.join("traces.jsonl"), &rows)?;
    write_json(&spec.out_dir.join("report.json"), &report)?;
    Ok(report)
}
