//! WAL recovery timing and the base-tree import probe.
//!
//! Recovery: populate a fresh `SynapseStore` with `N` generated changesets, then time
//! repeated reopens (raw WAL replay, `SynapseStore::open` and `SynapseService::open`), then
//! checkpoint and compact and time reopens again. Reopens run immediately after writing,
//! so the page cache is warm; cold-cache recovery is not measured.
//!
//! Import probe: time the crate's own `import_base_tree_from_git_repo` on the pinned
//! commit and compare its virtual tree with the one built by the harness loader.

use crate::fixture;
use crate::stats::{round3, spread, Spread};
use crate::synapse_arm;
use crate::workload::generate_proposal;
use crate::write_jsonl;
use crate::write_phase::du_total;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::time::Instant;
use synapse_api::{SynapseService, TreeTarget};
use synapse_core::GitOid;
use synapse_store::{FsyncPolicy, IngestOutcome, RecoveryPolicy, StoreLimits, SynapseStore};

/// Input for the recovery cell.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoverySpec {
    pub seed: u64,
    pub sizes: Vec<usize>,
    pub reopen_reps: usize,
    pub clone_dir: PathBuf,
    pub base_commit: String,
    pub cell_dir: PathBuf,
    pub trace_path: PathBuf,
}

/// One timed reopen.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReopenTrace {
    pub changesets: usize,
    pub phase: String,
    pub opener: String,
    pub rep: usize,
    pub open_ms: f64,
    pub ok: bool,
    pub error: Option<String>,
}

/// Results for one store size.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoverySizeResult {
    pub changesets: usize,
    pub populate_ms: f64,
    pub wal_bytes: u64,
    pub store_apparent_bytes: u64,
    pub store_allocated_bytes: u64,
    pub blob_files: usize,
    pub store_open_raw_wal_ms: Option<Spread>,
    pub service_open_raw_wal_ms: Option<Spread>,
    pub checkpoint_compact_ms: f64,
    pub wal_bytes_after_checkpoint: u64,
    pub checkpoint_bytes: u64,
    pub store_open_after_checkpoint_ms: Option<Spread>,
    pub checkpoint_evicted_changesets: usize,
    pub committed_seq_preserved: bool,
    pub state_root_preserved: bool,
    pub reopen_failures: usize,
}

/// Recovery cell output.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoveryResult {
    pub populate_fsync_policy: String,
    pub cache_note: String,
    pub sizes: Vec<RecoverySizeResult>,
}

fn ms(t: Instant) -> f64 {
    round3(t.elapsed().as_secs_f64() * 1000.0)
}

fn file_len(p: &std::path::Path) -> u64 {
    std::fs::metadata(p).map(|m| m.len()).unwrap_or(0)
}

fn count_files(dir: &std::path::Path) -> usize {
    let mut n = 0;
    if let Ok(rd) = std::fs::read_dir(dir) {
        for e in rd.flatten() {
            match e.file_type() {
                Ok(t) if t.is_dir() => n += count_files(&e.path()),
                Ok(t) if t.is_file() => n += 1,
                _ => {}
            }
        }
    }
    n
}

/// Run the recovery cell.
pub fn run_recovery_cell(spec: &RecoverySpec) -> Result<RecoveryResult, String> {
    std::fs::create_dir_all(&spec.cell_dir)
        .map_err(|e| format!("mkdir {}: {e}", spec.cell_dir.display()))?;
    let base = fixture::list_base_tree(&spec.clone_dir, &spec.base_commit)?;
    let files = fixture::load_editable_files(&spec.clone_dir, &base)?;
    let base_oid = GitOid::from_hex(&base.commit_hex).map_err(|e| e.to_string())?;
    let ids = synapse_arm::issue_identities(spec.seed, 1, crate::unix_now_ms())?;
    let populate_policy = FsyncPolicy::BatchWindow { max_records: 1024 };
    let mut traces = Vec::new();
    let mut sizes = Vec::new();

    for &n in &spec.sizes {
        let dir = spec.cell_dir.join(format!("store-{n}"));
        let _ = std::fs::remove_dir_all(&dir);
        let t = Instant::now();
        let (committed, state_root) = {
            let mut store = SynapseStore::open(
                &dir,
                populate_policy,
                RecoveryPolicy::StrictFailClosed,
                StoreLimits::default(),
            )
            .map_err(|e| e.to_string())?;
            for i in 0..n {
                let p = generate_proposal(spec.seed, &[20_000, n as u64], 0, i, &files);
                let req = synapse_arm::build_submit_request(
                    &ids.agents[0],
                    &ids.repo_id,
                    base_oid,
                    &p,
                    &format!("gate4/recovery/{n}/{i}"),
                    crate::unix_now_ms(),
                )?;
                let payload = req.payload;
                match store
                    .ingest_changeset(payload.envelope, &payload.blobs)
                    .map_err(|e| format!("ingest {i}: {e}"))?
                {
                    IngestOutcome::Committed { .. } => {}
                    IngestOutcome::IdempotentDuplicate { .. } => {
                        return Err(format!("unexpected duplicate at {i}"))
                    }
                }
            }
            store.sync_wal().map_err(|e| e.to_string())?;
            (
                store.committed_seq(),
                store.state_root_digest(None).map_err(|e| e.to_string())?,
            )
        };
        let populate_ms = ms(t);
        let wal_bytes = file_len(&dir.join("wal.log"));
        let footprint = du_total(std::slice::from_ref(&dir))?;
        let blob_files = count_files(&dir.join("blobs"));

        let mut failures = 0usize;
        let mut seq_ok = true;
        let mut root_ok = true;
        let mut timed = |phase: &str, opener: &str, out: &mut Vec<f64>| {
            for rep in 0..spec.reopen_reps {
                let t = Instant::now();
                let r: Result<(), String> = if opener == "SynapseStore::open" {
                    SynapseStore::open(
                        &dir,
                        FsyncPolicy::EveryCommit,
                        RecoveryPolicy::StrictFailClosed,
                        StoreLimits::default(),
                    )
                    .map_err(|e| e.to_string())
                    .and_then(|s| {
                        let elapsed = ms(t);
                        out.push(elapsed);
                        seq_ok &= s.committed_seq() == committed;
                        root_ok &=
                            s.state_root_digest(None).map_err(|e| e.to_string())? == state_root;
                        Ok(())
                    })
                } else {
                    SynapseService::open(
                        &dir,
                        ids.repo_id.clone(),
                        FsyncPolicy::EveryCommit,
                        RecoveryPolicy::StrictFailClosed,
                        StoreLimits::default(),
                    )
                    .map_err(|e| e.to_string())
                    .map(|s| {
                        out.push(ms(t));
                        seq_ok &= s.store().committed_seq() == committed;
                    })
                };
                let open_ms = out.last().copied().unwrap_or(0.0);
                if r.is_err() {
                    failures += 1;
                }
                traces.push(ReopenTrace {
                    changesets: n,
                    phase: phase.to_string(),
                    opener: opener.to_string(),
                    rep,
                    open_ms,
                    ok: r.is_ok(),
                    error: r.err(),
                });
            }
        };
        let mut store_raw = Vec::new();
        let mut svc_raw = Vec::new();
        timed("raw_wal", "SynapseStore::open", &mut store_raw);
        timed("raw_wal", "SynapseService::open", &mut svc_raw);

        let t = Instant::now();
        let compaction = {
            let mut store = SynapseStore::open(
                &dir,
                FsyncPolicy::EveryCommit,
                RecoveryPolicy::StrictFailClosed,
                StoreLimits::default(),
            )
            .map_err(|e| e.to_string())?;
            store
                .checkpoint_and_compact(crate::unix_now_ms())
                .map_err(|e| format!("checkpoint_and_compact: {e}"))?
        };
        let checkpoint_compact_ms = ms(t);
        let wal_after = file_len(&dir.join("wal.log"));
        let ckpt_bytes = file_len(&dir.join("checkpoint.v1"));
        let mut store_ckpt = Vec::new();
        timed("after_checkpoint", "SynapseStore::open", &mut store_ckpt);

        sizes.push(RecoverySizeResult {
            changesets: n,
            populate_ms,
            wal_bytes,
            store_apparent_bytes: footprint.apparent_bytes,
            store_allocated_bytes: footprint.allocated_bytes,
            blob_files,
            store_open_raw_wal_ms: spread(&store_raw),
            service_open_raw_wal_ms: spread(&svc_raw),
            checkpoint_compact_ms,
            checkpoint_evicted_changesets: compaction.evicted_changesets,
            wal_bytes_after_checkpoint: wal_after,
            checkpoint_bytes: ckpt_bytes,
            store_open_after_checkpoint_ms: spread(&store_ckpt),
            committed_seq_preserved: seq_ok,
            state_root_preserved: root_ok,
            reopen_failures: failures,
        });
        let _ = std::fs::remove_dir_all(&dir);
    }
    write_jsonl(&spec.trace_path, &traces)?;
    Ok(RecoveryResult {
        populate_fsync_policy: "BatchWindow { max_records: 1024 }, then sync_wal".into(),
        cache_note: "reopens follow population immediately (warm page cache)".into(),
        sizes,
    })
}

/// Input for the base-tree import probe.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImportProbeSpec {
    pub seed: u64,
    pub clone_dir: PathBuf,
    pub base_commit: String,
    pub cell_dir: PathBuf,
}

/// Import probe output.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImportProbeResult {
    pub files: usize,
    pub bytes: u64,
    pub official_import_ms: f64,
    pub harness_load_ms: f64,
    pub harness_register_ms: f64,
    pub virtual_trees_identical: bool,
    pub official_error: Option<String>,
}

/// Time `import_base_tree_from_git_repo` and compare with the harness loader.
pub fn run_import_probe(spec: &ImportProbeSpec) -> Result<ImportProbeResult, String> {
    std::fs::create_dir_all(&spec.cell_dir)
        .map_err(|e| format!("mkdir {}: {e}", spec.cell_dir.display()))?;
    let ids = synapse_arm::issue_identities(spec.seed, 1, crate::unix_now_ms())?;
    let open = |name: &str| {
        synapse_arm::open_service(
            &spec.cell_dir.join(name),
            &ids,
            FsyncPolicy::EveryCommit,
            RecoveryPolicy::StrictFailClosed,
        )
    };

    let mut official = open("official")?;
    let t = Instant::now();
    let imported = official.import_base_tree_from_git_repo(&spec.clone_dir, &spec.base_commit);
    let official_import_ms = ms(t);

    let t = Instant::now();
    let base = fixture::list_base_tree(&spec.clone_dir, &spec.base_commit)?;
    let full = fixture::load_full_base(&spec.clone_dir, &base)?;
    let harness_load_ms = ms(t);
    let files = full.len();
    let bytes = full.iter().map(|(_, _, b)| b.len() as u64).sum();
    let mut harness = open("harness")?;
    let t = Instant::now();
    let oid = synapse_arm::register_base(&mut harness, &spec.base_commit, full)?;
    let harness_register_ms = ms(t);

    let (identical, official_error) = match imported {
        Ok(official_oid) => {
            let a = official
                .materialize_virtual_tree(TreeTarget::BaseGitCommit(official_oid), None)
                .map_err(|e| e.to_string())?;
            let b = harness
                .materialize_virtual_tree(TreeTarget::BaseGitCommit(oid), None)
                .map_err(|e| e.to_string())?;
            (official_oid == oid && a == b, None)
        }
        Err(e) => (false, Some(e.to_string())),
    };
    let _ = std::fs::remove_dir_all(&spec.cell_dir);
    Ok(ImportProbeResult {
        files,
        bytes,
        official_import_ms,
        harness_load_ms,
        harness_register_ms,
        virtual_trees_identical: identical,
        official_error,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fixture::test_support::{make_fixture_repo, temp_dir};
    use crate::fixture::{clone_no_checkout, configure_bench_clone};

    #[test]
    fn recovery_and_import_probe_preserve_state_on_small_fixture() {
        let root = temp_dir("recovery");
        let commit = make_fixture_repo(&root, 16, 20);
        let clone = root.join("clone");
        clone_no_checkout(&root.join("fixture"), &clone).unwrap();
        configure_bench_clone(&clone).unwrap();
        let r = run_recovery_cell(&RecoverySpec {
            seed: 5,
            sizes: vec![20],
            reopen_reps: 2,
            clone_dir: clone.clone(),
            base_commit: commit.clone(),
            cell_dir: root.join("cell"),
            trace_path: root.join("recovery.jsonl"),
        })
        .unwrap();
        let s = &r.sizes[0];
        assert_eq!(s.reopen_failures, 0);
        assert!(s.committed_seq_preserved && s.state_root_preserved);
        assert_eq!(s.store_open_raw_wal_ms.as_ref().unwrap().reps, 2);
        let p = run_import_probe(&ImportProbeSpec {
            seed: 5,
            clone_dir: clone,
            base_commit: commit,
            cell_dir: root.join("probe"),
        })
        .unwrap();
        assert!(p.virtual_trees_identical, "{:?}", p.official_error);
        let _ = std::fs::remove_dir_all(&root);
    }
}
