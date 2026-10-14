//! Neutral conformance suites with recorded pass/fail per case.
//!
//! * `wal`: crash and torn-write recovery of `SynapseStore` (fault injection hooks).
//! * `git`: deterministic Git materialization, `git fsck`, fetch/checkout byte parity,
//!   and human-branch fast-forward enforcement (`synapse-git`).
//! * `radicle`: delegate-threshold canonical promotion and refusals (`synapse-radicle`),
//!   plus an optional read-only check of a live Radicle storage repository.
//!
//! Each case compares observed behaviour with its documented expectation and records
//! the outcome. A harness error inside a case marks that case failed; it never aborts
//! the suite, and no outcome is hard-coded.

use crate::fixture::configure_bench_clone;
use crate::gitcmd::{git_line, git_ok, run_git};
use crate::path_str;
use crate::synapse_arm::{self, BenchIdentities};
use crate::workload::{EditOp, FileEdit, Proposal};
use ed25519_dalek::SigningKey;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use synapse_api::{SynapseService, TreeTarget};
use synapse_core::{
    encode_did_key_ed25519, BlobDigest, ChangesetEnvelope, ChangesetId, FileMode, GitOid,
    IdempotencyKey, MutationOp, PathMutation, RefusalCode, RepoId, WalSeq,
    SYNAPSE_ENVELOPE_VERSION,
};
use synapse_git::{
    advance_human_branch_fast_forward, materialize_changeset_to_git, GitProjectionIndex,
};
use synapse_radicle::{
    load_radicle_state_from_bare_repo, CanonicalPromotionEngine, DelegateSigrefs,
    PromotionCandidate, RadicleIdentityDoc, RadiclePayloadMap, RadicleProjectPayload,
    ReconciliationState,
};
use synapse_store::{
    FaultInjection, FsyncPolicy, IngestOutcome, RecoveryPolicy, StoreLimits, SynapseStore,
};

/// Outcome of one case.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CaseOutcome {
    Pass,
    Fail,
    Skipped,
}

/// One recorded conformance case.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaseResult {
    pub suite: String,
    pub case: String,
    pub expected: String,
    pub observed: String,
    pub outcome: CaseOutcome,
}

/// All cases of one suite.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SuiteResult {
    pub suite: String,
    pub cases: Vec<CaseResult>,
    pub passed: usize,
    pub failed: usize,
    pub skipped: usize,
}

impl SuiteResult {
    fn from_cases(suite: &str, cases: Vec<CaseResult>) -> Self {
        let count = |o: CaseOutcome| cases.iter().filter(|c| c.outcome == o).count();
        Self {
            suite: suite.to_string(),
            passed: count(CaseOutcome::Pass),
            failed: count(CaseOutcome::Fail),
            skipped: count(CaseOutcome::Skipped),
            cases,
        }
    }
}

/// Observation returned by a case body: `(passed, observed description)`.
type Observation = Result<(bool, String), String>;

fn record(
    suite: &str,
    case: &str,
    expected: &str,
    body: impl FnOnce() -> Observation,
) -> CaseResult {
    let (outcome, observed) = match body() {
        Ok((true, obs)) => (CaseOutcome::Pass, obs),
        Ok((false, obs)) => (CaseOutcome::Fail, obs),
        Err(e) => (CaseOutcome::Fail, format!("harness error: {e}")),
    };
    CaseResult {
        suite: suite.to_string(),
        case: case.to_string(),
        expected: expected.to_string(),
        observed,
        outcome,
    }
}

fn skipped(suite: &str, case: &str, expected: &str, reason: &str) -> CaseResult {
    CaseResult {
        suite: suite.to_string(),
        case: case.to_string(),
        expected: expected.to_string(),
        observed: reason.to_string(),
        outcome: CaseOutcome::Skipped,
    }
}

fn code_of<T>(r: &Result<T, synapse_core::SynapseError>) -> Option<RefusalCode> {
    r.as_ref().err().map(|e| e.code)
}

// ---------------------------------------------------------------------------------------
// WAL suite
// ---------------------------------------------------------------------------------------

const WAL: &str = "wal";

fn wal_key() -> SigningKey {
    synapse_arm::deterministic_key(0x57A1, "wal-conformance", 0)
}

/// Content-addressed blobs supplied with an envelope.
type BlobSet = Vec<(BlobDigest, Vec<u8>)>;

fn wal_envelope(i: u64) -> Result<(ChangesetEnvelope, BlobSet), String> {
    let key = wal_key();
    let content = format!("wal conformance changeset {i}\n").into_bytes();
    let digest = BlobDigest::compute(&content);
    let mut env = ChangesetEnvelope {
        version: SYNAPSE_ENVELOPE_VERSION,
        repo_id: RepoId::new("aien-spark/wal-conformance").map_err(|e| e.to_string())?,
        base_git_oid: GitOid::compute_blob(b"wal conformance base"),
        parent_changesets: Vec::new(),
        author_did: String::new(),
        idempotency_key: IdempotencyKey::from_label(&format!("wal-conformance-{i}")),
        created_at_ms: 1_700_000_000_000 + i,
        intent_summary: format!("wal conformance {i}"),
        mutations: vec![PathMutation {
            path: format!("conformance/file-{i}.txt"),
            op: MutationOp::Upsert {
                mode: FileMode::Regular644,
                blob_digest: digest,
                size_bytes: content.len() as u64,
            },
        }],
        evidence_receipts: Vec::new(),
        signature: Vec::new(),
    };
    env.sign(&key);
    Ok((env, vec![(digest, content)]))
}

fn open_store(dir: &Path, policy: RecoveryPolicy) -> synapse_core::SynapseResult<SynapseStore> {
    SynapseStore::open(
        dir,
        FsyncPolicy::EveryCommit,
        policy,
        StoreLimits::default(),
    )
}

/// State acknowledged before a fault is injected.
struct Acked {
    ids: Vec<ChangesetId>,
    blobs: BlobSet,
    state_root: [u8; 32],
    committed: WalSeq,
    wal_bytes: Vec<u8>,
}

fn seed_store(dir: &Path) -> Result<Acked, String> {
    let _ = std::fs::remove_dir_all(dir);
    let mut store = open_store(dir, RecoveryPolicy::StrictFailClosed).map_err(|e| e.to_string())?;
    let mut ids = Vec::new();
    let mut all_blobs = Vec::new();
    for i in 0..3 {
        let (env, blobs) = wal_envelope(i)?;
        match store
            .ingest_changeset(env, &blobs)
            .map_err(|e| e.to_string())?
        {
            IngestOutcome::Committed { changeset_id, .. } => ids.push(changeset_id),
            IngestOutcome::IdempotentDuplicate { .. } => {
                return Err("unexpected idempotent duplicate while seeding".into())
            }
        }
        all_blobs.extend(blobs);
    }
    let state_root = store.state_root_digest(None).map_err(|e| e.to_string())?;
    let committed = store.committed_seq();
    drop(store);
    let wal_bytes = std::fs::read(dir.join("wal.log")).map_err(|e| format!("read wal.log: {e}"))?;
    Ok(Acked {
        ids,
        blobs: all_blobs,
        state_root,
        committed,
        wal_bytes,
    })
}

fn acked_intact(store: &SynapseStore, acked: &Acked) -> Result<bool, String> {
    if store.committed_seq() != acked.committed {
        return Ok(false);
    }
    for id in &acked.ids {
        if store.get_changeset(*id, None, None).is_err() {
            return Ok(false);
        }
    }
    for (d, bytes) in &acked.blobs {
        match store.get_blob_visible(*d, None, None) {
            Ok(b) if &b == bytes => {}
            _ => return Ok(false),
        }
    }
    Ok(store.state_root_digest(None).map_err(|e| e.to_string())? == acked.state_root)
}

fn wal_prefix_unchanged(dir: &Path, acked: &Acked) -> Result<bool, String> {
    let now = std::fs::read(dir.join("wal.log")).map_err(|e| format!("read wal.log: {e}"))?;
    Ok(now.len() >= acked.wal_bytes.len() && now[..acked.wal_bytes.len()] == acked.wal_bytes[..])
}

/// Seed, inject `fault` on the next ingest, and return (ingest refusal code, acked state).
fn inject(
    dir: &Path,
    fault: FaultInjection,
) -> Result<(Option<RefusalCode>, Acked, ChangesetId), String> {
    let acked = seed_store(dir)?;
    let mut store = open_store(dir, RecoveryPolicy::StrictFailClosed).map_err(|e| e.to_string())?;
    store.set_fault_injection(fault);
    let (env, blobs) = wal_envelope(10)?;
    let id = env.compute_id();
    let r = store.ingest_changeset(env, &blobs);
    Ok((code_of(&r), acked, id))
}

fn torn_refusal_case(work: &Path, name: &str, fault: FaultInjection) -> CaseResult {
    record(
        WAL,
        name,
        "faulted append refused with WalTornFrame; StrictFailClosed reopen refuses with WalTornFrame; acknowledged WAL prefix unchanged",
        || {
            let dir = work.join(name);
            let (ingest_code, acked, _) = inject(&dir, fault)?;
            let strict = open_store(&dir, RecoveryPolicy::StrictFailClosed);
            let strict_code = code_of(&strict);
            drop(strict);
            let prefix = wal_prefix_unchanged(&dir, &acked)?;
            Ok((
                ingest_code == Some(RefusalCode::WalTornFrame)
                    && strict_code == Some(RefusalCode::WalTornFrame)
                    && prefix,
                format!(
                    "ingest refusal {ingest_code:?}; strict reopen {strict_code:?}; acknowledged prefix unchanged: {prefix}"
                ),
            ))
        },
    )
}

fn torn_recovery_case(work: &Path, name: &str, fault: FaultInjection) -> CaseResult {
    record(
        WAL,
        name,
        "TruncateTornTail reopen succeeds, truncates exactly 1 torn frame, acknowledged changesets/blobs/state root intact, unacknowledged changeset absent, next append and strict reopen succeed",
        || {
            let dir = work.join(name);
            let (_, acked, unacked_id) = inject(&dir, fault)?;
            let mut store =
                open_store(&dir, RecoveryPolicy::TruncateTornTail).map_err(|e| e.to_string())?;
            let truncated = store.torn_frames_truncated_on_open();
            let intact = acked_intact(&store, &acked)?;
            let absent = store.get_changeset(unacked_id, None, None).is_err();
            let (env, blobs) = wal_envelope(11)?;
            let next_ok = store.ingest_changeset(env, &blobs).is_ok();
            drop(store);
            let strict = open_store(&dir, RecoveryPolicy::StrictFailClosed);
            let strict_ok = strict
                .as_ref()
                .map(|s| s.committed_seq() == acked.committed.next())
                .unwrap_or(false);
            Ok((
                truncated == 1 && intact && absent && next_ok && strict_ok,
                format!(
                    "truncated frames {truncated}; acknowledged intact {intact}; unacknowledged absent {absent}; next append ok {next_ok}; strict reopen at seq+1 ok {strict_ok}"
                ),
            ))
        },
    )
}

fn corruption_case(
    work: &Path,
    name: &str,
    fault: FaultInjection,
    code: RefusalCode,
) -> CaseResult {
    let expected = format!(
        "both StrictFailClosed and TruncateTornTail reopens refuse with {code:?} (corruption is never truncated away); acknowledged WAL prefix unchanged"
    );
    record(WAL, name, &expected, || {
        let dir = work.join(name);
        let (ingest_code, acked, _) = inject(&dir, fault)?;
        let strict = code_of(&open_store(&dir, RecoveryPolicy::StrictFailClosed));
        let lenient = code_of(&open_store(&dir, RecoveryPolicy::TruncateTornTail));
        let prefix = wal_prefix_unchanged(&dir, &acked)?;
        Ok((
            strict == Some(code) && lenient == Some(code) && prefix,
            format!(
                "faulted ingest result {ingest_code:?} (None = acknowledged); strict reopen {strict:?}; truncate-tail reopen {lenient:?}; acknowledged prefix unchanged {prefix}"
            ),
        ))
    })
}

/// Run the WAL crash and torn-write recovery suite under `work`.
pub fn run_wal_suite(work: &Path) -> SuiteResult {
    let mut cases = Vec::new();
    cases.push(record(
        WAL,
        "clean_reopen_baseline",
        "StrictFailClosed reopen of an undamaged store succeeds with all acknowledged state intact (positive control)",
        || {
            let dir = work.join("clean_reopen_baseline");
            let acked = seed_store(&dir)?;
            let store =
                open_store(&dir, RecoveryPolicy::StrictFailClosed).map_err(|e| e.to_string())?;
            let intact = acked_intact(&store, &acked)?;
            Ok((intact, format!("reopen ok; acknowledged intact {intact}")))
        },
    ));
    cases.push(record(
        WAL,
        "crash_after_blob_write_before_wal_append",
        "append refused with IoFailure; StrictFailClosed reopen succeeds; unacknowledged changeset absent; acknowledged state intact",
        || {
            let dir = work.join("crash_after_blob_write_before_wal_append");
            let (code, acked, id) = inject(&dir, FaultInjection::CrashAfterBlobWriteBeforeWalAppend)?;
            let store =
                open_store(&dir, RecoveryPolicy::StrictFailClosed).map_err(|e| e.to_string())?;
            let absent = store.get_changeset(id, None, None).is_err();
            let intact = acked_intact(&store, &acked)?;
            Ok((
                code == Some(RefusalCode::IoFailure) && absent && intact,
                format!("ingest refusal {code:?}; unacknowledged absent {absent}; acknowledged intact {intact}"),
            ))
        },
    ));
    let header = FaultInjection::TornWalHeaderWrite { bytes_written: 40 };
    let payload = FaultInjection::TornWalPayloadWrite { bytes_written: 10 };
    cases.push(torn_refusal_case(
        work,
        "torn_header_strict_refuses",
        header,
    ));
    cases.push(torn_recovery_case(
        work,
        "torn_header_truncate_recovers",
        header,
    ));
    cases.push(torn_refusal_case(
        work,
        "torn_payload_strict_refuses",
        payload,
    ));
    cases.push(torn_recovery_case(
        work,
        "torn_payload_truncate_recovers",
        payload,
    ));
    cases.push(corruption_case(
        work,
        "crc_corruption_refused",
        FaultInjection::CorruptNextWalCrc,
        RefusalCode::WalCrcMismatch,
    ));
    cases.push(corruption_case(
        work,
        "chain_corruption_refused",
        FaultInjection::CorruptNextWalChain,
        RefusalCode::WalChainMismatch,
    ));
    cases.push(corruption_case(
        work,
        "sequence_gap_refused",
        FaultInjection::InjectNextWalSequenceGap,
        RefusalCode::WalSequenceGap,
    ));
    cases.push(corruption_case(
        work,
        "duplicate_sequence_refused",
        FaultInjection::InjectDuplicateWalSequence,
        RefusalCode::WalSequenceGap,
    ));
    cases.push(record(
        WAL,
        "committed_blob_bitflip_refused",
        "flipping one byte of a committed blob file makes StrictFailClosed reopen refuse with BlobDigestMismatch",
        || {
            let dir = work.join("committed_blob_bitflip_refused");
            let acked = seed_store(&dir)?;
            let (digest, _) = acked.blobs.first().ok_or("no seeded blob")?;
            let hex = digest.to_hex();
            let path = dir.join("blobs").join(&hex[0..2]).join(&hex);
            let mut bytes = std::fs::read(&path).map_err(|e| format!("read blob: {e}"))?;
            bytes[0] ^= 0x01;
            std::fs::write(&path, bytes).map_err(|e| format!("write blob: {e}"))?;
            let code = code_of(&open_store(&dir, RecoveryPolicy::StrictFailClosed));
            Ok((
                code == Some(RefusalCode::BlobDigestMismatch),
                format!("strict reopen {code:?}"),
            ))
        },
    ));
    SuiteResult::from_cases(WAL, cases)
}

// ---------------------------------------------------------------------------------------
// Git suite
// ---------------------------------------------------------------------------------------

const GIT: &str = "git";

struct GitFixture {
    base_repo: PathBuf,
    base_commit: String,
    svc: SynapseService,
    c1: ChangesetId,
    c2: ChangesetId,
    c3: ChangesetId,
}

fn upsert(path: &str, body: &str, mode: FileMode) -> FileEdit {
    FileEdit {
        path: path.to_string(),
        op: EditOp::Upsert {
            mode,
            content: Arc::new(body.as_bytes().to_vec()),
        },
    }
}

fn proposal(index: usize, mut edits: Vec<FileEdit>) -> Proposal {
    edits.sort_by(|a, b| a.path.cmp(&b.path));
    Proposal {
        agent: 0,
        index,
        summary: format!("git conformance changeset {index}"),
        edits,
    }
}

fn submit(
    svc: &mut SynapseService,
    ids: &BenchIdentities,
    base: GitOid,
    parents: Vec<ChangesetId>,
    p: &Proposal,
) -> Result<ChangesetId, String> {
    let now = crate::unix_now_ms();
    let req = synapse_arm::build_submit_request_with_parents(
        &ids.agents[0],
        &ids.repo_id,
        base,
        parents,
        p,
        &format!("git-conformance-{}", p.index),
        now,
    )?;
    match svc.submit(&req, now).map_err(|e| e.to_string())? {
        IngestOutcome::Committed { changeset_id, .. }
        | IngestOutcome::IdempotentDuplicate { changeset_id, .. } => Ok(changeset_id),
    }
}

fn git_fixture(work: &Path) -> Result<GitFixture, String> {
    let base_repo = work.join("git-base");
    let _ = std::fs::remove_dir_all(&base_repo);
    std::fs::create_dir_all(base_repo.join("src/net")).map_err(|e| e.to_string())?;
    std::fs::create_dir_all(base_repo.join("docs")).map_err(|e| e.to_string())?;
    std::fs::create_dir_all(base_repo.join("scripts")).map_err(|e| e.to_string())?;
    git_ok(&base_repo, &[], &[], &["init", "-q", "-b", "main"], None)?;
    configure_bench_clone(&base_repo)?;
    let files = [
        ("README.md", "# conformance base\n"),
        ("src/lib.rs", "pub mod net;\n"),
        ("src/net/http.rs", "pub fn serve() {}\n"),
        ("docs/a.md", "doc a\n"),
        ("scripts/run.sh", "#!/bin/sh\necho base\n"),
    ];
    for (p, body) in files {
        std::fs::write(base_repo.join(p), body).map_err(|e| e.to_string())?;
    }
    let script = base_repo.join("scripts/run.sh");
    let mut perm = std::fs::metadata(&script)
        .map_err(|e| e.to_string())?
        .permissions();
    std::os::unix::fs::PermissionsExt::set_mode(&mut perm, 0o755);
    std::fs::set_permissions(&script, perm).map_err(|e| e.to_string())?;
    git_ok(&base_repo, &[], &[], &["add", "-A"], None)?;
    git_ok(
        &base_repo,
        &[],
        &[],
        &["commit", "-q", "-m", "conformance base"],
        None,
    )?;
    let base_commit = git_line(&base_repo, &["rev-parse", "HEAD"])?;

    let ids = synapse_arm::issue_identities(0x617, 1, crate::unix_now_ms())?;
    let mut svc = synapse_arm::open_service(
        &work.join("git-svc"),
        &ids,
        FsyncPolicy::EveryCommit,
        RecoveryPolicy::StrictFailClosed,
    )?;
    let base_oid = svc
        .import_base_tree_from_git_repo(&base_repo, "HEAD")
        .map_err(|e| e.to_string())?;
    let p1 = proposal(
        1,
        vec![
            upsert(
                "src/lib.rs",
                "pub mod net;\npub mod store;\n",
                FileMode::Regular644,
            ),
            upsert("src/store.rs", "pub struct Wal;\n", FileMode::Regular644),
            FileEdit {
                path: "docs/a.md".into(),
                op: EditOp::Delete,
            },
        ],
    );
    let p2 = proposal(
        2,
        vec![
            upsert("README.md", "# conformance stacked\n", FileMode::Regular644),
            upsert(
                "scripts/new.sh",
                "#!/bin/sh\necho new\n",
                FileMode::Executable755,
            ),
        ],
    );
    let p3 = proposal(
        3,
        vec![upsert(
            "src/lib.rs",
            "pub mod net;\npub mod other;\n",
            FileMode::Regular644,
        )],
    );
    let c1 = submit(&mut svc, &ids, base_oid, Vec::new(), &p1)?;
    let c2 = submit(&mut svc, &ids, base_oid, vec![c1], &p2)?;
    let c3 = submit(&mut svc, &ids, base_oid, Vec::new(), &p3)?;
    Ok(GitFixture {
        base_repo,
        base_commit,
        svc,
        c1,
        c2,
        c3,
    })
}

fn bare_clone(src: &Path, dest: &Path) -> Result<(), String> {
    let _ = std::fs::remove_dir_all(dest);
    let parent = dest.parent().ok_or("destination has no parent")?;
    git_ok(
        parent,
        &[],
        &[],
        &["clone", "--bare", "-q", path_str(src)?, path_str(dest)?],
        None,
    )?;
    Ok(())
}

fn copy_dir(src: &Path, dst: &Path) -> Result<(), String> {
    std::fs::create_dir_all(dst).map_err(|e| format!("mkdir {}: {e}", dst.display()))?;
    for entry in std::fs::read_dir(src).map_err(|e| format!("read_dir {}: {e}", src.display()))? {
        let entry = entry.map_err(|e| e.to_string())?;
        let ty = entry.file_type().map_err(|e| e.to_string())?;
        let target = dst.join(entry.file_name());
        if ty.is_dir() {
            copy_dir(&entry.path(), &target)?;
        } else if ty.is_file() {
            std::fs::copy(entry.path(), &target)
                .map_err(|e| format!("copy {}: {e}", entry.path().display()))?;
        }
    }
    Ok(())
}

fn walk_files(
    root: &Path,
    rel: &str,
    out: &mut BTreeMap<String, (bool, Vec<u8>)>,
) -> Result<(), String> {
    let dir = if rel.is_empty() {
        root.to_path_buf()
    } else {
        root.join(rel)
    };
    for entry in std::fs::read_dir(&dir).map_err(|e| format!("read_dir {}: {e}", dir.display()))? {
        let entry = entry.map_err(|e| e.to_string())?;
        let name = entry.file_name().to_string_lossy().to_string();
        if rel.is_empty() && name == ".git" {
            continue;
        }
        let path = if rel.is_empty() {
            name
        } else {
            format!("{rel}/{name}")
        };
        let ty = entry.file_type().map_err(|e| e.to_string())?;
        if ty.is_dir() {
            walk_files(root, &path, out)?;
        } else {
            let meta = entry.metadata().map_err(|e| e.to_string())?;
            let exec = std::os::unix::fs::PermissionsExt::mode(&meta.permissions()) & 0o111 != 0;
            let bytes = std::fs::read(entry.path()).map_err(|e| e.to_string())?;
            out.insert(path, (exec, bytes));
        }
    }
    Ok(())
}

/// Run the Git materialization suite under `work`.
pub fn run_git_suite(work: &Path) -> SuiteResult {
    let mut cases = Vec::new();
    let mut fx = match git_fixture(work) {
        Ok(fx) => fx,
        Err(e) => {
            cases.push(record(GIT, "fixture_setup", "fixture builds", || {
                Err(e.clone())
            }));
            return SuiteResult::from_cases(GIT, cases);
        }
    };
    let t1 = work.join("target-1.git");
    let t2 = work.join("target-2.git");
    let mut index = GitProjectionIndex::new();
    let mut c2_commit: Option<GitOid> = None;
    let mut c1_commit: Option<GitOid> = None;

    cases.push(record(
        GIT,
        "deterministic_rematerialization",
        "materializing the same stacked changeset into two fresh repositories yields identical commit and tree OIDs",
        || {
            bare_clone(&fx.base_repo, &t1)?;
            bare_clone(&fx.base_repo, &t2)?;
            let m1 = materialize_changeset_to_git(&mut fx.svc, &mut index, &t1, fx.c2, Some("conformance"), None)
                .map_err(|e| e.to_string())?;
            let mut index2 = GitProjectionIndex::new();
            let m2 = materialize_changeset_to_git(&mut fx.svc, &mut index2, &t2, fx.c2, None, None)
                .map_err(|e| e.to_string())?;
            c2_commit = Some(m1.commit_oid);
            c1_commit = index.commit_for_changeset(fx.c1);
            Ok((
                m1.commit_oid == m2.commit_oid && m1.tree_oid == m2.tree_oid,
                format!("commit {} vs {}; tree {} vs {}", m1.commit_oid, m2.commit_oid, m1.tree_oid, m2.tree_oid),
            ))
        },
    ));

    cases.push(record(
        GIT,
        "fsck_full_strict_clean",
        "`git fsck --full --strict` exits 0 on the materialized repository",
        || {
            let run = run_git(&t1, &[], &[], &["fsck", "--full", "--strict"], None)?;
            Ok((
                run.code == Some(0),
                format!("exit {:?} {}", run.code, run.stderr_tail()),
            ))
        },
    ));

    cases.push(record(
        GIT,
        "fsck_detects_corrupted_object",
        "negative control: overwriting one materialized loose object makes `git fsck --full --strict` exit non-zero",
        || {
            let commit = c2_commit.ok_or("no materialized commit")?;
            let t3 = work.join("target-3-corrupt.git");
            let _ = std::fs::remove_dir_all(&t3);
            copy_dir(&t1, &t3)?;
            let hex = commit.to_hex();
            let obj = t3.join("objects").join(&hex[0..2]).join(&hex[2..]);
            let mut perm = std::fs::metadata(&obj).map_err(|e| format!("stat {}: {e}", obj.display()))?.permissions();
            std::os::unix::fs::PermissionsExt::set_mode(&mut perm, 0o644);
            std::fs::set_permissions(&obj, perm).map_err(|e| e.to_string())?;
            std::fs::write(&obj, b"not a zlib stream").map_err(|e| e.to_string())?;
            let run = run_git(&t3, &[], &[], &["fsck", "--full", "--strict"], None)?;
            Ok((run.code.is_some_and(|c| c != 0), format!("exit {:?}", run.code)))
        },
    ));

    cases.push(record(
        GIT,
        "fetch_checkout_byte_parity",
        "fetching the changeset ref into a new repository and checking it out yields exactly the Synapse virtual tree (paths, bytes, executable bits)",
        || {
            let commit = c2_commit.ok_or("no materialized commit")?;
            let dst = work.join("fetch-check");
            let _ = std::fs::remove_dir_all(&dst);
            std::fs::create_dir_all(&dst).map_err(|e| e.to_string())?;
            git_ok(&dst, &[], &[], &["init", "-q"], None)?;
            let refspec = format!("{}:refs/heads/check", synapse_git::changeset_git_ref(fx.c2));
            git_ok(&dst, &[], &[], &["fetch", "-q", path_str(&t1)?, &refspec], None)?;
            git_ok(&dst, &[], &[], &["checkout", "-q", "check"], None)?;
            let head = git_line(&dst, &["rev-parse", "HEAD"])?;
            let mut on_disk = BTreeMap::new();
            walk_files(&dst, "", &mut on_disk)?;
            let vt = fx
                .svc
                .materialize_virtual_tree(TreeTarget::Changeset(fx.c2), None)
                .map_err(|e| e.to_string())?;
            let mut expected = BTreeMap::new();
            for (path, entry) in &vt {
                let bytes = fx.svc.read_blob_bytes(entry.blob_digest, None).map_err(|e| e.to_string())?;
                expected.insert(path.clone(), (entry.mode == FileMode::Executable755, bytes));
            }
            Ok((
                head == commit.to_hex() && on_disk == expected,
                format!("checked out {head}; {} files on disk vs {} in virtual tree; identical {}", on_disk.len(), expected.len(), on_disk == expected),
            ))
        },
    ));

    cases.push(record(
        GIT,
        "materialized_diff_matches_changeset_paths",
        "`git diff-tree -r --name-status <base> <C1>` lists exactly the changeset's mutations (unchanged paths reproduce identical tree objects)",
        || {
            let c1 = c1_commit.ok_or("no materialized parent commit")?;
            let out = git_ok(&t1, &[], &[], &["diff-tree", "-r", "--name-status", &fx.base_commit, &c1.to_hex()], None)?;
            let got: Vec<String> = String::from_utf8_lossy(&out).lines().map(|l| l.replace('\t', " ")).collect();
            let want = vec!["D docs/a.md".to_string(), "M src/lib.rs".to_string(), "A src/store.rs".to_string()];
            Ok((got == want, format!("{got:?}")))
        },
    ));

    cases.push(record(
        GIT,
        "fast_forward_human_branch_allowed",
        "advancing refs/heads/main from the base to the stacked descendant succeeds (positive control)",
        || {
            let commit = c2_commit.ok_or("no materialized commit")?;
            let r = advance_human_branch_fast_forward(&t1, "main", commit);
            let head = git_line(&t1, &["rev-parse", "refs/heads/main"])?;
            Ok((r.is_ok() && head == commit.to_hex(), format!("result {:?}; main at {head}", code_of(&r))))
        },
    ));

    cases.push(record(
        GIT,
        "non_fast_forward_human_branch_refused",
        "advancing refs/heads/main to a sibling changeset commit is refused with GitRefNonFastForward and main is unchanged",
        || {
            let before = git_line(&t1, &["rev-parse", "refs/heads/main"])?;
            let m3 = materialize_changeset_to_git(&mut fx.svc, &mut index, &t1, fx.c3, None, None)
                .map_err(|e| e.to_string())?;
            let r = advance_human_branch_fast_forward(&t1, "main", m3.commit_oid);
            let after = git_line(&t1, &["rev-parse", "refs/heads/main"])?;
            Ok((
                code_of(&r) == Some(RefusalCode::GitRefNonFastForward) && before == after,
                format!("result {:?}; main before {before} after {after}", code_of(&r)),
            ))
        },
    ));
    SuiteResult::from_cases(GIT, cases)
}

// ---------------------------------------------------------------------------------------
// Radicle suite
// ---------------------------------------------------------------------------------------

const RAD: &str = "radicle";

fn rad_doc(delegates: &[SigningKey], threshold: usize) -> RadicleIdentityDoc {
    RadicleIdentityDoc {
        delegates: delegates
            .iter()
            .map(|k| encode_did_key_ed25519(&k.verifying_key().to_bytes()))
            .collect(),
        payload: RadiclePayloadMap {
            project: RadicleProjectPayload {
                default_branch: "main".into(),
                description: String::new(),
                name: "gate4-conformance".into(),
            },
        },
        threshold,
    }
}

fn signed(key: &SigningKey, oid: GitOid) -> DelegateSigrefs {
    let mut refs = BTreeMap::new();
    refs.insert("refs/heads/main".to_string(), oid);
    DelegateSigrefs::sign_refs(key, &refs)
}

fn cand(base: GitOid, oid: GitOid, merged: bool) -> Result<PromotionCandidate, String> {
    Ok(PromotionCandidate {
        repo_id: RepoId::new("aien-spark/radicle-conformance").map_err(|e| e.to_string())?,
        changeset_id: None,
        proposal_base_git_oid: base,
        candidate_git_oid: oid,
        github_pr_merged: merged,
        verified_at_ms: 1_700_000_000_000,
    })
}

/// Run the Radicle canonicality suite; `live_repo` is an optional bare Radicle storage repo.
pub fn run_radicle_suite(live_repo: Option<&Path>) -> SuiteResult {
    let keys: Vec<SigningKey> = (0..3)
        .map(|i| synapse_arm::deterministic_key(0x4AD, "delegate", i))
        .collect();
    let outsider = synapse_arm::deterministic_key(0x4AD, "outsider", 0);
    let base = GitOid::compute_git_object("commit", b"radicle conformance base");
    let x = GitOid::compute_git_object("commit", b"radicle conformance candidate x");
    let y = GitOid::compute_git_object("commit", b"radicle conformance candidate y");
    let doc = rad_doc(&keys, 2);
    let engine =
        || CanonicalPromotionEngine::new(doc.clone(), None, None).map_err(|e| e.to_string());
    let mut cases = Vec::new();

    cases.push(record(
        RAD,
        "threshold_met_promotes",
        "2 of 3 delegate signatures on X promote X with 2 verified delegates",
        || {
            let mut e = engine()?;
            let r = e.verify_and_promote(
                &cand(base, x, false)?,
                &[signed(&keys[0], x), signed(&keys[1], x)],
            );
            let ok = r
                .as_ref()
                .is_ok_and(|h| h.canonical_git_oid == x && h.verified_delegates.len() == 2);
            Ok((
                ok,
                format!(
                    "result {:?}",
                    r.map(|h| (h.canonical_git_oid, h.verified_delegates.len()))
                        .map_err(|e| e.code)
                ),
            ))
        },
    ));
    cases.push(record(
        RAD,
        "below_threshold_refused",
        "1 of 3 signatures (threshold 2) is refused with RadicleQuorumInsufficient",
        || {
            let mut e = engine()?;
            let r = e.verify_and_promote(&cand(base, x, false)?, &[signed(&keys[0], x)]);
            Ok((
                code_of(&r) == Some(RefusalCode::RadicleQuorumInsufficient),
                format!("result {:?}", code_of(&r)),
            ))
        },
    ));
    cases.push(record(RAD, "vote_for_other_oid_not_counted", "a delegate signature over Y does not count toward X; promotion of X refused with RadicleQuorumInsufficient", || {
        let mut e = engine()?;
        let r = e.verify_and_promote(&cand(base, x, false)?, &[signed(&keys[0], x), signed(&keys[1], y)]);
        Ok((code_of(&r) == Some(RefusalCode::RadicleQuorumInsufficient), format!("result {:?}", code_of(&r))))
    }));
    cases.push(record(
        RAD,
        "tampered_refs_blob_refused",
        "a sigrefs blob edited after signing (OID swapped) is refused with RadicleSignatureInvalid",
        || {
            let mut e = engine()?;
            let mut forged = signed(&keys[1], y);
            let text = String::from_utf8(forged.refs_blob.clone()).map_err(|e| e.to_string())?;
            forged.refs_blob = text.replace(&y.to_hex(), &x.to_hex()).into_bytes();
            let r = e.verify_and_promote(&cand(base, x, false)?, &[signed(&keys[0], x), forged]);
            Ok((
                code_of(&r) == Some(RefusalCode::RadicleSignatureInvalid),
                format!("result {:?}", code_of(&r)),
            ))
        },
    ));
    cases.push(record(RAD, "non_delegate_signer_refused", "a valid signature from a key not listed in the identity document is refused with RadicleIdentityInvalid", || {
        let mut e = engine()?;
        let r = e.verify_and_promote(&cand(base, x, false)?, &[signed(&keys[0], x), signed(&outsider, x)]);
        Ok((code_of(&r) == Some(RefusalCode::RadicleIdentityInvalid), format!("result {:?}", code_of(&r))))
    }));
    cases.push(record(RAD, "forged_delegate_signature_refused", "a sigrefs claiming a delegate DID but signed by another key is refused with RadicleSignatureInvalid", || {
        let mut e = engine()?;
        let mut forged = signed(&outsider, x);
        forged.delegate_did = encode_did_key_ed25519(&keys[1].verifying_key().to_bytes());
        let r = e.verify_and_promote(&cand(base, x, false)?, &[signed(&keys[0], x), forged]);
        Ok((code_of(&r) == Some(RefusalCode::RadicleSignatureInvalid), format!("result {:?}", code_of(&r))))
    }));
    cases.push(record(RAD, "stale_base_refused", "after X is canonical, a candidate whose proposal base is not X is refused with StaleBaseHead", || {
        let mut e = engine()?;
        e.verify_and_promote(&cand(base, x, false)?, &[signed(&keys[0], x), signed(&keys[1], x)])
            .map_err(|e| e.to_string())?;
        let r = e.verify_and_promote(&cand(base, y, false)?, &[signed(&keys[0], y), signed(&keys[1], y)]);
        let still_x = e.current_canonical().is_some_and(|h| h.canonical_git_oid == x);
        Ok((code_of(&r) == Some(RefusalCode::StaleBaseHead) && still_x, format!("result {:?}; canonical still X {still_x}", code_of(&r))))
    }));
    cases.push(record(RAD, "github_merged_without_quorum_refused", "a GitHub-merged candidate with 1 of 2 required signatures classifies as SplitBrainGithubMergedWithoutRadicleQuorum and promotion is refused with RadicleQuorumInsufficient", || {
        let mut e = engine()?;
        let c = cand(base, x, true)?;
        let sigs = [signed(&keys[0], x)];
        let state = e.classify_reconciliation(&c, &sigs).map_err(|e| e.to_string())?;
        let classified = matches!(state, ReconciliationState::SplitBrainGithubMergedWithoutRadicleQuorum { .. });
        let r = e.verify_and_promote(&c, &sigs);
        Ok((classified && code_of(&r) == Some(RefusalCode::RadicleQuorumInsufficient), format!("state {state:?}; result {:?}", code_of(&r))))
    }));
    cases.push(record(
        RAD,
        "diverged_quorum_refused",
        "when the delegate quorum signs Y, promoting X is refused with SplitBrainDivergence",
        || {
            let mut e = engine()?;
            let r = e.verify_and_promote(
                &cand(base, x, false)?,
                &[signed(&keys[0], y), signed(&keys[1], y)],
            );
            Ok((
                code_of(&r) == Some(RefusalCode::SplitBrainDivergence),
                format!("result {:?}", code_of(&r)),
            ))
        },
    ));
    cases.push(record(RAD, "invalid_threshold_identity_refused", "an identity document with threshold 4 of 3 delegates is refused with RadicleIdentityInvalid", || {
        let r = CanonicalPromotionEngine::new(rad_doc(&keys, 4), None, None);
        let code = r.as_ref().err().map(|e| e.code);
        Ok((code == Some(RefusalCode::RadicleIdentityInvalid), format!("result {code:?}")))
    }));

    let live_expected = "read-only: load refs/rad/id and every delegate's sigrefs from the given bare Radicle storage repository, verify signatures, and classify the delegate-signed default-branch head as CanonicalQuorumSatisfied";
    match live_repo {
        None => cases.push(skipped(RAD, "live_repository_load_and_classify", live_expected, "skipped: no --radicle-repo given")),
        Some(p) if !p.exists() => cases.push(skipped(RAD, "live_repository_load_and_classify", live_expected, &format!("skipped: {} does not exist", p.display()))),
        Some(p) => cases.push(record(RAD, "live_repository_load_and_classify", live_expected, || {
            let (doc, id_oid, sigrefs) = load_radicle_state_from_bare_repo(p).map_err(|e| e.to_string())?;
            let default_ref = doc.default_branch_ref();
            let mut votes: BTreeMap<GitOid, usize> = BTreeMap::new();
            for s in &sigrefs {
                let (_, refs) = s.verify_and_parse().map_err(|e| e.to_string())?;
                if let Some(oid) = refs.get(&default_ref) {
                    *votes.entry(*oid).or_default() += 1;
                }
            }
            let (head, count) = votes.iter().max_by_key(|(_, c)| **c).map(|(o, c)| (*o, *c)).ok_or("no delegate signed the default branch")?;
            let engine = CanonicalPromotionEngine::new(doc.clone(), Some(id_oid), None).map_err(|e| e.to_string())?;
            let state = engine.classify_reconciliation(&cand(head, head, false)?, &sigrefs).map_err(|e| e.to_string())?;
            let ok = matches!(state, ReconciliationState::CanonicalQuorumSatisfied { .. });
            Ok((ok, format!(
                "project {:?}; delegates {}; threshold {}; sigrefs loaded {}; default branch {default_ref} head {head} signed by {count}; state {}",
                doc.payload.project.name, doc.delegates.len(), doc.threshold, sigrefs.len(),
                match state { ReconciliationState::CanonicalQuorumSatisfied { .. } => "CanonicalQuorumSatisfied".to_string(), other => format!("{other:?}") }
            )))
        })),
    }
    SuiteResult::from_cases(RAD, cases)
}

/// Run one suite by name (`wal`, `git`, or `radicle`).
pub fn run_suite(
    name: &str,
    work: &Path,
    radicle_repo: Option<&Path>,
) -> Result<SuiteResult, String> {
    std::fs::create_dir_all(work).map_err(|e| format!("mkdir {}: {e}", work.display()))?;
    match name {
        WAL => Ok(run_wal_suite(work)),
        GIT => Ok(run_git_suite(work)),
        RAD => Ok(run_radicle_suite(radicle_repo)),
        other => Err(format!("unknown conformance suite {other}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fixture::test_support::temp_dir;

    fn assert_all_pass(s: &SuiteResult) {
        for c in &s.cases {
            assert_eq!(
                c.outcome,
                CaseOutcome::Pass,
                "{}::{} observed {}",
                c.suite,
                c.case,
                c.observed
            );
        }
    }

    #[test]
    fn wal_suite_cases_pass() {
        let dir = temp_dir("conf-wal");
        let s = run_wal_suite(&dir);
        assert_eq!(s.cases.len(), 11);
        assert_all_pass(&s);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// ADR 0003 A1: the WAL suite's stores hold binary codec v2 frames, so its 11 cases
    /// qualify the binary codec, not the v1 JSON one.
    #[test]
    fn wal_suite_stores_write_binary_codec_frames() {
        let dir = temp_dir("conf-wal-codec");
        let acked = seed_store(&dir).unwrap();
        let log = acked.wal_bytes;
        let mut at = 0;
        let mut frames = 0;
        while at < log.len() {
            assert_eq!(
                log[at + 7],
                synapse_store::codec::WAL_FLAG_CODEC_V2,
                "frame {frames} flags"
            );
            let len = u32::from_le_bytes(log[at + 48..at + 52].try_into().unwrap()) as usize;
            at += synapse_store::WAL_HEADER_LEN + len;
            frames += 1;
        }
        assert_eq!(frames, 3);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn git_suite_cases_pass() {
        let dir = temp_dir("conf-git");
        let s = run_git_suite(&dir);
        assert_eq!(s.cases.len(), 7);
        assert_all_pass(&s);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn radicle_suite_cases_pass_and_live_case_skips_without_path() {
        let s = run_radicle_suite(None);
        assert_eq!(s.skipped, 1);
        assert_eq!(s.failed, 0);
        assert_eq!(s.passed, s.cases.len() - 1);
    }
}
