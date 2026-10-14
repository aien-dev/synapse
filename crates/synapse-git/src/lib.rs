//! Deterministic Git loose object materialization (`blob`, `tree`, `commit`),
//! bidirectional `ChangesetId <-> GitOid` index, explicit ref namespace contract
//! (`refs/synapse/*` vs human `refs/heads/*`), and GitHub Pull Request projection
//! builder (`synapse-git`, Gate 3).

use serde::{Deserialize, Serialize};
use sha1::Sha1;
use sha2::{Digest, Sha256};
use std::cmp::Ordering;
use std::collections::BTreeMap;
use std::fs::{self, File};
use std::io::Write;
use std::path::Path;
use std::process::Command;
use synapse_api::{SynapseService, TreeTarget, VirtualTreeEntry};
use synapse_auth::AuthenticatedRequest;
use synapse_core::{
    ChangesetId, GitHubPullRequestProjection, GitOid, RefusalCode, SynapseError, SynapseResult,
    WalSeq,
};

/// Explicit ref namespace for a materialized Synapse changeset commit.
pub fn changeset_git_ref(changeset_id: ChangesetId) -> String {
    format!("refs/synapse/changesets/{}", changeset_id.to_hex())
}

/// Explicit ref namespace consumed by CLI/autonomous agent workers on `lane`.
pub fn agent_lane_head_ref(lane: &str) -> String {
    format!("refs/synapse/agent-head/{lane}")
}

/// Explicit ref namespace recording the verified Radicle canonical head projection.
pub fn canonical_projection_ref(branch: &str) -> String {
    format!("refs/synapse/canonical/{branch}")
}

/// Bidirectional mapping between `ChangesetId` and materialized Git commit `GitOid`,
/// plus associated root tree `GitOid`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct GitProjectionIndex {
    changeset_to_commit: BTreeMap<ChangesetId, GitOid>,
    changeset_to_tree: BTreeMap<ChangesetId, GitOid>,
    commit_to_changeset: BTreeMap<GitOid, ChangesetId>,
}

impl GitProjectionIndex {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn record(&mut self, changeset_id: ChangesetId, commit_oid: GitOid, tree_oid: GitOid) {
        self.changeset_to_commit.insert(changeset_id, commit_oid);
        self.changeset_to_tree.insert(changeset_id, tree_oid);
        self.commit_to_changeset.insert(commit_oid, changeset_id);
    }

    pub fn commit_for_changeset(&self, changeset_id: ChangesetId) -> Option<GitOid> {
        self.changeset_to_commit.get(&changeset_id).copied()
    }

    pub fn tree_for_changeset(&self, changeset_id: ChangesetId) -> Option<GitOid> {
        self.changeset_to_tree.get(&changeset_id).copied()
    }

    pub fn changeset_for_commit(&self, commit_oid: GitOid) -> Option<ChangesetId> {
        self.commit_to_changeset.get(&commit_oid).copied()
    }
}

/// Receipt returned when a Synapse changeset is materialized into a Git repository.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MaterializedGitCommit {
    pub changeset_id: ChangesetId,
    pub commit_oid: GitOid,
    pub tree_oid: GitOid,
    pub parent_commit_oids: Vec<GitOid>,
    pub changeset_ref: String,
    pub agent_lane_ref: Option<String>,
}

/// Request payload for projecting a changeset to a GitHub Pull Request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GitHubPrProjectionRequest {
    pub pr_number: u64,
    pub changeset_id: ChangesetId,
    pub pr_branch_ref: String,
    pub title: String,
    pub github_merged: bool,
}

/// Request payload for advancing a human-facing Git branch (`refs/heads/<branch>`)
/// to a fast-forward descendant commit (`Capability::Publish` at `BoundaryKind::Export`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HumanBranchAdvanceRequest {
    pub branch: String,
    pub new_commit_oid: GitOid,
}

/// Compute RFC 1950 Adler-32 checksum over `data`.
pub fn adler32(data: &[u8]) -> u32 {
    const MOD_ADLER: u32 = 65521;
    let mut a: u32 = 1;
    let mut b: u32 = 0;
    for &byte in data {
        a = (a + u32::from(byte)) % MOD_ADLER;
        b = (b + a) % MOD_ADLER;
    }
    (b << 16) | a
}

/// Compress `raw` into RFC 1950 zlib stream using uncompressed DEFLATE store blocks (`BTYPE=00`).
/// Standard Git (`git fsck --full`, `git cat-file`, `git clone`, `git fetch`) natively accepts
/// RFC 1950 store-block streams with zero external C dependency.
pub fn zlib_compress_store(raw: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(raw.len() + (raw.len() / 65535 + 1) * 5 + 6);
    // RFC 1950 header: CMF = 0x78 (Deflate, 32K window), FLG = 0x01 (no dict, FCHECK valid: 0x7801 % 31 == 0)
    out.push(0x78);
    out.push(0x01);

    if raw.is_empty() {
        // Single final empty store block
        out.push(0x01); // BFINAL=1, BTYPE=00
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&(!0u16).to_le_bytes());
    } else {
        let chunks: Vec<&[u8]> = raw.chunks(65_535).collect();
        for (i, chunk) in chunks.iter().enumerate() {
            let is_last = i + 1 == chunks.len();
            out.push(u8::from(is_last)); // BFINAL=1 on last chunk, BTYPE=00
            let len = chunk.len() as u16;
            let nlen = !len;
            out.extend_from_slice(&len.to_le_bytes());
            out.extend_from_slice(&nlen.to_le_bytes());
            out.extend_from_slice(chunk);
        }
    }

    let checksum = adler32(raw);
    out.extend_from_slice(&checksum.to_be_bytes());
    out
}

/// Write a standard Git loose object (`blob`, `tree`, or `commit`) into `<git_dir>/objects/<xx>/<38-hex>`
/// and return its deterministic 20-byte SHA-1 `GitOid`.
pub fn write_git_loose_object(git_dir: &Path, kind: &str, payload: &[u8]) -> SynapseResult<GitOid> {
    let header = format!("{kind} {}\0", payload.len());
    let mut full = Vec::with_capacity(header.len() + payload.len());
    full.extend_from_slice(header.as_bytes());
    full.extend_from_slice(payload);

    let oid_bytes: [u8; 20] = Sha1::digest(&full).into();
    let oid = GitOid(oid_bytes);
    let hex = oid.to_hex();

    let shard_dir = git_dir.join("objects").join(&hex[0..2]);
    let obj_path = shard_dir.join(&hex[2..40]);
    if obj_path.exists() {
        return Ok(oid);
    }

    fs::create_dir_all(&shard_dir)
        .map_err(|e| SynapseError::new(RefusalCode::IoFailure, e.to_string()))?;
    let compressed = zlib_compress_store(&full);
    let tmp_path = shard_dir.join(format!("{}.tmp.{}", &hex[2..40], std::process::id()));
    {
        let mut f = File::create(&tmp_path)
            .map_err(|e| SynapseError::new(RefusalCode::IoFailure, e.to_string()))?;
        f.write_all(&compressed)
            .map_err(|e| SynapseError::new(RefusalCode::IoFailure, e.to_string()))?;
        f.sync_all()
            .map_err(|e| SynapseError::new(RefusalCode::IoFailure, e.to_string()))?;
    }
    fs::rename(&tmp_path, &obj_path)
        .map_err(|e| SynapseError::new(RefusalCode::IoFailure, e.to_string()))?;
    Ok(oid)
}

#[derive(Default)]
struct DirNode {
    files: BTreeMap<String, VirtualTreeEntry>,
    subdirs: BTreeMap<String, DirNode>,
}

/// Compare two tree entry names using Git's exact tree sort rule:
/// directory entries are compared as if they had a trailing `'/'`.
fn git_tree_entry_cmp(name_a: &str, is_dir_a: bool, name_b: &str, is_dir_b: bool) -> Ordering {
    let bytes_a = name_a.as_bytes();
    let bytes_b = name_b.as_bytes();
    let min_len = bytes_a.len().min(bytes_b.len());
    match bytes_a[..min_len].cmp(&bytes_b[..min_len]) {
        Ordering::Equal => {
            let next_a = if bytes_a.len() > min_len {
                Some(bytes_a[min_len])
            } else if is_dir_a {
                Some(b'/')
            } else {
                None
            };
            let next_b = if bytes_b.len() > min_len {
                Some(bytes_b[min_len])
            } else if is_dir_b {
                Some(b'/')
            } else {
                None
            };
            next_a.cmp(&next_b)
        }
        non_eq => non_eq,
    }
}

fn write_dir_node_recursive(git_dir: &Path, node: &DirNode) -> SynapseResult<GitOid> {
    // 1. Materialize all child subdirectories first
    let mut entries: Vec<(String, bool, &'static str, GitOid)> =
        Vec::with_capacity(node.files.len() + node.subdirs.len());

    for (name, entry) in &node.files {
        entries.push((
            name.clone(),
            false,
            entry.mode.git_octal_str(),
            entry.git_blob_oid,
        ));
    }
    for (dir_name, subnode) in &node.subdirs {
        let sub_oid = write_dir_node_recursive(git_dir, subnode)?;
        entries.push((dir_name.clone(), true, "40000", sub_oid));
    }

    // 2. Sort entries using Git's canonical tree comparator
    entries.sort_by(|(na, da, _, _), (nb, db, _, _)| git_tree_entry_cmp(na, *da, nb, *db));

    // 3. Encode binary Git tree payload: "<mode> <name>\0<20-byte raw oid>"
    let mut tree_payload = Vec::new();
    for (name, _, mode_str, oid) in entries {
        tree_payload.extend_from_slice(mode_str.as_bytes());
        tree_payload.push(b' ');
        tree_payload.extend_from_slice(name.as_bytes());
        tree_payload.push(0);
        tree_payload.extend_from_slice(&oid.0);
    }

    write_git_loose_object(git_dir, "tree", &tree_payload)
}

/// Write a Synapse namespace Git ref file (`refs/synapse/...`) atomically inside `git_dir`.
/// Human-facing refs (`refs/heads/...`) must go through [`advance_human_branch_fast_forward`].
pub fn write_git_ref(git_dir: &Path, ref_name: &str, oid: GitOid) -> SynapseResult<()> {
    if !ref_name.starts_with("refs/synapse/") || ref_name.contains("..") {
        return Err(SynapseError::new(
            RefusalCode::PathInvalid,
            format!("invalid or unauthenticated human git ref name: {ref_name}"),
        ));
    }
    write_git_ref_raw(git_dir, ref_name, oid)
}

fn write_git_ref_raw(git_dir: &Path, ref_name: &str, oid: GitOid) -> SynapseResult<()> {
    if !ref_name.starts_with("refs/") || ref_name.contains("..") {
        return Err(SynapseError::new(
            RefusalCode::PathInvalid,
            format!("invalid git ref name: {ref_name}"),
        ));
    }
    let ref_path = git_dir.join(ref_name);
    if let Some(parent) = ref_path.parent() {
        fs::create_dir_all(parent)
            .map_err(|e| SynapseError::new(RefusalCode::IoFailure, e.to_string()))?;
    }
    let tmp_path = ref_path.with_extension(format!("lock.{}", std::process::id()));
    let content = format!("{}\n", oid.to_hex());
    {
        let mut f = File::create(&tmp_path)
            .map_err(|e| SynapseError::new(RefusalCode::IoFailure, e.to_string()))?;
        f.write_all(content.as_bytes())
            .map_err(|e| SynapseError::new(RefusalCode::IoFailure, e.to_string()))?;
        f.sync_all()
            .map_err(|e| SynapseError::new(RefusalCode::IoFailure, e.to_string()))?;
    }
    fs::rename(&tmp_path, &ref_path)
        .map_err(|e| SynapseError::new(RefusalCode::IoFailure, e.to_string()))?;
    Ok(())
}

/// Deterministically materialize a committed Synapse `ChangesetId` into standard Git
/// `blob`, `tree`, and `commit` objects in `git_dir`, updating `refs/synapse/changesets/<id>`
/// and optionally `refs/synapse/agent-head/<lane>` without touching human `refs/heads/*` branches.
pub fn materialize_changeset_to_git(
    service: &mut SynapseService,
    index: &mut GitProjectionIndex,
    git_dir: &Path,
    changeset_id: ChangesetId,
    agent_lane: Option<&str>,
    snapshot_seq: Option<WalSeq>,
) -> SynapseResult<MaterializedGitCommit> {
    let stored = service
        .store()
        .get_changeset(changeset_id, None, snapshot_seq)?;
    let virtual_tree =
        service.materialize_virtual_tree(TreeTarget::Changeset(changeset_id), snapshot_seq)?;

    // 1. Write all blobs in the virtual tree into `<git_dir>/objects`
    let mut root_node = DirNode::default();
    for entry in virtual_tree.values() {
        let raw_bytes = service.read_blob_bytes(entry.blob_digest, snapshot_seq)?;
        let written_blob_oid = write_git_loose_object(git_dir, "blob", &raw_bytes)?;
        if written_blob_oid != entry.git_blob_oid {
            return Err(SynapseError::new(
                RefusalCode::GitObjectCorrupt,
                format!(
                    "materialized blob OID {} != virtual tree OID {}",
                    written_blob_oid, entry.git_blob_oid
                ),
            ));
        }

        // Insert into hierarchical DirNode
        let segments: Vec<&str> = entry.path.split('/').collect();
        let mut curr = &mut root_node;
        for &dir_seg in &segments[..segments.len() - 1] {
            curr = curr.subdirs.entry(dir_seg.to_string()).or_default();
        }
        let file_name = segments.last().expect("non-empty path").to_string();
        curr.files.insert(file_name, entry.clone());
    }

    // 2. Write recursive Git tree objects
    let tree_oid = write_dir_node_recursive(git_dir, &root_node)?;

    // 3. Resolve parent Git commit OIDs:
    //    If `parent_changesets` is empty, parent is `base_git_oid` (unless `base_git_oid == GitOid::ZERO`).
    //    Otherwise, materialize/lookup each parent changeset's `GitOid`.
    let mut parent_commit_oids = Vec::new();
    if stored.envelope.parent_changesets.is_empty() {
        if stored.envelope.base_git_oid != GitOid::ZERO {
            parent_commit_oids.push(stored.envelope.base_git_oid);
        }
    } else {
        for &parent_cs in &stored.envelope.parent_changesets {
            let parent_oid = if let Some(existing) = index.commit_for_changeset(parent_cs) {
                existing
            } else {
                materialize_changeset_to_git(
                    service,
                    index,
                    git_dir,
                    parent_cs,
                    None,
                    snapshot_seq,
                )?
                .commit_oid
            };
            parent_commit_oids.push(parent_oid);
        }
    }

    // 4. Format deterministic Git commit payload
    let timestamp_sec = stored.envelope.created_at_ms / 1000;
    let mut commit_payload = String::new();
    commit_payload.push_str(&format!("tree {}\n", tree_oid.to_hex()));
    for p in &parent_commit_oids {
        commit_payload.push_str(&format!("parent {}\n", p.to_hex()));
    }
    commit_payload.push_str(&format!(
        "author {} <agent@synapse.aienos.local> {} +0000\n",
        stored.envelope.author_did, timestamp_sec
    ));
    commit_payload.push_str(&format!(
        "committer Synapse Engine <synapse@aienos.local> {} +0000\n\n",
        timestamp_sec
    ));
    commit_payload.push_str(&stored.envelope.intent_summary);
    commit_payload.push_str(&format!(
        "\n\nSynapse-Changeset-Id: {}\nSynapse-Wal-Seq: {}\n",
        changeset_id.to_hex(),
        stored.committed_seq.0
    ));

    let commit_oid = write_git_loose_object(git_dir, "commit", commit_payload.as_bytes())?;
    index.record(changeset_id, commit_oid, tree_oid);

    // 5. Write explicit Synapse changeset ref and optional agent lane ref (never touching human branches!)
    let cs_ref = changeset_git_ref(changeset_id);
    write_git_ref(git_dir, &cs_ref, commit_oid)?;

    let lane_ref = if let Some(lane) = agent_lane {
        let r = agent_lane_head_ref(lane);
        write_git_ref(git_dir, &r, commit_oid)?;
        Some(r)
    } else {
        None
    };

    Ok(MaterializedGitCommit {
        changeset_id,
        commit_oid,
        tree_oid,
        parent_commit_oids,
        changeset_ref: cs_ref,
        agent_lane_ref: lane_ref,
    })
}

fn validate_human_branch_name(branch: &str) -> SynapseResult<()> {
    if branch.is_empty()
        || branch.starts_with('/')
        || branch.ends_with('/')
        || branch.starts_with('.')
        || branch.ends_with(".lock")
        || branch.contains("..")
        || branch.contains("//")
        || branch.contains("@{")
        || branch.contains('\\')
        || branch
            .bytes()
            .any(|b| b <= b' ' || b == 0x7f || matches!(b, b'~' | b'^' | b':' | b'?' | b'*' | b'['))
    {
        return Err(SynapseError::new(
            RefusalCode::PathInvalid,
            format!("invalid human branch name: {branch}"),
        ));
    }
    Ok(())
}

/// Unauthenticated crate-private helper that advances `refs/heads/<branch>` only if
/// `new_commit_oid` is a fast-forward descendant of the current branch head.
fn advance_human_branch_fast_forward_unchecked(
    git_dir: &Path,
    branch: &str,
    new_commit_oid: GitOid,
) -> SynapseResult<()> {
    validate_human_branch_name(branch)?;
    let ref_name = format!("refs/heads/{branch}");
    let rev_out = Command::new("git")
        .arg("--git-dir")
        .arg(git_dir)
        .arg("rev-parse")
        .arg("--verify")
        .arg(&ref_name)
        .output()
        .map_err(|e| SynapseError::new(RefusalCode::IoFailure, e.to_string()))?;

    if rev_out.status.success() {
        let current_hex = String::from_utf8_lossy(&rev_out.stdout).trim().to_string();
        let ff_check = Command::new("git")
            .arg("--git-dir")
            .arg(git_dir)
            .arg("merge-base")
            .arg("--is-ancestor")
            .arg(&current_hex)
            .arg(new_commit_oid.to_hex())
            .status()
            .map_err(|e| SynapseError::new(RefusalCode::IoFailure, e.to_string()))?;
        if !ff_check.success() {
            return Err(SynapseError::new(
                RefusalCode::GitRefNonFastForward,
                format!(
                    "refusing non-fast-forward update of human branch {ref_name} from {current_hex} to {new_commit_oid}"
                ),
            ));
        }
    }

    write_git_ref_raw(git_dir, &ref_name, new_commit_oid)
}

/// Advance a human-facing branch (`refs/heads/<branch>`) after authorizing `Capability::Publish`
/// at `BoundaryKind::Export` via `SynapseService::authorize_export`, and ONLY if `new_commit_oid`
/// is a fast-forward descendant of the current branch head (refusing non-fast-forward updates
/// with `RefusalCode::GitRefNonFastForward`).
pub fn advance_human_branch_fast_forward(
    service: &mut SynapseService,
    git_dir: &Path,
    req: &AuthenticatedRequest<HumanBranchAdvanceRequest>,
    now_ms: u64,
) -> SynapseResult<()> {
    service.authorize_export("advance_human_branch_fast_forward", req, now_ms)?;
    advance_human_branch_fast_forward_unchecked(
        git_dir,
        &req.payload.branch,
        req.payload.new_commit_oid,
    )
}

/// Build and record a bounded `GitHubPullRequestProjection` (`Capability::Publish` at `BoundaryKind::Export`).
/// Summarizes evidence digests in markdown while keeping bulky machine logs inside Synapse.
pub fn project_github_pull_request(
    service: &mut SynapseService,
    index: &GitProjectionIndex,
    req: &AuthenticatedRequest<GitHubPrProjectionRequest>,
    now_ms: u64,
) -> SynapseResult<GitHubPullRequestProjection> {
    let repo_id = service.repo_id().clone();
    service.authorize_export("project_github_pr", req, now_ms)?;

    let stored = service
        .store()
        .get_changeset(req.payload.changeset_id, None, None)?;
    let head_git_oid = index
        .commit_for_changeset(req.payload.changeset_id)
        .ok_or_else(|| {
            SynapseError::new(
                RefusalCode::GitObjectCorrupt,
                format!(
                    "changeset {} must be materialized to Git before projecting a GitHub PR",
                    req.payload.changeset_id
                ),
            )
        })?;

    let mut hasher = Sha256::new();
    hasher.update(b"SYNAPSE_GH_PR_EVIDENCE_V1\0");
    let mut table_rows = String::new();
    for ev in &stored.evaluations {
        hasher.update(ev.gate_name.as_bytes());
        hasher.update([u8::from(ev.passed)]);
        hasher.update(ev.artifact_digest);
        table_rows.push_str(&format!(
            "| `{}` | `{}` | `{}` | {} |\n",
            ev.gate_name,
            if ev.passed { "PASS" } else { "FAIL" },
            hex::encode(&ev.artifact_digest[..8]),
            ev.summary
        ));
    }
    let evidence_summary_digest: [u8; 32] = hasher.finalize().into();

    let body_markdown = format!(
        "### Synapse Projection Summary\n\
         * **ChangesetId**: `{}`\n\
         * **Git Commit OID**: `{}`\n\
         * **Base Git OID**: `{}`\n\
         * **Author DID**: `{}`\n\
         * **Evidence Summary Digest**: `{}`\n\n\
         | Gate | Verdict | Artifact Digest (prefix) | Summary |\n\
         | :--- | :--- | :--- | :--- |\n\
         {}",
        req.payload.changeset_id,
        head_git_oid,
        stored.envelope.base_git_oid,
        stored.envelope.author_did,
        hex::encode(evidence_summary_digest),
        table_rows
    );

    let projection = GitHubPullRequestProjection {
        repo_id,
        pr_number: req.payload.pr_number,
        changeset_id: req.payload.changeset_id,
        head_git_oid,
        base_git_oid: stored.envelope.base_git_oid,
        pr_branch_ref: req.payload.pr_branch_ref.clone(),
        title: req.payload.title.clone(),
        body_markdown,
        evidence_summary_digest,
        github_merged: req.payload.github_merged,
    };

    service
        .store_mut()
        .record_github_projection(projection.clone())?;
    Ok(projection)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use synapse_api::SubmitChangesetPayload;
    use synapse_auth::{AgentCapabilityGrant, Capability};
    use synapse_core::{
        encode_did_key_ed25519, BlobDigest, ChangesetEnvelope, EvidenceAttachment, FileMode,
        IdempotencyKey, MutationOp, PathMutation, RepoId, SYNAPSE_ENVELOPE_VERSION,
    };
    use synapse_store::{FsyncPolicy, IngestOutcome, RecoveryPolicy, StoreLimits};

    fn temp_dir(label: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "synapse-git-test-{}-{}-{}",
            label,
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn test_git_materialization_fsck_clone_fetch_and_human_branch_protection() {
        let work = temp_dir("materialize-clone");
        let bare_git_dir = work.join("origin.git");
        let clone_dir = work.join("client-clone");
        let svc_dir = work.join("synapse-service");

        // 1. Initialize bare Git repository
        Command::new("git")
            .args(["init", "--bare"])
            .arg(&bare_git_dir)
            .output()
            .unwrap();

        let repo_id = RepoId::new("aien-spark/synapse").unwrap();
        let mut svc = SynapseService::open(
            &svc_dir,
            repo_id.clone(),
            FsyncPolicy::EveryCommit,
            RecoveryPolicy::StrictFailClosed,
            StoreLimits::default(),
        )
        .unwrap();

        let auth_key = SigningKey::from_bytes(&[40u8; 32]);
        let auth_did = encode_did_key_ed25519(&auth_key.verifying_key().to_bytes());
        svc.register_authority(auth_did);

        let agent_key = SigningKey::from_bytes(&[41u8; 32]);
        let agent_did = encode_did_key_ed25519(&agent_key.verifying_key().to_bytes());
        let grant = AgentCapabilityGrant::issue(
            &auth_key,
            [1u8; 32],
            repo_id.clone(),
            agent_did,
            vec![
                Capability::Read,
                Capability::Propose,
                Capability::Evaluate,
                Capability::Publish,
            ],
            1024 * 1024,
            100,
            60_000,
            10,
            100_000,
        );

        // Register empty initial base tree (`GitOid::ZERO`)
        svc.register_base_tree(GitOid::ZERO, vec![]).unwrap();

        // 2. Submit Changeset 1 with nested directories + files
        let cargo_toml = b"[package]\nname = \"demo\"\nversion = \"0.1.0\"\n";
        let main_rs = b"fn main() {\n    println!(\"hello from synapse-git\");\n}\n";
        let d_cargo = BlobDigest::compute(cargo_toml);
        let d_main = BlobDigest::compute(main_rs);

        let mut env1 = ChangesetEnvelope {
            version: SYNAPSE_ENVELOPE_VERSION,
            repo_id: repo_id.clone(),
            base_git_oid: GitOid::ZERO,
            parent_changesets: vec![],
            author_did: String::new(),
            idempotency_key: IdempotencyKey::from_label("git-cs1"),
            created_at_ms: 1_700_000_000_000,
            intent_summary: "Initial commit via Synapse".to_string(),
            mutations: vec![
                PathMutation {
                    path: "Cargo.toml".to_string(),
                    op: MutationOp::Upsert {
                        mode: FileMode::Regular644,
                        blob_digest: d_cargo,
                        size_bytes: cargo_toml.len() as u64,
                    },
                },
                PathMutation {
                    path: "src/main.rs".to_string(),
                    op: MutationOp::Upsert {
                        mode: FileMode::Regular644,
                        blob_digest: d_main,
                        size_bytes: main_rs.len() as u64,
                    },
                },
            ],
            evidence_receipts: vec![],
            signature: vec![],
        };
        env1.sign(&agent_key);
        let sub1 = AuthenticatedRequest::sign_new(
            &agent_key,
            grant.clone(),
            repo_id.clone(),
            Capability::Propose,
            [1u8; 32],
            1_000,
            0,
            SubmitChangesetPayload {
                envelope: env1,
                blobs: vec![(d_cargo, cargo_toml.to_vec()), (d_main, main_rs.to_vec())],
            },
        )
        .unwrap();
        let cs1_id = match svc.submit(&sub1, 1_000).unwrap() {
            IngestOutcome::Committed { changeset_id, .. } => changeset_id,
            _ => unreachable!(),
        };

        // 3. Materialize cs1 into `bare_git_dir` using pure-Rust loose object writer
        let mut index = GitProjectionIndex::new();
        let mat1 = materialize_changeset_to_git(
            &mut svc,
            &mut index,
            &bare_git_dir,
            cs1_id,
            Some("lane-alpha"),
            None,
        )
        .unwrap();
        // Materializing a second time must produce the exact same deterministic GitOid
        let mat1_repeat = materialize_changeset_to_git(
            &mut svc,
            &mut index,
            &bare_git_dir,
            cs1_id,
            Some("lane-alpha"),
            None,
        )
        .unwrap();
        assert_eq!(mat1.commit_oid, mat1_repeat.commit_oid);
        assert_eq!(index.changeset_for_commit(mat1.commit_oid), Some(cs1_id));

        // Fast-forward human `main` branch to `mat1.commit_oid`
        let adv1_req = AuthenticatedRequest::sign_new(
            &agent_key,
            grant.clone(),
            repo_id.clone(),
            Capability::Publish,
            [11u8; 32],
            1_500,
            0,
            HumanBranchAdvanceRequest {
                branch: "main".to_string(),
                new_commit_oid: mat1.commit_oid,
            },
        )
        .unwrap();
        advance_human_branch_fast_forward(&mut svc, &bare_git_dir, &adv1_req, 1_500).unwrap();

        // 4. Verify `git fsck --full --strict` passes with zero errors or warnings
        let fsck_out = Command::new("git")
            .arg("--git-dir")
            .arg(&bare_git_dir)
            .args(["fsck", "--full", "--strict"])
            .output()
            .unwrap();
        assert!(
            fsck_out.status.success(),
            "git fsck failed: {}",
            String::from_utf8_lossy(&fsck_out.stderr)
        );

        // 5. Ordinary `git clone` of `bare_git_dir` into `clone_dir`
        let clone_out = Command::new("git")
            .args(["clone", "--branch", "main"])
            .arg(&bare_git_dir)
            .arg(&clone_dir)
            .output()
            .unwrap();
        assert!(
            clone_out.status.success(),
            "git clone failed: {}",
            String::from_utf8_lossy(&clone_out.stderr)
        );
        assert_eq!(fs::read(clone_dir.join("Cargo.toml")).unwrap(), cargo_toml);
        assert_eq!(fs::read(clone_dir.join("src/main.rs")).unwrap(), main_rs);

        // 6. Submit stacked Changeset 2 and materialize it to `refs/synapse/agent-head/lane-alpha`,
        //    then verify `git fetch origin refs/synapse/agent-head/lane-alpha` works in `clone_dir`!
        let readme = b"# Demo\n";
        let d_readme = BlobDigest::compute(readme);
        let mut env2 = ChangesetEnvelope {
            version: SYNAPSE_ENVELOPE_VERSION,
            repo_id: repo_id.clone(),
            base_git_oid: GitOid::ZERO,
            parent_changesets: vec![cs1_id],
            author_did: String::new(),
            idempotency_key: IdempotencyKey::from_label("git-cs2"),
            created_at_ms: 1_700_000_060_000,
            intent_summary: "Add README.md on lane-alpha".to_string(),
            mutations: vec![PathMutation {
                path: "README.md".to_string(),
                op: MutationOp::Upsert {
                    mode: FileMode::Regular644,
                    blob_digest: d_readme,
                    size_bytes: readme.len() as u64,
                },
            }],
            evidence_receipts: vec![],
            signature: vec![],
        };
        env2.sign(&agent_key);
        let sub2 = AuthenticatedRequest::sign_new(
            &agent_key,
            grant.clone(),
            repo_id.clone(),
            Capability::Propose,
            [2u8; 32],
            2_000,
            0,
            SubmitChangesetPayload {
                envelope: env2,
                blobs: vec![(d_readme, readme.to_vec())],
            },
        )
        .unwrap();
        let cs2_id = match svc.submit(&sub2, 2_000).unwrap() {
            IngestOutcome::Committed { changeset_id, .. } => changeset_id,
            _ => unreachable!(),
        };
        let mat2 = materialize_changeset_to_git(
            &mut svc,
            &mut index,
            &bare_git_dir,
            cs2_id,
            Some("lane-alpha"),
            None,
        )
        .unwrap();
        assert_eq!(mat2.parent_commit_oids, vec![mat1.commit_oid]);

        let fetch_out = Command::new("git")
            .current_dir(&clone_dir)
            .args(["fetch", "origin", "refs/synapse/agent-head/lane-alpha"])
            .output()
            .unwrap();
        assert!(fetch_out.status.success());

        // 7. Verify non-fast-forward human branch protection:
        //    Advance human `main` to `mat2.commit_oid` (fast-forward succeeds),
        //    then attempt to move human `main` backwards to `mat1.commit_oid` -> refused with GitRefNonFastForward!
        let adv2_req = AuthenticatedRequest::sign_new(
            &agent_key,
            grant.clone(),
            repo_id.clone(),
            Capability::Publish,
            [12u8; 32],
            2_500,
            0,
            HumanBranchAdvanceRequest {
                branch: "main".to_string(),
                new_commit_oid: mat2.commit_oid,
            },
        )
        .unwrap();
        advance_human_branch_fast_forward(&mut svc, &bare_git_dir, &adv2_req, 2_500).unwrap();
        let adv_back_req = AuthenticatedRequest::sign_new(
            &agent_key,
            grant.clone(),
            repo_id.clone(),
            Capability::Publish,
            [13u8; 32],
            2_600,
            0,
            HumanBranchAdvanceRequest {
                branch: "main".to_string(),
                new_commit_oid: mat1.commit_oid,
            },
        )
        .unwrap();
        let non_ff_err =
            advance_human_branch_fast_forward(&mut svc, &bare_git_dir, &adv_back_req, 2_600)
                .unwrap_err();
        assert_eq!(non_ff_err.code, RefusalCode::GitRefNonFastForward);

        // 8. Attach evaluation receipt and build GitHub PR projection (`Capability::Publish`)
        svc.store_mut()
            .attach_evaluation(
                cs2_id,
                EvidenceAttachment {
                    gate_name: "cargo-test".to_string(),
                    passed: true,
                    artifact_digest: [0xab; 32],
                    summary: "14 passed, 0 failed".to_string(),
                },
            )
            .unwrap();

        let pr_req = AuthenticatedRequest::sign_new(
            &agent_key,
            grant,
            repo_id,
            Capability::Publish,
            [3u8; 32],
            3_000,
            0,
            GitHubPrProjectionRequest {
                pr_number: 42,
                changeset_id: cs2_id,
                pr_branch_ref: "refs/synapse/agent-head/lane-alpha".to_string(),
                title: "feat: Add README.md".to_string(),
                github_merged: false,
            },
        )
        .unwrap();
        let proj = project_github_pull_request(&mut svc, &index, &pr_req, 3_000).unwrap();
        assert_eq!(proj.head_git_oid, mat2.commit_oid);
        assert!(proj.body_markdown.contains("cargo-test"));

        let _ = fs::remove_dir_all(&work);
    }

    #[test]
    fn test_advance_human_branch_requires_publish_capability_and_rejects_bypass() {
        let work = temp_dir("publish-gate");
        let bare_git_dir = work.join("origin.git");
        let svc_dir = work.join("synapse-service");

        Command::new("git")
            .args(["init", "--bare"])
            .arg(&bare_git_dir)
            .output()
            .unwrap();

        let repo_id = RepoId::new("aien-spark/synapse").unwrap();
        let mut svc = SynapseService::open(
            &svc_dir,
            repo_id.clone(),
            FsyncPolicy::EveryCommit,
            RecoveryPolicy::StrictFailClosed,
            StoreLimits::default(),
        )
        .unwrap();

        let auth_key = SigningKey::from_bytes(&[50u8; 32]);
        let auth_did = encode_did_key_ed25519(&auth_key.verifying_key().to_bytes());
        svc.register_authority(auth_did);
        svc.register_base_tree(GitOid::ZERO, vec![]).unwrap();

        let author_key = SigningKey::from_bytes(&[51u8; 32]);
        let author_did = encode_did_key_ed25519(&author_key.verifying_key().to_bytes());
        let no_publish_grant = AgentCapabilityGrant::issue(
            &auth_key,
            [21u8; 32],
            repo_id.clone(),
            author_did.clone(),
            vec![
                Capability::Read,
                Capability::Propose,
                Capability::Evaluate,
                Capability::Review,
            ],
            1024 * 1024,
            100,
            60_000,
            10,
            100_000,
        );

        let body = b"fn gated() {}
";
        let d_body = BlobDigest::compute(body);
        let mut env = ChangesetEnvelope {
            version: SYNAPSE_ENVELOPE_VERSION,
            repo_id: repo_id.clone(),
            base_git_oid: GitOid::ZERO,
            parent_changesets: vec![],
            author_did: String::new(),
            idempotency_key: IdempotencyKey::from_label("publish-gate-cs1"),
            created_at_ms: 1_700_000_000_000,
            intent_summary: "Propose gated change".to_string(),
            mutations: vec![PathMutation {
                path: "src/lib.rs".to_string(),
                op: MutationOp::Upsert {
                    mode: FileMode::Regular644,
                    blob_digest: d_body,
                    size_bytes: body.len() as u64,
                },
            }],
            evidence_receipts: vec![],
            signature: vec![],
        };
        env.sign(&author_key);
        let sub_req = AuthenticatedRequest::sign_new(
            &author_key,
            no_publish_grant.clone(),
            repo_id.clone(),
            Capability::Propose,
            [22u8; 32],
            1_000,
            0,
            SubmitChangesetPayload {
                envelope: env,
                blobs: vec![(d_body, body.to_vec())],
            },
        )
        .unwrap();
        let cs_id = match svc.submit(&sub_req, 1_000).unwrap() {
            IngestOutcome::Committed { changeset_id, .. } => changeset_id,
            _ => unreachable!(),
        };

        // Attach a passing evaluation receipt to verify that passing validation never grants Publish.
        svc.store_mut()
            .attach_evaluation(
                cs_id,
                EvidenceAttachment {
                    gate_name: "cargo-test".to_string(),
                    passed: true,
                    artifact_digest: [0xcd; 32],
                    summary: "all tests passed".to_string(),
                },
            )
            .unwrap();

        let mut index = GitProjectionIndex::new();
        let mat = materialize_changeset_to_git(
            &mut svc,
            &mut index,
            &bare_git_dir,
            cs_id,
            Some("lane-beta"),
            None,
        )
        .unwrap();

        // Direct write_git_ref to refs/heads/main is refused as PathInvalid.
        let direct_err =
            write_git_ref(&bare_git_dir, "refs/heads/main", mat.commit_oid).unwrap_err();
        assert_eq!(direct_err.code, RefusalCode::PathInvalid);
        assert!(!bare_git_dir.join("refs/heads/main").exists());

        // 1. Grant without Capability::Publish is refused with AuthCapabilityDenied; ref does not move.
        let unauth_req = AuthenticatedRequest::sign_new(
            &author_key,
            no_publish_grant.clone(),
            repo_id.clone(),
            Capability::Publish,
            [23u8; 32],
            1_100,
            0,
            HumanBranchAdvanceRequest {
                branch: "main".to_string(),
                new_commit_oid: mat.commit_oid,
            },
        )
        .unwrap();
        let err = advance_human_branch_fast_forward(&mut svc, &bare_git_dir, &unauth_req, 1_100)
            .unwrap_err();
        assert_eq!(err.code, RefusalCode::AuthCapabilityDenied);
        assert!(!bare_git_dir.join("refs/heads/main").exists());

        // 2. Request signed with Capability::Propose instead of Capability::Publish is refused.
        let wrong_cap_req = AuthenticatedRequest::sign_new(
            &author_key,
            no_publish_grant,
            repo_id.clone(),
            Capability::Propose,
            [24u8; 32],
            1_200,
            0,
            HumanBranchAdvanceRequest {
                branch: "main".to_string(),
                new_commit_oid: mat.commit_oid,
            },
        )
        .unwrap();
        let err = advance_human_branch_fast_forward(&mut svc, &bare_git_dir, &wrong_cap_req, 1_200)
            .unwrap_err();
        assert_eq!(err.code, RefusalCode::AuthCapabilityDenied);
        assert!(!bare_git_dir.join("refs/heads/main").exists());

        // 3. Cross-repo grant is refused with AuthCrossRepoDenied.
        let other_repo = RepoId::new("aien-spark/other").unwrap();
        let cross_grant = AgentCapabilityGrant::issue(
            &auth_key,
            [25u8; 32],
            other_repo.clone(),
            author_did.clone(),
            vec![Capability::Publish],
            1024 * 1024,
            100,
            60_000,
            10,
            100_000,
        );
        let cross_req = AuthenticatedRequest::sign_new(
            &author_key,
            cross_grant,
            other_repo,
            Capability::Publish,
            [26u8; 32],
            1_300,
            0,
            HumanBranchAdvanceRequest {
                branch: "main".to_string(),
                new_commit_oid: mat.commit_oid,
            },
        )
        .unwrap();
        let err = advance_human_branch_fast_forward(&mut svc, &bare_git_dir, &cross_req, 1_300)
            .unwrap_err();
        assert_eq!(err.code, RefusalCode::AuthCrossRepoDenied);
        assert!(!bare_git_dir.join("refs/heads/main").exists());

        // 4. Expired Publish grant is refused with AuthGrantExpired.
        let publish_grant = AgentCapabilityGrant::issue(
            &auth_key,
            [27u8; 32],
            repo_id.clone(),
            author_did,
            vec![Capability::Publish],
            1024 * 1024,
            100,
            60_000,
            10,
            5_000,
        );
        let exp_req = AuthenticatedRequest::sign_new(
            &author_key,
            publish_grant.clone(),
            repo_id.clone(),
            Capability::Publish,
            [28u8; 32],
            6_000,
            0,
            HumanBranchAdvanceRequest {
                branch: "main".to_string(),
                new_commit_oid: mat.commit_oid,
            },
        )
        .unwrap();
        let err = advance_human_branch_fast_forward(&mut svc, &bare_git_dir, &exp_req, 6_000)
            .unwrap_err();
        assert_eq!(err.code, RefusalCode::AuthGrantExpired);
        assert!(!bare_git_dir.join("refs/heads/main").exists());

        // 5. Path traversal or malformed branch name is refused even with valid Publish grant.
        let bad_branch_req = AuthenticatedRequest::sign_new(
            &author_key,
            publish_grant.clone(),
            repo_id.clone(),
            Capability::Publish,
            [29u8; 32],
            2_000,
            0,
            HumanBranchAdvanceRequest {
                branch: "../synapse/agent-head/lane-beta".to_string(),
                new_commit_oid: mat.commit_oid,
            },
        )
        .unwrap();
        let err =
            advance_human_branch_fast_forward(&mut svc, &bare_git_dir, &bad_branch_req, 2_000)
                .unwrap_err();
        assert_eq!(err.code, RefusalCode::PathInvalid);
        assert!(!bare_git_dir.join("refs/heads/main").exists());

        // 6. Valid Publish grant succeeds and advances refs/heads/main; replay of the same nonce is refused.
        let valid_req = AuthenticatedRequest::sign_new(
            &author_key,
            publish_grant,
            repo_id,
            Capability::Publish,
            [30u8; 32],
            2_100,
            0,
            HumanBranchAdvanceRequest {
                branch: "main".to_string(),
                new_commit_oid: mat.commit_oid,
            },
        )
        .unwrap();
        advance_human_branch_fast_forward(&mut svc, &bare_git_dir, &valid_req, 2_100).unwrap();
        let head = fs::read_to_string(bare_git_dir.join("refs/heads/main")).unwrap();
        assert_eq!(head.trim(), mat.commit_oid.to_hex());

        let replay_err =
            advance_human_branch_fast_forward(&mut svc, &bare_git_dir, &valid_req, 2_101)
                .unwrap_err();
        assert_eq!(replay_err.code, RefusalCode::AuthReplayDetected);

        let _ = fs::remove_dir_all(&work);
    }
}
