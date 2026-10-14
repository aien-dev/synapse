//! Bounded paginated read/proposal API, checkout-free `VirtualTree` inspection,
//! exact `PathIndex` invalidation, and durable subscription cursors (`synapse-api`, Gate 2b).

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;
use synapse_auth::{AuditEntry, AuthenticatedRequest, BoundaryKind, Capability, PolicyEnforcer};
use synapse_core::{
    validate_repo_relative_path, BlobDigest, ChangesetEnvelope, ChangesetId, EvidenceAttachment,
    FileMode, GitHubPullRequestProjection, GitOid, IdempotencyKey, MutationOp,
    RadicleCanonicalHead, RefusalCode, RepoId, SynapseError, SynapseResult, WalSeq,
};
use synapse_store::{
    CompactionReport, FsyncPolicy, IngestOutcome, RecoveryPolicy, ReviewRecord, StoreLimits,
    StoredChangeset, SynapseStore,
};

mod advisory;
mod crumb;
mod evidence;
pub use advisory::{
    ChangesetAdvisory, ChangesetAdvisoryPayload, CoordinationStatus, GuidanceNote,
    OverlappingProposal, PathAdvisory, Staleness, MAX_ADVISORY_PATHS,
};
pub use crumb::CrumbContextQueryPayload;
pub use evidence::{
    EvidenceBase, EvidenceBaseQueryPayload, ReceiptMismatch, ReceiptVerification, StaleContext,
    StaleReason, VerifyEvidenceReceiptPayload,
};

/// Default maximum page size for bounded API queries.
pub const DEFAULT_MAX_PAGE_SIZE: usize = 256;

/// Bounded pagination parameters accepted by read/query APIs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PageRequest {
    pub cursor: Option<String>,
    pub limit: usize,
    pub min_visible_seq: Option<WalSeq>,
    pub snapshot_seq: Option<WalSeq>,
}

impl Default for PageRequest {
    fn default() -> Self {
        Self {
            cursor: None,
            limit: 64,
            min_visible_seq: None,
            snapshot_seq: None,
        }
    }
}

/// Paginated response envelope returned by read/query APIs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PageResponse<T> {
    pub items: Vec<T>,
    pub next_cursor: Option<String>,
    pub snapshot_seq: WalSeq,
    pub total_matching: usize,
}

/// Target selector for `tree` and `diff` inspection without a working-tree checkout.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum TreeTarget {
    BaseGitCommit(GitOid),
    Changeset(ChangesetId),
}

/// Single entry in a materialized `VirtualTree`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VirtualTreeEntry {
    pub path: String,
    pub mode: FileMode,
    pub blob_digest: BlobDigest,
    pub git_blob_oid: GitOid,
    pub size_bytes: u64,
}

/// Kind of difference between two `VirtualTree` views.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DiffStatus {
    Added,
    Modified,
    Deleted,
}

impl DiffStatus {
    pub fn git_status_char(self) -> &'static str {
        match self {
            Self::Added => "A",
            Self::Modified => "M",
            Self::Deleted => "D",
        }
    }
}

/// Single path difference entry returned by `diff`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiffEntry {
    pub path: String,
    pub status: DiffStatus,
    pub old_entry: Option<VirtualTreeEntry>,
    pub new_entry: Option<VirtualTreeEntry>,
}

/// Entry returned by the paginated `history` API.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HistoryEntry {
    pub changeset_id: ChangesetId,
    pub committed_seq: WalSeq,
    pub author_did: String,
    pub created_at_ms: u64,
    pub base_git_oid: GitOid,
    pub parent_changesets: Vec<ChangesetId>,
    pub intent_summary: String,
    pub mutated_paths_count: usize,
}

/// Comprehensive provenance receipt returned by `provenance`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProvenanceReport {
    pub changeset_id: ChangesetId,
    pub committed_seq: WalSeq,
    pub repo_id: RepoId,
    pub author_did: String,
    pub idempotency_key: IdempotencyKey,
    pub base_git_oid: GitOid,
    pub parent_changesets: Vec<ChangesetId>,
    pub evaluations: Vec<EvidenceAttachment>,
    pub reviews: Vec<ReviewRecord>,
    pub github_projection: Option<GitHubPullRequestProjection>,
    pub canonical_promotion: Option<RadicleCanonicalHead>,
    pub audit_trail: Vec<AuditEntry>,
}

/// Path-level or directory/file hierarchy conflict between two concurrent changesets.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PathConflict {
    pub path: String,
    pub candidate_changeset: ChangesetId,
    pub conflicting_changeset: ChangesetId,
    pub reason: String,
}

/// Repository service status returned by `status`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServiceStatus {
    pub repo_id: RepoId,
    pub committed_seq: WalSeq,
    pub last_frame_sha256: [u8; 32],
    pub state_root_digest: [u8; 32],
    pub total_changesets: usize,
    pub indexed_paths_count: usize,
    pub cached_virtual_trees: usize,
    pub canonical_head: Option<RadicleCanonicalHead>,
    pub audit_chain_head: [u8; 32],
}

/// Event item emitted on the `watch` subscription stream.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WatchEvent {
    pub wal_seq: WalSeq,
    pub changeset_id: ChangesetId,
    pub author_did: String,
    pub intent_summary: String,
    pub touched_paths: Vec<String>,
}

/// Durable subscriber cursor persisted on disk for crash-safe resumption.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WatchCursor {
    pub subscriber_id: String,
    pub repo_id: RepoId,
    pub last_seen_seq: WalSeq,
    pub last_frame_sha256: [u8; 32],
    pub updated_at_ms: u64,
}

/// Request payload for `submit`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SubmitChangesetPayload {
    pub envelope: ChangesetEnvelope,
    pub blobs: Vec<(BlobDigest, Vec<u8>)>,
}

/// Request payload for `tree`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TreeQueryPayload {
    pub target: TreeTarget,
    pub path_prefix: Option<String>,
    pub page: PageRequest,
}

/// Request payload for `diff`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiffQueryPayload {
    pub base: TreeTarget,
    pub target: TreeTarget,
    pub page: PageRequest,
}

/// Request payload for `history`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HistoryQueryPayload {
    pub ancestor_of: Option<ChangesetId>,
    pub path_filter: Option<String>,
    pub page: PageRequest,
}

/// Request payload for `conflicts`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConflictQueryPayload {
    pub candidate: ChangesetId,
    pub against: Option<Vec<ChangesetId>>,
    pub page: PageRequest,
}

/// Request payload for `watch`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WatchQueryPayload {
    pub subscriber_id: String,
    pub after_seq: Option<WalSeq>,
    pub page: PageRequest,
}

/// Exact path index mapping repository paths to touching `ChangesetId`s,
/// plus an invalidatable cache of materialized `VirtualTree` views.
#[derive(Debug, Default)]
pub struct PathIndex {
    path_to_changesets: BTreeMap<String, BTreeSet<ChangesetId>>,
    changeset_to_paths: BTreeMap<ChangesetId, Vec<String>>,
    virtual_tree_cache: BTreeMap<ChangesetId, BTreeMap<String, VirtualTreeEntry>>,
}

impl PathIndex {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn index_changeset(&mut self, changeset_id: ChangesetId, envelope: &ChangesetEnvelope) {
        let mut paths = Vec::with_capacity(envelope.mutations.len());
        for m in &envelope.mutations {
            self.path_to_changesets
                .entry(m.path.clone())
                .or_default()
                .insert(changeset_id);
            paths.push(m.path.clone());
        }
        self.changeset_to_paths.insert(changeset_id, paths);
    }

    /// Remove a `ChangesetId` from the path index and invalidate its cached `VirtualTree`
    /// (and any cached descendant trees).
    pub fn invalidate_changeset(&mut self, changeset_id: ChangesetId) {
        if let Some(paths) = self.changeset_to_paths.remove(&changeset_id) {
            for p in paths {
                if let Some(set) = self.path_to_changesets.get_mut(&p) {
                    set.remove(&changeset_id);
                    if set.is_empty() {
                        self.path_to_changesets.remove(&p);
                    }
                }
            }
        }
        self.virtual_tree_cache.remove(&changeset_id);
    }

    pub fn changesets_for_path(&self, path: &str) -> Option<&BTreeSet<ChangesetId>> {
        self.path_to_changesets.get(path)
    }

    pub fn indexed_paths_count(&self) -> usize {
        self.path_to_changesets.len()
    }

    pub fn cached_trees_count(&self) -> usize {
        self.virtual_tree_cache.len()
    }
}

/// API-first changeset and virtual-tree inspection service (`Gate 2`).
pub struct SynapseService {
    root_dir: PathBuf,
    cursors_dir: PathBuf,
    repo_id: RepoId,
    store: SynapseStore,
    auth: PolicyEnforcer,
    path_index: PathIndex,
    base_trees: BTreeMap<GitOid, BTreeMap<String, VirtualTreeEntry>>,
    base_blobs: BTreeMap<BlobDigest, Vec<u8>>,
    max_page_size: usize,
}

impl SynapseService {
    /// Open or create a `SynapseService` at `root_dir` for `repo_id`.
    pub fn open(
        root_dir: impl AsRef<Path>,
        repo_id: RepoId,
        fsync_policy: FsyncPolicy,
        recovery_policy: RecoveryPolicy,
        limits: StoreLimits,
    ) -> SynapseResult<Self> {
        let root_dir = root_dir.as_ref().to_path_buf();
        let cursors_dir = root_dir.join("cursors");
        fs::create_dir_all(&cursors_dir)
            .map_err(|e| SynapseError::new(RefusalCode::IoFailure, e.to_string()))?;

        let store = SynapseStore::open(&root_dir, fsync_policy, recovery_policy, limits)?;
        let mut path_index = PathIndex::new();
        for cs in store.list_changesets(Some(&repo_id), None, None)? {
            path_index.index_changeset(cs.changeset_id, &cs.envelope);
        }

        Ok(Self {
            root_dir,
            cursors_dir,
            repo_id,
            store,
            auth: PolicyEnforcer::new(),
            path_index,
            base_trees: BTreeMap::new(),
            base_blobs: BTreeMap::new(),
            max_page_size: DEFAULT_MAX_PAGE_SIZE,
        })
    }

    pub fn store(&self) -> &SynapseStore {
        &self.store
    }

    pub fn store_mut(&mut self) -> &mut SynapseStore {
        &mut self.store
    }

    pub fn auth(&self) -> &PolicyEnforcer {
        &self.auth
    }

    pub fn auth_mut(&mut self) -> &mut PolicyEnforcer {
        &mut self.auth
    }

    pub fn path_index(&self) -> &PathIndex {
        &self.path_index
    }

    /// Register a trusted repository authority `did:key:z6Mk...`.
    pub fn register_authority(&mut self, authority_did: impl Into<String>) {
        self.auth
            .register_repo_authority(self.repo_id.clone(), authority_did);
    }

    /// Register an in-memory base Git commit tree for checkout-free virtual tree overlays.
    pub fn register_base_tree(
        &mut self,
        base_git_oid: GitOid,
        files: Vec<(String, FileMode, Vec<u8>)>,
    ) -> SynapseResult<()> {
        let mut map = BTreeMap::new();
        for (path, mode, bytes) in files {
            validate_repo_relative_path(&path)?;
            let blob_digest = BlobDigest::compute(&bytes);
            let git_blob_oid = GitOid::compute_blob(&bytes);
            let size_bytes = bytes.len() as u64;
            self.base_blobs.insert(blob_digest, bytes);
            map.insert(
                path.clone(),
                VirtualTreeEntry {
                    path,
                    mode,
                    blob_digest,
                    git_blob_oid,
                    size_bytes,
                },
            );
        }
        self.base_trees.insert(base_git_oid, map);
        Ok(())
    }

    /// Import a real Git commit's tree from `git_repo_dir` without checking out a working tree,
    /// using `git ls-tree -r -z` and `git cat-file blob`.
    pub fn import_base_tree_from_git_repo(
        &mut self,
        git_repo_dir: &Path,
        commit_rev: &str,
    ) -> SynapseResult<GitOid> {
        let rev_out = Command::new("git")
            .arg("-C")
            .arg(git_repo_dir)
            .arg("rev-parse")
            .arg(format!("{commit_rev}^{{commit}}"))
            .output()
            .map_err(|e| SynapseError::new(RefusalCode::IoFailure, e.to_string()))?;
        if !rev_out.status.success() {
            return Err(SynapseError::new(
                RefusalCode::BaseTreeNotFound,
                format!("git rev-parse failed for {commit_rev}"),
            ));
        }
        let commit_hex = String::from_utf8_lossy(&rev_out.stdout).trim().to_string();
        let commit_oid = GitOid::from_hex(&commit_hex)?;

        let ls_out = Command::new("git")
            .arg("-C")
            .arg(git_repo_dir)
            .arg("ls-tree")
            .arg("-r")
            .arg("-z")
            .arg(&commit_hex)
            .output()
            .map_err(|e| SynapseError::new(RefusalCode::IoFailure, e.to_string()))?;
        if !ls_out.status.success() {
            return Err(SynapseError::new(
                RefusalCode::BaseTreeNotFound,
                "git ls-tree failed",
            ));
        }

        let mut files = Vec::new();
        for record in ls_out.stdout.split(|&b| b == 0) {
            if record.is_empty() {
                continue;
            }
            let rec_str = std::str::from_utf8(record)
                .map_err(|e| SynapseError::new(RefusalCode::GitObjectCorrupt, e.to_string()))?;
            let (meta, path) = rec_str.split_once('\t').ok_or_else(|| {
                SynapseError::new(RefusalCode::GitObjectCorrupt, "malformed git ls-tree line")
            })?;
            let mut parts = meta.split_whitespace();
            let mode_str = parts.next().unwrap_or("");
            let _obj_type = parts.next().unwrap_or("");
            let oid_hex = parts.next().unwrap_or("");

            let mode = match mode_str {
                "100644" => FileMode::Regular644,
                "100755" => FileMode::Executable755,
                "120000" => FileMode::Symlink120000,
                _ => continue,
            };

            let cat_out = Command::new("git")
                .arg("-C")
                .arg(git_repo_dir)
                .arg("cat-file")
                .arg("blob")
                .arg(oid_hex)
                .output()
                .map_err(|e| SynapseError::new(RefusalCode::IoFailure, e.to_string()))?;
            if !cat_out.status.success() {
                return Err(SynapseError::new(
                    RefusalCode::GitObjectCorrupt,
                    format!("git cat-file failed for {oid_hex}"),
                ));
            }
            files.push((path.to_string(), mode, cat_out.stdout));
        }

        self.register_base_tree(commit_oid, files)?;
        Ok(commit_oid)
    }

    /// API 1: `submit` a signed changeset proposal (`Capability::Propose`).
    /// Enforces capability and anti-replay at `BoundaryKind::Api` and store admission at `BoundaryKind::Store`.
    pub fn submit(
        &mut self,
        req: &AuthenticatedRequest<SubmitChangesetPayload>,
        now_ms: u64,
    ) -> SynapseResult<IngestOutcome> {
        self.admit_submit(req, now_ms)?;
        let outcome = self
            .store
            .ingest_changeset(req.payload.envelope.clone(), &req.payload.blobs)?;
        self.index_submitted(&outcome, &req.payload.envelope);
        Ok(outcome)
    }

    /// API-boundary half of [`Self::submit`]: capability, anti-replay, repository, author
    /// and base-tree checks, without touching the store. A caller that commits through a
    /// group-commit `SharedStore` runs this, then `SharedStore::submit`, then
    /// [`Self::index_submitted`].
    pub fn admit_submit(
        &mut self,
        req: &AuthenticatedRequest<SubmitChangesetPayload>,
        now_ms: u64,
    ) -> SynapseResult<()> {
        self.auth.authorize(
            BoundaryKind::Api,
            "submit",
            &self.repo_id,
            Capability::Propose,
            req,
            now_ms,
        )?;

        if req.payload.envelope.repo_id != self.repo_id {
            return Err(SynapseError::new(
                RefusalCode::AuthCrossRepoDenied,
                "envelope repo_id does not match service repo_id",
            ));
        }
        if req.payload.envelope.author_did != req.grant.agent_did {
            return Err(SynapseError::new(
                RefusalCode::AuthSignatureInvalid,
                "envelope author_did does not match authenticated grant agent_did",
            ));
        }
        if !self
            .base_trees
            .contains_key(&req.payload.envelope.base_git_oid)
        {
            return Err(SynapseError::new(
                RefusalCode::BaseTreeNotFound,
                format!(
                    "base_git_oid {} is not registered in service",
                    req.payload.envelope.base_git_oid
                ),
            ));
        }

        Ok(())
    }

    /// Index a committed (or duplicate) submission in the path index.
    pub fn index_submitted(&mut self, outcome: &IngestOutcome, envelope: &ChangesetEnvelope) {
        let cs_id = match outcome {
            IngestOutcome::Committed { changeset_id, .. }
            | IngestOutcome::IdempotentDuplicate { changeset_id, .. } => *changeset_id,
        };
        self.path_index.index_changeset(cs_id, envelope);
    }

    /// API 2: `get` a committed changeset (`Capability::Read`).
    pub fn get(
        &mut self,
        req: &AuthenticatedRequest<(ChangesetId, Option<WalSeq>, Option<WalSeq>)>,
        now_ms: u64,
    ) -> SynapseResult<StoredChangeset> {
        self.auth.authorize(
            BoundaryKind::Api,
            "get",
            &self.repo_id,
            Capability::Read,
            req,
            now_ms,
        )?;
        let (cs_id, min_seq, snap_seq) = req.payload;
        self.store.get_changeset(cs_id, min_seq, snap_seq)
    }

    /// Read a file's raw bytes at `TreeTarget` without cloning or checking out a working tree (`Capability::Read`).
    pub fn read_file(
        &mut self,
        req: &AuthenticatedRequest<(TreeTarget, String, Option<WalSeq>)>,
        now_ms: u64,
    ) -> SynapseResult<Vec<u8>> {
        self.auth.authorize(
            BoundaryKind::Api,
            "read_file",
            &self.repo_id,
            Capability::Read,
            req,
            now_ms,
        )?;
        let (target, ref path, snap_seq) = req.payload;
        let tree = self.materialize_virtual_tree(target, snap_seq)?;
        let entry = tree.get(path).ok_or_else(|| {
            SynapseError::new(
                RefusalCode::BlobNotFound,
                format!("path {path} not found in virtual tree"),
            )
        })?;
        self.read_blob_bytes(entry.blob_digest, snap_seq)
    }

    /// API 3: `tree` returns a bounded, cursor-paginated `VirtualTree` without checkout (`Capability::Read`).
    pub fn tree(
        &mut self,
        req: &AuthenticatedRequest<TreeQueryPayload>,
        now_ms: u64,
    ) -> SynapseResult<PageResponse<VirtualTreeEntry>> {
        self.auth.authorize(
            BoundaryKind::Api,
            "tree",
            &self.repo_id,
            Capability::Read,
            req,
            now_ms,
        )?;
        let snap_seq = self.validate_page_request(&req.payload.page)?;
        let full_tree = self.materialize_virtual_tree(req.payload.target, Some(snap_seq))?;

        let filtered: Vec<VirtualTreeEntry> = full_tree
            .values()
            .filter(|e| {
                req.payload
                    .path_prefix
                    .as_ref()
                    .is_none_or(|prefix| e.path.starts_with(prefix))
            })
            .cloned()
            .collect();

        paginate_slice(&filtered, &req.payload.page, snap_seq)
    }

    /// API 4: `diff` computes a bounded, cursor-paginated path diff between two `TreeTarget`s (`Capability::Read`).
    pub fn diff(
        &mut self,
        req: &AuthenticatedRequest<DiffQueryPayload>,
        now_ms: u64,
    ) -> SynapseResult<PageResponse<DiffEntry>> {
        self.auth.authorize(
            BoundaryKind::Api,
            "diff",
            &self.repo_id,
            Capability::Read,
            req,
            now_ms,
        )?;
        let snap_seq = self.validate_page_request(&req.payload.page)?;
        let base_tree = self.materialize_virtual_tree(req.payload.base, Some(snap_seq))?;
        let target_tree = self.materialize_virtual_tree(req.payload.target, Some(snap_seq))?;

        let mut all_paths: BTreeSet<&String> = BTreeSet::new();
        all_paths.extend(base_tree.keys());
        all_paths.extend(target_tree.keys());

        let mut diffs = Vec::new();
        for path in all_paths {
            match (base_tree.get(path), target_tree.get(path)) {
                (None, Some(new_e)) => diffs.push(DiffEntry {
                    path: path.clone(),
                    status: DiffStatus::Added,
                    old_entry: None,
                    new_entry: Some(new_e.clone()),
                }),
                (Some(old_e), None) => diffs.push(DiffEntry {
                    path: path.clone(),
                    status: DiffStatus::Deleted,
                    old_entry: Some(old_e.clone()),
                    new_entry: None,
                }),
                (Some(old_e), Some(new_e)) => {
                    if old_e.blob_digest != new_e.blob_digest || old_e.mode != new_e.mode {
                        diffs.push(DiffEntry {
                            path: path.clone(),
                            status: DiffStatus::Modified,
                            old_entry: Some(old_e.clone()),
                            new_entry: Some(new_e.clone()),
                        });
                    }
                }
                (None, None) => {}
            }
        }

        paginate_slice(&diffs, &req.payload.page, snap_seq)
    }

    /// API 5: `history` returns a bounded, cursor-paginated changeset history (`Capability::Read`).
    pub fn history(
        &mut self,
        req: &AuthenticatedRequest<HistoryQueryPayload>,
        now_ms: u64,
    ) -> SynapseResult<PageResponse<HistoryEntry>> {
        self.auth.authorize(
            BoundaryKind::Api,
            "history",
            &self.repo_id,
            Capability::Read,
            req,
            now_ms,
        )?;
        let snap_seq = self.validate_page_request(&req.payload.page)?;

        let allowed_by_ancestor: Option<BTreeSet<ChangesetId>> =
            if let Some(head_id) = req.payload.ancestor_of {
                let mut set = BTreeSet::new();
                let mut stack = vec![head_id];
                while let Some(curr) = stack.pop() {
                    if set.insert(curr) {
                        let stored = self.store.get_changeset(curr, None, Some(snap_seq))?;
                        for p in &stored.envelope.parent_changesets {
                            stack.push(*p);
                        }
                    }
                }
                Some(set)
            } else {
                None
            };

        let allowed_by_path: Option<BTreeSet<ChangesetId>> =
            req.payload.path_filter.as_ref().map(|p| {
                self.path_index
                    .changesets_for_path(p)
                    .cloned()
                    .unwrap_or_default()
            });

        let all_visible = self.store.list_changesets(
            Some(&self.repo_id),
            req.payload.page.min_visible_seq,
            Some(snap_seq),
        )?;

        let mut entries: Vec<HistoryEntry> = all_visible
            .into_iter()
            .rev() // newest first
            .filter(|cs| {
                allowed_by_ancestor
                    .as_ref()
                    .is_none_or(|s| s.contains(&cs.changeset_id))
                    && allowed_by_path
                        .as_ref()
                        .is_none_or(|s| s.contains(&cs.changeset_id))
            })
            .map(|cs| HistoryEntry {
                changeset_id: cs.changeset_id,
                committed_seq: cs.committed_seq,
                author_did: cs.envelope.author_did.clone(),
                created_at_ms: cs.envelope.created_at_ms,
                base_git_oid: cs.envelope.base_git_oid,
                parent_changesets: cs.envelope.parent_changesets.clone(),
                intent_summary: cs.envelope.intent_summary.clone(),
                mutated_paths_count: cs.envelope.mutations.len(),
            })
            .collect();

        entries.sort_by_key(|a| std::cmp::Reverse(a.committed_seq));
        paginate_slice(&entries, &req.payload.page, snap_seq)
    }

    /// API 6: `provenance` returns the full cryptographic and audit provenance for a `ChangesetId` (`Capability::Read`).
    pub fn provenance(
        &mut self,
        req: &AuthenticatedRequest<(ChangesetId, Option<WalSeq>)>,
        now_ms: u64,
    ) -> SynapseResult<ProvenanceReport> {
        self.auth.authorize(
            BoundaryKind::Api,
            "provenance",
            &self.repo_id,
            Capability::Read,
            req,
            now_ms,
        )?;
        let (cs_id, snap_seq) = req.payload;
        let stored = self.store.get_changeset(cs_id, None, snap_seq)?;
        let github_projection = self
            .store
            .github_projections()
            .values()
            .find(|p| p.changeset_id == cs_id)
            .cloned();
        let canonical_promotion = self
            .store
            .canonical_head(&self.repo_id)
            .filter(|c| c.promoted_changeset_id == Some(cs_id))
            .cloned();
        let audit_trail: Vec<AuditEntry> = self
            .auth
            .audit_log()
            .entries()
            .iter()
            .filter(|e| e.repo_id == self.repo_id)
            .cloned()
            .collect();

        Ok(ProvenanceReport {
            changeset_id: cs_id,
            committed_seq: stored.committed_seq,
            repo_id: stored.envelope.repo_id,
            author_did: stored.envelope.author_did,
            idempotency_key: stored.envelope.idempotency_key,
            base_git_oid: stored.envelope.base_git_oid,
            parent_changesets: stored.envelope.parent_changesets,
            evaluations: stored.evaluations,
            reviews: stored.reviews,
            github_projection,
            canonical_promotion,
            audit_trail,
        })
    }

    /// API 7: `conflicts` detects path-level and file/directory collisions across concurrent changesets (`Capability::Read`).
    pub fn conflicts(
        &mut self,
        req: &AuthenticatedRequest<ConflictQueryPayload>,
        now_ms: u64,
    ) -> SynapseResult<PageResponse<PathConflict>> {
        self.auth.authorize(
            BoundaryKind::Api,
            "conflicts",
            &self.repo_id,
            Capability::Read,
            req,
            now_ms,
        )?;
        let snap_seq = self.validate_page_request(&req.payload.page)?;
        let cand_stored = self
            .store
            .get_changeset(req.payload.candidate, None, Some(snap_seq))?;

        let peers: Vec<StoredChangeset> = if let Some(ref explicit) = req.payload.against {
            let mut list = Vec::with_capacity(explicit.len());
            for &id in explicit {
                if id != req.payload.candidate {
                    list.push(self.store.get_changeset(id, None, Some(snap_seq))?);
                }
            }
            list
        } else {
            self.store
                .list_changesets(Some(&self.repo_id), None, Some(snap_seq))?
                .into_iter()
                .filter(|cs| {
                    cs.changeset_id != req.payload.candidate
                        && cs.envelope.base_git_oid == cand_stored.envelope.base_git_oid
                        && !cand_stored
                            .envelope
                            .parent_changesets
                            .contains(&cs.changeset_id)
                        && !cs
                            .envelope
                            .parent_changesets
                            .contains(&req.payload.candidate)
                })
                .collect()
        };

        let mut conflicts = Vec::new();
        for peer in &peers {
            for cm in &cand_stored.envelope.mutations {
                for pm in &peer.envelope.mutations {
                    if cm.path == pm.path && cm.op != pm.op {
                        conflicts.push(PathConflict {
                            path: cm.path.clone(),
                            candidate_changeset: cand_stored.changeset_id,
                            conflicting_changeset: peer.changeset_id,
                            reason: "concurrent incompatible mutations on same path".to_string(),
                        });
                    } else if is_file_dir_prefix_collision(&cm.path, &pm.path)
                        && !matches!(cm.op, MutationOp::Delete)
                        && !matches!(pm.op, MutationOp::Delete)
                    {
                        conflicts.push(PathConflict {
                            path: cm.path.clone(),
                            candidate_changeset: cand_stored.changeset_id,
                            conflicting_changeset: peer.changeset_id,
                            reason: format!(
                                "file/directory hierarchy collision between {} and {}",
                                cm.path, pm.path
                            ),
                        });
                    }
                }
            }
        }

        paginate_slice(&conflicts, &req.payload.page, snap_seq)
    }

    /// API 8: `status` returns repository watermarks, index counts, and canonical state (`Capability::Read`).
    pub fn status(
        &mut self,
        req: &AuthenticatedRequest<Option<WalSeq>>,
        now_ms: u64,
    ) -> SynapseResult<ServiceStatus> {
        self.auth.authorize(
            BoundaryKind::Api,
            "status",
            &self.repo_id,
            Capability::Read,
            req,
            now_ms,
        )?;
        let snap_seq = req.payload.unwrap_or_else(|| self.store.committed_seq());
        let state_root_digest = self.store.state_root_digest(Some(snap_seq))?;
        let visible_cs = self
            .store
            .list_changesets(Some(&self.repo_id), None, Some(snap_seq))?;
        let audit_chain_head = self.auth.audit_log().verify_chain()?;

        Ok(ServiceStatus {
            repo_id: self.repo_id.clone(),
            committed_seq: self.store.committed_seq(),
            last_frame_sha256: self.store.last_frame_sha256(),
            state_root_digest,
            total_changesets: visible_cs.len(),
            indexed_paths_count: self.path_index.indexed_paths_count(),
            cached_virtual_trees: self.path_index.cached_trees_count(),
            canonical_head: self.store.canonical_head(&self.repo_id).cloned(),
            audit_chain_head,
        })
    }

    /// API 9: `watch` returns a bounded page of WAL events after `after_seq` (or the recovered
    /// durable subscriber cursor) and atomically persists the updated `WatchCursor` (`Capability::Read`).
    pub fn watch(
        &mut self,
        req: &AuthenticatedRequest<WatchQueryPayload>,
        now_ms: u64,
    ) -> SynapseResult<(PageResponse<WatchEvent>, WatchCursor)> {
        self.auth.authorize(
            BoundaryKind::Api,
            "watch",
            &self.repo_id,
            Capability::Read,
            req,
            now_ms,
        )?;
        let snap_seq = self.validate_page_request(&req.payload.page)?;

        let start_after = if let Some(explicit) = req.payload.after_seq {
            explicit
        } else if let Some(saved) = self.load_watch_cursor(&req.payload.subscriber_id)? {
            saved.last_seen_seq
        } else {
            WalSeq::ZERO
        };

        let all_visible = self.store.list_changesets(
            Some(&self.repo_id),
            req.payload.page.min_visible_seq,
            Some(snap_seq),
        )?;

        let matching: Vec<WatchEvent> = all_visible
            .into_iter()
            .filter(|cs| cs.committed_seq > start_after)
            .map(|cs| WatchEvent {
                wal_seq: cs.committed_seq,
                changeset_id: cs.changeset_id,
                author_did: cs.envelope.author_did.clone(),
                intent_summary: cs.envelope.intent_summary.clone(),
                touched_paths: cs
                    .envelope
                    .mutations
                    .iter()
                    .map(|m| m.path.clone())
                    .collect(),
            })
            .collect();

        let page_resp = paginate_slice(&matching, &req.payload.page, snap_seq)?;
        let new_last_seen = page_resp
            .items
            .last()
            .map(|ev| ev.wal_seq)
            .unwrap_or(start_after);

        let cursor = WatchCursor {
            subscriber_id: req.payload.subscriber_id.clone(),
            repo_id: self.repo_id.clone(),
            last_seen_seq: new_last_seen,
            last_frame_sha256: self.store.last_frame_sha256(),
            updated_at_ms: now_ms,
        };
        self.save_watch_cursor(&cursor)?;
        Ok((page_resp, cursor))
    }

    /// Load a durable `WatchCursor` from disk if one exists for `subscriber_id`.
    pub fn load_watch_cursor(&self, subscriber_id: &str) -> SynapseResult<Option<WatchCursor>> {
        validate_subscriber_id(subscriber_id)?;
        let path = self.cursors_dir.join(format!("{subscriber_id}.json"));
        if !path.exists() {
            return Ok(None);
        }
        let raw = fs::read(&path)
            .map_err(|e| SynapseError::new(RefusalCode::IoFailure, e.to_string()))?;
        let cursor: WatchCursor = serde_json::from_slice(&raw)
            .map_err(|e| SynapseError::new(RefusalCode::CursorInvalid, e.to_string()))?;
        Ok(Some(cursor))
    }

    /// Atomically persist a durable `WatchCursor` to disk (`sync_all` + rename).
    pub fn save_watch_cursor(&self, cursor: &WatchCursor) -> SynapseResult<()> {
        validate_subscriber_id(&cursor.subscriber_id)?;
        let final_path = self
            .cursors_dir
            .join(format!("{}.json", cursor.subscriber_id));
        let tmp_path = self
            .cursors_dir
            .join(format!("{}.json.tmp", cursor.subscriber_id));
        let bytes = serde_json::to_vec(cursor)
            .map_err(|e| SynapseError::new(RefusalCode::IoFailure, e.to_string()))?;
        {
            let mut f = File::create(&tmp_path)
                .map_err(|e| SynapseError::new(RefusalCode::IoFailure, e.to_string()))?;
            f.write_all(&bytes)
                .map_err(|e| SynapseError::new(RefusalCode::IoFailure, e.to_string()))?;
            f.sync_all()
                .map_err(|e| SynapseError::new(RefusalCode::IoFailure, e.to_string()))?;
        }
        fs::rename(&tmp_path, &final_path)
            .map_err(|e| SynapseError::new(RefusalCode::IoFailure, e.to_string()))?;
        Ok(())
    }

    /// Run store compaction and immediately perform exact path-index invalidation
    /// for all evicted speculative changesets.
    pub fn checkpoint_compact_and_invalidate_index(
        &mut self,
        now_ms: u64,
    ) -> SynapseResult<CompactionReport> {
        let before_ids: Vec<ChangesetId> = self
            .store
            .list_changesets(Some(&self.repo_id), None, None)?
            .into_iter()
            .map(|cs| cs.changeset_id)
            .collect();

        let report = self.store.checkpoint_and_compact(now_ms)?;

        let retained_set: BTreeSet<ChangesetId> = self
            .store
            .list_changesets(Some(&self.repo_id), None, None)?
            .into_iter()
            .map(|cs| cs.changeset_id)
            .collect();

        for id in before_ids {
            if !retained_set.contains(&id) {
                self.path_index.invalidate_changeset(id);
            }
        }
        Ok(report)
    }

    /// Materialize the complete sorted `VirtualTree` for `target` without a working-tree checkout.
    pub fn materialize_virtual_tree(
        &mut self,
        target: TreeTarget,
        snapshot_seq: Option<WalSeq>,
    ) -> SynapseResult<BTreeMap<String, VirtualTreeEntry>> {
        match target {
            TreeTarget::BaseGitCommit(oid) => self.base_trees.get(&oid).cloned().ok_or_else(|| {
                SynapseError::new(
                    RefusalCode::BaseTreeNotFound,
                    format!("base_git_oid {oid} not found"),
                )
            }),
            TreeTarget::Changeset(cs_id) => {
                // Ensure the changeset is visible at `snapshot_seq`
                let stored = self.store.get_changeset(cs_id, None, snapshot_seq)?;
                if let Some(cached) = self.path_index.virtual_tree_cache.get(&cs_id) {
                    return Ok(cached.clone());
                }

                // Start from base_git_oid or overlay parent changesets in topological order
                let mut tree = if stored.envelope.parent_changesets.is_empty() {
                    self.base_trees
                        .get(&stored.envelope.base_git_oid)
                        .cloned()
                        .ok_or_else(|| {
                            SynapseError::new(
                                RefusalCode::BaseTreeNotFound,
                                format!("base_git_oid {} not found", stored.envelope.base_git_oid),
                            )
                        })?
                } else {
                    let mut merged = BTreeMap::new();
                    for &parent_id in &stored.envelope.parent_changesets {
                        let parent_tree = self.materialize_virtual_tree(
                            TreeTarget::Changeset(parent_id),
                            snapshot_seq,
                        )?;
                        for (k, v) in parent_tree {
                            merged.insert(k, v);
                        }
                    }
                    merged
                };

                // Apply this changeset's sorted path mutations
                for m in &stored.envelope.mutations {
                    match &m.op {
                        MutationOp::Upsert {
                            mode,
                            blob_digest,
                            size_bytes,
                        } => {
                            // Remove any conflicting file-vs-directory ancestor/descendant entries
                            let keys_to_remove: Vec<String> = tree
                                .keys()
                                .filter(|existing| is_file_dir_prefix_collision(existing, &m.path))
                                .cloned()
                                .collect();
                            for k in keys_to_remove {
                                tree.remove(&k);
                            }

                            let raw = self.read_blob_bytes(*blob_digest, snapshot_seq)?;
                            let git_blob_oid = GitOid::compute_blob(&raw);
                            tree.insert(
                                m.path.clone(),
                                VirtualTreeEntry {
                                    path: m.path.clone(),
                                    mode: *mode,
                                    blob_digest: *blob_digest,
                                    git_blob_oid,
                                    size_bytes: *size_bytes,
                                },
                            );
                        }
                        MutationOp::Delete => {
                            tree.remove(&m.path);
                        }
                    }
                }

                self.path_index
                    .virtual_tree_cache
                    .insert(cs_id, tree.clone());
                Ok(tree)
            }
        }
    }

    /// Read raw blob bytes from either the committed `SynapseStore` or imported base blobs.
    pub fn read_blob_bytes(
        &self,
        digest: BlobDigest,
        snapshot_seq: Option<WalSeq>,
    ) -> SynapseResult<Vec<u8>> {
        if let Ok(bytes) = self.store.get_blob_visible(digest, None, snapshot_seq) {
            return Ok(bytes);
        }
        if let Some(bytes) = self.base_blobs.get(&digest) {
            return Ok(bytes.clone());
        }
        Err(SynapseError::new(
            RefusalCode::BlobNotFound,
            format!("blob {digest} not found in store or base tree"),
        ))
    }

    pub fn root_dir(&self) -> &Path {
        &self.root_dir
    }

    pub fn repo_id(&self) -> &RepoId {
        &self.repo_id
    }

    /// Authorize an export/publication request (`Capability::Publish` at `BoundaryKind::Export`)
    /// against this service's repository authority and policy enforcer.
    pub fn authorize_export<T: Serialize>(
        &mut self,
        operation: &str,
        req: &AuthenticatedRequest<T>,
        now_ms: u64,
    ) -> SynapseResult<()> {
        self.auth.authorize(
            BoundaryKind::Export,
            operation,
            &self.repo_id,
            Capability::Publish,
            req,
            now_ms,
        )
    }

    fn validate_page_request(&self, page: &PageRequest) -> SynapseResult<WalSeq> {
        if page.limit == 0 || page.limit > self.max_page_size {
            return Err(SynapseError::new(
                RefusalCode::PaginationLimitExceeded,
                format!(
                    "page limit {} must be in 1..={}",
                    page.limit, self.max_page_size
                ),
            ));
        }
        let committed = self.store.committed_seq();
        if let Some(min_seq) = page.min_visible_seq {
            if min_seq > committed {
                return Err(SynapseError::new(
                    RefusalCode::VisibilitySeqAhead,
                    format!("min_visible_seq {min_seq} exceeds committed {committed}"),
                ));
            }
        }
        if let Some(snap) = page.snapshot_seq {
            if snap > committed {
                return Err(SynapseError::new(
                    RefusalCode::VisibilitySeqAhead,
                    format!("snapshot_seq {snap} exceeds committed {committed}"),
                ));
            }
            Ok(snap)
        } else {
            Ok(committed)
        }
    }
}

fn paginate_slice<T: Clone>(
    all: &[T],
    page: &PageRequest,
    snapshot_seq: WalSeq,
) -> SynapseResult<PageResponse<T>> {
    let start_idx = if let Some(ref cur) = page.cursor {
        let stripped = cur.strip_prefix("offset:").ok_or_else(|| {
            SynapseError::new(
                RefusalCode::CursorInvalid,
                format!("invalid pagination cursor: {cur}"),
            )
        })?;
        let idx: usize = stripped.parse().map_err(|_| {
            SynapseError::new(
                RefusalCode::CursorInvalid,
                format!("non-numeric pagination cursor: {cur}"),
            )
        })?;
        if idx > all.len() {
            return Err(SynapseError::new(
                RefusalCode::CursorInvalid,
                format!("cursor offset {idx} out of bounds for {} items", all.len()),
            ));
        }
        idx
    } else {
        0
    };

    let end_idx = (start_idx + page.limit).min(all.len());
    let items = all[start_idx..end_idx].to_vec();
    let next_cursor = if end_idx < all.len() {
        Some(format!("offset:{end_idx}"))
    } else {
        None
    };

    Ok(PageResponse {
        items,
        next_cursor,
        snapshot_seq,
        total_matching: all.len(),
    })
}

fn is_file_dir_prefix_collision(a: &str, b: &str) -> bool {
    if a == b {
        return false;
    }
    if let Some(rest) = a.strip_prefix(b) {
        return rest.starts_with('/');
    }
    if let Some(rest) = b.strip_prefix(a) {
        return rest.starts_with('/');
    }
    false
}

fn validate_subscriber_id(id: &str) -> SynapseResult<()> {
    if id.is_empty()
        || id.len() > 64
        || !id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
    {
        return Err(SynapseError::new(
            RefusalCode::CursorInvalid,
            format!("invalid subscriber_id: {id}"),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use synapse_auth::AgentCapabilityGrant;
    use synapse_core::{encode_did_key_ed25519, PathMutation, SYNAPSE_ENVELOPE_VERSION};

    fn temp_dir(label: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "synapse-api-test-{}-{}-{}",
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
    fn test_virtual_tree_and_diff_parity_against_git_cli() {
        let work = temp_dir("git-parity");
        let git_dir = work.join("git-repo");
        let store_dir = work.join("synapse-service");
        fs::create_dir_all(&git_dir).unwrap();

        // 1. Initialize a real Git repository and create base commit with multiple files
        Command::new("git")
            .arg("init")
            .current_dir(&git_dir)
            .output()
            .unwrap();
        Command::new("git")
            .args(["config", "user.name", "Synapse Test"])
            .current_dir(&git_dir)
            .output()
            .unwrap();
        Command::new("git")
            .args(["config", "user.email", "synapse@aienos.com"])
            .current_dir(&git_dir)
            .output()
            .unwrap();

        fs::create_dir_all(git_dir.join("src/net")).unwrap();
        fs::write(git_dir.join("README.md"), b"# Base Repo\n").unwrap();
        fs::write(git_dir.join("src/lib.rs"), b"pub mod net;\n").unwrap();
        fs::write(git_dir.join("src/net/http.rs"), b"pub fn serve() {}\n").unwrap();

        Command::new("git")
            .args(["add", "."])
            .current_dir(&git_dir)
            .output()
            .unwrap();
        Command::new("git")
            .args(["commit", "-m", "base commit"])
            .current_dir(&git_dir)
            .output()
            .unwrap();

        // 2. Open SynapseService and import base tree from the real Git repository
        let repo_id = RepoId::new("aien-spark/synapse").unwrap();
        let mut svc = SynapseService::open(
            &store_dir,
            repo_id.clone(),
            FsyncPolicy::EveryCommit,
            RecoveryPolicy::StrictFailClosed,
            StoreLimits::default(),
        )
        .unwrap();

        let auth_key = SigningKey::from_bytes(&[10u8; 32]);
        let auth_did = encode_did_key_ed25519(&auth_key.verifying_key().to_bytes());
        svc.register_authority(auth_did);

        let agent_key = SigningKey::from_bytes(&[20u8; 32]);
        let agent_did = encode_did_key_ed25519(&agent_key.verifying_key().to_bytes());
        let grant = AgentCapabilityGrant::issue(
            &auth_key,
            [1u8; 32],
            repo_id.clone(),
            agent_did,
            vec![Capability::Read, Capability::Propose],
            1024 * 1024,
            100,
            60_000,
            100,
            100_000,
        );

        let base_oid = svc
            .import_base_tree_from_git_repo(&git_dir, "HEAD")
            .unwrap();

        // 3. Submit Changeset 1 (modify src/lib.rs, add src/store.rs) and stacked Changeset 2 (delete src/net/http.rs, add scripts/run.sh)
        let lib_v2 = b"pub mod net;\npub mod store;\n";
        let store_v1 = b"pub struct Wal;\n";
        let lib_digest = BlobDigest::compute(lib_v2);
        let store_digest = BlobDigest::compute(store_v1);

        let mut env1 = ChangesetEnvelope {
            version: SYNAPSE_ENVELOPE_VERSION,
            repo_id: repo_id.clone(),
            base_git_oid: base_oid,
            parent_changesets: vec![],
            author_did: String::new(),
            idempotency_key: IdempotencyKey::from_label("cs1"),
            created_at_ms: 1_000,
            intent_summary: "Add store module".to_string(),
            mutations: vec![
                PathMutation {
                    path: "src/lib.rs".to_string(),
                    op: MutationOp::Upsert {
                        mode: FileMode::Regular644,
                        blob_digest: lib_digest,
                        size_bytes: lib_v2.len() as u64,
                    },
                },
                PathMutation {
                    path: "src/store.rs".to_string(),
                    op: MutationOp::Upsert {
                        mode: FileMode::Regular644,
                        blob_digest: store_digest,
                        size_bytes: store_v1.len() as u64,
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
            [10u8; 32],
            1_000,
            0,
            SubmitChangesetPayload {
                envelope: env1,
                blobs: vec![
                    (lib_digest, lib_v2.to_vec()),
                    (store_digest, store_v1.to_vec()),
                ],
            },
        )
        .unwrap();
        let cs1_id = match svc.submit(&sub1, 1_000).unwrap() {
            IngestOutcome::Committed { changeset_id, .. } => changeset_id,
            _ => unreachable!(),
        };

        let run_sh = b"#!/usr/bin/env bash\necho ok\n";
        let run_digest = BlobDigest::compute(run_sh);
        let mut env2 = ChangesetEnvelope {
            version: SYNAPSE_ENVELOPE_VERSION,
            repo_id: repo_id.clone(),
            base_git_oid: base_oid,
            parent_changesets: vec![cs1_id],
            author_did: String::new(),
            idempotency_key: IdempotencyKey::from_label("cs2"),
            created_at_ms: 2_000,
            intent_summary: "Remove http.rs and add run.sh".to_string(),
            mutations: vec![
                PathMutation {
                    path: "scripts/run.sh".to_string(),
                    op: MutationOp::Upsert {
                        mode: FileMode::Executable755,
                        blob_digest: run_digest,
                        size_bytes: run_sh.len() as u64,
                    },
                },
                PathMutation {
                    path: "src/net/http.rs".to_string(),
                    op: MutationOp::Delete,
                },
            ],
            evidence_receipts: vec![],
            signature: vec![],
        };
        env2.sign(&agent_key);

        let sub2 = AuthenticatedRequest::sign_new(
            &agent_key,
            grant.clone(),
            repo_id.clone(),
            Capability::Propose,
            [11u8; 32],
            2_000,
            0,
            SubmitChangesetPayload {
                envelope: env2,
                blobs: vec![(run_digest, run_sh.to_vec())],
            },
        )
        .unwrap();
        let cs2_id = match svc.submit(&sub2, 2_000).unwrap() {
            IngestOutcome::Committed { changeset_id, .. } => changeset_id,
            _ => unreachable!(),
        };

        // 4. Perform the exact same changes in Git to compare against Git's own ls-tree and diff!
        fs::write(git_dir.join("src/lib.rs"), lib_v2).unwrap();
        fs::write(git_dir.join("src/store.rs"), store_v1).unwrap();
        fs::remove_file(git_dir.join("src/net/http.rs")).unwrap();
        fs::create_dir_all(git_dir.join("scripts")).unwrap();
        fs::write(git_dir.join("scripts/run.sh"), run_sh).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(
                git_dir.join("scripts/run.sh"),
                fs::Permissions::from_mode(0o755),
            )
            .unwrap();
        }
        Command::new("git")
            .args(["add", "-A"])
            .current_dir(&git_dir)
            .output()
            .unwrap();
        Command::new("git")
            .args(["commit", "-m", "target commit"])
            .current_dir(&git_dir)
            .output()
            .unwrap();

        // Compare `SynapseService::tree(cs2_id)` against `git ls-tree -r HEAD`
        let tree_req = AuthenticatedRequest::sign_new(
            &agent_key,
            grant.clone(),
            repo_id.clone(),
            Capability::Read,
            [12u8; 32],
            2_100,
            0,
            TreeQueryPayload {
                target: TreeTarget::Changeset(cs2_id),
                path_prefix: None,
                page: PageRequest {
                    cursor: None,
                    limit: 2, // Exercise pagination across 4 files!
                    min_visible_seq: Some(WalSeq(2)),
                    snapshot_seq: None,
                },
            },
        )
        .unwrap();
        let page1 = svc.tree(&tree_req, 2_100).unwrap();
        assert_eq!(page1.items.len(), 2);
        assert_eq!(page1.total_matching, 4);
        assert!(page1.next_cursor.is_some());

        let tree_req2 = AuthenticatedRequest::sign_new(
            &agent_key,
            grant.clone(),
            repo_id.clone(),
            Capability::Read,
            [13u8; 32],
            2_101,
            0,
            TreeQueryPayload {
                target: TreeTarget::Changeset(cs2_id),
                path_prefix: None,
                page: PageRequest {
                    cursor: page1.next_cursor,
                    limit: 2,
                    min_visible_seq: Some(WalSeq(2)),
                    snapshot_seq: None,
                },
            },
        )
        .unwrap();
        let page2 = svc.tree(&tree_req2, 2_101).unwrap();
        assert_eq!(page2.items.len(), 2);
        assert!(page2.next_cursor.is_none());

        let mut synapse_ls_tree = String::new();
        for entry in page1.items.iter().chain(page2.items.iter()) {
            synapse_ls_tree.push_str(&format!(
                "{} blob {}\t{}\n",
                entry.mode.git_octal_str(),
                entry.git_blob_oid.to_hex(),
                entry.path
            ));
        }

        let git_ls_out = Command::new("git")
            .args(["ls-tree", "-r", "HEAD"])
            .current_dir(&git_dir)
            .output()
            .unwrap();
        let git_ls_tree = String::from_utf8(git_ls_out.stdout).unwrap();
        assert_eq!(synapse_ls_tree, git_ls_tree);

        // Compare `SynapseService::diff(base_oid, cs2_id)` against `git diff --name-status HEAD~1 HEAD`
        let diff_req = AuthenticatedRequest::sign_new(
            &agent_key,
            grant,
            repo_id,
            Capability::Read,
            [14u8; 32],
            2_102,
            0,
            DiffQueryPayload {
                base: TreeTarget::BaseGitCommit(base_oid),
                target: TreeTarget::Changeset(cs2_id),
                page: PageRequest::default(),
            },
        )
        .unwrap();
        let diff_resp = svc.diff(&diff_req, 2_102).unwrap();
        let mut synapse_diff = String::new();
        for d in &diff_resp.items {
            synapse_diff.push_str(&format!("{}\t{}\n", d.status.git_status_char(), d.path));
        }

        let git_diff_out = Command::new("git")
            .args(["diff", "--name-status", "HEAD~1", "HEAD"])
            .current_dir(&git_dir)
            .output()
            .unwrap();
        let git_diff_str = String::from_utf8(git_diff_out.stdout).unwrap();
        assert_eq!(synapse_diff, git_diff_str);

        let _ = fs::remove_dir_all(&work);
    }

    #[test]
    fn test_conflicts_history_provenance_status_path_invalidation_and_watch_cursor_recovery() {
        let dir = temp_dir("api-lifecycle");
        let repo_id = RepoId::new("aien-spark/synapse").unwrap();
        let limits = StoreLimits {
            default_retention_window_ms: 500,
            ..Default::default()
        };

        let auth_key = SigningKey::from_bytes(&[30u8; 32]);
        let auth_did = encode_did_key_ed25519(&auth_key.verifying_key().to_bytes());
        let agent_a = SigningKey::from_bytes(&[31u8; 32]);
        let agent_a_did = encode_did_key_ed25519(&agent_a.verifying_key().to_bytes());
        let agent_b = SigningKey::from_bytes(&[32u8; 32]);
        let agent_b_did = encode_did_key_ed25519(&agent_b.verifying_key().to_bytes());

        let base_oid = GitOid::compute_blob(b"base-tree");

        let (cs_a_id, cs_b_id);
        {
            let mut svc = SynapseService::open(
                &dir,
                repo_id.clone(),
                FsyncPolicy::EveryCommit,
                RecoveryPolicy::StrictFailClosed,
                limits.clone(),
            )
            .unwrap();
            svc.register_authority(auth_did.clone());
            svc.register_base_tree(
                base_oid,
                vec![(
                    "src/shared.rs".to_string(),
                    FileMode::Regular644,
                    b"pub fn v0() {}\n".to_vec(),
                )],
            )
            .unwrap();

            let grant_a = AgentCapabilityGrant::issue(
                &auth_key,
                [1u8; 32],
                repo_id.clone(),
                agent_a_did.clone(),
                vec![Capability::Read, Capability::Propose],
                1024 * 1024,
                100,
                60_000,
                10,
                100_000,
            );
            let grant_b = AgentCapabilityGrant::issue(
                &auth_key,
                [2u8; 32],
                repo_id.clone(),
                agent_b_did,
                vec![Capability::Read, Capability::Propose],
                1024 * 1024,
                100,
                60_000,
                10,
                100_000,
            );

            // Agent A submits changeset at t=100 (will expire when compacting at t=2000)
            let bytes_a = b"pub fn v_agent_a() {}\n";
            let dig_a = BlobDigest::compute(bytes_a);
            let mut env_a = ChangesetEnvelope {
                version: SYNAPSE_ENVELOPE_VERSION,
                repo_id: repo_id.clone(),
                base_git_oid: base_oid,
                parent_changesets: vec![],
                author_did: String::new(),
                idempotency_key: IdempotencyKey::from_label("a-1"),
                created_at_ms: 100,
                intent_summary: "Agent A edit shared.rs".to_string(),
                mutations: vec![PathMutation {
                    path: "src/shared.rs".to_string(),
                    op: MutationOp::Upsert {
                        mode: FileMode::Regular644,
                        blob_digest: dig_a,
                        size_bytes: bytes_a.len() as u64,
                    },
                }],
                evidence_receipts: vec![],
                signature: vec![],
            };
            env_a.sign(&agent_a);
            let req_a = AuthenticatedRequest::sign_new(
                &agent_a,
                grant_a.clone(),
                repo_id.clone(),
                Capability::Propose,
                [1u8; 32],
                100,
                0,
                SubmitChangesetPayload {
                    envelope: env_a,
                    blobs: vec![(dig_a, bytes_a.to_vec())],
                },
            )
            .unwrap();
            cs_a_id = match svc.submit(&req_a, 100).unwrap() {
                IngestOutcome::Committed { changeset_id, .. } => changeset_id,
                _ => unreachable!(),
            };

            // Agent B submits conflicting changeset at t=1800 (within retention window at t=2000)
            let bytes_b = b"pub fn v_agent_b() {}\n";
            let dig_b = BlobDigest::compute(bytes_b);
            let mut env_b = ChangesetEnvelope {
                version: SYNAPSE_ENVELOPE_VERSION,
                repo_id: repo_id.clone(),
                base_git_oid: base_oid,
                parent_changesets: vec![],
                author_did: String::new(),
                idempotency_key: IdempotencyKey::from_label("b-1"),
                created_at_ms: 1800,
                intent_summary: "Agent B edit shared.rs".to_string(),
                mutations: vec![PathMutation {
                    path: "src/shared.rs".to_string(),
                    op: MutationOp::Upsert {
                        mode: FileMode::Regular644,
                        blob_digest: dig_b,
                        size_bytes: bytes_b.len() as u64,
                    },
                }],
                evidence_receipts: vec![],
                signature: vec![],
            };
            env_b.sign(&agent_b);
            let req_b = AuthenticatedRequest::sign_new(
                &agent_b,
                grant_b,
                repo_id.clone(),
                Capability::Propose,
                [2u8; 32],
                1800,
                0,
                SubmitChangesetPayload {
                    envelope: env_b,
                    blobs: vec![(dig_b, bytes_b.to_vec())],
                },
            )
            .unwrap();
            cs_b_id = match svc.submit(&req_b, 1800).unwrap() {
                IngestOutcome::Committed { changeset_id, .. } => changeset_id,
                _ => unreachable!(),
            };

            // Detect conflict between cs_a and cs_b on src/shared.rs
            let conf_req = AuthenticatedRequest::sign_new(
                &agent_a,
                grant_a.clone(),
                repo_id.clone(),
                Capability::Read,
                [3u8; 32],
                1850,
                0,
                ConflictQueryPayload {
                    candidate: cs_a_id,
                    against: None,
                    page: PageRequest::default(),
                },
            )
            .unwrap();
            let conf_resp = svc.conflicts(&conf_req, 1850).unwrap();
            assert_eq!(conf_resp.items.len(), 1);
            assert_eq!(conf_resp.items[0].path, "src/shared.rs");
            assert_eq!(conf_resp.items[0].conflicting_changeset, cs_b_id);

            // Watch cursor reads 1st event (`limit: 1`) and persists durable cursor at WalSeq(1)
            let watch_req1 = AuthenticatedRequest::sign_new(
                &agent_a,
                grant_a.clone(),
                repo_id.clone(),
                Capability::Read,
                [4u8; 32],
                1860,
                0,
                WatchQueryPayload {
                    subscriber_id: "worker-lane-1".to_string(),
                    after_seq: None,
                    page: PageRequest {
                        cursor: None,
                        limit: 1,
                        min_visible_seq: None,
                        snapshot_seq: None,
                    },
                },
            )
            .unwrap();
            let (wpage1, wcur1) = svc.watch(&watch_req1, 1860).unwrap();
            assert_eq!(wpage1.items.len(), 1);
            assert_eq!(wcur1.last_seen_seq, WalSeq(1));

            // Materialize virtual tree for cs_a so it enters the cache before compaction
            let _ = svc
                .materialize_virtual_tree(TreeTarget::Changeset(cs_a_id), None)
                .unwrap();
            assert_eq!(svc.path_index().cached_trees_count(), 1);
            assert_eq!(
                svc.path_index()
                    .changesets_for_path("src/shared.rs")
                    .unwrap()
                    .len(),
                2
            );

            // Compact at t=2000: cs_a (t=100) is evicted and invalidated from PathIndex!
            let report = svc.checkpoint_compact_and_invalidate_index(2000).unwrap();
            assert_eq!(report.evicted_changesets, 1);
            assert_eq!(svc.path_index().cached_trees_count(), 0);
            let remaining_for_shared = svc
                .path_index()
                .changesets_for_path("src/shared.rs")
                .unwrap();
            assert_eq!(remaining_for_shared.len(), 1);
            assert!(remaining_for_shared.contains(&cs_b_id));
            assert!(!remaining_for_shared.contains(&cs_a_id));
        }

        // Reopen service from disk and verify durable watch cursor resumes from WalSeq(1) -> WalSeq(2)
        let mut reopened = SynapseService::open(
            &dir,
            repo_id.clone(),
            FsyncPolicy::EveryCommit,
            RecoveryPolicy::StrictFailClosed,
            limits,
        )
        .unwrap();
        reopened.register_authority(auth_did);
        let grant_a = AgentCapabilityGrant::issue(
            &auth_key,
            [9u8; 32],
            repo_id.clone(),
            agent_a_did,
            vec![Capability::Read],
            1024 * 1024,
            100,
            60_000,
            10,
            100_000,
        );
        let watch_req2 = AuthenticatedRequest::sign_new(
            &agent_a,
            grant_a,
            repo_id,
            Capability::Read,
            [5u8; 32],
            2100,
            0,
            WatchQueryPayload {
                subscriber_id: "worker-lane-1".to_string(),
                after_seq: None, // Automatically resumes from durable cursor on disk!
                page: PageRequest::default(),
            },
        )
        .unwrap();
        let (wpage2, wcur2) = reopened.watch(&watch_req2, 2100).unwrap();
        assert_eq!(wpage2.items.len(), 1);
        assert_eq!(wpage2.items[0].changeset_id, cs_b_id);
        assert_eq!(wcur2.last_seen_seq, WalSeq(2));

        let _ = fs::remove_dir_all(&dir);
    }
}
