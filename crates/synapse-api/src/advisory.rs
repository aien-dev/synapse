//! Pre-submit Crumb and claim advisory for changesets (ADR 0004, deliverable D3).
//!
//! For each path a changeset would mutate, report the Directory Crumb context of the path
//! at the base snapshot, unexpired claims held by other agents in the shared coordination
//! plane, overlapping open proposals, open proposals that rewrite a `.crumb` in the path's
//! chain, the context's invariants as guidance, and whether the `.crumb` chain changed
//! between the base and both the newest visible changeset and the canonical head.
//!
//! Advisory only. Nothing here blocks, authorizes, or writes: one `Capability::Read`
//! authorization (with its audit entry), reads through `materialize_virtual_tree` and
//! `read_blob_bytes`, and a read-only `CoordStore::sniff` (no lock taken, nothing written).
//! Synapse source conflicts at submit stay the only hard refusal.

use crate::{is_file_dir_prefix_collision, SynapseService, TreeTarget, VirtualTreeEntry};
use serde::{Deserialize, Serialize};
use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::sync::{Arc, OnceLock};
use synapse_auth::{AuthenticatedRequest, BoundaryKind, Capability};
use synapse_coord::{CoordStore, Holder, LockView, PathOracle, Workspace};
use synapse_core::{
    validate_repo_relative_path, ChangesetId, RefusalCode, SynapseError, SynapseResult, TreeDigest,
    WalSeq,
};
use synapse_crumb::{CrumbContext, CrumbContextDigest, ROOT_DIR};

/// Most paths one advisory request may name. More is refused with `QuotaTooManyPaths`.
pub const MAX_ADVISORY_PATHS: usize = 256;

/// Workspace label used for the read-only coordination query. It never matches a real
/// worktree, so it only affects `Sniff::other_workspaces`, which the advisory ignores.
const ADVISORY_WORKSPACE: &str = "/synapse/advisory";

/// Request payload for [`SynapseService::changeset_advisory`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChangesetAdvisoryPayload {
    /// Snapshot the changeset would be built on.
    pub base: TreeTarget,
    /// Snapshot to compare `.crumb` chains against. `None`: the most recently committed
    /// visible changeset (promoted or not). The canonical head is compared separately.
    pub latest: Option<TreeTarget>,
    /// Repository-relative paths the changeset would mutate (at most [`MAX_ADVISORY_PATHS`]).
    pub paths: Vec<String>,
    /// The caller's agent name in the coordination plane. Its own claims are not reported.
    /// Self-declared: it can only hide claims from the caller's own report.
    pub agent: String,
    pub snapshot_seq: Option<WalSeq>,
}

/// Whether the shared coordination plane was consulted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CoordinationStatus {
    /// No `CoordStore` was supplied; claims are not reported.
    NotSupplied,
    Read,
    /// The store could not be read; claims are not reported. The advisory still answers.
    Unavailable {
        reason: String,
    },
}

/// Whether the `.crumb` chain of a path's directory differs between base and latest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Staleness {
    /// Same chain digest at base and latest (or base is the latest snapshot).
    Current,
    /// The chain changed after the base: the context below may be out of date.
    Stale { latest_digest: CrumbContextDigest },
    /// No latest snapshot to compare with.
    Unknown,
}

/// One invariant, surfaced as guidance. Nothing enforces it (ADR 0004 section 2.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GuidanceNote {
    /// Directory whose `.crumb` states the invariant.
    pub dir: String,
    pub text: String,
}

/// A visible changeset outside the base and canonical lineages that touches the path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OverlappingProposal {
    pub changeset_id: ChangesetId,
    pub author_did: String,
    pub committed_seq: WalSeq,
    /// The proposal's mutated path that overlaps (same path, or file/directory collision).
    pub mutated_path: String,
}

/// Advisory for one mutated path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PathAdvisory {
    pub path: String,
    /// Context of the path's directory at the base snapshot.
    pub context: CrumbContext,
    pub digest: CrumbContextDigest,
    /// Unexpired claims by other agents on the path or a directory containing it.
    pub claims: Vec<LockView>,
    pub overlapping_proposals: Vec<OverlappingProposal>,
    /// Open proposals that change a `.crumb` in the path's chain (the path's directory or
    /// any ancestor), whether or not they touch the path. Each also adds a guidance note.
    pub pending_crumb_changes: Vec<OverlappingProposal>,
    /// Invariants of the nearest crumb, then inherited ones (closest ancestor first).
    /// Then one note per entry of `pending_crumb_changes`.
    pub guidance: Vec<GuidanceNote>,
    /// Base chain against `compared_to`.
    pub staleness: Staleness,
    /// Base chain against the canonical head (`Unknown` unless `canonical` is `Promoted`).
    pub canonical_staleness: Staleness,
}

/// The canonical head the advisory compared against.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CanonicalStatus {
    /// No canonical head, or its promoted changeset is not visible at the snapshot.
    NoHead,
    /// The changeset the canonical head promotes.
    Promoted(TreeTarget),
    /// `snapshot_seq` is older than the committed state. The store keeps only the current
    /// head, so the head at that snapshot is not known and is not used.
    NotAtSnapshot,
}

/// Result of [`SynapseService::changeset_advisory`]. Grants nothing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChangesetAdvisory {
    /// Snapshot the staleness check compared against (`None`: nothing to compare with).
    pub compared_to: Option<TreeTarget>,
    /// Canonical head used for `canonical_staleness` and to settle its lineage.
    pub canonical: CanonicalStatus,
    pub coordination: CoordinationStatus,
    /// One entry per requested path, in request order.
    pub paths: Vec<PathAdvisory>,
}

/// Most materialized snapshots one thread keeps for advisory and Crumb reads.
pub const SNAPSHOT_VIEW_CACHE_ENTRIES: usize = 4;

/// Largest snapshot (file count) the view cache keeps. A larger tree is built for the call
/// and not kept, so the cache holds at most `ENTRIES x MAX_FILES` paths.
pub const SNAPSHOT_VIEW_CACHE_MAX_FILES: usize = 1 << 18;

/// A materialized snapshot shared by the advisory and Crumb reads of one thread (issue #94):
/// the virtual tree, and the set of its paths plus every ancestor directory (built on first
/// use). Keyed by the snapshot's [`TreeDigest`], which binds every path, mode, blob digest and
/// size of the tree (the Git blob OID is a function of the blob content), so a view is
/// never stale: a different tree has a different key. Visibility of the target at the
/// requested `snapshot_seq` is still checked on every call by resolving the digest.
pub(crate) struct SnapshotView {
    tree: BTreeMap<String, VirtualTreeEntry>,
    paths: OnceLock<BTreeSet<String>>,
}

impl SnapshotView {
    pub(crate) fn tree(&self) -> &BTreeMap<String, VirtualTreeEntry> {
        &self.tree
    }

    /// Every path of the tree plus its ancestor directories.
    fn paths(&self) -> &BTreeSet<String> {
        self.paths.get_or_init(|| {
            let mut set = BTreeSet::new();
            for path in self.tree.keys() {
                let mut p = path.as_str();
                set.insert(p.to_string());
                while let Some((parent, _)) = p.rsplit_once('/') {
                    if !set.insert(parent.to_string()) {
                        break;
                    }
                    p = parent;
                }
            }
            set
        })
    }
}

#[derive(Default)]
struct SnapshotViewCache {
    /// Oldest first.
    entries: VecDeque<(TreeDigest, Arc<SnapshotView>)>,
    /// Trees materialized for a view (cache misses).
    builds: u64,
}

thread_local! {
    static SNAPSHOT_VIEWS: RefCell<SnapshotViewCache> = RefCell::new(SnapshotViewCache::default());
}

/// Trees this thread materialized for snapshot views (cache misses).
#[cfg(test)]
pub(crate) fn snapshot_view_builds() -> u64 {
    SNAPSHOT_VIEWS.with(|c| c.borrow().builds)
}

/// Snapshot views this thread keeps.
#[cfg(test)]
pub(crate) fn snapshot_view_entries() -> usize {
    SNAPSHOT_VIEWS.with(|c| c.borrow().entries.len())
}

impl SynapseService {
    /// The materialized `target` at `snapshot_seq`: from this thread's view cache when the
    /// same tree was materialized before, else built once with `materialize_virtual_tree`.
    /// Same tree, same errors: the digest lookup runs the same visibility checks.
    pub(crate) fn snapshot_view(
        &mut self,
        target: TreeTarget,
        snapshot_seq: Option<WalSeq>,
    ) -> SynapseResult<Arc<SnapshotView>> {
        let root = self.tree_digest(target, snapshot_seq)?;
        let hit = SNAPSHOT_VIEWS
            .try_with(|c| {
                c.borrow()
                    .entries
                    .iter()
                    .find(|(d, _)| *d == root)
                    .map(|(_, v)| Arc::clone(v))
            })
            .ok()
            .flatten();
        if let Some(view) = hit {
            return Ok(view);
        }
        let view = Arc::new(SnapshotView {
            tree: self.materialize_virtual_tree(target, snapshot_seq)?,
            paths: OnceLock::new(),
        });
        let keep = view.tree.len() <= SNAPSHOT_VIEW_CACHE_MAX_FILES;
        let _ = SNAPSHOT_VIEWS.try_with(|c| {
            let mut c = c.borrow_mut();
            c.builds += 1;
            if keep {
                if c.entries.len() >= SNAPSHOT_VIEW_CACHE_ENTRIES {
                    c.entries.pop_front();
                }
                c.entries.push_back((root, Arc::clone(&view)));
            }
        });
        Ok(view)
    }
}

/// Answers `exists` from a snapshot (files and their ancestor directories), so claim keys
/// resolve the way `crumb.c` resolves them against a checkout.
struct SnapshotOracle(Arc<SnapshotView>);

impl PathOracle for SnapshotOracle {
    fn exists(&self, rel: &str) -> bool {
        self.0.paths().contains(rel)
    }
}

impl SynapseService {
    /// Pre-submit advisory for the paths a changeset would mutate (`Capability::Read`).
    ///
    /// `coord` is the shared coordination plane to read claims from; `None` skips claims.
    /// Refuses more than [`MAX_ADVISORY_PATHS`] paths (`QuotaTooManyPaths`), invalid paths
    /// (`PathInvalid`) and repeated paths (`PathDuplicate`). A path absent from the base is
    /// allowed (a new file) and gets the context of its parent directory.
    pub fn changeset_advisory(
        &mut self,
        req: &AuthenticatedRequest<ChangesetAdvisoryPayload>,
        coord: Option<&CoordStore>,
        now_ms: u64,
    ) -> SynapseResult<ChangesetAdvisory> {
        self.auth.authorize(
            BoundaryKind::Api,
            "changeset_advisory",
            &self.repo_id,
            Capability::Read,
            req,
            now_ms,
        )?;
        let payload = &req.payload;
        if payload.paths.len() > MAX_ADVISORY_PATHS {
            return Err(SynapseError::new(
                RefusalCode::QuotaTooManyPaths,
                format!(
                    "advisory names {} paths, more than {MAX_ADVISORY_PATHS}",
                    payload.paths.len()
                ),
            ));
        }
        let mut seen = BTreeSet::new();
        for p in &payload.paths {
            validate_repo_relative_path(p)?;
            if !seen.insert(p.as_str()) {
                return Err(SynapseError::new(
                    RefusalCode::PathDuplicate,
                    format!("path {p} named twice"),
                ));
            }
        }

        // Pin one snapshot so every read below sees the same state.
        let committed = self.store.committed_seq();
        let snap = Some(payload.snapshot_seq.unwrap_or(committed));
        let visible = self
            .store
            .list_changesets(Some(&self.repo_id), None, snap)?;
        // The store keeps only the current canonical head, with no history, so it is the
        // head at the pinned snapshot only when that snapshot is the committed state.
        let canonical = if snap == Some(committed) {
            match self
                .store
                .canonical_head(&self.repo_id)
                .and_then(|h| h.promoted_changeset_id)
                .filter(|id| visible.iter().any(|cs| cs.changeset_id == *id))
            {
                Some(id) => CanonicalStatus::Promoted(TreeTarget::Changeset(id)),
                None => CanonicalStatus::NoHead,
            }
        } else {
            CanonicalStatus::NotAtSnapshot
        };
        let promoted = match canonical {
            CanonicalStatus::Promoted(TreeTarget::Changeset(id)) => Some(id),
            _ => None,
        };

        let base_view = self.snapshot_view(payload.base, snap)?;
        let base_tree = base_view.tree();
        let compared_to = payload.latest.or_else(|| {
            visible
                .last()
                .map(|cs| TreeTarget::Changeset(cs.changeset_id))
        });
        let latest_tree = match compared_to {
            Some(t) if t != payload.base => Some(self.snapshot_view(t, snap)?),
            _ => None,
        };
        let canonical_tree = match canonical {
            CanonicalStatus::Promoted(t) if t != payload.base && Some(t) != compared_to => {
                Some(self.snapshot_view(t, snap)?)
            }
            _ => None,
        };

        // Changesets already in the base snapshot or the canonical lineage are not open.
        let mut settled = BTreeSet::new();
        if let TreeTarget::Changeset(id) = payload.base {
            self.collect_lineage(id, snap, &mut settled)?;
        }
        if let Some(id) = promoted {
            self.collect_lineage(id, snap, &mut settled)?;
        }
        let open: Vec<_> = visible
            .iter()
            .filter(|cs| !settled.contains(&cs.changeset_id))
            .collect();

        // One oracle over the base snapshot serves the store query and the claim keys.
        let oracle_ws = Workspace::with_oracle(
            ADVISORY_WORKSPACE,
            Holder::default(),
            Box::new(SnapshotOracle(Arc::clone(&base_view))),
        );
        let (coordination, locks) = match coord {
            None => (CoordinationStatus::NotSupplied, Vec::new()),
            Some(store) => match store.sniff(&oracle_ws, &payload.agent, ROOT_DIR) {
                // A lock record without a holder is malformed; it names no one to ask.
                Ok(s) => (
                    CoordinationStatus::Read,
                    s.locks
                        .into_iter()
                        .filter(|l| !l.holder.is_empty())
                        .collect(),
                ),
                Err(e) => (
                    CoordinationStatus::Unavailable {
                        reason: e.to_string(),
                    },
                    Vec::new(),
                ),
            },
        };

        let mut out = Vec::with_capacity(payload.paths.len());
        for path in &payload.paths {
            let dir = context_dir(base_tree, path);
            let context = self.resolve_crumb_context(base_tree, &dir, snap)?;
            let digest = context.digest();
            let staleness = match (&compared_to, &latest_tree) {
                (None, _) => Staleness::Unknown,
                (Some(_), None) => Staleness::Current,
                (Some(_), Some(lt)) => self.staleness_against(lt.tree(), &dir, digest, snap)?,
            };
            let canonical_staleness = match canonical {
                CanonicalStatus::Promoted(t) if t == payload.base => Staleness::Current,
                CanonicalStatus::Promoted(_) => match &canonical_tree {
                    Some(ct) => self.staleness_against(ct.tree(), &dir, digest, snap)?,
                    // The canonical changeset is `compared_to`: same answer.
                    None => staleness.clone(),
                },
                _ => Staleness::Unknown,
            };

            // Same key rule as `crumb claim` from the repository root.
            let key = oracle_ws
                .target_key(path, ROOT_DIR)
                .map_err(|e| SynapseError::new(RefusalCode::PathInvalid, e.to_string()))?;
            let claims = locks
                .iter()
                .filter(|l| l.holder != payload.agent && claim_covers(&l.key, &key))
                .cloned()
                .collect();

            let overlapping_proposals = open_mutations(&open, |m| {
                m == path || is_file_dir_prefix_collision(m, path)
            });
            let chain = crumb_chain(&dir);
            let pending_crumb_changes = open_mutations(&open, |m| chain.contains(m));

            let mut guidance = guidance_notes(&context);
            guidance.extend(pending_crumb_changes.iter().map(|p| {
                GuidanceNote {
                    dir: p
                        .mutated_path
                        .rsplit_once('/')
                        .map_or(ROOT_DIR, |(d, _)| d)
                        .to_string(),
                    text: format!(
                        "open proposal {} changes {}; this guidance may change",
                        p.changeset_id, p.mutated_path
                    ),
                }
            }));
            out.push(PathAdvisory {
                path: path.clone(),
                context,
                digest,
                claims,
                overlapping_proposals,
                pending_crumb_changes,
                guidance,
                staleness,
                canonical_staleness,
            });
        }
        Ok(ChangesetAdvisory {
            compared_to,
            canonical,
            coordination,
            paths: out,
        })
    }

    /// Compare `digest` (the base context of `dir`) with the context of `dir` in `tree`.
    fn staleness_against(
        &self,
        tree: &BTreeMap<String, VirtualTreeEntry>,
        dir: &str,
        digest: CrumbContextDigest,
        snap: Option<WalSeq>,
    ) -> SynapseResult<Staleness> {
        let latest_digest = self.resolve_crumb_context(tree, dir, snap)?.digest();
        Ok(if latest_digest == digest {
            Staleness::Current
        } else {
            Staleness::Stale { latest_digest }
        })
    }

    /// Add `start` and every changeset it transitively builds on to `out`.
    fn collect_lineage(
        &self,
        start: ChangesetId,
        snap: Option<WalSeq>,
        out: &mut BTreeSet<ChangesetId>,
    ) -> SynapseResult<()> {
        let mut stack = vec![start];
        while let Some(id) = stack.pop() {
            if out.insert(id) {
                let cs = self.store.get_changeset(id, None, snap)?;
                stack.extend(cs.envelope.parent_changesets.iter().copied());
            }
        }
        Ok(())
    }
}

/// Directory whose context applies: the path if it is a directory in `tree`, else its
/// parent (a file, or a path the changeset would create).
fn context_dir(tree: &BTreeMap<String, VirtualTreeEntry>, path: &str) -> String {
    let prefix = format!("{path}/");
    let is_dir = tree
        .range(prefix.clone()..)
        .next()
        .is_some_and(|(k, _)| k.starts_with(&prefix));
    if is_dir {
        return path.to_string();
    }
    path.rsplit_once('/')
        .map_or(ROOT_DIR.to_string(), |(parent, _)| parent.to_string())
}

/// A claim on `lock_key` covers `key` when it names the same path or a directory above it.
fn claim_covers(lock_key: &str, key: &str) -> bool {
    lock_key == ROOT_DIR
        || lock_key == key
        || key
            .strip_prefix(lock_key)
            .is_some_and(|rest| rest.starts_with('/'))
}

/// Every open proposal mutation whose path satisfies `hit`, in commit order.
fn open_mutations(
    open: &[&synapse_store::StoredChangeset],
    hit: impl Fn(&str) -> bool,
) -> Vec<OverlappingProposal> {
    open.iter()
        .flat_map(|cs| {
            cs.envelope
                .mutations
                .iter()
                .filter(|m| hit(&m.path))
                .map(move |m| OverlappingProposal {
                    changeset_id: cs.changeset_id,
                    author_did: cs.envelope.author_did.clone(),
                    committed_seq: cs.committed_seq,
                    mutated_path: m.path.clone(),
                })
        })
        .collect()
}

/// The `.crumb` paths of `dir` and every directory above it, root included.
fn crumb_chain(dir: &str) -> BTreeSet<String> {
    let mut out = BTreeSet::from([".crumb".to_string()]);
    let mut d = dir;
    while d != ROOT_DIR && !d.is_empty() {
        out.insert(format!("{d}/.crumb"));
        d = d.rsplit_once('/').map_or(ROOT_DIR, |(p, _)| p);
    }
    out
}

fn guidance_notes(context: &CrumbContext) -> Vec<GuidanceNote> {
    let own = context.nearest().and_then(|e| {
        e.crumb().map(|c| {
            c.invariants()
                .iter()
                .map(move |i| (e.dir.as_str(), i.as_str()))
        })
    });
    own.into_iter()
        .flatten()
        .chain(context.inherited_invariants())
        .map(|(dir, text)| GuidanceNote {
            dir: dir.to_string(),
            text: text.to_string(),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{FsyncPolicy, RecoveryPolicy, StoreLimits, SubmitChangesetPayload};
    use ed25519_dalek::SigningKey;
    use std::fs;
    use std::path::PathBuf;
    use synapse_auth::AgentCapabilityGrant;
    use synapse_coord::{ClaimOutcome, NoOracle};
    use synapse_core::{
        encode_did_key_ed25519, BlobDigest, ChangesetEnvelope, FileMode, GitOid, IdempotencyKey,
        MutationOp, PathMutation, RepoId, SYNAPSE_ENVELOPE_VERSION,
    };
    use synapse_store::IngestOutcome;

    const ROOT: &[u8] =
        br#"{"schema_version":"1.0.0","name":"root","purpose":"Root.","invariants":["root rule"]}"#;
    const SRC: &[u8] = br#"{"schema_version":"1.0.0","name":"src","purpose":"Sources.","invariants":["src rule"]}"#;
    const T0: i64 = 1_800_000_000;

    struct Fixture {
        svc: SynapseService,
        auth: SigningKey,
        repo: RepoId,
        nonce: u8,
        dir: PathBuf,
        base: TreeTarget,
    }

    impl Fixture {
        fn new(label: &str) -> Self {
            let dir = std::env::temp_dir().join(format!(
                "synapse-api-advisory-{label}-{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            ));
            let repo = RepoId::new("aien-spark/synapse").unwrap();
            let mut svc = SynapseService::open(
                dir.join("svc"),
                repo.clone(),
                FsyncPolicy::EveryCommit,
                RecoveryPolicy::StrictFailClosed,
                StoreLimits::default(),
            )
            .unwrap();
            let auth = SigningKey::from_bytes(&[10u8; 32]);
            svc.register_authority(encode_did_key_ed25519(&auth.verifying_key().to_bytes()));
            let oid = GitOid([1; 20]);
            let files = [
                (".crumb", ROOT),
                ("src/.crumb", SRC),
                ("src/a.rs", b"fn a() {}\n".as_slice()),
                ("src/b.rs", b"fn b() {}\n".as_slice()),
                ("docs/x.md", b"# x\n".as_slice()),
            ];
            svc.register_base_tree(
                oid,
                files
                    .iter()
                    .map(|(p, b)| (p.to_string(), FileMode::Regular644, b.to_vec()))
                    .collect(),
            )
            .unwrap();
            Self {
                svc,
                auth,
                repo,
                nonce: 0,
                dir,
                base: TreeTarget::BaseGitCommit(oid),
            }
        }

        fn grant(&mut self, agent: &SigningKey, caps: Vec<Capability>) -> AgentCapabilityGrant {
            self.nonce += 1;
            AgentCapabilityGrant::issue(
                &self.auth,
                [self.nonce; 32],
                self.repo.clone(),
                encode_did_key_ed25519(&agent.verifying_key().to_bytes()),
                caps,
                1024 * 1024,
                100,
                60_000,
                10,
                100_000,
            )
        }

        /// Submit a changeset on the base by `agent` upserting `path` with `bytes`.
        fn propose(
            &mut self,
            agent: &SigningKey,
            label: &str,
            path: &str,
            bytes: &[u8],
        ) -> ChangesetId {
            let digest = BlobDigest::compute(bytes);
            let mut env = ChangesetEnvelope {
                version: SYNAPSE_ENVELOPE_VERSION,
                repo_id: self.repo.clone(),
                base_git_oid: GitOid([1; 20]),
                parent_changesets: vec![],
                author_did: String::new(),
                idempotency_key: IdempotencyKey::from_label(label),
                created_at_ms: 100,
                intent_summary: label.to_string(),
                mutations: vec![PathMutation {
                    path: path.to_string(),
                    op: MutationOp::Upsert {
                        mode: FileMode::Regular644,
                        blob_digest: digest,
                        size_bytes: bytes.len() as u64,
                    },
                }],
                evidence_receipts: vec![],
                signature: vec![],
            };
            env.sign(agent);
            let grant = self.grant(agent, vec![Capability::Propose]);
            let now = 1000 + u64::from(self.nonce);
            let req = AuthenticatedRequest::sign_new(
                agent,
                grant,
                self.repo.clone(),
                Capability::Propose,
                [self.nonce; 32],
                now,
                0,
                SubmitChangesetPayload {
                    envelope: env,
                    blobs: vec![(digest, bytes.to_vec())],
                },
            )
            .unwrap();
            match self.svc.submit(&req, now).unwrap() {
                IngestOutcome::Committed { changeset_id, .. } => changeset_id,
                other => panic!("unexpected {other:?}"),
            }
        }

        fn advise_as(
            &mut self,
            caps: Vec<Capability>,
            agent: &str,
            paths: &[&str],
            coord: Option<&CoordStore>,
        ) -> SynapseResult<ChangesetAdvisory> {
            let key = SigningKey::from_bytes(&[20u8; 32]);
            let grant = self.grant(&key, caps);
            let now = 1000 + u64::from(self.nonce);
            let req = AuthenticatedRequest::sign_new(
                &key,
                grant,
                self.repo.clone(),
                Capability::Read,
                [self.nonce; 32],
                now,
                0,
                ChangesetAdvisoryPayload {
                    base: self.base,
                    latest: None,
                    paths: paths.iter().map(|p| p.to_string()).collect(),
                    agent: agent.to_string(),
                    snapshot_seq: None,
                },
            )?;
            self.svc.changeset_advisory(&req, coord, now)
        }

        fn advise(&mut self, paths: &[&str], coord: Option<&CoordStore>) -> ChangesetAdvisory {
            self.advise_as(vec![Capability::Read], "alice", paths, coord)
                .unwrap()
        }

        fn coord(&self, now: i64) -> CoordStore {
            CoordStore::open(self.dir.join("coord")).with_clock(move || now)
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.dir);
        }
    }

    fn claim(store: &CoordStore, agent: &str, target: &str, ttl: i64) {
        let ws = Workspace::with_oracle(
            format!("/synapse/ws/{agent}"),
            Holder::synapse("lane", "00112233445566778899", "aabbccddeeff00112233"),
            Box::new(NoOracle),
        );
        let out = store
            .claim(&ws, agent, ROOT_DIR, target, "edit", Some(ttl))
            .unwrap();
        assert!(matches!(out, ClaimOutcome::Claimed { .. }), "{out:?}");
    }

    fn bob() -> SigningKey {
        SigningKey::from_bytes(&[30u8; 32])
    }

    #[test]
    fn same_file_collision_reports_the_open_proposal() {
        let mut fx = Fixture::new("same");
        let cs = fx.propose(&bob(), "bob-a", "src/a.rs", b"fn a2() {}\n");
        let adv = fx.advise(&["src/a.rs"], None);
        let p = &adv.paths[0];
        assert_eq!(p.overlapping_proposals.len(), 1);
        assert_eq!(p.overlapping_proposals[0].changeset_id, cs);
        assert_eq!(p.overlapping_proposals[0].mutated_path, "src/a.rs");
        assert_eq!(
            p.overlapping_proposals[0].author_did,
            encode_did_key_ed25519(&bob().verifying_key().to_bytes())
        );
        assert_eq!(adv.coordination, CoordinationStatus::NotSupplied);
        assert_eq!(adv.compared_to, Some(TreeTarget::Changeset(cs)));
        assert_eq!(p.staleness, Staleness::Current);
    }

    #[test]
    fn separate_files_do_not_overlap() {
        let mut fx = Fixture::new("separate");
        fx.propose(&bob(), "bob-b", "src/b.rs", b"fn b2() {}\n");
        let adv = fx.advise(&["src/a.rs", "docs/x.md"], None);
        assert!(adv.paths.iter().all(|p| p.overlapping_proposals.is_empty()));
    }

    #[test]
    fn proposal_in_the_base_lineage_is_not_open() {
        let mut fx = Fixture::new("lineage");
        let cs = fx.propose(&bob(), "bob-a", "src/a.rs", b"fn a2() {}\n");
        fx.base = TreeTarget::Changeset(cs);
        let adv = fx.advise(&["src/a.rs"], None);
        assert!(adv.paths[0].overlapping_proposals.is_empty());
    }

    #[test]
    fn context_digest_and_guidance_come_from_the_base() {
        let mut fx = Fixture::new("context");
        let adv = fx.advise(&["src/new.rs", "src"], None);
        let new_file = &adv.paths[0];
        assert_eq!(new_file.context.target_dir(), "src");
        assert_eq!(new_file.digest, new_file.context.digest());
        let notes: Vec<(&str, &str)> = new_file
            .guidance
            .iter()
            .map(|n| (n.dir.as_str(), n.text.as_str()))
            .collect();
        assert_eq!(notes, [("src", "src rule"), (".", "root rule")]);
        // A directory path resolves to itself, so it shares the file's context.
        assert_eq!(adv.paths[1].digest, new_file.digest);
        // No changesets yet: nothing to compare with.
        assert_eq!(adv.compared_to, None);
        assert_eq!(new_file.staleness, Staleness::Unknown);
    }

    #[test]
    fn claim_held_by_another_agent_is_reported() {
        let mut fx = Fixture::new("claim");
        let store = fx.coord(T0);
        claim(&store, "bob", "src/a.rs", 600);
        claim(&store, "carol", "docs", 600);
        let adv = fx.advise(&["src/a.rs", "src/b.rs", "docs/x.md"], Some(&store));
        assert_eq!(adv.coordination, CoordinationStatus::Read);
        assert_eq!(adv.paths[0].claims.len(), 1);
        assert_eq!(adv.paths[0].claims[0].holder, "bob");
        assert_eq!(adv.paths[0].claims[0].key, "src/a.rs");
        assert!(adv.paths[1].claims.is_empty());
        // A directory claim covers the files under it.
        assert_eq!(adv.paths[2].claims.len(), 1);
        assert_eq!(adv.paths[2].claims[0].holder, "carol");
    }

    #[test]
    fn expired_claim_is_ignored() {
        let mut fx = Fixture::new("expired");
        claim(&fx.coord(T0), "bob", "src/a.rs", 60);
        let live = fx.advise(&["src/a.rs"], Some(&fx.coord(T0 + 60)));
        assert_eq!(live.paths[0].claims.len(), 1);
        let later = fx.advise(&["src/a.rs"], Some(&fx.coord(T0 + 61)));
        assert_eq!(later.coordination, CoordinationStatus::Read);
        assert!(later.paths[0].claims.is_empty());
    }

    #[test]
    fn own_claim_is_not_reported_as_conflict() {
        let mut fx = Fixture::new("own");
        let store = fx.coord(T0);
        claim(&store, "alice", "src/a.rs", 600);
        let mine = fx.advise(&["src/a.rs"], Some(&store));
        assert!(mine.paths[0].claims.is_empty());
        let theirs = fx
            .advise_as(vec![Capability::Read], "bob", &["src/a.rs"], Some(&store))
            .unwrap();
        assert_eq!(theirs.paths[0].claims[0].holder, "alice");
    }

    #[test]
    fn stale_context_is_flagged() {
        let mut fx = Fixture::new("stale");
        let newer = br#"{"schema_version":"1.0.0","name":"src","purpose":"Changed.","invariants":["new rule"]}"#;
        let cs = fx.propose(&bob(), "bob-crumb", "src/.crumb", newer);
        let adv = fx.advise(&["src/a.rs", "docs/x.md"], None);
        assert_eq!(adv.compared_to, Some(TreeTarget::Changeset(cs)));
        let Staleness::Stale { latest_digest } = adv.paths[0].staleness else {
            panic!("expected stale, got {:?}", adv.paths[0].staleness);
        };
        assert_ne!(latest_digest, adv.paths[0].digest);
        // Guidance still reports the base context, not the newer one.
        assert_eq!(adv.paths[0].guidance[0].text, "src rule");
        // A directory whose chain did not change stays current.
        assert_eq!(adv.paths[1].staleness, Staleness::Current);
    }

    #[test]
    fn refusals_over_cap_duplicate_invalid_and_without_read() {
        let mut fx = Fixture::new("refuse");
        let many: Vec<String> = (0..=MAX_ADVISORY_PATHS).map(|i| format!("f{i}")).collect();
        let many: Vec<&str> = many.iter().map(String::as_str).collect();
        let err = fx
            .advise_as(vec![Capability::Read], "alice", &many, None)
            .unwrap_err();
        assert_eq!(err.code, RefusalCode::QuotaTooManyPaths);
        let at_cap = fx
            .advise_as(
                vec![Capability::Read],
                "alice",
                &many[..MAX_ADVISORY_PATHS],
                None,
            )
            .unwrap();
        assert_eq!(at_cap.paths.len(), MAX_ADVISORY_PATHS);
        let dup = fx
            .advise_as(
                vec![Capability::Read],
                "alice",
                &["src/a.rs", "src/a.rs"],
                None,
            )
            .unwrap_err();
        assert_eq!(dup.code, RefusalCode::PathDuplicate);
        let bad = fx
            .advise_as(vec![Capability::Read], "alice", &["../x"], None)
            .unwrap_err();
        assert_eq!(bad.code, RefusalCode::PathInvalid);
        let denied = fx
            .advise_as(vec![Capability::Propose], "alice", &["src/a.rs"], None)
            .unwrap_err();
        assert_eq!(denied.code, RefusalCode::AuthCapabilityDenied);
    }

    #[test]
    fn advisory_writes_nothing_to_the_coordination_store() {
        let mut fx = Fixture::new("nowrite");
        let store = fx.coord(T0);
        let adv = fx.advise(&["src/a.rs"], Some(&store));
        assert_eq!(adv.coordination, CoordinationStatus::Read);
        assert!(!fx.dir.join("coord").exists());
    }

    fn promote(fx: &mut Fixture, cs: ChangesetId) {
        fx.svc
            .store
            .record_canonical_promotion(synapse_core::RadicleCanonicalHead {
                repo_id: fx.repo.clone(),
                default_branch: "main".to_string(),
                canonical_git_oid: GitOid([2; 20]),
                promoted_changeset_id: Some(cs),
                rad_id_commit_oid: GitOid([3; 20]),
                threshold: 1,
                verified_delegates: vec![],
                verified_at_ms: 5,
            })
            .unwrap();
    }

    #[test]
    fn pending_crumb_rewrite_after_a_promotion_is_flagged() {
        let mut fx = Fixture::new("pending-crumb");
        let cs1 = fx.propose(&bob(), "bob-b", "src/b.rs", b"fn b2() {}\n");
        promote(&mut fx, cs1);
        let newer = br#"{"schema_version":"1.0.0","name":"src","purpose":"Changed.","invariants":["new rule"]}"#;
        let cs2 = fx.propose(&bob(), "bob-crumb", "src/.crumb", newer);
        let adv = fx.advise(&["src/a.rs"], None);
        let p = &adv.paths[0];
        assert!(
            matches!(p.staleness, Staleness::Stale { .. }),
            "compared_to {:?}, staleness {:?}, overlaps {:?}",
            adv.compared_to,
            p.staleness,
            p.overlapping_proposals
        );
        assert_eq!(adv.compared_to, Some(TreeTarget::Changeset(cs2)));
        assert_eq!(
            adv.canonical,
            CanonicalStatus::Promoted(TreeTarget::Changeset(cs1))
        );
        // The promoted changeset kept the base `.crumb` chain.
        assert_eq!(p.canonical_staleness, Staleness::Current);
        // The pending rewrite is surfaced even though it does not touch the path.
        assert!(p.overlapping_proposals.is_empty());
        assert_eq!(p.pending_crumb_changes.len(), 1);
        assert_eq!(p.pending_crumb_changes[0].changeset_id, cs2);
        assert_eq!(p.pending_crumb_changes[0].mutated_path, "src/.crumb");
        let last = p.guidance.last().unwrap();
        assert_eq!(last.dir, "src");
        assert!(last.text.contains("src/.crumb"), "{last:?}");
        // A path outside `src` has no pending rewrite in its chain.
        let docs = fx.advise(&["docs/x.md"], None);
        assert!(docs.paths[0].pending_crumb_changes.is_empty());
        // An unrelated newer proposal does not hide the pending rewrite.
        let carol = SigningKey::from_bytes(&[40u8; 32]);
        let cs3 = fx.propose(&carol, "carol-docs", "docs/x.md", b"# y\n");
        let adv = fx.advise(&["src/a.rs"], None);
        assert_eq!(adv.compared_to, Some(TreeTarget::Changeset(cs3)));
        assert_eq!(adv.paths[0].staleness, Staleness::Current);
        assert_eq!(adv.paths[0].pending_crumb_changes[0].changeset_id, cs2);
    }

    #[test]
    fn canonical_head_is_not_used_at_an_older_snapshot() {
        let mut fx = Fixture::new("canon-snap");
        let cs1 = fx.propose(&bob(), "bob-b", "src/b.rs", b"fn b2() {}\n");
        let before = fx.svc.store.committed_seq();
        promote(&mut fx, cs1);
        let now = fx.advise(&["src/b.rs"], None);
        assert_eq!(
            now.canonical,
            CanonicalStatus::Promoted(TreeTarget::Changeset(cs1))
        );
        assert!(now.paths[0].overlapping_proposals.is_empty());
        // At the earlier snapshot the head was not promoted yet; the store cannot say so,
        // so the head is not used and cs1 is still an open proposal there.
        let key = SigningKey::from_bytes(&[20u8; 32]);
        let grant = fx.grant(&key, vec![Capability::Read]);
        let t = 1000 + u64::from(fx.nonce);
        let req = AuthenticatedRequest::sign_new(
            &key,
            grant,
            fx.repo.clone(),
            Capability::Read,
            [fx.nonce; 32],
            t,
            0,
            ChangesetAdvisoryPayload {
                base: fx.base,
                latest: None,
                paths: vec!["src/b.rs".to_string()],
                agent: "alice".to_string(),
                snapshot_seq: Some(before),
            },
        )
        .unwrap();
        let old = fx.svc.changeset_advisory(&req, None, t).unwrap();
        assert_eq!(old.canonical, CanonicalStatus::NotAtSnapshot);
        assert_eq!(old.paths[0].canonical_staleness, Staleness::Unknown);
        assert_eq!(old.paths[0].overlapping_proposals[0].changeset_id, cs1);
    }

    #[test]
    fn lock_without_holder_is_skipped() {
        let mut fx = Fixture::new("noholder");
        let store = fx.coord(T0);
        claim(&store, "bob", "src/a.rs", 600);
        let file = fx.dir.join("coord/dirs/src.json");
        let text = fs::read_to_string(&file).unwrap();
        let stripped = text.replacen("\"holder\": \"bob\",", "", 1);
        assert_ne!(stripped, text, "fixture: holder field not found in {text}");
        fs::write(&file, stripped).unwrap();
        let adv = fx.advise(&["src/a.rs"], Some(&store));
        assert_eq!(adv.coordination, CoordinationStatus::Read);
        assert!(adv.paths[0].claims.is_empty(), "{:?}", adv.paths[0].claims);
    }

    /// Issue #94: repeated advisory calls on one snapshot materialize its tree once; a new
    /// snapshot costs one more build while the base stays cached.
    #[test]
    fn advisory_builds_each_snapshot_once() {
        let mut fx = Fixture::new("views-once");
        let b0 = snapshot_view_builds();
        for _ in 0..5 {
            fx.advise(&["src/a.rs", "docs/x.md"], None);
        }
        assert_eq!(snapshot_view_builds() - b0, 1, "base built once");
        let cs = fx.propose(&bob(), "bob-a", "src/a.rs", b"fn a2() {}\n");
        for _ in 0..5 {
            let adv = fx.advise(&["src/a.rs"], None);
            assert_eq!(adv.compared_to, Some(TreeTarget::Changeset(cs)));
        }
        assert_eq!(
            snapshot_view_builds() - b0,
            2,
            "latest built once, base still cached"
        );
    }

    /// Issue #94: the view cache keeps at most `SNAPSHOT_VIEW_CACHE_ENTRIES` snapshots and
    /// evicts the oldest first.
    #[test]
    fn snapshot_view_cache_is_bounded() {
        let mut fx = Fixture::new("views-bound");
        let n = SNAPSHOT_VIEW_CACHE_ENTRIES + 2;
        let ids: Vec<_> = (0..n)
            .map(|i| {
                let path = format!("gen/f{i}.rs");
                fx.propose(&bob(), &format!("bob-{i}"), &path, path.as_bytes())
            })
            .collect();
        let b0 = snapshot_view_builds();
        for &cs in &ids {
            fx.base = TreeTarget::Changeset(cs);
            fx.advise(&["src/a.rs"], None);
            assert!(snapshot_view_entries() <= SNAPSHOT_VIEW_CACHE_ENTRIES);
        }
        // Each base is new; `latest` (the newest changeset) is built once and stays cached
        // until evicted, so at least one build per base.
        let built = snapshot_view_builds() - b0;
        assert!(built >= n as u64, "{built} builds for {n} snapshots");
        assert_eq!(snapshot_view_entries(), SNAPSHOT_VIEW_CACHE_ENTRIES);
        // The first base was evicted: asking again builds it again.
        let before = snapshot_view_builds();
        fx.base = TreeTarget::Changeset(ids[0]);
        fx.advise(&["src/a.rs"], None);
        assert!(snapshot_view_builds() > before);
    }
}
