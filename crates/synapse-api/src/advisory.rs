//! Pre-submit Crumb and claim advisory for changesets (ADR 0004, deliverable D3).
//!
//! For each path a changeset would mutate, report the Directory Crumb context of the path
//! at the base snapshot, unexpired claims held by other agents in the shared coordination
//! plane, overlapping open proposals, the context's invariants as guidance, and whether the
//! `.crumb` chain changed between the base and the latest snapshot.
//!
//! Advisory only. Nothing here blocks, authorizes, or writes: one `Capability::Read`
//! authorization (with its audit entry), reads through `materialize_virtual_tree` and
//! `read_blob_bytes`, and a read-only `CoordStore::sniff` (no lock taken, nothing written).
//! Synapse source conflicts at submit stay the only hard refusal.

use crate::{is_file_dir_prefix_collision, SynapseService, TreeTarget, VirtualTreeEntry};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use synapse_auth::{AuthenticatedRequest, BoundaryKind, Capability};
use synapse_coord::{CoordStore, Holder, LockView, PathOracle, Workspace};
use synapse_core::{
    validate_repo_relative_path, ChangesetId, RefusalCode, SynapseError, SynapseResult, WalSeq,
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
    /// Snapshot to compare `.crumb` chains against. `None`: the changeset promoted by the
    /// canonical head if it is visible, else the most recently committed changeset.
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
    Unavailable { reason: String },
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
    /// Invariants of the nearest crumb, then inherited ones (closest ancestor first).
    pub guidance: Vec<GuidanceNote>,
    pub staleness: Staleness,
}

/// Result of [`SynapseService::changeset_advisory`]. Grants nothing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChangesetAdvisory {
    /// Snapshot the staleness check compared against (`None`: nothing to compare with).
    pub compared_to: Option<TreeTarget>,
    pub coordination: CoordinationStatus,
    /// One entry per requested path, in request order.
    pub paths: Vec<PathAdvisory>,
}

/// Answers `exists` from a snapshot (files and their ancestor directories), so claim keys
/// resolve the way `crumb.c` resolves them against a checkout.
struct SnapshotOracle(BTreeSet<String>);

impl SnapshotOracle {
    fn new(tree: &BTreeMap<String, VirtualTreeEntry>) -> Self {
        let mut set = BTreeSet::new();
        for path in tree.keys() {
            let mut p = path.as_str();
            set.insert(p.to_string());
            while let Some((parent, _)) = p.rsplit_once('/') {
                if !set.insert(parent.to_string()) {
                    break;
                }
                p = parent;
            }
        }
        Self(set)
    }
}

impl PathOracle for SnapshotOracle {
    fn exists(&self, rel: &str) -> bool {
        self.0.contains(rel)
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
        let snap = Some(payload.snapshot_seq.unwrap_or(self.store.committed_seq()));
        let visible = self
            .store
            .list_changesets(Some(&self.repo_id), None, snap)?;
        let promoted = self
            .store
            .canonical_head(&self.repo_id)
            .and_then(|h| h.promoted_changeset_id)
            .filter(|id| visible.iter().any(|cs| cs.changeset_id == *id));

        let base_tree = self.materialize_virtual_tree(payload.base, snap)?;
        let compared_to = payload.latest.or_else(|| {
            promoted
                .or_else(|| visible.last().map(|cs| cs.changeset_id))
                .map(TreeTarget::Changeset)
        });
        let latest_tree = match compared_to {
            Some(t) if t != payload.base => Some(self.materialize_virtual_tree(t, snap)?),
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

        let (coordination, locks) = match coord {
            None => (CoordinationStatus::NotSupplied, Vec::new()),
            Some(store) => {
                let ws = Workspace::with_oracle(
                    ADVISORY_WORKSPACE,
                    Holder::default(),
                    Box::new(SnapshotOracle::new(&base_tree)),
                );
                match store.sniff(&ws, &payload.agent, ROOT_DIR) {
                    Ok(s) => (CoordinationStatus::Read, s.locks),
                    Err(e) => (
                        CoordinationStatus::Unavailable {
                            reason: e.to_string(),
                        },
                        Vec::new(),
                    ),
                }
            }
        };
        let oracle_ws = Workspace::with_oracle(
            ADVISORY_WORKSPACE,
            Holder::default(),
            Box::new(SnapshotOracle::new(&base_tree)),
        );

        let mut out = Vec::with_capacity(payload.paths.len());
        for path in &payload.paths {
            let dir = context_dir(&base_tree, path);
            let context = self.resolve_crumb_context(&base_tree, &dir, snap)?;
            let digest = context.digest();
            let staleness = match (&compared_to, &latest_tree) {
                (None, _) => Staleness::Unknown,
                (Some(_), None) => Staleness::Current,
                (Some(_), Some(lt)) => {
                    let latest_digest = self.resolve_crumb_context(lt, &dir, snap)?.digest();
                    if latest_digest == digest {
                        Staleness::Current
                    } else {
                        Staleness::Stale { latest_digest }
                    }
                }
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

            let overlapping_proposals = visible
                .iter()
                .filter(|cs| !settled.contains(&cs.changeset_id))
                .flat_map(|cs| {
                    cs.envelope
                        .mutations
                        .iter()
                        .filter(|m| m.path == *path || is_file_dir_prefix_collision(&m.path, path))
                        .map(move |m| OverlappingProposal {
                            changeset_id: cs.changeset_id,
                            author_did: cs.envelope.author_did.clone(),
                            committed_seq: cs.committed_seq,
                            mutated_path: m.path.clone(),
                        })
                })
                .collect();

            let guidance = guidance_notes(&context);
            out.push(PathAdvisory {
                path: path.clone(),
                context,
                digest,
                claims,
                overlapping_proposals,
                guidance,
                staleness,
            });
        }
        Ok(ChangesetAdvisory {
            compared_to,
            coordination,
            paths: out,
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

fn guidance_notes(context: &CrumbContext) -> Vec<GuidanceNote> {
    let own = context.nearest().and_then(|e| {
        e.crumb()
            .map(|c| c.invariants().iter().map(move |i| (e.dir.as_str(), i.as_str())))
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
