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
                &dir.join("svc"),
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
}
