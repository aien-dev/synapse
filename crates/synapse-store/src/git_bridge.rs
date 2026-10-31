//! Git bridge records and the persistent `GitOid` map (ADR 0003 section 5.10, step H1 cut 2).
//! See `docs/H1_GIT_BRIDGE.md`.
//!
//! An import is a sequence of WAL kind 10 records ([`crate::WalRecord::GitBridgeImported`]),
//! one [`GitBridgeEntry`] each:
//!
//! * `Objects`: Git blobs mapped to `BlobDigest`s (their bytes stored as ordinary blobs) and Git
//!   trees mapped to canonical `TreeDigest` nodes (C1). A Git tree ID is never stored as native
//!   identity: at export it is recomputed from the node.
//! * `Commit`: an imported revision. Its native form is the commit's `TreeDigest`, its parents
//!   as imported revision IDs in Git's written order, and the rest of the commit (author,
//!   committer, extra headers such as `gpgsig` and `mergetag`, message) as opaque bytes. Its
//!   `ChangesetId` is [`GitImportedCommit::changeset_id`].
//! * `Tag`: an annotated tag, its target as a native identity and every byte after the
//!   `object` line opaque.
//! * `Refs`: the repository's references and `HEAD` at import.
//!
//! The ledger is a pure function of the kind 10 records that took effect, in `WalSeq` order:
//! replay, a checkpoint (which keeps the records) and a live store rebuild the same map. In a
//! store opened with a seal key, kind 10 is a revision record like kinds 7, 8, 9 and 11: it is
//! written sealed and applied only when its seal verifies against the chain so far (issue
//! #101). Every check runs before the write ([`crate::SynapseStore::record_git_import`]);
//! apply itself is total.

use crate::WalRecord;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use synapse_core::{
    decode_tree_node, git_tree_payload_of_node, BlobDigest, ChangesetId, GitOid, RefusalCode,
    RepoId, SynapseError, SynapseResult, TreeDigest, TreeNodeEntryKind, WalSeq,
};

/// Domain tag of an imported revision's `ChangesetId`. Distinct from the v1 and v2 domains, so
/// an imported revision never shares an identity with an agent revision.
pub const DOMAIN_GIT_IMPORTED_REVISION_V1: &[u8] = b"SYNAPSE_GIT_IMPORTED_REVISION_V1\0";

/// Version of the imported revision encoding hashed into its `ChangesetId`.
pub const GIT_IMPORTED_REVISION_VERSION: u16 = 1;

/// Longest reference name the bridge stores.
pub const MAX_GIT_REF_NAME_BYTES: usize = 1024;

/// One Git blob and the native blob holding its bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GitBlobMapping {
    pub git_oid: GitOid,
    pub blob: BlobDigest,
    pub size_bytes: u64,
}

/// One Git tree and its canonical native node (C1 version 1 encoding). The `TreeDigest` is
/// derived from the node bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GitTreeMapping {
    pub git_oid: GitOid,
    pub node: Vec<u8>,
}

impl GitTreeMapping {
    pub fn digest(&self) -> TreeDigest {
        TreeDigest::of_encoded_node(&self.node)
    }
}

/// An imported Git commit: tree, parents in written order, and the opaque remainder of the
/// commit object (every byte after the `tree` and `parent` lines).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GitImportedCommit {
    /// The original Git commit ID (the map key; checked again at every export).
    pub git_oid: GitOid,
    pub tree: TreeDigest,
    /// Imported revision IDs of the parents, in the commit's written order.
    pub parents: Vec<ChangesetId>,
    /// Author, committer, extra headers and message, byte for byte.
    pub headers: Vec<u8>,
}

impl GitImportedCommit {
    /// `version u16 (1) | tree [32] | u32 n | parent [32]*n | u32 len | headers`.
    pub fn encode_content(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(46 + 32 * self.parents.len() + self.headers.len());
        buf.extend_from_slice(&GIT_IMPORTED_REVISION_VERSION.to_le_bytes());
        buf.extend_from_slice(&self.tree.0);
        buf.extend_from_slice(&(self.parents.len() as u32).to_le_bytes());
        for p in &self.parents {
            buf.extend_from_slice(&p.0);
        }
        buf.extend_from_slice(&(self.headers.len() as u32).to_le_bytes());
        buf.extend_from_slice(&self.headers);
        buf
    }

    /// `SHA-256(DOMAIN_GIT_IMPORTED_REVISION_V1 || u64 len || encode_content())`. It covers the
    /// tree, the parents in order and the opaque headers, so two Git commits are one imported
    /// revision exactly when their objects are identical; the Git ID itself is not hashed in.
    pub fn changeset_id(&self) -> ChangesetId {
        let bytes = self.encode_content();
        let mut h = Sha256::new();
        h.update(DOMAIN_GIT_IMPORTED_REVISION_V1);
        h.update((bytes.len() as u64).to_le_bytes());
        h.update(&bytes);
        ChangesetId(h.finalize().into())
    }
}

/// A native identity a tag or reference points at.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum GitBridgeTarget {
    /// An imported revision.
    Commit(ChangesetId),
    Tree(TreeDigest),
    Blob(BlobDigest),
    /// Another imported tag, by its Git ID (tags have no native identity).
    Tag(GitOid),
}

/// An imported annotated tag: its target and every byte after its `object` line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GitImportedTag {
    pub git_oid: GitOid,
    pub target: GitBridgeTarget,
    /// From the `type` line to the end of the object, byte for byte.
    pub rest: Vec<u8>,
}

/// The references of an imported repository: names strictly ascending, and the branch `HEAD`
/// names.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GitImportedRefs {
    pub refs: Vec<(String, GitBridgeTarget)>,
    pub head: Option<String>,
}

/// The body of one kind 10 record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GitBridgeEntry {
    Objects {
        blobs: Vec<GitBlobMapping>,
        trees: Vec<GitTreeMapping>,
    },
    Commit(GitImportedCommit),
    Tag(GitImportedTag),
    Refs(GitImportedRefs),
}

impl GitBridgeEntry {
    /// Entry tag in the record encoding.
    pub fn tag(&self) -> u8 {
        match self {
            Self::Objects { .. } => 1,
            Self::Commit(_) => 2,
            Self::Tag(_) => 3,
            Self::Refs(_) => 4,
        }
    }

    /// Blob digests an `Objects` entry maps (all must be visible once the record commits).
    pub fn blobs(&self) -> Vec<BlobDigest> {
        match self {
            Self::Objects { blobs, .. } => blobs.iter().map(|b| b.blob).collect(),
            _ => Vec::new(),
        }
    }
}

/// Is `name` a reference name the bridge accepts: under `refs/`, no empty, `.`-leading or
/// `..` components, no `.lock` suffix, no control or `" ~^:?*[\"` bytes, at most
/// [`MAX_GIT_REF_NAME_BYTES`]. Export writes each reference as a file below the new
/// repository, so this rule also keeps every write inside it.
pub fn valid_git_ref_name(name: &str) -> bool {
    name.len() <= MAX_GIT_REF_NAME_BYTES
        && name.starts_with("refs/")
        && !name.ends_with('/')
        && !name.ends_with(".lock")
        && !name.contains("@{")
        && name.split('/').all(|c| {
            !c.is_empty() && !c.starts_with('.') && !c.ends_with(".lock") && !c.contains("..")
        })
        && !name
            .bytes()
            .any(|b| b < 0x20 || b == 0x7f || b" ~^:?*[\\".contains(&b))
}

/// Blobs that come with one kind 10 record: digest and bytes.
pub type GitImportBlobs<'a> = Vec<(BlobDigest, &'a [u8])>;

/// One record of a Git import batch: the entry and the blobs it brings.
pub type GitImportRecord<'a> = (GitBridgeEntry, GitImportBlobs<'a>);

fn refused(code: RefusalCode, msg: impl Into<String>) -> SynapseError {
    SynapseError::new(code, msg)
}

/// The persistent map of one repository.
#[derive(Debug, Clone, Default)]
pub struct GitBridgeRepo {
    blobs: BTreeMap<GitOid, (BlobDigest, u64)>,
    trees: BTreeMap<GitOid, TreeDigest>,
    commits: BTreeMap<GitOid, (ChangesetId, GitImportedCommit)>,
    by_changeset: BTreeMap<ChangesetId, GitOid>,
    tags: BTreeMap<GitOid, GitImportedTag>,
    refs: Option<GitImportedRefs>,
    /// Reverse maps (native identity to Git ID), so a tree, commit or tag can be re-hashed.
    blob_oids: BTreeMap<BlobDigest, GitOid>,
    tree_oids: BTreeMap<TreeDigest, GitOid>,
}

impl GitBridgeRepo {
    /// The map: an imported commit's (`ChangesetId`, `TreeDigest`).
    pub fn commit(&self, git_oid: GitOid) -> Option<(ChangesetId, TreeDigest)> {
        self.commits.get(&git_oid).map(|(id, c)| (*id, c.tree))
    }

    /// The imported commit behind an imported revision ID.
    pub fn commit_by_changeset(&self, id: ChangesetId) -> Option<&GitImportedCommit> {
        self.by_changeset
            .get(&id)
            .and_then(|oid| self.commits.get(oid))
            .map(|(_, c)| c)
    }

    pub fn blob(&self, git_oid: GitOid) -> Option<(BlobDigest, u64)> {
        self.blobs.get(&git_oid).copied()
    }

    pub fn tree(&self, git_oid: GitOid) -> Option<TreeDigest> {
        self.trees.get(&git_oid).copied()
    }

    pub fn tag(&self, git_oid: GitOid) -> Option<&GitImportedTag> {
        self.tags.get(&git_oid)
    }

    /// Every mapped blob: Git ID to (`BlobDigest`, size).
    pub fn blobs(&self) -> &BTreeMap<GitOid, (BlobDigest, u64)> {
        &self.blobs
    }

    /// Every mapped tree: Git ID to `TreeDigest`.
    pub fn trees(&self) -> &BTreeMap<GitOid, TreeDigest> {
        &self.trees
    }

    /// Every imported commit by Git ID, with its imported revision ID.
    pub fn commits(&self) -> impl Iterator<Item = (&GitOid, &(ChangesetId, GitImportedCommit))> {
        self.commits.iter()
    }

    pub fn tags(&self) -> &BTreeMap<GitOid, GitImportedTag> {
        &self.tags
    }

    /// The references of the latest `Refs` record.
    pub fn refs(&self) -> Option<&GitImportedRefs> {
        self.refs.as_ref()
    }

    /// Commits, trees, blobs and tags held.
    pub fn object_count(&self) -> usize {
        self.blobs.len() + self.trees.len() + self.commits.len() + self.tags.len()
    }
}

/// In-memory bridge state, rebuilt from kind 10 records.
#[derive(Debug, Clone, Default)]
pub(crate) struct GitBridgeLedger {
    repos: BTreeMap<RepoId, GitBridgeRepo>,
    /// Canonical tree nodes by digest (content addressed, shared by every repository).
    nodes: BTreeMap<TreeDigest, Vec<u8>>,
    /// Size of every blob a Git blob maps to (content addressed, shared).
    blob_sizes: BTreeMap<BlobDigest, u64>,
}

impl GitBridgeLedger {
    pub(crate) fn from_log<'a>(log: impl IntoIterator<Item = &'a (WalSeq, WalRecord)>) -> Self {
        let mut l = Self::default();
        for (_, record) in log {
            l.apply(record);
        }
        l
    }

    pub(crate) fn repo(&self, repo: &RepoId) -> Option<&GitBridgeRepo> {
        self.repos.get(repo)
    }

    pub(crate) fn node(&self, digest: TreeDigest) -> Option<&[u8]> {
        self.nodes.get(&digest).map(Vec::as_slice)
    }

    /// Every blob any repository maps (compaction keeps them).
    pub(crate) fn blob_digests(&self) -> impl Iterator<Item = BlobDigest> + '_ {
        self.blob_sizes.keys().copied()
    }

    /// Apply one kind 10 record (other records are ignored). Total: replay applies every
    /// record the same way on every replica.
    pub(crate) fn apply(&mut self, record: &WalRecord) {
        let WalRecord::GitBridgeImported { repo_id, entry, .. } = record else {
            return;
        };
        let repo = self.repos.entry(repo_id.clone()).or_default();
        match entry {
            GitBridgeEntry::Objects { blobs, trees } => {
                for b in blobs {
                    repo.blobs.insert(b.git_oid, (b.blob, b.size_bytes));
                    repo.blob_oids.insert(b.blob, b.git_oid);
                    self.blob_sizes.entry(b.blob).or_insert(b.size_bytes);
                }
                for t in trees {
                    let d = t.digest();
                    repo.trees.insert(t.git_oid, d);
                    repo.tree_oids.insert(d, t.git_oid);
                    self.nodes.entry(d).or_insert_with(|| t.node.clone());
                }
            }
            GitBridgeEntry::Commit(c) => {
                let id = c.changeset_id();
                repo.by_changeset.insert(id, c.git_oid);
                repo.commits.insert(c.git_oid, (id, c.clone()));
            }
            GitBridgeEntry::Tag(t) => {
                repo.tags.insert(t.git_oid, t.clone());
            }
            GitBridgeEntry::Refs(r) => repo.refs = Some(r.clone()),
        }
    }

    /// Check one entry against the map before it is written. Returns `false` when the entry
    /// is already fully recorded (nothing to write). `provided` holds the blobs whose bytes
    /// come with the record; `blob_visible` says whether a blob is already committed and
    /// `read_blob` reads one that is.
    ///
    /// Beyond structure (sizes, visibility, subtrees, parents and targets imported in this
    /// repository, no Git ID remapped), every Git ID the entry newly maps is re-hashed from
    /// the content it maps to (blob bytes; tree, commit and tag payloads rebuilt from the
    /// stored form and the Git IDs already mapped), and a Git ID may appear only once in an
    /// entry. So a record cannot map a Git ID to anything export would not give back.
    pub(crate) fn check(
        &self,
        repo_id: &RepoId,
        entry: &GitBridgeEntry,
        provided: &BTreeMap<BlobDigest, &[u8]>,
        blob_visible: &dyn Fn(&BlobDigest) -> bool,
        read_blob: &dyn Fn(&BlobDigest) -> SynapseResult<Vec<u8>>,
    ) -> SynapseResult<bool> {
        let repo = self.repos.get(repo_id);
        let conflict = |what: &str, oid: GitOid| {
            refused(
                RefusalCode::GitObjectCorrupt,
                format!("{what} {oid} is already mapped to a different native object"),
            )
        };
        match entry {
            GitBridgeEntry::Objects { blobs, trees } => {
                if blobs.is_empty() && trees.is_empty() {
                    return Err(refused(
                        RefusalCode::GitObjectCorrupt,
                        "an objects entry maps no object",
                    ));
                }
                let mut ids: BTreeSet<GitOid> = BTreeSet::new();
                for oid in blobs
                    .iter()
                    .map(|b| b.git_oid)
                    .chain(trees.iter().map(|t| t.git_oid))
                {
                    if !ids.insert(oid) {
                        return Err(refused(
                            RefusalCode::GitObjectCorrupt,
                            format!("Git ID {oid} appears more than once in one objects entry"),
                        ));
                    }
                }
                let mut fresh = false;
                // Blobs this entry maps: digest to (Git ID, size).
                let mut entry_blobs: BTreeMap<BlobDigest, (GitOid, u64)> = BTreeMap::new();
                for b in blobs {
                    let known = match repo.and_then(|r| r.blobs.get(&b.git_oid)) {
                        Some(&(d, s)) if d == b.blob && s == b.size_bytes => true,
                        Some(_) => return Err(conflict("Git blob", b.git_oid)),
                        None => false,
                    };
                    match provided.get(&b.blob) {
                        Some(bytes) if bytes.len() as u64 != b.size_bytes => {
                            return Err(refused(
                                RefusalCode::BlobDigestMismatch,
                                format!(
                                    "Git blob {} declares {} bytes but its blob holds {}",
                                    b.git_oid,
                                    b.size_bytes,
                                    bytes.len()
                                ),
                            ))
                        }
                        Some(_) => {}
                        None if blob_visible(&b.blob) => {}
                        None => {
                            return Err(refused(
                                RefusalCode::BlobNotFound,
                                format!("Git blob {} maps to missing blob {}", b.git_oid, b.blob),
                            ))
                        }
                    }
                    if !known {
                        fresh = true;
                        let read;
                        let content: &[u8] = match provided.get(&b.blob) {
                            Some(bytes) => bytes,
                            None => {
                                read = read_blob(&b.blob)?;
                                &read
                            }
                        };
                        if content.len() as u64 != b.size_bytes {
                            return Err(refused(
                                RefusalCode::BlobDigestMismatch,
                                format!(
                                    "Git blob {} declares {} bytes but its blob holds {}",
                                    b.git_oid,
                                    b.size_bytes,
                                    content.len()
                                ),
                            ));
                        }
                        verify_git_id("blob", b.git_oid, content)?;
                    }
                    entry_blobs.insert(b.blob, (b.git_oid, b.size_bytes));
                }
                let mapped_blob = |blob: &BlobDigest| -> Option<(GitOid, u64)> {
                    entry_blobs.get(blob).copied().or_else(|| {
                        let r = repo?;
                        let oid = *r.blob_oids.get(blob)?;
                        r.blobs.get(&oid).map(|&(_, s)| (oid, s))
                    })
                };
                // Trees this entry maps: digest to Git ID.
                let mut entry_trees: BTreeMap<TreeDigest, GitOid> = BTreeMap::new();
                for t in trees {
                    let digest = t.digest();
                    let known = match repo.and_then(|r| r.trees.get(&t.git_oid)) {
                        Some(&d) if d == digest => true,
                        Some(_) => return Err(conflict("Git tree", t.git_oid)),
                        None => false,
                    };
                    let mapped_tree = |child: &TreeDigest| -> Option<GitOid> {
                        entry_trees
                            .get(child)
                            .or_else(|| repo.and_then(|r| r.tree_oids.get(child)))
                            .copied()
                    };
                    for e in decode_tree_node(&t.node)? {
                        match e.kind {
                            TreeNodeEntryKind::File {
                                blob, size_bytes, ..
                            } => match mapped_blob(&blob) {
                                None => {
                                    return Err(refused(
                                        RefusalCode::BlobNotFound,
                                        format!(
                                            "tree {} names blob {blob} that no Git blob of this repository maps",
                                            t.git_oid
                                        ),
                                    ))
                                }
                                Some((_, s)) if s != size_bytes => {
                                    return Err(refused(
                                        RefusalCode::BlobDigestMismatch,
                                        format!(
                                            "tree {} gives {} the size {size_bytes} but its blob holds {s}",
                                            t.git_oid, e.name
                                        ),
                                    ))
                                }
                                Some(_) => {}
                            },
                            TreeNodeEntryKind::Dir(child) => {
                                if child == TreeDigest::empty() || mapped_tree(&child).is_none() {
                                    return Err(refused(
                                        RefusalCode::TreeNodeNotFound,
                                        format!(
                                            "tree {} names subtree {child} that is empty or not imported",
                                            t.git_oid
                                        ),
                                    ));
                                }
                            }
                        }
                    }
                    if !known {
                        fresh = true;
                        let unmapped = || refused(RefusalCode::GitObjectCorrupt, "unmapped entry");
                        let payload = git_tree_payload_of_node(
                            &t.node,
                            &mut |b| mapped_blob(&b).map(|(o, _)| o).ok_or_else(unmapped),
                            &mut |c| mapped_tree(&c).ok_or_else(unmapped),
                        )?;
                        verify_git_id("tree", t.git_oid, &payload)?;
                    }
                    entry_trees.insert(digest, t.git_oid);
                }
                Ok(fresh)
            }
            GitBridgeEntry::Commit(c) => {
                let id = c.changeset_id();
                if let Some((existing, _)) = repo.and_then(|r| r.commits.get(&c.git_oid)) {
                    return if *existing == id {
                        Ok(false)
                    } else {
                        Err(conflict("Git commit", c.git_oid))
                    };
                }
                if let Some(other) = repo.and_then(|r| r.by_changeset.get(&id)) {
                    return Err(refused(
                        RefusalCode::GitObjectCorrupt,
                        format!(
                            "commit {} has the same content as the imported commit {other}",
                            c.git_oid
                        ),
                    ));
                }
                let tree = target_oid(repo, &GitBridgeTarget::Tree(c.tree)).map_err(|_| {
                    refused(
                        RefusalCode::TreeNodeNotFound,
                        format!(
                            "commit {} names tree {} that is not imported",
                            c.git_oid, c.tree
                        ),
                    )
                })?;
                let mut payload = format!("tree {}\n", tree.to_hex()).into_bytes();
                for p in &c.parents {
                    let Some(parent) = repo.and_then(|r| r.by_changeset.get(p)) else {
                        return Err(refused(
                            RefusalCode::ParentChangesetNotFound,
                            format!("commit {} names parent {p} that is not imported", c.git_oid),
                        ));
                    };
                    payload.extend_from_slice(format!("parent {}\n", parent.to_hex()).as_bytes());
                }
                payload.extend_from_slice(&c.headers);
                verify_git_id("commit", c.git_oid, &payload)?;
                Ok(true)
            }
            GitBridgeEntry::Tag(t) => {
                if let Some(existing) = repo.and_then(|r| r.tags.get(&t.git_oid)) {
                    return if existing == t {
                        Ok(false)
                    } else {
                        Err(conflict("Git tag", t.git_oid))
                    };
                }
                let target = target_oid(repo, &t.target)?;
                let mut payload = format!("object {}\n", target.to_hex()).into_bytes();
                payload.extend_from_slice(&t.rest);
                verify_git_id("tag", t.git_oid, &payload)?;
                Ok(true)
            }
            GitBridgeEntry::Refs(r) => {
                check_git_ref_names(r.refs.iter().map(|(n, _)| n.as_str()), r.head.as_deref())?;
                for (_, target) in &r.refs {
                    target_oid(repo, target)?;
                }
                Ok(repo.and_then(|x| x.refs.as_ref()) != Some(r))
            }
        }
    }
}

/// The Git ID a bridge target names in `repo`, refused unless it is imported there (the
/// empty tree is always known: its Git ID is that of the empty Git tree).
fn target_oid(repo: Option<&GitBridgeRepo>, target: &GitBridgeTarget) -> SynapseResult<GitOid> {
    let oid = match target {
        GitBridgeTarget::Commit(id) => repo.and_then(|r| r.by_changeset.get(id).copied()),
        GitBridgeTarget::Tree(d) if *d == TreeDigest::empty() => {
            Some(GitOid::compute_git_object("tree", b""))
        }
        GitBridgeTarget::Tree(d) => repo.and_then(|r| r.tree_oids.get(d).copied()),
        GitBridgeTarget::Blob(b) => repo.and_then(|r| r.blob_oids.get(b).copied()),
        GitBridgeTarget::Tag(oid) => repo.filter(|r| r.tags.contains_key(oid)).map(|_| *oid),
    };
    oid.ok_or_else(|| {
        refused(
            RefusalCode::GitObjectCorrupt,
            format!("bridge target {target:?} is not imported"),
        )
    })
}

/// Refuse a Git ID that is not the SHA-1 of its object (`{kind} {len}\0{payload}`).
fn verify_git_id(kind: &str, claimed: GitOid, payload: &[u8]) -> SynapseResult<()> {
    let actual = GitOid::compute_git_object(kind, payload);
    if actual == claimed {
        Ok(())
    } else {
        Err(refused(
            RefusalCode::GitObjectCorrupt,
            format!("Git {kind} {claimed} does not match its content (which hashes to {actual})"),
        ))
    }
}

/// Check reference names as a `Refs` record must hold them: each [`valid_git_ref_name`],
/// strictly ascending, no name a directory prefix of another (`refs/a` beside `refs/a/b`:
/// one would be a file and the other a directory), and a valid `HEAD` target.
pub fn check_git_ref_names<'a>(
    names: impl IntoIterator<Item = &'a str>,
    head: Option<&str>,
) -> SynapseResult<()> {
    let mut seen: BTreeSet<&str> = BTreeSet::new();
    for name in names {
        if !valid_git_ref_name(name) {
            return Err(refused(
                RefusalCode::PathInvalid,
                format!("invalid reference name {name:?}"),
            ));
        }
        if seen.last().is_some_and(|p| *p >= name) {
            return Err(refused(
                RefusalCode::PathInvalid,
                "reference names must be strictly ascending",
            ));
        }
        // A prefix sorts first, so it is already in `seen`.
        for (i, _) in name.match_indices('/') {
            if seen.contains(&name[..i]) {
                return Err(refused(
                    RefusalCode::PathInvalid,
                    format!("reference {} is a prefix directory of {name}", &name[..i]),
                ));
            }
        }
        seen.insert(name);
    }
    if let Some(head) = head {
        if !valid_git_ref_name(head) {
            return Err(refused(
                RefusalCode::PathInvalid,
                format!("invalid HEAD target {head:?}"),
            ));
        }
    }
    Ok(())
}

/// Digest input of one kind 10 record for the state root and the seal chain: its body
/// (`repo_id | entry`) without the seal trailer, length first.
pub(crate) fn record_digest_input(repo_id: &RepoId, entry: &GitBridgeEntry, h: &mut Sha256) {
    if let Ok(bytes) = crate::codec::git_bridge_body(repo_id, entry) {
        h.update((bytes.len() as u64).to_le_bytes());
        h.update(&bytes);
    }
}

impl crate::SynapseStore {
    /// Write one Git bridge record (WAL kind 10) for `repo_id`: a batch of one, see
    /// [`Self::record_git_imports`]. Returns `None` when the entry is already recorded.
    pub fn record_git_import(
        &mut self,
        repo_id: &RepoId,
        entry: GitBridgeEntry,
        blobs: &[(BlobDigest, &[u8])],
    ) -> SynapseResult<Option<WalSeq>> {
        let mut out = self.record_git_imports(repo_id, vec![(entry, blobs.to_vec())])?;
        Ok(out.pop().flatten())
    }

    /// Write a whole Git import (WAL kind 10 records, in order) for `repo_id`, checked as one
    /// unit before the first write. Every record of a batch of more than one is first run
    /// against a copy of the map in which the earlier records of the batch are already applied: binary codec, blob caps,
    /// each provided blob's digest and that the entry maps it, [`GitBridgeLedger::check`]
    /// (structure and every new Git ID re-hashed from its content) and the exact size of its
    /// WAL frame against `max_wal_record_bytes`. Only when every record passes are they
    /// written, each checked again against the live map. So any refusal the checks can give
    /// leaves the store untouched; a failure while writing (an I/O error) can still stop a
    /// batch part way, and a re-import then finishes it. Blobs not yet visible go inline.
    /// Returns, per record, its sequence number or `None` when it was already recorded.
    pub fn record_git_imports(
        &mut self,
        repo_id: &RepoId,
        records: Vec<GitImportRecord<'_>>,
    ) -> SynapseResult<Vec<Option<WalSeq>>> {
        self.check_writable()?;
        self.check_binary_codec()?;
        // Dry run on a copy of the map. A single record needs none: its write checks every
        // limit, the frame size included, before anything is written.
        let mut sim = (records.len() > 1).then(|| self.git_bridge.clone());
        let mut sim_visible: BTreeSet<BlobDigest> = BTreeSet::new();
        let mut prepared = Vec::with_capacity(records.len());
        for (entry, blobs) in records {
            let record = WalRecord::GitBridgeImported {
                repo_id: repo_id.clone(),
                entry,
                seal: None,
            };
            if let Some(sim) = sim.as_mut() {
                let visible = |d: &BlobDigest| {
                    self.blob_first_visible_seq.contains_key(d) || sim_visible.contains(d)
                };
                if let Some(inline) = self.prepare_git_import(sim, &record, &blobs, &visible)? {
                    self.check_frame_cap(self.git_import_frame_len(&record, &inline)?)?;
                    sim_visible.extend(inline.iter().map(|(d, _)| *d));
                    sim.apply(&record);
                }
            }
            prepared.push((record, blobs));
        }
        drop(sim);
        let mut out = Vec::with_capacity(prepared.len());
        for (record, blobs) in prepared {
            let visible = |d: &BlobDigest| self.blob_first_visible_seq.contains_key(d);
            let seq = match self.prepare_git_import(&self.git_bridge, &record, &blobs, &visible)? {
                None => None,
                Some(inline) => Some(self.append_revision_record(record, &inline, None)?),
            };
            out.push(seq);
        }
        Ok(out)
    }

    /// Every check of one kind 10 record against `ledger`. Returns the blobs to put inline,
    /// or `None` when the entry is already recorded.
    fn prepare_git_import<'b>(
        &self,
        ledger: &GitBridgeLedger,
        record: &WalRecord,
        blobs: &[(BlobDigest, &'b [u8])],
        visible: &dyn Fn(&BlobDigest) -> bool,
    ) -> SynapseResult<Option<GitImportBlobs<'b>>> {
        let WalRecord::GitBridgeImported { repo_id, entry, .. } = record else {
            return Err(refused(
                RefusalCode::GitObjectCorrupt,
                "not a Git bridge record",
            ));
        };
        let mapped: BTreeSet<BlobDigest> = entry.blobs().into_iter().collect();
        let mut provided: BTreeMap<BlobDigest, &[u8]> = BTreeMap::new();
        let mut total = 0u64;
        for (declared, bytes) in blobs {
            let len = bytes.len() as u64;
            total = total.saturating_add(len);
            if len > self.limits.max_blob_bytes || total > self.limits.max_total_changeset_bytes {
                return Err(refused(
                    RefusalCode::QuotaPayloadTooLarge,
                    "Git bridge blobs exceed max_blob_bytes or max_total_changeset_bytes",
                ));
            }
            let actual = BlobDigest::compute(bytes);
            if actual != *declared {
                return Err(refused(
                    RefusalCode::BlobDigestMismatch,
                    format!("declared blob digest {declared} does not match computed {actual}"),
                ));
            }
            if !mapped.contains(declared) {
                return Err(refused(
                    RefusalCode::GitObjectCorrupt,
                    format!("blob {declared} is provided but no Git blob maps to it"),
                ));
            }
            provided.insert(*declared, bytes);
        }
        let read_blob = |d: &BlobDigest| self.get_blob_visible(*d, None, None);
        if !ledger.check(repo_id, entry, &provided, visible, &read_blob)? {
            return Ok(None);
        }
        let mut inline: GitImportBlobs<'b> = Vec::new();
        for (digest, bytes) in blobs {
            if !visible(digest) && !inline.iter().any(|(d, _)| d == digest) {
                inline.push((*digest, *bytes));
            }
        }
        Ok(Some(inline))
    }

    /// The exact WAL payload length `append_revision_record` gives `record` with `inline`
    /// blobs (v2: `u32 meta_len | meta | u32 count | (digest | u32 len | bytes)*`; v1: the
    /// metadata, blobs go to files). A sealed store adds the seal trailer `tag | server key |
    /// signature` (1 + 32 + 64 bytes) that the write seals `record` with.
    fn git_import_frame_len(
        &self,
        record: &WalRecord,
        inline: &[(BlobDigest, &[u8])],
    ) -> SynapseResult<usize> {
        let trailer = if self.revision_seal.is_some() && record.seal().is_none() {
            1 + 32 + 64
        } else {
            0
        };
        let meta = crate::codec::encode_record_with(record, self.codec)?.len() + trailer;
        Ok(if self.v2_mode {
            inline
                .iter()
                .fold(8 + meta, |n, (_, b)| n.saturating_add(36 + b.len()))
        } else {
            meta
        })
    }

    /// The Git bridge map of `repo_id`, if anything was imported into it.
    pub fn git_bridge_repo(&self, repo_id: &RepoId) -> Option<&GitBridgeRepo> {
        self.git_bridge.repo(repo_id)
    }

    /// The canonical node bytes of an imported tree (`TreeDigest` to C1 version 1 encoding).
    pub fn git_bridge_tree_node(&self, digest: TreeDigest) -> Option<&[u8]> {
        self.git_bridge.node(digest)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec::{decode_record, encode_record, encode_record_with, RecordCodec};
    use synapse_core::{FileMode, TreeNodeEncoder};

    const CAP: u64 = 1 << 20;

    fn records() -> Vec<WalRecord> {
        let repo = RepoId::new("aien-dev/h1-codec").unwrap();
        let body = b"hello\n";
        let blob = BlobDigest::compute(body);
        let mut enc = TreeNodeEncoder::new(1);
        enc.file("a.txt", FileMode::Regular644, &blob, body.len() as u64)
            .unwrap();
        let (tree, node) = enc.finish().unwrap();
        let commit = GitImportedCommit {
            git_oid: GitOid::compute_git_object("commit", b"c"),
            tree,
            parents: vec![ChangesetId(Sha256::digest(b"parent").into())],
            headers: b"author a <a@b> 0 +0000\ncommitter a <a@b> 0 +0000\n\nm\n".to_vec(),
        };
        let entries = vec![
            GitBridgeEntry::Objects {
                blobs: vec![GitBlobMapping {
                    git_oid: GitOid::compute_blob(body),
                    blob,
                    size_bytes: body.len() as u64,
                }],
                trees: vec![GitTreeMapping {
                    git_oid: GitOid::compute_git_object("tree", b"t"),
                    node,
                }],
            },
            GitBridgeEntry::Commit(commit.clone()),
            GitBridgeEntry::Tag(GitImportedTag {
                git_oid: GitOid::compute_git_object("tag", b"t"),
                target: GitBridgeTarget::Commit(commit.changeset_id()),
                rest: b"type commit\ntag v1\n\nm\n".to_vec(),
            }),
            GitBridgeEntry::Refs(GitImportedRefs {
                refs: vec![
                    ("refs/heads/main".into(), GitBridgeTarget::Tree(tree)),
                    ("refs/tags/b".into(), GitBridgeTarget::Blob(blob)),
                    (
                        "refs/tags/t".into(),
                        GitBridgeTarget::Tag(GitOid::compute_git_object("tag", b"t")),
                    ),
                ],
                head: Some("refs/heads/main".into()),
            }),
            GitBridgeEntry::Refs(GitImportedRefs {
                refs: Vec::new(),
                head: None,
            }),
        ];
        entries
            .into_iter()
            .map(|entry| WalRecord::GitBridgeImported {
                repo_id: repo.clone(),
                entry,
                seal: None,
            })
            .collect()
    }

    #[test]
    fn kind_10_round_trips_and_every_truncation_is_refused() {
        for record in records() {
            let bytes = encode_record(&record).unwrap();
            assert_eq!(bytes[1], 10, "record kind 10");
            assert_eq!(decode_record(&bytes, CAP).unwrap(), record);
            for cut in 0..bytes.len() {
                assert!(
                    decode_record(&bytes[..cut], CAP).is_err(),
                    "a record cut at {cut} of {} bytes decoded",
                    bytes.len()
                );
            }
            let mut trailing = bytes.clone();
            trailing.push(0);
            assert!(decode_record(&trailing, CAP).is_err(), "trailing byte");
            assert!(
                encode_record_with(&record, RecordCodec::JsonV1).is_err(),
                "kind 10 has no JSON form"
            );
        }
    }

    #[test]
    fn kind_10_is_a_sealed_revision_record_and_its_digest_excludes_the_seal() {
        for mut record in records() {
            assert!(
                record.is_revision_record(),
                "kind 10 is sealed (issue #101)"
            );
            let unsealed = encode_record(&record).unwrap();
            let digest = crate::revision::record_digest(&record);
            record.set_seal(crate::RevisionSeal {
                server_key: [7; 32],
                signature: [9; 64],
            });
            let sealed = encode_record(&record).unwrap();
            assert_eq!(sealed.len(), unsealed.len() + 1 + 32 + 64, "seal trailer");
            assert_eq!(&sealed[..unsealed.len()], &unsealed[..]);
            assert_eq!(decode_record(&sealed, CAP).unwrap(), record);
            assert_eq!(
                crate::revision::record_digest(&record),
                digest,
                "the seal covers the digest, so the digest leaves the seal out"
            );
        }
    }

    #[test]
    fn imported_revision_id_covers_tree_parents_and_headers() {
        let base = match &records()[1] {
            WalRecord::GitBridgeImported {
                entry: GitBridgeEntry::Commit(c),
                ..
            } => c.clone(),
            _ => unreachable!(),
        };
        let id = base.changeset_id();
        let mut other_oid = base.clone();
        other_oid.git_oid = GitOid::compute_git_object("commit", b"other");
        assert_eq!(other_oid.changeset_id(), id, "the Git ID is not hashed in");
        let mut changed = base.clone();
        changed.headers.push(b'x');
        assert_ne!(changed.changeset_id(), id);
        let mut changed = base.clone();
        changed.parents.push(changed.parents[0]);
        assert_ne!(changed.changeset_id(), id);
        let mut changed = base;
        changed.tree = TreeDigest::empty();
        assert_ne!(changed.changeset_id(), id);
    }
}
