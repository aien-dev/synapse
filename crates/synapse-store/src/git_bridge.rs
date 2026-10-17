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
//! The ledger is a pure function of the kind 10 records in `WalSeq` order: replay, a checkpoint
//! (which keeps the records) and a live store rebuild the same map. Every check runs before the
//! write ([`crate::SynapseStore::record_git_import`]); apply itself is total.

use crate::WalRecord;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use synapse_core::{
    decode_tree_node, BlobDigest, ChangesetId, GitOid, RefusalCode, RepoId, SynapseError,
    SynapseResult, TreeDigest, TreeNodeEntryKind, WalSeq,
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
        let WalRecord::GitBridgeImported { repo_id, entry } = record else {
            return;
        };
        let repo = self.repos.entry(repo_id.clone()).or_default();
        match entry {
            GitBridgeEntry::Objects { blobs, trees } => {
                for b in blobs {
                    repo.blobs.insert(b.git_oid, (b.blob, b.size_bytes));
                    self.blob_sizes.entry(b.blob).or_insert(b.size_bytes);
                }
                for t in trees {
                    let d = t.digest();
                    repo.trees.insert(t.git_oid, d);
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

    fn tree_known(&self, digest: TreeDigest, pending: &BTreeSet<TreeDigest>) -> bool {
        digest == TreeDigest::empty()
            || self.nodes.contains_key(&digest)
            || pending.contains(&digest)
    }

    fn target_known(
        &self,
        repo: Option<&GitBridgeRepo>,
        target: &GitBridgeTarget,
        blob_visible: &dyn Fn(&BlobDigest) -> bool,
    ) -> SynapseResult<()> {
        let ok = match target {
            GitBridgeTarget::Commit(id) => repo.is_some_and(|r| r.by_changeset.contains_key(id)),
            GitBridgeTarget::Tree(d) => self.tree_known(*d, &BTreeSet::new()),
            GitBridgeTarget::Blob(b) => blob_visible(b),
            GitBridgeTarget::Tag(oid) => repo.is_some_and(|r| r.tags.contains_key(oid)),
        };
        if ok {
            Ok(())
        } else {
            Err(refused(
                RefusalCode::GitObjectCorrupt,
                format!("bridge target {target:?} is not imported"),
            ))
        }
    }

    /// Check one entry against the map before it is written. Returns `false` when the entry
    /// is already fully recorded (nothing to write). `provided` maps blobs whose bytes come with
    /// the record to their length; `blob_visible` says whether a blob is already committed.
    pub(crate) fn check(
        &self,
        repo_id: &RepoId,
        entry: &GitBridgeEntry,
        provided: &BTreeMap<BlobDigest, u64>,
        blob_visible: &dyn Fn(&BlobDigest) -> bool,
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
                let mut fresh = false;
                let mut sizes: BTreeMap<BlobDigest, u64> = BTreeMap::new();
                for b in blobs {
                    match repo.and_then(|r| r.blobs.get(&b.git_oid)) {
                        Some(&(d, s)) if d == b.blob && s == b.size_bytes => {}
                        Some(_) => return Err(conflict("Git blob", b.git_oid)),
                        None => fresh = true,
                    }
                    match provided.get(&b.blob) {
                        Some(&len) if len != b.size_bytes => {
                            return Err(refused(
                                RefusalCode::BlobDigestMismatch,
                                format!(
                                    "Git blob {} declares {} bytes but its blob holds {len}",
                                    b.git_oid, b.size_bytes
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
                    sizes.insert(b.blob, b.size_bytes);
                }
                let mut pending: BTreeSet<TreeDigest> = BTreeSet::new();
                for t in trees {
                    let digest = t.digest();
                    match repo.and_then(|r| r.trees.get(&t.git_oid)) {
                        Some(&d) if d == digest => {}
                        Some(_) => return Err(conflict("Git tree", t.git_oid)),
                        None => fresh = true,
                    }
                    for e in decode_tree_node(&t.node)? {
                        match e.kind {
                            TreeNodeEntryKind::File {
                                blob, size_bytes, ..
                            } => {
                                let known_size = sizes
                                    .get(&blob)
                                    .or_else(|| self.blob_sizes.get(&blob))
                                    .copied();
                                if !(sizes.contains_key(&blob) || blob_visible(&blob)) {
                                    return Err(refused(
                                        RefusalCode::BlobNotFound,
                                        format!("tree {} names missing blob {blob}", t.git_oid),
                                    ));
                                }
                                if known_size.is_some_and(|s| s != size_bytes) {
                                    return Err(refused(
                                        RefusalCode::BlobDigestMismatch,
                                        format!(
                                            "tree {} gives {} the size {size_bytes}",
                                            t.git_oid, e.name
                                        ),
                                    ));
                                }
                            }
                            TreeNodeEntryKind::Dir(child) => {
                                if child == TreeDigest::empty() || !self.tree_known(child, &pending)
                                {
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
                    pending.insert(digest);
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
                if !self.tree_known(c.tree, &BTreeSet::new()) {
                    return Err(refused(
                        RefusalCode::TreeNodeNotFound,
                        format!(
                            "commit {} names tree {} that is not imported",
                            c.git_oid, c.tree
                        ),
                    ));
                }
                for p in &c.parents {
                    if !repo.is_some_and(|r| r.by_changeset.contains_key(p)) {
                        return Err(refused(
                            RefusalCode::ParentChangesetNotFound,
                            format!("commit {} names parent {p} that is not imported", c.git_oid),
                        ));
                    }
                }
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
                self.target_known(repo, &t.target, blob_visible)?;
                Ok(true)
            }
            GitBridgeEntry::Refs(r) => {
                check_git_ref_names(r.refs.iter().map(|(n, _)| n.as_str()), r.head.as_deref())?;
                for (_, target) in &r.refs {
                    self.target_known(repo, target, blob_visible)?;
                }
                Ok(repo.and_then(|x| x.refs.as_ref()) != Some(r))
            }
        }
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

/// Digest input of one kind 10 record for the state root: its canonical record encoding.
pub(crate) fn record_digest_input(record: &WalRecord, h: &mut Sha256) {
    if let Ok(bytes) = crate::codec::encode_record(record) {
        h.update((bytes.len() as u64).to_le_bytes());
        h.update(&bytes);
    }
}

impl crate::SynapseStore {
    /// Write one Git bridge record (WAL kind 10) for `repo_id`, after every check: binary
    /// codec, blob caps, each provided blob's digest and that every provided blob is mapped by
    /// the entry, then [`GitBridgeLedger::check`] (blob sizes and visibility, subtrees, parents
    /// and targets already imported, no Git ID remapped, reference names). Blobs not yet visible
    /// go inline in the record. Returns `None` when the entry is already recorded.
    pub fn record_git_import(
        &mut self,
        repo_id: &RepoId,
        entry: GitBridgeEntry,
        blobs: &[(BlobDigest, &[u8])],
    ) -> SynapseResult<Option<WalSeq>> {
        self.check_writable()?;
        self.check_binary_codec()?;
        let mapped: BTreeSet<BlobDigest> = entry.blobs().into_iter().collect();
        let mut provided: BTreeMap<BlobDigest, u64> = BTreeMap::new();
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
            provided.insert(*declared, len);
        }
        let visible = |d: &BlobDigest| self.blob_first_visible_seq.contains_key(d);
        if !self
            .git_bridge
            .check(repo_id, &entry, &provided, &visible)?
        {
            return Ok(None);
        }
        let mut inline: Vec<(BlobDigest, &[u8])> = Vec::new();
        for (digest, bytes) in blobs {
            if !visible(digest) && !inline.iter().any(|(d, _)| d == digest) {
                inline.push((*digest, *bytes));
            }
        }
        let record = WalRecord::GitBridgeImported {
            repo_id: repo_id.clone(),
            entry,
        };
        self.append_revision_record(record, &inline).map(Some)
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
