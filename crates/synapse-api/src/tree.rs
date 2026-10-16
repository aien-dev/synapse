//! Shared Merkle tree store with a bounded cache (ADR 0003 sections 5.1 and 5.6, step C1).
//!
//! Every repository state is a persistent Merkle tree of directory nodes named by their
//! [`TreeDigest`]. Nodes are immutable and content-addressed, so every tree that contains an
//! unchanged subtree shares the one node for it: memory grows with what changed, not with the
//! number of revisions or workspaces. This replaces the unbounded per-changeset flat
//! `VirtualTree` cache measured in Gate 4 section 4.
//!
//! [`TreeStore`] holds the nodes. Its memory is bounded: the accounted bytes of every node, the
//! hash tables, and the changeset root memo never exceed [`TreeCacheConfig::max_bytes`]. Base
//! trees are *pinned* (they are the source the other trees are rebuilt from, so they are never
//! evicted, and pinning one that does not fit is refused); every other node and memo entry is
//! evictable, least recently used first. A walk that reaches an evicted node fails with
//! `RefusalCode::TreeNodeNotFound`, and the caller rebuilds that tree from its source (base tree
//! plus changeset mutations), which reproduces the same digests.
//!
//! Byte accounting is conservative: it counts every heap allocation's requested size plus
//! [`ALLOC_OVERHEAD_BYTES`] for allocator headers and rounding, and hash tables by their bucket
//! capacity. A test with a counting allocator checks that the accounted figure never falls below
//! the bytes actually allocated (`tests/c1_tree_digest.rs`).
//!
//! Walks run in canonical entry order ([`synapse_core::tree_entry_order`]), which lists full
//! paths in byte order, so tree pages and diffs come out in the same order as `git ls-tree -r`
//! and `git diff-tree -r`. Paging seeks by subtree file counts, so a page costs the depth of the
//! tree plus the entries returned, without building a flat list of the whole tree.

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};
use std::mem::size_of;
use std::sync::Arc;
use synapse_core::{
    tree_entry_order, validate_repo_relative_path, BlobDigest, ChangesetId, FileMode, GitOid,
    RefusalCode, SynapseError, SynapseResult, TreeDigest, TreeNodeEncoder,
};

/// Default bound on tree memory: 64 MiB.
pub const DEFAULT_TREE_CACHE_BYTES: usize = 64 * 1024 * 1024;
/// Smallest bound accepted: 1 MiB, enough for the overlay nodes of any one tree to coexist.
pub const MIN_TREE_CACHE_BYTES: usize = 1024 * 1024;
/// Bytes charged per heap allocation on top of its requested size (glibc malloc: an 8-byte
/// chunk header and 16-byte granularity).
pub const ALLOC_OVERHEAD_BYTES: usize = 16;

/// Configuration of a [`TreeStore`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct TreeCacheConfig {
    /// Upper bound on the store's accounted bytes (pinned base trees included).
    pub max_bytes: usize,
}

impl Default for TreeCacheConfig {
    fn default() -> Self {
        Self {
            max_bytes: DEFAULT_TREE_CACHE_BYTES,
        }
    }
}

/// One file in a tree: the native fields bound by the [`TreeDigest`] plus the Git blob OID.
///
/// `git_blob_oid` is a bridge attribute kept beside the native fields so listings can answer
/// `git ls-tree` parity without re-reading blob bytes. It is a function of the blob content, is
/// never encoded into a tree node, and never affects a `TreeDigest`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TreeFile {
    pub mode: FileMode,
    pub blob_digest: BlobDigest,
    pub size_bytes: u64,
    pub git_blob_oid: GitOid,
}

/// What a tree entry names.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TreeEntryKind {
    File(TreeFile),
    /// A non-empty subdirectory: its node digest and the number of files anywhere below it.
    Dir {
        digest: TreeDigest,
        file_count: u64,
    },
}

/// One entry of a tree node.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TreeEntry {
    pub name: Box<str>,
    pub kind: TreeEntryKind,
}

impl TreeEntry {
    fn is_dir(&self) -> bool {
        matches!(self.kind, TreeEntryKind::Dir { .. })
    }
}

/// One immutable directory node: entries in canonical order, its digest, and derived counts.
#[derive(Debug)]
pub struct TreeNode {
    digest: TreeDigest,
    entries: Box<[TreeEntry]>,
    file_count: u64,
    encoded_len: usize,
}

impl TreeNode {
    /// Build a node from entries in any order. Entries are sorted canonically; invalid or
    /// duplicate names are refused with `RefusalCode::TreeNodeMalformed`.
    pub fn new(mut entries: Vec<TreeEntry>) -> SynapseResult<Self> {
        entries.sort_by(|a, b| tree_entry_order(&a.name, a.is_dir(), &b.name, b.is_dir()));
        let mut enc = TreeNodeEncoder::new(entries.len() as u32);
        let mut file_count = 0u64;
        for e in &entries {
            match &e.kind {
                TreeEntryKind::File(f) => {
                    enc.file(&e.name, f.mode, &f.blob_digest, f.size_bytes)?;
                    file_count += 1;
                }
                TreeEntryKind::Dir {
                    digest,
                    file_count: n,
                } => {
                    enc.dir(&e.name, digest)?;
                    file_count += n;
                }
            }
        }
        let (digest, bytes) = enc.finish()?;
        Ok(Self {
            digest,
            entries: entries.into_boxed_slice(),
            file_count,
            encoded_len: bytes.len(),
        })
    }

    pub fn digest(&self) -> TreeDigest {
        self.digest
    }

    pub fn entries(&self) -> &[TreeEntry] {
        &self.entries
    }

    /// Files anywhere below this node.
    pub fn file_count(&self) -> u64 {
        self.file_count
    }

    /// Length of this node's canonical encoding (the bytes its digest covers).
    pub fn encoded_len(&self) -> usize {
        self.encoded_len
    }

    /// Accounted heap bytes of this node (see the module documentation).
    pub fn heap_bytes(&self) -> usize {
        // ArcInner (two counters plus the node) and the entry slice, each one allocation.
        let mut bytes = 2 * size_of::<usize>() + size_of::<TreeNode>() + ALLOC_OVERHEAD_BYTES;
        if !self.entries.is_empty() {
            bytes += self.entries.len() * size_of::<TreeEntry>() + ALLOC_OVERHEAD_BYTES;
        }
        for e in self.entries.iter() {
            bytes += e.name.len() + ALLOC_OVERHEAD_BYTES;
        }
        bytes
    }
}

/// A path-level difference between two trees.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TreeDiffEntry {
    pub path: String,
    pub old: Option<TreeFile>,
    pub new: Option<TreeFile>,
}

/// Counters and gauges of a [`TreeStore`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct TreeStoreStats {
    /// Configured bound.
    pub max_bytes: usize,
    /// Accounted bytes now (nodes, tables, memo).
    pub total_bytes: usize,
    /// Highest `total_bytes` observed after any insertion.
    pub high_water_bytes: usize,
    /// Accounted bytes of pinned (base) nodes.
    pub pinned_bytes: usize,
    pub nodes: usize,
    pub pinned_nodes: usize,
    pub memoized_roots: usize,
    /// Changeset trees built (cold path); a memo hit does not count.
    pub root_builds: u64,
    /// Changeset tree lookups answered from the memo (warm path).
    pub root_hits: u64,
    pub node_hits: u64,
    pub node_misses: u64,
    pub nodes_inserted: u64,
    /// Canonical encoded bytes of the inserted nodes (the bytes a cold build writes and hashes).
    pub encoded_bytes_inserted: u64,
    pub nodes_evicted: u64,
    pub roots_evicted: u64,
}

struct Slot {
    node: Arc<TreeNode>,
    bytes: usize,
    tick: u64,
    pins: u32,
}

struct RootMemo {
    digest: TreeDigest,
    tick: u64,
}

enum Victim {
    Node(TreeDigest),
    Root(ChangesetId),
}

/// Content-addressed store of tree nodes with a byte bound (see the module documentation).
pub struct TreeStore {
    config: TreeCacheConfig,
    nodes: HashMap<TreeDigest, Slot>,
    roots: HashMap<ChangesetId, RootMemo>,
    node_bytes: usize,
    tick: u64,
    stats: TreeStoreStats,
}

/// Accounted bytes of a hashbrown table that can hold `capacity` items without growing.
fn table_bytes<K, V>(capacity: usize) -> usize {
    if capacity == 0 {
        return 0;
    }
    let buckets = (capacity * 8).div_ceil(7).next_power_of_two();
    buckets * (size_of::<(K, V)>() + 1) + 16 + ALLOC_OVERHEAD_BYTES
}

/// Accounted table bytes after one more insertion into a table holding `len` of `capacity`.
fn table_bytes_after_insert<K, V>(len: usize, capacity: usize) -> usize {
    if len < capacity {
        return table_bytes::<K, V>(capacity);
    }
    // hashbrown doubles its bucket count (from 0 to 4 buckets, capacity 3).
    let grown = if capacity < 3 {
        3
    } else {
        let buckets = (capacity * 8).div_ceil(7).next_power_of_two();
        buckets * 2 * 7 / 8
    };
    table_bytes::<K, V>(grown)
}

fn not_found(digest: TreeDigest) -> SynapseError {
    SynapseError::new(
        RefusalCode::TreeNodeNotFound,
        format!("tree node {digest} is not in the tree store (evicted or never built)"),
    )
}

/// Does `a` followed by `b` start with `prefix`?
fn concat_starts_with(a: &str, b: &str, prefix: &str) -> bool {
    if prefix.len() <= a.len() {
        return a.starts_with(prefix);
    }
    prefix.starts_with(a) && b.starts_with(&prefix[a.len()..])
}

/// How the files below directory path `dir` (ending in `/`) relate to a path prefix.
enum PrefixRelation {
    All,
    Some,
    None,
}

fn relate(dir: &str, prefix: &str) -> PrefixRelation {
    if dir.starts_with(prefix) {
        PrefixRelation::All
    } else if prefix.starts_with(dir) {
        PrefixRelation::Some
    } else {
        PrefixRelation::None
    }
}

impl TreeStore {
    /// Open an empty store. A bound below [`MIN_TREE_CACHE_BYTES`] is refused with
    /// `RefusalCode::BackpressureOverCapacity`.
    pub fn new(config: TreeCacheConfig) -> SynapseResult<Self> {
        if config.max_bytes < MIN_TREE_CACHE_BYTES {
            return Err(SynapseError::new(
                RefusalCode::BackpressureOverCapacity,
                format!(
                    "tree cache bound {} bytes is below the minimum {MIN_TREE_CACHE_BYTES}",
                    config.max_bytes
                ),
            ));
        }
        let mut store = Self {
            config,
            nodes: HashMap::new(),
            roots: HashMap::new(),
            node_bytes: 0,
            tick: 0,
            stats: TreeStoreStats {
                max_bytes: config.max_bytes,
                ..TreeStoreStats::default()
            },
        };
        // The empty tree always exists (an empty repository) and is pinned.
        let empty = store.insert(TreeNode::new(Vec::new())?);
        store.pin(empty)?;
        Ok(store)
    }

    pub fn config(&self) -> TreeCacheConfig {
        self.config
    }

    /// Accounted bytes now.
    pub fn total_bytes(&self) -> usize {
        self.node_bytes
            + table_bytes::<TreeDigest, Slot>(self.nodes.capacity())
            + table_bytes::<ChangesetId, RootMemo>(self.roots.capacity())
    }

    pub fn stats(&self) -> TreeStoreStats {
        let mut s = self.stats;
        s.total_bytes = self.total_bytes();
        s.nodes = self.nodes.len();
        s.memoized_roots = self.roots.len();
        s
    }

    fn next_tick(&mut self) -> u64 {
        self.tick += 1;
        self.tick
    }

    /// Is the node for `digest` present?
    pub fn contains(&self, digest: TreeDigest) -> bool {
        self.nodes.contains_key(&digest)
    }

    /// Fetch a node, marking it recently used.
    pub fn get(&mut self, digest: TreeDigest) -> SynapseResult<Arc<TreeNode>> {
        let tick = self.next_tick();
        match self.nodes.get_mut(&digest) {
            Some(slot) => {
                slot.tick = tick;
                self.stats.node_hits += 1;
                Ok(Arc::clone(&slot.node))
            }
            None => {
                self.stats.node_misses += 1;
                Err(not_found(digest))
            }
        }
    }

    /// Insert a node (deduplicated by digest) and return its digest, evicting least recently
    /// used unpinned nodes and memo entries first so the bound holds after the insertion.
    pub fn insert(&mut self, node: TreeNode) -> TreeDigest {
        let digest = node.digest;
        let tick = self.next_tick();
        if let Some(slot) = self.nodes.get_mut(&digest) {
            slot.tick = tick;
            return digest;
        }
        let bytes = node.heap_bytes();
        let encoded = node.encoded_len() as u64;
        self.make_room(bytes, true, false);
        self.nodes.insert(
            digest,
            Slot {
                node: Arc::new(node),
                bytes,
                tick,
                pins: 0,
            },
        );
        self.node_bytes += bytes;
        self.stats.nodes_inserted += 1;
        self.stats.encoded_bytes_inserted += encoded;
        self.note_high_water();
        digest
    }

    fn note_high_water(&mut self) {
        let total = self.total_bytes();
        if total > self.stats.high_water_bytes {
            self.stats.high_water_bytes = total;
        }
    }

    /// Evict least recently used victims until `incoming` more bytes (plus any table growth from
    /// one insertion into the node or root table) fit under the bound.
    fn make_room(&mut self, incoming: usize, into_nodes: bool, into_roots: bool) {
        let need = |s: &Self| {
            let nodes_table = if into_nodes {
                table_bytes_after_insert::<TreeDigest, Slot>(s.nodes.len(), s.nodes.capacity())
            } else {
                table_bytes::<TreeDigest, Slot>(s.nodes.capacity())
            };
            let roots_table = if into_roots {
                table_bytes_after_insert::<ChangesetId, RootMemo>(s.roots.len(), s.roots.capacity())
            } else {
                table_bytes::<ChangesetId, RootMemo>(s.roots.capacity())
            };
            s.node_bytes + nodes_table + roots_table + incoming
        };
        if need(self) <= self.config.max_bytes {
            return;
        }
        // Evict down to seven eighths of the bound so eviction runs in batches.
        let target = self.config.max_bytes - self.config.max_bytes / 8;
        let mut victims: Vec<(u64, Victim)> = self
            .nodes
            .iter()
            .filter(|(_, s)| s.pins == 0)
            .map(|(d, s)| (s.tick, Victim::Node(*d)))
            .chain(self.roots.iter().map(|(c, r)| (r.tick, Victim::Root(*c))))
            .collect();
        victims.sort_unstable_by_key(|(t, _)| *t);
        for (_, v) in victims {
            if need(self) <= target {
                break;
            }
            match v {
                Victim::Node(d) => {
                    if let Some(slot) = self.nodes.remove(&d) {
                        self.node_bytes -= slot.bytes;
                        self.stats.nodes_evicted += 1;
                    }
                }
                Victim::Root(c) => {
                    self.roots.remove(&c);
                    self.stats.roots_evicted += 1;
                }
            }
        }
    }

    /// Pin every node reachable from `root` so it is never evicted. Fails with
    /// `TreeNodeNotFound` if the tree is incomplete, or `BackpressureOverCapacity` if the pinned
    /// bytes would exceed the bound; on failure nothing stays pinned by this call.
    pub fn pin(&mut self, root: TreeDigest) -> SynapseResult<()> {
        let mut pinned: Vec<TreeDigest> = Vec::new();
        let mut stack = vec![root];
        let mut result = Ok(());
        while let Some(d) = stack.pop() {
            let Some(slot) = self.nodes.get_mut(&d) else {
                result = Err(not_found(d));
                break;
            };
            slot.pins += 1;
            if slot.pins == 1 {
                self.stats.pinned_bytes += slot.bytes;
                self.stats.pinned_nodes += 1;
            }
            pinned.push(d);
            for e in slot.node.entries.iter() {
                if let TreeEntryKind::Dir { digest, .. } = e.kind {
                    stack.push(digest);
                }
            }
        }
        if result.is_ok() && self.stats.pinned_bytes > self.config.max_bytes {
            result = Err(SynapseError::new(
                RefusalCode::BackpressureOverCapacity,
                format!(
                    "pinned base trees need {} bytes, over the tree cache bound {}",
                    self.stats.pinned_bytes, self.config.max_bytes
                ),
            ));
        }
        if result.is_err() {
            for d in pinned {
                if let Some(slot) = self.nodes.get_mut(&d) {
                    slot.pins -= 1;
                    if slot.pins == 0 {
                        self.stats.pinned_bytes -= slot.bytes;
                        self.stats.pinned_nodes -= 1;
                    }
                }
            }
        }
        result
    }

    /// Release one pin taken by [`TreeStore::pin`] on `root`; nodes left with no pin become
    /// evictable.
    pub fn unpin(&mut self, root: TreeDigest) {
        let mut stack = vec![root];
        while let Some(d) = stack.pop() {
            let Some(slot) = self.nodes.get_mut(&d) else {
                continue;
            };
            if slot.pins == 0 {
                continue;
            }
            slot.pins -= 1;
            if slot.pins == 0 {
                self.stats.pinned_bytes -= slot.bytes;
                self.stats.pinned_nodes -= 1;
            }
            for e in slot.node.entries.iter() {
                if let TreeEntryKind::Dir { digest, .. } = e.kind {
                    stack.push(digest);
                }
            }
        }
    }

    /// Remembered root of a changeset tree, if its root node is still present.
    pub fn memo_root(&mut self, changeset: ChangesetId) -> Option<TreeDigest> {
        let tick = self.next_tick();
        let memo = self.roots.get_mut(&changeset)?;
        if !self.nodes.contains_key(&memo.digest) {
            return None;
        }
        memo.tick = tick;
        self.stats.root_hits += 1;
        Some(memo.digest)
    }

    /// Remember the root of a changeset tree (an evictable memo entry).
    pub fn remember_root(&mut self, changeset: ChangesetId, digest: TreeDigest) {
        let tick = self.next_tick();
        if let Some(m) = self.roots.get_mut(&changeset) {
            m.digest = digest;
            m.tick = tick;
            return;
        }
        self.make_room(0, false, true);
        self.roots.insert(changeset, RootMemo { digest, tick });
        self.note_high_water();
    }

    /// Forget a changeset's memoized root (exact invalidation; its nodes stay shared).
    pub fn forget_root(&mut self, changeset: ChangesetId) {
        self.roots.remove(&changeset);
    }

    pub(crate) fn count_root_build(&mut self) {
        self.stats.root_builds += 1;
    }

    /// Number of memoized changeset roots.
    pub fn memoized_roots(&self) -> usize {
        self.roots.len()
    }

    /// Look up the file at `path`.
    pub fn lookup(&mut self, root: TreeDigest, path: &str) -> SynapseResult<Option<TreeFile>> {
        let mut node = self.get(root)?;
        let mut segments = path.split('/').peekable();
        while let Some(seg) = segments.next() {
            let last = segments.peek().is_none();
            let found = node
                .entries
                .iter()
                .find(|e| &*e.name == seg)
                .map(|e| e.kind);
            match (found, last) {
                (Some(TreeEntryKind::File(f)), true) => return Ok(Some(f)),
                (Some(TreeEntryKind::Dir { digest, .. }), false) => node = self.get(digest)?,
                _ => return Ok(None),
            }
        }
        Ok(None)
    }

    /// Number of files whose full path starts with `prefix` (empty prefix: every file).
    pub fn count_files(&mut self, root: TreeDigest, prefix: &str) -> SynapseResult<u64> {
        let node = self.get(root)?;
        if prefix.is_empty() {
            return Ok(node.file_count);
        }
        let mut dir = String::new();
        self.count_rec(&node, &mut dir, prefix)
    }

    fn count_rec(&mut self, node: &TreeNode, dir: &mut String, prefix: &str) -> SynapseResult<u64> {
        let mut n = 0;
        for e in node.entries.iter() {
            match e.kind {
                TreeEntryKind::File(_) => n += u64::from(concat_starts_with(dir, &e.name, prefix)),
                TreeEntryKind::Dir { digest, file_count } => {
                    let len = dir.len();
                    dir.push_str(&e.name);
                    dir.push('/');
                    match relate(dir, prefix) {
                        PrefixRelation::All => n += file_count,
                        PrefixRelation::Some => {
                            let child = self.get(digest)?;
                            n += self.count_rec(&child, dir, prefix)?;
                        }
                        PrefixRelation::None => {}
                    }
                    dir.truncate(len);
                }
            }
        }
        Ok(n)
    }

    /// Up to `limit` files whose path starts with `prefix`, skipping the first `offset` of them,
    /// in path byte order. Whole subtrees inside the skipped range are passed over by count.
    pub fn page_files(
        &mut self,
        root: TreeDigest,
        prefix: &str,
        offset: u64,
        limit: usize,
    ) -> SynapseResult<Vec<(String, TreeFile)>> {
        let node = self.get(root)?;
        let mut out = Vec::with_capacity(limit.min(4096));
        let mut skip = offset;
        let mut dir = String::new();
        self.page_rec(&node, &mut dir, prefix, &mut skip, limit, &mut out)?;
        Ok(out)
    }

    fn page_rec(
        &mut self,
        node: &TreeNode,
        dir: &mut String,
        prefix: &str,
        skip: &mut u64,
        limit: usize,
        out: &mut Vec<(String, TreeFile)>,
    ) -> SynapseResult<()> {
        for e in node.entries.iter() {
            if out.len() >= limit {
                return Ok(());
            }
            match e.kind {
                TreeEntryKind::File(f) => {
                    if concat_starts_with(dir, &e.name, prefix) {
                        if *skip > 0 {
                            *skip -= 1;
                        } else {
                            let mut path = String::with_capacity(dir.len() + e.name.len());
                            path.push_str(dir);
                            path.push_str(&e.name);
                            out.push((path, f));
                        }
                    }
                }
                TreeEntryKind::Dir { digest, file_count } => {
                    let len = dir.len();
                    dir.push_str(&e.name);
                    dir.push('/');
                    let descend = match relate(dir, prefix) {
                        PrefixRelation::All if *skip >= file_count => {
                            *skip -= file_count;
                            false
                        }
                        PrefixRelation::All | PrefixRelation::Some => true,
                        PrefixRelation::None => false,
                    };
                    if descend {
                        let child = self.get(digest)?;
                        self.page_rec(&child, dir, prefix, skip, limit, out)?;
                    }
                    dir.truncate(len);
                }
            }
        }
        Ok(())
    }

    /// Every file of the tree in path byte order.
    pub fn files(&mut self, root: TreeDigest) -> SynapseResult<Vec<(String, TreeFile)>> {
        let n = self.count_files(root, "")?;
        self.page_files(root, "", 0, n as usize)
    }

    /// Path-level differences from tree `old` to tree `new`, in path byte order. Equal subtrees
    /// (equal digests) are skipped without being read.
    pub fn diff(&mut self, old: TreeDigest, new: TreeDigest) -> SynapseResult<Vec<TreeDiffEntry>> {
        let mut out = Vec::new();
        if old != new {
            let a = self.get(old)?;
            let b = self.get(new)?;
            let mut dir = String::new();
            self.diff_rec(&a, &b, &mut dir, &mut out)?;
        }
        Ok(out)
    }

    fn emit_all(
        &mut self,
        entry: &TreeEntry,
        dir: &mut String,
        added: bool,
        out: &mut Vec<TreeDiffEntry>,
    ) -> SynapseResult<()> {
        let len = dir.len();
        dir.push_str(&entry.name);
        match entry.kind {
            TreeEntryKind::File(f) => out.push(TreeDiffEntry {
                path: dir.clone(),
                old: (!added).then_some(f),
                new: added.then_some(f),
            }),
            TreeEntryKind::Dir { digest, .. } => {
                dir.push('/');
                let node = self.get(digest)?;
                for e in node.entries.iter() {
                    self.emit_all(e, dir, added, out)?;
                }
            }
        }
        dir.truncate(len);
        Ok(())
    }

    fn diff_rec(
        &mut self,
        a: &TreeNode,
        b: &TreeNode,
        dir: &mut String,
        out: &mut Vec<TreeDiffEntry>,
    ) -> SynapseResult<()> {
        let (ea, eb) = (&a.entries, &b.entries);
        let (mut i, mut j) = (0, 0);
        while i < ea.len() || j < eb.len() {
            let ord = match (ea.get(i), eb.get(j)) {
                (Some(x), Some(y)) => tree_entry_order(&x.name, x.is_dir(), &y.name, y.is_dir()),
                (Some(_), None) => std::cmp::Ordering::Less,
                _ => std::cmp::Ordering::Greater,
            };
            match ord {
                std::cmp::Ordering::Less => {
                    self.emit_all(&ea[i], dir, false, out)?;
                    i += 1;
                }
                std::cmp::Ordering::Greater => {
                    self.emit_all(&eb[j], dir, true, out)?;
                    j += 1;
                }
                std::cmp::Ordering::Equal => {
                    match (ea[i].kind, eb[j].kind) {
                        (TreeEntryKind::File(x), TreeEntryKind::File(y)) => {
                            if x.blob_digest != y.blob_digest || x.mode != y.mode {
                                let mut path = dir.clone();
                                path.push_str(&ea[i].name);
                                out.push(TreeDiffEntry {
                                    path,
                                    old: Some(x),
                                    new: Some(y),
                                });
                            }
                        }
                        (
                            TreeEntryKind::Dir { digest: x, .. },
                            TreeEntryKind::Dir { digest: y, .. },
                        ) => {
                            if x != y {
                                let len = dir.len();
                                dir.push_str(&ea[i].name);
                                dir.push('/');
                                let (na, nb) = (self.get(x)?, self.get(y)?);
                                self.diff_rec(&na, &nb, dir, out)?;
                                dir.truncate(len);
                            }
                        }
                        // Equal order implies equal name and kind.
                        _ => unreachable!("tree_entry_order Equal with differing kinds"),
                    }
                    i += 1;
                    j += 1;
                }
            }
        }
        Ok(())
    }

    /// Bytes of canonical node encoding reachable from `root` (each distinct node once), and the
    /// number of distinct nodes. Used for the memory-bandwidth bound of a full walk.
    pub fn encoded_bytes(&mut self, root: TreeDigest) -> SynapseResult<(u64, u64)> {
        let mut seen = std::collections::HashSet::new();
        let mut stack = vec![root];
        let (mut bytes, mut nodes) = (0u64, 0u64);
        while let Some(d) = stack.pop() {
            if !seen.insert(d) {
                continue;
            }
            let node = self.get(d)?;
            bytes += node.encoded_len as u64;
            nodes += 1;
            for e in node.entries.iter() {
                if let TreeEntryKind::Dir { digest, .. } = e.kind {
                    stack.push(digest);
                }
            }
        }
        Ok((bytes, nodes))
    }
}

/// A mutable edit of one tree: opens only the directories on touched paths, applies path
/// mutations in order with the same rules as the flat overlay it replaces, and writes back only
/// the changed nodes ([`TreeEdit::finish`]). Unchanged subtrees keep their digests.
pub struct TreeEdit {
    root: EditDir,
    /// Canonical bytes of the nodes written by `finish` (for cold-build bounds).
    written_bytes: u64,
    written_nodes: u64,
}

enum EditDir {
    Stored { digest: TreeDigest, file_count: u64 },
    Open(BTreeMap<Box<str>, EditEntry>),
}

enum EditEntry {
    File(TreeFile),
    Dir(EditDir),
}

impl EditDir {
    fn open(&mut self, store: &mut TreeStore) -> SynapseResult<&mut BTreeMap<Box<str>, EditEntry>> {
        if let EditDir::Stored { digest, .. } = *self {
            let node = store.get(digest)?;
            let map = node
                .entries
                .iter()
                .map(|e| {
                    let v = match e.kind {
                        TreeEntryKind::File(f) => EditEntry::File(f),
                        TreeEntryKind::Dir { digest, file_count } => {
                            EditEntry::Dir(EditDir::Stored { digest, file_count })
                        }
                    };
                    (e.name.clone(), v)
                })
                .collect();
            *self = EditDir::Open(map);
        }
        match self {
            EditDir::Open(map) => Ok(map),
            EditDir::Stored { .. } => unreachable!("opened above"),
        }
    }
}

impl TreeEdit {
    /// Start editing the tree `base` (its root node must be present).
    pub fn new(store: &mut TreeStore, base: TreeDigest) -> SynapseResult<Self> {
        let file_count = store.get(base)?.file_count;
        Ok(Self {
            root: EditDir::Stored {
                digest: base,
                file_count,
            },
            written_bytes: 0,
            written_nodes: 0,
        })
    }

    /// Create or replace the file at `path`. A file at an ancestor path is replaced by a
    /// directory, and a directory at `path` (with everything below it) is replaced by the file.
    pub fn upsert(
        &mut self,
        store: &mut TreeStore,
        path: &str,
        file: TreeFile,
    ) -> SynapseResult<()> {
        validate_repo_relative_path(path)?;
        let mut segments: Vec<&str> = path.split('/').collect();
        let name = segments.pop().expect("validated path is non-empty");
        let mut dir = &mut self.root;
        for seg in segments {
            let map = dir.open(store)?;
            let slot = map
                .entry(seg.into())
                .or_insert_with(|| EditEntry::Dir(EditDir::Open(BTreeMap::new())));
            if matches!(slot, EditEntry::File(_)) {
                *slot = EditEntry::Dir(EditDir::Open(BTreeMap::new()));
            }
            dir = match slot {
                EditEntry::Dir(d) => d,
                EditEntry::File(_) => unreachable!("replaced above"),
            };
        }
        dir.open(store)?.insert(name.into(), EditEntry::File(file));
        Ok(())
    }

    /// Remove the file at `path`. A missing path, or a path naming a directory, is left as is.
    pub fn delete(&mut self, store: &mut TreeStore, path: &str) -> SynapseResult<()> {
        validate_repo_relative_path(path)?;
        let mut segments: Vec<&str> = path.split('/').collect();
        let name = segments.pop().expect("validated path is non-empty");
        let mut dir = &mut self.root;
        for seg in segments {
            let map = dir.open(store)?;
            dir = match map.get_mut(seg) {
                Some(EditEntry::Dir(d)) => d,
                _ => return Ok(()),
            };
        }
        let map = dir.open(store)?;
        if matches!(map.get(name), Some(EditEntry::File(_))) {
            map.remove(name);
        }
        Ok(())
    }

    /// Overlay every file of tree `other` onto this edit, as if each were upserted in path
    /// order: files of `other` win, a file and a directory at the same path resolve to
    /// `other`'s entry, and subtrees equal on both sides are not opened.
    pub fn overlay(&mut self, store: &mut TreeStore, other: TreeDigest) -> SynapseResult<()> {
        let node = store.get(other)?;
        overlay_dir(&mut self.root, &node, store)
    }

    /// Write the changed nodes and return the new root digest.
    pub fn finish(self, store: &mut TreeStore) -> SynapseResult<TreeDigest> {
        self.finish_with_counts(store).map(|(digest, _, _)| digest)
    }

    /// Like [`TreeEdit::finish`], also returning the canonical bytes and count of nodes written.
    pub fn finish_with_counts(
        mut self,
        store: &mut TreeStore,
    ) -> SynapseResult<(TreeDigest, u64, u64)> {
        let root = std::mem::replace(
            &mut self.root,
            EditDir::Stored {
                digest: TreeDigest::empty(),
                file_count: 0,
            },
        );
        let digest = match self.freeze(root, store)? {
            Some((digest, _)) => digest,
            None => store.insert(TreeNode::new(Vec::new())?),
        };
        Ok((digest, self.written_bytes, self.written_nodes))
    }

    /// Freeze a directory bottom-up. Returns `None` for an empty directory (pruned).
    fn freeze(
        &mut self,
        dir: EditDir,
        store: &mut TreeStore,
    ) -> SynapseResult<Option<(TreeDigest, u64)>> {
        let map = match dir {
            EditDir::Stored { digest, file_count } => return Ok(Some((digest, file_count))),
            EditDir::Open(map) => map,
        };
        let mut entries = Vec::with_capacity(map.len());
        for (name, entry) in map {
            match entry {
                EditEntry::File(f) => entries.push(TreeEntry {
                    name,
                    kind: TreeEntryKind::File(f),
                }),
                EditEntry::Dir(d) => {
                    if let Some((digest, file_count)) = self.freeze(d, store)? {
                        entries.push(TreeEntry {
                            name,
                            kind: TreeEntryKind::Dir { digest, file_count },
                        });
                    }
                }
            }
        }
        if entries.is_empty() {
            return Ok(None);
        }
        let node = TreeNode::new(entries)?;
        let file_count = node.file_count;
        self.written_bytes += node.encoded_len as u64;
        self.written_nodes += 1;
        Ok(Some((store.insert(node), file_count)))
    }
}

fn overlay_dir(dir: &mut EditDir, other: &TreeNode, store: &mut TreeStore) -> SynapseResult<()> {
    if let EditDir::Stored { digest, .. } = dir {
        if *digest == other.digest {
            return Ok(());
        }
    }
    let map = dir.open(store)?;
    for e in other.entries.iter() {
        match e.kind {
            TreeEntryKind::File(f) => {
                map.insert(e.name.clone(), EditEntry::File(f));
            }
            TreeEntryKind::Dir { digest, file_count } => match map.get_mut(&e.name) {
                Some(EditEntry::Dir(mine)) => {
                    let child = store.get(digest)?;
                    overlay_dir(mine, &child, store)?;
                }
                _ => {
                    map.insert(
                        e.name.clone(),
                        EditEntry::Dir(EditDir::Stored { digest, file_count }),
                    );
                }
            },
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn file(content: &[u8]) -> TreeFile {
        TreeFile {
            mode: FileMode::Regular644,
            blob_digest: BlobDigest::compute(content),
            size_bytes: content.len() as u64,
            git_blob_oid: GitOid::compute_blob(content),
        }
    }

    fn build(store: &mut TreeStore, files: &[(&str, &[u8])]) -> TreeDigest {
        let mut edit = TreeEdit::new(store, TreeDigest::empty()).unwrap();
        for (p, c) in files {
            edit.upsert(store, p, file(c)).unwrap();
        }
        edit.finish(store).unwrap()
    }

    fn paths(store: &mut TreeStore, root: TreeDigest) -> Vec<String> {
        store
            .files(root)
            .unwrap()
            .into_iter()
            .map(|(p, _)| p)
            .collect()
    }

    #[test]
    fn digest_is_independent_of_edit_order_and_history() {
        let mut s = TreeStore::new(TreeCacheConfig::default()).unwrap();
        let a = build(&mut s, &[("x/y", b"1"), ("a-b", b"2"), ("a/c", b"3")]);
        let b = build(&mut s, &[("a/c", b"3"), ("x/y", b"1"), ("a-b", b"2")]);
        assert_eq!(a, b);
        // Add then delete returns to the same digest.
        let mut e = TreeEdit::new(&mut s, a).unwrap();
        e.upsert(&mut s, "z/new", file(b"9")).unwrap();
        e.delete(&mut s, "z/new").unwrap();
        assert_eq!(e.finish(&mut s).unwrap(), a);
        assert_eq!(paths(&mut s, a), vec!["a-b", "a/c", "x/y"]);
    }

    #[test]
    fn upsert_replaces_file_dir_collisions_and_delete_prunes_empty_dirs() {
        let mut s = TreeStore::new(TreeCacheConfig::default()).unwrap();
        let root = build(&mut s, &[("a", b"f"), ("d/e/f", b"g"), ("d/h", b"i")]);
        let mut e = TreeEdit::new(&mut s, root).unwrap();
        e.upsert(&mut s, "a/b", file(b"new")).unwrap(); // file a becomes dir a
        e.upsert(&mut s, "d/e", file(b"file")).unwrap(); // dir d/e becomes file d/e
        e.delete(&mut s, "d/h").unwrap();
        e.delete(&mut s, "nope/x").unwrap();
        let r2 = e.finish(&mut s).unwrap();
        assert_eq!(paths(&mut s, r2), vec!["a/b", "d/e"]);
        let mut e = TreeEdit::new(&mut s, r2).unwrap();
        e.delete(&mut s, "a/b").unwrap();
        e.delete(&mut s, "d/e").unwrap();
        assert_eq!(e.finish(&mut s).unwrap(), TreeDigest::empty());
    }

    #[test]
    fn paging_with_offset_and_prefix_matches_a_flat_listing() {
        let mut s = TreeStore::new(TreeCacheConfig::default()).unwrap();
        let names: Vec<String> = (0..200)
            .map(|i| format!("d{}/s{}/f{i}", i % 7, i % 3))
            .chain((0..20).map(|i| format!("d1-top{i}")))
            .collect();
        let files: Vec<(&str, &[u8])> = names.iter().map(|n| (n.as_str(), n.as_bytes())).collect();
        let root = build(&mut s, &files);
        let mut flat: Vec<String> = names.clone();
        flat.sort();
        for prefix in ["", "d1", "d1/", "d1/s", "d1/s2/", "d1-", "zz"] {
            let expect: Vec<&String> = flat.iter().filter(|p| p.starts_with(prefix)).collect();
            assert_eq!(s.count_files(root, prefix).unwrap(), expect.len() as u64);
            for (offset, limit) in [(0, 1000), (0, 7), (5, 13), (expect.len(), 4)] {
                let got = s.page_files(root, prefix, offset as u64, limit).unwrap();
                let want: Vec<&String> = expect.iter().skip(offset).take(limit).copied().collect();
                let got: Vec<&String> = got.iter().map(|(p, _)| p).collect();
                assert_eq!(got, want, "prefix {prefix:?} offset {offset} limit {limit}");
            }
        }
    }

    #[test]
    fn diff_skips_equal_subtrees_and_reports_in_path_order() {
        let mut s = TreeStore::new(TreeCacheConfig::default()).unwrap();
        let a = build(
            &mut s,
            &[("a", b"1"), ("big/x", b"2"), ("big/y", b"3"), ("k/l", b"4")],
        );
        let b = build(
            &mut s,
            &[
                ("a/z", b"1"),
                ("big/x", b"2"),
                ("big/y", b"3"),
                ("k/l", b"5"),
            ],
        );
        let d = s.diff(a, b).unwrap();
        let summary: Vec<(String, bool, bool)> = d
            .iter()
            .map(|e| (e.path.clone(), e.old.is_some(), e.new.is_some()))
            .collect();
        assert_eq!(
            summary,
            vec![
                ("a".into(), true, false),
                ("a/z".into(), false, true),
                ("k/l".into(), true, true),
            ]
        );
        let hits_before = s.stats().node_hits;
        assert!(s.diff(a, a).unwrap().is_empty());
        assert_eq!(s.stats().node_hits, hits_before, "equal roots are not read");
    }

    #[test]
    fn overlay_matches_upserting_every_file_of_the_other_tree() {
        let mut s = TreeStore::new(TreeCacheConfig::default()).unwrap();
        let a = build(
            &mut s,
            &[("x", b"1"), ("d/p", b"2"), ("d/q", b"3"), ("e/f", b"4")],
        );
        let b = build(
            &mut s,
            &[("x/y", b"5"), ("d/q", b"6"), ("e", b"7"), ("n", b"8")],
        );
        let mut e = TreeEdit::new(&mut s, a).unwrap();
        e.overlay(&mut s, b).unwrap();
        let merged = e.finish(&mut s).unwrap();
        let mut e = TreeEdit::new(&mut s, a).unwrap();
        for (p, f) in s.files(b).unwrap() {
            e.upsert(&mut s, &p, f).unwrap();
        }
        assert_eq!(merged, e.finish(&mut s).unwrap());
        assert_eq!(paths(&mut s, merged), vec!["d/p", "d/q", "e", "n", "x/y"]);
    }

    #[test]
    fn bound_is_enforced_pinned_nodes_survive_and_evicted_nodes_are_reported() {
        let mut s = TreeStore::new(TreeCacheConfig {
            max_bytes: MIN_TREE_CACHE_BYTES,
        })
        .unwrap();
        let base = build(&mut s, &[("keep/me", b"base")]);
        s.pin(base).unwrap();
        let mut last = base;
        for i in 0..4000u32 {
            let mut e = TreeEdit::new(&mut s, base).unwrap();
            e.upsert(&mut s, &format!("gen/{i}/f"), file(&i.to_le_bytes()))
                .unwrap();
            last = e.finish(&mut s).unwrap();
            assert!(s.total_bytes() <= MIN_TREE_CACHE_BYTES);
        }
        let st = s.stats();
        assert!(st.nodes_evicted > 0, "{st:?}");
        assert!(st.high_water_bytes <= MIN_TREE_CACHE_BYTES);
        assert!(s.contains(base) && s.contains(last));
        assert_eq!(paths(&mut s, base), vec!["keep/me"]);
        let err = TreeStore::new(TreeCacheConfig { max_bytes: 1024 })
            .err()
            .unwrap();
        assert_eq!(err.code, RefusalCode::BackpressureOverCapacity);
    }
}
