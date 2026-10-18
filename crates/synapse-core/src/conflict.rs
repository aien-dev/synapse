//! First-class conflict terms (ADR 0003 section 5.3, section 9 step D2). See
//! `docs/D2_CONFLICT_TERMS.md`.
//!
//! * An [`EntryState`] is the full state of one tree entry: absent, a file (regular,
//!   executable or symlink, with its content digest and size), or a directory (its
//!   `TreeDigest`).
//! * A [`ConflictTerm`] is a sum of entry states (the Jujutsu model): `adds` and `removes`,
//!   each a sorted multiset, with exactly one more add than remove. It is always stored
//!   *reduced*: no state is both added and removed, and at least one state is removed (one add
//!   and no removes is a resolved entry, never a conflict).
//! * [`reduce`] is the one cancellation rule: it removes the multiset intersection of adds and
//!   removes from both sides. The result does not depend on the order of the terms.
//! * [`sum_trees`] adds and removes whole trees entry by entry, over the Merkle tree: equal
//!   subtrees cancel without being read, directories are summed recursively, and whatever does
//!   not cancel to one state becomes a conflict entry. A rebase of a tree `t` from base `b`
//!   onto `o` is `o + t - b`; a revert of `t` (based on `b`) on top of `o` is `o + b - t`.
//!   A conflict entry already in a summed tree takes part with its own terms, so rebasing
//!   twice reduces to a plain three-way conflict and reverting returns a clean tree.
//! * [`diff_mutations`] turns the difference between two trees back into path mutations
//!   (upserts, deletes, and [`MutationOp::Conflict`]), so a derived revision can carry the
//!   result as ordinary content.

use crate::revision::{malformed, Reader};
use crate::tree::{tree_entry_order, TreeDigest};
use crate::{BlobDigest, FileMode, MutationOp, PathMutation, SynapseResult};
use std::cmp::Ordering;

/// Most remove terms one conflict term holds (it then holds one more add). A sum that would
/// exceed it is refused rather than truncated.
pub const MAX_CONFLICT_REMOVES: usize = 32;

const STATE_TAG_ABSENT: u8 = 0;
const STATE_TAG_DIRECTORY: u8 = 4;

/// The full state of one tree entry. Ordered by kind (absent, file, directory), then by mode,
/// content digest and size: the order of the canonical multisets.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum EntryState {
    Absent,
    File {
        mode: FileMode,
        blob_digest: BlobDigest,
        size_bytes: u64,
    },
    Dir(TreeDigest),
}

impl EntryState {
    fn is_dir_or_absent(&self) -> bool {
        matches!(self, EntryState::Absent | EntryState::Dir(_))
    }

    /// `0` (absent) | `mode tag u8 (1..=3) | blob_digest [32] | size u64` (file) |
    /// `4 | tree [32]` (directory).
    pub fn encode_into(&self, buf: &mut Vec<u8>) {
        match self {
            EntryState::Absent => buf.push(STATE_TAG_ABSENT),
            EntryState::File {
                mode,
                blob_digest,
                size_bytes,
            } => {
                buf.push(mode.tag_byte());
                buf.extend_from_slice(&blob_digest.0);
                buf.extend_from_slice(&size_bytes.to_le_bytes());
            }
            EntryState::Dir(t) => {
                buf.push(STATE_TAG_DIRECTORY);
                buf.extend_from_slice(&t.0);
            }
        }
    }

    pub(crate) fn decode_from(r: &mut Reader) -> SynapseResult<Self> {
        match r.u8()? {
            STATE_TAG_ABSENT => Ok(EntryState::Absent),
            STATE_TAG_DIRECTORY => Ok(EntryState::Dir(TreeDigest(r.array()?))),
            tag => {
                let mode = FileMode::from_tag_byte(tag)
                    .ok_or_else(|| malformed(format!("unknown entry state tag {tag}")))?;
                Ok(EntryState::File {
                    mode,
                    blob_digest: BlobDigest(r.array()?),
                    size_bytes: r.u64()?,
                })
            }
        }
    }
}

/// What kind of conflict a term is, from its add terms (the states the sides produced):
///
/// 1. `ModifyDelete`: some side removed the entry and another changed it.
/// 2. `FileDirectory`: some side has a directory and another a file or symlink.
/// 3. `Mode`: every side has a file, and the modes differ.
/// 4. `Content`: every side has a file of the same mode with different content.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ConflictKind {
    ModifyDelete,
    FileDirectory,
    Mode,
    Content,
}

/// A reduced conflict term: sorted multisets `adds` and `removes` with
/// `adds.len() == removes.len() + 1`, `1 <= removes.len() <= MAX_CONFLICT_REMOVES`, and no
/// state on both sides. Built only by [`reduce`] or [`ConflictTerm::decode`].
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ConflictTerm {
    adds: Vec<EntryState>,
    removes: Vec<EntryState>,
}

/// The outcome of [`reduce`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Reduced {
    /// One state remains: the entry is resolved (to absence when it is `Absent`).
    Resolved(EntryState),
    /// Terms remain on both sides.
    Conflict(ConflictTerm),
}

/// Reduce a sum of entry states: sort both sides and remove their multiset intersection.
/// Needs `adds.len() == removes.len() + 1`. Refused (`EnvelopeMalformed`) when the sides do
/// not balance or when more than [`MAX_CONFLICT_REMOVES`] removes remain.
pub fn reduce(mut adds: Vec<EntryState>, mut removes: Vec<EntryState>) -> SynapseResult<Reduced> {
    if adds.len() != removes.len() + 1 {
        return Err(malformed(format!(
            "a conflict sum needs one more add than remove, got {} adds and {} removes",
            adds.len(),
            removes.len()
        )));
    }
    adds.sort();
    removes.sort();
    let (mut a, mut r) = (
        Vec::with_capacity(adds.len()),
        Vec::with_capacity(removes.len()),
    );
    let (mut i, mut j) = (0, 0);
    while i < adds.len() && j < removes.len() {
        match adds[i].cmp(&removes[j]) {
            Ordering::Less => {
                a.push(adds[i]);
                i += 1;
            }
            Ordering::Greater => {
                r.push(removes[j]);
                j += 1;
            }
            Ordering::Equal => {
                i += 1;
                j += 1;
            }
        }
    }
    a.extend_from_slice(&adds[i..]);
    r.extend_from_slice(&removes[j..]);
    if r.is_empty() {
        return Ok(Reduced::Resolved(a[0]));
    }
    if r.len() > MAX_CONFLICT_REMOVES {
        return Err(malformed(format!(
            "a conflict term would hold {} removes, more than {MAX_CONFLICT_REMOVES}",
            r.len()
        )));
    }
    Ok(Reduced::Conflict(ConflictTerm {
        adds: a,
        removes: r,
    }))
}

impl ConflictTerm {
    /// The added states, sorted.
    pub fn adds(&self) -> &[EntryState] {
        &self.adds
    }

    /// The removed states, sorted.
    pub fn removes(&self) -> &[EntryState] {
        &self.removes
    }

    /// Heap bytes the two term vectors hold (by capacity), for memory accounting.
    pub fn heap_capacity_bytes(&self) -> usize {
        (self.adds.capacity() + self.removes.capacity()) * std::mem::size_of::<EntryState>()
    }

    /// The kind of conflict (see [`ConflictKind`]).
    pub fn kind(&self) -> ConflictKind {
        let adds = &self.adds;
        if adds.iter().any(|s| *s == EntryState::Absent) {
            return ConflictKind::ModifyDelete;
        }
        if adds.iter().any(|s| matches!(s, EntryState::Dir(_))) {
            return ConflictKind::FileDirectory;
        }
        let mode = |s: &EntryState| match s {
            EntryState::File { mode, .. } => Some(*mode),
            _ => None,
        };
        if adds.iter().any(|s| mode(s) != mode(&adds[0])) {
            ConflictKind::Mode
        } else {
            ConflictKind::Content
        }
    }

    /// `n u8 (removes, 1..=32) | state * (n + 1) (adds, sorted) | state * n (removes,
    /// sorted)`.
    pub fn encode_into(&self, buf: &mut Vec<u8>) {
        buf.push(self.removes.len() as u8);
        for s in self.adds.iter().chain(&self.removes) {
            s.encode_into(buf);
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        self.encode_into(&mut buf);
        buf
    }

    /// Decode exactly one canonical term (`EnvelopeMalformed` otherwise: a count outside
    /// 1..=32, an unsorted side, a state on both sides, or trailing bytes).
    pub fn decode(bytes: &[u8]) -> SynapseResult<Self> {
        let mut r = Reader::new(bytes);
        let t = Self::decode_from(&mut r)?;
        r.finish()?;
        Ok(t)
    }

    pub(crate) fn decode_from(r: &mut Reader) -> SynapseResult<Self> {
        let n = r.u8()? as usize;
        if n == 0 || n > MAX_CONFLICT_REMOVES {
            return Err(malformed(format!(
                "a conflict term holds {n} removes, outside 1..={MAX_CONFLICT_REMOVES}"
            )));
        }
        let mut adds = Vec::with_capacity(n + 1);
        for _ in 0..=n {
            adds.push(EntryState::decode_from(r)?);
        }
        let mut removes = Vec::with_capacity(n);
        for _ in 0..n {
            removes.push(EntryState::decode_from(r)?);
        }
        if adds.windows(2).any(|w| w[0] > w[1]) || removes.windows(2).any(|w| w[0] > w[1]) {
            return Err(malformed("conflict term sides are not sorted"));
        }
        if adds.iter().any(|a| removes.contains(a)) {
            return Err(malformed(
                "conflict term is not reduced: a state is both added and removed",
            ));
        }
        Ok(Self { adds, removes })
    }
}

// ---------------------------------------------------------------------------------------
// Summing trees
// ---------------------------------------------------------------------------------------

/// One entry of a tree node as the conflict algebra sees it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NodeEntry {
    /// A file or a directory (never `EntryState::Absent`).
    State(EntryState),
    /// A conflict entry.
    Conflict(ConflictTerm),
}

impl NodeEntry {
    fn is_dir(&self) -> bool {
        matches!(self, NodeEntry::State(EntryState::Dir(_)))
    }
}

/// Node access the conflict algebra needs: read one directory node, and store one.
pub trait ConflictTrees {
    /// The entries of the node `tree`, in canonical order.
    fn node(&mut self, tree: TreeDigest) -> SynapseResult<Vec<(String, NodeEntry)>>;
    /// Store a node with `entries` (any order, unique names) and return its digest.
    fn put_node(&mut self, entries: Vec<(String, NodeEntry)>) -> SynapseResult<TreeDigest>;
}

/// `adds[0] + ... + adds[n] - removes[0] - ... - removes[n-1]` over whole trees (needs
/// `adds.len() == removes.len() + 1`). Returns the root of the result.
pub fn sum_trees(
    t: &mut dyn ConflictTrees,
    adds: &[TreeDigest],
    removes: &[TreeDigest],
) -> SynapseResult<TreeDigest> {
    let adds = adds
        .iter()
        .map(|d| Some(NodeEntry::State(EntryState::Dir(*d))));
    let removes = removes
        .iter()
        .map(|d| Some(NodeEntry::State(EntryState::Dir(*d))));
    match sum_entry(t, adds.collect(), removes.collect())? {
        Some(NodeEntry::State(EntryState::Dir(d))) => Ok(d),
        None => t.put_node(Vec::new()),
        Some(_) => unreachable!("a sum of directories is a directory or absent"),
    }
}

/// Sum of one entry's states across trees (`None` = absent). Returns the resulting entry.
fn sum_entry(
    t: &mut dyn ConflictTrees,
    adds: Vec<Option<NodeEntry>>,
    removes: Vec<Option<NodeEntry>>,
) -> SynapseResult<Option<NodeEntry>> {
    let mut a = Vec::with_capacity(adds.len());
    let mut r = Vec::with_capacity(removes.len());
    // A conflict entry contributes its own terms: added as a whole, its adds add and its
    // removes remove; removed as a whole, the other way round.
    for (entry, added) in adds
        .into_iter()
        .map(|e| (e, true))
        .chain(removes.into_iter().map(|e| (e, false)))
    {
        let (plus, minus) = if added {
            (&mut a, &mut r)
        } else {
            (&mut r, &mut a)
        };
        match entry {
            None => plus.push(EntryState::Absent),
            Some(NodeEntry::State(s)) => plus.push(s),
            Some(NodeEntry::Conflict(c)) => {
                plus.extend_from_slice(&c.adds);
                minus.extend_from_slice(&c.removes);
            }
        }
    }
    let term = match reduce(a, r)? {
        Reduced::Resolved(EntryState::Absent) => return Ok(None),
        Reduced::Resolved(s) => return Ok(Some(NodeEntry::State(s))),
        Reduced::Conflict(c) => c,
    };
    if !term
        .adds
        .iter()
        .chain(&term.removes)
        .all(EntryState::is_dir_or_absent)
    {
        return Ok(Some(NodeEntry::Conflict(term)));
    }
    // Only directories (and absences, read as empty directories) remain: sum their entries.
    let mut read = |states: &[EntryState]| -> SynapseResult<Vec<Vec<(String, NodeEntry)>>> {
        states
            .iter()
            .map(|s| match s {
                EntryState::Dir(d) => t.node(*d),
                _ => Ok(Vec::new()),
            })
            .collect()
    };
    let add_nodes = read(&term.adds)?;
    let remove_nodes = read(&term.removes)?;
    let mut names: Vec<&str> = add_nodes
        .iter()
        .chain(&remove_nodes)
        .flat_map(|n| n.iter().map(|(name, _)| name.as_str()))
        .collect();
    names.sort_unstable();
    names.dedup();
    let pick = |nodes: &[Vec<(String, NodeEntry)>], name: &str| -> Vec<Option<NodeEntry>> {
        nodes
            .iter()
            .map(|n| n.iter().find(|(x, _)| x == name).map(|(_, e)| e.clone()))
            .collect()
    };
    let mut entries = Vec::new();
    for name in names {
        let child = sum_entry(t, pick(&add_nodes, name), pick(&remove_nodes, name))?;
        if let Some(e) = child {
            entries.push((name.to_string(), e));
        }
    }
    if entries.is_empty() {
        return Ok(None);
    }
    Ok(Some(NodeEntry::State(EntryState::Dir(
        t.put_node(entries)?,
    ))))
}

/// Path mutations that turn tree `from` into tree `to`, sorted by path. Applying them to
/// `from` (upserts and conflict entries replace whatever is at or above their path, as an
/// upsert does) gives `to`.
pub fn diff_mutations(
    t: &mut dyn ConflictTrees,
    from: TreeDigest,
    to: TreeDigest,
) -> SynapseResult<Vec<PathMutation>> {
    let mut out = Vec::new();
    diff_dir(t, Some(from), Some(to), "", &mut out)?;
    out.sort_by(|x, y| x.path.cmp(&y.path));
    Ok(out)
}

fn join(prefix: &str, name: &str) -> String {
    if prefix.is_empty() {
        name.to_string()
    } else {
        format!("{prefix}/{name}")
    }
}

fn leaf_mutation(path: String, e: &NodeEntry) -> Option<PathMutation> {
    let op = match e {
        NodeEntry::State(EntryState::File {
            mode,
            blob_digest,
            size_bytes,
        }) => MutationOp::Upsert {
            mode: *mode,
            blob_digest: *blob_digest,
            size_bytes: *size_bytes,
        },
        NodeEntry::Conflict(c) => MutationOp::Conflict(c.clone()),
        NodeEntry::State(_) => return None,
    };
    Some(PathMutation { path, op })
}

fn diff_dir(
    t: &mut dyn ConflictTrees,
    from: Option<TreeDigest>,
    to: Option<TreeDigest>,
    prefix: &str,
    out: &mut Vec<PathMutation>,
) -> SynapseResult<()> {
    if from == to {
        return Ok(());
    }
    let a = match from {
        Some(d) => t.node(d)?,
        None => Vec::new(),
    };
    let b = match to {
        Some(d) => t.node(d)?,
        None => Vec::new(),
    };
    let mut names: Vec<&str> = a.iter().chain(&b).map(|(n, _)| n.as_str()).collect();
    names.sort_unstable();
    names.dedup();
    for name in names {
        let x = a.iter().find(|(n, _)| n == name).map(|(_, e)| e);
        let y = b.iter().find(|(n, _)| n == name).map(|(_, e)| e);
        if x == y {
            continue;
        }
        let path = join(prefix, name);
        let dir_of = |e: Option<&NodeEntry>| match e {
            Some(NodeEntry::State(EntryState::Dir(d))) => Some(*d),
            _ => None,
        };
        match (x, y) {
            // Becomes or stays a directory: diff below it. From a non-directory, every leaf
            // of the new directory is written (an upsert below a file replaces the file).
            (_, Some(ye)) if ye.is_dir() => {
                diff_dir(t, dir_of(x), dir_of(y), &path, out)?;
            }
            // Becomes a file or a conflict entry: one mutation replaces whatever was there.
            (_, Some(ye)) => out.extend(leaf_mutation(path, ye)),
            // Removed: delete the file or conflict entry, or every leaf below the directory.
            (Some(xe), None) if xe.is_dir() => delete_all(t, dir_of(x), &path, out)?,
            (Some(_), None) => out.push(PathMutation {
                path,
                op: MutationOp::Delete,
            }),
            (None, None) => {}
        }
    }
    Ok(())
}

fn delete_all(
    t: &mut dyn ConflictTrees,
    dir: Option<TreeDigest>,
    prefix: &str,
    out: &mut Vec<PathMutation>,
) -> SynapseResult<()> {
    let Some(d) = dir else { return Ok(()) };
    for (name, e) in t.node(d)? {
        let path = join(prefix, &name);
        if e.is_dir() {
            let child = match e {
                NodeEntry::State(EntryState::Dir(c)) => Some(c),
                _ => None,
            };
            delete_all(t, child, &path, out)?;
        } else {
            out.push(PathMutation {
                path,
                op: MutationOp::Delete,
            });
        }
    }
    Ok(())
}

/// Canonical order of two node entries (a conflict entry sorts as a non-directory).
pub fn node_entry_order(a: &(String, NodeEntry), b: &(String, NodeEntry)) -> Ordering {
    tree_entry_order(&a.0, a.1.is_dir(), &b.0, b.1.is_dir())
}

#[cfg(test)]
#[path = "conflict_tests.rs"]
mod tests;
