//! `TreeDigest`: the native, domain-separated digest of a whole repository state encoded as a
//! Merkle tree of directories (ADR 0003 section 5.1, step C1).
//!
//! A directory is one *tree node*: its entries in canonical order, each either a file (mode,
//! `BlobDigest`, size in bytes) or a subdirectory named by the `TreeDigest` of its own node. The
//! digest of the root node names the whole tree, so two repository states are equal exactly
//! when their root digests are equal, and every unchanged subtree keeps its digest across
//! revisions, forks, and repositories (structural sharing).
//!
//! The encoding is Synapse's own, not Git's. Git tree OIDs are derived from these nodes only at
//! the Git bridge; nothing here hashes with SHA-1 or depends on a Git object.
//!
//! # Canonical node encoding, version 1
//!
//! All integers are little-endian.
//!
//! ```text
//! node    = count:u32 entry*                       (count entries, strictly ascending)
//! entry   = tag:u8 name_len:u16 name:[u8; name_len] body
//! tag     = 1 regular file (100644) | 2 executable (100755) | 3 symlink (120000) | 4 directory
//! body    = blob:[u8; 32] size:u64                 (tags 1, 2, 3: BlobDigest and byte length)
//!         | tree:[u8; 32]                          (tag 4: TreeDigest of the child node)
//! digest  = SHA-256("SYNAPSE_TREE_V1\0" || len(node):u64 || node)
//! ```
//!
//! Entry names are single path segments: 1 to 2048 bytes of UTF-8, without `/`, `\`, or NUL,
//! and never `.`, `..`, or `.git` (the segment rules of [`crate::validate_repo_relative_path`]).
//! Entries are ordered by [`tree_entry_order`]: byte order of the name, with a directory compared
//! as if its name ended in `/`. This is Git's tree order, chosen because a depth-first walk in
//! that order yields full paths in plain byte order, the order every Synapse tree listing and
//! diff pages in. A name may appear once per node. The empty node (count 0) is the digest of an
//! empty repository; a directory entry never names an empty node.

use crate::{FileMode, RefusalCode, SynapseError, SynapseResult};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::cmp::Ordering;
use std::fmt;

/// Domain tag for `TreeDigest` SHA-256 computation (canonical node encoding version 1).
pub const DOMAIN_TREE_V1: &[u8] = b"SYNAPSE_TREE_V1\0";

/// Tag byte of a directory entry in the canonical node encoding.
pub const TREE_TAG_DIRECTORY: u8 = 4;

/// Tag byte of a conflict entry (ADR 0003 step D2): the body is the canonical
/// [`crate::ConflictTerm`] encoding. A conflict entry sorts as a non-directory.
pub const TREE_TAG_CONFLICT: u8 = 5;

/// Longest entry name accepted, matching the whole-path cap of `validate_repo_relative_path`.
pub const MAX_TREE_ENTRY_NAME_BYTES: usize = 2048;

/// 32-byte domain-separated SHA-256 digest of one canonical tree node, and therefore of the
/// whole tree below it. Distinct from `GitOid` (a Git tree OID is computed only at the Git
/// bridge), `BlobDigest`, and `ChangesetId`.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct TreeDigest(pub [u8; 32]);

impl TreeDigest {
    /// Digest of canonical node bytes as produced by [`TreeNodeEncoder::finish`]. The bytes are
    /// not re-validated here; use the encoder to build them.
    pub fn of_encoded_node(encoded: &[u8]) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(DOMAIN_TREE_V1);
        hasher.update((encoded.len() as u64).to_le_bytes());
        hasher.update(encoded);
        Self(hasher.finalize().into())
    }

    /// Digest of the empty tree (an empty repository).
    pub fn empty() -> Self {
        TreeNodeEncoder::new(0)
            .finish()
            .map(|(d, _)| d)
            .expect("empty node is canonical")
    }

    pub fn to_hex(self) -> String {
        hex::encode(self.0)
    }

    pub fn from_hex(s: &str) -> SynapseResult<Self> {
        let bytes = hex::decode(s).map_err(|_| {
            SynapseError::new(RefusalCode::TreeNodeMalformed, "invalid hex for TreeDigest")
        })?;
        let arr: [u8; 32] = bytes.try_into().map_err(|_| {
            SynapseError::new(
                RefusalCode::TreeNodeMalformed,
                "TreeDigest must be 32 bytes (64 hex chars)",
            )
        })?;
        Ok(Self(arr))
    }
}

impl fmt::Debug for TreeDigest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "TreeDigest({})", self.to_hex())
    }
}

impl fmt::Display for TreeDigest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex())
    }
}

/// Canonical order of two entries in one tree node: byte order of the names, with a directory
/// compared as if its name had a trailing `/` (Git's tree order). A depth-first walk in this
/// order lists full paths in byte order.
pub fn tree_entry_order(name_a: &str, is_dir_a: bool, name_b: &str, is_dir_b: bool) -> Ordering {
    let a = name_a.as_bytes();
    let b = name_b.as_bytes();
    let n = a.len().min(b.len());
    match a[..n].cmp(&b[..n]) {
        Ordering::Equal => {
            let next = |s: &[u8], is_dir: bool| match s.get(n) {
                Some(&c) => Some(c),
                None if is_dir => Some(b'/'),
                None => None,
            };
            next(a, is_dir_a).cmp(&next(b, is_dir_b))
        }
        other => other,
    }
}

/// Check that `name` is a valid single path segment for a tree entry.
pub fn validate_tree_entry_name(name: &str) -> SynapseResult<()> {
    if name.is_empty() || name.len() > MAX_TREE_ENTRY_NAME_BYTES {
        return Err(SynapseError::new(
            RefusalCode::TreeNodeMalformed,
            "tree entry name must be 1..=2048 bytes",
        ));
    }
    if name.contains(['/', '\\', '\0']) || name == "." || name == ".." || name == ".git" {
        return Err(SynapseError::new(
            RefusalCode::TreeNodeMalformed,
            format!("tree entry name is not a valid path segment: {name:?}"),
        ));
    }
    Ok(())
}

/// Streaming writer of one canonical tree node. Entries must be pushed in [`tree_entry_order`];
/// a bad name, a duplicate name, an out-of-order entry, or a count that does not match the
/// declared count is refused with `RefusalCode::TreeNodeMalformed`.
pub struct TreeNodeEncoder {
    buf: Vec<u8>,
    declared: u32,
    written: u32,
    last: Option<(String, bool)>,
}

impl TreeNodeEncoder {
    /// Start a node that will hold exactly `count` entries.
    pub fn new(count: u32) -> Self {
        let mut buf = Vec::with_capacity(4 + count as usize * 64);
        buf.extend_from_slice(&count.to_le_bytes());
        Self {
            buf,
            declared: count,
            written: 0,
            last: None,
        }
    }

    fn header(&mut self, name: &str, is_dir: bool, tag: u8) -> SynapseResult<()> {
        validate_tree_entry_name(name)?;
        if self.written == self.declared {
            return Err(SynapseError::new(
                RefusalCode::TreeNodeMalformed,
                "more tree entries than declared",
            ));
        }
        if let Some((prev, prev_dir)) = &self.last {
            if prev == name {
                return Err(SynapseError::new(
                    RefusalCode::TreeNodeMalformed,
                    format!("duplicate tree entry name {name:?}"),
                ));
            }
            if tree_entry_order(prev, *prev_dir, name, is_dir) != Ordering::Less {
                return Err(SynapseError::new(
                    RefusalCode::TreeNodeMalformed,
                    format!("tree entry {name:?} is out of canonical order"),
                ));
            }
        }
        self.buf.push(tag);
        self.buf
            .extend_from_slice(&(name.len() as u16).to_le_bytes());
        self.buf.extend_from_slice(name.as_bytes());
        self.written += 1;
        self.last = Some((name.to_string(), is_dir));
        Ok(())
    }

    /// Append a file entry.
    pub fn file(
        &mut self,
        name: &str,
        mode: FileMode,
        blob: &crate::BlobDigest,
        size_bytes: u64,
    ) -> SynapseResult<()> {
        self.header(name, false, mode.tag_byte())?;
        self.buf.extend_from_slice(&blob.0);
        self.buf.extend_from_slice(&size_bytes.to_le_bytes());
        Ok(())
    }

    /// Append a subdirectory entry naming the child node's digest.
    pub fn dir(&mut self, name: &str, child: &TreeDigest) -> SynapseResult<()> {
        self.header(name, true, TREE_TAG_DIRECTORY)?;
        self.buf.extend_from_slice(&child.0);
        Ok(())
    }

    /// Append a conflict entry (sorted as a non-directory).
    pub fn conflict(&mut self, name: &str, term: &crate::ConflictTerm) -> SynapseResult<()> {
        self.header(name, false, TREE_TAG_CONFLICT)?;
        term.encode_into(&mut self.buf);
        Ok(())
    }

    /// Finish the node: returns its digest and canonical bytes.
    pub fn finish(self) -> SynapseResult<(TreeDigest, Vec<u8>)> {
        if self.written != self.declared {
            return Err(SynapseError::new(
                RefusalCode::TreeNodeMalformed,
                format!(
                    "tree node declared {} entries but {} were written",
                    self.declared, self.written
                ),
            ));
        }
        Ok((TreeDigest::of_encoded_node(&self.buf), self.buf))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::BlobDigest;

    #[test]
    fn empty_tree_digest_is_the_domain_separated_hash_of_a_zero_count() {
        let mut h = Sha256::new();
        h.update(b"SYNAPSE_TREE_V1\0");
        h.update(4u64.to_le_bytes());
        h.update(0u32.to_le_bytes());
        let expect: [u8; 32] = h.finalize().into();
        assert_eq!(TreeDigest::empty().0, expect);
    }

    #[test]
    fn encoding_is_exact_and_digest_changes_with_any_field() {
        let blob = BlobDigest::compute(b"hello\n");
        let child = TreeDigest::empty();
        let mut enc = TreeNodeEncoder::new(2);
        enc.file("a.rs", FileMode::Regular644, &blob, 6).unwrap();
        enc.dir("src", &child).unwrap();
        let (d, bytes) = enc.finish().unwrap();
        let mut expect = Vec::new();
        expect.extend_from_slice(&2u32.to_le_bytes());
        expect.push(1);
        expect.extend_from_slice(&4u16.to_le_bytes());
        expect.extend_from_slice(b"a.rs");
        expect.extend_from_slice(&blob.0);
        expect.extend_from_slice(&6u64.to_le_bytes());
        expect.push(4);
        expect.extend_from_slice(&3u16.to_le_bytes());
        expect.extend_from_slice(b"src");
        expect.extend_from_slice(&child.0);
        assert_eq!(bytes, expect);
        assert_eq!(d, TreeDigest::of_encoded_node(&expect));

        let mut enc = TreeNodeEncoder::new(2);
        enc.file("a.rs", FileMode::Executable755, &blob, 6).unwrap();
        enc.dir("src", &child).unwrap();
        assert_ne!(enc.finish().unwrap().0, d, "mode is bound");
    }

    #[test]
    fn order_names_and_counts_are_enforced() {
        let blob = BlobDigest::compute(b"x");
        // Directory "a" sorts after file "a-b" because it compares as "a/".
        assert_eq!(tree_entry_order("a-b", false, "a", true), Ordering::Less);
        assert_eq!(tree_entry_order("a", false, "a-b", false), Ordering::Less);
        let mut enc = TreeNodeEncoder::new(2);
        enc.dir("a", &TreeDigest::empty()).unwrap();
        let err = enc.file("a-b", FileMode::Regular644, &blob, 1).unwrap_err();
        assert_eq!(err.code, RefusalCode::TreeNodeMalformed);

        let mut enc = TreeNodeEncoder::new(2);
        enc.file("a", FileMode::Regular644, &blob, 1).unwrap();
        assert!(
            enc.dir("a", &TreeDigest::empty()).is_err(),
            "duplicate name"
        );

        for bad in ["", ".", "..", ".git", "a/b", "a\\b", "a\0b"] {
            let mut enc = TreeNodeEncoder::new(1);
            assert!(
                enc.file(bad, FileMode::Regular644, &blob, 1).is_err(),
                "{bad:?}"
            );
        }
        assert!(TreeNodeEncoder::new(1).finish().is_err(), "count mismatch");
        let mut enc = TreeNodeEncoder::new(0);
        assert!(enc.file("a", FileMode::Regular644, &blob, 1).is_err());
    }

    #[test]
    fn hex_round_trips() {
        let d = TreeDigest::empty();
        assert_eq!(TreeDigest::from_hex(&d.to_hex()).unwrap(), d);
        assert!(TreeDigest::from_hex("00").is_err());
    }
}
