//! Git object model for the bridge (ADR 0003 step H1): the four object kinds, object IDs, and
//! the links between objects (a tree's entries, a commit's tree and parents, a tag's target),
//! following `gitformat-pack` (object types) and Git's object encoding
//! (`<kind> <size>\0<payload>`, SHA-1 of that).
//!
//! Parsers here read only what the bridge needs to walk history. Every other byte of a commit
//! or tag (author, committer, signatures, extra headers, message) is kept as opaque data and
//! never rewritten, so a stored object re-encodes to the same Git object ID.

use synapse_core::{GitOid, RefusalCode, SynapseError, SynapseResult};

fn corrupt(msg: impl Into<String>) -> SynapseError {
    SynapseError::new(RefusalCode::GitObjectCorrupt, msg)
}

/// The four Git object kinds; the discriminant is the pack type number (`OBJ_COMMIT` = 1 to
/// `OBJ_TAG` = 4 in `gitformat-pack`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ObjectKind {
    Commit = 1,
    Tree = 2,
    Blob = 3,
    Tag = 4,
}

impl ObjectKind {
    /// The kind name in an object header (`commit`, `tree`, `blob`, `tag`).
    pub fn name(self) -> &'static str {
        match self {
            Self::Commit => "commit",
            Self::Tree => "tree",
            Self::Blob => "blob",
            Self::Tag => "tag",
        }
    }

    pub fn from_name(name: &[u8]) -> SynapseResult<Self> {
        match name {
            b"commit" => Ok(Self::Commit),
            b"tree" => Ok(Self::Tree),
            b"blob" => Ok(Self::Blob),
            b"tag" => Ok(Self::Tag),
            other => Err(corrupt(format!(
                "unknown Git object kind {:?}",
                String::from_utf8_lossy(other)
            ))),
        }
    }

    /// The pack type number (1 to 4).
    pub fn pack_type(self) -> u8 {
        self as u8
    }

    pub fn from_pack_type(t: u8) -> SynapseResult<Self> {
        match t {
            1 => Ok(Self::Commit),
            2 => Ok(Self::Tree),
            3 => Ok(Self::Blob),
            4 => Ok(Self::Tag),
            other => Err(corrupt(format!(
                "pack type {other} is not a base object kind"
            ))),
        }
    }
}

/// One Git object: its kind and payload (the bytes after the `<kind> <size>\0` header).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GitObject {
    pub kind: ObjectKind,
    pub payload: Vec<u8>,
}

impl GitObject {
    pub fn new(kind: ObjectKind, payload: Vec<u8>) -> Self {
        Self { kind, payload }
    }

    /// The object's SHA-1 Git object ID.
    pub fn oid(&self) -> GitOid {
        GitOid::compute_git_object(self.kind.name(), &self.payload)
    }

    /// The loose object encoding `<kind> <size>\0<payload>` (before zlib).
    pub fn encode_loose(&self) -> Vec<u8> {
        let header = format!("{} {}\0", self.kind.name(), self.payload.len());
        let mut out = Vec::with_capacity(header.len() + self.payload.len());
        out.extend_from_slice(header.as_bytes());
        out.extend_from_slice(&self.payload);
        out
    }

    /// Parse a decompressed loose object `<kind> <size>\0<payload>`; the size must match.
    pub fn decode_loose(raw: &[u8]) -> SynapseResult<Self> {
        let nul = raw
            .iter()
            .position(|&b| b == 0)
            .ok_or_else(|| corrupt("loose object header has no NUL"))?;
        let header = &raw[..nul];
        let space = header
            .iter()
            .position(|&b| b == b' ')
            .ok_or_else(|| corrupt("loose object header has no space"))?;
        let kind = ObjectKind::from_name(&header[..space])?;
        let size = parse_decimal(&header[space + 1..])?;
        let payload = &raw[nul + 1..];
        if payload.len() as u64 != size {
            return Err(corrupt(format!(
                "loose object declares {size} bytes but holds {}",
                payload.len()
            )));
        }
        Ok(Self::new(kind, payload.to_vec()))
    }
}

fn parse_decimal(digits: &[u8]) -> SynapseResult<u64> {
    if digits.is_empty() || (digits.len() > 1 && digits[0] == b'0') {
        return Err(corrupt("object size is not canonical decimal"));
    }
    let mut value: u64 = 0;
    for &d in digits {
        if !d.is_ascii_digit() {
            return Err(corrupt("object size is not decimal"));
        }
        value = value
            .checked_mul(10)
            .and_then(|v| v.checked_add(u64::from(d - b'0')))
            .ok_or_else(|| corrupt("object size overflows u64"))?;
    }
    Ok(value)
}

/// One entry of a Git tree: the mode exactly as written (ASCII octal), the name bytes, and the
/// object ID it names.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GitTreeEntry {
    pub mode: Vec<u8>,
    pub name: Vec<u8>,
    pub oid: GitOid,
}

impl GitTreeEntry {
    /// The kind of object this entry names, from its mode: `40000` a tree, `160000` a commit
    /// (a gitlink, never present in this repository's object store), anything else a blob.
    pub fn target_kind(&self) -> ObjectKind {
        match self.mode.as_slice() {
            b"40000" | b"040000" => ObjectKind::Tree,
            b"160000" => ObjectKind::Commit,
            _ => ObjectKind::Blob,
        }
    }
}

/// Parse a tree payload: `(<mode> <name>\0<20-byte oid>)*`.
pub fn parse_tree(payload: &[u8]) -> SynapseResult<Vec<GitTreeEntry>> {
    let mut entries = Vec::new();
    let mut rest = payload;
    while !rest.is_empty() {
        let space = rest
            .iter()
            .position(|&b| b == b' ')
            .ok_or_else(|| corrupt("tree entry has no space after its mode"))?;
        let mode = &rest[..space];
        if mode.is_empty() || !mode.iter().all(|b| (b'0'..=b'7').contains(b)) {
            return Err(corrupt("tree entry mode is not octal"));
        }
        let after = &rest[space + 1..];
        let nul = after
            .iter()
            .position(|&b| b == 0)
            .ok_or_else(|| corrupt("tree entry name has no NUL"))?;
        let oid_bytes = after
            .get(nul + 1..nul + 21)
            .ok_or_else(|| corrupt("tree entry truncated before its object ID"))?;
        let mut oid = [0u8; 20];
        oid.copy_from_slice(oid_bytes);
        entries.push(GitTreeEntry {
            mode: mode.to_vec(),
            name: after[..nul].to_vec(),
            oid: GitOid(oid),
        });
        rest = &after[nul + 21..];
    }
    Ok(entries)
}

/// Encode tree entries in the order given (callers keep Git's tree order).
pub fn encode_tree(entries: &[GitTreeEntry]) -> Vec<u8> {
    let mut out = Vec::new();
    for e in entries {
        out.extend_from_slice(&e.mode);
        out.push(b' ');
        out.extend_from_slice(&e.name);
        out.push(0);
        out.extend_from_slice(&e.oid.0);
    }
    out
}

fn header_oid(value: &[u8], what: &str) -> SynapseResult<GitOid> {
    let hex = std::str::from_utf8(value).map_err(|_| corrupt(format!("{what} is not hex")))?;
    if hex.len() != 40 || hex.bytes().any(|b| b.is_ascii_uppercase()) {
        return Err(corrupt(format!("{what} is not 40 lowercase hex digits")));
    }
    GitOid::from_hex(hex)
}

/// Header lines of a commit or tag up to the blank line (continuation lines starting with a
/// space belong to the header above them and are skipped).
fn header_lines(payload: &[u8]) -> impl Iterator<Item = &[u8]> {
    let end = payload
        .windows(2)
        .position(|w| w == b"\n\n")
        .map_or(payload.len(), |p| p + 1);
    payload[..end]
        .split(|&b| b == b'\n')
        .filter(|l| !l.is_empty() && l[0] != b' ')
}

/// The links of a commit: its tree and parents in their written order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommitLinks {
    pub tree: GitOid,
    pub parents: Vec<GitOid>,
}

/// Parse a commit's `tree` line (first) and `parent` lines (immediately after, in order).
pub fn parse_commit_links(payload: &[u8]) -> SynapseResult<CommitLinks> {
    let mut lines = header_lines(payload);
    let tree = match lines.next() {
        Some(l) if l.starts_with(b"tree ") => header_oid(&l[5..], "commit tree")?,
        _ => return Err(corrupt("commit does not start with a tree line")),
    };
    let mut parents = Vec::new();
    for l in lines {
        if let Some(hex) = l.strip_prefix(b"parent ") {
            parents.push(header_oid(hex, "commit parent")?);
        } else {
            break;
        }
    }
    Ok(CommitLinks { tree, parents })
}

/// The target of an annotated tag: its `object` and `type` lines.
pub fn parse_tag_target(payload: &[u8]) -> SynapseResult<(GitOid, ObjectKind)> {
    let mut lines = header_lines(payload);
    let object = match lines.next() {
        Some(l) if l.starts_with(b"object ") => header_oid(&l[7..], "tag object")?,
        _ => return Err(corrupt("tag does not start with an object line")),
    };
    let kind = match lines.next() {
        Some(l) if l.starts_with(b"type ") => ObjectKind::from_name(&l[5..])?,
        _ => return Err(corrupt("tag has no type line after its object line")),
    };
    Ok((object, kind))
}

/// Every object ID `object` links to, with the kind it must have: tree entries (gitlinks
/// excluded: they name commits of another repository), a commit's tree and parents, a tag's
/// target.
pub fn object_links(object: &GitObject) -> SynapseResult<Vec<(GitOid, ObjectKind)>> {
    Ok(match object.kind {
        ObjectKind::Blob => Vec::new(),
        ObjectKind::Tree => parse_tree(&object.payload)?
            .into_iter()
            .filter(|e| e.target_kind() != ObjectKind::Commit)
            .map(|e| {
                let kind = e.target_kind();
                (e.oid, kind)
            })
            .collect(),
        ObjectKind::Commit => {
            let links = parse_commit_links(&object.payload)?;
            let mut out = vec![(links.tree, ObjectKind::Tree)];
            out.extend(links.parents.into_iter().map(|p| (p, ObjectKind::Commit)));
            out
        }
        ObjectKind::Tag => vec![parse_tag_target(&object.payload)?],
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loose_encoding_round_trips_and_ids_match_git_known_values() {
        // `git hash-object -t blob /dev/null` and `git mktree < /dev/null`.
        let empty_blob = GitObject::new(ObjectKind::Blob, Vec::new());
        assert_eq!(
            empty_blob.oid().to_hex(),
            "e69de29bb2d1d6434b8b29ae775ad8c2e48c5391"
        );
        let empty_tree = GitObject::new(ObjectKind::Tree, Vec::new());
        assert_eq!(
            empty_tree.oid().to_hex(),
            "4b825dc642cb6eb9a060e54bf8d69288fbee4904"
        );
        let raw = empty_blob.encode_loose();
        assert_eq!(GitObject::decode_loose(&raw).unwrap(), empty_blob);
        assert!(GitObject::decode_loose(b"blob 01\0x").is_err());
        assert!(GitObject::decode_loose(b"blob 2\0x").is_err());
        assert!(GitObject::decode_loose(b"blub 1\0x").is_err());
    }

    #[test]
    fn commit_and_tag_links_parse_and_keep_parent_order() {
        let c = b"tree 4b825dc642cb6eb9a060e54bf8d69288fbee4904\n\
parent 2222222222222222222222222222222222222222\n\
parent 1111111111111111111111111111111111111111\n\
author A <a@x> 1 +0000\ncommitter A <a@x> 1 +0000\n\nparent ffff\n";
        let links = parse_commit_links(c).unwrap();
        assert_eq!(links.parents.len(), 2);
        assert_eq!(links.parents[0].0[0], 0x22);
        let t = b"object 4b825dc642cb6eb9a060e54bf8d69288fbee4904\ntype tree\ntag v\n\nmsg\n";
        assert_eq!(parse_tag_target(t).unwrap().1, ObjectKind::Tree);
        assert!(parse_commit_links(b"parent x\n").is_err());
    }

    #[test]
    fn tree_entries_parse_and_re_encode_exactly() {
        let mut payload = Vec::new();
        payload.extend_from_slice(b"100644 a.txt\0");
        payload.extend_from_slice(&[1u8; 20]);
        payload.extend_from_slice(b"40000 dir\0");
        payload.extend_from_slice(&[2u8; 20]);
        let entries = parse_tree(&payload).unwrap();
        assert_eq!(entries[1].target_kind(), ObjectKind::Tree);
        assert_eq!(encode_tree(&entries), payload);
        assert!(parse_tree(&payload[..payload.len() - 1]).is_err());
    }
}
