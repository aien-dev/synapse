//! Native Git repository reader and pack exporter for the bridge (ADR 0003 step H1).
//!
//! [`GitRepository`] reads a repository's object database directly: loose objects
//! (`objects/xx/<38 hex>`, zlib) and every `objects/pack/pack-*.pack` with its version 2
//! `.idx`, resolving deltas natively; and its references (loose refs, `packed-refs`, `HEAD`).
//! [`GitRepository::full_history`] collects every object reachable from every reference, so an
//! import sees the whole history: merge parents, annotated tags (including tags of tags),
//! file modes, and signatures inside commit and tag headers.
//!
//! [`export_repository`] writes an object set into a new bare repository as one pack and its
//! index plus the references, never as loose objects. It refuses an existing destination, so it
//! can never move a human branch of a repository that already exists.
//!
//! No Git process is started here; the system `git` is used only by the tests, as an
//! independent oracle.

use crate::inflate::zlib_decompress;
use crate::object::{object_links, GitObject, ObjectKind};
use crate::pack::{write_pack, PackReader, WrittenPack};
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fs::{self, File};
use std::io::Write;
use std::path::{Path, PathBuf};
use synapse_core::{GitOid, RefusalCode, SynapseError, SynapseResult};

fn corrupt(msg: impl Into<String>) -> SynapseError {
    SynapseError::new(RefusalCode::GitObjectCorrupt, msg)
}

fn io(e: std::io::Error, what: &Path) -> SynapseError {
    SynapseError::new(RefusalCode::IoFailure, format!("{}: {e}", what.display()))
}

/// Most bytes a loose object may inflate to.
pub const MAX_LOOSE_OBJECT_BYTES: usize = 1 << 30;

/// A Git repository opened for reading (its `.git` directory or a bare repository).
pub struct GitRepository {
    git_dir: PathBuf,
    packs: Vec<PackReader>,
}

/// Every object reachable from a repository's references, with the references themselves.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GitHistory {
    /// Reference name to object ID (`refs/...`), sorted by name.
    pub refs: BTreeMap<String, GitOid>,
    /// The branch `HEAD` names (`refs/heads/...`), or `None` for a detached or missing `HEAD`.
    pub head: Option<String>,
    /// Every reachable object, keyed by ID.
    pub objects: BTreeMap<GitOid, GitObject>,
}

impl GitRepository {
    /// Open `git_dir` and load the index of every pack in `objects/pack` (a pack without its
    /// `.idx` is ignored, as Git ignores it).
    pub fn open(git_dir: &Path) -> SynapseResult<Self> {
        let objects = git_dir.join("objects");
        if !objects.is_dir() {
            return Err(SynapseError::new(
                RefusalCode::PathInvalid,
                format!("{} has no objects directory", git_dir.display()),
            ));
        }
        if git_dir.join("objects/info/alternates").exists() {
            return Err(corrupt(
                "repositories with alternate object stores are not read by the bridge",
            ));
        }
        let mut packs = Vec::new();
        let pack_dir = objects.join("pack");
        if pack_dir.is_dir() {
            let mut names: Vec<PathBuf> = fs::read_dir(&pack_dir)
                .map_err(|e| io(e, &pack_dir))?
                .filter_map(|e| e.ok().map(|e| e.path()))
                .filter(|p| p.extension().is_some_and(|x| x == "idx"))
                .collect();
            names.sort();
            for idx_path in names {
                let pack_path = idx_path.with_extension("pack");
                if !pack_path.exists() {
                    continue;
                }
                let idx = fs::read(&idx_path).map_err(|e| io(e, &idx_path))?;
                let data = fs::read(&pack_path).map_err(|e| io(e, &pack_path))?;
                packs.push(PackReader::with_index(data, &idx)?);
            }
        }
        Ok(Self {
            git_dir: git_dir.to_path_buf(),
            packs,
        })
    }

    /// Read object `oid` from the packs or the loose store, checking that it hashes to `oid`.
    pub fn read_object(&mut self, oid: GitOid) -> SynapseResult<Option<GitObject>> {
        for pack in &mut self.packs {
            if let Some(object) = pack.read(oid)? {
                return Ok(Some(object));
            }
        }
        let hex = oid.to_hex();
        let path = self.git_dir.join("objects").join(&hex[..2]).join(&hex[2..]);
        let compressed = match fs::read(&path) {
            Ok(bytes) => bytes,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(io(e, &path)),
        };
        let (raw, used) = zlib_decompress(&compressed, MAX_LOOSE_OBJECT_BYTES)?;
        if used != compressed.len() {
            return Err(corrupt(format!("loose object {hex} has trailing bytes")));
        }
        let object = GitObject::decode_loose(&raw)?;
        if object.oid() != oid {
            return Err(corrupt(format!(
                "loose object {hex} hashes to {}",
                object.oid()
            )));
        }
        Ok(Some(object))
    }

    /// Every reference: loose refs under `refs/` override `packed-refs`; peeled lines (`^`)
    /// and comments are skipped. Also returns the branch `HEAD` points to, if symbolic.
    pub fn refs(&self) -> SynapseResult<(BTreeMap<String, GitOid>, Option<String>)> {
        let mut refs = BTreeMap::new();
        let packed = self.git_dir.join("packed-refs");
        if packed.exists() {
            let text = fs::read_to_string(&packed).map_err(|e| io(e, &packed))?;
            for line in text.lines() {
                if line.is_empty() || line.starts_with('#') || line.starts_with('^') {
                    continue;
                }
                let (hex, name) = line
                    .split_once(' ')
                    .ok_or_else(|| corrupt("malformed packed-refs line"))?;
                refs.insert(name.to_string(), GitOid::from_hex(hex)?);
            }
        }
        let mut stack = vec![self.git_dir.join("refs")];
        while let Some(dir) = stack.pop() {
            if !dir.is_dir() {
                continue;
            }
            for entry in fs::read_dir(&dir).map_err(|e| io(e, &dir))? {
                let path = entry.map_err(|e| io(e, &dir))?.path();
                if path.is_dir() {
                    stack.push(path);
                    continue;
                }
                let rel = path
                    .strip_prefix(&self.git_dir)
                    .ok()
                    .and_then(|p| p.to_str())
                    .ok_or_else(|| corrupt("reference name is not UTF-8"))?
                    .replace(std::path::MAIN_SEPARATOR, "/");
                let text = fs::read_to_string(&path).map_err(|e| io(e, &path))?;
                let value = text.trim_end();
                if value.starts_with("ref: ") {
                    // Symbolic refs other than HEAD (for example refs/remotes/origin/HEAD)
                    // name another ref; the target is exported on its own.
                    continue;
                }
                refs.insert(rel, GitOid::from_hex(value)?);
            }
        }
        let head_path = self.git_dir.join("HEAD");
        let head = match fs::read_to_string(&head_path) {
            Ok(text) => text
                .trim_end()
                .strip_prefix("ref: ")
                .map(|name| name.to_string()),
            Err(_) => None,
        };
        Ok((refs, head))
    }

    /// Collect every object reachable from every reference (breadth first). A missing object
    /// or an object of the wrong kind for its link is refused (`GitObjectCorrupt`): a partial
    /// or shallow repository cannot be imported as full history.
    pub fn full_history(&mut self) -> SynapseResult<GitHistory> {
        if self.git_dir.join("shallow").exists() {
            return Err(corrupt("shallow repositories do not hold full history"));
        }
        let (refs, head) = self.refs()?;
        let mut objects = BTreeMap::new();
        let mut queued: BTreeSet<GitOid> = BTreeSet::new();
        let mut queue: VecDeque<(GitOid, Option<ObjectKind>)> = VecDeque::new();
        for oid in refs.values() {
            if queued.insert(*oid) {
                queue.push_back((*oid, None));
            }
        }
        while let Some((oid, expected)) = queue.pop_front() {
            let object = self
                .read_object(oid)?
                .ok_or_else(|| corrupt(format!("object {oid} is missing")))?;
            if let Some(kind) = expected {
                if object.kind != kind {
                    return Err(corrupt(format!(
                        "object {oid} is a {} where a {} is linked",
                        object.kind.name(),
                        kind.name()
                    )));
                }
            }
            for (link, kind) in object_links(&object)? {
                if queued.insert(link) {
                    queue.push_back((link, Some(kind)));
                }
            }
            objects.insert(oid, object);
        }
        Ok(GitHistory {
            refs,
            head,
            objects,
        })
    }
}

/// What [`export_repository`] wrote.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExportReceipt {
    pub pack_path: PathBuf,
    pub idx_path: PathBuf,
    pub pack_checksum: GitOid,
    pub object_count: usize,
    pub pack_bytes: u64,
}

fn write_file_synced(path: &Path, bytes: &[u8]) -> SynapseResult<()> {
    let tmp = path.with_extension(format!("tmp.{}", std::process::id()));
    {
        let mut f = File::create(&tmp).map_err(|e| io(e, &tmp))?;
        f.write_all(bytes).map_err(|e| io(e, &tmp))?;
        f.sync_all().map_err(|e| io(e, &tmp))?;
    }
    fs::rename(&tmp, path).map_err(|e| io(e, path))
}

fn valid_ref_name(name: &str) -> bool {
    name.starts_with("refs/")
        && !name.ends_with('/')
        && !name.ends_with(".lock")
        && name
            .split('/')
            .all(|c| !c.is_empty() && !c.starts_with('.') && c != ".." && !c.contains(".."))
        && !name
            .bytes()
            .any(|b| b < 0x20 || b == 0x7f || b" ~^:?*[\\".contains(&b))
}

/// Create the bare repository `dest` (which must not exist) holding `objects` as one version 2
/// pack with its index, the references `refs`, and `HEAD` naming `head` (default
/// `refs/heads/main`). Every reference must name an object in the set. Returns where the pack
/// went; the same inputs always give the same pack bytes.
pub fn export_repository(
    dest: &Path,
    objects: &[GitObject],
    refs: &BTreeMap<String, GitOid>,
    head: Option<&str>,
) -> SynapseResult<ExportReceipt> {
    if dest.exists() {
        return Err(SynapseError::new(
            RefusalCode::PathInvalid,
            format!(
                "{} already exists; export writes only a new repository",
                dest.display()
            ),
        ));
    }
    let present: BTreeSet<GitOid> = objects.iter().map(GitObject::oid).collect();
    for (name, oid) in refs {
        if !valid_ref_name(name) {
            return Err(SynapseError::new(
                RefusalCode::PathInvalid,
                format!("invalid reference name {name:?}"),
            ));
        }
        if !present.contains(oid) {
            return Err(corrupt(format!(
                "reference {name} names {oid}, not exported"
            )));
        }
    }
    let head = head.unwrap_or("refs/heads/main");
    if !valid_ref_name(head) {
        return Err(SynapseError::new(
            RefusalCode::PathInvalid,
            format!("invalid HEAD target {head:?}"),
        ));
    }
    let pack_dir = dest.join("objects/pack");
    for dir in [
        pack_dir.clone(),
        dest.join("objects/info"),
        dest.join("refs/heads"),
        dest.join("refs/tags"),
    ] {
        fs::create_dir_all(&dir).map_err(|e| io(e, &dir))?;
    }
    write_file_synced(
        &dest.join("config"),
        b"[core]\n\trepositoryformatversion = 0\n\tfilemode = true\n\tbare = true\n",
    )?;
    let WrittenPack {
        pack,
        idx,
        checksum,
        entries,
    } = write_pack(objects);
    let base = pack_dir.join(format!("pack-{}", checksum.to_hex()));
    let pack_path = base.with_extension("pack");
    let idx_path = base.with_extension("idx");
    // The pack first, then its index: Git ignores a pack until its index exists.
    write_file_synced(&pack_path, &pack)?;
    write_file_synced(&idx_path, &idx)?;
    for (name, oid) in refs {
        let path = dest.join(name);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|e| io(e, parent))?;
        }
        write_file_synced(&path, format!("{}\n", oid.to_hex()).as_bytes())?;
    }
    write_file_synced(&dest.join("HEAD"), format!("ref: {head}\n").as_bytes())?;
    Ok(ExportReceipt {
        pack_path,
        idx_path,
        pack_checksum: checksum,
        object_count: entries.len(),
        pack_bytes: pack.len() as u64,
    })
}
