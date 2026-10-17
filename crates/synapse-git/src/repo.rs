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

use crate::inflate::{zlib_decompress, zlib_inflate_prefix};
use crate::object::{object_links, GitObject, ObjectKind};
use crate::pack::{write_pack, PackReader, WrittenPack};
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use synapse_core::{GitOid, RefusalCode, SynapseError, SynapseResult};

fn corrupt(msg: impl Into<String>) -> SynapseError {
    SynapseError::new(RefusalCode::GitObjectCorrupt, msg)
}

fn io(e: std::io::Error, what: &Path) -> SynapseError {
    SynapseError::new(RefusalCode::IoFailure, format!("{}: {e}", what.display()))
}

fn over_cap(what: &Path, size: u64, cap: u64) -> SynapseError {
    SynapseError::new(
        RefusalCode::QuotaPayloadTooLarge,
        format!(
            "{} holds {size} bytes, over the {cap} byte cap",
            what.display()
        ),
    )
}

fn not_regular(what: &Path, detail: &str) -> SynapseError {
    SynapseError::new(
        RefusalCode::PathInvalid,
        format!(
            "{} is {detail}; the bridge reads only regular files and directories inside the repository",
            what.display()
        ),
    )
}

fn describe(t: fs::FileType) -> &'static str {
    if t.is_symlink() {
        "a symbolic link"
    } else if t.is_dir() {
        "a directory"
    } else {
        "not a regular file (a pipe, socket or device)"
    }
}

/// Most bytes a loose object may inflate to by default.
pub const MAX_LOOSE_OBJECT_BYTES: usize = 1 << 30;

/// Default cap on a loose reference file and on `HEAD` (a 40-hex ID or `ref: <name>`).
pub const DEFAULT_MAX_REF_FILE_BYTES: u64 = 4096;
/// Default cap on `packed-refs`.
pub const DEFAULT_MAX_PACKED_REFS_BYTES: u64 = 64 << 20;
/// Default cap on all `.pack` and `.idx` files together (they are held in memory).
pub const DEFAULT_MAX_PACK_FILES_BYTES: u64 = 2 << 30;
/// Default budget for the inflated bytes of every object a read may hold.
pub const DEFAULT_MAX_TOTAL_OBJECT_BYTES: u64 = 1 << 30;

/// What reading a repository may cost. Every limit is checked before the bytes it bounds are
/// allocated, and an excess is refused with `QuotaPayloadTooLarge`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReadLimits {
    /// A loose reference file or `HEAD`.
    pub max_ref_file_bytes: u64,
    /// `packed-refs`.
    pub max_packed_refs_bytes: u64,
    /// Every `.pack` and `.idx` file together.
    pub max_pack_files_bytes: u64,
    /// One object (whole, delta stream, or delta result), packed or loose.
    pub max_object_bytes: u64,
    /// The objects of the whole read: the sizes every pack entry declares (counted at
    /// [`GitRepository::open_with_limits`]) plus every loose object read.
    pub max_total_object_bytes: u64,
}

impl Default for ReadLimits {
    fn default() -> Self {
        Self {
            max_ref_file_bytes: DEFAULT_MAX_REF_FILE_BYTES,
            max_packed_refs_bytes: DEFAULT_MAX_PACKED_REFS_BYTES,
            max_pack_files_bytes: DEFAULT_MAX_PACK_FILES_BYTES,
            max_object_bytes: MAX_LOOSE_OBJECT_BYTES as u64,
            max_total_object_bytes: DEFAULT_MAX_TOTAL_OBJECT_BYTES,
        }
    }
}

/// Read `path` if it is a regular file of at most `max` bytes. `Ok(None)` when it does not
/// exist. A symbolic link, directory, pipe, socket or device is refused (`PathInvalid`)
/// without being opened, so a pipe cannot block the reader and a link cannot lead outside the
/// repository. The open itself uses `O_NOFOLLOW | O_NONBLOCK` and the opened file must be the
/// regular file inspected (same device and inode), so a file swapped between the check and the
/// open is refused too; at most `max + 1` bytes are read even if it grows.
pub(crate) fn read_regular(path: &Path, max: u64) -> SynapseResult<Option<Vec<u8>>> {
    let meta = match fs::symlink_metadata(path) {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(io(e, path)),
    };
    if !meta.file_type().is_file() {
        return Err(not_regular(path, describe(meta.file_type())));
    }
    if meta.len() > max {
        return Err(over_cap(path, meta.len(), max));
    }
    let (file, opened) = open_inspected(path, &meta)?;
    let mut bytes = Vec::with_capacity(opened.len().min(max) as usize);
    file.take(max.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|e| io(e, path))?;
    if bytes.len() as u64 > max {
        return Err(over_cap(path, bytes.len() as u64, max));
    }
    Ok(Some(bytes))
}

/// Open `path`, which `symlink_metadata` reported as `meta` (a regular file), and require the
/// opened file to be that same regular file. `O_NOFOLLOW`: a link swapped in after the check
/// fails to open (`ELOOP`). `O_NONBLOCK`: a pipe swapped in opens at once instead of waiting for
/// a writer, and the device and inode check refuses it.
fn open_inspected(path: &Path, meta: &fs::Metadata) -> SynapseResult<(File, fs::Metadata)> {
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    let file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .map_err(|e| match e.raw_os_error() {
            Some(libc::ELOOP) => not_regular(path, "a symbolic link"),
            _ => io(e, path),
        })?;
    let opened = file.metadata().map_err(|e| io(e, path))?;
    if !opened.file_type().is_file() || opened.ino() != meta.ino() || opened.dev() != meta.dev() {
        return Err(not_regular(path, "a file that changed while being opened"));
    }
    Ok((file, opened))
}

/// `Ok(true)` if `path` is a real directory, `Ok(false)` if it does not exist; a symbolic link
/// or any other file type is refused.
fn real_dir(path: &Path) -> SynapseResult<bool> {
    match fs::symlink_metadata(path) {
        Ok(m) if m.file_type().is_dir() => Ok(true),
        Ok(m) => Err(not_regular(path, describe(m.file_type()))),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(io(e, path)),
    }
}

/// A Git repository opened for reading (its `.git` directory or a bare repository).
pub struct GitRepository {
    git_dir: PathBuf,
    packs: Vec<PackReader>,
    limits: ReadLimits,
    /// Object bytes counted against `limits.max_total_object_bytes` so far.
    object_bytes: u64,
}

/// Every object reachable from a repository's references, with the references themselves.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GitHistory {
    /// Reference name to object ID (`refs/...`), sorted by name.
    pub refs: BTreeMap<String, GitOid>,
    /// The branch `HEAD` names (`refs/heads/...`), or `None` for a detached or missing `HEAD`.
    pub head: Option<String>,
    /// The commit a detached `HEAD` names (its history is collected too).
    pub detached_head: Option<GitOid>,
    /// Every reachable object, keyed by ID.
    pub objects: BTreeMap<GitOid, GitObject>,
}

/// What `HEAD` holds.
enum HeadState {
    Missing,
    Symbolic(String),
    Detached(GitOid),
}

impl GitRepository {
    /// Open `git_dir` with the default [`ReadLimits`].
    pub fn open(git_dir: &Path) -> SynapseResult<Self> {
        Self::open_with_limits(git_dir, ReadLimits::default())
    }

    /// Open `git_dir` and load the index of every pack in `objects/pack` (a pack without its
    /// `.idx` is ignored, as Git ignores it). The pack and index files must be regular files
    /// within `limits.max_pack_files_bytes` together, and the sizes their entries declare must
    /// fit `limits.max_total_object_bytes`; both are checked before any object is resolved.
    pub fn open_with_limits(git_dir: &Path, limits: ReadLimits) -> SynapseResult<Self> {
        let objects = git_dir.join("objects");
        if !real_dir(&objects)? {
            return Err(SynapseError::new(
                RefusalCode::PathInvalid,
                format!("{} has no objects directory", git_dir.display()),
            ));
        }
        if fs::symlink_metadata(git_dir.join("objects/info/alternates")).is_ok() {
            return Err(corrupt(
                "repositories with alternate object stores are not read by the bridge",
            ));
        }
        let mut packs = Vec::new();
        let mut file_bytes = 0u64;
        let mut object_bytes = 0u64;
        let pack_dir = objects.join("pack");
        if real_dir(&pack_dir)? {
            let mut names: Vec<PathBuf> = fs::read_dir(&pack_dir)
                .map_err(|e| io(e, &pack_dir))?
                .filter_map(|e| e.ok().map(|e| e.path()))
                .filter(|p| p.extension().is_some_and(|x| x == "idx"))
                .collect();
            names.sort();
            for idx_path in names {
                let pack_path = idx_path.with_extension("pack");
                if fs::symlink_metadata(&pack_path).is_err() {
                    continue;
                }
                let room = limits.max_pack_files_bytes - file_bytes;
                let idx = read_regular(&idx_path, room)?
                    .ok_or_else(|| corrupt(format!("{} vanished", idx_path.display())))?;
                file_bytes += idx.len() as u64;
                let room = limits.max_pack_files_bytes - file_bytes;
                let data = read_regular(&pack_path, room)?
                    .ok_or_else(|| corrupt(format!("{} vanished", pack_path.display())))?;
                file_bytes += data.len() as u64;
                let pack = PackReader::with_index_limited(data, &idx, limits.max_object_bytes)?;
                object_bytes = object_bytes.saturating_add(pack.declared_bytes()?);
                if object_bytes > limits.max_total_object_bytes {
                    return Err(SynapseError::new(
                        RefusalCode::QuotaPayloadTooLarge,
                        format!(
                            "pack objects declare {object_bytes} bytes, over the {} byte budget",
                            limits.max_total_object_bytes
                        ),
                    ));
                }
                packs.push(pack);
            }
        }
        Ok(Self {
            git_dir: git_dir.to_path_buf(),
            packs,
            limits,
            object_bytes,
        })
    }

    /// Read object `oid` from the packs or the loose store, checking that it hashes to `oid`.
    /// A loose object's declared size is read from the first bytes of its stream and checked
    /// against the per-object cap and the remaining budget before it is inflated.
    pub fn read_object(&mut self, oid: GitOid) -> SynapseResult<Option<GitObject>> {
        for pack in &mut self.packs {
            if let Some(object) = pack.read(oid)? {
                return Ok(Some(object));
            }
        }
        let hex = oid.to_hex();
        // The fan-out directory must be a real directory too: `O_NOFOLLOW` covers only the
        // last path component, so a linked `objects/ab` could lead the read outside.
        let fanout = self.git_dir.join("objects").join(&hex[..2]);
        if !real_dir(&fanout)? {
            return Ok(None);
        }
        let path = fanout.join(&hex[2..]);
        // An incompressible object stored as zlib grows by 5 bytes per 65,535-byte block plus
        // 6; allow the object cap plus 1/64 and 1 KiB for that and the object header.
        let max_file = self.limits.max_object_bytes / 64 * 65 + 1024;
        let Some(compressed) = read_regular(&path, max_file)? else {
            return Ok(None);
        };
        let head = zlib_inflate_prefix(&compressed, 64)?;
        let nul = head
            .iter()
            .position(|&b| b == 0)
            .ok_or_else(|| corrupt(format!("loose object {hex} has no header")))?;
        let size: u64 = std::str::from_utf8(&head[..nul])
            .ok()
            .and_then(|h| h.split_once(' '))
            .and_then(|(_, n)| n.parse().ok())
            .ok_or_else(|| corrupt(format!("loose object {hex} has a malformed header")))?;
        if size > self.limits.max_object_bytes {
            return Err(over_cap(&path, size, self.limits.max_object_bytes));
        }
        let total = self.object_bytes.saturating_add(size);
        if total > self.limits.max_total_object_bytes {
            return Err(SynapseError::new(
                RefusalCode::QuotaPayloadTooLarge,
                format!(
                    "loose object {hex} brings the read to {total} bytes, over the {} byte budget",
                    self.limits.max_total_object_bytes
                ),
            ));
        }
        self.object_bytes = total;
        let (raw, used) = zlib_decompress(&compressed, nul + 1 + size as usize)?;
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

    fn head_state(&self) -> SynapseResult<HeadState> {
        let path = self.git_dir.join("HEAD");
        let Some(bytes) = read_regular(&path, self.limits.max_ref_file_bytes)? else {
            return Ok(HeadState::Missing);
        };
        let text = std::str::from_utf8(&bytes).map_err(|_| corrupt("HEAD is not UTF-8"))?;
        let value = text.trim_end();
        if let Some(name) = value.strip_prefix("ref: ") {
            return Ok(HeadState::Symbolic(name.to_string()));
        }
        Ok(HeadState::Detached(GitOid::from_hex(value).map_err(
            |_| corrupt("HEAD is neither a symbolic reference nor an object ID"),
        )?))
    }

    /// Every reference: loose refs under `refs/` override `packed-refs`; peeled lines (`^`)
    /// and comments are skipped, as are `*.lock` files (Git's in-progress updates). Also
    /// returns the branch `HEAD` points to, if symbolic. Every file read must be a regular file
    /// within its cap; a symbolic link, pipe or device anywhere under `refs/` is refused.
    pub fn refs(&self) -> SynapseResult<(BTreeMap<String, GitOid>, Option<String>)> {
        let mut refs = BTreeMap::new();
        let packed = self.git_dir.join("packed-refs");
        if let Some(bytes) = read_regular(&packed, self.limits.max_packed_refs_bytes)? {
            let text =
                std::str::from_utf8(&bytes).map_err(|_| corrupt("packed-refs is not UTF-8"))?;
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
        let root = self.git_dir.join("refs");
        let mut stack = if real_dir(&root)? {
            vec![root]
        } else {
            Vec::new()
        };
        while let Some(dir) = stack.pop() {
            for entry in fs::read_dir(&dir).map_err(|e| io(e, &dir))? {
                let entry = entry.map_err(|e| io(e, &dir))?;
                let path = entry.path();
                // `DirEntry::file_type` does not follow symbolic links.
                let file_type = entry.file_type().map_err(|e| io(e, &path))?;
                if file_type.is_dir() {
                    stack.push(path);
                    continue;
                }
                if !file_type.is_file() {
                    return Err(not_regular(&path, describe(file_type)));
                }
                if path.extension().is_some_and(|x| x == "lock") {
                    continue;
                }
                let rel = path
                    .strip_prefix(&self.git_dir)
                    .ok()
                    .and_then(|p| p.to_str())
                    .ok_or_else(|| corrupt("reference name is not UTF-8"))?
                    .replace(std::path::MAIN_SEPARATOR, "/");
                let bytes = read_regular(&path, self.limits.max_ref_file_bytes)?
                    .ok_or_else(|| corrupt(format!("reference {rel} vanished")))?;
                let text = std::str::from_utf8(&bytes)
                    .map_err(|_| corrupt(format!("reference {rel} is not UTF-8")))?;
                let value = text.trim_end();
                if value.starts_with("ref: ") {
                    // Symbolic refs other than HEAD (for example refs/remotes/origin/HEAD)
                    // name another ref; the target is exported on its own.
                    continue;
                }
                refs.insert(rel, GitOid::from_hex(value)?);
            }
        }
        let head = match self.head_state()? {
            HeadState::Symbolic(name) => Some(name),
            HeadState::Missing | HeadState::Detached(_) => None,
        };
        Ok((refs, head))
    }

    /// Collect every object reachable from every reference and from a detached `HEAD`
    /// (breadth first). A missing object or an object of the wrong kind for its link is
    /// refused (`GitObjectCorrupt`): a partial or shallow repository cannot be imported as
    /// full history.
    pub fn full_history(&mut self) -> SynapseResult<GitHistory> {
        if fs::symlink_metadata(self.git_dir.join("shallow")).is_ok() {
            return Err(corrupt("shallow repositories do not hold full history"));
        }
        let (refs, head) = self.refs()?;
        let detached_head = match self.head_state()? {
            HeadState::Detached(oid) => Some(oid),
            _ => None,
        };
        let mut objects = BTreeMap::new();
        let mut queued: BTreeSet<GitOid> = BTreeSet::new();
        let mut queue: VecDeque<(GitOid, Option<ObjectKind>)> = VecDeque::new();
        for oid in refs.values() {
            if queued.insert(*oid) {
                queue.push_back((*oid, None));
            }
        }
        if let Some(oid) = detached_head {
            if queued.insert(oid) {
                queue.push_back((oid, Some(ObjectKind::Commit)));
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
            detached_head,
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::mpsc;
    use std::time::Duration;

    fn scratch(label: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "synapse-h1-open-{label}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// The file is inspected as a regular file, then swapped before the open (the race the
    /// `symlink_metadata` check alone cannot close). The open must refuse it at once.
    #[test]
    fn a_file_swapped_for_a_pipe_or_link_after_the_check_is_refused_without_blocking() {
        for swap in ["pipe", "link"] {
            let dir = scratch(swap);
            let path = dir.join("ref");
            fs::write(&path, b"0000000000000000000000000000000000000000\n").unwrap();
            let meta = fs::symlink_metadata(&path).unwrap();
            fs::remove_file(&path).unwrap();
            if swap == "pipe" {
                let ok = std::process::Command::new("mkfifo")
                    .arg(&path)
                    .status()
                    .unwrap()
                    .success();
                assert!(ok);
            } else {
                fs::write(dir.join("elsewhere"), b"x").unwrap();
                std::os::unix::fs::symlink(dir.join("elsewhere"), &path).unwrap();
            }
            let (tx, rx) = mpsc::channel();
            let p = path.clone();
            std::thread::spawn(move || {
                let _ = tx.send(open_inspected(&p, &meta).map(|_| ()));
            });
            let result = match rx.recv_timeout(Duration::from_secs(10)) {
                Ok(r) => r,
                Err(_) => {
                    drop(fs::OpenOptions::new().write(true).open(&path));
                    panic!("{swap}: open blocked for more than 10 s");
                }
            };
            assert_eq!(result.unwrap_err().code, RefusalCode::PathInvalid, "{swap}");
        }
    }
}
