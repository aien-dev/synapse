//! Segment store (ADR 0003 step A2, section 5.9): WAL records and blob content in
//! append-only segment files instead of one file per blob.
//!
//! * Segment `1` is `wal.v2.log`; segment `n >= 2` is `wal.v2.<n, at least 6 digits>.log`,
//!   all in the store root. Every segment has the WAL v2 layout ([`super::wal2`]): 4 KiB
//!   aligned batches, frames with inline blobs, zero-filled and synced space ahead of the
//!   write position. A batch is one positioned write plus one `fdatasync` of the active
//!   segment.
//! * Rotation: when the active segment holds data and the next batch would end past
//!   `StoreLimits::segment_bytes`, a new segment file is created, zero-filled, synced
//!   (`sync_all`), and the store directory is flushed before any batch is written into it.
//!   The active segment is synced and the directory flushed again on every open, so a
//!   file left by a process that died before its directory flush is made durable before
//!   it receives a batch.
//! * Index: in memory, blob digest to `(segment, offset, length)`. Recovery rebuilds it
//!   from the segment index file bound to the checkpoint plus the batches replayed after
//!   it. Checkpoints never move blobs out of the segments and never empty a segment
//!   (no garbage collection of segment data before ADR 0003 step K1).
//! * Segment index file `wal.v2.index.<16 hex>`: written (temp, sync, rename, directory
//!   sync) before the checkpoint it is bound to. Layout, little-endian:
//!   `magic "SSX1" | u16 version = 1 | u16 reserved = 0 | binding[32] |
//!   u64 replay_segment | u64 replay_offset | u64 count |
//!   count x (digest[32] | u64 segment | u64 offset | u32 len) | sha256[32]`, entries in
//!   strictly increasing digest order, the trailing digest over
//!   `"SYNAPSE_SEGMENT_INDEX_V1\0" || every preceding byte`. `binding` is the digest of the
//!   checkpoint file the index belongs to ([`checkpoint_binding`]), so an index written
//!   just before a crash that kept the older checkpoint is never used with it.
//! * Chunks (ADR 0003 G2): an index whose checkpoint retains chunked blobs has version 2:
//!   the version 1 layout up to the blob entries, then `u64 chunk_count | chunk_count x
//!   (chunk_digest[32] | u64 segment | u64 offset | u32 len) | u64 manifest_count |
//!   manifest_count x (blob_digest[32] | u64 len | u32 n | n x (chunk_digest[32] | u32 len))`
//!   before the trailing digest; chunks and manifests in strictly increasing digest order,
//!   every chunk named by a manifest and before the replay position, every manifest length
//!   the sum of its chunks. An index without chunks stays version 1, so a store that never
//!   chunked stays readable by builds before G2; builds before G2 refuse one that did
//!   (`CheckpointCorrupt` for the index, `WalFlagsNonZero` for its chunked frames).

use super::*;
use std::os::unix::fs::FileExt;

/// Marker frame version in `wal.log` for the segment layout (version 2 is the WAL v2
/// marker of the single-file layout). Binaries that predate A2 refuse version 3
/// (`WalVersionUnsupported`) instead of missing segments 2 and up.
pub const WAL_SEGMENT_MARKER_VERSION: u16 = 3;
/// File name prefix of segment index files.
pub const SEGMENT_INDEX_PREFIX: &str = "wal.v2.index.";
/// Segment index magic.
pub const SEGMENT_INDEX_MAGIC: [u8; 4] = *b"SSX1";
/// Segment index format version.
pub const SEGMENT_INDEX_VERSION: u16 = 1;
/// Segment index format version with chunks and manifests (ADR 0003 G2).
pub const SEGMENT_INDEX_VERSION_CHUNKS: u16 = 2;
/// Domain tag of the segment index trailer digest.
pub const DOMAIN_SEGMENT_INDEX: &[u8] = b"SYNAPSE_SEGMENT_INDEX_V1\0";
/// Domain tag of the checkpoint binding digest.
pub const DOMAIN_SEGMENT_BINDING: &[u8] = b"SYNAPSE_SEGMENT_CHECKPOINT_BINDING_V1\0";

const INDEX_HEADER_LEN: usize = 64;
const INDEX_ENTRY_LEN: usize = 52;

/// File name of segment `id` (`id >= 1`).
pub fn segment_file_name(id: u64) -> String {
    if id == 1 {
        wal2::WAL_V2_FILE.to_string()
    } else {
        format!("wal.v2.{id:06}.log")
    }
}

/// Segment id of a file name, if it is one in canonical form.
pub fn parse_segment_file_name(name: &str) -> Option<u64> {
    if name == wal2::WAL_V2_FILE {
        return Some(1);
    }
    let digits = name.strip_prefix("wal.v2.")?.strip_suffix(".log")?;
    if digits.len() < 6 || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let id: u64 = digits.parse().ok()?;
    (id >= 2 && segment_file_name(id) == name).then_some(id)
}

/// Ids of the segment files present in `root`, ascending.
pub(crate) fn list_segments(root: &Path) -> SynapseResult<Vec<u64>> {
    let mut ids = Vec::new();
    for entry in fs::read_dir(root).map_err(io_err)? {
        let entry = entry.map_err(io_err)?;
        if let Some(id) = entry.file_name().to_str().and_then(parse_segment_file_name) {
            ids.push(id);
        }
    }
    ids.sort_unstable();
    Ok(ids)
}

/// Location of one blob inside a segment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct BlobLoc {
    pub segment: u64,
    pub offset: u64,
    pub len: u32,
}

/// Digest that binds a segment index to one checkpoint file's exact bytes.
pub(crate) fn binding_of(checkpoint: Option<(&str, &[u8])>) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(DOMAIN_SEGMENT_BINDING);
    match checkpoint {
        Some((name, bytes)) => {
            h.update([1u8]);
            h.update((name.len() as u32).to_le_bytes());
            h.update(name.as_bytes());
            h.update(bytes);
        }
        None => h.update([0u8]),
    }
    h.finalize().into()
}

/// Binding of the checkpoint on disk: `checkpoint.v2` when present, else a
/// `checkpoint.v1` that is not the tombstone, else none.
pub(crate) fn checkpoint_binding(root: &Path) -> SynapseResult<[u8; 32]> {
    let v2 = root.join(codec::CHECKPOINT_V2_FILE);
    if v2.exists() {
        let bytes = fs::read(&v2).map_err(io_err)?;
        return Ok(binding_of(Some((codec::CHECKPOINT_V2_FILE, &bytes))));
    }
    let v1 = root.join("checkpoint.v1");
    if v1.exists() {
        let bytes = fs::read(&v1).map_err(io_err)?;
        if bytes != codec::v1_tombstone_bytes() {
            return Ok(binding_of(Some(("checkpoint.v1", &bytes))));
        }
    }
    Ok(binding_of(None))
}

/// The segment index persisted next to a checkpoint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SegmentIndex {
    /// [`binding_of`] the checkpoint this index belongs to.
    pub binding: [u8; 32],
    /// Replay starts at this segment and byte offset: everything before it is covered
    /// by the checkpoint.
    pub replay_segment: u64,
    pub replay_offset: u64,
    /// Locations of the blobs the checkpoint retains that live in segment bytes before
    /// the replay position.
    pub entries: BTreeMap<BlobDigest, BlobLoc>,
    /// Locations of the chunks the retained chunked blobs name (ADR 0003 G2; version 2).
    pub chunks: BTreeMap<ChunkDigest, BlobLoc>,
    /// Manifests of the retained chunked blobs (version 2).
    pub manifests: BTreeMap<BlobDigest, ChunkManifest>,
}

fn index_corrupt(what: &str) -> SynapseError {
    SynapseError::new(
        RefusalCode::CheckpointCorrupt,
        format!("segment index: {what}"),
    )
}

fn index_digest(bytes: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(DOMAIN_SEGMENT_INDEX);
    h.update(bytes);
    h.finalize().into()
}

impl SegmentIndex {
    /// File name of the index bound to `binding`.
    pub fn file_name(binding: &[u8; 32]) -> String {
        format!("{SEGMENT_INDEX_PREFIX}{}", hex::encode(&binding[..8]))
    }

    /// Encoded index: version 1 when it holds no chunks (readable by pre-G2 builds),
    /// version 2 otherwise.
    pub fn encode(&self) -> Vec<u8> {
        let v2 = !self.chunks.is_empty() || !self.manifests.is_empty();
        let mut b =
            Vec::with_capacity(INDEX_HEADER_LEN + self.entries.len() * INDEX_ENTRY_LEN + 32);
        b.extend_from_slice(&SEGMENT_INDEX_MAGIC);
        let version = if v2 {
            SEGMENT_INDEX_VERSION_CHUNKS
        } else {
            SEGMENT_INDEX_VERSION
        };
        b.extend_from_slice(&version.to_le_bytes());
        b.extend_from_slice(&0u16.to_le_bytes());
        b.extend_from_slice(&self.binding);
        b.extend_from_slice(&self.replay_segment.to_le_bytes());
        b.extend_from_slice(&self.replay_offset.to_le_bytes());
        b.extend_from_slice(&(self.entries.len() as u64).to_le_bytes());
        let put_loc = |b: &mut Vec<u8>, d: &[u8; 32], loc: &BlobLoc| {
            b.extend_from_slice(d);
            b.extend_from_slice(&loc.segment.to_le_bytes());
            b.extend_from_slice(&loc.offset.to_le_bytes());
            b.extend_from_slice(&loc.len.to_le_bytes());
        };
        for (d, loc) in &self.entries {
            put_loc(&mut b, &d.0, loc);
        }
        if v2 {
            b.extend_from_slice(&(self.chunks.len() as u64).to_le_bytes());
            for (d, loc) in &self.chunks {
                put_loc(&mut b, &d.0, loc);
            }
            b.extend_from_slice(&(self.manifests.len() as u64).to_le_bytes());
            for m in self.manifests.values() {
                b.extend_from_slice(&m.blob.0);
                b.extend_from_slice(&m.len.to_le_bytes());
                b.extend_from_slice(&(m.chunks.len() as u32).to_le_bytes());
                for (d, l) in &m.chunks {
                    b.extend_from_slice(&d.0);
                    b.extend_from_slice(&l.to_le_bytes());
                }
            }
        }
        let sha = index_digest(&b);
        b.extend_from_slice(&sha);
        b
    }

    /// Strict decoder: one encoding per index; every failure is `CheckpointCorrupt`.
    pub fn decode(bytes: &[u8]) -> SynapseResult<Self> {
        if bytes.len() < INDEX_HEADER_LEN + 32 {
            return Err(index_corrupt("shorter than its header"));
        }
        let (body, trailer) = bytes.split_at(bytes.len() - 32);
        if index_digest(body) != trailer {
            return Err(index_corrupt("digest mismatch"));
        }
        if body[0..4] != SEGMENT_INDEX_MAGIC {
            return Err(index_corrupt("bad magic"));
        }
        let version = u16::from_le_bytes([body[4], body[5]]);
        let v2 = match version {
            SEGMENT_INDEX_VERSION => false,
            SEGMENT_INDEX_VERSION_CHUNKS => true,
            _ => return Err(index_corrupt("unsupported version or reserved bytes")),
        };
        if body[6..8] != [0, 0] {
            return Err(index_corrupt("unsupported version or reserved bytes"));
        }
        let u64_at = |at: usize| u64::from_le_bytes(body[at..at + 8].try_into().expect("8"));
        let binding: [u8; 32] = body[8..40].try_into().expect("32");
        let replay_segment = u64_at(40);
        let replay_offset = u64_at(48);
        let count = u64_at(56);
        if replay_segment == 0 || replay_offset % wal2::WAL_V2_ALIGN != 0 {
            return Err(index_corrupt("invalid replay position"));
        }
        let mut at = INDEX_HEADER_LEN;
        let take = |at: &mut usize, n: u128| -> SynapseResult<&[u8]> {
            if n > (body.len() - *at) as u128 {
                return Err(index_corrupt("entry count does not match the length"));
            }
            let s = &body[*at..*at + n as usize];
            *at += n as usize;
            Ok(s)
        };
        let check_loc = |e: &[u8]| -> SynapseResult<BlobLoc> {
            let loc = BlobLoc {
                segment: u64::from_le_bytes(e[32..40].try_into().expect("8")),
                offset: u64::from_le_bytes(e[40..48].try_into().expect("8")),
                len: u32::from_le_bytes(e[48..52].try_into().expect("4")),
            };
            let end = loc.offset.checked_add(u64::from(loc.len));
            let before_replay =
                (loc.segment, end.unwrap_or(u64::MAX)) <= (replay_segment, replay_offset);
            if loc.segment == 0 || end.is_none() || !before_replay {
                return Err(index_corrupt("entry outside the covered segment bytes"));
            }
            Ok(loc)
        };
        let region = take(&mut at, count as u128 * INDEX_ENTRY_LEN as u128)?;
        let mut entries = BTreeMap::new();
        let mut prev: Option<BlobDigest> = None;
        for e in region.as_chunks::<INDEX_ENTRY_LEN>().0 {
            let d = BlobDigest(e[0..32].try_into().expect("32"));
            if prev.is_some_and(|p| p >= d) {
                return Err(index_corrupt("entries not in strictly increasing order"));
            }
            prev = Some(d);
            entries.insert(d, check_loc(e)?);
        }
        let mut chunks = BTreeMap::new();
        let mut manifests = BTreeMap::new();
        if v2 {
            let n = u64::from_le_bytes(take(&mut at, 8)?.try_into().expect("8"));
            let region = take(&mut at, n as u128 * INDEX_ENTRY_LEN as u128)?;
            let mut prev: Option<ChunkDigest> = None;
            for e in region.as_chunks::<INDEX_ENTRY_LEN>().0 {
                let d = ChunkDigest(e[0..32].try_into().expect("32"));
                if prev.is_some_and(|p| p >= d) {
                    return Err(index_corrupt("chunks not in strictly increasing order"));
                }
                prev = Some(d);
                chunks.insert(d, check_loc(e)?);
            }
            let n = u64::from_le_bytes(take(&mut at, 8)?.try_into().expect("8"));
            let mut prev: Option<BlobDigest> = None;
            let mut referenced = BTreeSet::new();
            for _ in 0..n {
                let h = take(&mut at, 44)?;
                let blob = BlobDigest(h[0..32].try_into().expect("32"));
                let len = u64::from_le_bytes(h[32..40].try_into().expect("8"));
                let k = u32::from_le_bytes(h[40..44].try_into().expect("4"));
                if prev.is_some_and(|p| p >= blob) {
                    return Err(index_corrupt("manifests not in strictly increasing order"));
                }
                prev = Some(blob);
                let region = take(&mut at, k as u128 * 36)?;
                let mut list = Vec::with_capacity(k as usize);
                let mut sum = 0u64;
                for e in region.as_chunks::<36>().0 {
                    let d = ChunkDigest(e[0..32].try_into().expect("32"));
                    let l = u32::from_le_bytes(e[32..36].try_into().expect("4"));
                    if chunks.get(&d).is_none_or(|loc: &BlobLoc| loc.len != l) || l == 0 {
                        return Err(index_corrupt("manifest names a chunk the index lacks"));
                    }
                    referenced.insert(d);
                    sum += u64::from(l);
                    list.push((d, l));
                }
                if k == 0 || sum != len {
                    return Err(index_corrupt("manifest length does not match its chunks"));
                }
                manifests.insert(
                    blob,
                    ChunkManifest {
                        blob,
                        len,
                        chunks: list,
                    },
                );
            }
            if referenced.len() != chunks.len() {
                return Err(index_corrupt("chunk named by no manifest"));
            }
            if chunks.is_empty() {
                return Err(index_corrupt("version 2 index without chunks"));
            }
        }
        if at != body.len() {
            return Err(index_corrupt("entry count does not match the length"));
        }
        Ok(Self {
            binding,
            replay_segment,
            replay_offset,
            entries,
            chunks,
            manifests,
        })
    }

    /// Write atomically (temp file, sync, rename, directory sync); returns the file name.
    pub fn write(&self, root: &Path) -> SynapseResult<String> {
        let name = Self::file_name(&self.binding);
        write_file_atomic(
            root,
            &root.join(format!("{name}.tmp")),
            &root.join(&name),
            &self.encode(),
        )?;
        Ok(name)
    }

    /// Load the index bound to `binding` (`CheckpointCorrupt` when missing or invalid).
    pub fn load(root: &Path, binding: &[u8; 32]) -> SynapseResult<Self> {
        let name = Self::file_name(binding);
        let bytes = fs::read(root.join(&name)).map_err(|e| {
            index_corrupt(&format!(
                "{name} for the checkpoint on disk cannot be read: {e}"
            ))
        })?;
        let index = Self::decode(&bytes)?;
        if &index.binding != binding {
            return Err(index_corrupt(&format!(
                "{name} is bound to a different checkpoint"
            )));
        }
        Ok(index)
    }
}

/// Remove every segment index file (and leftover temp file) except `keep`. Index files
/// are metadata: this never touches segment data.
pub(crate) fn remove_other_indexes(root: &Path, keep: &str) -> SynapseResult<()> {
    let mut removed = false;
    for entry in fs::read_dir(root).map_err(io_err)? {
        let entry = entry.map_err(io_err)?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        if name.starts_with(SEGMENT_INDEX_PREFIX) && name != keep {
            fs::remove_file(entry.path()).map_err(io_err)?;
            removed = true;
        }
    }
    if removed {
        sync_dir(root)?;
    }
    Ok(())
}

/// Faults injected into the next segment rotation (test hooks).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RotationFault {
    None,
    /// Create and pre-write the new segment, then exit the process with `code` before
    /// the directory flush.
    CrashBeforeDirSync {
        code: i32,
    },
    /// The directory flush after creating the new segment fails.
    FailDirSync,
}

/// Durability events of the segment writer, in order (test camera).
#[cfg(test)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SegEvent {
    /// A new segment file was created.
    Created(u64),
    /// The segment file's data and size were synced (`sync_all`).
    FileSynced(u64),
    /// The store directory was flushed after this segment was created or opened.
    DirSynced(u64),
    /// A batch write into this segment started.
    BatchWrite(u64),
    /// A batch in this segment was written and `fdatasync` returned success.
    BatchDurable(u64),
}

/// Writer of the active segment, rotating to new segment files.
#[derive(Debug)]
pub(crate) struct SegmentLog {
    root: PathBuf,
    active: u64,
    writer: wal2::WalV2Writer,
    segment_bytes: u64,
    chunk: u64,
    #[cfg(test)]
    pub trace: Vec<SegEvent>,
}

impl SegmentLog {
    /// Open the active segment `active` with the log ending at `write_offset`. The file
    /// is synced and the directory flushed before anything is written into it.
    pub fn open(
        root: &Path,
        active: u64,
        write_offset: u64,
        segment_bytes: u64,
        chunk: u64,
    ) -> SynapseResult<Self> {
        let segment_bytes = segment_bytes.max(wal2::WAL_V2_ALIGN);
        let chunk = chunk.min(segment_bytes);
        let path = root.join(segment_file_name(active));
        let mut writer = wal2::WalV2Writer::open(&path, write_offset, chunk)?;
        writer.set_prewrite_cap(segment_bytes);
        // The file may come from a process that died before flushing the directory
        // entry: make both durable before the first batch lands in it.
        writer.sync_all()?;
        sync_dir(root)?;
        Ok(Self {
            root: root.to_path_buf(),
            active,
            writer,
            segment_bytes,
            chunk,
            #[cfg(test)]
            trace: vec![SegEvent::FileSynced(active), SegEvent::DirSynced(active)],
        })
    }

    pub fn active(&self) -> u64 {
        self.active
    }

    pub fn write_offset(&self) -> u64 {
        self.writer.write_offset
    }

    /// Make room for a batch of `len` bytes and return `(segment, offset)` where it
    /// goes. Rotates when the active segment holds data and the batch would end past
    /// the segment size: the new file is created, zero-filled, synced, and the
    /// directory flushed before this returns. On failure nothing was written into any
    /// log extent and the active segment is unchanged.
    pub fn reserve(
        &mut self,
        len: u64,
        fault: RotationFault,
    ) -> Result<(u64, u64), wal2::BatchFailure> {
        let at = self.writer.write_offset;
        if at == 0 || at.saturating_add(len) <= self.segment_bytes {
            return Ok((self.active, at));
        }
        let id = self.active + 1;
        let fail = |e: std::io::Error| {
            wal2::BatchFailure::RolledBack(SynapseError::new(
                RefusalCode::IoFailure,
                format!("create segment {id}: {e}"),
            ))
        };
        // A file with this id can only be one an earlier failed rotation of this
        // process created (or an all-zero one recovery verified): never acknowledged
        // data, so it is truncated and pre-written again.
        let file = OpenOptions::new()
            .create(true)
            .truncate(true)
            .read(true)
            .write(true)
            .open(self.root.join(segment_file_name(id)))
            .map_err(fail)?;
        #[cfg(test)]
        self.trace.push(SegEvent::Created(id));
        let mut writer = wal2::WalV2Writer::new_empty(file, self.chunk, self.segment_bytes);
        writer.ensure_space(len).map_err(fail)?;
        #[cfg(test)]
        self.trace.push(SegEvent::FileSynced(id));
        match fault {
            RotationFault::None => {}
            RotationFault::CrashBeforeDirSync { code } => std::process::exit(code),
            RotationFault::FailDirSync => {
                return Err(fail(std::io::Error::other(
                    "injected fault: directory flush failed",
                )))
            }
        }
        File::open(&self.root)
            .and_then(|d| d.sync_all())
            .map_err(fail)?;
        #[cfg(test)]
        self.trace.push(SegEvent::DirSynced(id));
        self.writer = writer;
        self.active = id;
        Ok((id, 0))
    }

    /// Write one batch at the reserved position: one write, one `fdatasync`.
    pub fn write_batch(
        &mut self,
        buf: &[u8],
        fault: wal2::BatchIoFault,
    ) -> Result<(), wal2::BatchFailure> {
        #[cfg(test)]
        self.trace.push(SegEvent::BatchWrite(self.active));
        self.writer.write_batch(buf, fault)?;
        #[cfg(test)]
        self.trace.push(SegEvent::BatchDurable(self.active));
        Ok(())
    }

    pub fn sync(&self) -> SynapseResult<()> {
        self.writer.sync()
    }
}

/// Read `len` bytes at `offset` of an open segment file.
pub(crate) fn read_at(f: &File, offset: u64, len: u32) -> std::io::Result<Vec<u8>> {
    let mut bytes = vec![0u8; len as usize];
    f.read_exact_at(&mut bytes, offset)?;
    Ok(bytes)
}

/// Fill `buf` from `offset` of `f`.
pub(crate) fn read_into(f: &File, offset: u64, buf: &mut [u8]) -> std::io::Result<()> {
    f.read_exact_at(buf, offset)
}
