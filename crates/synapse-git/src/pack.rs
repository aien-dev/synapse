//! Native Git packfile (version 2) and pack index (version 2) codec for the bridge (ADR 0003
//! step H1, section 5.10: "Export ... written as packfiles, not loose objects"). Formats follow
//! `gitformat-pack` (Git 2.43 manual on this host): `PACK`, version, object count, entries of
//! "n-byte type and length (3-bit type, (n-1)*7+4-bit length)" then zlib data, deltified
//! entries (`OBJ_OFS_DELTA` 6 with the "offset encoding", `OBJ_REF_DELTA` 7 with the base
//! object name), and a trailing SHA-1 of everything before it. The index is `\377tOc`,
//! version 2, a 256-entry fan-out, sorted object names, CRC-32 of each packed entry, 31-bit
//! offsets with an 8-byte table for offsets of 2 GiB and more, the pack checksum, and its own
//! SHA-1.
//!
//! The writer emits whole (undeltified) objects in object ID order, so the same object set
//! always gives the same pack and index bytes. Deltas are read, never written: ADR 0003 keeps
//! deltas "only on the bridge wire" (thin packs, step H2). The reader resolves both delta
//! kinds and checks every size, offset and checksum before it trusts them; malformed input is
//! refused with `RefusalCode::GitObjectCorrupt`.

use crate::inflate::zlib_decompress;
use crate::object::{GitObject, ObjectKind};
use crate::zlib_compress_store;
use sha1::{Digest, Sha1};
use std::collections::{BTreeMap, HashMap};
use synapse_core::{GitOid, RefusalCode, SynapseError, SynapseResult};

fn corrupt(msg: impl Into<String>) -> SynapseError {
    SynapseError::new(RefusalCode::GitObjectCorrupt, msg)
}

const PACK_SIGNATURE: &[u8; 4] = b"PACK";
const PACK_VERSION: u32 = 2;
const IDX_MAGIC: [u8; 4] = [0xff, b't', b'O', b'c'];
const IDX_VERSION: u32 = 2;
const OBJ_OFS_DELTA: u8 = 6;
const OBJ_REF_DELTA: u8 = 7;
/// Most bytes one resolved object may hold while reading a pack (a declared size above it is
/// refused before anything is allocated).
pub const MAX_PACK_OBJECT_BYTES: u64 = 1 << 30;
/// Longest delta chain the reader follows (Git's own `pack.depth` maximum is 4095).
pub const MAX_DELTA_CHAIN: usize = 4096;

/// CRC-32 (IEEE 802.3, reflected polynomial 0xEDB88320), the checksum `gitformat-pack` puts in
/// the version 2 index for each packed entry (the same CRC zlib's `crc32` computes).
pub fn crc32(data: &[u8]) -> u32 {
    static TABLE: std::sync::OnceLock<[u32; 256]> = std::sync::OnceLock::new();
    let table = TABLE.get_or_init(|| {
        let mut t = [0u32; 256];
        for (i, slot) in t.iter_mut().enumerate() {
            let mut c = i as u32;
            for _ in 0..8 {
                c = if c & 1 != 0 {
                    0xedb8_8320 ^ (c >> 1)
                } else {
                    c >> 1
                };
            }
            *slot = c;
        }
        t
    });
    let mut crc = !0u32;
    for &b in data {
        crc = table[((crc ^ u32::from(b)) & 0xff) as usize] ^ (crc >> 8);
    }
    !crc
}

/// One object's place in a pack: its ID, the offset of its entry header, and the CRC-32 of the
/// whole packed entry (header, delta base reference, and compressed data).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PackIndexEntry {
    pub oid: GitOid,
    pub offset: u64,
    pub crc32: u32,
}

/// A written pack and its index.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WrittenPack {
    pub pack: Vec<u8>,
    pub idx: Vec<u8>,
    /// The pack's trailing SHA-1, which also names the files (`pack-<hex>.pack`).
    pub checksum: GitOid,
    pub entries: Vec<PackIndexEntry>,
}

fn encode_entry_header(pack_type: u8, size: u64, out: &mut Vec<u8>) {
    let mut byte = (pack_type << 4) | (size & 0x0f) as u8;
    let mut rest = size >> 4;
    while rest != 0 {
        out.push(byte | 0x80);
        byte = (rest & 0x7f) as u8;
        rest >>= 7;
    }
    out.push(byte);
}

/// Write `objects` (duplicates collapse) as one version 2 pack of whole objects in object ID
/// order, and its version 2 index. The output is a function of the object set alone.
pub fn write_pack(objects: &[GitObject]) -> WrittenPack {
    let mut by_oid: BTreeMap<GitOid, &GitObject> = BTreeMap::new();
    for object in objects {
        by_oid.entry(object.oid()).or_insert(object);
    }
    let mut pack = Vec::new();
    pack.extend_from_slice(PACK_SIGNATURE);
    pack.extend_from_slice(&PACK_VERSION.to_be_bytes());
    pack.extend_from_slice(&(by_oid.len() as u32).to_be_bytes());
    let mut entries = Vec::with_capacity(by_oid.len());
    for (oid, object) in &by_oid {
        let offset = pack.len();
        encode_entry_header(
            object.kind.pack_type(),
            object.payload.len() as u64,
            &mut pack,
        );
        pack.extend_from_slice(&zlib_compress_store(&object.payload));
        entries.push(PackIndexEntry {
            oid: *oid,
            offset: offset as u64,
            crc32: crc32(&pack[offset..]),
        });
    }
    let checksum: [u8; 20] = Sha1::digest(&pack).into();
    pack.extend_from_slice(&checksum);
    let checksum = GitOid(checksum);
    let idx = write_idx(&entries, checksum);
    WrittenPack {
        pack,
        idx,
        checksum,
        entries,
    }
}

/// Encode a version 2 pack index for `entries` (sorted by object ID here) of the pack whose
/// trailing checksum is `pack_checksum`.
pub fn write_idx(entries: &[PackIndexEntry], pack_checksum: GitOid) -> Vec<u8> {
    let mut sorted = entries.to_vec();
    sorted.sort_by_key(|e| e.oid);
    let mut idx = Vec::with_capacity(8 + 1024 + sorted.len() * 28 + 40);
    idx.extend_from_slice(&IDX_MAGIC);
    idx.extend_from_slice(&IDX_VERSION.to_be_bytes());
    let mut fanout = [0u32; 256];
    for e in &sorted {
        fanout[usize::from(e.oid.0[0])] += 1;
    }
    let mut running = 0u32;
    for count in fanout {
        running += count;
        idx.extend_from_slice(&running.to_be_bytes());
    }
    for e in &sorted {
        idx.extend_from_slice(&e.oid.0);
    }
    for e in &sorted {
        idx.extend_from_slice(&e.crc32.to_be_bytes());
    }
    let mut large = Vec::new();
    for e in &sorted {
        if e.offset < 0x8000_0000 {
            idx.extend_from_slice(&(e.offset as u32).to_be_bytes());
        } else {
            idx.extend_from_slice(&(0x8000_0000u32 | large.len() as u32).to_be_bytes());
            large.push(e.offset);
        }
    }
    for offset in large {
        idx.extend_from_slice(&offset.to_be_bytes());
    }
    idx.extend_from_slice(&pack_checksum.0);
    let own: [u8; 20] = Sha1::digest(&idx).into();
    idx.extend_from_slice(&own);
    idx
}

/// Decode and check a version 2 pack index: magic, version, monotone fan-out that matches the
/// names, strictly ascending names, offsets (large ones through the 8-byte table), and the
/// index's own SHA-1. Returns the entries in name order and the pack checksum it records.
pub fn decode_idx(idx: &[u8]) -> SynapseResult<(Vec<PackIndexEntry>, GitOid)> {
    if idx.len() < 8 + 1024 + 40 || idx[..4] != IDX_MAGIC {
        return Err(corrupt(
            "pack index is not version 2 (bad magic or too short)",
        ));
    }
    if u32::from_be_bytes([idx[4], idx[5], idx[6], idx[7]]) != IDX_VERSION {
        return Err(corrupt("pack index version is not 2"));
    }
    let body = &idx[..idx.len() - 20];
    let own: [u8; 20] = Sha1::digest(body).into();
    if own[..] != idx[idx.len() - 20..] {
        return Err(corrupt("pack index checksum mismatch"));
    }
    let be32 = |at: usize| u32::from_be_bytes([idx[at], idx[at + 1], idx[at + 2], idx[at + 3]]);
    let mut prev = 0u32;
    for i in 0..256 {
        let v = be32(8 + i * 4);
        if v < prev {
            return Err(corrupt("pack index fan-out is not monotone"));
        }
        prev = v;
    }
    let n = prev as usize;
    let names_at = 8 + 1024;
    let crcs_at = names_at + n * 20;
    let offs_at = crcs_at + n * 4;
    let large_at = offs_at + n * 4;
    if large_at + 40 > idx.len() {
        return Err(corrupt("pack index is shorter than its object count"));
    }
    let large_len = idx.len() - 40 - large_at;
    if !large_len.is_multiple_of(8) {
        return Err(corrupt(
            "pack index large offset table is not whole entries",
        ));
    }
    let mut entries = Vec::with_capacity(n);
    let mut large_used = 0usize;
    for i in 0..n {
        let mut oid = [0u8; 20];
        oid.copy_from_slice(&idx[names_at + i * 20..names_at + i * 20 + 20]);
        let oid = GitOid(oid);
        if let Some(last) = entries.last().map(|e: &PackIndexEntry| e.oid) {
            if oid <= last {
                return Err(corrupt("pack index names are not strictly ascending"));
            }
        }
        let first = usize::from(oid.0[0]);
        let below = if first == 0 {
            0
        } else {
            be32(8 + (first - 1) * 4)
        };
        if (i as u32) < below || (i as u32) >= be32(8 + first * 4) {
            return Err(corrupt("pack index fan-out does not match its names"));
        }
        let raw = be32(offs_at + i * 4);
        let offset = if raw & 0x8000_0000 == 0 {
            u64::from(raw)
        } else {
            let slot = (raw & 0x7fff_ffff) as usize;
            if slot * 8 + 8 > large_len {
                return Err(corrupt("pack index large offset slot out of range"));
            }
            large_used = large_used.max(slot + 1);
            let at = large_at + slot * 8;
            let mut b = [0u8; 8];
            b.copy_from_slice(&idx[at..at + 8]);
            u64::from_be_bytes(b)
        };
        entries.push(PackIndexEntry {
            oid,
            offset,
            crc32: be32(crcs_at + i * 4),
        });
    }
    if large_used * 8 != large_len {
        return Err(corrupt("pack index large offset table has unused entries"));
    }
    let mut checksum = [0u8; 20];
    checksum.copy_from_slice(&idx[idx.len() - 40..idx.len() - 20]);
    Ok((entries, GitOid(checksum)))
}

/// One raw pack entry before delta resolution.
enum RawEntry {
    Whole(ObjectKind, Vec<u8>),
    OfsDelta(u64, Vec<u8>),
    RefDelta(GitOid, Vec<u8>),
}

/// A version 2 (or 3) pack held in memory with its object ID to offset map. Objects are
/// resolved on demand (delta chains followed iteratively) and checked against the requested
/// object ID.
pub struct PackReader {
    data: Vec<u8>,
    by_oid: HashMap<GitOid, u64>,
    entries: Vec<PackIndexEntry>,
    cache: HashMap<u64, (ObjectKind, std::sync::Arc<Vec<u8>>)>,
    cache_bytes: usize,
}

const CACHE_BOUND_BYTES: usize = 256 << 20;

fn check_pack_framing(data: &[u8]) -> SynapseResult<u32> {
    if data.len() < 12 + 20 || &data[..4] != PACK_SIGNATURE {
        return Err(corrupt("not a Git pack (bad signature or too short)"));
    }
    let version = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
    if version != 2 && version != 3 {
        return Err(corrupt(format!("pack version {version} is not 2 or 3")));
    }
    let body = &data[..data.len() - 20];
    let sum: [u8; 20] = Sha1::digest(body).into();
    if sum[..] != data[data.len() - 20..] {
        return Err(corrupt("pack checksum mismatch"));
    }
    Ok(u32::from_be_bytes([data[8], data[9], data[10], data[11]]))
}

impl PackReader {
    /// Open a pack with its version 2 index (as Git writes them side by side). The index must
    /// record this pack's checksum and name exactly the pack's object count; every offset must
    /// fall inside the pack body.
    pub fn with_index(data: Vec<u8>, idx: &[u8]) -> SynapseResult<Self> {
        let count = check_pack_framing(&data)?;
        let (entries, pack_sum) = decode_idx(idx)?;
        if pack_sum.0[..] != data[data.len() - 20..] {
            return Err(corrupt("pack index names a different pack checksum"));
        }
        if entries.len() != count as usize {
            return Err(corrupt(
                "pack index object count differs from the pack header",
            ));
        }
        let body_end = (data.len() - 20) as u64;
        let mut by_oid = HashMap::with_capacity(entries.len());
        for e in &entries {
            if e.offset < 12 || e.offset >= body_end {
                return Err(corrupt("pack index offset outside the pack body"));
            }
            by_oid.insert(e.oid, e.offset);
        }
        Ok(Self {
            data,
            by_oid,
            entries,
            cache: HashMap::new(),
            cache_bytes: 0,
        })
    }

    /// Index a pack with no index file (`git index-pack` done natively): walk every entry in
    /// order, resolve it, and compute its object ID and CRC-32. The entries must end exactly at
    /// the trailing checksum. Every `OBJ_REF_DELTA` base must be in the pack (a self-contained
    /// pack, as `gitformat-pack` requires on disk).
    pub fn index(data: Vec<u8>) -> SynapseResult<Self> {
        let count = check_pack_framing(&data)?;
        let body_end = data.len() - 20;
        let mut offsets = Vec::with_capacity(count as usize);
        let mut pos = 12usize;
        for _ in 0..count {
            if pos >= body_end {
                return Err(corrupt("pack holds fewer entries than its header declares"));
            }
            let (_, next) = read_raw_entry(&data[..body_end], pos as u64)?;
            offsets.push((pos as u64, crc32(&data[pos..next])));
            pos = next;
        }
        if pos != body_end {
            return Err(corrupt(
                "pack has bytes between its last entry and its checksum",
            ));
        }
        let mut reader = Self {
            data,
            by_oid: HashMap::with_capacity(offsets.len()),
            entries: Vec::with_capacity(offsets.len()),
            cache: HashMap::new(),
            cache_bytes: 0,
        };
        // Whole objects and offset deltas resolve by position alone; reference deltas need
        // their base's ID first, so repeat until every entry is resolved or nothing moves.
        let mut pending: Vec<(u64, u32)> = offsets;
        while !pending.is_empty() {
            let mut next_round = Vec::new();
            for (offset, crc) in pending.iter().copied() {
                match reader.resolve_at(offset) {
                    Ok((kind, payload)) => {
                        let oid = GitOid::compute_git_object(kind.name(), &payload);
                        if reader.by_oid.insert(oid, offset).is_some() {
                            return Err(corrupt(format!("pack holds object {oid} twice")));
                        }
                        reader.entries.push(PackIndexEntry {
                            oid,
                            offset,
                            crc32: crc,
                        });
                    }
                    Err(e) if e.message.starts_with(MISSING_REF_BASE) => {
                        next_round.push((offset, crc))
                    }
                    Err(e) => return Err(e),
                }
            }
            if next_round.len() == pending.len() {
                return Err(corrupt(
                    "pack has reference deltas whose base is not in the pack (thin pack)",
                ));
            }
            pending = next_round;
        }
        reader.entries.sort_by_key(|e| e.oid);
        Ok(reader)
    }

    /// Entries in object ID order.
    pub fn entries(&self) -> &[PackIndexEntry] {
        &self.entries
    }

    pub fn contains(&self, oid: GitOid) -> bool {
        self.by_oid.contains_key(&oid)
    }

    /// Read and resolve object `oid`, checking that its content hashes to `oid`.
    pub fn read(&mut self, oid: GitOid) -> SynapseResult<Option<GitObject>> {
        let Some(&offset) = self.by_oid.get(&oid) else {
            return Ok(None);
        };
        let (kind, payload) = self.resolve_at(offset)?;
        let object = GitObject::new(kind, payload.as_ref().clone());
        if object.oid() != oid {
            return Err(corrupt(format!(
                "pack object at offset {offset} hashes to {} not {oid}",
                object.oid()
            )));
        }
        Ok(Some(object))
    }

    fn remember(&mut self, offset: u64, kind: ObjectKind, payload: std::sync::Arc<Vec<u8>>) {
        if self.cache_bytes + payload.len() > CACHE_BOUND_BYTES {
            self.cache.clear();
            self.cache_bytes = 0;
        }
        self.cache_bytes += payload.len();
        self.cache.insert(offset, (kind, payload));
    }

    fn resolve_at(&mut self, offset: u64) -> SynapseResult<(ObjectKind, std::sync::Arc<Vec<u8>>)> {
        let body_end = self.data.len() - 20;
        let mut chain: Vec<(u64, Vec<u8>)> = Vec::new();
        let mut at = offset;
        let (kind, mut payload) = loop {
            if let Some((kind, payload)) = self.cache.get(&at) {
                break (*kind, payload.clone());
            }
            if chain.len() > MAX_DELTA_CHAIN {
                return Err(corrupt(
                    "pack delta chain is longer than the reader follows",
                ));
            }
            let (raw, _) = read_raw_entry(&self.data[..body_end], at)?;
            match raw {
                RawEntry::Whole(kind, payload) => break (kind, std::sync::Arc::new(payload)),
                RawEntry::OfsDelta(base, delta) => {
                    chain.push((at, delta));
                    at = base;
                }
                RawEntry::RefDelta(base_oid, delta) => {
                    let base = *self
                        .by_oid
                        .get(&base_oid)
                        .ok_or_else(|| corrupt(format!("{MISSING_REF_BASE} {base_oid}")))?;
                    chain.push((at, delta));
                    at = base;
                }
            }
            if chain.iter().any(|(o, _)| *o == at) {
                return Err(corrupt("pack delta chain loops"));
            }
        };
        while let Some((at, delta)) = chain.pop() {
            payload = std::sync::Arc::new(apply_delta(&payload, &delta)?);
            self.remember(at, kind, payload.clone());
        }
        Ok((kind, payload))
    }
}

const MISSING_REF_BASE: &str = "pack reference delta base not found:";

fn read_size_encoding(data: &[u8], pos: &mut usize) -> SynapseResult<u64> {
    let mut value = 0u64;
    let mut shift = 0u32;
    loop {
        let byte = *data
            .get(*pos)
            .ok_or_else(|| corrupt("size encoding truncated"))?;
        *pos += 1;
        if shift > 63 || (shift == 63 && byte & 0x7e != 0) {
            return Err(corrupt("size encoding overflows u64"));
        }
        value |= u64::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            return Ok(value);
        }
        shift += 7;
    }
}

/// Read the entry at `offset`: header, delta base, and decompressed data. Returns the entry
/// and the offset just past it.
fn read_raw_entry(body: &[u8], offset: u64) -> SynapseResult<(RawEntry, usize)> {
    let mut pos = usize::try_from(offset).map_err(|_| corrupt("pack offset overflows"))?;
    let first = *body
        .get(pos)
        .ok_or_else(|| corrupt("pack entry offset past the pack body"))?;
    pos += 1;
    let pack_type = (first >> 4) & 0x07;
    let mut size = u64::from(first & 0x0f);
    if first & 0x80 != 0 {
        let rest = read_size_encoding(body, &mut pos)?;
        if rest > (u64::MAX >> 4) {
            return Err(corrupt("pack entry size overflows u64"));
        }
        size |= rest << 4;
    }
    if size > MAX_PACK_OBJECT_BYTES {
        return Err(corrupt(format!(
            "pack entry declares {size} bytes, over the {MAX_PACK_OBJECT_BYTES} byte cap"
        )));
    }
    let entry_start = offset;
    let base = match pack_type {
        1..=4 => None,
        OBJ_OFS_DELTA => {
            let mut byte = *body
                .get(pos)
                .ok_or_else(|| corrupt("offset delta truncated"))?;
            pos += 1;
            let mut back = u64::from(byte & 0x7f);
            while byte & 0x80 != 0 {
                byte = *body
                    .get(pos)
                    .ok_or_else(|| corrupt("offset delta truncated"))?;
                pos += 1;
                back = back
                    .checked_add(1)
                    .and_then(|b| b.checked_mul(128))
                    .map(|b| b | u64::from(byte & 0x7f))
                    .ok_or_else(|| corrupt("offset delta overflows"))?;
            }
            if back == 0 || back > entry_start {
                return Err(corrupt("offset delta base is not before the entry"));
            }
            Some(Ok(entry_start - back))
        }
        OBJ_REF_DELTA => {
            let raw = body
                .get(pos..pos + 20)
                .ok_or_else(|| corrupt("reference delta truncated"))?;
            pos += 20;
            let mut oid = [0u8; 20];
            oid.copy_from_slice(raw);
            Some(Err(GitOid(oid)))
        }
        other => return Err(corrupt(format!("pack entry type {other} is invalid"))),
    };
    let (data, used) = zlib_decompress(&body[pos..], size as usize)?;
    if data.len() as u64 != size {
        return Err(corrupt(format!(
            "pack entry declares {size} bytes but inflates to {}",
            data.len()
        )));
    }
    let entry = match base {
        None => RawEntry::Whole(ObjectKind::from_pack_type(pack_type)?, data),
        Some(Ok(base)) => RawEntry::OfsDelta(base, data),
        Some(Err(oid)) => RawEntry::RefDelta(oid, data),
    };
    Ok((entry, pos + used))
}

/// Apply a Git delta (`gitformat-pack`, "Deltified representation") to `base`.
pub fn apply_delta(base: &[u8], delta: &[u8]) -> SynapseResult<Vec<u8>> {
    let mut pos = 0usize;
    let base_size = read_size_encoding(delta, &mut pos)?;
    if base_size != base.len() as u64 {
        return Err(corrupt(format!(
            "delta expects a {base_size} byte base, base has {}",
            base.len()
        )));
    }
    let result_size = read_size_encoding(delta, &mut pos)?;
    if result_size > MAX_PACK_OBJECT_BYTES {
        return Err(corrupt("delta result is over the object byte cap"));
    }
    let mut out = Vec::with_capacity(result_size as usize);
    while pos < delta.len() {
        let op = delta[pos];
        pos += 1;
        if op & 0x80 != 0 {
            let mut fields = [0u64; 7];
            for (bit, field) in fields.iter_mut().enumerate() {
                if op & (1 << bit) != 0 {
                    *field = u64::from(
                        *delta
                            .get(pos)
                            .ok_or_else(|| corrupt("delta copy instruction truncated"))?,
                    );
                    pos += 1;
                }
            }
            let offset = fields[0] | fields[1] << 8 | fields[2] << 16 | fields[3] << 24;
            let mut size = fields[4] | fields[5] << 8 | fields[6] << 16;
            if size == 0 {
                size = 0x10000;
            }
            let end = offset
                .checked_add(size)
                .filter(|&e| e <= base.len() as u64)
                .ok_or_else(|| corrupt("delta copy reaches past the base"))?;
            out.extend_from_slice(&base[offset as usize..end as usize]);
        } else if op != 0 {
            let n = usize::from(op);
            let data = delta
                .get(pos..pos + n)
                .ok_or_else(|| corrupt("delta insert instruction truncated"))?;
            out.extend_from_slice(data);
            pos += n;
        } else {
            return Err(corrupt("delta instruction 0 is reserved"));
        }
        if out.len() as u64 > result_size {
            return Err(corrupt("delta output exceeds its declared size"));
        }
    }
    if out.len() as u64 != result_size {
        return Err(corrupt(format!(
            "delta declares {result_size} bytes, produced {}",
            out.len()
        )));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crc32_matches_the_ieee_check_value() {
        assert_eq!(crc32(b"123456789"), 0xcbf4_3926);
        assert_eq!(crc32(b""), 0);
    }

    #[test]
    fn written_pack_indexes_back_to_the_same_entries_and_objects() {
        let objects = vec![
            GitObject::new(ObjectKind::Blob, b"hello\n".to_vec()),
            GitObject::new(ObjectKind::Blob, vec![7u8; 70_000]),
            GitObject::new(ObjectKind::Tree, Vec::new()),
            GitObject::new(ObjectKind::Blob, b"hello\n".to_vec()),
        ];
        let written = write_pack(&objects);
        assert_eq!(written.entries.len(), 3);
        assert_eq!(write_pack(&objects), written, "deterministic");
        let mut reader = PackReader::index(written.pack.clone()).unwrap();
        assert_eq!(reader.entries(), &written.entries[..]);
        let (decoded, sum) = decode_idx(&written.idx).unwrap();
        assert_eq!(decoded, written.entries);
        assert_eq!(sum, written.checksum);
        for o in &objects {
            assert_eq!(reader.read(o.oid()).unwrap().as_ref(), Some(o));
        }
        let mut with_idx = PackReader::with_index(written.pack.clone(), &written.idx).unwrap();
        assert_eq!(
            with_idx.read(objects[1].oid()).unwrap().as_ref(),
            Some(&objects[1])
        );
    }

    #[test]
    fn large_offsets_use_the_eight_byte_table() {
        let entries = vec![
            PackIndexEntry {
                oid: GitOid([1; 20]),
                offset: 12,
                crc32: 5,
            },
            PackIndexEntry {
                oid: GitOid([2; 20]),
                offset: 0x1_0000_0000,
                crc32: 6,
            },
        ];
        let idx = write_idx(&entries, GitOid([9; 20]));
        assert_eq!(decode_idx(&idx).unwrap(), (entries, GitOid([9; 20])));
    }

    #[test]
    fn delta_copy_and_insert_apply_and_bad_deltas_are_refused() {
        let base = b"0123456789abcdef";
        // base 16, result 7: copy offset 10 size 3 ("abc"), insert "XYZ!"? (4 bytes).
        let delta = [16u8, 7, 0x91, 10, 3, 4, b'X', b'Y', b'Z', b'!'];
        assert_eq!(apply_delta(base, &delta).unwrap(), b"abcXYZ!");
        assert!(
            apply_delta(base, &[15, 7, 0x91, 10, 3]).is_err(),
            "base size"
        );
        assert!(
            apply_delta(base, &[16, 3, 0x91, 15, 3]).is_err(),
            "copy past base"
        );
        assert!(apply_delta(base, &[16, 3, 0x00]).is_err(), "reserved op");
        assert!(
            apply_delta(base, &[16, 4, 0x91, 10, 3]).is_err(),
            "short result"
        );
    }

    #[test]
    fn every_truncation_and_bit_flip_of_a_pack_is_refused_without_panic() {
        let written = write_pack(&[
            GitObject::new(ObjectKind::Blob, b"a".to_vec()),
            GitObject::new(ObjectKind::Tree, Vec::new()),
        ]);
        let p = &written.pack;
        for cut in 0..p.len() {
            assert!(PackReader::index(p[..cut].to_vec()).is_err());
        }
        for bit in 0..p.len() * 8 {
            let mut d = p.clone();
            d[bit / 8] ^= 1 << (bit % 8);
            assert!(PackReader::index(d.clone()).is_err(), "flip {bit}");
            assert!(
                PackReader::with_index(d, &written.idx).is_err(),
                "flip {bit}"
            );
        }
        for bit in 0..written.idx.len() * 8 {
            let mut d = written.idx.clone();
            d[bit / 8] ^= 1 << (bit % 8);
            assert!(
                PackReader::with_index(p.clone(), &d).is_err(),
                "idx flip {bit}"
            );
        }
    }
}
