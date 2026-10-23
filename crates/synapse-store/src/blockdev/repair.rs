//! R1 store repair after a `CheckpointCorrupt` refusal (issue #105, follow-up to #103).
//!
//! When the newest superblock copy is damaged, mount refuses with `CheckpointCorrupt`
//! because the older copy would silently drop batches acknowledged after it. This module
//! gives the operator what the refusal lacks:
//!
//! * [`diagnose`] reads both superblock copies (read-only, no write of any kind) and says
//!   which copy is damaged, which checkpoint the older copy holds, the exact device byte
//!   range of the acknowledged data past it, and the WAL v2 batches found there (first
//!   sequence number and record count, from a scan of the batch headers). It also lists
//!   the signed repair history already on the device.
//! * [`repair`] writes only for the [`RepairAction`] the caller names:
//!   - [`RepairAction::RollForward`] commits the slot past the older checkpoint, so every
//!     acknowledged batch in it is kept byte for byte. The damaged commit can only have
//!     been the rotation that raised the segment count (a metadata commit never puts
//!     data in the next slot), so the repair rewrites exactly that commit.
//!   - [`RepairAction::AdoptOlderCheckpoint`] keeps the older checkpoint and zeroes the
//!     reported range, recording what was dropped.
//!
//!   Before its first device write it saves every byte range it will overwrite to a new
//!   backup file and syncs it ([`read_backup`] reads it back). The repair is one ordinary
//!   metadata commit into the damaged copy's position: a new namespace that appends a
//!   signed [`RepairEntry`] to the `repair.log` object, and the superblock that points at
//!   it. Adopt writes that record before it zeroes anything, so a crash in between leaves
//!   the record and a store that still refuses; running the same action again finishes
//!   the zeroing without a second record.
//! * The repair log is append-only and hash-chained (each entry names the SHA-256 of the
//!   one before it) and every entry carries the operator's Ed25519 signature. Mount
//!   verifies the whole log and refuses a store whose log does not verify;
//!   [`BlockDevice::repair_log`] returns it, so replay can show that a repair happened,
//!   who signed it and which range it covered.
//!
//! Limit: the signature attributes an entry to a key; it does not stop someone with write
//! access to the device from replacing the whole log with one signed by another key.
//! Which operator keys to trust is not decided here.

use super::*;
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};

/// Named object holding the signed repair log.
pub const REPAIR_LOG_NAME: &str = "repair.log";
/// Domain tag of the operator's signature over a repair entry.
pub const DOMAIN_R1_REPAIR_SIGN_V1: &[u8] = b"SYNAPSE_R1_REPAIR_SIGN_V1\0";
/// Domain tag of the digest that chains repair entries.
pub const DOMAIN_R1_REPAIR_ENTRY_V1: &[u8] = b"SYNAPSE_R1_REPAIR_ENTRY_V1\0";
const ENTRY_MAGIC: [u8; 4] = *b"SRP1";
const ENTRY_VERSION: u16 = 1;

/// State of one superblock copy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CopyState {
    /// All 4 KiB are zero.
    Blank,
    /// A valid superblock whose metadata region matches its digest.
    Intact {
        generation: u64,
        segment_count: u64,
        meta_slot: u8,
    },
    /// A valid superblock whose metadata region does not match its digest.
    MetaDamaged { generation: u64, segment_count: u64 },
    /// Not a valid superblock (the reason names the first failed check).
    Damaged(String),
}

/// One superblock copy: index 0 or 1, at byte `copy * 4096`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CopyReport {
    pub copy: u8,
    pub state: CopyState,
}

/// One WAL v2 batch whose header was found in a slot past the checkpoint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LostBatch {
    /// Device byte offset of the batch header.
    pub offset: u64,
    /// Sequence number of the batch's first record.
    pub first_seq: u64,
    /// Records in the batch.
    pub records: u32,
}

/// Acknowledged data in a slot past the checkpoint the older copy holds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LostRange {
    /// Segment slot id.
    pub slot: u64,
    /// Device byte offset of the first and one past the last non-zero byte.
    pub start: u64,
    pub end: u64,
    /// Number of non-zero bytes in the slot.
    pub nonzero_bytes: u64,
    /// Batches found by walking the batch headers from the start of the slot.
    pub batches: Vec<LostBatch>,
}

impl LostRange {
    /// Records in [`Self::batches`].
    pub fn records(&self) -> u64 {
        self.batches.iter().map(|b| u64::from(b.records)).sum()
    }
}

/// What the diagnosis concludes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    /// The store opens as it is; nothing to repair.
    Healthy,
    /// A superblock copy is unusable but the other one loses no acknowledged data.
    OneCopyDamagedNothingLost,
    /// Adopting the older checkpoint drops the listed ranges.
    OlderCheckpointLosesRange,
    /// No usable checkpoint (or contradictory geometry, or a repair log that does not
    /// verify): this tool cannot repair it.
    Unrepairable(String),
}

/// Result of [`diagnose`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RepairReport {
    pub device_uuid: Option<[u8; 16]>,
    pub copies: [CopyReport; 2],
    /// Copy and generation of the checkpoint in force (the newest intact copy).
    pub adopt: Option<(u8, u64)>,
    pub segment_count: u64,
    pub lost: Vec<LostRange>,
    /// Signed repair entries already on the device, oldest first.
    pub history: Vec<RepairEntry>,
    pub verdict: Verdict,
}

impl std::fmt::Display for RepairReport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "R1 store diagnosis")?;
        for c in &self.copies {
            let at = u64::from(c.copy) * BLOCK;
            match &c.state {
                CopyState::Blank => {
                    writeln!(f, "superblock copy {} (byte {at}): blank", c.copy)?
                }
                CopyState::Intact {
                    generation,
                    segment_count,
                    meta_slot,
                } => writeln!(
                    f,
                    "superblock copy {} (byte {at}): intact, generation {generation}, checkpoint: {segment_count} committed segments, metadata region {meta_slot}",
                    c.copy
                )?,
                CopyState::MetaDamaged {
                    generation,
                    segment_count,
                } => writeln!(
                    f,
                    "superblock copy {} (byte {at}): CORRUPT metadata region, generation {generation}, {segment_count} committed segments",
                    c.copy
                )?,
                CopyState::Damaged(why) => {
                    writeln!(f, "superblock copy {} (byte {at}): CORRUPT, {why}", c.copy)?
                }
            }
        }
        if self.history.is_empty() {
            writeln!(f, "repair history: none")?;
        }
        for (i, e) in self.history.iter().enumerate() {
            writeln!(f, "repair history entry {}: {e}", i + 1)?;
        }
        match &self.verdict {
            Verdict::Healthy => writeln!(f, "verdict: healthy, nothing to repair")?,
            Verdict::OneCopyDamagedNothingLost => writeln!(
                f,
                "verdict: one copy is unusable, but the checkpoint in force loses no acknowledged data; the next commit rewrites the bad copy"
            )?,
            Verdict::Unrepairable(why) => {
                writeln!(f, "verdict: cannot be repaired by this tool: {why}")?
            }
            Verdict::OlderCheckpointLosesRange => {
                let (copy, generation) = self.adopt.unwrap_or((0, 0));
                writeln!(
                    f,
                    "verdict: the store refuses to open (CheckpointCorrupt). The checkpoint in force (copy {copy}, generation {generation}, {} committed segments) is behind acknowledged data:",
                    self.segment_count
                )?;
                for r in &self.lost {
                    writeln!(
                        f,
                        "  segment slot {}: device bytes {}..{} ({} non-zero bytes), {} batches, {} records",
                        r.slot,
                        r.start,
                        r.end,
                        r.nonzero_bytes,
                        r.batches.len(),
                        r.records()
                    )?;
                    for b in &r.batches {
                        let last = b.first_seq + u64::from(b.records.max(1)) - 1;
                        writeln!(
                            f,
                            "    batch at device byte {}: records {}..={} ({} records)",
                            b.offset, b.first_seq, last, b.records
                        )?;
                    }
                }
                writeln!(
                    f,
                    "nothing was written. Re-run with --operator-key <file> --backup <new file> and one action:"
                )?;
                writeln!(
                    f,
                    "  --roll-forward            commit the slot past the checkpoint and keep every record above"
                )?;
                writeln!(
                    f,
                    "  --adopt-older-checkpoint  DROP the range above and record the loss in the signed repair log"
                )?;
            }
        }
        Ok(())
    }
}

// --- repair log ---------------------------------------------------------------------

/// The action a repair takes; the caller names it, there is no default.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RepairAction {
    /// Commit the slot past the older checkpoint: every acknowledged batch in it is kept.
    RollForward,
    /// Keep the older checkpoint and zero the acknowledged data past it (a named loss).
    AdoptOlderCheckpoint,
}

impl RepairAction {
    fn code(self) -> u8 {
        match self {
            Self::RollForward => 1,
            Self::AdoptOlderCheckpoint => 2,
        }
    }
    fn from_code(c: u8) -> Option<Self> {
        match c {
            1 => Some(Self::RollForward),
            2 => Some(Self::AdoptOlderCheckpoint),
            _ => None,
        }
    }
}

/// A range a repair covered: kept by a roll forward, dropped by an adopt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordedRange {
    pub slot: u64,
    /// Block-aligned device byte range `start..end`.
    pub start: u64,
    pub end: u64,
    pub nonzero_bytes: u64,
    pub batches: u32,
    pub records: u64,
    /// First record sequence number (0 when no batch header was found).
    pub first_seq: u64,
    /// SHA-256 of the device bytes `start..end` before the repair.
    pub bytes_sha256: [u8; 32],
}

/// One signed, hash-chained entry of the repair log.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RepairEntry {
    pub action: RepairAction,
    pub device_uuid: [u8; 16],
    /// Superblock generation the repair committed.
    pub generation: u64,
    pub segment_count_before: u64,
    pub segment_count_after: u64,
    /// Seconds since the Unix epoch, as given by the operator's tool.
    pub unix_secs: u64,
    /// Digest of the previous entry ([`Self::digest`]); zero for the first.
    pub prev_sha256: [u8; 32],
    /// SHA-256 of the 4 KiB superblock copy the repair overwrote, as it was before.
    pub replaced_copy_sha256: [u8; 32],
    pub ranges: Vec<RecordedRange>,
    pub operator_key: [u8; 32],
    pub signature: [u8; 64],
}

impl std::fmt::Display for RepairEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let what = match self.action {
            RepairAction::RollForward => "roll forward (kept)",
            RepairAction::AdoptOlderCheckpoint => "adopt older checkpoint (DROPPED)",
        };
        write!(
            f,
            "{what} at generation {}, segments {} -> {}, time {}, operator key {}",
            self.generation,
            self.segment_count_before,
            self.segment_count_after,
            self.unix_secs,
            hex::encode(self.operator_key)
        )?;
        for r in &self.ranges {
            write!(
                f,
                "; slot {} device bytes {}..{}, {} records from seq {}, sha256 {}",
                r.slot,
                r.start,
                r.end,
                r.records,
                r.first_seq,
                hex::encode(r.bytes_sha256)
            )?;
        }
        Ok(())
    }
}

impl RepairEntry {
    fn encode_unsigned(&self) -> Vec<u8> {
        let mut b = Vec::new();
        b.extend_from_slice(&ENTRY_MAGIC);
        b.extend_from_slice(&ENTRY_VERSION.to_le_bytes());
        b.push(self.action.code());
        b.push(0);
        b.extend_from_slice(&self.device_uuid);
        for v in [
            self.generation,
            self.segment_count_before,
            self.segment_count_after,
            self.unix_secs,
        ] {
            b.extend_from_slice(&v.to_le_bytes());
        }
        b.extend_from_slice(&self.prev_sha256);
        b.extend_from_slice(&self.replaced_copy_sha256);
        b.extend_from_slice(&(self.ranges.len() as u32).to_le_bytes());
        for r in &self.ranges {
            for v in [r.slot, r.start, r.end, r.nonzero_bytes] {
                b.extend_from_slice(&v.to_le_bytes());
            }
            b.extend_from_slice(&r.batches.to_le_bytes());
            b.extend_from_slice(&r.records.to_le_bytes());
            b.extend_from_slice(&r.first_seq.to_le_bytes());
            b.extend_from_slice(&r.bytes_sha256);
        }
        b.extend_from_slice(&self.operator_key);
        b
    }

    /// `DOMAIN_R1_REPAIR_SIGN_V1 || unsigned entry`: the bytes the operator signs.
    pub fn signable_bytes(&self) -> Vec<u8> {
        let mut m = DOMAIN_R1_REPAIR_SIGN_V1.to_vec();
        m.extend_from_slice(&self.encode_unsigned());
        m
    }

    fn encode(&self) -> Vec<u8> {
        let mut b = self.encode_unsigned();
        b.extend_from_slice(&self.signature);
        b
    }

    /// `SHA-256(DOMAIN_R1_REPAIR_ENTRY_V1 || entry with signature)`: the next entry's
    /// `prev_sha256`.
    pub fn digest(&self) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(DOMAIN_R1_REPAIR_ENTRY_V1);
        h.update(self.encode());
        h.finalize().into()
    }

    fn decode(b: &[u8]) -> Option<Self> {
        let mut at = 0usize;
        let mut take = |n: usize| -> Option<&[u8]> {
            let s = b.get(at..at.checked_add(n)?)?;
            at += n;
            Some(s)
        };
        if take(4)? != ENTRY_MAGIC || u16::from_le_bytes(take(2)?.try_into().ok()?) != ENTRY_VERSION
        {
            return None;
        }
        let action = RepairAction::from_code(take(1)?[0])?;
        if take(1)?[0] != 0 {
            return None;
        }
        let device_uuid = take(16)?.try_into().ok()?;
        let mut u64s = [0u64; 4];
        for v in &mut u64s {
            *v = u64::from_le_bytes(take(8)?.try_into().ok()?);
        }
        let prev_sha256 = take(32)?.try_into().ok()?;
        let replaced_copy_sha256 = take(32)?.try_into().ok()?;
        let n = u32::from_le_bytes(take(4)?.try_into().ok()?);
        let mut ranges = Vec::new();
        for _ in 0..n {
            let mut r = [0u64; 4];
            for v in &mut r {
                *v = u64::from_le_bytes(take(8)?.try_into().ok()?);
            }
            let batches = u32::from_le_bytes(take(4)?.try_into().ok()?);
            let records = u64::from_le_bytes(take(8)?.try_into().ok()?);
            let first_seq = u64::from_le_bytes(take(8)?.try_into().ok()?);
            ranges.push(RecordedRange {
                slot: r[0],
                start: r[1],
                end: r[2],
                nonzero_bytes: r[3],
                batches,
                records,
                first_seq,
                bytes_sha256: take(32)?.try_into().ok()?,
            });
        }
        let operator_key = take(32)?.try_into().ok()?;
        let signature = take(64)?.try_into().ok()?;
        (at == b.len()).then_some(Self {
            action,
            device_uuid,
            generation: u64s[0],
            segment_count_before: u64s[1],
            segment_count_after: u64s[2],
            unix_secs: u64s[3],
            prev_sha256,
            replaced_copy_sha256,
            ranges,
            operator_key,
            signature,
        })
    }

    fn verify_signature(&self) -> bool {
        VerifyingKey::from_bytes(&self.operator_key)
            .and_then(|vk| {
                vk.verify_strict(
                    &self.signable_bytes(),
                    &Signature::from_bytes(&self.signature),
                )
            })
            .is_ok()
    }
}

fn append_entry(log: &[u8], e: &RepairEntry) -> Vec<u8> {
    let enc = e.encode();
    let mut out = log.to_vec();
    out.extend_from_slice(&(enc.len() as u32).to_le_bytes());
    out.extend_from_slice(&enc);
    out
}

/// Parse and verify a repair log (`u32 len | entry` repeated): every entry decodes,
/// carries a valid operator signature, names this device and chains to the one before
/// it, and generations increase. Anything else is `CheckpointCorrupt`.
pub fn verify_repair_log(log: &[u8], device_uuid: &[u8; 16]) -> SynapseResult<Vec<RepairEntry>> {
    let mut at = 0usize;
    let mut prev = [0u8; 32];
    let mut last_generation = 0u64;
    let mut out = Vec::new();
    while at < log.len() {
        let n = log
            .get(at..at + 4)
            .map(|s| u32::from_le_bytes(s.try_into().expect("4")) as usize)
            .ok_or_else(|| corrupt("repair log: truncated entry length"))?;
        let k = out.len() + 1;
        let body = log
            .get(at + 4..at + 4 + n)
            .ok_or_else(|| corrupt(format!("repair log entry {k}: truncated")))?;
        let e = RepairEntry::decode(body)
            .ok_or_else(|| corrupt(format!("repair log entry {k}: does not decode")))?;
        if !e.verify_signature() {
            return Err(corrupt(format!(
                "repair log entry {k}: operator signature does not verify"
            )));
        }
        if &e.device_uuid != device_uuid {
            return Err(corrupt(format!(
                "repair log entry {k}: names another device"
            )));
        }
        if e.prev_sha256 != prev {
            return Err(corrupt(format!(
                "repair log entry {k}: breaks the hash chain (an entry was removed, reordered or changed)"
            )));
        }
        if e.generation <= last_generation {
            return Err(corrupt(format!(
                "repair log entry {k}: generation does not increase"
            )));
        }
        prev = e.digest();
        last_generation = e.generation;
        out.push(e);
        at += 4 + n;
    }
    Ok(out)
}

impl BlockDevice {
    /// The signed repair log in force (verified at mount), oldest first.
    pub fn repair_log(&self) -> SynapseResult<Vec<RepairEntry>> {
        match self.read_named(REPAIR_LOG_NAME) {
            Some(log) => verify_repair_log(&log, &self.geo.uuid),
            None => Ok(Vec::new()),
        }
    }
}

// --- diagnosis ----------------------------------------------------------------------

fn classify_copy(
    b: &[u8],
    i: u64,
    io: &dyn BlockIo,
) -> std::io::Result<(CopyState, Option<Superblock>)> {
    if b.iter().all(|x| *x == 0) {
        return Ok((CopyState::Blank, None));
    }
    let bad = |why: &str| Ok((CopyState::Damaged(why.to_string()), None));
    if b[0..8] != SUPERBLOCK_MAGIC {
        return bad("the Synapse magic is missing");
    }
    if u32::from_le_bytes(b[160..164].try_into().expect("4")) != crc32c(&b[..160]) {
        return bad("CRC-32C mismatch");
    }
    let Some(sb) = Superblock::decode(b) else {
        return bad("fields fail validation");
    };
    if sb.generation % 2 != i {
        return bad("generation does not belong in this copy");
    }
    if sb.geo.device_bytes > io.len() {
        return bad("describes more bytes than the device holds");
    }
    let mut meta = vec![0u8; sb.meta_len as usize];
    io.read_at(&mut meta, sb.geo.meta_offset[sb.meta_slot as usize])?;
    if meta_digest(&meta) != sb.meta_sha256 || decode_meta(&meta).is_none() {
        return Ok((
            CopyState::MetaDamaged {
                generation: sb.generation,
                segment_count: sb.segment_count,
            },
            Some(sb),
        ));
    }
    Ok((
        CopyState::Intact {
            generation: sb.generation,
            segment_count: sb.segment_count,
            meta_slot: sb.meta_slot,
        },
        Some(sb),
    ))
}

/// Non-zero extent of slot `id`'s data: (first, one past last, count), block-unaligned.
fn nonzero_extent(
    io: &dyn BlockIo,
    geo: &Geometry,
    id: u64,
) -> std::io::Result<Option<(u64, u64, u64)>> {
    let start = geo.slot_offset(id) + BLOCK;
    let mut buf = vec![0u8; (ZERO_CHUNK as u64).min(geo.segment_bytes) as usize];
    let (mut first, mut last, mut count) = (None, 0u64, 0u64);
    let mut at = 0;
    while at < geo.segment_bytes {
        let n = buf.len().min((geo.segment_bytes - at) as usize);
        io.read_at(&mut buf[..n], start + at)?;
        for (k, b) in buf[..n].iter().enumerate() {
            if *b != 0 {
                let pos = start + at + k as u64;
                first.get_or_insert(pos);
                last = pos + 1;
                count += 1;
            }
        }
        at += n as u64;
    }
    Ok(first.map(|f| (f, last, count)))
}

/// Walk the WAL v2 batch headers from the start of slot `id`'s data; stop at the first
/// offset that holds no valid header. Headers only: the full frame and hash-chain check
/// is the store's recovery, which runs when the repaired store is opened.
fn scan_batches(io: &dyn BlockIo, geo: &Geometry, id: u64) -> std::io::Result<Vec<LostBatch>> {
    use crate::wal2::{parse_batch_header, WAL_V2_BATCH_HEADER_LEN};
    let base = geo.slot_offset(id) + BLOCK;
    let hl = WAL_V2_BATCH_HEADER_LEN as u64;
    let mut h = [0u8; WAL_V2_BATCH_HEADER_LEN];
    let mut out = Vec::new();
    let mut off = 0u64;
    while off + hl <= geo.segment_bytes {
        io.read_at(&mut h, base + off)?;
        let Some((records, body, first)) = parse_batch_header(&h) else {
            break;
        };
        out.push(LostBatch {
            offset: base + off,
            first_seq: first.0,
            records,
        });
        match (off + hl).checked_add(body) {
            Some(end) if end <= geo.segment_bytes => off = align_up(end, BLOCK),
            _ => break,
        }
    }
    Ok(out)
}

fn slot_header_valid(io: &dyn BlockIo, geo: &Geometry, id: u64) -> std::io::Result<bool> {
    if id == 0 || id > geo.slot_count {
        return Ok(false);
    }
    let mut b = vec![0u8; BLOCK as usize];
    io.read_at(&mut b, geo.slot_offset(id))?;
    Ok(b == segment_header(geo, id))
}

/// Diagnosis plus what [`repair`] needs: the superblock in force and its namespace.
struct Inspection {
    report: RepairReport,
    sb: Option<Superblock>,
    names: BTreeMap<String, Vec<u8>>,
}

fn inspect(io: &dyn BlockIo) -> SynapseResult<Inspection> {
    if io.len() < LABEL_BYTES {
        return Err(refuse("device is smaller than the label area"));
    }
    match classify_device(io).map_err(io_err)? {
        DeviceLabel::Synapse => {}
        other => {
            return Err(refuse(format!(
                "refusing to diagnose: the device is not a Synapse store ({other:?})"
            )))
        }
    }
    let mut parsed = Vec::new();
    for i in 0..2u64 {
        let mut b = vec![0u8; BLOCK as usize];
        io.read_at(&mut b, i * BLOCK).map_err(io_err)?;
        parsed.push(classify_copy(&b, i, io).map_err(io_err)?);
    }
    let copies = [
        CopyReport {
            copy: 0,
            state: parsed[0].0.clone(),
        },
        CopyReport {
            copy: 1,
            state: parsed[1].0.clone(),
        },
    ];
    let valid: Vec<&Superblock> = parsed.iter().filter_map(|(_, s)| s.as_ref()).collect();
    let device_uuid = valid.first().map(|s| s.geo.uuid);
    let unrepairable = |why: String| Inspection {
        report: RepairReport {
            device_uuid,
            copies: copies.clone(),
            adopt: None,
            segment_count: 0,
            lost: vec![],
            history: vec![],
            verdict: Verdict::Unrepairable(why),
        },
        sb: None,
        names: BTreeMap::new(),
    };
    if valid.len() == 2 && valid[0].geo != valid[1].geo {
        return Ok(unrepairable(
            "the two superblock copies disagree on the geometry".into(),
        ));
    }
    // The checkpoint mount would use: newest intact copy.
    let mut intact: Vec<(u8, &Superblock)> = parsed
        .iter()
        .enumerate()
        .filter(|(_, (st, _))| matches!(st, CopyState::Intact { .. }))
        .filter_map(|(i, (_, sb))| sb.as_ref().map(|s| (i as u8, s)))
        .collect();
    intact.sort_by_key(|(_, s)| std::cmp::Reverse(s.generation));
    let Some((copy, sb)) = intact.first().copied() else {
        return Ok(unrepairable(
            "no superblock copy with an intact metadata region".into(),
        ));
    };
    let mut meta = vec![0u8; sb.meta_len as usize];
    io.read_at(&mut meta, sb.geo.meta_offset[sb.meta_slot as usize])
        .map_err(io_err)?;
    let names = decode_meta(&meta).expect("an intact copy's region decodes");
    let history = match names.get(REPAIR_LOG_NAME) {
        Some(log) => match verify_repair_log(log, &sb.geo.uuid) {
            Ok(h) => h,
            Err(e) => return Ok(unrepairable(e.message)),
        },
        None => Vec::new(),
    };
    let mut lost = Vec::new();
    let mut id = sb.segment_count + 1;
    while slot_header_valid(io, &sb.geo, id).map_err(io_err)? {
        if let Some((start, end, nonzero_bytes)) =
            nonzero_extent(io, &sb.geo, id).map_err(io_err)?
        {
            lost.push(LostRange {
                slot: id,
                start,
                end,
                nonzero_bytes,
                batches: scan_batches(io, &sb.geo, id).map_err(io_err)?,
            });
        }
        id += 1;
    }
    // A freshly formatted store has only generation 1 (in copy 1); copy 0 is blank.
    let both_ok = intact.len() == 2 || (sb.generation == 1 && copies[0].state == CopyState::Blank);
    let verdict = if !lost.is_empty() {
        Verdict::OlderCheckpointLosesRange
    } else if both_ok {
        Verdict::Healthy
    } else {
        Verdict::OneCopyDamagedNothingLost
    };
    Ok(Inspection {
        report: RepairReport {
            device_uuid,
            copies,
            adopt: Some((copy, sb.generation)),
            segment_count: sb.segment_count,
            lost,
            history,
            verdict,
        },
        sb: Some(sb.clone()),
        names,
    })
}

/// Read-only diagnosis of the device. Writes nothing. Refuses a device that does not
/// carry the Synapse magic (never inspects a foreign device further).
pub fn diagnose(io: &dyn BlockIo) -> SynapseResult<RepairReport> {
    Ok(inspect(io)?.report)
}

// --- backup ---------------------------------------------------------------------

const BACKUP_MAGIC: &[u8; 16] = b"SYNREPAIRBAK001\n";

/// One saved byte range.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackupSection {
    pub offset: u64,
    pub bytes: Vec<u8>,
}

/// Contents of a repair backup file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Backup {
    pub device_uuid: [u8; 16],
    pub sections: Vec<BackupSection>,
}

fn block_range(r: &LostRange) -> (u64, u64) {
    (r.start / BLOCK * BLOCK, align_up(r.end, BLOCK))
}

/// Parse and verify (trailing SHA-256) a backup file written by the repair.
pub fn read_backup(path: &Path) -> SynapseResult<Backup> {
    let b = fs::read(path).map_err(io_err)?;
    if b.len() < 16 + 16 + 4 + 32 || &b[..16] != BACKUP_MAGIC {
        return Err(refuse("not a repair backup file"));
    }
    let (body, tail) = b.split_at(b.len() - 32);
    if Sha256::digest(body).as_slice() != tail {
        return Err(refuse("repair backup digest mismatch"));
    }
    let device_uuid: [u8; 16] = body[16..32].try_into().expect("16");
    let n = u32::from_le_bytes(body[32..36].try_into().expect("4"));
    let mut at = 36usize;
    let mut sections = Vec::new();
    for _ in 0..n {
        let data_start = at
            .checked_add(16)
            .ok_or_else(|| refuse("repair backup section header overflow"))?;
        let hdr = body
            .get(at..data_start)
            .ok_or_else(|| refuse("truncated repair backup"))?;
        let offset = u64::from_le_bytes(hdr[..8].try_into().expect("8"));
        let len = usize::try_from(u64::from_le_bytes(hdr[8..].try_into().expect("8")))
            .map_err(|_| refuse("repair backup section length does not fit this host"))?;
        let end = data_start
            .checked_add(len)
            .ok_or_else(|| refuse("repair backup section length overflow"))?;
        let bytes = body
            .get(data_start..end)
            .ok_or_else(|| refuse("truncated repair backup"))?
            .to_vec();
        sections.push(BackupSection { offset, bytes });
        at = end;
    }
    Ok(Backup {
        device_uuid,
        sections,
    })
}

/// Save the device bytes of every `(start, end)` range to a new file and sync it (and
/// its directory). An existing file is never overwritten.
fn write_backup(
    io: &dyn BlockIo,
    path: &Path,
    uuid: [u8; 16],
    ranges: &[(u64, u64)],
) -> SynapseResult<()> {
    let mut body = Vec::new();
    body.extend_from_slice(BACKUP_MAGIC);
    body.extend_from_slice(&uuid);
    body.extend_from_slice(&(ranges.len() as u32).to_le_bytes());
    for &(a, b) in ranges {
        let mut bytes = vec![0u8; (b - a) as usize];
        io.read_at(&mut bytes, a).map_err(io_err)?;
        body.extend_from_slice(&a.to_le_bytes());
        body.extend_from_slice(&(bytes.len() as u64).to_le_bytes());
        body.extend_from_slice(&bytes);
    }
    let digest = Sha256::digest(&body);
    body.extend_from_slice(&digest);
    // create_new: an existing file is never overwritten; owner-only.
    let mut f = {
        use std::os::unix::fs::OpenOptionsExt;
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)
            .map_err(|e| refuse(format!("backup file {}: {e}", path.display())))?
    };
    f.write_all(&body).map_err(io_err)?;
    f.sync_all().map_err(io_err)?;
    if let Some(dir) = path.parent().filter(|d| !d.as_os_str().is_empty()) {
        File::open(dir).and_then(|d| d.sync_all()).map_err(io_err)?;
    }
    Ok(())
}

// --- repair -------------------------------------------------------------------------

/// What [`repair`] did: the diagnosis it acted on, and the signed entry it committed (or,
/// when it finished an interrupted adopt, the entry that already recorded it).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RepairReceipt {
    pub report: RepairReport,
    /// `None` when there was nothing to repair and nothing was written.
    pub entry: Option<RepairEntry>,
    /// Whether the device was written.
    pub wrote: bool,
}

impl std::fmt::Display for RepairReceipt {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match (&self.entry, self.wrote) {
            (Some(e), true) => write!(
                f,
                "repair receipt: {e}; entry sha256 {}",
                hex::encode(e.digest())
            ),
            _ => write!(f, "nothing to repair; nothing was written"),
        }
    }
}

fn zero_ranges(io: &dyn BlockIo, ranges: &[(u64, u64)]) -> SynapseResult<()> {
    let zero = vec![0u8; ZERO_CHUNK];
    for &(mut at, end) in ranges {
        while at < end {
            let n = (ZERO_CHUNK as u64).min(end - at) as usize;
            io.write_at(&zero[..n], at).map_err(io_err)?;
            at += n as u64;
        }
    }
    io.flush().map_err(io_err)
}

fn sha256_range(io: &dyn BlockIo, (a, b): (u64, u64)) -> SynapseResult<[u8; 32]> {
    let mut bytes = vec![0u8; (b - a) as usize];
    io.read_at(&mut bytes, a).map_err(io_err)?;
    Ok(Sha256::digest(&bytes).into())
}

/// Repair the store on `io` with the named `action`, signed by `operator`.
///
/// * Nothing to repair ([`Verdict::Healthy`], [`Verdict::OneCopyDamagedNothingLost`]):
///   nothing is written, no backup is created.
/// * [`Verdict::Unrepairable`]: refused, nothing written.
/// * Otherwise: refuse unless `action` fits the diagnosis; save every byte range about
///   to be overwritten to `backup_path` (must not exist) and sync it; commit the new
///   superblock and a namespace whose repair log ends with the signed entry, in one
///   flush; for an adopt, then zero the dropped range and flush; re-diagnose and
///   refuse if anything is still past the checkpoint.
pub fn repair(
    io: &dyn BlockIo,
    action: RepairAction,
    operator: &SigningKey,
    backup_path: &Path,
    unix_secs: u64,
) -> SynapseResult<RepairReceipt> {
    let Inspection { report, sb, names } = inspect(io)?;
    match &report.verdict {
        Verdict::Unrepairable(_) => return Err(corrupt(format!("{report}"))),
        Verdict::Healthy | Verdict::OneCopyDamagedNothingLost => {
            return Ok(RepairReceipt {
                report,
                entry: None,
                wrote: false,
            })
        }
        Verdict::OlderCheckpointLosesRange => {}
    }
    let sb = sb.expect("a repairable diagnosis has a checkpoint in force");
    let uuid = sb.geo.uuid;
    let lost_blocks: Vec<(u64, u64)> = report.lost.iter().map(block_range).collect();

    // An adopt whose record committed but whose zeroing did not finish: the newest entry
    // is that adopt, at the generation in force, and covers every range still holding
    // data. Finish it; never record it twice, never roll it forward.
    if let Some(last) = report.history.last().filter(|e| {
        e.action == RepairAction::AdoptOlderCheckpoint
            && e.generation == sb.generation
            && lost_blocks.iter().zip(&report.lost).all(|(&(a, b), l)| {
                e.ranges
                    .iter()
                    .any(|r| r.slot == l.slot && r.start <= a && b <= r.end)
            })
    }) {
        if action != RepairAction::AdoptOlderCheckpoint {
            return Err(refuse(format!(
                "refusing {action:?}: the signed repair log already records an adopt of this range that did not finish; re-run with the same action. Nothing was written.\n{report}"
            )));
        }
        let entry = last.clone();
        write_backup(io, backup_path, uuid, &lost_blocks)?;
        zero_ranges(io, &lost_blocks)?;
        return finish(io, report, entry);
    }

    if action == RepairAction::RollForward {
        let next = sb.segment_count + 1;
        if report.lost.len() != 1 || report.lost[0].slot != next {
            return Err(refuse(format!(
                "refusing to roll forward: exactly one slot (slot {next}) past the checkpoint may hold data, and this device has {} such slots; a damaged superblock loses one commit. Nothing was written.\n{report}",
                report.lost.len()
            )));
        }
        if report.lost[0].batches.is_empty() {
            return Err(refuse(format!(
                "refusing to roll forward: slot {next} holds data but no WAL v2 batch header at its start. Nothing was written.\n{report}"
            )));
        }
    }

    let generation = sb.generation + 1;
    let target_copy = (generation % 2) * BLOCK;
    let mut ranges = Vec::new();
    for (l, &(a, b)) in report.lost.iter().zip(&lost_blocks) {
        ranges.push(RecordedRange {
            slot: l.slot,
            start: a,
            end: b,
            nonzero_bytes: l.nonzero_bytes,
            batches: l.batches.len() as u32,
            records: l.records(),
            first_seq: l.batches.first().map_or(0, |x| x.first_seq),
            bytes_sha256: sha256_range(io, (a, b))?,
        });
    }
    let mut entry = RepairEntry {
        action,
        device_uuid: uuid,
        generation,
        segment_count_before: sb.segment_count,
        segment_count_after: match action {
            RepairAction::RollForward => sb.segment_count + 1,
            RepairAction::AdoptOlderCheckpoint => sb.segment_count,
        },
        unix_secs,
        prev_sha256: report.history.last().map_or([0u8; 32], |e| e.digest()),
        replaced_copy_sha256: sha256_range(io, (target_copy, target_copy + BLOCK))?,
        ranges,
        operator_key: operator.verifying_key().to_bytes(),
        signature: [0u8; 64],
    };
    entry.signature = operator.sign(&entry.signable_bytes()).to_bytes();

    let mut new_names = names;
    let log = new_names.remove(REPAIR_LOG_NAME).unwrap_or_default();
    new_names.insert(REPAIR_LOG_NAME.to_string(), append_entry(&log, &entry));
    let meta = encode_meta(&new_names);
    if meta.len() as u64 > sb.geo.meta_region_bytes {
        return Err(refuse(
            "the repair entry does not fit the metadata region; nothing was written",
        ));
    }
    // The region no valid copy in force points at (the commit protocol's spare region).
    let meta_slot = 1 - sb.meta_slot;
    let region_at = sb.geo.meta_offset[meta_slot as usize];
    let mut region = meta.clone();
    region.resize(align_up(region.len() as u64, BLOCK) as usize, 0);
    let new_sb = Superblock {
        geo: sb.geo,
        generation,
        segment_count: entry.segment_count_after,
        meta_len: meta.len() as u64,
        meta_slot,
        meta_sha256: meta_digest(&meta),
    };

    let mut backup = vec![
        (0u64, 2 * BLOCK),
        (region_at, region_at + region.len() as u64),
    ];
    if action == RepairAction::AdoptOlderCheckpoint {
        backup.extend_from_slice(&lost_blocks);
    }
    write_backup(io, backup_path, uuid, &backup)?;
    io.write_at(&region, region_at).map_err(io_err)?;
    io.write_at(&new_sb.encode(), target_copy).map_err(io_err)?;
    io.flush().map_err(io_err)?;
    if action == RepairAction::AdoptOlderCheckpoint {
        zero_ranges(io, &lost_blocks)?;
    }
    finish(io, report, entry)
}

fn finish(
    io: &dyn BlockIo,
    report: RepairReport,
    entry: RepairEntry,
) -> SynapseResult<RepairReceipt> {
    let after = diagnose(io)?;
    if after.verdict != Verdict::Healthy || after.history.last() != Some(&entry) {
        return Err(corrupt(format!(
            "the repair was written but the device does not diagnose healthy with the entry in force:\n{after}"
        )));
    }
    Ok(RepairReceipt {
        report,
        entry: Some(entry),
        wrote: true,
    })
}

/// [`repair`] on the device at `path`, opened read-write under the same exclusive lock
/// the store takes ([`DirectFile::open`]): refused while a store or another repair holds it.
pub fn repair_path(
    path: &Path,
    action: RepairAction,
    operator: &SigningKey,
    backup_path: &Path,
    unix_secs: u64,
) -> SynapseResult<RepairReceipt> {
    let io = DirectFile::open(path)?;
    repair(&io, action, operator, backup_path, unix_secs)
}

/// [`diagnose`] on the device at `path`, opened read-only under the exclusive lock.
pub fn diagnose_path(path: &Path) -> SynapseResult<RepairReport> {
    let io = DirectFile::open_read_only(path)?;
    diagnose(&io)
}
