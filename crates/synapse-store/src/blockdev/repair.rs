//! R1 store repair, non-destructive path (issue #105, follow-up to #103).
//!
//! When the newest superblock copy is damaged, mount refuses with `CheckpointCorrupt`
//! because the older copy would silently drop batches acknowledged after it. This module
//! gives the operator what the refusal lacks:
//!
//! * [`diagnose`] reads both superblock copies (read-only, no write of any kind) and says
//!   which copy is damaged, which checkpoint an older copy would fall back to, and the
//!   exact device byte range of the acknowledged data that fallback would lose.
//! * [`repair_dropping_acknowledged_range`] adopts that older checkpoint. It writes
//!   nothing unless the caller passes `accept_loss = true` (CLI flag
//!   `--drop-acknowledged-range`), and before its first device write it saves the
//!   superblocks and the exact bytes it is about to zero to a new backup file and syncs
//!   it ([`read_backup`] reads it back). It zeroes only the reported range.
//!
//! Not here (the policy is Drake's to set): rolling the log forward past the older
//! checkpoint, and a signed repair entry in the log.

use super::*;

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

/// Acknowledged data in a slot past the checkpoint an older copy would adopt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LostRange {
    /// Segment slot id.
    pub slot: u64,
    /// Device byte offset of the first and one past the last non-zero byte.
    pub start: u64,
    pub end: u64,
    /// Number of non-zero bytes in the slot.
    pub nonzero_bytes: u64,
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
    /// No usable checkpoint (or contradictory geometry): this tool cannot repair it.
    Unrepairable(String),
}

/// Result of [`diagnose`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RepairReport {
    pub device_uuid: Option<[u8; 16]>,
    pub copies: [CopyReport; 2],
    /// Copy and generation of the checkpoint an older copy would adopt.
    pub adopt: Option<(u8, u64)>,
    pub segment_count: u64,
    pub lost: Vec<LostRange>,
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
                    "verdict: the store refuses to open (CheckpointCorrupt). Adopting the older checkpoint (copy {copy}, generation {generation}, {} committed segments) would DROP acknowledged data:",
                    self.segment_count
                )?;
                for r in &self.lost {
                    writeln!(
                        f,
                        "  segment slot {}: device bytes {}..{} ({} non-zero bytes)",
                        r.slot, r.start, r.end, r.nonzero_bytes
                    )?;
                }
                writeln!(
                    f,
                    "  metadata changes committed by the damaged superblock cannot be read and are lost too"
                )?;
                writeln!(
                    f,
                    "nothing was written. To accept this loss re-run with --drop-acknowledged-range and --backup <new file>"
                )?;
            }
        }
        Ok(())
    }
}

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

fn slot_header_valid(io: &dyn BlockIo, geo: &Geometry, id: u64) -> std::io::Result<bool> {
    if id == 0 || id > geo.slot_count {
        return Ok(false);
    }
    let mut b = vec![0u8; BLOCK as usize];
    io.read_at(&mut b, geo.slot_offset(id))?;
    Ok(b == segment_header(geo, id))
}

/// Read-only diagnosis of the device. Writes nothing. Refuses a device that does not
/// carry the Synapse magic (never inspects a foreign device further).
pub fn diagnose(io: &dyn BlockIo) -> SynapseResult<RepairReport> {
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
    let mk = |adopt, segment_count, lost, verdict| RepairReport {
        device_uuid,
        copies: copies.clone(),
        adopt,
        segment_count,
        lost,
        verdict,
    };
    if valid.len() == 2 && valid[0].geo != valid[1].geo {
        return Ok(mk(
            None,
            0,
            vec![],
            Verdict::Unrepairable("the two superblock copies disagree on the geometry".into()),
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
        return Ok(mk(
            None,
            0,
            vec![],
            Verdict::Unrepairable("no superblock copy with an intact metadata region".into()),
        ));
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
            });
        }
        id += 1;
    }
    let both_ok = intact.len() == 2;
    let verdict = if !lost.is_empty() {
        Verdict::OlderCheckpointLosesRange
    } else if both_ok {
        Verdict::Healthy
    } else {
        Verdict::OneCopyDamagedNothingLost
    };
    Ok(mk(
        Some((copy, sb.generation)),
        sb.segment_count,
        lost,
        verdict,
    ))
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
    let mut at = 36;
    let mut sections = Vec::new();
    for _ in 0..n {
        let hdr = body
            .get(at..at + 16)
            .ok_or_else(|| refuse("truncated repair backup"))?;
        let offset = u64::from_le_bytes(hdr[..8].try_into().expect("8"));
        let len = u64::from_le_bytes(hdr[8..].try_into().expect("8")) as usize;
        let bytes = body
            .get(at + 16..at + 16 + len)
            .ok_or_else(|| refuse("truncated repair backup"))?
            .to_vec();
        sections.push(BackupSection { offset, bytes });
        at += 16 + len;
    }
    Ok(Backup {
        device_uuid,
        sections,
    })
}

fn write_backup(
    io: &dyn BlockIo,
    path: &Path,
    uuid: [u8; 16],
    report: &RepairReport,
) -> SynapseResult<()> {
    let mut ranges = vec![(0u64, 2 * BLOCK)];
    for r in &report.lost {
        ranges.push(block_range(r));
    }
    let mut body = Vec::new();
    body.extend_from_slice(BACKUP_MAGIC);
    body.extend_from_slice(&uuid);
    body.extend_from_slice(&(ranges.len() as u32).to_le_bytes());
    for (a, b) in ranges {
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

/// Adopt the older checkpoint by zeroing exactly the ranges [`diagnose`] reports.
///
/// * Without `accept_loss` nothing is written and the call fails, naming the range.
/// * When the diagnosis finds no acknowledged data at risk, nothing is written and the
///   report is returned.
/// * Otherwise the backup file is written and synced first (it must not exist), then
///   only the reported blocks are zeroed and flushed. Superblocks are not touched: the
///   damaged copy fails its CRC and is rewritten by the next commit.
pub fn repair_dropping_acknowledged_range(
    io: &dyn BlockIo,
    backup_path: &Path,
    accept_loss: bool,
) -> SynapseResult<RepairReport> {
    let report = diagnose(io)?;
    if report.verdict != Verdict::OlderCheckpointLosesRange {
        if matches!(report.verdict, Verdict::Unrepairable(_)) {
            return Err(corrupt(format!("{report}")));
        }
        return Ok(report);
    }
    if !accept_loss {
        return Err(refuse(format!(
            "refusing to drop acknowledged data without --drop-acknowledged-range; nothing was written.\n{report}"
        )));
    }
    let uuid = report.device_uuid.expect("a usable copy has a uuid");
    write_backup(io, backup_path, uuid, &report)?;
    let zero = vec![0u8; ZERO_CHUNK];
    for r in &report.lost {
        let (mut at, end) = block_range(r);
        while at < end {
            let n = (ZERO_CHUNK as u64).min(end - at) as usize;
            io.write_at(&zero[..n], at).map_err(io_err)?;
            at += n as u64;
        }
    }
    io.flush().map_err(io_err)?;
    let after = diagnose(io)?;
    if !after.lost.is_empty() {
        return Err(corrupt("range still holds data after the repair write"));
    }
    Ok(report)
}
