//! WAL v2 (`wal.v2.log`): pre-written log of 4 KiB-aligned batches with inline blobs.
//!
//! Why: on this host's ext4/NVMe, writing into space that is already written and synced
//! and then calling `fdatasync` measured 0.81 to 1.11 ms median (4 KiB to 1 MiB), while
//! any append, `fallocate`d write, or new file plus `fsync` needs a journal commit and
//! measured 3.5 to 6.4 ms median (`docs/PHASE5_GROUP_COMMIT.md`,
//! `evidence/phase5-group-commit/floor.json`). v2 therefore
//! keeps every durable commit inside pre-written space, stores blobs inside the log
//! instead of one file each, and commits a whole batch with one `pwrite` and one
//! `fdatasync`.
//!
//! Layout:
//! * The file is zero-filled ahead of the write position in chunks (`sync_all` after
//!   each extension, so size and blocks are durable before any batch lands there).
//! * A batch starts at a 4 KiB-aligned offset with a 64-byte batch header
//!   (`SWB2`, version 2, record count, body length, first `WalSeq`, CRC-32C of the
//!   header), followed by `record_count` frames and the 8-byte trailer `SWB2END!` (no
//!   zero byte in it), then zero padding to the next 4 KiB. The declared body length
//!   covers the frames and the trailer.
//! * Each frame keeps the v1 88-byte header layout with `version = 2`. The payload is
//!   `u32 meta_len | meta (JSON WalRecord) | u32 blob_count | (digest[32] | u32 len |
//!   bytes)*`. `payload_crc32c` is CRC-32C of the payload. `frame_sha256 =
//!   SHA-256("SYNAPSE_WAL_FRAME_V2\0" || header[0..56] || payload_sha256)` with
//!   `payload_sha256 = SHA-256("SYNAPSE_WAL_PAYLOAD_V2\0" || payload)`, so the payload
//!   digest is computed by the submitter in parallel and the writer hashes 120 bytes.
//! * `seq`, `prev_frame_sha256` and the hash chain continue across v1 and v2 frames.
//!
//! Recovery applies a batch only when every frame in it validates (all or nothing).
//! The end of the log is the first all-zero batch header followed only by zeros. An
//! invalid batch is a torn tail only if no valid batch header follows it and the
//! sector that should hold its end reads back as zeros (see [`torn_evidence`]); the
//! space was zero before the write and the trailer has no zero byte, so a complete batch
//! never ends in zeros. Otherwise recovery fails closed with the specific refusal code.
//! Assumption (UNVERIFIED for this drive): a 512-byte sector write is atomic.

use super::*;
use std::os::unix::fs::FileExt;

/// WAL v2 file name inside the store root.
pub const WAL_V2_FILE: &str = "wal.v2.log";
/// Frame and batch format version for WAL v2.
pub const WAL_V2_VERSION: u16 = 2;
/// Domain tag for the v2 frame chain digest.
pub const DOMAIN_WAL_FRAME_V2: &[u8] = b"SYNAPSE_WAL_FRAME_V2\0";
/// Domain tag for the v2 payload digest.
pub const DOMAIN_WAL_PAYLOAD_V2: &[u8] = b"SYNAPSE_WAL_PAYLOAD_V2\0";
/// Batch header magic.
pub const WAL_V2_BATCH_MAGIC: [u8; 4] = *b"SWB2";
/// Batch header length.
pub const WAL_V2_BATCH_HEADER_LEN: usize = 64;
/// Batch alignment.
pub const WAL_V2_ALIGN: u64 = 4096;
/// Sector size used for torn-write evidence.
pub const WAL_V2_SECTOR: usize = 512;
/// Last 8 bytes of every batch body. No byte is zero, so the sector holding the end of
/// a batch is all zero only when that sector never reached the disk.
pub const WAL_V2_BATCH_TRAILER: [u8; 8] = *b"SWB2END!";

pub(crate) fn align_up(x: u64) -> u64 {
    x.div_ceil(WAL_V2_ALIGN) * WAL_V2_ALIGN
}

/// A record encoded for WAL v2 before the critical section (payload, its digest, CRC).
#[derive(Debug, Clone)]
pub(crate) struct EncodedRecord {
    pub kind: u8,
    /// Frame header flags byte: the codec of the record metadata.
    pub flags: u8,
    pub payload: Vec<u8>,
    pub payload_sha256: [u8; 32],
    pub payload_crc32c: u32,
    /// Inline blobs: (digest, byte offset inside the payload, length).
    pub inline: Vec<(BlobDigest, u32, u32)>,
}

pub(crate) fn payload_digest(payload: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(DOMAIN_WAL_PAYLOAD_V2);
    h.update(payload);
    h.finalize().into()
}

fn too_large(what: &str) -> SynapseError {
    SynapseError::new(
        RefusalCode::QuotaPayloadTooLarge,
        format!("{what} exceeds the WAL v2 32-bit length field"),
    )
}

/// Encode `record` with `blobs` stored inline.
pub(crate) fn encode_record(
    record: &WalRecord,
    blobs: &[(BlobDigest, &[u8])],
    codec: RecordCodec,
) -> SynapseResult<EncodedRecord> {
    let meta = codec::encode_record_with(record, codec)?;
    let blob_bytes: usize = blobs.iter().map(|(_, b)| 36 + b.len()).sum();
    let mut payload = Vec::with_capacity(8 + meta.len() + blob_bytes);
    payload.extend_from_slice(
        &u32::try_from(meta.len())
            .map_err(|_| too_large("record metadata"))?
            .to_le_bytes(),
    );
    payload.extend_from_slice(&meta);
    payload.extend_from_slice(
        &u32::try_from(blobs.len())
            .map_err(|_| too_large("blob count"))?
            .to_le_bytes(),
    );
    let mut inline = Vec::with_capacity(blobs.len());
    for (digest, bytes) in blobs {
        let len = u32::try_from(bytes.len()).map_err(|_| too_large("blob"))?;
        payload.extend_from_slice(&digest.0);
        payload.extend_from_slice(&len.to_le_bytes());
        let off = u32::try_from(payload.len()).map_err(|_| too_large("payload"))?;
        payload.extend_from_slice(bytes);
        inline.push((*digest, off, len));
    }
    u32::try_from(payload.len()).map_err(|_| too_large("payload"))?;
    Ok(EncodedRecord {
        kind: record.kind_byte(),
        flags: codec.frame_flags(),
        payload_sha256: payload_digest(&payload),
        payload_crc32c: crc32c(&payload),
        payload,
        inline,
    })
}

impl EncodedRecord {
    /// Codec of the record metadata.
    pub fn codec(&self) -> RecordCodec {
        RecordCodec::from_frame_flags(self.flags).expect("encoded with a known codec")
    }

    /// The same record with its metadata re-encoded as `codec` (inline blobs kept, their
    /// offsets shifted). Used when a store migrates between prepare and commit.
    pub fn recode(&self, record: &WalRecord, codec: RecordCodec) -> SynapseResult<Self> {
        if self.codec() == codec {
            return Ok(self.clone());
        }
        let old_meta = u32::from_le_bytes(self.payload[0..4].try_into().expect("4 bytes")) as usize;
        let meta = codec::encode_record_with(record, codec)?;
        let rest = &self.payload[4 + old_meta..];
        let mut payload = Vec::with_capacity(4 + meta.len() + rest.len());
        payload.extend_from_slice(
            &u32::try_from(meta.len())
                .map_err(|_| too_large("record metadata"))?
                .to_le_bytes(),
        );
        payload.extend_from_slice(&meta);
        payload.extend_from_slice(rest);
        u32::try_from(payload.len()).map_err(|_| too_large("payload"))?;
        let shift = |off: u32| (off as usize - 4 - old_meta + 4 + meta.len()) as u32;
        Ok(Self {
            kind: self.kind,
            flags: codec.frame_flags(),
            payload_sha256: payload_digest(&payload),
            payload_crc32c: crc32c(&payload),
            inline: self
                .inline
                .iter()
                .map(|(d, o, l)| (*d, shift(*o), *l))
                .collect(),
            payload,
        })
    }
}

/// Decoded v2 payload.
pub(crate) struct DecodedPayload {
    pub record: WalRecord,
    /// Inline blobs: (digest, byte offset inside the payload, length).
    pub inline: Vec<(BlobDigest, u32, u32)>,
}

fn corrupt(seq: WalSeq, what: &str) -> SynapseError {
    SynapseError::new(
        RefusalCode::WalCrcMismatch,
        format!("corrupt WAL v2 payload at {seq}: {what}"),
    )
}

/// Decode a v2 payload, verifying every inline blob digest.
pub(crate) fn decode_payload(
    seq: WalSeq,
    payload: &[u8],
    codec: RecordCodec,
    cap: u64,
) -> SynapseResult<DecodedPayload> {
    let rd_u32 = |at: usize| -> SynapseResult<u32> {
        payload
            .get(at..at + 4)
            .map(|b| u32::from_le_bytes(b.try_into().expect("4 bytes")))
            .ok_or_else(|| corrupt(seq, "truncated length field"))
    };
    let meta_len = rd_u32(0)? as usize;
    let meta = payload
        .get(4..4 + meta_len)
        .ok_or_else(|| corrupt(seq, "truncated metadata"))?;
    let record = match codec {
        RecordCodec::JsonV1 => {
            serde_json::from_slice(meta).map_err(|e| corrupt(seq, &format!("record JSON: {e}")))?
        }
        RecordCodec::BinaryV2 => codec::decode_record(meta, cap).map_err(|r| {
            r.into_error(
                RefusalCode::WalRecordMalformed,
                &format!("binary WAL v2 record at {seq}"),
            )
        })?,
    };
    let mut at = 4 + meta_len;
    let count = rd_u32(at)? as usize;
    at += 4;
    let mut inline = Vec::with_capacity(count.min(4096));
    for _ in 0..count {
        let digest_bytes: [u8; 32] = payload
            .get(at..at + 32)
            .ok_or_else(|| corrupt(seq, "truncated blob digest"))?
            .try_into()
            .expect("32 bytes");
        let len = rd_u32(at + 32)? as usize;
        let start = at + 36;
        let bytes = payload
            .get(start..start + len)
            .ok_or_else(|| corrupt(seq, "truncated blob bytes"))?;
        let digest = BlobDigest(digest_bytes);
        if BlobDigest::compute(bytes) != digest {
            return Err(SynapseError::new(
                RefusalCode::BlobDigestMismatch,
                format!("inline blob {digest} corrupt in WAL v2 frame {seq}"),
            ));
        }
        inline.push((digest, start as u32, len as u32));
        at = start + len;
    }
    if at != payload.len() {
        return Err(corrupt(seq, "trailing bytes after the last inline blob"));
    }
    Ok(DecodedPayload { record, inline })
}

/// Build the 88-byte v2 frame header and its chain digest.
pub(crate) fn frame_header(
    seq: WalSeq,
    prev_sha: [u8; 32],
    kind: u8,
    flags: u8,
    payload_len: u32,
    payload_crc32c: u32,
    payload_sha256: &[u8; 32],
) -> ([u8; WAL_HEADER_LEN], [u8; 32]) {
    let mut h = [0u8; WAL_HEADER_LEN];
    h[0..4].copy_from_slice(&WAL_MAGIC);
    h[4..6].copy_from_slice(&WAL_V2_VERSION.to_le_bytes());
    h[6] = kind;
    h[7] = flags;
    h[8..16].copy_from_slice(&seq.0.to_le_bytes());
    h[16..48].copy_from_slice(&prev_sha);
    h[48..52].copy_from_slice(&payload_len.to_le_bytes());
    h[52..56].copy_from_slice(&payload_crc32c.to_le_bytes());
    let sha = frame_digest(&h[0..56], payload_sha256);
    h[56..88].copy_from_slice(&sha);
    (h, sha)
}

pub(crate) fn frame_digest(header_prefix_56: &[u8], payload_sha256: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(DOMAIN_WAL_FRAME_V2);
    hasher.update(header_prefix_56);
    hasher.update(payload_sha256);
    hasher.finalize().into()
}

fn batch_header(record_count: u32, body_len: u64, first_seq: WalSeq) -> [u8; 64] {
    let mut h = [0u8; WAL_V2_BATCH_HEADER_LEN];
    h[0..4].copy_from_slice(&WAL_V2_BATCH_MAGIC);
    h[4..6].copy_from_slice(&WAL_V2_VERSION.to_le_bytes());
    h[8..12].copy_from_slice(&record_count.to_le_bytes());
    h[16..24].copy_from_slice(&body_len.to_le_bytes());
    h[24..32].copy_from_slice(&first_seq.0.to_le_bytes());
    let crc = crc32c(&h[0..60]);
    h[60..64].copy_from_slice(&crc.to_le_bytes());
    h
}

/// Parsed batch header (`None` when magic, version, reserved bytes or CRC are wrong).
pub(crate) fn parse_batch_header(h: &[u8]) -> Option<(u32, u64, WalSeq)> {
    if h.len() < WAL_V2_BATCH_HEADER_LEN || h[0..4] != WAL_V2_BATCH_MAGIC {
        return None;
    }
    if u16::from_le_bytes([h[4], h[5]]) != WAL_V2_VERSION {
        return None;
    }
    let crc = u32::from_le_bytes(h[60..64].try_into().ok()?);
    if crc != crc32c(&h[0..60]) {
        return None;
    }
    if h[6..8]
        .iter()
        .chain(&h[12..16])
        .chain(&h[32..60])
        .any(|b| *b != 0)
    {
        return None;
    }
    let count = u32::from_le_bytes(h[8..12].try_into().ok()?);
    let body = u64::from_le_bytes(h[16..24].try_into().ok()?);
    let first = WalSeq(u64::from_le_bytes(h[24..32].try_into().ok()?));
    Some((count, body, first))
}

/// Frame-level faults applied to the first frame of the next batch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FrameFault {
    None,
    CorruptCrc,
    CorruptChain,
    SequenceGap,
    DuplicateSequence,
}

/// Builds one batch buffer: header, frames, zero padding to 4 KiB.
pub(crate) struct BatchBuilder {
    buf: Vec<u8>,
    base_offset: u64,
    count: u32,
    first_seq: Option<WalSeq>,
}

/// Placement of one frame inside a batch.
pub(crate) struct PlacedFrame {
    pub seq: WalSeq,
    pub frame_sha256: [u8; 32],
    /// Absolute file offset of the frame payload.
    pub payload_offset: u64,
}

impl BatchBuilder {
    pub fn new(base_offset: u64, capacity: usize) -> Self {
        let mut buf = Vec::with_capacity(capacity + WAL_V2_ALIGN as usize);
        buf.resize(WAL_V2_BATCH_HEADER_LEN, 0);
        Self {
            buf,
            base_offset,
            count: 0,
            first_seq: None,
        }
    }

    /// Append one frame. `fault` alters only this frame (test hook).
    pub fn push(
        &mut self,
        seq: WalSeq,
        prev_sha: [u8; 32],
        enc: &EncodedRecord,
        fault: FrameFault,
    ) -> PlacedFrame {
        let seq_on_disk = match fault {
            FrameFault::SequenceGap => seq.next(),
            FrameFault::DuplicateSequence => WalSeq(seq.0.saturating_sub(1)),
            _ => seq,
        };
        let mut prev = prev_sha;
        if fault == FrameFault::CorruptChain {
            prev[0] ^= 0xff;
        }
        let mut crc = enc.payload_crc32c;
        if fault == FrameFault::CorruptCrc {
            crc ^= 0xdead_beef;
        }
        let (header, sha) = frame_header(
            seq_on_disk,
            prev,
            enc.kind,
            enc.flags,
            enc.payload.len() as u32,
            crc,
            &enc.payload_sha256,
        );
        if self.first_seq.is_none() {
            self.first_seq = Some(seq_on_disk);
        }
        self.buf.extend_from_slice(&header);
        let payload_offset = self.base_offset + self.buf.len() as u64;
        self.buf.extend_from_slice(&enc.payload);
        self.count += 1;
        PlacedFrame {
            seq,
            frame_sha256: sha,
            payload_offset,
        }
    }

    /// Finish the batch: append the trailer, fill the header and pad to 4 KiB.
    pub fn finish(mut self) -> Vec<u8> {
        self.buf.extend_from_slice(&WAL_V2_BATCH_TRAILER);
        let body_len = (self.buf.len() - WAL_V2_BATCH_HEADER_LEN) as u64;
        let h = batch_header(self.count, body_len, self.first_seq.unwrap_or(WalSeq::ZERO));
        self.buf[0..WAL_V2_BATCH_HEADER_LEN].copy_from_slice(&h);
        let padded = align_up(self.buf.len() as u64) as usize;
        self.buf.resize(padded, 0);
        self.buf
    }
}

/// I/O faults for one batch write (test hooks).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum BatchIoFault {
    None,
    /// Write only the first `n` bytes, then return an error.
    FailWrite {
        bytes_written: usize,
    },
    /// Write everything, then report an `fdatasync` failure.
    FailSync,
    /// As `FailSync`, and the rollback write also fails (store becomes poisoned).
    FailSyncAndRollback,
    /// Write the first `n` bytes, then exit the process with `code` (crash simulation).
    CrashAfterBytes {
        bytes_written: usize,
        code: i32,
    },
    /// Write everything without syncing, then exit the process with `code`.
    CrashBeforeSync {
        code: i32,
    },
    /// Write and sync the first `n` bytes, then stop as if the process had died: no
    /// rollback, and the store refuses further writes until reopened.
    TornThenStop {
        bytes_written: usize,
    },
}

/// Outcome of a failed batch write.
#[derive(Debug, Clone)]
pub(crate) enum BatchFailure {
    /// The batch bytes were overwritten with zeros and synced; the log is unchanged.
    RolledBack(SynapseError),
    /// Rollback failed too; the on-disk tail is unknown until the store is reopened.
    Poisoned(SynapseError),
}

/// Writer for `wal.v2.log`.
#[derive(Debug)]
pub(crate) struct WalV2Writer {
    file: File,
    pub write_offset: u64,
    pub prewritten_end: u64,
    chunk: u64,
}

fn injected(msg: &str) -> std::io::Error {
    std::io::Error::other(format!("injected fault: {msg}"))
}

impl WalV2Writer {
    /// Open (creating if needed) with the log ending at `write_offset` and every byte in
    /// `write_offset..file_len` known to be zero. Pre-writes one chunk ahead.
    pub fn open(path: &Path, write_offset: u64, chunk: u64) -> SynapseResult<Self> {
        let existed = path.exists();
        let file = OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(path)
            .map_err(io_err)?;
        if !existed {
            file.sync_all().map_err(io_err)?;
            if let Some(parent) = path.parent() {
                sync_dir(parent)?;
            }
        }
        let len = file.metadata().map_err(io_err)?.len();
        let mut w = Self {
            file,
            write_offset,
            prewritten_end: len.max(write_offset),
            chunk: chunk.max(WAL_V2_ALIGN),
        };
        w.ensure_space(WAL_V2_ALIGN).map_err(io_err)?;
        Ok(w)
    }

    /// Zero-fill and `sync_all` ahead of the write position until `need` bytes fit.
    pub fn ensure_space(&mut self, need: u64) -> std::io::Result<()> {
        if self.write_offset + need <= self.prewritten_end {
            return Ok(());
        }
        let target = align_up((self.write_offset + need).max(self.prewritten_end + self.chunk));
        let zeros = vec![0u8; 1 << 20];
        let mut at = self.prewritten_end;
        while at < target {
            let n = ((target - at) as usize).min(zeros.len());
            self.file.write_all_at(&zeros[..n], at)?;
            at += n as u64;
        }
        self.file.sync_all()?;
        self.prewritten_end = target;
        Ok(())
    }

    /// Write one finished batch at the write position and make it durable with one
    /// `fdatasync`. On failure the batch extent is zeroed and synced again (rollback).
    pub fn write_batch(&mut self, buf: &[u8], fault: BatchIoFault) -> Result<(), BatchFailure> {
        let at = self.write_offset;
        let fail = |e: std::io::Error| SynapseError::new(RefusalCode::IoFailure, e.to_string());
        if let Err(e) = self.ensure_space(buf.len() as u64) {
            // Nothing was written into the log extent; extension bytes are zeros.
            return Err(BatchFailure::RolledBack(fail(e)));
        }
        let res: std::io::Result<()> = match fault {
            BatchIoFault::None => self
                .file
                .write_all_at(buf, at)
                .and_then(|_| self.file.sync_data()),
            BatchIoFault::FailWrite { bytes_written } => self
                .file
                .write_all_at(&buf[..bytes_written.min(buf.len())], at)
                .and_then(|_| Err(injected("batch write failed"))),
            BatchIoFault::FailSync | BatchIoFault::FailSyncAndRollback => self
                .file
                .write_all_at(buf, at)
                .and_then(|_| Err(injected("fdatasync failed"))),
            BatchIoFault::CrashAfterBytes {
                bytes_written,
                code,
            } => {
                let _ = self
                    .file
                    .write_all_at(&buf[..bytes_written.min(buf.len())], at);
                std::process::exit(code);
            }
            BatchIoFault::CrashBeforeSync { code } => {
                let _ = self.file.write_all_at(buf, at);
                std::process::exit(code);
            }
            BatchIoFault::TornThenStop { bytes_written } => {
                let n = bytes_written.min(buf.len().saturating_sub(1));
                self.file
                    .write_all_at(&buf[..n], at)
                    .and_then(|_| self.file.sync_data())
                    .map_err(|e| BatchFailure::Poisoned(fail(e)))?;
                return Err(BatchFailure::Poisoned(SynapseError::new(
                    RefusalCode::WalTornFrame,
                    format!("injected fault: torn WAL v2 batch write ({n} bytes)"),
                )));
            }
        };
        match res {
            Ok(()) => {
                self.write_offset = at + buf.len() as u64;
                Ok(())
            }
            Err(e) => {
                let err = fail(e);
                let zeros = vec![0u8; buf.len()];
                let rollback = if fault == BatchIoFault::FailSyncAndRollback {
                    Err(injected("rollback write failed"))
                } else {
                    self.file
                        .write_all_at(&zeros, at)
                        .and_then(|_| self.file.sync_data())
                };
                match rollback {
                    Ok(()) => Err(BatchFailure::RolledBack(err)),
                    Err(re) => Err(BatchFailure::Poisoned(SynapseError::new(
                        RefusalCode::IoFailure,
                        format!(
                            "{}; rollback failed: {re}; the outcome is unknown (the batch may be durable): reopen, then retry with the same idempotency key",
                            err.message
                        ),
                    ))),
                }
            }
        }
    }

    /// Empty the log after a checkpoint and pre-write one chunk again.
    pub fn reset(&mut self) -> SynapseResult<()> {
        self.file.set_len(0).map_err(io_err)?;
        self.file.sync_all().map_err(io_err)?;
        self.write_offset = 0;
        self.prewritten_end = 0;
        self.ensure_space(WAL_V2_ALIGN).map_err(io_err)
    }

    pub fn sync(&self) -> SynapseResult<()> {
        self.file.sync_data().map_err(io_err)
    }
}

/// A batch read back during recovery.
pub(crate) struct RecoveredFrame {
    pub seq: WalSeq,
    pub frame_sha256: [u8; 32],
    pub codec: RecordCodec,
    pub record: WalRecord,
    /// Inline blobs: (digest, absolute file offset, length).
    pub inline: Vec<(BlobDigest, u64, u32)>,
}

/// Validate the batch at `off`; on success return its frames and the aligned next offset.
pub(crate) fn validate_batch(
    buf: &[u8],
    off: usize,
    mut expected_seq: WalSeq,
    mut prev_sha: [u8; 32],
    cap: u64,
) -> SynapseResult<(Vec<RecoveredFrame>, usize)> {
    let torn = |what: &str| {
        SynapseError::new(
            RefusalCode::WalTornFrame,
            format!("torn WAL v2 batch at byte offset {off}: {what}"),
        )
    };
    let header = buf
        .get(off..off + WAL_V2_BATCH_HEADER_LEN)
        .ok_or_else(|| torn("batch header past end of file"))?;
    let (count, body_len, first_seq) = parse_batch_header(header).ok_or_else(|| {
        SynapseError::new(
            RefusalCode::WalMagicInvalid,
            format!("invalid WAL v2 batch header at byte offset {off}"),
        )
    })?;
    let body_start = off + WAL_V2_BATCH_HEADER_LEN;
    let body_end = body_start
        .checked_add(usize::try_from(body_len).map_err(|_| torn("body length overflow"))?)
        .ok_or_else(|| torn("body length overflow"))?;
    if body_end > buf.len() {
        return Err(torn("batch body past end of file"));
    }
    if first_seq != expected_seq {
        return Err(SynapseError::new(
            RefusalCode::WalSequenceGap,
            format!("WAL v2 batch at {off} starts at {first_seq}, expected {expected_seq}"),
        ));
    }
    let mut frames = Vec::with_capacity(count as usize);
    let mut at = body_start;
    for _ in 0..count {
        let h = buf
            .get(at..at + WAL_HEADER_LEN)
            .filter(|_| at + WAL_HEADER_LEN <= body_end)
            .ok_or_else(|| torn("frame header past batch end"))?;
        if h[0..4] != WAL_MAGIC {
            return Err(SynapseError::new(
                RefusalCode::WalMagicInvalid,
                format!("invalid WAL magic at byte offset {at}"),
            ));
        }
        let version = u16::from_le_bytes([h[4], h[5]]);
        if version != WAL_V2_VERSION {
            return Err(SynapseError::new(
                RefusalCode::WalVersionUnsupported,
                format!("frame version {version} inside a WAL v2 batch at offset {at}"),
            ));
        }
        let codec = RecordCodec::from_frame_flags(h[7]).ok_or_else(|| {
            SynapseError::new(
                RefusalCode::WalFlagsNonZero,
                format!("unknown WAL flags {} at offset {at}", h[7]),
            )
        })?;
        let seq = WalSeq(u64::from_le_bytes(h[8..16].try_into().expect("8")));
        let prev: [u8; 32] = h[16..48].try_into().expect("32");
        let payload_len = u32::from_le_bytes(h[48..52].try_into().expect("4")) as usize;
        let crc = u32::from_le_bytes(h[52..56].try_into().expect("4"));
        let stored_sha: [u8; 32] = h[56..88].try_into().expect("32");
        if payload_len as u64 > cap {
            return Err(SynapseError::new(
                RefusalCode::QuotaPayloadTooLarge,
                format!("WAL v2 frame at offset {at} declares {payload_len} payload bytes, above the cap {cap}"),
            ));
        }
        let p_start = at + WAL_HEADER_LEN;
        let p_end = p_start + payload_len;
        if p_end > body_end {
            return Err(torn("frame payload past batch end"));
        }
        if seq != expected_seq {
            return Err(SynapseError::new(
                RefusalCode::WalSequenceGap,
                format!(
                    "WAL sequence mismatch at offset {at}: expected {expected_seq}, found {seq}"
                ),
            ));
        }
        if prev != prev_sha {
            return Err(SynapseError::new(
                RefusalCode::WalChainMismatch,
                format!("WAL prev_frame_sha256 mismatch at {seq}"),
            ));
        }
        let payload = &buf[p_start..p_end];
        let actual_crc = crc32c(payload);
        if actual_crc != crc {
            return Err(SynapseError::new(
                RefusalCode::WalCrcMismatch,
                format!(
                    "WAL payload CRC32C mismatch at {seq}: expected {crc:#x}, computed {actual_crc:#x}"
                ),
            ));
        }
        if frame_digest(&h[0..56], &payload_digest(payload)) != stored_sha {
            return Err(SynapseError::new(
                RefusalCode::WalChainMismatch,
                format!("WAL frame_sha256 mismatch at {seq}"),
            ));
        }
        let decoded = decode_payload(seq, payload, codec, cap)?;
        if decoded.record.kind_byte() != h[6] {
            return Err(match codec {
                RecordCodec::JsonV1 => corrupt(seq, "record kind byte does not match payload"),
                RecordCodec::BinaryV2 => SynapseError::new(
                    RefusalCode::WalRecordMalformed,
                    format!("record kind byte does not match payload at {seq}"),
                ),
            });
        }
        frames.push(RecoveredFrame {
            seq,
            frame_sha256: stored_sha,
            codec,
            record: decoded.record,
            inline: decoded
                .inline
                .into_iter()
                .map(|(d, o, l)| (d, (p_start + o as usize) as u64, l))
                .collect(),
        });
        expected_seq = seq.next();
        prev_sha = stored_sha;
        at = p_end;
    }
    if at + WAL_V2_BATCH_TRAILER.len() != body_end {
        return Err(torn("batch body length does not match its frames"));
    }
    if buf[at..body_end] != WAL_V2_BATCH_TRAILER {
        return Err(torn("batch trailer missing or damaged"));
    }
    Ok((frames, align_up(body_end as u64) as usize))
}

/// `prev_frame_sha256` stated by the first frame of the batch at `off` (zeros when the
/// bytes are missing; validation then fails on its own).
pub(crate) fn first_frame_prev(buf: &[u8], off: usize) -> [u8; 32] {
    let at = off + WAL_V2_BATCH_HEADER_LEN;
    buf.get(at + 16..at + 48)
        .and_then(|s| s.try_into().ok())
        .unwrap_or([0u8; 32])
}

/// True when any 4 KiB-aligned offset at or after `from` holds a valid batch header.
pub(crate) fn valid_batch_after(buf: &[u8], from: usize) -> bool {
    let mut o = align_up(from as u64) as usize;
    while o + WAL_V2_BATCH_HEADER_LEN <= buf.len() {
        if parse_batch_header(&buf[o..o + WAL_V2_BATCH_HEADER_LEN]).is_some() {
            return true;
        }
        o += WAL_V2_ALIGN as usize;
    }
    false
}

/// Torn-write evidence for the batch at `off` (it is invalid, and no valid batch header
/// follows it). Batches go into space that was zero and synced, one batch in flight at a
/// time, and every batch ends with the non-zero [`WAL_V2_BATCH_TRAILER`]. So:
///
/// * Readable header: torn only if the sector holding the end of the declared extent
///   reads back all zero inside the extent (that sector never reached the disk; a
///   complete batch never ends in zeros, however short that last part is), and every
///   byte after the extent is zero (nothing was written after it). A batch that ends
///   with its trailer but fails validation is corruption, never truncated, even when its
///   content holds whole zero sectors.
/// * Header past the end of the file, or a declared body past it: a short file, torn.
/// * Unreadable header: torn only if the header's whole sector is zero (lost).
///
/// Limitation: a torn write that lost a middle sector but persisted the last one is not
/// recognised as torn; recovery then fails closed even under `TruncateTornTail`.
pub(crate) fn torn_evidence(buf: &[u8], off: usize) -> bool {
    let Some(header) = buf.get(off..off + WAL_V2_BATCH_HEADER_LEN) else {
        return true;
    };
    let Some((_, body, _)) = parse_batch_header(header) else {
        let sector_end = (off + WAL_V2_SECTOR).min(buf.len());
        return buf[off..sector_end].iter().all(|b| *b == 0);
    };
    let Some(end) = usize::try_from(body)
        .ok()
        .and_then(|b| (off + WAL_V2_BATCH_HEADER_LEN).checked_add(b))
    else {
        return false;
    };
    if end > buf.len() {
        // The declared body runs past the end of the file: a short (torn) tail.
        return true;
    }
    let last_sector = ((end - 1) / WAL_V2_SECTOR * WAL_V2_SECTOR).max(off);
    let lost_end = buf[last_sector..end].iter().all(|b| *b == 0);
    let nothing_after = buf[end..].iter().all(|b| *b == 0);
    lost_end && nothing_after
}
