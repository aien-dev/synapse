//! R1 raw block segment store (ADR 0003 section 9 step 27): the A2 segment store on a
//! block device with no filesystem. The specification is `docs/R1_RAW_BLOCK_STORE.md`.
//!
//! The device is one byte range opened with `O_DIRECT` (page cache bypassed). On Linux
//! that is a dedicated partition; tests and benchmarks use a preallocated regular file at
//! a path the caller names. Nothing else is ever opened: no `/dev` scan, no globbing, no
//! derived paths. The opened device is held under an exclusive lock (`flock`, plus
//! `O_EXCL` for a block device). A device that carries a recognisable filesystem,
//! partition, or volume signature anywhere it is looked for ([`SIGNATURES`], including
//! the backup GPT header, MD RAID and ZFS labels near the end), or any other non-zero
//! byte in its label area, is refused unless the caller sets
//! [`BlockDeviceConfig::allow_foreign_signature`]. Formatting is never the default.
//!
//! On-device layout (little-endian, 4 KiB blocks):
//!
//! * `0..128 KiB` label area. Superblock copy 0 at byte 0, copy 1 at byte 4096; the rest
//!   is zero. Generation `g` is written to copy `g % 2`, so the newest valid copy and
//!   the one before it are always on the device.
//! * Two metadata regions of `meta_region_bytes` each (region 0 at 1 MiB). A metadata
//!   region holds the named objects the A2 store keeps as small files (`wal.log`,
//!   `checkpoint.v1`, `checkpoint.v2`, `wal.v2.index.*`): `"SBM1" | u32 count |
//!   count x (u16 name_len | name | u64 len | bytes)`, names strictly increasing.
//! * Segment slots from `data_offset` (1 MiB aligned): slot `k >= 1` is a 4 KiB segment
//!   header (`"SBSG" | u32 version | uuid[16] | u64 segment id | u64 segment_bytes |
//!   u32 crc32c`) followed by `segment_bytes` of segment data in the WAL v2 batch format
//!   ([`crate::wal2`]), unchanged from A2.
//!
//! Superblock (first 164 bytes of its 4 KiB block, rest zero): `"SYNBLKS1" | u32 version
//! | u32 block | uuid[16] | u64 generation | u64 device_bytes | u64 meta_offset0 | u64
//! meta_offset1 | u64 meta_region_bytes | u64 data_offset | u64 slot_stride | u64
//! segment_bytes | u64 slot_count | u64 segment_count | u64 meta_len | u8 meta_slot |
//! 7 zero bytes | meta_sha256[32] | u32 crc32c(preceding 160 bytes)`, where `meta_sha256
//! = SHA-256("SYNAPSE_BLOCK_META_V1\0" || meta bytes)`.
//!
//! Durability (one `fdatasync` of the device per step; on a block device that is a
//! FLUSH of the drive's volatile cache):
//!
//! * Metadata commit (the A2 "temp file, sync, rename, directory sync"): write the whole
//!   new namespace into the region no valid superblock copy points at, write superblock
//!   generation `g + 1` into copy `(g + 1) % 2`, `fdatasync`. Recovery takes the newest
//!   copy whose CRC holds and whose region matches its digest, else the older copy,
//!   whose region was not touched. One flush suffices because a superblock without its
//!   region is detected and skipped.
//! * Segment rotation (the A2 "create, sync, directory flush"): zero the whole data area,
//!   `fdatasync`; write the slot header, `fdatasync`; then a superblock-only commit
//!   raises `segment_count`, `fdatasync`. Only then does a batch go into the slot. A slot
//!   past `segment_count` is never data: without a valid header its bytes are ignored
//!   (they may be stale from earlier use of the device) and the next rotation zeroes it.
//!   A valid header always sits on a zeroed slot, so slot `segment_count + 1` with a valid
//!   header and any non-zero byte means its commit was flushed and the superblock copy
//!   in use is older than the newest: mount refuses it (`CheckpointCorrupt`) rather than
//!   drop the changes acknowledged there.
//! * Batch: one aligned positioned write plus one `fdatasync` (unchanged from A2).

use super::*;
use std::os::unix::fs::{FileExt, FileTypeExt, MetadataExt, OpenOptionsExt};
use std::sync::{Arc, Mutex};

/// I/O block size: offsets, lengths and buffers of `O_DIRECT` transfers are multiples of it.
pub const BLOCK: u64 = 4096;
/// Superblock magic.
pub const SUPERBLOCK_MAGIC: [u8; 8] = *b"SYNBLKS1";
/// Superblock format version.
pub const SUPERBLOCK_VERSION: u32 = 1;
/// Label area at the start of the device: superblocks plus zeros. It covers the
/// start-of-device offsets of the common signatures; [`classify_device`] also checks the
/// ones further in and near the end of the device.
pub const LABEL_BYTES: u64 = 128 * 1024;
/// Segment header magic.
pub const SEGMENT_HEADER_MAGIC: [u8; 4] = *b"SBSG";
/// Metadata region magic.
pub const META_MAGIC: [u8; 4] = *b"SBM1";
/// Domain tag of the metadata digest.
pub const DOMAIN_BLOCK_META: &[u8] = b"SYNAPSE_BLOCK_META_V1\0";
/// Default size of each of the two metadata regions.
pub const DEFAULT_META_REGION_BYTES: u64 = 64 << 20;
/// Byte offset of metadata region 0.
const META_START: u64 = 1 << 20;
/// Bytes zeroed per write when a segment slot is cleared.
const ZERO_CHUNK: usize = 1 << 20;
const SB_LEN: usize = 164;

const fn align_up(x: u64, a: u64) -> u64 {
    x.div_ceil(a) * a
}

fn refuse(msg: impl Into<String>) -> SynapseError {
    SynapseError::new(RefusalCode::IoFailure, msg.into())
}

fn corrupt(msg: impl Into<String>) -> SynapseError {
    SynapseError::new(RefusalCode::CheckpointCorrupt, msg.into())
}

// --- device I/O ----------------------------------------------------------------

/// Byte-addressed device I/O. Implementations may require nothing of the caller's
/// alignment; [`DirectFile`] turns every call into aligned `O_DIRECT` transfers.
pub trait BlockIo: Send + Sync + std::fmt::Debug {
    /// Device length in bytes.
    fn len(&self) -> u64;
    /// True when the device has no bytes.
    fn is_empty(&self) -> bool {
        self.len() == 0
    }
    /// Read exactly `buf.len()` bytes at `off`.
    fn read_at(&self, buf: &mut [u8], off: u64) -> std::io::Result<()>;
    /// Write all of `data` at `off`. Not durable until [`BlockIo::flush`] returns.
    fn write_at(&self, data: &[u8], off: u64) -> std::io::Result<()>;
    /// Make every completed write durable (`fdatasync`).
    fn flush(&self) -> std::io::Result<()>;
}

/// A heap buffer whose usable part starts at a [`BLOCK`]-aligned address (safe Rust:
/// the start is found with `align_offset` inside an over-allocated `Vec`).
struct AlignedBuf {
    raw: Vec<u8>,
    start: usize,
    len: usize,
}

impl AlignedBuf {
    fn zeroed(len: usize) -> Self {
        let raw = vec![0u8; len + BLOCK as usize];
        let start = raw.as_ptr().align_offset(BLOCK as usize);
        assert!(start <= BLOCK as usize, "alignment offset out of range");
        Self { raw, start, len }
    }
    fn as_slice(&self) -> &[u8] {
        &self.raw[self.start..self.start + self.len]
    }
    fn as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.raw[self.start..self.start + self.len]
    }
}

const O_DIRECT: i32 = libc::O_DIRECT;

/// The device opened with `O_DIRECT`: a dedicated partition, or for tests and benchmarks a
/// preallocated regular file. Unaligned requests are served through aligned bounce
/// buffers (read-modify-write of the edge blocks for writes); the store's batch, zeroing,
/// header and metadata writes are all block-aligned.
#[derive(Debug)]
pub struct DirectFile {
    file: File,
    len: u64,
}

impl DirectFile {
    /// Open exactly `path` (absolute; a regular file or a block device, nothing else).
    /// A block device is opened with `O_EXCL`, so the kernel refuses one that is mounted
    /// or held by another opener. The opened file must be the one `path` named when it
    /// was checked (same device and inode). The opened file is held under an exclusive
    /// advisory lock (`flock`): a second opener is refused while this one lives.
    pub fn open(path: &Path) -> SynapseResult<Self> {
        Self::open_with(path, true)
    }

    /// Test inspection only: open without taking the lock (the A2 suite shim reads the
    /// device while the store under test holds it).
    #[cfg(test)]
    pub(crate) fn open_unlocked(path: &Path) -> SynapseResult<Self> {
        Self::open_with(path, false)
    }

    fn open_with(path: &Path, lock: bool) -> SynapseResult<Self> {
        if !path.is_absolute() {
            return Err(refuse(format!(
                "block device path must be absolute: {}",
                path.display()
            )));
        }
        // `symlink_metadata` plus `O_NOFOLLOW`: a symbolic link is refused, so the path
        // opened is the configured one and never a link target.
        let meta = fs::symlink_metadata(path)
            .map_err(|e| refuse(format!("block device {}: {e}", path.display())))?;
        let ft = meta.file_type();
        let is_block = ft.is_block_device();
        if !is_block && !ft.is_file() {
            return Err(refuse(format!(
                "{} is neither a block device nor a regular file (symbolic links are refused)",
                path.display()
            )));
        }
        let mut flags = O_DIRECT | libc::O_NOFOLLOW;
        if is_block {
            flags |= libc::O_EXCL;
        }
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(flags)
            .open(path)
            .map_err(|e| refuse(format!("open {} with O_DIRECT: {e}", path.display())))?;
        let opened = file.metadata().map_err(io_err)?;
        if opened.dev() != meta.dev() || opened.ino() != meta.ino() || opened.rdev() != meta.rdev()
        {
            return Err(refuse(format!(
                "{} changed between the check and the open",
                path.display()
            )));
        }
        // One opener at a time: an exclusive advisory lock (flock) on the opened file, on
        // top of O_EXCL for block devices. A second store on the same device would
        // overwrite the first one's slots and metadata.
        match if lock { file.try_lock() } else { Ok(()) } {
            Ok(()) => {}
            Err(fs::TryLockError::WouldBlock) => {
                return Err(refuse(format!(
                    "{} is in use: another opener holds its exclusive lock",
                    path.display()
                )))
            }
            Err(fs::TryLockError::Error(e)) => {
                return Err(refuse(format!("lock {}: {e}", path.display())))
            }
        }
        let len = if is_block {
            use std::io::Seek;
            let mut f = &file;
            f.seek(SeekFrom::End(0)).map_err(io_err)?
        } else {
            opened.len()
        };
        if len % BLOCK != 0 {
            return Err(refuse(format!(
                "{}: length {len} is not a multiple of {BLOCK}",
                path.display()
            )));
        }
        Ok(Self { file, len })
    }
}

impl BlockIo for DirectFile {
    fn len(&self) -> u64 {
        self.len
    }

    fn read_at(&self, buf: &mut [u8], off: u64) -> std::io::Result<()> {
        if buf.is_empty() {
            return Ok(());
        }
        let end = off
            .checked_add(buf.len() as u64)
            .filter(|e| *e <= self.len)
            .ok_or_else(|| std::io::Error::other("read past the end of the device"))?;
        let a = off / BLOCK * BLOCK;
        let b = align_up(end, BLOCK);
        let mut bounce = AlignedBuf::zeroed((b - a) as usize);
        self.file.read_exact_at(bounce.as_mut_slice(), a)?;
        let at = (off - a) as usize;
        buf.copy_from_slice(&bounce.as_slice()[at..at + buf.len()]);
        Ok(())
    }

    fn write_at(&self, data: &[u8], off: u64) -> std::io::Result<()> {
        if data.is_empty() {
            return Ok(());
        }
        let end = off
            .checked_add(data.len() as u64)
            .filter(|e| *e <= self.len)
            .ok_or_else(|| std::io::Error::other("write past the end of the device"))?;
        let a = off / BLOCK * BLOCK;
        let b = align_up(end, BLOCK);
        let mut bounce = AlignedBuf::zeroed((b - a) as usize);
        let s = bounce.as_mut_slice();
        // Read-modify-write of partly covered edge blocks.
        if off != a {
            self.file.read_exact_at(&mut s[..BLOCK as usize], a)?;
        }
        if end != b && (b - BLOCK >= a + BLOCK || off == a) {
            let last = s.len() - BLOCK as usize;
            self.file.read_exact_at(&mut s[last..], b - BLOCK)?;
        }
        let at = (off - a) as usize;
        s[at..at + data.len()].copy_from_slice(data);
        self.file.write_all_at(bounce.as_slice(), a)
    }

    fn flush(&self) -> std::io::Result<()> {
        self.file.sync_data()
    }
}

// --- label classification -------------------------------------------------------

/// What a device holds before Synapse touches it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeviceLabel {
    /// Every byte of the label area is zero and no known signature is anywhere.
    Blank,
    /// A Synapse superblock magic is present at byte 0 or 4096 (valid or not).
    Synapse,
    /// A recognised filesystem, partition table, or volume signature.
    Foreign(&'static str),
    /// Non-zero bytes in the label area that match no known signature.
    Unknown,
}

/// Where a signature sits on a device of `len` bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SigAt {
    /// Byte offset from the start.
    Start(u64),
    /// Bytes before the end.
    End(u64),
    /// Linux MD RAID 0.90 superblock: `(len & !(64 KiB - 1)) - 64 KiB`.
    Md090,
    /// Linux MD RAID 1.0 superblock: `(len - 8 KiB) & !(4 KiB - 1)`.
    Md10,
    /// ZFS vdev label `n` (L0 at 0, L1 at 256 KiB, L2 and L3 at 512 KiB and 256 KiB
    /// below the length rounded down to 256 KiB): any 1 KiB uberblock slot of its
    /// 128 KiB uberblock array (label offset 128 KiB).
    ZfsLabel(u8),
}

/// One recognised signature.
#[derive(Debug, Clone, Copy)]
pub struct Signature {
    pub name: &'static str,
    pub at: SigAt,
    pub magic: &'static [u8],
}

const fn sig(name: &'static str, at: SigAt, magic: &'static [u8]) -> Signature {
    Signature { name, at, magic }
}

const MD_MAGIC: &[u8] = &[0xFC, 0x4E, 0x2B, 0xA9];
const ZFS_UB_LE: &[u8] = &[0x0C, 0xB1, 0xBA, 0, 0, 0, 0, 0];
const ZFS_UB_BE: &[u8] = &[0, 0, 0, 0, 0, 0xBA, 0xB1, 0x0C];
const KIB: u64 = 1024;

/// Every signature that makes a device foreign, in the order they are checked (the
/// first match names the refusal). Each entry is pinned by its own test.
pub const SIGNATURES: &[Signature] = &[
    sig("GPT partition table", SigAt::Start(512), b"EFI PART"),
    sig(
        "GPT partition table (4 KiB sectors)",
        SigAt::Start(4096),
        b"EFI PART",
    ),
    sig("GPT backup header", SigAt::End(512), b"EFI PART"),
    sig(
        "GPT backup header (4 KiB sectors)",
        SigAt::End(4096),
        b"EFI PART",
    ),
    sig("ext2/ext3/ext4", SigAt::Start(1080), &[0x53, 0xEF]),
    sig("XFS", SigAt::Start(0), b"XFSB"),
    sig("btrfs", SigAt::Start(0x1_0040), b"_BHRfS_M"),
    sig(
        "btrfs (mirror at 64 MiB)",
        SigAt::Start(0x400_0040),
        b"_BHRfS_M",
    ),
    sig(
        "btrfs (mirror at 256 GiB)",
        SigAt::Start(0x40_0000_0040),
        b"_BHRfS_M",
    ),
    sig("NTFS", SigAt::Start(3), b"NTFS    "),
    sig("exFAT", SigAt::Start(3), b"EXFAT   "),
    sig("FAT12/FAT16", SigAt::Start(54), b"FAT1"),
    sig("FAT32", SigAt::Start(82), b"FAT32   "),
    sig("LUKS", SigAt::Start(0), b"LUKS\xba\xbe"),
    sig(
        "LVM2 physical volume (sector 0)",
        SigAt::Start(0),
        b"LABELONE",
    ),
    sig(
        "LVM2 physical volume (sector 1)",
        SigAt::Start(512),
        b"LABELONE",
    ),
    sig(
        "LVM2 physical volume (sector 2)",
        SigAt::Start(1024),
        b"LABELONE",
    ),
    sig(
        "LVM2 physical volume (sector 3)",
        SigAt::Start(1536),
        b"LABELONE",
    ),
    sig(
        "Linux swap (4 KiB pages)",
        SigAt::Start(4096 - 10),
        b"SWAPSPACE2",
    ),
    sig(
        "Linux swap, old (4 KiB pages)",
        SigAt::Start(4096 - 10),
        b"SWAP-SPACE",
    ),
    sig(
        "Linux swap (16 KiB pages)",
        SigAt::Start(16384 - 10),
        b"SWAPSPACE2",
    ),
    sig(
        "Linux swap (64 KiB pages)",
        SigAt::Start(65536 - 10),
        b"SWAPSPACE2",
    ),
    sig("ISO 9660", SigAt::Start(0x8001), b"CD001"),
    sig("squashfs", SigAt::Start(0), b"hsqs"),
    sig("F2FS", SigAt::Start(1024), &[0x10, 0x20, 0xF5, 0xF2]),
    sig("Linux MD RAID (1.2)", SigAt::Start(4096), MD_MAGIC),
    sig("Linux MD RAID (1.1)", SigAt::Start(0), MD_MAGIC),
    sig("Linux MD RAID (1.0)", SigAt::Md10, MD_MAGIC),
    sig("Linux MD RAID (0.90)", SigAt::Md090, MD_MAGIC),
    sig("ZFS label L0", SigAt::ZfsLabel(0), ZFS_UB_LE),
    sig("ZFS label L0 (big-endian)", SigAt::ZfsLabel(0), ZFS_UB_BE),
    sig("ZFS label L1", SigAt::ZfsLabel(1), ZFS_UB_LE),
    sig("ZFS label L1 (big-endian)", SigAt::ZfsLabel(1), ZFS_UB_BE),
    sig("ZFS label L2", SigAt::ZfsLabel(2), ZFS_UB_LE),
    sig("ZFS label L2 (big-endian)", SigAt::ZfsLabel(2), ZFS_UB_BE),
    sig("ZFS label L3", SigAt::ZfsLabel(3), ZFS_UB_LE),
    sig("ZFS label L3 (big-endian)", SigAt::ZfsLabel(3), ZFS_UB_BE),
    sig("MBR or boot sector", SigAt::Start(510), &[0x55, 0xAA]),
];

impl Signature {
    /// Whether this signature is on `io`.
    pub fn found(&self, io: &dyn BlockIo) -> std::io::Result<bool> {
        let len = io.len();
        let n = self.magic.len() as u64;
        let at = |off: Option<u64>| -> std::io::Result<bool> {
            match off.filter(|o| o.checked_add(n).is_some_and(|e| e <= len)) {
                Some(o) => {
                    let mut b = vec![0u8; n as usize];
                    io.read_at(&mut b, o)?;
                    Ok(b == self.magic)
                }
                None => Ok(false),
            }
        };
        match self.at {
            SigAt::Start(o) => at(Some(o)),
            SigAt::End(b) => at(len.checked_sub(b)),
            SigAt::Md090 => at((len & !(64 * KIB - 1)).checked_sub(64 * KIB)),
            SigAt::Md10 => at(len.checked_sub(8 * KIB).map(|o| o & !(4 * KIB - 1))),
            SigAt::ZfsLabel(l) => {
                let end = len & !(256 * KIB - 1);
                let base = match l {
                    0 => Some(0),
                    1 => Some(256 * KIB),
                    2 => end.checked_sub(512 * KIB),
                    _ => end.checked_sub(256 * KIB),
                };
                let Some(arr) = base.map(|b| b + 128 * KIB) else {
                    return Ok(false);
                };
                if arr + 128 * KIB > len {
                    return Ok(false);
                }
                let mut b = vec![0u8; (128 * KIB) as usize];
                io.read_at(&mut b, arr)?;
                Ok(b.chunks(KIB as usize).any(|s| s.starts_with(self.magic)))
            }
        }
    }
}

/// Classify a device: its label area (the first [`LABEL_BYTES`]) and every
/// [`SIGNATURES`] location, including the ones near the end of the device.
pub fn classify_device(io: &dyn BlockIo) -> std::io::Result<DeviceLabel> {
    let mut label = vec![0u8; LABEL_BYTES.min(io.len()) as usize];
    io.read_at(&mut label, 0)?;
    let at =
        |off: usize| label.get(off..off + SUPERBLOCK_MAGIC.len()) == Some(&SUPERBLOCK_MAGIC[..]);
    if at(0) || at(BLOCK as usize) {
        return Ok(DeviceLabel::Synapse);
    }
    for s in SIGNATURES {
        if s.found(io)? {
            return Ok(DeviceLabel::Foreign(s.name));
        }
    }
    Ok(if label.iter().all(|b| *b == 0) {
        DeviceLabel::Blank
    } else {
        DeviceLabel::Unknown
    })
}

// --- superblock -----------------------------------------------------------------

/// Fixed geometry of a formatted device.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Geometry {
    pub uuid: [u8; 16],
    pub device_bytes: u64,
    pub meta_offset: [u64; 2],
    pub meta_region_bytes: u64,
    pub data_offset: u64,
    pub slot_stride: u64,
    pub segment_bytes: u64,
    pub slot_count: u64,
}

impl Geometry {
    fn new(
        uuid: [u8; 16],
        device_bytes: u64,
        meta_region_bytes: u64,
        segment_bytes: u64,
    ) -> SynapseResult<Self> {
        let meta_region_bytes = align_up(meta_region_bytes.max(BLOCK), BLOCK);
        let segment_bytes = align_up(segment_bytes.max(BLOCK), BLOCK);
        let meta_offset = [META_START, META_START + meta_region_bytes];
        let data_offset = align_up(meta_offset[1] + meta_region_bytes, 1 << 20);
        let slot_stride = BLOCK + segment_bytes;
        let slot_count = device_bytes.saturating_sub(data_offset) / slot_stride;
        if slot_count < 2 {
            return Err(refuse(format!(
                "device of {device_bytes} bytes holds {slot_count} segment slots of {segment_bytes} bytes after {data_offset} bytes of label and metadata; at least 2 are needed"
            )));
        }
        Ok(Self {
            uuid,
            device_bytes,
            meta_offset,
            meta_region_bytes,
            data_offset,
            slot_stride,
            segment_bytes,
            slot_count,
        })
    }

    /// Byte offset of slot `id`'s header (`1 <= id <= slot_count`).
    pub fn slot_offset(&self, id: u64) -> u64 {
        self.data_offset + (id - 1) * self.slot_stride
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Superblock {
    geo: Geometry,
    generation: u64,
    segment_count: u64,
    meta_len: u64,
    meta_slot: u8,
    meta_sha256: [u8; 32],
}

fn meta_digest(bytes: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(DOMAIN_BLOCK_META);
    h.update(bytes);
    h.finalize().into()
}

impl Superblock {
    fn encode(&self) -> Vec<u8> {
        let g = &self.geo;
        let mut b = Vec::with_capacity(BLOCK as usize);
        b.extend_from_slice(&SUPERBLOCK_MAGIC);
        b.extend_from_slice(&SUPERBLOCK_VERSION.to_le_bytes());
        b.extend_from_slice(&(BLOCK as u32).to_le_bytes());
        b.extend_from_slice(&g.uuid);
        for v in [
            self.generation,
            g.device_bytes,
            g.meta_offset[0],
            g.meta_offset[1],
            g.meta_region_bytes,
            g.data_offset,
            g.slot_stride,
            g.segment_bytes,
            g.slot_count,
            self.segment_count,
            self.meta_len,
        ] {
            b.extend_from_slice(&v.to_le_bytes());
        }
        b.push(self.meta_slot);
        b.extend_from_slice(&[0u8; 7]);
        b.extend_from_slice(&self.meta_sha256);
        let crc = crc32c(&b);
        b.extend_from_slice(&crc.to_le_bytes());
        debug_assert_eq!(b.len(), SB_LEN);
        b.resize(BLOCK as usize, 0);
        b
    }

    /// Strict decoder; `None` for anything but a valid superblock.
    fn decode(b: &[u8]) -> Option<Self> {
        if b.len() < BLOCK as usize || b[0..8] != SUPERBLOCK_MAGIC {
            return None;
        }
        let crc = u32::from_le_bytes(b[160..164].try_into().ok()?);
        if crc32c(&b[..160]) != crc || b[SB_LEN..BLOCK as usize].iter().any(|x| *x != 0) {
            return None;
        }
        let u32_at = |at: usize| u32::from_le_bytes(b[at..at + 4].try_into().expect("4"));
        let u64_at = |at: usize| u64::from_le_bytes(b[at..at + 8].try_into().expect("8"));
        if u32_at(8) != SUPERBLOCK_VERSION || u64::from(u32_at(12)) != BLOCK {
            return None;
        }
        if b[121..128].iter().any(|x| *x != 0) || b[120] > 1 {
            return None;
        }
        let uuid: [u8; 16] = b[16..32].try_into().ok()?;
        let sb = Self {
            geo: Geometry {
                uuid,
                device_bytes: u64_at(40),
                meta_offset: [u64_at(48), u64_at(56)],
                meta_region_bytes: u64_at(64),
                data_offset: u64_at(72),
                slot_stride: u64_at(80),
                segment_bytes: u64_at(88),
                slot_count: u64_at(96),
            },
            generation: u64_at(32),
            segment_count: u64_at(104),
            meta_len: u64_at(112),
            meta_slot: b[120],
            meta_sha256: b[128..160].try_into().ok()?,
        };
        // The geometry must be the one `Geometry::new` derives from its own inputs.
        let expect = Geometry::new(
            uuid,
            sb.geo.device_bytes,
            sb.geo.meta_region_bytes,
            sb.geo.segment_bytes,
        )
        .ok()?;
        if expect != sb.geo
            || sb.meta_len > sb.geo.meta_region_bytes
            || sb.segment_count > sb.geo.slot_count
            || sb.generation == 0
        {
            return None;
        }
        Some(sb)
    }
}

fn encode_meta(names: &BTreeMap<String, Vec<u8>>) -> Vec<u8> {
    let mut b = Vec::new();
    b.extend_from_slice(&META_MAGIC);
    b.extend_from_slice(&(names.len() as u32).to_le_bytes());
    for (name, bytes) in names {
        b.extend_from_slice(&(name.len() as u16).to_le_bytes());
        b.extend_from_slice(name.as_bytes());
        b.extend_from_slice(&(bytes.len() as u64).to_le_bytes());
        b.extend_from_slice(bytes);
    }
    b
}

fn decode_meta(b: &[u8]) -> Option<BTreeMap<String, Vec<u8>>> {
    let take = |at: &mut usize, n: usize| -> Option<&[u8]> {
        let s = b.get(*at..at.checked_add(n)?)?;
        *at += n;
        Some(s)
    };
    let mut at = 0usize;
    if take(&mut at, 4)? != META_MAGIC {
        return None;
    }
    let count = u32::from_le_bytes(take(&mut at, 4)?.try_into().ok()?);
    let mut names = BTreeMap::new();
    let mut prev: Option<String> = None;
    for _ in 0..count {
        let nl = u16::from_le_bytes(take(&mut at, 2)?.try_into().ok()?) as usize;
        let name = std::str::from_utf8(take(&mut at, nl)?).ok()?.to_string();
        if name.is_empty() || prev.as_ref().is_some_and(|p| *p >= name) {
            return None;
        }
        let len = usize::try_from(u64::from_le_bytes(take(&mut at, 8)?.try_into().ok()?)).ok()?;
        let bytes = take(&mut at, len)?.to_vec();
        prev = Some(name.clone());
        names.insert(name, bytes);
    }
    (at == b.len()).then_some(names)
}

fn segment_header(geo: &Geometry, id: u64) -> Vec<u8> {
    let mut b = Vec::with_capacity(BLOCK as usize);
    b.extend_from_slice(&SEGMENT_HEADER_MAGIC);
    b.extend_from_slice(&1u32.to_le_bytes());
    b.extend_from_slice(&geo.uuid);
    b.extend_from_slice(&id.to_le_bytes());
    b.extend_from_slice(&geo.segment_bytes.to_le_bytes());
    let crc = crc32c(&b);
    b.extend_from_slice(&crc.to_le_bytes());
    b.resize(BLOCK as usize, 0);
    b
}

// --- the device -------------------------------------------------------------------

/// How [`BlockDevice::open`] treats a device without a Synapse superblock.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FormatPolicy {
    /// Open only a device that already holds a Synapse store.
    OpenExisting,
    /// Format a blank device (label area all zero); open an existing store as it is.
    FormatIfBlank,
}

/// Where and how to open the raw block store.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockDeviceConfig {
    /// The one device path this store may open (absolute). Nothing else is opened.
    pub path: PathBuf,
    /// Treatment of a device without a Synapse superblock.
    pub format: FormatPolicy,
    /// Size of each of the two metadata regions, used when formatting.
    pub meta_region_bytes: u64,
    /// Format over a recognised filesystem/partition signature or other non-zero label
    /// bytes. Destroys what was there; never set it for a device you have not checked.
    pub allow_foreign_signature: bool,
}

impl BlockDeviceConfig {
    /// Open the existing store at `path`: no formatting (set [`FormatPolicy::FormatIfBlank`]
    /// to format a blank device deliberately), default metadata regions, no override.
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
            format: FormatPolicy::OpenExisting,
            meta_region_bytes: DEFAULT_META_REGION_BYTES,
            allow_foreign_signature: false,
        }
    }
}

#[derive(Debug)]
struct MetaState {
    generation: u64,
    meta_slot: u8,
    segment_count: u64,
    names: BTreeMap<String, Vec<u8>>,
}

/// An opened raw block store device: geometry, the committed metadata namespace and
/// segment count, and the segment slots.
#[derive(Debug)]
pub struct BlockDevice {
    io: Box<dyn BlockIo>,
    geo: Geometry,
    state: Mutex<MetaState>,
}

fn new_uuid(io: &dyn BlockIo) -> [u8; 16] {
    let mut h = Sha256::new();
    h.update(b"SYNAPSE_BLOCK_UUID_V1\0");
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    h.update(now.to_le_bytes());
    h.update(std::process::id().to_le_bytes());
    h.update(io.len().to_le_bytes());
    let d: [u8; 32] = h.finalize().into();
    d[..16].try_into().expect("16")
}

impl BlockDevice {
    /// Open the device at `cfg.path` with `O_DIRECT`. `segment_bytes` is used only when
    /// a blank device is formatted; an existing store keeps its own.
    pub fn open_path(cfg: &BlockDeviceConfig, segment_bytes: u64) -> SynapseResult<Arc<Self>> {
        let io = DirectFile::open(&cfg.path)?;
        Self::open(Box::new(io), cfg, segment_bytes)
    }

    /// Test inspection only: [`Self::open_path`] without the exclusive lock.
    #[cfg(test)]
    pub(crate) fn open_path_unlocked(cfg: &BlockDeviceConfig) -> SynapseResult<Arc<Self>> {
        let io = DirectFile::open_unlocked(&cfg.path)?;
        Self::open(Box::new(io), cfg, 0)
    }

    /// Open (or format, per `cfg`) the store on `io`.
    pub fn open(
        io: Box<dyn BlockIo>,
        cfg: &BlockDeviceConfig,
        segment_bytes: u64,
    ) -> SynapseResult<Arc<Self>> {
        if io.len() < LABEL_BYTES {
            return Err(refuse(format!(
                "device of {} bytes is smaller than the label area",
                io.len()
            )));
        }
        match classify_device(io.as_ref()).map_err(io_err)? {
            DeviceLabel::Synapse => {}
            DeviceLabel::Blank if cfg.format == FormatPolicy::FormatIfBlank => {
                Self::format(io.as_ref(), cfg.meta_region_bytes, segment_bytes)?;
            }
            DeviceLabel::Blank => {
                return Err(refuse(format!(
                    "{} is blank and the format policy is OpenExisting",
                    cfg.path.display()
                )))
            }
            other if cfg.allow_foreign_signature && cfg.format == FormatPolicy::FormatIfBlank => {
                let _ = other;
                Self::format(io.as_ref(), cfg.meta_region_bytes, segment_bytes)?;
            }
            DeviceLabel::Foreign(what) => {
                return Err(refuse(format!(
                    "refusing {}: it carries a {what} signature (set allow_foreign_signature to format over it)",
                    cfg.path.display()
                )))
            }
            DeviceLabel::Unknown => {
                return Err(refuse(format!(
                    "refusing {}: its first {LABEL_BYTES} bytes are not blank and hold no Synapse superblock (set allow_foreign_signature to format over them)",
                    cfg.path.display()
                )))
            }
        }
        Self::mount(io)
    }

    /// Write a new, empty store: zero the label area, write an empty namespace into
    /// metadata region 0 and superblock generation 1, `fdatasync`.
    fn format(io: &dyn BlockIo, meta_region_bytes: u64, segment_bytes: u64) -> SynapseResult<()> {
        let geo = Geometry::new(new_uuid(io), io.len(), meta_region_bytes, segment_bytes)?;
        let meta = encode_meta(&BTreeMap::new());
        let sb = Superblock {
            geo,
            generation: 1,
            segment_count: 0,
            meta_len: meta.len() as u64,
            meta_slot: 0,
            meta_sha256: meta_digest(&meta),
        };
        let mut label = vec![0u8; LABEL_BYTES as usize];
        label[BLOCK as usize..2 * BLOCK as usize].copy_from_slice(&sb.encode());
        let mut region = meta;
        region.resize(align_up(region.len() as u64, BLOCK) as usize, 0);
        io.write_at(&region, geo.meta_offset[0]).map_err(io_err)?;
        io.write_at(&label, 0).map_err(io_err)?;
        io.flush().map_err(io_err)
    }

    /// Recover the committed state: the newest superblock copy whose CRC holds and whose
    /// metadata region matches its digest, else the older copy.
    fn mount(io: Box<dyn BlockIo>) -> SynapseResult<Arc<Self>> {
        let mut copies = Vec::new();
        for i in 0..2u64 {
            let mut b = vec![0u8; BLOCK as usize];
            io.read_at(&mut b, i * BLOCK).map_err(io_err)?;
            if let Some(sb) = Superblock::decode(&b) {
                if sb.generation % 2 == i {
                    copies.push(sb);
                }
            }
        }
        copies.sort_by_key(|sb| std::cmp::Reverse(sb.generation));
        if copies.len() == 2 && copies[0].geo != copies[1].geo {
            return Err(corrupt(
                "the two superblock copies disagree on the geometry",
            ));
        }
        for sb in copies {
            if sb.geo.device_bytes > io.len() {
                return Err(corrupt(format!(
                    "superblock describes {} bytes, device has {}",
                    sb.geo.device_bytes,
                    io.len()
                )));
            }
            let mut meta = vec![0u8; sb.meta_len as usize];
            io.read_at(&mut meta, sb.geo.meta_offset[sb.meta_slot as usize])
                .map_err(io_err)?;
            if meta_digest(&meta) != sb.meta_sha256 {
                continue;
            }
            let Some(names) = decode_meta(&meta) else {
                continue;
            };
            let dev = Self {
                io,
                geo: sb.geo,
                state: Mutex::new(MetaState {
                    generation: sb.generation,
                    meta_slot: sb.meta_slot,
                    segment_count: sb.segment_count,
                    names,
                }),
            };
            dev.refuse_data_past_segment_count()?;
            return Ok(Arc::new(dev));
        }
        Err(corrupt(
            "no superblock copy with an intact metadata region (the device carries the Synapse magic but no valid store)",
        ))
    }

    /// Refuse a mount whose segment count is behind the data on the device. Slot
    /// `segment_count + 1` can hold a non-zero byte only after the commit that raised the
    /// count to it was flushed (a rotation zeroes the slot and flushes before that
    /// commit, and no batch goes in before it). So a valid header there with data means
    /// the newest superblock copy was lost (damaged) and the copy in use is older:
    /// mounting it would silently drop every change acknowledged in that slot.
    fn refuse_data_past_segment_count(&self) -> SynapseResult<()> {
        let next = self.lock().segment_count + 1;
        if !self.header_valid(next).map_err(io_err)? {
            return Ok(());
        }
        let start = self.data_offset(next);
        let mut buf = vec![0u8; (ZERO_CHUNK as u64).min(self.geo.segment_bytes) as usize];
        let mut at = 0;
        while at < self.geo.segment_bytes {
            let n = buf.len().min((self.geo.segment_bytes - at) as usize);
            self.io.read_at(&mut buf[..n], start + at).map_err(io_err)?;
            if buf[..n].iter().any(|b| *b != 0) {
                return Err(corrupt(format!(
                    "segment slot {next} holds data past the committed segment count {}: the \
                     newest superblock copy is damaged and the older copy would drop \
                     acknowledged changes",
                    next - 1
                )));
            }
            at += n as u64;
        }
        Ok(())
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, MetaState> {
        self.state.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// The device geometry.
    pub fn geometry(&self) -> Geometry {
        self.geo
    }

    /// Committed segment count (segments `1..=count` may hold data).
    pub fn segment_count(&self) -> u64 {
        self.lock().segment_count
    }

    /// Metadata region the superblock in force points at.
    #[cfg(test)]
    pub(crate) fn meta_slot(&self) -> u8 {
        self.lock().meta_slot
    }

    /// Commit generation of the superblock in force.
    pub fn generation(&self) -> u64 {
        self.lock().generation
    }

    /// `fdatasync` the device.
    pub fn flush(&self) -> std::io::Result<()> {
        self.io.flush()
    }

    /// Write a new superblock generation (and, with `names`, a new metadata region),
    /// then `fdatasync`. On failure the in-memory state is unchanged.
    fn commit(
        &self,
        st: &mut MetaState,
        names: Option<BTreeMap<String, Vec<u8>>>,
        segment_count: u64,
    ) -> std::io::Result<()> {
        let generation = st.generation + 1;
        let (meta_slot, meta) = match &names {
            Some(n) => (1 - st.meta_slot, encode_meta(n)),
            None => (st.meta_slot, encode_meta(&st.names)),
        };
        if meta.len() as u64 > self.geo.meta_region_bytes {
            return Err(std::io::Error::other(format!(
                "metadata of {} bytes does not fit the {}-byte metadata region",
                meta.len(),
                self.geo.meta_region_bytes
            )));
        }
        if names.is_some() {
            let mut region = meta.clone();
            region.resize(align_up(region.len() as u64, BLOCK) as usize, 0);
            self.io
                .write_at(&region, self.geo.meta_offset[meta_slot as usize])?;
        }
        let sb = Superblock {
            geo: self.geo,
            generation,
            segment_count,
            meta_len: meta.len() as u64,
            meta_slot,
            meta_sha256: meta_digest(&meta),
        };
        self.io.write_at(&sb.encode(), (generation % 2) * BLOCK)?;
        self.io.flush()?;
        st.generation = generation;
        st.meta_slot = meta_slot;
        st.segment_count = segment_count;
        if let Some(n) = names {
            st.names = n;
        }
        Ok(())
    }

    // --- named objects (the A2 store's small files) ---

    /// Bytes of named object `name`, if present.
    pub fn read_named(&self, name: &str) -> Option<Vec<u8>> {
        self.lock().names.get(name).cloned()
    }

    /// Names of every object, ascending.
    pub fn list_named(&self) -> Vec<String> {
        self.lock().names.keys().cloned().collect()
    }

    /// Atomically create or replace `name` (one metadata commit).
    pub fn write_named(&self, name: &str, bytes: &[u8]) -> std::io::Result<()> {
        if name.is_empty() || name.len() > usize::from(u16::MAX) {
            return Err(std::io::Error::other("invalid object name"));
        }
        let mut st = self.lock();
        let mut names = st.names.clone();
        names.insert(name.to_string(), bytes.to_vec());
        let count = st.segment_count;
        self.commit(&mut st, Some(names), count)
    }

    /// Atomically remove every object whose name satisfies `pred` (one metadata commit,
    /// none when nothing matches). Returns whether anything was removed.
    pub fn remove_named_where(&self, pred: impl Fn(&str) -> bool) -> std::io::Result<bool> {
        let mut st = self.lock();
        let mut names = st.names.clone();
        names.retain(|n, _| !pred(n));
        if names.len() == st.names.len() {
            return Ok(false);
        }
        let count = st.segment_count;
        self.commit(&mut st, Some(names), count)?;
        Ok(true)
    }

    // --- segment slots ---

    fn check_slot(&self, id: u64) -> std::io::Result<()> {
        if id == 0 || id > self.geo.slot_count {
            return Err(std::io::Error::other(format!(
                "no segment slot {id}: the device has {} slots (device full)",
                self.geo.slot_count
            )));
        }
        Ok(())
    }

    fn data_offset(&self, id: u64) -> u64 {
        self.geo.slot_offset(id) + BLOCK
    }

    /// True when slot `id` carries this store's header for segment `id`.
    pub fn header_valid(&self, id: u64) -> std::io::Result<bool> {
        if id == 0 || id > self.geo.slot_count {
            return Ok(false);
        }
        let mut b = vec![0u8; BLOCK as usize];
        self.io.read_at(&mut b, self.geo.slot_offset(id))?;
        Ok(b == segment_header(&self.geo, id))
    }

    /// Segment ids present: slots `1..=count` with a valid header, plus slot `count + 1`
    /// when it carries a header (created by a rotation that never committed). A missing
    /// id inside `1..=count` is reported by recovery as a gap.
    pub fn list_segments(&self) -> std::io::Result<Vec<u64>> {
        let count = self.segment_count();
        let mut ids = Vec::new();
        for id in 1..=count + 1 {
            if self.header_valid(id)? {
                ids.push(id);
            }
        }
        Ok(ids)
    }

    /// Segment `id`'s data from byte `from` on. A slot past the committed count is never
    /// data: it reads back empty.
    pub fn read_segment(&self, id: u64, from: u64) -> std::io::Result<Vec<u8>> {
        if id > self.segment_count() || from >= self.geo.segment_bytes {
            return Ok(Vec::new());
        }
        self.check_slot(id)?;
        let mut b = vec![0u8; (self.geo.segment_bytes - from) as usize];
        self.io.read_at(&mut b, self.data_offset(id) + from)?;
        Ok(b)
    }

    /// Read `len` bytes at `offset` of segment `id` (blob reads).
    pub fn read_segment_at(&self, id: u64, offset: u64, len: u32) -> std::io::Result<Vec<u8>> {
        self.check_slot(id)?;
        if offset + u64::from(len) > self.geo.segment_bytes {
            return Err(std::io::Error::other("read past the end of the segment"));
        }
        let mut b = vec![0u8; len as usize];
        self.io.read_at(&mut b, self.data_offset(id) + offset)?;
        Ok(b)
    }

    /// Write `data` at `offset` of segment `id` (not durable until [`Self::flush`]).
    pub fn write_segment(&self, id: u64, offset: u64, data: &[u8]) -> std::io::Result<()> {
        self.check_slot(id)?;
        if offset + data.len() as u64 > self.geo.segment_bytes {
            return Err(std::io::Error::other(format!(
                "write of {} bytes at {offset} does not fit the {}-byte segment slot",
                data.len(),
                self.geo.segment_bytes
            )));
        }
        self.io.write_at(data, self.data_offset(id) + offset)
    }

    /// Rotation step 2: write slot `id`'s header (not yet durable; the caller flushes).
    pub fn write_segment_header(&self, id: u64) -> std::io::Result<()> {
        self.check_slot(id)?;
        self.io
            .write_at(&segment_header(&self.geo, id), self.geo.slot_offset(id))
    }

    /// Rotation step 1: zero slot `id`'s whole data area, then `fdatasync`.
    pub fn zero_segment(&self, id: u64) -> std::io::Result<()> {
        self.check_slot(id)?;
        let zeros = vec![0u8; ZERO_CHUNK];
        let mut at = 0u64;
        while at < self.geo.segment_bytes {
            let n = ((self.geo.segment_bytes - at) as usize).min(ZERO_CHUNK);
            self.io.write_at(&zeros[..n], self.data_offset(id) + at)?;
            at += n as u64;
        }
        self.io.flush()
    }

    /// Rotation step 3 (the directory flush): commit `segment_count = id`. Only the next
    /// segment can be committed.
    pub fn commit_segment(&self, id: u64) -> std::io::Result<()> {
        let mut st = self.lock();
        if st.segment_count >= id {
            return Ok(());
        }
        if id != st.segment_count + 1 {
            return Err(std::io::Error::other(format!(
                "segment {id} cannot follow committed segment {}",
                st.segment_count
            )));
        }
        self.commit(&mut st, None, id)
    }

    /// Zero bytes `from..to` of segment `id`, then `fdatasync` (torn-tail truncation).
    pub fn zero_segment_range(&self, id: u64, from: u64, to: u64) -> std::io::Result<()> {
        if to > from {
            self.write_segment(id, from, &vec![0u8; (to - from) as usize])?;
        }
        self.io.flush()
    }

    /// Erase slot `id`'s header (test view: a lost segment file).
    #[cfg(test)]
    pub(crate) fn erase_segment_header(&self, id: u64) -> std::io::Result<()> {
        self.check_slot(id)?;
        self.io
            .write_at(&vec![0u8; BLOCK as usize], self.geo.slot_offset(id))?;
        self.io.flush()
    }
}

/// The segment medium of a store: a directory of files (A2) or a raw block device (R1).
#[derive(Debug, Clone)]
pub(crate) enum Medium {
    Dir(PathBuf),
    Block(Arc<BlockDevice>),
}

impl Medium {
    pub fn exists(&self, name: &str) -> bool {
        match self {
            Medium::Dir(root) => root.join(name).exists(),
            Medium::Block(dev) => dev.read_named(name).is_some(),
        }
    }

    pub fn read(&self, name: &str) -> std::io::Result<Vec<u8>> {
        match self {
            Medium::Dir(root) => fs::read(root.join(name)),
            Medium::Block(dev) => dev.read_named(name).ok_or_else(|| {
                std::io::Error::new(std::io::ErrorKind::NotFound, format!("no object {name}"))
            }),
        }
    }

    /// Atomically create or replace `name` (A2: `<name>.tmp`, sync, rename, directory
    /// sync; R1: one metadata commit).
    pub fn write_atomic(&self, name: &str, bytes: &[u8]) -> SynapseResult<()> {
        match self {
            Medium::Dir(root) => write_file_atomic(
                root,
                &root.join(format!("{name}.tmp")),
                &root.join(name),
                bytes,
            ),
            Medium::Block(dev) => dev.write_named(name, bytes).map_err(io_err),
        }
    }

    pub fn list_segments(&self) -> SynapseResult<Vec<u64>> {
        match self {
            Medium::Dir(root) => segment::list_segments(root),
            Medium::Block(dev) => dev.list_segments().map_err(io_err),
        }
    }

    /// True when segment `id` exists and holds a non-zero byte.
    pub fn segment_has_data(&self, id: u64) -> SynapseResult<bool> {
        match self {
            Medium::Dir(root) => match fs::read(root.join(segment::segment_file_name(id))) {
                Ok(b) => Ok(b.iter().any(|x| *x != 0)),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
                Err(e) => Err(io_err(e)),
            },
            Medium::Block(dev) => Ok(dev
                .read_segment(id, 0)
                .map_err(io_err)?
                .iter()
                .any(|x| *x != 0)),
        }
    }

    /// Segment `id` from byte `base` on; `None` when the segment does not exist.
    pub fn read_segment_from(&self, id: u64, base: u64) -> SynapseResult<Option<Vec<u8>>> {
        match self {
            Medium::Dir(root) => {
                let path = root.join(segment::segment_file_name(id));
                if !path.exists() {
                    return Ok(None);
                }
                let mut f = File::open(&path).map_err(io_err)?;
                f.seek(SeekFrom::Start(base)).map_err(io_err)?;
                let mut b = Vec::new();
                f.read_to_end(&mut b).map_err(io_err)?;
                Ok(Some(b))
            }
            Medium::Block(dev) => {
                if !dev.header_valid(id).map_err(io_err)? {
                    return Ok(None);
                }
                Ok(Some(dev.read_segment(id, base).map_err(io_err)?))
            }
        }
    }

    /// Zero bytes `from..to` of segment `id` and `fdatasync` it (torn-tail truncation).
    pub fn zero_segment_range(&self, id: u64, from: u64, to: u64) -> SynapseResult<()> {
        match self {
            Medium::Dir(root) => {
                let f = OpenOptions::new()
                    .write(true)
                    .open(root.join(segment::segment_file_name(id)))
                    .map_err(io_err)?;
                f.write_all_at(&vec![0u8; (to - from) as usize], from)
                    .map_err(io_err)?;
                f.sync_data().map_err(io_err)
            }
            Medium::Block(dev) => dev.zero_segment_range(id, from, to).map_err(io_err),
        }
    }

    /// A read handle on segment `id` (`NotFound` when it does not exist or, on a
    /// device, is not committed).
    pub fn open_reader(&self, id: u64) -> std::io::Result<segment::SegReader> {
        match self {
            Medium::Dir(root) => {
                File::open(root.join(segment::segment_file_name(id))).map(segment::SegReader::File)
            }
            Medium::Block(dev) => {
                if id <= dev.segment_count() && dev.header_valid(id)? {
                    Ok(segment::SegReader::Block(dev.clone(), id))
                } else {
                    Err(std::io::Error::new(
                        std::io::ErrorKind::NotFound,
                        format!("segment {id} is not on the device"),
                    ))
                }
            }
        }
    }

    /// Flush the namespace (A2: `fsync` the store directory; R1: every metadata commit
    /// is already durable, so nothing is left to do).
    pub fn sync_namespace(&self) -> SynapseResult<()> {
        match self {
            Medium::Dir(root) => sync_dir(root),
            Medium::Block(_) => Ok(()),
        }
    }
}
