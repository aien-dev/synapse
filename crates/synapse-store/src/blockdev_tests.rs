//! R1 raw block store tests (issue #47): device refusal rules, superblock fallback,
//! slot exhaustion, and the power-cut simulation. The A2 crash suite itself runs
//! unchanged against the device in `blockdev_a2_suite.rs`.
//!
//! Power-cut simulation: a workload runs on an in-memory device that records every
//! write and every flush. Crash images are rebuilt from that log for every cut point,
//! under four models of what reached the medium:
//!
//! * prefix tear: every write before the cut landed, the write at the cut landed for its
//!   first `k` 512-byte sectors, for every `k`;
//! * suffix tear: the same with only the last `k` sectors landed;
//! * lost write: one write issued since the last flush did not land at all (the drive
//!   may persist unflushed writes in any order), for every such write;
//! * hole: the write at the cut landed except for one sector in its middle.
//!
//! Every acknowledged change must survive the first three models under
//! `TruncateTornTail` (strict recovery may refuse only with `WalTornFrame`). A hole may
//! make recovery fail closed (the A2 limit documented at `wal2::torn_evidence`), but it
//! must never open with an acknowledged change missing.

use super::blockdev::*;
use super::tests::make_signed_changeset;
use super::*;
use ed25519_dalek::SigningKey;
use std::sync::{Arc, Mutex};

/// File in a test store directory that turns it into a raw block store.
pub(crate) const TEST_DEVICE_FILE: &str = "raw.device";
/// Size of the test devices (sparse files).
pub(crate) const TEST_DEVICE_BYTES: u64 = 16 << 20;
/// Metadata region size of the test devices.
pub(crate) const TEST_META_BYTES: u64 = 1 << 20;

/// Test hook of [`SynapseStore::open`]: a directory holding [`TEST_DEVICE_FILE`] is
/// opened as a raw block store on that file.
pub(crate) fn redirect(root: &Path) -> Option<BlockDeviceConfig> {
    let path = root.join(TEST_DEVICE_FILE);
    path.is_file().then_some(BlockDeviceConfig {
        path,
        format: FormatPolicy::FormatIfBlank,
        meta_region_bytes: TEST_META_BYTES,
        allow_foreign_signature: false,
    })
}

/// Create a zero-filled (sparse) test device file of `len` bytes.
pub(crate) fn make_device_file(path: &Path, len: u64) {
    let f = File::create(path).unwrap();
    f.set_len(len).unwrap();
    f.sync_all().unwrap();
}

fn temp_dir(label: &str) -> PathBuf {
    super::tests::temp_store_dir(&format!("r1-{label}"))
}

// --- in-memory device with a write log -------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
enum Op {
    Write { off: u64, data: Vec<u8> },
    Flush,
}

#[derive(Debug)]
struct Rec {
    image: Vec<u8>,
    ops: Vec<Op>,
    fail_flushes: bool,
}

#[derive(Debug, Clone)]
struct MemIo(Arc<Mutex<Rec>>);

impl MemIo {
    fn new(image: Vec<u8>) -> Self {
        Self(Arc::new(Mutex::new(Rec {
            image,
            ops: Vec::new(),
            fail_flushes: false,
        })))
    }
    fn rec(&self) -> std::sync::MutexGuard<'_, Rec> {
        self.0.lock().unwrap()
    }
}

impl BlockIo for MemIo {
    fn len(&self) -> u64 {
        self.rec().image.len() as u64
    }
    fn read_at(&self, buf: &mut [u8], off: u64) -> std::io::Result<()> {
        let r = self.rec();
        let src = r
            .image
            .get(off as usize..off as usize + buf.len())
            .ok_or_else(|| std::io::Error::other("read past the end"))?;
        buf.copy_from_slice(src);
        Ok(())
    }
    fn write_at(&self, data: &[u8], off: u64) -> std::io::Result<()> {
        let mut r = self.rec();
        let dst = r
            .image
            .get_mut(off as usize..off as usize + data.len())
            .ok_or_else(|| std::io::Error::other("write past the end"))?;
        dst.copy_from_slice(data);
        r.ops.push(Op::Write {
            off,
            data: data.to_vec(),
        });
        Ok(())
    }
    fn flush(&self) -> std::io::Result<()> {
        let mut r = self.rec();
        if r.fail_flushes {
            return Err(std::io::Error::other("injected flush failure"));
        }
        r.ops.push(Op::Flush);
        Ok(())
    }
}

fn mem_cfg(format: FormatPolicy, meta: u64) -> BlockDeviceConfig {
    BlockDeviceConfig {
        path: PathBuf::from("/r1-test/in-memory"),
        format,
        meta_region_bytes: meta,
        allow_foreign_signature: false,
    }
}

/// Deterministic non-zero filler (xorshift), standing in for stale bytes from an
/// earlier use of the device.
fn garbage(len: usize, mut x: u64) -> Vec<u8> {
    let mut v = Vec::with_capacity(len);
    while v.len() < len {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        v.extend_from_slice(&x.to_le_bytes());
    }
    v.truncate(len);
    v
}

// --- store helpers ---------------------------------------------------------------

const SEG: u64 = 64 * 1024;
const BLOB: usize = 6000;
const STRICT: RecoveryPolicy = RecoveryPolicy::StrictFailClosed;
const TRUNCATE: RecoveryPolicy = RecoveryPolicy::TruncateTornTail;

fn limits() -> StoreLimits {
    StoreLimits {
        segment_bytes: SEG,
        wal_prealloc_bytes: 16 * 1024,
        ..Default::default()
    }
}

fn key(n: u8) -> SigningKey {
    SigningKey::from_bytes(&[n; 32])
}

fn commit(store: &mut SynapseStore, key: &SigningKey, label: &str) -> SynapseResult<WalSeq> {
    let mut content = format!("// {label}\n").into_bytes();
    let mut x: u8 = label
        .bytes()
        .fold(7u8, |a, b| a.wrapping_mul(31).wrapping_add(b));
    while content.len() < BLOB {
        x = x.wrapping_mul(13).wrapping_add(1);
        content.push(b'a' + x % 26);
    }
    let (env, blobs) = make_signed_changeset(
        key,
        label,
        &format!("src/{label}.rs"),
        &content,
        vec![],
        1000,
    );
    match store.ingest_changeset(env, &blobs)? {
        IngestOutcome::Committed {
            wal_seq,
            durability,
            ..
        } => {
            assert_eq!(durability, DurabilityGuarantee::FsyncBeforeAck);
            Ok(wal_seq)
        }
        other => panic!("expected Committed, got {other:?}"),
    }
}

/// Every changeset is listed and every blob reads back with its digest.
fn check_readable(store: &SynapseStore) -> Result<usize, String> {
    let all = store
        .list_changesets(None, None, None)
        .map_err(|e| format!("list: {e:?}"))?;
    for c in &all {
        for m in &c.envelope.mutations {
            if let MutationOp::Upsert {
                blob_digest,
                size_bytes,
                ..
            } = &m.op
            {
                let bytes = store
                    .get_blob_visible(*blob_digest, None, None)
                    .map_err(|e| format!("blob {blob_digest}: {e:?}"))?;
                if bytes.len() as u64 != *size_bytes {
                    return Err(format!("blob {blob_digest}: wrong length"));
                }
            }
        }
    }
    Ok(all.len())
}

// --- refusal rules ---------------------------------------------------------------

#[test]
fn r1_refuses_a_device_carrying_a_filesystem_or_partition_signature() {
    let dir = temp_dir("sig");
    let cases: [(&str, usize, &[u8]); 4] = [
        ("ext4", 1080, &[0x53, 0xEF]),
        ("gpt", 512, b"EFI PART"),
        ("xfs", 0, b"XFSB"),
        ("luks", 0, b"LUKS\xba\xbe"),
    ];
    for (name, off, sig) in cases {
        let path = dir.join(format!("{name}.img"));
        make_device_file(&path, TEST_DEVICE_BYTES);
        {
            use std::os::unix::fs::FileExt;
            let f = OpenOptions::new().write(true).open(&path).unwrap();
            f.write_all_at(sig, off as u64).unwrap();
            f.write_all_at(b"user data that must survive", 64 * 1024 + 7)
                .unwrap();
        }
        let before = fs::read(&path).unwrap();
        let cfg = BlockDeviceConfig {
            format: FormatPolicy::FormatIfBlank,
            meta_region_bytes: TEST_META_BYTES,
            ..BlockDeviceConfig::new(&path)
        };
        let err = SynapseStore::open_block_device(
            &cfg,
            FsyncPolicy::GROUP_COMMIT_DEFAULT,
            STRICT,
            limits(),
        )
        .err()
        .unwrap_or_else(|| panic!("{name}: a device with a signature was opened"));
        assert_eq!(err.code, RefusalCode::IoFailure, "{name}: {err:?}");
        assert!(err.message.contains("carries a"), "{name}: {}", err.message);
        assert_eq!(
            fs::read(&path).unwrap(),
            before,
            "{name}: refused device changed"
        );
        // The explicit override formats over it.
        let cfg = BlockDeviceConfig {
            allow_foreign_signature: true,
            ..cfg
        };
        let mut s = SynapseStore::open_block_device(
            &cfg,
            FsyncPolicy::GROUP_COMMIT_DEFAULT,
            STRICT,
            limits(),
        )
        .unwrap_or_else(|e| panic!("{name}: override refused: {e:?}"));
        assert_eq!(commit(&mut s, &key(1), name).unwrap(), WalSeq(1));
        drop(s);
        let dev = DirectFile::open(&path).unwrap();
        assert_eq!(
            classify_device(&dev).unwrap(),
            DeviceLabel::Synapse,
            "{name}"
        );
    }
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn r1_refuses_unknown_label_bytes_and_blank_devices_without_format() {
    let dir = temp_dir("unknown");
    let path = dir.join("dev.img");
    make_device_file(&path, TEST_DEVICE_BYTES);
    let cfg = BlockDeviceConfig {
        format: FormatPolicy::OpenExisting,
        ..BlockDeviceConfig::new(&path)
    };
    let err = BlockDevice::open_path(&cfg, SEG).unwrap_err();
    assert!(err.message.contains("blank"), "{}", err.message);
    {
        use std::os::unix::fs::FileExt;
        let f = OpenOptions::new().write(true).open(&path).unwrap();
        f.write_all_at(b"\x01", 100 * 1024).unwrap();
    }
    let cfg = BlockDeviceConfig::new(&path);
    let err = BlockDevice::open_path(&cfg, SEG).unwrap_err();
    assert!(err.message.contains("not blank"), "{}", err.message);
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn r1_opens_only_the_configured_path() {
    let dir = temp_dir("paths");
    let path = dir.join("dev.img");
    make_device_file(&path, TEST_DEVICE_BYTES);
    // Relative path.
    let err = DirectFile::open(Path::new("dev.img")).unwrap_err();
    assert!(err.message.contains("absolute"), "{}", err.message);
    // A directory.
    let err = DirectFile::open(&dir).unwrap_err();
    assert!(err.message.contains("neither"), "{}", err.message);
    // A symbolic link to a valid device file.
    let link = dir.join("link.img");
    std::os::unix::fs::symlink(&path, &link).unwrap();
    let err = DirectFile::open(&link).unwrap_err();
    assert!(err.message.contains("symbolic"), "{}", err.message);
    // Missing file: nothing is created.
    let missing = dir.join("missing.img");
    assert!(DirectFile::open(&missing).is_err());
    assert!(!missing.exists());
    // Length not a multiple of the block size.
    let odd = dir.join("odd.img");
    make_device_file(&odd, TEST_DEVICE_BYTES + 512);
    let err = DirectFile::open(&odd).unwrap_err();
    assert!(err.message.contains("multiple"), "{}", err.message);
    // The configured file itself opens, and unaligned I/O round-trips through O_DIRECT.
    let d = DirectFile::open(&path).unwrap();
    d.write_at(b"0123456789", 4090).unwrap();
    d.flush().unwrap();
    let mut b = [0u8; 12];
    d.read_at(&mut b, 4089).unwrap();
    assert_eq!(&b, b"\x000123456789\x00");
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn r1_classifies_known_signatures() {
    let label = |patches: Vec<(u64, Vec<u8>)>| {
        classify_device(&SparseIo {
            len: LABEL_BYTES,
            patches,
        })
        .unwrap()
    };
    assert_eq!(label(vec![]), DeviceLabel::Blank);
    assert_eq!(label(vec![(100 * 1024, vec![1])]), DeviceLabel::Unknown);
    assert_eq!(
        label(vec![(4096, SUPERBLOCK_MAGIC.to_vec())]),
        DeviceLabel::Synapse
    );
    // A GPT disk carries a protective MBR too: the GPT name wins.
    assert_eq!(
        label(vec![(510, vec![0x55, 0xAA]), (512, b"EFI PART".to_vec())]),
        DeviceLabel::Foreign("GPT partition table")
    );
}

/// A sparse read-only device: zeros except for `patches`.
#[derive(Debug)]
struct SparseIo {
    len: u64,
    patches: Vec<(u64, Vec<u8>)>,
}

impl BlockIo for SparseIo {
    fn len(&self) -> u64 {
        self.len
    }
    fn read_at(&self, buf: &mut [u8], off: u64) -> std::io::Result<()> {
        buf.fill(0);
        let end = off + buf.len() as u64;
        for (at, bytes) in &self.patches {
            for (i, b) in bytes.iter().enumerate() {
                let p = at + i as u64;
                if p >= off && p < end {
                    buf[(p - off) as usize] = *b;
                }
            }
        }
        Ok(())
    }
    fn write_at(&self, _: &[u8], _: u64) -> std::io::Result<()> {
        Err(std::io::Error::other("read-only"))
    }
    fn flush(&self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Large enough for every offset (btrfs's 256 GiB mirror) and not a multiple of 64 KiB,
/// so the MD RAID and ZFS end rounding is exercised.
const PIN_LEN: u64 = (300 << 30) + (12 << 20) + 3 * 4096;
const PIN_ZFS_END: u64 = PIN_LEN & !(256 * 1024 - 1);
const PIN_MD: &[u8] = &[0xFC, 0x4E, 0x2B, 0xA9];
const PIN_ZFS_LE: &[u8] = &[0x0C, 0xB1, 0xBA, 0, 0, 0, 0, 0];
const PIN_ZFS_BE: &[u8] = &[0, 0, 0, 0, 0, 0xBA, 0xB1, 0x0C];

/// A device carrying only `magic` at `off` is refused as `name`.
fn pinned(name: &str, off: u64, magic: &[u8]) {
    let io = SparseIo {
        len: PIN_LEN,
        patches: vec![(off, magic.to_vec())],
    };
    match classify_device(&io).unwrap() {
        DeviceLabel::Foreign(n) => assert_eq!(n, name),
        other => panic!("{name}: classified {other:?}"),
    }
}

// One test per signature, written independently of `SIGNATURES`: deleting or moving an
// entry turns its test red.
macro_rules! pin {
    ($($t:ident: $name:expr, $off:expr, $magic:expr;)*) => {
        $(#[test] fn $t() { pinned($name, $off, $magic) })*
    };
}

pin! {
    r1_sig_gpt: "GPT partition table", 512, b"EFI PART";
    r1_sig_gpt_4k: "GPT partition table (4 KiB sectors)", 4096, b"EFI PART";
    r1_sig_gpt_backup: "GPT backup header", PIN_LEN - 512, b"EFI PART";
    r1_sig_gpt_backup_4k: "GPT backup header (4 KiB sectors)", PIN_LEN - 4096, b"EFI PART";
    r1_sig_ext: "ext2/ext3/ext4", 1080, &[0x53, 0xEF];
    r1_sig_xfs: "XFS", 0, b"XFSB";
    r1_sig_btrfs: "btrfs", 0x1_0040, b"_BHRfS_M";
    r1_sig_btrfs_64m: "btrfs (mirror at 64 MiB)", 64 * 1024 * 1024 + 0x40, b"_BHRfS_M";
    r1_sig_btrfs_256g: "btrfs (mirror at 256 GiB)", (256 << 30) + 0x40, b"_BHRfS_M";
    r1_sig_ntfs: "NTFS", 3, b"NTFS    ";
    r1_sig_exfat: "exFAT", 3, b"EXFAT   ";
    r1_sig_fat16: "FAT12/FAT16", 54, b"FAT1";
    r1_sig_fat32: "FAT32", 82, b"FAT32   ";
    r1_sig_luks: "LUKS", 0, b"LUKS\xba\xbe";
    r1_sig_lvm0: "LVM2 physical volume (sector 0)", 0, b"LABELONE";
    r1_sig_lvm1: "LVM2 physical volume (sector 1)", 512, b"LABELONE";
    r1_sig_lvm2: "LVM2 physical volume (sector 2)", 1024, b"LABELONE";
    r1_sig_lvm3: "LVM2 physical volume (sector 3)", 1536, b"LABELONE";
    r1_sig_swap: "Linux swap (4 KiB pages)", 4086, b"SWAPSPACE2";
    r1_sig_swap_old: "Linux swap, old (4 KiB pages)", 4086, b"SWAP-SPACE";
    r1_sig_swap_16k: "Linux swap (16 KiB pages)", 16374, b"SWAPSPACE2";
    r1_sig_swap_64k: "Linux swap (64 KiB pages)", 65526, b"SWAPSPACE2";
    r1_sig_iso9660: "ISO 9660", 0x8001, b"CD001";
    r1_sig_squashfs: "squashfs", 0, b"hsqs";
    r1_sig_f2fs: "F2FS", 1024, &[0x10, 0x20, 0xF5, 0xF2];
    r1_sig_md_1_2: "Linux MD RAID (1.2)", 4096, PIN_MD;
    r1_sig_md_1_1: "Linux MD RAID (1.1)", 0, PIN_MD;
    r1_sig_md_1_0: "Linux MD RAID (1.0)", (PIN_LEN - 8192) & !4095, PIN_MD;
    r1_sig_md_0_90: "Linux MD RAID (0.90)", (PIN_LEN & !0xFFFF) - 0x10000, PIN_MD;
    r1_sig_zfs_l0: "ZFS label L0", 128 * 1024 + 5 * 1024, PIN_ZFS_LE;
    r1_sig_zfs_l0_be: "ZFS label L0 (big-endian)", 255 * 1024, PIN_ZFS_BE;
    r1_sig_zfs_l1: "ZFS label L1", 384 * 1024, PIN_ZFS_LE;
    r1_sig_zfs_l1_be: "ZFS label L1 (big-endian)", 400 * 1024, PIN_ZFS_BE;
    r1_sig_zfs_l2: "ZFS label L2", PIN_ZFS_END - 512 * 1024 + 192 * 1024, PIN_ZFS_LE;
    r1_sig_zfs_l2_be: "ZFS label L2 (big-endian)", PIN_ZFS_END - 384 * 1024, PIN_ZFS_BE;
    r1_sig_zfs_l3: "ZFS label L3", PIN_ZFS_END - 128 * 1024, PIN_ZFS_LE;
    r1_sig_zfs_l3_be: "ZFS label L3 (big-endian)", PIN_ZFS_END - 1024, PIN_ZFS_BE;
    r1_sig_mbr: "MBR or boot sector", 510, &[0x55, 0xAA];
}

/// The pinned list and `SIGNATURES` have the same size: a new entry needs a pin test.
#[test]
fn r1_every_signature_has_a_pin_test() {
    assert_eq!(SIGNATURES.len(), 38);
}

// --- superblock and metadata commits ----------------------------------------------

#[test]
fn r1_superblock_falls_back_to_the_older_copy_when_the_newest_is_damaged() {
    let io = MemIo::new(vec![0u8; 8 << 20]);
    let cfg = mem_cfg(FormatPolicy::FormatIfBlank, 64 * 1024);
    let dev = BlockDevice::open(Box::new(io.clone()), &cfg, SEG).unwrap();
    dev.write_named("a", b"first").unwrap();
    dev.write_named("b", b"second").unwrap();
    let g = dev.generation();
    let geo = dev.geometry();
    drop(dev);
    let reopen = |io: &MemIo| {
        BlockDevice::open(
            Box::new(MemIo::new(io.rec().image.clone())),
            &mem_cfg(FormatPolicy::OpenExisting, 64 * 1024),
            SEG,
        )
    };
    let d = reopen(&io).unwrap();
    assert_eq!(d.read_named("b").as_deref(), Some(&b"second"[..]));
    // Damage the newest superblock copy: the older one (without "b") is used.
    let newest = (g % 2 * BLOCK) as usize;
    let saved = io.rec().image[newest + 40];
    io.rec().image[newest + 40] ^= 0xFF;
    let d = reopen(&io).unwrap();
    assert_eq!(d.generation(), g - 1);
    assert_eq!(d.read_named("a").as_deref(), Some(&b"first"[..]));
    assert_eq!(d.read_named("b"), None);
    io.rec().image[newest + 40] = saved;
    // Damage the metadata region the newest copy points at: same fallback. The byte is
    // the last byte of "second" ("SBM1", count, then "a" and "b" entries: 41 bytes), so
    // the region still decodes and only its digest catches the damage.
    let d = reopen(&io).unwrap();
    assert_eq!(d.generation(), g);
    let slot = d.meta_slot() as usize;
    let region = geo.meta_offset[slot] as usize;
    io.rec().image[region + 40] ^= 0x01;
    let d = reopen(&io).unwrap();
    assert_eq!(d.generation(), g - 1);
    assert_eq!(d.read_named("b"), None);
    // Both copies damaged: refused, never formatted over.
    let other = ((g - 1) % 2 * BLOCK) as usize;
    io.rec().image[other + 40] ^= 0xFF;
    let err = reopen(&io).unwrap_err();
    assert_eq!(err.code, RefusalCode::CheckpointCorrupt, "{err:?}");
}

#[test]
fn r1_full_device_refuses_the_batch_and_keeps_every_ack() {
    // Room for exactly 2 slots of 64 KiB after 2 MiB of label and metadata.
    let io = MemIo::new(vec![0u8; (2 << 20) + 2 * (BLOCK + SEG) as usize]);
    let cfg = mem_cfg(FormatPolicy::FormatIfBlank, 256 * 1024);
    let dev = BlockDevice::open(Box::new(io.clone()), &cfg, SEG).unwrap();
    assert_eq!(dev.geometry().slot_count, 2);
    let mut s = SynapseStore::open_on_device(dev, cfg.path.clone(), STRICT, limits()).unwrap();
    let mut acked = 0;
    let err = loop {
        match commit(&mut s, &key(5), &format!("full-{acked}")) {
            Ok(seq) => acked = seq.0,
            Err(e) => break e,
        }
    };
    assert_eq!(acked, 16, "two slots of 8 batches");
    assert_eq!(err.code, RefusalCode::IoFailure, "{err:?}");
    assert!(err.message.contains("device full"), "{}", err.message);
    assert!(s.poisoned().is_none());
    assert_eq!(check_readable(&s).unwrap(), 16);
    drop(s);
    let dev = BlockDevice::open(
        Box::new(MemIo::new(io.rec().image.clone())),
        &mem_cfg(FormatPolicy::OpenExisting, 256 * 1024),
        SEG,
    )
    .unwrap();
    let s = SynapseStore::open_on_device(dev, cfg.path, STRICT, limits()).unwrap();
    assert_eq!(s.committed_seq(), WalSeq(16));
}

#[test]
fn r1_failed_device_flush_acknowledges_nothing() {
    let io = MemIo::new(vec![0u8; 4 << 20]);
    let cfg = mem_cfg(FormatPolicy::FormatIfBlank, 256 * 1024);
    let dev = BlockDevice::open(Box::new(io.clone()), &cfg, SEG).unwrap();
    let mut s = SynapseStore::open_on_device(dev, cfg.path.clone(), STRICT, limits()).unwrap();
    for i in 0..3 {
        commit(&mut s, &key(6), &format!("ff-{i}")).unwrap();
    }
    io.rec().fail_flushes = true;
    let err = commit(&mut s, &key(6), "ff-fail").unwrap_err();
    assert_eq!(err.code, RefusalCode::IoFailure, "{err:?}");
    assert_eq!(s.committed_seq(), WalSeq(3));
    io.rec().fail_flushes = false;
    drop(s);
    let dev = BlockDevice::open(
        Box::new(MemIo::new(io.rec().image.clone())),
        &mem_cfg(FormatPolicy::OpenExisting, 256 * 1024),
        SEG,
    )
    .unwrap();
    let mut s = SynapseStore::open_on_device(dev, cfg.path, TRUNCATE, limits()).unwrap();
    assert!(s.committed_seq() == WalSeq(3) || s.committed_seq() == WalSeq(4));
    let next = commit(&mut s, &key(6), "ff-after").unwrap();
    assert_eq!(next.0, s.committed_seq().0);
    assert_eq!(check_readable(&s).unwrap() as u64, next.0);
}

// --- power-cut simulation -----------------------------------------------------------

const PC_DEVICE: usize = 4 << 20;
const PC_META: u64 = 256 * 1024;
const SECTOR: usize = 512;

struct Workload {
    base: Vec<u8>,
    ops: Vec<Op>,
    /// `(ops completed when the ack returned, acknowledged seq)`.
    acks: Vec<(usize, u64)>,
    max_seq: u64,
}

/// Format, 20 commits across three segments, a checkpoint, 6 more commits, reopen,
/// 2 more commits: every device write and flush is logged.
fn record_workload() -> Workload {
    let mut base = vec![0u8; PC_DEVICE];
    base[LABEL_BYTES as usize..].copy_from_slice(&garbage(PC_DEVICE - LABEL_BYTES as usize, 47));
    let io = MemIo::new(base.clone());
    let cfg = mem_cfg(FormatPolicy::FormatIfBlank, PC_META);
    let mut acks = Vec::new();
    let mut n = 0u64;
    let mut run = |s: &mut SynapseStore, count: usize, acks: &mut Vec<(usize, u64)>| {
        for _ in 0..count {
            let seq = commit(s, &key(9), &format!("pc-{n}")).unwrap();
            n += 1;
            acks.push((io.rec().ops.len(), seq.0));
        }
    };
    {
        let dev = BlockDevice::open(Box::new(io.clone()), &cfg, SEG).unwrap();
        let mut s = SynapseStore::open_on_device(dev, cfg.path.clone(), STRICT, limits()).unwrap();
        run(&mut s, 20, &mut acks);
        s.checkpoint_and_compact(1000).unwrap();
        // The checkpoint acknowledges nothing new, but its commits are cut points too.
        run(&mut s, 6, &mut acks);
    }
    {
        let dev = BlockDevice::open(Box::new(io.clone()), &cfg, SEG).unwrap();
        let mut s = SynapseStore::open_on_device(dev, cfg.path.clone(), STRICT, limits()).unwrap();
        run(&mut s, 2, &mut acks);
    }
    let ops = io.rec().ops.clone();
    let max_seq = acks.last().unwrap().1;
    Workload {
        base,
        ops,
        acks,
        max_seq,
    }
}

fn apply(img: &mut [u8], op: &Op) {
    if let Op::Write { off, data } = op {
        img[*off as usize..*off as usize + data.len()].copy_from_slice(data);
    }
}

#[derive(Debug, Default)]
struct Tally {
    states: usize,
    opened: usize,
    strict_torn_refusals: usize,
    fail_closed: usize,
    continued: usize,
}

/// Recover a crash image and check it. `must_open`: the image must open (with every
/// ack) under `TruncateTornTail`; otherwise failing closed is allowed.
fn check_image(img: &[u8], acked: u64, max_seq: u64, must_open: bool, what: &str, t: &mut Tally) {
    t.states += 1;
    let open = |policy| -> SynapseResult<SynapseStore> {
        let dev = BlockDevice::open(
            Box::new(MemIo::new(img.to_vec())),
            &mem_cfg(FormatPolicy::OpenExisting, PC_META),
            SEG,
        )?;
        SynapseStore::open_on_device(dev, PathBuf::from("/r1-test/in-memory"), policy, limits())
    };
    let verify = |s: &SynapseStore, policy: &str| {
        let c = s.committed_seq().0;
        assert!(
            c >= acked && c <= max_seq,
            "{what} ({policy}): committed {c}, acknowledged {acked}, written {max_seq}"
        );
        let listed = check_readable(s).unwrap_or_else(|e| panic!("{what} ({policy}): {e}"));
        assert_eq!(listed as u64, c, "{what} ({policy}): changesets listed");
    };
    match open(TRUNCATE) {
        Ok(mut s) => {
            t.opened += 1;
            verify(&s, "truncate");
            // Sample: the recovered store keeps working and reopens.
            if t.states.is_multiple_of(23) {
                let next = commit(&mut s, &key(10), &format!("after-{}", t.states))
                    .unwrap_or_else(|e| panic!("{what}: commit after recovery: {e:?}"));
                assert_eq!(next.0, s.committed_seq().0);
                t.continued += 1;
            }
        }
        Err(e) if acked == 0 => {
            // Before the first acknowledgment (the format flush has not returned) a
            // device may refuse to open; nothing was promised.
            let _ = e;
        }
        Err(e) if !must_open => {
            t.fail_closed += 1;
            let _ = e;
        }
        Err(e) => panic!("{what}: truncating recovery refused with acks up to {acked}: {e:?}"),
    }
    match open(STRICT) {
        Ok(s) => verify(&s, "strict"),
        Err(e) if e.code == RefusalCode::WalTornFrame => t.strict_torn_refusals += 1,
        Err(_) if acked == 0 || !must_open => {}
        Err(e) => panic!("{what}: strict recovery refused other than as torn: {e:?}"),
    }
}

fn acked_at(w: &Workload, completed_ops: usize) -> u64 {
    w.acks
        .iter()
        .filter(|(at, _)| *at <= completed_ops)
        .map(|(_, s)| *s)
        .max()
        .unwrap_or(0)
}

#[test]
fn r1_power_cut_at_every_write_boundary_keeps_every_ack() {
    let w = record_workload();
    let writes = w
        .ops
        .iter()
        .filter(|o| matches!(o, Op::Write { .. }))
        .count();
    let flushes = w.ops.len() - writes;
    let mut prefix = Tally::default();
    let mut suffix = Tally::default();
    let mut lost = Tally::default();
    let mut hole = Tally::default();
    let mut img = w.base.clone();
    let mut last_flush = 0usize; // ops[..last_flush] are durable for sure
    for (i, op) in w.ops.iter().enumerate() {
        // Cut while op `i` is in flight: ops[..i] were issued and completed.
        let acked = acked_at(&w, i);
        if let Op::Write { off, data } = op {
            let sectors = data.len().div_ceil(SECTOR);
            for k in 0..sectors {
                let mut c = img.clone();
                let n = k * SECTOR;
                c[*off as usize..*off as usize + n].copy_from_slice(&data[..n]);
                check_image(
                    &c,
                    acked,
                    w.max_seq,
                    true,
                    &format!("op {i} prefix {k}/{sectors}"),
                    &mut prefix,
                );
                let mut c = img.clone();
                let from = data.len() - n;
                c[*off as usize + from..*off as usize + data.len()].copy_from_slice(&data[from..]);
                check_image(
                    &c,
                    acked,
                    w.max_seq,
                    true,
                    &format!("op {i} suffix {k}/{sectors}"),
                    &mut suffix,
                );
            }
            for k in 1..sectors.saturating_sub(1) {
                let mut c = img.clone();
                apply(&mut c, op);
                let at = *off as usize + k * SECTOR;
                let end = (at + SECTOR).min(*off as usize + data.len());
                c[at..end].copy_from_slice(&w_before(&w, i, at, end));
                check_image(
                    &c,
                    acked,
                    w.max_seq,
                    false,
                    &format!("op {i} hole {k}/{sectors}"),
                    &mut hole,
                );
            }
        }
        // Lost write: one write issued since the last flush never landed.
        for j in last_flush..i {
            if !matches!(w.ops[j], Op::Write { .. }) {
                continue;
            }
            let mut c = w.base.clone();
            for (m, o) in w.ops[..i].iter().enumerate() {
                if m != j {
                    apply(&mut c, o);
                }
            }
            check_image(
                &c,
                acked,
                w.max_seq,
                true,
                &format!("cut {i} lost write {j}"),
                &mut lost,
            );
        }
        apply(&mut img, op);
        if matches!(op, Op::Flush) {
            last_flush = i + 1;
        }
    }
    // The finished workload.
    check_image(&img, w.max_seq, w.max_seq, true, "complete", &mut prefix);
    eprintln!(
        "R1 power-cut simulation: {} device writes, {flushes} flushes, {} acks; \
         prefix {prefix:?}; suffix {suffix:?}; lost-write {lost:?}; hole {hole:?}",
        writes,
        w.acks.len()
    );
    assert!(prefix.states > 1000 && suffix.states > 1000 && lost.states > 20);
    assert_eq!(
        prefix.fail_closed + suffix.fail_closed + lost.fail_closed,
        0
    );
}

/// Bytes `at..end` of the device just before op `i` (for the hole model).
fn w_before(w: &Workload, i: usize, at: usize, end: usize) -> Vec<u8> {
    let mut v = w.base[at..end].to_vec();
    for o in &w.ops[..i] {
        if let Op::Write { off, data } = o {
            let (o0, o1) = (*off as usize, *off as usize + data.len());
            let (s, e) = (at.max(o0), end.min(o1));
            if s < e {
                v[s - at..e - at].copy_from_slice(&data[s - o0..e - o0]);
            }
        }
    }
    v
}

// --- review of PR #103 ----------------------------------------------------------------

/// Reviewer's scenario (B2): 10 acknowledged changes across two slots, then one damaged
/// byte in the newest superblock copy (the rotation commit that raised the segment
/// count). Recovery may refuse loudly; it must never open with fewer changes.
#[test]
fn r1_lost_newest_superblock_never_drops_acknowledged_changes() {
    let io = MemIo::new(vec![0u8; 4 << 20]);
    let cfg = mem_cfg(FormatPolicy::FormatIfBlank, 256 * 1024);
    let dev = BlockDevice::open(Box::new(io.clone()), &cfg, SEG).unwrap();
    let mut s = SynapseStore::open_on_device(dev, cfg.path.clone(), TRUNCATE, limits()).unwrap();
    for i in 0..10 {
        commit(&mut s, &key(8), &format!("lost-sb-{i}")).unwrap();
    }
    drop(s);
    let reopen_dev = |io: &MemIo| {
        BlockDevice::open(
            Box::new(MemIo::new(io.rec().image.clone())),
            &mem_cfg(FormatPolicy::OpenExisting, 256 * 1024),
            SEG,
        )
    };
    let dev = reopen_dev(&io).unwrap();
    assert_eq!(
        dev.segment_count(),
        2,
        "8 batches per slot: 10 changes use 2 slots"
    );
    let newest = (dev.generation() % 2 * BLOCK) as usize;
    drop(dev);
    io.rec().image[newest + 40] ^= 0xFF;
    for policy in [TRUNCATE, STRICT] {
        let opened = reopen_dev(&io)
            .and_then(|dev| SynapseStore::open_on_device(dev, cfg.path.clone(), policy, limits()));
        match opened {
            Ok(s) => {
                assert_eq!(
                    s.committed_seq(),
                    WalSeq(10),
                    "{policy:?}: acknowledged changes lost"
                );
                assert_eq!(check_readable(&s).unwrap(), 10, "{policy:?}");
            }
            Err(e) => assert_eq!(e.code, RefusalCode::CheckpointCorrupt, "{policy:?}: {e:?}"),
        }
    }
}

/// N4: a second opener of the same device (here a device file) is refused while the
/// first holds it.
#[test]
fn r1_a_second_opener_of_the_device_is_refused() {
    let dir = temp_dir("lock");
    let path = dir.join("dev.img");
    make_device_file(&path, TEST_DEVICE_BYTES);
    let first = DirectFile::open(&path).unwrap();
    let err = DirectFile::open(&path).unwrap_err();
    assert!(err.message.contains("in use"), "{}", err.message);
    drop(first);
    DirectFile::open(&path).unwrap();
    let _ = fs::remove_dir_all(&dir);
}

/// N1: a device whose label area is zero but that carries a signature near its end
/// (backup GPT header, MD RAID 0.90 or 1.0 superblock, ZFS label L2 or L3) is refused
/// and left unchanged, even with `FormatIfBlank`.
#[test]
fn r1_refuses_a_device_whose_signature_is_only_at_its_end() {
    let dir = temp_dir("endsig");
    let len = TEST_DEVICE_BYTES;
    let md = [0xFC, 0x4E, 0x2B, 0xA9];
    let zfs_le = 0x00ba_b10c_u64.to_le_bytes();
    let zfs_end = len & !(256 * 1024 - 1);
    let cases: [(&str, u64, &[u8]); 5] = [
        ("gpt-backup", len - 512, b"EFI PART"),
        ("md-0.90", (len & !0xFFFF) - 0x10000, &md),
        ("md-1.0", (len - 8192) & !4095, &md),
        ("zfs-l2", zfs_end - 512 * 1024 + 128 * 1024, &zfs_le),
        (
            "zfs-l3",
            zfs_end - 256 * 1024 + 128 * 1024 + 3 * 1024,
            &zfs_le,
        ),
    ];
    for (name, off, sig) in cases {
        let path = dir.join(format!("{name}.img"));
        make_device_file(&path, len);
        {
            use std::os::unix::fs::FileExt;
            let f = OpenOptions::new().write(true).open(&path).unwrap();
            f.write_all_at(sig, off).unwrap();
            f.write_all_at(b"user data that must survive", 2 << 20)
                .unwrap();
        }
        let before = fs::read(&path).unwrap();
        let cfg = BlockDeviceConfig {
            format: FormatPolicy::FormatIfBlank,
            meta_region_bytes: TEST_META_BYTES,
            ..BlockDeviceConfig::new(&path)
        };
        let opened = SynapseStore::open_block_device(
            &cfg,
            FsyncPolicy::GROUP_COMMIT_DEFAULT,
            STRICT,
            limits(),
        );
        assert!(
            opened.is_err(),
            "{name}: a device with an end signature was formatted"
        );
        assert_eq!(
            fs::read(&path).unwrap(),
            before,
            "{name}: refused device changed"
        );
    }
    let _ = fs::remove_dir_all(&dir);
}

// --- repair tool (issue #105) -----------------------------------------------------

mod repair_tests {
    use super::*;
    use crate::blockdev::repair::*;
    use ed25519_dalek::Signer;

    const META: u64 = 256 * 1024;
    const NOW: u64 = 1_790_000_000;

    fn operator() -> SigningKey {
        SigningKey::from_bytes(&[0x0B; 32])
    }

    fn sha(b: &[u8]) -> [u8; 32] {
        Sha256::digest(b).into()
    }

    /// 10 acknowledged changes over two slots (8 batches per slot), then the newest
    /// superblock copy (the rotation commit that raised the count to 2) damaged.
    /// Returns the device, the damaged image, and the image before the damage.
    fn damaged_fixture() -> (MemIo, Vec<u8>, Vec<u8>) {
        let io = MemIo::new(vec![0u8; 4 << 20]);
        let cfg = mem_cfg(FormatPolicy::FormatIfBlank, META);
        let dev = BlockDevice::open(Box::new(io.clone()), &cfg, SEG).unwrap();
        let mut s =
            SynapseStore::open_on_device(dev, cfg.path.clone(), TRUNCATE, limits()).unwrap();
        for i in 0..10 {
            commit(&mut s, &key(9), &format!("repair-{i}")).unwrap();
        }
        drop(s);
        let pristine = io.rec().image.clone();
        let g = {
            let d = BlockDevice::open(
                Box::new(MemIo::new(pristine.clone())),
                &mem_cfg(FormatPolicy::OpenExisting, META),
                SEG,
            )
            .unwrap();
            assert_eq!(d.segment_count(), 2);
            d.generation()
        };
        io.rec().image[(g % 2 * BLOCK) as usize + 40] ^= 0xFF;
        let damaged = io.rec().image.clone();
        (io, damaged, pristine)
    }

    fn open_dev(image: Vec<u8>) -> SynapseResult<Arc<BlockDevice>> {
        BlockDevice::open(
            Box::new(MemIo::new(image)),
            &mem_cfg(FormatPolicy::OpenExisting, META),
            SEG,
        )
    }

    fn open_store(image: Vec<u8>) -> SynapseResult<SynapseStore> {
        open_dev(image).and_then(|dev| {
            SynapseStore::open_on_device(
                dev,
                PathBuf::from("/r1-test/in-memory"),
                TRUNCATE,
                limits(),
            )
        })
    }

    fn open_seq(image: Vec<u8>) -> Result<u64, RefusalCode> {
        open_store(image)
            .map(|s| s.committed_seq().0)
            .map_err(|e| e.code)
    }

    /// Every changeset in seq order with the bytes of every blob it names.
    fn contents(s: &SynapseStore) -> Vec<(String, Vec<Vec<u8>>)> {
        let mut out = Vec::new();
        for c in s.list_changesets(None, None, None).unwrap() {
            let mut blobs = Vec::new();
            for m in &c.envelope.mutations {
                if let MutationOp::Upsert { blob_digest, .. } = &m.op {
                    blobs.push(s.get_blob_visible(*blob_digest, None, None).unwrap());
                }
            }
            out.push((format!("{:?}", c.envelope), blobs));
        }
        out
    }

    fn writes(io: &MemIo) -> usize {
        io.rec()
            .ops
            .iter()
            .filter(|o| matches!(o, Op::Write { .. }))
            .count()
    }

    fn image(io: &MemIo) -> Vec<u8> {
        io.rec().image.clone()
    }

    #[test]
    fn r1_repair_report_lists_the_records_past_the_older_checkpoint() {
        let (io, damaged, _) = damaged_fixture();
        assert_eq!(
            open_seq(damaged.clone()),
            Err(RefusalCode::CheckpointCorrupt)
        );
        let before = writes(&io);
        let r = diagnose(&io).unwrap();
        assert_eq!(writes(&io), before, "diagnose must not write");
        assert_eq!(image(&io), damaged);
        assert_eq!(r.verdict, Verdict::OlderCheckpointLosesRange);
        assert_eq!(r.segment_count, 1);
        assert_eq!(r.lost.len(), 1);
        assert_eq!(r.lost[0].slot, 2);
        // Changes 9 and 10 sit past the older checkpoint, one batch each.
        let seqs: Vec<(u64, u32)> = r.lost[0]
            .batches
            .iter()
            .map(|b| (b.first_seq, b.records))
            .collect();
        assert_eq!(seqs, vec![(9, 1), (10, 1)]);
        assert!(r.history.is_empty());
        let text = r.to_string();
        assert!(text.contains("CORRUPT, CRC-32C mismatch"), "{text}");
        assert!(text.contains("1 committed segments"), "{text}");
        assert!(
            text.contains(&format!(
                "segment slot 2: device bytes {}..{}",
                r.lost[0].start, r.lost[0].end
            )),
            "{text}"
        );
        assert!(text.contains("2 batches, 2 records"), "{text}");
        assert!(text.contains("records 9..=9"), "{text}");
        assert!(text.contains("records 10..=10"), "{text}");
        assert!(text.contains("repair history: none"), "{text}");
        assert!(text.contains("nothing was written"), "{text}");
        assert!(text.contains("--roll-forward"), "{text}");
        assert!(text.contains("--adopt-older-checkpoint"), "{text}");
    }

    #[test]
    fn r1_repair_roll_forward_recovers_every_record_byte_identical() {
        let (io, damaged, pristine) = damaged_fixture();
        // Red: the damaged image refuses to open.
        assert_eq!(
            open_seq(damaged.clone()),
            Err(RefusalCode::CheckpointCorrupt)
        );
        let want = contents(&open_store(pristine.clone()).unwrap());
        assert_eq!(want.len(), 10);
        let geo = open_dev(pristine).unwrap().geometry();

        let dir = temp_dir("repair-roll");
        let backup = dir.join("backup.bin");
        let receipt = repair(&io, RepairAction::RollForward, &operator(), &backup, NOW).unwrap();
        assert!(receipt.wrote);
        let after = image(&io);

        // Green: the store opens with all 10 changes, byte for byte the ones acknowledged.
        let s = open_store(after.clone()).unwrap();
        assert_eq!(s.committed_seq().0, 10);
        assert_eq!(check_readable(&s), Ok(10));
        assert_eq!(contents(&s), want);
        // The log itself was not touched: every segment slot byte is as it was.
        let d = geo.data_offset as usize;
        assert_eq!(sha(&after[d..]), sha(&damaged[d..]));

        // The signed receipt names the action and the range it kept.
        let e = receipt.entry.clone().unwrap();
        assert_eq!(e.action, RepairAction::RollForward);
        assert_eq!((e.segment_count_before, e.segment_count_after), (1, 2));
        assert_eq!(e.operator_key, operator().verifying_key().to_bytes());
        assert_eq!(e.ranges.len(), 1);
        assert_eq!((e.ranges[0].slot, e.ranges[0].records), (2, 2));
        assert_eq!(e.ranges[0].first_seq, 9);
        let (a, b) = (e.ranges[0].start as usize, e.ranges[0].end as usize);
        assert_eq!(e.ranges[0].bytes_sha256, sha(&damaged[a..b]));
        assert!(receipt.to_string().contains("roll forward (kept)"));
        // Replay shows it: the repair log of the reopened device holds that one entry.
        let dev = open_dev(after.clone()).unwrap();
        assert_eq!(dev.repair_log().unwrap(), vec![e.clone()]);
        assert_eq!(dev.segment_count(), 2);

        // The backup holds what was overwritten: both superblocks (the damaged one
        // included) and the spare metadata region bytes.
        let bk = read_backup(&backup).unwrap();
        assert_eq!(bk.sections[0].offset, 0);
        assert_eq!(bk.sections[0].bytes, damaged[..2 * BLOCK as usize]);
        assert_eq!(bk.sections.len(), 2);
        let (o, n) = (bk.sections[1].offset as usize, bk.sections[1].bytes.len());
        assert_eq!(bk.sections[1].bytes, damaged[o..o + n]);
        // Nothing outside the backed-up ranges changed.
        for (i, (x, y)) in damaged.iter().zip(&after).enumerate() {
            if x != y {
                assert!(
                    i < 2 * BLOCK as usize || (o..o + n).contains(&i),
                    "byte {i} changed outside the backed-up ranges"
                );
            }
        }

        // A second run has nothing to do and writes nothing.
        let w = writes(&io);
        let again = repair(
            &io,
            RepairAction::RollForward,
            &operator(),
            &dir.join("b2"),
            NOW,
        )
        .unwrap();
        assert!(!again.wrote);
        assert_eq!(again.report.verdict, Verdict::Healthy);
        assert_eq!(again.report.history, vec![e]);
        assert_eq!(writes(&io), w);
        assert!(!dir.join("b2").exists());
        // And the store keeps working after the repair: a new change commits on top.
        let mut s = open_store(after).unwrap();
        assert_eq!(commit(&mut s, &key(9), "after-repair").unwrap().0, 11);
    }

    #[test]
    fn r1_repair_adopt_older_backs_up_drops_only_the_range_and_records_it() {
        let (io, damaged, _) = damaged_fixture();
        let dir = temp_dir("repair-adopt");
        let backup = dir.join("backup.bin");
        let report = diagnose(&io).unwrap();
        let l = &report.lost[0];
        let (a, e) = (l.start / BLOCK * BLOCK, l.end.div_ceil(BLOCK) * BLOCK);
        let receipt = repair(
            &io,
            RepairAction::AdoptOlderCheckpoint,
            &operator(),
            &backup,
            NOW,
        )
        .unwrap();
        let after = image(&io);
        // The store opens with the older checkpoint: slot 1's 8 changes.
        assert_eq!(open_seq(after.clone()), Ok(8));
        assert!(after[a as usize..e as usize].iter().all(|x| *x == 0));
        // The record names exactly what was dropped, with the digest of those bytes.
        let entry = receipt.entry.clone().unwrap();
        assert_eq!(entry.action, RepairAction::AdoptOlderCheckpoint);
        assert_eq!(
            (entry.segment_count_before, entry.segment_count_after),
            (1, 1)
        );
        let r = &entry.ranges[0];
        assert_eq!(
            (r.slot, r.start, r.end, r.records, r.first_seq),
            (2, a, e, 2, 9)
        );
        assert_eq!(r.bytes_sha256, sha(&damaged[a as usize..e as usize]));
        assert!(receipt.to_string().contains("DROPPED"));
        assert_eq!(
            open_dev(after.clone()).unwrap().repair_log().unwrap(),
            vec![entry]
        );
        // The backup holds the dropped bytes, so the loss can still be undone by hand.
        let bk = read_backup(&backup).unwrap();
        let s = bk.sections.iter().find(|s| s.offset == a).unwrap();
        assert_eq!(s.bytes, damaged[a as usize..e as usize]);
        assert!(s.bytes.iter().any(|x| *x != 0));
        // Changed bytes lie only in the backed-up ranges.
        for (i, (x, y)) in damaged.iter().zip(&after).enumerate() {
            if x != y {
                assert!(
                    bk.sections
                        .iter()
                        .any(|s| (s.offset..s.offset + s.bytes.len() as u64).contains(&(i as u64))),
                    "byte {i} changed outside the backed-up ranges"
                );
            }
        }
        // The backup file is never overwritten.
        assert!(repair(
            &io,
            RepairAction::AdoptOlderCheckpoint,
            &operator(),
            &backup,
            NOW
        )
        .is_ok_and(|r| !r.wrote));
    }

    #[test]
    fn r1_repair_interrupted_adopt_finishes_without_a_second_record() {
        let (io, damaged, _) = damaged_fixture();
        let dir = temp_dir("repair-resume");
        let first = repair(
            &io,
            RepairAction::AdoptOlderCheckpoint,
            &operator(),
            &dir.join("b1"),
            NOW,
        )
        .unwrap();
        // Power cut after the record committed but before the zeroing reached the
        // device: put the slot bytes back.
        let l = &first.report.lost[0];
        let (a, e) = (
            (l.start / BLOCK * BLOCK) as usize,
            (l.end.div_ceil(BLOCK) * BLOCK) as usize,
        );
        io.rec().image[a..e].copy_from_slice(&damaged[a..e]);
        assert_eq!(
            open_seq(image(&io)),
            Err(RefusalCode::CheckpointCorrupt),
            "still refuses: the drop is recorded but not done"
        );
        // Rolling forward over a recorded drop is refused and writes nothing.
        let w = writes(&io);
        let err = repair(
            &io,
            RepairAction::RollForward,
            &operator(),
            &dir.join("b2"),
            NOW,
        )
        .unwrap_err();
        assert!(err.message.contains("did not finish"), "{err:?}");
        assert_eq!(writes(&io), w);
        // The same action finishes it; the log still holds exactly one entry.
        let second = repair(
            &io,
            RepairAction::AdoptOlderCheckpoint,
            &operator(),
            &dir.join("b3"),
            NOW + 1,
        )
        .unwrap();
        assert_eq!(second.entry, first.entry);
        assert_eq!(open_seq(image(&io)), Ok(8));
        let log = open_dev(image(&io)).unwrap().repair_log().unwrap();
        assert_eq!(log, vec![first.entry.unwrap()]);
    }

    #[test]
    fn r1_repair_refuses_to_roll_forward_a_slot_without_batches() {
        let (io, _, _) = damaged_fixture();
        let start = diagnose(&io).unwrap().lost[0].batches[0].offset as usize;
        // The first batch header no longer parses: there is nothing to roll forward.
        io.rec().image[start] ^= 0xFF;
        let img = image(&io);
        let w = writes(&io);
        let dir = temp_dir("repair-nobatch");
        let err = repair(
            &io,
            RepairAction::RollForward,
            &operator(),
            &dir.join("b"),
            NOW,
        )
        .unwrap_err();
        assert!(err.message.contains("no WAL v2 batch header"), "{err:?}");
        assert_eq!((image(&io), writes(&io)), (img, w));
        assert!(!dir.join("b").exists());
    }

    /// Negative control: an intact image has nothing to repair, and neither action
    /// writes a byte (device SHA-256 before and after).
    #[test]
    fn r1_repair_intact_image_has_nothing_to_do_and_never_writes() {
        let io = MemIo::new(vec![0u8; 4 << 20]);
        let cfg = mem_cfg(FormatPolicy::FormatIfBlank, META);
        let dev = BlockDevice::open(Box::new(io.clone()), &cfg, SEG).unwrap();
        let mut s =
            SynapseStore::open_on_device(dev, cfg.path.clone(), TRUNCATE, limits()).unwrap();
        for i in 0..10 {
            commit(&mut s, &key(9), &format!("intact-{i}")).unwrap();
        }
        drop(s);
        // Two statements: the guard from io.rec() would otherwise live to the end of the
        // tuple expression while writes(&io) takes the same lock on this thread.
        let before = sha(&image(&io));
        let w = writes(&io);
        let dir = temp_dir("repair-intact");
        let r = diagnose(&io).unwrap();
        assert_eq!(r.verdict, Verdict::Healthy);
        assert!(r.lost.is_empty());
        for (i, action) in [
            RepairAction::RollForward,
            RepairAction::AdoptOlderCheckpoint,
        ]
        .into_iter()
        .enumerate()
        {
            let b = dir.join(format!("b{i}"));
            let receipt = repair(&io, action, &operator(), &b, NOW).unwrap();
            assert!(!receipt.wrote);
            assert_eq!(receipt.entry, None);
            assert!(!b.exists());
        }
        assert_eq!(sha(&image(&io)), before);
        assert_eq!(writes(&io), w);
    }

    #[test]
    fn r1_repair_log_that_does_not_verify_refuses_the_mount() {
        let (io, _, _) = damaged_fixture();
        let dir = temp_dir("repair-tamper");
        repair(
            &io,
            RepairAction::RollForward,
            &operator(),
            &dir.join("b"),
            NOW,
        )
        .unwrap();
        let good = image(&io);
        let log = open_dev(good.clone())
            .unwrap()
            .read_named(REPAIR_LOG_NAME)
            .unwrap();

        // Rewrite the log through an ordinary metadata commit (its region digest holds),
        // so only the repair log's own checks can catch each change.
        let rewritten = |log: Vec<u8>| {
            let mem = MemIo::new(good.clone());
            let d = BlockDevice::open(
                Box::new(mem.clone()),
                &mem_cfg(FormatPolicy::OpenExisting, META),
                SEG,
            )
            .unwrap();
            d.write_named(REPAIR_LOG_NAME, &log).unwrap();
            drop(d);
            image(&mem)
        };
        // A flipped signature bit.
        let mut bad_sig = log.clone();
        *bad_sig.last_mut().unwrap() ^= 1;
        // A changed range (the signature no longer covers it).
        let mut bad_range = log.clone();
        bad_range[4 + 4 + 2 + 2 + 16 + 32 + 64 + 4 + 8] ^= 1;
        // A second entry signed correctly but not chained to the first.
        let entry = verify_repair_log(&log, &open_dev(good.clone()).unwrap().geometry().uuid)
            .unwrap()
            .remove(0);
        let mut forged = entry.clone();
        forged.generation += 10;
        forged.signature = operator().sign(&forged.signable_bytes()).to_bytes();
        let mut unchained = log.clone();
        let enc_len = log.len() - 4;
        unchained.extend_from_slice(&(enc_len as u32).to_le_bytes());
        let mut forged_bytes = forged.signable_bytes()[DOMAIN_R1_REPAIR_SIGN_V1.len()..].to_vec();
        forged_bytes.extend_from_slice(&forged.signature);
        unchained.extend_from_slice(&forged_bytes);

        for (what, bytes, needle) in [
            ("signature", bad_sig, "signature does not verify"),
            ("range", bad_range, "signature does not verify"),
            ("chain", unchained, "breaks the hash chain"),
        ] {
            let img = rewritten(bytes);
            let err = open_dev(img.clone()).unwrap_err();
            assert_eq!(err.code, RefusalCode::CheckpointCorrupt, "{what}");
            assert!(err.message.contains(needle), "{what}: {err:?}");
            match diagnose(&MemIo::new(img)).unwrap().verdict {
                Verdict::Unrepairable(why) => assert!(why.contains(needle), "{what}: {why}"),
                v => panic!("{what}: {v:?}"),
            }
        }
        // Control: the untouched log mounts.
        assert!(open_dev(rewritten(log)).is_ok());
    }

    #[test]
    fn r1_repair_backup_overflow_length_is_refused_without_panicking() {
        let dir = temp_dir("repair-backup-overflow");
        let path = dir.join("overflow.backup");
        let mut body = b"SYNREPAIRBAK001\n".to_vec();
        body.extend_from_slice(&[0u8; 16]);
        body.extend_from_slice(&1u32.to_le_bytes());
        body.extend_from_slice(&0u64.to_le_bytes());
        body.extend_from_slice(&u64::MAX.to_le_bytes());
        let digest = sha(&body);
        body.extend_from_slice(&digest);
        fs::write(&path, &body).unwrap();
        assert!(
            read_backup(&path).is_err(),
            "an impossible section length must be refused"
        );
        assert_eq!(
            fs::read(&path).unwrap(),
            body,
            "a refused backup must not change"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn r1_repair_refuses_a_foreign_device() {
        let mut img = vec![0u8; 4 << 20];
        img[510] = 0x55;
        img[511] = 0xAA; // MBR
        let io = MemIo::new(img);
        assert!(diagnose(&io).is_err());
        let b = temp_dir("repair-foreign").join("b");
        assert!(repair(&io, RepairAction::RollForward, &operator(), &b, NOW).is_err());
        assert_eq!(writes(&io), 0);
        assert!(!b.exists());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn r1_repair_parent_drop_releases_lock_despite_inherited_helper_fd() {
        let dir = temp_dir("repair-inherited-lock");
        let path = dir.join("device.img");
        fs::File::create(&path).unwrap().set_len(4 * BLOCK).unwrap();
        let io = DirectFile::open(&path).unwrap();
        let mut ready = [0i32; 2];
        let mut release = [0i32; 2];
        // The child models a helper between fork and exec. It runs only async-signal-safe
        // libc calls, never accesses the device, and closes on parent EOF as well.
        unsafe {
            assert_eq!(libc::pipe2(ready.as_mut_ptr(), libc::O_CLOEXEC), 0);
            assert_eq!(libc::pipe2(release.as_mut_ptr(), libc::O_CLOEXEC), 0);
            let pid = libc::fork();
            if pid == 0 {
                libc::close(ready[0]);
                libc::close(release[1]);
                let sent = libc::write(ready[1], b"r".as_ptr().cast(), 1);
                libc::close(ready[1]);
                let mut byte = 0u8;
                let received = libc::read(release[0], (&mut byte as *mut u8).cast(), 1);
                libc::close(release[0]);
                libc::_exit(if sent == 1 && received == 1 { 0 } else { 1 });
            }
            if pid < 0 {
                for fd in ready.into_iter().chain(release) {
                    libc::close(fd);
                }
                panic!("fork failed");
            }
            libc::close(ready[1]);
            libc::close(release[0]);
            let mut byte = 0u8;
            let received = libc::read(ready[0], (&mut byte as *mut u8).cast(), 1);
            libc::close(ready[0]);
            // The helper is alive with the inherited descriptor, but the actual owner
            // is gone. Capture the result, then reap the child before any assertion.
            drop(io);
            let reopened = DirectFile::open(&path);
            let sent = libc::write(release[1], b"x".as_ptr().cast(), 1);
            libc::close(release[1]);
            let mut status = 0;
            let waited = libc::waitpid(pid, &mut status, 0);
            assert_eq!((received, sent, waited, status), (1, 1, pid, 0));
            assert!(reopened.is_ok(), "a helper that never uses the device retained the departed owner's lock: {reopened:?}");
        }
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn r1_repair_holds_the_exclusive_lock() {
        let dir = temp_dir("repair-lock");
        let path = dir.join(TEST_DEVICE_FILE);
        make_device_file(&path, TEST_DEVICE_BYTES);
        let cfg = BlockDeviceConfig {
            path: path.clone(),
            format: FormatPolicy::FormatIfBlank,
            meta_region_bytes: TEST_META_BYTES,
            allow_foreign_signature: false,
        };
        let held = BlockDevice::open_path(&cfg, SEG).unwrap();
        assert!(diagnose_path(&path).is_err());
        let b = dir.join("b");
        assert!(repair_path(&path, RepairAction::RollForward, &operator(), &b, NOW).is_err());
        assert!(!b.exists());
        drop(held);
        // Control: once the store is closed the lock is free and the device diagnoses.
        assert_eq!(diagnose_path(&path).unwrap().verdict, Verdict::Healthy);
        let _ = fs::remove_dir_all(&dir);
    }
}
