# R1: Segment Store on a Raw Block Device (AIENOS Block-Store Specification)

ADR 0003 section 9 step 27 (issue #47). R1 runs the A2 segment store (`docs/A2_SEGMENT_STORE.md`) on one
byte range of a block device with no filesystem under it. The store above the device is unchanged: the
same WAL v2 batches, the same segment index, the same checkpoint, the same recovery rules. What changes
is where the bytes live and what replaces the filesystem's guarantees (file creation, atomic rename,
directory flush). This document is the on-device format AIENOS implements; the code is
`crates/synapse-store/src/blockdev.rs`.

Status: implemented and tested on a preallocated regular file opened with `O_DIRECT`. Not yet run on a
real raw partition (section 7).

## 1. The Device

- **One path, named by the caller.** `BlockDeviceConfig::path` must be absolute. The store opens that
  path and nothing else: no `/dev` scan, no globbing, no derived or temporary paths, never creates it.
  Symlinks are refused (`O_NOFOLLOW`, plus a `symlink_metadata` check). The path must be a regular file
  or a block device; a block device is opened `O_EXCL` (the kernel refuses it while it is mounted or held
  by another exclusive user). After opening, the device and inode numbers are compared with the checked
  path, so a swap between check and open is refused.
- **One opener.** The open takes an exclusive `flock` on the descriptor (non-blocking); a second opener,
  in this process or another, is refused with "in use" while the first holds it. This covers regular
  files, where `O_EXCL` means nothing.
- **Formatting is never the default.** `BlockDeviceConfig::new` uses `FormatPolicy::OpenExisting`; the
  caller must ask for `FormatIfBlank`.
- **`O_DIRECT`.** Every read and write bypasses the page cache. Transfers are 4 KiB aligned in offset,
  length, and buffer address (an aligned bounce buffer in safe Rust). A write that is not block aligned
  is done as read, modify, write of the covering blocks.
- **Length.** The device length must be a multiple of 4 KiB and hold the label area, two metadata
  regions, and at least two segment slots.

### 1.1 Refusing a disk that is not mine

Before anything is written, the device is classified (`classify_device`) from its label area (the first
128 KiB) and from fixed offsets near its end:

| Label | Meaning | Action |
| :--- | :--- | :--- |
| Synapse | The R1 superblock magic at byte 0 or 4096 | Mount (section 4 validates the copies) |
| Blank | Every byte of the label area is zero | Format only with `FormatPolicy::FormatIfBlank`, else refuse |
| Foreign | A signature from the table below, at the start or the end of the device | Refuse (`CapacityRefused`, names the signature) |
| Unknown | Any other non-zero byte | Refuse |

The Synapse magic is checked first, then `SIGNATURES` in order (MBR last, so a GPT disk is named GPT).
`L` is the device length:

| Signature | Where |
| :--- | :--- |
| GPT header / backup header | `EFI PART` at 512 and 4096; backup at `L - 512` and `L - 4096` |
| ext2/3/4 | `53 EF` at 1080 |
| XFS, LUKS, squashfs | `XFSB`, `LUKS BA BE`, `hsqs` at 0 |
| btrfs | `_BHRfS_M` at 0x10040 and its mirrors at 64 MiB + 0x40 and 256 GiB + 0x40 |
| NTFS, exFAT | OEM id at 3 |
| FAT12/16, FAT32 | `FAT1` at 54, `FAT32` at 82 |
| LVM2 | `LABELONE` in any of sectors 0 to 3 |
| Linux swap | `SWAPSPACE2` at page end minus 10 for 4, 16, 64 KiB pages; `SWAP-SPACE` for 4 KiB |
| ISO 9660 | `CD001` at 0x8001 |
| F2FS | `10 20 F5 F2` at 1024 |
| MD RAID 1.2, 1.1 | `FC 4E 2B A9` at 4096, at 0 |
| MD RAID 1.0 | same magic at `(L - 8 KiB)` rounded down to 4 KiB |
| MD RAID 0.90 | same magic at `L` rounded down to 64 KiB, minus 64 KiB |
| ZFS labels L0 to L3 | an uberblock magic (either byte order) in a 1 KiB slot of the uberblock array (label + 128 KiB) of the 256 KiB labels at 0, 256 KiB, and at `L'` - 512 KiB, `L'` - 256 KiB, where `L'` is `L` rounded down to 256 KiB |
| MBR / boot sector | `55 AA` at 510 |

Each entry has its own test that builds a device with only that signature and expects it named, plus a
test that the table has exactly that many entries, so deleting or changing one turns a test red. A Foreign or Unknown device is formatted only when the caller sets
`allow_foreign_signature: true` and `FormatPolicy::FormatIfBlank`; the refusal leaves the device
byte-for-byte unchanged (tested).

## 2. On-Device Layout

All integers little-endian. Block size 4,096 bytes.

| Range | Content |
| :--- | :--- |
| `0 .. 4 KiB` | Superblock copy 0 |
| `4 KiB .. 8 KiB` | Superblock copy 1 |
| `8 KiB .. 128 KiB` | Zero (part of the label area that the signature check reads) |
| `1 MiB .. 1 MiB + M` | Metadata region 0 (`M = meta_region_bytes`, default 64 MiB, 4 KiB multiple) |
| `1 MiB + M .. 1 MiB + 2M` | Metadata region 1 |
| `data_offset ..` (1 MiB aligned) | Segment slots 1, 2, ... each `slot_stride = 4 KiB + segment_bytes` |

### 2.1 Superblock

The first 164 bytes of its 4 KiB block; the rest of the block is zero.

| Offset | Size | Field |
| ---: | ---: | :--- |
| 0 | 8 | magic `SYNBLKS1` |
| 8 | 4 | format version (1) |
| 12 | 4 | block size (4096) |
| 16 | 16 | device uuid (random at format) |
| 32 | 8 | generation |
| 40 | 8 | device_bytes |
| 48 | 8 | meta_offset0 |
| 56 | 8 | meta_offset1 |
| 64 | 8 | meta_region_bytes |
| 72 | 8 | data_offset |
| 80 | 8 | slot_stride |
| 88 | 8 | segment_bytes |
| 96 | 8 | slot_count |
| 104 | 8 | segment_count (committed segments) |
| 112 | 8 | meta_len (bytes of namespace in the active region) |
| 120 | 1 | meta_slot (active region, 0 or 1) |
| 121 | 7 | zero |
| 128 | 32 | meta_sha256 = SHA-256 of `"SYNAPSE_BLOCK_META_V1\0"` followed by the namespace bytes |
| 160 | 4 | CRC-32C of bytes 0..160 |

Decoding is strict: wrong magic, version, block size, CRC, a geometry that does not fit the device,
regions that overlap, `segment_count > slot_count`, or non-zero padding make the copy invalid.
Generation `g` is always written to copy `g % 2`, so the newest copy and the one before it are both on
the device.

### 2.2 Metadata region (the namespace)

The A2 store keeps a few small files next to its segments: `wal.log` (the segment marker),
`checkpoint.v2`, `checkpoint.v1` (tombstone), and `wal.v2.index.<16-hex>`. On the device these are named
objects in one namespace, stored whole in a metadata region:

```
"SBM1" | u32 count | count x ( u16 name_len | name (UTF-8) | u64 len | bytes )
```

Names are strictly increasing. The active region is the one the newest valid superblock names; its
digest is in the superblock.

### 2.3 Segment slot

```
4 KiB header: "SBSG" | u32 version (1) | uuid[16] | u64 segment id | u64 segment_bytes | u32 CRC-32C
then segment_bytes of WAL v2 batches (crate::wal2), byte-for-byte the A2 segment file contents
```

Slot `k` holds segment id `k`. A header is valid only with the right magic, version, CRC, this device's
uuid, id `k`, and the superblock's `segment_bytes`, so a header left over from an earlier format of the
same disk is not data.

## 3. Durability Ordering

Every step ends with one `fdatasync` of the device descriptor. On a raw block device that is a FLUSH of
the drive's volatile write cache; on the file-backed test device it is `fdatasync` of the file.

1. **Format.** Write an empty namespace into metadata region 0, then the label area (zeros, with
   superblock generation 1, `segment_count` 0, naming region 0, in copy 1), flush.
2. **Metadata commit** (replaces A2's "write temporary file, sync, rename, sync directory"). Write the
   whole new namespace into the region the current superblock does *not* name; write superblock
   generation `g + 1` (naming that region, with its digest) into copy `(g + 1) % 2`; flush. A commit
   that changes only `segment_count` writes only the superblock.
3. **Segment rotation** (replaces A2's "create file, sync, sync directory"). Zero the whole data area,
   flush; write the slot header, flush; then a metadata commit raises `segment_count` to the new id,
   flush. Only then is a batch written into the slot. The order matters: a valid header is only ever
   written over a data area that is already durably zero, so a valid header past `segment_count` with
   non-zero data can only mean acknowledged batches whose commit record was lost (section 4, step 3).
4. **Batch** (unchanged from A2). One aligned positioned write of the batch into the active slot, one
   flush. A change is acknowledged only after that flush returned success.

Why one flush per commit is enough: if power fails after the region write but before the superblock is
durable, the old superblock names the old region, which was not touched. If the superblock is durable
but part of the region is not (the drive reordered the writes inside the flush window), the region's
SHA-256 does not match the superblock, so recovery skips that copy and takes the older one, whose region
is intact. A torn superblock fails its CRC and is skipped the same way.

A failed flush acknowledges nothing (tested: the batch and every later ingest return errors).

## 4. Recovery

1. Read both superblock copies. Take the one with the highest generation whose CRC holds and whose
   active region matches `meta_sha256`. If it fails, take the other. If both fail, or the two copies disagree on the
   geometry, refuse (`CheckpointCorrupt`).
2. The namespace in that region supplies `wal.log`, `checkpoint.v2`, `checkpoint.v1`, and the segment
   index exactly as the A2 files would.
3. Segments 1..=`segment_count` are data. Slot `segment_count + 1` is listed only if its header is
   valid (a rotation that crashed before its superblock commit); it is then treated as A2 treats a last
   segment file that is all zero. If that slot's header is valid and its data area holds any non-zero
   byte, the superblock in use is older than the data on the device (the newest copy was damaged, so
   acknowledged batches in that slot would be dropped): mount refuses with `CheckpointCorrupt` and
   names the slot, under strict and truncating recovery alike. Slots beyond are ignored; their bytes may
   be stale and the next rotation zeroes them.
4. From there the A2 rules apply unchanged: index bound to the checkpoint by SHA-256, torn tail accepted
   only in the last segment holding data (strict recovery refuses it as `WalTornFrame`, truncating
   recovery zeroes it on the device and flushes), any damage elsewhere fails closed.

A device that is full refuses the batch that would need a new slot ("device full") and keeps every
acknowledged change.

## 5. Acceptance and Tests

| Test | What it proves |
| :--- | :--- |
| A2 crash suite, `segment_tests.rs`, compiled a second time unchanged in `blockdev_a2_suite.rs` (11 tests, 9 of which touch the device; see section 7) | Every A2 crash, damage, and recovery case passes on the device. The suite's file operations get a device meaning (a segment file is a slot's data area, deleting it erases the slot header, small files are named objects); crash children reopen through the same device. |
| `r1_suite_stores_are_raw_block_stores` | Control: the stores that suite opens hold only the device file; segments and metadata are on the device. |
| `r1_power_cut_at_every_write_boundary_keeps_every_ack` | Power-cut simulation, below. |
| `r1_refuses_a_device_carrying_a_filesystem_or_partition_signature` | ext4, GPT, XFS, LUKS images are refused and left unchanged; the explicit override formats. |
| `r1_refuses_a_device_whose_signature_is_only_at_its_end` | GPT backup, MD 0.90, MD 1.0, ZFS L2 and L3 placed only at the end of a zeroed device are refused and the device is left unchanged. |
| `r1_sig_*` (38) and `r1_every_signature_has_a_pin_test` | One test per `SIGNATURES` entry (a sparse 300 GiB device carrying only that magic at its offset), and the table length pinned. |
| `r1_lost_newest_superblock_never_drops_acknowledged_changes` | 10 acknowledged changes over two slots, newest superblock copy damaged: reopen either refuses with `CheckpointCorrupt` or returns all 10, under both recovery modes; never fewer. |
| `r1_a_second_opener_of_the_device_is_refused` | A second open while the store holds the device is refused ("in use"). |
| `r1_refuses_unknown_label_bytes_and_blank_devices_without_format` | Unknown bytes refused; a blank device is not formatted without `FormatIfBlank`. |
| `r1_opens_only_the_configured_path` | Relative path, directory, symlink, missing path (not created), odd length refused; unaligned writes round-trip through `O_DIRECT`. |
| `r1_classifies_known_signatures` | Blank, Unknown, Synapse (magic in copy 1 only), and GPT named before MBR on a protective-MBR disk. |
| `r1_superblock_falls_back_to_the_older_copy_when_the_newest_is_damaged` | Damaged newest superblock or region: mount uses the older copy. |
| `r1_full_device_refuses_the_batch_and_keeps_every_ack` | Two slots: "device full" refusal, all 16 acknowledged changes kept. |
| `r1_failed_device_flush_acknowledges_nothing` | A flush error acknowledges nothing. |
| bench `block_device_bench_never_writes_to_a_file_it_did_not_create` | `--block-device` on an existing file carrying an ext4 magic, or on a symlink to it, is refused and the file is unchanged. |
| bench `block_device_bench_creates_formats_and_removes_its_own_device` | The bench creates its device file, formats it, runs, and removes it. |

### 5.1 Power-cut simulation

An in-memory device records every write and flush of a workload: format, 20 commits across three
segments, a checkpoint, 6 more commits, reopen, 2 more commits (56 device writes, 50 flushes, 28
acknowledgements). The bytes outside the label area start as pseudo-random garbage (a disk used before).
For every write the device image is cut while that write is in flight, four ways, at every 512-byte
sector boundary:

- **prefix**: the first k sectors of the write landed;
- **suffix**: the last k sectors landed;
- **lost write**: one write issued since the last completed flush never landed (the drive reordered);
- **hole**: the write landed except one middle sector, which keeps its old bytes.

Each image is recovered with truncating and with strict recovery. Required: every change acknowledged
before the cut is present and readable, nothing beyond what was written appears, and the recovered store
keeps working (every 23rd image commits again and reopens).

Result: prefix 1,465 images, 1,448 opened; suffix 1,464, 1,208 opened; lost write 64, 61 opened; every
image that did not open was cut before the first acknowledgement (the format had not completed, nothing
promised). No acknowledged change was lost in any image. Strict recovery refused 336 + 336 images as
`WalTornFrame` (a torn tail), never any other way. Hole images: 1,352, 1,037 opened, 297 failed closed
with an error and 0 lost an acknowledged change silently; a hole in the middle of a batch is damage the
A2 format cannot tell from corruption, so failing closed is the A2 behaviour, and it is never silent.

### 5.2 Red before green

`evidence/r1-raw-block-store/red-green/`: on main the new tests do not compile (no device store); each
recorded mutation of the R1 code (`mutation-M*.txt`, each with its diff and the failing test) turns a named test red; the branch is green.

## 6. Seconds and Joules per Accepted Change

This section is a performance report. It is not acceptance (section 5 is).

**Method.** The A2 harness (`synapse-bench segments`, `docs/A2_SEGMENT_STORE.md` section 4) unchanged,
plus `--block-device <path>`: the same workload (N agent threads, 4,000 changesets of one 11,949-byte
blob each, a checkpoint every 1,000, 16 MiB segments) on the R1 store. Both arms on the same NVMe
partition (`/dev/nvme0n1p2`, ext4): A2 as files in a directory; R1 on a 512 MiB regular file that the
bench creates for each cell (`O_CREAT | O_EXCL | O_NOFOLLOW`, written with zeros and synced), the store
opens with `O_DIRECT` and formats, and the bench removes after the cell. The two arms ran interleaved
(R1, A2, R1, A2, R1, A2), one repetition per invocation, so both saw the same host conditions; the
figures are the median and range of the three. Agents 1, 4, 8, 32. The bounds are those of A2 (ADR
section 6): the flush bound is the cheapest `overwrite_*_fdatasync` p50 measured by `synapse-bench
floor` in the same session, 0.802 ms (64 KiB); fraction of bound = bound / measured, so 1.0 is at the
bound.

**Results** (run 2026-10-17T05:45:44Z to 05:50:31Z, branch commit `222c24d`; raw samples
`evidence/r1-raw-block-store/measurement/raw-{r1,a2}-{0,1,2}.json`, per-invocation reports
`report-*.json`, aggregate `summary.json`):

| Agents | R1 interval per change (ms) median [range] | A2 on ext4 (ms) median [range] | Interval bound (ms) | R1 fraction | A2 fraction | R1 / A2 median |
| ---: | :--- | :--- | ---: | ---: | ---: | ---: |
| 1 | 1.2945 [1.2396, 1.4545] | 1.3858 [1.3796, 1.4494] | 0.8020 | 0.620 | 0.579 | 0.934 (calc:acce0c48) |
| 4 | 0.5817 [0.5696, 0.6484] | 0.6058 [0.5701, 0.6584] | 0.2005 | 0.345 | 0.331 | 0.960 (calc:aa16356c) |
| 8 | 0.3271 [0.3170, 0.3271] | 0.3468 [0.3416, 0.3833] | 0.1003 | 0.307 | 0.289 | 0.943 (calc:7358d145) |
| 32 | 0.1068 [0.1059, 0.1139] | 0.1264 [0.1242, 0.1710] | 0.0251 | 0.235 | 0.198 | 0.845 (calc:c585502f) |

| Agents | R1 latency p50 / p99 (ms) | A2 latency p50 / p99 (ms) | R1 package energy per change (mJ) median [range] | A2 package energy per change (mJ) median [range] | Changes per flush R1 / A2 |
| ---: | :--- | :--- | :--- | :--- | :--- |
| 1 | 1.198 / 1.929 | 1.204 / 2.299 | 34.397 [27.943, 37.420] | 37.937 [33.608, 45.635] | 1.00 / 1.00 |
| 4 | 2.220 / 4.900 | 2.112 / 3.712 | 14.639 [12.228, 17.533] | 16.597 [15.289, 19.674] | 2.31 / 2.19 |
| 8 | 2.296 / 9.524 | 2.392 / 12.194 | 8.049 [7.626, 11.075] | 9.432 [8.813, 10.506] | 4.02 / 4.09 |
| 32 | 2.570 / 18.504 | 2.638 / 40.349 | 3.384 [2.774, 3.992] | 4.568 [3.310, 4.648] | 15.94 / 15.81 |

Latency fraction (p50, 1 agent): R1 0.669, A2 0.666. Every cell accepted 4,000 changes, wrote 4
segments and no blob files. Checkpoints (48 per arm): R1 median 29.3 ms [12.1, 131.1], A2 median
41.7 ms [30.6, 82.9].

**Is R1 lower?** The R1 median is lower than A2's at every agent count (0.85 to 0.96 of A2). At 8 and
32 agents all three R1 samples are below all three A2 samples; at 1 and 4 agents the ranges overlap,
so there the difference is inside the spread. Three samples per arm is a small count; this is the
file-backed R1 format, not R1 on a raw partition. Package energy per change is also lower for R1 at
every agent count, but the ranges overlap at 1, 4 and 8 agents, the idle window read 22.6 to 34.4 W
from other sessions' load, and the meter covers the SoC package only (NVMe unmeasured).

**Did R1 get slower after the review changes?** Not measurably. The rotation order change adds one
flush per new segment (4 per 4,000-change cell). Against the previous run at `57d1135`, R1's median
interval is 0.950 of it at 1 agent (calc:54ddff70), 0.978 at 4 (calc:cda8bb34), 1.053 at 8
(calc:7bfbaa0f) and 0.950 at 32 (calc:64f82441). The two sessions ran under different host load (load
average 2.4 now, 6 to 8.5 then) and a different flush floor (0.802 vs 0.894 ms), and A2, whose code did
not change, moved the same way at 8 agents (1.060 of its previous median, calc:b2b6a60a), so the
cross-session differences are host conditions, not the store. The previous run is kept in
`evidence/r1-raw-block-store/measurement-57d1135/`.

**This does not decide adoption.** Issue #47 keeps the layer only if it is lower. The R1 arm here is
the R1 format on a regular file: its `fdatasync` still goes through ext4's block mapping and journal
path for the file. The deciding measurement, R1 on a dedicated raw partition beside A2 on ext4 on the
same drive, is owed (section 7).

**Reproduce.**

```sh
cargo build --release -p synapse-bench
target/release/synapse-bench floor --dir <scratch-dir> --out floor.json --iterations 300
target/release/synapse-bench segments --dir <dir> --out raw-r1.json --reps 1 --block-device <new-absolute-path>
target/release/synapse-bench segments --dir <dir> --out raw-a2.json --reps 1
target/release/synapse-bench segments-report --raw raw-<arm>.json --floor floor.json > report-<arm>.json
```

`--block-device` names an absolute path that must not exist; the bench creates the device file there
for each cell (`--block-device-mib`, `--block-meta-mib` set its size) and removes it afterwards. It
refuses an existing path or a symlink. `measurement/run.sh` is the exact sequence; `manifest.json`
records the binary's SHA-256, the host, and the run window; `SHA256SUMS` seals the files.


## 7. Limits

- **Not yet measured on a raw partition.** Every R1 figure here is the R1 store on a preallocated
  regular file on ext4, opened with `O_DIRECT`. The file's blocks still pass through ext4's block mapping
  and its `fdatasync` path. The true raw-partition measurement is owed (it needs a dedicated partition,
  which this host does not have spare), so this report cannot by itself decide whether R1 is adopted.
- **Drive cache power loss is UNVERIFIED.** The ordering assumes a FLUSH makes earlier completed
  writes durable. No physical power cut was run; the simulation models torn, lost, and holed writes.
- The lost-write model drops one unflushed write at a time, not every subset.
- NVMe energy is UNMEASURED; the meter is the SoC package (`aien_spbm`), uncalibrated.
- 9 of the 11 A2 suite tests touch the device. The other two do not: `a2_segment_index_round_trips_and_refuses_damage`
  is a pure codec test, and the pre-A2 upgrade test copies directory fixtures (there are no pre-A2 raw
  block stores), so in the R1 run it exercises the directory store again.
- A crash during format may leave a device that refuses to open; nothing was acknowledged by then, and
  the device is reformatted only through an explicit `FormatIfBlank` (and override, if the label area is
  no longer zero).
- The device store requires group commit (WAL v2); the v1 per-change WAL is not supported on it.
