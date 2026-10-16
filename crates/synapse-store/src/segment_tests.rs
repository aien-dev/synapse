//! ADR 0003 A2 segment store tests: the extended crash suite of issue #23.
//!
//! Acceptance under test: torn segment, crash between payload and index, flush failure,
//! crash after a new segment file before its directory flush; every acknowledged change
//! survives each of them. The stores here use 64 KiB segments so a few changesets of
//! about 6 KB cross several segment files. Process crashes run the test binary again as
//! a child that terminates itself at the injected fault (exit code
//! [`FAULT_CRASH_EXIT_CODE`]); the child records every acknowledgment in `acks.txt`
//! right after the store returns it.

use super::a1_tests::{copy_fixture, copy_tree, expect};
use super::tests::{make_signed_changeset, temp_store_dir};
use super::*;
use ed25519_dalek::SigningKey;
use segment::SegEvent;
use std::collections::BTreeSet;
use std::process::Command;

/// Segment size of the test stores.
const SEG: u64 = 64 * 1024;
/// Blob size per changeset: one changeset per batch, one batch = 8 KiB on disk.
const BLOB: usize = 6000;
/// On-disk length of one batch of one changeset (asserted on the first commit).
const PER: u64 = 8192;
const CHILD_ENV: &str = "SYNAPSE_A2_CRASH_CHILD";
const STRICT: RecoveryPolicy = RecoveryPolicy::StrictFailClosed;
const TRUNCATE: RecoveryPolicy = RecoveryPolicy::TruncateTornTail;

fn limits() -> StoreLimits {
    StoreLimits {
        segment_bytes: SEG,
        wal_prealloc_bytes: 16 * 1024,
        ..Default::default()
    }
}

fn try_open(dir: &Path, recovery: RecoveryPolicy) -> SynapseResult<SynapseStore> {
    SynapseStore::open(dir, FsyncPolicy::GROUP_COMMIT_DEFAULT, recovery, limits())
}

fn open(dir: &Path) -> SynapseStore {
    try_open(dir, STRICT).unwrap()
}

fn key(n: u8) -> SigningKey {
    SigningKey::from_bytes(&[n; 32])
}

/// A signed single-file changeset with distinct content per label.
fn cs(key: &SigningKey, label: &str) -> (ChangesetEnvelope, Vec<(BlobDigest, Vec<u8>)>) {
    let mut content = format!("// {label}\n").into_bytes();
    let mut x: u8 = label
        .bytes()
        .fold(11u8, |a, b| a.wrapping_mul(31).wrapping_add(b));
    while content.len() < BLOB {
        x = x.wrapping_mul(13).wrapping_add(1);
        content.push(b'a' + x % 26);
    }
    make_signed_changeset(
        key,
        label,
        &format!("src/{label}.rs"),
        &content,
        vec![],
        1000,
    )
}

fn committed_seq_of(out: &IngestOutcome) -> WalSeq {
    match out {
        IngestOutcome::Committed {
            wal_seq,
            durability,
            ..
        } => {
            assert_eq!(*durability, DurabilityGuarantee::FsyncBeforeAck);
            *wal_seq
        }
        other => panic!("expected Committed, got {other:?}"),
    }
}

fn commit(store: &mut SynapseStore, key: &SigningKey, label: &str) -> WalSeq {
    let before = store
        .wal_v2
        .as_ref()
        .map(|w| (w.active(), w.write_offset()));
    let (env, blobs) = cs(key, label);
    let seq = committed_seq_of(&store.ingest_changeset(env, &blobs).unwrap());
    if before == Some((1, 0)) {
        assert_eq!(offset(store), PER, "one changeset per 8 KiB batch");
    }
    seq
}

fn active(store: &SynapseStore) -> u64 {
    store.wal_v2.as_ref().unwrap().active()
}

fn offset(store: &SynapseStore) -> u64 {
    store.wal_v2.as_ref().unwrap().write_offset()
}

/// True when the next one-changeset batch starts a new segment file.
fn next_rotates(store: &SynapseStore) -> bool {
    let at = offset(store);
    at > 0 && at + PER > SEG
}

/// Every changeset and its blobs are readable at the latest snapshot.
fn assert_all_readable(store: &SynapseStore, expected: usize) {
    let all = store.list_changesets(None, None, None).unwrap();
    assert_eq!(all.len(), expected, "changeset count");
    for c in &all {
        for m in &c.envelope.mutations {
            if let MutationOp::Upsert {
                blob_digest,
                size_bytes,
                ..
            } = &m.op
            {
                let bytes = store.get_blob_visible(*blob_digest, None, None).unwrap();
                assert_eq!(bytes.len() as u64, *size_bytes);
            }
        }
    }
}

fn seg_path(dir: &Path, id: u64) -> PathBuf {
    dir.join(segment::segment_file_name(id))
}

fn segments(dir: &Path) -> Vec<u64> {
    segment::list_segments(dir).unwrap()
}

fn index_files(dir: &Path) -> usize {
    fs::read_dir(dir)
        .unwrap()
        .filter(|e| {
            e.as_ref()
                .unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with(segment::SEGMENT_INDEX_PREFIX)
        })
        .count()
}

/// Number of regular files under `blobs/` (the v1 file-per-blob layout).
fn blob_files(dir: &Path) -> usize {
    fn walk(p: &Path) -> usize {
        let Ok(rd) = fs::read_dir(p) else { return 0 };
        rd.map(|e| {
            let e = e.unwrap();
            if e.file_type().unwrap().is_dir() {
                walk(&e.path())
            } else {
                1
            }
        })
        .sum()
    }
    walk(&dir.join("blobs"))
}

/// Byte offsets of the batches in a segment file.
fn batch_starts(bytes: &[u8]) -> Vec<usize> {
    (0..bytes.len())
        .step_by(wal2::WAL_V2_ALIGN as usize)
        .filter(|&o| {
            bytes
                .get(o..o + wal2::WAL_V2_BATCH_HEADER_LEN)
                .and_then(wal2::parse_batch_header)
                .is_some()
        })
        .collect()
}

/// Position of the first `ev` in the durability trace.
fn pos(trace: &[SegEvent], ev: SegEvent) -> Option<usize> {
    trace.iter().position(|e| *e == ev)
}

/// In a new segment `k`, the file is created, then synced, then the directory flushed,
/// and only then does a batch write start in it.
fn assert_dir_flush_before_first_batch(trace: &[SegEvent], k: u64) {
    let created = pos(trace, SegEvent::Created(k)).expect("segment created");
    let synced = pos(trace, SegEvent::FileSynced(k)).expect("segment file synced");
    let dir = pos(trace, SegEvent::DirSynced(k))
        .unwrap_or_else(|| panic!("no directory flush for segment {k}: {trace:?}"));
    let write = pos(trace, SegEvent::BatchWrite(k)).expect("batch written");
    assert!(
        created < synced && synced < dir && dir < write,
        "segment {k}: create {created}, sync {synced}, dir flush {dir}, first batch {write}: {trace:?}"
    );
}

// --- crash child plumbing --------------------------------------------------

fn child_dir() -> Option<PathBuf> {
    std::env::var(CHILD_ENV).ok().map(PathBuf::from)
}

/// Run `test` again in a child process on a new store dir; it must crash at the fault.
fn run_crash_child(test: &str, label: &str) -> PathBuf {
    let dir = temp_store_dir(label);
    let status = Command::new(std::env::current_exe().expect("test binary path"))
        .arg("--exact")
        .arg(format!("segment_tests::{test}"))
        .arg("--nocapture")
        .env(CHILD_ENV, &dir)
        .status()
        .expect("spawn child process");
    assert_eq!(
        status.code(),
        Some(FAULT_CRASH_EXIT_CODE),
        "the child must terminate at the injected fault"
    );
    dir
}

fn record_ack(dir: &Path, seq: WalSeq) {
    let mut f = OpenOptions::new()
        .create(true)
        .append(true)
        .open(dir.join("acks.txt"))
        .unwrap();
    f.write_all(format!("{}\n", seq.0).as_bytes()).unwrap();
}

fn acks(dir: &Path) -> BTreeSet<u64> {
    fs::read_to_string(dir.join("acks.txt"))
        .unwrap_or_default()
        .lines()
        .map(|l| l.parse().unwrap())
        .collect()
}

fn commit_acked(store: &mut SynapseStore, dir: &Path, key: &SigningKey, label: &str) {
    let seq = commit(store, key, label);
    record_ack(dir, seq);
}

/// Child side: attempt one more commit with `fault` armed; the fault ends the process.
fn crash_on_commit(
    store: &mut SynapseStore,
    key: &SigningKey,
    label: &str,
    fault: FaultInjection,
) -> ! {
    store.set_fault_injection(fault);
    let (env, blobs) = cs(key, label);
    let r = store.ingest_changeset(env, &blobs);
    panic!("the injected fault did not end the process: {r:?}");
}

// --- torn segment ----------------------------------------------------------

/// Crash in the middle of a batch in segment 2: strict recovery refuses the torn tail,
/// truncating recovery drops it, and every acknowledged change survives.
#[test]
fn a2_torn_segment_crash_mid_batch_keeps_every_ack() {
    if let Some(dir) = child_dir() {
        let key = key(81);
        let mut s = open(&dir);
        for i in 0..12 {
            commit_acked(&mut s, &dir, &key, &format!("torn-{i}"));
        }
        assert_eq!(active(&s), 2);
        crash_on_commit(
            &mut s,
            &key,
            "torn-crash",
            FaultInjection::CrashMidBatchWrite {
                bytes_written: 3000,
            },
        );
    }
    let dir = run_crash_child("a2_torn_segment_crash_mid_batch_keeps_every_ack", "a2-torn");
    assert_eq!(acks(&dir), (1..=12).collect::<BTreeSet<_>>());
    assert_eq!(segments(&dir), vec![1, 2]);

    let err = try_open(&dir, STRICT)
        .err()
        .expect("strict recovery must refuse the torn batch");
    assert_eq!(err.code, RefusalCode::WalTornFrame, "{err:?}");
    let store = try_open(&dir, TRUNCATE).unwrap();
    assert_eq!(store.torn_frames_truncated_on_open(), 1);
    assert_eq!(store.committed_seq(), WalSeq(12), "no lost ack, no phantom");
    assert_all_readable(&store, 12);
    drop(store);
    {
        let mut s = open(&dir);
        assert_eq!(commit(&mut s, &key(82), "after-torn"), WalSeq(13));
    }
    let store = open(&dir);
    assert_eq!(store.committed_seq(), WalSeq(13));
    assert_all_readable(&store, 13);
    let _ = fs::remove_dir_all(&dir);
}

/// The same torn-looking damage is a crash tail only in the last segment holding data.
/// In an earlier segment (data after it in a later segment) it is corruption of
/// acknowledged data and both recovery policies refuse to open.
#[test]
fn a2_torn_segment_with_data_after_it_fails_closed_under_both_policies() {
    let dir = temp_store_dir("a2-torn-middle");
    let key = key(83);
    {
        let mut s = open(&dir);
        for i in 0..20 {
            commit(&mut s, &key, &format!("mid-{i}"));
        }
        assert_eq!(active(&s), 3);
    }
    let tear = |id: u64| -> Vec<u8> {
        let good = fs::read(seg_path(&dir, id)).unwrap();
        let mut bad = good.clone();
        let last = *batch_starts(&good).last().unwrap();
        bad[last + 3000..last + PER as usize].fill(0);
        fs::write(seg_path(&dir, id), &bad).unwrap();
        good
    };
    // Segment 2 is full and segment 3 holds data after it.
    let good2 = tear(2);
    for policy in [STRICT, TRUNCATE] {
        assert!(
            try_open(&dir, policy).is_err(),
            "{policy:?} accepted a torn batch in segment 2 with data in segment 3"
        );
    }
    fs::write(seg_path(&dir, 2), &good2).unwrap();
    assert_eq!(open(&dir).committed_seq(), WalSeq(20));
    // Control: the same damage in the last segment is a torn tail.
    tear(3);
    let err = try_open(&dir, STRICT).err().expect("strict refuses");
    assert_eq!(err.code, RefusalCode::WalTornFrame, "{err:?}");
    let store = try_open(&dir, TRUNCATE).unwrap();
    assert_eq!(store.committed_seq(), WalSeq(19));
    assert_all_readable(&store, 19);
    let _ = fs::remove_dir_all(&dir);
}

// --- crash between payload and index ---------------------------------------

/// Crash after a batch is written and `fdatasync` returned, before the in-memory blob
/// index is updated or anything is acknowledged. On reopen the index is rebuilt from the
/// checkpoint's segment index plus the segments: every acknowledged change survives, the
/// durable unacknowledged change is present with its blob, and a retry is a duplicate.
#[test]
fn a2_crash_between_payload_and_index_keeps_every_ack() {
    if let Some(dir) = child_dir() {
        let key = key(84);
        let mut s = open(&dir);
        for i in 0..6 {
            commit_acked(&mut s, &dir, &key, &format!("pi-{i}"));
        }
        s.checkpoint_and_compact(1000).unwrap();
        for i in 6..10 {
            commit_acked(&mut s, &dir, &key, &format!("pi-{i}"));
        }
        assert_eq!(active(&s), 2);
        crash_on_commit(
            &mut s,
            &key,
            "pi-pending",
            FaultInjection::CrashAfterBatchSyncBeforeIndex,
        );
    }
    let dir = run_crash_child(
        "a2_crash_between_payload_and_index_keeps_every_ack",
        "a2-pi",
    );
    assert_eq!(acks(&dir), (1..=10).collect::<BTreeSet<_>>());
    let mut store = open(&dir);
    // The pending batch was durable before the crash: it is kept (never acknowledged,
    // so keeping it loses nothing; the caller's retry is idempotent).
    assert_eq!(store.committed_seq(), WalSeq(11));
    assert_all_readable(&store, 11);
    let (env, blobs) = cs(&key(84), "pi-pending");
    assert!(matches!(
        store.ingest_changeset(env, &blobs).unwrap(),
        IngestOutcome::IdempotentDuplicate { wal_seq, .. } if wal_seq == WalSeq(11)
    ));
    store.checkpoint_and_compact(1000).unwrap();
    drop(store);
    let store = open(&dir);
    assert_eq!(store.committed_seq(), WalSeq(11));
    assert_all_readable(&store, 11);
    assert_eq!(blob_files(&dir), 0, "blobs stay in the segments");
    let _ = fs::remove_dir_all(&dir);
}

/// Crash after the checkpoint's segment index file is written, before the checkpoint
/// replaces the previous one: the old checkpoint and its own index still describe the
/// store, every acknowledged change survives, and the next checkpoint removes the
/// orphan index.
#[test]
fn a2_crash_after_segment_index_before_checkpoint_keeps_every_ack() {
    if let Some(dir) = child_dir() {
        let key = key(85);
        let mut s = open(&dir);
        for i in 0..6 {
            commit_acked(&mut s, &dir, &key, &format!("ix-{i}"));
        }
        s.checkpoint_and_compact(1000).unwrap();
        for i in 6..10 {
            commit_acked(&mut s, &dir, &key, &format!("ix-{i}"));
        }
        s.set_fault_injection(FaultInjection::CrashAfterSegmentIndexBeforeCheckpoint);
        let r = s.checkpoint_and_compact(1000);
        panic!("the injected fault did not end the process: {r:?}");
    }
    let dir = run_crash_child(
        "a2_crash_after_segment_index_before_checkpoint_keeps_every_ack",
        "a2-ix",
    );
    assert_eq!(acks(&dir), (1..=10).collect::<BTreeSet<_>>());
    assert_eq!(index_files(&dir), 2, "old index and the orphan new one");
    let mut store = open(&dir);
    assert_eq!(store.committed_seq(), WalSeq(10));
    assert_all_readable(&store, 10);
    store.checkpoint_and_compact(1000).unwrap();
    assert_eq!(index_files(&dir), 1);
    assert_eq!(commit(&mut store, &key(86), "ix-after"), WalSeq(11));
    drop(store);
    let store = open(&dir);
    assert_eq!(store.committed_seq(), WalSeq(11));
    assert_all_readable(&store, 11);
    let _ = fs::remove_dir_all(&dir);
}

// --- flush failure -----------------------------------------------------------

fn flush_failure_case(label: &str, fault: FaultInjection) {
    let dir = temp_store_dir(label);
    let key = key(87);
    {
        let mut s = open(&dir);
        while s.committed_seq() == WalSeq(0) || !next_rotates(&s) {
            let n = s.committed_seq().0;
            commit(&mut s, &key, &format!("{label}-{n}"));
        }
        assert_eq!(s.committed_seq(), WalSeq(8));
        let root = s.state_root_digest(None).unwrap();
        s.set_fault_injection(fault);
        let (env, blobs) = cs(&key, &format!("{label}-x"));
        let err = s
            .ingest_changeset(env, &blobs)
            .expect_err("a failed flush acknowledges nothing");
        assert_eq!(err.code, RefusalCode::IoFailure);
        assert_eq!(s.committed_seq(), WalSeq(8));
        assert_eq!(s.state_root_digest(None).unwrap(), root);
        assert!(s.poisoned().is_none());
        let trace = &s.wal_v2.as_ref().unwrap().trace;
        if fault == FaultInjection::FailNextSegmentDirSync {
            assert!(pos(trace, SegEvent::DirSynced(2)).is_none(), "{trace:?}");
            assert!(pos(trace, SegEvent::BatchWrite(2)).is_none(), "{trace:?}");
            assert_eq!(active(&s), 1, "the failed rotation leaves segment 1 active");
        }
        assert!(pos(trace, SegEvent::BatchDurable(2)).is_none(), "{trace:?}");
    }
    // Nothing of the failed attempt survives a reopen; the retry commits exactly once.
    {
        let mut s = open(&dir);
        assert_eq!(s.committed_seq(), WalSeq(8));
        assert_all_readable(&s, 8);
        assert_eq!(commit(&mut s, &key, &format!("{label}-x")), WalSeq(9));
        let (env, blobs) = cs(&key, &format!("{label}-x"));
        assert!(matches!(
            s.ingest_changeset(env, &blobs).unwrap(),
            IngestOutcome::IdempotentDuplicate { .. }
        ));
        assert_eq!(active(&s), 2);
        assert_dir_flush_before_first_batch(&s.wal_v2.as_ref().unwrap().trace, 2);
    }
    let store = open(&dir);
    assert_eq!(store.committed_seq(), WalSeq(9));
    assert_all_readable(&store, 9);
    let _ = fs::remove_dir_all(&dir);
}

/// The directory flush after a new segment file is created fails: the batch is not
/// written, nothing is acknowledged, and the retry commits once.
#[test]
fn a2_flush_failure_directory_flush_of_new_segment_acks_nothing() {
    flush_failure_case("a2-flush-dir", FaultInjection::FailNextSegmentDirSync);
}

/// The `fdatasync` of the first batch in a new segment fails: it is rolled back,
/// nothing is acknowledged, and the retry commits once.
#[test]
fn a2_flush_failure_batch_sync_in_new_segment_acks_nothing() {
    flush_failure_case("a2-flush-batch", FaultInjection::FailNextBatchSync);
}

// --- crash after a new segment file before its directory flush ---------------

/// Crash after segment 2 is created and pre-written, before the directory flush. After
/// a power loss its directory entry may survive (file kept), survive without its size
/// (empty file) or be lost (no file): every case reopens strictly with every
/// acknowledged change, and the next commit flushes the directory before writing.
#[test]
fn a2_crash_after_new_segment_file_before_directory_flush_keeps_every_ack() {
    if let Some(dir) = child_dir() {
        let key = key(88);
        let mut s = open(&dir);
        while s.committed_seq() == WalSeq(0) || !next_rotates(&s) {
            let n = s.committed_seq().0;
            commit_acked(&mut s, &dir, &key, &format!("nd-{n}"));
        }
        crash_on_commit(
            &mut s,
            &key,
            "nd-lost",
            FaultInjection::CrashAfterSegmentCreateBeforeDirSync,
        );
    }
    let dir = run_crash_child(
        "a2_crash_after_new_segment_file_before_directory_flush_keeps_every_ack",
        "a2-nodirflush",
    );
    assert_eq!(acks(&dir), (1..=8).collect::<BTreeSet<_>>());
    assert_eq!(segments(&dir), vec![1, 2], "segment 2 was created");
    let variants = ["file kept", "file empty", "file lost"];
    for (n, variant) in variants.iter().enumerate() {
        let d = temp_store_dir(&format!("a2-nodirflush-{n}"));
        copy_tree(&dir, &d);
        match n {
            0 => {}
            1 => fs::write(seg_path(&d, 2), b"").unwrap(),
            _ => fs::remove_file(seg_path(&d, 2)).unwrap(),
        }
        {
            let mut s = try_open(&d, STRICT)
                .unwrap_or_else(|e| panic!("{variant}: strict reopen failed: {e:?}"));
            assert_eq!(s.committed_seq(), WalSeq(8), "{variant}");
            assert_all_readable(&s, 8);
            assert_eq!(commit(&mut s, &key(88), "nd-lost"), WalSeq(9), "{variant}");
            assert_eq!(active(&s), 2, "{variant}");
            assert_dir_flush_before_first_batch(&s.wal_v2.as_ref().unwrap().trace, 2);
        }
        let store = open(&d);
        assert_eq!(store.committed_seq(), WalSeq(9), "{variant}");
        assert_all_readable(&store, 9);
        let _ = fs::remove_dir_all(&d);
    }
    let _ = fs::remove_dir_all(&dir);
}

/// Durability camera: in every new segment the directory flush precedes the first batch,
/// and a reopened store syncs its active segment file and the directory before writing.
#[test]
fn a2_directory_flush_precedes_every_batch_in_a_new_segment() {
    let dir = temp_store_dir("a2-camera");
    let key = key(89);
    {
        let mut s = open(&dir);
        for i in 0..20 {
            commit(&mut s, &key, &format!("cam-{i}"));
        }
        assert_eq!(active(&s), 3);
        let trace = &s.wal_v2.as_ref().unwrap().trace;
        for k in 2..=3 {
            assert_dir_flush_before_first_batch(trace, k);
        }
    }
    let mut s = open(&dir);
    commit(&mut s, &key, "cam-reopen");
    let trace = &s.wal_v2.as_ref().unwrap().trace;
    assert_eq!(
        trace[..3],
        [
            SegEvent::FileSynced(3),
            SegEvent::DirSynced(3),
            SegEvent::BatchWrite(3)
        ],
        "{trace:?}"
    );
    let _ = fs::remove_dir_all(&dir);
}

// --- layout -----------------------------------------------------------------

/// A checkpoint keeps the blobs in the segments: no blob files, segment bytes untouched,
/// blobs readable across segments after reopen, and one segment index left.
#[test]
fn a2_checkpoint_keeps_blobs_in_segments_across_reopen() {
    let dir = temp_store_dir("a2-ckpt");
    let key = key(90);
    let (root, before);
    {
        let mut s = open(&dir);
        for i in 0..20 {
            commit(&mut s, &key, &format!("ck-{i}"));
        }
        before = segments(&dir)
            .into_iter()
            .map(|id| fs::read(seg_path(&dir, id)).unwrap())
            .collect::<Vec<_>>();
        root = s.state_root_digest(None).unwrap();
        s.checkpoint_and_compact(1000).unwrap();
        assert_all_readable(&s, 20);
    }
    assert_eq!(blob_files(&dir), 0, "no file per blob");
    for (i, old) in before.iter().enumerate() {
        let now = fs::read(seg_path(&dir, i as u64 + 1)).unwrap();
        assert_eq!(now[..old.len()], old[..], "segment {} rewritten", i + 1);
    }
    {
        let mut s = open(&dir);
        assert_eq!(s.committed_seq(), WalSeq(20));
        assert_eq!(s.state_root_digest(None).unwrap(), root);
        assert_all_readable(&s, 20);
        for i in 20..25 {
            commit(&mut s, &key, &format!("ck-{i}"));
        }
        s.checkpoint_and_compact(1000).unwrap();
    }
    let store = open(&dir);
    assert_eq!(store.committed_seq(), WalSeq(25));
    assert_all_readable(&store, 25);
    assert_eq!(index_files(&dir), 1);
    assert_eq!(blob_files(&dir), 0);
    assert_eq!(segments(&dir), vec![1, 2, 3, 4]);
    let _ = fs::remove_dir_all(&dir);
}

/// Stores written before A2 (v1 file-per-blob, single-file WAL v2) still replay, switch
/// to the segment layout on open, and keep their state across new segments.
#[test]
fn a2_pre_a2_stores_replay_and_switch_to_segments() {
    for name in ["v1-wal-log", "v1-wal-v2-log"] {
        let dir = copy_fixture(name);
        let ex = expect(name);
        let key = key(91);
        {
            let mut s = open(&dir);
            assert_eq!(s.log_layout, LogLayout::Segments, "{name}");
            assert_eq!(s.committed_seq(), WalSeq(ex.committed_seq), "{name}");
            assert_eq!(s.state_root_digest(None).unwrap(), ex.state_root, "{name}");
            for i in 0..10 {
                commit(&mut s, &key, &format!("{name}-{i}"));
            }
            assert!(active(&s) >= 2, "{name}");
            s.checkpoint_and_compact(1000).unwrap();
        }
        let store = open(&dir);
        assert_eq!(
            store.committed_seq(),
            WalSeq(ex.committed_seq + 10),
            "{name}"
        );
        let all = store.list_changesets(None, None, None).unwrap();
        assert!(all.len() >= 10, "{name}");
        assert_all_readable(&store, all.len());
        let _ = fs::remove_dir_all(&dir);
    }
}

/// The segment index decoder is strict: it round-trips, and a flipped bit, a truncated
/// file, an entry not before the replay position, or unsorted entries are refused as
/// `CheckpointCorrupt` (recovery then refuses to open rather than guess blob locations).
#[test]
fn a2_segment_index_round_trips_and_refuses_damage() {
    let loc = |segment, offset, len| segment::BlobLoc {
        segment,
        offset,
        len,
    };
    let index = segment::SegmentIndex {
        binding: [7u8; 32],
        replay_segment: 3,
        replay_offset: 8192,
        entries: [
            (BlobDigest([1u8; 32]), loc(1, 4096, 100)),
            (BlobDigest([2u8; 32]), loc(3, 0, 8000)),
        ]
        .into_iter()
        .collect(),
    };
    let bytes = index.encode();
    assert_eq!(segment::SegmentIndex::decode(&bytes).unwrap(), index);
    let refused = |b: &[u8]| {
        assert_eq!(
            segment::SegmentIndex::decode(b).unwrap_err().code,
            RefusalCode::CheckpointCorrupt
        )
    };
    for at in [0, 5, 45, bytes.len() / 2, bytes.len() - 1] {
        let mut bad = bytes.clone();
        bad[at] ^= 0x01;
        refused(&bad);
    }
    refused(&bytes[..bytes.len() - 1]);
    // An entry ending past the replay position (bytes recovery would also replay).
    let mut past = index.clone();
    past.entries
        .insert(BlobDigest([3u8; 32]), loc(3, 4096, 4097));
    refused(&past.encode());
    // Entries out of order: swap the two encoded entries and fix the trailing digest.
    let header = bytes.len() - 32 - 2 * 52;
    let mut swapped = bytes[..bytes.len() - 32].to_vec();
    let (a, b) = swapped[header..].split_at_mut(52);
    a.swap_with_slice(b);
    let digest: [u8; 32] = {
        let mut h = Sha256::new();
        h.update(segment::DOMAIN_SEGMENT_INDEX);
        h.update(&swapped);
        h.finalize().into()
    };
    swapped.extend_from_slice(&digest);
    refused(&swapped);
}
