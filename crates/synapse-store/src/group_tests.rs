//! Group commit (WAL v2 and [`SharedStore`]) tests.
//!
//! Durability rule under test: blobs, directories and the WAL are synced before any
//! acknowledgment. In WAL v2 blobs live inside the batch, so the one `fdatasync` per
//! batch covers them. These tests never assert a speed-up; they check correctness only.

use super::tests::{make_signed_changeset, temp_store_dir};
use super::*;
use ed25519_dalek::SigningKey;
use std::collections::BTreeSet;
use std::process::Command;
use std::sync::{Barrier, Mutex};
use std::time::Duration;

fn group(max_batch_records: u32, max_batch_delay_us: u32) -> FsyncPolicy {
    FsyncPolicy::GroupCommit {
        max_batch_records,
        max_batch_delay_us,
    }
}

fn open_shared(dir: &Path, policy: FsyncPolicy) -> SharedStore {
    SharedStore::open(
        dir,
        policy,
        RecoveryPolicy::StrictFailClosed,
        StoreLimits::default(),
    )
    .unwrap()
}

fn reopen(dir: &Path, policy: FsyncPolicy, recovery: RecoveryPolicy) -> SynapseStore {
    SynapseStore::open(dir, policy, recovery, StoreLimits::default()).unwrap()
}

/// A signed single-file changeset with a distinct key, path and content per label.
fn cs(
    key: &SigningKey,
    label: &str,
    blob_len: usize,
) -> (ChangesetEnvelope, Vec<(BlobDigest, Vec<u8>)>) {
    let mut content = format!("// {label}\n").into_bytes();
    let mut x: u8 = label
        .bytes()
        .fold(7u8, |a, b| a.wrapping_mul(31).wrapping_add(b));
    while content.len() < blob_len {
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

#[test]
fn test_crc32c_hardware_matches_portable() {
    assert_eq!(crc32c_portable(b"123456789"), 0xe306_9283);
    let mut data = vec![0u8; 70_000];
    let mut s: u64 = 0x9e37_79b9_7f4a_7c15;
    for b in data.iter_mut() {
        s ^= s << 13;
        s ^= s >> 7;
        s ^= s << 17;
        *b = s as u8;
    }
    let mut sizes: Vec<usize> = (0..=1100).collect();
    sizes.extend([4095, 4096, 4097, 65_535, 65_536, 65_537]);
    for &n in &sizes {
        for start in [0usize, 1, 3, 7] {
            let slice = &data[start..start + n];
            assert_eq!(
                crc32c(slice),
                crc32c_portable(slice),
                "size {n} start {start}"
            );
        }
    }
}

#[test]
fn test_group_commit_roundtrip_reopen_and_legacy_policy_refusal() {
    let dir = temp_store_dir("gc-roundtrip");
    let key = SigningKey::from_bytes(&[61u8; 32]);
    let root;
    {
        let shared = open_shared(&dir, FsyncPolicy::GROUP_COMMIT_DEFAULT);
        assert!(shared.read().is_wal_v2());
        for i in 1..=4u64 {
            let (env, blobs) = cs(&key, &format!("rt-{i}"), 300);
            assert_eq!(
                committed_seq_of(&shared.submit(env, &blobs).unwrap()),
                WalSeq(i)
            );
        }
        // The single-store path writes WAL v2 too.
        let mut store = shared.into_inner();
        let (env, blobs) = cs(&key, "rt-5", 300);
        let out = store.ingest_changeset(env.clone(), &blobs).unwrap();
        assert_eq!(committed_seq_of(&out), WalSeq(5));
        let dup = store.ingest_changeset(env, &blobs).unwrap();
        assert!(
            matches!(dup, IngestOutcome::IdempotentDuplicate { wal_seq, .. } if wal_seq == WalSeq(5))
        );
        root = store.state_root_digest(None).unwrap();
        assert_all_readable(&store, 5);
    }
    let store = reopen(
        &dir,
        FsyncPolicy::GROUP_COMMIT_DEFAULT,
        RecoveryPolicy::StrictFailClosed,
    );
    assert_eq!(store.committed_seq(), WalSeq(5));
    assert_eq!(store.state_root_digest(None).unwrap(), root);
    assert_all_readable(&store, 5);
    drop(store);

    for legacy in [
        FsyncPolicy::EveryCommit,
        FsyncPolicy::BatchWindow { max_records: 8 },
    ] {
        let err = SynapseStore::open(
            &dir,
            legacy,
            RecoveryPolicy::StrictFailClosed,
            StoreLimits::default(),
        )
        .err()
        .expect("legacy policy must refuse a WAL v2 store");
        assert_eq!(err.code, RefusalCode::WalVersionUnsupported);
    }
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn test_v1_store_upgrades_to_v2_with_continuous_chain() {
    let dir = temp_store_dir("gc-upgrade");
    let key = SigningKey::from_bytes(&[62u8; 32]);
    {
        let mut v1 = reopen(
            &dir,
            FsyncPolicy::EveryCommit,
            RecoveryPolicy::StrictFailClosed,
        );
        for i in 1..=3u64 {
            let (env, blobs) = cs(&key, &format!("up-{i}"), 200);
            assert_eq!(
                committed_seq_of(&v1.ingest_changeset(env, &blobs).unwrap()),
                WalSeq(i)
            );
        }
        assert!(!v1.is_wal_v2());
    }
    let root;
    {
        let shared = open_shared(&dir, FsyncPolicy::GROUP_COMMIT_DEFAULT);
        assert!(shared.read().is_wal_v2());
        assert_eq!(shared.read().committed_seq(), WalSeq(3));
        let v1_tip = shared.read().last_frame_sha256();
        let (env, blobs) = cs(&key, "up-4", 200);
        assert_eq!(
            committed_seq_of(&shared.submit(env, &blobs).unwrap()),
            WalSeq(4)
        );
        assert_ne!(shared.read().last_frame_sha256(), v1_tip);
        // A v2 changeset that reuses a v1 blob file (not provided again).
        let (_, v1_blobs) = cs(&key, "up-1", 200);
        let (mut env5, _) = cs(&key, "up-5", 200);
        if let MutationOp::Upsert {
            blob_digest,
            size_bytes,
            ..
        } = &mut env5.mutations[0].op
        {
            *blob_digest = v1_blobs[0].0;
            *size_bytes = v1_blobs[0].1.len() as u64;
        }
        env5.sign(&key);
        assert_eq!(
            committed_seq_of(&shared.submit(env5, &[]).unwrap()),
            WalSeq(5)
        );
        root = shared.read().state_root_digest(None).unwrap();
    }
    // Reopen replays v1 frames, the marker, then v2 batches: same chain and state.
    let store = reopen(
        &dir,
        FsyncPolicy::GROUP_COMMIT_DEFAULT,
        RecoveryPolicy::StrictFailClosed,
    );
    assert_eq!(store.committed_seq(), WalSeq(5));
    assert_eq!(store.state_root_digest(None).unwrap(), root);
    assert_all_readable(&store, 5);
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn test_concurrent_submitters_acks_unique_contiguous_and_durable_before_ack() {
    const THREADS: usize = 16;
    const PER_THREAD: usize = 8;
    let dir = temp_store_dir("gc-concurrent");
    let shared = open_shared(&dir, FsyncPolicy::GROUP_COMMIT_DEFAULT);
    let barrier = Barrier::new(THREADS);
    // (acked seq, committed watermark observed right after the ack)
    let acks: Mutex<Vec<(WalSeq, WalSeq)>> = Mutex::new(Vec::new());
    std::thread::scope(|s| {
        for t in 0..THREADS {
            let (shared, barrier, acks) = (&shared, &barrier, &acks);
            s.spawn(move || {
                let key = SigningKey::from_bytes(&[t as u8 + 100; 32]);
                let work: Vec<_> = (0..PER_THREAD)
                    .map(|i| cs(&key, &format!("t{t}-{i}"), 256))
                    .collect();
                barrier.wait();
                for (env, blobs) in work {
                    let seq = committed_seq_of(&shared.submit(env, &blobs).unwrap());
                    let watermark = shared.read().committed_seq();
                    acks.lock().unwrap().push((seq, watermark));
                }
            });
        }
    });
    let acks = acks.into_inner().unwrap();
    let total = (THREADS * PER_THREAD) as u64;
    for (seq, watermark) in &acks {
        assert!(
            watermark >= seq,
            "acknowledged {seq} while the durable watermark was {watermark}"
        );
    }
    let seqs: BTreeSet<u64> = acks.iter().map(|(s, _)| s.0).collect();
    assert_eq!(seqs.len() as u64, total, "acks are unique");
    assert_eq!(
        seqs,
        (1..=total).collect::<BTreeSet<_>>(),
        "acks are contiguous"
    );
    // Release order equals WAL order.
    let released: Vec<u64> = shared.ack_log().iter().map(|s| s.0).collect();
    assert_eq!(released, (1..=total).collect::<Vec<_>>());
    let stats = shared.stats();
    assert_eq!(stats.records, total);
    assert_eq!(stats.failed_batches, 0);
    let root = shared.read().state_root_digest(None).unwrap();
    drop(shared);

    let store = reopen(
        &dir,
        FsyncPolicy::GROUP_COMMIT_DEFAULT,
        RecoveryPolicy::StrictFailClosed,
    );
    assert_eq!(store.committed_seq(), WalSeq(total));
    assert_eq!(store.state_root_digest(None).unwrap(), root);
    assert_all_readable(&store, total as usize);
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn test_duplicate_idempotency_keys_inside_one_batch() {
    let dir = temp_store_dir("gc-dup-batch");
    let key = SigningKey::from_bytes(&[63u8; 32]);
    // The leader waits (up to 5 s) until all four submissions are queued: one batch.
    let shared = open_shared(&dir, group(4, 5_000_000));
    let (same, same_blobs) = cs(&key, "dup", 128);
    // Same idempotency key, different content: a different changeset id.
    let (conflict, conflict_blobs) =
        make_signed_changeset(&key, "dup", "src/other.rs", b"other\n", vec![], 1000);
    let inputs = vec![
        (same.clone(), same_blobs.clone()),
        (same.clone(), same_blobs.clone()),
        (same, same_blobs),
        (conflict, conflict_blobs),
    ];
    let barrier = Barrier::new(inputs.len());
    let results: Vec<SynapseResult<IngestOutcome>> = std::thread::scope(|s| {
        let handles: Vec<_> = inputs
            .into_iter()
            .map(|(env, blobs)| {
                let (shared, barrier) = (&shared, &barrier);
                s.spawn(move || {
                    barrier.wait();
                    shared.submit(env, &blobs)
                })
            })
            .collect();
        handles.into_iter().map(|h| h.join().unwrap()).collect()
    });
    let committed: Vec<_> = results
        .iter()
        .filter(|r| matches!(r, Ok(IngestOutcome::Committed { .. })))
        .collect();
    assert_eq!(committed.len(), 1, "exactly one Committed: {results:?}");
    for r in &results {
        match r {
            Ok(IngestOutcome::Committed { wal_seq, .. })
            | Ok(IngestOutcome::IdempotentDuplicate { wal_seq, .. }) => {
                assert_eq!(*wal_seq, WalSeq(1))
            }
            Err(e) => assert_eq!(e.code, RefusalCode::IdempotencyKeyConflict),
        }
    }
    let stats = shared.stats();
    assert_eq!((stats.batches, stats.records), (1, 1));
    drop(shared);
    let store = reopen(
        &dir,
        FsyncPolicy::GROUP_COMMIT_DEFAULT,
        RecoveryPolicy::StrictFailClosed,
    );
    assert_eq!(store.committed_seq(), WalSeq(1));
    assert_all_readable(&store, 1);
    let _ = fs::remove_dir_all(&dir);
}

/// Inject `fault`, submit a batch of four concurrently, and check: no waiter acked,
/// nothing visible (also after reopen), the retry commits, exactly one copy after reopen.
fn failed_batch_case(label: &str, fault: FaultInjection) {
    let dir = temp_store_dir(label);
    let key = SigningKey::from_bytes(&[64u8; 32]);
    let work: Vec<_> = (0..4)
        .map(|i| cs(&key, &format!("{label}-{i}"), 700))
        .collect();
    {
        let shared = open_shared(&dir, group(4, 5_000_000));
        let (env0, blobs0) = cs(&key, &format!("{label}-base"), 100);
        let out0 = shared
            .with_exclusive(|s| s.ingest_changeset(env0, &blobs0))
            .unwrap();
        assert_eq!(committed_seq_of(&out0), WalSeq(1));
        let root_before = shared.read().state_root_digest(None).unwrap();
        shared.with_exclusive(|s| s.set_fault_injection(fault));

        let barrier = Barrier::new(work.len());
        let results: Vec<_> = std::thread::scope(|s| {
            let handles: Vec<_> = work
                .iter()
                .map(|(env, blobs)| {
                    let (shared, barrier) = (&shared, &barrier);
                    s.spawn(move || {
                        barrier.wait();
                        shared.submit(env.clone(), blobs)
                    })
                })
                .collect();
            handles.into_iter().map(|h| h.join().unwrap()).collect()
        });
        for r in &results {
            let e = r
                .as_ref()
                .expect_err("no waiter of a failed batch is acknowledged");
            assert_eq!(e.code, RefusalCode::IoFailure);
        }
        assert_eq!(shared.stats().failed_batches, 1);
        assert_eq!(shared.read().committed_seq(), WalSeq(1));
        assert_eq!(shared.read().state_root_digest(None).unwrap(), root_before);
        assert!(shared.read().poisoned().is_none());
    }
    // Nothing of the failed batch survives a reopen.
    {
        let store = reopen(
            &dir,
            FsyncPolicy::GROUP_COMMIT_DEFAULT,
            RecoveryPolicy::StrictFailClosed,
        );
        assert_eq!(
            store.committed_seq(),
            WalSeq(1),
            "failed batch visible after reopen"
        );
        assert_all_readable(&store, 1);
    }
    // Retry succeeds; then a reopen shows exactly one copy of each.
    {
        let shared = open_shared(&dir, FsyncPolicy::GROUP_COMMIT_DEFAULT);
        for (env, blobs) in &work {
            committed_seq_of(&shared.submit(env.clone(), blobs).unwrap());
        }
        for (env, blobs) in &work {
            assert!(matches!(
                shared.submit(env.clone(), blobs).unwrap(),
                IngestOutcome::IdempotentDuplicate { .. }
            ));
        }
    }
    let store = reopen(
        &dir,
        FsyncPolicy::GROUP_COMMIT_DEFAULT,
        RecoveryPolicy::StrictFailClosed,
    );
    assert_eq!(store.committed_seq(), WalSeq(5));
    assert_all_readable(&store, 5);
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn test_injected_sync_failure_acks_nothing_and_retry_commits_once() {
    failed_batch_case("gc-fail-sync", FaultInjection::FailNextBatchSync);
}

#[test]
fn test_injected_write_failure_acks_nothing_and_retry_commits_once() {
    failed_batch_case(
        "gc-fail-write",
        FaultInjection::FailNextBatchWrite {
            bytes_written: 1500,
        },
    );
}

#[test]
fn test_rollback_failure_poisons_store_until_reopen() {
    let dir = temp_store_dir("gc-poison");
    let key = SigningKey::from_bytes(&[65u8; 32]);
    let (env1, blobs1) = cs(&key, "poison-1", 100);
    let (env2, blobs2) = cs(&key, "poison-2", 100);
    {
        let shared = open_shared(&dir, FsyncPolicy::GROUP_COMMIT_DEFAULT);
        shared.with_exclusive(|s| {
            s.set_fault_injection(FaultInjection::FailNextBatchSyncAndRollback)
        });
        let e = shared.submit(env1.clone(), &blobs1).unwrap_err();
        assert_eq!(e.code, RefusalCode::IoFailure);
        assert!(shared.read().poisoned().is_some());
        // Every later write is refused, including through the single-store path.
        let e = shared.submit(env2.clone(), &blobs2).unwrap_err();
        assert_eq!(e.code, RefusalCode::IoFailure);
        let mut store = shared.into_inner();
        assert_eq!(
            store
                .ingest_changeset(env2.clone(), &blobs2)
                .unwrap_err()
                .code,
            RefusalCode::IoFailure
        );
        assert_eq!(
            store.checkpoint_and_compact(0).unwrap_err().code,
            RefusalCode::IoFailure
        );
        assert_eq!(store.committed_seq(), WalSeq::ZERO);
    }
    // Reopen recovers. The failed record's outcome was unknown (its bytes may be on disk);
    // an idempotent retry resolves it to exactly one copy.
    let shared = open_shared(&dir, FsyncPolicy::GROUP_COMMIT_DEFAULT);
    assert!(shared.read().poisoned().is_none());
    let r1 = shared.submit(env1, &blobs1).unwrap();
    assert!(matches!(
        r1,
        IngestOutcome::Committed { wal_seq, .. } | IngestOutcome::IdempotentDuplicate { wal_seq, .. }
            if wal_seq == WalSeq(1)
    ));
    assert_eq!(
        committed_seq_of(&shared.submit(env2, &blobs2).unwrap()),
        WalSeq(2)
    );
    drop(shared);
    let store = reopen(
        &dir,
        FsyncPolicy::GROUP_COMMIT_DEFAULT,
        RecoveryPolicy::StrictFailClosed,
    );
    assert_eq!(store.committed_seq(), WalSeq(2));
    assert_all_readable(&store, 2);
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn test_shutdown_drains_queued_submissions_and_refuses_new_ones() {
    const THREADS: usize = 8;
    let dir = temp_store_dir("gc-shutdown");
    // A long linger keeps submissions queued until shutdown releases the leader.
    let shared = open_shared(&dir, group(64, 2_000_000));
    let barrier = Barrier::new(THREADS + 1);
    let mut committed_at_shutdown = WalSeq::ZERO;
    let results: Vec<SynapseResult<IngestOutcome>> = std::thread::scope(|s| {
        let handles: Vec<_> = (0..THREADS)
            .map(|t| {
                let (shared, barrier) = (&shared, &barrier);
                s.spawn(move || {
                    let key = SigningKey::from_bytes(&[t as u8 + 150; 32]);
                    let (env, blobs) = cs(&key, &format!("sd-{t}"), 64);
                    barrier.wait();
                    shared.submit(env, &blobs)
                })
            })
            .collect();
        barrier.wait();
        std::thread::sleep(Duration::from_millis(50));
        shared.shutdown();
        committed_at_shutdown = shared.read().committed_seq();
        handles.into_iter().map(|h| h.join().unwrap()).collect()
    });
    let mut ok = 0u64;
    for r in &results {
        match r {
            Ok(out) => {
                committed_seq_of(out);
                ok += 1;
            }
            Err(e) => assert_eq!(e.code, RefusalCode::BackpressureOverCapacity),
        }
    }
    assert!(ok > 0, "queued submissions were committed");
    // Everything admitted was durable before shutdown() returned.
    assert_eq!(committed_at_shutdown, WalSeq(ok));
    let key = SigningKey::from_bytes(&[66u8; 32]);
    let (env, blobs) = cs(&key, "after-shutdown", 64);
    assert_eq!(
        shared.submit(env, &blobs).unwrap_err().code,
        RefusalCode::BackpressureOverCapacity
    );
    drop(shared);
    let store = reopen(
        &dir,
        FsyncPolicy::GROUP_COMMIT_DEFAULT,
        RecoveryPolicy::StrictFailClosed,
    );
    assert_eq!(store.committed_seq(), WalSeq(ok));
    assert_all_readable(&store, ok as usize);
    let _ = fs::remove_dir_all(&dir);
}

const CRASH_CHILD_ENV: &str = "SYNAPSE_GC_CRASH_CHILD_DIR";
const CRASH_BATCH: usize = 4;

#[test]
fn test_subprocess_crash_mid_batch_no_lost_ack_no_phantom() {
    if let Ok(child_dir) = std::env::var(CRASH_CHILD_ENV) {
        let dir = PathBuf::from(child_dir);
        let ack_file = dir.join("acks.txt");
        let key = SigningKey::from_bytes(&[67u8; 32]);
        let shared = open_shared(&dir, group(CRASH_BATCH as u32, 5_000_000));
        let ack = |seq: WalSeq| {
            let mut f = OpenOptions::new()
                .create(true)
                .append(true)
                .open(&ack_file)
                .unwrap();
            // One write per line: O_APPEND keeps concurrent lines whole.
            f.write_all(format!("{}\n", seq.0).as_bytes()).unwrap();
        };
        // Phase 1 commits one acknowledged batch of four; phase 2 crashes mid-batch.
        let acked: Vec<_> = (0..CRASH_BATCH)
            .map(|i| cs(&key, &format!("acked-{i}"), 1500))
            .collect();
        let crash: Vec<_> = (0..CRASH_BATCH)
            .map(|i| cs(&key, &format!("crash-{i}"), 1500))
            .collect();
        // Crash after the first frame of the batch is complete and the second is torn.
        let lens: Vec<usize> = crash
            .iter()
            .map(|(env, blobs)| {
                SynapseStore::prepare_ingest(&StoreLimits::default(), env.clone(), blobs, true)
                    .unwrap()
                    .encoded
                    .unwrap()
                    .payload
                    .len()
            })
            .collect();
        let frame = |len: usize| WAL_HEADER_LEN + len;
        let max = lens.iter().copied().max().unwrap();
        let min = lens.iter().copied().min().unwrap();
        let cut = wal2::WAL_V2_BATCH_HEADER_LEN + frame(max) + 100;
        assert!(cut < wal2::WAL_V2_BATCH_HEADER_LEN + 2 * frame(min) - 600);

        for (n, phase) in [&acked, &crash].into_iter().enumerate() {
            if n == 1 {
                shared.with_exclusive(|s| {
                    s.set_fault_injection(FaultInjection::CrashMidBatchWrite { bytes_written: cut })
                });
            }
            let barrier = Barrier::new(CRASH_BATCH);
            std::thread::scope(|s| {
                for (env, blobs) in phase.iter() {
                    let (shared, barrier, ack) = (&shared, &barrier, &ack);
                    s.spawn(move || {
                        barrier.wait();
                        if let Ok(out) = shared.submit(env.clone(), blobs) {
                            ack(committed_seq_of(&out));
                        }
                    });
                }
            });
        }
        // Unreachable when the fault fires.
        std::process::exit(0);
    }

    let dir = temp_store_dir("gc-subprocess-crash");
    let exe = std::env::current_exe().expect("test binary path");
    let status = Command::new(exe)
        .arg("--exact")
        .arg("group_tests::test_subprocess_crash_mid_batch_no_lost_ack_no_phantom")
        .arg("--nocapture")
        .env(CRASH_CHILD_ENV, &dir)
        .status()
        .expect("spawn child process");
    assert_eq!(status.code(), Some(FAULT_CRASH_EXIT_CODE));

    let acked: BTreeSet<u64> = fs::read_to_string(dir.join("acks.txt"))
        .unwrap_or_default()
        .lines()
        .map(|l| l.parse().unwrap())
        .collect();
    assert_eq!(acked, (1..=CRASH_BATCH as u64).collect::<BTreeSet<_>>());

    // Strict recovery refuses the torn tail; truncating recovery drops it.
    let strict = SynapseStore::open(
        &dir,
        FsyncPolicy::GROUP_COMMIT_DEFAULT,
        RecoveryPolicy::StrictFailClosed,
        StoreLimits::default(),
    );
    match strict {
        Ok(s) => panic!(
            "strict recovery accepted the torn batch: committed_seq {} with {} acknowledged",
            s.committed_seq(),
            CRASH_BATCH
        ),
        Err(e) => assert_eq!(e.code, RefusalCode::WalTornFrame),
    }
    let store = reopen(
        &dir,
        FsyncPolicy::GROUP_COMMIT_DEFAULT,
        RecoveryPolicy::TruncateTornTail,
    );
    assert_eq!(store.torn_frames_truncated_on_open(), 1);
    // No lost ack: every acknowledged record is there. No phantom: nothing else is.
    assert_eq!(store.committed_seq(), WalSeq(CRASH_BATCH as u64));
    assert_all_readable(&store, CRASH_BATCH);
    drop(store);
    // The truncated store accepts new batches and reopens strictly.
    {
        let shared = open_shared(&dir, FsyncPolicy::GROUP_COMMIT_DEFAULT);
        let key = SigningKey::from_bytes(&[68u8; 32]);
        let (env, blobs) = cs(&key, "post-crash", 100);
        assert_eq!(
            committed_seq_of(&shared.submit(env, &blobs).unwrap()),
            WalSeq(CRASH_BATCH as u64 + 1)
        );
    }
    let store = reopen(
        &dir,
        FsyncPolicy::GROUP_COMMIT_DEFAULT,
        RecoveryPolicy::StrictFailClosed,
    );
    assert_eq!(store.committed_seq(), WalSeq(CRASH_BATCH as u64 + 1));
    let _ = fs::remove_dir_all(&dir);
}
