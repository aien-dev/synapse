//! ADR 0003 G2 content-defined chunking tests (issue #45).
//!
//! Acceptance under test: every blob round-trips byte for byte through chunking with an
//! unchanged `BlobDigest`; deduplication between two revisions that share content
//! follows the rule X6 fixed before its runs (`evidence/g2-content-defined-chunking/x6/
//! RULE.md` section 5). The expected chunk bytes are computed here from the chunker
//! alone ([`chunk::chunk_ranges`] and [`ChunkDigest::compute`]), never read back from
//! the store under test.

use super::a1_tests::{copy_fixture, copy_tree, expect};
use super::tests::{make_signed_changeset, temp_store_dir};
use super::*;
use ed25519_dalek::SigningKey;
use std::collections::BTreeSet;
use std::process::Command;
use std::sync::Barrier;
use synapse_core::{FileMode, GitOid, PathMutation, SYNAPSE_ENVELOPE_VERSION};

/// Chunk parameters of the test stores: X6 candidate K1 (T = 16 KiB, avg 4 KiB).
const P: ChunkParams = ChunkParams::candidate(16 * 1024, 4 * 1024);
const T: usize = 16 * 1024;
const STRICT: RecoveryPolicy = RecoveryPolicy::StrictFailClosed;
const CHILD_ENV: &str = "SYNAPSE_G2_CRASH_CHILD";

fn limits_with(chunking: ChunkParams) -> StoreLimits {
    StoreLimits {
        segment_bytes: 1024 * 1024,
        wal_prealloc_bytes: 64 * 1024,
        max_blob_bytes: 8 * 1024 * 1024,
        max_total_changeset_bytes: 16 * 1024 * 1024,
        max_wal_record_bytes: 32 * 1024 * 1024,
        chunking,
        ..Default::default()
    }
}

fn open_with(dir: &Path, chunking: ChunkParams) -> SynapseStore {
    SynapseStore::open(
        dir,
        FsyncPolicy::GROUP_COMMIT_DEFAULT,
        STRICT,
        limits_with(chunking),
    )
    .unwrap()
}

fn open(dir: &Path) -> SynapseStore {
    open_with(dir, P)
}

fn key(n: u8) -> SigningKey {
    SigningKey::from_bytes(&[n; 32])
}

/// Deterministic pseudo-random bytes (xorshift64).
fn random(len: usize, seed: u64) -> Vec<u8> {
    let mut x = seed | 1;
    (0..len)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            (x >> 24) as u8
        })
        .collect()
}

/// A signed changeset upserting every `(path, content)` in `files`.
fn multi(
    key: &SigningKey,
    label: &str,
    files: &[(&str, &[u8])],
) -> (ChangesetEnvelope, Vec<(BlobDigest, Vec<u8>)>) {
    let mut blobs: Vec<(BlobDigest, Vec<u8>)> = Vec::new();
    let mutations = files
        .iter()
        .map(|(path, content)| {
            let digest = BlobDigest::compute(content);
            if !blobs.iter().any(|(d, _)| *d == digest) {
                blobs.push((digest, content.to_vec()));
            }
            PathMutation {
                path: path.to_string(),
                op: MutationOp::Upsert {
                    mode: FileMode::Regular644,
                    blob_digest: digest,
                    size_bytes: content.len() as u64,
                },
            }
        })
        .collect();
    let mut env = ChangesetEnvelope {
        version: SYNAPSE_ENVELOPE_VERSION,
        repo_id: RepoId::new("aien-spark/synapse").unwrap(),
        base_git_oid: GitOid::compute_blob(b"base"),
        parent_changesets: vec![],
        author_did: String::new(),
        idempotency_key: IdempotencyKey::from_label(label),
        created_at_ms: 1000,
        intent_summary: format!("G2 {label}"),
        mutations,
        evidence_receipts: vec![],
        signature: vec![],
    };
    env.sign(key);
    (env, blobs)
}

fn commit_env(store: &mut SynapseStore, env: ChangesetEnvelope, blobs: &[(BlobDigest, Vec<u8>)]) {
    match store.ingest_changeset(env, blobs).unwrap() {
        IngestOutcome::Committed { .. } => {}
        other => panic!("expected Committed, got {other:?}"),
    }
}

/// Commit `content` as one file; returns its digest.
fn commit_blob(
    store: &mut SynapseStore,
    key: &SigningKey,
    label: &str,
    content: &[u8],
) -> BlobDigest {
    let (env, blobs) =
        make_signed_changeset(key, label, &format!("src/{label}"), content, vec![], 1000);
    commit_env(store, env, &blobs);
    BlobDigest::compute(content)
}

/// The distinct chunks of `data` under `p`, from the chunker alone.
fn chunks_of(data: &[u8], p: &ChunkParams) -> BTreeMap<ChunkDigest, u64> {
    chunk::chunk_ranges(data, p)
        .into_iter()
        .map(|r| (ChunkDigest::compute(&data[r.clone()]), r.len() as u64))
        .collect()
}

/// Bytes of the chunks of `data` not in `known` (the X6 rule, section 5.3).
fn new_chunk_bytes(data: &[u8], known: &BTreeMap<ChunkDigest, u64>) -> u64 {
    chunks_of(data, &P)
        .iter()
        .filter(|(d, _)| !known.contains_key(d))
        .map(|(_, l)| l)
        .sum()
}

/// `blob` reads back as exactly `content`, with the storage form the X6 rule requires.
fn assert_round_trip(store: &SynapseStore, content: &[u8], what: &str) {
    let digest = BlobDigest::compute(content);
    let back = store.get_blob_visible(digest, None, None).unwrap();
    assert!(
        back == content,
        "{what}: bytes differ ({} vs {})",
        back.len(),
        content.len()
    );
    assert_eq!(BlobDigest::compute(&back), digest, "{what}: digest changed");
    let m = store.blob_manifest(&digest);
    if content.len() > T {
        let m = m.unwrap_or_else(|| panic!("{what}: above T but not chunked"));
        assert_eq!(m.blob, digest);
        assert_eq!(m.len, content.len() as u64);
        let ranges = chunk::chunk_ranges(content, &P);
        let expect: Vec<(ChunkDigest, u32)> = ranges
            .iter()
            .map(|r| (ChunkDigest::compute(&content[r.clone()]), r.len() as u32))
            .collect();
        assert_eq!(
            m.chunks, expect,
            "{what}: manifest is not the chunker's cut"
        );
    } else {
        assert!(m.is_none(), "{what}: at most T but chunked");
    }
}

/// The blobs of the round-trip test: edge sizes around T, random, repetitive, zeros, text.
fn round_trip_corpus() -> Vec<(String, Vec<u8>)> {
    let text: Vec<u8> = (0..120_000u32)
        .flat_map(|i| format!("line {i}: fn f{}() {{}}\n", i % 97).into_bytes())
        .take(150_000)
        .collect();
    let pattern: Vec<u8> = random(1000, 5)
        .into_iter()
        .cycle()
        .take(1_000_000)
        .collect();
    vec![
        ("empty".into(), vec![]),
        ("one".into(), vec![42]),
        ("t-minus-1".into(), random(T - 1, 1)),
        ("t".into(), random(T, 2)),
        ("t-plus-1".into(), random(T + 1, 3)),
        ("random-3m".into(), random(3_000_000, 4)),
        ("repetitive-1m".into(), pattern),
        ("zeros-500k".into(), vec![0u8; 500_000]),
        ("text".into(), text),
        ("max-chunk-edge".into(), random(P.max_bytes as usize * 3, 6)),
    ]
}

// --- acceptance 1: round trip ------------------------------------------------

/// Every blob, at every size class, reads back byte for byte with an unchanged
/// `BlobDigest`: right after commit, after a checkpoint, after reopen from the
/// checkpoint's segment index, and after reopen by replaying frames.
#[test]
fn g2_every_blob_round_trips_byte_for_byte_with_unchanged_blob_digest() {
    let dir = temp_store_dir("g2-round-trip");
    let k = key(120);
    let corpus = round_trip_corpus();
    let (first, second) = corpus.split_at(6);
    {
        let mut s = open(&dir);
        for (label, content) in first {
            commit_blob(&mut s, &k, label, content);
        }
        for (label, content) in first {
            assert_round_trip(&s, content, label);
        }
        s.checkpoint_and_compact(1000).unwrap();
        for (label, content) in first {
            assert_round_trip(&s, content, &format!("{label} after checkpoint"));
        }
    }
    {
        let mut s = open(&dir);
        for (label, content) in first {
            assert_round_trip(&s, content, &format!("{label} after reopen (index)"));
        }
        for (label, content) in second {
            commit_blob(&mut s, &k, label, content);
        }
    }
    let s = open(&dir);
    for (label, content) in &corpus {
        assert_round_trip(&s, content, &format!("{label} after reopen (replay)"));
    }
    assert_eq!(s.committed_seq(), WalSeq(corpus.len() as u64));
    let _ = fs::remove_dir_all(&dir);
}

// --- acceptance 2: deduplication under the X6 rule ---------------------------

/// Two revisions that share content: the second stores exactly its chunks not already
/// indexed (X6 rule 5.3); an identical revision and a re-provided blob add nothing; a
/// blob of at most T is stored whole (5.1). The same holds against chunks that come
/// from the checkpoint's segment index after reopen.
#[test]
fn g2_dedup_between_two_revisions_follows_the_x6_rule() {
    let dir = temp_store_dir("g2-dedup");
    let k = key(121);
    let a = random(400_000, 11);
    // B: A with 100 bytes inserted in the middle, 50 bytes changed near the start, and
    // 30 KB appended.
    let mut b = a.clone();
    b.splice(200_000..200_000, random(100, 12));
    b[10_000..10_050].copy_from_slice(&random(50, 13));
    b.extend_from_slice(&random(30_000, 14));
    // C (after reopen): B with its tail cut and a new middle edit.
    let mut c = b[..380_000].to_vec();
    c.splice(100_000..100_000, random(64, 15));

    let mut known = BTreeMap::new();
    {
        let mut s = open(&dir);
        commit_blob(&mut s, &k, "rev-a", &a);
        known.extend(chunks_of(&a, &P));
        let (n0, bytes0) = s.chunk_storage();
        assert_eq!(n0, known.len());
        assert_eq!(bytes0, known.values().sum::<u64>());

        let expected_b = new_chunk_bytes(&b, &known);
        assert!(
            expected_b > 0 && expected_b < b.len() as u64 / 4,
            "B shares most of A"
        );
        let log0 = s.log_bytes_written();
        commit_blob(&mut s, &k, "rev-b", &b);
        let (n1, bytes1) = s.chunk_storage();
        assert_eq!(bytes1 - bytes0, expected_b, "B adds exactly its new chunks");
        known.extend(chunks_of(&b, &P));
        assert_eq!(n1, known.len());
        let log_b = s.log_bytes_written() - log0;
        assert!(
            log_b < expected_b + 64 * 1024,
            "log bytes of B ({log_b}) carry only the new chunks ({expected_b}) plus metadata"
        );

        // Identical content under another path, bytes provided again: nothing added.
        commit_blob(&mut s, &k, "rev-a-again", &a);
        assert_eq!(s.chunk_storage(), (n1, bytes1));
        // Two files of one changeset sharing chunks with each other and with A.
        let mut a2 = a.clone();
        a2[300_000..300_010].copy_from_slice(&[7u8; 10]);
        let mut a3 = a2.clone();
        a3.extend_from_slice(&random(20_000, 16));
        let mut both = known.clone();
        let expected_23 = new_chunk_bytes(&a2, &both);
        both.extend(chunks_of(&a2, &P));
        let expected_23 = expected_23 + new_chunk_bytes(&a3, &both);
        let (env, blobs) = multi(&k, "rev-a2-a3", &[("x/a2", &a2), ("x/a3", &a3)]);
        commit_env(&mut s, env, &blobs);
        assert_eq!(
            s.chunk_storage().1 - bytes1,
            expected_23,
            "chunks shared inside one record"
        );
        known = both;
        known.extend(chunks_of(&a3, &P));

        // At most T: stored whole, never cut, also when committed twice.
        let small = random(T, 17);
        commit_blob(&mut s, &k, "small", &small);
        let inline0 = s.inline_blob_bytes();
        assert!(s.blob_manifest(&BlobDigest::compute(&small)).is_none());
        assert_eq!(s.chunk_storage().0, known.len());
        assert!(inline0 >= T as u64);
        for (what, content) in [
            ("a", &a),
            ("b", &b),
            ("a2", &a2),
            ("a3", &a3),
            ("small", &small),
        ] {
            assert_round_trip(&s, content, what);
        }
        s.checkpoint_and_compact(1000).unwrap();
        assert_eq!(
            s.chunk_storage().0,
            known.len(),
            "checkpoint keeps every chunk"
        );
    }
    let mut s = open(&dir);
    assert_eq!(
        s.chunk_storage().0,
        known.len(),
        "chunk index restored from the checkpoint"
    );
    let before = s.chunk_storage().1;
    let expected_c = new_chunk_bytes(&c, &known);
    commit_blob(&mut s, &k, "rev-c", &c);
    assert_eq!(
        s.chunk_storage().1 - before,
        expected_c,
        "dedup against indexed chunks"
    );
    drop(s);
    let s = open(&dir);
    for (what, content) in [("a", &a), ("b", &b), ("c", &c)] {
        assert_round_trip(&s, content, what);
    }
    let _ = fs::remove_dir_all(&dir);
}

/// Records accepted earlier in the same group-commit batch count as indexed (X6 rule
/// 5.3): four revisions sharing content in one batch store each chunk once.
#[test]
fn g2_dedup_inside_one_batch_counts_earlier_records() {
    let dir = temp_store_dir("g2-batch");
    let k = key(122);
    let base = random(300_000, 21);
    let revs: Vec<Vec<u8>> = (0..4u8)
        .map(|i| {
            let mut r = base.clone();
            r.extend_from_slice(&random(5000, 30 + u64::from(i)));
            r
        })
        .collect();
    let mut known = BTreeMap::new();
    for r in &revs {
        known.extend(chunks_of(r, &P));
    }
    let shared = SharedStore::open(
        &dir,
        FsyncPolicy::GroupCommit {
            max_batch_records: 4,
            max_batch_delay_us: 5_000_000,
        },
        STRICT,
        limits_with(P),
    )
    .unwrap();
    let inputs: Vec<_> = revs
        .iter()
        .enumerate()
        .map(|(i, r)| {
            make_signed_changeset(&k, &format!("b{i}"), &format!("b/{i}"), r, vec![], 1000)
        })
        .collect();
    let barrier = Barrier::new(inputs.len());
    std::thread::scope(|sc| {
        for (env, blobs) in inputs {
            let (shared, barrier) = (&shared, &barrier);
            sc.spawn(move || {
                barrier.wait();
                assert!(matches!(
                    shared.submit(env, &blobs).unwrap(),
                    IngestOutcome::Committed { .. }
                ));
            });
        }
    });
    let stats = shared.stats();
    assert_eq!((stats.batches, stats.records), (1, 4), "one batch");
    {
        let st = shared.read();
        assert_eq!(
            st.chunk_storage(),
            (known.len(), known.values().sum::<u64>())
        );
        let log = st.log_bytes_written();
        assert!(
            log < known.values().sum::<u64>() + 64 * 1024,
            "the batch carries each chunk once: {log} log bytes for {} chunk bytes",
            known.values().sum::<u64>()
        );
    }
    drop(shared);
    let s = open(&dir);
    assert_eq!(
        s.chunk_storage(),
        (known.len(), known.values().sum::<u64>())
    );
    for (i, r) in revs.iter().enumerate() {
        assert_round_trip(&s, r, &format!("batch rev {i}"));
    }
    let _ = fs::remove_dir_all(&dir);
}

/// The parameters are a storage choice only: a blob stored whole with chunking off is
/// still read whole, and re-providing it once chunking is on adds no chunks; a store
/// opened with other chunk parameters reads everything written with the first ones.
#[test]
fn g2_parameters_change_without_changing_identity() {
    let dir = temp_store_dir("g2-params");
    let k = key(123);
    let a = random(200_000, 41);
    let b = random(200_000, 42);
    {
        let mut s = open_with(&dir, ChunkParams::OFF);
        commit_blob(&mut s, &k, "off-a", &a);
        assert!(s.blob_manifest(&BlobDigest::compute(&a)).is_none());
    }
    {
        let mut s = open(&dir);
        commit_blob(&mut s, &k, "on-a", &a);
        assert_eq!(s.chunk_storage(), (0, 0), "already stored whole: no chunks");
        commit_blob(&mut s, &k, "on-b", &b);
        assert!(s.blob_manifest(&BlobDigest::compute(&b)).is_some());
    }
    let other = ChunkParams::candidate(64 * 1024, 16 * 1024);
    let s = open_with(&dir, other);
    for content in [&a, &b] {
        let d = BlobDigest::compute(content);
        assert!(s.get_blob_visible(d, None, None).unwrap() == *content);
    }
    let _ = fs::remove_dir_all(&dir);
}

// --- fail closed ---------------------------------------------------------------

/// Index position of a chunk of `blob` (the first one) on disk.
fn first_chunk_loc(store: &SynapseStore, blob: &BlobDigest) -> segment::BlobLoc {
    let m = store.blob_manifest(blob).unwrap();
    store.chunk_locations[&m.chunks[0].0]
}

fn flip_byte(dir: &Path, loc: segment::BlobLoc, at: u64) {
    use std::os::unix::fs::FileExt;
    let path = dir.join(segment::segment_file_name(loc.segment));
    let f = OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)
        .unwrap();
    let mut b = [0u8; 1];
    f.read_exact_at(&mut b, loc.offset + at).unwrap();
    f.write_all_at(&[b[0] ^ 0x40], loc.offset + at).unwrap();
}

/// A damaged chunk byte is never served: replay refuses the frame (its payload digest
/// covers the chunk digests and every chunk is checked against its digest), and a chunk
/// the checkpoint vouches for fails the blob read with `BlobDigestMismatch`.
#[test]
fn g2_damaged_chunk_is_refused() {
    let k = key(124);
    let a = random(100_000, 51);
    let da = BlobDigest::compute(&a);
    // Replayed frame.
    let dir = temp_store_dir("g2-damage-replay");
    let loc = {
        let mut s = open(&dir);
        commit_blob(&mut s, &k, "dmg", &a);
        first_chunk_loc(&s, &da)
    };
    flip_byte(&dir, loc, 7);
    let Err(err) = SynapseStore::open(
        &dir,
        FsyncPolicy::GROUP_COMMIT_DEFAULT,
        STRICT,
        limits_with(P),
    ) else {
        panic!("open must refuse");
    };
    assert!(
        matches!(
            err.code,
            RefusalCode::BlobDigestMismatch
                | RefusalCode::WalCrcMismatch
                | RefusalCode::WalTornFrame
        ),
        "replay must refuse: {err:?}"
    );
    let _ = fs::remove_dir_all(&dir);
    // Damaged chunk byte with the payload CRC and the frame digest repaired (as an
    // adversary, or a CRC collision, would leave it): only the chunk digest catches it.
    let dir = temp_store_dir("g2-damage-crc-repaired");
    let (loc, first_chunk_off) = {
        let mut s = open(&dir);
        commit_blob(&mut s, &k, "dmg", &a);
        let off = s.chunk_locations.values().map(|l| l.offset).min().unwrap();
        (first_chunk_loc(&s, &da), off)
    };
    assert_eq!(loc.segment, 1);
    flip_byte(&dir, loc, 7);
    {
        let path = dir.join(segment::segment_file_name(1));
        let mut seg = fs::read(&path).unwrap();
        let h0 = wal2::WAL_V2_BATCH_HEADER_LEN;
        let p0 = h0 + WAL_HEADER_LEN;
        let plen = u32::from_le_bytes(seg[h0 + 48..h0 + 52].try_into().unwrap()) as usize;
        let crc = crc32c(&seg[p0..p0 + plen]);
        seg[h0 + 52..h0 + 56].copy_from_slice(&crc.to_le_bytes());
        let psha = wal2::chunked_payload_digest(&seg[p0..p0 + plen], first_chunk_off as usize - p0);
        let fsha = wal2::frame_digest(&seg[h0..h0 + 56], &psha);
        seg[h0 + 56..h0 + 88].copy_from_slice(&fsha);
        fs::write(&path, &seg).unwrap();
    }
    let Err(err) = SynapseStore::open(
        &dir,
        FsyncPolicy::GROUP_COMMIT_DEFAULT,
        STRICT,
        limits_with(P),
    ) else {
        panic!("open must refuse a chunk whose digest does not match");
    };
    assert_eq!(err.code, RefusalCode::BlobDigestMismatch, "{err:?}");
    let _ = fs::remove_dir_all(&dir);
    // Chunk covered by the checkpoint.
    let dir = temp_store_dir("g2-damage-index");
    let loc = {
        let mut s = open(&dir);
        commit_blob(&mut s, &k, "dmg", &a);
        s.checkpoint_and_compact(1000).unwrap();
        first_chunk_loc(&s, &da)
    };
    flip_byte(&dir, loc, 7);
    let s = open(&dir);
    assert_eq!(
        s.get_blob_visible(da, None, None).unwrap_err().code,
        RefusalCode::BlobDigestMismatch
    );
    let _ = fs::remove_dir_all(&dir);
}

/// A frame whose manifest names a chunk that is nowhere indexed is refused at replay.
#[test]
fn g2_manifest_naming_an_unindexed_chunk_is_refused_at_replay() {
    let dir = temp_store_dir("g2-orphan-manifest");
    let k = key(125);
    let a = random(100_000, 61);
    {
        let mut s = open(&dir);
        commit_blob(&mut s, &k, "base", &a);
        // Forge the state of a store that already holds every chunk of A2 (it does not):
        // the next record then carries A2's manifest without its chunk bytes.
        let mut a2 = a.clone();
        a2.extend_from_slice(&random(40_000, 62));
        let fake = segment::BlobLoc {
            segment: 1,
            offset: 0,
            len: 1,
        };
        for (d, l) in chunks_of(&a2, &P) {
            s.chunk_locations.entry(d).or_insert(segment::BlobLoc {
                len: l as u32,
                ..fake
            });
        }
        commit_blob(&mut s, &k, "forged", &a2);
    }
    let Err(err) = SynapseStore::open(
        &dir,
        FsyncPolicy::GROUP_COMMIT_DEFAULT,
        STRICT,
        limits_with(P),
    ) else {
        panic!("open must refuse");
    };
    assert_eq!(err.code, RefusalCode::BlobNotFound, "{err:?}");
    let _ = fs::remove_dir_all(&dir);
}

/// Invalid chunk parameters are refused at open.
#[test]
fn g2_invalid_chunk_parameters_are_refused_at_open() {
    let dir = temp_store_dir("g2-bad-params");
    let bad = ChunkParams {
        avg_bytes: 3000,
        ..P
    };
    assert!(SynapseStore::open(
        &dir,
        FsyncPolicy::GROUP_COMMIT_DEFAULT,
        STRICT,
        limits_with(bad)
    )
    .is_err());
    let _ = fs::remove_dir_all(&dir);
}

/// Segment index version 2 round-trips chunks and manifests and refuses an orphan chunk,
/// a manifest naming a missing chunk, a manifest whose length disagrees, a chunk after
/// the replay position, and a flipped bit; an index without chunks stays version 1.
#[test]
fn g2_segment_index_v2_round_trips_and_refuses_damage() {
    let loc = |segment, offset, len| segment::BlobLoc {
        segment,
        offset,
        len,
    };
    let (c1, c2) = (ChunkDigest([1u8; 32]), ChunkDigest([2u8; 32]));
    let blob = BlobDigest([9u8; 32]);
    let index = segment::SegmentIndex {
        binding: [7u8; 32],
        replay_segment: 3,
        replay_offset: 8192,
        entries: [(BlobDigest([3u8; 32]), loc(1, 4096, 100))]
            .into_iter()
            .collect(),
        chunks: [(c1, loc(1, 100, 50)), (c2, loc(2, 0, 70))]
            .into_iter()
            .collect(),
        manifests: [(
            blob,
            ChunkManifest {
                blob,
                len: 170,
                chunks: vec![(c1, 50), (c2, 70), (c1, 50)],
            },
        )]
        .into_iter()
        .collect(),
    };
    let bytes = index.encode();
    assert_eq!(&bytes[4..6], &2u16.to_le_bytes());
    assert_eq!(segment::SegmentIndex::decode(&bytes).unwrap(), index);
    let refused = |i: &segment::SegmentIndex, what: &str| {
        assert_eq!(
            segment::SegmentIndex::decode(&i.encode()).unwrap_err().code,
            RefusalCode::CheckpointCorrupt,
            "{what}"
        )
    };
    let mut orphan = index.clone();
    orphan.chunks.insert(ChunkDigest([4u8; 32]), loc(1, 0, 10));
    refused(&orphan, "orphan chunk");
    let mut missing = index.clone();
    missing.chunks.remove(&c2);
    refused(&missing, "missing chunk");
    let mut short = index.clone();
    short.manifests.get_mut(&blob).unwrap().len = 169;
    refused(&short, "length mismatch");
    let mut late = index.clone();
    late.chunks.insert(c2, loc(3, 8192, 70));
    refused(&late, "chunk after the replay position");
    for at in [10, 70, bytes.len() - 40] {
        let mut b = bytes.clone();
        b[at] ^= 1;
        assert!(
            segment::SegmentIndex::decode(&b).is_err(),
            "bit flip at {at}"
        );
    }
    let plain = segment::SegmentIndex {
        chunks: BTreeMap::new(),
        manifests: BTreeMap::new(),
        ..index.clone()
    };
    assert_eq!(&plain.encode()[4..6], &1u16.to_le_bytes());
    assert_eq!(
        segment::SegmentIndex::decode(&plain.encode()).unwrap(),
        plain
    );
}

/// With chunking off the store writes exactly the A2 formats (no chunk flag, segment
/// index version 1), so builds before G2 still open it.
#[test]
fn g2_chunking_off_writes_the_a2_formats() {
    let dir = temp_store_dir("g2-off");
    let k = key(126);
    {
        let mut s = open_with(&dir, ChunkParams::OFF);
        commit_blob(&mut s, &k, "big", &random(300_000, 71));
        s.checkpoint_and_compact(1000).unwrap();
        assert_eq!(s.chunk_storage(), (0, 0));
    }
    let index = fs::read_dir(&dir)
        .unwrap()
        .map(|e| e.unwrap().path())
        .find(|p| {
            p.file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.starts_with(segment::SEGMENT_INDEX_PREFIX))
        })
        .unwrap();
    assert_eq!(&fs::read(index).unwrap()[4..6], &1u16.to_le_bytes());
    let _ = fs::remove_dir_all(&dir);
}

// --- crash ---------------------------------------------------------------------

fn child_dir() -> Option<PathBuf> {
    std::env::var(CHILD_ENV).ok().map(PathBuf::from)
}

/// A crash after a chunked batch is durable but before the in-memory index is updated
/// keeps every acknowledged change; the pending batch is kept whole and its blob reads
/// back byte for byte.
#[test]
fn g2_crash_after_chunked_batch_sync_before_index_keeps_every_ack() {
    let k = key(127);
    let revs: Vec<Vec<u8>> = (0..5u64)
        .map(|i| {
            let mut r = random(150_000, 80);
            r.extend_from_slice(&random(9000, 81 + i));
            r
        })
        .collect();
    if let Some(dir) = child_dir() {
        let mut s = open(&dir);
        for (i, r) in revs[..4].iter().enumerate() {
            commit_blob(&mut s, &k, &format!("cr-{i}"), r);
            if i == 1 {
                s.checkpoint_and_compact(1000).unwrap();
            }
        }
        s.set_fault_injection(FaultInjection::CrashAfterBatchSyncBeforeIndex);
        let (env, blobs) = make_signed_changeset(&k, "cr-4", "src/cr-4", &revs[4], vec![], 1000);
        let r = s.ingest_changeset(env, &blobs);
        panic!("the injected fault did not end the process: {r:?}");
    }
    let dir = temp_store_dir("g2-crash");
    let status = Command::new(std::env::current_exe().unwrap())
        .arg("--exact")
        .arg("g2_tests::g2_crash_after_chunked_batch_sync_before_index_keeps_every_ack")
        .arg("--nocapture")
        .env(CHILD_ENV, &dir)
        .status()
        .unwrap();
    assert_eq!(status.code(), Some(FAULT_CRASH_EXIT_CODE));
    let s = open(&dir);
    assert_eq!(s.committed_seq(), WalSeq(5));
    let mut known = BTreeMap::new();
    for (i, r) in revs.iter().enumerate() {
        assert_round_trip(&s, r, &format!("rev {i}"));
        known.extend(chunks_of(r, &P));
    }
    assert_eq!(
        s.chunk_storage(),
        (known.len(), known.values().sum::<u64>())
    );
    let _ = fs::remove_dir_all(&dir);
}

// --- old stores ------------------------------------------------------------------

/// Stores written before G2 stay readable with chunking on: the A1 fixtures (v1 WAL,
/// single-file WAL v2, blobs as files) and an A2 segment store written by the A2 code
/// itself (`tests/fixtures/g2-a2/segment-store`, generator under
/// `evidence/g2-content-defined-chunking/fixture-generator`). Their blobs read back
/// whole, new chunked blobs land next to them, and everything survives a checkpoint and
/// reopen.
#[test]
fn g2_old_stores_stay_readable() {
    let k = key(128);
    let big = random(120_000, 91);
    for name in ["v1-wal-log", "v1-wal-v2-log"] {
        let dir = copy_fixture(name);
        let ex = expect(name);
        old_store_case(&dir, name, ex.committed_seq, ex.state_root, &k, &big);
    }
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/g2-a2/segment-store");
    let dir = temp_store_dir("g2-a2-fixture");
    copy_tree(&src, &dir);
    let text = fs::read_to_string(dir.join("EXPECT")).unwrap();
    let _ = fs::remove_file(dir.join("EXPECT"));
    let field = |key: &str| {
        text.lines()
            .find_map(|l| l.strip_prefix(key).map(|v| v.trim().to_string()))
            .unwrap()
    };
    let seq: u64 = field("committed_seq ").parse().unwrap();
    let root: [u8; 32] = hex::decode(field("state_root "))
        .unwrap()
        .try_into()
        .unwrap();
    assert!(
        segment::list_segments(&dir).unwrap().len() >= 2,
        "fixture spans segments"
    );
    old_store_case(&dir, "a2-segment-store", seq, root, &k, &big);
}

fn old_store_case(dir: &Path, name: &str, seq: u64, root: [u8; 32], k: &SigningKey, big: &[u8]) {
    let old_blobs = |s: &SynapseStore| -> Vec<BlobDigest> {
        let mut v = BTreeSet::new();
        for c in s.list_changesets(None, None, Some(WalSeq(seq))).unwrap() {
            for m in &c.envelope.mutations {
                if let MutationOp::Upsert { blob_digest, .. } = &m.op {
                    v.insert(*blob_digest);
                }
            }
        }
        v.into_iter().collect()
    };
    let check_old = |s: &SynapseStore, what: &str| {
        let blobs = old_blobs(s);
        assert!(!blobs.is_empty(), "{name}: fixture holds blobs");
        for d in blobs {
            let bytes = s.get_blob_visible(d, None, None).unwrap();
            assert_eq!(BlobDigest::compute(&bytes), d, "{name} {what}");
            assert!(
                s.blob_manifest(&d).is_none(),
                "{name}: old blob stays whole"
            );
        }
    };
    {
        let mut s = open(dir);
        assert_eq!(s.committed_seq(), WalSeq(seq), "{name}");
        assert_eq!(s.state_root_digest(None).unwrap(), root, "{name}");
        check_old(&s, "on open");
        commit_blob(&mut s, k, &format!("{name}-g2"), big);
        assert_round_trip(&s, big, name);
        s.checkpoint_and_compact(1000).unwrap();
    }
    let s = open(dir);
    assert_eq!(s.committed_seq(), WalSeq(seq + 1), "{name}");
    check_old(&s, "after checkpoint and reopen");
    assert_round_trip(&s, big, name);
    let _ = fs::remove_dir_all(dir);
}
