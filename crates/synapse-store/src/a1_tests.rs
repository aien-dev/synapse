//! ADR 0003 section 9 step A1 acceptance tests: binary canonical codec v2 for WAL records
//! and checkpoints.
//!
//! The v1 fixtures under `tests/fixtures/a1-v1` were written by the merged main-branch
//! store (`b04ad31`, JSON codec), so "the v1 JSON form" here is real v1 output, not a
//! re-serialization by the code under test. The generator is kept in
//! `evidence/a1-binary-codec/fixture-generator`.

use super::tests::{make_signed_changeset, temp_store_dir};
use super::*;
use crate::codec::*;
use ed25519_dalek::SigningKey;
use synapse_core::{FileMode, GitOid, PathMutation, SYNAPSE_ENVELOPE_VERSION};

const STRICT: RecoveryPolicy = RecoveryPolicy::StrictFailClosed;

fn fixture_dir(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/a1-v1")
        .join(name)
}

fn copy_tree(src: &Path, dst: &Path) {
    fs::create_dir_all(dst).unwrap();
    for e in fs::read_dir(src).unwrap() {
        let e = e.unwrap();
        let to = dst.join(e.file_name());
        if e.file_type().unwrap().is_dir() {
            copy_tree(&e.path(), &to);
        } else {
            fs::copy(e.path(), &to).unwrap();
        }
    }
}

/// Copy a fixture store into a fresh temporary directory (opening a store writes to it).
fn copy_fixture(name: &str) -> PathBuf {
    let dir = temp_store_dir(&format!("a1-{name}"));
    copy_tree(&fixture_dir(name), &dir);
    let _ = fs::remove_file(dir.join("EXPECT"));
    dir
}

struct Expect {
    committed_seq: u64,
    state_root: [u8; 32],
}

fn expect(name: &str) -> Expect {
    let text = fs::read_to_string(fixture_dir(name).join("EXPECT")).unwrap();
    let field = |k: &str| {
        text.lines()
            .find_map(|l| l.strip_prefix(k).map(|v| v.trim().to_string()))
            .unwrap()
    };
    Expect {
        committed_seq: field("committed_seq ").parse().unwrap(),
        state_root: hex::decode(field("state_root "))
            .unwrap()
            .try_into()
            .unwrap(),
    }
}

/// `(kind, flags, payload)` of every frame in a `wal.log` (the v2 marker excluded).
fn v1_log_frames(bytes: &[u8]) -> Vec<(u8, u8, Vec<u8>)> {
    let mut out = Vec::new();
    let mut at = 0;
    while at < bytes.len() {
        let h = &bytes[at..at + WAL_HEADER_LEN];
        let len = u32::from_le_bytes(h[48..52].try_into().unwrap()) as usize;
        if h[6] != 0xFF {
            out.push((
                h[6],
                h[7],
                bytes[at + WAL_HEADER_LEN..at + WAL_HEADER_LEN + len].to_vec(),
            ));
        }
        at += WAL_HEADER_LEN + len;
    }
    out
}

/// `(kind, flags, record bytes)` of every frame in a `wal.v2.log` (the record bytes are
/// the payload's metadata part, without inline blobs).
fn v2_log_frames(bytes: &[u8]) -> Vec<(u8, u8, Vec<u8>)> {
    let mut out = Vec::new();
    let mut off = 0usize;
    while off + wal2::WAL_V2_BATCH_HEADER_LEN <= bytes.len()
        && bytes[off..off + 4] == wal2::WAL_V2_BATCH_MAGIC
    {
        let count = u32::from_le_bytes(bytes[off + 8..off + 12].try_into().unwrap());
        let body = u64::from_le_bytes(bytes[off + 16..off + 24].try_into().unwrap()) as usize;
        let mut at = off + wal2::WAL_V2_BATCH_HEADER_LEN;
        for _ in 0..count {
            let h = &bytes[at..at + WAL_HEADER_LEN];
            let len = u32::from_le_bytes(h[48..52].try_into().unwrap()) as usize;
            let p = &bytes[at + WAL_HEADER_LEN..at + WAL_HEADER_LEN + len];
            let meta_len = u32::from_le_bytes(p[0..4].try_into().unwrap()) as usize;
            out.push((h[6], h[7], p[4..4 + meta_len].to_vec()));
            at += WAL_HEADER_LEN + len;
        }
        off = wal2::align_up((off + wal2::WAL_V2_BATCH_HEADER_LEN + body) as u64) as usize;
    }
    out
}

fn v1_flags(dir: &Path) -> Vec<u8> {
    v1_log_frames(&fs::read(dir.join("wal.log")).unwrap())
        .into_iter()
        .map(|(_, f, _)| f)
        .collect()
}

fn v2_flags(dir: &Path) -> Vec<u8> {
    v2_log_frames(&fs::read(dir.join(wal2::WAL_V2_FILE)).unwrap())
        .into_iter()
        .map(|(_, f, _)| f)
        .collect()
}

/// Every v1 JSON record payload in both fixtures.
fn fixture_json_records() -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    for (kind, flags, json) in
        v1_log_frames(&fs::read(fixture_dir("v1-wal-log").join("wal.log")).unwrap())
    {
        assert_eq!(flags, 0, "fixture frames are v1 JSON");
        assert_ne!(kind, 0);
        out.push(json);
    }
    for (_, flags, json) in
        v2_log_frames(&fs::read(fixture_dir("v1-wal-v2-log").join(wal2::WAL_V2_FILE)).unwrap())
    {
        assert_eq!(flags, 0, "fixture frames are v1 JSON");
        out.push(json);
    }
    out
}

const CAP: u64 = 128 * 1024 * 1024;

/// Both directions for one record, starting from its v1 JSON bytes.
fn assert_both_directions(json: &[u8]) -> u8 {
    let record: WalRecord = serde_json::from_slice(json).unwrap();
    // JSON -> binary -> the same logical record, whose JSON form is the original bytes.
    let bin = encode_record(&record).unwrap();
    assert_eq!(bin.first(), Some(&CODEC_V2), "codec version byte");
    assert_eq!(bin.get(1), Some(&record.kind_byte()), "record kind byte");
    let from_bin = decode_record(&bin, CAP).unwrap();
    assert_eq!(from_bin, record);
    assert_eq!(serde_json::to_vec(&from_bin).unwrap(), json);
    // binary -> JSON -> the same logical record, whose binary form is the original bytes.
    let via_json: WalRecord =
        serde_json::from_slice(&serde_json::to_vec(&from_bin).unwrap()).unwrap();
    assert_eq!(via_json, from_bin);
    assert_eq!(encode_record(&via_json).unwrap(), bin);
    record.kind_byte()
}

#[test]
fn a1_every_record_kind_matches_its_v1_json_form_in_both_directions() {
    let mut kinds = BTreeSet::new();
    let records = fixture_json_records();
    // 8 frames left in the v1 wal.log after its checkpoint, 8 in the group-commit log.
    assert_eq!(records.len(), 16, "fixture record count");
    for json in &records {
        kinds.insert(assert_both_directions(json));
    }
    assert_eq!(
        kinds,
        (1u8..=6).collect::<BTreeSet<_>>(),
        "every WalRecord kind is covered"
    );
}

fn edge_records() -> Vec<WalRecord> {
    let key = SigningKey::from_bytes(&[0xE1; 32]);
    let a = BlobDigest::compute(b"a");
    let mut env = ChangesetEnvelope {
        version: SYNAPSE_ENVELOPE_VERSION,
        repo_id: RepoId::new("a/b.c_d-e").unwrap(),
        base_git_oid: GitOid::ZERO,
        parent_changesets: vec![ChangesetId([0u8; 32]), ChangesetId([0xFF; 32])],
        author_did: String::new(),
        idempotency_key: IdempotencyKey([0xAB; 32]),
        created_at_ms: u64::MAX,
        intent_summary: "\u{0}\u{7f}\u{10FFFF} edge".into(),
        mutations: vec![
            PathMutation {
                path: "a".into(),
                op: MutationOp::Upsert {
                    mode: FileMode::Regular644,
                    blob_digest: a,
                    size_bytes: 0,
                },
            },
            PathMutation {
                path: "b/c".into(),
                op: MutationOp::Upsert {
                    mode: FileMode::Symlink120000,
                    blob_digest: a,
                    size_bytes: u64::MAX,
                },
            },
            PathMutation {
                path: "d".into(),
                op: MutationOp::Delete,
            },
        ],
        evidence_receipts: vec![
            EvidenceAttachment {
                gate_name: String::new(),
                passed: false,
                artifact_digest: [0u8; 32],
                summary: String::new(),
            },
            EvidenceAttachment {
                gate_name: "g".into(),
                passed: true,
                artifact_digest: [1u8; 32],
                summary: "s".repeat(300),
            },
        ],
        signature: vec![],
    };
    env.sign(&key);
    let id = env.compute_id();
    vec![
        WalRecord::ChangesetIngest {
            envelope: env.clone(),
            changeset_id: id,
            new_blobs: vec![],
        },
        WalRecord::ChangesetIngest {
            envelope: ChangesetEnvelope {
                signature: vec![],
                parent_changesets: vec![],
                evidence_receipts: vec![],
                ..env
            },
            changeset_id: id,
            new_blobs: vec![a, BlobDigest([0u8; 32])],
        },
        WalRecord::EvaluationAttached {
            changeset_id: id,
            attachment: EvidenceAttachment {
                gate_name: "\u{1F600}".into(),
                passed: true,
                artifact_digest: [2u8; 32],
                summary: "x\ty".into(),
            },
        },
        WalRecord::ReviewRecorded {
            changeset_id: id,
            review: ReviewRecord {
                reviewer_did: String::new(),
                approved: false,
                comment: String::new(),
                recorded_at_ms: 0,
            },
        },
        WalRecord::GitProjected {
            projection: GitHubPullRequestProjection {
                repo_id: RepoId::new("x").unwrap(),
                pr_number: u64::MAX,
                changeset_id: id,
                head_git_oid: GitOid([0xFF; 20]),
                base_git_oid: GitOid::ZERO,
                pr_branch_ref: String::new(),
                title: String::new(),
                body_markdown: "\r\n".into(),
                evidence_summary_digest: [0u8; 32],
                github_merged: true,
            },
        },
        WalRecord::CanonicalPromoted {
            canonical: RadicleCanonicalHead {
                repo_id: RepoId::new("x/y").unwrap(),
                default_branch: String::new(),
                canonical_git_oid: GitOid::ZERO,
                promoted_changeset_id: None,
                rad_id_commit_oid: GitOid([1u8; 20]),
                threshold: usize::MAX,
                verified_delegates: vec![String::new(), "d".into()],
                verified_at_ms: u64::MAX,
            },
        },
        WalRecord::LeaseUpdated {
            changeset_id: id,
            lease_expires_at_ms: 0,
        },
    ]
}

#[test]
fn a1_edge_records_match_their_json_form_in_both_directions() {
    for r in edge_records() {
        let json = serde_json::to_vec(&r).unwrap();
        assert_both_directions(&json);
    }
}

#[test]
fn a1_encoder_refuses_a_repository_id_that_rejects_validation() {
    // `RepoId`'s serde derive accepts any string; the binary decoder validates, so the
    // encoder must refuse what the decoder would refuse.
    let bad: RepoId = serde_json::from_str("\"a//b\"").unwrap();
    let r = WalRecord::CanonicalPromoted {
        canonical: RadicleCanonicalHead {
            repo_id: bad,
            default_branch: "main".into(),
            canonical_git_oid: GitOid::ZERO,
            promoted_changeset_id: None,
            rad_id_commit_oid: GitOid::ZERO,
            threshold: 1,
            verified_delegates: vec![],
            verified_at_ms: 0,
        },
    };
    assert_eq!(
        encode_record(&r).unwrap_err().code,
        RefusalCode::RepoIdInvalid
    );
}

fn put_str(b: &mut Vec<u8>, s: &[u8]) {
    b.extend_from_slice(&(s.len() as u32).to_le_bytes());
    b.extend_from_slice(s);
}

/// `ReviewRecorded` written by hand from the documented layout.
fn review_bytes(did: &[u8], approved: u8, comment: &[u8]) -> Vec<u8> {
    let mut b = vec![CODEC_V2, 3];
    b.extend_from_slice(&[9u8; 32]);
    put_str(&mut b, did);
    b.push(approved);
    put_str(&mut b, comment);
    b.extend_from_slice(&7u64.to_le_bytes());
    b
}

/// `CanonicalPromoted` written by hand with option tag `tag` and repository id `repo`.
fn canonical_bytes(repo: &[u8], tag: u8) -> Vec<u8> {
    let mut b = vec![CODEC_V2, 5];
    put_str(&mut b, repo);
    put_str(&mut b, b"main");
    b.extend_from_slice(&[1u8; 20]);
    b.push(tag);
    if tag == 1 {
        b.extend_from_slice(&[2u8; 32]);
    }
    b.extend_from_slice(&[3u8; 20]);
    b.extend_from_slice(&2u64.to_le_bytes());
    b.extend_from_slice(&0u32.to_le_bytes());
    b.extend_from_slice(&5u64.to_le_bytes());
    b
}

#[test]
fn a1_documented_layout_decodes_and_every_non_canonical_form_is_refused() {
    // Positive controls: the hand-written layout is what the codec reads and writes.
    let review = review_bytes(b"did:key:z", 1, b"ok");
    let r = decode_record(&review, CAP).unwrap();
    assert_eq!(
        r,
        WalRecord::ReviewRecorded {
            changeset_id: ChangesetId([9u8; 32]),
            review: ReviewRecord {
                reviewer_did: "did:key:z".into(),
                approved: true,
                comment: "ok".into(),
                recorded_at_ms: 7,
            },
        }
    );
    assert_eq!(encode_record(&r).unwrap(), review);
    let canon = canonical_bytes(b"a/b", 1);
    let c = decode_record(&canon, CAP).unwrap();
    assert_eq!(encode_record(&c).unwrap(), canon);
    assert_eq!(
        decode_record(&canonical_bytes(b"a/b", 0), CAP)
            .map(|r| matches!(r, WalRecord::CanonicalPromoted { canonical } if canonical.promoted_changeset_id.is_none())),
        Ok(true)
    );

    let kind = |r: Result<WalRecord, CodecRefusal>| r.unwrap_err().kind();
    let mut v1 = review.clone();
    v1[0] = 1;
    assert_eq!(
        decode_record(&v1, CAP),
        Err(CodecRefusal::VersionUnsupported { found: 1 })
    );
    let mut k = review.clone();
    k[1] = 7;
    assert_eq!(kind(decode_record(&k, CAP)), "UnknownTag");
    let mut k0 = review.clone();
    k0[1] = 0;
    assert_eq!(kind(decode_record(&k0, CAP)), "UnknownTag");
    let mut trailing = review.clone();
    trailing.push(0);
    assert_eq!(kind(decode_record(&trailing, CAP)), "TrailingBytes");
    assert_eq!(
        kind(decode_record(&review[..review.len() - 1], CAP)),
        "Truncated"
    );
    assert_eq!(kind(decode_record(&[], CAP)), "Truncated");
    assert_eq!(
        kind(decode_record(&review_bytes(b"d", 2, b""), CAP)),
        "UnknownTag"
    );
    assert_eq!(
        kind(decode_record(&review_bytes(b"\xff\xfe", 1, b""), CAP)),
        "InvalidUtf8"
    );
    assert_eq!(
        kind(decode_record(&canonical_bytes(b"a/b", 2), CAP)),
        "UnknownTag"
    );
    assert_eq!(
        kind(decode_record(&canonical_bytes(b"a//b", 0), CAP)),
        "InvalidRepoId"
    );
    // A declared length longer than what remains, and one longer than the cap.
    let mut long = review.clone();
    long[34..38].copy_from_slice(&1000u32.to_le_bytes());
    assert_eq!(kind(decode_record(&long, CAP)), "Truncated");
    let mut huge = review.clone();
    huge[34..38].copy_from_slice(&u32::MAX.to_le_bytes());
    assert_eq!(
        decode_record(&huge, 4096),
        Err(CodecRefusal::LengthOverCap {
            at: 34,
            declared: u64::from(u32::MAX),
            cap: 4096
        })
    );
    // Malformed binary records surface as WalRecordMalformed.
    assert_eq!(
        decode_record_with(&trailing, RecordCodec::BinaryV2, CAP)
            .unwrap_err()
            .code,
        RefusalCode::WalRecordMalformed
    );
}

#[test]
fn a1_checkpoint_state_matches_its_v1_json_form_in_both_directions() {
    let v1_bytes = fs::read(fixture_dir("v1-wal-log").join("checkpoint.v1")).unwrap();
    let manifest: CheckpointManifest = serde_json::from_slice(&v1_bytes).unwrap();
    let state = CheckpointState::from_v1_manifest(manifest.clone()).unwrap();
    assert!(!state.changesets.is_empty() && !state.github_projections.is_empty());
    assert_eq!(state.to_v1_manifest(), manifest);
    assert_eq!(
        serde_json::to_vec(&state.to_v1_manifest()).unwrap(),
        v1_bytes
    );

    let (bytes, chain) = encode_checkpoint_v2(&state, [1u8; 32], [2u8; 32]).unwrap();
    assert_eq!(bytes[0..4], CHECKPOINT_V2_MAGIC);
    let (back, back_chain) = decode_checkpoint_v2(&bytes).unwrap();
    assert_eq!(back, state);
    assert_eq!(back_chain, chain);
    assert_eq!(
        serde_json::to_vec(&back.to_v1_manifest()).unwrap(),
        v1_bytes
    );
    // Canonical: the decoded state encodes to the same bytes.
    assert_eq!(
        encode_checkpoint_v2(&back, [1u8; 32], [2u8; 32]).unwrap().0,
        bytes
    );
    assert_eq!(chain.v1_state_root, [1u8; 32]);
    assert_eq!(chain.prev_checkpoint_root, [2u8; 32]);
    assert_eq!(chain.state_root, state.state_root());
    assert_eq!(
        chain.checkpoint_root,
        checkpoint_root(
            &[1u8; 32],
            &[2u8; 32],
            state.checkpoint_seq,
            &state.anchor_frame_sha256,
            &chain.state_root,
            &chain.content_sha256
        )
    );
}

#[test]
fn a1_state_root_helpers_match_the_store() {
    let empty = temp_store_dir("a1-empty-root");
    let s = SynapseStore::open(
        &empty,
        FsyncPolicy::EveryCommit,
        STRICT,
        StoreLimits::default(),
    )
    .unwrap();
    assert_eq!(s.state_root_digest(None).unwrap(), empty_state_root());
    let dir = copy_fixture("v1-wal-log");
    let s = SynapseStore::open(
        &dir,
        FsyncPolicy::EveryCommit,
        STRICT,
        StoreLimits::default(),
    )
    .unwrap();
    assert_eq!(
        state_root_of(&s.changesets, s.committed_seq),
        s.state_root_digest(None).unwrap()
    );
    assert_eq!(
        state_root_of(&s.changesets, WalSeq(3)),
        s.state_root_digest(Some(WalSeq(3))).unwrap()
    );
}

fn first_changeset(s: &SynapseStore) -> ChangesetId {
    *s.changesets.keys().next().unwrap()
}

/// Legacy v1 store: replay unchanged, keeps writing v1 until its first v2 checkpoint,
/// which records the last v1 state root and chains its own root to it.
fn migration_case(name: &str, policy: FsyncPolicy, flags: fn(&Path) -> Vec<u8>) {
    let limits = StoreLimits {
        wal_prealloc_bytes: 64 * 1024,
        ..Default::default()
    };
    let dir = copy_fixture(name);
    let ex = expect(name);
    let mut s = SynapseStore::open(&dir, policy, STRICT, limits.clone()).unwrap();
    assert_eq!(s.committed_seq(), WalSeq(ex.committed_seq), "{name}");
    assert_eq!(s.state_root_digest(None).unwrap(), ex.state_root, "{name}");
    assert_eq!(
        s.record_codec(),
        RecordCodec::JsonV1,
        "{name}: legacy store"
    );
    assert_eq!(s.checkpoint_chain(), None);
    let cs = first_changeset(&s);
    s.update_lease(cs, 7).unwrap();
    assert!(flags(&dir).iter().all(|f| *f == 0), "{name}: still v1");

    let last_v1_root = s.state_root_digest(None).unwrap();
    s.checkpoint_and_compact(2_000).unwrap();
    let chain = s.checkpoint_chain().expect("first v2 checkpoint");
    assert_eq!(chain.v1_state_root, last_v1_root, "{name}");
    assert_eq!(chain.prev_checkpoint_root, last_v1_root, "{name}");
    assert_eq!(chain.checkpoint_seq, s.committed_seq());
    assert_eq!(chain.anchor_frame_sha256, s.last_frame_sha256());
    assert_eq!(chain.state_root, s.state_root_digest(None).unwrap());
    assert_eq!(
        chain.checkpoint_root,
        checkpoint_root(
            &last_v1_root,
            &last_v1_root,
            chain.checkpoint_seq,
            &chain.anchor_frame_sha256,
            &chain.state_root,
            &chain.content_sha256
        )
    );
    let file = fs::read(dir.join(CHECKPOINT_V2_FILE)).unwrap();
    assert_eq!(decode_checkpoint_v2(&file).unwrap().1, chain);
    assert_eq!(
        fs::read(dir.join("checkpoint.v1")).unwrap(),
        v1_tombstone_bytes()
    );
    assert_eq!(s.record_codec(), RecordCodec::BinaryV2, "{name}");

    s.update_lease(cs, 8).unwrap();
    s.update_lease(cs, 9).unwrap();
    let f = flags(&dir);
    assert!(
        !f.is_empty() && f.iter().all(|f| *f == WAL_FLAG_CODEC_V2),
        "{name}: frames after the migration are binary: {f:?}"
    );
    let root = s.state_root_digest(None).unwrap();
    drop(s);

    let mut s = SynapseStore::open(&dir, policy, STRICT, limits).unwrap();
    assert_eq!(s.state_root_digest(None).unwrap(), root, "{name}: reopen");
    assert_eq!(s.checkpoint_chain(), Some(chain));
    assert_eq!(s.record_codec(), RecordCodec::BinaryV2);
    s.checkpoint_and_compact(3_000).unwrap();
    let next = s.checkpoint_chain().unwrap();
    assert_eq!(next.prev_checkpoint_root, chain.checkpoint_root, "{name}");
    assert_eq!(next.v1_state_root, last_v1_root, "{name}");
    assert_eq!(
        next.checkpoint_root,
        checkpoint_root(
            &last_v1_root,
            &chain.checkpoint_root,
            next.checkpoint_seq,
            &next.anchor_frame_sha256,
            &next.state_root,
            &next.content_sha256
        )
    );
}

#[test]
fn a1_first_v2_checkpoint_records_last_v1_root_and_chains_wal_log() {
    migration_case("v1-wal-log", FsyncPolicy::EveryCommit, v1_flags);
}

#[test]
fn a1_first_v2_checkpoint_records_last_v1_root_and_chains_wal_v2_log() {
    migration_case("v1-wal-v2-log", FsyncPolicy::GROUP_COMMIT_DEFAULT, v2_flags);
}

#[test]
fn a1_v1_readers_refuse_the_tombstone() {
    // A binary that only knows v1 parses checkpoint.v1 and refuses any version but 1.
    let m: CheckpointManifest = serde_json::from_slice(&v1_tombstone_bytes()).unwrap();
    assert_eq!(m.version, CHECKPOINT_V2_VERSION);
    assert_ne!(m.version, CHECKPOINT_VERSION);
    // This binary refuses a tombstone whose checkpoint.v2 is missing.
    let dir = temp_store_dir("a1-tombstone-alone");
    fs::write(dir.join("checkpoint.v1"), v1_tombstone_bytes()).unwrap();
    let r = SynapseStore::open(
        &dir,
        FsyncPolicy::EveryCommit,
        STRICT,
        StoreLimits::default(),
    );
    assert_eq!(
        r.err().map(|e| e.code),
        Some(RefusalCode::CheckpointCorrupt)
    );
}

fn fresh_case(policy: FsyncPolicy, flags: fn(&Path) -> Vec<u8>) {
    let dir = temp_store_dir("a1-fresh");
    let key = SigningKey::from_bytes(&[0xF1; 32]);
    let mut s = SynapseStore::open(&dir, policy, STRICT, StoreLimits::default()).unwrap();
    assert_eq!(s.record_codec(), RecordCodec::BinaryV2);
    for i in 0..3u64 {
        let (env, blobs) = make_signed_changeset(
            &key,
            &format!("fresh-{i}"),
            &format!("f{i}.rs"),
            format!("{i}").as_bytes(),
            vec![],
            1,
        );
        s.ingest_changeset(env, &blobs).unwrap();
    }
    let f = flags(&dir);
    assert_eq!(f, vec![WAL_FLAG_CODEC_V2; 3]);
    s.checkpoint_and_compact(2).unwrap();
    let chain = s.checkpoint_chain().unwrap();
    assert_eq!(chain.v1_state_root, empty_state_root());
    assert_eq!(chain.prev_checkpoint_root, empty_state_root());
    let root = s.state_root_digest(None).unwrap();
    drop(s);
    let s = SynapseStore::open(&dir, policy, STRICT, StoreLimits::default()).unwrap();
    assert_eq!(s.state_root_digest(None).unwrap(), root);
    assert_eq!(s.committed_seq(), WalSeq(3));
}

#[test]
fn a1_fresh_store_writes_binary_frames_and_records_the_empty_v1_root() {
    fresh_case(FsyncPolicy::EveryCommit, v1_flags);
    fresh_case(FsyncPolicy::GROUP_COMMIT_DEFAULT, v2_flags);
}

/// Append a correctly chained frame with `codec` to `wal.log`.
fn append_frame(dir: &Path, s: &SynapseStore, record: &WalRecord, codec: RecordCodec) {
    let payload = encode_record_with(record, codec).unwrap();
    let (frame, _) = wal_frame_from_payload(
        s.committed_seq().next(),
        s.last_frame_sha256(),
        record.kind_byte(),
        codec.frame_flags(),
        &payload,
    );
    let mut f = OpenOptions::new()
        .append(true)
        .open(dir.join("wal.log"))
        .unwrap();
    f.write_all(&frame).unwrap();
}

#[test]
fn a1_codec_never_goes_back_and_never_runs_ahead_of_the_migration() {
    // A v1 JSON frame after binary frames is refused.
    let dir = temp_store_dir("a1-downgrade");
    let key = SigningKey::from_bytes(&[0xD1; 32]);
    let mut s = SynapseStore::open(
        &dir,
        FsyncPolicy::EveryCommit,
        STRICT,
        StoreLimits::default(),
    )
    .unwrap();
    let (env, blobs) = make_signed_changeset(&key, "d", "d.rs", b"d", vec![], 1);
    s.ingest_changeset(env, &blobs).unwrap();
    let lease = WalRecord::LeaseUpdated {
        changeset_id: first_changeset(&s),
        lease_expires_at_ms: 5,
    };
    append_frame(&dir, &s, &lease, RecordCodec::JsonV1);
    drop(s);
    let r = SynapseStore::open(
        &dir,
        FsyncPolicy::EveryCommit,
        STRICT,
        StoreLimits::default(),
    );
    assert_eq!(
        r.err().map(|e| e.code),
        Some(RefusalCode::WalVersionUnsupported)
    );

    // A binary frame in a v1 store before its migration checkpoint is refused.
    let dir = copy_fixture("v1-wal-log");
    let s = SynapseStore::open(
        &dir,
        FsyncPolicy::EveryCommit,
        STRICT,
        StoreLimits::default(),
    )
    .unwrap();
    let lease = WalRecord::LeaseUpdated {
        changeset_id: first_changeset(&s),
        lease_expires_at_ms: 5,
    };
    append_frame(&dir, &s, &lease, RecordCodec::BinaryV2);
    drop(s);
    let r = SynapseStore::open(
        &dir,
        FsyncPolicy::EveryCommit,
        STRICT,
        StoreLimits::default(),
    );
    assert_eq!(
        r.err().map(|e| e.code),
        Some(RefusalCode::WalVersionUnsupported)
    );
}

#[test]
fn a1_damaged_checkpoint_v2_is_refused() {
    let dir = temp_store_dir("a1-ckpt-damage");
    let key = SigningKey::from_bytes(&[0xC1; 32]);
    {
        let mut s = SynapseStore::open(
            &dir,
            FsyncPolicy::EveryCommit,
            STRICT,
            StoreLimits::default(),
        )
        .unwrap();
        let (env, blobs) = make_signed_changeset(&key, "c", "c.rs", b"c", vec![], 1);
        s.ingest_changeset(env, &blobs).unwrap();
        s.checkpoint_and_compact(2).unwrap();
    }
    let path = dir.join(CHECKPOINT_V2_FILE);
    let good = fs::read(&path).unwrap();
    for damaged in [
        {
            let mut b = good.clone();
            let last = b.len() - 1;
            b[last] ^= 0x01;
            b
        },
        {
            let mut b = good.clone();
            b[20] ^= 0x80;
            b
        },
        good[..good.len() - 1].to_vec(),
        good[..CHECKPOINT_V2_HEADER_LEN - 1].to_vec(),
    ] {
        fs::write(&path, &damaged).unwrap();
        for policy in [STRICT, RecoveryPolicy::TruncateTornTail] {
            let r = SynapseStore::open(
                &dir,
                FsyncPolicy::EveryCommit,
                policy,
                StoreLimits::default(),
            );
            assert_eq!(
                r.err().map(|e| e.code),
                Some(RefusalCode::CheckpointCorrupt)
            );
        }
    }
}

#[test]
fn a1_frame_length_cap_is_enforced_on_write_and_on_replay() {
    let key = SigningKey::from_bytes(&[0xCA; 32]);
    let small = StoreLimits {
        max_wal_record_bytes: 64,
        ..Default::default()
    };
    // Writer: a record above the cap is refused and nothing is logged.
    let dir = temp_store_dir("a1-cap-write");
    let mut s = SynapseStore::open(&dir, FsyncPolicy::EveryCommit, STRICT, small.clone()).unwrap();
    let (env, blobs) = make_signed_changeset(&key, "w", "w.rs", b"w", vec![], 1);
    assert_eq!(
        s.ingest_changeset(env, &blobs).unwrap_err().code,
        RefusalCode::QuotaPayloadTooLarge
    );
    assert_eq!(s.committed_seq(), WalSeq::ZERO);
    assert_eq!(fs::read(dir.join("wal.log")).unwrap_or_default().len(), 0);
    drop(s);

    // Replay: a frame declaring more than the cap is refused under both policies (never
    // truncated away as a torn tail) before its payload is read.
    let dir = temp_store_dir("a1-cap-replay");
    {
        let mut s = SynapseStore::open(
            &dir,
            FsyncPolicy::EveryCommit,
            STRICT,
            StoreLimits::default(),
        )
        .unwrap();
        let (env, blobs) = make_signed_changeset(&key, "r", "r.rs", b"r", vec![], 1);
        s.ingest_changeset(env, &blobs).unwrap();
    }
    for policy in [STRICT, RecoveryPolicy::TruncateTornTail] {
        let r = SynapseStore::open(&dir, FsyncPolicy::EveryCommit, policy, small.clone());
        assert_eq!(
            r.err().map(|e| e.code),
            Some(RefusalCode::QuotaPayloadTooLarge)
        );
    }
    // The same log opens under the default cap.
    assert!(SynapseStore::open(
        &dir,
        FsyncPolicy::EveryCommit,
        STRICT,
        StoreLimits::default()
    )
    .is_ok());
}

#[test]
fn a1_record_prepared_before_the_migration_commits_in_the_new_codec() {
    // Group commit prepares records outside the store lock; the migration checkpoint can
    // land between prepare and commit. The record must then be written as binary v2 with
    // its inline blob still readable after reopen.
    let limits = StoreLimits {
        wal_prealloc_bytes: 64 * 1024,
        ..Default::default()
    };
    let policy = FsyncPolicy::GROUP_COMMIT_DEFAULT;
    let dir = copy_fixture("v1-wal-v2-log");
    let mut s = SynapseStore::open(&dir, policy, STRICT, limits.clone()).unwrap();
    assert_eq!(s.record_codec(), RecordCodec::JsonV1);
    let key = SigningKey::from_bytes(&[0x5E; 32]);
    let content = b"prepared before the migration checkpoint";
    let (env, blobs) = make_signed_changeset(&key, "late", "late.rs", content, vec![], 9);
    let digest = blobs[0].0;
    let prepared =
        SynapseStore::prepare_ingest(&limits, env, &blobs, Some(RecordCodec::JsonV1)).unwrap();
    s.checkpoint_and_compact(10).unwrap();
    assert_eq!(s.record_codec(), RecordCodec::BinaryV2);
    let IngestOutcome::Committed { wal_seq, .. } = s.ingest_prepared(prepared).unwrap() else {
        panic!("expected a commit");
    };
    assert_eq!(v2_flags(&dir), vec![WAL_FLAG_CODEC_V2]);
    assert_eq!(
        s.get_blob_visible(digest, None, None).unwrap(),
        content.to_vec()
    );
    let root = s.state_root_digest(None).unwrap();
    drop(s);
    let s = SynapseStore::open(&dir, policy, STRICT, limits).unwrap();
    assert_eq!(s.committed_seq(), wal_seq);
    assert_eq!(s.state_root_digest(None).unwrap(), root);
    assert_eq!(
        s.get_blob_visible(digest, None, None).unwrap(),
        content.to_vec()
    );
}
