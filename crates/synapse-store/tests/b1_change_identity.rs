//! ADR 0003 step B1 acceptance tests (issue #27): change identity bound to its creating
//! chain, admission witnesses, obsolescence markers, envelope v2 with a native base, and v1
//! identities unchanged. Chains here are plain link-digest paths; `synapse-api` tests the
//! same rules with real signed F1 capability chains.

use ed25519_dalek::SigningKey;
use std::path::{Path, PathBuf};
use synapse_core::{
    encode_did_key_ed25519, BlobDigest, ChainPath, ChangeId, ChangesetEnvelope,
    ChangesetEnvelopeV2, ChangesetId, FileMode, GitOid, IdempotencyKey, MutationOp,
    ObsolescenceMarker, PathMutation, RefusalCode, RepoId, RevisionContent, RevisionState,
    TreeDigest, WalSeq,
};
use synapse_store::codec::{decode_record, encode_record};
use synapse_store::{
    AdmissionAuthority, FsyncPolicy, IngestOutcome, RecordCodec, RecoveryPolicy, RevisionOutcome,
    StoreLimits, SynapseStore, WalRecord,
};

const STRICT: RecoveryPolicy = RecoveryPolicy::StrictFailClosed;
const CHANGE: ChangeId = ChangeId([0xC1; 16]);

fn temp_dir(name: &str) -> PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir =
        std::env::temp_dir().join(format!("synapse-b1-{name}-{}-{nanos}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn limits() -> StoreLimits {
    StoreLimits {
        wal_prealloc_bytes: 64 * 1024,
        ..Default::default()
    }
}

fn open(dir: &Path, policy: FsyncPolicy) -> SynapseStore {
    SynapseStore::open(dir, policy, STRICT, limits()).unwrap()
}

fn repo() -> RepoId {
    RepoId::new("aien-spark/synapse").unwrap()
}

/// The delegation tree of these tests: root authority `R`, orchestrator `O` under it,
/// workers `W1` and `W2` under `O`, and an outsider `X` under `R` beside `O`.
struct Chains {
    r: ChainPath,
    o: ChainPath,
    w1: ChainPath,
    w2: ChainPath,
    x: ChainPath,
}

fn chains() -> Chains {
    let p = |v: &[u8]| ChainPath::new(v.iter().map(|b| [*b; 32]).collect()).unwrap();
    Chains {
        r: p(&[1]),
        o: p(&[1, 2]),
        w1: p(&[1, 2, 3]),
        w2: p(&[1, 2, 4]),
        x: p(&[1, 9]),
    }
}

fn key(n: u8) -> SigningKey {
    SigningKey::from_bytes(&[n; 32])
}

fn auth(chain: &ChainPath) -> AdmissionAuthority {
    AdmissionAuthority {
        chain: chain.clone(),
        change_scope: Vec::new(),
    }
}

/// A revision of `CHANGE` writing `body` to `src/lib.rs`, with its blob.
fn revision(
    author: &SigningKey,
    body: &[u8],
    idem: u8,
    parents: Vec<ChangesetId>,
) -> (ChangesetEnvelopeV2, Vec<(BlobDigest, Vec<u8>)>) {
    let digest = BlobDigest::compute(body);
    let content = RevisionContent {
        change_id: CHANGE,
        base_tree: TreeDigest([0x7E; 32]),
        parents,
        mutations: vec![PathMutation {
            path: "src/lib.rs".into(),
            op: MutationOp::Upsert {
                mode: FileMode::Regular644,
                blob_digest: digest,
                size_bytes: body.len() as u64,
            },
        }],
        intent_summary: "implement the task".into(),
    };
    let env =
        ChangesetEnvelopeV2::sign_new(author, repo(), content, IdempotencyKey([idem; 32]), 1_000);
    (env, vec![(digest, body.to_vec())])
}

fn admitted(outcome: RevisionOutcome) -> (WalSeq, ChangesetId) {
    match outcome {
        RevisionOutcome::Admitted {
            wal_seq,
            changeset_id,
            ..
        } => (wal_seq, changeset_id),
        other => panic!("expected an admission, got {other:?}"),
    }
}

fn admit(
    s: &mut SynapseStore,
    author: &SigningKey,
    chain: &ChainPath,
    body: &[u8],
    idem: u8,
) -> ChangesetId {
    let (env, blobs) = revision(author, body, idem, vec![]);
    admitted(s.admit_revision(env, &blobs, auth(chain), 5_000).unwrap()).1
}

fn marker(signer: &SigningKey, pred: ChangesetId, succ: Vec<ChangesetId>) -> ObsolescenceMarker {
    ObsolescenceMarker::sign_new(signer, repo(), CHANGE, pred, succ, 6_000)
}

#[test]
fn b1_rewrite_keeps_change_id_and_gets_new_changeset_id() {
    let c = chains();
    let dir = temp_dir("rewrite");
    let mut s = open(&dir, FsyncPolicy::EveryCommit);
    let a = admit(&mut s, &key(2), &c.o, b"fn a() {}", 1);
    let a2 = admit(&mut s, &key(2), &c.o, b"fn a() { /* rewritten */ }", 2);
    assert_ne!(a, a2, "a rewrite gets a new ChangesetId");
    let rev = s.get_revision(&repo(), a2).unwrap();
    assert_eq!(rev.content.change_id, CHANGE, "and keeps its ChangeId");
    assert_eq!(
        s.get_revision(&repo(), a).unwrap().content.change_id,
        CHANGE
    );
    s.record_obsolescence(marker(&key(2), a, vec![a2]), c.o.clone(), 6_000)
        .unwrap();
    let st = s.change_status(&repo(), CHANGE).unwrap();
    assert_eq!(st.revisions, vec![a, a2]);
    assert_eq!(st.live, vec![a2]);
    assert_eq!(st.obsolete, vec![a]);
    assert!(!st.divergent);
    assert_eq!(st.creating_chain, c.o);
}

#[test]
fn b1_divergence_two_live_successors_is_detected() {
    let c = chains();
    let dir = temp_dir("diverge");
    let mut s = open(&dir, FsyncPolicy::EveryCommit);
    let a = admit(&mut s, &key(2), &c.o, b"attempt 0", 1);
    let b1 = admit(&mut s, &key(3), &c.w1, b"attempt 1", 1);
    let b2 = admit(&mut s, &key(4), &c.w2, b"attempt 2", 1);
    s.record_obsolescence(marker(&key(2), a, vec![b1]), c.o.clone(), 6_000)
        .unwrap();
    s.record_obsolescence(marker(&key(2), a, vec![b2]), c.o.clone(), 6_001)
        .unwrap();
    let st = s.change_status(&repo(), CHANGE).unwrap();
    assert_eq!(st.obsolete, vec![a]);
    assert_eq!(
        st.live,
        vec![b1, b2],
        "two live successors of one predecessor"
    );
    assert!(st.divergent, "divergence is detected");
    // Selecting one attempt prunes the other: no longer divergent.
    s.record_obsolescence(marker(&key(2), b2, vec![]), c.o.clone(), 6_002)
        .unwrap();
    let st = s.change_status(&repo(), CHANGE).unwrap();
    assert_eq!(st.live, vec![b1]);
    assert!(!st.divergent);
    // Divergence survives a reopen (replay) unchanged.
    drop(s);
    let s = open(&dir, FsyncPolicy::EveryCommit);
    assert_eq!(s.change_status(&repo(), CHANGE).unwrap(), st);
}

fn identical_content_case(policy: FsyncPolicy, name: &str) {
    let c = chains();
    let dir = temp_dir(name);
    let mut s = open(&dir, policy);
    let (env_o, blobs) = revision(&key(2), b"same bytes", 1, vec![]);
    let (env_w, _) = revision(&key(3), b"same bytes", 7, vec![]);
    let (s1, id) = admitted(s.admit_revision(env_o, &blobs, auth(&c.o), 5_000).unwrap());
    // The second agent provides no blob: it is already visible.
    let out = s.admit_revision(env_w, &[], auth(&c.w1), 5_001).unwrap();
    let RevisionOutcome::Admitted {
        wal_seq: s2,
        changeset_id: id2,
        joined_existing_revision: true,
    } = out
    else {
        panic!("expected a join of the existing revision, got {out:?}");
    };
    assert_eq!(id, id2, "identical content is one revision");
    let rev = s.get_revision(&repo(), id).unwrap();
    assert_eq!(rev.attestations.len(), 2, "two attestations");
    assert_eq!(rev.witnesses.len(), 2, "two admission witnesses");
    assert_eq!(
        rev.attestations[0].author_key,
        key(2).verifying_key().to_bytes()
    );
    assert_eq!(
        rev.attestations[1].author_key,
        key(3).verifying_key().to_bytes()
    );
    assert_eq!(
        (
            rev.witnesses[0].admission_seq,
            rev.witnesses[1].admission_seq
        ),
        (s1, s2)
    );
    assert_eq!(
        (
            rev.witnesses[0].chain.clone(),
            rev.witnesses[1].chain.clone()
        ),
        (c.o.clone(), c.w1)
    );
    assert_eq!(
        rev.witnesses[1].admitted_at_ms, 5_001,
        "server time, not the agent's"
    );
    assert_ne!(rev.witnesses[0].digest(), rev.witnesses[1].digest());
    assert_eq!(
        s.change_status(&repo(), CHANGE).unwrap().revisions,
        vec![id]
    );
    let root = s.state_root_digest(None).unwrap();
    // Replay, then a checkpoint, then a reopen from the checkpoint rebuild the same ledger.
    drop(s);
    let mut s = open(&dir, policy);
    assert_eq!(s.get_revision(&repo(), id).unwrap(), rev);
    assert_eq!(s.state_root_digest(None).unwrap(), root);
    s.checkpoint_and_compact(9_000).unwrap();
    drop(s);
    let s = open(&dir, policy);
    assert_eq!(s.get_revision(&repo(), id).unwrap(), rev);
    assert_eq!(s.state_root_digest(None).unwrap(), root);
    assert_eq!(
        s.get_blob_visible(BlobDigest::compute(b"same bytes"), None, None)
            .unwrap(),
        b"same bytes"
    );
}

#[test]
fn b1_identical_content_two_agents_one_chain_one_change_is_one_revision_two_attestations_two_witnesses(
) {
    identical_content_case(FsyncPolicy::EveryCommit, "identical-wal-log");
    identical_content_case(FsyncPolicy::GROUP_COMMIT_DEFAULT, "identical-segments");
}

#[test]
fn b1_join_from_key_outside_creating_chain_without_change_scope_is_refused() {
    let c = chains();
    let dir = temp_dir("join");
    let mut s = open(&dir, FsyncPolicy::EveryCommit);
    admit(&mut s, &key(2), &c.o, b"created by the orchestrator", 1);
    let before = s.committed_seq();
    let (env, blobs) = revision(&key(9), b"outsider attempt", 1, vec![]);
    let err = s
        .admit_revision(env.clone(), &blobs, auth(&c.x), 5_000)
        .unwrap_err();
    assert_eq!(err.code, RefusalCode::AuthChangeOutOfScope);
    // A scope naming another change, or the root's parent chain, is not enough either.
    let other = AdmissionAuthority {
        chain: c.x.clone(),
        change_scope: vec![ChangeId([0xEE; 16])],
    };
    assert_eq!(
        s.admit_revision(env.clone(), &blobs, other, 5_000)
            .unwrap_err()
            .code,
        RefusalCode::AuthChangeOutOfScope
    );
    assert_eq!(
        s.admit_revision(env.clone(), &blobs, auth(&c.r), 5_000)
            .unwrap_err()
            .code,
        RefusalCode::AuthChangeOutOfScope,
        "an ancestor chain does not descend from the creating chain"
    );
    assert_eq!(s.committed_seq(), before, "nothing written on refusal");
    // The same key with a grant naming the change in its change scope may join.
    let scoped = AdmissionAuthority {
        chain: c.x.clone(),
        change_scope: vec![CHANGE],
    };
    admitted(s.admit_revision(env, &blobs, scoped, 5_000).unwrap());
    // A worker whose chain descends from the creating chain joins without any scope.
    admit(&mut s, &key(3), &c.w1, b"worker attempt", 1);
}

#[test]
fn b1_prune_by_chain_not_dominating_creating_chain_is_refused() {
    let c = chains();
    let dir = temp_dir("prune");
    let mut s = open(&dir, FsyncPolicy::EveryCommit);
    let a = admit(&mut s, &key(2), &c.o, b"orchestrator attempt", 1);
    let b = admit(&mut s, &key(3), &c.w1, b"worker attempt", 1);
    // The owner shares it (ADR 0003 B4), so the other chains see it and are refused for
    // dominance rather than as an unknown revision.
    s.advance_revision_state(&repo(), a, RevisionState::Draft, c.o.clone(), 5_500)
        .unwrap();
    let before = s.committed_seq();
    for (signer, chain) in [(key(3), &c.w1), (key(9), &c.x), (key(4), &c.w2)] {
        let err = s
            .record_obsolescence(marker(&signer, a, vec![]), chain.clone(), 6_000)
            .unwrap_err();
        assert_eq!(err.code, RefusalCode::AuthChainNotDominant, "{chain:?}");
    }
    assert_eq!(s.committed_seq(), before, "nothing written on refusal");
    // A worker may rewrite its own attempt (it dominates that revision's first admission)
    // but not prune it, and not rewrite the orchestrator's.
    let b2 = admit(&mut s, &key(3), &c.w1, b"worker attempt, rewritten", 2);
    s.record_obsolescence(marker(&key(3), b, vec![b2]), c.w1.clone(), 6_000)
        .unwrap();
    assert_eq!(
        s.record_obsolescence(marker(&key(3), b2, vec![]), c.w1.clone(), 6_000)
            .unwrap_err()
            .code,
        RefusalCode::AuthChainNotDominant
    );
    assert_eq!(
        s.record_obsolescence(marker(&key(3), a, vec![b2]), c.w1.clone(), 6_000)
            .unwrap_err()
            .code,
        RefusalCode::AuthChainNotDominant
    );
    // The creating chain and a chain that dominates it may prune.
    s.record_obsolescence(marker(&key(2), b2, vec![]), c.o.clone(), 6_001)
        .unwrap();
    s.record_obsolescence(marker(&key(1), a, vec![]), c.r.clone(), 6_002)
        .unwrap();
    let st = s.change_status(&repo(), CHANGE).unwrap();
    assert!(st.live.is_empty());
    // Markers that would close a cycle are refused.
    assert_eq!(
        s.record_obsolescence(marker(&key(2), b2, vec![b]), c.o.clone(), 6_003)
            .unwrap_err()
            .code,
        RefusalCode::ObsolescenceMarkerInvalid
    );
}

#[test]
fn b1_repeat_same_repo_did_idempotency_key_returns_first_wal_seq() {
    let c = chains();
    let dir = temp_dir("idem");
    let mut s = open(&dir, FsyncPolicy::EveryCommit);
    let (env, blobs) = revision(&key(2), b"first", 5, vec![]);
    let (first, id) = admitted(
        s.admit_revision(env.clone(), &blobs, auth(&c.o), 5_000)
            .unwrap(),
    );
    admit(&mut s, &key(3), &c.w1, b"something else", 1);
    let dup = RevisionOutcome::IdempotentDuplicate {
        wal_seq: first,
        changeset_id: id,
    };
    let before = s.committed_seq();
    assert_eq!(
        s.admit_revision(env.clone(), &blobs, auth(&c.o), 7_000)
            .unwrap(),
        dup
    );
    assert_eq!(s.committed_seq(), before, "a repeat writes nothing");
    // The same key bound to other content is a conflict.
    let (other, other_blobs) = revision(&key(2), b"second", 5, vec![]);
    assert_eq!(
        s.admit_revision(other, &other_blobs, auth(&c.o), 7_000)
            .unwrap_err()
            .code,
        RefusalCode::IdempotencyKeyConflict
    );
    // Another DID with the same key and content is its own admission.
    let (env_w, _) = revision(&key(3), b"first", 5, vec![]);
    let (seq_w, id_w) = admitted(s.admit_revision(env_w, &[], auth(&c.w1), 7_000).unwrap());
    assert_eq!(id_w, id);
    assert_ne!(seq_w, first);
    // Still the first WalSeq after replay and after a checkpoint.
    drop(s);
    let mut s = open(&dir, FsyncPolicy::EveryCommit);
    assert_eq!(
        s.admit_revision(env.clone(), &blobs, auth(&c.o), 8_000)
            .unwrap(),
        dup
    );
    s.checkpoint_and_compact(9_000).unwrap();
    drop(s);
    let mut s = open(&dir, FsyncPolicy::EveryCommit);
    assert_eq!(
        s.admit_revision(env, &blobs, auth(&c.o), 9_000).unwrap(),
        dup
    );
}

fn fixture(name: &str) -> PathBuf {
    let src = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/a1-v1")
        .join(name);
    let dst = temp_dir(&format!("v1-{name}"));
    copy_tree(&src, &dst);
    let _ = std::fs::remove_file(dst.join("EXPECT"));
    dst
}

fn copy_tree(src: &Path, dst: &Path) {
    std::fs::create_dir_all(dst).unwrap();
    for e in std::fs::read_dir(src).unwrap() {
        let e = e.unwrap();
        let to = dst.join(e.file_name());
        if e.file_type().unwrap().is_dir() {
            copy_tree(&e.path(), &to);
        } else {
            std::fs::copy(e.path(), &to).unwrap();
        }
    }
}

/// Every v1 changeset of `s` resolves to its record, whose envelope still hashes to it.
fn assert_v1_ids_resolve(s: &SynapseStore, ids: &[ChangesetId]) {
    for id in ids {
        let cs = s.get_changeset(*id, None, None).unwrap();
        assert_eq!(cs.changeset_id, *id);
        assert_eq!(cs.envelope.compute_id(), *id, "v1 identity unchanged");
    }
}

fn v1_case(name: &str, policy: FsyncPolicy) {
    let c = chains();
    let dir = fixture(name);
    let mut s = open(&dir, policy);
    assert_eq!(s.record_codec(), RecordCodec::JsonV1);
    let ids: Vec<ChangesetId> = s
        .list_changesets(None, None, None)
        .unwrap()
        .iter()
        .map(|cs| cs.changeset_id)
        .collect();
    assert!(!ids.is_empty(), "{name}: the fixture holds v1 changesets");
    assert_v1_ids_resolve(&s, &ids);
    // Envelope v2 needs the binary codec: refused before the migration checkpoint.
    let (env, blobs) = revision(&key(2), b"v2 on v1 history", 1, vec![ids[0]]);
    assert_eq!(
        s.admit_revision(env.clone(), &blobs, auth(&c.o), 0)
            .unwrap_err()
            .code,
        RefusalCode::EnvelopeVersionUnsupported
    );
    s.checkpoint_and_compact(0).unwrap();
    assert_v1_ids_resolve(&s, &ids);
    // A v2 revision on top of a v1 parent; its id is in its own domain.
    let (_, v2) = admitted(s.admit_revision(env, &blobs, auth(&c.o), 0).unwrap());
    assert!(!ids.contains(&v2));
    assert!(
        s.get_changeset(v2, None, None).is_err(),
        "v2 ids are not v1 records"
    );
    assert_v1_ids_resolve(&s, &ids);
    drop(s);
    let mut s = open(&dir, policy);
    assert_v1_ids_resolve(&s, &ids);
    // Compaction keeps the v1 parent of a revision even outside the retention window.
    s.checkpoint_and_compact(u64::MAX).unwrap();
    drop(s);
    let s = open(&dir, policy);
    assert_v1_ids_resolve(&s, &[ids[0]]);
    assert_eq!(
        s.get_revision(&repo(), v2).unwrap().content.parents,
        vec![ids[0]]
    );
}

/// A v1 changeset far outside the retention window, with no other root, stays because a
/// revision names it as parent; without that root compaction evicts it.
fn v1_parent_outside_retention_case(policy: FsyncPolicy, name: &str) {
    let c = chains();
    let dir = temp_dir(name);
    let mut s = open(&dir, policy);
    let author = key(2);
    let mut v1 = |body: &[u8], idem: u8| {
        let mut env = ChangesetEnvelope {
            version: 1,
            repo_id: repo(),
            base_git_oid: GitOid([0x0B; 20]),
            parent_changesets: vec![],
            author_did: encode_did_key_ed25519(&author.verifying_key().to_bytes()),
            idempotency_key: IdempotencyKey([idem; 32]),
            created_at_ms: 1,
            intent_summary: "v1 work".into(),
            mutations: vec![PathMutation {
                path: "src/v1.rs".into(),
                op: MutationOp::Upsert {
                    mode: FileMode::Regular644,
                    blob_digest: BlobDigest::compute(body),
                    size_bytes: body.len() as u64,
                },
            }],
            evidence_receipts: vec![],
            signature: vec![],
        };
        env.sign(&author);
        let blobs = vec![(BlobDigest::compute(body), body.to_vec())];
        match s.ingest_changeset(env, &blobs).unwrap() {
            IngestOutcome::Committed { changeset_id, .. } => changeset_id,
            other => panic!("{other:?}"),
        }
    };
    let named = v1(b"named by a revision", 1);
    let unnamed = v1(b"named by nothing", 2);
    let (env, blobs) = revision(&key(2), b"on v1", 1, vec![named]);
    admitted(s.admit_revision(env, &blobs, auth(&c.o), 0).unwrap());
    s.checkpoint_and_compact(u64::MAX).unwrap();
    assert!(
        s.get_changeset(unnamed, None, None).is_err(),
        "control: evicted"
    );
    assert_v1_ids_resolve(&s, &[named]);
    drop(s);
    let s = open(&dir, policy);
    assert_v1_ids_resolve(&s, &[named]);
    assert_eq!(
        s.get_blob_visible(BlobDigest::compute(b"named by a revision"), None, None)
            .unwrap(),
        b"named by a revision"
    );
}

#[test]
fn b1_every_v1_changeset_id_still_resolves_to_its_record() {
    v1_parent_outside_retention_case(FsyncPolicy::EveryCommit, "v1-parent-wal-log");
    v1_parent_outside_retention_case(FsyncPolicy::GROUP_COMMIT_DEFAULT, "v1-parent-segments");
    v1_case("v1-wal-log", FsyncPolicy::EveryCommit);
    v1_case("v1-wal-v2-log", FsyncPolicy::GROUP_COMMIT_DEFAULT);
}

#[test]
fn b1_revision_records_round_trip_and_malformed_bytes_are_refused_typed() {
    let c = chains();
    let (env, _) = revision(&key(2), b"x", 1, vec![]);
    let records = [
        WalRecord::RevisionAdmitted {
            envelope: env.clone(),
            chain: c.w1.clone(),
            admitted_at_ms: 5,
            new_blobs: vec![BlobDigest::compute(b"x")],
        },
        WalRecord::ObsolescenceRecorded {
            marker: marker(&key(2), env.changeset_id(), vec![ChangesetId([3; 32])]),
            chain: c.o.clone(),
            recorded_at_ms: 6,
        },
    ];
    for record in records {
        let bytes = encode_record(&record).unwrap();
        assert_eq!(decode_record(&bytes, 1 << 20).unwrap(), record);
        for cut in 0..bytes.len() {
            assert!(decode_record(&bytes[..cut], 1 << 20).is_err(), "cut {cut}");
        }
        let mut longer = bytes.clone();
        longer.push(0);
        assert!(decode_record(&longer, 1 << 20).is_err());
        // Flip each byte of the embedded value: refused or decodes to a different record,
        // never a panic.
        for i in 2..bytes.len() {
            let mut b = bytes.clone();
            b[i] ^= 0x41;
            if let Ok(r) = decode_record(&b, 1 << 20) {
                assert_ne!(r, record);
            }
        }
        // No v1 JSON form.
        assert!(serde_json::to_vec(&record).is_err());
    }
}
