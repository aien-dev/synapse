//! ADR 0003 step B4 acceptance tests (issue #28): the revision state machine (`Private`,
//! `Draft`, `Proposed`, `Verified`, `Canonical`). Over random operation sequences no revision
//! moves backwards; a `Private` revision is invisible to every key outside its owner chain;
//! any move to `Canonical` outside the promotion queue is refused. Chains here are digests of
//! real F1 links from the shared fixture (`common`), and every state move carries its leaf
//! link and the leaf key's signature (issue #89).
//!
//! The property tests use a seeded SplitMix64 generator (no new dependency, as in F1); the
//! seed and case counts are fixed so every run checks the same sequences.

use ed25519_dalek::SigningKey;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use synapse_core::{
    BlobDigest, ChainPath, ChangeId, ChangesetEnvelopeV2, ChangesetId, FileMode, IdempotencyKey,
    MutationOp, ObsolescenceMarker, PathMutation, RefusalCode, RevisionContent, RevisionState,
    TreeDigest,
};
mod common;
use common::{key_of, mv, path, repo, signed};
use synapse_store::codec::{decode_record, encode_record};
use synapse_store::{
    AdmissionAuthority, FsyncPolicy, RecoveryPolicy, RevisionOutcome, StoreLimits, SynapseStore,
    WalRecord,
};

const STRICT: RecoveryPolicy = RecoveryPolicy::StrictFailClosed;
const CHANGE: ChangeId = ChangeId([0xC4; 16]);

struct SplitMix64(u64);

impl SplitMix64 {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }
}

fn temp_dir(name: &str) -> PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir =
        std::env::temp_dir().join(format!("synapse-b4-{name}-{}-{nanos}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn open(dir: &Path, policy: FsyncPolicy) -> SynapseStore {
    let limits = StoreLimits {
        wal_prealloc_bytes: 64 * 1024,
        ..Default::default()
    };
    SynapseStore::open(dir, policy, STRICT, limits).unwrap()
}

/// The delegation tree: root `R` = [1]; orchestrator `O` = [1,2] under it; workers
/// `W1` = [1,2,3] and `W2` = [1,2,4] under `O`; `W1s` = [1,2,3,5], a sub-delegate of `W1`;
/// outsider `X` = [1,9] beside `O`. Each chain presents its own key.
const TREE: [&[u8]; 6] = [
    &[1],
    &[1, 2],
    &[1, 2, 3],
    &[1, 2, 4],
    &[1, 2, 3, 5],
    &[1, 9],
];

fn auth(chain: &ChainPath) -> AdmissionAuthority {
    AdmissionAuthority {
        chain: chain.clone(),
        change_scope: Vec::new(),
    }
}

/// A revision of `change` writing `body` to `src/lib.rs`, with its blob.
fn revision(
    author: &SigningKey,
    change: ChangeId,
    body: &[u8],
    idem: [u8; 32],
    parents: Vec<ChangesetId>,
) -> (ChangesetEnvelopeV2, Vec<(BlobDigest, Vec<u8>)>) {
    let digest = BlobDigest::compute(body);
    let content = RevisionContent {
        change_id: change,
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
    let env = ChangesetEnvelopeV2::sign_new(author, repo(), content, IdempotencyKey(idem), 1_000);
    (env, vec![(digest, body.to_vec())])
}

fn admit(s: &mut SynapseStore, links: &[u8], body: &[u8], idem: u8) -> ChangesetId {
    let (env, blobs) = revision(&key_of(links), CHANGE, body, [idem; 32], vec![]);
    match s
        .admit_revision(env, &blobs, auth(&path(links)), 5_000)
        .unwrap()
    {
        RevisionOutcome::Admitted { changeset_id, .. } => changeset_id,
        other => panic!("expected an admission, got {other:?}"),
    }
}

fn state(s: &SynapseStore, id: ChangesetId) -> RevisionState {
    s.get_revision(&repo(), id).unwrap().state
}

/// The model the store must agree with: owner moves along the edges of section 5.3 only.
fn model_move(
    current: RevisionState,
    to: RevisionState,
    owner: bool,
    visible: bool,
) -> Result<RevisionState, RefusalCode> {
    if to == RevisionState::Canonical {
        return Err(RefusalCode::CanonicalOutsidePromotionQueue);
    }
    if !visible {
        return Err(RefusalCode::ChangesetNotFound);
    }
    if !owner {
        return Err(RefusalCode::AuthChainNotDominant);
    }
    let edge = matches!(
        (current, to),
        (RevisionState::Private, RevisionState::Draft)
            | (RevisionState::Private, RevisionState::Proposed)
            | (RevisionState::Draft, RevisionState::Proposed)
    );
    if edge {
        Ok(to)
    } else {
        Err(RefusalCode::RevisionStateMoveInvalid)
    }
}

/// Property (acceptance 1): over random operation sequences (admissions by random chains,
/// moves of random revisions to random states by random chains, reopen with replay, and
/// checkpoint with compaction), no revision ever moves backwards, none reaches `Verified` or
/// `Canonical`, every outcome equals the model's, and a refused move writes nothing.
#[test]
fn b4_property_random_operation_sequences_never_move_a_revision_backwards() {
    let mut rng = SplitMix64(0xB4_0001);
    let mut moves_applied = 0u32;
    let mut refusals = BTreeMap::<String, u32>::new();
    for case in 0..12 {
        let policy = if case % 2 == 0 {
            FsyncPolicy::EveryCommit
        } else {
            FsyncPolicy::GROUP_COMMIT_DEFAULT
        };
        let dir = temp_dir(&format!("property-{case}"));
        let mut s = open(&dir, policy);
        // Every revision: (id, change, body, admission chains (the first owns it), last state).
        let mut known: Vec<(ChangesetId, ChangeId, String, Vec<ChainPath>, RevisionState)> =
            Vec::new();
        let mut idem = 0u32;
        for _op in 0..40 {
            idem += 1;
            let mut idem_key = [0u8; 32];
            idem_key[..4].copy_from_slice(&idem.to_le_bytes());
            match rng.below(10) {
                // Admit a revision under a fresh change (no join rule in play) from a random
                // chain, or identical content of a known revision from another chain whose
                // grant names that change (one revision, one more witness, no new owner).
                0..=2 => {
                    let links = TREE[rng.below(TREE.len() as u64) as usize];
                    let rejoin = !known.is_empty() && rng.below(3) == 0;
                    let (change, body) = if rejoin {
                        let k = &known[rng.below(known.len() as u64) as usize];
                        (k.1, k.2.clone())
                    } else {
                        (
                            ChangeId([(idem % 251) as u8; 16]),
                            format!("revision {idem}"),
                        )
                    };
                    let (env, blobs) =
                        revision(&key_of(links), change, body.as_bytes(), idem_key, vec![]);
                    let id = env.changeset_id();
                    let authority = AdmissionAuthority {
                        chain: path(links),
                        change_scope: vec![change],
                    };
                    let out = s.admit_revision(env, &blobs, authority, 5_000).unwrap();
                    assert!(matches!(out, RevisionOutcome::Admitted { .. }));
                    match known.iter_mut().find(|k| k.0 == id) {
                        Some(k) => k.3.push(path(links)),
                        None => {
                            assert_eq!(state(&s, id), RevisionState::Private, "starts Private");
                            known.push((
                                id,
                                change,
                                body,
                                vec![path(links)],
                                RevisionState::Private,
                            ));
                        }
                    }
                }
                // Attempt a move of a random revision (or an unknown ID) to a random state.
                3..=7 => {
                    if known.is_empty() {
                        continue;
                    }
                    let i = rng.below(known.len() as u64) as usize;
                    let unknown = rng.below(16) == 0;
                    let id = if unknown {
                        ChangesetId([0xEE; 32])
                    } else {
                        known[i].0
                    };
                    let to = RevisionState::ALL[rng.below(5) as usize];
                    let labels = TREE[rng.below(TREE.len() as u64) as usize];
                    let chain = path(labels);
                    let (cur, owners) = (known[i].4, &known[i].3);
                    let owner = !unknown && chain.dominates(&owners[0]);
                    let visible = !unknown && (cur != RevisionState::Private || owner);
                    let expected = model_move(cur, to, owner, visible);
                    let before = s.committed_seq();
                    let got = mv(&mut s, labels, id, to, 6_000).map_err(|e| e.code);
                    match (&expected, &got) {
                        (Ok(want), Ok(_)) => {
                            known[i].4 = *want;
                            moves_applied += 1;
                        }
                        (Err(want), Err(code)) => {
                            assert_eq!(want, code, "{cur:?} -> {to:?}");
                            assert_eq!(s.committed_seq(), before, "a refusal writes nothing");
                            *refusals.entry(format!("{code:?}")).or_default() += 1;
                        }
                        _ => panic!("{cur:?} -> {to:?}: model {expected:?}, store {got:?}"),
                    }
                }
                // Reopen: the ledger is rebuilt by replay.
                8 => {
                    drop(s);
                    s = open(&dir, policy);
                }
                // Checkpoint with compaction, then reopen from the checkpoint.
                _ => {
                    s.checkpoint_and_compact(9_000).unwrap();
                    drop(s);
                    s = open(&dir, policy);
                }
            }
            for (id, _, _, _, last) in &mut known {
                let now = state(&s, *id);
                assert!(
                    now.rank() >= last.rank(),
                    "revision {id} moved backwards {last:?} -> {now:?}"
                );
                assert!(
                    now <= RevisionState::Proposed,
                    "revision {id} reached {now:?}"
                );
                assert_eq!(now, *last, "store and model agree on revision {id}");
                *last = now;
            }
        }
    }
    // The sequences exercised every outcome.
    assert!(moves_applied > 0);
    for code in [
        "CanonicalOutsidePromotionQueue",
        "ChangesetNotFound",
        "AuthChainNotDominant",
        "RevisionStateMoveInvalid",
    ] {
        assert!(refusals.contains_key(code), "no {code} in {refusals:?}");
    }
}

/// Acceptance 2: a `Private` revision is invisible to every key outside its owner chain
/// (the submitting chain and the chains it descends from): not readable, not listed in its
/// change, not nameable as a parent or in a marker, not movable, also after replay and a
/// checkpoint. Checked for the fixed delegation tree and for random chains.
#[test]
fn b4_private_revision_is_invisible_to_every_key_outside_its_owner_chain() {
    let dir = temp_dir("private");
    let mut s = open(&dir, FsyncPolicy::EveryCommit);
    let w1: &[u8] = &[1, 2, 3];
    let o: &[u8] = &[1, 2];
    // O creates the change (Draft, so the change itself is visible); W1 adds a Private one.
    let shared = admit(&mut s, o, b"orchestrator draft", 1);
    mv(&mut s, o, shared, RevisionState::Draft, 5_100).unwrap();
    let p = admit(&mut s, w1, b"worker private attempt", 1);
    assert_eq!(state(&s, p), RevisionState::Private);
    let unknown = ChangesetId([0xEE; 32]);
    let not_found = s
        .get_revision_visible_to(&repo(), unknown, &path(o))
        .unwrap_err();

    let check = |s: &mut SynapseStore, labels: &[u8]| {
        let viewer = &path(labels);
        let owner = viewer.dominates(&path(w1));
        let read = s.get_revision_visible_to(&repo(), p, viewer);
        let listed = s
            .change_status_visible_to(&repo(), CHANGE, viewer)
            .map(|st| st.revisions.contains(&p))
            .unwrap_or(false);
        if owner {
            assert_eq!(read.unwrap().changeset_id, p, "{viewer:?} owns it");
            assert!(listed, "{viewer:?} owns it");
            return;
        }
        // Refused exactly like an unknown revision: same code, same message shape.
        let err = read.unwrap_err();
        assert_eq!(err.code, not_found.code, "{viewer:?}");
        assert_eq!(
            err.message,
            not_found
                .message
                .replace(&unknown.to_string(), &p.to_string())
        );
        assert!(!listed, "{viewer:?} must not see it in the change");
        let before = s.committed_seq();
        let signer = key_of(labels);
        // Not nameable as a parent.
        let (env, blobs) = revision(
            &signer,
            ChangeId([0x77; 16]),
            b"child",
            common::derived("idempotency", labels),
            vec![p],
        );
        assert_eq!(
            s.admit_revision(env, &blobs, auth(viewer), 5_200)
                .unwrap_err()
                .code,
            RefusalCode::ParentChangesetNotFound,
            "{viewer:?}"
        );
        // Not nameable in a marker, as predecessor or successor.
        for (pred, succ) in [(p, vec![]), (shared, vec![p])] {
            let m = ObsolescenceMarker::sign_new(&signer, repo(), CHANGE, pred, succ, 6_000);
            assert_eq!(
                s.record_obsolescence(m, viewer.clone(), 6_000)
                    .unwrap_err()
                    .code,
                RefusalCode::ChangesetNotFound,
                "{viewer:?}"
            );
        }
        // Not movable.
        assert_eq!(
            mv(s, labels, p, RevisionState::Draft, 6_000)
                .unwrap_err()
                .code,
            RefusalCode::ChangesetNotFound,
            "{viewer:?}"
        );
        assert_eq!(s.committed_seq(), before, "nothing written");
    };

    // The fixed tree: R, O, W1 own it; W2, the sub-delegate W1s, and X do not.
    for links in TREE {
        check(&mut s, links);
    }
    // Random chains over the same link alphabet.
    let mut rng = SplitMix64(0xB4_0002);
    for _ in 0..200 {
        let len = 1 + rng.below(4) as usize;
        let links: Vec<u8> = (0..len)
            .map(|_| [1u8, 2, 3, 4, 5, 9][rng.below(6) as usize])
            .collect();
        check(&mut s, &links);
    }
    // The same after replay and after a checkpoint.
    drop(s);
    let mut s = open(&dir, FsyncPolicy::EveryCommit);
    for links in TREE {
        check(&mut s, links);
    }
    s.checkpoint_and_compact(9_000).unwrap();
    drop(s);
    let mut s = open(&dir, FsyncPolicy::EveryCommit);
    for links in TREE {
        check(&mut s, links);
    }
    // Once its owner moves it to Draft, it is visible to every chain.
    mv(&mut s, w1, p, RevisionState::Draft, 9_100).unwrap();
    for links in TREE {
        let viewer = path(links);
        assert_eq!(
            s.get_revision_visible_to(&repo(), p, &viewer)
                .unwrap()
                .state,
            RevisionState::Draft
        );
        let st = s
            .change_status_visible_to(&repo(), CHANGE, &viewer)
            .unwrap();
        assert_eq!(st.revisions, vec![shared, p]);
    }
}

/// Acceptance 3: any move to `Canonical` outside the promotion queue is refused, from every
/// state, by every chain (owner, root, outsider), for known and unknown revisions, and
/// nothing is written. The owner chain cannot assert `Verified` either.
#[test]
fn b4_any_move_to_canonical_outside_the_promotion_queue_is_refused() {
    let dir = temp_dir("canonical");
    let mut s = open(&dir, FsyncPolicy::EveryCommit);
    let w1: &[u8] = &[1, 2, 3];
    let private = admit(&mut s, w1, b"private", 1);
    let draft = admit(&mut s, w1, b"draft", 2);
    let proposed = admit(&mut s, w1, b"proposed", 3);
    mv(&mut s, w1, draft, RevisionState::Draft, 5_100).unwrap();
    mv(&mut s, w1, proposed, RevisionState::Proposed, 5_101).unwrap();
    let before = s.committed_seq();
    for id in [private, draft, proposed, ChangesetId([0xEE; 32])] {
        for links in TREE {
            let err = mv(&mut s, links, id, RevisionState::Canonical, 6_000).unwrap_err();
            assert_eq!(err.code, RefusalCode::CanonicalOutsidePromotionQueue);
        }
    }
    for id in [private, draft, proposed] {
        assert_eq!(
            mv(&mut s, w1, id, RevisionState::Verified, 6_000)
                .unwrap_err()
                .code,
            RefusalCode::RevisionStateMoveInvalid
        );
    }
    assert_eq!(s.committed_seq(), before, "nothing written");
    assert_eq!(state(&s, private), RevisionState::Private);
    assert_eq!(state(&s, draft), RevisionState::Draft);
    assert_eq!(state(&s, proposed), RevisionState::Proposed);
    // Backwards and in place are refused too.
    for to in [
        RevisionState::Private,
        RevisionState::Draft,
        RevisionState::Proposed,
    ] {
        assert_eq!(
            mv(&mut s, w1, proposed, to, 6_000).unwrap_err().code,
            RefusalCode::RevisionStateMoveInvalid
        );
    }
}

/// Acceptance 2, joins: a chain outside the owner chain that submits byte-identical content
/// joins the existing `Private` revision (B1 identity) but gains no ownership of it. The
/// owner chain is fixed by the revision's first admission. The joiner cannot read it (its
/// witnesses and attestations stay hidden), cannot find it in the change, and cannot move
/// it; outsiders still cannot see it. After the owner shares it, the joiner may read it but
/// still not move it. The same holds after replay and a checkpoint.
#[test]
fn b4_joining_identical_content_grants_no_ownership_of_a_private_revision() {
    let dir = temp_dir("join");
    let mut s = open(&dir, FsyncPolicy::EveryCommit);
    let o: &[u8] = &[1, 2];
    let w1: &[u8] = &[1, 2, 3];
    let x: &[u8] = &[1, 9];
    let p = admit(&mut s, o, b"orchestrator private attempt", 1);
    // W1 descends from the creating chain, so B1 lets it join without change scope.
    let (env, blobs) = revision(
        &key_of(w1),
        CHANGE,
        b"orchestrator private attempt",
        [2; 32],
        vec![],
    );
    match s
        .admit_revision(env, &blobs, auth(&path(w1)), 5_000)
        .unwrap()
    {
        RevisionOutcome::Admitted {
            changeset_id,
            joined_existing_revision,
            ..
        } => {
            assert_eq!(changeset_id, p);
            assert!(joined_existing_revision);
        }
        other => panic!("expected a join, got {other:?}"),
    }
    assert_eq!(s.get_revision(&repo(), p).unwrap().witnesses.len(), 2);
    let check = |s: &mut SynapseStore| {
        assert_eq!(state(s, p), RevisionState::Private);
        for labels in [w1, x] {
            let viewer = path(labels);
            assert_eq!(
                s.get_revision_visible_to(&repo(), p, &viewer)
                    .unwrap_err()
                    .code,
                RefusalCode::ChangesetNotFound,
                "{viewer:?} joined or is outside: not an owner"
            );
            assert!(s
                .change_status_visible_to(&repo(), CHANGE, &viewer)
                .is_err());
            let before = s.committed_seq();
            for to in [RevisionState::Draft, RevisionState::Proposed] {
                assert_eq!(
                    mv(s, labels, p, to, 6_000).unwrap_err().code,
                    RefusalCode::ChangesetNotFound,
                    "{viewer:?}"
                );
            }
            assert_eq!(s.committed_seq(), before, "nothing written");
        }
        assert_eq!(
            s.get_revision_visible_to(&repo(), p, &path(o))
                .unwrap()
                .witnesses
                .len(),
            2
        );
    };
    check(&mut s);
    drop(s);
    let mut s = open(&dir, FsyncPolicy::EveryCommit);
    check(&mut s);
    s.checkpoint_and_compact(9_000).unwrap();
    drop(s);
    let mut s = open(&dir, FsyncPolicy::EveryCommit);
    check(&mut s);
    // The owner shares it: the joiner reads it now, but moving it stays the owner's.
    mv(&mut s, o, p, RevisionState::Draft, 9_100).unwrap();
    assert_eq!(
        s.get_revision_visible_to(&repo(), p, &path(w1))
            .unwrap()
            .state,
        RevisionState::Draft
    );
    assert_eq!(
        mv(&mut s, w1, p, RevisionState::Proposed, 9_200)
            .unwrap_err()
            .code,
        RefusalCode::AuthChainNotDominant
    );
    mv(&mut s, o, p, RevisionState::Proposed, 9_300).unwrap();
}

/// The kind 9 v2 record (issue #89) round-trips byte for byte and its move verifies after
/// decoding; truncated, extended, unknown-state, and malformed-leaf-link bytes are refused
/// typed, never a panic; the unsigned layout of #88 is refused (truncated).
#[test]
fn b4_state_move_records_round_trip_and_malformed_bytes_are_refused_typed() {
    let w1: &[u8] = &[1, 2, 3];
    let id = ChangesetId(common::derived("codec revision", &[]));
    let record = WalRecord::RevisionStateMoved {
        state_move: signed(w1, id, RevisionState::Proposed, 7),
        moved_at_ms: 8,
        seal: None,
    };
    let bytes = encode_record(&record).unwrap();
    assert_eq!(record.kind_byte(), 9);
    let decoded = decode_record(&bytes, 1 << 20).unwrap();
    assert_eq!(decoded, record);
    assert_eq!(encode_record(&decoded).unwrap(), bytes);
    match &decoded {
        WalRecord::RevisionStateMoved { state_move, .. } => {
            assert_eq!(state_move.verify(), Ok(()))
        }
        other => panic!("decoded {other:?}"),
    }
    for cut in 0..bytes.len() {
        let err = decode_record(&bytes[..cut], 1 << 20).unwrap_err();
        assert!(
            matches!(err.kind(), "Truncated" | "EmbeddedMalformed"),
            "cut {cut}: {err:?}"
        );
    }
    let mut longer = bytes.clone();
    longer.push(0);
    assert_eq!(
        decode_record(&longer, 1 << 20).unwrap_err().kind(),
        "TrailingBytes"
    );
    // The state tag sits after the codec byte, kind, repo string, and changeset ID.
    let tag_at = 2 + 4 + repo().as_str().len() + 32;
    assert_eq!(bytes[tag_at], RevisionState::Proposed.tag_byte());
    for bad in [0u8, 6, 0xFF] {
        let mut b = bytes.clone();
        b[tag_at] = bad;
        assert_eq!(
            decode_record(&b, 1 << 20).unwrap_err().kind(),
            "UnknownTag",
            "state tag {bad}"
        );
    }
    // #88's unsigned layout ends after `moved_at_ms`: `repo | id | to | chain | moved_at_ms`.
    let v1_len = tag_at + 1 + 4 + (1 + 32 * w1.len()) + 8;
    assert_eq!(
        decode_record(&bytes[..v1_len], 1 << 20).unwrap_err().kind(),
        "Truncated"
    );
    // The leaf link is decoded strictly by `CapabilityLink::decode` (its version first).
    let link_at = v1_len + 8 + 4;
    let mut b = bytes.clone();
    b[link_at] ^= 0x02;
    assert_eq!(
        decode_record(&b, 1 << 20).unwrap_err().kind(),
        "EmbeddedMalformed"
    );
    for i in 2..bytes.len() {
        let mut b = bytes.clone();
        b[i] ^= 0x41;
        if let Ok(r) = decode_record(&b, 1 << 20) {
            assert_ne!(r, record);
        }
    }
}
