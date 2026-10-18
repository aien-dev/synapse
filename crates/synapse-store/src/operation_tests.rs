//! B2 (issue #30): operation views, undo, plain and final discard, revocation as a fact.

use crate::codec::{decode_record, encode_record, CodecRefusal};
use crate::revision::b4_tests::{body, key_of, open, path, repo, temp_dir, SplitMix64};
use crate::{AdmissionAuthority, RecoveryPolicy, SynapseStore, ViewOperation, WalRecord};
use std::collections::BTreeMap;
use synapse_core::{
    BlobDigest, ChangeId, ChangesetEnvelopeV2, ChangesetId, FileMode, IdempotencyKey, MutationOp,
    ObsolescenceMarker, PathMutation, RefusalCode, RevisionContent, TreeDigest, WalSeq,
};

const STRICT: RecoveryPolicy = RecoveryPolicy::StrictFailClosed;
/// Root chain: dominates both actors.
const ROOT: &[u8] = &[1];
const ALICE: &[u8] = &[1, 2];
const BOB: &[u8] = &[1, 3];

/// Admit revision `n` of change `change` under the chain (and key) `owner`.
fn admit(s: &mut SynapseStore, owner: &[u8], n: u32, change: u8) -> ChangesetId {
    let b = body(n);
    let content = RevisionContent {
        change_id: ChangeId([change; 16]),
        base_tree: TreeDigest([0x7E; 32]),
        parents: vec![],
        mutations: vec![PathMutation {
            path: "src/lib.rs".into(),
            op: MutationOp::Upsert {
                mode: FileMode::Regular644,
                blob_digest: BlobDigest::compute(&b),
                size_bytes: b.len() as u64,
            },
        }],
        intent_summary: "implement the task".into(),
    };
    let mut idem = [0u8; 32];
    idem[..4].copy_from_slice(&n.to_le_bytes());
    idem[4] = change;
    let envelope =
        ChangesetEnvelopeV2::sign_new(&key_of(owner), repo(), content, IdempotencyKey(idem), 1_000);
    let id = envelope.changeset_id();
    let authority = AdmissionAuthority {
        chain: path(owner),
        change_scope: Vec::new(),
    };
    s.admit_revision(
        envelope,
        &[(BlobDigest::compute(&b), b.to_vec())],
        authority,
        5_000,
    )
    .unwrap();
    id
}

fn rewrite(s: &mut SynapseStore, owner: &[u8], change: u8, pred: ChangesetId, succ: ChangesetId) {
    let m = ObsolescenceMarker::sign_new(
        &key_of(owner),
        repo(),
        ChangeId([change; 16]),
        pred,
        vec![succ],
        6_000,
    );
    s.record_obsolescence(m, path(owner), 6_000).unwrap();
}

fn digest(s: &SynapseStore) -> [u8; 32] {
    s.view(&repo()).digest(&repo())
}

fn heads(s: &SynapseStore, change: u8) -> Vec<ChangesetId> {
    s.view(&repo())
        .heads
        .get(&ChangeId([change; 16]))
        .map(|h| h.iter().copied().collect())
        .unwrap_or_default()
}

fn undo(
    s: &mut SynapseStore,
    target: WalSeq,
    actor: Option<&[u8]>,
    by: &[u8],
) -> synapse_core::SynapseResult<crate::ViewOutcome> {
    s.record_undo(repo(), target, actor.map(path), path(by), 7_000)
}

/// The owner chain of each of the three actors.
fn actor(i: u64) -> &'static [u8] {
    [ROOT, ALICE, BOB][i as usize]
}

/// Acceptance 1 (property): random sequences of admissions, rewrites, plain and final
/// discards, revocations, whole and per-actor undos and undos of undos. Every whole undo to
/// `T` that is admitted gives back exactly the view digest of `T`; every refused operation
/// writes nothing and leaves the view unchanged; replay, `checkpoint_and_compact`, and a
/// strict reopen give back the digest of every point of the log.
#[test]
fn b2_property_undo_to_t_restores_the_view_of_t_across_replay_and_compaction() {
    let mut rng = SplitMix64(0xB2_0030);
    let mut checked_undos = 0u32;
    let mut refused = 0u32;
    for round in 0..6u32 {
        let dir = temp_dir(&format!("b2-prop-{round}"));
        let mut s = open(&dir, STRICT).unwrap();
        let mut at: BTreeMap<u64, [u8; 32]> = BTreeMap::new();
        at.insert(0, digest(&s));
        // (owner index, change, changeset) of every admission, in order.
        let mut revs: Vec<(u64, u8, ChangesetId)> = Vec::new();
        let mut n = 0u32;
        for _ in 0..40 {
            let before = (s.committed_seq(), digest(&s));
            let pick = rng.below(16);
            let result: Result<(), RefusalCode> = match pick {
                0..=4 => {
                    let who = 1 + rng.below(2);
                    let change = (10 * who + rng.below(2)) as u8;
                    n += 1;
                    let id = admit(&mut s, actor(who), round * 1_000 + n, change);
                    revs.push((who, change, id));
                    Ok(())
                }
                5..=6 => {
                    // Rewrite an earlier revision of a change into a later one (no cycles).
                    let k = rng.below(revs.len().max(1) as u64) as usize;
                    match revs.get(k).copied() {
                        Some((who, change, pred)) => {
                            match revs[k + 1..].iter().find(|r| r.1 == change) {
                                Some(&(_, _, succ)) => {
                                    rewrite(&mut s, actor(who), change, pred, succ);
                                    Ok(())
                                }
                                None => Ok(()),
                            }
                        }
                        None => Ok(()),
                    }
                }
                7..=8 => match revs.get(rng.below(revs.len().max(1) as u64) as usize) {
                    Some(&(who, _, id)) => s
                        .record_discard(repo(), id, rng.below(6) == 0, path(actor(who)), 7_000)
                        .map(|_| ())
                        .map_err(|e| e.code),
                    None => Ok(()),
                },
                9 => {
                    if rng.below(3) == 0 {
                        s.record_revocation(repo(), path(&[1, 2, 9]), path(ROOT), 7_000)
                            .map(|_| ())
                            .map_err(|e| e.code)
                    } else {
                        Ok(())
                    }
                }
                _ => {
                    let last = s.committed_seq().0;
                    let target = WalSeq(rng.below(last + 1));
                    let (by, filter) = match rng.below(4) {
                        0 => (ROOT, None),
                        1 => (ALICE, Some(ALICE)),
                        2 => (BOB, Some(BOB)),
                        _ => (actor(rng.below(3)), None),
                    };
                    match undo(&mut s, target, filter, by) {
                        Ok(out) => {
                            if filter.is_none() {
                                assert_eq!(
                                    out.view_digest, at[&target.0],
                                    "a whole undo to {target} must restore the view of {target}"
                                );
                                checked_undos += 1;
                            }
                            at.insert(out.wal_seq.0, digest(&s));
                            // Undo is undoable: undoing the undo restores the view before it.
                            if rng.below(2) == 0 {
                                let prev = WalSeq(out.wal_seq.0 - 1);
                                let back = undo(&mut s, prev, None, ROOT).unwrap();
                                assert_eq!(back.view_digest, at[&prev.0]);
                                at.insert(back.wal_seq.0, back.view_digest);
                                checked_undos += 1;
                            }
                            Ok(())
                        }
                        Err(e) => Err(e.code),
                    }
                }
            };
            match result {
                Ok(()) => {
                    at.insert(s.committed_seq().0, digest(&s));
                }
                Err(code) => {
                    refused += 1;
                    assert!(
                        matches!(
                            code,
                            RefusalCode::UndoIrreversible
                                | RefusalCode::AuthChainNotDominant
                                | RefusalCode::DiscardInvalid
                        ),
                        "unexpected refusal {code:?}"
                    );
                    assert_eq!(
                        (s.committed_seq(), digest(&s)),
                        before,
                        "a refusal writes nothing"
                    );
                }
            }
        }
        let check = |s: &SynapseStore| {
            for (seq, d) in &at {
                assert_eq!(
                    &s.view_at(&repo(), WalSeq(*seq)).digest(&repo()),
                    d,
                    "view of {seq}"
                );
            }
            assert_eq!(s.view_replay_report(), crate::ViewReplayReport::default());
        };
        check(&s);
        drop(s);
        let mut s = open(&dir, STRICT).unwrap();
        check(&s);
        s.checkpoint_and_compact(8_000).unwrap();
        check(&s);
        drop(s);
        check(&open(&dir, STRICT).unwrap());
        let _ = std::fs::remove_dir_all(&dir);
    }
    assert!(checked_undos >= 20, "only {checked_undos} undos checked");
    assert!(refused >= 5, "only {refused} refusals exercised");
}

/// A per-actor undo disables only the operations of that actor (and the chains below it);
/// another actor's later work stays, and a marker of another actor that names an undone
/// revision is reported as conflict data instead of being dropped.
#[test]
fn b2_per_actor_undo_leaves_other_actors_intact() {
    let dir = temp_dir("b2-per-actor");
    let mut s = open(&dir, STRICT).unwrap();
    let a1 = admit(&mut s, ALICE, 1, 20);
    let t = s.committed_seq();
    let b1 = admit(&mut s, BOB, 2, 30);
    let a2 = admit(&mut s, ALICE, 3, 20);
    rewrite(&mut s, ALICE, 20, a1, a2);
    let b2 = admit(&mut s, BOB, 4, 30);
    rewrite(&mut s, BOB, 30, b1, b2);
    assert_eq!(heads(&s, 20), vec![a2]);
    assert_eq!(heads(&s, 30), vec![b2]);

    let out = undo(&mut s, t, Some(ALICE), ALICE).unwrap();
    assert_eq!(heads(&s, 20), vec![a1], "Alice's later work is undone");
    assert_eq!(heads(&s, 30), vec![b2], "Bob's work is untouched");
    assert!(out.conflicts.is_empty());

    // Undo Alice's first admission too: Bob's rewrite of Bob's change is still fine, and
    // undoing all of Alice's work from the start leaves only Bob's view.
    undo(&mut s, WalSeq(0), Some(ALICE), ALICE).unwrap();
    assert_eq!(heads(&s, 20), Vec::<ChangesetId>::new());
    assert_eq!(heads(&s, 30), vec![b2]);
    // Undo of the undo by the root gives Alice's state back.
    let prev = WalSeq(s.committed_seq().0 - 1);
    undo(&mut s, prev, None, ROOT).unwrap();
    assert_eq!(heads(&s, 20), vec![a1]);
    let _ = std::fs::remove_dir_all(&dir);
}

/// A per-actor undo that removes an admission another actor's later marker names keeps the
/// marker in effect and reports it as conflict data in the view instead of dropping it.
#[test]
fn b2_per_actor_undo_records_conflicts_with_other_actors_markers() {
    let dir = temp_dir("b2-conflict");
    let mut s = open(&dir, STRICT).unwrap();
    // The root creates change 40; Alice (below the root) joins it; the root rewrites its
    // revision into Alice's.
    let r1 = admit(&mut s, ROOT, 1, 40);
    let t = s.committed_seq();
    let a1 = admit(&mut s, ALICE, 2, 40);
    rewrite(&mut s, ROOT, 40, r1, a1);
    let marker_seq = s.committed_seq();
    assert_eq!(heads(&s, 40), vec![a1]);
    // The root undoes only Alice's work: her admission goes, the root's marker stays.
    let out = undo(&mut s, t, Some(ALICE), ROOT).unwrap();
    assert_eq!(heads(&s, 40), Vec::<ChangesetId>::new());
    assert_eq!(
        out.conflicts.iter().copied().collect::<Vec<_>>(),
        vec![marker_seq]
    );
    assert_eq!(s.view(&repo()).conflicts, out.conflicts);
    // Undoing that undo resolves the conflict; no object was ever deleted.
    let prev = WalSeq(out.wal_seq.0 - 1);
    let back = undo(&mut s, prev, None, ROOT).unwrap();
    assert!(back.conflicts.is_empty());
    assert_eq!(heads(&s, 40), vec![a1]);
    assert!(s.get_revision(&repo(), a1).is_ok());
    let _ = std::fs::remove_dir_all(&dir);
}

/// Facts are never undone: an undo that reaches a revocation or a final discard is refused
/// with `UndoIrreversible` and writes nothing; an undo that stops after the fact, or a
/// per-actor undo whose filter excludes it, is admitted. A finally discarded revision cannot
/// be discarded again.
#[test]
fn b2_undo_of_a_revocation_or_a_final_discard_is_refused() {
    let dir = temp_dir("b2-facts");
    let mut s = open(&dir, STRICT).unwrap();
    let a1 = admit(&mut s, ALICE, 1, 20);
    let before_final = s.committed_seq();
    s.record_discard(repo(), a1, true, path(ALICE), 7_000)
        .unwrap();
    let after_final = s.committed_seq();
    let seq = s.committed_seq();
    let err = undo(&mut s, before_final, None, ROOT).unwrap_err();
    assert_eq!(err.code, RefusalCode::UndoIrreversible, "{err:?}");
    assert_eq!(s.committed_seq(), seq, "nothing written");
    let err = undo(&mut s, before_final, Some(ALICE), ALICE).unwrap_err();
    assert_eq!(err.code, RefusalCode::UndoIrreversible);
    let err = s
        .record_discard(repo(), a1, false, path(ALICE), 7_000)
        .unwrap_err();
    assert_eq!(err.code, RefusalCode::DiscardInvalid);

    let b1 = admit(&mut s, BOB, 2, 30);
    s.record_revocation(repo(), path(&[1, 3, 7]), path(BOB), 7_000)
        .unwrap();
    let err = undo(&mut s, after_final, None, ROOT).unwrap_err();
    assert_eq!(err.code, RefusalCode::UndoIrreversible);
    // Bob's per-actor undo to before his revision reaches his revocation: refused too.
    let err = undo(&mut s, after_final, Some(BOB), BOB).unwrap_err();
    assert_eq!(err.code, RefusalCode::UndoIrreversible);
    // A revocation needs a chain that dominates the revoked one.
    let err = s
        .record_revocation(repo(), path(&[1, 2, 7]), path(BOB), 7_000)
        .unwrap_err();
    assert_eq!(err.code, RefusalCode::AuthChainNotDominant);
    // Alice's per-actor undo after her final discard (filter excludes Bob's revocation).
    let a2 = admit(&mut s, ALICE, 3, 21);
    undo(&mut s, after_final, Some(ALICE), ALICE).unwrap();
    assert_eq!(heads(&s, 21), Vec::<ChangesetId>::new());
    assert_eq!(heads(&s, 30), vec![b1]);
    assert_eq!(s.view(&repo()).discarded.get(&a1), Some(&true));
    let _ = a2;
    let _ = std::fs::remove_dir_all(&dir);
}

/// An undo that reaches an operation of an actor chain the undoer does not dominate is
/// refused (`AuthChainNotDominant`), whole or per-actor; so is a discard by a chain that does
/// not own the revision. A target at or after the undo is `UndoTargetInvalid`.
#[test]
fn b2_undo_by_a_non_dominating_chain_is_refused() {
    let dir = temp_dir("b2-dominance");
    let mut s = open(&dir, STRICT).unwrap();
    let a1 = admit(&mut s, ALICE, 1, 20);
    admit(&mut s, BOB, 2, 30);
    let seq = s.committed_seq();
    let err = undo(&mut s, WalSeq(0), None, BOB).unwrap_err();
    assert_eq!(err.code, RefusalCode::AuthChainNotDominant);
    let err = undo(&mut s, WalSeq(0), Some(ALICE), BOB).unwrap_err();
    assert_eq!(err.code, RefusalCode::AuthChainNotDominant);
    let err = s
        .record_discard(repo(), a1, false, path(BOB), 7_000)
        .unwrap_err();
    assert_eq!(err.code, RefusalCode::AuthChainNotDominant);
    let err = s
        .record_discard(repo(), ChangesetId([9; 32]), false, path(ROOT), 7_000)
        .unwrap_err();
    assert_eq!(err.code, RefusalCode::ChangesetNotFound);
    let err = undo(&mut s, WalSeq(seq.0 + 1), None, ROOT).unwrap_err();
    assert_eq!(err.code, RefusalCode::UndoTargetInvalid);
    assert_eq!(s.committed_seq(), seq, "nothing written");
    // Bob may undo his own work, and the root may undo anyone's.
    undo(&mut s, WalSeq(0), Some(BOB), BOB).unwrap();
    undo(&mut s, WalSeq(0), None, ROOT).unwrap();
    assert!(s.view(&repo()).heads.is_empty());
    let _ = std::fs::remove_dir_all(&dir);
}

/// Kind 12 records written without the store (an undo of another actor's work, an undo
/// reaching a final discard, a discard by a non-owner, a revocation by a non-dominating
/// chain) change nothing on replay and are counted by reason.
#[test]
fn b2_forged_view_operations_change_nothing_on_replay() {
    let dir = temp_dir("b2-forged");
    let mut s = open(&dir, STRICT).unwrap();
    let a1 = admit(&mut s, ALICE, 1, 20);
    let a2 = admit(&mut s, ALICE, 2, 21);
    s.record_discard(repo(), a2, true, path(ALICE), 7_000)
        .unwrap();
    let honest = digest(&s);
    let forged = |op: ViewOperation, by: &[u8]| WalRecord::ViewOperationRecorded {
        op,
        chain: path(by),
        recorded_at_ms: 7_000,
    };
    let undo_other = forged(
        ViewOperation::Undo {
            repo_id: repo(),
            target: WalSeq(0),
            actor: None,
        },
        BOB,
    );
    let undo_fact = forged(
        ViewOperation::Undo {
            repo_id: repo(),
            target: WalSeq(0),
            actor: Some(path(ALICE)),
        },
        ALICE,
    );
    let discard_other = forged(
        ViewOperation::Discard {
            repo_id: repo(),
            changeset_id: a1,
            final_discard: false,
        },
        BOB,
    );
    let revoke_other = forged(
        ViewOperation::Revoke {
            repo_id: repo(),
            revoked: path(ALICE),
        },
        BOB,
    );
    for r in [undo_other, undo_fact, discard_other, revoke_other] {
        s.append_revision_record(r, &[], None).unwrap();
    }
    let check = |s: &SynapseStore| {
        assert_eq!(digest(s), honest, "forged kind 12 records change nothing");
        assert_eq!(heads(s, 20), vec![a1]);
        let r = s.view_replay_report();
        assert_eq!(
            (r.undo_refused, r.discard_refused, r.revoke_refused),
            (2, 1, 1)
        );
    };
    check(&s);
    drop(s);
    let mut s = open(&dir, STRICT).unwrap();
    check(&s);
    s.checkpoint_and_compact(8_000).unwrap();
    drop(s);
    check(&open(&dir, STRICT).unwrap());
    let _ = std::fs::remove_dir_all(&dir);
}

/// The kind 12 codec round-trips every operation, refuses unknown operation and flag tags,
/// and the state root digest covers every field.
#[test]
fn b2_kind_12_codec_round_trips_and_refuses_unknown_tags() {
    let ops = [
        ViewOperation::Undo {
            repo_id: repo(),
            target: WalSeq(7),
            actor: None,
        },
        ViewOperation::Undo {
            repo_id: repo(),
            target: WalSeq(0),
            actor: Some(path(ALICE)),
        },
        ViewOperation::Discard {
            repo_id: repo(),
            changeset_id: ChangesetId([3; 32]),
            final_discard: true,
        },
        ViewOperation::Revoke {
            repo_id: repo(),
            revoked: path(&[1, 2, 9]),
        },
    ];
    let mut digests = std::collections::BTreeSet::new();
    for op in ops {
        let record = WalRecord::ViewOperationRecorded {
            op,
            chain: path(ROOT),
            recorded_at_ms: 9_000,
        };
        let bytes = encode_record(&record).unwrap();
        assert_eq!(decode_record(&bytes, 1 << 20).unwrap(), record);
        assert!(digests.insert(crate::revision::record_digest(&record)));
    }
    let record = WalRecord::ViewOperationRecorded {
        op: ViewOperation::Undo {
            repo_id: repo(),
            target: WalSeq(1),
            actor: None,
        },
        chain: path(ROOT),
        recorded_at_ms: 9_000,
    };
    let bytes = encode_record(&record).unwrap();
    // Layout: codec version, kind, op tag.
    let tag_at = 2;
    assert_eq!(bytes[tag_at], 1);
    let mut bad = bytes.clone();
    bad[tag_at] = 4;
    assert!(matches!(
        decode_record(&bad, 1 << 20),
        Err(CodecRefusal::UnknownTag {
            field: "view operation",
            tag: 4,
            ..
        })
    ));
    // The actor flag follows repository (u32 len + bytes) and target (u64).
    let flag_at = tag_at + 1 + 4 + repo().as_str().len() + 8;
    assert_eq!(bytes[flag_at], 0);
    let mut bad = bytes;
    bad[flag_at] = 2;
    assert!(matches!(
        decode_record(&bad, 1 << 20),
        Err(CodecRefusal::UnknownTag {
            field: "undo actor",
            tag: 2,
            ..
        })
    ));
}
