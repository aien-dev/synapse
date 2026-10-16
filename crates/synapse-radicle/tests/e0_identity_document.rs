//! ADR 0003 step E0: repository identity document (delegates, threshold, registered executor
//! keys, the server's machine key).
//!
//! Acceptance (ADR 0003 section 9, row 6):
//! * an edit signed by fewer than the threshold is refused
//!   (`e0_edit_signed_by_fewer_than_threshold_is_refused`);
//! * an edit signed by the threshold applies (`e0_edit_signed_by_threshold_applies`);
//! * a removed executor's later receipts are refused
//!   (`e0_removed_executor_later_receipts_are_refused`);
//! * Radicle conformance stays 11 of 11 (synapse-bench conformance child, evidence directory).

use ed25519_dalek::{Signer, SigningKey};
use synapse_core::{encode_did_key_ed25519, ChangesetId, GitOid, RefusalCode, RepoId, WalSeq};
use synapse_crumb::CrumbContextDigest;
use synapse_evidence::{
    CrumbContextBinding, DeclaredOutput, EvidenceReceipt, ExitStatus, InputRoot, Observation,
    Outcome, OutputDigest, ReceiptBody, ReceiptResult, SourceRevision, TestIdentity,
};
use synapse_radicle::identity::{
    DOMAIN_IDENTITY_DOCUMENT_DIGEST_V1, DOMAIN_IDENTITY_EDIT_SIGN_V1, MAX_DELEGATES,
};
use synapse_radicle::{
    IdentityDocumentDigest, IdentityEdit, IdentityLog, IdentitySignature, ReceiptRefusal,
    RepositoryIdentityDocument,
};

fn key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

fn pubkey(k: &SigningKey) -> [u8; 32] {
    k.verifying_key().to_bytes()
}

fn sorted(keys: &[&SigningKey]) -> Vec<[u8; 32]> {
    let mut v: Vec<[u8; 32]> = keys.iter().map(|k| pubkey(k)).collect();
    v.sort();
    v
}

fn repo() -> RepoId {
    RepoId::new("aien-spark/synapse").unwrap()
}

struct Fixture {
    d1: SigningKey,
    d2: SigningKey,
    d3: SigningKey,
    e1: SigningKey,
    e2: SigningKey,
    s1: SigningKey,
}

fn fixture() -> Fixture {
    Fixture {
        d1: key(0xd1),
        d2: key(0xd2),
        d3: key(0xd3),
        e1: key(0xe1),
        e2: key(0xe2),
        s1: key(0x51),
    }
}

/// Genesis: 3 delegates, threshold 2, executors e1 and e2, server key s1.
fn genesis_doc(f: &Fixture) -> RepositoryIdentityDocument {
    RepositoryIdentityDocument {
        repo_id: repo(),
        revision: 0,
        prev: IdentityDocumentDigest::ZERO,
        threshold: 2,
        delegates: sorted(&[&f.d1, &f.d2, &f.d3]),
        executors: sorted(&[&f.e1, &f.e2]),
        server_key: pubkey(&f.s1),
    }
}

fn genesis_log(f: &Fixture) -> IdentityLog {
    let edit = IdentityEdit::sign(genesis_doc(f), &[&f.d1, &f.d2]);
    IdentityLog::genesis(&edit, WalSeq(1)).expect("genesis signed by the threshold applies")
}

fn receipt_by(executor: &SigningKey) -> EvidenceReceipt {
    let repo = repo();
    let cs = ChangesetId([3; 32]);
    let body = ReceiptBody {
        repo_id: repo.clone(),
        changeset_id: cs,
        source: SourceRevision {
            base_git_oid: GitOid([1; 20]),
            parent_changesets: vec![],
        },
        crumb_contexts: vec![CrumbContextBinding {
            dir: ".".into(),
            at_base: CrumbContextDigest([0xa1; 32]),
            in_changeset: CrumbContextDigest([0xa1; 32]),
        }],
        input_root: InputRoot::single_repo(repo, cs),
        test: TestIdentity {
            name: "cargo-test-workspace".into(),
            command: vec!["cargo".into(), "test".into(), "--workspace".into()],
            toolchain: "rustc 1.89.0".into(),
            platform: "aarch64-unknown-linux-gnu".into(),
            environment: vec![],
        },
        result: ReceiptResult {
            exit_status: ExitStatus::Code(0),
            outcome: Outcome::Pass,
            outputs: vec![DeclaredOutput {
                name: "verdicts".into(),
                digest: OutputDigest::of_bytes(b"all pass"),
            }],
        },
        observation: Observation {
            started_at_ms: 1,
            duration_ms: 2,
            log: b"ok".to_vec(),
        },
    };
    EvidenceReceipt::sign(body, executor).expect("receipt body is valid")
}

fn identity_code(r: Result<synapse_evidence::EvidenceReceiptId, ReceiptRefusal>) -> RefusalCode {
    match r {
        Err(ReceiptRefusal::Identity(e)) => e.code,
        other => panic!("expected an identity refusal, got {other:?}"),
    }
}

#[test]
fn e0_edit_signed_by_fewer_than_threshold_is_refused() {
    let f = fixture();
    let mut log = genesis_log(&f);
    let before = log.current().clone();

    let mut next = before.successor();
    next.executors = sorted(&[&f.e1]);

    // One of three delegates; the threshold is two.
    let one = IdentityEdit::sign(next.clone(), &[&f.d1]);
    let err = log.apply(&one, WalSeq(10)).unwrap_err();
    assert_eq!(err.code, RefusalCode::RadicleQuorumInsufficient, "{err}");

    // The same delegate's signature twice still counts once.
    let mut twice = one.clone();
    twice.signatures.push(one.signatures[0]);
    let err = log.apply(&twice, WalSeq(10)).unwrap_err();
    assert_eq!(err.code, RefusalCode::RadicleQuorumInsufficient, "{err}");

    // No signature at all.
    let none = IdentityEdit::sign(next.clone(), &[]);
    let err = log.apply(&none, WalSeq(10)).unwrap_err();
    assert_eq!(err.code, RefusalCode::RadicleQuorumInsufficient, "{err}");

    // A key that is not a current delegate cannot make up the count, even one the edit
    // itself would add as a delegate.
    let d4 = key(0xd4);
    let mut adds_d4 = next.clone();
    adds_d4.delegates = sorted(&[&f.d1, &f.d2, &f.d3, &d4]);
    let self_added = IdentityEdit::sign(adds_d4, &[&f.d1, &d4]);
    let err = log.apply(&self_added, WalSeq(10)).unwrap_err();
    assert_eq!(err.code, RefusalCode::RadicleIdentityInvalid, "{err}");

    // A forged signature from a real delegate is refused, not counted.
    let mut forged = IdentityEdit::sign(next, &[&f.d1, &f.d2]);
    forged.signatures[1].signature[0] ^= 0x01;
    let err = log.apply(&forged, WalSeq(10)).unwrap_err();
    assert_eq!(err.code, RefusalCode::RadicleSignatureInvalid, "{err}");

    // Nothing changed.
    assert_eq!(log.current(), &before);
    assert_eq!(log.entries().len(), 1);
}

#[test]
fn e0_edit_signed_by_threshold_applies() {
    let f = fixture();
    let mut log = genesis_log(&f);
    let g = log.current().clone();

    let s2 = key(0x52);
    let mut next = g.successor();
    next.executors = sorted(&[&f.e1]);
    next.server_key = pubkey(&s2);
    next.threshold = 3;

    let edit = IdentityEdit::sign(next.clone(), &[&f.d2, &f.d3]);
    log.apply(&edit, WalSeq(10))
        .expect("2 of 3 delegates meet threshold 2");

    assert_eq!(log.current(), &next);
    assert_eq!(log.current().revision, 1);
    assert_eq!(log.current().prev, g.digest());
    assert_eq!(log.entries().len(), 2);
    assert_eq!(log.entries()[1].applied_at, WalSeq(10));

    // The document in effect, and the server's machine key, follow the WalSeq.
    assert_eq!(log.document_at(WalSeq(0)), None);
    assert_eq!(log.document_at(WalSeq(9)), Some(&g));
    assert_eq!(log.document_at(WalSeq(10)), Some(&next));
    assert_eq!(log.server_key_at(WalSeq(9)), Some(pubkey(&f.s1)));
    assert_eq!(log.server_key_at(WalSeq(10)), Some(pubkey(&s2)));

    // The next edit needs the new threshold (3): two signatures no longer apply, three do.
    let mut third = next.successor();
    third.executors = sorted(&[&f.e1, &f.e2]);
    let two = IdentityEdit::sign(third.clone(), &[&f.d1, &f.d2]);
    let err = log.apply(&two, WalSeq(20)).unwrap_err();
    assert_eq!(err.code, RefusalCode::RadicleQuorumInsufficient, "{err}");
    let three = IdentityEdit::sign(third.clone(), &[&f.d1, &f.d2, &f.d3]);
    log.apply(&three, WalSeq(20))
        .expect("3 of 3 meet threshold 3");
    assert_eq!(log.current(), &third);
}

#[test]
fn e0_removed_executor_later_receipts_are_refused() {
    let f = fixture();
    let mut log = genesis_log(&f);
    let r1 = receipt_by(&f.e1);
    let r2 = receipt_by(&f.e2);
    let e2 = pubkey(&f.e2);

    // Before removal both registered executors' receipts are admitted.
    assert!(log.executor_registered_at(&e2, WalSeq(5)));
    assert_eq!(log.admit_executor_receipt(&r2, WalSeq(5)), Ok(r2.id()));

    // Remove e2 at WalSeq 10 under the threshold.
    let mut next = log.current().successor();
    next.executors = sorted(&[&f.e1]);
    log.apply(&IdentityEdit::sign(next, &[&f.d1, &f.d3]), WalSeq(10))
        .unwrap();

    // e2's receipts from WalSeq 10 on are refused; e1's are still admitted.
    assert!(!log.executor_registered_at(&e2, WalSeq(10)));
    assert_eq!(
        identity_code(log.admit_executor_receipt(&r2, WalSeq(10))),
        RefusalCode::RadicleIdentityInvalid
    );
    assert_eq!(
        identity_code(log.admit_executor_receipt(&r2, WalSeq(11))),
        RefusalCode::RadicleIdentityInvalid
    );
    assert_eq!(log.admit_executor_receipt(&r1, WalSeq(11)), Ok(r1.id()));

    // Replay: the receipt accepted at WalSeq 5 is judged against the document in effect then,
    // so the later removal never revokes it.
    assert_eq!(log.admit_executor_receipt(&r2, WalSeq(5)), Ok(r2.id()));

    // A key never registered, a receipt before any identity document, and a forged receipt.
    let stranger = receipt_by(&key(0x99));
    assert_eq!(
        identity_code(log.admit_executor_receipt(&stranger, WalSeq(5))),
        RefusalCode::RadicleIdentityInvalid
    );
    assert_eq!(
        identity_code(log.admit_executor_receipt(&r1, WalSeq(0))),
        RefusalCode::RadicleIdentityInvalid
    );
    let mut forged = r1.clone();
    forged.signature[0] ^= 0x01;
    assert!(matches!(
        log.admit_executor_receipt(&forged, WalSeq(11)),
        Err(ReceiptRefusal::Receipt(_))
    ));
}

#[test]
fn e0_edits_chain_and_cannot_be_replayed_or_reordered() {
    let f = fixture();
    let mut log = genesis_log(&f);
    let g = log.current().clone();

    let mut rev1 = g.successor();
    rev1.executors = sorted(&[&f.e1]);
    let mut rev2 = rev1.successor();
    rev2.executors = sorted(&[&f.e2]);
    let edit1 = IdentityEdit::sign(rev1.clone(), &[&f.d1, &f.d2]);
    let edit2 = IdentityEdit::sign(rev2.clone(), &[&f.d1, &f.d2]);

    // Reorder: revision 2 before revision 1.
    let err = log.apply(&edit2, WalSeq(10)).unwrap_err();
    assert_eq!(err.code, RefusalCode::RadicleIdentityInvalid, "{err}");

    log.apply(&edit1, WalSeq(10)).unwrap();

    // Replay of an applied edit.
    let err = log.apply(&edit1, WalSeq(11)).unwrap_err();
    assert_eq!(err.code, RefusalCode::RadicleIdentityInvalid, "{err}");

    // A WalSeq that does not move forward.
    let err = log.apply(&edit2, WalSeq(10)).unwrap_err();
    assert_eq!(err.code, RefusalCode::RadicleIdentityInvalid, "{err}");

    // Right revision number but the wrong prev digest (a fork of revision 1).
    let mut fork = rev2.clone();
    fork.prev = g.digest();
    let err = log
        .apply(&IdentityEdit::sign(fork, &[&f.d1, &f.d2]), WalSeq(20))
        .unwrap_err();
    assert_eq!(err.code, RefusalCode::RadicleIdentityInvalid, "{err}");

    // Another repository's edit.
    let mut other = rev2.clone();
    other.repo_id = RepoId::new("aien-spark/other").unwrap();
    let err = log
        .apply(&IdentityEdit::sign(other, &[&f.d1, &f.d2]), WalSeq(20))
        .unwrap_err();
    assert_eq!(err.code, RefusalCode::RadicleIdentityInvalid, "{err}");

    // A signature over the bare digest, without the domain tag, does not count.
    let mut undomained = IdentityEdit::sign(rev2.clone(), &[&f.d1]);
    undomained.signatures.push(IdentitySignature {
        key: pubkey(&f.d2),
        signature: f.d2.sign(&rev2.digest().0).to_bytes(),
    });
    let err = log.apply(&undomained, WalSeq(20)).unwrap_err();
    assert_eq!(err.code, RefusalCode::RadicleSignatureInvalid, "{err}");

    log.apply(&edit2, WalSeq(20)).unwrap();
    assert_eq!(log.current(), &rev2);
    assert_eq!(log.entries().len(), 3);
}

#[test]
fn e0_genesis_needs_its_own_threshold_and_a_valid_document() {
    let f = fixture();
    let g = genesis_doc(&f);

    let err =
        IdentityLog::genesis(&IdentityEdit::sign(g.clone(), &[&f.d1]), WalSeq(1)).unwrap_err();
    assert_eq!(err.code, RefusalCode::RadicleQuorumInsufficient, "{err}");

    let mut not_genesis = g.clone();
    not_genesis.revision = 1;
    let err = IdentityLog::genesis(&IdentityEdit::sign(not_genesis, &[&f.d1, &f.d2]), WalSeq(1))
        .unwrap_err();
    assert_eq!(err.code, RefusalCode::RadicleIdentityInvalid, "{err}");

    let invalid: Vec<(&str, RepositoryIdentityDocument)> = vec![
        ("threshold 0", {
            let mut d = g.clone();
            d.threshold = 0;
            d
        }),
        ("threshold above delegates", {
            let mut d = g.clone();
            d.threshold = 4;
            d
        }),
        ("no delegates", {
            let mut d = g.clone();
            d.delegates.clear();
            d
        }),
        ("delegates unsorted", {
            let mut d = g.clone();
            d.delegates.reverse();
            d
        }),
        ("delegate twice", {
            let mut d = g.clone();
            d.delegates[1] = d.delegates[0];
            d
        }),
        ("executors unsorted", {
            let mut d = g.clone();
            d.executors.reverse();
            d
        }),
        ("delegate key not an Ed25519 point", {
            let mut d = g.clone();
            // y = 2 has no x on the curve, so this encoding does not decompress.
            let mut bad = [0u8; 32];
            bad[0] = 2;
            d.delegates = vec![bad];
            d.threshold = 1;
            d
        }),
    ];
    for (label, d) in invalid {
        assert_eq!(
            d.validate().map_err(|e| e.code),
            Err(RefusalCode::RadicleIdentityInvalid),
            "{label}"
        );
    }
    assert_eq!(g.validate(), Ok(()));
}

#[test]
fn e0_binary_format_round_trips_and_refuses_malformed_bytes() {
    let f = fixture();
    let g = genesis_doc(&f);
    let edit = IdentityEdit::sign(g.clone(), &[&f.d1, &f.d2]);

    let doc_bytes = g.encode();
    assert!(doc_bytes.starts_with(b"SYNAPSE_IDENTITY_DOCUMENT_V1\0"));
    assert_eq!(
        RepositoryIdentityDocument::decode(&doc_bytes),
        Ok(g.clone())
    );
    let edit_bytes = edit.encode();
    assert!(edit_bytes.starts_with(b"SYNAPSE_IDENTITY_EDIT_V1\0"));
    assert_eq!(IdentityEdit::decode(&edit_bytes), Ok(edit.clone()));

    // Digest and signed bytes are domain separated and bound to the encoding.
    let mut h = sha2_digest(DOMAIN_IDENTITY_DOCUMENT_DIGEST_V1, &doc_bytes);
    assert_eq!(g.digest().0, h);
    let mut signable = DOMAIN_IDENTITY_EDIT_SIGN_V1.to_vec();
    signable.extend_from_slice(&h);
    assert_eq!(g.signable_bytes(), signable);
    h[0] ^= 1;
    assert_ne!(g.digest().0, h);

    // Every truncation and a trailing byte are refused.
    for n in 0..doc_bytes.len() {
        assert!(
            RepositoryIdentityDocument::decode(&doc_bytes[..n]).is_err(),
            "doc prefix {n}"
        );
    }
    for n in 0..edit_bytes.len() {
        assert!(
            IdentityEdit::decode(&edit_bytes[..n]).is_err(),
            "edit prefix {n}"
        );
    }
    let mut trailing = doc_bytes.clone();
    trailing.push(0);
    assert!(RepositoryIdentityDocument::decode(&trailing).is_err());
    let mut trailing = edit_bytes.clone();
    trailing.push(0);
    assert!(IdentityEdit::decode(&trailing).is_err());

    // A wrong version is refused.
    let tag = b"SYNAPSE_IDENTITY_DOCUMENT_V1\0".len();
    let mut wrong_version = doc_bytes.clone();
    wrong_version[tag] = 2;
    assert!(RepositoryIdentityDocument::decode(&wrong_version).is_err());

    // A delegate count above the cap is refused before anything is allocated for it.
    // Layout: tag, u16 version, u32 repo_id length, repo_id, u64 revision, 32 prev,
    // u32 threshold, u32 delegate count.
    let count_at = tag + 2 + 4 + repo().as_str().len() + 8 + 32 + 4;
    let mut huge = doc_bytes.clone();
    huge[count_at..count_at + 4].copy_from_slice(&((MAX_DELEGATES as u32) + 1).to_le_bytes());
    let err = RepositoryIdentityDocument::decode(&huge).unwrap_err();
    assert_eq!(err.code, RefusalCode::RadicleIdentityInvalid, "{err}");
    huge[count_at..count_at + 4].copy_from_slice(&u32::MAX.to_le_bytes());
    assert!(RepositoryIdentityDocument::decode(&huge).is_err());

    // A decoded document that breaks a rule is refused at decode.
    let mut unsorted = g.clone();
    unsorted.delegates.reverse();
    assert!(RepositoryIdentityDocument::decode(&unsorted.encode()).is_err());

    // The did:key spelling of every key is the Radicle one.
    assert!(encode_did_key_ed25519(&g.delegates[0]).starts_with("did:key:z6Mk"));
}

fn sha2_digest(domain: &[u8], bytes: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(domain);
    h.update((bytes.len() as u64).to_le_bytes());
    h.update(bytes);
    h.finalize().into()
}
