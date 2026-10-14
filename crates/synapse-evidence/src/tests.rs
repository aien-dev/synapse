use super::*;
use synapse_core::DOMAIN_CHANGESET_SIGN_V1;

fn executor() -> SigningKey {
    SigningKey::from_bytes(&[7u8; 32])
}

fn body() -> ReceiptBody {
    let repo = RepoId::new("aien-spark/synapse").unwrap();
    let cs = ChangesetId([3; 32]);
    ReceiptBody {
        repo_id: repo.clone(),
        changeset_id: cs,
        source: SourceRevision {
            base_git_oid: GitOid([1; 20]),
            parent_changesets: vec![ChangesetId([0x10; 32]), ChangesetId([0x20; 32])],
        },
        crumb_contexts: vec![
            CrumbContextBinding {
                dir: ".".into(),
                at_base: CrumbContextDigest([0xa1; 32]),
                in_changeset: CrumbContextDigest([0xb1; 32]),
            },
            CrumbContextBinding {
                dir: "src".into(),
                at_base: CrumbContextDigest([0xa2; 32]),
                in_changeset: CrumbContextDigest([0xa2; 32]),
            },
        ],
        input_root: InputRoot::single_repo(repo, cs),
        test: TestIdentity {
            name: "cargo-test-workspace".into(),
            command: vec!["cargo".into(), "test".into(), "--workspace".into()],
            toolchain: "rustc 1.89.0".into(),
            platform: "aarch64-unknown-linux-gnu".into(),
            environment: vec![
                EnvVar {
                    name: "CARGO_TERM_COLOR".into(),
                    value: "never".into(),
                },
                EnvVar {
                    name: "RUST_BACKTRACE".into(),
                    value: "1".into(),
                },
            ],
        },
        result: ReceiptResult {
            exit_status: ExitStatus::Code(0),
            outcome: Outcome::Pass,
            outputs: vec![
                DeclaredOutput {
                    name: "junit.xml".into(),
                    digest: OutputDigest::of_bytes(b"<testsuite/>"),
                },
                DeclaredOutput {
                    name: "verdicts".into(),
                    digest: OutputDigest::of_bytes(b"all pass"),
                },
            ],
        },
        observation: Observation {
            started_at_ms: 1_000,
            duration_ms: 42_000,
            log: b"running 120 tests\ntest result: ok\n".to_vec(),
        },
    }
}

fn signed() -> EvidenceReceipt {
    EvidenceReceipt::sign(body(), &executor()).unwrap()
}

#[test]
fn round_trip_encoding_is_canonical() {
    let r = signed();
    let bytes = r.encode().unwrap();
    assert!(bytes.starts_with(DOMAIN_EVIDENCE_RECEIPT_V1));
    let (back, id) = EvidenceReceipt::decode_verified(&bytes).unwrap();
    assert_eq!(back, r);
    assert_eq!(id, r.id());
    assert_eq!(back.encode().unwrap(), bytes);
    // Deterministic: signing the same body twice gives identical bytes (Ed25519 is deterministic).
    assert_eq!(signed().encode().unwrap(), bytes);
}

#[test]
fn every_bound_field_is_tamper_evident() {
    type Tamper = (&'static str, fn(&mut EvidenceReceipt));
    let cases: Vec<Tamper> = vec![
        ("repo_id", |r| {
            let other = RepoId::new("aien-spark/other").unwrap();
            r.body.repo_id = other.clone();
            r.body.input_root = InputRoot::single_repo(other, r.body.changeset_id);
        }),
        ("changeset_id", |r| {
            r.body.changeset_id = ChangesetId([4; 32]);
            r.body.input_root = InputRoot::single_repo(r.body.repo_id.clone(), r.body.changeset_id);
        }),
        ("source.base_git_oid", |r| {
            r.body.source.base_git_oid = GitOid([2; 20])
        }),
        ("source.parent_changesets", |r| {
            r.body.source.parent_changesets.pop();
        }),
        ("crumb_contexts.at_base", |r| {
            r.body.crumb_contexts[1].at_base = CrumbContextDigest([0xb2; 32])
        }),
        ("crumb_contexts.in_changeset", |r| {
            r.body.crumb_contexts[1].in_changeset = CrumbContextDigest([0xb2; 32])
        }),
        ("crumb_contexts.dir", |r| {
            r.body.crumb_contexts[1].dir = "srd".into()
        }),
        ("crumb_contexts.count", |r| {
            r.body.crumb_contexts.pop();
        }),
        ("test.name", |r| r.body.test.name = "cargo-test".into()),
        ("test.command", |r| r.body.test.command.push("-q".into())),
        ("test.toolchain", |r| {
            r.body.test.toolchain = "rustc 1.90.0".into()
        }),
        ("test.platform", |r| {
            r.body.test.platform = "x86_64-unknown-linux-gnu".into()
        }),
        ("test.environment", |r| {
            r.body.test.environment[1].value = "0".into()
        }),
        ("result.exit_status", |r| {
            r.body.result.exit_status = ExitStatus::Code(1);
            r.body.result.outcome = Outcome::Fail;
        }),
        ("result.outcome", |r| r.body.result.outcome = Outcome::Flaky),
        ("result.outputs", |r| {
            r.body.result.outputs[0].digest = OutputDigest::of_bytes(b"<x/>")
        }),
        ("observation.log", |r| r.body.observation.log.push(b'!')),
        ("observation.duration_ms", |r| {
            r.body.observation.duration_ms += 1
        }),
        ("observation.started_at_ms", |r| {
            r.body.observation.started_at_ms += 1
        }),
        ("executor_did", |r| {
            r.executor_did = encode_did_key_ed25519(
                &SigningKey::from_bytes(&[8u8; 32])
                    .verifying_key()
                    .to_bytes(),
            )
        }),
    ];
    for (field, tamper) in cases {
        let mut r = signed();
        tamper(&mut r);
        assert_eq!(
            r.verify(),
            Err(ReceiptError::SignatureInvalid),
            "tampering {field} must break the signature"
        );
        // The same tamper through the wire form is refused too.
        assert_eq!(
            EvidenceReceipt::decode_verified(&r.encode().unwrap()).map(|_| ()),
            Err(ReceiptError::SignatureInvalid),
            "{field} via bytes"
        );
    }
}

#[test]
fn every_single_byte_flip_is_refused() {
    let bytes = signed().encode().unwrap();
    for i in 0..bytes.len() {
        let mut b = bytes.clone();
        b[i] ^= 0x01;
        assert!(
            EvidenceReceipt::decode_verified(&b).is_err(),
            "flip at byte {i} accepted"
        );
    }
}

#[test]
fn forged_signatures_are_refused() {
    // Signed by a different key than the one named.
    let mut r = signed();
    let forger = SigningKey::from_bytes(&[9u8; 32]);
    r.signature = forger.sign(&r.signable_bytes()).to_bytes();
    assert_eq!(r.verify(), Err(ReceiptError::SignatureInvalid));

    // Forger names itself but replays the executor's signature.
    let mut r = signed();
    r.executor_did = encode_did_key_ed25519(&forger.verifying_key().to_bytes());
    assert_eq!(r.verify(), Err(ReceiptError::SignatureInvalid));

    // Zero signature.
    let mut r = signed();
    r.signature = [0; 64];
    assert_eq!(r.verify(), Err(ReceiptError::SignatureInvalid));

    // Executor DID that is not an Ed25519 did:key.
    let mut r = signed();
    r.executor_did = "did:web:example.com".into();
    assert_eq!(r.verify(), Err(ReceiptError::ExecutorDidInvalid));
}

#[test]
fn wrong_domain_is_refused() {
    // Record bytes under another tag.
    let mut bytes = signed().encode().unwrap();
    bytes[..DOMAIN_EVIDENCE_RECEIPT_V1.len()].copy_from_slice(b"SYNAPSE_EVIDENCE_RECEIPT_V2\0");
    assert_eq!(
        EvidenceReceipt::decode(&bytes),
        Err(ReceiptError::WrongDomain)
    );
    assert_eq!(
        EvidenceReceipt::decode(b"SYN"),
        Err(ReceiptError::WrongDomain)
    );

    // A signature the executor made over the same content under another domain (the
    // changeset signing tag) does not verify as a receipt signature.
    let key = executor();
    let mut r = signed();
    let mut cross = r.signable_bytes();
    cross.splice(
        ..DOMAIN_EVIDENCE_RECEIPT_SIGN_V1.len(),
        DOMAIN_CHANGESET_SIGN_V1.iter().copied(),
    );
    r.signature = key.sign(&cross).to_bytes();
    assert_eq!(r.verify(), Err(ReceiptError::SignatureInvalid));
}

#[test]
fn unknown_version_is_refused() {
    let r = signed();
    let mut bytes = r.encode().unwrap();
    let at = DOMAIN_EVIDENCE_RECEIPT_V1.len();
    bytes[at..at + 2].copy_from_slice(&2u16.to_le_bytes());
    assert_eq!(
        EvidenceReceipt::decode(&bytes),
        Err(ReceiptError::UnknownVersion(2))
    );

    let mut r2 = r.clone();
    r2.record_version = 2;
    assert_eq!(r2.verify(), Err(ReceiptError::UnknownVersion(2)));
    // Even when re-signed by the executor under version 2.
    r2.signature = executor().sign(&r2.signable_bytes()).to_bytes();
    assert_eq!(r2.verify(), Err(ReceiptError::UnknownVersion(2)));
}

#[test]
fn flaky_and_error_never_count_as_pass() {
    assert!(Outcome::Pass.is_pass());
    assert!(!Outcome::Fail.is_pass());
    assert!(!Outcome::Flaky.is_pass());
    assert!(!Outcome::Error.is_pass());

    // A Flaky run that exited 0 is still not a pass and has a different identity from Pass.
    let mut b = body();
    b.result.outcome = Outcome::Flaky;
    let flaky = EvidenceReceipt::sign(b, &executor()).unwrap();
    assert!(!flaky.body.result.outcome.is_pass());
    assert_ne!(flaky.result_digest(), signed().result_digest());
    assert_ne!(flaky.id(), signed().id());
}

#[test]
fn outcome_must_agree_with_exit_status() {
    let mut b = body();
    b.result.exit_status = ExitStatus::Code(1);
    assert_eq!(
        EvidenceReceipt::sign(b, &executor()),
        Err(ReceiptError::OutcomeInconsistent)
    );
    let mut b = body();
    b.result.exit_status = ExitStatus::Signal(9);
    assert_eq!(
        EvidenceReceipt::sign(b, &executor()),
        Err(ReceiptError::OutcomeInconsistent)
    );
    let mut b = body();
    b.result.outcome = Outcome::Fail;
    assert_eq!(
        EvidenceReceipt::sign(b, &executor()),
        Err(ReceiptError::OutcomeInconsistent)
    );
}

#[test]
fn identity_excludes_logs_and_timings() {
    let a = signed();
    let mut b2 = body();
    b2.observation = Observation {
        started_at_ms: 9_999_999,
        duration_ms: 1,
        log: b"completely different log, other timings\n".to_vec(),
    };
    let b = EvidenceReceipt::sign(b2, &executor()).unwrap();
    // Both verify, carry different observations, and share one identity.
    let ida = a.verify().unwrap();
    let idb = b.verify().unwrap();
    assert_ne!(a.encode().unwrap(), b.encode().unwrap());
    assert_eq!(a.result_digest(), b.result_digest());
    assert_eq!(a.body.action_digest(), b.body.action_digest());
    assert_eq!(ida, idb);

    // The deterministic part does move the identity.
    let mut b3 = body();
    b3.result.outputs[1].digest = OutputDigest::of_bytes(b"one fail");
    let c = EvidenceReceipt::sign(b3, &executor()).unwrap();
    assert_ne!(c.result_digest(), a.result_digest());
    assert_ne!(c.id(), ida);
    let mut b4 = body();
    b4.result.exit_status = ExitStatus::Code(3);
    b4.result.outcome = Outcome::Error;
    assert_ne!(EvidenceReceipt::sign(b4, &executor()).unwrap().id(), ida);
    // So do the action (context seen) and the executor.
    let mut b5 = body();
    b5.crumb_contexts[0].at_base = CrumbContextDigest([0; 32]);
    assert_ne!(EvidenceReceipt::sign(b5, &executor()).unwrap().id(), ida);
    let mut b6 = body();
    b6.crumb_contexts[0].in_changeset = CrumbContextDigest([0; 32]);
    assert_ne!(EvidenceReceipt::sign(b6, &executor()).unwrap().id(), ida);
    let other = SigningKey::from_bytes(&[11u8; 32]);
    assert_ne!(EvidenceReceipt::sign(body(), &other).unwrap().id(), ida);
}

#[test]
fn digest_types_and_tags_are_distinct() {
    let tags: [&[u8]; 7] = [
        DOMAIN_EVIDENCE_RECEIPT_V1,
        DOMAIN_EVIDENCE_RECEIPT_SIGN_V1,
        DOMAIN_EVIDENCE_RECEIPT_ID_V1,
        DOMAIN_EVIDENCE_ACTION_V1,
        DOMAIN_EVIDENCE_RESULT_V1,
        DOMAIN_EVIDENCE_INPUT_ROOT_V1,
        DOMAIN_EVIDENCE_OUTPUT_V1,
    ];
    let others: [&[u8]; 4] = [
        synapse_core::DOMAIN_BLOB_V1,
        synapse_core::DOMAIN_CHANGESET_ID_V1,
        synapse_core::DOMAIN_CHANGESET_SIGN_V1,
        synapse_crumb::DOMAIN_CRUMB_CONTEXT_V1,
    ];
    for (i, t) in tags.iter().enumerate() {
        assert!(t.ends_with(b"\0"));
        for u in tags.iter().skip(i + 1) {
            assert_ne!(t, u);
        }
        for o in others {
            assert_ne!(*t, o);
        }
    }
    // Same 32 bytes under OutputDigest and BlobDigest differ.
    assert_ne!(
        OutputDigest::of_bytes(b"x").0,
        synapse_core::BlobDigest::compute(b"x").0
    );
}

#[test]
fn structural_rules_are_enforced() {
    let k = executor();
    let mut b = body();
    b.crumb_contexts.reverse();
    assert_eq!(
        EvidenceReceipt::sign(b, &k),
        Err(ReceiptError::Unsorted("crumb_contexts"))
    );
    let mut b = body();
    b.crumb_contexts.clear();
    assert_eq!(
        EvidenceReceipt::sign(b, &k),
        Err(ReceiptError::Empty("crumb_contexts"))
    );
    let mut b = body();
    b.crumb_contexts[1].dir = "../etc".into();
    assert!(matches!(
        EvidenceReceipt::sign(b, &k),
        Err(ReceiptError::InvalidPath(_))
    ));
    let mut b = body();
    b.input_root.members[0].changeset_id = ChangesetId([5; 32]);
    assert_eq!(
        EvidenceReceipt::sign(b, &k),
        Err(ReceiptError::InputRootMismatch)
    );
    let mut b = body();
    let extra = b.input_root.members[0].clone();
    b.input_root.members.push(extra);
    assert_eq!(
        EvidenceReceipt::sign(b, &k),
        Err(ReceiptError::InputRootUnsupported(2))
    );
    let mut b = body();
    b.result.outputs.reverse();
    assert_eq!(
        EvidenceReceipt::sign(b, &k),
        Err(ReceiptError::Unsorted("result.outputs"))
    );
    let mut b = body();
    b.observation.log = vec![0; MAX_LOG_BYTES + 1];
    assert_eq!(
        EvidenceReceipt::sign(b, &k),
        Err(ReceiptError::OverCap("observation.log"))
    );
}

#[test]
fn malformed_bytes_are_refused_without_panic() {
    let bytes = signed().encode().unwrap();
    for n in 0..bytes.len() {
        assert!(EvidenceReceipt::decode(&bytes[..n]).is_err(), "prefix {n}");
    }
    let mut long = bytes.clone();
    long.push(0);
    assert_eq!(
        EvidenceReceipt::decode(&long),
        Err(ReceiptError::TrailingBytes)
    );
    // A huge declared length is refused by its cap before any allocation.
    let mut huge = DOMAIN_EVIDENCE_RECEIPT_V1.to_vec();
    huge.extend_from_slice(&1u16.to_le_bytes());
    huge.extend_from_slice(&u32::MAX.to_le_bytes());
    assert_eq!(
        EvidenceReceipt::decode(&huge),
        Err(ReceiptError::OverCap("repo_id"))
    );
}

#[test]
fn executor_did_must_be_canonical() {
    // Same key, same body, DID spelled as a bare multibase key: refused even when re-signed,
    // so one key has one spelling and one receipt identity.
    let mut r = signed();
    r.executor_did = r.executor_did.strip_prefix("did:key:").unwrap().to_string();
    r.signature = executor().sign(&r.signable_bytes()).to_bytes();
    assert_eq!(r.verify(), Err(ReceiptError::ExecutorDidInvalid));
}

#[test]
fn encode_refuses_what_validate_refuses() {
    // A record built by hand with more items than a u32-prefixed list may carry under v1 is
    // refused, not written with a silently truncated count.
    let mut r = signed();
    r.body.source.parent_changesets = (0..=MAX_LIST_ITEMS as u32)
        .map(|i| {
            let mut id = [0u8; 32];
            id[..4].copy_from_slice(&i.to_be_bytes());
            ChangesetId(id)
        })
        .collect();
    assert_eq!(
        r.encode(),
        Err(ReceiptError::OverCap("source.parent_changesets"))
    );
    let mut r = signed();
    r.record_version = 2;
    assert_eq!(r.encode(), Err(ReceiptError::UnknownVersion(2)));
}

#[test]
fn total_record_size_is_capped() {
    // Decode refuses an oversized record before reading any field, even with a valid prefix.
    let mut big = signed().encode().unwrap();
    big.resize(MAX_RECEIPT_BYTES + 1, 0);
    assert_eq!(
        EvidenceReceipt::decode(&big),
        Err(ReceiptError::OverCap("receipt"))
    );
    // A body whose every field is within its own cap but whose record is over the total cap
    // is refused at signing and at encoding.
    let mut b = body();
    b.observation.log = vec![b'x'; MAX_LOG_BYTES];
    b.test.command = (0..300)
        .map(|i| format!("{i:04}{}", "a".repeat(4000)))
        .collect();
    assert_eq!(
        EvidenceReceipt::sign(b.clone(), &executor()),
        Err(ReceiptError::OverCap("receipt"))
    );
    let mut r = signed();
    r.body = b;
    assert_eq!(r.encode(), Err(ReceiptError::OverCap("receipt")));
    // The largest log that fits still round-trips.
    let mut b = body();
    b.observation.log = vec![b'x'; MAX_LOG_BYTES];
    let r = EvidenceReceipt::sign(b, &executor()).unwrap();
    assert_eq!(
        EvidenceReceipt::decode_verified(&r.encode().unwrap())
            .unwrap()
            .0,
        r
    );
}
