//! ADR 0003 step B5: `DerivationAttestation` for server-derived revisions, through the service
//! with the C1 tree store and the E0 identity log.
//!
//! Acceptance (ADR 0003 section 9, row 9):
//! * a replica recomputes every derived revision from the inputs and rule its attestation names
//!   and gets the same digests
//!   (`b5_replica_recomputes_every_derived_revision_and_gets_the_same_digests`);
//! * an attestation naming different inputs, a different rule, or an unregistered server key is
//!   refused at admission and at replay
//!   (`b5_attestation_naming_different_inputs_is_refused_at_admission_and_replay`,
//!   `b5_attestation_naming_a_different_rule_is_refused_at_admission_and_replay`,
//!   `b5_unregistered_server_key_is_refused_at_admission_and_replay`);
//! * a derived revision presented with an agent signature it does not have is refused
//!   (`b5_derived_revision_presented_with_an_agent_signature_it_does_not_have_is_refused`).
//!
//! Also: a signature by another key, a replayed attestation, and a recomputation that disagrees.
//!
//! Keys, idempotency keys, change ids and chain digests are derived from labels (`label`), so
//! no literal value is used as key material.

use ed25519_dalek::SigningKey;
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use synapse_api::{SynapseService, TreeTarget};
use synapse_core::{
    BlobDigest, ChainPath, ChangeId, ChangesetEnvelopeV2, ChangesetId, DerivationAttestation,
    DerivationInput, DerivationRule, DerivedRevision, FileMode, GitOid, IdempotencyKey, MergeTier,
    MutationOp, PathMutation, RefusalCode, RepoId, RevisionContent, TreeDigest, WalSeq,
    WitnessSigner,
};
use synapse_radicle::{
    IdentityDocumentDigest, IdentityEdit, IdentityLog, RepositoryIdentityDocument,
};
use synapse_store::{
    AdmissionAuthority, FsyncPolicy, RecoveryPolicy, RevisionOutcome, StoreLimits, WalRecord,
};

const NOW: u64 = 5_000;
const T0: DerivationRule = DerivationRule::Merge {
    tier: MergeTier::T0Path,
};

/// Base `B0`: README.md, docs/x.md, src/a.rs. `B1`: `B0` with docs/x.md changed.
const B0: GitOid = GitOid([0xB0; 20]);
const B1: GitOid = GitOid([0xB1; 20]);
/// Independent expectations: `B1` with src/a.rs = "a1" (the rebase of `ra` onto `B1`) and `B0`
/// with src/a.rs = "a1" and src/b.rs = "b1" (the T0 merge of `ra` and `rb`).
const B1_REBASED_A: GitOid = GitOid([0xE1; 20]);
const B0_MERGED_AB: GitOid = GitOid([0xE2; 20]);

fn repo() -> RepoId {
    RepoId::new("aien-spark/synapse").unwrap()
}

/// 32 bytes derived from a label.
fn label(s: &str) -> [u8; 32] {
    Sha256::digest(format!("synapse b5 test: {s}").as_bytes()).into()
}

fn key(s: &str) -> SigningKey {
    SigningKey::from_bytes(&label(&format!("key {s}")))
}

fn change(s: &str) -> ChangeId {
    let mut id = [0u8; 16];
    id.copy_from_slice(&label(&format!("change {s}"))[..16]);
    ChangeId(id)
}

fn authority(s: &str) -> AdmissionAuthority {
    AdmissionAuthority {
        chain: ChainPath::new(vec![label(&format!("chain {s}"))]).unwrap(),
        change_scope: vec![],
    }
}

fn pk(k: &SigningKey) -> [u8; 32] {
    k.verifying_key().to_bytes()
}

fn files(x: &[u8], a: &[u8], b: Option<&[u8]>) -> Vec<(String, FileMode, Vec<u8>)> {
    let mut f = vec![
        (
            "README.md".to_string(),
            FileMode::Regular644,
            b"base".to_vec(),
        ),
        ("docs/x.md".to_string(), FileMode::Regular644, x.to_vec()),
        ("src/a.rs".to_string(), FileMode::Regular644, a.to_vec()),
    ];
    if let Some(b) = b {
        f.push(("src/b.rs".to_string(), FileMode::Regular644, b.to_vec()));
    }
    f
}

fn open(dir: &Path) -> SynapseService {
    let mut svc = SynapseService::open(
        dir,
        repo(),
        FsyncPolicy::EveryCommit,
        RecoveryPolicy::StrictFailClosed,
        StoreLimits {
            wal_prealloc_bytes: 64 * 1024,
            ..Default::default()
        },
    )
    .unwrap();
    svc.register_base_tree(B0, files(b"x0", b"a0", None))
        .unwrap();
    svc.register_base_tree(B1, files(b"x1", b"a0", None))
        .unwrap();
    svc.register_base_tree(B1_REBASED_A, files(b"x1", b"a1", None))
        .unwrap();
    svc.register_base_tree(B0_MERGED_AB, files(b"x0", b"a1", Some(b"b1")))
        .unwrap();
    svc
}

fn upsert(path: &str, body: &[u8]) -> PathMutation {
    PathMutation {
        path: path.into(),
        op: MutationOp::Upsert {
            mode: FileMode::Regular644,
            blob_digest: BlobDigest::compute(body),
            size_bytes: body.len() as u64,
        },
    }
}

fn agent_revision(s: &str, base: TreeDigest, path: &str, body: &[u8]) -> ChangesetEnvelopeV2 {
    let content = RevisionContent {
        change_id: change(s),
        base_tree: base,
        parents: vec![],
        mutations: vec![upsert(path, body)],
        intent_summary: format!("agent revision {s}"),
    };
    ChangesetEnvelopeV2::sign_new(
        &key(&format!("agent {s}")),
        repo(),
        content,
        IdempotencyKey(label(&format!("idempotency {s}"))),
        NOW,
    )
}

/// Re-sign `content` as `signer`, naming `rule`, `inputs` and `tree`.
fn forge(
    signer: &SigningKey,
    content: RevisionContent,
    rule: DerivationRule,
    inputs: Vec<DerivationInput>,
    tree: TreeDigest,
) -> DerivedRevision {
    let attestation =
        DerivationAttestation::sign(signer, repo(), rule, inputs, content.changeset_id(), tree);
    DerivedRevision {
        content,
        attestation,
    }
}

/// A derived record holding `derived`, as a lying server would have written it.
fn derived_record(derived: DerivedRevision) -> WalRecord {
    WalRecord::DerivedRevisionAdmitted {
        derived,
        chain: authority("a").chain,
        admitted_at_ms: NOW,
    }
}

struct Fx {
    dir: PathBuf,
    svc: SynapseService,
    server: SigningKey,
    keys: IdentityLog,
    delegates: [SigningKey; 2],
    b0: TreeDigest,
    b1: TreeDigest,
    /// `ra` upserts src/a.rs, `rb` adds src/b.rs, `rc` upserts docs/x.md; all on `B0`.
    ra: ChangesetEnvelopeV2,
    rb: ChangesetEnvelopeV2,
    rc: ChangesetEnvelopeV2,
}

impl Fx {
    fn new(name: &str) -> Self {
        let dir: PathBuf = std::env::temp_dir().join(format!(
            "synapse-b5-{name}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let mut svc = open(&dir);
        let b0 = svc
            .tree_digest(TreeTarget::BaseGitCommit(B0), None)
            .unwrap();
        let b1 = svc
            .tree_digest(TreeTarget::BaseGitCommit(B1), None)
            .unwrap();
        let server = key("server");
        let delegates = [key("delegate 1"), key("delegate 2")];
        let mut ds = vec![pk(&delegates[0]), pk(&delegates[1])];
        ds.sort();
        let genesis = RepositoryIdentityDocument {
            repo_id: repo(),
            revision: 0,
            prev: IdentityDocumentDigest::ZERO,
            threshold: 2,
            delegates: ds,
            executors: vec![],
            server_key: pk(&server),
        };
        let edit = IdentityEdit::sign(genesis, &[&delegates[0], &delegates[1]]);
        let keys = IdentityLog::genesis(&edit, WalSeq(0)).unwrap();
        let ra = agent_revision("a", b0, "src/a.rs", b"a1");
        let rb = agent_revision("b", b0, "src/b.rs", b"b1");
        let rc = agent_revision("c", b0, "docs/x.md", b"xc");
        for (env, who, body) in [
            (&ra, "a", b"a1".as_slice()),
            (&rb, "b", b"b1".as_slice()),
            (&rc, "c", b"xc".as_slice()),
        ] {
            let out = svc
                .store_mut()
                .admit_revision(
                    env.clone(),
                    &[(BlobDigest::compute(body), body.to_vec())],
                    authority(who),
                    NOW,
                )
                .unwrap();
            assert!(matches!(out, RevisionOutcome::Admitted { .. }));
        }
        Self {
            dir,
            svc,
            server,
            keys,
            delegates,
            b0,
            b1,
            ra,
            rb,
            rc,
        }
    }

    fn derive(&mut self, rule: DerivationRule, inputs: Vec<DerivationInput>) -> DerivedRevision {
        let server = self.server.clone();
        self.svc.derive_revision(&server, rule, inputs).unwrap()
    }

    fn rebase_inputs(&self, of: &ChangesetEnvelopeV2) -> Vec<DerivationInput> {
        vec![
            DerivationInput::Revision(of.changeset_id()),
            DerivationInput::Tree(self.b1),
        ]
    }

    /// The honest rebase of `ra` onto `B1`.
    fn rebase_a(&mut self) -> DerivedRevision {
        let inputs = self.rebase_inputs(&self.ra);
        self.derive(DerivationRule::Rebase, inputs)
    }

    /// The honest T0 merge of `ra` and `rb` on `B0`, inputs in the canonical merge order.
    fn merge_ab(&mut self) -> DerivedRevision {
        let mut ids = vec![self.ra.changeset_id(), self.rb.changeset_id()];
        ids.sort();
        let mut inputs = vec![DerivationInput::Tree(self.b0)];
        inputs.extend(ids.into_iter().map(DerivationInput::Revision));
        self.derive(T0, inputs)
    }

    fn admit(&mut self, derived: DerivedRevision, who: &str) -> Result<WalSeq, RefusalCode> {
        let keys = self.keys.clone();
        match self
            .svc
            .admit_derived_revision(derived, authority(who), &keys, NOW)
        {
            Ok(RevisionOutcome::Admitted { wal_seq, .. }) => Ok(wal_seq),
            Ok(other) => panic!("unexpected outcome {other:?}"),
            Err(e) => Err(e.code),
        }
    }

    /// Admit `derived` and expect `code`, with nothing written.
    fn refused_at_admission(&mut self, derived: DerivedRevision, code: RefusalCode) {
        let before = self.svc.store().committed_seq();
        assert_eq!(self.admit(derived, "a"), Err(code), "refused at admission");
        assert_eq!(self.svc.store().committed_seq(), before, "nothing written");
    }

    fn records(&self) -> Vec<(WalSeq, WalRecord)> {
        self.svc.store().revision_records().to_vec()
    }

    /// The store's revision records with the record at `seq` replaced by `record`.
    fn records_with(&self, seq: WalSeq, record: WalRecord) -> Vec<(WalSeq, WalRecord)> {
        let mut records = self.records();
        let slot = records.iter_mut().find(|(s, _)| *s == seq).unwrap();
        slot.1 = record;
        records
    }

    fn verify(&mut self, records: &[(WalSeq, WalRecord)]) -> Result<usize, RefusalCode> {
        let keys = self.keys.clone();
        self.svc
            .verify_revision_records(records, &keys)
            .map_err(|e| e.code)
    }

    /// Refused at admission, and refused at replay when a record carrying `forged` replaces
    /// the honest derived record at `honest_seq`.
    fn refused_at_admission_and_replay(
        &mut self,
        honest_seq: WalSeq,
        forged: DerivedRevision,
        code: RefusalCode,
    ) {
        self.refused_at_admission(forged.clone(), code);
        let records = self.records_with(honest_seq, derived_record(forged));
        assert_eq!(self.verify(&records), Err(code), "refused at replay");
    }
}

#[test]
fn b5_replica_recomputes_every_derived_revision_and_gets_the_same_digests() {
    let mut fx = Fx::new("recompute");
    let rebase = fx.rebase_a();
    let merge = fx.merge_ab();
    // The derived trees equal independently built trees.
    let rebased_tree = fx
        .svc
        .tree_digest(TreeTarget::BaseGitCommit(B1_REBASED_A), None)
        .unwrap();
    let merged_tree = fx
        .svc
        .tree_digest(TreeTarget::BaseGitCommit(B0_MERGED_AB), None)
        .unwrap();
    assert_eq!(rebase.attestation.output_tree, rebased_tree);
    assert_eq!(merge.attestation.output_tree, merged_tree);
    // A rebase keeps the change, parents, mutations and intent; only the base moves.
    assert_eq!(rebase.content.change_id, fx.ra.content.change_id);
    assert_eq!(rebase.content.base_tree, fx.b1);
    assert_eq!(rebase.content.mutations, fx.ra.content.mutations);
    assert_eq!(rebase.content.intent_summary, fx.ra.content.intent_summary);
    // A merge's parents are the merged revisions in the canonical order.
    let mut parents = vec![fx.ra.changeset_id(), fx.rb.changeset_id()];
    parents.sort();
    assert_eq!(merge.content.parents, parents);
    assert_eq!(merge.content.base_tree, fx.b0);
    assert_eq!(merge.content.mutations.len(), 2);

    let s_rebase = fx.admit(rebase.clone(), "a").unwrap();
    let s_merge = fx.admit(merge.clone(), "merge").unwrap();
    assert!(s_rebase < s_merge);
    // The witness names the server key and the attestation; no agent signature is claimed.
    for d in [&rebase, &merge] {
        let stored = fx
            .svc
            .store()
            .get_revision(&repo(), d.changeset_id())
            .unwrap();
        assert!(stored.attestations.is_empty(), "no authorship attestation");
        assert_eq!(stored.derivations, vec![d.attestation.clone()]);
        assert_eq!(stored.witnesses.len(), 1);
        assert_eq!(
            stored.witnesses[0].signer,
            WitnessSigner::Server {
                server_key: pk(&fx.server),
                signature: d.attestation.signature,
                attestation_digest: d.attestation.digest(),
            }
        );
    }
    let live = fx.records();
    assert_eq!(fx.verify(&live), Ok(5), "3 agent and 2 derived revisions");

    // A replica: reopen from the WAL (base trees registered again), recompute everything.
    let Fx {
        dir,
        svc,
        keys,
        server,
        ..
    } = fx;
    drop(svc);
    let mut replica = open(&dir);
    assert_eq!(replica.store().revision_records(), live.as_slice());
    assert_eq!(replica.verify_revision_log(&keys).unwrap(), 5);
    // Recomputing on the replica gives byte-identical revisions and attestations.
    let again = replica
        .derive_revision(
            &server,
            DerivationRule::Rebase,
            rebase.attestation.inputs.clone(),
        )
        .unwrap();
    assert_eq!(again, rebase);
    let again = replica
        .derive_revision(&server, T0, merge.attestation.inputs.clone())
        .unwrap();
    assert_eq!(again, merge);
    // Through a checkpoint (which keeps revision records) and another reopen.
    replica.store_mut().checkpoint_and_compact(NOW).unwrap();
    drop(replica);
    let mut replica = open(&dir);
    assert_eq!(replica.store().revision_records(), live.as_slice());
    assert_eq!(replica.verify_revision_log(&keys).unwrap(), 5);
}

#[test]
fn b5_attestation_naming_different_inputs_is_refused_at_admission_and_replay() {
    let mut fx = Fx::new("inputs");
    let honest = fx.rebase_a();
    let at = fx.admit(honest.clone(), "a").unwrap();
    let rule = DerivationRule::Rebase;
    let tree = honest.attestation.output_tree;
    // The same output, attributed to another real revision (`rb` rebased onto `B1` is not it).
    let other = fx.rebase_inputs(&fx.rb);
    let forged = forge(&fx.server, honest.content.clone(), rule, other, tree);
    fx.refused_at_admission_and_replay(at, forged, RefusalCode::DerivationRecomputeMismatch);
    // Attributed to a revision nobody admitted.
    let unknown = vec![
        DerivationInput::Revision(ChangesetId(label("unknown revision"))),
        DerivationInput::Tree(fx.b1),
    ];
    let forged = forge(&fx.server, honest.content.clone(), rule, unknown, tree);
    fx.refused_at_admission_and_replay(at, forged, RefusalCode::DerivationInputMismatch);
    // Onto a tree nobody holds.
    let nowhere = vec![
        DerivationInput::Revision(fx.ra.changeset_id()),
        DerivationInput::Tree(TreeDigest(label("unknown tree"))),
    ];
    let forged = forge(&fx.server, honest.content.clone(), rule, nowhere, tree);
    fx.refused_at_admission_and_replay(at, forged, RefusalCode::DerivationInputMismatch);
    // The honest record still verifies.
    let live = fx.records();
    assert_eq!(fx.verify(&live), Ok(4));
}

#[test]
fn b5_attestation_naming_a_different_rule_is_refused_at_admission_and_replay() {
    let mut fx = Fx::new("rule");
    let merge = fx.merge_ab();
    let at = fx.admit(merge.clone(), "merge").unwrap();
    let tree = merge.attestation.output_tree;
    // The merge's own inputs under the rebase rule.
    let forged = forge(
        &fx.server,
        merge.content.clone(),
        DerivationRule::Rebase,
        merge.attestation.inputs.clone(),
        tree,
    );
    fx.refused_at_admission_and_replay(at, forged, RefusalCode::DerivationInputMismatch);
    // The merge's output claimed as a rebase of its first input onto its own base (no move).
    let as_rebase = vec![
        DerivationInput::Revision(merge.content.parents[0]),
        DerivationInput::Tree(fx.b0),
    ];
    let forged = forge(
        &fx.server,
        merge.content.clone(),
        DerivationRule::Rebase,
        as_rebase,
        tree,
    );
    fx.refused_at_admission_and_replay(at, forged, RefusalCode::DerivationRecomputeMismatch);
    // A rebase's output and inputs claimed as a T0 merge.
    let rebase = fx.rebase_a();
    let forged = forge(
        &fx.server,
        rebase.content.clone(),
        T0,
        rebase.attestation.inputs.clone(),
        rebase.attestation.output_tree,
    );
    fx.refused_at_admission(forged, RefusalCode::DerivationInputMismatch);
    let live = fx.records();
    assert_eq!(fx.verify(&live), Ok(4));
}

#[test]
fn b5_unregistered_server_key_is_refused_at_admission_and_replay() {
    let mut fx = Fx::new("unregistered");
    let honest = fx.rebase_a();
    let at = fx.admit(honest.clone(), "a").unwrap();
    // A correctly computed and validly signed derivation by a key the identity document does
    // not register as `server_key` (a delegate's key is not a server key either).
    for signer in [key("rogue server"), fx.delegates[0].clone()] {
        let a = &honest.attestation;
        let forged = forge(
            &signer,
            honest.content.clone(),
            a.rule,
            a.inputs.clone(),
            a.output_tree,
        );
        assert_eq!(forged.attestation.server_key, pk(&signer));
        fx.refused_at_admission_and_replay(
            at,
            forged,
            RefusalCode::DerivationServerKeyUnregistered,
        );
    }

    // Rotation: from the next sequence the document names `s2`. The derivation admitted
    // before still verifies at its own sequence; the old key is refused after it.
    let s2 = key("server 2");
    let rotate_at = fx.svc.store().committed_seq().next();
    let mut next = fx.keys.current().successor();
    next.server_key = pk(&s2);
    let edit = IdentityEdit::sign(next, &[&fx.delegates[0], &fx.delegates[1]]);
    fx.keys.apply(&edit, rotate_at).unwrap();
    let merge = fx.merge_ab();
    assert_eq!(merge.attestation.server_key, pk(&fx.server));
    fx.refused_at_admission(merge.clone(), RefusalCode::DerivationServerKeyUnregistered);
    let a = &merge.attestation;
    let by_s2 = forge(
        &s2,
        merge.content.clone(),
        a.rule,
        a.inputs.clone(),
        a.output_tree,
    );
    let s_merge = fx.admit(by_s2, "merge").unwrap();
    assert!(s_merge >= rotate_at);
    let live = fx.records();
    assert_eq!(fx.verify(&live), Ok(5), "each verifies at its own sequence");
    // At replay, the old key's merge in place of the new key's is refused.
    let records = fx.records_with(s_merge, derived_record(merge));
    assert_eq!(
        fx.verify(&records),
        Err(RefusalCode::DerivationServerKeyUnregistered)
    );
}

#[test]
fn b5_attestation_signed_by_another_key_is_refused_at_admission_and_replay() {
    let mut fx = Fx::new("signature");
    let honest = fx.rebase_a();
    let at = fx.admit(honest.clone(), "a").unwrap();
    // Signed by a rogue key while naming the registered server key.
    let a = &honest.attestation;
    let mut forged = forge(
        &key("rogue server"),
        honest.content.clone(),
        a.rule,
        a.inputs.clone(),
        a.output_tree,
    );
    forged.attestation.server_key = pk(&fx.server);
    fx.refused_at_admission_and_replay(at, forged, RefusalCode::DerivationSignatureInvalid);
    // The registered key's attestation presented with content it does not name.
    let mut swapped = honest.clone();
    swapped.content.intent_summary = "a different intent".into();
    fx.refused_at_admission_and_replay(at, swapped, RefusalCode::DerivationSignatureInvalid);
    // A field changed after signing.
    let mut tampered = honest.clone();
    tampered.attestation.output_tree = fx.b0;
    fx.refused_at_admission_and_replay(at, tampered, RefusalCode::DerivationSignatureInvalid);
}

#[test]
fn b5_derived_revision_presented_with_an_agent_signature_it_does_not_have_is_refused() {
    let mut fx = Fx::new("agent-signature");
    let derived = fx.rebase_a();
    // `ra`'s author never signed the rebased content: its attestation as is, or re-pointed at
    // the derived revision, is refused.
    let mut repointed = fx.ra.attestation.clone();
    repointed.changeset_id = derived.changeset_id();
    let borrowed: Vec<ChangesetEnvelopeV2> = [fx.ra.attestation.clone(), repointed]
        .into_iter()
        .map(|attestation| ChangesetEnvelopeV2 {
            content: derived.content.clone(),
            attestation,
        })
        .collect();
    let body = b"a1";
    for env in &borrowed {
        let before = fx.svc.store().committed_seq();
        let err = fx
            .svc
            .store_mut()
            .admit_revision(
                env.clone(),
                &[(BlobDigest::compute(body), body.to_vec())],
                authority("a"),
                NOW,
            )
            .unwrap_err();
        assert_eq!(err.code, RefusalCode::AuthSignatureInvalid);
        assert_eq!(fx.svc.store().committed_seq(), before, "nothing written");
    }
    // At replay: a revision record carrying a borrowed signature in place of the derived
    // record is refused.
    let at = fx.admit(derived.clone(), "a").unwrap();
    for env in borrowed {
        let record = WalRecord::RevisionAdmitted {
            envelope: env,
            chain: authority("a").chain,
            admitted_at_ms: NOW,
            new_blobs: vec![],
        };
        let records = fx.records_with(at, record);
        assert_eq!(fx.verify(&records), Err(RefusalCode::AuthSignatureInvalid));
    }
    // The stored revision claims no agent signature.
    let stored = fx
        .svc
        .store()
        .get_revision(&repo(), derived.changeset_id())
        .unwrap();
    assert!(stored.attestations.is_empty());
}

#[test]
fn b5_replayed_attestation_is_refused_at_admission_and_replay() {
    let mut fx = Fx::new("replayed");
    let honest = fx.rebase_a();
    let at = fx.admit(honest.clone(), "a").unwrap();
    // The same attestation presented again, under the same or another chain.
    fx.refused_at_admission(honest.clone(), RefusalCode::DerivationAttestationReplayed);
    let before = fx.svc.store().committed_seq();
    assert_eq!(
        fx.admit(honest.clone(), "b"),
        Err(RefusalCode::DerivationAttestationReplayed)
    );
    assert_eq!(fx.svc.store().committed_seq(), before);
    // At replay: the record duplicated at a later sequence is refused.
    let mut records = fx.records();
    let dup = records.iter().find(|(s, _)| *s == at).unwrap().1.clone();
    records.push((before.next(), dup));
    assert_eq!(
        fx.verify(&records),
        Err(RefusalCode::DerivationAttestationReplayed)
    );
}

#[test]
fn b5_recomputation_that_disagrees_is_refused_at_admission_and_replay() {
    let mut fx = Fx::new("disagree");
    let honest = fx.rebase_a();
    let at = fx.admit(honest.clone(), "a").unwrap();
    let a = honest.attestation.clone();
    // The right inputs and rule with a wrong output tree (the independently built merge tree).
    let wrong_tree = fx
        .svc
        .tree_digest(TreeTarget::BaseGitCommit(B0_MERGED_AB), None)
        .unwrap();
    let forged = forge(
        &fx.server,
        honest.content.clone(),
        a.rule,
        a.inputs.clone(),
        wrong_tree,
    );
    fx.refused_at_admission_and_replay(at, forged, RefusalCode::DerivationRecomputeMismatch);
    // The right inputs and rule with other content (an extra mutation the rule never makes).
    let mut content = honest.content.clone();
    content.mutations.push(upsert("src/z.rs", b"a1"));
    let forged = forge(&fx.server, content, a.rule, a.inputs.clone(), a.output_tree);
    fx.refused_at_admission_and_replay(at, forged, RefusalCode::DerivationRecomputeMismatch);
    // `rc` changed docs/x.md, which `B1` also changed: the rebase conflicts and cannot be
    // derived, so no attestation of it is produced.
    let inputs = fx.rebase_inputs(&fx.rc);
    let server = fx.server.clone();
    let err = fx
        .svc
        .derive_revision(&server, DerivationRule::Rebase, inputs)
        .unwrap_err();
    assert_eq!(err.code, RefusalCode::DerivationRecomputeMismatch);
    let live = fx.records();
    assert_eq!(fx.verify(&live), Ok(4));
}
