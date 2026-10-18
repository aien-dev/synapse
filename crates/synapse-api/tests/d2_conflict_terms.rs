//! ADR 0003 step D2 through the service: rebases that collide are derived with first-class
//! conflict terms, admitted, replayed and recomputed; rebasing twice cancels to a plain
//! three-way conflict; reverting returns a clean tree; conflicted trees refuse materialization
//! and promotion.
//!
//! Base `B0`: `src/lib.rs` (v0), `README.md`, `notes` (a file), `tool.sh` (regular). Revision
//! `c` on `B0` changes all four: new `src/lib.rs` and `README.md` and `notes` content, and
//! `tool.sh` made executable. `B1` changes `src/lib.rs` (b1), deletes `README.md`, replaces the
//! file `notes` with a directory `notes/`, and makes `tool.sh` a symlink. `B2` is `B1` with
//! `src/lib.rs` b2. Rebasing `c` onto `B1` meets every typed conflict once.

use ed25519_dalek::SigningKey;
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use synapse_api::{SynapseService, TreeTarget};
use synapse_auth::{
    Capability, CapabilityChain, CapabilityLink, ChainQuotas, ChangeScope, LinkCaveats,
    OperationSet, PathScope, ReferenceScope, SignedStateMove, ROOT_PARENT,
};
use synapse_core::{
    reduce, BlobDigest, ChainPath, ChangeId, ChangesetEnvelope, ChangesetEnvelopeV2, ChangesetId,
    ConflictKind, ConflictTerm, DerivationInput, DerivationRule, DerivedRevision, EntryState,
    FileMode, GitOid, IdempotencyKey, MergeTier, MutationOp, PathMutation, Reduced, RefusalCode,
    RepoId, RevisionContent, RevisionState, TreeDigest, WalSeq, SYNAPSE_ENVELOPE_VERSION,
};
use synapse_radicle::{
    IdentityDocumentDigest, IdentityEdit, IdentityLog, RepositoryIdentityDocument,
};
use synapse_store::{
    AdmissionAuthority, FsyncPolicy, RecoveryPolicy, RevisionOutcome, StoreLimits,
};

const NOW: u64 = 5_000;
const B0: GitOid = GitOid([0xB0; 20]);
const B1: GitOid = GitOid([0xB1; 20]);
const B2: GitOid = GitOid([0xB2; 20]);

fn repo() -> RepoId {
    RepoId::new("aien-spark/synapse").unwrap()
}

fn label(s: &str) -> [u8; 32] {
    Sha256::digest(format!("synapse d2 test: {s}").as_bytes()).into()
}

fn key(s: &str) -> SigningKey {
    SigningKey::from_bytes(&label(&format!("key {s}")))
}

fn pk(k: &SigningKey) -> [u8; 32] {
    k.verifying_key().to_bytes()
}

fn change(s: &str) -> ChangeId {
    let mut id = [0u8; 16];
    id.copy_from_slice(&label(&format!("change {s}"))[..16]);
    ChangeId(id)
}

fn chain(s: &str) -> CapabilityChain {
    let caveats = LinkCaveats {
        operations: OperationSet::from_capabilities(&[Capability::Read, Capability::Propose]),
        paths: PathScope::whole_repository(),
        references: ReferenceScope::from_kinds(&[]),
        changes: ChangeScope::any(),
        quotas: ChainQuotas {
            max_ops_per_window: 1_000,
            window_duration_ms: 60_000,
            storage_bytes: 1 << 30,
            footprint_paths: 1 << 20,
            max_bytes_per_op: 1 << 20,
        },
        issued_at_ms: 0,
        expires_at_ms: u64::MAX,
    };
    CapabilityChain::new(vec![CapabilityLink::issue(
        &key("authority"),
        ROOT_PARENT,
        label(&format!("nonce {s}")),
        repo(),
        pk(&key(&format!("chain {s}"))),
        caveats,
    )])
}

fn authority(s: &str) -> AdmissionAuthority {
    let links = chain(s).link_digests().iter().map(|d| d.0).collect();
    AdmissionAuthority {
        chain: ChainPath::new(links).unwrap(),
        change_scope: vec![],
    }
}

fn file(mode: FileMode, body: &[u8]) -> EntryState {
    EntryState::File {
        mode,
        blob_digest: BlobDigest::compute(body),
        size_bytes: body.len() as u64,
    }
}

fn regular(body: &[u8]) -> EntryState {
    file(FileMode::Regular644, body)
}

fn three_way(base: EntryState, a: EntryState, b: EntryState) -> ConflictTerm {
    match reduce(vec![a, b], vec![base]).unwrap() {
        Reduced::Conflict(c) => c,
        r => panic!("not a conflict: {r:?}"),
    }
}

type Files = Vec<(String, FileMode, Vec<u8>)>;

/// One path of an agent revision: its new mode and content, or `None` for a delete.
type AgentMutation<'a> = (&'a str, Option<(FileMode, Vec<u8>)>);

fn b0_files() -> Files {
    vec![
        (
            "README.md".into(),
            FileMode::Regular644,
            b"readme\n".to_vec(),
        ),
        ("notes".into(), FileMode::Regular644, b"notes\n".to_vec()),
        ("src/lib.rs".into(), FileMode::Regular644, b"v0\n".to_vec()),
        ("tool.sh".into(), FileMode::Regular644, b"run\n".to_vec()),
    ]
}

fn b1_files(lib: &[u8]) -> Files {
    vec![
        (
            "notes/today.md".into(),
            FileMode::Regular644,
            b"today\n".to_vec(),
        ),
        ("src/lib.rs".into(), FileMode::Regular644, lib.to_vec()),
        ("tool.sh".into(), FileMode::Symlink120000, b"run\n".to_vec()),
    ]
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
    svc.register_base_tree(B0, b0_files()).unwrap();
    svc.register_base_tree(B1, b1_files(b"b1\n")).unwrap();
    svc.register_base_tree(B2, b1_files(b"b2\n")).unwrap();
    svc
}

/// `c`'s changes on `B0`.
fn c_changes() -> Vec<(&'static str, FileMode, &'static [u8])> {
    vec![
        ("README.md", FileMode::Regular644, b"readme c\n"),
        ("notes", FileMode::Regular644, b"notes c\n"),
        ("src/lib.rs", FileMode::Regular644, b"c\n"),
        ("tool.sh", FileMode::Executable755, b"run\n"),
    ]
}

struct Fx {
    dir: PathBuf,
    svc: SynapseService,
    server: SigningKey,
    keys: IdentityLog,
    b: [TreeDigest; 3],
    c: ChangesetId,
}

impl Fx {
    fn new(name: &str) -> Self {
        let dir: PathBuf = std::env::temp_dir().join(format!(
            "synapse-d2-{name}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let mut svc = open(&dir);
        let mut b = [TreeDigest::empty(); 3];
        for (slot, oid) in b.iter_mut().zip([B0, B1, B2]) {
            *slot = svc
                .tree_digest(TreeTarget::BaseGitCommit(oid), None)
                .unwrap();
        }
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
        let mut fx = Self {
            dir,
            svc,
            server,
            keys,
            b,
            c: ChangesetId([0; 32]),
        };
        let muts = c_changes()
            .into_iter()
            .map(|(p, mode, body)| (p, Some((mode, body.to_vec()))))
            .collect();
        fx.c = fx.admit_agent("c", fx.b[0], muts).unwrap();
        // Proposed, so other chains (the one that asks for the derivation) can name it.
        let mv = SignedStateMove::sign_new(
            &key("chain c"),
            repo(),
            fx.c,
            RevisionState::Proposed,
            &chain("c"),
            NOW,
        )
        .unwrap();
        fx.svc.store_mut().advance_revision_state(mv, NOW).unwrap();
        fx
    }

    /// Admit agent `s`'s revision on `base` (`None`: delete the path).
    fn admit_agent(
        &mut self,
        s: &str,
        base: TreeDigest,
        muts: Vec<AgentMutation>,
    ) -> Result<ChangesetId, RefusalCode> {
        let mut blobs = Vec::new();
        let mutations = muts
            .into_iter()
            .map(|(p, m)| PathMutation {
                path: p.into(),
                op: match m {
                    Some((mode, body)) => {
                        let op = MutationOp::Upsert {
                            mode,
                            blob_digest: BlobDigest::compute(&body),
                            size_bytes: body.len() as u64,
                        };
                        blobs.push((BlobDigest::compute(&body), body));
                        op
                    }
                    None => MutationOp::Delete,
                },
            })
            .collect();
        self.admit_content(
            s,
            RevisionContent {
                change_id: change(s),
                base_tree: base,
                parents: vec![],
                mutations,
                intent_summary: format!("agent revision {s}"),
            },
            &blobs,
        )
    }

    fn admit_content(
        &mut self,
        s: &str,
        content: RevisionContent,
        blobs: &[(BlobDigest, Vec<u8>)],
    ) -> Result<ChangesetId, RefusalCode> {
        let env = ChangesetEnvelopeV2::sign_new(
            &key(&format!("agent {s}")),
            repo(),
            content,
            IdempotencyKey(label(&format!("idempotency {s}"))),
            NOW,
        );
        let id = env.changeset_id();
        self.svc
            .store_mut()
            .admit_revision(env, blobs, authority(s), NOW)
            .map_err(|e| e.code)?;
        Ok(id)
    }

    fn derive(
        &mut self,
        rule: DerivationRule,
        inputs: Vec<DerivationInput>,
    ) -> Result<DerivedRevision, RefusalCode> {
        let server = self.server.clone();
        self.svc
            .derive_revision(&server, rule, inputs)
            .map_err(|e| e.code)
    }

    fn rebase(&mut self, r: ChangesetId, onto: TreeDigest) -> DerivedRevision {
        self.derive(
            DerivationRule::Rebase,
            vec![DerivationInput::Revision(r), DerivationInput::Tree(onto)],
        )
        .unwrap()
    }

    fn admit(&mut self, derived: DerivedRevision) -> ChangesetId {
        let keys = self.keys.clone();
        let id = derived.content.changeset_id();
        match self
            .svc
            .admit_derived_revision(derived, authority("c"), &keys, NOW)
        {
            Ok(RevisionOutcome::Admitted { .. }) => id,
            other => panic!("unexpected outcome {other:?}"),
        }
    }

    fn verify(&mut self) -> Result<usize, RefusalCode> {
        let keys = self.keys.clone();
        self.svc.verify_revision_log(&keys).map_err(|e| e.code)
    }

    fn move_to(&mut self, id: ChangesetId, to: RevisionState) -> Result<WalSeq, RefusalCode> {
        let mv =
            SignedStateMove::sign_new(&key("chain c"), repo(), id, to, &chain("c"), NOW).unwrap();
        self.svc
            .store_mut()
            .advance_revision_state(mv, NOW)
            .map_err(|e| e.code)
    }
}

/// The conflict terms `c` meets on `B1`, by path.
fn conflicts_on(lib_onto: &[u8]) -> Vec<(String, ConflictTerm)> {
    vec![
        (
            "README.md".into(),
            three_way(
                regular(b"readme\n"),
                regular(b"readme c\n"),
                EntryState::Absent,
            ),
        ),
        ("notes".into(), {
            // `notes/` in B1 is a directory: its digest is the subtree holding today.md.
            let mut s = synapse_api::TreeStore::new(Default::default()).unwrap();
            let empty = s.insert(synapse_api::TreeNode::new(Vec::new()).unwrap());
            let mut e = synapse_api::TreeEdit::new(&mut s, empty).unwrap();
            let body = b"today\n";
            e.upsert(
                &mut s,
                "today.md",
                synapse_api::TreeFile {
                    mode: FileMode::Regular644,
                    blob_digest: BlobDigest::compute(body),
                    size_bytes: body.len() as u64,
                    git_blob_oid: GitOid::compute_blob(body),
                },
            )
            .unwrap();
            let dir = e.finish(&mut s).unwrap();
            three_way(
                regular(b"notes\n"),
                regular(b"notes c\n"),
                EntryState::Dir(dir),
            )
        }),
        (
            "src/lib.rs".into(),
            three_way(regular(b"v0\n"), regular(b"c\n"), regular(lib_onto)),
        ),
        (
            "tool.sh".into(),
            three_way(
                regular(b"run\n"),
                file(FileMode::Executable755, b"run\n"),
                file(FileMode::Symlink120000, b"run\n"),
            ),
        ),
    ]
}

/// Acceptance: modify/delete, file/directory and mode conflicts (and a content conflict)
/// round-trip as typed terms: derived, admitted, read back, replayed after a reopen and after
/// checkpoint plus compaction, and recomputed by a replica.
#[test]
fn d2_api_typed_conflict_terms_round_trip_through_the_revision_log() {
    let mut fx = Fx::new("typed");
    let r1 = fx.rebase(fx.c, fx.b[1]);
    let want = conflicts_on(b"b1\n");
    let got: Vec<(String, ConflictTerm)> = r1
        .content
        .mutations
        .iter()
        .map(|m| match &m.op {
            MutationOp::Conflict(t) => (m.path.clone(), t.clone()),
            other => panic!("{}: not a conflict: {other:?}", m.path),
        })
        .collect();
    assert_eq!(got, want);
    let kinds: Vec<ConflictKind> = got.iter().map(|(_, t)| t.kind()).collect();
    assert_eq!(
        kinds,
        [
            ConflictKind::ModifyDelete,
            ConflictKind::FileDirectory,
            ConflictKind::Content,
            ConflictKind::Mode,
        ]
    );
    // The output keeps `c`'s change identity and intent, on the new base.
    assert_eq!(r1.content.change_id, change("c"));
    assert_eq!(r1.content.base_tree, fx.b[1]);
    let tree = r1.attestation.output_tree;
    let id = fx.admit(r1.clone());
    assert_eq!(
        fx.svc.store().get_revision(&repo(), id).unwrap().content,
        r1.content
    );
    assert_eq!(fx.svc.tree_conflicts(tree).unwrap(), want);
    assert_eq!(fx.verify(), Ok(3));
    // Reopen: replayed from the WAL, recomputed by the replica, the same terms.
    let dir = fx.dir.clone();
    fx.svc = open(&dir);
    assert_eq!(
        fx.svc.store().get_revision(&repo(), id).unwrap().content,
        r1.content
    );
    assert_eq!(fx.verify(), Ok(3));
    assert_eq!(fx.svc.revision_tree(id).unwrap(), tree);
    fx.svc.checkpoint_compact_and_invalidate_index(NOW).unwrap();
    assert_eq!(
        fx.svc.store().get_revision(&repo(), id).unwrap().content,
        r1.content
    );
    assert_eq!(fx.verify(), Ok(3));
    let _ = std::fs::remove_dir_all(&dir);
}

/// Acceptance: rebasing twice cancels to a plain three-way conflict, and reverting returns a
/// clean tree.
#[test]
fn d2_api_rebase_twice_cancels_to_a_plain_three_way_conflict_and_revert_is_clean() {
    let mut fx = Fx::new("twice");
    let r1 = fx.rebase(fx.c, fx.b[1]);
    let r1_tree = r1.attestation.output_tree;
    let r1_id = fx.admit(r1);
    // Rebase the conflicted revision again, from B1 to B2: B1's version of src/lib.rs
    // cancels, leaving c against b2 over v0, the same tree one rebase of c onto B2 gives.
    let r2 = fx.rebase(r1_id, fx.b[2]);
    let direct = fx.rebase(fx.c, fx.b[2]);
    assert_eq!(r2.attestation.output_tree, direct.attestation.output_tree);
    assert_eq!(r2.content.mutations, direct.content.mutations);
    let lib = r2
        .content
        .mutations
        .iter()
        .find(|m| m.path == "src/lib.rs")
        .unwrap();
    assert_eq!(
        lib.op,
        MutationOp::Conflict(three_way(
            regular(b"v0\n"),
            regular(b"c\n"),
            regular(b"b2\n")
        ))
    );
    assert_eq!(
        fx.svc.tree_conflicts(r2.attestation.output_tree).unwrap(),
        conflicts_on(b"b2\n")
    );
    fx.admit(r2);

    // Revert c on top of the conflicted tree: B1's tree, clean.
    let revert = fx
        .derive(
            DerivationRule::Revert,
            vec![
                DerivationInput::Revision(fx.c),
                DerivationInput::Tree(r1_tree),
            ],
        )
        .unwrap();
    assert_eq!(revert.attestation.output_tree, fx.b[1]);
    assert_eq!(revert.content.base_tree, r1_tree);
    assert_eq!(revert.content.parents, vec![fx.c]);
    assert_eq!(revert.content.intent_summary, format!("revert of {}", fx.c));
    assert!(fx.svc.tree_conflicts(fx.b[1]).unwrap().is_empty());
    let revert_id = fx.admit(revert);
    // B1's files the revert restored (only a base tree held them) are now in the store, written
    // with the derived revision, so every replica of the log can read them.
    for body in [&b"today\n"[..], b"b1\n", b"run\n"] {
        let d = BlobDigest::compute(body);
        assert_eq!(
            fx.svc.store().get_blob_visible(d, None, None).unwrap(),
            body
        );
    }
    // Every derived revision (two rebases, one revert) is recomputed by a replica.
    assert_eq!(fx.verify(), Ok(5));
    let dir = fx.dir.clone();
    fx.svc = open(&dir);
    assert_eq!(fx.verify(), Ok(5));
    assert_eq!(fx.svc.revision_tree(revert_id).unwrap(), fx.b[1]);
    // Reverting on a tree that does not hold the change records the revert as conflicts.
    let on_b2 = fx
        .derive(
            DerivationRule::Revert,
            vec![
                DerivationInput::Revision(fx.c),
                DerivationInput::Tree(fx.b[2]),
            ],
        )
        .unwrap();
    assert!(!fx
        .svc
        .tree_conflicts(on_b2.attestation.output_tree)
        .unwrap()
        .is_empty());
    let _ = std::fs::remove_dir_all(&dir);
}

/// Acceptance: conflicted trees refuse materialization and promotion.
#[test]
fn d2_api_conflicted_trees_refuse_materialization_and_promotion() {
    let mut fx = Fx::new("refuse");
    let r1 = fx.rebase(fx.c, fx.b[1]);
    let tree = r1.attestation.output_tree;
    let id = fx.admit(r1);
    // Materialization of the conflicted tree is refused; the clean base is not.
    assert_eq!(
        fx.svc.materialize_tree(tree).unwrap_err().code,
        RefusalCode::TreeConflicted
    );
    assert_eq!(fx.svc.materialize_tree(fx.b[1]).unwrap().len(), 3);
    // Promotion: the revision moves to Proposed, never to Verified, and the gate refuses it.
    fx.move_to(id, RevisionState::Draft).unwrap();
    fx.move_to(id, RevisionState::Proposed).unwrap();
    assert_eq!(
        fx.move_to(id, RevisionState::Verified),
        Err(RefusalCode::TreeConflicted)
    );
    assert_eq!(
        fx.svc.check_promotion(id).unwrap_err().code,
        RefusalCode::TreeConflicted
    );
    assert_eq!(fx.svc.check_promotion(fx.c), Ok(()));
    // A revision based on the conflicted tree that leaves the conflicts in place is still
    // conflicted; one that resolves every conflict is promotable.
    let on_top = fx
        .admit_agent(
            "t",
            tree,
            vec![("extra.txt", Some((FileMode::Regular644, b"x\n".to_vec())))],
        )
        .unwrap();
    assert_eq!(
        fx.svc.check_promotion(on_top).unwrap_err().code,
        RefusalCode::TreeConflicted
    );
    let resolved = fx
        .admit_agent(
            "r",
            tree,
            vec![
                ("README.md", None),
                ("notes", Some((FileMode::Regular644, b"notes c\n".to_vec()))),
                (
                    "src/lib.rs",
                    Some((FileMode::Regular644, b"resolved\n".to_vec())),
                ),
                (
                    "tool.sh",
                    Some((FileMode::Executable755, b"run\n".to_vec())),
                ),
            ],
        )
        .unwrap();
    assert_eq!(fx.svc.check_promotion(resolved), Ok(()));
    let resolved_tree = fx.svc.revision_tree(resolved).unwrap();
    assert!(fx.svc.tree_conflicts(resolved_tree).unwrap().is_empty());
    assert_eq!(fx.svc.materialize_tree(resolved_tree).unwrap().len(), 3);
    let _ = std::fs::remove_dir_all(&fx.dir);
}

/// Conflict terms are recorded only by derivation rules: an agent-submitted revision that
/// carries one is refused (`ConflictNotDerived`), and envelope v1 JSON cannot carry one.
#[test]
fn d2_api_agent_revisions_cannot_carry_conflict_terms() {
    let mut fx = Fx::new("agent");
    let term = three_way(regular(b"v0\n"), regular(b"c\n"), EntryState::Absent);
    let content = RevisionContent {
        change_id: change("forger"),
        base_tree: fx.b[0],
        parents: vec![],
        mutations: vec![PathMutation {
            path: "src/lib.rs".into(),
            op: MutationOp::Conflict(term.clone()),
        }],
        intent_summary: "a hand-made conflict".into(),
    };
    assert_eq!(
        fx.admit_content("forger", content, &[]),
        Err(RefusalCode::ConflictNotDerived)
    );
    let json = serde_json::to_string(&MutationOp::Conflict(term.clone()));
    assert!(
        json.is_err(),
        "envelope v1 JSON never carries a conflict term"
    );
    // A signed envelope v1 built in memory with one is refused by validation and by the v1
    // binary codec.
    let mut v1 = ChangesetEnvelope {
        version: SYNAPSE_ENVELOPE_VERSION,
        repo_id: repo(),
        base_git_oid: B0,
        parent_changesets: vec![],
        author_did: String::new(),
        idempotency_key: IdempotencyKey(label("idempotency v1")),
        created_at_ms: NOW,
        intent_summary: "a hand-made conflict".into(),
        mutations: vec![PathMutation {
            path: "src/lib.rs".into(),
            op: MutationOp::Conflict(term),
        }],
        evidence_receipts: vec![],
        signature: vec![],
    };
    v1.sign(&key("agent v1"));
    assert_eq!(
        v1.validate().unwrap_err().code,
        RefusalCode::ConflictNotDerived
    );
    assert_eq!(
        synapse_store::codec::encode_envelope(&v1).unwrap_err().code,
        RefusalCode::ConflictNotDerived
    );
    let _ = std::fs::remove_dir_all(&fx.dir);
}

/// A tier T1 merge does not merge a recorded conflict term line by line: it is refused.
#[test]
fn d2_api_tier_t1_merge_refuses_a_recorded_conflict_term() {
    let mut fx = Fx::new("t1");
    let r1 = fx.rebase(fx.c, fx.b[1]);
    let r1_id = fx.admit(r1);
    fx.move_to(r1_id, RevisionState::Proposed).unwrap();
    let d = fx
        .admit_agent(
            "d",
            fx.b[1],
            vec![("src/lib.rs", Some((FileMode::Regular644, b"d\n".to_vec())))],
        )
        .unwrap();
    let mv = SignedStateMove::sign_new(
        &key("chain d"),
        repo(),
        d,
        RevisionState::Proposed,
        &chain("d"),
        NOW,
    )
    .unwrap();
    fx.svc.store_mut().advance_revision_state(mv, NOW).unwrap();
    let t1 = DerivationRule::Merge {
        tier: MergeTier::T1Region,
    };
    // Merge revisions are named in canonical order (ascending ChangesetId).
    let (lo, hi) = (r1_id.min(d), r1_id.max(d));
    let inputs = vec![
        DerivationInput::Tree(fx.b[1]),
        DerivationInput::Revision(lo),
        DerivationInput::Revision(hi),
    ];
    assert_eq!(
        fx.derive(t1, inputs).unwrap_err(),
        RefusalCode::DerivationRecomputeMismatch
    );
    let _ = std::fs::remove_dir_all(&fx.dir);
}
