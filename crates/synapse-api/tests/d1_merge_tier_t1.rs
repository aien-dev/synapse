//! ADR 0003 step D1 through the service: tier T1 merges of revisions that write the same file,
//! derived by the server, admitted with the merged file, and recomputed by a replica.
//!
//! Base `B0` holds `src/lib.rs` (20 lines) and `README.md`. On `B0`: `ra` changes line 2,
//! `rb` changes line 15, `rc` changes line 3 (touching `ra`'s region), `rd` deletes
//! `src/lib.rs`, `re` changes line 15 exactly as `rb` does plus line 18, `rf` changes line 18
//! and makes the file executable.

use ed25519_dalek::SigningKey;
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use synapse_api::{SynapseService, TreeTarget};
use synapse_auth::{
    Capability, CapabilityChain, CapabilityLink, ChainQuotas, ChangeScope, LinkCaveats,
    OperationSet, PathScope, ReferenceScope, SignedStateMove, ROOT_PARENT,
};
use synapse_core::{
    BlobDigest, ChainPath, ChangeId, ChangesetEnvelopeV2, ChangesetId, DerivationAttestation,
    DerivationInput, DerivationRule, DerivedRevision, FileMode, GitOid, IdempotencyKey, MergeTier,
    MutationOp, PathMutation, RefusalCode, RepoId, RevisionContent, RevisionState, TreeDigest,
    WalSeq,
};
use synapse_radicle::{
    IdentityDocumentDigest, IdentityEdit, IdentityLog, RepositoryIdentityDocument,
};
use synapse_store::{
    AdmissionAuthority, FsyncPolicy, RecoveryPolicy, RevisionOutcome, StoreLimits,
};

const NOW: u64 = 5_000;
const T0: DerivationRule = DerivationRule::Merge {
    tier: MergeTier::T0Path,
};
const T1: DerivationRule = DerivationRule::Merge {
    tier: MergeTier::T1Region,
};
const B0: GitOid = GitOid([0xB0; 20]);

fn repo() -> RepoId {
    RepoId::new("aien-spark/synapse").unwrap()
}

fn label(s: &str) -> [u8; 32] {
    Sha256::digest(format!("synapse d1 test: {s}").as_bytes()).into()
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

fn base_lib() -> String {
    (0..20).map(|i| format!("fn line_{i}() {{}}\n")).collect()
}

/// `base_lib` with each `(line, text)` replaced.
fn edited(edits: &[(usize, &str)]) -> Vec<u8> {
    base_lib()
        .split_inclusive('\n')
        .enumerate()
        .map(|(i, l)| match edits.iter().find(|(n, _)| *n == i) {
            Some((_, t)) => format!("{t}\n"),
            None => l.to_string(),
        })
        .collect::<String>()
        .into_bytes()
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
    svc.register_base_tree(
        B0,
        vec![
            ("README.md".into(), FileMode::Regular644, b"base\n".to_vec()),
            (
                "src/lib.rs".into(),
                FileMode::Regular644,
                base_lib().into_bytes(),
            ),
        ],
    )
    .unwrap();
    svc
}

struct Fx {
    dir: PathBuf,
    svc: SynapseService,
    server: SigningKey,
    keys: IdentityLog,
    b0: TreeDigest,
    revs: Vec<(String, ChangesetId)>,
}

impl Fx {
    fn new(name: &str) -> Self {
        let dir: PathBuf = std::env::temp_dir().join(format!(
            "synapse-d1-{name}-{}-{}",
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
            b0,
            revs: Vec::new(),
        };
        fx.admit_agent("a", Some(edited(&[(2, "fn a() {}")])));
        fx.admit_agent("b", Some(edited(&[(15, "fn b() {}")])));
        fx.admit_agent("c", Some(edited(&[(3, "fn c() {}")])));
        fx.admit_agent("d", None);
        fx.admit_agent("e", Some(edited(&[(15, "fn b() {}"), (18, "fn e() {}")])));
        fx.admit_agent("f", Some(edited(&[(18, "fn f() {}")])));
        fx
    }

    /// Admit and publish agent `s`'s revision of `src/lib.rs` (`None`: delete it).
    fn admit_agent(&mut self, s: &str, body: Option<Vec<u8>>) {
        let op = match &body {
            Some(b) => MutationOp::Upsert {
                mode: if s == "f" {
                    FileMode::Executable755
                } else {
                    FileMode::Regular644
                },
                blob_digest: BlobDigest::compute(b),
                size_bytes: b.len() as u64,
            },
            None => MutationOp::Delete,
        };
        let content = RevisionContent {
            change_id: change(s),
            base_tree: self.b0,
            parents: vec![],
            mutations: vec![PathMutation {
                path: "src/lib.rs".into(),
                op,
            }],
            intent_summary: format!("agent revision {s}"),
        };
        let env = ChangesetEnvelopeV2::sign_new(
            &key(&format!("agent {s}")),
            repo(),
            content,
            IdempotencyKey(label(&format!("idempotency {s}"))),
            NOW,
        );
        let id = env.changeset_id();
        let blobs: Vec<(BlobDigest, Vec<u8>)> = body
            .into_iter()
            .map(|b| (BlobDigest::compute(&b), b))
            .collect();
        self.svc
            .store_mut()
            .admit_revision(env, &blobs, authority(s), NOW)
            .unwrap();
        let mv = SignedStateMove::sign_new(
            &key(&format!("chain {s}")),
            repo(),
            id,
            RevisionState::Proposed,
            &chain(s),
            NOW,
        )
        .unwrap();
        self.svc
            .store_mut()
            .advance_revision_state(mv, NOW)
            .unwrap();
        self.revs.push((s.to_string(), id));
    }

    fn id(&self, s: &str) -> ChangesetId {
        self.revs.iter().find(|(n, _)| n == s).unwrap().1
    }

    /// Merge inputs for `names` in the canonical merge order.
    fn inputs(&self, names: &[&str]) -> Vec<DerivationInput> {
        let mut ids: Vec<ChangesetId> = names.iter().map(|n| self.id(n)).collect();
        ids.sort();
        let mut inputs = vec![DerivationInput::Tree(self.b0)];
        inputs.extend(ids.into_iter().map(DerivationInput::Revision));
        inputs
    }

    fn derive(
        &mut self,
        rule: DerivationRule,
        names: &[&str],
    ) -> Result<DerivedRevision, RefusalCode> {
        let server = self.server.clone();
        let inputs = self.inputs(names);
        self.svc
            .derive_revision(&server, rule, inputs)
            .map_err(|e| e.code)
    }

    fn admit(&mut self, derived: DerivedRevision) -> Result<WalSeq, RefusalCode> {
        let keys = self.keys.clone();
        match self
            .svc
            .admit_derived_revision(derived, authority("a"), &keys, NOW)
        {
            Ok(RevisionOutcome::Admitted { wal_seq, .. }) => Ok(wal_seq),
            Ok(other) => panic!("unexpected outcome {other:?}"),
            Err(e) => Err(e.code),
        }
    }

    fn verify(&mut self) -> Result<usize, RefusalCode> {
        let keys = self.keys.clone();
        self.svc.verify_revision_log(&keys).map_err(|e| e.code)
    }
}

fn lib_blob(content: &RevisionContent) -> (BlobDigest, u64) {
    match &content
        .mutations
        .iter()
        .find(|m| m.path == "src/lib.rs")
        .unwrap()
        .op
    {
        MutationOp::Upsert {
            blob_digest,
            size_bytes,
            ..
        } => (*blob_digest, *size_bytes),
        MutationOp::Delete => panic!("merged file deleted"),
        MutationOp::Conflict(_) => panic!("merged file recorded as a conflict"),
    }
}

/// Acceptance with the service: two revisions that change different regions of one file are
/// refused at T0 (path level) and merge at T1. The attestation records the tier and the merge
/// order, the merged file is written with the derived revision, and a replica recomputes the
/// same output (also after a reopen).
#[test]
fn d1_api_t1_merges_disjoint_regions_of_one_file_end_to_end() {
    let mut fx = Fx::new("e2e");
    assert_eq!(
        fx.derive(T0, &["a", "b"]).unwrap_err(),
        RefusalCode::DerivationRecomputeMismatch
    );
    let merged = fx.derive(T1, &["a", "b"]).unwrap();
    assert_eq!(merged.attestation.rule, T1);
    assert_eq!(merged.attestation.inputs, fx.inputs(&["a", "b"]));
    assert_eq!(
        merged.content.intent_summary,
        "merge tier T1 of 2 revisions"
    );
    let want = edited(&[(2, "fn a() {}"), (15, "fn b() {}")]);
    let (blob, size) = lib_blob(&merged.content);
    assert_eq!(blob, BlobDigest::compute(&want));
    assert_eq!(size, want.len() as u64);
    // Nothing is stored until admission.
    assert!(fx.svc.read_blob_bytes(blob, None).is_err());
    fx.admit(merged.clone()).unwrap();
    assert_eq!(fx.svc.read_blob_bytes(blob, None).unwrap(), want);
    let id = merged.content.changeset_id();
    let stored = fx.svc.store().get_revision(&repo(), id).unwrap();
    assert_eq!(stored.content, merged.content);
    // 6 admissions, 6 state moves, 1 derived revision.
    assert_eq!(fx.verify(), Ok(13));

    // `rb` and `re` make the same change to line 15, but `re` also changes line 18, so the
    // files differ and their line 15 regions overlap: refused (identical edits inside
    // different files are not merged). `ra` with `re` merges.
    assert_eq!(
        fx.derive(T1, &["b", "e"]).unwrap_err(),
        RefusalCode::DerivationRecomputeMismatch
    );
    let second = fx.derive(T1, &["a", "e"]).unwrap();
    fx.admit(second).unwrap();

    let dir = fx.dir.clone();
    drop(fx.svc);
    fx.svc = open(&dir);
    assert_eq!(fx.svc.read_blob_bytes(blob, None).unwrap(), want);
    assert!(fx.verify().is_ok());
    fx.svc.checkpoint_compact_and_invalidate_index(NOW).unwrap();
    assert_eq!(fx.svc.read_blob_bytes(blob, None).unwrap(), want);
    assert!(fx.verify().is_ok());
    let _ = std::fs::remove_dir_all(&dir);
}

/// Regions that touch, a delete against a change, and a mode change are conflicts at T1:
/// refused with
/// `DerivationRecomputeMismatch`, nothing derived.
#[test]
fn d1_api_t1_refuses_touching_regions_and_modify_delete() {
    let mut fx = Fx::new("conflicts");
    for pair in [["a", "c"], ["a", "d"], ["b", "e"], ["a", "f"]] {
        assert_eq!(
            fx.derive(T1, &pair).unwrap_err(),
            RefusalCode::DerivationRecomputeMismatch,
            "{pair:?}"
        );
    }
    let _ = std::fs::remove_dir_all(&fx.dir);
}

/// A server that signs a T1 merge with different merged bytes than the rule produces is
/// refused at admission (the store recomputes) and at replay.
#[test]
fn d1_api_forged_t1_merge_output_is_refused() {
    let mut fx = Fx::new("forged");
    let honest = fx.derive(T1, &["a", "b"]).unwrap();
    let mut content = honest.content.clone();
    let lie = edited(&[(2, "fn a() {}"), (15, "fn b() {}"), (19, "fn extra() {}")]);
    for m in &mut content.mutations {
        if m.path == "src/lib.rs" {
            m.op = MutationOp::Upsert {
                mode: FileMode::Regular644,
                blob_digest: BlobDigest::compute(&lie),
                size_bytes: lie.len() as u64,
            };
        }
    }
    let attestation = DerivationAttestation::sign(
        &fx.server,
        repo(),
        T1,
        honest.attestation.inputs.clone(),
        content.changeset_id(),
        honest.attestation.output_tree,
    );
    let forged = DerivedRevision {
        content,
        attestation,
    };
    let before = fx.svc.store().committed_seq();
    assert_eq!(
        fx.admit(forged).unwrap_err(),
        RefusalCode::DerivationRecomputeMismatch
    );
    assert_eq!(fx.svc.store().committed_seq(), before);
    let _ = std::fs::remove_dir_all(&fx.dir);
}
