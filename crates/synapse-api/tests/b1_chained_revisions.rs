//! ADR 0003 step B1 through the API with real signed F1 capability chains: authority `A`
//! grants orchestrator `O` and outsider `X` (root links); `O` delegates worker `W` (scoped to
//! `src`) and worker `V` (scoped to change `C`).

use ed25519_dalek::SigningKey;
use std::path::PathBuf;
use synapse_api::{RevisionStateMovePayload, SynapseService, TreeTarget};
use synapse_auth::{
    Capability, CapabilityChain, CapabilityLink, ChainQuotas, ChainedRequest, ChangeScope,
    LinkCaveats, OperationSet, PathScope, ReferenceKind, ReferenceScope, RequestScope, ROOT_PARENT,
};
use synapse_core::{
    encode_did_key_ed25519, BlobDigest, ChangeId, ChangesetEnvelopeV2, ChangesetId, FileMode,
    GitOid, IdempotencyKey, MutationOp, ObsolescenceMarker, PathMutation, RefusalCode, RepoId,
    RevisionContent, RevisionState, TreeDigest, WalSeq,
};
use synapse_store::{FsyncPolicy, RecoveryPolicy, RevisionOutcome, StoreLimits};

const NOW: u64 = 2_000;
const C: ChangeId = ChangeId([0xC1; 16]);

fn repo() -> RepoId {
    RepoId::new("aien-spark/synapse").unwrap()
}

fn pk(k: &SigningKey) -> [u8; 32] {
    k.verifying_key().to_bytes()
}

/// `share` is the part of the parent's quotas a child link takes (children of one parent
/// must partition its quotas).
fn caveats(paths: PathScope, changes: ChangeScope, share: u64) -> LinkCaveats {
    LinkCaveats {
        operations: OperationSet::from_capabilities(&[Capability::Read, Capability::Propose]),
        paths,
        references: ReferenceScope::from_kinds(&[ReferenceKind::OwnDrafts]),
        changes,
        quotas: ChainQuotas {
            max_ops_per_window: (1_000 / share) as u32,
            window_duration_ms: 60_000,
            storage_bytes: (1 << 30) / share,
            footprint_paths: (1 << 20) / share,
            max_bytes_per_op: 1 << 20,
        },
        issued_at_ms: 1_000,
        expires_at_ms: 100_000,
    }
}

struct Fx {
    svc: SynapseService,
    base: TreeDigest,
    o: (SigningKey, CapabilityChain),
    w: (SigningKey, CapabilityChain),
    v: (SigningKey, CapabilityChain),
    x: (SigningKey, CapabilityChain),
    nonce: u8,
}

impl Fx {
    fn new(name: &str) -> Self {
        let dir: PathBuf = std::env::temp_dir().join(format!(
            "synapse-b1-api-{name}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let mut svc = SynapseService::open(
            &dir,
            repo(),
            FsyncPolicy::EveryCommit,
            RecoveryPolicy::StrictFailClosed,
            StoreLimits {
                wal_prealloc_bytes: 64 * 1024,
                ..Default::default()
            },
        )
        .unwrap();
        let a = SigningKey::from_bytes(&[1; 32]);
        let key = |n: u8| SigningKey::from_bytes(&[n; 32]);
        let (o, w, v, x) = (key(2), key(3), key(4), key(9));
        svc.auth_mut()
            .register_repo_authority(repo(), encode_did_key_ed25519(&pk(&a)));
        let whole = PathScope::whole_repository;
        let root_o = CapabilityLink::issue(
            &a,
            ROOT_PARENT,
            [0xA0; 32],
            repo(),
            pk(&o),
            caveats(whole(), ChangeScope::any(), 1),
        );
        let root_x = CapabilityLink::issue(
            &a,
            ROOT_PARENT,
            [0xA9; 32],
            repo(),
            pk(&x),
            caveats(whole(), ChangeScope::any(), 1),
        );
        let link_w = CapabilityLink::issue(
            &o,
            root_o.digest(),
            [0xB3; 32],
            repo(),
            pk(&w),
            caveats(
                PathScope::new(vec!["src".into()]).unwrap(),
                ChangeScope::any(),
                4,
            ),
        );
        let link_v = CapabilityLink::issue(
            &o,
            root_o.digest(),
            [0xB4; 32],
            repo(),
            pk(&v),
            caveats(whole(), ChangeScope::only(vec![C]).unwrap(), 4),
        );
        let co = CapabilityChain::new(vec![root_o]);
        let cx = CapabilityChain::new(vec![root_x]);
        let cw = co.extended(link_w);
        let cv = co.extended(link_v);
        for c in [&co, &cx, &cw, &cv] {
            svc.auth_mut().grant_link(c, WalSeq(0), NOW).unwrap();
        }
        let base_oid = GitOid([0x0B; 20]);
        svc.register_base_tree(
            base_oid,
            vec![("README.md".into(), FileMode::Regular644, b"base".to_vec())],
        )
        .unwrap();
        let base = svc
            .tree_digest(TreeTarget::BaseGitCommit(base_oid), None)
            .unwrap();
        Self {
            svc,
            base,
            o: (o, co),
            w: (w, cw),
            v: (v, cv),
            x: (x, cx),
            nonce: 0,
        }
    }

    fn envelope(&self, author: &SigningKey, body: &[u8], idem: u8) -> ChangesetEnvelopeV2 {
        let content = RevisionContent {
            change_id: C,
            base_tree: self.base,
            parents: vec![],
            mutations: vec![PathMutation {
                path: "src/lib.rs".into(),
                op: MutationOp::Upsert {
                    mode: FileMode::Regular644,
                    blob_digest: BlobDigest::compute(body),
                    size_bytes: body.len() as u64,
                },
            }],
            intent_summary: "implement the task".into(),
        };
        ChangesetEnvelopeV2::sign_new(author, repo(), content, IdempotencyKey([idem; 32]), NOW)
    }

    fn request(
        &mut self,
        who: &(SigningKey, CapabilityChain),
        paths: Vec<String>,
        payload: Vec<u8>,
    ) -> ChainedRequest {
        self.nonce += 1;
        ChainedRequest::sign_new(
            &who.0,
            who.1.clone(),
            repo(),
            Capability::Propose,
            RequestScope {
                paths,
                reference: None,
                join_change: Some(C),
            },
            [self.nonce; 32],
            NOW,
            payload,
        )
    }

    fn submit(
        &mut self,
        who: &(SigningKey, CapabilityChain),
        body: &[u8],
        idem: u8,
    ) -> Result<RevisionOutcome, RefusalCode> {
        let env = self.envelope(&who.0, body, idem);
        let req = self.request(who, vec!["src/lib.rs".into()], env.encode());
        let blobs = vec![(BlobDigest::compute(body), body.to_vec())];
        self.svc
            .submit_revision(&req, &blobs, NOW)
            .map_err(|e| e.code)
    }

    /// The owner shares a revision (ADR 0003 B4): `Private` -> `Draft`, so chains outside
    /// its owner chain see it and are refused for dominance rather than as unknown.
    fn share(&mut self, who: &(SigningKey, CapabilityChain), rev: ChangesetId) {
        let payload = RevisionStateMovePayload::sign_new(
            &who.0,
            &repo(),
            &who.1,
            rev,
            RevisionState::Draft,
            NOW,
        )
        .unwrap()
        .encode();
        let req = self.request(who, vec![], payload);
        self.svc.advance_revision_state(&req, NOW).unwrap();
    }

    fn mark(
        &mut self,
        who: &(SigningKey, CapabilityChain),
        pred: ChangesetId,
        succ: Vec<ChangesetId>,
    ) -> Result<WalSeq, RefusalCode> {
        let m = ObsolescenceMarker::sign_new(&who.0, repo(), C, pred, succ, NOW);
        let req = self.request(who, vec![], m.encode());
        self.svc.record_obsolescence(&req, NOW).map_err(|e| e.code)
    }
}

fn id(o: RevisionOutcome) -> ChangesetId {
    match o {
        RevisionOutcome::Admitted { changeset_id, .. }
        | RevisionOutcome::IdempotentDuplicate { changeset_id, .. } => changeset_id,
    }
}

#[test]
fn b1_api_join_and_prune_follow_the_creating_chain_of_real_f1_chains() {
    let mut fx = Fx::new("join-prune");
    let (o, w, v, x) = (fx.o.clone(), fx.w.clone(), fx.v.clone(), fx.x.clone());
    let a = id(fx.submit(&o, b"orchestrator attempt", 1).unwrap());
    // W descends from the creating chain (O's): it joins without change scope.
    let b = id(fx.submit(&w, b"worker attempt", 1).unwrap());
    // X is outside it and its grant allows any change, which names none: refused.
    assert_eq!(
        fx.submit(&x, b"outsider attempt", 1).unwrap_err(),
        RefusalCode::AuthChangeOutOfScope
    );
    // V's grant names C explicitly.
    fx.submit(&v, b"scoped attempt", 1).unwrap();
    fx.share(&o, a);
    // Pruning needs a chain that is or dominates the creating chain.
    assert_eq!(
        fx.mark(&w, a, vec![]).unwrap_err(),
        RefusalCode::AuthChainNotDominant
    );
    assert_eq!(
        fx.mark(&x, a, vec![]).unwrap_err(),
        RefusalCode::AuthChainNotDominant
    );
    fx.mark(&o, b, vec![]).unwrap();
    let st = fx.svc.store().change_status(&repo(), C).unwrap();
    assert_eq!(st.obsolete, vec![b]);
    assert!(
        st.divergent,
        "the orchestrator's and V's attempts are both live"
    );
    // Identical content from O and W: one revision, two attestations, two witnesses.
    let r1 = id(fx.submit(&o, b"agreed", 7).unwrap());
    let r2 = id(fx.submit(&w, b"agreed", 7).unwrap());
    assert_eq!(r1, r2);
    let rev = fx.svc.store().get_revision(&repo(), r1).unwrap();
    assert_eq!((rev.attestations.len(), rev.witnesses.len()), (2, 2));
    let digests = |c: &CapabilityChain| c.link_digests().iter().map(|d| d.0).collect::<Vec<_>>();
    assert_eq!(rev.witnesses[0].chain.links(), digests(&o.1).as_slice());
    assert_eq!(rev.witnesses[1].chain.links(), digests(&w.1).as_slice());
    // A repeat with the same repository, DID, and idempotency key: the first WalSeq.
    let first = rev.witnesses[0].admission_seq;
    assert_eq!(
        fx.submit(&o, b"agreed", 7).unwrap(),
        RevisionOutcome::IdempotentDuplicate {
            wal_seq: first,
            changeset_id: r1
        }
    );
}

#[test]
fn b1_api_refuses_paths_outside_scope_foreign_authors_and_unknown_bases() {
    let mut fx = Fx::new("refusals");
    let (o, w) = (fx.o.clone(), fx.w.clone());
    fx.submit(&o, b"created", 1).unwrap();
    // W's path scope is `src`: a revision touching `docs` is refused by F1.
    let mut env = fx.envelope(&w.0, b"doc", 2);
    env.content.mutations[0].path = "docs/x.md".into();
    let env =
        ChangesetEnvelopeV2::sign_new(&w.0, repo(), env.content, IdempotencyKey([2; 32]), NOW);
    let req = fx.request(&w, vec!["docs/x.md".into()], env.encode());
    assert_eq!(
        fx.svc.submit_revision(&req, &[], NOW).unwrap_err().code,
        RefusalCode::AuthPathOutOfScope
    );
    // The request scope must list exactly the mutation paths.
    let env = fx.envelope(&w.0, b"x", 3);
    let req = fx.request(&w, vec![], env.encode());
    assert_eq!(
        fx.svc.submit_revision(&req, &[], NOW).unwrap_err().code,
        RefusalCode::AuthPathOutOfScope
    );
    // An envelope attested by another key than the chain's agent.
    let env = fx.envelope(&o.0, b"y", 4);
    let req = fx.request(&w, vec!["src/lib.rs".into()], env.encode());
    assert_eq!(
        fx.svc.submit_revision(&req, &[], NOW).unwrap_err().code,
        RefusalCode::AuthSignatureInvalid
    );
    // An unknown base tree.
    let mut env = fx.envelope(&w.0, b"z", 5);
    env.content.base_tree = TreeDigest([0xEE; 32]);
    let env =
        ChangesetEnvelopeV2::sign_new(&w.0, repo(), env.content, IdempotencyKey([5; 32]), NOW);
    let blobs = vec![(BlobDigest::compute(b"z"), b"z".to_vec())];
    let req = fx.request(&w, vec!["src/lib.rs".into()], env.encode());
    assert_eq!(
        fx.svc.submit_revision(&req, &blobs, NOW).unwrap_err().code,
        RefusalCode::BaseTreeNotFound
    );
}
