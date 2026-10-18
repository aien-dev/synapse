//! ADR 0003 step B2 through the API with real signed F1 capability chains: authority `A`
//! grants orchestrator `O` (`Read`, `Propose`, `Undo`); `O` delegates worker `W` (`Read`,
//! `Propose`, `Undo`) and worker `V` (`Read`, `Propose`, no `Undo`).

use ed25519_dalek::SigningKey;
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use synapse_api::{DiscardPayload, SynapseService, TreeTarget, UndoPayload};
use synapse_auth::{
    Capability, CapabilityChain, CapabilityLink, ChainQuotas, ChainedRequest, ChangeScope,
    LinkCaveats, OperationSet, PathScope, ReferenceKind, ReferenceScope, RequestScope, ROOT_PARENT,
};
use synapse_core::{
    encode_did_key_ed25519, BlobDigest, ChainPath, ChangeId, ChangesetEnvelopeV2, ChangesetId,
    FileMode, GitOid, IdempotencyKey, MutationOp, PathMutation, RefusalCode, RepoId,
    RevisionContent, TreeDigest, WalSeq,
};
use synapse_store::{FsyncPolicy, RecoveryPolicy, RevisionOutcome, StoreLimits, ViewOutcome};

const NOW: u64 = 2_000;

type Agent = (SigningKey, CapabilityChain);

fn link_nonces(dir: &Path) -> impl FnMut() -> [u8; 32] {
    let seed = dir.to_string_lossy().into_owned();
    let mut issued = 0u32;
    move || {
        issued += 1;
        let mut h = Sha256::new();
        h.update(seed.as_bytes());
        h.update(issued.to_le_bytes());
        h.finalize().into()
    }
}

fn repo() -> RepoId {
    RepoId::new("aien-spark/synapse").unwrap()
}

fn pk(k: &SigningKey) -> [u8; 32] {
    k.verifying_key().to_bytes()
}

fn chain_path(a: &Agent) -> ChainPath {
    ChainPath::new(a.1.link_digests().iter().map(|d| d.0).collect()).unwrap()
}

fn caveats(ops: &[Capability], share: u64) -> LinkCaveats {
    LinkCaveats {
        operations: OperationSet::from_capabilities(ops),
        paths: PathScope::whole_repository(),
        references: ReferenceScope::from_kinds(&[ReferenceKind::OwnDrafts]),
        changes: ChangeScope::any(),
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
    o: Agent,
    w: Agent,
    v: Agent,
    nonce: u8,
}

impl Fx {
    fn new(name: &str) -> Self {
        let dir: PathBuf = std::env::temp_dir().join(format!(
            "synapse-b2-api-{name}-{}-{}",
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
        let (o, w, v) = (key(2), key(3), key(4));
        svc.auth_mut()
            .register_repo_authority(repo(), encode_did_key_ed25519(&pk(&a)));
        let rpu = [Capability::Read, Capability::Propose, Capability::Undo];
        let rp = [Capability::Read, Capability::Propose];
        let mut nonce = link_nonces(&dir);
        let root_o =
            CapabilityLink::issue(&a, ROOT_PARENT, nonce(), repo(), pk(&o), caveats(&rpu, 1));
        let link_w = CapabilityLink::issue(
            &o,
            root_o.digest(),
            nonce(),
            repo(),
            pk(&w),
            caveats(&rpu, 4),
        );
        let link_v = CapabilityLink::issue(
            &o,
            root_o.digest(),
            nonce(),
            repo(),
            pk(&v),
            caveats(&rp, 4),
        );
        let co = CapabilityChain::new(vec![root_o]);
        let (cw, cv) = (co.extended(link_w), co.extended(link_v));
        for c in [&co, &cw, &cv] {
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
            nonce: 0,
        }
    }

    fn request(
        &mut self,
        who: &Agent,
        cap: Capability,
        scope: RequestScope,
        payload: Vec<u8>,
    ) -> ChainedRequest {
        self.nonce += 1;
        ChainedRequest::sign_new(
            &who.0,
            who.1.clone(),
            repo(),
            cap,
            scope,
            [self.nonce; 32],
            NOW,
            payload,
        )
    }

    /// `who` submits a revision of change `change` writing `body` to `src/lib.rs`.
    fn submit(&mut self, who: &Agent, change: u8, body: &[u8]) -> Result<ChangesetId, RefusalCode> {
        let c = ChangeId([change; 16]);
        let content = RevisionContent {
            change_id: c,
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
        let mut idem = [change; 32];
        idem[1] = self.nonce;
        let env = ChangesetEnvelopeV2::sign_new(&who.0, repo(), content, IdempotencyKey(idem), NOW);
        let scope = RequestScope {
            paths: vec!["src/lib.rs".into()],
            reference: None,
            join_change: Some(c),
        };
        let req = self.request(who, Capability::Propose, scope, env.encode());
        let blobs = vec![(BlobDigest::compute(body), body.to_vec())];
        match self
            .svc
            .submit_revision(&req, &blobs, NOW)
            .map_err(|e| e.code)?
        {
            RevisionOutcome::Admitted { changeset_id, .. } => Ok(changeset_id),
            other => panic!("expected an admission, got {other:?}"),
        }
    }

    fn undo(
        &mut self,
        who: &Agent,
        cap: Capability,
        target: WalSeq,
        actor: Option<&Agent>,
    ) -> Result<ViewOutcome, RefusalCode> {
        let payload = UndoPayload {
            target,
            actor: actor.map(chain_path),
        }
        .encode();
        let req = self.request(who, cap, RequestScope::default(), payload);
        self.svc.undo(&req, NOW).map_err(|e| e.code)
    }

    fn discard(
        &mut self,
        who: &Agent,
        id: ChangesetId,
        final_discard: bool,
    ) -> Result<ViewOutcome, RefusalCode> {
        let payload = DiscardPayload {
            changeset_id: id,
            final_discard,
        }
        .encode();
        let req = self.request(who, Capability::Propose, RequestScope::default(), payload);
        self.svc.discard(&req, NOW).map_err(|e| e.code)
    }

    fn seq(&self) -> WalSeq {
        self.svc.store().committed_seq()
    }

    fn heads(&self, change: u8) -> Vec<ChangesetId> {
        self.svc
            .store()
            .view(&repo())
            .heads
            .get(&ChangeId([change; 16]))
            .map(|h| h.iter().copied().collect())
            .unwrap_or_default()
    }
}

/// `undo` needs a chain granting `Undo` (`AuthCapabilityDenied` otherwise, nothing written);
/// with it, an undo restores the view of the target and undoing it gives the view back.
#[test]
fn b2_api_undo_requires_the_undo_capability() {
    let mut fx = Fx::new("cap");
    let (w, v) = (fx.w.clone(), fx.v.clone());
    let t = fx.seq();
    let rv = fx.submit(&v, 0x31, b"v attempt").unwrap();
    let seq = fx.seq();
    assert_eq!(
        fx.undo(&v, Capability::Undo, t, Some(&v)).unwrap_err(),
        RefusalCode::AuthCapabilityDenied
    );
    assert_eq!(
        fx.undo(&v, Capability::Propose, t, Some(&v)).unwrap_err(),
        RefusalCode::AuthCapabilityDenied
    );
    assert_eq!(fx.seq(), seq, "nothing written");
    assert_eq!(fx.heads(0x31), vec![rv]);

    let t = fx.seq();
    let rw = fx.submit(&w, 0x32, b"w attempt").unwrap();
    let before = fx.svc.store().view_at(&repo(), t).digest(&repo());
    let out = fx.undo(&w, Capability::Undo, t, Some(&w)).unwrap();
    assert_eq!(out.view_digest, before);
    assert_eq!(fx.heads(0x32), Vec::<ChangesetId>::new());
    assert_eq!(fx.heads(0x31), vec![rv]);
    fx.undo(&w, Capability::Undo, WalSeq(out.wal_seq.0 - 1), None)
        .unwrap();
    assert_eq!(fx.heads(0x32), vec![rw]);
    // Malformed payloads are refused typed.
    let req = fx.request(&w, Capability::Undo, RequestScope::default(), vec![1, 2, 3]);
    assert_eq!(
        fx.svc.undo(&req, NOW).unwrap_err().code,
        RefusalCode::EnvelopeMalformed
    );
}

/// Undoing another actor's work needs a chain that dominates that actor's: the sibling `W`
/// may not undo `V`'s revision, the orchestrator `O` may. A discard needs the owner chain.
#[test]
fn b2_api_undo_and_discard_of_another_actor_need_a_dominating_chain() {
    let mut fx = Fx::new("dominance");
    let (o, w, v) = (fx.o.clone(), fx.w.clone(), fx.v.clone());
    let t = fx.seq();
    let rv = fx.submit(&v, 0x41, b"v attempt").unwrap();
    assert_eq!(
        fx.undo(&w, Capability::Undo, t, None).unwrap_err(),
        RefusalCode::AuthChainNotDominant
    );
    assert_eq!(
        fx.undo(&w, Capability::Undo, t, Some(&v)).unwrap_err(),
        RefusalCode::AuthChainNotDominant
    );
    assert_eq!(
        fx.discard(&w, rv, false).unwrap_err(),
        RefusalCode::AuthChainNotDominant
    );
    assert_eq!(fx.heads(0x41), vec![rv]);
    fx.undo(&o, Capability::Undo, t, Some(&v)).unwrap();
    assert_eq!(fx.heads(0x41), Vec::<ChangesetId>::new());
}

/// A plain discard is undoable; a final discard is a fact: an undo reaching it is
/// `UndoIrreversible` even for the orchestrator, and the revision cannot be discarded again.
#[test]
fn b2_api_final_discard_can_never_be_undone() {
    let mut fx = Fx::new("discard");
    let (o, w) = (fx.o.clone(), fx.w.clone());
    let rw = fx.submit(&w, 0x51, b"w attempt").unwrap();
    let t = fx.seq();
    fx.discard(&w, rw, false).unwrap();
    assert_eq!(fx.heads(0x51), Vec::<ChangesetId>::new());
    fx.undo(&w, Capability::Undo, t, None).unwrap();
    assert_eq!(fx.heads(0x51), vec![rw]);
    let t = fx.seq();
    fx.discard(&w, rw, true).unwrap();
    assert_eq!(
        fx.undo(&o, Capability::Undo, t, None).unwrap_err(),
        RefusalCode::UndoIrreversible
    );
    assert_eq!(
        fx.discard(&w, rw, false).unwrap_err(),
        RefusalCode::DiscardInvalid
    );
    assert_eq!(fx.svc.store().view(&repo()).discarded.get(&rw), Some(&true));
}

/// A revocation is written to the operation log as a fact and enforced on requests: the
/// revoked worker's next request is `AuthGrantRevoked`, and an undo reaching the revocation
/// is `UndoIrreversible`. Only a dominating chain may revoke; a link never granted is
/// `AuthChainBroken`; neither refusal writes anything.
#[test]
fn b2_api_revocation_is_a_fact_and_is_enforced() {
    let mut fx = Fx::new("revoke");
    let (o, w, v) = (fx.o.clone(), fx.w.clone(), fx.v.clone());
    let t = fx.seq();
    fx.submit(&w, 0x61, b"w attempt").unwrap();
    let seq = fx.seq();
    assert_eq!(
        fx.svc
            .revoke_link(chain_path(&w), chain_path(&v), NOW)
            .unwrap_err()
            .code,
        RefusalCode::AuthChainNotDominant
    );
    let never = ChainPath::new(vec![[0xAB; 32]]).unwrap();
    assert_eq!(
        fx.svc
            .revoke_link(never.clone(), never, NOW)
            .unwrap_err()
            .code,
        RefusalCode::AuthChainBroken
    );
    assert_eq!(fx.seq(), seq, "nothing written");
    fx.svc
        .revoke_link(chain_path(&w), chain_path(&o), NOW)
        .unwrap();
    assert_eq!(
        fx.submit(&w, 0x62, b"after revocation").unwrap_err(),
        RefusalCode::AuthGrantRevoked
    );
    assert_eq!(
        fx.undo(&o, Capability::Undo, t, None).unwrap_err(),
        RefusalCode::UndoIrreversible
    );
    // V is untouched.
    fx.submit(&v, 0x63, b"v attempt").unwrap();
}
