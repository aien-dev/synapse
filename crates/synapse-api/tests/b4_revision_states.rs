//! ADR 0003 step B4 through the API with real signed F1 capability chains: authority `A`
//! grants orchestrator `O`, outsider `X`, and publisher `P` (root links; `P` may also
//! `Publish` and touch the canonical reference through the promotion queue); `O` delegates
//! worker `W` (scoped to `src`), worker `V` (whole repository), and reader `D` (scoped to
//! `docs`).

use ed25519_dalek::SigningKey;
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use synapse_api::{RevisionStateMovePayload, SynapseService, TreeTarget};
use synapse_auth::{
    Capability, CapabilityChain, CapabilityLink, ChainQuotas, ChainedRequest, ChangeScope,
    LinkCaveats, OperationSet, PathScope, ReferenceKind, ReferenceScope, RequestScope, ROOT_PARENT,
};
use synapse_core::{
    encode_did_key_ed25519, BlobDigest, ChangeId, ChangesetEnvelopeV2, ChangesetId, FileMode,
    GitOid, IdempotencyKey, MutationOp, PathMutation, RefusalCode, RepoId, RevisionContent,
    RevisionState, TreeDigest, WalSeq,
};
use synapse_store::{FsyncPolicy, RecoveryPolicy, RevisionOutcome, StoreLimits, StoredRevision};

const NOW: u64 = 2_000;
const C: ChangeId = ChangeId([0xC4; 16]);

type Agent = (SigningKey, CapabilityChain);

/// Link nonces for one fixture: SHA-256 of the fixture's unique directory and a counter, so
/// every link gets a fresh nonce and none is a fixed value.
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

fn caveats(
    ops: &[Capability],
    paths: PathScope,
    refs: &[ReferenceKind],
    share: u64,
) -> LinkCaveats {
    LinkCaveats {
        operations: OperationSet::from_capabilities(ops),
        paths,
        references: ReferenceScope::from_kinds(refs),
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
    d: Agent,
    x: Agent,
    p: Agent,
    nonce: u8,
}

impl Fx {
    fn new(name: &str) -> Self {
        let dir: PathBuf = std::env::temp_dir().join(format!(
            "synapse-b4-api-{name}-{}-{}",
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
        let (o, w, v, d, x, p) = (key(2), key(3), key(4), key(5), key(9), key(7));
        svc.auth_mut()
            .register_repo_authority(repo(), encode_did_key_ed25519(&pk(&a)));
        let rp = [Capability::Read, Capability::Propose];
        let own = [ReferenceKind::OwnDrafts];
        let whole = PathScope::whole_repository;
        let mut nonce = link_nonces(&dir);
        let root = |nonce: [u8; 32], to: &SigningKey, c: LinkCaveats| {
            CapabilityLink::issue(&a, ROOT_PARENT, nonce, repo(), pk(to), c)
        };
        let root_o = root(nonce(), &o, caveats(&rp, whole(), &own, 1));
        let root_x = root(nonce(), &x, caveats(&rp, whole(), &own, 1));
        let root_p = root(
            nonce(),
            &p,
            caveats(
                &[Capability::Read, Capability::Propose, Capability::Publish],
                whole(),
                &[
                    ReferenceKind::OwnDrafts,
                    ReferenceKind::CanonicalViaPromotionQueue,
                ],
                1,
            ),
        );
        let child = |nonce: [u8; 32], to: &SigningKey, paths: PathScope| {
            CapabilityLink::issue(
                &o,
                root_o.digest(),
                nonce,
                repo(),
                pk(to),
                caveats(&rp, paths, &own, 4),
            )
        };
        let link_w = child(nonce(), &w, PathScope::new(vec!["src".into()]).unwrap());
        let link_v = child(nonce(), &v, whole());
        let link_d = child(nonce(), &d, PathScope::new(vec!["docs".into()]).unwrap());
        let co = CapabilityChain::new(vec![root_o]);
        let cx = CapabilityChain::new(vec![root_x]);
        let cp = CapabilityChain::new(vec![root_p]);
        let (cw, cv, cd) = (
            co.extended(link_w),
            co.extended(link_v),
            co.extended(link_d),
        );
        for c in [&co, &cx, &cp, &cw, &cv, &cd] {
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
            d: (d, cd),
            x: (x, cx),
            p: (p, cp),
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

    /// `who` submits a revision of change `C` writing `body` to `src/lib.rs`.
    fn submit(&mut self, who: &Agent, body: &[u8], idem: u8) -> ChangesetId {
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
        let env =
            ChangesetEnvelopeV2::sign_new(&who.0, repo(), content, IdempotencyKey([idem; 32]), NOW);
        let scope = RequestScope {
            paths: vec!["src/lib.rs".into()],
            reference: None,
            join_change: Some(C),
        };
        let req = self.request(who, Capability::Propose, scope, env.encode());
        let blobs = vec![(BlobDigest::compute(body), body.to_vec())];
        match self.svc.submit_revision(&req, &blobs, NOW).unwrap() {
            RevisionOutcome::Admitted { changeset_id, .. } => changeset_id,
            other => panic!("expected an admission, got {other:?}"),
        }
    }

    fn read(
        &mut self,
        who: &Agent,
        id: ChangesetId,
    ) -> Result<StoredRevision, (RefusalCode, String)> {
        let req = self.request(
            who,
            Capability::Read,
            RequestScope::default(),
            id.0.to_vec(),
        );
        self.svc
            .read_revision(&req, NOW)
            .map_err(|e| (e.code, e.message))
    }

    fn mv(
        &mut self,
        who: &Agent,
        id: ChangesetId,
        to: RevisionState,
    ) -> Result<WalSeq, RefusalCode> {
        let payload = RevisionStateMovePayload {
            changeset_id: id,
            to,
        }
        .encode();
        let req = self.request(who, Capability::Propose, RequestScope::default(), payload);
        self.svc
            .advance_revision_state(&req, NOW)
            .map_err(|e| e.code)
    }
}

/// Acceptance 2 with real F1 chains: `W`'s `Private` revision is readable by `W` and by `O`
/// (whose grant `W`'s descends from) and by nobody else: not by the sibling `V`, the reader
/// `D`, or the outsider `X`, each refused exactly like an unknown revision; none of them can
/// move it. After `W` moves it to `Draft` it is visible within `Read` scope: to `V` and `X`,
/// still not to `D`, whose path scope does not cover `src/lib.rs`.
#[test]
fn b4_api_private_revision_is_invisible_outside_its_owner_chain_with_real_f1_chains() {
    let mut fx = Fx::new("private");
    let (o, w, v, d, x, p) = (
        fx.o.clone(),
        fx.w.clone(),
        fx.v.clone(),
        fx.d.clone(),
        fx.x.clone(),
        fx.p.clone(),
    );
    fx.submit(&o, b"orchestrator attempt", 1);
    let rev = fx.submit(&w, b"worker private attempt", 1);
    assert_eq!(fx.read(&w, rev).unwrap().state, RevisionState::Private);
    assert_eq!(fx.read(&o, rev).unwrap().changeset_id, rev);
    let unknown = ChangesetId([0xEE; 32]);
    let (code, msg) = fx.read(&o, unknown).unwrap_err();
    assert_eq!(code, RefusalCode::ChangesetNotFound);
    for outsider in [&v, &d, &x, &p] {
        let (c, m) = fx.read(outsider, rev).unwrap_err();
        assert_eq!(c, code);
        assert_eq!(m, msg.replace(&unknown.to_string(), &rev.to_string()));
        assert_eq!(
            fx.mv(outsider, rev, RevisionState::Draft).unwrap_err(),
            RefusalCode::ChangesetNotFound
        );
    }
    // The owner shares it: Draft is visible within Read scope.
    fx.mv(&w, rev, RevisionState::Draft).unwrap();
    for reader in [&o, &w, &v, &x, &p] {
        assert_eq!(fx.read(reader, rev).unwrap().state, RevisionState::Draft);
    }
    assert_eq!(
        fx.read(&d, rev).unwrap_err().0,
        RefusalCode::ChangesetNotFound
    );
    // A non-owner may read the Draft but not move it.
    assert_eq!(
        fx.mv(&v, rev, RevisionState::Proposed).unwrap_err(),
        RefusalCode::AuthChainNotDominant
    );
    // The orchestrator, whose grant W's descends from, may propose it; then it never goes back.
    fx.mv(&o, rev, RevisionState::Proposed).unwrap();
    for to in [
        RevisionState::Private,
        RevisionState::Draft,
        RevisionState::Proposed,
    ] {
        assert_eq!(
            fx.mv(&w, rev, to).unwrap_err(),
            RefusalCode::RevisionStateMoveInvalid
        );
    }
    assert_eq!(fx.read(&x, rev).unwrap().state, RevisionState::Proposed);
}

/// Acceptance 3 with real F1 chains: a move to `Canonical` through the state API is refused
/// for every chain, including one whose grant allows `Publish` and the canonical reference
/// through the promotion queue; nothing is written. Malformed payloads are refused typed.
#[test]
fn b4_api_move_to_canonical_outside_the_promotion_queue_is_refused() {
    let mut fx = Fx::new("canonical");
    let (o, w, x, p) = (fx.o.clone(), fx.w.clone(), fx.x.clone(), fx.p.clone());
    let rev = fx.submit(&w, b"worker attempt", 1);
    fx.mv(&w, rev, RevisionState::Proposed).unwrap();
    let before = fx.svc.store().committed_seq();
    for who in [&o, &w, &x, &p] {
        for id in [rev, ChangesetId([0xEE; 32])] {
            assert_eq!(
                fx.mv(who, id, RevisionState::Canonical).unwrap_err(),
                RefusalCode::CanonicalOutsidePromotionQueue
            );
        }
    }
    // Asking with the canonical reference in the request scope changes nothing.
    let payload = RevisionStateMovePayload {
        changeset_id: rev,
        to: RevisionState::Canonical,
    }
    .encode();
    let scope = RequestScope {
        paths: vec![],
        reference: Some(ReferenceKind::CanonicalViaPromotionQueue),
        join_change: None,
    };
    let req = fx.request(&p, Capability::Propose, scope, payload);
    assert_eq!(
        fx.svc.advance_revision_state(&req, NOW).unwrap_err().code,
        RefusalCode::CanonicalOutsidePromotionQueue
    );
    assert_eq!(
        fx.mv(&w, rev, RevisionState::Verified).unwrap_err(),
        RefusalCode::RevisionStateMoveInvalid
    );
    assert_eq!(fx.svc.store().committed_seq(), before, "nothing written");
    assert_eq!(
        fx.svc.store().get_revision(&repo(), rev).unwrap().state,
        RevisionState::Proposed
    );
    // Payloads: exactly changeset_id [32] | state 1..=5.
    let mut bad_tag = rev.0.to_vec();
    bad_tag.push(6);
    for payload in [vec![], rev.0.to_vec(), bad_tag, vec![0; 34]] {
        let req = fx.request(&w, Capability::Propose, RequestScope::default(), payload);
        assert_eq!(
            fx.svc.advance_revision_state(&req, NOW).unwrap_err().code,
            RefusalCode::EnvelopeMalformed
        );
    }
    let req = fx.request(&w, Capability::Read, RequestScope::default(), vec![0; 31]);
    assert_eq!(
        fx.svc.read_revision(&req, NOW).unwrap_err().code,
        RefusalCode::EnvelopeMalformed
    );
}

/// Joins with real F1 chains: `W`, whose grant descends from `O`'s, submits content
/// byte-identical to `O`'s `Private` revision and joins it (B1), but gains no ownership: it
/// cannot read the revision (so not `O`'s witness or attestation) and cannot move it to
/// `Draft`, so the outsider `X` still cannot see it. Only after `O` shares it can `W` read
/// it, and moving it stays `O`'s.
#[test]
fn b4_api_joining_identical_content_grants_no_ownership_of_a_private_revision() {
    let mut fx = Fx::new("join");
    let (o, w, x) = (fx.o.clone(), fx.w.clone(), fx.x.clone());
    let rev = fx.submit(&o, b"orchestrator private attempt", 1);
    assert_eq!(fx.submit(&w, b"orchestrator private attempt", 2), rev);
    assert_eq!(fx.read(&o, rev).unwrap().witnesses.len(), 2);
    for who in [&w, &x] {
        assert_eq!(
            fx.read(who, rev).unwrap_err().0,
            RefusalCode::ChangesetNotFound
        );
    }
    assert_eq!(
        fx.mv(&w, rev, RevisionState::Draft).unwrap_err(),
        RefusalCode::ChangesetNotFound
    );
    assert_eq!(
        fx.read(&x, rev).unwrap_err().0,
        RefusalCode::ChangesetNotFound
    );
    fx.mv(&o, rev, RevisionState::Draft).unwrap();
    assert_eq!(fx.read(&w, rev).unwrap().state, RevisionState::Draft);
    assert_eq!(
        fx.mv(&w, rev, RevisionState::Proposed).unwrap_err(),
        RefusalCode::AuthChainNotDominant
    );
}
