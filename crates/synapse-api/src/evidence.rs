//! Read-only checks of evidence receipts against Synapse (ADR 0004, deliverable D4).
//!
//! Two reads, each under `Capability::Read`, neither of which writes anything or touches the
//! submission path:
//!
//! * [`SynapseService::evidence_base`] gives a runner the source revision and the
//!   per-directory `CrumbContextDigest`s it must bind for a changeset;
//! * [`SynapseService::verify_evidence_receipt`] checks a signed receipt, then recomputes
//!   those digests at the changeset's base and reports a typed [`ReceiptVerification`]. A
//!   context that differs is reported as [`ReceiptVerification::Stale`], never accepted.
//!
//! A `Current` verdict grants nothing: AEGIS stays the sole execution and publication
//! authority and Radicle canonical promotion stays independent. Receipts are not stored.

use crate::{SynapseService, TreeTarget, VirtualTreeEntry};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use synapse_auth::{AuthenticatedRequest, BoundaryKind, Capability};
use synapse_core::{ChangesetEnvelope, ChangesetId, RepoId, SynapseResult, WalSeq};
use synapse_crumb::{CrumbContextDigest, ROOT_DIR};
use synapse_evidence::{
    CrumbContextBinding, EvidenceReceipt, EvidenceReceiptId, Outcome, ReceiptError, SourceRevision,
};

/// Request payload for [`SynapseService::evidence_base`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceBaseQueryPayload {
    pub changeset_id: ChangesetId,
    pub snapshot_seq: Option<WalSeq>,
}

/// Request payload for [`SynapseService::verify_evidence_receipt`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerifyEvidenceReceiptPayload {
    /// Canonical receipt bytes ([`EvidenceReceipt::encode`]).
    pub receipt: Vec<u8>,
    pub snapshot_seq: Option<WalSeq>,
}

/// What a runner must bind for a changeset.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvidenceBase {
    pub source: SourceRevision,
    /// One per distinct directory of the changeset's mutated paths, sorted by directory.
    pub crumb_contexts: Vec<CrumbContextBinding>,
}

/// A directory whose context at the base differs from the one the receipt binds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StaleContext {
    pub dir: String,
    pub in_receipt: CrumbContextDigest,
    pub at_base: CrumbContextDigest,
}

/// Why a well-formed, correctly signed receipt does not describe this changeset.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReceiptMismatch {
    /// The receipt names another repository.
    Repository(RepoId),
    /// The receipt's source revision is not the changeset's base and parents.
    SourceRevision,
    /// The receipt binds a different directory set than the changeset's mutated paths give.
    ContextSet {
        missing: Vec<String>,
        extra: Vec<String>,
    },
}

/// Typed result of checking a receipt against Synapse. Only `Current` means the receipt
/// binds exactly the context at the changeset's base; even then it grants nothing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReceiptVerification {
    /// Signature, version, and structure hold, and every bound context matches the base.
    Current {
        receipt_id: EvidenceReceiptId,
        outcome: Outcome,
    },
    /// At least one bound context differs from the context at the changeset's base.
    Stale {
        receipt_id: EvidenceReceiptId,
        stale: Vec<StaleContext>,
    },
    /// The receipt is valid but describes something else.
    Mismatch {
        receipt_id: EvidenceReceiptId,
        reason: ReceiptMismatch,
    },
    /// The record itself is refused (bad signature, wrong domain, unknown version, malformed).
    Refused(ReceiptError),
}

impl SynapseService {
    /// Source revision and per-directory Crumb contexts at the base of `changeset_id`
    /// (`Capability::Read`). A runner binds these into its receipt.
    pub fn evidence_base(
        &mut self,
        req: &AuthenticatedRequest<EvidenceBaseQueryPayload>,
        now_ms: u64,
    ) -> SynapseResult<EvidenceBase> {
        self.auth.authorize(
            BoundaryKind::Api,
            "evidence_base",
            &self.repo_id,
            Capability::Read,
            req,
            now_ms,
        )?;
        let p = &req.payload;
        self.compute_evidence_base(p.changeset_id, p.snapshot_seq)
    }

    /// Check a signed receipt and recompute its Crumb contexts at the changeset's base
    /// (`Capability::Read`). An unknown or invisible changeset is an error, as for `get`.
    pub fn verify_evidence_receipt(
        &mut self,
        req: &AuthenticatedRequest<VerifyEvidenceReceiptPayload>,
        now_ms: u64,
    ) -> SynapseResult<ReceiptVerification> {
        self.auth.authorize(
            BoundaryKind::Api,
            "verify_evidence_receipt",
            &self.repo_id,
            Capability::Read,
            req,
            now_ms,
        )?;
        let (receipt, receipt_id) = match EvidenceReceipt::decode_verified(&req.payload.receipt) {
            Ok(v) => v,
            Err(e) => return Ok(ReceiptVerification::Refused(e)),
        };
        let body = &receipt.body;
        if body.repo_id != self.repo_id {
            return Ok(ReceiptVerification::Mismatch {
                receipt_id,
                reason: ReceiptMismatch::Repository(body.repo_id.clone()),
            });
        }
        let base = self.compute_evidence_base(body.changeset_id, req.payload.snapshot_seq)?;
        if base.source != body.source {
            return Ok(ReceiptVerification::Mismatch {
                receipt_id,
                reason: ReceiptMismatch::SourceRevision,
            });
        }
        let want: BTreeSet<&str> = base.crumb_contexts.iter().map(|c| c.dir.as_str()).collect();
        let got: BTreeSet<&str> = body.crumb_contexts.iter().map(|c| c.dir.as_str()).collect();
        if want != got {
            return Ok(ReceiptVerification::Mismatch {
                receipt_id,
                reason: ReceiptMismatch::ContextSet {
                    missing: want.difference(&got).map(|d| d.to_string()).collect(),
                    extra: got.difference(&want).map(|d| d.to_string()).collect(),
                },
            });
        }
        // Both lists are sorted by directory and hold the same set, so they pair up.
        let stale: Vec<StaleContext> = body
            .crumb_contexts
            .iter()
            .zip(&base.crumb_contexts)
            .filter(|(r, b)| r.digest != b.digest)
            .map(|(r, b)| StaleContext {
                dir: r.dir.clone(),
                in_receipt: r.digest,
                at_base: b.digest,
            })
            .collect();
        if stale.is_empty() {
            Ok(ReceiptVerification::Current {
                receipt_id,
                outcome: body.result.outcome,
            })
        } else {
            Ok(ReceiptVerification::Stale { receipt_id, stale })
        }
    }

    /// No authorization: callers authorize first.
    fn compute_evidence_base(
        &mut self,
        changeset_id: ChangesetId,
        snapshot_seq: Option<WalSeq>,
    ) -> SynapseResult<EvidenceBase> {
        let envelope = self
            .store
            .get_changeset(changeset_id, None, snapshot_seq)?
            .envelope;
        let tree = self.base_tree(&envelope, snapshot_seq)?;
        let mut crumb_contexts = Vec::new();
        for dir in mutated_dirs(&envelope) {
            let digest = self
                .resolve_crumb_context(&tree, &dir, snapshot_seq)?
                .digest();
            crumb_contexts.push(CrumbContextBinding { dir, digest });
        }
        Ok(EvidenceBase {
            source: SourceRevision {
                base_git_oid: envelope.base_git_oid,
                parent_changesets: envelope.parent_changesets.clone(),
            },
            crumb_contexts,
        })
    }

    /// The tree a changeset was built on: its base Git tree when it has no parents, else its
    /// parents overlaid in order (the same order `materialize_virtual_tree` uses).
    fn base_tree(
        &mut self,
        envelope: &ChangesetEnvelope,
        snapshot_seq: Option<WalSeq>,
    ) -> SynapseResult<BTreeMap<String, VirtualTreeEntry>> {
        if envelope.parent_changesets.is_empty() {
            return self.materialize_virtual_tree(
                TreeTarget::BaseGitCommit(envelope.base_git_oid),
                snapshot_seq,
            );
        }
        let mut merged = BTreeMap::new();
        for &parent in &envelope.parent_changesets {
            merged.extend(
                self.materialize_virtual_tree(TreeTarget::Changeset(parent), snapshot_seq)?,
            );
        }
        Ok(merged)
    }
}

/// Distinct parent directories of the mutated paths (`"."` for the root), sorted.
fn mutated_dirs(envelope: &ChangesetEnvelope) -> BTreeSet<String> {
    envelope
        .mutations
        .iter()
        .map(|m| {
            m.path
                .rsplit_once('/')
                .map_or(ROOT_DIR.to_string(), |(dir, _)| dir.to_string())
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{FsyncPolicy, IngestOutcome, RecoveryPolicy, StoreLimits, SubmitChangesetPayload};
    use ed25519_dalek::{Signer, SigningKey};
    use std::path::PathBuf;
    use synapse_auth::AgentCapabilityGrant;
    use synapse_core::{
        encode_did_key_ed25519, BlobDigest, FileMode, GitOid, IdempotencyKey, MutationOp,
        PathMutation, RefusalCode, SYNAPSE_ENVELOPE_VERSION,
    };
    use synapse_evidence::{
        ExitStatus, InputRoot, Observation, ReceiptBody, ReceiptResult, TestIdentity,
    };

    const ROOT: &[u8] = br#"{"schema_version":"1.0.0","name":"root","purpose":"Root."}"#;
    const SRC: &[u8] = br#"{"schema_version":"1.0.0","name":"src","purpose":"Sources."}"#;

    struct Fixture {
        svc: SynapseService,
        auth: SigningKey,
        agent: SigningKey,
        runner: SigningKey,
        repo: RepoId,
        nonce: u8,
        dir: PathBuf,
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }

    impl Fixture {
        fn new(label: &str) -> Self {
            let dir = std::env::temp_dir().join(format!(
                "synapse-api-evidence-{label}-{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            ));
            let repo = RepoId::new("aien-spark/synapse").unwrap();
            let mut svc = SynapseService::open(
                &dir,
                repo.clone(),
                FsyncPolicy::EveryCommit,
                RecoveryPolicy::StrictFailClosed,
                StoreLimits::default(),
            )
            .unwrap();
            let auth = SigningKey::from_bytes(&[10u8; 32]);
            svc.register_authority(encode_did_key_ed25519(&auth.verifying_key().to_bytes()));
            for (seed, src) in [
                (1u8, SRC),
                (
                    2u8,
                    b"{\"schema_version\":\"1.0.0\",\"name\":\"src\",\"purpose\":\"Changed.\"}"
                        .as_slice(),
                ),
            ] {
                svc.register_base_tree(
                    GitOid([seed; 20]),
                    vec![
                        (".crumb".into(), FileMode::Regular644, ROOT.to_vec()),
                        ("src/.crumb".into(), FileMode::Regular644, src.to_vec()),
                        (
                            "src/a.rs".into(),
                            FileMode::Regular644,
                            b"fn a() {}\n".to_vec(),
                        ),
                    ],
                )
                .unwrap();
            }
            Self {
                svc,
                auth,
                agent: SigningKey::from_bytes(&[20u8; 32]),
                runner: SigningKey::from_bytes(&[30u8; 32]),
                repo,
                nonce: 0,
                dir,
            }
        }

        fn sign<T: Serialize>(&mut self, cap: Capability, payload: T) -> AuthenticatedRequest<T> {
            self.nonce += 1;
            let grant = AgentCapabilityGrant::issue(
                &self.auth,
                [self.nonce; 32],
                self.repo.clone(),
                encode_did_key_ed25519(&self.agent.verifying_key().to_bytes()),
                vec![Capability::Read, Capability::Propose],
                4 * 1024 * 1024,
                100,
                60_000,
                10,
                100_000,
            );
            AuthenticatedRequest::sign_new(
                &self.agent,
                grant,
                self.repo.clone(),
                cap,
                [self.nonce; 32],
                self.now(),
                0,
                payload,
            )
            .unwrap()
        }

        fn now(&self) -> u64 {
            1000 + u64::from(self.nonce)
        }

        /// Submit a changeset on base `seed` upserting `src/b.rs` and `docs/x.md`.
        fn propose(&mut self, seed: u8) -> ChangesetId {
            let files: [(&str, &[u8]); 2] = [("docs/x.md", b"# x\n"), ("src/b.rs", b"fn b() {}\n")];
            let mut env = ChangesetEnvelope {
                version: SYNAPSE_ENVELOPE_VERSION,
                repo_id: self.repo.clone(),
                base_git_oid: GitOid([seed; 20]),
                parent_changesets: vec![],
                author_did: String::new(),
                idempotency_key: IdempotencyKey::from_label(&format!("ev-{seed}")),
                created_at_ms: 100,
                intent_summary: "evidence fixture".into(),
                mutations: files
                    .iter()
                    .map(|(p, b)| PathMutation {
                        path: p.to_string(),
                        op: MutationOp::Upsert {
                            mode: FileMode::Regular644,
                            blob_digest: BlobDigest::compute(b),
                            size_bytes: b.len() as u64,
                        },
                    })
                    .collect(),
                evidence_receipts: vec![],
                signature: vec![],
            };
            let agent = self.agent.clone();
            env.sign(&agent);
            let blobs = files
                .iter()
                .map(|(_, b)| (BlobDigest::compute(b), b.to_vec()))
                .collect();
            let req = self.sign(
                Capability::Propose,
                SubmitChangesetPayload {
                    envelope: env,
                    blobs,
                },
            );
            match self.svc.submit(&req, self.now()).unwrap() {
                IngestOutcome::Committed { changeset_id, .. } => changeset_id,
                other => panic!("unexpected {other:?}"),
            }
        }

        fn base(&mut self, cs: ChangesetId) -> EvidenceBase {
            let req = self.sign(
                Capability::Read,
                EvidenceBaseQueryPayload {
                    changeset_id: cs,
                    snapshot_seq: None,
                },
            );
            self.svc.evidence_base(&req, self.now()).unwrap()
        }

        fn receipt(&self, cs: ChangesetId, base: EvidenceBase) -> EvidenceReceipt {
            EvidenceReceipt::sign(
                ReceiptBody {
                    repo_id: self.repo.clone(),
                    changeset_id: cs,
                    source: base.source,
                    crumb_contexts: base.crumb_contexts,
                    input_root: InputRoot::single_repo(self.repo.clone(), cs),
                    test: TestIdentity {
                        name: "unit".into(),
                        command: vec!["cargo".into(), "test".into()],
                        toolchain: "rustc".into(),
                        platform: "aarch64-unknown-linux-gnu".into(),
                        environment: vec![],
                    },
                    result: ReceiptResult {
                        exit_status: ExitStatus::Code(0),
                        outcome: Outcome::Pass,
                        outputs: vec![],
                    },
                    observation: Observation {
                        started_at_ms: 1,
                        duration_ms: 2,
                        log: b"ok\n".to_vec(),
                    },
                },
                &self.runner,
            )
            .unwrap()
        }

        fn verify(&mut self, bytes: Vec<u8>) -> SynapseResult<ReceiptVerification> {
            let req = self.sign(
                Capability::Read,
                VerifyEvidenceReceiptPayload {
                    receipt: bytes,
                    snapshot_seq: None,
                },
            );
            self.svc.verify_evidence_receipt(&req, self.now())
        }
    }

    #[test]
    fn base_binds_one_context_per_mutated_directory() {
        let mut fx = Fixture::new("base");
        let cs = fx.propose(1);
        let base = fx.base(cs);
        let dirs: Vec<&str> = base.crumb_contexts.iter().map(|c| c.dir.as_str()).collect();
        assert_eq!(dirs, ["docs", "src"]);
        assert_eq!(base.source.base_git_oid, GitOid([1; 20]));
        assert!(base.source.parent_changesets.is_empty());
    }

    #[test]
    fn matching_receipt_is_current_and_grants_nothing() {
        let mut fx = Fixture::new("current");
        let cs = fx.propose(1);
        let base = fx.base(cs);
        let r = fx.receipt(cs, base);
        let v = fx.verify(r.encode()).unwrap();
        assert_eq!(
            v,
            ReceiptVerification::Current {
                receipt_id: r.id(),
                outcome: Outcome::Pass
            }
        );
    }

    #[test]
    fn context_from_another_base_is_stale_not_accepted() {
        let mut fx = Fixture::new("stale");
        let cs1 = fx.propose(1);
        let cs2 = fx.propose(2);
        // The runner saw base 2's `src/.crumb` but signs for the changeset on base 1.
        let seen = fx.base(cs2);
        let mut bound = fx.base(cs1);
        bound.crumb_contexts = seen.crumb_contexts.clone();
        let truth = fx.base(cs1);
        let r = fx.receipt(cs1, bound);
        match fx.verify(r.encode()).unwrap() {
            ReceiptVerification::Stale { receipt_id, stale } => {
                assert_eq!(receipt_id, r.id());
                assert_eq!(stale.len(), 1);
                assert_eq!(stale[0].dir, "src");
                assert_eq!(stale[0].in_receipt, seen.crumb_contexts[1].digest);
                assert_eq!(stale[0].at_base, truth.crumb_contexts[1].digest);
            }
            other => panic!("expected Stale, got {other:?}"),
        }
    }

    #[test]
    fn wrong_source_or_directory_set_is_a_mismatch() {
        let mut fx = Fixture::new("mismatch");
        let cs = fx.propose(1);
        let mut base = fx.base(cs);
        base.source.base_git_oid = GitOid([2; 20]);
        let r = fx.receipt(cs, base);
        assert!(matches!(
            fx.verify(r.encode()).unwrap(),
            ReceiptVerification::Mismatch {
                reason: ReceiptMismatch::SourceRevision,
                ..
            }
        ));

        let mut base = fx.base(cs);
        base.crumb_contexts.remove(0);
        let r = fx.receipt(cs, base);
        assert_eq!(
            fx.verify(r.encode()).unwrap(),
            ReceiptVerification::Mismatch {
                receipt_id: r.id(),
                reason: ReceiptMismatch::ContextSet {
                    missing: vec!["docs".into()],
                    extra: vec![],
                },
            }
        );
    }

    #[test]
    fn forged_or_unknown_receipts_are_refused() {
        let mut fx = Fixture::new("refused");
        let cs = fx.propose(1);
        let base = fx.base(cs);
        let mut r = fx.receipt(cs, base);
        r.signature = SigningKey::from_bytes(&[99u8; 32])
            .sign(&r.signable_bytes())
            .to_bytes();
        assert_eq!(
            fx.verify(r.encode()).unwrap(),
            ReceiptVerification::Refused(ReceiptError::SignatureInvalid)
        );
        assert_eq!(
            fx.verify(b"not a receipt".to_vec()).unwrap(),
            ReceiptVerification::Refused(ReceiptError::WrongDomain)
        );
        // A receipt for a changeset Synapse does not have is an error, not a verdict.
        let base = fx.base(cs);
        let ghost = ChangesetId([0xee; 32]);
        let r = fx.receipt(ghost, base);
        assert_eq!(
            fx.verify(r.encode()).unwrap_err().code,
            RefusalCode::ChangesetNotFound
        );
    }
}
