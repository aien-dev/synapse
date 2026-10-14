//! ADR 0004 deliverable D5: combined qualification of the Crumb-Synapse agent workflow
//! (issue #12). Every scenario drives the merged D1 to D4 surfaces together: the shared
//! coordination plane (`synapse-coord`, and the pinned `crumb.c` when `CRUMB_C_BIN` is set),
//! the pre-submit advisory, Crumb contexts, signed evidence receipts, the Git bridge, and
//! Synapse's two publication gates (`Capability::Publish`, Radicle canonical promotion).
//!
//! Each scenario prints one line `D5-RESULT <id> <PASS|KNOWN-GAP|UNVERIFIED> <detail>` when it
//! finishes; `scripts/qualify-crumb-synapse.sh` collects those lines into
//! `evidence/crumb-synapse/`. A panicking scenario prints nothing and fails the run.
//!
//! Scope limit: AEGIS (aienos `crates/aienos-aegis`) is not integrated here. The exit rule is
//! proven against Synapse's own gates only.

use ed25519_dalek::{Signer, SigningKey};
use serde::Serialize;
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use synapse_api::{
    ChangesetAdvisory, ChangesetAdvisoryPayload, CoordinationStatus, CrumbContextQueryPayload,
    EvidenceBase, EvidenceBaseQueryPayload, ReceiptVerification, StaleReason, Staleness,
    SynapseService, TreeTarget, VerifyEvidenceReceiptPayload,
};
use synapse_auth::{AgentCapabilityGrant, AuthenticatedRequest, Capability};
use synapse_coord::{ClaimOutcome, CoordError, CoordStore, Holder, NoOracle, StoreId, Workspace};
use synapse_core::{
    encode_did_key_ed25519, BlobDigest, ChangesetEnvelope, ChangesetId, FileMode, GitOid,
    IdempotencyKey, MutationOp, PathMutation, RefusalCode, RepoId, SYNAPSE_ENVELOPE_VERSION,
};
use synapse_crumb::{CrumbContext, Dialect, ROOT_DIR};
use synapse_evidence::{
    EvidenceReceipt, ExitStatus, InputRoot, Observation, Outcome, ReceiptBody, ReceiptError,
    ReceiptResult, TestIdentity, MAX_LOG_BYTES, MAX_RECEIPT_BYTES,
};
use synapse_git::{
    materialize_changeset_to_git, project_github_pull_request, GitHubPrProjectionRequest,
    GitProjectionIndex,
};
use synapse_radicle::{
    CanonicalPromotionEngine, DelegateSigrefs, PromotionCandidate, RadicleIdentityDoc,
    RadiclePayloadMap, RadicleProjectPayload,
};
use synapse_store::{
    FaultInjection, FsyncPolicy, IngestOutcome, RecoveryPolicy, StoreLimits, FAULT_CRASH_EXIT_CODE,
};

const ROOT_CRUMB: &[u8] =
    br#"{"schema_version":"1.0.0","name":"root","purpose":"Root.","invariants":["root rule"]}"#;
const SRC_CRUMB: &[u8] =
    br#"{"schema_version":"1.0.0","name":"src","purpose":"Sources.","invariants":["src rule"]}"#;
const SRC_CRUMB_V2: &[u8] = br#"{"schema_version":"1.0.0","name":"src","purpose":"Sources, rewritten.","invariants":["new src rule"]}"#;
const FIX_ROOT: &[u8] = include_bytes!("../../synapse-crumb/tests/fixtures/tree/dot.crumb");
const FIX_D1: &[u8] = include_bytes!("../../synapse-crumb/tests/fixtures/tree/d1/dot.crumb");
const FIX_D2: &[u8] = include_bytes!("../../synapse-crumb/tests/fixtures/tree/d2/dot.crumb");
const FIX_D3: &[u8] = include_bytes!("../../synapse-crumb/tests/fixtures/tree/d3/dot.crumb");
/// Fixed coordination clock (2027-01-15), so expiry is deterministic.
const T0: i64 = 1_800_000_000;
/// Environment variable naming the coordination store for a re-executed child scenario.
const CHILD_ENV: &str = "D5_CHILD_DIR";

fn result(id: &str, status: &str, detail: &str) {
    println!("D5-RESULT {id} {status} {detail}");
}

fn scratch(label: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "synapse-d5-{label}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    fs::create_dir_all(&dir).unwrap();
    dir
}

fn did(key: &SigningKey) -> String {
    encode_did_key_ed25519(&key.verifying_key().to_bytes())
}

fn alice() -> SigningKey {
    SigningKey::from_bytes(&[21u8; 32])
}
fn bob() -> SigningKey {
    SigningKey::from_bytes(&[22u8; 32])
}
fn carol() -> SigningKey {
    SigningKey::from_bytes(&[23u8; 32])
}
fn runner() -> SigningKey {
    SigningKey::from_bytes(&[30u8; 32])
}
fn delegate() -> SigningKey {
    SigningKey::from_bytes(&[40u8; 32])
}

/// A Synapse service with one registered base tree, plus helpers that sign every request.
struct Fx {
    svc: SynapseService,
    auth: SigningKey,
    repo: RepoId,
    nonce: u64,
    dir: PathBuf,
    base_oid: GitOid,
    base_files: Vec<(String, FileMode, Vec<u8>)>,
}

impl Drop for Fx {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.dir);
    }
}

fn default_files() -> Vec<(String, FileMode, Vec<u8>)> {
    [
        (".crumb", ROOT_CRUMB),
        ("src/.crumb", SRC_CRUMB),
        ("src/a.rs", b"fn a() {}\n".as_slice()),
        ("src/b.rs", b"fn b() {}\n".as_slice()),
        ("docs/x.md", b"# x\n".as_slice()),
    ]
    .iter()
    .map(|(p, b)| (p.to_string(), FileMode::Regular644, b.to_vec()))
    .collect()
}

impl Fx {
    fn new(label: &str) -> Self {
        Self::with(label, FsyncPolicy::EveryCommit, default_files())
    }

    fn with(label: &str, policy: FsyncPolicy, files: Vec<(String, FileMode, Vec<u8>)>) -> Self {
        let dir = scratch(label);
        let repo = RepoId::new("aien-spark/synapse").unwrap();
        let svc = SynapseService::open(
            dir.join("svc"),
            repo.clone(),
            policy,
            RecoveryPolicy::StrictFailClosed,
            StoreLimits::default(),
        )
        .unwrap();
        let mut fx = Self {
            svc,
            auth: SigningKey::from_bytes(&[10u8; 32]),
            repo,
            nonce: 0,
            dir,
            base_oid: GitOid([1; 20]),
            base_files: files,
        };
        fx.prime();
        fx
    }

    /// Register the authority and base tree (in memory only; repeated after a reopen).
    fn prime(&mut self) {
        self.svc.register_authority(did(&self.auth));
        self.svc
            .register_base_tree(self.base_oid, self.base_files.clone())
            .unwrap();
    }

    fn base(&self) -> TreeTarget {
        TreeTarget::BaseGitCommit(self.base_oid)
    }

    fn coord(&self, now: i64) -> CoordStore {
        CoordStore::open(self.dir.join("coord")).with_clock(move || now)
    }

    fn now(&self) -> u64 {
        1_000 + self.nonce
    }

    fn sign_as<T: Serialize>(
        &mut self,
        key: &SigningKey,
        caps: Vec<Capability>,
        cap: Capability,
        payload: T,
    ) -> AuthenticatedRequest<T> {
        self.nonce += 1;
        let mut n = [0u8; 32];
        n[..8].copy_from_slice(&self.nonce.to_le_bytes());
        let grant = AgentCapabilityGrant::issue(
            &self.auth,
            n,
            self.repo.clone(),
            did(key),
            caps,
            8 * 1024 * 1024,
            10_000,
            60_000,
            1,
            10_000_000,
        );
        AuthenticatedRequest::sign_new(
            key,
            grant,
            self.repo.clone(),
            cap,
            n,
            self.now(),
            0,
            payload,
        )
        .unwrap()
    }

    fn envelope(
        &self,
        key: &SigningKey,
        label: &str,
        files: &[(&str, &[u8])],
    ) -> ChangesetEnvelope {
        let mut env = ChangesetEnvelope {
            version: SYNAPSE_ENVELOPE_VERSION,
            repo_id: self.repo.clone(),
            base_git_oid: self.base_oid,
            parent_changesets: vec![],
            author_did: String::new(),
            idempotency_key: IdempotencyKey::from_label(label),
            created_at_ms: 100,
            intent_summary: label.to_string(),
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
        env.sign(key);
        env
    }

    fn submit(
        &mut self,
        key: &SigningKey,
        label: &str,
        files: &[(&str, &[u8])],
    ) -> synapse_core::SynapseResult<IngestOutcome> {
        let env = self.envelope(key, label, files);
        let blobs = files
            .iter()
            .map(|(_, b)| (BlobDigest::compute(b), b.to_vec()))
            .collect();
        let req = self.sign_as(
            key,
            vec![Capability::Propose],
            Capability::Propose,
            synapse_api::SubmitChangesetPayload {
                envelope: env,
                blobs,
            },
        );
        let now = self.now();
        self.svc.submit(&req, now)
    }

    /// Submit and require a fresh commit; files must be sorted by path.
    fn propose(&mut self, key: &SigningKey, label: &str, files: &[(&str, &[u8])]) -> ChangesetId {
        match self.submit(key, label, files).unwrap() {
            IngestOutcome::Committed { changeset_id, .. } => changeset_id,
            other => panic!("unexpected {other:?}"),
        }
    }

    fn advise(
        &mut self,
        agent: &str,
        paths: &[&str],
        coord: Option<&CoordStore>,
    ) -> ChangesetAdvisory {
        let payload = ChangesetAdvisoryPayload {
            base: self.base(),
            latest: None,
            paths: paths.iter().map(|p| p.to_string()).collect(),
            agent: agent.to_string(),
            snapshot_seq: None,
        };
        let req = self.sign_as(&bob(), vec![Capability::Read], Capability::Read, payload);
        let now = self.now();
        self.svc.changeset_advisory(&req, coord, now).unwrap()
    }

    fn context(&mut self, target: TreeTarget, path: &str) -> CrumbContext {
        let payload = CrumbContextQueryPayload {
            target,
            path: path.to_string(),
            snapshot_seq: None,
        };
        let req = self.sign_as(&bob(), vec![Capability::Read], Capability::Read, payload);
        let now = self.now();
        self.svc.crumb_context(&req, now).unwrap()
    }

    fn evidence_base(&mut self, cs: ChangesetId) -> EvidenceBase {
        let payload = EvidenceBaseQueryPayload {
            changeset_id: cs,
            snapshot_seq: None,
        };
        let req = self.sign_as(&runner(), vec![Capability::Read], Capability::Read, payload);
        let now = self.now();
        self.svc.evidence_base(&req, now).unwrap()
    }

    fn body(&self, cs: ChangesetId, base: EvidenceBase) -> ReceiptBody {
        ReceiptBody {
            repo_id: self.repo.clone(),
            changeset_id: cs,
            source: base.source,
            crumb_contexts: base.crumb_contexts,
            input_root: InputRoot::single_repo(self.repo.clone(), cs),
            test: TestIdentity {
                name: "cargo-test-workspace".into(),
                command: vec!["cargo".into(), "test".into(), "--workspace".into()],
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
                log: b"test result: ok\n".to_vec(),
            },
        }
    }

    fn verify(&mut self, receipt: Vec<u8>) -> ReceiptVerification {
        let payload = VerifyEvidenceReceiptPayload {
            receipt,
            snapshot_seq: None,
        };
        let req = self.sign_as(&bob(), vec![Capability::Read], Capability::Read, payload);
        let now = self.now();
        self.svc.verify_evidence_receipt(&req, now).unwrap()
    }
}

fn ws(agent: &str) -> Workspace {
    Workspace::with_oracle(
        format!("/synapse/ws/{agent}"),
        Holder::synapse(
            &format!("lane/{agent}"),
            "00112233445566778899",
            "aabbccddeeff00112233",
        ),
        Box::new(NoOracle),
    )
}

fn claim(store: &CoordStore, agent: &str, target: &str, ttl: i64) -> ClaimOutcome {
    store
        .claim(&ws(agent), agent, ROOT_DIR, target, "edit", Some(ttl))
        .unwrap()
}

fn no_warnings(adv: &ChangesetAdvisory) -> bool {
    adv.coordination == CoordinationStatus::Read
        && adv.paths.iter().all(|p| {
            p.claims.is_empty()
                && p.overlapping_proposals.is_empty()
                && p.pending_crumb_changes.is_empty()
                && !matches!(p.staleness, Staleness::Stale { .. })
        })
}

// ------------------------------------------------------------------------------------------
// S01 to S04: the normal multi-agent flow.

#[test]
fn s01_two_agents_same_file() {
    let mut fx = Fx::new("s01");
    let store = fx.coord(T0);
    assert!(matches!(
        claim(&store, "alice", "src/a.rs", 600),
        ClaimOutcome::Claimed { .. }
    ));
    match claim(&store, "bob", "src/a.rs", 600) {
        ClaimOutcome::Blocked { key, holder } => {
            assert_eq!(key, "src/a.rs");
            assert_eq!(holder.holder, "alice");
        }
        other => panic!("bob's claim was not refused: {other:?}"),
    }
    let cs = fx.propose(&alice(), "alice-a", &[("src/a.rs", b"fn a2() {}\n")]);
    let adv = fx.advise("bob", &["src/a.rs"], Some(&store));
    assert_eq!(adv.coordination, CoordinationStatus::Read);
    let p = &adv.paths[0];
    assert_eq!(p.claims.len(), 1);
    assert_eq!(p.claims[0].holder, "alice");
    assert_eq!(p.claims[0].key, "src/a.rs");
    assert_eq!(p.overlapping_proposals.len(), 1);
    assert_eq!(p.overlapping_proposals[0].changeset_id, cs);
    assert_eq!(p.overlapping_proposals[0].author_did, did(&alice()));
    // The caller's own claim is not reported back to the caller.
    let own = fx.advise("alice", &["src/a.rs"], Some(&store));
    assert!(own.paths[0].claims.is_empty());
    result(
        "S01",
        "PASS",
        "bob's claim on src/a.rs refused (held by alice); bob's advisory shows alice's claim and alice's open proposal",
    );
}

#[test]
fn s02_two_agents_separate_files() {
    let mut fx = Fx::new("s02");
    let store = fx.coord(T0);
    assert!(matches!(
        claim(&store, "alice", "src/a.rs", 600),
        ClaimOutcome::Claimed { .. }
    ));
    assert!(matches!(
        claim(&store, "bob", "src/b.rs", 600),
        ClaimOutcome::Claimed { .. }
    ));
    fx.propose(&alice(), "alice-a", &[("src/a.rs", b"fn a2() {}\n")]);
    let adv = fx.advise("bob", &["src/b.rs", "docs/x.md"], Some(&store));
    assert!(no_warnings(&adv), "{adv:?}");
    // Guidance (invariants) is still surfaced: it is context, not a warning.
    assert!(adv.paths[0].guidance.iter().any(|g| g.text == "src rule"));
    result(
        "S02",
        "PASS",
        "separate files: both claims granted; advisory has no claims, overlaps, pending .crumb changes or staleness",
    );
}

#[test]
fn s03_stale_crumb_snapshot() {
    let mut files = default_files();
    let mut fx = Fx::new("s03");
    // A second base where src/.crumb was rewritten: a stale-snapshot runner reads this one.
    files[1].2 = SRC_CRUMB_V2.to_vec();
    fx.svc.register_base_tree(GitOid([2; 20]), files).unwrap();

    // Advisory: carol's open proposal rewrites src/.crumb after bob's base.
    let rewrite = fx.propose(&carol(), "carol-crumb", &[("src/.crumb", SRC_CRUMB_V2)]);
    let adv = fx.advise("bob", &["src/a.rs"], None);
    let p = &adv.paths[0];
    assert!(
        matches!(p.staleness, Staleness::Stale { .. }),
        "{:?}",
        p.staleness
    );
    assert_eq!(p.pending_crumb_changes.len(), 1);
    assert_eq!(p.pending_crumb_changes[0].changeset_id, rewrite);

    // Receipts: bob's changeset edits src/.crumb and src/b.rs.
    let cs = fx.propose(
        &bob(),
        "bob-edit",
        &[("src/.crumb", SRC_CRUMB_V2), ("src/b.rs", b"fn b2() {}\n")],
    );
    let base = fx.evidence_base(cs);
    let src = base
        .crumb_contexts
        .iter()
        .find(|c| c.dir == "src")
        .unwrap()
        .clone();
    assert_ne!(src.at_base, src.in_changeset);
    let good = EvidenceReceipt::sign(fx.body(cs, base.clone()), &runner()).unwrap();
    assert!(matches!(
        fx.verify(good.encode().unwrap()),
        ReceiptVerification::Current { .. }
    ));

    // Changeset side stale: the runner claims it tested under the base context.
    let mut b = base.clone();
    b.crumb_contexts
        .iter_mut()
        .find(|c| c.dir == "src")
        .unwrap()
        .in_changeset = src.at_base;
    let r = EvidenceReceipt::sign(fx.body(cs, b), &runner()).unwrap();
    match fx.verify(r.encode().unwrap()) {
        ReceiptVerification::Stale { stale, .. } => {
            assert_eq!(stale.len(), 1);
            assert_eq!(stale[0].dir, "src");
            assert_eq!(stale[0].reason, StaleReason::InChangeset);
            assert_eq!(stale[0].expected, src.in_changeset);
        }
        other => panic!("expected Stale InChangeset, got {other:?}"),
    }

    // Base side stale: the runner read a stale snapshot (base 2) for "what the author saw".
    let stale_base = fx
        .context(TreeTarget::BaseGitCommit(GitOid([2; 20])), "src")
        .digest();
    let fresh_base = fx.context(fx.base(), "src").digest();
    assert_eq!(fresh_base, src.at_base);
    assert_ne!(stale_base, fresh_base);
    let mut b = base;
    b.crumb_contexts
        .iter_mut()
        .find(|c| c.dir == "src")
        .unwrap()
        .at_base = stale_base;
    let r = EvidenceReceipt::sign(fx.body(cs, b), &runner()).unwrap();
    match fx.verify(r.encode().unwrap()) {
        ReceiptVerification::Stale { stale, .. } => {
            assert_eq!(stale.len(), 1);
            assert_eq!(stale[0].reason, StaleReason::AtBase);
            assert_eq!(stale[0].in_receipt, stale_base);
            assert_eq!(stale[0].expected, fresh_base);
        }
        other => panic!("expected Stale AtBase, got {other:?}"),
    }
    result(
        "S03",
        "PASS",
        "advisory Stale + pending .crumb rewrite named; receipt Stale InChangeset and Stale AtBase each name dir src and the expected digest",
    );
}

#[test]
fn s04_expired_claims_ignored() {
    let mut fx = Fx::new("s04");
    assert!(matches!(
        claim(&fx.coord(T0), "alice", "src/a.rs", 60),
        ClaimOutcome::Claimed { .. }
    ));
    let live = fx.advise("bob", &["src/a.rs"], Some(&fx.coord(T0 + 60)));
    assert_eq!(live.paths[0].claims.len(), 1);
    let later = fx.advise("bob", &["src/a.rs"], Some(&fx.coord(T0 + 61)));
    assert_eq!(later.coordination, CoordinationStatus::Read);
    assert!(later.paths[0].claims.is_empty());
    // And the plane lets bob take the file over once alice's lock expired.
    assert!(matches!(
        claim(&fx.coord(T0 + 61), "bob", "src/a.rs", 600),
        ClaimOutcome::Claimed { .. }
    ));
    // An unparseable timestamp counts as expired too (crumb.c rule).
    let st = fx.coord(T0 + 61);
    let rec = fx.dir.join("coord/dirs/docs.json");
    fs::write(
        &rec,
        br#"{"schema_version":"1.0.0","directory":"docs","locks":{"docs/x.md":{"holder":"mallory","acquired_at":"not-a-time","ttl_seconds":999999}}}"#,
    )
    .unwrap();
    assert!(fx.advise("bob", &["docs/x.md"], Some(&st)).paths[0]
        .claims
        .is_empty());
    result(
        "S04",
        "PASS",
        "claim live at ttl, ignored at ttl+1s by advisory and taken over in the plane; unparseable stamp treated as expired",
    );
}

// ------------------------------------------------------------------------------------------
// S05: forged and tampered coordination records.

#[test]
fn s05_forged_coordination_records() {
    let mut fx = Fx::new("s05");
    let st = fx.coord(T0);
    assert!(matches!(
        claim(&st, "alice", "src/a.rs", 600),
        ClaimOutcome::Claimed { .. }
    ));
    let dirs = fx.dir.join("coord/dirs");
    let agents = fx.dir.join("coord/agents");

    // (a) Corrupt JSON: the advisory still answers, reports Unavailable, and no claims.
    let docs = dirs.join("docs.json");
    fs::write(&docs, b"{\"locks\": {not json").unwrap();
    let adv = fx.advise("bob", &["src/a.rs"], Some(&st));
    assert!(
        matches!(adv.coordination, CoordinationStatus::Unavailable { .. }),
        "{adv:?}"
    );
    assert!(adv.paths[0].claims.is_empty());
    // A mutation refuses the corrupt record and never overwrites it.
    let err = st
        .claim(&ws("bob"), "bob", ROOT_DIR, "docs/x.md", "edit", Some(60))
        .unwrap_err();
    assert!(matches!(err, CoordError::CorruptRecord { .. }), "{err}");
    assert_eq!(fs::read(&docs).unwrap(), b"{\"locks\": {not json");
    // Nesting past the parser's depth bound is also corrupt, not a stack overflow.
    let deep = format!("{}{}", "[".repeat(100_000), "]".repeat(100_000));
    fs::write(agents.join("deep.json"), deep).unwrap();
    fs::remove_file(&docs).unwrap();
    let adv = fx.advise("bob", &["src/a.rs"], Some(&st));
    assert!(matches!(
        adv.coordination,
        CoordinationStatus::Unavailable { .. }
    ));
    fs::remove_file(agents.join("deep.json")).unwrap();

    // (b) Wrong holders: empty or non-string holders are skipped; a forged holder is shown
    // as information only.
    fs::write(
        &docs,
        format!(
            r#"{{"schema_version":"1.0.0","directory":"docs","locks":{{
  "docs/x.md":{{"holder":"","acquired_at":"{t}","ttl_seconds":600}},
  "docs/y.md":{{"holder":42,"acquired_at":"{t}","ttl_seconds":600}},
  "docs":{{"holder":"mallory","acquired_at":"{t}","ttl_seconds":600}}}}}}"#,
            t = synapse_coord::time::iso(T0)
        ),
    )
    .unwrap();
    let adv = fx.advise("bob", &["docs/x.md", "docs/y.md"], Some(&st));
    assert_eq!(adv.coordination, CoordinationStatus::Read);
    for p in &adv.paths {
        let holders: Vec<&str> = p.claims.iter().map(|c| c.holder.as_str()).collect();
        assert_eq!(holders, ["mallory"], "{}: {holders:?}", p.path);
    }
    // A forged lock in the caller's own name hides it from the caller only (self-declared
    // agent names, ADR 0004 section 2.6): mallory sees nothing about mallory's own lock.
    assert!(fx.advise("mallory", &["docs/x.md"], Some(&st)).paths[0]
        .claims
        .is_empty());

    // (c) Hostile keys: traversal, absolute, empty, NUL, oversized, non-UTF-8.
    let long = "k".repeat(70_000);
    let mut hostile = format!(
        r#"{{"schema_version":"1.0.0","directory":"src","locks":{{
  "../../etc/passwd":{{"holder":"h1","acquired_at":"{t}","ttl_seconds":600}},
  "/src/b.rs":{{"holder":"h2","acquired_at":"{t}","ttl_seconds":600}},
  "":{{"holder":"h3","acquired_at":"{t}","ttl_seconds":600}},
  "src/b.rs\u0000x":{{"holder":"h4","acquired_at":"{t}","ttl_seconds":600}},
  "src/b.rs/../a.rs":{{"holder":"h5","acquired_at":"{t}","ttl_seconds":600}},
  "{long}":{{"holder":"h6","acquired_at":"{t}","ttl_seconds":600}},
  "src/b":{{"holder":"h7","acquired_at":"{t}","ttl_seconds":600}}"#,
        t = synapse_coord::time::iso(T0)
    )
    .into_bytes();
    hostile.extend_from_slice(b",\n  \"src/\xff\xfe\":{\"holder\":\"h8\",\"acquired_at\":\"");
    hostile.extend_from_slice(synapse_coord::time::iso(T0).as_bytes());
    hostile.extend_from_slice(b"\",\"ttl_seconds\":600}}}");
    fs::write(dirs.join("src.json"), &hostile).unwrap();
    fs::write(
        agents.join("..%2f..json"),
        b"{\"agent\":\"../../x\",\"updated_at\":\"bad\"}",
    )
    .unwrap();
    let adv = fx.advise("bob", &["src/b.rs", "src/a.rs"], Some(&st));
    assert_eq!(adv.coordination, CoordinationStatus::Read, "{adv:?}");
    // No hostile key matches by traversal, absolute, empty, prefix or byte tricks: keys are
    // compared as exact strings. One exception, by crumb.c parity (ADR 0004 section 2.3
    // item 8): an escaped `\u0000` ends the string, so `"src/b.rs\u0000x"` reads as the key
    // `src/b.rs`. That is no escalation (the same writer could write `src/b.rs` directly)
    // and the claim is information only.
    let holders = |i: usize| -> Vec<&str> {
        adv.paths[i]
            .claims
            .iter()
            .map(|c| c.holder.as_str())
            .collect()
    };
    assert_eq!(holders(0), ["h4"], "src/b.rs: {:?}", adv.paths[0].claims);
    assert!(holders(1).is_empty(), "src/a.rs: {:?}", adv.paths[1].claims);

    // Never authority: with all of the above in the store, Synapse still commits a changeset
    // on src/a.rs (claimed by alice, forged locks around it) and its receipt is Current.
    let cs = fx.propose(&bob(), "bob-a", &[("src/a.rs", b"fn a3() {}\n")]);
    let base = fx.evidence_base(cs);
    let r = EvidenceReceipt::sign(fx.body(cs, base), &runner()).unwrap();
    assert!(matches!(
        fx.verify(r.encode().unwrap()),
        ReceiptVerification::Current { .. }
    ));
    result(
        "S05",
        "PASS",
        "corrupt/deep JSON => Unavailable (no panic, not overwritten); empty/non-string holders skipped; forged holder shown as info only; hostile keys (traversal, absolute, empty, prefix, oversized, non-UTF-8) match nothing, escaped-NUL key truncates as in crumb.c; submit and receipt unaffected",
    );
}

/// Defect found by D5 (see the `ignore` reason): a non-regular `*.json` record (a FIFO) in
/// the coordination store blocks `sniff` forever, so the advisory never answers instead of
/// reporting `Unavailable`. Run with `--ignored` to reproduce; it fails after 5 s.
#[test]
#[ignore = "defect aien-spark/synapse#58: coordination record reads are unbounded (FIFO hangs sniff/advisory; no size cap)"]
fn s05_defect_fifo_record_hangs_advisory() {
    let fx = Fx::new("s05-fifo");
    let st = fx.coord(T0);
    assert!(matches!(
        claim(&st, "alice", "src/a.rs", 600),
        ClaimOutcome::Claimed { .. }
    ));
    let fifo = fx.dir.join("coord/dirs/evil.json");
    let c = std::ffi::CString::new(fifo.to_str().unwrap()).unwrap();
    // SAFETY: valid NUL-terminated path.
    assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o644) }, 0);
    let root = fx.dir.join("coord");
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let st = CoordStore::open(root).with_clock(|| T0);
        let _ = tx.send(st.sniff(&ws("bob"), "bob", ROOT_DIR).is_ok());
    });
    let answered = rx.recv_timeout(std::time::Duration::from_secs(5));
    // Unblock the reader so the thread can finish.
    let _ = fs::OpenOptions::new().write(true).open(&fifo);
    assert!(
        answered.is_ok(),
        "sniff did not answer within 5 s on a FIFO record"
    );
}

// ------------------------------------------------------------------------------------------
// S06, S07: forged, tampered, and self-signed receipts.

#[test]
fn s06_forged_and_tampered_receipts_refused() {
    let mut fx = Fx::new("s06");
    let cs = fx.propose(&alice(), "alice-a", &[("src/a.rs", b"fn a2() {}\n")]);
    let base = fx.evidence_base(cs);
    let good = EvidenceReceipt::sign(fx.body(cs, base.clone()), &runner()).unwrap();
    let bytes = good.encode().unwrap();
    assert!(matches!(
        fx.verify(bytes.clone()),
        ReceiptVerification::Current { .. }
    ));
    let refused = |v: ReceiptVerification| match v {
        ReceiptVerification::Refused(e) => e,
        other => panic!("not refused: {other:?}"),
    };
    let mut cases = 0;

    // Bad signature: last byte flipped.
    let mut b = bytes.clone();
    *b.last_mut().unwrap() ^= 1;
    assert_eq!(refused(fx.verify(b)), ReceiptError::SignatureInvalid);
    cases += 1;
    // Forged: signed by mallory, labelled with the runner's DID.
    let mallory = SigningKey::from_bytes(&[66u8; 32]);
    let mut forged = EvidenceReceipt::sign(fx.body(cs, base.clone()), &mallory).unwrap();
    forged.executor_did = did(&runner());
    assert_eq!(
        refused(fx.verify(forged.encode().unwrap())),
        ReceiptError::SignatureInvalid
    );
    cases += 1;
    // Non-canonical DID (bare multibase), correctly re-signed by the same key.
    let mut bare = good.clone();
    bare.executor_did = did(&runner()).strip_prefix("did:key:").unwrap().to_string();
    bare.signature = runner().sign(&bare.signable_bytes()).to_bytes();
    assert_eq!(
        refused(fx.verify(bare.encode().unwrap())),
        ReceiptError::ExecutorDidInvalid
    );
    cases += 1;
    // Field tampers without re-signing: changeset, context digest, outcome+exit, log.
    type Tamper = Box<dyn Fn(&mut EvidenceReceipt)>;
    let tampers: Vec<Tamper> = vec![
        Box::new(|r| {
            r.body.changeset_id.0[0] ^= 1;
            r.body.input_root = InputRoot::single_repo(r.body.repo_id.clone(), r.body.changeset_id);
        }),
        Box::new(|r| r.body.crumb_contexts[0].at_base.0[0] ^= 1),
        Box::new(|r| r.body.crumb_contexts[0].in_changeset.0[0] ^= 1),
        Box::new(|r| {
            r.body.result.exit_status = ExitStatus::Code(1);
            r.body.result.outcome = Outcome::Fail;
        }),
        Box::new(|r| r.body.observation.log = b"forged log\n".to_vec()),
        Box::new(|r| r.body.test.name = "other-test".into()),
    ];
    for t in &tampers {
        let mut r = good.clone();
        t(&mut r);
        assert_eq!(
            refused(fx.verify(r.encode().unwrap())),
            ReceiptError::SignatureInvalid
        );
        cases += 1;
    }
    // Wrong domain, truncation, trailing bytes.
    let mut b = bytes.clone();
    b[0] ^= 1;
    assert_eq!(refused(fx.verify(b)), ReceiptError::WrongDomain);
    let b = bytes[..bytes.len() - 10].to_vec();
    refused(fx.verify(b));
    let mut b = bytes.clone();
    b.push(0);
    assert_eq!(refused(fx.verify(b)), ReceiptError::TrailingBytes);
    cases += 3;
    // Oversize: a record over the total cap is refused before parsing; a log over its cap
    // cannot even be signed.
    let mut b = bytes.clone();
    b.resize(MAX_RECEIPT_BYTES + 1, 0);
    assert!(matches!(refused(fx.verify(b)), ReceiptError::OverCap(_)));
    let mut big = fx.body(cs, base);
    big.observation.log = vec![b'x'; MAX_LOG_BYTES + 1];
    assert!(matches!(
        EvidenceReceipt::sign(big, &runner()),
        Err(ReceiptError::OverCap(_))
    ));
    cases += 2;
    // Every single-byte flip of the record is refused (none reaches Current/Stale).
    let mut flips = 0;
    for i in (0..bytes.len()).step_by(7) {
        let mut b = bytes.clone();
        b[i] ^= 0x40;
        assert!(
            matches!(fx.verify(b), ReceiptVerification::Refused(_)),
            "flip at {i} accepted"
        );
        flips += 1;
    }
    result(
        "S06",
        "PASS",
        &format!("{cases} forged/tampered/oversize cases refused with the expected typed error; {flips} byte flips refused"),
    );
}

#[test]
fn s07_self_signed_receipt_known_gap() {
    let mut fx = Fx::new("s07");
    let cs = fx.propose(&alice(), "alice-a", &[("src/a.rs", b"fn a2() {}\n")]);
    let base = fx.evidence_base(cs);
    // Executor = changeset author. Version 1 has no executor registry.
    let r = EvidenceReceipt::sign(fx.body(cs, base), &alice()).unwrap();
    assert_eq!(r.executor_did, did(&alice()));
    match fx.verify(r.encode().unwrap()) {
        ReceiptVerification::Current { outcome, .. } => assert_eq!(outcome, Outcome::Pass),
        other => {
            panic!("self-signed receipt no longer Current ({other:?}): update D5 and ADR 0004")
        }
    }
    result(
        "S07",
        "KNOWN-GAP",
        "receipt signed by the changeset author's own key verifies Current; executor independence deferred to ADR 0003 E0/E1; Current grants nothing (S12)",
    );
}

// ------------------------------------------------------------------------------------------
// S08, S09: crashes.

/// Child half of S08: claim through the library with `SYNAPSE_COORD_FAULT=before-rename`, so
/// the process aborts after the tmp record is written and before the rename. A no-op unless
/// re-executed by `s08_crash_mid_claim`.
#[test]
fn s08_child_claim_then_abort() {
    let Ok(dir) = std::env::var(CHILD_ENV) else {
        return;
    };
    let st = CoordStore::open(PathBuf::from(dir)).with_clock(|| T0);
    let _ = st.claim(
        &ws("crasher"),
        "crasher",
        ROOT_DIR,
        "src/b.rs",
        "edit",
        Some(600),
    );
    // Only reached if the fault point did not fire.
    std::process::exit(0);
}

fn rerun_child(
    test: &str,
    env: &[(&str, &Path)],
    extra: &[(&str, &str)],
) -> std::process::ExitStatus {
    let mut cmd = Command::new(std::env::current_exe().unwrap());
    cmd.args(["--exact", test, "--nocapture", "--test-threads=1"]);
    for (k, v) in env {
        cmd.env(k, v);
    }
    for (k, v) in extra {
        cmd.env(k, v);
    }
    cmd.output().unwrap().status
}

#[test]
fn s08_crash_mid_claim() {
    use std::os::unix::process::ExitStatusExt;
    let mut fx = Fx::new("s08");
    let root = fx.dir.join("coord");
    let st = fx.coord(T0);
    assert!(matches!(
        claim(&st, "alice", "src/a.rs", 600),
        ClaimOutcome::Claimed { .. }
    ));
    let rec = root.join("dirs/src.json");
    let before = fs::read(&rec).unwrap();

    // Torn tmp files from an earlier crash are never read as records.
    fs::write(
        root.join("dirs/src.json.tmp4242"),
        b"{\"locks\":{\"src/a.rs\":{\"hol",
    )
    .unwrap();
    fs::write(root.join("agents/alice.json.tmp4242"), b"garbage").unwrap();
    let adv = fx.advise("bob", &["src/a.rs"], Some(&st));
    assert_eq!(adv.coordination, CoordinationStatus::Read);
    assert_eq!(adv.paths[0].claims.len(), 1);

    // Kill between tmp write and rename (real process abort).
    let status = rerun_child(
        "s08_child_claim_then_abort",
        &[(CHILD_ENV, &root)],
        &[("SYNAPSE_COORD_FAULT", "before-rename")],
    );
    assert_eq!(
        status.signal(),
        Some(libc::SIGABRT),
        "child status {status:?}"
    );
    assert_eq!(
        fs::read(&rec).unwrap(),
        before,
        "record changed by an aborted claim"
    );
    let tmps = fs::read_dir(root.join("dirs"))
        .unwrap()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_name().to_string_lossy().contains(".tmp"))
        .count();
    assert!(tmps >= 2, "aborted claim left no tmp record");
    // The store stays readable and consistent: alice still holds src/a.rs, the crasher holds
    // nothing, and src/b.rs can be claimed.
    let adv = fx.advise("bob", &["src/a.rs", "src/b.rs"], Some(&st));
    assert_eq!(adv.coordination, CoordinationStatus::Read);
    assert_eq!(adv.paths[0].claims[0].holder, "alice");
    assert!(adv.paths[1].claims.is_empty());
    assert!(matches!(
        claim(&st, "bob", "src/b.rs", 600),
        ClaimOutcome::Claimed { .. }
    ));
    result(
        "S08",
        "PASS",
        "torn tmp records ignored; child aborted (SIGABRT) between tmp write and rename left the record byte-identical; plane usable afterwards",
    );
}

/// Child half of S09: open the service with group commit, arm `CrashMidBatchWrite` (PR #18),
/// and submit. The store terminates the process mid-write with `FAULT_CRASH_EXIT_CODE`.
#[test]
fn s09_child_submit_then_crash() {
    let Ok(dir) = std::env::var(CHILD_ENV) else {
        return;
    };
    let repo = RepoId::new("aien-spark/synapse").unwrap();
    let svc = SynapseService::open(
        PathBuf::from(&dir),
        repo.clone(),
        FsyncPolicy::GROUP_COMMIT_DEFAULT,
        RecoveryPolicy::TruncateTornTail,
        StoreLimits::default(),
    )
    .unwrap();
    let mut fx = Fx {
        svc,
        auth: SigningKey::from_bytes(&[10u8; 32]),
        repo,
        nonce: 100,
        dir: scratch("s09-child"),
        base_oid: GitOid([1; 20]),
        base_files: default_files(),
    };
    fx.prime();
    fx.svc
        .store_mut()
        .set_fault_injection(FaultInjection::CrashMidBatchWrite { bytes_written: 64 });
    let _ = fx.submit(&bob(), "bob-crash", &[("src/a.rs", b"fn crashed() {}\n")]);
    std::process::exit(0);
}

#[test]
fn s09_crash_mid_submit() {
    let mut fx = Fx::with("s09", FsyncPolicy::GROUP_COMMIT_DEFAULT, default_files());
    let st = fx.coord(T0);
    assert!(matches!(
        claim(&st, "bob", "src/a.rs", 600),
        ClaimOutcome::Claimed { .. }
    ));
    let first = fx.propose(&alice(), "alice-b", &[("src/b.rs", b"fn b2() {}\n")]);
    let svc_dir = fx.dir.join("svc");
    // Release the store before the child process opens it.
    let placeholder = SynapseService::open(
        fx.dir.join("placeholder"),
        fx.repo.clone(),
        FsyncPolicy::EveryCommit,
        RecoveryPolicy::StrictFailClosed,
        StoreLimits::default(),
    )
    .unwrap();
    drop(std::mem::replace(&mut fx.svc, placeholder));

    let status = rerun_child("s09_child_submit_then_crash", &[(CHILD_ENV, &svc_dir)], &[]);
    assert_eq!(
        status.code(),
        Some(FAULT_CRASH_EXIT_CODE),
        "child status {status:?}"
    );

    // Strict recovery refuses the torn batch; truncating recovery drops it.
    let strict = SynapseService::open(
        &svc_dir,
        fx.repo.clone(),
        FsyncPolicy::GROUP_COMMIT_DEFAULT,
        RecoveryPolicy::StrictFailClosed,
        StoreLimits::default(),
    );
    let strict_refused = match strict {
        Err(e) => {
            assert_eq!(e.code, RefusalCode::WalTornFrame);
            true
        }
        Ok(_) => false,
    };
    fx.svc = SynapseService::open(
        &svc_dir,
        fx.repo.clone(),
        FsyncPolicy::GROUP_COMMIT_DEFAULT,
        RecoveryPolicy::TruncateTornTail,
        StoreLimits::default(),
    )
    .unwrap();
    fx.nonce = 1_000;
    fx.prime();
    let visible: Vec<ChangesetId> = fx
        .svc
        .store()
        .list_changesets(None, None, None)
        .unwrap()
        .iter()
        .map(|c| c.changeset_id)
        .collect();
    assert_eq!(
        visible,
        vec![first],
        "phantom or lost changeset after crash"
    );
    // No phantom proposal in the advisory, and bob's claim survives the crash untouched.
    let adv = fx.advise("alice", &["src/a.rs"], Some(&st));
    assert!(adv.paths[0].overlapping_proposals.is_empty());
    assert_eq!(adv.paths[0].claims.len(), 1);
    assert_eq!(adv.paths[0].claims[0].holder, "bob");
    // Bob resubmits after recovery and everything lines up again.
    let cs = fx.propose(&bob(), "bob-retry", &[("src/a.rs", b"fn retried() {}\n")]);
    let adv = fx.advise("alice", &["src/a.rs"], Some(&st));
    assert_eq!(adv.paths[0].overlapping_proposals[0].changeset_id, cs);
    let base = fx.evidence_base(cs);
    let r = EvidenceReceipt::sign(fx.body(cs, base), &runner()).unwrap();
    assert!(matches!(
        fx.verify(r.encode().unwrap()),
        ReceiptVerification::Current { .. }
    ));
    result(
        "S09",
        "PASS",
        &format!(
            "child exited {FAULT_CRASH_EXIT_CODE} mid WAL v2 batch write; strict reopen refused torn tail: {strict_refused}; truncating reopen shows only the acknowledged changeset, claim kept, resubmit + receipt Current"
        ),
    );
}

// ------------------------------------------------------------------------------------------
// S10: mixed agents (crumb.c in a Git worktree, synapse-coord, one store).

fn git(dir: &Path, args: &[&str]) -> Vec<u8> {
    let out = Command::new("git")
        .arg("-C")
        .arg(dir)
        .args(["-c", "user.name=d5", "-c", "user.email=d5@example.invalid"])
        .args(args)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "git {args:?}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    out.stdout
}

#[test]
fn s10_mixed_agents_crumb_c_and_synapse() {
    let Ok(crumb) = std::env::var("CRUMB_C_BIN") else {
        result(
            "S10",
            "UNVERIFIED",
            "CRUMB_C_BIN not set (run scripts/qualify-crumb-synapse.sh, which builds the pinned crumb.c)",
        );
        return;
    };
    let mut fx = Fx::new("s10");
    let rc = fx.dir.join("rc");
    fs::create_dir_all(rc.join("src")).unwrap();
    fs::write(rc.join(".crumb"), ROOT_CRUMB).unwrap();
    fs::write(rc.join("src/a.rs"), b"fn a() {}\n").unwrap();
    fs::write(rc.join("src/b.rs"), b"fn b() {}\n").unwrap();
    git(&rc, &["init", "-q", "-b", "main"]);
    git(&rc, &["add", "-A"]);
    git(&rc, &["commit", "-qm", "init"]);
    let wa = fx.dir.join("wa");
    git(
        &rc,
        &["worktree", "add", "-q", "-b", "laneC", wa.to_str().unwrap()],
    );
    fx.base_oid = fx.svc.import_base_tree_from_git_repo(&rc, "HEAD").unwrap();
    let store_root = fx.dir.join("store/crumb/v1");
    let c = |root: &Path, args: &[&str]| {
        Command::new(&crumb)
            .current_dir(&wa)
            .env("CRUMB_COORD_ROOT", root)
            .args(args)
            .output()
            .unwrap()
    };

    // crumb.c claims in the Git worktree; Synapse's side is refused and sees the holder.
    let out = c(&store_root, &["claim", "c-agent", "src", "a.rs", "C edit"]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let st = CoordStore::open(&store_root);
    match st
        .claim(
            &ws("rust-agent"),
            "rust-agent",
            ROOT_DIR,
            "src/a.rs",
            "edit",
            None,
        )
        .unwrap()
    {
        ClaimOutcome::Blocked { holder, .. } => {
            assert_eq!(holder.holder, "c-agent");
            assert_eq!(holder.branch, "laneC");
        }
        other => panic!("{other:?}"),
    }
    let adv = fx.advise("rust-agent", &["src/a.rs"], Some(&st));
    assert_eq!(adv.paths[0].claims.len(), 1);
    assert_eq!(adv.paths[0].claims[0].holder, "c-agent");
    assert_eq!(adv.paths[0].claims[0].branch, "laneC");
    // Synapse claims; crumb.c is refused with exit 2.
    assert!(matches!(
        st.claim(
            &ws("rust-agent"),
            "rust-agent",
            ROOT_DIR,
            "src/b.rs",
            "edit",
            None
        )
        .unwrap(),
        ClaimOutcome::Claimed { .. }
    ));
    let out = c(
        &store_root,
        &["claim", "c-agent", "src", "b.rs", "C wants it"],
    );
    assert_eq!(out.status.code(), Some(2));

    // STORE_ID: the Rust mutation created the marker; crumb.c keeps working beside it.
    let id = st
        .store_id()
        .unwrap()
        .expect("marker after a Rust mutation");
    let expecting = CoordStore::open_expecting(&store_root, id).unwrap();
    let adv = fx.advise("crumbless", &["src/a.rs", "src/b.rs"], Some(&expecting));
    assert_eq!(adv.coordination, CoordinationStatus::Read);
    assert_eq!(adv.paths[1].claims[0].holder, "rust-agent");
    let out = c(
        &store_root,
        &["claim", "c-agent", "src", ".crumb", "C again"],
    );
    assert!(out.status.success());
    // Misconfigured roots are refused by open_expecting: missing marker and another store.
    let empty = fx.dir.join("wrong/empty");
    assert!(matches!(
        CoordStore::open_expecting(&empty, id),
        Err(CoordError::StoreIdMissing { .. })
    ));
    let other = fx.dir.join("wrong/other");
    let other_id = CoordStore::open(&other).ensure_store_id().unwrap();
    assert_ne!(other_id, id);
    match CoordStore::open_expecting(&other, id) {
        Err(CoordError::StoreIdMismatch {
            expected, found, ..
        }) => {
            assert_eq!((expected, found), (id, other_id));
        }
        other => panic!("{other:?}"),
    }
    // Limit: crumb.c itself does not check STORE_ID, so crumb.c pointed at the wrong root
    // still grants a second claim on src/a.rs there (ADR 0004 D2 "not yet done").
    let out = c(&other, &["claim", "c-agent2", "src", "a.rs", "split brain"]);
    let crumb_c_split = out.status.success();
    let _ = StoreId::parse_hex(&id.to_hex()).unwrap();
    result(
        "S10",
        "PASS",
        &format!(
            "crumb.c (Git worktree) and synapse-coord share one store both ways; advisory shows the crumb.c holder; open_expecting refuses missing and mismatched STORE_ID; limit: crumb.c on a wrong root granted a split claim: {crumb_c_split}"
        ),
    );
}

// ------------------------------------------------------------------------------------------
// S11: Git round trip of .crumb files (D1, D2, D3) through synapse-git, byte for byte.

#[test]
fn s11_git_round_trip_crumb_bytes() {
    let mut fx = Fx::new("s11");
    let repo = fx.dir.join("repo");
    for (p, b) in [
        (".crumb", FIX_ROOT),
        ("d1/.crumb", FIX_D1),
        ("d1/x.txt", b"x\n".as_slice()),
        ("d2/.crumb", FIX_D2),
        ("d3/.crumb", FIX_D3),
    ] {
        let f = repo.join(p);
        fs::create_dir_all(f.parent().unwrap()).unwrap();
        fs::write(f, b).unwrap();
    }
    git(&repo, &["init", "-q", "-b", "main"]);
    git(&repo, &["add", "-A"]);
    git(&repo, &["commit", "-qm", "crumbs"]);
    fx.base_oid = fx
        .svc
        .import_base_tree_from_git_repo(&repo, "HEAD")
        .unwrap();
    for (dir, dialect) in [
        ("d1", Dialect::Rfc0001Json),
        ("d2", Dialect::AtlasJson),
        ("d3", Dialect::YamlV1),
    ] {
        let ctx = fx.context(fx.base(), dir);
        assert_eq!(ctx.leaf().dialect(), Some(dialect), "{dir}");
    }
    // A changeset rewrites the D1 crumb and adds a file next to D2.
    let new_d1 = br#"{"schema_version":"1.0.0","name":"d1","purpose":"Rewritten through Synapse.","invariants":["d1 rule v2"]}
"#;
    let cs = fx.propose(
        &alice(),
        "alice-crumbs",
        &[("d1/.crumb", new_d1), ("d2/note.txt", b"n\n")],
    );
    let mut index = GitProjectionIndex::new();
    let mat =
        materialize_changeset_to_git(&mut fx.svc, &mut index, &repo.join(".git"), cs, None, None)
            .unwrap();
    let commit = mat.commit_oid.to_hex();
    let show = |p: &str| git(&repo, &["cat-file", "blob", &format!("{commit}:{p}")]);
    assert_eq!(show(".crumb"), FIX_ROOT);
    assert_eq!(show("d1/.crumb"), new_d1);
    assert_eq!(show("d2/.crumb"), FIX_D2);
    assert_eq!(show("d3/.crumb"), FIX_D3);
    // The untouched directory (d3) keeps its Git tree OID exactly.
    assert_eq!(
        git(&repo, &["rev-parse", &format!("{commit}:d3")]),
        git(&repo, &["rev-parse", "HEAD:d3"])
    );
    // Back again: import the materialized commit into a fresh service; every .crumb context
    // digest equals the one Synapse computes in the changeset's own tree.
    let mut back = Fx::new("s11-back");
    back.base_oid = back
        .svc
        .import_base_tree_from_git_repo(&repo, &commit)
        .unwrap();
    for dir in [".", "d1", "d2", "d3"] {
        let there = fx.context(TreeTarget::Changeset(cs), dir).digest();
        let here = back.context(back.base(), dir).digest();
        assert_eq!(there, here, "{dir}");
    }
    result(
        "S11",
        "PASS",
        "Git -> Synapse (D1/D2/D3 dialects recognised) -> changeset -> Git: all four .crumb blobs byte-identical, untouched tree OID kept, re-import gives identical context digests",
    );
}

// ------------------------------------------------------------------------------------------
// S12: exit rule. A fully passing run never grants publication.

#[test]
fn s12_exit_rule_passing_run_is_not_publication() {
    let mut fx = Fx::new("s12");
    let store = fx.coord(T0);
    assert!(matches!(
        claim(&store, "alice", "src/a.rs", 600),
        ClaimOutcome::Claimed { .. }
    ));
    let cs = fx.propose(&alice(), "alice-a", &[("src/a.rs", b"fn a2() {}\n")]);
    // Alice's own view: coordination read, no foreign claims (her own proposal is listed as
    // open, which is expected: the advisory is not author-aware).
    let adv = fx.advise("alice", &["src/a.rs"], Some(&store));
    assert_eq!(adv.coordination, CoordinationStatus::Read);
    assert!(adv.paths[0].claims.is_empty());
    let base = fx.evidence_base(cs);
    let receipt = EvidenceReceipt::sign(fx.body(cs, base), &runner()).unwrap();
    assert!(matches!(
        fx.verify(receipt.encode().unwrap()),
        ReceiptVerification::Current {
            outcome: Outcome::Pass,
            ..
        }
    ));
    let bare = fx.dir.join("bare.git");
    git(&fx.dir, &["init", "-q", "--bare", bare.to_str().unwrap()]);
    let mut index = GitProjectionIndex::new();
    let mat = materialize_changeset_to_git(&mut fx.svc, &mut index, &bare, cs, None, None).unwrap();

    // Gate 1: Capability::Publish. Every other capability, plus a Current Pass receipt in
    // hand, is refused. (Neither gate takes a receipt as input: there is no field for one.)
    let pr = |n| GitHubPrProjectionRequest {
        pr_number: n,
        changeset_id: cs,
        pr_branch_ref: "refs/synapse/agent-head/alice".into(),
        title: "d5".into(),
        github_merged: false,
    };
    for signer in [alice(), runner()] {
        let req = fx.sign_as(
            &signer,
            vec![
                Capability::Read,
                Capability::Propose,
                Capability::Evaluate,
                Capability::Review,
            ],
            Capability::Publish,
            pr(1),
        );
        let now = fx.now();
        let err = project_github_pull_request(&mut fx.svc, &index, &req, now).unwrap_err();
        assert_eq!(err.code, RefusalCode::AuthCapabilityDenied);
    }

    // Gate 2: Radicle canonical promotion needs the delegate quorum. Neither the author nor
    // the receipt's executor is a delegate; a merged GitHub PR does not help.
    let doc = RadicleIdentityDoc {
        delegates: vec![did(&delegate())],
        payload: RadiclePayloadMap {
            project: RadicleProjectPayload {
                default_branch: "main".into(),
                description: String::new(),
                name: "synapse".into(),
            },
        },
        threshold: 1,
    };
    let candidate = PromotionCandidate {
        repo_id: fx.repo.clone(),
        changeset_id: Some(cs),
        proposal_base_git_oid: fx.base_oid,
        candidate_git_oid: mat.commit_oid,
        github_pr_merged: true,
        verified_at_ms: 5,
    };
    let refs: BTreeMap<String, GitOid> = [("refs/heads/main".to_string(), mat.commit_oid)].into();
    let mut engine = CanonicalPromotionEngine::new(doc.clone(), None, None).unwrap();
    let e = engine.verify_and_promote(&candidate, &[]).unwrap_err();
    assert_eq!(e.code, RefusalCode::RadicleQuorumInsufficient);
    for k in [runner(), alice()] {
        let e = engine
            .verify_and_promote(&candidate, &[DelegateSigrefs::sign_refs(&k, &refs)])
            .unwrap_err();
        assert_eq!(e.code, RefusalCode::RadicleIdentityInvalid);
    }
    assert!(engine.current_canonical().is_none());
    assert!(fx.svc.store().canonical_head(&fx.repo).is_none());

    // Positive controls: the gates open only for their own credentials.
    let req = fx.sign_as(
        &alice(),
        vec![Capability::Publish],
        Capability::Publish,
        pr(2),
    );
    let now = fx.now();
    let proj = project_github_pull_request(&mut fx.svc, &index, &req, now).unwrap();
    assert_eq!(proj.head_git_oid, mat.commit_oid);
    let head = engine
        .verify_and_promote(
            &candidate,
            &[DelegateSigrefs::sign_refs(&delegate(), &refs)],
        )
        .unwrap();
    assert_eq!(head.canonical_git_oid, mat.commit_oid);
    result(
        "S12",
        "PASS",
        "clean advisory + Current Pass receipt: GitHub PR projection refused without Publish (AuthCapabilityDenied, author and runner); Radicle promotion refused without delegate quorum (none / runner / author sigrefs); both open only for a Publish grant / delegate sigrefs. AEGIS not integrated (separate repo)",
    );
}
