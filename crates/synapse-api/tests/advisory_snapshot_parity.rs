//! Issue #94 parity: advisory and Crumb context answers over a recorded corpus are
//! byte-identical (their `Debug` rendering, errors included) to the answers recorded on
//! `origin/main` before snapshot views were cached.
//!
//! The corpus: a base tree with nested `.crumb` files; every file, directory and two absent
//! paths, alone and all together; against the base, a changeset base, an explicit `latest`,
//! an older `snapshot_seq`, a promoted canonical head, with and without claims in the
//! coordination plane. It runs, then new proposals land (a new snapshot, a `.crumb`
//! rewrite, a promotion), and it runs again twice (the second time fully warm). The SHA-256
//! of the whole transcript was recorded on `origin/main` (3d78efe).
//!
//! Keys, nonces and grant ids are derived from labels and counters, never literals.

use ed25519_dalek::SigningKey;
use sha2::{Digest, Sha256};
use std::fmt::Debug;
use std::fs;
use std::path::PathBuf;
use synapse_api::{
    ChangesetAdvisoryPayload, CrumbContextQueryPayload, SubmitChangesetPayload, SynapseService,
    TreeTarget,
};
use synapse_auth::{AgentCapabilityGrant, AuthenticatedRequest, Capability};
use synapse_coord::{ClaimOutcome, CoordStore, Holder, NoOracle, Workspace};
use synapse_core::{
    encode_did_key_ed25519, BlobDigest, ChangesetEnvelope, ChangesetId, FileMode, GitOid,
    IdempotencyKey, MutationOp, PathMutation, RadicleCanonicalHead, RepoId, SynapseResult, WalSeq,
    SYNAPSE_ENVELOPE_VERSION,
};
use synapse_store::{FsyncPolicy, IngestOutcome, RecoveryPolicy, StoreLimits};

/// SHA-256 of the transcript, recorded on `origin/main` 3d78efe (before #94).
const RECORDED_TRANSCRIPT_SHA256: &str =
    "9278ca4a986420bc32358186f450ba4c74d6252e96b1fa591d2ac16337694b0f";

const T0: i64 = 1_800_000_000;

fn derived(label: &str, n: u64) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"SYNAPSE_API_ADVISORY_PARITY_TEST_V1\0");
    h.update(label.as_bytes());
    h.update(n.to_le_bytes());
    h.finalize().into()
}

fn key(label: &str) -> SigningKey {
    SigningKey::from_bytes(&derived(label, 0))
}

fn did(k: &SigningKey) -> String {
    encode_did_key_ed25519(&k.verifying_key().to_bytes())
}

fn crumb(name: &str, rule: &str) -> Vec<u8> {
    format!(
        r#"{{"schema_version":"1.0.0","name":"{name}","purpose":"{name} purpose.","invariants":["{rule}"]}}"#
    )
    .into_bytes()
}

struct Corpus {
    svc: SynapseService,
    authority: SigningKey,
    repo: RepoId,
    base_oid: GitOid,
    counter: u64,
    dir: PathBuf,
    transcript: Vec<u8>,
}

impl Drop for Corpus {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.dir);
    }
}

impl Corpus {
    fn new() -> Self {
        let dir = std::env::temp_dir().join(format!(
            "synapse-api-advisory-parity-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let repo = RepoId::new("aien-spark/synapse").unwrap();
        let mut svc = SynapseService::open(
            dir.join("svc"),
            repo.clone(),
            FsyncPolicy::EveryCommit,
            RecoveryPolicy::StrictFailClosed,
            StoreLimits::default(),
        )
        .unwrap();
        let authority = key("authority");
        svc.register_authority(did(&authority));
        let base_oid = GitOid::compute_blob(b"advisory parity base");
        let files: Vec<(String, FileMode, Vec<u8>)> = [
            (".crumb", crumb("root", "root rule")),
            ("README.md", b"# readme\n".to_vec()),
            ("src/.crumb", crumb("src", "src rule")),
            ("src/a.rs", b"fn a() {}\n".to_vec()),
            ("src/b.rs", b"fn b() {}\n".to_vec()),
            ("src/deep/z.rs", b"fn z() {}\n".to_vec()),
            ("src/deep/x/.crumb", crumb("x", "x rule")),
            ("src/deep/x/y.rs", b"fn y() {}\n".to_vec()),
            ("docs/x.md", b"# x\n".to_vec()),
            ("docs/guide/intro.md", b"# intro\n".to_vec()),
        ]
        .into_iter()
        .map(|(p, b)| (p.to_string(), FileMode::Regular644, b))
        .collect();
        svc.register_base_tree(base_oid, files).unwrap();
        Self {
            svc,
            authority,
            repo,
            base_oid,
            counter: 0,
            dir,
            transcript: Vec::new(),
        }
    }

    fn next(&mut self) -> u64 {
        self.counter += 1;
        self.counter
    }

    fn grant(&mut self, agent: &SigningKey, caps: Vec<Capability>) -> AgentCapabilityGrant {
        let n = self.next();
        AgentCapabilityGrant::issue(
            &self.authority,
            derived("grant", n),
            self.repo.clone(),
            did(agent),
            caps,
            1024 * 1024,
            1_000_000,
            60_000,
            10,
            u64::MAX / 2,
        )
    }

    fn propose(
        &mut self,
        agent: &SigningKey,
        label: &str,
        path: &str,
        bytes: &[u8],
    ) -> ChangesetId {
        let digest = BlobDigest::compute(bytes);
        let mut env = ChangesetEnvelope {
            version: SYNAPSE_ENVELOPE_VERSION,
            repo_id: self.repo.clone(),
            base_git_oid: self.base_oid,
            parent_changesets: vec![],
            author_did: String::new(),
            idempotency_key: IdempotencyKey::from_label(label),
            created_at_ms: 100,
            intent_summary: label.to_string(),
            mutations: vec![PathMutation {
                path: path.to_string(),
                op: MutationOp::Upsert {
                    mode: FileMode::Regular644,
                    blob_digest: digest,
                    size_bytes: bytes.len() as u64,
                },
            }],
            evidence_receipts: vec![],
            signature: vec![],
        };
        env.sign(agent);
        let grant = self.grant(agent, vec![Capability::Propose]);
        let n = self.next();
        let now = 1000 + n;
        let req = AuthenticatedRequest::sign_new(
            agent,
            grant,
            self.repo.clone(),
            Capability::Propose,
            derived("nonce", n),
            now,
            0,
            SubmitChangesetPayload {
                envelope: env,
                blobs: vec![(digest, bytes.to_vec())],
            },
        )
        .unwrap();
        match self.svc.submit(&req, now).unwrap() {
            IngestOutcome::Committed { changeset_id, .. } => changeset_id,
            other => panic!("unexpected {other:?}"),
        }
    }

    fn promote(&mut self, cs: ChangesetId) {
        self.svc
            .store_mut()
            .record_canonical_promotion(RadicleCanonicalHead {
                repo_id: self.repo.clone(),
                default_branch: "main".to_string(),
                canonical_git_oid: GitOid::compute_blob(b"canonical"),
                promoted_changeset_id: Some(cs),
                rad_id_commit_oid: GitOid::compute_blob(b"rad id"),
                threshold: 1,
                verified_delegates: vec![],
                verified_at_ms: 5,
            })
            .unwrap();
    }

    fn record<T: Debug>(&mut self, what: &str, r: SynapseResult<T>) {
        let line = match r {
            Ok(v) => format!("{what} => {v:?}\n"),
            Err(e) => format!("{what} => ERR {:?} {}\n", e.code, e.message),
        };
        self.transcript.extend_from_slice(line.as_bytes());
    }

    fn advise(
        &mut self,
        base: TreeTarget,
        latest: Option<TreeTarget>,
        paths: &[&str],
        snapshot_seq: Option<WalSeq>,
        coord: Option<&CoordStore>,
    ) {
        let reader = key("reader");
        let grant = self.grant(&reader, vec![Capability::Read]);
        let n = self.next();
        let now = 1000 + n;
        let r = AuthenticatedRequest::sign_new(
            &reader,
            grant,
            self.repo.clone(),
            Capability::Read,
            derived("nonce", n),
            now,
            0,
            ChangesetAdvisoryPayload {
                base,
                latest,
                paths: paths.iter().map(|p| p.to_string()).collect(),
                agent: "alice".to_string(),
                snapshot_seq,
            },
        )
        .and_then(|req| self.svc.changeset_advisory(&req, coord, now));
        let what = format!(
            "advise base={base:?} latest={latest:?} seq={snapshot_seq:?} coord={} paths={paths:?}",
            coord.is_some()
        );
        self.record(&what, r);
    }

    fn crumb_context(&mut self, target: TreeTarget, path: &str, snapshot_seq: Option<WalSeq>) {
        let reader = key("reader");
        let grant = self.grant(&reader, vec![Capability::Read]);
        let n = self.next();
        let now = 1000 + n;
        let r = AuthenticatedRequest::sign_new(
            &reader,
            grant,
            self.repo.clone(),
            Capability::Read,
            derived("nonce", n),
            now,
            0,
            CrumbContextQueryPayload {
                target,
                path: path.to_string(),
                snapshot_seq,
            },
        )
        .and_then(|req| self.svc.crumb_context(&req, now));
        let what = format!("crumb target={target:?} seq={snapshot_seq:?} path={path}");
        self.record(&what, r);
    }

    /// One pass of the corpus over `targets`.
    fn pass(&mut self, targets: &[TreeTarget], older: Option<WalSeq>, coord: &CoordStore) {
        const PATHS: &[&str] = &[
            ".crumb",
            "README.md",
            "src",
            "src/.crumb",
            "src/a.rs",
            "src/b.rs",
            "src/deep",
            "src/deep/z.rs",
            "src/deep/x",
            "src/deep/x/.crumb",
            "src/deep/x/y.rs",
            "docs",
            "docs/x.md",
            "docs/guide",
            "docs/guide/intro.md",
            "src/new.rs",
            "new/dir/f.rs",
        ];
        for &base in targets {
            for &p in PATHS {
                self.advise(base, None, &[p], None, None);
                self.advise(base, None, &[p], None, Some(coord));
                self.crumb_context(base, p, None);
            }
            self.crumb_context(base, ".", None);
            self.advise(base, None, PATHS, None, Some(coord));
            for &latest in targets {
                self.advise(
                    base,
                    Some(latest),
                    &["src/a.rs", "src/deep/x/y.rs"],
                    None,
                    None,
                );
            }
            self.advise(base, None, PATHS, older, Some(coord));
            self.crumb_context(base, "src/deep/x/y.rs", older);
        }
    }
}

fn claim(store: &CoordStore, agent: &str, target: &str) {
    let ws = Workspace::with_oracle(
        format!("/synapse/ws/{agent}"),
        Holder::synapse("lane", "00112233445566778899", "aabbccddeeff00112233"),
        Box::new(NoOracle),
    );
    let out = store
        .claim(&ws, agent, ".", target, "edit", Some(600))
        .unwrap();
    assert!(matches!(out, ClaimOutcome::Claimed { .. }), "{out:?}");
}

#[test]
fn advisory_and_crumb_answers_match_the_transcript_recorded_on_main() {
    let mut c = Corpus::new();
    let coord = CoordStore::open(c.dir.join("coord")).with_clock(|| T0);
    claim(&coord, "carol", "src/deep");
    claim(&coord, "alice", "src/b.rs");
    claim(&coord, "dave", "docs/guide/intro.md");

    let bob = key("bob");
    let base = TreeTarget::BaseGitCommit(c.base_oid);
    let cs1 = c.propose(&bob, "bob-a", "src/a.rs", b"fn a2() {}\n");
    let cs2 = c.propose(&bob, "bob-new", "src/deep/new.rs", b"fn n() {}\n");
    let older = Some(c.svc.store().committed_seq());
    let cs3 = c.propose(
        &bob,
        "bob-crumb",
        "src/deep/x/.crumb",
        &crumb("x", "x rule 2"),
    );
    let targets = [
        base,
        TreeTarget::Changeset(cs1),
        TreeTarget::Changeset(cs2),
        TreeTarget::Changeset(cs3),
    ];
    c.pass(&targets, older, &coord);

    // New snapshots: a root `.crumb` rewrite and a promotion, then two more passes.
    let cs4 = c.propose(&bob, "bob-root", ".crumb", &crumb("root", "root rule 2"));
    c.promote(cs1);
    let older = Some(c.svc.store().committed_seq());
    let cs5 = c.propose(&bob, "bob-docs", "docs/guide/intro.md", b"# intro 2\n");
    let targets = [
        base,
        TreeTarget::Changeset(cs1),
        TreeTarget::Changeset(cs4),
        TreeTarget::Changeset(cs5),
    ];
    c.pass(&targets, older, &coord);
    c.promote(cs4);
    c.pass(&targets, older, &coord);
    c.pass(&targets, older, &coord);

    let digest = hex::encode(Sha256::digest(&c.transcript));
    println!(
        "advisory parity transcript: {} bytes, {} answers, sha256 {digest}",
        c.transcript.len(),
        c.transcript.iter().filter(|&&b| b == b'\n').count()
    );
    assert_eq!(digest, RECORDED_TRANSCRIPT_SHA256);
}
