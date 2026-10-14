//! Writes legacy v1 (JSON) stores with the merged main-branch synapse-store, for ADR 0003 A1 fixtures.
use ed25519_dalek::SigningKey;
use std::path::Path;
use synapse_core::*;
use synapse_store::*;

fn cs(key: &SigningKey, label: &str, path: &str, content: &[u8], parents: Vec<ChangesetId>, extra_delete: bool, receipts: bool) -> (ChangesetEnvelope, Vec<(BlobDigest, Vec<u8>)>) {
    let digest = BlobDigest::compute(content);
    let mut mutations = vec![PathMutation { path: path.to_string(), op: MutationOp::Upsert { mode: FileMode::Executable755, blob_digest: digest, size_bytes: content.len() as u64 } }];
    if extra_delete {
        mutations.push(PathMutation { path: format!("{path}.old"), op: MutationOp::Delete });
    }
    let mut env = ChangesetEnvelope {
        version: SYNAPSE_ENVELOPE_VERSION,
        repo_id: RepoId::new("aien-spark/synapse").unwrap(),
        base_git_oid: GitOid::compute_blob(b"a1 fixture base"),
        parent_changesets: parents,
        author_did: String::new(),
        idempotency_key: IdempotencyKey::from_label(label),
        created_at_ms: 1_000,
        intent_summary: format!("A1 fixture {label}: \u{e9}t\u{e9} \u{1F980} \"quoted\" \\ back"),
        mutations,
        evidence_receipts: if receipts { vec![EvidenceAttachment { gate_name: "cargo-test".into(), passed: true, artifact_digest: [7u8; 32], summary: "ok\nline2".into() }] } else { vec![] },
        signature: vec![],
    };
    env.sign(key);
    (env, vec![(digest, content.to_vec())])
}

fn id(o: IngestOutcome) -> ChangesetId {
    match o { IngestOutcome::Committed { changeset_id, .. } => changeset_id, IngestOutcome::IdempotentDuplicate { changeset_id, .. } => changeset_id }
}

fn all_kinds(store: &mut SynapseStore, key: &SigningKey, tag: &str, parent: Option<ChangesetId>) -> ChangesetId {
    let (e1, b1) = cs(key, &format!("{tag}-1"), &format!("src/{tag}/a.rs"), format!("fn {tag}() {{}}\n").as_bytes(), parent.into_iter().collect(), false, false);
    let c1 = id(store.ingest_changeset(e1, &b1).unwrap());
    let (e2, b2) = cs(key, &format!("{tag}-2"), &format!("src/{tag}/b.rs"), b"\x00\xffbinary", vec![c1], true, true);
    let c2 = id(store.ingest_changeset(e2, &b2).unwrap());
    store.attach_evaluation(c2, EvidenceAttachment { gate_name: "clippy".into(), passed: false, artifact_digest: [9u8; 32], summary: String::new() }).unwrap();
    store.record_review(c2, ReviewRecord { reviewer_did: "did:key:z6MkReviewerA1".into(), approved: true, comment: "lgtm \u{2713}".into(), recorded_at_ms: u64::MAX }).unwrap();
    store.record_github_projection(GitHubPullRequestProjection { repo_id: RepoId::new("aien-spark/synapse").unwrap(), pr_number: 22, changeset_id: c2, head_git_oid: GitOid::compute_blob(b"head"), base_git_oid: GitOid::ZERO, pr_branch_ref: format!("refs/heads/{tag}"), title: "A1 \u{1F680}".into(), body_markdown: "# body\n\n- item".into(), evidence_summary_digest: [3u8; 32], github_merged: false }).unwrap();
    store.record_canonical_promotion(RadicleCanonicalHead { repo_id: RepoId::new("aien-spark/synapse").unwrap(), default_branch: "main".into(), canonical_git_oid: GitOid::compute_blob(b"canon"), promoted_changeset_id: Some(c1), rad_id_commit_oid: GitOid::compute_blob(b"rad"), threshold: 2, verified_delegates: vec!["did:key:a".into(), "did:key:b".into()], verified_at_ms: 5 }).unwrap();
    store.record_canonical_promotion(RadicleCanonicalHead { repo_id: RepoId::new("aien-spark/other").unwrap(), default_branch: "trunk".into(), canonical_git_oid: GitOid::ZERO, promoted_changeset_id: None, rad_id_commit_oid: GitOid::ZERO, threshold: 0, verified_delegates: vec![], verified_at_ms: 0 }).unwrap();
    store.update_lease(c1, 9_999_999_999).unwrap();
    c2
}

fn write_expect(dir: &Path, store: &SynapseStore) {
    let root = store.state_root_digest(None).unwrap();
    std::fs::write(dir.join("EXPECT"), format!("committed_seq {}\nstate_root {}\nlast_frame_sha256 {}\n", store.committed_seq().0, hex::encode(root), hex::encode(store.last_frame_sha256()))).unwrap();
}

fn main() {
    let out = Path::new(&std::env::args().nth(1).expect("out dir")).to_path_buf();
    let key = SigningKey::from_bytes(&[0xA1; 32]);
    // 1. wal.log store: JSON frames, checkpoint.v1 (retention keeps everything), then JSON frames after it.
    let d1 = out.join("v1-wal-log");
    let _ = std::fs::remove_dir_all(&d1);
    {
        let limits = StoreLimits { default_retention_window_ms: u64::MAX, ..Default::default() };
        let mut s = SynapseStore::open(&d1, FsyncPolicy::EveryCommit, RecoveryPolicy::StrictFailClosed, limits).unwrap();
        let last = all_kinds(&mut s, &key, "pre", None);
        s.checkpoint_and_compact(2_000).unwrap();
        all_kinds(&mut s, &key, "post", Some(last));
        write_expect(&d1, &s);
    }
    // 2. wal.v2.log store (group commit): JSON metadata with inline blobs, small preallocation.
    let d2 = out.join("v1-wal-v2-log");
    let _ = std::fs::remove_dir_all(&d2);
    {
        let limits = StoreLimits { default_retention_window_ms: u64::MAX, wal_prealloc_bytes: 64 * 1024, ..Default::default() };
        let mut s = SynapseStore::open(&d2, FsyncPolicy::GROUP_COMMIT_DEFAULT, RecoveryPolicy::StrictFailClosed, limits).unwrap();
        all_kinds(&mut s, &key, "gc", None);
        write_expect(&d2, &s);
    }
}
