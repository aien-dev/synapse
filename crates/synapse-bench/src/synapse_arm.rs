//! Synapse client and service helpers: deterministic identities and grants, signed
//! submit and read requests, and the JSON wire round trip used as the transport
//! approximation (there is no socket or daemon in Gate 4).

use crate::workload::{EditOp, Proposal};
use ed25519_dalek::SigningKey;
use serde::de::DeserializeOwned;
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::path::Path;
use synapse_api::{SubmitChangesetPayload, SynapseService};
use synapse_auth::{AgentCapabilityGrant, AuthenticatedRequest, Capability};
use synapse_core::{
    encode_did_key_ed25519, BlobDigest, ChangesetEnvelope, ChangesetId, FileMode, GitOid,
    IdempotencyKey, MutationOp, PathMutation, RepoId, SYNAPSE_ENVELOPE_VERSION,
};
use synapse_store::{FsyncPolicy, RecoveryPolicy, StoreLimits};

/// Repository identifier used for the representative fixture.
pub const BENCH_REPO_ID: &str = "aien-spark/aien-sovereign-core";

/// Grant quotas sized so that quotas never throttle a benchmark run.
pub const BENCH_MAX_BYTES_PER_OP: u64 = 1024 * 1024 * 1024;
pub const BENCH_RATE_WINDOW_MS: u64 = 60_000;

/// One agent's key and capability grant.
#[derive(Debug, Clone)]
pub struct AgentIdentity {
    pub key: SigningKey,
    pub did: String,
    pub grant: AgentCapabilityGrant,
}

/// Repository authority plus agent identities.
#[derive(Debug, Clone)]
pub struct BenchIdentities {
    pub repo_id: RepoId,
    pub authority_key: SigningKey,
    pub authority_did: String,
    pub agents: Vec<AgentIdentity>,
}

fn derive_bytes(seed: u64, role: &str, index: u64) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"SYNAPSE_GATE4_BENCH_V1\0");
    h.update(seed.to_le_bytes());
    h.update(role.as_bytes());
    h.update(index.to_le_bytes());
    h.finalize().into()
}

/// Deterministic Ed25519 key for `(seed, role, index)`.
pub fn deterministic_key(seed: u64, role: &str, index: u64) -> SigningKey {
    SigningKey::from_bytes(&derive_bytes(seed, role, index))
}

/// 32 bytes derived from a label (used for request nonces).
pub fn label_bytes(label: &str) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"SYNAPSE_GATE4_BENCH_LABEL_V1\0");
    h.update(label.as_bytes());
    h.finalize().into()
}

/// Issue `agents` identities with `Read` and `Propose` grants valid around `now_ms`.
pub fn issue_identities(seed: u64, agents: usize, now_ms: u64) -> Result<BenchIdentities, String> {
    let repo_id = RepoId::new(BENCH_REPO_ID).map_err(|e| e.to_string())?;
    let authority_key = deterministic_key(seed, "authority", 0);
    let authority_did = encode_did_key_ed25519(&authority_key.verifying_key().to_bytes());
    let agents = (0..agents)
        .map(|i| {
            let key = deterministic_key(seed, "agent", i as u64);
            let did = encode_did_key_ed25519(&key.verifying_key().to_bytes());
            let grant = AgentCapabilityGrant::issue(
                &authority_key,
                derive_bytes(seed, "grant", i as u64),
                repo_id.clone(),
                did.clone(),
                vec![Capability::Read, Capability::Propose],
                BENCH_MAX_BYTES_PER_OP,
                u32::MAX,
                BENCH_RATE_WINDOW_MS,
                now_ms.saturating_sub(3_600_000),
                now_ms + 7 * 24 * 3_600_000,
            );
            AgentIdentity { key, did, grant }
        })
        .collect();
    Ok(BenchIdentities {
        repo_id,
        authority_key,
        authority_did,
        agents,
    })
}

/// Open a `SynapseService` and trust the bench authority.
pub fn open_service(
    dir: &Path,
    ids: &BenchIdentities,
    fsync: FsyncPolicy,
    recovery: RecoveryPolicy,
) -> Result<SynapseService, String> {
    let mut svc = SynapseService::open(
        dir,
        ids.repo_id.clone(),
        fsync,
        recovery,
        StoreLimits::default(),
    )
    .map_err(|e| e.to_string())?;
    svc.register_authority(ids.authority_did.clone());
    Ok(svc)
}

/// Register the pinned base commit tree from already-loaded `(path, mode, bytes)` files.
pub fn register_base(
    svc: &mut SynapseService,
    base_commit_hex: &str,
    files: Vec<(String, FileMode, Vec<u8>)>,
) -> Result<GitOid, String> {
    let oid = GitOid::from_hex(base_commit_hex).map_err(|e| e.to_string())?;
    svc.register_base_tree(oid, files)
        .map_err(|e| e.to_string())?;
    Ok(oid)
}

/// Build the signed envelope and signed `submit` request for `proposal`.
pub fn build_submit_request(
    agent: &AgentIdentity,
    repo_id: &RepoId,
    base_oid: GitOid,
    proposal: &Proposal,
    label: &str,
    now_ms: u64,
) -> Result<AuthenticatedRequest<SubmitChangesetPayload>, String> {
    build_submit_request_with_parents(
        agent,
        repo_id,
        base_oid,
        Vec::new(),
        proposal,
        label,
        now_ms,
    )
}

/// Same as [`build_submit_request`] with explicit (sorted, unique) parent changesets.
pub fn build_submit_request_with_parents(
    agent: &AgentIdentity,
    repo_id: &RepoId,
    base_oid: GitOid,
    parent_changesets: Vec<ChangesetId>,
    proposal: &Proposal,
    label: &str,
    now_ms: u64,
) -> Result<AuthenticatedRequest<SubmitChangesetPayload>, String> {
    let mut mutations = Vec::with_capacity(proposal.edits.len());
    let mut blobs: Vec<(BlobDigest, Vec<u8>)> = Vec::new();
    for edit in &proposal.edits {
        let op = match &edit.op {
            EditOp::Upsert { mode, content } => {
                let digest = BlobDigest::compute(content);
                if !blobs.iter().any(|(d, _)| *d == digest) {
                    blobs.push((digest, content.as_ref().clone()));
                }
                MutationOp::Upsert {
                    mode: *mode,
                    blob_digest: digest,
                    size_bytes: content.len() as u64,
                }
            }
            EditOp::Delete => MutationOp::Delete,
        };
        mutations.push(PathMutation {
            path: edit.path.clone(),
            op,
        });
    }
    let mut envelope = ChangesetEnvelope {
        version: SYNAPSE_ENVELOPE_VERSION,
        repo_id: repo_id.clone(),
        base_git_oid: base_oid,
        parent_changesets,
        author_did: agent.did.clone(),
        idempotency_key: IdempotencyKey::from_label(label),
        created_at_ms: now_ms,
        intent_summary: proposal.summary.clone(),
        mutations,
        evidence_receipts: Vec::new(),
        signature: Vec::new(),
    };
    envelope.sign(&agent.key);
    AuthenticatedRequest::sign_new(
        &agent.key,
        agent.grant.clone(),
        repo_id.clone(),
        Capability::Propose,
        label_bytes(label),
        now_ms,
        0,
        SubmitChangesetPayload { envelope, blobs },
    )
    .map_err(|e| e.to_string())
}

/// Build a signed `Read` request carrying `payload`.
pub fn build_read_request<T: Serialize>(
    agent: &AgentIdentity,
    repo_id: &RepoId,
    payload: T,
    label: &str,
    now_ms: u64,
) -> Result<AuthenticatedRequest<T>, String> {
    AuthenticatedRequest::sign_new(
        &agent.key,
        agent.grant.clone(),
        repo_id.clone(),
        Capability::Read,
        label_bytes(label),
        now_ms,
        0,
        payload,
    )
    .map_err(|e| e.to_string())
}

/// Encode `value` as JSON and decode it again (client encode plus server decode).
/// Returns the decoded value and the encoded byte count.
pub fn wire_roundtrip<T: Serialize + DeserializeOwned>(value: &T) -> Result<(T, usize), String> {
    let bytes = serde_json::to_vec(value).map_err(|e| format!("wire encode: {e}"))?;
    let decoded = serde_json::from_slice(&bytes).map_err(|e| format!("wire decode: {e}"))?;
    Ok((decoded, bytes.len()))
}
