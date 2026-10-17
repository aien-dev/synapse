//! Capability-scoped Ed25519 authentication, replay protection, quota enforcement,
//! and tamper-evident hash-chained security audit logging (`synapse-auth`, Gate 2a).

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use synapse_core::{
    decode_did_key_ed25519, encode_did_key_ed25519, RefusalCode, RepoId, SynapseError,
    SynapseResult,
};

mod chain;
mod state_move;
pub use chain::*;
pub use state_move::*;
mod digest;
pub use digest::payload_digest;

/// Current capability grant schema version.
pub const CAPABILITY_GRANT_VERSION: u16 = 1;

/// Domain tag for signing `AgentCapabilityGrant`.
pub const DOMAIN_CAPABILITY_GRANT_V1: &[u8] = b"SYNAPSE_CAPABILITY_GRANT_V1\0";

/// Domain tag for signing `AuthenticatedRequest`.
pub const DOMAIN_AUTH_REQUEST_V1: &[u8] = b"SYNAPSE_AUTH_REQUEST_V1\0";

/// Domain tag for hash-chaining `AuditEntry`.
pub const DOMAIN_AUDIT_ENTRY_V1: &[u8] = b"SYNAPSE_AUDIT_ENTRY_V1\0";

/// Fine-grained capabilities enforced across Synapse boundaries.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum Capability {
    /// Inspect changesets, virtual trees, diffs, history, provenance, conflicts, status, and watch cursors.
    Read,
    /// Submit new changeset proposals (`submit`).
    Propose,
    /// Attach machine evaluation and benchmark receipts (`attach_evaluation`).
    Evaluate,
    /// Record review verdicts on changesets authored by other agents (`record_review`).
    Review,
    /// Project changesets to Git/GitHub or request canonical promotion (`project_git`, `promote_canonical`).
    Publish,
    /// Restore an earlier operation view (ADR 0003 section 5.4); undoing another actor's
    /// operations also needs a delegation chain that dominates that actor's (step B2).
    Undo,
}

impl Capability {
    pub fn tag_byte(self) -> u8 {
        match self {
            Self::Read => 1,
            Self::Propose => 2,
            Self::Evaluate => 3,
            Self::Review => 4,
            Self::Publish => 5,
            Self::Undo => 6,
        }
    }

    pub fn is_mutating(self) -> bool {
        !matches!(self, Self::Read)
    }
}

/// Boundary at which a policy check is enforced and audited.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BoundaryKind {
    Api,
    Store,
    Worker,
    Export,
}

/// Repository-scoped capability grant signed by a trusted repository authority Ed25519 key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentCapabilityGrant {
    pub version: u16,
    pub grant_id: [u8; 32],
    pub repo_id: RepoId,
    pub issuer_did: String,
    pub agent_did: String,
    pub capabilities: Vec<Capability>,
    pub max_bytes_per_op: u64,
    pub max_ops_per_window: u32,
    pub window_duration_ms: u64,
    pub issued_at_ms: u64,
    pub expires_at_ms: u64,
    pub signature: Vec<u8>,
}

impl AgentCapabilityGrant {
    /// Create and sign a new `AgentCapabilityGrant` using the repository authority's `SigningKey`.
    #[allow(clippy::too_many_arguments)]
    pub fn issue(
        authority_key: &SigningKey,
        grant_id: [u8; 32],
        repo_id: RepoId,
        agent_did: String,
        mut capabilities: Vec<Capability>,
        max_bytes_per_op: u64,
        max_ops_per_window: u32,
        window_duration_ms: u64,
        issued_at_ms: u64,
        expires_at_ms: u64,
    ) -> Self {
        capabilities.sort();
        capabilities.dedup();
        let issuer_did = encode_did_key_ed25519(&authority_key.verifying_key().to_bytes());
        let mut grant = Self {
            version: CAPABILITY_GRANT_VERSION,
            grant_id,
            repo_id,
            issuer_did,
            agent_did,
            capabilities,
            max_bytes_per_op,
            max_ops_per_window,
            window_duration_ms,
            issued_at_ms,
            expires_at_ms,
            signature: Vec::new(),
        };
        let signable = grant.canonical_signable_bytes();
        grant.signature = authority_key.sign(&signable).to_bytes().to_vec();
        grant
    }

    /// Deterministically encode unsigned grant fields for Ed25519 authority signing.
    pub fn canonical_signable_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(256);
        buf.extend_from_slice(DOMAIN_CAPABILITY_GRANT_V1);
        buf.extend_from_slice(&self.version.to_le_bytes());
        buf.extend_from_slice(&self.grant_id);
        put_str(&mut buf, self.repo_id.as_str());
        put_str(&mut buf, &self.issuer_did);
        put_str(&mut buf, &self.agent_did);
        buf.extend_from_slice(&(self.capabilities.len() as u32).to_le_bytes());
        for cap in &self.capabilities {
            buf.push(cap.tag_byte());
        }
        buf.extend_from_slice(&self.max_bytes_per_op.to_le_bytes());
        buf.extend_from_slice(&self.max_ops_per_window.to_le_bytes());
        buf.extend_from_slice(&self.window_duration_ms.to_le_bytes());
        buf.extend_from_slice(&self.issued_at_ms.to_le_bytes());
        buf.extend_from_slice(&self.expires_at_ms.to_le_bytes());
        buf
    }

    /// Verify the authority's Ed25519 signature over the grant.
    pub fn verify_authority_signature(&self) -> SynapseResult<()> {
        if self.version != CAPABILITY_GRANT_VERSION {
            return Err(SynapseError::new(
                RefusalCode::EnvelopeVersionUnsupported,
                format!("unsupported capability grant version {}", self.version),
            ));
        }
        let pubkey_bytes = decode_did_key_ed25519(&self.issuer_did)?;
        let verifying_key = VerifyingKey::from_bytes(&pubkey_bytes).map_err(|_| {
            SynapseError::new(
                RefusalCode::DidKeyInvalid,
                "invalid authority Ed25519 public key",
            )
        })?;
        let sig_arr: [u8; 64] = self.signature.as_slice().try_into().map_err(|_| {
            SynapseError::new(
                RefusalCode::AuthGrantSignatureInvalid,
                "grant signature must be 64 bytes",
            )
        })?;
        let sig = Signature::from_bytes(&sig_arr);
        verifying_key
            .verify_strict(&self.canonical_signable_bytes(), &sig)
            .map_err(|_| {
                SynapseError::new(
                    RefusalCode::AuthGrantSignatureInvalid,
                    "grant signature verification failed",
                )
            })
    }
}

/// Signed request envelope binding an `AgentCapabilityGrant`, a single-use `request_nonce`,
/// the target `RepoId`, the required `Capability`, and the payload digest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthenticatedRequest<T> {
    pub grant: AgentCapabilityGrant,
    pub target_repo_id: RepoId,
    pub required_capability: Capability,
    pub request_nonce: [u8; 32],
    pub timestamp_ms: u64,
    pub payload_bytes_len: u64,
    pub payload_sha256: [u8; 32],
    pub payload: T,
    pub agent_signature: Vec<u8>,
}

impl<T: Serialize> AuthenticatedRequest<T> {
    #[allow(clippy::too_many_arguments)]
    /// Construct and sign an `AuthenticatedRequest` with the agent's Ed25519 `SigningKey`.
    pub fn sign_new(
        agent_key: &SigningKey,
        grant: AgentCapabilityGrant,
        target_repo_id: RepoId,
        required_capability: Capability,
        request_nonce: [u8; 32],
        timestamp_ms: u64,
        declared_payload_bytes_len: u64,
        payload: T,
    ) -> SynapseResult<Self> {
        let (payload_sha256, serialized_len) = payload_digest(&payload)?;
        let effective_len = declared_payload_bytes_len.max(serialized_len);

        let mut req = Self {
            grant,
            target_repo_id,
            required_capability,
            request_nonce,
            timestamp_ms,
            payload_bytes_len: effective_len,
            payload_sha256,
            payload,
            agent_signature: Vec::new(),
        };
        let signable = req.canonical_signable_bytes();
        req.agent_signature = agent_key.sign(&signable).to_bytes().to_vec();
        Ok(req)
    }

    /// Deterministically encode request metadata + payload digest for agent Ed25519 signing.
    pub fn canonical_signable_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(256);
        buf.extend_from_slice(DOMAIN_AUTH_REQUEST_V1);
        buf.extend_from_slice(&self.grant.grant_id);
        put_str(&mut buf, self.target_repo_id.as_str());
        buf.push(self.required_capability.tag_byte());
        buf.extend_from_slice(&self.request_nonce);
        buf.extend_from_slice(&self.timestamp_ms.to_le_bytes());
        buf.extend_from_slice(&self.payload_bytes_len.to_le_bytes());
        buf.extend_from_slice(&self.payload_sha256);
        buf
    }
}

/// Outcome recorded in the security `AuditLog`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AuditOutcome {
    Admitted,
    Refused { code: RefusalCode, reason: String },
}

/// Hash-chained security audit entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditEntry {
    pub audit_seq: u64,
    pub timestamp_ms: u64,
    pub boundary: BoundaryKind,
    pub repo_id: RepoId,
    pub actor_did: String,
    pub capability: Capability,
    pub operation: String,
    pub outcome: AuditOutcome,
    pub prev_entry_sha256: [u8; 32],
    pub entry_sha256: [u8; 32],
}

impl AuditEntry {
    pub fn compute_sha256(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(DOMAIN_AUDIT_ENTRY_V1);
        hasher.update(self.audit_seq.to_le_bytes());
        hasher.update(self.timestamp_ms.to_le_bytes());
        hasher.update([self.boundary as u8]);
        hasher.update(self.repo_id.as_str().as_bytes());
        hasher.update(b"\0");
        hasher.update(self.actor_did.as_bytes());
        hasher.update(b"\0");
        hasher.update([self.capability.tag_byte()]);
        hasher.update(self.operation.as_bytes());
        hasher.update(b"\0");
        match &self.outcome {
            AuditOutcome::Admitted => hasher.update([1u8]),
            AuditOutcome::Refused { code, reason } => {
                hasher.update([0u8]);
                hasher.update(format!("{code:?}").as_bytes());
                hasher.update(b"\0");
                hasher.update(reason.as_bytes());
            }
        }
        hasher.update(self.prev_entry_sha256);
        hasher.finalize().into()
    }
}

/// Tamper-evident hash-chained security audit log.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AuditLog {
    entries: Vec<AuditEntry>,
    last_sha256: [u8; 32],
}

impl AuditLog {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn entries(&self) -> &[AuditEntry] {
        &self.entries
    }

    pub fn entries_mut_for_testing(&mut self) -> &mut Vec<AuditEntry> {
        &mut self.entries
    }

    #[allow(clippy::too_many_arguments)]
    pub fn record(
        &mut self,
        timestamp_ms: u64,
        boundary: BoundaryKind,
        repo_id: RepoId,
        actor_did: String,
        capability: Capability,
        operation: impl Into<String>,
        outcome: AuditOutcome,
    ) -> &AuditEntry {
        let audit_seq = (self.entries.len() as u64).saturating_add(1);
        let mut entry = AuditEntry {
            audit_seq,
            timestamp_ms,
            boundary,
            repo_id,
            actor_did,
            capability,
            operation: operation.into(),
            outcome,
            prev_entry_sha256: self.last_sha256,
            entry_sha256: [0u8; 32],
        };
        entry.entry_sha256 = entry.compute_sha256();
        self.last_sha256 = entry.entry_sha256;
        self.entries.push(entry);
        self.entries.last().expect("just pushed")
    }

    /// Verify the entire hash chain and sequence continuity of the audit log.
    pub fn verify_chain(&self) -> SynapseResult<[u8; 32]> {
        let mut prev = [0u8; 32];
        for (idx, entry) in self.entries.iter().enumerate() {
            let expected_seq = (idx as u64) + 1;
            if entry.audit_seq != expected_seq {
                return Err(SynapseError::new(
                    RefusalCode::AuditChainCorrupt,
                    format!(
                        "audit sequence gap: expected {}, got {}",
                        expected_seq, entry.audit_seq
                    ),
                ));
            }
            if entry.prev_entry_sha256 != prev {
                return Err(SynapseError::new(
                    RefusalCode::AuditChainCorrupt,
                    format!(
                        "audit prev_entry_sha256 mismatch at seq {}",
                        entry.audit_seq
                    ),
                ));
            }
            let computed = entry.compute_sha256();
            if entry.entry_sha256 != computed {
                return Err(SynapseError::new(
                    RefusalCode::AuditChainCorrupt,
                    format!("audit entry_sha256 tampered at seq {}", entry.audit_seq),
                ));
            }
            prev = computed;
        }
        Ok(prev)
    }
}

/// Policy enforcer verifying capability grants, Ed25519 request signatures, replay nonces,
/// cross-repository isolation, and rate/size quotas across all Synapse boundaries.
pub struct PolicyEnforcer {
    trusted_authorities: BTreeMap<RepoId, BTreeSet<String>>,
    consumed_nonces: BTreeSet<(RepoId, String, [u8; 32])>,
    rate_windows: BTreeMap<(RepoId, String), Vec<u64>>,
    audit_log: AuditLog,
    chains: ChainRegistry,
}

impl Default for PolicyEnforcer {
    fn default() -> Self {
        Self::new()
    }
}

impl PolicyEnforcer {
    pub fn new() -> Self {
        Self {
            trusted_authorities: BTreeMap::new(),
            consumed_nonces: BTreeSet::new(),
            rate_windows: BTreeMap::new(),
            audit_log: AuditLog::new(),
            chains: ChainRegistry::default(),
        }
    }

    /// Register a trusted repository authority `did:key:z6Mk...` for `repo_id`.
    pub fn register_repo_authority(&mut self, repo_id: RepoId, authority_did: impl Into<String>) {
        self.trusted_authorities
            .entry(repo_id)
            .or_default()
            .insert(authority_did.into());
    }

    /// Return a reference to the tamper-evident security audit log.
    pub fn audit_log(&self) -> &AuditLog {
        &self.audit_log
    }

    /// Return a mutable reference to the audit log (for persistence or tamper-detection tests).
    pub fn audit_log_mut(&mut self) -> &mut AuditLog {
        &mut self.audit_log
    }

    /// Verify and authorize an `AuthenticatedRequest<T>` at `boundary` and `now_ms`,
    /// recording either `Admitted` or `Refused` in the hash-chained `AuditLog`.
    pub fn authorize<T: Serialize>(
        &mut self,
        boundary: BoundaryKind,
        operation: &str,
        expected_repo_id: &RepoId,
        expected_capability: Capability,
        req: &AuthenticatedRequest<T>,
        now_ms: u64,
    ) -> SynapseResult<()> {
        let result = self.check_request_inner(expected_repo_id, expected_capability, req, now_ms);
        match &result {
            Ok(()) => {
                self.audit_log.record(
                    now_ms,
                    boundary,
                    expected_repo_id.clone(),
                    req.grant.agent_did.clone(),
                    expected_capability,
                    operation,
                    AuditOutcome::Admitted,
                );
            }
            Err(err) => {
                self.audit_log.record(
                    now_ms,
                    boundary,
                    expected_repo_id.clone(),
                    req.grant.agent_did.clone(),
                    expected_capability,
                    operation,
                    AuditOutcome::Refused {
                        code: err.code,
                        reason: err.message.clone(),
                    },
                );
            }
        }
        result
    }

    fn check_request_inner<T: Serialize>(
        &mut self,
        expected_repo_id: &RepoId,
        expected_capability: Capability,
        req: &AuthenticatedRequest<T>,
        now_ms: u64,
    ) -> SynapseResult<()> {
        // 1. Cross-repository check on both request target and grant scope
        if &req.target_repo_id != expected_repo_id || &req.grant.repo_id != expected_repo_id {
            return Err(SynapseError::new(
                RefusalCode::AuthCrossRepoDenied,
                format!(
                    "cross-repo access denied: grant repo {} vs target repo {}",
                    req.grant.repo_id, expected_repo_id
                ),
            ));
        }

        // 2. Verify grant issuer is a trusted authority for `expected_repo_id`
        let trusted = self
            .trusted_authorities
            .get(expected_repo_id)
            .is_some_and(|set| set.contains(&req.grant.issuer_did));
        if !trusted {
            return Err(SynapseError::new(
                RefusalCode::AuthGrantSignatureInvalid,
                format!(
                    "issuer {} is not a trusted authority for {}",
                    req.grant.issuer_did, expected_repo_id
                ),
            ));
        }

        // 3. Cryptographically verify the authority signature on the capability grant
        req.grant.verify_authority_signature()?;

        // 4. Verify grant time validity (`issued_at_ms <= now_ms <= expires_at_ms`)
        if now_ms > req.grant.expires_at_ms || now_ms < req.grant.issued_at_ms {
            return Err(SynapseError::new(
                RefusalCode::AuthGrantExpired,
                format!(
                    "capability grant expired or not yet valid (now={now_ms}, window={}..={})",
                    req.grant.issued_at_ms, req.grant.expires_at_ms
                ),
            ));
        }

        // 5. Verify required capability is present in both request and grant
        if req.required_capability != expected_capability
            || !req.grant.capabilities.contains(&expected_capability)
        {
            return Err(SynapseError::new(
                RefusalCode::AuthCapabilityDenied,
                format!(
                    "agent {} lacks required capability {:?}",
                    req.grant.agent_did, expected_capability
                ),
            ));
        }

        // 6. Verify payload digest and agent's Ed25519 signature over the request
        let (actual_payload_sha256, serialized_payload_len) = payload_digest(&req.payload)?;
        if actual_payload_sha256 != req.payload_sha256 {
            return Err(SynapseError::new(
                RefusalCode::AuthSignatureInvalid,
                "request payload_sha256 does not match serialized payload",
            ));
        }

        let agent_pubkey_bytes = decode_did_key_ed25519(&req.grant.agent_did)?;
        let agent_verifying_key = VerifyingKey::from_bytes(&agent_pubkey_bytes).map_err(|_| {
            SynapseError::new(RefusalCode::DidKeyInvalid, "invalid agent Ed25519 key")
        })?;
        let sig_arr: [u8; 64] = req.agent_signature.as_slice().try_into().map_err(|_| {
            SynapseError::new(
                RefusalCode::AuthSignatureInvalid,
                "agent request signature must be 64 bytes",
            )
        })?;
        let sig = Signature::from_bytes(&sig_arr);
        agent_verifying_key
            .verify_strict(&req.canonical_signable_bytes(), &sig)
            .map_err(|_| {
                SynapseError::new(
                    RefusalCode::AuthSignatureInvalid,
                    "agent Ed25519 request signature verification failed",
                )
            })?;

        // 7. Enforce payload byte quota
        let effective_bytes = req.payload_bytes_len.max(serialized_payload_len);
        if effective_bytes > req.grant.max_bytes_per_op {
            return Err(SynapseError::new(
                RefusalCode::QuotaPayloadTooLarge,
                format!(
                    "request payload size {} exceeds grant max_bytes_per_op {}",
                    effective_bytes, req.grant.max_bytes_per_op
                ),
            ));
        }

        // 8. Enforce sliding-window rate limit per `(repo_id, agent_did)`
        let window_key = (expected_repo_id.clone(), req.grant.agent_did.clone());
        let window_start = now_ms.saturating_sub(req.grant.window_duration_ms);
        let timestamps = self.rate_windows.entry(window_key).or_default();
        timestamps.retain(|&ts| ts >= window_start);
        if timestamps.len() as u32 >= req.grant.max_ops_per_window {
            return Err(SynapseError::new(
                RefusalCode::QuotaRateLimitExceeded,
                format!(
                    "agent {} exceeded rate limit ({} ops per {} ms)",
                    req.grant.agent_did, req.grant.max_ops_per_window, req.grant.window_duration_ms
                ),
            ));
        }

        // 9. Enforce single-use nonce anti-replay for all mutating operations
        if expected_capability.is_mutating() {
            let nonce_key = (
                expected_repo_id.clone(),
                req.grant.agent_did.clone(),
                req.request_nonce,
            );
            if !self.consumed_nonces.insert(nonce_key) {
                return Err(SynapseError::new(
                    RefusalCode::AuthReplayDetected,
                    "replayed mutation request_nonce refused",
                ));
            }
        }

        timestamps.push(now_ms);
        Ok(())
    }
}

fn put_str(buf: &mut Vec<u8>, s: &str) {
    buf.extend_from_slice(&(s.len() as u32).to_le_bytes());
    buf.extend_from_slice(s.as_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_capability_matrix_adversarial_refusals_and_audit_chain() {
        let authority_key = SigningKey::from_bytes(&[1u8; 32]);
        let authority_did = encode_did_key_ed25519(&authority_key.verifying_key().to_bytes());

        let proposer_key = SigningKey::from_bytes(&[2u8; 32]);
        let proposer_did = encode_did_key_ed25519(&proposer_key.verifying_key().to_bytes());

        let attacker_key = SigningKey::from_bytes(&[99u8; 32]);

        let repo_a = RepoId::new("aien-spark/synapse").unwrap();
        let repo_b = RepoId::new("aien-spark/aien-sovereign-core").unwrap();

        let mut enforcer = PolicyEnforcer::new();
        enforcer.register_repo_authority(repo_a.clone(), authority_did);

        let grant = AgentCapabilityGrant::issue(
            &authority_key,
            [0x10; 32],
            repo_a.clone(),
            proposer_did.clone(),
            vec![Capability::Read, Capability::Propose],
            1024, // max 1024 bytes per op
            2,    // max 2 ops per 10s window
            10_000,
            1_000,
            5_000,
        );

        // 1. Valid Propose request succeeds
        let req1 = AuthenticatedRequest::sign_new(
            &proposer_key,
            grant.clone(),
            repo_a.clone(),
            Capability::Propose,
            [1u8; 32],
            2_000,
            128,
            "changeset-1",
        )
        .unwrap();
        enforcer
            .authorize(
                BoundaryKind::Api,
                "submit",
                &repo_a,
                Capability::Propose,
                &req1,
                2_000,
            )
            .expect("valid Propose must be admitted");

        // 2. Replay of the exact same mutation request (same request_nonce) is refused
        let replay_err = enforcer
            .authorize(
                BoundaryKind::Api,
                "submit",
                &repo_a,
                Capability::Propose,
                &req1,
                2_001,
            )
            .unwrap_err();
        assert_eq!(replay_err.code, RefusalCode::AuthReplayDetected);

        // 3. Forged agent signature (signed by attacker_key claiming proposer's grant) is refused
        let forged_req = AuthenticatedRequest::sign_new(
            &attacker_key,
            grant.clone(),
            repo_a.clone(),
            Capability::Propose,
            [2u8; 32],
            2_002,
            128,
            "forged-changeset",
        )
        .unwrap();
        let forged_err = enforcer
            .authorize(
                BoundaryKind::Api,
                "submit",
                &repo_a,
                Capability::Propose,
                &forged_req,
                2_002,
            )
            .unwrap_err();
        assert_eq!(forged_err.code, RefusalCode::AuthSignatureInvalid);

        // 4. Cross-repository token reuse (grant for repo_a used against repo_b) is refused
        let cross_err = enforcer
            .authorize(
                BoundaryKind::Store,
                "submit",
                &repo_b,
                Capability::Propose,
                &req1,
                2_003,
            )
            .unwrap_err();
        assert_eq!(cross_err.code, RefusalCode::AuthCrossRepoDenied);

        // 5. Insufficient capability (proposer attempting Publish) is refused
        let publish_req = AuthenticatedRequest::sign_new(
            &proposer_key,
            grant.clone(),
            repo_a.clone(),
            Capability::Publish,
            [3u8; 32],
            2_004,
            128,
            "promote-main",
        )
        .unwrap();
        let cap_err = enforcer
            .authorize(
                BoundaryKind::Export,
                "promote_canonical",
                &repo_a,
                Capability::Publish,
                &publish_req,
                2_004,
            )
            .unwrap_err();
        assert_eq!(cap_err.code, RefusalCode::AuthCapabilityDenied);

        // 6. Expired grant (now_ms = 6_000 > expires_at_ms = 5_000) is refused
        let expired_err = enforcer
            .authorize(
                BoundaryKind::Api,
                "submit",
                &repo_a,
                Capability::Propose,
                &req1,
                6_000,
            )
            .unwrap_err();
        assert_eq!(expired_err.code, RefusalCode::AuthGrantExpired);

        // 7. Payload byte quota exceeded (2048 > 1024) is refused
        let oversize_req = AuthenticatedRequest::sign_new(
            &proposer_key,
            grant.clone(),
            repo_a.clone(),
            Capability::Propose,
            [4u8; 32],
            2_100,
            2_048,
            "oversize",
        )
        .unwrap();
        let quota_err = enforcer
            .authorize(
                BoundaryKind::Api,
                "submit",
                &repo_a,
                Capability::Propose,
                &oversize_req,
                2_100,
            )
            .unwrap_err();
        assert_eq!(quota_err.code, RefusalCode::QuotaPayloadTooLarge);

        // 8. Rate-limit exhaustion (2nd valid op succeeds, 3rd within 10s window is refused)
        let req2 = AuthenticatedRequest::sign_new(
            &proposer_key,
            grant.clone(),
            repo_a.clone(),
            Capability::Read,
            [5u8; 32],
            2_200,
            64,
            "read-tree",
        )
        .unwrap();
        enforcer
            .authorize(
                BoundaryKind::Api,
                "tree",
                &repo_a,
                Capability::Read,
                &req2,
                2_200,
            )
            .unwrap();

        let rate_err = enforcer
            .authorize(
                BoundaryKind::Api,
                "tree",
                &repo_a,
                Capability::Read,
                &req2,
                2_300,
            )
            .unwrap_err();
        assert_eq!(rate_err.code, RefusalCode::QuotaRateLimitExceeded);

        // 9. Verify the hash-chained security audit log is intact across all 9 checks
        assert_eq!(enforcer.audit_log().entries().len(), 9);
        assert!(enforcer.audit_log().verify_chain().is_ok());

        // 10. Tampering with any historical audit entry breaks the SHA-256 chain
        enforcer.audit_log_mut().entries_mut_for_testing()[2].operation =
            "tampered_operation".to_string();
        let audit_err = enforcer.audit_log().verify_chain().unwrap_err();
        assert_eq!(audit_err.code, RefusalCode::AuditChainCorrupt);
    }

    /// Ed25519 group order L, little-endian.
    const ED25519_L: [u8; 32] = [
        0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde,
        0x14, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10,
    ];

    /// Identity point encoding: a small-order public key. Under non-strict verify,
    /// signature (R = identity, S = 0) is accepted for every message.
    fn small_order_key_bytes() -> [u8; 32] {
        let mut b = [0u8; 32];
        b[0] = 1;
        b
    }

    fn weak_signature() -> Vec<u8> {
        let mut sig = vec![0u8; 64];
        sig[0] = 1;
        sig
    }

    fn repo() -> RepoId {
        RepoId::new("aien-spark/synapse").unwrap()
    }

    #[test]
    fn small_order_issuer_key_grant_is_refused() {
        let key = SigningKey::from_bytes(&[1u8; 32]);
        let mut grant = AgentCapabilityGrant::issue(
            &key,
            [0x10; 32],
            repo(),
            encode_did_key_ed25519(&[2u8; 32]),
            vec![Capability::Read],
            1024,
            2,
            10_000,
            1_000,
            5_000,
        );
        grant.issuer_did = encode_did_key_ed25519(&small_order_key_bytes());
        grant.signature = weak_signature();
        let err = grant.verify_authority_signature().unwrap_err();
        assert_eq!(err.code, RefusalCode::AuthGrantSignatureInvalid);
    }

    #[test]
    fn small_order_agent_key_request_is_refused() {
        let authority_key = SigningKey::from_bytes(&[1u8; 32]);
        let authority_did = encode_did_key_ed25519(&authority_key.verifying_key().to_bytes());
        let weak_did = encode_did_key_ed25519(&small_order_key_bytes());
        let mut enforcer = PolicyEnforcer::new();
        enforcer.register_repo_authority(repo(), authority_did);
        let grant = AgentCapabilityGrant::issue(
            &authority_key,
            [0x11; 32],
            repo(),
            weak_did,
            vec![Capability::Propose],
            1024,
            2,
            10_000,
            1_000,
            5_000,
        );
        let mut req = AuthenticatedRequest::sign_new(
            &SigningKey::from_bytes(&[2u8; 32]),
            grant,
            repo(),
            Capability::Propose,
            [4u8; 32],
            2_000,
            128,
            "weak-key",
        )
        .unwrap();
        req.agent_signature = weak_signature();
        let err = enforcer
            .authorize(
                BoundaryKind::Api,
                "submit",
                &repo(),
                Capability::Propose,
                &req,
                2_000,
            )
            .unwrap_err();
        assert_eq!(err.code, RefusalCode::AuthSignatureInvalid);
    }

    #[test]
    fn non_canonical_malleable_signatures_are_refused() {
        let key = SigningKey::from_bytes(&[1u8; 32]);
        let mut grant = AgentCapabilityGrant::issue(
            &key,
            [0x12; 32],
            repo(),
            encode_did_key_ed25519(&[2u8; 32]),
            vec![Capability::Read],
            1024,
            2,
            10_000,
            1_000,
            5_000,
        );
        grant
            .verify_authority_signature()
            .expect("valid grant passes");
        // Malleate: S' = S + L encodes the same scalar non-canonically.
        let mut carry = 0u16;
        for (i, l) in ED25519_L.iter().enumerate() {
            let v = grant.signature[32 + i] as u16 + *l as u16 + carry;
            grant.signature[32 + i] = v as u8;
            carry = v >> 8;
        }
        let err = grant.verify_authority_signature().unwrap_err();
        assert_eq!(err.code, RefusalCode::AuthGrantSignatureInvalid);
    }
}
