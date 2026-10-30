//! Shared fixture of the store's revision tests: real F1 capability links for byte-labelled
//! chains. A state move carries its chain's leaf link and the leaf audience's signature
//! (ADR 0003 B4, issue #89), so the chains here are digests of real signed links, not
//! arbitrary bytes. The link of label path `L` is issued by the key of `L` without its last
//! label (a fixture authority for a root link), names that parent link's digest, and
//! delegates to the key of `L`. Keys and nonces are SHA-256 of the labels, never fixed byte
//! values.

#![allow(dead_code)]

use ed25519_dalek::SigningKey;
use sha2::{Digest, Sha256};
use synapse_auth::{
    Capability, CapabilityChain, CapabilityLink, ChainQuotas, ChangeScope, LinkCaveats,
    OperationSet, PathScope, ReferenceScope, SignedStateMove, ROOT_PARENT,
};
use synapse_core::{ChainPath, ChangesetId, RepoId, RevisionState, SynapseResult, WalSeq};
use synapse_store::SynapseStore;

pub fn repo() -> RepoId {
    RepoId::new("aien-spark/synapse").unwrap()
}

/// SHA-256 of a purpose and a label path.
pub fn derived(what: &str, labels: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"synapse-store revision fixture\0");
    h.update(what.as_bytes());
    h.update([0]);
    h.update(labels);
    h.finalize().into()
}

/// The key presenting the chain with label path `labels`.
pub fn key_of(labels: &[u8]) -> SigningKey {
    SigningKey::from_bytes(&derived("key", labels))
}

fn caveats() -> LinkCaveats {
    LinkCaveats {
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
    }
}

/// The last link of the chain with label path `labels` (non-empty).
pub fn link_of(labels: &[u8]) -> CapabilityLink {
    let (issuer, parent) = match labels.split_last() {
        Some((_, [])) | None => (
            SigningKey::from_bytes(&derived("authority", &[])),
            ROOT_PARENT,
        ),
        Some((_, up)) => (key_of(up), link_of(up).digest()),
    };
    CapabilityLink::issue(
        &issuer,
        parent,
        derived("nonce", labels),
        repo(),
        key_of(labels).verifying_key().to_bytes(),
        caveats(),
    )
}

/// The chain with label path `labels`, root first.
pub fn chain_of(labels: &[u8]) -> CapabilityChain {
    CapabilityChain::new((1..=labels.len()).map(|n| link_of(&labels[..n])).collect())
}

/// Link digests of the chain with label path `labels`: prefixes of a label path are its
/// ancestors, so dominance follows the labels.
pub fn path(labels: &[u8]) -> ChainPath {
    ChainPath::new(
        chain_of(labels)
            .link_digests()
            .iter()
            .map(|d| d.0)
            .collect(),
    )
    .unwrap()
}

/// A move of `id` to `to` signed by the leaf of the chain with label path `labels`.
pub fn signed(labels: &[u8], id: ChangesetId, to: RevisionState, at: u64) -> SignedStateMove {
    SignedStateMove::sign_new(&key_of(labels), repo(), id, to, &chain_of(labels), at).unwrap()
}

/// Record a signed move by the chain with label path `labels` at server time `at`.
pub fn mv(
    s: &mut SynapseStore,
    labels: &[u8],
    id: ChangesetId,
    to: RevisionState,
    at: u64,
) -> SynapseResult<WalSeq> {
    s.advance_revision_state(signed(labels, id, to, at), at)
}
