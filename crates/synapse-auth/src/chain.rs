//! Attenuated capability chains (ADR 0003 section 5.8, section 9 step F1).
//!
//! The repository authority issues a root link; any holder can sign a narrower link to another
//! key. Every link signs its parent's digest, the `repo_id`, its audience key, and its caveats
//! (operations, path prefixes, reference kinds, change scope, partitioned quotas, validity
//! window) under a domain-separated Ed25519 signature. Granting a link and revoking it are
//! operations at a `WalSeq`; the server accepts a chain only if every link was granted at or
//! before the request's `WalSeq`, is unrevoked at it, is unexpired, and narrows its parent.
//!
//! Every signed and persisted form here is the fixed-width, little-endian, length-prefixed binary
//! encoding of `docs/F1_CAPABILITY_CHAINS.md` (ADR 0003 principle P5); there is no serde form.

use crate::{AuditOutcome, BoundaryKind, Capability, PolicyEnforcer};
use ed25519_dalek::{Signature, Signer, SigningKey};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use synapse_core::{
    encode_did_key_ed25519, validate_repo_relative_path, ChangeId, RefusalCode, RepoId,
    SynapseError, SynapseResult, WalSeq,
};

/// Capability link format version.
pub const CAPABILITY_LINK_VERSION: u16 = 1;
/// Capability chain format version.
pub const CAPABILITY_CHAIN_VERSION: u16 = 1;
/// Domain tag for the Ed25519 signature over a link body.
pub const DOMAIN_CAPABILITY_LINK_SIGN_V1: &[u8] = b"SYNAPSE_CAPABILITY_LINK_SIGN_V1\0";
/// Domain tag for a link digest (the identity a child link signs as its parent).
pub const DOMAIN_CAPABILITY_LINK_ID_V1: &[u8] = b"SYNAPSE_CAPABILITY_LINK_ID_V1\0";
/// Domain tag for the presenting agent's Ed25519 signature over a chained request.
pub const DOMAIN_CHAIN_REQUEST_V1: &[u8] = b"SYNAPSE_CHAIN_REQUEST_V1\0";
/// Domain tag for the digest of a chained request's payload bytes.
pub const DOMAIN_CHAIN_PAYLOAD_V1: &[u8] = b"SYNAPSE_CHAIN_PAYLOAD_V1\0";
/// Most links in one chain (root included).
pub const MAX_CHAIN_DEPTH: usize = 16;
/// Most path prefixes in one link's path scope.
pub const MAX_PATH_PREFIXES: usize = 256;
/// Most `ChangeId`s in one link's change scope.
pub const MAX_CHANGE_IDS: usize = 1024;
/// Longest path prefix (the `validate_repo_relative_path` bound).
pub const MAX_PATH_BYTES: usize = 2048;
/// Longest repository id (the `RepoId::new` bound).
pub const MAX_REPO_ID_BYTES: usize = 128;
/// Parent digest of a root link.
pub const ROOT_PARENT: LinkDigest = LinkDigest([0u8; 32]);

const KNOWN_OPERATION_BITS: u8 = 0b0011_1111;
const KNOWN_REFERENCE_BITS: u8 = 0b0000_0011;

fn malformed(msg: impl Into<String>) -> SynapseError {
    SynapseError::new(RefusalCode::AuthChainMalformed, msg)
}

/// Domain-separated SHA-256 identity of one encoded capability link.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct LinkDigest(pub [u8; 32]);

/// Set of operations a link allows, one bit per `Capability` (bit `tag_byte - 1`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct OperationSet(u8);

impl OperationSet {
    pub fn from_capabilities(caps: &[Capability]) -> Self {
        Self(
            caps.iter()
                .fold(0u8, |acc, c| acc | (1u8 << (c.tag_byte() - 1))),
        )
    }

    pub fn from_bits(bits: u8) -> SynapseResult<Self> {
        if bits & !KNOWN_OPERATION_BITS != 0 {
            return Err(malformed(format!("unknown operation bits {bits:#04x}")));
        }
        Ok(Self(bits))
    }

    pub fn bits(self) -> u8 {
        self.0
    }

    pub fn contains(self, cap: Capability) -> bool {
        self.0 & (1u8 << (cap.tag_byte() - 1)) != 0
    }

    pub fn is_subset_of(self, parent: Self) -> bool {
        self.0 & !parent.0 == 0
    }
}

/// Kind of reference a request touches (ADR 0003 section 5.8: own drafts only; canonical only
/// through the promotion queue).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ReferenceKind {
    /// References owned by the holder's chain (drafts, workspaces).
    OwnDrafts,
    /// The canonical reference, moved only by the promotion queue (step E2).
    CanonicalViaPromotionQueue,
}

impl ReferenceKind {
    pub fn tag_byte(self) -> u8 {
        match self {
            Self::OwnDrafts => 1,
            Self::CanonicalViaPromotionQueue => 2,
        }
    }
}

/// Set of reference kinds a link allows, one bit per `ReferenceKind` (bit `tag_byte - 1`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ReferenceScope(u8);

impl ReferenceScope {
    pub fn from_kinds(kinds: &[ReferenceKind]) -> Self {
        Self(
            kinds
                .iter()
                .fold(0u8, |acc, k| acc | (1u8 << (k.tag_byte() - 1))),
        )
    }

    pub fn from_bits(bits: u8) -> SynapseResult<Self> {
        if bits & !KNOWN_REFERENCE_BITS != 0 {
            return Err(malformed(format!("unknown reference bits {bits:#04x}")));
        }
        Ok(Self(bits))
    }

    pub fn bits(self) -> u8 {
        self.0
    }

    pub fn contains(self, kind: ReferenceKind) -> bool {
        self.0 & (1u8 << (kind.tag_byte() - 1)) != 0
    }

    pub fn is_subset_of(self, parent: Self) -> bool {
        self.0 & !parent.0 == 0
    }
}

/// Path prefixes a link allows, in canonical form: strictly ascending bytes, no prefix covered
/// by another, and the empty prefix (the whole repository) only on its own. A prefix covers a
/// path when it is empty, equal to the path, or followed in the path by `/` (segment boundary).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PathScope {
    prefixes: Vec<String>,
}

fn prefix_covers(prefix: &str, path: &str) -> bool {
    prefix.is_empty()
        || path == prefix
        || (path.len() > prefix.len()
            && path.starts_with(prefix)
            && path.as_bytes()[prefix.len()] == b'/')
}

impl PathScope {
    /// The whole repository (the single empty prefix).
    pub fn whole_repository() -> Self {
        Self {
            prefixes: vec![String::new()],
        }
    }

    /// Build a canonical scope from any prefixes: each must be empty or a valid
    /// repository-relative path; the result is sorted with covered prefixes removed.
    pub fn new(prefixes: Vec<String>) -> SynapseResult<Self> {
        if prefixes.len() > MAX_PATH_PREFIXES {
            return Err(SynapseError::new(
                RefusalCode::PathInvalid,
                format!("path scope has more than {MAX_PATH_PREFIXES} prefixes"),
            ));
        }
        for p in &prefixes {
            if !p.is_empty() {
                validate_repo_relative_path(p)?;
            }
        }
        if prefixes.iter().any(String::is_empty) {
            return Ok(Self::whole_repository());
        }
        let mut sorted = prefixes;
        sorted.sort();
        sorted.dedup();
        let mut kept: Vec<String> = Vec::with_capacity(sorted.len());
        for p in sorted {
            if !kept.iter().any(|k| prefix_covers(k, &p)) {
                kept.retain(|k| !prefix_covers(&p, k));
                kept.push(p);
            }
        }
        kept.sort();
        Ok(Self { prefixes: kept })
    }

    pub fn prefixes(&self) -> &[String] {
        &self.prefixes
    }

    pub fn covers_path(&self, path: &str) -> bool {
        self.prefixes.iter().any(|p| prefix_covers(p, path))
    }

    /// True when every path this scope covers is covered by `parent`.
    pub fn is_within(&self, parent: &PathScope) -> bool {
        self.prefixes.iter().all(|c| parent.covers_path(c))
    }

    fn is_canonical(prefixes: &[String]) -> bool {
        if prefixes.iter().any(String::is_empty) {
            return prefixes.len() == 1;
        }
        prefixes.windows(2).all(|w| w[0] < w[1])
            && prefixes.iter().enumerate().all(|(i, p)| {
                prefixes
                    .iter()
                    .enumerate()
                    .all(|(j, q)| i == j || !prefix_covers(q, p))
            })
    }
}

/// `ChangeId`s a link's holder may join (ADR 0003 sections 5.1 and 5.8): any, or exactly the
/// listed ones (strictly ascending; an empty list allows none).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ChangeScope {
    only: Option<Vec<ChangeId>>,
}

impl ChangeScope {
    pub fn any() -> Self {
        Self { only: None }
    }

    pub fn only(mut ids: Vec<ChangeId>) -> SynapseResult<Self> {
        ids.sort();
        ids.dedup();
        if ids.len() > MAX_CHANGE_IDS {
            return Err(malformed(format!(
                "change scope has more than {MAX_CHANGE_IDS} ids"
            )));
        }
        Ok(Self { only: Some(ids) })
    }

    /// `None` for any `ChangeId`, else the allowed ids.
    pub fn ids(&self) -> Option<&[ChangeId]> {
        self.only.as_deref()
    }

    pub fn contains(&self, id: ChangeId) -> bool {
        match &self.only {
            None => true,
            Some(ids) => ids.binary_search(&id).is_ok(),
        }
    }

    pub fn is_within(&self, parent: &ChangeScope) -> bool {
        match (&self.only, &parent.only) {
            (_, None) => true,
            (None, Some(_)) => false,
            (Some(child), Some(_)) => child.iter().all(|id| parent.contains(*id)),
        }
    }
}

/// Quotas of one link. Request rate, storage, and footprint are partitioned: the children of
/// one link together never exceed it, and the link itself keeps only what it has not handed
/// down. `window_duration_ms` is inherited unchanged; `max_bytes_per_op` is a per-request cap
/// that may only narrow (it is not a pool and is not partitioned).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ChainQuotas {
    pub max_ops_per_window: u32,
    pub window_duration_ms: u64,
    pub storage_bytes: u64,
    /// Footprint breadth: declared prefixes weighted by the tracked paths beneath them (step F2).
    pub footprint_paths: u64,
    pub max_bytes_per_op: u64,
}

/// Caveats of one link: what its holder may do.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct LinkCaveats {
    pub operations: OperationSet,
    pub paths: PathScope,
    pub references: ReferenceScope,
    pub changes: ChangeScope,
    pub quotas: ChainQuotas,
    pub issued_at_ms: u64,
    pub expires_at_ms: u64,
}

impl LinkCaveats {
    /// The first dimension in which `self` is wider than `parent`, or `None` if it narrows.
    pub fn escalation_against(&self, parent: &LinkCaveats) -> Option<&'static str> {
        if !self.operations.is_subset_of(parent.operations) {
            return Some("operations");
        }
        if !self.paths.is_within(&parent.paths) {
            return Some("paths");
        }
        if !self.references.is_subset_of(parent.references) {
            return Some("references");
        }
        if !self.changes.is_within(&parent.changes) {
            return Some("change scope");
        }
        let (c, p) = (&self.quotas, &parent.quotas);
        if c.window_duration_ms != p.window_duration_ms
            || c.max_ops_per_window > p.max_ops_per_window
            || c.storage_bytes > p.storage_bytes
            || c.footprint_paths > p.footprint_paths
            || c.max_bytes_per_op > p.max_bytes_per_op
        {
            return Some("quotas");
        }
        if self.issued_at_ms < parent.issued_at_ms || self.expires_at_ms > parent.expires_at_ms {
            return Some("expiry");
        }
        None
    }
}

/// One signed link of a capability chain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapabilityLink {
    pub version: u16,
    pub nonce: [u8; 32],
    pub parent: LinkDigest,
    pub repo_id: RepoId,
    pub issuer_key: [u8; 32],
    pub audience_key: [u8; 32],
    pub caveats: LinkCaveats,
    pub signature: [u8; 64],
}

impl CapabilityLink {
    /// Sign a link with `signer`. A root link has `parent == ROOT_PARENT` and is signed by a
    /// repository authority; a derived link names its parent's digest and is signed by the
    /// parent's audience. Narrowing is checked by the server, not here.
    pub fn issue(
        signer: &SigningKey,
        parent: LinkDigest,
        nonce: [u8; 32],
        repo_id: RepoId,
        audience_key: [u8; 32],
        caveats: LinkCaveats,
    ) -> Self {
        let mut link = Self {
            version: CAPABILITY_LINK_VERSION,
            nonce,
            parent,
            repo_id,
            issuer_key: signer.verifying_key().to_bytes(),
            audience_key,
            caveats,
            signature: [0u8; 64],
        };
        link.signature = signer.sign(&link.signable_bytes()).to_bytes();
        link
    }

    pub fn issuer_did(&self) -> String {
        encode_did_key_ed25519(&self.issuer_key)
    }

    pub fn audience_did(&self) -> String {
        encode_did_key_ed25519(&self.audience_key)
    }

    fn encode_body(&self, buf: &mut Vec<u8>) {
        let c = &self.caveats;
        buf.extend_from_slice(&self.version.to_le_bytes());
        buf.extend_from_slice(&self.nonce);
        buf.extend_from_slice(&self.parent.0);
        put_str(buf, self.repo_id.as_str());
        buf.extend_from_slice(&self.issuer_key);
        buf.extend_from_slice(&self.audience_key);
        buf.push(c.operations.bits());
        buf.push(c.references.bits());
        buf.extend_from_slice(&(c.paths.prefixes.len() as u32).to_le_bytes());
        for p in &c.paths.prefixes {
            put_str(buf, p);
        }
        match &c.changes.only {
            None => buf.push(0),
            Some(ids) => {
                buf.push(1);
                buf.extend_from_slice(&(ids.len() as u32).to_le_bytes());
                for id in ids {
                    buf.extend_from_slice(&id.0);
                }
            }
        }
        let q = &c.quotas;
        buf.extend_from_slice(&q.max_ops_per_window.to_le_bytes());
        buf.extend_from_slice(&q.window_duration_ms.to_le_bytes());
        buf.extend_from_slice(&q.storage_bytes.to_le_bytes());
        buf.extend_from_slice(&q.footprint_paths.to_le_bytes());
        buf.extend_from_slice(&q.max_bytes_per_op.to_le_bytes());
        buf.extend_from_slice(&c.issued_at_ms.to_le_bytes());
        buf.extend_from_slice(&c.expires_at_ms.to_le_bytes());
    }

    /// `DOMAIN_CAPABILITY_LINK_SIGN_V1 || body`: what the issuer signs.
    pub fn signable_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(512);
        buf.extend_from_slice(DOMAIN_CAPABILITY_LINK_SIGN_V1);
        self.encode_body(&mut buf);
        buf
    }

    /// Canonical binary encoding: `body || signature`.
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(512);
        self.encode_body(&mut buf);
        buf.extend_from_slice(&self.signature);
        buf
    }

    /// `SHA-256(DOMAIN_CAPABILITY_LINK_ID_V1 || encode())`.
    pub fn digest(&self) -> LinkDigest {
        let mut h = Sha256::new();
        h.update(DOMAIN_CAPABILITY_LINK_ID_V1);
        h.update(self.encode());
        LinkDigest(h.finalize().into())
    }

    /// Decode exactly one canonical link; anything else is `AuthChainMalformed`.
    pub fn decode(bytes: &[u8]) -> SynapseResult<Self> {
        let mut r = Reader::new(bytes);
        let link = Self::decode_from(&mut r)?;
        r.finish()?;
        Ok(link)
    }

    fn decode_from(r: &mut Reader<'_>) -> SynapseResult<Self> {
        let version = r.u16()?;
        if version != CAPABILITY_LINK_VERSION {
            return Err(malformed(format!(
                "unsupported capability link version {version}"
            )));
        }
        let nonce = r.arr32()?;
        let parent = LinkDigest(r.arr32()?);
        let repo_raw = r.string(MAX_REPO_ID_BYTES)?;
        let repo_id = RepoId::new(repo_raw).map_err(|e| malformed(e.message))?;
        let issuer_key = r.arr32()?;
        let audience_key = r.arr32()?;
        let operations = OperationSet::from_bits(r.u8()?)?;
        let references = ReferenceScope::from_bits(r.u8()?)?;
        let path_count = r.count(MAX_PATH_PREFIXES, 4)?;
        let mut prefixes = Vec::with_capacity(path_count);
        for _ in 0..path_count {
            let p = r.string(MAX_PATH_BYTES)?;
            if !p.is_empty() {
                validate_repo_relative_path(&p).map_err(|e| malformed(e.message))?;
            }
            prefixes.push(p);
        }
        if !PathScope::is_canonical(&prefixes) {
            return Err(malformed("path scope is not in canonical form"));
        }
        let changes = match r.u8()? {
            0 => ChangeScope::any(),
            1 => {
                let n = r.count(MAX_CHANGE_IDS, 16)?;
                let mut ids = Vec::with_capacity(n);
                for _ in 0..n {
                    let mut id = [0u8; 16];
                    id.copy_from_slice(r.take(16)?);
                    ids.push(ChangeId(id));
                }
                if !ids.windows(2).all(|w| w[0] < w[1]) {
                    return Err(malformed("change scope ids are not strictly ascending"));
                }
                ChangeScope { only: Some(ids) }
            }
            other => return Err(malformed(format!("unknown change scope tag {other}"))),
        };
        let quotas = ChainQuotas {
            max_ops_per_window: r.u32()?,
            window_duration_ms: r.u64()?,
            storage_bytes: r.u64()?,
            footprint_paths: r.u64()?,
            max_bytes_per_op: r.u64()?,
        };
        let issued_at_ms = r.u64()?;
        let expires_at_ms = r.u64()?;
        let mut signature = [0u8; 64];
        signature.copy_from_slice(r.take(64)?);
        Ok(Self {
            version,
            nonce,
            parent,
            repo_id,
            issuer_key,
            audience_key,
            caveats: LinkCaveats {
                operations,
                paths: PathScope { prefixes },
                references,
                changes,
                quotas,
                issued_at_ms,
                expires_at_ms,
            },
            signature,
        })
    }

    /// Verify the issuer's Ed25519 signature over `signable_bytes()`.
    pub fn verify_signature(&self) -> SynapseResult<()> {
        let invalid = |msg: &str| SynapseError::new(RefusalCode::AuthGrantSignatureInvalid, msg);
        let key = crate::key_cache::verifying_key(&self.issuer_key)
            .map_err(|_| invalid("link issuer key is not a valid Ed25519 key"))?;
        key.verify_strict(
            &self.signable_bytes(),
            &Signature::from_bytes(&self.signature),
        )
        .map_err(|_| invalid("link signature verification failed"))
    }
}

/// A capability chain, root first.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapabilityChain {
    pub links: Vec<CapabilityLink>,
}

impl CapabilityChain {
    pub fn new(links: Vec<CapabilityLink>) -> Self {
        Self { links }
    }

    /// The chain with `link` appended (the parent chain plus a newly issued child).
    pub fn extended(&self, link: CapabilityLink) -> Self {
        let mut links = self.links.clone();
        links.push(link);
        Self { links }
    }

    pub fn leaf(&self) -> Option<&CapabilityLink> {
        self.links.last()
    }

    pub fn link_digests(&self) -> Vec<LinkDigest> {
        self.links.iter().map(CapabilityLink::digest).collect()
    }

    /// `version u16 | count u8 | (len u32 | link)*`.
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(512 * self.links.len() + 3);
        buf.extend_from_slice(&CAPABILITY_CHAIN_VERSION.to_le_bytes());
        buf.push(self.links.len() as u8);
        for link in &self.links {
            let bytes = link.encode();
            buf.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
            buf.extend_from_slice(&bytes);
        }
        buf
    }

    /// Decode exactly one canonical chain of 1..=`MAX_CHAIN_DEPTH` links.
    pub fn decode(bytes: &[u8]) -> SynapseResult<Self> {
        let mut r = Reader::new(bytes);
        let version = r.u16()?;
        if version != CAPABILITY_CHAIN_VERSION {
            return Err(malformed(format!(
                "unsupported capability chain version {version}"
            )));
        }
        let count = r.u8()? as usize;
        if count == 0 || count > MAX_CHAIN_DEPTH {
            return Err(malformed(format!(
                "chain length {count} outside 1..={MAX_CHAIN_DEPTH}"
            )));
        }
        let mut links = Vec::with_capacity(count);
        for _ in 0..count {
            let len = r.u32()? as usize;
            let mut inner = Reader::new(r.take(len)?);
            links.push(CapabilityLink::decode_from(&mut inner)?);
            inner.finish()?;
        }
        r.finish()?;
        Ok(Self { links })
    }
}

/// What a chained request touches, checked against the leaf link's scopes.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RequestScope {
    /// Repository-relative paths the request reads or writes.
    pub paths: Vec<String>,
    /// Reference kind the request reads or moves, if any.
    pub reference: Option<ReferenceKind>,
    /// `ChangeId` the request joins through change scope, if any (when change scope is needed
    /// is decided by step B1).
    pub join_change: Option<ChangeId>,
}

impl RequestScope {
    fn encode_into(&self, buf: &mut Vec<u8>) {
        buf.extend_from_slice(&(self.paths.len() as u32).to_le_bytes());
        for p in &self.paths {
            put_str(buf, p);
        }
        buf.push(self.reference.map_or(0, ReferenceKind::tag_byte));
        match self.join_change {
            None => buf.push(0),
            Some(id) => {
                buf.push(1);
                buf.extend_from_slice(&id.0);
            }
        }
    }
}

/// A request presented with a capability chain and signed by the leaf link's audience.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChainedRequest {
    pub chain: CapabilityChain,
    pub target_repo_id: RepoId,
    pub agent_key: [u8; 32],
    pub required_capability: Capability,
    pub scope: RequestScope,
    pub request_nonce: [u8; 32],
    pub timestamp_ms: u64,
    pub payload: Vec<u8>,
    pub agent_signature: [u8; 64],
}

impl ChainedRequest {
    #[allow(clippy::too_many_arguments)]
    pub fn sign_new(
        agent_key: &SigningKey,
        chain: CapabilityChain,
        target_repo_id: RepoId,
        required_capability: Capability,
        scope: RequestScope,
        request_nonce: [u8; 32],
        timestamp_ms: u64,
        payload: Vec<u8>,
    ) -> Self {
        let mut req = Self {
            chain,
            target_repo_id,
            agent_key: agent_key.verifying_key().to_bytes(),
            required_capability,
            scope,
            request_nonce,
            timestamp_ms,
            payload,
            agent_signature: [0u8; 64],
        };
        req.agent_signature = agent_key.sign(&req.canonical_signable_bytes()).to_bytes();
        req
    }

    pub fn agent_did(&self) -> String {
        encode_did_key_ed25519(&self.agent_key)
    }

    /// `SHA-256(DOMAIN_CHAIN_PAYLOAD_V1 || payload)`.
    pub fn payload_sha256(&self) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(DOMAIN_CHAIN_PAYLOAD_V1);
        h.update(&self.payload);
        h.finalize().into()
    }

    /// `DOMAIN_CHAIN_REQUEST_V1 || leaf digest || repo || agent key || capability || scope ||
    /// nonce || timestamp || payload length || payload digest`.
    pub fn canonical_signable_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(256);
        buf.extend_from_slice(DOMAIN_CHAIN_REQUEST_V1);
        let leaf = self
            .chain
            .leaf()
            .map_or(ROOT_PARENT, CapabilityLink::digest);
        buf.extend_from_slice(&leaf.0);
        put_str(&mut buf, self.target_repo_id.as_str());
        buf.extend_from_slice(&self.agent_key);
        buf.push(self.required_capability.tag_byte());
        self.scope.encode_into(&mut buf);
        buf.extend_from_slice(&self.request_nonce);
        buf.extend_from_slice(&self.timestamp_ms.to_le_bytes());
        buf.extend_from_slice(&(self.payload.len() as u64).to_le_bytes());
        buf.extend_from_slice(&self.payload_sha256());
        buf
    }
}

#[derive(Debug, Clone)]
struct GrantedLink {
    granted_at: WalSeq,
    revoked_at: Option<WalSeq>,
    quotas: ChainQuotas,
}

/// Sums of the partitioned quotas handed down to a link's granted children.
#[derive(Debug, Clone, Copy, Default)]
struct Allocated {
    ops: u64,
    storage: u64,
    footprint: u64,
}

/// Server-side record of granted and revoked links, quota partitions, and per-link rate windows.
#[derive(Debug, Default)]
pub(crate) struct ChainRegistry {
    granted: BTreeMap<LinkDigest, GrantedLink>,
    allocated: BTreeMap<LinkDigest, Allocated>,
    rate_windows: BTreeMap<LinkDigest, Vec<u64>>,
}

impl PolicyEnforcer {
    /// Stateless checks plus trusted root: linkage, repository, signatures, audience, narrowing,
    /// and validity window of every link. Returns the link digests, root first.
    fn verify_chain_links(
        &self,
        chain: &CapabilityChain,
        expected_repo_id: &RepoId,
        now_ms: u64,
    ) -> SynapseResult<Vec<LinkDigest>> {
        let n = chain.links.len();
        if n == 0 || n > MAX_CHAIN_DEPTH {
            return Err(SynapseError::new(
                RefusalCode::AuthChainBroken,
                format!("chain length {n} outside 1..={MAX_CHAIN_DEPTH}"),
            ));
        }
        let mut digests: Vec<LinkDigest> = Vec::with_capacity(n);
        for (i, link) in chain.links.iter().enumerate() {
            if link.version != CAPABILITY_LINK_VERSION {
                return Err(malformed(format!(
                    "link {i}: unsupported version {}",
                    link.version
                )));
            }
            if &link.repo_id != expected_repo_id {
                return Err(SynapseError::new(
                    RefusalCode::AuthCrossRepoDenied,
                    format!(
                        "link {i} is bound to repository {} not {expected_repo_id}",
                        link.repo_id
                    ),
                ));
            }
            link.verify_signature()
                .map_err(|e| SynapseError::new(e.code, format!("link {i}: {}", e.message)))?;
            if i == 0 {
                if link.parent != ROOT_PARENT {
                    return Err(SynapseError::new(
                        RefusalCode::AuthChainBroken,
                        "first link is not a root link",
                    ));
                }
                let trusted = self
                    .trusted_authorities
                    .get(expected_repo_id)
                    .is_some_and(|set| set.contains(&link.issuer_did()));
                if !trusted {
                    return Err(SynapseError::new(
                        RefusalCode::AuthGrantSignatureInvalid,
                        format!(
                            "root issuer {} is not a trusted authority for {expected_repo_id}",
                            link.issuer_did()
                        ),
                    ));
                }
            } else {
                let parent = &chain.links[i - 1];
                if link.parent != digests[i - 1] {
                    return Err(SynapseError::new(
                        RefusalCode::AuthChainBroken,
                        format!("link {i} does not name link {} as its parent", i - 1),
                    ));
                }
                if link.issuer_key != parent.audience_key {
                    return Err(SynapseError::new(
                        RefusalCode::AuthAudienceMismatch,
                        format!(
                            "link {i} issuer {} is not the audience {} of its parent",
                            link.issuer_did(),
                            parent.audience_did()
                        ),
                    ));
                }
                if let Some(dim) = link.caveats.escalation_against(&parent.caveats) {
                    return Err(SynapseError::new(
                        RefusalCode::AuthScopeEscalation,
                        format!("link {i} is wider than its parent in {dim}"),
                    ));
                }
            }
            if now_ms < link.caveats.issued_at_ms || now_ms > link.caveats.expires_at_ms {
                return Err(SynapseError::new(
                    RefusalCode::AuthGrantExpired,
                    format!(
                        "link {i} expired or not yet valid (now={now_ms}, window={}..={})",
                        link.caveats.issued_at_ms, link.caveats.expires_at_ms
                    ),
                ));
            }
            digests.push(link.digest());
        }
        Ok(digests)
    }

    /// Every listed link must be granted at or before `seq` and not revoked at `seq`.
    fn check_granted_at(&self, digests: &[LinkDigest], seq: WalSeq) -> SynapseResult<()> {
        for (i, d) in digests.iter().enumerate() {
            let Some(rec) = self.chains.granted.get(d) else {
                return Err(SynapseError::new(
                    RefusalCode::AuthChainBroken,
                    format!("link {i} was never granted"),
                ));
            };
            if rec.revoked_at.is_some_and(|r| r <= seq) {
                return Err(SynapseError::new(
                    RefusalCode::AuthGrantRevoked,
                    format!("link {i} is revoked at {seq}"),
                ));
            }
            if rec.granted_at > seq {
                return Err(SynapseError::new(
                    RefusalCode::AuthChainBroken,
                    format!(
                        "link {i} is granted only at {}, after {seq}",
                        rec.granted_at
                    ),
                ));
            }
        }
        Ok(())
    }

    /// Grant the leaf link of `chain` at `seq` (granting is an operation in the log). Every
    /// earlier link must already be granted and unrevoked at `seq`; the leaf must narrow its
    /// parent and fit in what the parent has not yet handed to other children. Granting a link
    /// that is already granted returns its digest without charging its quotas again.
    pub fn grant_link(
        &mut self,
        chain: &CapabilityChain,
        seq: WalSeq,
        now_ms: u64,
    ) -> SynapseResult<LinkDigest> {
        let leaf = chain.leaf().ok_or_else(|| {
            SynapseError::new(RefusalCode::AuthChainBroken, "empty capability chain")
        })?;
        let repo_id = leaf.repo_id.clone();
        let digests = self.verify_chain_links(chain, &repo_id, now_ms)?;
        let (leaf_digest, ancestors) = digests.split_last().expect("non-empty chain");
        self.check_granted_at(ancestors, seq)?;
        if let Some(rec) = self.chains.granted.get(leaf_digest) {
            if rec.revoked_at.is_some() {
                return Err(SynapseError::new(
                    RefusalCode::AuthGrantRevoked,
                    "link is revoked; a revoked link cannot be granted again",
                ));
            }
            return Ok(*leaf_digest);
        }
        let quotas = leaf.caveats.quotas;
        if let Some(parent_digest) = ancestors.last() {
            let parent_quotas = self.chains.granted[parent_digest].quotas;
            let used = self
                .chains
                .allocated
                .get(parent_digest)
                .copied()
                .unwrap_or_default();
            let next_ops = used.ops.checked_add(u64::from(quotas.max_ops_per_window));
            let next_storage = used.storage.checked_add(quotas.storage_bytes);
            let next_footprint = used.footprint.checked_add(quotas.footprint_paths);
            let over = if next_ops.is_none_or(|v| v > u64::from(parent_quotas.max_ops_per_window)) {
                Some("request rate")
            } else if next_storage.is_none_or(|v| v > parent_quotas.storage_bytes) {
                Some("storage")
            } else if next_footprint.is_none_or(|v| v > parent_quotas.footprint_paths) {
                Some("footprint")
            } else {
                None
            };
            if let Some(dim) = over {
                return Err(SynapseError::new(
                    RefusalCode::QuotaPartitionExceeded,
                    format!("children of the parent link would together exceed its {dim} quota"),
                ));
            }
            self.chains.allocated.insert(
                *parent_digest,
                Allocated {
                    ops: next_ops.expect("checked above"),
                    storage: next_storage.expect("checked above"),
                    footprint: next_footprint.expect("checked above"),
                },
            );
        }
        self.chains.granted.insert(
            *leaf_digest,
            GrantedLink {
                granted_at: seq,
                revoked_at: None,
                quotas,
            },
        );
        Ok(*leaf_digest)
    }

    /// Revoke a granted link at `seq`. Revocation cannot be undone: a later revocation never
    /// moves an earlier one, and there is no operation that clears it. Every chain through the
    /// link is refused for requests at `seq` or later.
    pub fn revoke_link(&mut self, link: LinkDigest, seq: WalSeq) -> SynapseResult<()> {
        let rec = self.chains.granted.get_mut(&link).ok_or_else(|| {
            SynapseError::new(
                RefusalCode::AuthChainBroken,
                "cannot revoke a link never granted",
            )
        })?;
        rec.revoked_at = Some(rec.revoked_at.map_or(seq, |r| r.min(seq)));
        Ok(())
    }

    /// The part of a granted link's partitioned quotas (rate, storage, footprint) not handed
    /// down to its children; `None` if the link was never granted.
    pub fn unallocated_quota(&self, link: &LinkDigest) -> Option<ChainQuotas> {
        let rec = self.chains.granted.get(link)?;
        let used = self.chains.allocated.get(link).copied().unwrap_or_default();
        let mut q = rec.quotas;
        q.max_ops_per_window = q
            .max_ops_per_window
            .saturating_sub(u32::try_from(used.ops).unwrap_or(u32::MAX));
        q.storage_bytes = q.storage_bytes.saturating_sub(used.storage);
        q.footprint_paths = q.footprint_paths.saturating_sub(used.footprint);
        Some(q)
    }

    /// Verify and authorize a `ChainedRequest` whose `WalSeq` is `request_seq`, recording
    /// `Admitted` or `Refused` in the hash-chained audit log.
    #[allow(clippy::too_many_arguments)]
    pub fn authorize_chain(
        &mut self,
        boundary: BoundaryKind,
        operation: &str,
        expected_repo_id: &RepoId,
        expected_capability: Capability,
        req: &ChainedRequest,
        request_seq: WalSeq,
        now_ms: u64,
    ) -> SynapseResult<()> {
        let result = self.check_chained_request(
            expected_repo_id,
            expected_capability,
            req,
            request_seq,
            now_ms,
        );
        let outcome = match &result {
            Ok(()) => AuditOutcome::Admitted,
            Err(err) => AuditOutcome::Refused {
                code: err.code,
                reason: err.message.clone(),
            },
        };
        self.audit_log.record(
            now_ms,
            boundary,
            expected_repo_id.clone(),
            req.agent_did(),
            expected_capability,
            operation,
            outcome,
        );
        result
    }

    fn check_chained_request(
        &mut self,
        expected_repo_id: &RepoId,
        expected_capability: Capability,
        req: &ChainedRequest,
        request_seq: WalSeq,
        now_ms: u64,
    ) -> SynapseResult<()> {
        if &req.target_repo_id != expected_repo_id {
            return Err(SynapseError::new(
                RefusalCode::AuthCrossRepoDenied,
                format!(
                    "request targets {} not {expected_repo_id}",
                    req.target_repo_id
                ),
            ));
        }
        let digests = self.verify_chain_links(&req.chain, expected_repo_id, now_ms)?;
        self.check_granted_at(&digests, request_seq)?;
        let leaf = req.chain.leaf().expect("verified non-empty chain");
        let leaf_digest = *digests.last().expect("verified non-empty chain");

        if req.agent_key != leaf.audience_key {
            return Err(SynapseError::new(
                RefusalCode::AuthAudienceMismatch,
                format!(
                    "request presented by {} but the leaf link's audience is {}",
                    req.agent_did(),
                    leaf.audience_did()
                ),
            ));
        }
        let agent_key = crate::key_cache::verifying_key(&req.agent_key).map_err(|_| {
            SynapseError::new(RefusalCode::DidKeyInvalid, "invalid agent Ed25519 key")
        })?;
        agent_key
            .verify_strict(
                &req.canonical_signable_bytes(),
                &Signature::from_bytes(&req.agent_signature),
            )
            .map_err(|_| {
                SynapseError::new(
                    RefusalCode::AuthSignatureInvalid,
                    "agent Ed25519 chained request signature verification failed",
                )
            })?;

        let caveats = &leaf.caveats;
        if req.required_capability != expected_capability
            || !caveats.operations.contains(expected_capability)
        {
            return Err(SynapseError::new(
                RefusalCode::AuthCapabilityDenied,
                format!(
                    "chain of {} lacks required capability {expected_capability:?}",
                    req.agent_did()
                ),
            ));
        }
        for path in &req.scope.paths {
            validate_repo_relative_path(path)?;
            if !caveats.paths.covers_path(path) {
                return Err(SynapseError::new(
                    RefusalCode::AuthPathOutOfScope,
                    format!("path {path} is outside the chain's path scope"),
                ));
            }
        }
        if let Some(kind) = req.scope.reference {
            if !caveats.references.contains(kind) {
                return Err(SynapseError::new(
                    RefusalCode::AuthReferenceOutOfScope,
                    format!("reference kind {kind:?} is outside the chain's reference scope"),
                ));
            }
        }
        if let Some(id) = req.scope.join_change {
            if !caveats.changes.contains(id) {
                return Err(SynapseError::new(
                    RefusalCode::AuthChangeOutOfScope,
                    format!("{id:?} is outside the chain's change scope"),
                ));
            }
        }
        let payload_len = req.payload.len() as u64;
        if payload_len > caveats.quotas.max_bytes_per_op {
            return Err(SynapseError::new(
                RefusalCode::QuotaPayloadTooLarge,
                format!(
                    "request payload size {payload_len} exceeds the chain's max_bytes_per_op {}",
                    caveats.quotas.max_bytes_per_op
                ),
            ));
        }

        // Partitioned rate: the leaf may use only the part it has not handed to children.
        let own = self
            .unallocated_quota(&leaf_digest)
            .expect("granted leaf has a quota record");
        let window_start = now_ms.saturating_sub(own.window_duration_ms);
        let timestamps = self.chains.rate_windows.entry(leaf_digest).or_default();
        timestamps.retain(|&ts| ts >= window_start);
        if timestamps.len() as u64 >= u64::from(own.max_ops_per_window) {
            return Err(SynapseError::new(
                RefusalCode::QuotaRateLimitExceeded,
                format!(
                    "link exceeded its unallocated rate ({} ops per {} ms)",
                    own.max_ops_per_window, own.window_duration_ms
                ),
            ));
        }

        if expected_capability.is_mutating() {
            let nonce_key = (expected_repo_id.clone(), req.agent_did(), req.request_nonce);
            if !self.consumed_nonces.insert(nonce_key) {
                return Err(SynapseError::new(
                    RefusalCode::AuthReplayDetected,
                    "replayed mutation request_nonce refused",
                ));
            }
        }
        self.chains
            .rate_windows
            .entry(leaf_digest)
            .or_default()
            .push(now_ms);
        Ok(())
    }
}

fn put_str(buf: &mut Vec<u8>, s: &str) {
    buf.extend_from_slice(&(s.len() as u32).to_le_bytes());
    buf.extend_from_slice(s.as_bytes());
}

/// Bounds-checked little-endian reader; every failure is `AuthChainMalformed`.
struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    fn take(&mut self, n: usize) -> SynapseResult<&'a [u8]> {
        let remaining = self.buf.len() - self.pos;
        if n > remaining {
            return Err(malformed(format!(
                "truncated: need {n} bytes at offset {}, {remaining} remain",
                self.pos
            )));
        }
        let out = &self.buf[self.pos..self.pos + n];
        self.pos += n;
        Ok(out)
    }

    fn u8(&mut self) -> SynapseResult<u8> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> SynapseResult<u16> {
        Ok(u16::from_le_bytes(
            self.take(2)?.try_into().expect("2 bytes"),
        ))
    }

    fn u32(&mut self) -> SynapseResult<u32> {
        Ok(u32::from_le_bytes(
            self.take(4)?.try_into().expect("4 bytes"),
        ))
    }

    fn u64(&mut self) -> SynapseResult<u64> {
        Ok(u64::from_le_bytes(
            self.take(8)?.try_into().expect("8 bytes"),
        ))
    }

    fn arr32(&mut self) -> SynapseResult<[u8; 32]> {
        Ok(self.take(32)?.try_into().expect("32 bytes"))
    }

    /// A `u32` count, refused above `cap` or above what `min_item_bytes` per item could fit.
    fn count(&mut self, cap: usize, min_item_bytes: usize) -> SynapseResult<usize> {
        let n = self.u32()? as usize;
        let remaining = self.buf.len() - self.pos;
        if n > cap || n.saturating_mul(min_item_bytes) > remaining {
            return Err(malformed(format!(
                "count {n} above cap {cap} or the {remaining} bytes that remain"
            )));
        }
        Ok(n)
    }

    fn string(&mut self, cap: usize) -> SynapseResult<String> {
        let len = self.u32()? as usize;
        if len > cap {
            return Err(malformed(format!("string length {len} above cap {cap}")));
        }
        let bytes = self.take(len)?;
        String::from_utf8(bytes.to_vec()).map_err(|_| malformed("string is not UTF-8"))
    }

    fn finish(&self) -> SynapseResult<()> {
        if self.pos != self.buf.len() {
            return Err(malformed(format!(
                "{} trailing bytes",
                self.buf.len() - self.pos
            )));
        }
        Ok(())
    }
}
