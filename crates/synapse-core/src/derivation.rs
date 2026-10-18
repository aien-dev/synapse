//! Server-derived revisions and their `DerivationAttestation` (ADR 0003 sections 5.1, 5.3, 5.6
//! and 5.8, section 9 step B5). See `docs/B5_DERIVATION_ATTESTATION.md`.
//!
//! * A **derived revision** is one the server produced rather than an agent: a rebase of an
//!   admitted revision onto another tree, or a merge of admitted revisions. It carries no agent
//!   signature. A [`DerivedRevision`] is its content plus one [`DerivationAttestation`].
//! * A [`DerivationAttestation`] is signed by the server's machine key (the `server_key` of the
//!   repository identity document, step E0). It names the inputs (revisions and trees), the
//!   deterministic [`DerivationRule`], and the output `ChangesetId` and `TreeDigest`.
//! * [`derive_revision_output`] is the one definition of every rule. The server uses it to
//!   produce a derived revision and every replica uses it to recompute one; an attestation whose
//!   recomputation differs is refused.
//!
//! The encodings follow `docs/B1_CHANGE_IDENTITY.md` section 3 (principle P5): little-endian,
//! length-prefixed, every count bounded before allocation, trailing bytes refused, and every
//! decode refusal `EnvelopeMalformed`.

use crate::revision::{malformed, put_str, Reader};
use crate::{
    encode_did_key_ed25519, AdmissionWitness, BlobDigest, ChainPath, ChangeId, ChangesetId,
    FileMode, IdempotencyKey, MutationOp, PathMutation, RefusalCode, RepoId, RevisionContent,
    SynapseError, SynapseResult, TreeDigest, WalSeq, WitnessSigner,
};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use sha2::{Digest, Sha256};

/// Domain tag of the server's Ed25519 signature over a [`DerivationAttestation`].
pub const DOMAIN_DERIVATION_SIGN_V1: &[u8] = b"SYNAPSE_DERIVATION_SIGN_V1\0";
/// Domain tag of [`DerivationAttestation::digest`].
pub const DOMAIN_DERIVATION_ATTESTATION_V1: &[u8] = b"SYNAPSE_DERIVATION_ATTESTATION_V1\0";
/// Domain tag of the `ChangeId` of a merge output (a merge starts a new unit of work whose
/// identity must be recomputable from its inputs).
pub const DOMAIN_DERIVED_MERGE_CHANGE_V1: &[u8] = b"SYNAPSE_DERIVED_MERGE_CHANGE_V1\0";
/// Domain tag of the `ChangeId` of a revert output (ADR 0003 step D2).
pub const DOMAIN_DERIVED_REVERT_CHANGE_V1: &[u8] = b"SYNAPSE_DERIVED_REVERT_CHANGE_V1\0";
/// Most inputs one attestation names.
pub const MAX_DERIVATION_INPUTS: usize = 256;

const RULE_TAG_REBASE: u8 = 1;
const RULE_TAG_MERGE: u8 = 2;
// Tag 3 is reserved for the derived-file action (the `ActionDigest` of the declared action,
// ADR 0003 section 5.3); it needs registered executors and is not decodable yet.
const RULE_TAG_REVERT: u8 = 4;
const TIER_TAG_T0: u8 = 0;
const TIER_TAG_T1: u8 = 1;
const INPUT_TAG_REVISION: u8 = 1;
const INPUT_TAG_TREE: u8 = 2;
/// Encoded size of the smallest input (tag and a 32-byte digest).
const MIN_INPUT_BYTES: usize = 1 + 32;

fn input_mismatch(msg: impl Into<String>) -> SynapseError {
    SynapseError::new(RefusalCode::DerivationInputMismatch, msg)
}

fn recompute_mismatch(msg: impl Into<String>) -> SynapseError {
    SynapseError::new(RefusalCode::DerivationRecomputeMismatch, msg)
}

// ---------------------------------------------------------------------------------------
// Rules and inputs
// ---------------------------------------------------------------------------------------

/// The level a merge works at (`MergeTier` in `CONTEXT.md`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum MergeTier {
    /// Path level: the merged revisions touch disjoint paths (no path of one equals, contains,
    /// or lies inside a path of another).
    T0Path,
    /// Region level (step D1): the T0 rule, except that revisions may write the same file
    /// when its versions merge line by line ([`crate::merge::region_merge`]: every changed
    /// region separated from every other revision's by an unchanged base line). Identical
    /// mutations of one path are taken once.
    T1Region,
}

/// The deterministic rule a derivation applied.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DerivationRule {
    /// Rebase one admitted revision onto another tree. Inputs: exactly
    /// `[Revision(r), Tree(onto)]`. The output keeps `r`'s `ChangeId`, parents and intent and
    /// takes `onto` as its base. When no path `r` mutates collides with a path that differs
    /// between `r`'s base and `onto`, it keeps `r`'s mutations as they are. Otherwise its tree
    /// is the conflict sum `onto + tree(r) - base(r)` ([`crate::sum_trees`], step D2) and its
    /// mutations turn `onto` into that tree, recording what does not cancel as conflict terms.
    /// Refused when `onto` is already `r`'s base or the rebase changes nothing.
    Rebase,
    /// Merge admitted revisions that share one base. Inputs: `[Tree(base), Revision(a1), ...,
    /// Revision(an)]` with `n >= 2` and the revisions in the canonical merge order (strictly
    /// ascending `ChangesetId`). The output's base is `base`, its parents are the merged
    /// revisions, its mutations are their union (paths must be disjoint at tier T0), its
    /// `ChangeId` is the first 16 bytes of `SHA-256(DOMAIN_DERIVED_MERGE_CHANGE_V1 || base ||
    /// u32 n || id*)`, and its intent summary is `merge tier T0 of <n> revisions`.
    Merge { tier: MergeTier },
    /// Revert an admitted revision on top of a tree (ADR 0003 step D2). Inputs: exactly
    /// `[Revision(x), Tree(onto)]`. The output's tree is the conflict sum
    /// `onto + base(x) - tree(x)`; its base is `onto`, its parents are `[x]`, its mutations turn
    /// `onto` into that tree, its `ChangeId` is the first 16 bytes of
    /// `SHA-256(DOMAIN_DERIVED_REVERT_CHANGE_V1 || x || onto)`, and its intent summary is
    /// `revert of <x>`. Reverting a change whose rebase conflicted, on top of that conflicted
    /// tree, gives a clean tree. Refused when the revert changes nothing.
    Revert,
}

impl DerivationRule {
    fn encode_into(&self, buf: &mut Vec<u8>) {
        match self {
            DerivationRule::Rebase => buf.push(RULE_TAG_REBASE),
            DerivationRule::Revert => buf.push(RULE_TAG_REVERT),
            DerivationRule::Merge { tier } => {
                buf.push(RULE_TAG_MERGE);
                buf.push(match tier {
                    MergeTier::T0Path => TIER_TAG_T0,
                    MergeTier::T1Region => TIER_TAG_T1,
                });
            }
        }
    }

    fn decode_from(r: &mut Reader) -> SynapseResult<Self> {
        match r.u8()? {
            RULE_TAG_REBASE => Ok(DerivationRule::Rebase),
            RULE_TAG_REVERT => Ok(DerivationRule::Revert),
            RULE_TAG_MERGE => match r.u8()? {
                TIER_TAG_T0 => Ok(DerivationRule::Merge {
                    tier: MergeTier::T0Path,
                }),
                TIER_TAG_T1 => Ok(DerivationRule::Merge {
                    tier: MergeTier::T1Region,
                }),
                tag => Err(malformed(format!("unknown merge tier tag {tag}"))),
            },
            tag => Err(malformed(format!("unknown derivation rule tag {tag}"))),
        }
    }
}

/// One input a derivation names: an admitted revision or a tree.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum DerivationInput {
    Revision(ChangesetId),
    Tree(TreeDigest),
}

impl DerivationInput {
    fn encode_into(&self, buf: &mut Vec<u8>) {
        match self {
            DerivationInput::Revision(id) => {
                buf.push(INPUT_TAG_REVISION);
                buf.extend_from_slice(&id.0);
            }
            DerivationInput::Tree(t) => {
                buf.push(INPUT_TAG_TREE);
                buf.extend_from_slice(&t.0);
            }
        }
    }

    fn decode_from(r: &mut Reader) -> SynapseResult<Self> {
        match r.u8()? {
            INPUT_TAG_REVISION => Ok(DerivationInput::Revision(ChangesetId(r.array()?))),
            INPUT_TAG_TREE => Ok(DerivationInput::Tree(TreeDigest(r.array()?))),
            tag => Err(malformed(format!("unknown derivation input tag {tag}"))),
        }
    }
}

// ---------------------------------------------------------------------------------------
// Attestation and derived revision
// ---------------------------------------------------------------------------------------

/// The server's signed statement that revision `output_changeset`, whose tree is
/// `output_tree`, is what `rule` gives on `inputs` in repository `repo_id` (ADR 0003 section
/// 5.1). Deterministic: the same derivation always gives the same attestation bytes, so a
/// second presentation of one derivation is a replay.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DerivationAttestation {
    pub repo_id: RepoId,
    pub rule: DerivationRule,
    pub inputs: Vec<DerivationInput>,
    pub output_changeset: ChangesetId,
    pub output_tree: TreeDigest,
    /// The server machine key that signed (must be the identity document's `server_key` in
    /// effect at the admission `WalSeq`).
    pub server_key: [u8; 32],
    pub signature: [u8; 64],
}

impl DerivationAttestation {
    /// Sign an attestation with the server's machine key.
    pub fn sign(
        server: &SigningKey,
        repo_id: RepoId,
        rule: DerivationRule,
        inputs: Vec<DerivationInput>,
        output_changeset: ChangesetId,
        output_tree: TreeDigest,
    ) -> Self {
        let mut att = Self {
            repo_id,
            rule,
            inputs,
            output_changeset,
            output_tree,
            server_key: server.verifying_key().to_bytes(),
            signature: [0u8; 64],
        };
        att.signature = server.sign(&att.signable_bytes()).to_bytes();
        att
    }

    /// The server key's `did:key`.
    pub fn server_did(&self) -> String {
        encode_did_key_ed25519(&self.server_key)
    }

    fn encode_body(&self, buf: &mut Vec<u8>) {
        put_str(buf, self.repo_id.as_str());
        self.rule.encode_into(buf);
        buf.extend_from_slice(&(self.inputs.len() as u32).to_le_bytes());
        for i in &self.inputs {
            i.encode_into(buf);
        }
        buf.extend_from_slice(&self.output_changeset.0);
        buf.extend_from_slice(&self.output_tree.0);
        buf.extend_from_slice(&self.server_key);
    }

    /// `DOMAIN_DERIVATION_SIGN_V1 || repo_id str || rule || u32 count || input* ||
    /// output_changeset [32] || output_tree [32] || server_key [32]`.
    pub fn signable_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(192 + 33 * self.inputs.len());
        buf.extend_from_slice(DOMAIN_DERIVATION_SIGN_V1);
        self.encode_body(&mut buf);
        buf
    }

    /// 1..=`MAX_DERIVATION_INPUTS` inputs and a strict Ed25519 signature by `server_key`.
    /// Both a key that is not an Ed25519 point and a signature that does not verify are
    /// `DerivationSignatureInvalid`.
    pub fn verify(&self) -> SynapseResult<()> {
        if self.inputs.is_empty() || self.inputs.len() > MAX_DERIVATION_INPUTS {
            return Err(input_mismatch(format!(
                "derivation names {} inputs, outside 1..={MAX_DERIVATION_INPUTS}",
                self.inputs.len()
            )));
        }
        let invalid = |what: &str| {
            SynapseError::new(
                RefusalCode::DerivationSignatureInvalid,
                format!("derivation attestation: {what}"),
            )
        };
        let vk = VerifyingKey::from_bytes(&self.server_key)
            .map_err(|_| invalid("server key is not an Ed25519 public key"))?;
        vk.verify_strict(
            &self.signable_bytes(),
            &Signature::from_bytes(&self.signature),
        )
        .map_err(|_| invalid("signature does not verify under the named server key"))
    }

    /// Body (as signed, without the domain tag) then the 64-byte signature.
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(256 + 33 * self.inputs.len());
        self.encode_into(&mut buf);
        buf
    }

    fn encode_into(&self, buf: &mut Vec<u8>) {
        self.encode_body(buf);
        buf.extend_from_slice(&self.signature);
    }

    /// Decode exactly one canonical attestation (structure only; see [`Self::verify`]).
    pub fn decode(bytes: &[u8]) -> SynapseResult<Self> {
        let mut r = Reader::new(bytes);
        let att = Self::decode_from(&mut r)?;
        r.finish()?;
        Ok(att)
    }

    fn decode_from(r: &mut Reader) -> SynapseResult<Self> {
        let repo_id = r.repo()?;
        let rule = DerivationRule::decode_from(r)?;
        let n = r.count(MAX_DERIVATION_INPUTS, MIN_INPUT_BYTES)?;
        if n == 0 {
            return Err(malformed("derivation names no inputs"));
        }
        let mut inputs = Vec::with_capacity(n);
        for _ in 0..n {
            inputs.push(DerivationInput::decode_from(r)?);
        }
        Ok(Self {
            repo_id,
            rule,
            inputs,
            output_changeset: ChangesetId(r.array()?),
            output_tree: TreeDigest(r.array()?),
            server_key: r.array()?,
            signature: r.array()?,
        })
    }

    /// `SHA-256(DOMAIN_DERIVATION_ATTESTATION_V1 || encode())`: the identity of one signed
    /// attestation, recorded in the admission witness and used to refuse replays.
    pub fn digest(&self) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(DOMAIN_DERIVATION_ATTESTATION_V1);
        h.update(self.encode());
        h.finalize().into()
    }
}

/// A server-derived revision: its content and the attestation over it. It has no agent
/// signature and never claims one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DerivedRevision {
    pub content: RevisionContent,
    pub attestation: DerivationAttestation,
}

impl DerivedRevision {
    /// Produce a derived revision: recompute `rule` on `inputs` (the same function every
    /// replica runs) and sign the attestation with the server's machine key.
    pub fn derive(
        server: &SigningKey,
        repo_id: RepoId,
        rule: DerivationRule,
        inputs: Vec<DerivationInput>,
        revision: &dyn Fn(ChangesetId) -> Option<RevisionContent>,
        trees: &mut dyn DerivationTrees,
    ) -> SynapseResult<Self> {
        let (content, tree) = derive_revision_output(rule, &inputs, revision, trees)?;
        let attestation = DerivationAttestation::sign(
            server,
            repo_id,
            rule,
            inputs,
            content.changeset_id(),
            tree,
        );
        Ok(Self {
            content,
            attestation,
        })
    }

    /// The content-only v2 `ChangesetId`.
    pub fn changeset_id(&self) -> ChangesetId {
        self.content.changeset_id()
    }

    /// Validate the content (the B1 rules), check that the attestation names this content
    /// (`DerivationSignatureInvalid` otherwise), and verify the attestation. This needs no
    /// state; registration of the server key, replay, and recomputation are checked against
    /// the ledger, the identity document, and the tree store.
    pub fn validate(&self) -> SynapseResult<ChangesetId> {
        self.content.validate()?;
        let id = self.content.changeset_id();
        if self.attestation.output_changeset != id {
            return Err(SynapseError::new(
                RefusalCode::DerivationSignatureInvalid,
                format!(
                    "derivation attestation names revision {} but the content is revision {id}",
                    self.attestation.output_changeset
                ),
            ));
        }
        self.attestation.verify()?;
        Ok(id)
    }

    /// `u32 content_len | content | attestation`.
    pub fn encode(&self) -> Vec<u8> {
        let content = self.content.encode();
        let mut buf = Vec::with_capacity(content.len() + 256);
        buf.extend_from_slice(&(content.len() as u32).to_le_bytes());
        buf.extend_from_slice(&content);
        self.attestation.encode_into(&mut buf);
        buf
    }

    /// Decode exactly one canonical derived revision (structure only; see [`Self::validate`]).
    pub fn decode(bytes: &[u8]) -> SynapseResult<Self> {
        let mut r = Reader::new(bytes);
        let len = r.u32()? as usize;
        let mut inner = Reader::new(r.take(len)?);
        let content = RevisionContent::decode_from(&mut inner)?;
        inner.finish()?;
        let attestation = DerivationAttestation::decode_from(&mut r)?;
        r.finish()?;
        Ok(Self {
            content,
            attestation,
        })
    }
}

impl AdmissionWitness {
    /// The witness of admitting `derived` at `admission_seq` under `chain`: the server key,
    /// its signature, and the attestation digest instead of an agent signature. The
    /// idempotency key is the attestation digest (a derivation has no client key; a second
    /// presentation of one attestation is refused as a replay).
    pub fn of_derivation(
        derived: &DerivedRevision,
        chain: ChainPath,
        admission_seq: WalSeq,
        admitted_at_ms: u64,
    ) -> Self {
        let att = &derived.attestation;
        let digest = att.digest();
        Self {
            repo_id: att.repo_id.clone(),
            changeset_id: att.output_changeset,
            signer: WitnessSigner::Server {
                server_key: att.server_key,
                signature: att.signature,
                attestation_digest: digest,
            },
            idempotency_key: IdempotencyKey(digest),
            admission_seq,
            admitted_at_ms,
            chain,
        }
    }
}

// ---------------------------------------------------------------------------------------
// What a replica needs to check and recompute
// ---------------------------------------------------------------------------------------

/// What a [`ServerKeyRegistry`] answers for one repository at one `WalSeq`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ServerKeyLookup {
    /// The `server_key` of the repository's identity document in effect at the sequence.
    Registered([u8; 32]),
    /// No identity document of the repository is in effect at the sequence (before genesis).
    NoDocument,
    /// The registry holds the identity documents of another repository (named here), so it
    /// says nothing about the one asked for.
    OtherRepository(RepoId),
}

/// Which server machine key a repository identity document registered at a `WalSeq`
/// (`synapse_radicle::IdentityLog` implements it from the E0 document chain). The repository
/// is part of the question, so one repository's documents can never vouch for another's
/// derivations, even when both register the same server machine key.
pub trait ServerKeyRegistry {
    /// The `server_key` of `repo`'s document in effect at `at`.
    fn registered_server_key(&self, repo: &RepoId, at: WalSeq) -> ServerKeyLookup;
}

/// The tree operations a derivation rule needs (the C1 tree store implements them), including
/// the node access of the conflict algebra (step D2).
pub trait DerivationTrees: crate::ConflictTrees {
    /// Whether the tree `tree` can be read (its root node is held).
    fn holds_tree(&mut self, tree: TreeDigest) -> bool;
    /// The root of `base` with `mutations` applied in order.
    fn apply_mutations(
        &mut self,
        base: TreeDigest,
        mutations: &[PathMutation],
    ) -> SynapseResult<TreeDigest>;
    /// The file at `path` of `tree` (mode and blob), `None` when there is none (tier T1).
    fn file_at(
        &mut self,
        tree: TreeDigest,
        path: &str,
    ) -> SynapseResult<Option<(FileMode, BlobDigest)>>;
    /// The bytes of a stored blob (`BlobNotFound` when this replica cannot read it; tier T1).
    fn blob_bytes(&mut self, digest: BlobDigest) -> SynapseResult<Vec<u8>>;
    /// Hold the bytes of a blob a derivation produced (a tier T1 merged file) so that later
    /// mutations can name it and the store can write it with the derived revision; returns
    /// its digest.
    fn put_blob(&mut self, bytes: Vec<u8>) -> SynapseResult<BlobDigest>;
    /// The bytes of a blob a derived revision writes that the store may not hold, if any: one
    /// produced by [`DerivationTrees::put_blob`], or a file only a base tree holds that a
    /// conflict sum restores (step D2). The store checks the digest and writes the bytes with
    /// the derived revision.
    fn produced_blob(&self, digest: BlobDigest) -> Option<&[u8]>;
}

/// `true` when `inner` lies strictly below directory `dir`.
fn is_below(inner: &str, dir: &str) -> bool {
    inner.len() > dir.len() && inner.starts_with(dir) && inner.as_bytes()[dir.len()] == b'/'
}

/// Two paths collide at path level when they are equal or one lies below the other.
fn paths_collide(a: &str, b: &str) -> bool {
    a == b || is_below(a, b) || is_below(b, a)
}

/// Any pair of paths, one from each sorted list, that collides.
fn first_collision<'a>(a: &'a [&'a str], b: &'a [&'a str]) -> Option<(&'a str, &'a str)> {
    for x in a {
        for y in b {
            if paths_collide(x, y) {
                return Some((x, y));
            }
        }
    }
    None
}

/// Tier T0 mutations of a merge: the union of every source's mutations, refused when a path
/// of one source collides (equal, or one below the other) with a path of another.
fn t0_mutations(sources: &[RevisionContent]) -> SynapseResult<Vec<PathMutation>> {
    for i in 0..sources.len() {
        let a: Vec<&str> = sources[i]
            .mutations
            .iter()
            .map(|m| m.path.as_str())
            .collect();
        for s in &sources[i + 1..] {
            let b: Vec<&str> = s.mutations.iter().map(|m| m.path.as_str()).collect();
            if let Some((x, y)) = first_collision(&a, &b) {
                return Err(recompute_mismatch(format!(
                    "tier T0 merge conflicts: {x} collides with {y}"
                )));
            }
        }
    }
    let mut mutations: Vec<PathMutation> = sources
        .iter()
        .flat_map(|s| s.mutations.iter().cloned())
        .collect();
    mutations.sort_by(|a, b| a.path.cmp(&b.path));
    Ok(mutations)
}

/// Tier T1 mutations of a merge on `base` (step D1). Paths written by one source are taken
/// as they are; byte-identical mutations of one path are taken once; a file several sources
/// upsert differently with the base's mode is merged line by line
/// ([`crate::merge::region_merge`]) and the merged bytes are held through
/// [`DerivationTrees::put_blob`]. Refused (`DerivationRecomputeMismatch`): a path of one
/// source lying below a path of another, a path deleted by one source and changed by
/// another, a mode change, a file added by several sources with different content, and any
/// region conflict.
fn t1_mutations(
    base: TreeDigest,
    sources: &[RevisionContent],
    trees: &mut dyn DerivationTrees,
) -> SynapseResult<Vec<PathMutation>> {
    let mut by_path: std::collections::BTreeMap<&str, Vec<(usize, &PathMutation)>> =
        std::collections::BTreeMap::new();
    for (i, s) in sources.iter().enumerate() {
        for m in &s.mutations {
            by_path.entry(m.path.as_str()).or_default().push((i, m));
        }
    }
    let paths: Vec<(&str, Vec<usize>)> = by_path
        .iter()
        .map(|(p, v)| (*p, v.iter().map(|(i, _)| *i).collect()))
        .collect();
    for (x, xs) in &paths {
        for (y, ys) in &paths {
            if is_below(y, x) && xs.iter().any(|i| ys.iter().any(|j| i != j)) {
                return Err(recompute_mismatch(format!(
                    "tier T1 merge conflicts: {y} lies below {x}, written by another revision"
                )));
            }
        }
    }
    let mut out = Vec::with_capacity(by_path.len());
    for (path, muts) in by_path {
        let mut distinct: Vec<&PathMutation> = Vec::new();
        for (_, m) in &muts {
            if !distinct.contains(m) {
                distinct.push(m);
            }
        }
        if let [only] = distinct.as_slice() {
            out.push((*only).clone());
            continue;
        }
        let conflict =
            |why: String| recompute_mismatch(format!("tier T1 merge conflicts on {path}: {why}"));
        let mut versions = Vec::with_capacity(distinct.len());
        for m in &distinct {
            match &m.op {
                MutationOp::Upsert {
                    mode, blob_digest, ..
                } => versions.push((*mode, *blob_digest)),
                MutationOp::Delete => {
                    return Err(conflict(
                        "deleted by one revision and changed by another".into(),
                    ))
                }
                // A recorded conflict term is not merged line by line (step D2).
                MutationOp::Conflict(_) => {
                    return Err(conflict(
                        "a revision records a conflict term at the path".into(),
                    ))
                }
            }
        }
        let Some((base_mode, base_blob)) = trees.file_at(base, path)? else {
            return Err(conflict(
                "added by several revisions with different content".into(),
            ));
        };
        // Every version keeps the base mode (a mode change is not merged line by line).
        if versions.iter().any(|(mode, _)| *mode != base_mode) {
            return Err(conflict("a revision changes the file's mode".into()));
        }
        let base_bytes = trees.blob_bytes(base_blob)?;
        let mut bytes = Vec::with_capacity(versions.len());
        for (_, v) in &versions {
            bytes.push(trees.blob_bytes(*v)?);
        }
        let refs: Vec<&[u8]> = bytes.iter().map(Vec::as_slice).collect();
        let merged =
            crate::merge::region_merge(&base_bytes, &refs).map_err(|c| conflict(c.to_string()))?;
        let size_bytes = merged.len() as u64;
        let blob_digest = trees.put_blob(merged)?;
        out.push(PathMutation {
            path: path.to_string(),
            op: MutationOp::Upsert {
                mode: base_mode,
                blob_digest,
                size_bytes,
            },
        });
    }
    Ok(out)
}

/// The tree of a conflict-sum output, built the way every revision tree is built (its base
/// with its mutations applied), and checked against the sum it was derived from.
fn applied_sum(
    trees: &mut dyn DerivationTrees,
    base: TreeDigest,
    mutations: &[PathMutation],
    summed: TreeDigest,
) -> SynapseResult<TreeDigest> {
    let tree = trees.apply_mutations(base, mutations)?;
    if tree != summed {
        return Err(recompute_mismatch(format!(
            "applying the derived mutations to {base} gives {tree}, not the conflict sum {summed}"
        )));
    }
    Ok(tree)
}

/// The `ChangeId` of a revert of `x` on `onto`.
fn revert_change_id(x: ChangesetId, onto: TreeDigest) -> ChangeId {
    let mut h = Sha256::new();
    h.update(DOMAIN_DERIVED_REVERT_CHANGE_V1);
    h.update(x.0);
    h.update(onto.0);
    let d: [u8; 32] = h.finalize().into();
    let mut out = [0u8; 16];
    out.copy_from_slice(&d[..16]);
    ChangeId(out)
}

fn require_tree(trees: &mut dyn DerivationTrees, t: TreeDigest, what: &str) -> SynapseResult<()> {
    if trees.holds_tree(t) {
        Ok(())
    } else {
        Err(input_mismatch(format!(
            "{what} {t} is not held by this replica"
        )))
    }
}

/// The `ChangeId` of a merge (any tier) of `ids` (canonical order) on `base`.
fn merge_change_id(base: TreeDigest, ids: &[ChangesetId]) -> ChangeId {
    let mut h = Sha256::new();
    h.update(DOMAIN_DERIVED_MERGE_CHANGE_V1);
    h.update(base.0);
    h.update((ids.len() as u32).to_le_bytes());
    for id in ids {
        h.update(id.0);
    }
    let d: [u8; 32] = h.finalize().into();
    let mut out = [0u8; 16];
    out.copy_from_slice(&d[..16]);
    ChangeId(out)
}

/// The output content and tree of `rule` on `inputs`: the one definition of every rule, run
/// by the server to derive and by every replica to recompute. `revision` resolves an admitted
/// revision of the attestation's repository (admitted before the derivation).
///
/// Refusals: inputs that do not fit the rule (kind, count, order, duplicates) or that are not
/// held (`revision` returns `None`, or the tree is not held) are `DerivationInputMismatch`; a
/// rule that does not apply to the inputs (a rebase onto its own base or with a path conflict,
/// a merge of revisions on another base or with colliding paths) is
/// `DerivationRecomputeMismatch`. Tree store failures propagate unchanged.
pub fn derive_revision_output(
    rule: DerivationRule,
    inputs: &[DerivationInput],
    revision: &dyn Fn(ChangesetId) -> Option<RevisionContent>,
    trees: &mut dyn DerivationTrees,
) -> SynapseResult<(RevisionContent, TreeDigest)> {
    if inputs.is_empty() || inputs.len() > MAX_DERIVATION_INPUTS {
        return Err(input_mismatch(format!(
            "derivation names {} inputs, outside 1..={MAX_DERIVATION_INPUTS}",
            inputs.len()
        )));
    }
    let resolve = |id: ChangesetId| {
        revision(id).ok_or_else(|| {
            input_mismatch(format!(
                "input revision {id} is not an admitted revision of this repository"
            ))
        })
    };
    match rule {
        DerivationRule::Rebase => {
            let [DerivationInput::Revision(r), DerivationInput::Tree(onto)] = inputs else {
                return Err(input_mismatch(
                    "a rebase names exactly [Revision(r), Tree(onto)]",
                ));
            };
            let source = resolve(*r)?;
            require_tree(trees, *onto, "rebase target tree")?;
            require_tree(trees, source.base_tree, "base tree of the rebased revision")?;
            if source.base_tree == *onto {
                return Err(recompute_mismatch(format!(
                    "revision {r} is already based on {onto}: nothing to rebase"
                )));
            }
            let changed = crate::diff_mutations(trees, source.base_tree, *onto)?;
            let changed: Vec<&str> = changed.iter().map(|m| m.path.as_str()).collect();
            let mutated: Vec<&str> = source.mutations.iter().map(|m| m.path.as_str()).collect();
            if first_collision(&mutated, &changed).is_none() {
                let content = RevisionContent {
                    base_tree: *onto,
                    ..source
                };
                content.validate()?;
                let tree = trees.apply_mutations(*onto, &content.mutations)?;
                return Ok((content, tree));
            }
            // Colliding paths: onto + tree(r) - base(r), conflicts recorded as terms.
            let source_tree = trees.apply_mutations(source.base_tree, &source.mutations)?;
            let summed = crate::sum_trees(trees, &[*onto, source_tree], &[source.base_tree])?;
            let mutations = crate::diff_mutations(trees, *onto, summed)?;
            if mutations.is_empty() {
                return Err(recompute_mismatch(format!(
                    "rebasing {r} onto {onto} changes nothing: {onto} already holds its change"
                )));
            }
            let content = RevisionContent {
                base_tree: *onto,
                mutations,
                ..source
            };
            content.validate()?;
            let tree = applied_sum(trees, *onto, &content.mutations, summed)?;
            Ok((content, tree))
        }
        DerivationRule::Revert => {
            let [DerivationInput::Revision(x), DerivationInput::Tree(onto)] = inputs else {
                return Err(input_mismatch(
                    "a revert names exactly [Revision(x), Tree(onto)]",
                ));
            };
            let source = resolve(*x)?;
            require_tree(trees, *onto, "revert target tree")?;
            require_tree(
                trees,
                source.base_tree,
                "base tree of the reverted revision",
            )?;
            let source_tree = trees.apply_mutations(source.base_tree, &source.mutations)?;
            let summed = crate::sum_trees(trees, &[*onto, source.base_tree], &[source_tree])?;
            let mutations = crate::diff_mutations(trees, *onto, summed)?;
            if mutations.is_empty() {
                return Err(recompute_mismatch(format!(
                    "reverting {x} on {onto} changes nothing"
                )));
            }
            let content = RevisionContent {
                change_id: revert_change_id(*x, *onto),
                base_tree: *onto,
                parents: vec![*x],
                mutations,
                intent_summary: format!("revert of {x}"),
            };
            content.validate()?;
            let tree = applied_sum(trees, *onto, &content.mutations, summed)?;
            Ok((content, tree))
        }
        DerivationRule::Merge { tier } => {
            let Some((DerivationInput::Tree(base), rest)) = inputs.split_first() else {
                return Err(input_mismatch(
                    "a merge names [Tree(base), Revision(a1), ..., Revision(an)]",
                ));
            };
            let mut ids = Vec::with_capacity(rest.len());
            for i in rest {
                match i {
                    DerivationInput::Revision(id) => ids.push(*id),
                    DerivationInput::Tree(_) => {
                        return Err(input_mismatch("a merge names exactly one tree, first"))
                    }
                }
            }
            if ids.len() < 2 {
                return Err(input_mismatch("a merge names at least two revisions"));
            }
            if ids.windows(2).any(|w| w[0] >= w[1]) {
                return Err(input_mismatch(
                    "merge revisions must be in the canonical merge order (strictly ascending ChangesetId)",
                ));
            }
            require_tree(trees, *base, "merge base tree")?;
            let mut sources = Vec::with_capacity(ids.len());
            for id in &ids {
                sources.push(resolve(*id)?);
            }
            for (id, s) in ids.iter().zip(&sources) {
                if s.base_tree != *base {
                    return Err(recompute_mismatch(format!(
                        "revision {id} is based on {}, not on the merge base {base}",
                        s.base_tree
                    )));
                }
            }
            let mutations = match tier {
                MergeTier::T0Path => t0_mutations(&sources)?,
                MergeTier::T1Region => t1_mutations(*base, &sources, trees)?,
            };
            let content = RevisionContent {
                change_id: merge_change_id(*base, &ids),
                base_tree: *base,
                parents: ids.clone(),
                mutations,
                intent_summary: format!(
                    "merge tier {} of {} revisions",
                    match tier {
                        MergeTier::T0Path => "T0",
                        MergeTier::T1Region => "T1",
                    },
                    ids.len()
                ),
            };
            content.validate()?;
            let tree = trees.apply_mutations(*base, &content.mutations)?;
            Ok((content, tree))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{BlobDigest, FileMode, MutationOp};

    fn repo() -> RepoId {
        RepoId::new("aien-spark/synapse").unwrap()
    }

    fn server() -> SigningKey {
        let seed: [u8; 32] = Sha256::digest(b"b5 unit server key").into();
        SigningKey::from_bytes(&seed)
    }

    fn attestation() -> DerivationAttestation {
        DerivationAttestation::sign(
            &server(),
            repo(),
            DerivationRule::Merge {
                tier: MergeTier::T0Path,
            },
            vec![
                DerivationInput::Tree(TreeDigest([0x5A; 32])),
                DerivationInput::Revision(ChangesetId([1; 32])),
                DerivationInput::Revision(ChangesetId([2; 32])),
            ],
            ChangesetId([3; 32]),
            TreeDigest([4; 32]),
        )
    }

    #[test]
    fn b5_attestation_round_trips_and_refuses_malformed_bytes() {
        let att = attestation();
        att.verify().unwrap();
        let bytes = att.encode();
        assert_eq!(DerivationAttestation::decode(&bytes).unwrap(), att);
        for cut in 0..bytes.len() {
            assert_eq!(
                DerivationAttestation::decode(&bytes[..cut])
                    .unwrap_err()
                    .code,
                RefusalCode::EnvelopeMalformed,
                "cut {cut}"
            );
        }
        let mut trailing = bytes.clone();
        trailing.push(0);
        assert!(DerivationAttestation::decode(&trailing).is_err());
        // The rule tag follows `u32 len | repo`; tag 3 (derived-file action) is reserved.
        let rule_at = 4 + repo().as_str().len();
        let mut reserved = bytes.clone();
        reserved[rule_at] = 3;
        assert_eq!(
            DerivationAttestation::decode(&reserved).unwrap_err().code,
            RefusalCode::EnvelopeMalformed
        );
        let mut tier = bytes.clone();
        tier[rule_at + 1] = 2;
        assert!(DerivationAttestation::decode(&tier).is_err());
        // Tier tag 1 is T1 (step D1): it decodes, to a different attestation whose
        // signature no longer verifies.
        tier[rule_at + 1] = 1;
        let t1 = DerivationAttestation::decode(&tier).unwrap();
        assert_eq!(
            t1.rule,
            DerivationRule::Merge {
                tier: MergeTier::T1Region
            }
        );
        assert!(t1.verify().is_err());
        let mut zero = bytes.clone();
        zero[rule_at + 2..rule_at + 6].copy_from_slice(&0u32.to_le_bytes());
        assert!(DerivationAttestation::decode(&zero).is_err());
        let mut huge = bytes;
        huge[rule_at + 2..rule_at + 6].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(DerivationAttestation::decode(&huge).is_err());
    }

    #[test]
    fn b5_attestation_signature_binds_every_field() {
        let att = attestation();
        let mut t = att.clone();
        t.output_tree = TreeDigest([9; 32]);
        assert_eq!(
            t.verify().unwrap_err().code,
            RefusalCode::DerivationSignatureInvalid
        );
        let mut t = att.clone();
        t.rule = DerivationRule::Rebase;
        assert_eq!(
            t.verify().unwrap_err().code,
            RefusalCode::DerivationSignatureInvalid
        );
        let mut t = att.clone();
        t.inputs.pop();
        assert_eq!(
            t.verify().unwrap_err().code,
            RefusalCode::DerivationSignatureInvalid
        );
        let mut t = att.clone();
        t.repo_id = RepoId::new("aien-spark/other").unwrap();
        assert_eq!(
            t.verify().unwrap_err().code,
            RefusalCode::DerivationSignatureInvalid
        );
        assert_ne!(att.digest(), t.digest());
    }

    #[test]
    fn b5_server_witness_round_trips_and_is_not_an_agent() {
        let content = RevisionContent {
            change_id: ChangeId([7; 16]),
            base_tree: TreeDigest([0x5A; 32]),
            parents: vec![],
            mutations: vec![PathMutation {
                path: "src/lib.rs".into(),
                op: MutationOp::Upsert {
                    mode: FileMode::Regular644,
                    blob_digest: BlobDigest::compute(b"x"),
                    size_bytes: 1,
                },
            }],
            intent_summary: "derived".into(),
        };
        let attestation = DerivationAttestation::sign(
            &server(),
            repo(),
            DerivationRule::Rebase,
            vec![
                DerivationInput::Revision(ChangesetId([1; 32])),
                DerivationInput::Tree(TreeDigest([0x5A; 32])),
            ],
            content.changeset_id(),
            TreeDigest([4; 32]),
        );
        let derived = DerivedRevision {
            content,
            attestation,
        };
        derived.validate().unwrap();
        assert_eq!(DerivedRevision::decode(&derived.encode()).unwrap(), derived);
        let chain = ChainPath::new(vec![[1; 32]]).unwrap();
        let w = AdmissionWitness::of_derivation(&derived, chain, WalSeq(3), 9);
        assert_eq!(AdmissionWitness::decode(&w.encode()).unwrap(), w);
        assert_eq!(w.signer_did(), derived.attestation.server_did());
        assert!(
            matches!(w.signer, WitnessSigner::Server { attestation_digest, .. }
            if attestation_digest == derived.attestation.digest())
        );
    }

    #[test]
    fn b5_path_collision_is_equal_or_below() {
        assert!(paths_collide("a", "a"));
        assert!(paths_collide("a", "a/b"));
        assert!(paths_collide("a/b/c", "a/b"));
        assert!(!paths_collide("a", "ab"));
        assert!(!paths_collide("a/b", "a/c"));
    }
}
