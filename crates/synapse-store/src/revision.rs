//! Revision ledger: envelope v2 revisions, their change identities, admission witnesses,
//! and obsolescence markers (ADR 0003 section 5.1, step B1). See `docs/B1_CHANGE_IDENTITY.md`.
//!
//! The ledger is a pure function of the revision records (`RevisionAdmitted`,
//! `ObsolescenceRecorded`) applied in `WalSeq` order: replay, a checkpoint (which keeps the
//! records themselves), and a live store all rebuild exactly the same ledger. v1 changesets
//! stay in their own map with their own IDs; the two ID domains never meet.

use crate::WalRecord;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use synapse_core::{
    derive_revision_output, AdmissionWitness, AuthorshipAttestation, BlobDigest, ChainPath,
    ChangeId, ChangesetEnvelopeV2, ChangesetId, DerivationAttestation, DerivationTrees,
    DerivedRevision, IdempotencyKey, MutationOp, ObsolescenceKind, ObsolescenceMarker, RefusalCode,
    RepoId, RevisionContent, ServerKeyLookup, ServerKeyRegistry, SynapseError, SynapseResult,
    WalSeq,
};

/// Domain tag of the revision part of the state root (only hashed when revisions exist).
pub const DOMAIN_STATE_ROOT_REVISIONS_V1: &[u8] = b"SYNAPSE_STATE_ROOT_REVISIONS_V1\0";

/// The authority an admission was granted under, from the verified delegation chain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdmissionAuthority {
    /// The request's chain (link digests, root first).
    pub chain: ChainPath,
    /// `ChangeId`s the chain's leaf grant names explicitly in its change scope. A grant
    /// that allows any change names none: it never lets a key join a change outside its
    /// creating chain.
    pub change_scope: Vec<ChangeId>,
}

/// One admitted revision: its content, every authorship attestation (agents), every
/// derivation attestation (the server, step B5), and every admission witness, in admission
/// order. A revision only the server derived has no authorship attestation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredRevision {
    pub repo_id: RepoId,
    pub changeset_id: ChangesetId,
    pub content: RevisionContent,
    /// Sequence of the first admission.
    pub first_seq: WalSeq,
    pub attestations: Vec<AuthorshipAttestation>,
    pub derivations: Vec<DerivationAttestation>,
    pub witnesses: Vec<AdmissionWitness>,
}

/// A recorded obsolescence marker with the chain it was recorded under.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordedMarker {
    pub seq: WalSeq,
    pub marker: ObsolescenceMarker,
    pub chain: ChainPath,
    pub recorded_at_ms: u64,
}

/// Status of one change: its creating chain, revisions, and which of them are live.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChangeStatus {
    pub repo_id: RepoId,
    pub change_id: ChangeId,
    /// The chain of the first admission under this `ChangeId`.
    pub creating_chain: ChainPath,
    /// Every revision, in first-admission order.
    pub revisions: Vec<ChangesetId>,
    /// Revisions no marker names as predecessor, in first-admission order.
    pub live: Vec<ChangesetId>,
    /// Revisions some marker names as predecessor, in first-admission order.
    pub obsolete: Vec<ChangesetId>,
    pub markers: Vec<RecordedMarker>,
    /// More than one live revision: divergent attempts (ADR 0003 section 5.1).
    pub divergent: bool,
}

/// Outcome of [`crate::SynapseStore::admit_revision`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RevisionOutcome {
    /// A new admission (a new revision, or a new attestation of an existing one) at
    /// `wal_seq`.
    Admitted {
        wal_seq: WalSeq,
        changeset_id: ChangesetId,
        /// The revision already existed: this admission added an attestation and a witness.
        joined_existing_revision: bool,
    },
    /// The same repository, signer DID, and `IdempotencyKey` were already admitted with the
    /// same revision: the first admission's `WalSeq`.
    IdempotentDuplicate {
        wal_seq: WalSeq,
        changeset_id: ChangesetId,
    },
}

#[derive(Debug, Clone, Default)]
struct ChangeEntry {
    creating_chain: Option<ChainPath>,
    revisions: Vec<ChangesetId>,
    markers: Vec<RecordedMarker>,
}

/// In-memory revision state, rebuilt from revision records.
#[derive(Debug, Clone, Default)]
pub(crate) struct RevisionLedger {
    /// Every revision record applied, in sequence order (what checkpoints keep).
    log: Vec<(WalSeq, WalRecord)>,
    revisions: BTreeMap<(RepoId, ChangesetId), StoredRevision>,
    changes: BTreeMap<(RepoId, ChangeId), ChangeEntry>,
    /// (repository, signer key, idempotency key) to the first admission.
    idempotency: BTreeMap<(RepoId, [u8; 32], IdempotencyKey), (WalSeq, ChangesetId)>,
    /// (repository, derivation attestation digest) to its admission (replay refusal, B5).
    derivations: BTreeMap<(RepoId, [u8; 32]), WalSeq>,
}

/// Digest of one revision record over its canonical core encodings.
fn record_digest(record: &WalRecord) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update([record.kind_byte()]);
    let mut chain = Vec::new();
    match record {
        WalRecord::RevisionAdmitted {
            envelope,
            chain: c,
            admitted_at_ms,
            new_blobs,
        } => {
            let e = envelope.encode();
            h.update((e.len() as u64).to_le_bytes());
            h.update(&e);
            c.encode_into(&mut chain);
            h.update(&chain);
            h.update(admitted_at_ms.to_le_bytes());
            h.update((new_blobs.len() as u64).to_le_bytes());
            for b in new_blobs {
                h.update(b.0);
            }
        }
        WalRecord::ObsolescenceRecorded {
            marker,
            chain: c,
            recorded_at_ms,
        } => {
            let m = marker.encode();
            h.update((m.len() as u64).to_le_bytes());
            h.update(&m);
            c.encode_into(&mut chain);
            h.update(&chain);
            h.update(recorded_at_ms.to_le_bytes());
        }
        WalRecord::DerivedRevisionAdmitted {
            derived,
            chain: c,
            admitted_at_ms,
        } => {
            let d = derived.encode();
            h.update((d.len() as u64).to_le_bytes());
            h.update(&d);
            c.encode_into(&mut chain);
            h.update(&chain);
            h.update(admitted_at_ms.to_le_bytes());
        }
        _ => {}
    }
    h.finalize().into()
}

fn not_found(msg: String) -> SynapseError {
    SynapseError::new(RefusalCode::ChangesetNotFound, msg)
}

impl RevisionLedger {
    pub(crate) fn log(&self) -> &[(WalSeq, WalRecord)] {
        &self.log
    }

    /// Rebuild a ledger from checkpointed records.
    pub(crate) fn from_log(log: Vec<(WalSeq, WalRecord)>) -> Self {
        let mut l = Self::default();
        for (seq, record) in log {
            l.apply(seq, record);
        }
        l
    }

    /// Feed the revision part of the state root (nothing when the ledger is empty, so roots
    /// of stores without revisions are unchanged).
    pub(crate) fn hash_into(log: &[(WalSeq, WalRecord)], snapshot: WalSeq, h: &mut Sha256) {
        let visible: Vec<_> = log.iter().filter(|(s, _)| *s <= snapshot).collect();
        if visible.is_empty() {
            return;
        }
        h.update(DOMAIN_STATE_ROOT_REVISIONS_V1);
        h.update((visible.len() as u64).to_le_bytes());
        for (seq, record) in visible {
            h.update(seq.0.to_le_bytes());
            h.update(record_digest(record));
        }
    }

    /// Apply one revision record (other records are ignored). Total: a record that could
    /// not have been admitted is still applied the same way on every replica.
    pub(crate) fn apply(&mut self, seq: WalSeq, record: WalRecord) {
        match &record {
            WalRecord::RevisionAdmitted {
                envelope,
                chain,
                admitted_at_ms,
                ..
            } => {
                let att = &envelope.attestation;
                let id = att.changeset_id;
                let repo = att.repo_id.clone();
                let witness =
                    AdmissionWitness::of_attestation(att, chain.clone(), seq, *admitted_at_ms);
                let entry = self
                    .changes
                    .entry((repo.clone(), envelope.content.change_id))
                    .or_default();
                if entry.creating_chain.is_none() {
                    entry.creating_chain = Some(chain.clone());
                }
                if !entry.revisions.contains(&id) {
                    entry.revisions.push(id);
                }
                self.idempotency
                    .entry((repo.clone(), att.author_key, att.idempotency_key))
                    .or_insert((seq, id));
                let rev =
                    self.revisions
                        .entry((repo.clone(), id))
                        .or_insert_with(|| StoredRevision {
                            repo_id: repo,
                            changeset_id: id,
                            content: envelope.content.clone(),
                            first_seq: seq,
                            attestations: Vec::new(),
                            derivations: Vec::new(),
                            witnesses: Vec::new(),
                        });
                rev.attestations.push(att.clone());
                rev.witnesses.push(witness);
            }
            WalRecord::DerivedRevisionAdmitted {
                derived,
                chain,
                admitted_at_ms,
            } => {
                let att = &derived.attestation;
                let id = att.output_changeset;
                let repo = att.repo_id.clone();
                let witness =
                    AdmissionWitness::of_derivation(derived, chain.clone(), seq, *admitted_at_ms);
                let entry = self
                    .changes
                    .entry((repo.clone(), derived.content.change_id))
                    .or_default();
                if entry.creating_chain.is_none() {
                    entry.creating_chain = Some(chain.clone());
                }
                if !entry.revisions.contains(&id) {
                    entry.revisions.push(id);
                }
                self.derivations
                    .entry((repo.clone(), att.digest()))
                    .or_insert(seq);
                let rev =
                    self.revisions
                        .entry((repo.clone(), id))
                        .or_insert_with(|| StoredRevision {
                            repo_id: repo,
                            changeset_id: id,
                            content: derived.content.clone(),
                            first_seq: seq,
                            attestations: Vec::new(),
                            derivations: Vec::new(),
                            witnesses: Vec::new(),
                        });
                rev.derivations.push(att.clone());
                rev.witnesses.push(witness);
            }
            WalRecord::ObsolescenceRecorded {
                marker,
                chain,
                recorded_at_ms,
            } => {
                self.changes
                    .entry((marker.repo_id.clone(), marker.change_id))
                    .or_default()
                    .markers
                    .push(RecordedMarker {
                        seq,
                        marker: marker.clone(),
                        chain: chain.clone(),
                        recorded_at_ms: *recorded_at_ms,
                    });
            }
            _ => return,
        }
        self.log.push((seq, record));
    }

    pub(crate) fn get_revision(&self, repo: &RepoId, id: ChangesetId) -> Option<&StoredRevision> {
        self.revisions.get(&(repo.clone(), id))
    }

    /// Every revision (for compaction roots).
    pub(crate) fn revisions(&self) -> impl Iterator<Item = &StoredRevision> {
        self.revisions.values()
    }

    pub(crate) fn idempotent(
        &self,
        repo: &RepoId,
        key: &[u8; 32],
        idem: IdempotencyKey,
    ) -> Option<(WalSeq, ChangesetId)> {
        self.idempotency.get(&(repo.clone(), *key, idem)).copied()
    }

    /// Join rule (ADR 0003 sections 5.1 and 5.8): a revision under an existing `ChangeId`
    /// is admitted only from a chain that descends from the creating chain, or when the
    /// leaf grant names the `ChangeId` in its change scope.
    pub(crate) fn check_join(
        &self,
        repo: &RepoId,
        change_id: ChangeId,
        authority: &AdmissionAuthority,
    ) -> SynapseResult<()> {
        let Some(creating) = self
            .changes
            .get(&(repo.clone(), change_id))
            .and_then(|e| e.creating_chain.as_ref())
        else {
            return Ok(());
        };
        if authority.chain.descends_from(creating) || authority.change_scope.contains(&change_id) {
            return Ok(());
        }
        Err(SynapseError::new(
            RefusalCode::AuthChangeOutOfScope,
            format!(
                "change {change_id} belongs to another creating chain and the grant does not name it in its change scope"
            ),
        ))
    }

    /// Checks of a derived revision at admission `WalSeq` `at` (ADR 0003 B5), shared by
    /// admission and replay verification so both refuse exactly the same records. In order:
    /// content rules, the attestation names this content and its signature verifies under the
    /// server key it names (`DerivationSignatureInvalid`); the identity documents `keys` holds
    /// belong to the attestation's repository (`DerivationIdentityRepoMismatch`); that key is
    /// the identity document's server key in effect at `at` (`DerivationServerKeyUnregistered`);
    /// the attestation was not admitted before (`DerivationAttestationReplayed`); the inputs fit
    /// the rule and are held (`DerivationInputMismatch`); recomputing the rule on them gives the
    /// attested `ChangesetId` and `TreeDigest` (`DerivationRecomputeMismatch`).
    pub(crate) fn check_derivation(
        &self,
        derived: &DerivedRevision,
        at: WalSeq,
        keys: &dyn ServerKeyRegistry,
        trees: &mut dyn DerivationTrees,
    ) -> SynapseResult<ChangesetId> {
        let id = derived.validate()?;
        let att = &derived.attestation;
        let repo = att.repo_id.clone();
        match keys.registered_server_key(&repo, at) {
            ServerKeyLookup::Registered(key) if key == att.server_key => {}
            ServerKeyLookup::Registered(_) => {
                return Err(SynapseError::new(
                    RefusalCode::DerivationServerKeyUnregistered,
                    format!(
                        "server key {} is not the server key of the identity document in effect at {at}",
                        att.server_did()
                    ),
                ))
            }
            ServerKeyLookup::NoDocument => {
                return Err(SynapseError::new(
                    RefusalCode::DerivationServerKeyUnregistered,
                    format!("no identity document of {repo} is in effect at {at}"),
                ))
            }
            ServerKeyLookup::OtherRepository(other) => {
                return Err(SynapseError::new(
                    RefusalCode::DerivationIdentityRepoMismatch,
                    format!(
                        "the identity documents checked belong to {other}, the derivation attestation names {repo}"
                    ),
                ))
            }
        }
        let digest = att.digest();
        if let Some(first) = self.derivations.get(&(repo.clone(), digest)) {
            return Err(SynapseError::new(
                RefusalCode::DerivationAttestationReplayed,
                format!(
                    "derivation attestation {} was already admitted at {first}",
                    hex::encode(digest)
                ),
            ));
        }
        let lookup =
            |input: ChangesetId| self.get_revision(&repo, input).map(|r| r.content.clone());
        let (content, tree) = derive_revision_output(att.rule, &att.inputs, &lookup, trees)?;
        let recomputed = content.changeset_id();
        if recomputed != att.output_changeset || tree != att.output_tree {
            return Err(SynapseError::new(
                RefusalCode::DerivationRecomputeMismatch,
                format!(
                    "recomputed {:?} on the named inputs gives revision {recomputed} tree {tree}, the attestation names revision {} tree {}",
                    att.rule, att.output_changeset, att.output_tree
                ),
            ));
        }
        Ok(id)
    }

    /// Checks of an obsolescence marker against the ledger. `Ok(Some(seq))` when the same
    /// predecessor and successors are already recorded (the first marker's sequence).
    pub(crate) fn plan_marker(
        &self,
        marker: &ObsolescenceMarker,
        chain: &ChainPath,
    ) -> SynapseResult<Option<WalSeq>> {
        marker.validate()?;
        let repo = &marker.repo_id;
        let entry = self
            .changes
            .get(&(repo.clone(), marker.change_id))
            .filter(|e| e.creating_chain.is_some())
            .ok_or_else(|| not_found(format!("change {} not found", marker.change_id)))?;
        for id in std::iter::once(&marker.predecessor).chain(&marker.successors) {
            if !entry.revisions.contains(id) {
                return Err(not_found(format!(
                    "revision {id} is not a revision of change {}",
                    marker.change_id
                )));
            }
        }
        if let Some(m) = entry.markers.iter().find(|m| {
            m.marker.predecessor == marker.predecessor && m.marker.successors == marker.successors
        }) {
            return Ok(Some(m.seq));
        }
        // No cycles: no successor may already lead back to the predecessor.
        let mut seen = BTreeSet::new();
        let mut work: Vec<ChangesetId> = marker.successors.clone();
        while let Some(id) = work.pop() {
            if id == marker.predecessor {
                return Err(SynapseError::new(
                    RefusalCode::ObsolescenceMarkerInvalid,
                    format!("marker would make revision {id} its own successor"),
                ));
            }
            if seen.insert(id) {
                for m in entry.markers.iter().filter(|m| m.marker.predecessor == id) {
                    work.extend(m.marker.successors.iter().copied());
                }
            }
        }
        let creating = entry.creating_chain.as_ref().expect("filtered above");
        let allowed = match marker.kind() {
            ObsolescenceKind::Pruned => chain.dominates(creating),
            ObsolescenceKind::Rewritten | ObsolescenceKind::Split => {
                chain.dominates(creating)
                    || self
                        .get_revision(repo, marker.predecessor)
                        .and_then(|r| r.witnesses.first())
                        .is_some_and(|w| chain.dominates(&w.chain))
            }
        };
        if !allowed {
            return Err(SynapseError::new(
                RefusalCode::AuthChainNotDominant,
                format!(
                    "{:?} of revision {} needs a chain that is or dominates the creating chain of change {}",
                    marker.kind(),
                    marker.predecessor,
                    marker.change_id
                ),
            ));
        }
        Ok(None)
    }

    pub(crate) fn change_status(&self, repo: &RepoId, change_id: ChangeId) -> Option<ChangeStatus> {
        let entry = self.changes.get(&(repo.clone(), change_id))?;
        let creating_chain = entry.creating_chain.clone()?;
        let obsoleted: BTreeSet<ChangesetId> =
            entry.markers.iter().map(|m| m.marker.predecessor).collect();
        let (obsolete, live): (Vec<_>, Vec<_>) = entry
            .revisions
            .iter()
            .copied()
            .partition(|id| obsoleted.contains(id));
        Some(ChangeStatus {
            repo_id: repo.clone(),
            change_id,
            creating_chain,
            revisions: entry.revisions.clone(),
            divergent: live.len() > 1,
            live,
            obsolete,
            markers: entry.markers.clone(),
        })
    }
}

/// Replica verification of revision records (ADR 0003 B5): replay `records` in `WalSeq`
/// order into a fresh ledger and refuse the first record that could not have been admitted
/// on its own evidence. An agent revision (kind 7) must carry a strictly verifying agent
/// signature over its own content: a derived revision presented with an agent signature it
/// does not have is refused (`AuthSignatureInvalid`). A marker (kind 8) must verify. A derived
/// revision (kind 11) must pass the admission checks of its derivation at its own `WalSeq`
/// (signature, server key registered then, not a replay, inputs admitted before it, the same
/// digests on recomputation). The refusal keeps its code and names the record's `WalSeq`.
/// Returns the number of records verified. Authorization (chains, join rule) and blobs are
/// not re-checked here.
pub fn verify_revision_log(
    records: &[(WalSeq, WalRecord)],
    keys: &dyn ServerKeyRegistry,
    trees: &mut dyn DerivationTrees,
) -> SynapseResult<usize> {
    let mut ledger = RevisionLedger::default();
    let mut prev: Option<WalSeq> = None;
    for (seq, record) in records {
        let at_seq = |e: SynapseError| {
            SynapseError::new(e.code, format!("revision record at {seq}: {}", e.message))
        };
        if prev.is_some_and(|p| p >= *seq) {
            return Err(SynapseError::new(
                RefusalCode::WalSequenceGap,
                format!("revision record at {seq} does not follow the previous record"),
            ));
        }
        prev = Some(*seq);
        match record {
            WalRecord::RevisionAdmitted { envelope, .. } => {
                envelope.validate().map_err(at_seq)?;
            }
            WalRecord::ObsolescenceRecorded { marker, .. } => {
                marker.validate().map_err(at_seq)?;
            }
            WalRecord::DerivedRevisionAdmitted { derived, .. } => {
                ledger
                    .check_derivation(derived, *seq, keys, trees)
                    .map_err(at_seq)?;
            }
            other => {
                return Err(SynapseError::new(
                    RefusalCode::WalRecordMalformed,
                    format!(
                        "record of kind {} at {seq} is not a revision record",
                        other.kind_byte()
                    ),
                ))
            }
        }
        ledger.apply(*seq, record.clone());
    }
    Ok(records.len())
}

impl crate::SynapseStore {
    /// Admit an envelope v2 revision under `authority` at server time `now_ms` (ADR 0003
    /// B1). Checks, in order: the envelope (content rules, attestation names this content,
    /// strict signature); idempotency on (repository, signer key, `IdempotencyKey`), where a
    /// repeat with the same revision returns the first `WalSeq` and any other revision is
    /// `IdempotencyKeyConflict`; the path-count limit; the join rule
    /// (`AuthChangeOutOfScope`); parents (an admitted revision or a v1 changeset of the same
    /// repository); blobs (provided with the declared digest and size, or already visible).
    /// Identical content already admitted gains one more attestation and witness.
    pub fn admit_revision(
        &mut self,
        envelope: ChangesetEnvelopeV2,
        blobs: &[(BlobDigest, Vec<u8>)],
        authority: AdmissionAuthority,
        now_ms: u64,
    ) -> SynapseResult<RevisionOutcome> {
        self.check_writable()?;
        self.check_binary_codec()?;
        let id = envelope.validate()?;
        let content = &envelope.content;
        let att = &envelope.attestation;
        let repo = att.repo_id.clone();
        if let Some((wal_seq, existing)) =
            self.revisions
                .idempotent(&repo, &att.author_key, att.idempotency_key)
        {
            if existing == id {
                return Ok(RevisionOutcome::IdempotentDuplicate {
                    wal_seq,
                    changeset_id: id,
                });
            }
            return Err(SynapseError::new(
                RefusalCode::IdempotencyKeyConflict,
                format!(
                    "idempotency key {} of {} already bound to revision {existing}, cannot rebind to {id}",
                    att.idempotency_key.to_hex(),
                    att.author_did()
                ),
            ));
        }
        if content.mutations.len() > self.limits.max_paths_per_changeset {
            return Err(SynapseError::new(
                RefusalCode::QuotaTooManyPaths,
                format!(
                    "revision touches {} paths, exceeding limit {}",
                    content.mutations.len(),
                    self.limits.max_paths_per_changeset
                ),
            ));
        }
        self.revisions
            .check_join(&repo, content.change_id, &authority)?;
        self.check_revision_parents(&repo, content)?;
        let mut provided: BTreeMap<BlobDigest, &[u8]> = BTreeMap::new();
        let mut total = 0u64;
        for (declared, bytes) in blobs {
            let len = bytes.len() as u64;
            total = total.saturating_add(len);
            if len > self.limits.max_blob_bytes || total > self.limits.max_total_changeset_bytes {
                return Err(SynapseError::new(
                    RefusalCode::QuotaPayloadTooLarge,
                    "revision blobs exceed max_blob_bytes or max_total_changeset_bytes",
                ));
            }
            let actual = BlobDigest::compute(bytes);
            if actual != *declared {
                return Err(SynapseError::new(
                    RefusalCode::BlobDigestMismatch,
                    format!("declared blob digest {declared} does not match computed {actual}"),
                ));
            }
            provided.insert(*declared, bytes.as_slice());
        }
        let mut inline: Vec<(BlobDigest, &[u8])> = Vec::new();
        for m in &content.mutations {
            if let MutationOp::Upsert {
                blob_digest,
                size_bytes,
                ..
            } = &m.op
            {
                if let Some(raw) = provided.get(blob_digest) {
                    if raw.len() as u64 != *size_bytes {
                        return Err(SynapseError::new(
                            RefusalCode::BlobDigestMismatch,
                            format!(
                                "mutation path {} declared size {size_bytes} but blob is {} bytes",
                                m.path,
                                raw.len()
                            ),
                        ));
                    }
                    if !inline.iter().any(|(d, _)| d == blob_digest) {
                        inline.push((*blob_digest, raw));
                    }
                } else if !self.blob_first_visible_seq.contains_key(blob_digest) {
                    return Err(SynapseError::new(
                        RefusalCode::BlobNotFound,
                        format!(
                            "mutation path {} references missing blob {blob_digest}",
                            m.path
                        ),
                    ));
                }
            }
        }
        let joined_existing_revision = self.revisions.get_revision(&repo, id).is_some();
        let record = WalRecord::RevisionAdmitted {
            envelope,
            chain: authority.chain,
            admitted_at_ms: now_ms,
            new_blobs: inline.iter().map(|(d, _)| *d).collect(),
        };
        let wal_seq = self.append_revision_record(record, &inline, None)?;
        Ok(RevisionOutcome::Admitted {
            wal_seq,
            changeset_id: id,
            joined_existing_revision,
        })
    }

    /// Parents of a revision: each an admitted revision or a v1 changeset of `repo`.
    fn check_revision_parents(
        &self,
        repo: &RepoId,
        content: &RevisionContent,
    ) -> SynapseResult<()> {
        for parent in &content.parents {
            let parent_repo = if self.revisions.get_revision(repo, *parent).is_some() {
                repo
            } else if let Some(cs) = self.changesets.get(parent) {
                &cs.envelope.repo_id
            } else {
                return Err(SynapseError::new(
                    RefusalCode::ParentChangesetNotFound,
                    format!("parent {parent} not found"),
                ));
            };
            if parent_repo != repo {
                return Err(SynapseError::new(
                    RefusalCode::AuthCrossRepoDenied,
                    "parent changeset belongs to a different repository",
                ));
            }
        }
        Ok(())
    }

    /// Admit a server-derived revision (ADR 0003 B5) under `authority` at server time
    /// `now_ms`. `keys` answers which server key the repository identity document registered
    /// at the admission `WalSeq`; `trees` is the tree store the rule is recomputed on. Checks,
    /// in order: the derivation (see `RevisionLedger::check_derivation`: signature, registered
    /// key, replay, inputs, recomputation); the path-count limit; the join rule against the
    /// change's creating chain (`AuthChangeOutOfScope`); parents; every upserted blob already
    /// visible (`BlobNotFound`: a derived revision brings no new content). Nothing is written
    /// on a refusal. The witness records the server key, its signature, and the attestation
    /// digest; no agent signature is recorded or claimed.
    pub fn admit_derived_revision(
        &mut self,
        derived: DerivedRevision,
        authority: AdmissionAuthority,
        keys: &dyn ServerKeyRegistry,
        trees: &mut dyn DerivationTrees,
        now_ms: u64,
    ) -> SynapseResult<RevisionOutcome> {
        self.check_writable()?;
        self.check_binary_codec()?;
        let at = self.committed_seq().next();
        let id = self.revisions.check_derivation(&derived, at, keys, trees)?;
        let content = &derived.content;
        let repo = derived.attestation.repo_id.clone();
        if content.mutations.len() > self.limits.max_paths_per_changeset {
            return Err(SynapseError::new(
                RefusalCode::QuotaTooManyPaths,
                format!(
                    "revision touches {} paths, exceeding limit {}",
                    content.mutations.len(),
                    self.limits.max_paths_per_changeset
                ),
            ));
        }
        self.revisions
            .check_join(&repo, content.change_id, &authority)?;
        self.check_revision_parents(&repo, content)?;
        for m in &content.mutations {
            if let MutationOp::Upsert { blob_digest, .. } = &m.op {
                if !self.blob_first_visible_seq.contains_key(blob_digest) {
                    return Err(SynapseError::new(
                        RefusalCode::BlobNotFound,
                        format!(
                            "derived mutation path {} references blob {blob_digest}, which is not visible",
                            m.path
                        ),
                    ));
                }
            }
        }
        let joined_existing_revision = self.revisions.get_revision(&repo, id).is_some();
        let record = WalRecord::DerivedRevisionAdmitted {
            derived,
            chain: authority.chain,
            admitted_at_ms: now_ms,
        };
        let wal_seq = self.append_revision_record(record, &[], Some(at))?;
        Ok(RevisionOutcome::Admitted {
            wal_seq,
            changeset_id: id,
            joined_existing_revision,
        })
    }

    /// Every revision record (kinds 7, 8 and 11) this store holds, in `WalSeq` order: what a
    /// replica replays and verifies with [`verify_revision_log`].
    pub fn revision_records(&self) -> &[(WalSeq, WalRecord)] {
        self.revisions.log()
    }

    /// [`verify_revision_log`] over this store's revision records.
    pub fn verify_revisions(
        &self,
        keys: &dyn ServerKeyRegistry,
        trees: &mut dyn DerivationTrees,
    ) -> SynapseResult<usize> {
        verify_revision_log(self.revisions.log(), keys, trees)
    }

    /// Record an obsolescence marker authorized under `chain` at server time `now_ms`. A
    /// prune needs a chain that is or dominates the change's creating chain; a rewrite or a
    /// split needs that, or a chain that is or dominates the chain of the predecessor's first
    /// admission (`AuthChainNotDominant` otherwise). Predecessor and successors must be
    /// revisions of the marker's change (`ChangesetNotFound`); a marker that would close a
    /// cycle is `ObsolescenceMarkerInvalid`. The same predecessor and successors recorded
    /// again return the first marker's `WalSeq`.
    pub fn record_obsolescence(
        &mut self,
        marker: ObsolescenceMarker,
        chain: ChainPath,
        now_ms: u64,
    ) -> SynapseResult<WalSeq> {
        self.check_writable()?;
        self.check_binary_codec()?;
        if let Some(seq) = self.revisions.plan_marker(&marker, &chain)? {
            return Ok(seq);
        }
        let record = WalRecord::ObsolescenceRecorded {
            marker,
            chain,
            recorded_at_ms: now_ms,
        };
        self.append_revision_record(record, &[], None)
    }

    /// An admitted revision of `repo_id`.
    pub fn get_revision(
        &self,
        repo_id: &RepoId,
        changeset_id: ChangesetId,
    ) -> SynapseResult<StoredRevision> {
        self.revisions
            .get_revision(repo_id, changeset_id)
            .cloned()
            .ok_or_else(|| not_found(format!("revision {changeset_id} not found")))
    }

    /// Creating chain, revisions, live and obsolete revisions, and divergence of a change.
    pub fn change_status(
        &self,
        repo_id: &RepoId,
        change_id: ChangeId,
    ) -> SynapseResult<ChangeStatus> {
        self.revisions
            .change_status(repo_id, change_id)
            .ok_or_else(|| not_found(format!("change {change_id} not found")))
    }

    fn check_binary_codec(&self) -> SynapseResult<()> {
        if self.codec == crate::RecordCodec::JsonV1 {
            return Err(SynapseError::new(
                RefusalCode::EnvelopeVersionUnsupported,
                "this store still writes v1 JSON records: envelope v2 needs the binary codec (run the migration checkpoint first)",
            ));
        }
        Ok(())
    }

    /// Append one revision record (blobs inline in the segment store, blob files first in
    /// the `wal.log` layout) and apply it. With `checked_at`, the record was checked against
    /// that `WalSeq` (a derivation against the identity document in effect there) and must be
    /// written at exactly that sequence: a writer whose next sequence differs is refused
    /// before anything is written, and a frame that lands at another sequence anyway is not
    /// applied and poisons the store (`WalSequenceGap` in both cases), so a record is never
    /// admitted at a sequence it was not checked at. Real checks in every build profile.
    fn append_revision_record(
        &mut self,
        record: WalRecord,
        blobs: &[(BlobDigest, &[u8])],
        checked_at: Option<WalSeq>,
    ) -> SynapseResult<WalSeq> {
        if self.v2_mode {
            let encoded = crate::wal2::encode_record(&record, blobs, self.codec)?;
            self.check_frame_cap(encoded.payload.len())?;
            let mut ticket = self.v2_begin()?;
            if let Some(err) =
                checked_at.and_then(|at| sequence_mismatch(at, ticket.base_seq.next(), false))
            {
                // Hand the writer back untouched; the refusal is the result.
                let refused = self.v2_finish(
                    ticket,
                    Err(crate::wal2::BatchFailure::RolledBack(err.clone())),
                );
                return Err(refused.err().unwrap_or(err));
            }
            let result = Self::v2_write(&mut ticket, &[&encoded]);
            let placed = self.v2_finish(ticket, result)?;
            let seq = placed[0].seq;
            self.refuse_misplaced(checked_at, seq)?;
            self.apply_v2_ingest(&placed[0], record, &encoded.inline);
            return Ok(seq);
        }
        if let Some(err) =
            checked_at.and_then(|at| sequence_mismatch(at, self.committed_seq.next(), false))
        {
            return Err(err);
        }
        let payload = self.encode_v1_payload(&record)?;
        for (digest, bytes) in blobs {
            self.write_blob_file(*digest, bytes)?;
        }
        let (seq, _, _) = self.append_v1_payload(record.kind_byte(), &payload)?;
        self.refuse_misplaced(checked_at, seq)?;
        self.apply_record(seq, record);
        Ok(seq)
    }

    /// After a durable write: a record checked at `checked_at` that landed at `seq` instead
    /// is not applied, and the store refuses writes until it is reopened.
    fn refuse_misplaced(&mut self, checked_at: Option<WalSeq>, seq: WalSeq) -> SynapseResult<()> {
        match checked_at.and_then(|at| sequence_mismatch(at, seq, true)) {
            Some(err) => {
                self.poisoned = Some(err.message.clone());
                Err(err)
            }
            None => Ok(()),
        }
    }
}

/// `WalSequenceGap` when a record checked at `checked_at` would be (`written == false`) or was
/// (`written == true`) placed at `seq`.
fn sequence_mismatch(checked_at: WalSeq, seq: WalSeq, written: bool) -> Option<SynapseError> {
    (checked_at != seq).then(|| {
        SynapseError::new(
            RefusalCode::WalSequenceGap,
            if written {
                format!("record checked at {checked_at} was written at {seq}; it is not applied and the store refuses writes until it is reopened")
            } else {
                format!("record checked at {checked_at} would be written at {seq}; nothing was written")
            },
        )
    })
}
