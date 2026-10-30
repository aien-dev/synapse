//! Revision ledger: envelope v2 revisions, their change identities, admission witnesses,
//! obsolescence markers (ADR 0003 section 5.1, step B1; `docs/B1_CHANGE_IDENTITY.md`), and
//! revision states with owner-chain visibility (section 5.3, step B4;
//! `docs/B4_REVISION_STATES.md`).
//!
//! The ledger is a pure function of the revision records (`RevisionAdmitted`,
//! `ObsolescenceRecorded`, `RevisionStateMoved`) applied in `WalSeq` order: replay, a
//! checkpoint (which keeps the records themselves), and a live store all rebuild exactly the
//! same ledger. v1 changesets stay in their own map with their own IDs; the two ID domains
//! never meet.

use crate::seal::{next_head, RevisionSealKey};
use crate::{SignedStateMove, StateMoveFault, WalRecord};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use synapse_core::{
    derive_revision_output, AdmissionWitness, AuthorshipAttestation, BlobDigest, ChainPath,
    ChangeId, ChangesetEnvelopeV2, ChangesetId, DerivationAttestation, DerivationTrees,
    DerivedRevision, IdempotencyKey, MutationOp, ObsolescenceKind, ObsolescenceMarker, RefusalCode,
    RepoId, RevisionContent, RevisionState, ServerKeyLookup, ServerKeyRegistry, SynapseError,
    SynapseResult, WalSeq,
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
    /// Current state (step B4): `Private` from the first admission; it only moves forward.
    pub state: RevisionState,
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

/// What replay did with WAL kind 9 state moves that changed nothing (ADR 0003 B4, issue
/// #89). A live store writes only moves that verify and are owner moves, so every count here
/// is a record written without the store: a forgery or a bug, never a normal event.
/// `StrictFailClosed` recovery refuses a store with any unverified move
/// (`RevisionStateMoveUnverified`); `TruncateTornTail` opens it with the moves applied as
/// no-ops and reports them here.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct StateMoveReplayReport {
    /// Moves whose mover signature does not verify strictly.
    pub signature_invalid: u64,
    /// Moves whose mover key is not the audience of their chain's leaf link.
    pub signer_not_chain_leaf: u64,
    /// Verified moves that are not owner moves: not by an owner chain, not an edge the owner
    /// may take, or naming an unknown revision (#88's replay rule; kept, change nothing).
    pub not_owner_move: u64,
    /// Sequence of the first unverified move (signature or leaf), for the refusal message.
    pub first_unverified: Option<(WalSeq, StateMoveFault)>,
    /// Unverified moves this process left out of a checkpoint (`checkpoint_and_compact`
    /// under `TruncateTornTail`), so they are gone from the store and strict recovery
    /// accepts it again. Not persisted: a reopened store reports zero.
    pub dropped_by_compaction: u64,
}

impl StateMoveReplayReport {
    /// Moves that do not verify (signature or leaf).
    pub fn unverified(&self) -> u64 {
        self.signature_invalid + self.signer_not_chain_leaf
    }
}

/// What replay did with revision records whose keyed seal (issue #101) did not verify, in a
/// store opened with a seal key. A sealing store writes only sealed records, so every count
/// here is a record written without the server's key: a forgery, a removed or reordered
/// record (which breaks the seal chain from there on), or a record from before the store was
/// sealed. Such records stay in the log but change nothing. `StrictFailClosed` recovery
/// refuses the store (`RevisionRecordUnsealed`); `TruncateTornTail` opens it and reports them
/// here. All zero in a store opened without a seal key (seals are then not checked).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SealReplayReport {
    /// Revision records whose seal is missing or does not verify against the chain so far.
    pub unsealed: u64,
    /// Sequence of the first such record, for the refusal message.
    pub first_unsealed: Option<WalSeq>,
    /// Unsealed records this process left out of a checkpoint (`checkpoint_and_compact`
    /// under `TruncateTornTail`). Not persisted: a reopened store reports zero.
    pub dropped_by_compaction: u64,
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
    /// Kind 9 records that changed nothing, by reason.
    state_moves: StateMoveReplayReport,
    /// (repository, derivation attestation digest) to its admission (replay refusal, B5).
    derivations: BTreeMap<(RepoId, [u8; 32]), WalSeq>,
    /// Public half of the seal key (issue #101): when set, a revision record is applied only
    /// if its seal verifies against `seal_head`.
    seal_key: Option<[u8; 32]>,
    /// Head of the seal chain after the last sealed record applied (zero before the first).
    seal_head: [u8; 32],
    /// Revision records whose seal did not verify (applied as nothing).
    unsealed: BTreeSet<WalSeq>,
    seals: SealReplayReport,
}

/// What a checkpoint keeps of the revision log, and what it leaves out.
pub(crate) struct CompactedRevisionLog {
    pub(crate) log: Vec<(WalSeq, WalRecord)>,
    pub(crate) dropped_moves: u64,
    pub(crate) dropped_unsealed: u64,
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
            ..
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
            ..
        } => {
            let m = marker.encode();
            h.update((m.len() as u64).to_le_bytes());
            h.update(&m);
            c.encode_into(&mut chain);
            h.update(&chain);
            h.update(recorded_at_ms.to_le_bytes());
        }
        WalRecord::RevisionStateMoved {
            state_move: m,
            moved_at_ms,
            ..
        } => {
            h.update((m.repo_id.as_str().len() as u64).to_le_bytes());
            h.update(m.repo_id.as_str().as_bytes());
            h.update(m.changeset_id.0);
            h.update([m.to.tag_byte()]);
            m.chain.encode_into(&mut chain);
            h.update(&chain);
            h.update(moved_at_ms.to_le_bytes());
            h.update(m.signed_at_ms.to_le_bytes());
            let link = m.leaf_link.encode();
            h.update((link.len() as u64).to_le_bytes());
            h.update(&link);
            h.update(m.mover_key);
            h.update(m.signature);
        }
        WalRecord::DerivedRevisionAdmitted {
            derived,
            chain: c,
            admitted_at_ms,
            ..
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

/// Owner chain rule (ADR 0003 section 5.3, step B4): `chain` owns a revision when it is, or
/// dominates, the chain of the revision's first admission (the key that submitted it and the
/// keys its grant descends from). A later admission of identical content (a B1 join) adds a
/// witness but never an owner: otherwise a joiner could read the owner's authorship records
/// and publish its `Private` attempt without the owner's consent.
fn owned_by(rev: &StoredRevision, chain: &ChainPath) -> bool {
    rev.witnesses
        .first()
        .is_some_and(|w| chain.dominates(&w.chain))
}

/// A `Private` revision is visible only to its owner chain; every later state is visible to
/// any chain (path `Read` scope is the API's filter).
fn visible_to(rev: &StoredRevision, viewer: &ChainPath) -> bool {
    rev.state != RevisionState::Private || owned_by(rev, viewer)
}

impl RevisionLedger {
    pub(crate) fn log(&self) -> &[(WalSeq, WalRecord)] {
        &self.log
    }

    /// Kind 9 records that changed nothing, by reason (issue #89).
    pub(crate) fn state_move_report(&self) -> StateMoveReplayReport {
        self.state_moves
    }

    /// What a checkpoint keeps: the log without the records that changed nothing because
    /// they do not verify, and how many were left out. Unsealed records (issue #101) go,
    /// since they never joined the seal chain; so do kind 9 records that do not verify
    /// (review of PR #100), unless they are sealed: removing a sealed record would break
    /// the chain of every later one. Verified moves that changed nothing stay.
    pub(crate) fn compacted_log(&self) -> CompactedRevisionLog {
        let mut out = CompactedRevisionLog {
            log: Vec::with_capacity(self.log.len()),
            dropped_moves: 0,
            dropped_unsealed: 0,
        };
        for (seq, record) in &self.log {
            if self.unsealed.contains(seq) {
                out.dropped_unsealed += 1;
                continue;
            }
            if let WalRecord::RevisionStateMoved { state_move, .. } = record {
                if self.seal_key.is_none() && state_move.verify().is_err() {
                    out.dropped_moves += 1;
                    continue;
                }
            }
            out.log.push((*seq, record.clone()));
        }
        out
    }

    /// Rebuild from the log a checkpoint kept, recording what it left out.
    pub(crate) fn rebuild_after_compaction(&mut self, compacted: CompactedRevisionLog) {
        let moves = self.state_moves.dropped_by_compaction + compacted.dropped_moves;
        let unsealed = self.seals.dropped_by_compaction + compacted.dropped_unsealed;
        *self = Self::from_log(compacted.log, self.seal_key);
        self.state_moves.dropped_by_compaction = moves;
        self.seals.dropped_by_compaction = unsealed;
    }

    /// An empty ledger that checks seals under `seal_key` when it is set (issue #101).
    pub(crate) fn new(seal_key: Option<[u8; 32]>) -> Self {
        Self {
            seal_key,
            ..Self::default()
        }
    }

    /// Rebuild a ledger from checkpointed records.
    pub(crate) fn from_log(log: Vec<(WalSeq, WalRecord)>, seal_key: Option<[u8; 32]>) -> Self {
        let mut l = Self::new(seal_key);
        for (seq, record) in log {
            l.apply(seq, record);
        }
        l
    }

    /// Unsealed revision records replay kept as no-ops (issue #101).
    pub(crate) fn seal_report(&self) -> SealReplayReport {
        self.seals
    }

    /// The seal head `record` at `seq` moves the chain to, when its seal verifies against the
    /// chain so far; `None` when it does not (and the record must change nothing).
    fn sealed_head(&self, key: &[u8; 32], seq: WalSeq, record: &WalRecord) -> Option<[u8; 32]> {
        let head = next_head(&self.seal_head, seq, &record_digest(record));
        record
            .seal()
            .is_some_and(|s| s.verifies(key, &head))
            .then_some(head)
    }

    /// Whether `record` at `seq` would take effect: always without a seal key, else only when
    /// its seal verifies against the chain so far (issue #101).
    pub(crate) fn accepts(&self, seq: WalSeq, record: &WalRecord) -> bool {
        match self.seal_key {
            Some(key) if record.is_revision_record() => {
                self.sealed_head(&key, seq, record).is_some()
            }
            _ => true,
        }
    }

    /// Seal `record`, to be written at `seq`, as the next link of this ledger's chain.
    pub(crate) fn seal_record(&self, key: &RevisionSealKey, seq: WalSeq, record: &mut WalRecord) {
        let head = next_head(&self.seal_head, seq, &record_digest(record));
        record.set_seal(key.seal(&head));
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
        if !record.is_revision_record() {
            return;
        }
        // Issue #101: in a sealed store a revision record counts only when the server's seal
        // over the chain so far verifies; nothing in it (not even its unsigned `chain`) can
        // then have been changed, inserted, reordered, or removed without the key.
        if let Some(key) = self.seal_key {
            if let Some(head) = self.sealed_head(&key, seq, &record) {
                self.seal_head = head;
            } else {
                self.seals.unsealed += 1;
                self.seals.first_unsealed.get_or_insert(seq);
                self.unsealed.insert(seq);
                self.log.push((seq, record));
                return;
            }
        }
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
                            state: RevisionState::Private,
                        });
                rev.attestations.push(att.clone());
                rev.witnesses.push(witness);
            }
            WalRecord::DerivedRevisionAdmitted {
                derived,
                chain,
                admitted_at_ms,
                ..
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
                            state: RevisionState::Private,
                        });
                rev.derivations.push(att.clone());
                rev.witnesses.push(witness);
            }
            WalRecord::ObsolescenceRecorded {
                marker,
                chain,
                recorded_at_ms,
                ..
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
            WalRecord::RevisionStateMoved { state_move: m, .. } => {
                // Kind 9 is permanently the owner-move record: `Verified` and `Canonical` come
                // only from the evidence-bearing records of B3, E1, and E2. The WAL seal is
                // unkeyed (CRC32C and an unkeyed hash chain detect corruption, not forgery),
                // so replay applies a move only when (1) its mover signature verifies strictly
                // and the mover key is the audience of the chain's leaf link (issue #89), and
                // (2) it is an owner move (`Private -> Draft`, `Private -> Proposed`,
                // `Draft -> Proposed`, by a chain that is or dominates the first admission's
                // chain; #88). Both are pure functions of the record and the log that never
                // change, so an old log keeps its meaning. Any other record stays in the log
                // and the state root but changes nothing; it is counted in the replay report,
                // and strict recovery refuses a store with an unverified one.
                match m.verify() {
                    Err(fault) => {
                        let r = &mut self.state_moves;
                        match fault {
                            StateMoveFault::SignatureInvalid => r.signature_invalid += 1,
                            StateMoveFault::SignerNotChainLeaf => r.signer_not_chain_leaf += 1,
                        }
                        r.first_unverified.get_or_insert((seq, fault));
                    }
                    Ok(()) => {
                        let rev = self.revisions.get_mut(&(m.repo_id.clone(), m.changeset_id));
                        match rev {
                            Some(rev)
                                if owned_by(rev, &m.chain)
                                    && rev.state.check_owner_move(m.to).is_ok() =>
                            {
                                rev.state = m.to;
                            }
                            _ => self.state_moves.not_owner_move += 1,
                        }
                    }
                }
            }
            _ => return,
        }
        self.log.push((seq, record));
    }

    pub(crate) fn get_revision(&self, repo: &RepoId, id: ChangesetId) -> Option<&StoredRevision> {
        self.revisions.get(&(repo.clone(), id))
    }

    /// The revision if `viewer` may see it; `None` both when it does not exist and when it
    /// is another owner's `Private` revision, so the two cannot be told apart.
    pub(crate) fn get_visible(
        &self,
        repo: &RepoId,
        id: ChangesetId,
        viewer: &ChainPath,
    ) -> Option<&StoredRevision> {
        self.get_revision(repo, id)
            .filter(|rev| visible_to(rev, viewer))
    }

    /// Checks of a signed state move (steps B4 and issue #89). A move to `Canonical` is
    /// refused first, whatever the revision (`CanonicalOutsidePromotionQueue`); then a
    /// signature that does not verify, or a mover key that is not the audience of the
    /// chain's leaf link, is `AuthSignatureInvalid`; a revision the chain cannot see is
    /// `ChangesetNotFound`; a chain that is not the owner chain is `AuthChainNotDominant`;
    /// then the owner-move rule of `RevisionState`.
    pub(crate) fn plan_move(&self, m: &SignedStateMove) -> SynapseResult<()> {
        let (id, to, chain) = (m.changeset_id, m.to, &m.chain);
        if to == RevisionState::Canonical {
            return Err(SynapseError::new(
                RefusalCode::CanonicalOutsidePromotionQueue,
                format!(
                    "revision {id} -> Canonical: canonical moves only through the promotion queue"
                ),
            ));
        }
        m.verify().map_err(StateMoveFault::into_error)?;
        let rev = self
            .get_visible(&m.repo_id, id, chain)
            .ok_or_else(|| not_found(format!("revision {id} not found")))?;
        if !owned_by(rev, chain) {
            return Err(SynapseError::new(
                RefusalCode::AuthChainNotDominant,
                format!(
                    "moving revision {id} needs a chain that is or dominates the chain of its first admission"
                ),
            ));
        }
        rev.state.check_owner_move(to)
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
    /// the rule and are held where `viewer` may see them, so another owner's `Private` revision
    /// counts as not held (step B4, `DerivationInputMismatch`); recomputing the rule on them
    /// gives the attested `ChangesetId` and `TreeDigest` (`DerivationRecomputeMismatch`).
    pub(crate) fn check_derivation(
        &self,
        derived: &DerivedRevision,
        at: WalSeq,
        viewer: &ChainPath,
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
        // Another owner's `Private` revision is not an input this chain can name (B4).
        let lookup = |input: ChangesetId| {
            self.get_visible(&repo, input, viewer)
                .map(|r| r.content.clone())
        };
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
            // Another owner's `Private` revision is refused exactly like an unknown one (B4).
            if !entry.revisions.contains(id) || self.get_visible(repo, *id, chain).is_none() {
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

    /// The change as `viewer` may see it (step B4): only revisions visible to it, and only
    /// markers whose predecessor and successors are all visible to it; live, obsolete, and
    /// divergence are computed over those. `None` when the viewer sees no revision.
    pub(crate) fn change_status_visible(
        &self,
        repo: &RepoId,
        change_id: ChangeId,
        viewer: &ChainPath,
    ) -> Option<ChangeStatus> {
        let entry = self.changes.get(&(repo.clone(), change_id))?;
        let creating_chain = entry.creating_chain.clone()?;
        let seen = |id: &ChangesetId| self.get_visible(repo, *id, viewer).is_some();
        let revisions: Vec<ChangesetId> = entry.revisions.iter().copied().filter(seen).collect();
        if revisions.is_empty() {
            return None;
        }
        let markers: Vec<RecordedMarker> = entry
            .markers
            .iter()
            .filter(|m| seen(&m.marker.predecessor) && m.marker.successors.iter().all(seen))
            .cloned()
            .collect();
        let obsoleted: BTreeSet<ChangesetId> =
            markers.iter().map(|m| m.marker.predecessor).collect();
        let (obsolete, live): (Vec<_>, Vec<_>) = revisions
            .iter()
            .copied()
            .partition(|id| obsoleted.contains(id));
        Some(ChangeStatus {
            repo_id: repo.clone(),
            change_id,
            creating_chain,
            revisions,
            divergent: live.len() > 1,
            live,
            obsolete,
            markers,
        })
    }
}

/// Replica verification of revision records (ADR 0003 B5): replay `records` in `WalSeq`
/// order into a fresh ledger and refuse the first record that could not have been admitted
/// on its own evidence. An agent revision (kind 7) must carry a strictly verifying agent
/// signature over its own content: a derived revision presented with an agent signature it
/// does not have is refused (`AuthSignatureInvalid`). A marker (kind 8) must verify. A derived
/// revision (kind 11) must pass the admission checks of its derivation at its own `WalSeq`
/// (signature, server key registered then, not a replay, inputs admitted before it and
/// visible to the record's chain, the same digests on recomputation). A state move (kind 9)
/// must verify (`RevisionStateMoveUnverified`), the rule strict recovery applies (issue #89).
/// The refusal keeps its code and names the record's `WalSeq`. Returns the number of records
/// verified. Authorization (chains, join rule) and blobs are not re-checked here.
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
            WalRecord::DerivedRevisionAdmitted { derived, chain, .. } => {
                ledger
                    .check_derivation(derived, *seq, chain, keys, trees)
                    .map_err(at_seq)?;
            }
            WalRecord::RevisionStateMoved { state_move, .. } => {
                // The same rule as strict recovery (issue #89): a move that does not verify
                // was not written with the mover's key.
                state_move.verify().map_err(|fault| {
                    SynapseError::new(
                        RefusalCode::RevisionStateMoveUnverified,
                        format!("state move at {seq} does not verify: {fault:?}"),
                    )
                })?;
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
        self.check_revision_parents(&repo, content, &authority.chain)?;
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
            seal: None,
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
        viewer: &ChainPath,
    ) -> SynapseResult<()> {
        for parent in &content.parents {
            // Another owner's `Private` revision is not a parent this chain can name (B4).
            let parent_repo = if self.revisions.get_visible(repo, *parent, viewer).is_some() {
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
        let id = self
            .revisions
            .check_derivation(&derived, at, &authority.chain, keys, trees)?;
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
        self.check_revision_parents(&repo, content, &authority.chain)?;
        // Every upserted blob is visible already, or was produced by the recomputation above
        // (a tier T1 merged file, step D1): those are written with the record.
        let mut produced: Vec<(BlobDigest, Vec<u8>)> = Vec::new();
        for m in &content.mutations {
            if let MutationOp::Upsert { blob_digest, .. } = &m.op {
                if self.blob_first_visible_seq.contains_key(blob_digest)
                    || produced.iter().any(|(d, _)| d == blob_digest)
                {
                    continue;
                }
                match trees.produced_blob(*blob_digest) {
                    Some(bytes) if BlobDigest::compute(bytes) == *blob_digest => {
                        produced.push((*blob_digest, bytes.to_vec()));
                    }
                    _ => {
                        return Err(SynapseError::new(
                            RefusalCode::BlobNotFound,
                            format!(
                                "derived mutation path {} references blob {blob_digest}, which is not visible",
                                m.path
                            ),
                        ))
                    }
                }
            }
        }
        let blobs: Vec<(BlobDigest, &[u8])> =
            produced.iter().map(|(d, b)| (*d, b.as_slice())).collect();
        let joined_existing_revision = self.revisions.get_revision(&repo, id).is_some();
        let record = WalRecord::DerivedRevisionAdmitted {
            derived,
            chain: authority.chain,
            admitted_at_ms: now_ms,
            seal: None,
        };
        let wal_seq = self.append_revision_record(record, &blobs, Some(at))?;
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
            seal: None,
        };
        self.append_revision_record(record, &[], None)
    }

    /// Record the signed state move `state_move` at server time `now_ms` (ADR 0003 step B4,
    /// issue #89). Refused, with nothing written: any move to `Canonical`
    /// (`CanonicalOutsidePromotionQueue`: canonical moves only through the promotion queue,
    /// step E2); a mover signature that does not verify strictly, or a mover key that is not
    /// the audience of the chain's leaf link (`AuthSignatureInvalid`); a revision the chain
    /// cannot see (`ChangesetNotFound`, the same as an unknown one); a chain that is not, and
    /// does not dominate, the chain of the revision's first admission
    /// (`AuthChainNotDominant`); a move to `Verified`, or any move that is backwards, in
    /// place, or skips a state (`RevisionStateMoveInvalid`). The owner chain may move
    /// `Private -> Draft`, `Private -> Proposed`, and `Draft -> Proposed`.
    pub fn advance_revision_state(
        &mut self,
        state_move: SignedStateMove,
        now_ms: u64,
    ) -> SynapseResult<WalSeq> {
        self.check_writable()?;
        self.check_binary_codec()?;
        self.revisions.plan_move(&state_move)?;
        let record = WalRecord::RevisionStateMoved {
            state_move,
            moved_at_ms: now_ms,
            seal: None,
        };
        self.append_revision_record(record, &[], None)
    }

    /// Kind 9 records replay kept as no-ops, by reason (issue #89): unverified moves (only
    /// under `TruncateTornTail`; strict recovery refuses them) and verified moves that are
    /// not owner moves. All zero for a log written only by stores.
    pub fn state_move_replay_report(&self) -> StateMoveReplayReport {
        self.revisions.state_move_report()
    }

    /// Revision records replay kept as no-ops because their seal did not verify (issue #101;
    /// only in a store opened with [`Self::open_sealed`] under `TruncateTornTail`, since
    /// strict recovery refuses them). All zero for a log written only by this sealed store.
    pub fn seal_replay_report(&self) -> SealReplayReport {
        self.revisions.seal_report()
    }

    /// An admitted revision of `repo_id` as `viewer` may see it (step B4): another owner's
    /// `Private` revision is `ChangesetNotFound`, exactly like an unknown one.
    pub fn get_revision_visible_to(
        &self,
        repo_id: &RepoId,
        changeset_id: ChangesetId,
        viewer: &ChainPath,
    ) -> SynapseResult<StoredRevision> {
        self.revisions
            .get_visible(repo_id, changeset_id, viewer)
            .cloned()
            .ok_or_else(|| not_found(format!("revision {changeset_id} not found")))
    }

    /// A change as `viewer` may see it (step B4): only its visible revisions and the markers
    /// that name only visible revisions. `ChangesetNotFound` when the viewer sees none.
    pub fn change_status_visible_to(
        &self,
        repo_id: &RepoId,
        change_id: ChangeId,
        viewer: &ChainPath,
    ) -> SynapseResult<ChangeStatus> {
        self.revisions
            .change_status_visible(repo_id, change_id, viewer)
            .ok_or_else(|| not_found(format!("change {change_id} not found")))
    }

    /// An admitted revision of `repo_id`, whatever its state (server side: no visibility
    /// filter; reads on behalf of a key use [`Self::get_revision_visible_to`]).
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
        mut record: WalRecord,
        blobs: &[(BlobDigest, &[u8])],
        mut checked_at: Option<WalSeq>,
    ) -> SynapseResult<WalSeq> {
        // Issue #101: a sealed store seals the record for the exact sequence it is written
        // at, so it is checked at that sequence like a derivation (a record that would land
        // elsewhere is refused, one that did is not applied).
        if let Some(key) = &self.revision_seal {
            let at = checked_at.unwrap_or_else(|| self.committed_seq.next());
            self.revisions.seal_record(key, at, &mut record);
            checked_at = Some(at);
        }
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

#[cfg(test)]
mod b4_tests {
    use super::*;
    use crate::{AdmissionAuthority, FsyncPolicy, RecoveryPolicy, StoreLimits, SynapseStore};
    use ed25519_dalek::SigningKey;
    use std::path::PathBuf;
    use synapse_auth::{
        Capability, CapabilityChain, CapabilityLink, ChainQuotas, ChangeScope, LinkCaveats,
        OperationSet, PathScope, ReferenceScope, ROOT_PARENT,
    };
    use synapse_core::{FileMode, PathMutation, TreeDigest};

    struct SplitMix64(u64);

    impl SplitMix64 {
        fn next(&mut self) -> u64 {
            self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
            let mut z = self.0;
            z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
            z ^ (z >> 31)
        }

        fn below(&mut self, n: u64) -> u64 {
            self.next() % n
        }
    }

    fn repo() -> RepoId {
        RepoId::new("aien-spark/synapse").unwrap()
    }

    /// SHA-256 of a purpose and a label path: keys and nonces of these tests are derived,
    /// never fixed byte values.
    fn derived(what: &str, labels: &[u8]) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(b"synapse-store revision unit fixture\0");
        h.update(what.as_bytes());
        h.update([0]);
        h.update(labels);
        h.finalize().into()
    }

    /// The key presenting the chain with label path `labels`.
    fn key_of(labels: &[u8]) -> SigningKey {
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

    /// The last F1 link of the chain with label path `labels`: issued by the key of the
    /// parent path (a fixture authority for a root link), delegating to the key of `labels`.
    fn link_of(labels: &[u8]) -> CapabilityLink {
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

    fn chain_of(labels: &[u8]) -> CapabilityChain {
        CapabilityChain::new((1..=labels.len()).map(|n| link_of(&labels[..n])).collect())
    }

    /// Link digests of the chain with label path `labels`; label prefixes are ancestors.
    fn path(labels: &[u8]) -> ChainPath {
        ChainPath::new(
            chain_of(labels)
                .link_digests()
                .iter()
                .map(|d| d.0)
                .collect(),
        )
        .unwrap()
    }

    fn random_labels(rng: &mut SplitMix64) -> Vec<u8> {
        let len = 1 + rng.below(3) as usize;
        (0..len).map(|_| 1 + rng.below(3) as u8).collect()
    }

    /// A move of `id` to `to` signed by the leaf key of the chain with label path `labels`.
    fn signed(labels: &[u8], id: ChangesetId, to: RevisionState) -> SignedStateMove {
        SignedStateMove::sign_new(&key_of(labels), repo(), id, to, &chain_of(labels), 6_000)
            .unwrap()
    }

    /// The same move with one signature bit flipped (a resealed edit of a signed record).
    fn bad_signature(mut m: SignedStateMove) -> SignedStateMove {
        m.signature[17] ^= 0x01;
        m
    }

    /// The same move re-signed, validly, by a key that is not the chain leaf's audience.
    fn non_leaf_signer(mut m: SignedStateMove, signer: &[u8]) -> SignedStateMove {
        let k = key_of(signer);
        m.mover_key = k.verifying_key().to_bytes();
        m.signature = SignedStateMove::sign_statement(
            &k,
            &m.repo_id,
            m.changeset_id,
            m.to,
            &m.chain,
            m.signed_at_ms,
        );
        m
    }

    fn moved(state_move: SignedStateMove) -> WalRecord {
        WalRecord::RevisionStateMoved {
            state_move,
            moved_at_ms: 6_000,
            seal: None,
        }
    }

    fn body(n: u32) -> [u8; 4] {
        n.to_le_bytes()
    }

    fn admission(chain: ChainPath, author: &[u8], n: u32) -> WalRecord {
        let body = body(n);
        let content = RevisionContent {
            change_id: ChangeId([(n % 7) as u8; 16]),
            base_tree: TreeDigest([0x7E; 32]),
            parents: vec![],
            mutations: vec![PathMutation {
                path: "src/lib.rs".into(),
                op: MutationOp::Upsert {
                    mode: FileMode::Regular644,
                    blob_digest: BlobDigest::compute(&body),
                    size_bytes: body.len() as u64,
                },
            }],
            intent_summary: "implement the task".into(),
        };
        let mut idem = derived("idempotency", &n.to_le_bytes());
        idem[0] ^= author.len() as u8;
        let envelope = ChangesetEnvelopeV2::sign_new(
            &key_of(author),
            repo(),
            content,
            IdempotencyKey(idem),
            1_000,
        );
        WalRecord::RevisionAdmitted {
            envelope,
            chain,
            admitted_at_ms: 5_000,
            new_blobs: vec![],
            seal: None,
        }
    }

    /// Property (acceptance 1 of B4 and of issue #89, replay side): the ledger applies any
    /// sequence of revision records, including forged moves no store call would write
    /// (backwards, in place, skipping, to `Verified` or `Canonical`, by chains that do not
    /// own the revision, with a broken signature, or signed by a key that is not the chain
    /// leaf's audience). Only verified owner moves apply, so no revision ever moves
    /// backwards or past `Proposed`, every verified owner move moves its revision, the
    /// replay report counts every no-op by reason, and rebuilding from the log gives the
    /// same states and the same report.
    #[test]
    fn b4_property_forged_record_sequences_never_move_a_revision_backwards() {
        let mut rng = SplitMix64(0xB4_0003);
        let (mut forged_refused, mut unverified_refused) = (0u32, 0u32);
        for _case in 0..200 {
            let mut ledger = RevisionLedger::default();
            let mut ids: Vec<ChangesetId> = Vec::new();
            let mut last: BTreeMap<ChangesetId, RevisionState> = BTreeMap::new();
            let mut want = StateMoveReplayReport::default();
            for seq in 1..=60u64 {
                let record = if ids.is_empty() || rng.below(4) == 0 {
                    let n = rng.below(12) as u32;
                    let author = random_labels(&mut rng);
                    let r = admission(path(&random_labels(&mut rng)), &author, n);
                    if let WalRecord::RevisionAdmitted { envelope, .. } = &r {
                        let id = envelope.changeset_id();
                        if !ids.contains(&id) {
                            ids.push(id);
                        }
                    }
                    r
                } else {
                    let id = ids[rng.below(ids.len() as u64) as usize];
                    let to = RevisionState::ALL[rng.below(5) as usize];
                    let m = signed(&random_labels(&mut rng), id, to);
                    moved(match rng.below(6) {
                        0 => bad_signature(m),
                        1 => non_leaf_signer(m, &random_labels(&mut rng)),
                        _ => m,
                    })
                };
                let before = match &record {
                    WalRecord::RevisionStateMoved { state_move: m, .. } => {
                        let rev = ledger.get_revision(&repo(), m.changeset_id).unwrap();
                        let verified = m.verify();
                        let owner =
                            owned_by(rev, &m.chain) && rev.state.check_owner_move(m.to).is_ok();
                        match verified {
                            Err(StateMoveFault::SignatureInvalid) => want.signature_invalid += 1,
                            Err(StateMoveFault::SignerNotChainLeaf) => {
                                want.signer_not_chain_leaf += 1
                            }
                            Ok(()) if !owner => want.not_owner_move += 1,
                            Ok(()) => {}
                        }
                        if let Err(fault) = verified {
                            want.first_unverified.get_or_insert((WalSeq(seq), fault));
                            unverified_refused += 1;
                        }
                        Some((m.changeset_id, m.to, rev.state, verified.is_ok() && owner))
                    }
                    _ => None,
                };
                ledger.apply(WalSeq(seq), record);
                if let Some((id, to, from, legal)) = before {
                    let now = ledger.get_revision(&repo(), id).unwrap().state;
                    assert_eq!(
                        now,
                        if legal { to } else { from },
                        "{id}: {from:?} -> {to:?}"
                    );
                    if !legal {
                        forged_refused += 1;
                    }
                }
                for id in &ids {
                    let now = ledger.get_revision(&repo(), *id).unwrap().state;
                    let before = last.insert(*id, now).unwrap_or(RevisionState::Private);
                    assert!(now.rank() >= before.rank(), "{id}: {before:?} -> {now:?}");
                    assert!(now <= RevisionState::Proposed, "{id} reached {now:?}");
                }
            }
            assert_eq!(ledger.state_move_report(), want);
            let rebuilt = RevisionLedger::from_log(ledger.log().to_vec(), None);
            assert_eq!(rebuilt.state_move_report(), want);
            for id in &ids {
                assert_eq!(
                    rebuilt.get_revision(&repo(), *id).unwrap().state,
                    ledger.get_revision(&repo(), *id).unwrap().state
                );
            }
        }
        assert!(forged_refused > 0, "the sequences included forged moves");
        assert!(
            unverified_refused > 0,
            "the sequences included unverified moves"
        );
    }

    /// Replay applies a state move only when its mover signature verifies, its mover key is
    /// the chain leaf's audience, and it is an owner move (`Private -> Draft`,
    /// `Private -> Proposed`, `Draft -> Proposed`, by a chain that is or dominates the first
    /// admission's chain). A signed `Proposed -> Verified` record, even by the owner, is
    /// refused on replay: `Verified` comes only from B3/E1 evidence records, never kind 9.
    #[test]
    fn b4_replay_refuses_a_forged_move_to_verified() {
        let owner: &[u8] = &[1, 2];
        let record = admission(path(owner), owner, 1);
        let id = match &record {
            WalRecord::RevisionAdmitted { envelope, .. } => envelope.changeset_id(),
            _ => unreachable!(),
        };
        let mv = |to: RevisionState, labels: &[u8]| moved(signed(labels, id, to));
        let log = vec![
            (WalSeq(1), record),
            (WalSeq(2), mv(RevisionState::Proposed, owner)),
            (WalSeq(3), mv(RevisionState::Verified, owner)),
            (WalSeq(4), mv(RevisionState::Verified, &[1, 9])),
            (WalSeq(5), mv(RevisionState::Canonical, owner)),
        ];
        let replayed = RevisionLedger::from_log(log, None);
        assert_eq!(
            replayed.get_revision(&repo(), id).unwrap().state,
            RevisionState::Proposed,
            "a move to Verified or Canonical changes nothing on replay"
        );
        assert_eq!(
            replayed.log().len(),
            5,
            "kept in the log, applied as no-ops"
        );
        let report = replayed.state_move_report();
        assert_eq!(report.not_owner_move, 3);
        assert_eq!(report.unverified(), 0);
    }

    fn temp_dir(name: &str) -> PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir =
            std::env::temp_dir().join(format!("synapse-b89-{name}-{}-{nanos}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn open(dir: &PathBuf, policy: RecoveryPolicy) -> SynapseResult<SynapseStore> {
        let limits = StoreLimits {
            wal_prealloc_bytes: 64 * 1024,
            ..Default::default()
        };
        SynapseStore::open(dir, FsyncPolicy::EveryCommit, policy, limits)
    }

    /// Admit revision 1 under the chain with label path `owner`; its changeset id.
    fn admit(s: &mut SynapseStore, owner: &[u8]) -> ChangesetId {
        let WalRecord::RevisionAdmitted { envelope, .. } = admission(path(owner), owner, 1) else {
            unreachable!()
        };
        let id = envelope.changeset_id();
        let body = body(1);
        let blobs = vec![(BlobDigest::compute(&body), body.to_vec())];
        let authority = AdmissionAuthority {
            chain: path(owner),
            change_scope: Vec::new(),
        };
        s.admit_revision(envelope, &blobs, authority, 5_000)
            .unwrap();
        id
    }

    /// Issue #89 acceptance 1 (red on the #88 head, where kind 9 carried no signature): an
    /// owner move written straight into the WAL through the store's own framing (valid
    /// CRC32C and hash chain, so a resealed forgery) without the owner's key changes nothing
    /// on replay, whether its signature is broken or it is validly signed by a key that is
    /// not the chain leaf's audience. Torn-tail recovery keeps both as counted no-ops
    /// and strict recovery refuses the store (until a torn-tail compaction drops them: see
    /// `b89_torn_tail_compaction_drops_unverified_moves_so_strict_recovery_accepts_the_store`).
    #[test]
    fn b89_forged_owner_move_resealed_in_the_wal_changes_nothing_on_replay() {
        const TORN: RecoveryPolicy = RecoveryPolicy::TruncateTornTail;
        let owner: &[u8] = &[1, 2];
        let dir = temp_dir("forged");
        let mut s = open(&dir, TORN).unwrap();
        let id = admit(&mut s, owner);
        let honest = signed(owner, id, RevisionState::Draft);
        let broken = bad_signature(honest.clone());
        assert_eq!(broken.verify(), Err(StateMoveFault::SignatureInvalid));
        let impostor = non_leaf_signer(honest, &[1, 9]);
        assert_eq!(impostor.verify(), Err(StateMoveFault::SignerNotChainLeaf));
        let first = s.append_revision_record(moved(broken), &[], None).unwrap();
        s.append_revision_record(moved(impostor), &[], None)
            .unwrap();
        assert_eq!(
            s.get_revision(&repo(), id).unwrap().state,
            RevisionState::Private
        );
        drop(s);

        let check = |s: &SynapseStore| {
            assert_eq!(
                s.get_revision(&repo(), id).unwrap().state,
                RevisionState::Private,
                "a forged, resealed owner move must change nothing on replay"
            );
            let report = s.state_move_replay_report();
            assert_eq!(report.signature_invalid, 1);
            assert_eq!(report.signer_not_chain_leaf, 1);
            assert_eq!(report.not_owner_move, 0);
            assert_eq!(
                report.first_unverified,
                Some((first, StateMoveFault::SignatureInvalid))
            );
        };
        let strict_refuses = || {
            let err = open(&dir, RecoveryPolicy::StrictFailClosed).err().unwrap();
            assert_eq!(
                err.code,
                RefusalCode::RevisionStateMoveUnverified,
                "{err:?}"
            );
        };
        check(&open(&dir, TORN).unwrap());
        strict_refuses();
        check(&open(&dir, TORN).unwrap());
        strict_refuses();
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Review of PR #100 (note 1): torn-tail recovery keeps unverified kind 9 records as
    /// no-ops, but compaction must not carry them into the checkpoint, or strict recovery
    /// refuses the store forever. A torn-tail open followed by `checkpoint_and_compact`
    /// drops them (and only them), keeps every applied move, and leaves a store strict
    /// recovery accepts with the same revision states.
    #[test]
    fn b89_torn_tail_compaction_drops_unverified_moves_so_strict_recovery_accepts_the_store() {
        const TORN: RecoveryPolicy = RecoveryPolicy::TruncateTornTail;
        const STRICT: RecoveryPolicy = RecoveryPolicy::StrictFailClosed;
        let owner: &[u8] = &[1, 2];
        let dir = temp_dir("compact-forged");
        let mut s = open(&dir, TORN).unwrap();
        let id = admit(&mut s, owner);
        let honest = signed(owner, id, RevisionState::Draft);
        s.append_revision_record(moved(bad_signature(honest.clone())), &[], None)
            .unwrap();
        s.append_revision_record(moved(non_leaf_signer(honest.clone(), &[1, 9])), &[], None)
            .unwrap();
        s.advance_revision_state(honest, 6_500).unwrap();
        // A verified move that is not an owner move is an ordinary no-op and stays.
        s.append_revision_record(
            moved(signed(&[1, 9], id, RevisionState::Proposed)),
            &[],
            None,
        )
        .unwrap();
        drop(s);
        assert!(
            open(&dir, STRICT).is_err(),
            "strict refuses before compaction"
        );

        let mut s = open(&dir, TORN).unwrap();
        assert_eq!(s.state_move_replay_report().unverified(), 2);
        s.checkpoint_and_compact(7_000).unwrap();
        let check = |s: &SynapseStore| {
            assert_eq!(
                s.get_revision(&repo(), id).unwrap().state,
                RevisionState::Draft
            );
            let report = s.state_move_replay_report();
            assert_eq!(report.unverified(), 0, "{report:?}");
            assert_eq!(report.first_unverified, None);
            assert_eq!(report.not_owner_move, 1, "verified no-ops are kept");
        };
        check(&s);
        assert_eq!(s.state_move_replay_report().dropped_by_compaction, 2);
        let root = s.state_root_digest(None).unwrap();
        drop(s);
        let s = open(&dir, STRICT).expect("strict recovery accepts the compacted store");
        check(&s);
        assert_eq!(
            s.state_move_replay_report().dropped_by_compaction,
            0,
            "not persisted"
        );
        assert_eq!(s.state_root_digest(None).unwrap(), root);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Review of PR #100 (note 2): `SignedStateMove::verify` checks only that the mover key
    /// is the audience of a link whose digest ends the chain; it does not check who issued
    /// that link. A forger can mint a root link of its own, or append a link of its own
    /// under the owner's chain, and sign a move that verifies. The store is safe because it
    /// also requires the chain to be, or dominate, the first admission's chain; this test
    /// fails if replay or the store call skips that check.
    #[test]
    fn b89_a_forger_minted_leaf_link_verifies_but_never_owns_a_revision() {
        let owner: &[u8] = &[1, 2];
        let record = admission(path(owner), owner, 1);
        let id = match &record {
            WalRecord::RevisionAdmitted { envelope, .. } => envelope.changeset_id(),
            _ => unreachable!(),
        };
        let forger = key_of(&[7]);
        let forged = |parent: Option<&[u8]>| {
            let (parent_digest, mut digests) = match parent {
                None => (ROOT_PARENT, Vec::new()),
                Some(labels) => (link_of(labels).digest(), path(labels).links().to_vec()),
            };
            let link = CapabilityLink::issue(
                &forger,
                parent_digest,
                derived("forged nonce", parent.unwrap_or(&[])),
                repo(),
                forger.verifying_key().to_bytes(),
                caveats(),
            );
            digests.push(link.digest().0);
            let chain = ChainPath::new(digests).unwrap();
            let to = RevisionState::Proposed;
            SignedStateMove {
                repo_id: repo(),
                changeset_id: id,
                to,
                signature: SignedStateMove::sign_statement(&forger, &repo(), id, to, &chain, 6_000),
                chain,
                signed_at_ms: 6_000,
                leaf_link: link,
                mover_key: forger.verifying_key().to_bytes(),
            }
        };
        let moves = [forged(None), forged(Some(owner))];
        for m in &moves {
            assert_eq!(
                m.verify(),
                Ok(()),
                "verify alone accepts a forger-minted leaf"
            );
        }
        let mut log = vec![
            (WalSeq(1), record),
            (WalSeq(2), moved(signed(owner, id, RevisionState::Draft))),
        ];
        // The revision is `Draft`, so every chain sees it: only ownership can refuse.
        let shared = RevisionLedger::from_log(log.clone(), None);
        for m in &moves {
            let err = shared.plan_move(m).unwrap_err();
            assert_eq!(err.code, RefusalCode::AuthChainNotDominant);
        }
        log.extend(
            moves
                .into_iter()
                .zip(3..)
                .map(|(m, n)| (WalSeq(n), moved(m))),
        );
        let replayed = RevisionLedger::from_log(log, None);
        assert_eq!(
            replayed.get_revision(&repo(), id).unwrap().state,
            RevisionState::Draft
        );
        assert_eq!(replayed.state_move_report().not_owner_move, 2);
    }

    /// Issue #89 acceptance 2: a legitimate signed owner move round-trips write, strict
    /// replay, checkpoint, and compaction, and the state root covers it.
    #[test]
    fn b89_signed_owner_move_round_trips_replay_checkpoint_and_compaction() {
        const STRICT: RecoveryPolicy = RecoveryPolicy::StrictFailClosed;
        let owner: &[u8] = &[1, 2];
        let dir = temp_dir("legit");
        let mut s = open(&dir, STRICT).unwrap();
        let id = admit(&mut s, owner);
        let before = s.state_root_digest(None).unwrap();
        s.advance_revision_state(signed(owner, id, RevisionState::Draft), 6_000)
            .unwrap();
        let root = s.state_root_digest(None).unwrap();
        assert_ne!(root, before, "the state root covers the move");
        drop(s);
        let check = |s: &SynapseStore| {
            assert_eq!(
                s.get_revision(&repo(), id).unwrap().state,
                RevisionState::Draft
            );
            assert_eq!(
                s.state_move_replay_report(),
                StateMoveReplayReport::default()
            );
            assert_eq!(s.state_root_digest(None).unwrap(), root);
        };
        let mut s = open(&dir, STRICT).unwrap();
        check(&s);
        s.checkpoint_and_compact(7_000).unwrap();
        check(&s);
        drop(s);
        check(&open(&dir, STRICT).unwrap());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The kind 9 record digest (an input of the state root) covers every signed and
    /// unsigned field, so two logs that differ only in a signature, a mover key, or a leaf
    /// link have different state roots.
    #[test]
    fn b89_state_root_record_digest_covers_the_signature_fields() {
        let id = ChangesetId(derived("changeset", &[1]));
        let m = signed(&[1, 2], id, RevisionState::Draft);
        let base = record_digest(&moved(m.clone()));
        let mut other_leaf = m.clone();
        other_leaf.leaf_link = link_of(&[1, 9]);
        let variants = [
            bad_signature(m.clone()),
            non_leaf_signer(m.clone(), &[1, 9]),
            other_leaf,
            SignedStateMove {
                signed_at_ms: 6_001,
                ..m.clone()
            },
        ];
        for v in variants {
            assert_ne!(record_digest(&moved(v)), base);
        }
        let later = WalRecord::RevisionStateMoved {
            state_move: m,
            moved_at_ms: 6_001,
            seal: None,
        };
        assert_ne!(record_digest(&later), base);
    }

    // ---------------------------------------------------------------------------------
    // Issue #101: the keyed seal over revision records
    // ---------------------------------------------------------------------------------

    fn server_key() -> crate::RevisionSealKey {
        crate::RevisionSealKey::new(SigningKey::from_bytes(&derived("server machine key", &[])))
    }

    fn open_sealed(dir: &PathBuf, policy: RecoveryPolicy) -> SynapseResult<SynapseStore> {
        open_sealed_with(dir, policy, server_key())
    }

    fn open_sealed_with(
        dir: &PathBuf,
        policy: RecoveryPolicy,
        key: crate::RevisionSealKey,
    ) -> SynapseResult<SynapseStore> {
        let limits = StoreLimits {
            wal_prealloc_bytes: 64 * 1024,
            ..Default::default()
        };
        SynapseStore::open_sealed(dir, FsyncPolicy::EveryCommit, policy, limits, key)
    }

    /// A root link a forger minted with its own key (no repository authority signed it),
    /// delegating to itself: what a whole-log rewrite can put in an unsigned `chain` field.
    fn forger_chain() -> (SigningKey, CapabilityChain, ChainPath) {
        let forger = key_of(&[7]);
        let link = CapabilityLink::issue(
            &forger,
            ROOT_PARENT,
            derived("forged nonce", &[]),
            repo(),
            forger.verifying_key().to_bytes(),
            caveats(),
        );
        let chain = CapabilityChain::new(vec![link]);
        let digests = chain.link_digests().iter().map(|d| d.0).collect();
        (forger, chain, ChainPath::new(digests).unwrap())
    }

    fn with_chain(mut record: WalRecord, swapped: ChainPath) -> WalRecord {
        if let WalRecord::RevisionAdmitted { chain, .. } = &mut record {
            *chain = swapped;
        }
        record
    }

    /// Issue #101 acceptance 1: a whole-log rewrite that swaps an admission's chain for a
    /// forger-minted one and signs an owner move under it. Written through the store's own
    /// framing (valid CRC32C and hash chain), carrying over the honest record's seal bytes.
    /// Opened without a seal key (the behaviour on PR #100's head) the forger owns and
    /// publishes the revision; opened with the server's seal key the rewrite changes nothing:
    /// strict recovery refuses the store, torn-tail recovery applies neither record. A
    /// rewrite resealed with another key is refused the same way.
    #[test]
    fn s101_whole_log_rewrite_swapping_an_admission_chain_changes_nothing_on_sealed_replay() {
        const TORN: RecoveryPolicy = RecoveryPolicy::TruncateTornTail;
        const STRICT: RecoveryPolicy = RecoveryPolicy::StrictFailClosed;
        let owner: &[u8] = &[1, 2];
        let honest_dir = temp_dir("s101-honest");
        let mut s = open_sealed(&honest_dir, STRICT).unwrap();
        let id = admit(&mut s, owner);
        let honest = s.revision_records()[0].1.clone();
        assert!(
            honest.seal().is_some(),
            "a sealed store seals what it writes"
        );
        drop(s);

        let (forger, forger_links, forged_chain) = forger_chain();
        let forged_move = SignedStateMove::sign_new(
            &forger,
            repo(),
            id,
            RevisionState::Draft,
            &forger_links,
            6_000,
        )
        .unwrap();
        assert_eq!(forged_move.verify(), Ok(()));

        for reseal in [None, Some(crate::RevisionSealKey::new(key_of(&[8])))] {
            let dir = temp_dir("s101-forged");
            // The rewrite: a fresh log holding the swapped admission and the forged move.
            let mut w = match reseal.clone() {
                None => open(&dir, STRICT).unwrap(),
                Some(k) => open_sealed_with(&dir, STRICT, k).unwrap(),
            };
            let swapped = with_chain(honest.clone(), forged_chain.clone());
            let blob = body(1);
            w.append_revision_record(swapped, &[(BlobDigest::compute(&blob), &blob[..])], None)
                .unwrap();
            w.append_revision_record(moved(forged_move.clone()), &[], None)
                .unwrap();
            drop(w);

            // Without a seal key the rewrite takes effect: the attack of issue #101.
            let unsealed = open(&dir, STRICT).unwrap();
            let rev = unsealed.get_revision(&repo(), id).unwrap();
            assert_eq!(rev.state, RevisionState::Draft);
            assert_eq!(rev.witnesses[0].chain, forged_chain);

            let err = open_sealed(&dir, STRICT).err().unwrap();
            assert_eq!(err.code, RefusalCode::RevisionRecordUnsealed, "{err:?}");
            let s = open_sealed(&dir, TORN).unwrap();
            assert_eq!(
                s.get_revision(&repo(), id).unwrap_err().code,
                RefusalCode::ChangesetNotFound,
                "the swapped admission must change nothing"
            );
            let report = s.seal_replay_report();
            assert_eq!(report.unsealed, 2, "{report:?}");
            assert_eq!(report.first_unsealed, Some(WalSeq(1)));
            assert_eq!(
                s.state_move_replay_report(),
                StateMoveReplayReport::default(),
                "an unsealed move is not even considered"
            );
            let _ = std::fs::remove_dir_all(&dir);
        }
        let _ = std::fs::remove_dir_all(&honest_dir);
    }

    /// Records appended to a sealed store without the key (here by opening it without one)
    /// change nothing on sealed replay; the honest records keep their meaning, the store
    /// keeps sealing after them, and a torn-tail compaction drops exactly the unsealed
    /// records so strict recovery accepts the store again with the same states and root.
    #[test]
    fn s101_appended_unsealed_records_change_nothing_and_compaction_restores_strict() {
        const TORN: RecoveryPolicy = RecoveryPolicy::TruncateTornTail;
        const STRICT: RecoveryPolicy = RecoveryPolicy::StrictFailClosed;
        let owner: &[u8] = &[1, 2];
        let dir = temp_dir("s101-appended");
        let mut s = open_sealed(&dir, STRICT).unwrap();
        let id = admit(&mut s, owner);
        drop(s);

        let (forger, forger_links, forged_chain) = forger_chain();
        let forged = admission(forged_chain, &[7], 2);
        let forged_id = match &forged {
            WalRecord::RevisionAdmitted { envelope, .. } => envelope.changeset_id(),
            _ => unreachable!(),
        };
        let mut w = open(&dir, STRICT).unwrap();
        let blob = body(2);
        w.append_revision_record(forged, &[(BlobDigest::compute(&blob), &blob[..])], None)
            .unwrap();
        let forged_move = SignedStateMove::sign_new(
            &forger,
            repo(),
            forged_id,
            RevisionState::Proposed,
            &forger_links,
            6_000,
        )
        .unwrap();
        w.append_revision_record(moved(forged_move), &[], None)
            .unwrap();
        drop(w);

        assert_eq!(
            open_sealed(&dir, STRICT).err().unwrap().code,
            RefusalCode::RevisionRecordUnsealed
        );
        let mut s = open_sealed(&dir, TORN).unwrap();
        assert_eq!(s.seal_replay_report().unsealed, 2);
        assert!(s.get_revision(&repo(), forged_id).is_err());
        // The sealed chain continues after the unsealed records.
        s.advance_revision_state(signed(owner, id, RevisionState::Draft), 6_500)
            .unwrap();
        drop(s);
        let mut s = open_sealed(&dir, TORN).unwrap();
        assert_eq!(
            s.get_revision(&repo(), id).unwrap().state,
            RevisionState::Draft
        );
        s.checkpoint_and_compact(7_000).unwrap();
        assert_eq!(s.seal_replay_report().dropped_by_compaction, 2);
        assert_eq!(s.seal_replay_report().unsealed, 0);
        let root = s.state_root_digest(None).unwrap();
        drop(s);
        let s = open_sealed(&dir, STRICT).expect("strict accepts the compacted store");
        assert_eq!(
            s.get_revision(&repo(), id).unwrap().state,
            RevisionState::Draft
        );
        assert!(s.get_revision(&repo(), forged_id).is_err());
        assert_eq!(s.seal_replay_report(), SealReplayReport::default());
        assert_eq!(s.state_root_digest(None).unwrap(), root);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The seal chain binds each record's sequence and the records before it: removing a
    /// sealed record (its sequence filled by anything else), reordering two sealed
    /// admissions (which would hand ownership to the second admitter), or changing any
    /// field breaks the chain from that record on. The ledger applies nothing from there.
    #[test]
    fn s101_removed_reordered_or_edited_sealed_records_break_the_chain() {
        let key = server_key();
        let public = Some(key.public_key());
        // Two admissions of the same content by different chains, then an owner move.
        let first = admission(path(&[1, 2]), &[1, 2], 1);
        let joiner = admission(path(&[3]), &[3], 1);
        let id = match &first {
            WalRecord::RevisionAdmitted { envelope, .. } => envelope.changeset_id(),
            _ => unreachable!(),
        };
        let mut sealing = RevisionLedger::new(public);
        let mut log = Vec::new();
        for (n, mut r) in [
            first,
            joiner,
            moved(signed(&[1, 2], id, RevisionState::Draft)),
        ]
        .into_iter()
        .enumerate()
        {
            let seq = WalSeq(n as u64 + 1);
            sealing.seal_record(&key, seq, &mut r);
            sealing.apply(seq, r.clone());
            log.push((seq, r));
        }
        let honest = RevisionLedger::from_log(log.clone(), public);
        assert_eq!(honest.seal_report(), SealReplayReport::default());
        let rev = honest.get_revision(&repo(), id).unwrap();
        assert_eq!(rev.state, RevisionState::Draft);
        assert_eq!(rev.witnesses[0].chain, path(&[1, 2]));

        // Removed: the joiner's record is gone; the move after it no longer verifies.
        let removed = vec![log[0].clone(), log[2].clone()];
        let l = RevisionLedger::from_log(removed, public);
        assert_eq!(l.seal_report().first_unsealed, Some(WalSeq(3)));
        assert_eq!(
            l.get_revision(&repo(), id).unwrap().state,
            RevisionState::Private
        );

        // Reordered: the joiner first would own the revision; neither record verifies.
        let reordered = vec![
            (WalSeq(1), log[1].1.clone()),
            (WalSeq(2), log[0].1.clone()),
            log[2].clone(),
        ];
        let l = RevisionLedger::from_log(reordered, public);
        assert_eq!(l.seal_report().unsealed, 3);
        assert!(l.get_revision(&repo(), id).is_none());

        // Edited: the first admission's time changed, everything after it is cut off.
        let mut edited = log.clone();
        if let WalRecord::RevisionAdmitted { admitted_at_ms, .. } = &mut edited[0].1 {
            *admitted_at_ms += 1;
        }
        let l = RevisionLedger::from_log(edited, public);
        assert_eq!(l.seal_report().unsealed, 3);

        // Without a seal key the seals are carried but not checked.
        let unchecked = RevisionLedger::from_log(log, None);
        assert_eq!(unchecked.seal_report(), SealReplayReport::default());
        assert_eq!(
            unchecked.get_revision(&repo(), id).unwrap().state,
            RevisionState::Draft
        );
    }

    /// Issue #101 acceptance 2: a legitimate sealed store (admission, owner move, marker)
    /// round-trips strict replay, checkpoint, and compaction unchanged, with the same state
    /// root as the same operations in an unsealed store (the seal is not part of the root).
    #[test]
    fn s101_sealed_store_round_trips_replay_checkpoint_and_compaction() {
        const STRICT: RecoveryPolicy = RecoveryPolicy::StrictFailClosed;
        let owner: &[u8] = &[1, 2];
        let run = |s: &mut SynapseStore| {
            let id = admit(s, owner);
            s.advance_revision_state(signed(owner, id, RevisionState::Draft), 6_000)
                .unwrap();
            let marker = ObsolescenceMarker::sign_new(
                &key_of(owner),
                repo(),
                ChangeId([1; 16]),
                id,
                vec![],
                6_100,
            );
            s.record_obsolescence(marker, path(owner), 6_200).unwrap();
            id
        };
        let plain_dir = temp_dir("s101-plain");
        let mut plain = open(&plain_dir, STRICT).unwrap();
        run(&mut plain);
        let plain_root = plain.state_root_digest(None).unwrap();

        let dir = temp_dir("s101-roundtrip");
        let mut s = open_sealed(&dir, STRICT).unwrap();
        let id = run(&mut s);
        assert_eq!(s.revision_records().len(), 3);
        assert!(s.revision_records().iter().all(|(_, r)| r.seal().is_some()));
        assert_eq!(s.state_root_digest(None).unwrap(), plain_root);
        drop(s);
        let check = |s: &SynapseStore| {
            assert_eq!(
                s.get_revision(&repo(), id).unwrap().state,
                RevisionState::Draft
            );
            assert_eq!(
                s.change_status(&repo(), ChangeId([1; 16]))
                    .unwrap()
                    .obsolete,
                vec![id]
            );
            assert_eq!(s.seal_replay_report(), SealReplayReport::default());
            assert_eq!(s.state_root_digest(None).unwrap(), plain_root);
        };
        let mut s = open_sealed(&dir, STRICT).unwrap();
        check(&s);
        s.checkpoint_and_compact(7_000).unwrap();
        check(&s);
        // Writing after the checkpoint continues the same chain.
        s.advance_revision_state(signed(owner, id, RevisionState::Proposed), 7_100)
            .unwrap();
        drop(s);
        let s = open_sealed(&dir, STRICT).unwrap();
        assert_eq!(
            s.get_revision(&repo(), id).unwrap().state,
            RevisionState::Proposed
        );
        assert_eq!(s.seal_replay_report(), SealReplayReport::default());
        drop(s);
        // An existing unsealed store is refused by strict sealed recovery: its records
        // predate the seal and cannot be told apart from forgeries.
        drop(plain);
        assert_eq!(
            open_sealed(&plain_dir, STRICT).err().unwrap().code,
            RefusalCode::RevisionRecordUnsealed
        );
        let _ = std::fs::remove_dir_all(&dir);
        let _ = std::fs::remove_dir_all(&plain_dir);
    }

    /// The segment store (group commit) seals and replays the same way.
    #[test]
    fn s101_group_commit_store_seals_and_replays() {
        const STRICT: RecoveryPolicy = RecoveryPolicy::StrictFailClosed;
        let owner: &[u8] = &[1, 2];
        let dir = temp_dir("s101-group");
        let reopen = || {
            let limits = StoreLimits {
                wal_prealloc_bytes: 64 * 1024,
                ..Default::default()
            };
            let fsync = FsyncPolicy::GroupCommit {
                max_batch_records: 8,
                max_batch_delay_us: 0,
            };
            SynapseStore::open_sealed(&dir, fsync, STRICT, limits, server_key()).unwrap()
        };
        let mut s = reopen();
        let id = admit(&mut s, owner);
        s.advance_revision_state(signed(owner, id, RevisionState::Draft), 6_000)
            .unwrap();
        assert!(s.revision_records().iter().all(|(_, r)| r.seal().is_some()));
        drop(s);
        let mut s = reopen();
        assert_eq!(
            s.get_revision(&repo(), id).unwrap().state,
            RevisionState::Draft
        );
        s.checkpoint_and_compact(7_000).unwrap();
        s.advance_revision_state(signed(owner, id, RevisionState::Proposed), 7_100)
            .unwrap();
        drop(s);
        let s = reopen();
        assert_eq!(
            s.get_revision(&repo(), id).unwrap().state,
            RevisionState::Proposed
        );
        assert_eq!(s.seal_replay_report(), SealReplayReport::default());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The seal trailer is canonical: sealed records of every kind round-trip the binary
    /// codec, an unsealed record ends at its body, a trailer cut short is `Truncated`, and
    /// bytes that do not open with the seal tag, or follow a seal, are `TrailingBytes`.
    #[test]
    fn s101_seal_trailer_round_trips_and_malformed_trailers_are_refused_typed() {
        let key = server_key();
        let id = ChangesetId(derived("changeset", &[1]));
        let marker = ObsolescenceMarker::sign_new(
            &key_of(&[1]),
            repo(),
            ChangeId([1; 16]),
            id,
            vec![],
            6_100,
        );
        let records = [
            admission(path(&[1, 2]), &[1, 2], 1),
            moved(signed(&[1, 2], id, RevisionState::Draft)),
            WalRecord::ObsolescenceRecorded {
                marker,
                chain: path(&[1]),
                recorded_at_ms: 6_200,
                seal: None,
            },
        ];
        let cap = 1 << 20;
        for mut record in records {
            let unsealed = crate::codec::encode_record(&record).unwrap();
            let ledger = RevisionLedger::new(Some(key.public_key()));
            ledger.seal_record(&key, WalSeq(1), &mut record);
            let sealed = crate::codec::encode_record(&record).unwrap();
            assert_eq!(sealed.len(), unsealed.len() + 97);
            assert_eq!(&sealed[..unsealed.len()], &unsealed[..]);
            assert_eq!(crate::codec::decode_record(&sealed, cap).unwrap(), record);
            let mut bad_tag = sealed.clone();
            bad_tag[unsealed.len()] = 2;
            assert!(matches!(
                crate::codec::decode_record(&bad_tag, cap),
                Err(crate::CodecRefusal::TrailingBytes { .. })
            ));
            for cut in unsealed.len() + 1..sealed.len() {
                assert!(matches!(
                    crate::codec::decode_record(&sealed[..cut], cap),
                    Err(crate::CodecRefusal::Truncated { .. })
                ));
            }
            let mut extra = sealed.clone();
            extra.push(0);
            assert!(matches!(
                crate::codec::decode_record(&extra, cap),
                Err(crate::CodecRefusal::TrailingBytes { .. })
            ));
        }
    }
}
