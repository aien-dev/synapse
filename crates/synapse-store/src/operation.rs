//! Operation views and undo, plain and final discard (ADR 0003 section 5.4, section 9 step B2).
//!
//! * **Operations.** Every revision record in the WAL is an operation with an actor chain:
//!   an admission (kinds 7 and 11), an obsolescence marker (kind 8), a state move (kind 9),
//!   and the view operations of WAL kind 12 ([`ViewOperation`]): undo, plain and final
//!   discard, and capability revocation.
//! * **View.** The references of one repository: for every change, its visible heads (an
//!   admitted revision that no marker names as predecessor and no discard names), the
//!   discarded revisions, and conflict data (a marker or discard whose revision is not in the
//!   view). Its digest is a two-level Merkle root ([`View::digest`]), so two views compare in
//!   one step. Revision states (B4) are facts of the revision, not references: they are not in
//!   the view and undo never moves a state backwards.
//! * **Undo.** An undo to operation `T` disables every later operation of the repository
//!   (whole undo) or every later operation whose actor chain descends from a given chain
//!   (per-actor undo). An operation is in effect when no undo in effect disables it, which is
//!   well defined because an undo only reaches earlier operations: undoing an undo re-enables
//!   what it disabled, so undo is undoable, and a whole undo to `T` gives back the exact view
//!   of `T`. Undo changes references only; no object is deleted.
//! * **Who may undo what.** The undoer's chain must be, or dominate, the actor chain of every
//!   operation the undo reaches (`AuthChainNotDominant`). Facts are never undone: an undo
//!   that reaches a revocation or a final discard is refused (`UndoIrreversible`). Canonical
//!   promotions, accepted receipts and erasures join this list when E1, E2 and M2 create them.
//! * **Replay.** The effect of every kind 12 operation is a pure function of the log: an undo
//!   that reaches an operation its actor may not undo, a discard by a chain that does not own
//!   the revision, or a revocation by a chain that does not dominate the revoked link changes
//!   nothing on replay and is counted in [`ViewReplayReport`], so a record written without the
//!   store cannot undo someone else's work.

use crate::WalRecord;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use synapse_core::{
    ChainPath, ChangeId, ChangesetId, RefusalCode, RepoId, SynapseError, SynapseResult, WalSeq,
};

/// Domain tag of [`View::digest`].
pub const DOMAIN_VIEW_V1: &[u8] = b"SYNAPSE_VIEW_V1\0";
/// Domain tag of the per-change leaf of a view digest.
pub const DOMAIN_VIEW_HEADS_V1: &[u8] = b"SYNAPSE_VIEW_HEADS_V1\0";

/// An operation on the references of one repository (WAL kind 12).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ViewOperation {
    /// Restore the view of operation `target` (`WalSeq(0)`: before any operation), either
    /// whole or, with `actor`, only for the operations whose actor chain is or descends from
    /// `actor`.
    Undo {
        repo_id: RepoId,
        target: WalSeq,
        actor: Option<ChainPath>,
    },
    /// Remove a revision from the view. A plain discard stays undoable; a final discard is
    /// the owner's choice to give up undo and can never be undone.
    Discard {
        repo_id: RepoId,
        changeset_id: ChangesetId,
        final_discard: bool,
    },
    /// Revoke the leaf link of `revoked` (a fact: never undone).
    Revoke { repo_id: RepoId, revoked: ChainPath },
}

impl ViewOperation {
    pub fn repo_id(&self) -> &RepoId {
        match self {
            ViewOperation::Undo { repo_id, .. }
            | ViewOperation::Discard { repo_id, .. }
            | ViewOperation::Revoke { repo_id, .. } => repo_id,
        }
    }

    /// Canonical bytes of the operation for the state-root record digest: tag, repository
    /// (`u64` length + bytes), then the fields in declaration order, chains in their core
    /// encoding with a `u64` length.
    pub(crate) fn digest_bytes(&self) -> Vec<u8> {
        fn put_repo(out: &mut Vec<u8>, repo: &RepoId) {
            out.extend_from_slice(&(repo.as_str().len() as u64).to_le_bytes());
            out.extend_from_slice(repo.as_str().as_bytes());
        }
        fn put_chain(out: &mut Vec<u8>, chain: &ChainPath) {
            let mut buf = Vec::new();
            chain.encode_into(&mut buf);
            out.extend_from_slice(&(buf.len() as u64).to_le_bytes());
            out.extend_from_slice(&buf);
        }
        let mut out = Vec::new();
        match self {
            ViewOperation::Undo {
                repo_id,
                target,
                actor,
            } => {
                out.push(1);
                put_repo(&mut out, repo_id);
                out.extend_from_slice(&target.0.to_le_bytes());
                match actor {
                    None => out.push(0),
                    Some(a) => {
                        out.push(1);
                        put_chain(&mut out, a);
                    }
                }
            }
            ViewOperation::Discard {
                repo_id,
                changeset_id,
                final_discard,
            } => {
                out.push(2);
                put_repo(&mut out, repo_id);
                out.extend_from_slice(&changeset_id.0);
                out.push(u8::from(*final_discard));
            }
            ViewOperation::Revoke { repo_id, revoked } => {
                out.push(3);
                put_repo(&mut out, repo_id);
                put_chain(&mut out, revoked);
            }
        }
        out
    }
}

/// The references of one repository at one point of its operation log.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct View {
    /// Visible heads of every change that has one.
    pub heads: BTreeMap<ChangeId, BTreeSet<ChangesetId>>,
    /// Discarded revisions; `true` for a final discard.
    pub discarded: BTreeMap<ChangesetId, bool>,
    /// Operations in effect whose revision is not in the view (a per-actor undo removed the
    /// admission a later marker or discard of another actor names): recorded, never dropped.
    pub conflicts: BTreeSet<WalSeq>,
}

impl View {
    /// `SHA-256(DOMAIN_VIEW_V1 || repo || u64 n || (change_id || leaf)* || u64 n ||
    /// (changeset_id || final u8)* || u64 n || seq*)`, where `leaf` is
    /// `SHA-256(DOMAIN_VIEW_HEADS_V1 || u64 n || head*)` with heads ascending.
    pub fn digest(&self, repo: &RepoId) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(DOMAIN_VIEW_V1);
        h.update((repo.as_str().len() as u64).to_le_bytes());
        h.update(repo.as_str().as_bytes());
        h.update((self.heads.len() as u64).to_le_bytes());
        for (change, heads) in &self.heads {
            let mut leaf = Sha256::new();
            leaf.update(DOMAIN_VIEW_HEADS_V1);
            leaf.update((heads.len() as u64).to_le_bytes());
            for id in heads {
                leaf.update(id.0);
            }
            h.update(change.0);
            h.update(leaf.finalize());
        }
        h.update((self.discarded.len() as u64).to_le_bytes());
        for (id, final_discard) in &self.discarded {
            h.update(id.0);
            h.update([u8::from(*final_discard)]);
        }
        h.update((self.conflicts.len() as u64).to_le_bytes());
        for seq in &self.conflicts {
            h.update(seq.0.to_le_bytes());
        }
        h.finalize().into()
    }
}

/// Kind 12 operations that replay found changing nothing, by reason. A live store writes none
/// of them, so every count is a record written without the store.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ViewReplayReport {
    pub undo_refused: u64,
    pub discard_refused: u64,
    pub revoke_refused: u64,
}

/// Why an undo is refused (the admission check and the replay rule are the same function).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UndoFault {
    /// The target is not before the undo.
    TargetInvalid,
    /// The undo reaches a revocation or a final discard at this sequence.
    Irreversible(WalSeq),
    /// The undo reaches an operation at this sequence whose actor chain the undoer does not
    /// dominate.
    NotDominant(WalSeq),
}

impl UndoFault {
    pub fn into_error(self) -> SynapseError {
        match self {
            UndoFault::TargetInvalid => SynapseError::new(
                RefusalCode::UndoTargetInvalid,
                "undo target must be an earlier operation of the window",
            ),
            UndoFault::Irreversible(seq) => SynapseError::new(
                RefusalCode::UndoIrreversible,
                format!("undo reaches operation {seq}, a revocation or final discard, which can never be undone"),
            ),
            UndoFault::NotDominant(seq) => SynapseError::new(
                RefusalCode::AuthChainNotDominant,
                format!("undo reaches operation {seq} of an actor chain the undoer does not dominate"),
            ),
        }
    }
}

#[derive(Debug, Clone)]
enum OpKind {
    Admit {
        change: ChangeId,
        id: ChangesetId,
    },
    Marker {
        pred: ChangesetId,
        succs: Vec<ChangesetId>,
    },
    StateMove,
    Undo {
        target: WalSeq,
        filter: Option<ChainPath>,
    },
    Discard {
        id: ChangesetId,
        final_discard: bool,
    },
    Revoke {
        revoked: ChainPath,
    },
}

#[derive(Debug, Clone)]
struct Op {
    seq: WalSeq,
    actor: ChainPath,
    kind: OpKind,
}

impl Op {
    fn is_fact(&self) -> bool {
        matches!(
            self.kind,
            OpKind::Revoke { .. }
                | OpKind::Discard {
                    final_discard: true,
                    ..
                }
        )
    }
}

/// The operations of `repo` in `log` (revision records in sequence order).
fn ops_of(log: &[(WalSeq, WalRecord)], repo: &RepoId) -> Vec<Op> {
    let mut ops = Vec::new();
    for (seq, record) in log {
        let (r, actor, kind) = match record {
            WalRecord::RevisionAdmitted {
                envelope, chain, ..
            } => (
                &envelope.attestation.repo_id,
                chain,
                OpKind::Admit {
                    change: envelope.content.change_id,
                    id: envelope.attestation.changeset_id,
                },
            ),
            WalRecord::DerivedRevisionAdmitted { derived, chain, .. } => (
                &derived.attestation.repo_id,
                chain,
                OpKind::Admit {
                    change: derived.content.change_id,
                    id: derived.attestation.output_changeset,
                },
            ),
            WalRecord::ObsolescenceRecorded { marker, chain, .. } => (
                &marker.repo_id,
                chain,
                OpKind::Marker {
                    pred: marker.predecessor,
                    succs: marker.successors.clone(),
                },
            ),
            WalRecord::RevisionStateMoved { state_move, .. } => {
                (&state_move.repo_id, &state_move.chain, OpKind::StateMove)
            }
            WalRecord::ViewOperationRecorded { op, chain, .. } => (
                op.repo_id(),
                chain,
                match op {
                    ViewOperation::Undo { target, actor, .. } => OpKind::Undo {
                        target: *target,
                        filter: actor.clone(),
                    },
                    ViewOperation::Discard {
                        changeset_id,
                        final_discard,
                        ..
                    } => OpKind::Discard {
                        id: *changeset_id,
                        final_discard: *final_discard,
                    },
                    ViewOperation::Revoke { revoked, .. } => OpKind::Revoke {
                        revoked: revoked.clone(),
                    },
                },
            ),
            _ => continue,
        };
        if r == repo {
            ops.push(Op {
                seq: *seq,
                actor: actor.clone(),
                kind,
            });
        }
    }
    ops
}

/// The operations an undo at `undo_seq` by `undoer` to `target`, filtered to `filter`,
/// reaches (indices into `ops`), or why it is refused.
fn undo_reach(
    ops: &[Op],
    undo_seq: WalSeq,
    undoer: &ChainPath,
    target: WalSeq,
    filter: Option<&ChainPath>,
) -> Result<Vec<usize>, UndoFault> {
    if target >= undo_seq {
        return Err(UndoFault::TargetInvalid);
    }
    let mut reach = Vec::new();
    for (i, op) in ops.iter().enumerate() {
        if op.seq <= target || op.seq >= undo_seq {
            continue;
        }
        if filter.is_some_and(|f| !f.dominates(&op.actor)) {
            continue;
        }
        if op.is_fact() {
            return Err(UndoFault::Irreversible(op.seq));
        }
        if !undoer.dominates(&op.actor) {
            return Err(UndoFault::NotDominant(op.seq));
        }
        reach.push(i);
    }
    Ok(reach)
}

/// The chain of the first admission of `id` before index `before`, if any.
fn first_admitter(ops: &[Op], id: ChangesetId, before: usize) -> Option<&ChainPath> {
    ops[..before].iter().find_map(|op| match op.kind {
        OpKind::Admit { id: a, .. } if a == id => Some(&op.actor),
        _ => None,
    })
}

/// Whether each operation of `ops` is in effect, and the replay report. An operation is in
/// effect unless an undo in effect reaches it; undos only reach earlier operations, so one
/// pass from the newest operation decides each one after every undo that could reach it.
fn effective(ops: &[Op]) -> (Vec<bool>, ViewReplayReport) {
    let mut report = ViewReplayReport::default();
    let mut valid = vec![true; ops.len()];
    let mut reaches: Vec<Vec<usize>> = vec![Vec::new(); ops.len()];
    for (i, op) in ops.iter().enumerate() {
        match &op.kind {
            OpKind::Undo { target, filter } => {
                match undo_reach(ops, op.seq, &op.actor, *target, filter.as_ref()) {
                    Ok(r) => reaches[i] = r,
                    Err(_) => {
                        valid[i] = false;
                        report.undo_refused += 1;
                    }
                }
            }
            OpKind::Discard { id, .. }
                if !first_admitter(ops, *id, i).is_some_and(|c| op.actor.dominates(c)) =>
            {
                valid[i] = false;
                report.discard_refused += 1;
            }
            OpKind::Revoke { revoked } if !op.actor.dominates(revoked) => {
                valid[i] = false;
                report.revoke_refused += 1;
            }
            _ => {}
        }
    }
    let mut on = valid;
    for j in (0..ops.len()).rev() {
        if on[j] {
            for &k in &reaches[j] {
                on[k] = false;
            }
        }
    }
    (on, report)
}

/// The view of `repo` after every operation of `log` up to and including `upto`.
pub(crate) fn view_at(log: &[(WalSeq, WalRecord)], repo: &RepoId, upto: WalSeq) -> View {
    let ops: Vec<Op> = ops_of(log, repo)
        .into_iter()
        .filter(|op| op.seq <= upto)
        .collect();
    fold(&ops)
}

fn fold(ops: &[Op]) -> View {
    let (on, _) = effective(ops);
    let mut admitted: BTreeMap<ChangesetId, ChangeId> = BTreeMap::new();
    let mut markers: Vec<(WalSeq, ChangesetId, &[ChangesetId])> = Vec::new();
    let mut discards: Vec<(WalSeq, ChangesetId, bool)> = Vec::new();
    for (op, _) in ops.iter().zip(&on).filter(|(_, on)| **on) {
        match &op.kind {
            OpKind::Admit { change, id } => {
                admitted.entry(*id).or_insert(*change);
            }
            OpKind::Marker { pred, succs } => markers.push((op.seq, *pred, succs)),
            OpKind::Discard { id, final_discard } => discards.push((op.seq, *id, *final_discard)),
            OpKind::StateMove | OpKind::Undo { .. } | OpKind::Revoke { .. } => {}
        }
    }
    let mut view = View::default();
    let mut hidden: BTreeSet<ChangesetId> = BTreeSet::new();
    for (seq, pred, succs) in &markers {
        hidden.insert(*pred);
        if !admitted.contains_key(pred) || succs.iter().any(|s| !admitted.contains_key(s)) {
            view.conflicts.insert(*seq);
        }
    }
    for (seq, id, final_discard) in &discards {
        hidden.insert(*id);
        let e = view.discarded.entry(*id).or_insert(false);
        *e |= *final_discard;
        if !admitted.contains_key(id) {
            view.conflicts.insert(*seq);
        }
    }
    for (id, change) in &admitted {
        if !hidden.contains(id) {
            view.heads.entry(*change).or_default().insert(*id);
        }
    }
    view
}

/// Replay report of the kind 12 operations of every repository in `log`.
pub(crate) fn replay_report(log: &[(WalSeq, WalRecord)]) -> ViewReplayReport {
    let repos: BTreeSet<RepoId> = log
        .iter()
        .filter_map(|(_, r)| match r {
            WalRecord::ViewOperationRecorded { op, .. } => Some(op.repo_id().clone()),
            _ => None,
        })
        .collect();
    let mut total = ViewReplayReport::default();
    for repo in repos {
        let (_, r) = effective(&ops_of(log, &repo));
        total.undo_refused += r.undo_refused;
        total.discard_refused += r.discard_refused;
        total.revoke_refused += r.revoke_refused;
    }
    total
}

/// Admission check of an undo at `undo_seq`: the same rule replay applies.
pub(crate) fn check_undo(
    log: &[(WalSeq, WalRecord)],
    repo: &RepoId,
    undo_seq: WalSeq,
    undoer: &ChainPath,
    target: WalSeq,
    filter: Option<&ChainPath>,
) -> SynapseResult<()> {
    undo_reach(&ops_of(log, repo), undo_seq, undoer, target, filter)
        .map(|_| ())
        .map_err(UndoFault::into_error)
}

/// Admission check of a discard: the revision was admitted in `repo` and `chain` is, or
/// dominates, the chain of its first admission; a revision already finally discarded is
/// refused.
pub(crate) fn check_discard(
    log: &[(WalSeq, WalRecord)],
    repo: &RepoId,
    id: ChangesetId,
    chain: &ChainPath,
) -> SynapseResult<()> {
    let ops = ops_of(log, repo);
    let owner = first_admitter(&ops, id, ops.len()).ok_or_else(|| {
        SynapseError::new(
            RefusalCode::ChangesetNotFound,
            format!("revision {id} is not admitted in {repo}"),
        )
    })?;
    if !chain.dominates(owner) {
        return Err(SynapseError::new(
            RefusalCode::AuthChainNotDominant,
            format!("only the owner chain of revision {id} or one dominating it may discard it"),
        ));
    }
    if fold(&ops).discarded.get(&id) == Some(&true) {
        return Err(SynapseError::new(
            RefusalCode::DiscardInvalid,
            format!("revision {id} is already finally discarded"),
        ));
    }
    Ok(())
}

/// A recorded view operation: where it landed and the repository view right after it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ViewOutcome {
    pub wal_seq: WalSeq,
    /// [`View::digest`] of the repository after the operation.
    pub view_digest: [u8; 32],
    /// Operations in effect whose revision is no longer in the view (see [`View::conflicts`]).
    pub conflicts: BTreeSet<WalSeq>,
}

impl crate::SynapseStore {
    /// Record an undo of `repo_id` to operation `target` under `chain` at server time
    /// `now_ms`: whole, or with `actor` only the operations whose actor chain is or descends
    /// from `actor`. Refused, with nothing written: a target not before the undo
    /// (`UndoTargetInvalid`), an undo reaching a revocation or a final discard
    /// (`UndoIrreversible`), or an operation whose actor chain `chain` does not dominate
    /// (`AuthChainNotDominant`). The check runs against the sequence the record is written
    /// at (`WalSequenceGap` if another writer took it).
    pub fn record_undo(
        &mut self,
        repo_id: RepoId,
        target: WalSeq,
        actor: Option<ChainPath>,
        chain: ChainPath,
        now_ms: u64,
    ) -> SynapseResult<ViewOutcome> {
        self.check_writable()?;
        self.check_binary_codec()?;
        let at = self.committed_seq().next();
        check_undo(
            self.revisions.log(),
            &repo_id,
            at,
            &chain,
            target,
            actor.as_ref(),
        )?;
        let op = ViewOperation::Undo {
            repo_id,
            target,
            actor,
        };
        self.append_view_operation(op, chain, now_ms, at)
    }

    /// Record a plain (undoable) or final (never undone) discard of revision `changeset_id`
    /// under `chain`. Refused: a revision not admitted in `repo_id` (`ChangesetNotFound`), a
    /// chain that is not and does not dominate the chain of its first admission
    /// (`AuthChainNotDominant`), a revision already finally discarded (`DiscardInvalid`).
    pub fn record_discard(
        &mut self,
        repo_id: RepoId,
        changeset_id: ChangesetId,
        final_discard: bool,
        chain: ChainPath,
        now_ms: u64,
    ) -> SynapseResult<ViewOutcome> {
        self.check_writable()?;
        self.check_binary_codec()?;
        let at = self.committed_seq().next();
        check_discard(self.revisions.log(), &repo_id, changeset_id, &chain)?;
        let op = ViewOperation::Discard {
            repo_id,
            changeset_id,
            final_discard,
        };
        self.append_view_operation(op, chain, now_ms, at)
    }

    /// Record the revocation of the leaf link of `revoked` by `chain` in the operation log of
    /// `repo_id`: a fact no undo can reach. `chain` must be or dominate `revoked`
    /// (`AuthChainNotDominant`). Enforcing the revocation on requests is the policy
    /// enforcer's job (`synapse-api` revokes the link there at the same sequence).
    pub fn record_revocation(
        &mut self,
        repo_id: RepoId,
        revoked: ChainPath,
        chain: ChainPath,
        now_ms: u64,
    ) -> SynapseResult<ViewOutcome> {
        self.check_writable()?;
        self.check_binary_codec()?;
        if !chain.dominates(&revoked) {
            return Err(SynapseError::new(
                RefusalCode::AuthChainNotDominant,
                "only the revoked chain or one dominating it may revoke its leaf link",
            ));
        }
        let at = self.committed_seq().next();
        let op = ViewOperation::Revoke { repo_id, revoked };
        self.append_view_operation(op, chain, now_ms, at)
    }

    /// The current view of `repo_id` (B2): references only, a fold over the operation log.
    pub fn view(&self, repo_id: &RepoId) -> View {
        view_at(self.revisions.log(), repo_id, self.committed_seq())
    }

    /// The view of `repo_id` right after operation `seq` (the view an undo to `seq` restores).
    pub fn view_at(&self, repo_id: &RepoId, seq: WalSeq) -> View {
        view_at(self.revisions.log(), repo_id, seq)
    }

    /// Kind 12 records that change nothing on replay, by reason. All zero for a log written
    /// only by stores.
    pub fn view_replay_report(&self) -> ViewReplayReport {
        replay_report(self.revisions.log())
    }

    fn append_view_operation(
        &mut self,
        op: ViewOperation,
        chain: ChainPath,
        now_ms: u64,
        at: WalSeq,
    ) -> SynapseResult<ViewOutcome> {
        let repo = op.repo_id().clone();
        let record = WalRecord::ViewOperationRecorded {
            op,
            chain,
            recorded_at_ms: now_ms,
        };
        let wal_seq = self.append_revision_record(record, &[], Some(at))?;
        let view = self.view(&repo);
        Ok(ViewOutcome {
            wal_seq,
            view_digest: view.digest(&repo),
            conflicts: view.conflicts,
        })
    }
}
