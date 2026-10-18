//! `IntentRecord` and claims (ADR 0003 section 5.2, section 9 step B3).
//!
//! The free-text `intent_summary` of envelope v2 content is replaced by an [`IntentRecord`]:
//!
//! * `kind`: a closed [`IntentKind`].
//! * `task`: an optional typed [`TaskRef`] (a tracker issue or a ledger lane), never free text.
//! * `claims`: machine-checkable [`Claim`]s; every [`ClaimKind`] names exactly one
//!   [`PredicateType`], the type of receipt predicate that discharges it (step E1).
//! * `footprint`: the paths the change intends to touch, as path prefixes with the F1
//!   segment-boundary rule. Every actual mutation must lie inside it
//!   (`MutationOutsideFootprint`).
//! * `supersedes`: revisions this one replaces (also expressed as obsolescence markers).
//! * `context`: the optional `BlobDigest` of a machine-readable rationale blob, stored and
//!   retained with the revision, never part of any decision rule.
//!
//! The binary form is canonical (ADR 0003 principle P5): one encoding per value, every length
//! checked against the bytes that remain before anything is allocated, and any other byte
//! sequence refused with `EnvelopeMalformed` (`docs/B3_INTENT_RECORD.md` section 2).

use crate::revision::{malformed, put_str, Reader};
use crate::{
    validate_repo_relative_path, BlobDigest, ChangesetId, PathMutation, RefusalCode, RepoId,
    SynapseError, SynapseResult,
};

/// Most claims in one intent record.
pub const MAX_INTENT_CLAIMS: usize = 64;
/// Most footprint entries in one intent record.
pub const MAX_FOOTPRINT_ENTRIES: usize = 256;
/// Most superseded revisions in one intent record.
pub const MAX_SUPERSEDES: usize = 256;
/// Longest ledger lane name.
pub const MAX_LANE_BYTES: usize = 64;

const MAX_PATH_BYTES: usize = 2048;
const TASK_TAG_NONE: u8 = 0;
const TASK_TAG_TRACKER_ISSUE: u8 = 1;
const TASK_TAG_LEDGER_LANE: u8 = 2;
const CONTEXT_TAG_NONE: u8 = 0;
const CONTEXT_TAG_BLOB: u8 = 1;
/// Encoded size of the smallest claim (`BehaviourUnchanged`: its tag only).
const MIN_CLAIM_BYTES: usize = 1;
/// Encoded size of the smallest footprint entry (`u32` length and one byte).
const MIN_FOOTPRINT_ENTRY_BYTES: usize = 4 + 1;

/// The closed set of intent kinds (ADR 0003 section 5.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum IntentKind {
    Fix,
    Feature,
    Refactor,
    Revert,
    Merge,
    ResolveConflict,
    Format,
    DependencyUpdate,
    Generated,
}

impl IntentKind {
    /// Every kind, in tag order.
    pub const ALL: [IntentKind; 9] = [
        IntentKind::Fix,
        IntentKind::Feature,
        IntentKind::Refactor,
        IntentKind::Revert,
        IntentKind::Merge,
        IntentKind::ResolveConflict,
        IntentKind::Format,
        IntentKind::DependencyUpdate,
        IntentKind::Generated,
    ];

    pub fn tag(self) -> u8 {
        match self {
            IntentKind::Fix => 1,
            IntentKind::Feature => 2,
            IntentKind::Refactor => 3,
            IntentKind::Revert => 4,
            IntentKind::Merge => 5,
            IntentKind::ResolveConflict => 6,
            IntentKind::Format => 7,
            IntentKind::DependencyUpdate => 8,
            IntentKind::Generated => 9,
        }
    }

    pub fn from_tag(tag: u8) -> Option<Self> {
        Self::ALL.into_iter().find(|k| k.tag() == tag)
    }
}

/// A typed reference to the work item a change serves: never free text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TaskRef {
    /// Issue `number` (at least 1) of tracker repository `repo`.
    TrackerIssue { repo: RepoId, number: u64 },
    /// A ledger lane: 1..=64 bytes of `[a-z0-9._-]`, starting with `[a-z0-9]`.
    LedgerLane { lane: String },
}

impl TaskRef {
    fn validate(&self) -> SynapseResult<()> {
        match self {
            TaskRef::TrackerIssue { number, .. } => {
                if *number == 0 {
                    return Err(malformed("task tracker issue number must be at least 1"));
                }
            }
            TaskRef::LedgerLane { lane } => {
                let b = lane.as_bytes();
                let ok = !b.is_empty()
                    && b.len() <= MAX_LANE_BYTES
                    && (b[0].is_ascii_lowercase() || b[0].is_ascii_digit())
                    && b.iter().all(|c| {
                        c.is_ascii_lowercase()
                            || c.is_ascii_digit()
                            || matches!(c, b'.' | b'_' | b'-')
                    });
                if !ok {
                    return Err(malformed(
                        "task ledger lane must be 1..=64 bytes of [a-z0-9._-] starting with [a-z0-9]",
                    ));
                }
            }
        }
        Ok(())
    }
}

/// The type of receipt predicate that discharges a claim (the in-toto predicate type of the
/// receipt that E1 accepts for it).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum PredicateType {
    /// The named action passed on the revision's resulting tree.
    ActionResult,
    /// The public interface of a module is identical before and after.
    InterfaceEquivalence,
    /// Behaviour is unchanged (an equivalence or test receipt), as a `Refactor` claims.
    BehaviourEquivalence,
    /// The resulting tree equals the tree before the named revision.
    ExactRevert,
}

impl PredicateType {
    /// Every predicate type.
    pub const ALL: [PredicateType; 4] = [
        PredicateType::ActionResult,
        PredicateType::InterfaceEquivalence,
        PredicateType::BehaviourEquivalence,
        PredicateType::ExactRevert,
    ];

    /// Stable name of the predicate type, as a receipt names it.
    pub fn name(self) -> &'static str {
        match self {
            PredicateType::ActionResult => "synapse.predicate.action-result.v1",
            PredicateType::InterfaceEquivalence => "synapse.predicate.interface-equivalence.v1",
            PredicateType::BehaviourEquivalence => "synapse.predicate.behaviour-equivalence.v1",
            PredicateType::ExactRevert => "synapse.predicate.exact-revert.v1",
        }
    }
}

/// The kind of a claim, without its arguments.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ClaimKind {
    ActionPasses,
    InterfaceUnchanged,
    BehaviourUnchanged,
    RevertsRevision,
}

impl ClaimKind {
    /// Every claim kind, in tag order.
    pub const ALL: [ClaimKind; 4] = [
        ClaimKind::ActionPasses,
        ClaimKind::InterfaceUnchanged,
        ClaimKind::BehaviourUnchanged,
        ClaimKind::RevertsRevision,
    ];

    pub fn tag(self) -> u8 {
        match self {
            ClaimKind::ActionPasses => 1,
            ClaimKind::InterfaceUnchanged => 2,
            ClaimKind::BehaviourUnchanged => 3,
            ClaimKind::RevertsRevision => 4,
        }
    }

    /// The one predicate type that discharges claims of this kind.
    pub fn predicate_type(self) -> PredicateType {
        match self {
            ClaimKind::ActionPasses => PredicateType::ActionResult,
            ClaimKind::InterfaceUnchanged => PredicateType::InterfaceEquivalence,
            ClaimKind::BehaviourUnchanged => PredicateType::BehaviourEquivalence,
            ClaimKind::RevertsRevision => PredicateType::ExactRevert,
        }
    }
}

/// A machine-checkable assertion a change makes. Promotion needs each one discharged by a
/// passing receipt of its [`PredicateType`] on the revision's exact tree (steps E1 and E2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Claim {
    /// Action `action` (the 32-byte action digest, `synapse_evidence::EvidenceActionDigest`
    /// until E1) passes on the resulting tree.
    ActionPasses { action: [u8; 32] },
    /// The public interface of the module at repository path `module` is unchanged.
    InterfaceUnchanged { module: String },
    /// Behaviour is unchanged.
    BehaviourUnchanged,
    /// The change reverts revision `revision` exactly.
    RevertsRevision { revision: ChangesetId },
}

impl Claim {
    pub fn kind(&self) -> ClaimKind {
        match self {
            Claim::ActionPasses { .. } => ClaimKind::ActionPasses,
            Claim::InterfaceUnchanged { .. } => ClaimKind::InterfaceUnchanged,
            Claim::BehaviourUnchanged => ClaimKind::BehaviourUnchanged,
            Claim::RevertsRevision { .. } => ClaimKind::RevertsRevision,
        }
    }

    /// The predicate type of the receipt that discharges this claim.
    pub fn predicate_type(&self) -> PredicateType {
        self.kind().predicate_type()
    }

    fn encode_into(&self, buf: &mut Vec<u8>) {
        buf.push(self.kind().tag());
        match self {
            Claim::ActionPasses { action } => buf.extend_from_slice(action),
            Claim::InterfaceUnchanged { module } => put_str(buf, module),
            Claim::BehaviourUnchanged => {}
            Claim::RevertsRevision { revision } => buf.extend_from_slice(&revision.0),
        }
    }

    fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(40);
        self.encode_into(&mut buf);
        buf
    }

    fn decode_from(r: &mut Reader) -> SynapseResult<Self> {
        match r.u8()? {
            1 => Ok(Claim::ActionPasses { action: r.array()? }),
            2 => Ok(Claim::InterfaceUnchanged {
                module: r.string(MAX_PATH_BYTES)?,
            }),
            3 => Ok(Claim::BehaviourUnchanged),
            4 => Ok(Claim::RevertsRevision {
                revision: ChangesetId(r.array()?),
            }),
            tag => Err(malformed(format!("unknown claim tag {tag}"))),
        }
    }

    fn validate(&self) -> SynapseResult<()> {
        if let Claim::InterfaceUnchanged { module } = self {
            validate_repo_relative_path(module)?;
        }
        Ok(())
    }
}

/// True when footprint entry `prefix` covers `path`: equal, or `path` continues it after a `/`
/// (the F1 `PathScope` segment-boundary rule).
pub fn footprint_entry_covers(prefix: &str, path: &str) -> bool {
    path == prefix
        || (path.len() > prefix.len()
            && path.starts_with(prefix)
            && path.as_bytes()[prefix.len()] == b'/')
}

/// The machine-structured purpose of a revision (ADR 0003 section 5.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IntentRecord {
    pub kind: IntentKind,
    pub task: Option<TaskRef>,
    /// Strictly ascending by canonical claim encoding, at most 64.
    pub claims: Vec<Claim>,
    /// Path prefixes, strictly ascending, none covering another, 1..=256.
    pub footprint: Vec<String>,
    /// Strictly ascending, at most 256.
    pub supersedes: Vec<ChangesetId>,
    /// Digest of a machine-readable rationale blob, stored and retained with the revision.
    pub context: Option<BlobDigest>,
}

impl IntentRecord {
    /// A record of `kind` whose footprint is `footprint`, with no task, claims, supersedes,
    /// or context. The footprint is put in canonical form (sorted, covered entries dropped).
    pub fn new(kind: IntentKind, footprint: Vec<String>) -> Self {
        let mut sorted = footprint;
        sorted.sort();
        sorted.dedup();
        let mut kept: Vec<String> = Vec::with_capacity(sorted.len());
        for p in sorted {
            if !kept.iter().any(|k| footprint_entry_covers(k, &p)) {
                kept.push(p);
            }
        }
        Self {
            kind,
            task: None,
            claims: Vec::new(),
            footprint: kept,
            supersedes: Vec::new(),
            context: None,
        }
    }

    /// True when some footprint entry covers `path`.
    pub fn footprint_covers(&self, path: &str) -> bool {
        self.footprint
            .iter()
            .any(|p| footprint_entry_covers(p, path))
    }

    /// The record's own rules: a valid task, valid claims in strictly ascending encoded order,
    /// a canonical non-empty footprint of valid paths, strictly ascending supersedes. Refused
    /// with `EnvelopeMalformed`, or `PathInvalid` for a bad path.
    pub fn validate(&self) -> SynapseResult<()> {
        if let Some(task) = &self.task {
            task.validate()?;
        }
        if self.claims.len() > MAX_INTENT_CLAIMS {
            return Err(malformed(format!(
                "intent has {} claims, above {MAX_INTENT_CLAIMS}",
                self.claims.len()
            )));
        }
        for c in &self.claims {
            c.validate()?;
        }
        let encoded: Vec<Vec<u8>> = self.claims.iter().map(Claim::encode).collect();
        if !encoded.windows(2).all(|w| w[0] < w[1]) {
            return Err(malformed(
                "intent claims must be strictly ascending by canonical encoding",
            ));
        }
        if self.footprint.is_empty() || self.footprint.len() > MAX_FOOTPRINT_ENTRIES {
            return Err(malformed(format!(
                "intent footprint must hold 1..={MAX_FOOTPRINT_ENTRIES} entries"
            )));
        }
        for p in &self.footprint {
            validate_repo_relative_path(p)?;
        }
        let canonical = self.footprint.windows(2).all(|w| w[0] < w[1])
            && self.footprint.iter().enumerate().all(|(i, p)| {
                self.footprint
                    .iter()
                    .enumerate()
                    .all(|(j, q)| i == j || !footprint_entry_covers(q, p))
            });
        if !canonical {
            return Err(malformed(
                "intent footprint must be strictly ascending with no entry covering another",
            ));
        }
        if self.supersedes.len() > MAX_SUPERSEDES
            || !self.supersedes.windows(2).all(|w| w[0] < w[1])
        {
            return Err(malformed(format!(
                "intent supersedes must be strictly ascending, at most {MAX_SUPERSEDES}"
            )));
        }
        Ok(())
    }

    /// [`Self::validate`], then every mutation path lies inside the footprint
    /// (`MutationOutsideFootprint`).
    pub fn validate_for(&self, mutations: &[PathMutation]) -> SynapseResult<()> {
        self.validate()?;
        if let Some(m) = mutations.iter().find(|m| !self.footprint_covers(&m.path)) {
            return Err(SynapseError::new(
                RefusalCode::MutationOutsideFootprint,
                format!(
                    "mutation path {} lies outside the declared footprint",
                    m.path
                ),
            ));
        }
        Ok(())
    }

    /// `kind u8 | task | u32 n | claim* | u32 n | path str* | u32 n | id [32]* | context`,
    /// where `task` is `0`, `1 | repo str | number u64`, or `2 | lane str`; a claim is
    /// `1 | action [32]`, `2 | module str`, `3`, or `4 | revision [32]`; `context` is `0` or
    /// `1 | blob [32]`.
    pub fn encode_into(&self, buf: &mut Vec<u8>) {
        buf.push(self.kind.tag());
        match &self.task {
            None => buf.push(TASK_TAG_NONE),
            Some(TaskRef::TrackerIssue { repo, number }) => {
                buf.push(TASK_TAG_TRACKER_ISSUE);
                put_str(buf, repo.as_str());
                buf.extend_from_slice(&number.to_le_bytes());
            }
            Some(TaskRef::LedgerLane { lane }) => {
                buf.push(TASK_TAG_LEDGER_LANE);
                put_str(buf, lane);
            }
        }
        buf.extend_from_slice(&(self.claims.len() as u32).to_le_bytes());
        for c in &self.claims {
            c.encode_into(buf);
        }
        buf.extend_from_slice(&(self.footprint.len() as u32).to_le_bytes());
        for p in &self.footprint {
            put_str(buf, p);
        }
        buf.extend_from_slice(&(self.supersedes.len() as u32).to_le_bytes());
        for s in &self.supersedes {
            buf.extend_from_slice(&s.0);
        }
        match &self.context {
            None => buf.push(CONTEXT_TAG_NONE),
            Some(d) => {
                buf.push(CONTEXT_TAG_BLOB);
                buf.extend_from_slice(&d.0);
            }
        }
    }

    /// Decode one record and refuse any encoding that is not canonical ([`Self::validate`]).
    pub(crate) fn decode_from(r: &mut Reader) -> SynapseResult<Self> {
        let tag = r.u8()?;
        let kind = IntentKind::from_tag(tag)
            .ok_or_else(|| malformed(format!("unknown intent kind {tag}")))?;
        let task = match r.u8()? {
            TASK_TAG_NONE => None,
            TASK_TAG_TRACKER_ISSUE => Some(TaskRef::TrackerIssue {
                repo: r.repo()?,
                number: r.u64()?,
            }),
            TASK_TAG_LEDGER_LANE => Some(TaskRef::LedgerLane {
                lane: r.string(MAX_LANE_BYTES)?,
            }),
            tag => return Err(malformed(format!("unknown task tag {tag}"))),
        };
        let n = r.count(MAX_INTENT_CLAIMS, MIN_CLAIM_BYTES)?;
        let mut claims = Vec::with_capacity(n);
        for _ in 0..n {
            claims.push(Claim::decode_from(r)?);
        }
        let n = r.count(MAX_FOOTPRINT_ENTRIES, MIN_FOOTPRINT_ENTRY_BYTES)?;
        let mut footprint = Vec::with_capacity(n);
        for _ in 0..n {
            footprint.push(r.string(MAX_PATH_BYTES)?);
        }
        let n = r.count(MAX_SUPERSEDES, 32)?;
        let mut supersedes = Vec::with_capacity(n);
        for _ in 0..n {
            supersedes.push(ChangesetId(r.array()?));
        }
        let context = match r.u8()? {
            CONTEXT_TAG_NONE => None,
            CONTEXT_TAG_BLOB => Some(BlobDigest(r.array()?)),
            tag => return Err(malformed(format!("unknown context tag {tag}"))),
        };
        let record = Self {
            kind,
            task,
            claims,
            footprint,
            supersedes,
            context,
        };
        record
            .validate()
            .map_err(|e| malformed(format!("intent record not canonical: {}", e.message)))?;
        Ok(record)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        ChangeId, ChangesetEnvelopeV2, FileMode, IdempotencyKey, MutationOp, RevisionContent,
        RevisionIntent, TreeDigest, ENVELOPE_V2_VERSION, INTENT_RECORD_CONTENT_VERSION,
    };
    use ed25519_dalek::SigningKey;
    use std::collections::BTreeSet;

    fn upsert(path: &str) -> PathMutation {
        PathMutation {
            path: path.into(),
            op: MutationOp::Upsert {
                mode: FileMode::Regular644,
                blob_digest: BlobDigest::compute(b"x"),
                size_bytes: 1,
            },
        }
    }

    fn full_record() -> IntentRecord {
        let mut r = IntentRecord::new(
            IntentKind::Refactor,
            vec!["src".into(), "docs/B3.md".into()],
        );
        r.task = Some(TaskRef::TrackerIssue {
            repo: RepoId::new("aien-dev/synapse").unwrap(),
            number: 31,
        });
        r.claims = vec![
            Claim::ActionPasses { action: [3; 32] },
            Claim::InterfaceUnchanged {
                module: "src/lib.rs".into(),
            },
            Claim::BehaviourUnchanged,
            Claim::RevertsRevision {
                revision: ChangesetId([9; 32]),
            },
        ];
        r.supersedes = vec![ChangesetId([1; 32]), ChangesetId([2; 32])];
        r.context = Some(BlobDigest::compute(b"plan"));
        r
    }

    fn content(intent: RevisionIntent, paths: &[&str]) -> RevisionContent {
        RevisionContent {
            change_id: ChangeId([7; 16]),
            base_tree: TreeDigest([0x5A; 32]),
            parents: vec![ChangesetId([1; 32])],
            mutations: paths.iter().map(|p| upsert(p)).collect(),
            intent,
        }
    }

    fn encoded(r: &IntentRecord) -> Vec<u8> {
        let mut buf = Vec::new();
        r.encode_into(&mut buf);
        buf
    }

    fn decode(bytes: &[u8]) -> SynapseResult<IntentRecord> {
        let mut r = Reader::new(bytes);
        let rec = IntentRecord::decode_from(&mut r)?;
        r.finish()?;
        Ok(rec)
    }

    /// Acceptance: every claim kind maps to a predicate type. The mapping is a bijection onto
    /// `PredicateType::ALL`, every claim value reports the kind its encoding tags, and every
    /// predicate type has its own stable name.
    #[test]
    fn b3_every_claim_kind_maps_to_a_predicate_type() {
        let mapped: BTreeSet<PredicateType> =
            ClaimKind::ALL.iter().map(|k| k.predicate_type()).collect();
        assert_eq!(
            mapped.len(),
            ClaimKind::ALL.len(),
            "one predicate type per kind"
        );
        assert_eq!(mapped, PredicateType::ALL.into_iter().collect());
        let names: BTreeSet<&str> = PredicateType::ALL.iter().map(|p| p.name()).collect();
        assert_eq!(names.len(), PredicateType::ALL.len());
        let tags: BTreeSet<u8> = ClaimKind::ALL.iter().map(|k| k.tag()).collect();
        assert_eq!(tags.len(), ClaimKind::ALL.len());
        let claims = full_record().claims;
        let kinds: BTreeSet<ClaimKind> = claims.iter().map(Claim::kind).collect();
        assert_eq!(
            kinds,
            ClaimKind::ALL.into_iter().collect(),
            "fixture covers every kind"
        );
        for c in &claims {
            assert_eq!(c.encode()[0], c.kind().tag());
            assert_eq!(c.predicate_type(), c.kind().predicate_type());
        }
        for k in IntentKind::ALL {
            assert_eq!(IntentKind::from_tag(k.tag()), Some(k));
        }
        assert_eq!(IntentKind::from_tag(0), None);
        assert_eq!(IntentKind::from_tag(10), None);
    }

    /// Acceptance: a mutation outside the declared footprint is refused, by the content rules
    /// and so by every signed envelope; the F1 segment-boundary rule decides "inside".
    #[test]
    fn b3_mutation_outside_declared_footprint_is_refused() {
        let rec = IntentRecord::new(IntentKind::Fix, vec!["src".into()]);
        let inside = content(RevisionIntent::Record(rec.clone()), &["src", "src/a/b.rs"]);
        assert_eq!(inside.validate(), Ok(()));
        for outside in ["srcx/lib.rs", "README.md", "sr"] {
            let c = content(RevisionIntent::Record(rec.clone()), &[outside]);
            assert_eq!(
                c.validate().unwrap_err().code,
                RefusalCode::MutationOutsideFootprint,
                "{outside}"
            );
            let env = ChangesetEnvelopeV2::sign_new(
                &SigningKey::from_bytes(&[1; 32]),
                RepoId::new("aien-dev/synapse").unwrap(),
                c,
                IdempotencyKey([1; 32]),
                10,
            );
            assert_eq!(
                env.validate().unwrap_err().code,
                RefusalCode::MutationOutsideFootprint
            );
            let bytes = env.encode();
            assert_eq!(
                ChangesetEnvelopeV2::decode(&bytes)
                    .unwrap()
                    .validate()
                    .unwrap_err()
                    .code,
                RefusalCode::MutationOutsideFootprint
            );
        }
        // One mutation outside among several inside is enough.
        let c = content(RevisionIntent::Record(rec), &["src/a.rs", "tests/a.rs"]);
        assert_eq!(
            c.validate().unwrap_err().code,
            RefusalCode::MutationOutsideFootprint
        );
    }

    #[test]
    fn b3_intent_record_round_trips_and_non_canonical_bytes_are_refused() {
        let rec = full_record();
        assert_eq!(rec.validate(), Ok(()));
        let bytes = encoded(&rec);
        assert_eq!(decode(&bytes).unwrap(), rec);
        let c = content(
            RevisionIntent::Record(rec.clone()),
            &["docs/B3.md", "src/lib.rs"],
        );
        let cb = c.encode();
        assert_eq!(
            u16::from_le_bytes([cb[0], cb[1]]),
            INTENT_RECORD_CONTENT_VERSION
        );
        assert_eq!(RevisionContent::decode(&cb).unwrap(), c);
        let lane = RevisionIntent::Record(IntentRecord {
            task: Some(TaskRef::LedgerLane {
                lane: "synapse-adr0003".into(),
            }),
            ..IntentRecord::new(IntentKind::Generated, vec!["a".into()])
        });
        let c = content(lane, &["a"]);
        assert_eq!(RevisionContent::decode(&c.encode()).unwrap(), c);

        let refused = |r: IntentRecord| {
            let e = decode(&encoded(&r)).unwrap_err();
            assert_eq!(e.code, RefusalCode::EnvelopeMalformed, "{e:?}");
        };
        let mut r = rec.clone();
        r.claims.swap(0, 1);
        refused(r);
        let mut r = rec.clone();
        r.claims.push(Claim::BehaviourUnchanged);
        r.claims.sort_by_key(Claim::encode);
        refused(r);
        let mut r = rec.clone();
        r.footprint = vec!["src".into(), "docs/B3.md".into()];
        refused(r);
        let mut r = rec.clone();
        r.footprint = vec!["src".into(), "src/lib.rs".into()];
        refused(r);
        let mut r = rec.clone();
        r.footprint = vec![];
        refused(r);
        let mut r = rec.clone();
        r.footprint = vec!["src/../x".into()];
        refused(r);
        let mut r = rec.clone();
        r.supersedes.reverse();
        refused(r);
        let mut r = rec.clone();
        r.task = Some(TaskRef::TrackerIssue {
            repo: RepoId::new("aien-dev/synapse").unwrap(),
            number: 0,
        });
        refused(r);
        for lane in ["", "Upper", "-x", "has space", &"a".repeat(65)] {
            let mut r = rec.clone();
            r.task = Some(TaskRef::LedgerLane { lane: lane.into() });
            refused(r);
        }
        let mut r = rec.clone();
        r.claims = vec![Claim::InterfaceUnchanged {
            module: "/abs".into(),
        }];
        refused(r);

        // Unknown tags and trailing bytes.
        let mut b = bytes.clone();
        b[0] = 0;
        assert_eq!(decode(&b).unwrap_err().code, RefusalCode::EnvelopeMalformed);
        let mut b = bytes.clone();
        b[1] = 9;
        assert_eq!(decode(&b).unwrap_err().code, RefusalCode::EnvelopeMalformed);
        let mut b = bytes.clone();
        let context_tag = b.len() - 33;
        b[context_tag] = 2;
        assert_eq!(decode(&b).unwrap_err().code, RefusalCode::EnvelopeMalformed);
        let mut b = bytes.clone();
        b.push(0);
        assert_eq!(decode(&b).unwrap_err().code, RefusalCode::EnvelopeMalformed);
        // A claim count above the cap is refused before anything is reserved.
        let mut r = IntentRecord::new(IntentKind::Fix, vec!["a".into()]);
        r.claims = (0..=MAX_INTENT_CLAIMS as u8)
            .map(|i| Claim::ActionPasses { action: [i; 32] })
            .collect();
        refused(r);
        // Every truncation is refused, never a panic.
        for n in 0..bytes.len() {
            assert!(decode(&bytes[..n]).is_err(), "prefix {n}");
        }
    }

    /// B3 leaves content version 2 exactly as B1 wrote it: the same bytes and the same
    /// `ChangesetId` (golden value computed on main 2f06c45, before B3), so every existing
    /// v2 record, attestation, and derived revision keeps its identity.
    #[test]
    fn b3_content_version_2_keeps_its_bytes_and_changeset_id() {
        let v2 = content(RevisionIntent::Summary("add lib".into()), &["src/lib.rs"]);
        let b = v2.encode();
        assert_eq!(u16::from_le_bytes([b[0], b[1]]), ENVELOPE_V2_VERSION);
        assert_eq!(
            v2.changeset_id().to_string(),
            "9e6878fe29d91b27135e21ee94f6a21e4a0c6551de4a0cf6d911280c32c668e2"
        );
        assert_eq!(RevisionContent::decode(&b).unwrap(), v2);
        let v3 = content(
            RevisionIntent::Record(IntentRecord::new(IntentKind::Feature, vec!["src".into()])),
            &["src/lib.rs"],
        );
        assert_ne!(v3.changeset_id(), v2.changeset_id());
    }
}
