//! J1 cross-check corpus for the Omega port of the binary codec (ADR 0003 section 9 step 33).
//!
//! The Rust codec (`codec.rs`) is the specification by test (ADR 0003 section 5.12). This
//! module writes what "decodes and re-encodes every record byte for byte, refuses the
//! malformed corpus identically" means for a port into one language-neutral file, sealed in
//! `evidence/j1-codec-corpus/corpus.bin`: every base record and checkpoint content with its
//! logical form, and every A1 malformed case (the mutation set of `a1_malformed_corpus.rs`)
//! with the outcome the Rust decoder gives. The format and the logical form are specified in
//! `docs/J1_OMEGA_CODEC.md`.
//!
//! `J1_CORPUS_WRITE=1 cargo test -p synapse-store --lib j1_corpus` rewrites the file; without
//! it the test only checks that the sealed file is what the codec gives today.

use super::a1_tests::{edge_records, fixture_dir, fixture_json_records};
use super::*;
use crate::codec::*;
use ed25519_dalek::SigningKey;
use synapse_core::{ChangeId, FileMode, PathMutation, RevisionContent, TreeDigest};

/// The sealed corpus, relative to the repository root.
const CORPUS_PATH: &str = "evidence/j1-codec-corpus/corpus.bin";
/// SHA-256 of the sealed corpus, so the seal is checked by a test, not by hand.
const CORPUS_SHA256: &str = "469a25239b6d683d137497b8cab1bebb186e11b180fb5061723af2fe8f6bb8b7";
const MAGIC: [u8; 8] = *b"SYNJ1COD";
const VERSION: u16 = 1;
/// Record cap of the A1 malformed corpus (`a1_malformed_corpus.rs`).
const CAP: u64 = 2048;

// Logical-form token types (docs/J1_OMEGA_CODEC.md section 3).
const T_U16: u64 = 2;
const T_U64: u64 = 4;
const T_BOOL: u64 = 5;
const T_TAG: u64 = 6;
const T_FIX: u64 = 7;
const T_STR: u64 = 8;
const T_BYTES: u64 = 9;
const T_REPO: u64 = 10;
const T_COUNT: u64 = 11;

/// Field names a refusal can carry, in id order (id = index + 1; 0 means none).
const FIELDS: [&str; 15] = [
    "bool",
    "option",
    "mutation op",
    "file mode",
    "record kind",
    "envelope v2",
    "chain path",
    "obsolescence marker",
    "changesets",
    "idempotency index",
    "blob visibility",
    "projections",
    "canonical heads",
    "revision records",
    "revision record kind",
];
/// Refusal codes an embedded `synapse-core` decoder gives, in id order (id = index + 1).
const CODES: [RefusalCode; 2] = [
    RefusalCode::EnvelopeMalformed,
    RefusalCode::EnvelopeVersionUnsupported,
];
/// `CodecRefusal` kinds in id order (id = index + 1).
const KINDS: [&str; 9] = [
    "Truncated",
    "LengthOverCap",
    "TrailingBytes",
    "UnknownTag",
    "InvalidUtf8",
    "VersionUnsupported",
    "NotCanonical",
    "InvalidRepoId",
    "EmbeddedMalformed",
];

const ENTRY_RECORD: u8 = 1;
const ENTRY_CHECKPOINT: u8 = 2;
/// A refused base is itself the case input (op 0).
const OP_AS_IS: u8 = 0;
const OP_TRUNCATE: u8 = 1;
const OP_FLIP: u8 = 2;
const OP_FALSE_LENGTH: u8 = 3;

// ---------------------------------------------------------------------------------------
// Logical form: the typed fields of a record, in encoding order, without derived lengths
// or constant bytes.
// ---------------------------------------------------------------------------------------

#[derive(Default)]
struct Lf(Vec<u64>);

impl Lf {
    fn scalar(&mut self, t: u64, v: u64) {
        self.0.push(t | 1 << 8);
        self.0.push(v);
    }
    fn run(&mut self, t: u64, b: &[u8]) {
        self.0.push(t | (b.len() as u64) << 8);
        self.0.extend(b.iter().map(|&x| u64::from(x)));
    }
    fn u64(&mut self, v: u64) {
        self.scalar(T_U64, v);
    }
    fn bool(&mut self, v: bool) {
        self.scalar(T_BOOL, u64::from(v));
    }
    fn tag(&mut self, v: u8) {
        self.scalar(T_TAG, u64::from(v));
    }
    fn count(&mut self, n: usize) {
        self.scalar(T_COUNT, n as u64);
    }
    fn fix(&mut self, b: &[u8]) {
        self.run(T_FIX, b);
    }
    fn str(&mut self, s: &str) {
        self.run(T_STR, s.as_bytes());
    }
    fn repo(&mut self, r: &RepoId) {
        self.run(T_REPO, r.as_str().as_bytes());
    }

    fn attachment(&mut self, a: &EvidenceAttachment) {
        self.str(&a.gate_name);
        self.bool(a.passed);
        self.fix(&a.artifact_digest);
        self.str(&a.summary);
    }
    fn attachments(&mut self, v: &[EvidenceAttachment]) {
        self.count(v.len());
        v.iter().for_each(|a| self.attachment(a));
    }
    fn mutations(&mut self, v: &[PathMutation]) {
        self.count(v.len());
        for m in v {
            self.str(&m.path);
            match &m.op {
                MutationOp::Upsert {
                    mode,
                    blob_digest,
                    size_bytes,
                } => {
                    self.tag(1);
                    self.tag(mode.tag_byte());
                    self.fix(&blob_digest.0);
                    self.u64(*size_bytes);
                }
                MutationOp::Delete => self.tag(2),
            }
        }
    }
    fn ids(&mut self, v: impl ExactSizeIterator<Item = [u8; 32]>) {
        self.count(v.len());
        v.for_each(|id| self.fix(&id));
    }
    fn envelope(&mut self, e: &ChangesetEnvelope) {
        self.scalar(T_U16, u64::from(e.version));
        self.repo(&e.repo_id);
        self.fix(&e.base_git_oid.0);
        self.ids(e.parent_changesets.iter().map(|p| p.0));
        self.str(&e.author_did);
        self.fix(&e.idempotency_key.0);
        self.u64(e.created_at_ms);
        self.str(&e.intent_summary);
        self.mutations(&e.mutations);
        self.attachments(&e.evidence_receipts);
        self.run(T_BYTES, &e.signature);
    }
    fn review(&mut self, r: &ReviewRecord) {
        self.str(&r.reviewer_did);
        self.bool(r.approved);
        self.str(&r.comment);
        self.u64(r.recorded_at_ms);
    }
    fn projection(&mut self, p: &GitHubPullRequestProjection) {
        self.repo(&p.repo_id);
        self.u64(p.pr_number);
        self.fix(&p.changeset_id.0);
        self.fix(&p.head_git_oid.0);
        self.fix(&p.base_git_oid.0);
        self.str(&p.pr_branch_ref);
        self.str(&p.title);
        self.str(&p.body_markdown);
        self.fix(&p.evidence_summary_digest);
        self.bool(p.github_merged);
    }
    fn canonical(&mut self, c: &RadicleCanonicalHead) {
        self.repo(&c.repo_id);
        self.str(&c.default_branch);
        self.fix(&c.canonical_git_oid.0);
        match &c.promoted_changeset_id {
            Some(id) => {
                self.tag(1);
                self.fix(&id.0);
            }
            None => self.tag(0),
        }
        self.fix(&c.rad_id_commit_oid.0);
        self.u64(c.threshold as u64);
        self.count(c.verified_delegates.len());
        c.verified_delegates.iter().for_each(|d| self.str(d));
        self.u64(c.verified_at_ms);
    }
    fn stored(&mut self, s: &StoredChangeset) {
        self.fix(&s.changeset_id.0);
        self.u64(s.committed_seq.0);
        self.envelope(&s.envelope);
        self.attachments(&s.evaluations);
        self.count(s.reviews.len());
        s.reviews.iter().for_each(|r| self.review(r));
        self.u64(s.lease_expires_at_ms);
    }
    fn chain(&mut self, c: &ChainPath) {
        self.ids(c.links().iter().copied());
    }
    fn record(&mut self, r: &WalRecord) {
        self.tag(r.kind_byte());
        match r {
            WalRecord::ChangesetIngest {
                envelope,
                changeset_id,
                new_blobs,
            } => {
                self.envelope(envelope);
                self.fix(&changeset_id.0);
                self.ids(new_blobs.iter().map(|b| b.0));
            }
            WalRecord::EvaluationAttached {
                changeset_id,
                attachment,
            } => {
                self.fix(&changeset_id.0);
                self.attachment(attachment);
            }
            WalRecord::ReviewRecorded {
                changeset_id,
                review,
            } => {
                self.fix(&changeset_id.0);
                self.review(review);
            }
            WalRecord::GitProjected { projection } => self.projection(projection),
            WalRecord::CanonicalPromoted { canonical } => self.canonical(canonical),
            WalRecord::LeaseUpdated {
                changeset_id,
                lease_expires_at_ms,
            } => {
                self.fix(&changeset_id.0);
                self.u64(*lease_expires_at_ms);
            }
            WalRecord::RevisionAdmitted {
                envelope,
                chain,
                admitted_at_ms,
                new_blobs,
            } => {
                let c = &envelope.content;
                self.fix(&c.change_id.0);
                self.fix(&c.base_tree.0);
                self.ids(c.parents.iter().map(|p| p.0));
                self.mutations(&c.mutations);
                self.str(&c.intent_summary);
                let a = &envelope.attestation;
                self.repo(&a.repo_id);
                self.fix(&a.changeset_id.0);
                self.fix(&a.author_key);
                self.fix(&a.idempotency_key.0);
                self.u64(a.attested_at_ms);
                self.fix(&a.signature);
                self.chain(chain);
                self.u64(*admitted_at_ms);
                self.ids(new_blobs.iter().map(|b| b.0));
            }
            WalRecord::ObsolescenceRecorded {
                marker,
                chain,
                recorded_at_ms,
            } => {
                self.repo(&marker.repo_id);
                self.fix(&marker.change_id.0);
                self.fix(&marker.predecessor.0);
                self.ids(marker.successors.iter().map(|s| s.0));
                self.fix(&marker.signer_key);
                self.u64(marker.signed_at_ms);
                self.fix(&marker.signature);
                self.chain(chain);
                self.u64(*recorded_at_ms);
            }
            // Kinds 9 and 11 landed on main after this corpus was sealed; the corpus covers
            // kinds 1 to 8 only (see the coverage test), so no corpus record reaches here.
            WalRecord::RevisionStateMoved { .. } | WalRecord::DerivedRevisionAdmitted { .. } => {
                unreachable!("J1 corpus does not yet cover record kinds 9 and 11")
            }
        }
    }
    fn checkpoint(&mut self, s: &CheckpointState) {
        self.count(s.changesets.len());
        s.changesets.values().for_each(|c| self.stored(c));
        self.count(s.idempotency_index.len());
        for ((repo, key), (seq, id)) in &s.idempotency_index {
            self.repo(repo);
            self.fix(&key.0);
            self.u64(seq.0);
            self.fix(&id.0);
        }
        self.count(s.blob_first_visible_seq.len());
        for (d, seq) in &s.blob_first_visible_seq {
            self.fix(&d.0);
            self.u64(seq.0);
        }
        self.count(s.github_projections.len());
        s.github_projections
            .values()
            .for_each(|p| self.projection(p));
        self.count(s.canonical_heads.len());
        s.canonical_heads.values().for_each(|c| self.canonical(c));
        // Always present in the logical form; the bytes hold the section only when n > 0.
        self.count(s.revision_log.len());
        for (seq, r) in &s.revision_log {
            self.u64(seq.0);
            self.record(r);
        }
    }
}

// ---------------------------------------------------------------------------------------
// Bases and outcomes
// ---------------------------------------------------------------------------------------

/// A test signing key derived from a label (no literal key material in the source).
fn derived_key(label: &str) -> SigningKey {
    SigningKey::from_bytes(&Sha256::digest(label.as_bytes()).into())
}

fn derived32(label: &str) -> [u8; 32] {
    Sha256::digest(label.as_bytes()).into()
}

fn repo() -> RepoId {
    RepoId::new("aien-dev/synapse").unwrap()
}

fn chain(depth: usize) -> ChainPath {
    ChainPath::new(
        (0..depth)
            .map(|i| derived32(&format!("j1 link {i}")))
            .collect(),
    )
    .unwrap()
}

/// Kind 7 and kind 8 records (on `main`; kinds 9 to 11 are reserved by open PRs).
fn revision_records() -> Vec<WalRecord> {
    let author = derived_key("j1 corpus author");
    let blob = |s: &str| BlobDigest::compute(s.as_bytes());
    let mut parents = vec![
        ChangesetId(derived32("j1 parent a")),
        ChangesetId(derived32("j1 parent b")),
    ];
    parents.sort();
    let content = RevisionContent {
        change_id: ChangeId(derived32("j1 change")[..16].try_into().unwrap()),
        base_tree: TreeDigest(derived32("j1 base tree")),
        parents,
        mutations: vec![
            PathMutation {
                path: "bin/run".into(),
                op: MutationOp::Upsert {
                    mode: FileMode::Executable755,
                    blob_digest: blob("run"),
                    size_bytes: 3,
                },
            },
            PathMutation {
                path: "old.txt".into(),
                op: MutationOp::Delete,
            },
            PathMutation {
                path: "src/lib.rs".into(),
                op: MutationOp::Upsert {
                    mode: FileMode::Regular644,
                    blob_digest: blob("lib"),
                    size_bytes: u64::MAX,
                },
            },
        ],
        intent_summary: "j1: été 🦀".into(),
    };
    let change_id = content.change_id;
    let env = ChangesetEnvelopeV2::sign_new(
        &author,
        repo(),
        content,
        IdempotencyKey(derived32("j1 idempotency")),
        1_000,
    );
    let id = env.changeset_id();
    let mut successors = vec![
        ChangesetId(derived32("j1 successor a")),
        ChangesetId(derived32("j1 successor b")),
    ];
    successors.sort();
    vec![
        WalRecord::RevisionAdmitted {
            envelope: env,
            chain: chain(3),
            admitted_at_ms: 5_000,
            new_blobs: vec![blob("run"), blob("lib")],
        },
        WalRecord::ObsolescenceRecorded {
            marker: ObsolescenceMarker::sign_new(&author, repo(), change_id, id, successors, 6_000),
            chain: chain(1),
            recorded_at_ms: 7_000,
        },
        WalRecord::ObsolescenceRecorded {
            marker: ObsolescenceMarker::sign_new(
                &author,
                RepoId::new("x").unwrap(),
                change_id,
                id,
                vec![],
                0,
            ),
            chain: chain(16),
            recorded_at_ms: u64::MAX,
        },
    ]
}

fn fixture_state() -> CheckpointState {
    let manifest: CheckpointManifest =
        serde_json::from_slice(&fs::read(fixture_dir("v1-wal-log").join("checkpoint.v1")).unwrap())
            .unwrap();
    CheckpointState::from_v1_manifest(manifest).unwrap()
}

/// A checkpoint with a revision section (kinds 7 and 8).
fn revision_state() -> CheckpointState {
    let r = revision_records();
    let mut s = CheckpointState {
        checkpoint_seq: WalSeq(9),
        anchor_frame_sha256: derived32("j1 anchor"),
        ..Default::default()
    };
    for (i, label) in ["run", "lib"].iter().enumerate() {
        s.blob_first_visible_seq
            .insert(BlobDigest::compute(label.as_bytes()), WalSeq(4 + i as u64));
    }
    s.revision_log = vec![(WalSeq(4), r[0].clone()), (WalSeq(9), r[1].clone())];
    s
}

/// One base: a record or a checkpoint content, its bytes, and its logical form.
struct Base {
    entry: u8,
    cap: u64,
    checkpoint_seq: u64,
    anchor: [u8; 32],
    label: String,
    bytes: Vec<u8>,
    /// `None`: a hand-made input the decoder refuses (no logical form, one op-0 case).
    lf: Option<Vec<u64>>,
    mutate: bool,
}

fn record_base(label: String, r: &WalRecord, mutate: bool) -> Base {
    let mut lf = Lf::default();
    lf.record(r);
    Base {
        entry: ENTRY_RECORD,
        cap: CAP,
        checkpoint_seq: 0,
        anchor: [0u8; 32],
        label,
        bytes: encode_record(r).unwrap(),
        lf: Some(lf.0),
        mutate,
    }
}

fn checkpoint_base(label: &str, s: &CheckpointState) -> Base {
    let mut lf = Lf::default();
    lf.checkpoint(s);
    Base {
        entry: ENTRY_CHECKPOINT,
        cap: 0,
        checkpoint_seq: s.checkpoint_seq.0,
        anchor: s.anchor_frame_sha256,
        label: label.into(),
        bytes: s.encode_content().unwrap(),
        lf: Some(lf.0),
        mutate: true,
    }
}

fn bases() -> Vec<Base> {
    let mut out = Vec::new();
    let mut first_of_kind = BTreeSet::new();
    for (i, json) in fixture_json_records().iter().enumerate() {
        let r: WalRecord = serde_json::from_slice(json).unwrap();
        // The A1 malformed corpus mutates the first record of each kind of the v1 log.
        let mutate = first_of_kind.insert(r.kind_byte());
        out.push(record_base(format!("fixture record {i}"), &r, mutate));
    }
    for (i, r) in edge_records().iter().enumerate() {
        out.push(record_base(format!("edge record {i}"), r, false));
    }
    for (i, r) in revision_records().iter().enumerate() {
        out.push(record_base(format!("revision record {i}"), r, i < 2));
    }
    let fixture = checkpoint_base("fixture checkpoint", &fixture_state());
    let revision = checkpoint_base("revision checkpoint", &revision_state());
    // Hand-made inputs no mutation reaches: record kinds 9 to 11 (reserved by open PRs, refused
    // on `main`), a revision section that is empty, and one that holds a kind 6 record.
    for kind in 9u8..=11 {
        out.push(refused_base(
            format!("reserved record kind {kind}"),
            ENTRY_RECORD,
            CAP,
            0,
            [0u8; 32],
            vec![CODEC_V2, kind, 0, 0],
        ));
    }
    let mut empty_section = fixture.bytes.clone();
    empty_section.extend_from_slice(&0u32.to_le_bytes());
    out.push(refused_base(
        "empty revision section".into(),
        ENTRY_CHECKPOINT,
        0,
        fixture.checkpoint_seq,
        fixture.anchor,
        empty_section,
    ));
    // Two projections, the second renumbered below the first: keys out of order.
    let mut two = fixture_state();
    let mut p = two.github_projections.values().next().unwrap().clone();
    let first = p.pr_number;
    p.pr_number = first + 1;
    let p_bytes = encode_record(&WalRecord::GitProjected {
        projection: p.clone(),
    })
    .unwrap()[2..]
        .to_vec();
    two.github_projections.insert(p.pr_number, p.clone());
    let mut misordered = two.encode_content().unwrap();
    let at = misordered
        .windows(p_bytes.len())
        .position(|w| w == p_bytes.as_slice())
        .unwrap();
    let num_at = at + 4 + p.repo_id.as_str().len();
    misordered[num_at..num_at + 8].copy_from_slice(&(first - 1).to_le_bytes());
    out.push(refused_base(
        "projections out of order".into(),
        ENTRY_CHECKPOINT,
        0,
        two.checkpoint_seq.0,
        two.anchor_frame_sha256,
        misordered,
    ));
    out.extend(equal_key_bases(&fixture_state()));
    out.extend(repo_id_bases());
    let mut same_seq = revision_state();
    same_seq.revision_log[1].0 = same_seq.revision_log[0].0;
    out.push(refused_base(
        "revision records with equal seqs".into(),
        ENTRY_CHECKPOINT,
        0,
        same_seq.checkpoint_seq.0,
        same_seq.anchor_frame_sha256,
        same_seq.encode_content().unwrap(),
    ));
    let mut wrong_kind = revision_state();
    let lease = WalRecord::LeaseUpdated {
        changeset_id: ChangesetId(derived32("j1 lease")),
        lease_expires_at_ms: 1,
    };
    wrong_kind.revision_log = vec![(WalSeq(2), lease)];
    out.push(refused_base(
        "revision section holding kind 6".into(),
        ENTRY_CHECKPOINT,
        0,
        wrong_kind.checkpoint_seq.0,
        wrong_kind.anchor_frame_sha256,
        wrong_kind.encode_content().unwrap(),
    ));
    out.push(fixture);
    out.push(revision);
    out
}

/// Hand-made checkpoints whose map holds two entries with equal keys (each map's keys must be
/// strictly increasing): the map's first entry is cloned under a fresh key above it, the state
/// is encoded, and the clone's key bytes are set back to the first key.
fn equal_key_bases(s: &CheckpointState) -> Vec<Base> {
    fn above(mut k: [u8; 32]) -> [u8; 32] {
        assert!(k[31] < 255, "test key ends in 0xff");
        k[31] += 1;
        k
    }
    /// `content` with its only occurrence of `from` replaced by `to` (lengths may differ: the
    /// patched run is a length-prefixed string or fixed bytes).
    fn patched(content: &[u8], from: &[u8], to: &[u8]) -> Vec<u8> {
        let hits: Vec<usize> = content
            .windows(from.len())
            .enumerate()
            .filter(|(_, w)| *w == from)
            .map(|(i, _)| i)
            .collect();
        assert_eq!(hits.len(), 1, "the clone's key must occur exactly once");
        let mut v = content.to_vec();
        v.splice(hits[0]..hits[0] + from.len(), to.iter().copied());
        v
    }
    let le = |v: u64| v.to_le_bytes();
    let mut out = Vec::new();
    let mut push = |label: &str, t: &CheckpointState, from: Vec<u8>, to: Vec<u8>| {
        out.push(refused_base(
            format!("equal keys: {label}"),
            ENTRY_CHECKPOINT,
            0,
            t.checkpoint_seq.0,
            t.anchor_frame_sha256,
            patched(&t.encode_content().unwrap(), &from, &to),
        ));
    };

    let (id, first) = s.changesets.iter().next().expect("fixture changeset");
    let mut t = s.clone();
    let mut c = first.clone();
    c.changeset_id = ChangesetId(above(id.0));
    t.changesets.insert(c.changeset_id, c.clone());
    let seq = le(c.committed_seq.0);
    push(
        "changesets",
        &t,
        [&c.changeset_id.0[..], &seq].concat(),
        [&id.0[..], &seq].concat(),
    );

    let ((repo, key), v) = s
        .idempotency_index
        .iter()
        .next()
        .expect("fixture idempotency entry");
    let mut t = s.clone();
    let key2 = IdempotencyKey(above(key.0));
    t.idempotency_index.insert((repo.clone(), key2), *v);
    let seq = le(v.0 .0);
    push(
        "idempotency index",
        &t,
        [&key2.0[..], &seq].concat(),
        [&key.0[..], &seq].concat(),
    );

    let mut t = s.clone();
    let d = BlobDigest::compute(b"j1 equal key blob");
    t.blob_first_visible_seq.insert(d, WalSeq(1));
    let d2 = BlobDigest(above(d.0));
    t.blob_first_visible_seq.insert(d2, WalSeq(1));
    push(
        "blob visibility",
        &t,
        [&d2.0[..], &le(1)].concat(),
        [&d.0[..], &le(1)].concat(),
    );

    let first = s
        .github_projections
        .values()
        .next()
        .expect("fixture projection");
    let mut t = s.clone();
    let mut p = first.clone();
    p.pr_number = first.pr_number + 1;
    t.github_projections.insert(p.pr_number, p.clone());
    let head = |n: u64| {
        let r = p.repo_id.as_str().as_bytes();
        [
            &(r.len() as u32).to_le_bytes()[..],
            r,
            &le(n),
            &p.changeset_id.0,
        ]
        .concat()
    };
    push("projections", &t, head(p.pr_number), head(first.pr_number));

    let (repo, h) = s
        .canonical_heads
        .iter()
        .next()
        .expect("fixture canonical head");
    let mut t = s.clone();
    let repo2 = RepoId::new(format!("{}-j1", repo.as_str())).unwrap();
    let mut h2 = h.clone();
    h2.repo_id = repo2.clone();
    t.canonical_heads.insert(repo2.clone(), h2);
    let run = |r: &RepoId| {
        let b = r.as_str().as_bytes();
        [&(b.len() as u32).to_le_bytes()[..], b].concat()
    };
    push("canonical heads", &t, run(&repo2), run(repo));
    out
}

/// Hand-made records whose repository id breaks one `RepoId::new` rule each (bit flips reach
/// only some of them): a projection record with its repository id bytes replaced.
fn repo_id_bases() -> Vec<Base> {
    let p = fixture_json_records()
        .iter()
        .map(|j| serde_json::from_slice::<WalRecord>(j).unwrap())
        .find(|r| r.kind_byte() == 4)
        .expect("fixture projection record");
    let bytes = encode_record(&p).unwrap();
    let n = u32::from_le_bytes(bytes[2..6].try_into().unwrap()) as usize;
    assert!(n >= 4, "fixture repository id too short");
    let good = bytes[6..6 + n].to_vec();
    let with = |label: &str, repo: Vec<u8>| {
        let mut b = bytes[..2].to_vec();
        b.extend_from_slice(&(repo.len() as u32).to_le_bytes());
        b.extend_from_slice(&repo);
        b.extend_from_slice(&bytes[6 + n..]);
        refused_base(
            format!("repository id: {label}"),
            ENTRY_RECORD,
            CAP,
            0,
            [0u8; 32],
            b,
        )
    };
    let at = |i: usize, s: &[u8]| {
        let mut r = good.clone();
        r[i..i + s.len()].copy_from_slice(s);
        r
    };
    vec![
        with("empty", Vec::new()),
        with("129 bytes", vec![b'a'; 129]),
        with("leading slash", at(0, b"/")),
        with("trailing slash", at(n - 1, b"/")),
        with("double slash", at(1, b"//")),
        with("double dot", at(1, b"..")),
        with("space", at(1, b" ")),
        with("two-byte UTF-8 letter", at(1, "\u{e9}".as_bytes())),
    ]
}

fn refused_base(
    label: String,
    entry: u8,
    cap: u64,
    checkpoint_seq: u64,
    anchor: [u8; 32],
    bytes: Vec<u8>,
) -> Base {
    Base {
        entry,
        cap,
        checkpoint_seq,
        anchor,
        label,
        bytes,
        lf: None,
        mutate: false,
    }
}

/// The A1 mutation set (`a1_malformed_corpus.rs` `mutations`): every truncation, every bit
/// flip, and a false `u32` length at every offset.
fn mutations(bytes: &[u8]) -> Vec<(u8, u32, u32, Vec<u8>)> {
    let mut out = Vec::new();
    for n in 0..bytes.len() {
        out.push((OP_TRUNCATE, n as u32, 0, bytes[..n].to_vec()));
    }
    for bit in 0..bytes.len() * 8 {
        let mut b = bytes.to_vec();
        b[bit / 8] ^= 1 << (bit % 8);
        out.push((OP_FLIP, bit as u32, 0, b));
    }
    for off in 0..bytes.len().saturating_sub(3) {
        let remaining = (bytes.len() - off - 4) as u64;
        for declared in [remaining + 1, CAP + 1, u64::from(u32::MAX)] {
            let mut b = bytes.to_vec();
            b[off..off + 4].copy_from_slice(&(declared as u32).to_le_bytes());
            out.push((OP_FALSE_LENGTH, off as u32, declared as u32, b));
        }
    }
    out
}

/// The cases of one base: its A1 mutations, or itself when it is a hand-made refusal.
fn cases_of(b: &Base) -> Vec<(u8, u32, u32, Vec<u8>)> {
    match (&b.lf, b.mutate) {
        (None, _) => vec![(OP_AS_IS, 0, 0, b.bytes.clone())],
        (Some(_), true) => mutations(&b.bytes),
        (Some(_), false) => Vec::new(),
    }
}

/// `(kind, at, x, y, field)`; kind 0 is an accept.
type Outcome = (u8, u32, u32, u32, u8);

fn field_id(f: &str) -> u8 {
    let i = FIELDS.iter().position(|&n| n == f);
    i.map(|i| i as u8 + 1)
        .unwrap_or_else(|| panic!("field {f:?} missing from the J1 field table"))
}

fn n32<T: TryInto<u32>>(v: T) -> u32 {
    v.try_into()
        .unwrap_or_else(|_| panic!("refusal value above u32"))
}

fn outcome_of(r: &CodecRefusal) -> Outcome {
    let k = KINDS.iter().position(|&n| n == r.kind()).unwrap() as u8 + 1;
    match r {
        CodecRefusal::Truncated { at, need } => (k, n32(*at), n32(*need), 0, 0),
        CodecRefusal::LengthOverCap { at, declared, cap } => {
            (k, n32(*at), n32(*declared), n32(*cap), 0)
        }
        CodecRefusal::TrailingBytes { at, count } => (k, n32(*at), n32(*count), 0, 0),
        CodecRefusal::UnknownTag { at, field, tag } => {
            (k, n32(*at), u32::from(*tag), 0, field_id(field))
        }
        CodecRefusal::InvalidUtf8 { at } => (k, n32(*at), 0, 0, 0),
        CodecRefusal::VersionUnsupported { found } => (k, 0, u32::from(*found), 0, 0),
        CodecRefusal::NotCanonical { at, field } => (k, n32(*at), 0, 0, field_id(field)),
        CodecRefusal::InvalidRepoId { at } => (k, n32(*at), 0, 0, 0),
        CodecRefusal::EmbeddedMalformed { at, field, code } => {
            let c = CODES.iter().position(|x| x == code).unwrap_or_else(|| {
                panic!("embedded refusal code {code:?} missing from the J1 code table")
            });
            (k, n32(*at), c as u32 + 1, 0, field_id(field))
        }
    }
}

/// What the Rust decoder does with `m` under base `b`. An accept must be canonical.
fn decide(b: &Base, m: &[u8]) -> Outcome {
    match b.entry {
        ENTRY_RECORD => match decode_record(m, b.cap) {
            Ok(r) => {
                assert_eq!(
                    encode_record(&r).unwrap(),
                    m,
                    "{}: non-canonical accept",
                    b.label
                );
                (0, 0, 0, 0, 0)
            }
            Err(e) => outcome_of(&e),
        },
        _ => match CheckpointState::decode_content(m, WalSeq(b.checkpoint_seq), b.anchor) {
            Ok(s) => {
                assert_eq!(
                    s.encode_content().unwrap(),
                    m,
                    "{}: non-canonical accept",
                    b.label
                );
                (0, 0, 0, 0, 0)
            }
            Err(e) => outcome_of(&e),
        },
    }
}

// ---------------------------------------------------------------------------------------
// File
// ---------------------------------------------------------------------------------------

fn put_name(out: &mut Vec<u8>, s: &str) {
    out.extend_from_slice(&(s.len() as u16).to_le_bytes());
    out.extend_from_slice(s.as_bytes());
}

/// Corpus bytes and a per-class tally `(class, cases, refused)`.
fn build() -> (Vec<u8>, BTreeMap<String, (usize, usize)>) {
    let bases = bases();
    let mut out = Vec::new();
    out.extend_from_slice(&MAGIC);
    out.extend_from_slice(&VERSION.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&(CAP as u32).to_le_bytes());
    // Rust layout sizes the record decoder's reservation check depends on (LengthOverCap).
    let layout = [
        std::mem::size_of::<EvidenceAttachment>(),
        std::mem::size_of::<PathMutation>(),
        std::mem::size_of::<ReviewRecord>(),
        std::mem::size_of::<String>(),
    ];
    out.extend_from_slice(&(layout.len() as u32).to_le_bytes());
    for s in layout {
        out.extend_from_slice(&(s as u32).to_le_bytes());
    }
    let codes: Vec<String> = CODES.iter().map(|c| format!("{c:?}")).collect();
    for table in [
        FIELDS.to_vec(),
        codes.iter().map(String::as_str).collect(),
        KINDS.to_vec(),
    ] {
        out.extend_from_slice(&(table.len() as u32).to_le_bytes());
        table.iter().for_each(|n| put_name(&mut out, n));
    }
    out.extend_from_slice(&(bases.len() as u32).to_le_bytes());
    for b in &bases {
        // A base with a logical form is accepted as is; a hand-made one is refused.
        let refused = decide(b, &b.bytes).0 != 0;
        assert_eq!(refused, b.lf.is_none(), "{}: unexpected outcome", b.label);
        out.push(b.entry);
        out.extend_from_slice(&b.cap.to_le_bytes());
        out.extend_from_slice(&b.checkpoint_seq.to_le_bytes());
        put_name(&mut out, &b.label);
        out.extend_from_slice(&(b.bytes.len() as u32).to_le_bytes());
        out.extend_from_slice(&b.bytes);
        match &b.lf {
            Some(lf) => {
                out.extend_from_slice(&(lf.len() as u32).to_le_bytes());
                lf.iter()
                    .for_each(|c| out.extend_from_slice(&c.to_le_bytes()));
            }
            None => out.extend_from_slice(&u32::MAX.to_le_bytes()),
        }
    }
    let mut cases = Vec::new();
    let mut n_cases: u32 = 0;
    let mut tally: BTreeMap<String, (usize, usize)> = BTreeMap::new();
    for (i, b) in bases.iter().enumerate() {
        let entry = if b.entry == ENTRY_RECORD {
            "record"
        } else {
            "checkpoint"
        };
        for (op, pos, declared, m) in cases_of(b) {
            let o = decide(b, &m);
            cases.extend_from_slice(&(i as u16).to_le_bytes());
            cases.push(op);
            cases.extend_from_slice(&pos.to_le_bytes());
            if op == OP_FALSE_LENGTH {
                cases.extend_from_slice(&declared.to_le_bytes());
            }
            cases.push(o.0);
            if o.0 != 0 {
                cases.extend_from_slice(&o.1.to_le_bytes());
                cases.extend_from_slice(&o.2.to_le_bytes());
                cases.extend_from_slice(&o.3.to_le_bytes());
                cases.push(o.4);
            }
            n_cases += 1;
            let class = ["hand_made", "truncated", "bit_flipped", "false_length"][op as usize];
            let t = tally.entry(format!("{entry}_{class}")).or_default();
            t.0 += 1;
            t.1 += usize::from(o.0 != 0);
        }
    }
    out.extend_from_slice(&n_cases.to_le_bytes());
    out.extend_from_slice(&cases);
    let seal: [u8; 32] = Sha256::digest(&out).into();
    out.extend_from_slice(&seal);
    (out, tally)
}

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

#[test]
fn j1_sealed_corpus_is_what_the_rust_codec_gives() {
    let (bytes, tally) = build();
    let digest = hex::encode(Sha256::digest(&bytes));
    let path = repo_root().join(CORPUS_PATH);
    if std::env::var_os("J1_CORPUS_WRITE").is_some() {
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(&path, &bytes).unwrap();
        println!(
            "wrote {} ({} bytes, sha256 {digest})",
            path.display(),
            bytes.len()
        );
    }
    let mut total = 0;
    for (class, (cases, refused)) in &tally {
        total += cases;
        println!(
            "  {class}: {cases} cases, {refused} refused, {} accepted (canonical)",
            cases - refused
        );
    }
    println!(
        "  total malformed cases: {total}; corpus {} bytes, sha256 {digest}",
        bytes.len()
    );
    let sealed = fs::read(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    assert!(
        sealed == bytes,
        "the sealed corpus differs from what the codec gives today"
    );
    assert_eq!(
        digest, CORPUS_SHA256,
        "the corpus seal moved; update CORPUS_SHA256 with the file"
    );
}

#[test]
fn j1_corpus_covers_every_record_kind_on_main_and_every_refusal_kind() {
    let bases = bases();
    let kinds: BTreeSet<u8> = bases
        .iter()
        .filter(|b| b.entry == ENTRY_RECORD && b.lf.is_some())
        .map(|b| b.bytes[1])
        .collect();
    assert_eq!(kinds, (1u8..=8).collect(), "record kinds 1 to 8");
    let mutated: BTreeSet<u8> = bases
        .iter()
        .filter(|b| b.entry == ENTRY_RECORD && b.mutate)
        .map(|b| b.bytes[1])
        .collect();
    assert_eq!(mutated, (1u8..=8).collect(), "every kind is mutated");
    let mut seen = BTreeSet::new();
    let mut fields = BTreeSet::new();
    for b in &bases {
        for (_, _, _, m) in cases_of(b) {
            let o = decide(b, &m);
            seen.insert(o.0);
            fields.insert(o.4);
        }
    }
    assert_eq!(
        seen,
        (0u8..=9).collect(),
        "every refusal kind and an accept are present"
    );
    assert_eq!(fields, (0u8..=15).collect(), "every field id is reached");
    // One encoding per logical form: equal forms have equal bytes, and the other way round.
    let pairs: BTreeSet<(&Vec<u64>, &Vec<u8>)> = bases
        .iter()
        .filter_map(|b| b.lf.as_ref().map(|lf| (lf, &b.bytes)))
        .collect();
    let forms: BTreeSet<&Vec<u64>> = pairs.iter().map(|p| p.0).collect();
    let encodings: BTreeSet<&Vec<u8>> = pairs.iter().map(|p| p.1).collect();
    assert_eq!(forms.len(), pairs.len());
    assert_eq!(encodings.len(), pairs.len());
}
