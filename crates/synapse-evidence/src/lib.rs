//! Evidence receipts bound to a `ChangesetId` and the `CrumbContextDigest` the runner saw
//! (ADR 0004 deliverable D4).
//!
//! An [`EvidenceReceipt`] is a separate, versioned, Ed25519-signed record. It references a
//! changeset by its `ChangesetId`; it is not part of the `ChangesetEnvelope` and does not
//! replace the envelope's `EvidenceAttachment` list. Record version 1 is shaped so that it
//! can grow into ADR 0003's E1 receipt (section 5.5) under a later `record_version`, not
//! into a second format.
//!
//! What a v1 receipt binds:
//!
//! * the repository and the `ChangesetId` under test;
//! * the source revision the changeset was built on ([`SourceRevision`]: its base `GitOid`
//!   and parent `ChangesetId`s, exactly as the envelope states them);
//! * one [`CrumbContextBinding`] per distinct directory of the changed path set, holding two
//!   `CrumbContextDigest`s of that directory's Directory Crumb context: at the base revision
//!   (what the author saw) and in the changeset's own tree (what the runner tested under);
//! * the inputs, named by an [`InputRootDigest`] over a list of repository members (one
//!   member in v1; ADR 0003 L1's composite multi-repository input root is the same digest
//!   over more than one member);
//! * the test identity ([`TestIdentity`]: name, command, toolchain, platform, environment);
//! * the result ([`ReceiptResult`]: exit status, typed [`Outcome`], declared output digests);
//! * an [`Observation`] (log bytes and timings), stored and signed with the receipt but
//!   excluded from its identity.
//!
//! Identity. The [`ResultDigest`] covers the exit status, the outcome, and the declared
//! output digests only. The [`EvidenceReceiptId`] covers the record version, the
//! [`EvidenceActionDigest`] (what was run, on what, under which context), the
//! `ResultDigest`, and the executor. Logs and timings never enter either digest, so two runs
//! that differ only in their observation have the same identity (ADR 0003 section 5.5).
//!
//! Authority. A receipt never grants publication. AEGIS stays the sole execution and
//! publication authority, and Radicle canonical promotion stays independent of receipts. A
//! valid receipt only states which context, inputs, and test produced which result.
//!
//! Coordination records (claims, scents, whispers, presence) are never evidence: no field of
//! a receipt holds or references one, and nothing in this crate reads the coordination
//! plane.
//!
//! Storage of receipts is out of scope for this crate: it encodes, decodes, signs, and
//! verifies records only.

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use sha2::{Digest, Sha256};
use std::fmt;
use synapse_core::{
    decode_did_key_ed25519, encode_did_key_ed25519, validate_repo_relative_path, ChangesetId,
    GitOid, RepoId,
};
use synapse_crumb::{CrumbContextDigest, ROOT_DIR};

/// The only receipt record version this crate reads or writes.
pub const EVIDENCE_RECEIPT_VERSION_V1: u16 = 1;

/// Domain tag that opens every encoded receipt record.
pub const DOMAIN_EVIDENCE_RECEIPT_V1: &[u8] = b"SYNAPSE_EVIDENCE_RECEIPT_V1\0";
/// Domain tag for the executor's Ed25519 signature over a receipt.
pub const DOMAIN_EVIDENCE_RECEIPT_SIGN_V1: &[u8] = b"SYNAPSE_EVIDENCE_RECEIPT_SIGN_V1\0";
/// Domain tag for [`EvidenceReceiptId`].
pub const DOMAIN_EVIDENCE_RECEIPT_ID_V1: &[u8] = b"SYNAPSE_EVIDENCE_RECEIPT_ID_V1\0";
/// Domain tag for [`EvidenceActionDigest`].
pub const DOMAIN_EVIDENCE_ACTION_V1: &[u8] = b"SYNAPSE_EVIDENCE_ACTION_V1\0";
/// Domain tag for [`ResultDigest`].
pub const DOMAIN_EVIDENCE_RESULT_V1: &[u8] = b"SYNAPSE_EVIDENCE_RESULT_V1\0";
/// Domain tag for [`InputRootDigest`].
pub const DOMAIN_EVIDENCE_INPUT_ROOT_V1: &[u8] = b"SYNAPSE_EVIDENCE_INPUT_ROOT_V1\0";
/// Domain tag for [`OutputDigest::of_bytes`].
pub const DOMAIN_EVIDENCE_OUTPUT_V1: &[u8] = b"SYNAPSE_EVIDENCE_OUTPUT_V1\0";

/// Maximum bytes of any string field.
pub const MAX_STRING_BYTES: usize = 4096;
/// Maximum number of items in any list field (parents, contexts, arguments, environment, outputs).
pub const MAX_LIST_ITEMS: usize = 4096;
/// Maximum bytes of the observation log carried inline.
pub const MAX_LOG_BYTES: usize = 1024 * 1024;
/// Maximum bytes of one whole encoded receipt record: the log cap plus 1 MiB for every other
/// field. [`EvidenceReceipt::decode`] checks it before parsing or allocating anything, and
/// [`EvidenceReceipt::sign`] and [`EvidenceReceipt::encode`] refuse to produce a larger record.
/// The per-field caps alone would allow a record of about 100 MB.
pub const MAX_RECEIPT_BYTES: usize = MAX_LOG_BYTES + 1024 * 1024;

/// Input root member kind tag for "a whole Synapse changeset tree" (the only v1 kind).
const INPUT_MEMBER_CHANGESET: u8 = 1;

macro_rules! digest32 {
    ($(#[$m:meta])* $name:ident) => {
        $(#[$m])*
        #[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $name(pub [u8; 32]);

        impl $name {
            pub fn to_hex(self) -> String {
                hex::encode(self.0)
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, concat!(stringify!($name), "({})"), self.to_hex())
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&self.to_hex())
            }
        }
    };
}

digest32!(
    /// Identity of one receipt (`"SYNAPSE_EVIDENCE_RECEIPT_ID_V1\0"`): record version, action
    /// digest, result digest, executor. Never a `BlobDigest`, `ChangesetId`, or
    /// `CrumbContextDigest`.
    EvidenceReceiptId
);
digest32!(
    /// What was run, on what, under which Directory Crumb context
    /// (`"SYNAPSE_EVIDENCE_ACTION_V1\0"`). The v1 stand-in for ADR 0003's `ActionDigest`.
    EvidenceActionDigest
);
digest32!(
    /// The deterministic part of a result (`"SYNAPSE_EVIDENCE_RESULT_V1\0"`): exit status,
    /// outcome, declared output digests. Logs and timings are never part of it.
    ResultDigest
);
digest32!(
    /// Digest of the inputs a run read (`"SYNAPSE_EVIDENCE_INPUT_ROOT_V1\0"`), over a sorted
    /// list of repository members. One member in v1.
    InputRootDigest
);
digest32!(
    /// Digest of one declared output. [`OutputDigest::of_bytes`] computes it with the
    /// `"SYNAPSE_EVIDENCE_OUTPUT_V1\0"` tag; a runner may supply its own 32 bytes.
    OutputDigest
);

impl OutputDigest {
    /// Domain-separated SHA-256 of an output's bytes.
    pub fn of_bytes(bytes: &[u8]) -> Self {
        let mut h = Sha256::new();
        h.update(DOMAIN_EVIDENCE_OUTPUT_V1);
        h.update((bytes.len() as u64).to_le_bytes());
        h.update(bytes);
        Self(h.finalize().into())
    }
}

/// Why a receipt was refused. Every refusal is typed; nothing is accepted by default.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReceiptError {
    /// The record does not open with `"SYNAPSE_EVIDENCE_RECEIPT_V1\0"`.
    WrongDomain,
    /// The record version is not one this crate understands.
    UnknownVersion(u16),
    /// The record ends before a field is complete.
    Truncated,
    /// Bytes remain after the signature.
    TrailingBytes,
    /// A string, list, or log is longer than its cap.
    OverCap(&'static str),
    /// A string field is not UTF-8.
    NotUtf8(&'static str),
    /// An enum tag byte has no meaning.
    UnknownTag(&'static str, u8),
    /// A list that must be strictly sorted and unique is not.
    Unsorted(&'static str),
    /// A field that must not be empty is empty.
    Empty(&'static str),
    /// A directory or path is not a clean repository-relative path.
    InvalidPath(String),
    /// The repository identifier is not valid.
    InvalidRepoId(String),
    /// The input root has a member count this record version does not support (v1: one).
    InputRootUnsupported(usize),
    /// The input root does not name the receipt's own repository and changeset.
    InputRootMismatch,
    /// The outcome contradicts the exit status (a `Pass` must exit with code 0, a `Fail` must not).
    OutcomeInconsistent,
    /// The executor's `did:key` is not an Ed25519 key.
    ExecutorDidInvalid,
    /// The Ed25519 signature does not verify over the signed bytes.
    SignatureInvalid,
}

impl fmt::Display for ReceiptError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "evidence receipt refused: {self:?}")
    }
}

impl std::error::Error for ReceiptError {}

/// The revision a changeset was built on, exactly as its envelope states it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceRevision {
    pub base_git_oid: GitOid,
    /// Strictly sorted and unique, as in the envelope.
    pub parent_changesets: Vec<ChangesetId>,
}

/// The Directory Crumb context of one directory, on both sides of the changeset. The two
/// digests differ when the changeset edits a `.crumb` on that directory's chain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CrumbContextBinding {
    /// `"."` for the repository root, else a repository-relative directory.
    pub dir: String,
    /// Context at the changeset's base: what the author saw.
    pub at_base: CrumbContextDigest,
    /// Context in the changeset's own tree (the input root): what the runner tested under.
    pub in_changeset: CrumbContextDigest,
}

/// One repository's contribution to an input root.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InputRootMember {
    pub repo_id: RepoId,
    /// The whole tree of this changeset is the input from this repository.
    pub changeset_id: ChangesetId,
}

/// The inputs a run read. v1 has exactly one member: the receipt's own repository and
/// changeset. ADR 0003 L1 extends this to several members sorted by `repo_id` (the
/// composite multi-repository input root) under a later record version; a later member kind
/// can name a `TreeDigest` instead of a changeset (ADR 0003 C1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InputRoot {
    pub members: Vec<InputRootMember>,
}

impl InputRoot {
    /// The v1 input root: the whole tree of one changeset in one repository.
    pub fn single_repo(repo_id: RepoId, changeset_id: ChangesetId) -> Self {
        Self {
            members: vec![InputRootMember {
                repo_id,
                changeset_id,
            }],
        }
    }

    /// Domain-separated digest over the member count and each member's repository, kind
    /// tag, and root.
    pub fn digest(&self) -> InputRootDigest {
        let mut h = Sha256::new();
        h.update(DOMAIN_EVIDENCE_INPUT_ROOT_V1);
        h.update((self.members.len() as u64).to_le_bytes());
        for m in &self.members {
            hash_str(&mut h, m.repo_id.as_str());
            h.update([INPUT_MEMBER_CHANGESET]);
            h.update(m.changeset_id.0);
        }
        InputRootDigest(h.finalize().into())
    }
}

/// One environment variable the test ran with.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnvVar {
    pub name: String,
    pub value: String,
}

/// What was run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TestIdentity {
    /// Stable name of the test or gate (for example `"cargo-test-workspace"`).
    pub name: String,
    /// Exact argument vector, program first.
    pub command: Vec<String>,
    /// Toolchain identity (for example `"rustc 1.89.0"`).
    pub toolchain: String,
    /// Platform identity (for example `"aarch64-unknown-linux-gnu"`).
    pub platform: String,
    /// Strictly sorted by name and unique.
    pub environment: Vec<EnvVar>,
}

/// How the test process ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExitStatus {
    Code(i32),
    Signal(i32),
}

/// The typed verdict of a run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// Every declared check passed. Requires exit code 0.
    Pass,
    /// A declared check failed. Requires an exit status other than code 0.
    Fail,
    /// The runner saw different results for the same action. Never a pass.
    Flaky,
    /// The run could not produce a verdict (harness or infrastructure failure). Never a pass.
    Error,
}

impl Outcome {
    /// `true` only for [`Outcome::Pass`]. `Flaky` and `Error` never count as a pass.
    pub fn is_pass(self) -> bool {
        matches!(self, Outcome::Pass)
    }

    fn tag_byte(self) -> u8 {
        match self {
            Outcome::Pass => 1,
            Outcome::Fail => 2,
            Outcome::Flaky => 3,
            Outcome::Error => 4,
        }
    }
}

/// One output the action declares (a built artifact, a per-test verdict file).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeclaredOutput {
    pub name: String,
    pub digest: OutputDigest,
}

/// The deterministic part of a result. Its digest is the [`ResultDigest`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReceiptResult {
    pub exit_status: ExitStatus,
    pub outcome: Outcome,
    /// Strictly sorted by name and unique.
    pub outputs: Vec<DeclaredOutput>,
}

impl ReceiptResult {
    pub fn digest(&self) -> ResultDigest {
        let mut buf = Vec::new();
        put_result(&mut buf, self);
        let mut h = Sha256::new();
        h.update(DOMAIN_EVIDENCE_RESULT_V1);
        h.update((buf.len() as u64).to_le_bytes());
        h.update(&buf);
        ResultDigest(h.finalize().into())
    }
}

/// The observation part: stored and signed with the receipt, never part of its identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Observation {
    pub started_at_ms: u64,
    pub duration_ms: u64,
    /// At most [`MAX_LOG_BYTES`].
    pub log: Vec<u8>,
}

/// Everything a receipt states, before it is signed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReceiptBody {
    pub repo_id: RepoId,
    pub changeset_id: ChangesetId,
    pub source: SourceRevision,
    /// One per distinct directory of the changeset's mutated paths (a path's parent, `"."`
    /// for the root), strictly sorted by `dir`.
    pub crumb_contexts: Vec<CrumbContextBinding>,
    pub input_root: InputRoot,
    pub test: TestIdentity,
    pub result: ReceiptResult,
    pub observation: Observation,
}

impl ReceiptBody {
    /// Check every structural rule of record version 1.
    pub fn validate(&self) -> Result<(), ReceiptError> {
        strictly_sorted(
            self.source.parent_changesets.iter(),
            "source.parent_changesets",
        )?;
        cap_list(
            self.source.parent_changesets.len(),
            "source.parent_changesets",
        )?;

        if self.crumb_contexts.is_empty() {
            return Err(ReceiptError::Empty("crumb_contexts"));
        }
        cap_list(self.crumb_contexts.len(), "crumb_contexts")?;
        for c in &self.crumb_contexts {
            if c.dir != ROOT_DIR {
                validate_repo_relative_path(&c.dir)
                    .map_err(|_| ReceiptError::InvalidPath(c.dir.clone()))?;
            }
        }
        strictly_sorted(self.crumb_contexts.iter().map(|c| &c.dir), "crumb_contexts")?;

        match self.input_root.members.as_slice() {
            [m] => {
                if m.repo_id != self.repo_id || m.changeset_id != self.changeset_id {
                    return Err(ReceiptError::InputRootMismatch);
                }
            }
            other => return Err(ReceiptError::InputRootUnsupported(other.len())),
        }

        let t = &self.test;
        if t.name.is_empty() {
            return Err(ReceiptError::Empty("test.name"));
        }
        if t.command.is_empty() {
            return Err(ReceiptError::Empty("test.command"));
        }
        cap_str(&t.name, "test.name")?;
        cap_list(t.command.len(), "test.command")?;
        for a in &t.command {
            cap_str(a, "test.command")?;
        }
        cap_str(&t.toolchain, "test.toolchain")?;
        cap_str(&t.platform, "test.platform")?;
        cap_list(t.environment.len(), "test.environment")?;
        for e in &t.environment {
            cap_str(&e.name, "test.environment")?;
            cap_str(&e.value, "test.environment")?;
        }
        strictly_sorted(t.environment.iter().map(|e| &e.name), "test.environment")?;

        let r = &self.result;
        cap_list(r.outputs.len(), "result.outputs")?;
        for o in &r.outputs {
            cap_str(&o.name, "result.outputs")?;
        }
        strictly_sorted(r.outputs.iter().map(|o| &o.name), "result.outputs")?;
        let exited_zero = r.exit_status == ExitStatus::Code(0);
        match r.outcome {
            Outcome::Pass if !exited_zero => return Err(ReceiptError::OutcomeInconsistent),
            Outcome::Fail if exited_zero => return Err(ReceiptError::OutcomeInconsistent),
            _ => {}
        }

        if self.observation.log.len() > MAX_LOG_BYTES {
            return Err(ReceiptError::OverCap("observation.log"));
        }
        Ok(())
    }

    /// What was run, on what, under which context. Excludes the result and the observation.
    pub fn action_digest(&self) -> EvidenceActionDigest {
        let mut buf = Vec::new();
        put_str(&mut buf, self.repo_id.as_str());
        buf.extend_from_slice(&self.changeset_id.0);
        put_source(&mut buf, &self.source);
        put_contexts(&mut buf, &self.crumb_contexts);
        buf.extend_from_slice(&self.input_root.digest().0);
        put_test(&mut buf, &self.test);
        let mut h = Sha256::new();
        h.update(DOMAIN_EVIDENCE_ACTION_V1);
        h.update(EVIDENCE_RECEIPT_VERSION_V1.to_le_bytes());
        h.update((buf.len() as u64).to_le_bytes());
        h.update(&buf);
        EvidenceActionDigest(h.finalize().into())
    }
}

/// A signed evidence receipt, record version 1.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvidenceReceipt {
    pub record_version: u16,
    pub body: ReceiptBody,
    /// `did:key` of the executor's Ed25519 key.
    pub executor_did: String,
    pub signature: [u8; 64],
}

impl EvidenceReceipt {
    /// Validate `body` and sign it as record version 1 with the executor's key, named by its
    /// canonical `did:key`. Refuses a body whose record would exceed [`MAX_RECEIPT_BYTES`].
    pub fn sign(body: ReceiptBody, executor: &SigningKey) -> Result<Self, ReceiptError> {
        body.validate()?;
        let mut receipt = Self {
            record_version: EVIDENCE_RECEIPT_VERSION_V1,
            body,
            executor_did: encode_did_key_ed25519(&executor.verifying_key().to_bytes()),
            signature: [0; 64],
        };
        let signable = receipt.signable_bytes();
        // The record is the signable bytes with the record tag in place of the sign tag, plus
        // the 64-byte signature.
        let record_len = signable.len() - DOMAIN_EVIDENCE_RECEIPT_SIGN_V1.len()
            + DOMAIN_EVIDENCE_RECEIPT_V1.len()
            + 64;
        if record_len > MAX_RECEIPT_BYTES {
            return Err(ReceiptError::OverCap("receipt"));
        }
        receipt.signature = executor.sign(&signable).to_bytes();
        Ok(receipt)
    }

    /// Bytes the executor signs: sign tag, version, body (observation included), executor.
    pub fn signable_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(512 + self.body.observation.log.len());
        buf.extend_from_slice(DOMAIN_EVIDENCE_RECEIPT_SIGN_V1);
        buf.extend_from_slice(&self.record_version.to_le_bytes());
        put_body(&mut buf, &self.body);
        put_str(&mut buf, &self.executor_did);
        buf
    }

    /// Check version, structure, executor key, and signature (strict Ed25519). Returns the
    /// receipt's identity. A receipt that passes still grants nothing.
    pub fn verify(&self) -> Result<EvidenceReceiptId, ReceiptError> {
        if self.record_version != EVIDENCE_RECEIPT_VERSION_V1 {
            return Err(ReceiptError::UnknownVersion(self.record_version));
        }
        self.body.validate()?;
        let key_bytes = decode_did_key_ed25519(&self.executor_did)
            .map_err(|_| ReceiptError::ExecutorDidInvalid)?;
        // One key has exactly one accepted spelling (`did:key:z6Mk...`), so the receipt
        // identity, which hashes the DID string, is a function of the key.
        if self.executor_did != encode_did_key_ed25519(&key_bytes) {
            return Err(ReceiptError::ExecutorDidInvalid);
        }
        let key =
            VerifyingKey::from_bytes(&key_bytes).map_err(|_| ReceiptError::ExecutorDidInvalid)?;
        key.verify_strict(
            &self.signable_bytes(),
            &Signature::from_bytes(&self.signature),
        )
        .map_err(|_| ReceiptError::SignatureInvalid)?;
        Ok(self.id())
    }

    /// The deterministic part's digest: exit status, outcome, declared outputs.
    pub fn result_digest(&self) -> ResultDigest {
        self.body.result.digest()
    }

    /// Receipt identity: version, action digest, result digest, executor. Logs and timings
    /// are excluded. Computed without checking the signature; use [`Self::verify`].
    pub fn id(&self) -> EvidenceReceiptId {
        let mut h = Sha256::new();
        h.update(DOMAIN_EVIDENCE_RECEIPT_ID_V1);
        h.update(self.record_version.to_le_bytes());
        h.update(self.body.action_digest().0);
        h.update(self.result_digest().0);
        hash_str(&mut h, &self.executor_did);
        EvidenceReceiptId(h.finalize().into())
    }

    /// Canonical record bytes: record tag, version, body, executor, signature. Refuses an
    /// unknown version, a body that breaks a version 1 rule (so no length or count is ever
    /// truncated into its u32 prefix), and a record over [`MAX_RECEIPT_BYTES`]. Does not
    /// check the signature.
    pub fn encode(&self) -> Result<Vec<u8>, ReceiptError> {
        if self.record_version != EVIDENCE_RECEIPT_VERSION_V1 {
            return Err(ReceiptError::UnknownVersion(self.record_version));
        }
        self.body.validate()?;
        cap_str(&self.executor_did, "executor_did")?;
        let mut buf = Vec::with_capacity(512 + self.body.observation.log.len());
        buf.extend_from_slice(DOMAIN_EVIDENCE_RECEIPT_V1);
        buf.extend_from_slice(&self.record_version.to_le_bytes());
        put_body(&mut buf, &self.body);
        put_str(&mut buf, &self.executor_did);
        buf.extend_from_slice(&self.signature);
        if buf.len() > MAX_RECEIPT_BYTES {
            return Err(ReceiptError::OverCap("receipt"));
        }
        Ok(buf)
    }

    /// Parse canonical record bytes. Refuses a record over [`MAX_RECEIPT_BYTES`] first, then
    /// a wrong domain tag and an unknown version before reading anything else; every length
    /// is checked against its cap before any allocation. Does not verify the signature; see
    /// [`Self::decode_verified`].
    pub fn decode(bytes: &[u8]) -> Result<Self, ReceiptError> {
        if bytes.len() > MAX_RECEIPT_BYTES {
            return Err(ReceiptError::OverCap("receipt"));
        }
        let mut r = Reader { bytes, pos: 0 };
        if r.take(DOMAIN_EVIDENCE_RECEIPT_V1.len())
            .map_err(|_| ReceiptError::WrongDomain)?
            != DOMAIN_EVIDENCE_RECEIPT_V1
        {
            return Err(ReceiptError::WrongDomain);
        }
        let record_version = r.u16()?;
        if record_version != EVIDENCE_RECEIPT_VERSION_V1 {
            return Err(ReceiptError::UnknownVersion(record_version));
        }
        let body = read_body(&mut r)?;
        let executor_did = r.string("executor_did")?;
        let signature: [u8; 64] = r.array()?;
        if r.pos != bytes.len() {
            return Err(ReceiptError::TrailingBytes);
        }
        Ok(Self {
            record_version,
            body,
            executor_did,
            signature,
        })
    }

    /// [`Self::decode`] followed by [`Self::verify`].
    pub fn decode_verified(bytes: &[u8]) -> Result<(Self, EvidenceReceiptId), ReceiptError> {
        let receipt = Self::decode(bytes)?;
        let id = receipt.verify()?;
        Ok((receipt, id))
    }
}

// ---------------------------------------------------------------------------------------
// Canonical encoding. Integers are little-endian; strings and byte runs are prefixed with a
// u32 length; lists with a u32 count. The encoding is injective, so equal bytes mean equal
// records and any change to a field changes the signed bytes.

fn put_str(buf: &mut Vec<u8>, s: &str) {
    put_bytes(buf, s.as_bytes());
}

fn put_bytes(buf: &mut Vec<u8>, b: &[u8]) {
    buf.extend_from_slice(&(b.len() as u32).to_le_bytes());
    buf.extend_from_slice(b);
}

fn put_count(buf: &mut Vec<u8>, n: usize) {
    buf.extend_from_slice(&(n as u32).to_le_bytes());
}

fn hash_str(h: &mut Sha256, s: &str) {
    h.update((s.len() as u64).to_le_bytes());
    h.update(s.as_bytes());
}

fn put_source(buf: &mut Vec<u8>, s: &SourceRevision) {
    buf.extend_from_slice(&s.base_git_oid.0);
    put_count(buf, s.parent_changesets.len());
    for p in &s.parent_changesets {
        buf.extend_from_slice(&p.0);
    }
}

fn put_contexts(buf: &mut Vec<u8>, cs: &[CrumbContextBinding]) {
    put_count(buf, cs.len());
    for c in cs {
        put_str(buf, &c.dir);
        buf.extend_from_slice(&c.at_base.0);
        buf.extend_from_slice(&c.in_changeset.0);
    }
}

fn put_test(buf: &mut Vec<u8>, t: &TestIdentity) {
    put_str(buf, &t.name);
    put_count(buf, t.command.len());
    for a in &t.command {
        put_str(buf, a);
    }
    put_str(buf, &t.toolchain);
    put_str(buf, &t.platform);
    put_count(buf, t.environment.len());
    for e in &t.environment {
        put_str(buf, &e.name);
        put_str(buf, &e.value);
    }
}

fn put_result(buf: &mut Vec<u8>, r: &ReceiptResult) {
    let (tag, value) = match r.exit_status {
        ExitStatus::Code(c) => (1u8, c),
        ExitStatus::Signal(s) => (2u8, s),
    };
    buf.push(tag);
    buf.extend_from_slice(&value.to_le_bytes());
    buf.push(r.outcome.tag_byte());
    put_count(buf, r.outputs.len());
    for o in &r.outputs {
        put_str(buf, &o.name);
        buf.extend_from_slice(&o.digest.0);
    }
}

fn put_body(buf: &mut Vec<u8>, b: &ReceiptBody) {
    put_str(buf, b.repo_id.as_str());
    buf.extend_from_slice(&b.changeset_id.0);
    put_source(buf, &b.source);
    put_contexts(buf, &b.crumb_contexts);
    put_count(buf, b.input_root.members.len());
    for m in &b.input_root.members {
        put_str(buf, m.repo_id.as_str());
        buf.push(INPUT_MEMBER_CHANGESET);
        buf.extend_from_slice(&m.changeset_id.0);
    }
    put_test(buf, &b.test);
    put_result(buf, &b.result);
    buf.extend_from_slice(&b.observation.started_at_ms.to_le_bytes());
    buf.extend_from_slice(&b.observation.duration_ms.to_le_bytes());
    put_bytes(buf, &b.observation.log);
}

struct Reader<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], ReceiptError> {
        let end = self.pos.checked_add(n).ok_or(ReceiptError::Truncated)?;
        let out = self
            .bytes
            .get(self.pos..end)
            .ok_or(ReceiptError::Truncated)?;
        self.pos = end;
        Ok(out)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], ReceiptError> {
        let mut out = [0u8; N];
        out.copy_from_slice(self.take(N)?);
        Ok(out)
    }

    fn u8(&mut self) -> Result<u8, ReceiptError> {
        Ok(self.array::<1>()?[0])
    }

    fn u16(&mut self) -> Result<u16, ReceiptError> {
        Ok(u16::from_le_bytes(self.array()?))
    }

    fn u32(&mut self) -> Result<u32, ReceiptError> {
        Ok(u32::from_le_bytes(self.array()?))
    }

    fn u64(&mut self) -> Result<u64, ReceiptError> {
        Ok(u64::from_le_bytes(self.array()?))
    }

    fn i32(&mut self) -> Result<i32, ReceiptError> {
        Ok(i32::from_le_bytes(self.array()?))
    }

    /// A u32 length checked against `cap` before anything is read or allocated.
    fn len(&mut self, cap: usize, field: &'static str) -> Result<usize, ReceiptError> {
        let n = self.u32()? as usize;
        if n > cap {
            return Err(ReceiptError::OverCap(field));
        }
        Ok(n)
    }

    fn string(&mut self, field: &'static str) -> Result<String, ReceiptError> {
        let n = self.len(MAX_STRING_BYTES, field)?;
        let raw = self.take(n)?;
        String::from_utf8(raw.to_vec()).map_err(|_| ReceiptError::NotUtf8(field))
    }

    fn repo_id(&mut self, field: &'static str) -> Result<RepoId, ReceiptError> {
        let s = self.string(field)?;
        RepoId::new(s.clone()).map_err(|_| ReceiptError::InvalidRepoId(s))
    }
}

fn read_body(r: &mut Reader<'_>) -> Result<ReceiptBody, ReceiptError> {
    let repo_id = r.repo_id("repo_id")?;
    let changeset_id = ChangesetId(r.array()?);

    let base_git_oid = GitOid(r.array()?);
    let n = r.len(MAX_LIST_ITEMS, "source.parent_changesets")?;
    let mut parent_changesets = Vec::with_capacity(n);
    for _ in 0..n {
        parent_changesets.push(ChangesetId(r.array()?));
    }

    let n = r.len(MAX_LIST_ITEMS, "crumb_contexts")?;
    let mut crumb_contexts = Vec::with_capacity(n);
    for _ in 0..n {
        let dir = r.string("crumb_contexts")?;
        crumb_contexts.push(CrumbContextBinding {
            dir,
            at_base: CrumbContextDigest(r.array()?),
            in_changeset: CrumbContextDigest(r.array()?),
        });
    }

    let n = r.len(MAX_LIST_ITEMS, "input_root")?;
    let mut members = Vec::with_capacity(n);
    for _ in 0..n {
        let repo_id = r.repo_id("input_root")?;
        let kind = r.u8()?;
        if kind != INPUT_MEMBER_CHANGESET {
            return Err(ReceiptError::UnknownTag("input_root.kind", kind));
        }
        members.push(InputRootMember {
            repo_id,
            changeset_id: ChangesetId(r.array()?),
        });
    }

    let name = r.string("test.name")?;
    let n = r.len(MAX_LIST_ITEMS, "test.command")?;
    let mut command = Vec::with_capacity(n);
    for _ in 0..n {
        command.push(r.string("test.command")?);
    }
    let toolchain = r.string("test.toolchain")?;
    let platform = r.string("test.platform")?;
    let n = r.len(MAX_LIST_ITEMS, "test.environment")?;
    let mut environment = Vec::with_capacity(n);
    for _ in 0..n {
        environment.push(EnvVar {
            name: r.string("test.environment")?,
            value: r.string("test.environment")?,
        });
    }

    let exit_status = match r.u8()? {
        1 => ExitStatus::Code(r.i32()?),
        2 => ExitStatus::Signal(r.i32()?),
        t => return Err(ReceiptError::UnknownTag("result.exit_status", t)),
    };
    let outcome = match r.u8()? {
        1 => Outcome::Pass,
        2 => Outcome::Fail,
        3 => Outcome::Flaky,
        4 => Outcome::Error,
        t => return Err(ReceiptError::UnknownTag("result.outcome", t)),
    };
    let n = r.len(MAX_LIST_ITEMS, "result.outputs")?;
    let mut outputs = Vec::with_capacity(n);
    for _ in 0..n {
        outputs.push(DeclaredOutput {
            name: r.string("result.outputs")?,
            digest: OutputDigest(r.array()?),
        });
    }

    let started_at_ms = r.u64()?;
    let duration_ms = r.u64()?;
    let n = r.len(MAX_LOG_BYTES, "observation.log")?;
    let log = r.take(n)?.to_vec();

    let body = ReceiptBody {
        repo_id,
        changeset_id,
        source: SourceRevision {
            base_git_oid,
            parent_changesets,
        },
        crumb_contexts,
        input_root: InputRoot { members },
        test: TestIdentity {
            name,
            command,
            toolchain,
            platform,
            environment,
        },
        result: ReceiptResult {
            exit_status,
            outcome,
            outputs,
        },
        observation: Observation {
            started_at_ms,
            duration_ms,
            log,
        },
    };
    body.validate()?;
    Ok(body)
}

fn cap_str(s: &str, field: &'static str) -> Result<(), ReceiptError> {
    if s.len() > MAX_STRING_BYTES {
        return Err(ReceiptError::OverCap(field));
    }
    Ok(())
}

fn cap_list(n: usize, field: &'static str) -> Result<(), ReceiptError> {
    if n > MAX_LIST_ITEMS {
        return Err(ReceiptError::OverCap(field));
    }
    Ok(())
}

fn strictly_sorted<T: Ord, I: Iterator<Item = T>>(
    mut it: I,
    field: &'static str,
) -> Result<(), ReceiptError> {
    let Some(mut prev) = it.next() else {
        return Ok(());
    };
    for next in it {
        if next <= prev {
            return Err(ReceiptError::Unsorted(field));
        }
        prev = next;
    }
    Ok(())
}

#[cfg(test)]
mod tests;
