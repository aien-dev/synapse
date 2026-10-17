//! Issue #92 parity proof: `synapse_auth::payload_digest` (compact JSON streamed into SHA-256)
//! returns exactly what the old code computed, `(SHA-256(serde_json::to_vec(p)), its length)`,
//! and every refusal code of `PolicyEnforcer::authorize` is unchanged.
//!
//! Corpus:
//! * the A1 malformed corpus, regenerated here the same way
//!   `crates/synapse-store/tests/a1_malformed_corpus.rs` builds it (one binary-v2 WAL frame per
//!   record kind from the `a1-v1` fixture, every truncation, every bit flip, oversized frame and
//!   inner lengths, and every truncation and bit flip of the v2 checkpoint), with each damaged
//!   byte string carried both as a blob in a `SubmitChangesetPayload` and as a lossy UTF-8
//!   string, so JSON number arrays and string escaping are both exercised;
//! * recorded requests: every record of the `a1-v1` WAL fixtures (v1 JSON log and v2 binary
//!   log), each `ChangesetIngest` rebuilt into the `SubmitChangesetPayload` that produced it
//!   (envelope plus the recorded blob bytes), and one payload of every query type built from
//!   the recorded ids;
//! * edge values: escapes, control characters, non-ASCII text, empty and maximal numbers.

use ed25519_dalek::SigningKey;
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use synapse_api::{
    ChangesetAdvisoryPayload, ConflictQueryPayload, CrumbContextQueryPayload, DiffQueryPayload,
    EvidenceBaseQueryPayload, HistoryQueryPayload, PageRequest, SubmitChangesetPayload,
    TreeQueryPayload, TreeTarget, VerifyEvidenceReceiptPayload, WatchQueryPayload,
};
use synapse_auth::{
    payload_digest, AgentCapabilityGrant, AuthenticatedRequest, BoundaryKind, Capability,
    PolicyEnforcer,
};
use synapse_core::{
    encode_did_key_ed25519, BlobDigest, ChangesetEnvelope, ChangesetId, RefusalCode, RepoId, WalSeq,
};
use synapse_store::codec::{
    decode_record_with, encode_checkpoint_v2, encode_record, CheckpointState, WAL_FLAG_CODEC_V2,
};
use synapse_store::wal2::{WAL_V2_ALIGN, WAL_V2_BATCH_HEADER_LEN, WAL_V2_BATCH_MAGIC};
use synapse_store::{
    encode_wal_frame, wal_frame_from_payload, CheckpointManifest, RecordCodec, WalRecord,
    WAL_HEADER_LEN,
};

/// Same record cap as the A1 corpus.
const CAP: u64 = 1 << 20;

fn fixtures() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../synapse-store/tests/fixtures/a1-v1")
}

fn fixture(rel: &str) -> Vec<u8> {
    std::fs::read(fixtures().join(rel)).unwrap_or_else(|e| panic!("fixture {rel}: {e}"))
}

fn derived(label: &str, counter: u64) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"SYNAPSE_API_PAYLOAD_DIGEST_PARITY_V1\0");
    h.update(label.as_bytes());
    h.update(counter.to_le_bytes());
    h.finalize().into()
}

/// The digest exactly as `check_request_inner` and `sign_new` computed it before #92.
fn old_digest<T: Serialize + ?Sized>(p: &T) -> Result<([u8; 32], u64), String> {
    let json = serde_json::to_vec(p).map_err(|e| format!("serialize payload: {e}"))?;
    Ok((Sha256::digest(&json).into(), json.len() as u64))
}

#[derive(Default)]
struct Parity {
    cases: usize,
    json_bytes: u64,
}

impl Parity {
    fn check<T: Serialize + ?Sized>(&mut self, what: &str, p: &T) {
        let old = old_digest(p).unwrap_or_else(|e| panic!("{what}: old digest failed: {e}"));
        let new = payload_digest(p).unwrap_or_else(|e| panic!("{what}: new digest failed: {e}"));
        assert_eq!(new, old, "{what}: digest or length differs");
        self.cases += 1;
        self.json_bytes += old.1;
    }

    /// One damaged byte string, as a blob and as a lossy string.
    fn bytes(&mut self, what: &str, envelope: &ChangesetEnvelope, b: &[u8]) {
        self.check(
            what,
            &SubmitChangesetPayload {
                envelope: envelope.clone(),
                blobs: vec![(BlobDigest::compute(b), b.to_vec())],
            },
        );
        self.check(what, &String::from_utf8_lossy(b));
    }
}

/// Every record of the v1 JSON WAL fixture, in log order.
fn v1_records() -> Vec<WalRecord> {
    let log = fixture("v1-wal-log/wal.log");
    let mut out = Vec::new();
    let mut at = 0;
    while at < log.len() {
        let len = u32::from_le_bytes(log[at + 48..at + 52].try_into().unwrap()) as usize;
        let payload = &log[at + WAL_HEADER_LEN..at + WAL_HEADER_LEN + len];
        out.push(serde_json::from_slice(payload).unwrap());
        at += WAL_HEADER_LEN + len;
    }
    out
}

type Blobs = BTreeMap<BlobDigest, Vec<u8>>;

/// Every record of the WAL v2 fixture (`wal.v2.log`: 4 KiB-aligned `SWB2` batches; each frame
/// payload is `u32 meta_len | meta | u32 blob_count | (digest[32] | u32 len | bytes)*`), with
/// its inline blobs.
fn v2_records() -> (Vec<WalRecord>, Blobs) {
    let log = fixture("v1-wal-v2-log/wal.v2.log");
    let u32_at = |b: &[u8], o: usize| u32::from_le_bytes(b[o..o + 4].try_into().unwrap()) as usize;
    let mut records = Vec::new();
    let mut blobs = Blobs::new();
    let mut off = 0usize;
    while off + WAL_V2_BATCH_HEADER_LEN <= log.len() && log[off..off + 4] == WAL_V2_BATCH_MAGIC {
        let count = u32_at(&log, off + 8);
        let body = u64::from_le_bytes(log[off + 16..off + 24].try_into().unwrap()) as usize;
        let mut at = off + WAL_V2_BATCH_HEADER_LEN;
        for _ in 0..count {
            let h = &log[at..at + WAL_HEADER_LEN];
            let len = u32_at(h, 48);
            let p = &log[at + WAL_HEADER_LEN..at + WAL_HEADER_LEN + len];
            let codec = if h[7] == WAL_FLAG_CODEC_V2 {
                RecordCodec::BinaryV2
            } else {
                RecordCodec::JsonV1
            };
            let meta_len = u32_at(p, 0);
            records.push(decode_record_with(&p[4..4 + meta_len], codec, CAP).unwrap());
            let mut b = 4 + meta_len;
            let n = u32_at(p, b);
            b += 4;
            for _ in 0..n {
                let digest = BlobDigest(p[b..b + 32].try_into().unwrap());
                let blen = u32_at(p, b + 32);
                let bytes = p[b + 36..b + 36 + blen].to_vec();
                assert_eq!(BlobDigest::compute(&bytes), digest, "inline blob");
                blobs.insert(digest, bytes);
                b += 36 + blen;
            }
            at += WAL_HEADER_LEN + len;
        }
        let end = (off + WAL_V2_BATCH_HEADER_LEN + body) as u64;
        off = end.div_ceil(WAL_V2_ALIGN) as usize * WAL_V2_ALIGN as usize;
    }
    (records, blobs)
}

/// The blobs recorded in the v1 fixture's blob store (`blobs/<2 hex>/<64 hex>`).
fn v1_blobs() -> Blobs {
    let mut out = Blobs::new();
    for dir in std::fs::read_dir(fixtures().join("v1-wal-log/blobs")).unwrap() {
        for file in std::fs::read_dir(dir.unwrap().path()).unwrap() {
            let file = file.unwrap();
            let digest = BlobDigest::from_hex(file.file_name().to_str().unwrap()).unwrap();
            let bytes = std::fs::read(file.path()).unwrap();
            assert_eq!(BlobDigest::compute(&bytes), digest, "stored blob");
            out.insert(digest, bytes);
        }
    }
    out
}

fn one_record_per_kind(records: &[WalRecord]) -> Vec<WalRecord> {
    let mut by_kind = BTreeMap::new();
    for r in records {
        by_kind.entry(r.kind_byte()).or_insert_with(|| r.clone());
    }
    assert_eq!(by_kind.len(), 6, "fixture must hold all six record kinds");
    by_kind.into_values().collect()
}

fn first_envelope(records: &[WalRecord]) -> ChangesetEnvelope {
    records
        .iter()
        .find_map(|r| match r {
            WalRecord::ChangesetIngest { envelope, .. } => Some(envelope.clone()),
            _ => None,
        })
        .expect("fixture holds a changeset")
}

/// The `SubmitChangesetPayload` each recorded `ChangesetIngest` was admitted from: its
/// envelope and the bytes of every blob it introduced.
fn recorded_submits(
    records: &[WalRecord],
    blobs: &Blobs,
) -> Vec<(ChangesetId, SubmitChangesetPayload)> {
    records
        .iter()
        .filter_map(|r| match r {
            WalRecord::ChangesetIngest {
                envelope,
                changeset_id,
                new_blobs,
            } => Some((
                *changeset_id,
                SubmitChangesetPayload {
                    envelope: envelope.clone(),
                    blobs: new_blobs
                        .iter()
                        .map(|d| {
                            let b = blobs.get(d).unwrap_or_else(|| panic!("blob {d} recorded"));
                            (*d, b.clone())
                        })
                        .collect(),
                },
            )),
            _ => None,
        })
        .collect()
}

/// Every recorded submit of both fixtures.
fn all_recorded_submits() -> Vec<(ChangesetId, SubmitChangesetPayload)> {
    let (v2, v2_blobs) = v2_records();
    let mut out = recorded_submits(&v1_records(), &v1_blobs());
    out.extend(recorded_submits(&v2, &v2_blobs));
    out
}

#[test]
fn new_digest_equals_old_over_the_a1_malformed_corpus() {
    let records = v1_records();
    let envelope = first_envelope(&records);
    let mut p = Parity::default();
    let mut classes: BTreeMap<&str, usize> = BTreeMap::new();
    let prev = derived("prev-frame", 0);
    for r in one_record_per_kind(&records) {
        let kind = r.kind_byte();
        let (frame, _) = encode_wal_frame(WalSeq(1), prev, &r, RecordCodec::BinaryV2, CAP).unwrap();
        p.bytes(&format!("kind {kind} frame"), &envelope, &frame);
        for n in 0..frame.len() {
            p.bytes(
                &format!("kind {kind} truncated to {n}"),
                &envelope,
                &frame[..n],
            );
            *classes.entry("truncated").or_default() += 1;
        }
        for bit in 0..frame.len() * 8 {
            let mut f = frame.clone();
            f[bit / 8] ^= 1 << (bit % 8);
            p.bytes(&format!("kind {kind} bit {bit}"), &envelope, &f);
            *classes.entry("bit_flipped").or_default() += 1;
        }
        for declared in [CAP + 1, 2 * CAP, u64::from(u32::MAX)] {
            let mut f = frame.clone();
            f[48..52].copy_from_slice(&(declared as u32).to_le_bytes());
            p.bytes(&format!("kind {kind} declares {declared}"), &envelope, &f);
            *classes.entry("oversized_frame_length").or_default() += 1;
        }
        let bin = encode_record(&r).unwrap();
        for off in 0..bin.len().saturating_sub(4) {
            let mut b = bin.clone();
            b[off..off + 4].copy_from_slice(&u32::MAX.to_le_bytes());
            let (f, _) = wal_frame_from_payload(WalSeq(1), prev, kind, frame[7], &b);
            p.bytes(&format!("kind {kind} inner length at {off}"), &envelope, &f);
            *classes.entry("oversized_inner_length").or_default() += 1;
        }
    }
    let manifest: CheckpointManifest =
        serde_json::from_slice(&fixture("v1-wal-log/checkpoint.v1")).unwrap();
    let state = CheckpointState::from_v1_manifest(manifest).unwrap();
    let (ckpt, _) =
        encode_checkpoint_v2(&state, derived("v1-root", 0), derived("prev-ckpt", 0)).unwrap();
    for n in 0..ckpt.len() {
        p.bytes(
            &format!("checkpoint truncated to {n}"),
            &envelope,
            &ckpt[..n],
        );
        *classes.entry("checkpoint_truncated").or_default() += 1;
    }
    for bit in 0..ckpt.len() * 8 {
        let mut c = ckpt.clone();
        c[bit / 8] ^= 1 << (bit % 8);
        p.bytes(&format!("checkpoint bit {bit}"), &envelope, &c);
        *classes.entry("checkpoint_bit_flipped").or_default() += 1;
    }
    println!(
        "A1 corpus parity: {} payloads, {} JSON bytes, classes {classes:?}",
        p.cases, p.json_bytes
    );
    for class in [
        "truncated",
        "bit_flipped",
        "oversized_frame_length",
        "oversized_inner_length",
        "checkpoint_truncated",
        "checkpoint_bit_flipped",
    ] {
        assert!(
            classes.get(class).copied().unwrap_or(0) > 0,
            "{class} empty"
        );
    }
}

#[test]
fn new_digest_equals_old_for_every_recorded_request() {
    let v1 = v1_records();
    let (v2, _) = v2_records();
    assert!(!v2.is_empty(), "v2 fixture decodes");
    let mut p = Parity::default();
    let mut submits = 0;
    let mut blob_bytes = 0;
    for (i, r) in v1.iter().chain(v2.iter()).enumerate() {
        p.check(&format!("record {i}"), r);
    }
    for (id, s) in all_recorded_submits() {
        blob_bytes += s.blobs.iter().map(|(_, b)| b.len()).sum::<usize>();
        p.check(&format!("submit {}", id.to_hex()), &s);
        // The same submit carrying bench-sized blobs (the write benches submit about 12 KiB).
        for size in [12 * 1024, 1 << 20] {
            let mut big = s.clone();
            let blob: Vec<u8> = (0..size)
                .map(|i| derived("bench-blob", (i / 32) as u64)[i % 32])
                .collect();
            big.blobs.push((BlobDigest::compute(&blob), blob));
            p.check(&format!("submit {} + {size} B blob", id.to_hex()), &big);
        }
        submits += 1;
        let page = PageRequest {
            cursor: Some(id.to_hex()),
            limit: 100,
            min_visible_seq: Some(WalSeq(1)),
            snapshot_seq: None,
        };
        let base = TreeTarget::BaseGitCommit(s.envelope.base_git_oid);
        let target = TreeTarget::Changeset(id);
        p.check(
            "tree",
            &TreeQueryPayload {
                target,
                path_prefix: Some("src/".into()),
                page: page.clone(),
            },
        );
        p.check(
            "diff",
            &DiffQueryPayload {
                base,
                target,
                page: page.clone(),
            },
        );
        p.check(
            "history",
            &HistoryQueryPayload {
                ancestor_of: Some(id),
                path_filter: None,
                page: page.clone(),
            },
        );
        p.check(
            "conflicts",
            &ConflictQueryPayload {
                candidate: id,
                against: Some(s.envelope.parent_changesets.clone()),
                page: page.clone(),
            },
        );
        p.check(
            "watch",
            &WatchQueryPayload {
                subscriber_id: s.envelope.author_did.clone(),
                after_seq: Some(WalSeq(u64::MAX)),
                page,
            },
        );
        p.check(
            "advisory",
            &ChangesetAdvisoryPayload {
                base,
                latest: Some(target),
                paths: s
                    .envelope
                    .mutations
                    .iter()
                    .map(|m| format!("{m:?}"))
                    .collect(),
                agent: s.envelope.author_did.clone(),
                snapshot_seq: None,
            },
        );
        p.check(
            "crumb",
            &CrumbContextQueryPayload {
                target,
                path: ".".into(),
                snapshot_seq: Some(WalSeq(0)),
            },
        );
        p.check(
            "evidence base",
            &EvidenceBaseQueryPayload {
                changeset_id: id,
                snapshot_seq: None,
            },
        );
        p.check(
            "verify receipt",
            &VerifyEvidenceReceiptPayload {
                receipt: s.envelope.signature.clone(),
                snapshot_seq: Some(WalSeq(3)),
            },
        );
        p.check("status", &(id, Some(WalSeq(1)), None::<WalSeq>));
        p.check("file", &(target, "README.md".to_string(), Some(WalSeq(2))));
        p.check("receipt", &(id, None::<WalSeq>));
        p.check("snapshot", &Some(WalSeq(7)));
    }
    assert!(
        submits >= 2 && blob_bytes > 0,
        "{submits} submits, {blob_bytes} blob bytes"
    );
    println!(
        "recorded parity: {} records, {submits} submits ({blob_bytes} blob bytes), {} payloads, {} JSON bytes",
        v1.len() + v2.len(),
        p.cases,
        p.json_bytes
    );
}

#[test]
fn new_digest_equals_old_on_edge_values() {
    let mut p = Parity::default();
    let all_bytes: Vec<u8> = (0..=255u8).collect();
    let all_chars: String = (0u32..0x800).filter_map(char::from_u32).collect();
    p.check("empty", &());
    p.check("empty string", "");
    p.check("empty blob", &Vec::<u8>::new());
    p.check("every byte value", &all_bytes);
    p.check("every char below U+0800", &all_chars);
    p.check(
        "escapes",
        "quote \" backslash \\ slash / \u{0} \u{1f} \u{7f} \n\r\t\u{8}\u{c}",
    );
    p.check("astral", "\u{1F600}\u{10FFFF}");
    p.check(
        "numbers",
        &(u64::MAX, i64::MIN, 0u8, u16::MAX, u32::MAX, i8::MIN),
    );
    p.check("nested", &vec![vec![Some(vec![0u8; 0]), None], vec![]]);
    let mut map = BTreeMap::new();
    map.insert("k\u{0}ey".to_string(), all_bytes.clone());
    map.insert(String::new(), Vec::new());
    p.check("map", &map);
    // A payload just over, at, and under the 8 KiB staging buffer, in every alignment.
    for len in 2_700..2_760usize {
        p.check(&format!("blob {len}"), &vec![b'7'; len]);
        p.check(&format!("string {len}"), &"x".repeat(len * 3));
    }
    // One write larger than the staging buffer (a long string is written in one piece).
    p.check("long string", &"\u{e9}".repeat(20_000));
}

#[test]
fn a_payload_that_cannot_serialize_is_refused_with_the_same_code_and_message() {
    let mut bad: BTreeMap<(u8, u8), u8> = BTreeMap::new();
    bad.insert((1, 2), 3);
    let old = old_digest(&bad).unwrap_err();
    let new = payload_digest(&bad).unwrap_err();
    assert_eq!(new.code, RefusalCode::IoFailure);
    assert_eq!(new.message, old);
}

struct Authority {
    repo: RepoId,
    authority: SigningKey,
    agent: SigningKey,
}

impl Authority {
    fn new() -> Self {
        Self {
            repo: RepoId::new("payload-digest-parity").unwrap(),
            authority: SigningKey::from_bytes(&derived("authority", 0)),
            agent: SigningKey::from_bytes(&derived("agent", 0)),
        }
    }

    fn enforcer(&self) -> PolicyEnforcer {
        let mut e = PolicyEnforcer::new();
        e.register_repo_authority(
            self.repo.clone(),
            encode_did_key_ed25519(&self.authority.verifying_key().to_bytes()),
        );
        e
    }

    fn request(
        &self,
        n: u64,
        max_bytes_per_op: u64,
        p: SubmitChangesetPayload,
    ) -> AuthenticatedRequest<SubmitChangesetPayload> {
        let grant = AgentCapabilityGrant::issue(
            &self.authority,
            derived("grant", n),
            self.repo.clone(),
            encode_did_key_ed25519(&self.agent.verifying_key().to_bytes()),
            vec![Capability::Propose],
            max_bytes_per_op,
            1_000,
            60_000,
            1_000,
            1_000_000,
        );
        AuthenticatedRequest::sign_new(
            &self.agent,
            grant,
            self.repo.clone(),
            Capability::Propose,
            derived("nonce", n),
            2_000,
            0,
            p,
        )
        .unwrap()
    }

    fn authorize(
        &self,
        req: &AuthenticatedRequest<SubmitChangesetPayload>,
    ) -> Result<(), RefusalCode> {
        self.enforcer()
            .authorize(
                BoundaryKind::Api,
                "submit",
                &self.repo,
                Capability::Propose,
                req,
                2_000,
            )
            .map_err(|e| e.code)
    }
}

#[test]
fn refusal_codes_are_unchanged_for_every_recorded_submit() {
    let a = Authority::new();
    let mut checked = 0;
    for (n, (id, s)) in all_recorded_submits().into_iter().enumerate() {
        let n = n as u64 * 8;
        let what = id.to_hex();
        let (old_sha, json_len) = old_digest(&s).unwrap();

        // Admitted, and the signed digest and length are the old ones.
        let req = a.request(n, u64::MAX, s.clone());
        assert_eq!(req.payload_sha256, old_sha, "{what}");
        assert_eq!(req.payload_bytes_len, json_len, "{what}");
        assert_eq!(a.authorize(&req), Ok(()), "{what}");

        // Quota boundary: the counted length is exactly the old JSON length.
        assert_eq!(
            a.authorize(&a.request(n + 1, json_len, s.clone())),
            Ok(()),
            "{what}"
        );
        assert_eq!(
            a.authorize(&a.request(n + 2, json_len - 1, s.clone())),
            Err(RefusalCode::QuotaPayloadTooLarge),
            "{what}"
        );

        // A payload changed after signing is refused at the digest check.
        let mut tampered = req.clone();
        tampered.payload.envelope.intent_summary.push('!');
        assert_eq!(
            a.authorize(&tampered),
            Err(RefusalCode::AuthSignatureInvalid),
            "{what}"
        );
        if !req.payload.blobs.is_empty() {
            let mut t = req.clone();
            t.payload.blobs[0].1.push(0);
            assert_eq!(
                a.authorize(&t),
                Err(RefusalCode::AuthSignatureInvalid),
                "{what}"
            );
        }

        // A digest changed after signing is refused (the signature binds it).
        let mut t = req.clone();
        t.payload_sha256[0] ^= 1;
        assert_eq!(
            a.authorize(&t),
            Err(RefusalCode::AuthSignatureInvalid),
            "{what}"
        );

        // A declared length lowered after signing is refused by the signature, not the quota.
        let mut t = req.clone();
        t.payload_bytes_len -= 1;
        assert_eq!(
            a.authorize(&t),
            Err(RefusalCode::AuthSignatureInvalid),
            "{what}"
        );
        checked += 1;
    }
    assert!(checked >= 2, "{checked} recorded submits");
}
