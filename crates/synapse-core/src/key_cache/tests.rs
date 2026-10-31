//! Issue #93, envelope path: `ChangesetEnvelope::validate` decodes each author key once per
//! thread, stays bounded, and gives the same verdict and refusal code as the uncached check
//! (`VerifyingKey::from_bytes` then `verify`) for every bad key, cold and warm.
//!
//! Keys and idempotency keys are derived from labels and counters (SHA-256), never written as
//! literals. Each `#[test]` runs on its own thread, so it starts with an empty cache; the
//! assertions still use before/after deltas.

use super::{cached_verifying_key, key_cache_stats, KEY_CACHE_CAPACITY};
use crate::{
    encode_did_key_ed25519, BlobDigest, ChangesetEnvelope, EvidenceAttachment, FileMode, GitOid,
    IdempotencyKey, MutationOp, PathMutation, RefusalCode, RepoId, SynapseResult,
    SYNAPSE_ENVELOPE_VERSION,
};
use ed25519_dalek::{Signature, SigningKey, Verifier, VerifyingKey};
use sha2::{Digest, Sha256};

fn derived(label: &str, n: u64) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"SYNAPSE_CORE_KEY_CACHE_TEST_V1\0");
    h.update(label.as_bytes());
    h.update(n.to_le_bytes());
    h.finalize().into()
}

fn key(label: &str, n: u64) -> SigningKey {
    SigningKey::from_bytes(&derived(label, n))
}

/// 32 derived bytes that are not the encoding of a curve point (`from_bytes` refuses them).
fn invalid_point(label: &str) -> [u8; 32] {
    (0u64..)
        .map(|n| derived(label, n))
        .find(|b| VerifyingKey::from_bytes(b).is_err())
        .expect("an undecodable encoding exists")
}

/// The identity point: decodes, but has small order.
fn small_order_point() -> [u8; 32] {
    let mut b = [0u8; 32];
    b[0] = 1;
    b
}

fn envelope(n: u64) -> ChangesetEnvelope {
    let payload = derived("payload", n);
    ChangesetEnvelope {
        version: SYNAPSE_ENVELOPE_VERSION,
        repo_id: RepoId::new("aien-spark/synapse").unwrap(),
        base_git_oid: GitOid::compute_blob(&payload),
        parent_changesets: vec![],
        author_did: String::new(),
        idempotency_key: IdempotencyKey(derived("idem", n)),
        created_at_ms: 1_789_800_000_000 + n,
        intent_summary: "key cache test".to_string(),
        mutations: vec![PathMutation {
            path: "src/lib.rs".to_string(),
            op: MutationOp::Upsert {
                mode: FileMode::Regular644,
                blob_digest: BlobDigest::compute(&payload),
                size_bytes: payload.len() as u64,
            },
        }],
        evidence_receipts: vec![EvidenceAttachment {
            gate_name: "cargo-test".to_string(),
            passed: true,
            artifact_digest: derived("artifact", n),
            summary: "ok".to_string(),
        }],
        signature: vec![],
    }
}

fn signed(k: &SigningKey, n: u64) -> ChangesetEnvelope {
    let mut env = envelope(n);
    env.sign(k);
    env
}

/// The pre-cache check, written out: decode with `from_bytes` on every call, then `verify`.
/// Used as the reference the cached path must agree with.
fn uncached_signature_verdict(env: &ChangesetEnvelope) -> SynapseResult<()> {
    let bytes = crate::decode_did_key_ed25519(&env.author_did)?;
    let vk = VerifyingKey::from_bytes(&bytes).map_err(|_| {
        crate::SynapseError::new(RefusalCode::DidKeyInvalid, "invalid Ed25519 public key")
    })?;
    let sig: [u8; 64] = env.signature.as_slice().try_into().map_err(|_| {
        crate::SynapseError::new(
            RefusalCode::AuthSignatureInvalid,
            "signature must be 64 bytes",
        )
    })?;
    vk.verify(
        &env.canonical_signable_bytes(),
        &Signature::from_bytes(&sig),
    )
    .map_err(|_| crate::SynapseError::new(RefusalCode::AuthSignatureInvalid, "verify failed"))
}

fn code(r: SynapseResult<impl Sized>) -> Option<RefusalCode> {
    r.err().map(|e| e.code)
}

#[test]
fn envelope_author_key_decodes_once_across_repeated_validates() {
    let author = key("author", 0);
    let (_, before) = key_cache_stats();
    for n in 0..32 {
        signed(&author, n).validate().expect("valid envelope");
    }
    let (len, after) = key_cache_stats();
    assert_eq!(
        after - before,
        1,
        "one decode for 32 validates by one author"
    );
    assert_eq!(len, 1);
}

#[test]
fn envelope_refusal_codes_for_bad_keys_are_unchanged_cold_and_warm() {
    let author = key("author", 1);
    let good = signed(&author, 0);

    let mut undecodable = good.clone();
    undecodable.author_did = encode_did_key_ed25519(&invalid_point("undecodable"));

    let mut no_z = good.clone();
    no_z.author_did = good.author_did.replacen("z", "y", 1);

    let mut wrong_codec = good.clone();
    wrong_codec.author_did = format!("did:key:z{}", "1".repeat(46));

    let mut forged = good.clone();
    forged.signature = signed(&key("impostor", 0), 0).signature;

    let mut tampered = good.clone();
    tampered.intent_summary = "tampered".to_string();

    let mut short_sig = good.clone();
    short_sig.signature.truncate(63);

    // Small-order author key with the (R = identity, S = 0) signature. The envelope check uses
    // non-strict `verify` (unchanged by this issue); the cached path must give the same verdict.
    let mut small_order = good.clone();
    small_order.author_did = encode_did_key_ed25519(&small_order_point());
    small_order.signature = {
        let mut s = vec![0u8; 64];
        s[0] = 1;
        s
    };

    let cases = [
        ("undecodable", undecodable, Some(RefusalCode::DidKeyInvalid)),
        ("no z", no_z, Some(RefusalCode::DidKeyInvalid)),
        (
            "wrong multicodec",
            wrong_codec,
            Some(RefusalCode::DidKeyInvalid),
        ),
        ("forged", forged, Some(RefusalCode::AuthSignatureInvalid)),
        (
            "tampered",
            tampered,
            Some(RefusalCode::AuthSignatureInvalid),
        ),
        (
            "short signature",
            short_sig,
            Some(RefusalCode::AuthSignatureInvalid),
        ),
    ];
    for round in ["cold", "warm"] {
        good.validate().expect("genuine envelope admitted");
        for (name, env, want) in &cases {
            assert_eq!(code(env.validate()), *want, "{name} ({round})");
            assert_eq!(
                code(uncached_signature_verdict(env)),
                *want,
                "{name} reference"
            );
        }
        assert_eq!(
            code(small_order.validate().map(|_| ())),
            code(uncached_signature_verdict(&small_order)),
            "small-order key ({round}) agrees with the uncached check"
        );
    }
}

#[test]
fn invalid_author_keys_are_refused_every_time_and_never_cached() {
    let (len0, d0) = key_cache_stats();
    let calls = 4 * KEY_CACHE_CAPACITY as u64;
    for n in 0..calls {
        let mut env = signed(&key("author", 2), n);
        env.author_did = encode_did_key_ed25519(&invalid_point(&format!("bad-{}", n % 8)));
        assert_eq!(code(env.validate()), Some(RefusalCode::DidKeyInvalid));
    }
    let (len1, d1) = key_cache_stats();
    assert_eq!(len1, len0, "invalid keys never enter the cache");
    assert_eq!(d1 - d0, calls, "every call with an invalid key decodes");
}

#[test]
fn hostile_author_churn_stays_at_the_cap() {
    let churn = 10 * KEY_CACHE_CAPACITY as u64;
    for n in 0..churn {
        signed(&key("churn", n), n)
            .validate()
            .expect("valid envelope");
        assert!(key_cache_stats().0 <= KEY_CACHE_CAPACITY);
    }
    assert_eq!(key_cache_stats().0, KEY_CACHE_CAPACITY);
}

/// Negative control: a warm cache holds the genuine author key, and still no envelope the
/// author did not sign is admitted; the cache returns the same key `from_bytes` does.
#[test]
fn warm_cache_admits_nothing_the_author_did_not_sign() {
    let author = key("author", 3);
    let good = signed(&author, 0);
    good.validate().expect("warm the cache");
    for n in 1..16 {
        let mut env = signed(&author, n);
        env.signature = good.signature.clone();
        assert_eq!(
            code(env.validate()),
            Some(RefusalCode::AuthSignatureInvalid)
        );
    }
    let bytes = author.verifying_key().to_bytes();
    assert_eq!(
        cached_verifying_key(&bytes).unwrap(),
        VerifyingKey::from_bytes(&bytes).unwrap()
    );
}
