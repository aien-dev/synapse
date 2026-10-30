//! Issue #93: the decoded-key cache decodes each key once, stays bounded under hostile key
//! churn, and leaves every refusal code for malformed or invalid keys unchanged.
//!
//! Keys, nonces and grant ids are derived from labels and counters (SHA-256), never written
//! as literals. Each `#[test]` runs on its own thread, so it starts with an empty cache;
//! the assertions still use before/after deltas.

use super::{stats, verifying_key, KEY_CACHE_CAPACITY};
use crate::{
    AgentCapabilityGrant, AuthenticatedRequest, BoundaryKind, Capability, CapabilityChain,
    CapabilityLink, ChainQuotas, ChainedRequest, ChangeScope, LinkCaveats, OperationSet, PathScope,
    PolicyEnforcer, ReferenceKind, ReferenceScope, RequestScope, ROOT_PARENT,
};
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use sha2::{Digest, Sha256};
use synapse_core::{encode_did_key_ed25519, RefusalCode, RepoId, WalSeq};

const NOW: u64 = 1_000_000;

fn derived(label: &str, n: u64) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"SYNAPSE_AUTH_KEY_CACHE_TEST_V1\0");
    h.update(label.as_bytes());
    h.update(n.to_le_bytes());
    h.finalize().into()
}

fn key(label: &str, n: u64) -> SigningKey {
    SigningKey::from_bytes(&derived(label, n))
}

fn did(k: &SigningKey) -> String {
    encode_did_key_ed25519(&k.verifying_key().to_bytes())
}

/// 32 derived bytes that are not the encoding of a curve point (`from_bytes` refuses them).
fn invalid_point(label: &str) -> [u8; 32] {
    (0u64..)
        .map(|n| derived(label, n))
        .find(|b| VerifyingKey::from_bytes(b).is_err())
        .expect("about half of all encodings are not points")
}

/// A small-order point encoding (decodes, but `verify_strict` refuses it as weak):
/// y = n for the first small n whose point is weak.
fn weak_point() -> [u8; 32] {
    (0u8..=u8::MAX)
        .map(|n| std::array::from_fn(|i| if i == 0 { n } else { 0 }))
        .find(|b: &[u8; 32]| VerifyingKey::from_bytes(b).is_ok_and(|k| k.is_weak()))
        .expect("y = 0 and y = 1 are small-order points")
}

fn repo() -> RepoId {
    RepoId::new("github.com/aien-dev/synapse-key-cache-test").unwrap()
}

fn caveats() -> LinkCaveats {
    LinkCaveats {
        operations: OperationSet::from_capabilities(&[Capability::Read, Capability::Propose]),
        paths: PathScope::whole_repository(),
        references: ReferenceScope::from_kinds(&[ReferenceKind::OwnDrafts]),
        changes: ChangeScope::any(),
        quotas: ChainQuotas {
            max_ops_per_window: 1_000,
            window_duration_ms: 60_000,
            storage_bytes: 1 << 30,
            footprint_paths: 1 << 20,
            max_bytes_per_op: 1 << 20,
        },
        issued_at_ms: NOW - 1,
        expires_at_ms: NOW + 60_000,
    }
}

fn grant(authority: &SigningKey, agent_did: String, n: u64) -> AgentCapabilityGrant {
    AgentCapabilityGrant::issue(
        authority,
        derived("grant", n),
        repo(),
        agent_did,
        vec![Capability::Read, Capability::Propose],
        1 << 20,
        1 << 20,
        60_000,
        NOW - 1,
        NOW + 60_000,
    )
}

fn request(
    agent: &SigningKey,
    grant: AgentCapabilityGrant,
    n: u64,
) -> AuthenticatedRequest<Vec<u8>> {
    AuthenticatedRequest::sign_new(
        agent,
        grant,
        repo(),
        Capability::Propose,
        derived("nonce", n),
        NOW,
        0,
        derived("payload", n).to_vec(),
    )
    .unwrap()
}

fn authorize(
    enf: &mut PolicyEnforcer,
    req: &AuthenticatedRequest<Vec<u8>>,
) -> Result<(), RefusalCode> {
    enf.authorize(
        BoundaryKind::Api,
        "submit",
        &repo(),
        Capability::Propose,
        req,
        NOW,
    )
    .map_err(|e| e.code)
}

/// The authority and agent keys are decoded once each, however many requests they sign.
#[test]
fn each_key_decodes_once_across_repeated_authorizations() {
    let authority = key("authority", 1);
    let agent = key("agent", 1);
    let mut enf = PolicyEnforcer::new();
    enf.register_repo_authority(repo(), did(&authority));
    let g = grant(&authority, did(&agent), 1);
    let (_, before) = stats();
    for n in 0..32 {
        assert_eq!(authorize(&mut enf, &request(&agent, g.clone(), n)), Ok(()));
    }
    let (len, after) = stats();
    assert_eq!(
        after - before,
        2,
        "authority and agent key decoded once each"
    );
    assert!(len >= 2);
}

/// Hostile churn of valid keys: every new key costs one decode and the cache never holds
/// more than the cap; the oldest keys are the ones evicted.
#[test]
fn hostile_valid_key_churn_stays_at_the_cap() {
    let churn = 10 * KEY_CACHE_CAPACITY as u64;
    let (_, before) = stats();
    for n in 0..churn {
        let bytes = key("churn", n).verifying_key().to_bytes();
        assert_eq!(
            verifying_key(&bytes).unwrap(),
            VerifyingKey::from_bytes(&bytes).unwrap()
        );
        assert!(
            stats().0 <= KEY_CACHE_CAPACITY,
            "cache above the cap at key {n}"
        );
    }
    let (len, after) = stats();
    assert_eq!(len, KEY_CACHE_CAPACITY);
    assert_eq!(after - before, churn, "every new key is one decode");

    // Newest key: a hit. Oldest key: evicted, decoded again.
    verifying_key(&key("churn", churn - 1).verifying_key().to_bytes()).unwrap();
    assert_eq!(stats().1, after);
    verifying_key(&key("churn", 0).verifying_key().to_bytes()).unwrap();
    assert_eq!(stats().1, after + 1);
    assert_eq!(stats().0, KEY_CACHE_CAPACITY);
}

/// Bytes that are not a point are refused on every call and never enter the cache, so
/// churn of invalid keys cannot grow it either.
#[test]
fn invalid_key_bytes_are_refused_every_time_and_never_cached() {
    let (len0, d0) = stats();
    for n in 0..(4 * KEY_CACHE_CAPACITY as u64) {
        let bad = invalid_point(&format!("invalid-churn-{n}"));
        assert!(verifying_key(&bad).is_err());
        assert!(verifying_key(&bad).is_err(), "second call refused too");
    }
    let (len1, d1) = stats();
    assert_eq!(len1, len0, "invalid keys are never cached");
    assert_eq!(d1 - d0, 8 * KEY_CACHE_CAPACITY as u64, "every call decodes");
}

/// Refusal codes for invalid authority and agent keys on the grant path, unchanged, both
/// before and after the valid keys are cached.
#[test]
fn grant_path_refusal_codes_for_bad_keys_are_unchanged_cold_and_warm() {
    let authority = key("authority", 2);
    let agent = key("agent", 2);
    let mut enf = PolicyEnforcer::new();
    enf.register_repo_authority(repo(), did(&authority));

    // Invalid authority key: a trusted issuer DID whose 32 bytes are not a point.
    let bad_issuer_did = encode_did_key_ed25519(&invalid_point("issuer"));
    enf.register_repo_authority(repo(), bad_issuer_did.clone());
    let mut bad_issuer = grant(&authority, did(&agent), 2);
    bad_issuer.issuer_did = bad_issuer_did;

    // Invalid agent key in a validly signed grant.
    let bad_agent_did = encode_did_key_ed25519(&invalid_point("agent"));
    let bad_agent = grant(&authority, bad_agent_did, 3);

    // Malformed DIDs: not multibase z, and the wrong multicodec prefix.
    let no_z = grant(
        &authority,
        did(&agent).replacen("did:key:z", "did:key:m", 1),
        4,
    );
    let wrong_codec = grant(
        &authority,
        did(&agent).replacen("did:key:z6Mk", "did:key:z6Mj", 1),
        5,
    );

    // Valid keys, wrong signatures.
    let mut forged_grant = grant(&authority, did(&agent), 6);
    forged_grant.signature = key("forger", 0)
        .sign(&forged_grant.canonical_signable_bytes())
        .to_bytes()
        .to_vec();
    let good = grant(&authority, did(&agent), 7);

    let cases = |enf: &mut PolicyEnforcer, round: u64| {
        let n = 100 * round;
        assert_eq!(
            authorize(enf, &request(&agent, bad_issuer.clone(), n)),
            Err(RefusalCode::DidKeyInvalid)
        );
        assert_eq!(
            authorize(enf, &request(&agent, bad_agent.clone(), n + 1)),
            Err(RefusalCode::DidKeyInvalid)
        );
        assert_eq!(
            authorize(enf, &request(&agent, no_z.clone(), n + 2)),
            Err(RefusalCode::DidKeyInvalid)
        );
        assert_eq!(
            authorize(enf, &request(&agent, wrong_codec.clone(), n + 3)),
            Err(RefusalCode::DidKeyInvalid)
        );
        assert_eq!(
            authorize(enf, &request(&agent, forged_grant.clone(), n + 4)),
            Err(RefusalCode::AuthGrantSignatureInvalid)
        );
        assert_eq!(
            authorize(enf, &request(&key("impostor", round), good.clone(), n + 5)),
            Err(RefusalCode::AuthSignatureInvalid)
        );
        assert_eq!(
            authorize(enf, &request(&agent, good.clone(), n + 6)),
            Ok(())
        );
    };
    cases(&mut enf, 1); // cold: nothing cached yet
    cases(&mut enf, 2); // warm: authority and agent keys cached
}

/// Refusal codes on the capability-chain path (`verify_strict`), unchanged cold and warm:
/// a link issuer key that is not a point and a small-order issuer key are both
/// `AuthGrantSignatureInvalid`; an agent key that is not a point is `DidKeyInvalid`.
#[test]
fn chain_path_refusal_codes_for_bad_keys_are_unchanged_cold_and_warm() {
    let authority = key("chain-authority", 1);
    let link = CapabilityLink::issue(
        &authority,
        ROOT_PARENT,
        derived("link-nonce", 1),
        repo(),
        key("chain-agent", 1).verifying_key().to_bytes(),
        caveats(),
    );
    let mut not_a_point = link.clone();
    not_a_point.issuer_key = invalid_point("link-issuer");
    let mut weak = link.clone();
    weak.issuer_key = weak_point();
    for _round in 0..2 {
        assert_eq!(link.verify_signature(), Ok(()));
        assert_eq!(
            not_a_point.verify_signature().map_err(|e| e.code),
            Err(RefusalCode::AuthGrantSignatureInvalid)
        );
        assert_eq!(
            weak.verify_signature().map_err(|e| e.code),
            Err(RefusalCode::AuthGrantSignatureInvalid)
        );
    }

    // Agent key that is not a point: a granted root link whose audience is those bytes.
    let bad_agent = invalid_point("chain-agent-bad");
    let mut enf = PolicyEnforcer::new();
    enf.register_repo_authority(repo(), did(&authority));
    let root = CapabilityLink::issue(
        &authority,
        ROOT_PARENT,
        derived("link-nonce", 2),
        repo(),
        bad_agent,
        caveats(),
    );
    let chain = CapabilityChain::new(vec![root]);
    enf.grant_link(&chain, WalSeq(1), NOW).unwrap();
    for round in 0..2u64 {
        let mut req = ChainedRequest::sign_new(
            &key("chain-signer", round),
            chain.clone(),
            repo(),
            Capability::Propose,
            RequestScope::default(),
            derived("chain-nonce", round),
            NOW,
            derived("chain-payload", round).to_vec(),
        );
        req.agent_key = bad_agent;
        assert_eq!(
            enf.authorize_chain(
                BoundaryKind::Api,
                "submit",
                &repo(),
                Capability::Propose,
                &req,
                WalSeq(2 + round),
                NOW,
            )
            .map_err(|e| e.code),
            Err(RefusalCode::DidKeyInvalid)
        );
    }
}
