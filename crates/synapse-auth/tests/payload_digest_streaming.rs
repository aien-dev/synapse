//! Issue #92: the request payload digest is computed by streaming the payload's compact JSON
//! straight into SHA-256, without first materializing the whole JSON text in memory.
//!
//! The digest definition does not change (SHA-256 of the compact `serde_json` encoding, which
//! the agent signs through `payload_sha256`); this file proves the memory shape of the check:
//! the largest single heap allocation made while signing or authorizing a large payload stays a
//! small fixed size, far below the payload's JSON length. Before #92 both paths built the JSON
//! text in one growing `Vec`, so the largest allocation was at least the JSON length.
//!
//! Byte-for-byte parity of the new digest with the old one is proven separately, over the A1
//! malformed corpus and recorded requests, in `crates/synapse-api/tests/payload_digest_parity.rs`.

use ed25519_dalek::SigningKey;
use sha2::{Digest, Sha256};
use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use synapse_auth::{
    payload_digest, AgentCapabilityGrant, AuthenticatedRequest, BoundaryKind, Capability,
    PolicyEnforcer,
};
use synapse_core::{encode_did_key_ed25519, RepoId};

/// Records the largest single allocation made on the measuring thread while a window is open.
struct PeakAlloc;

thread_local! {
    static MEASURING: Cell<bool> = const { Cell::new(false) };
    static PEAK: Cell<usize> = const { Cell::new(0) };
}

fn note(size: usize) {
    let _ = MEASURING.try_with(|m| {
        if m.get() {
            let _ = PEAK.try_with(|p| p.set(p.get().max(size)));
        }
    });
}

unsafe impl GlobalAlloc for PeakAlloc {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        note(layout.size());
        unsafe { System.alloc(layout) }
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) }
    }
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        note(layout.size());
        unsafe { System.alloc_zeroed(layout) }
    }
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        note(new_size);
        unsafe { System.realloc(ptr, layout, new_size) }
    }
}

#[global_allocator]
static GLOBAL: PeakAlloc = PeakAlloc;

/// Largest single allocation made by `f` on this thread.
fn peak_alloc<R>(f: impl FnOnce() -> R) -> (R, usize) {
    PEAK.with(|p| p.set(0));
    MEASURING.with(|m| m.set(true));
    let r = f();
    MEASURING.with(|m| m.set(false));
    (r, PEAK.with(|p| p.get()))
}

/// Ceiling for any single allocation during digesting: a fixed staging buffer plus slack.
const SMALL_ALLOC_CEILING: usize = 64 * 1024;
/// Blob size: its compact JSON (decimal byte values with commas) is several times larger.
const BLOB_LEN: usize = 256 * 1024;

fn derived(label: &str, counter: u64) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"SYNAPSE_AUTH_PAYLOAD_DIGEST_TEST_V1\0");
    h.update(label.as_bytes());
    h.update(counter.to_le_bytes());
    h.finalize().into()
}

fn key(label: &str) -> SigningKey {
    SigningKey::from_bytes(&derived(label, 0))
}

/// A blob whose bytes cover every value, so the JSON mixes one-, two- and three-digit numbers.
fn blob() -> Vec<u8> {
    (0..BLOB_LEN)
        .map(|i| derived("blob", (i / 32) as u64)[i % 32])
        .collect()
}

type Payload = (String, Vec<(String, Vec<u8>)>);

fn payload() -> Payload {
    ("submit".to_string(), vec![("blob-0".to_string(), blob())])
}

struct Fixture {
    repo: RepoId,
    authority: SigningKey,
    agent: SigningKey,
}

fn fixture() -> Fixture {
    Fixture {
        repo: RepoId::new("payload-digest-repo").unwrap(),
        authority: key("authority"),
        agent: key("agent"),
    }
}

fn grant(f: &Fixture, max_bytes_per_op: u64) -> AgentCapabilityGrant {
    AgentCapabilityGrant::issue(
        &f.authority,
        derived("grant", 0),
        f.repo.clone(),
        encode_did_key_ed25519(&f.agent.verifying_key().to_bytes()),
        vec![Capability::Propose],
        max_bytes_per_op,
        100,
        60_000,
        1_000,
        1_000_000,
    )
}

fn enforcer(f: &Fixture) -> PolicyEnforcer {
    let mut e = PolicyEnforcer::new();
    e.register_repo_authority(
        f.repo.clone(),
        encode_did_key_ed25519(&f.authority.verifying_key().to_bytes()),
    );
    e
}

#[test]
fn signing_a_large_payload_never_materializes_its_json() {
    let f = fixture();
    let p = payload();
    let json_len = serde_json::to_vec(&p).unwrap().len();
    assert!(
        json_len > 3 * BLOB_LEN,
        "JSON must dwarf the blob: {json_len}"
    );
    let g = grant(&f, u64::MAX);
    let (req, peak) = peak_alloc(|| {
        AuthenticatedRequest::sign_new(
            &f.agent,
            g,
            f.repo.clone(),
            Capability::Propose,
            derived("nonce", 0),
            2_000,
            0,
            p,
        )
    });
    let req = req.unwrap();
    assert_eq!(req.payload_bytes_len, json_len as u64);
    assert!(
        peak <= SMALL_ALLOC_CEILING,
        "sign_new made a {peak} byte allocation for a {json_len} byte JSON payload"
    );
}

#[test]
fn authorizing_a_large_payload_never_materializes_its_json() {
    let f = fixture();
    let p = payload();
    let json_len = serde_json::to_vec(&p).unwrap().len();
    let req = AuthenticatedRequest::sign_new(
        &f.agent,
        grant(&f, u64::MAX),
        f.repo.clone(),
        Capability::Propose,
        derived("nonce", 1),
        2_000,
        0,
        p,
    )
    .unwrap();
    let mut e = enforcer(&f);
    let (r, peak) = peak_alloc(|| {
        e.authorize(
            BoundaryKind::Api,
            "submit",
            &f.repo,
            Capability::Propose,
            &req,
            2_000,
        )
    });
    r.unwrap();
    assert!(
        peak <= SMALL_ALLOC_CEILING,
        "authorize made a {peak} byte allocation for a {json_len} byte JSON payload"
    );
}

#[test]
fn payload_digest_streams_and_matches_the_materialized_json() {
    let p = payload();
    let json = serde_json::to_vec(&p).unwrap();
    let want: [u8; 32] = Sha256::digest(&json).into();
    let (got, peak) = peak_alloc(|| payload_digest(&p).unwrap());
    assert_eq!(got, (want, json.len() as u64));
    assert!(
        peak <= SMALL_ALLOC_CEILING,
        "payload_digest made a {peak} byte allocation for a {} byte JSON payload",
        json.len()
    );
}
