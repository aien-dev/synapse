//! Deterministic fixtures shared by the G1 tests, the fuzzer's seed corpus, and the
//! transport benchmark: fixed keys, a capability chain granted by a fixed repository
//! authority, signed envelopes, and one valid frame of every kind.

use crate::frame::{Accepted, Chunk, Frame, FrameBody, Have, Hello, Refused, Want};
use crate::session::submit_request;
use ed25519_dalek::SigningKey;
use synapse_auth::{
    Capability, CapabilityChain, CapabilityLink, ChainQuotas, ChangeScope, LinkCaveats,
    OperationSet, PathScope, PolicyEnforcer, ReferenceKind, ReferenceScope, ROOT_PARENT,
};
use synapse_core::{
    encode_did_key_ed25519, BlobDigest, ChangesetEnvelope, ChangesetId, EvidenceAttachment,
    FileMode, GitOid, IdempotencyKey, MutationOp, PathMutation, RefusalCode, RepoId, WalSeq,
    SYNAPSE_ENVELOPE_VERSION,
};

/// Repository of every fixture.
pub const REPO: &str = "aien-spark/synapse";

pub fn repo() -> RepoId {
    RepoId::new(REPO).expect("valid fixture repository id")
}

/// Links are valid from 0 to this time (milliseconds, year 2096).
pub const FIXTURE_EXPIRES_AT_MS: u64 = 4_000_000_000_000;

fn wide_caveats() -> LinkCaveats {
    LinkCaveats {
        operations: OperationSet::from_capabilities(&[
            Capability::Read,
            Capability::Propose,
            Capability::Evaluate,
            Capability::Review,
            Capability::Publish,
            Capability::Undo,
        ]),
        paths: PathScope::whole_repository(),
        references: ReferenceScope::from_kinds(&[
            ReferenceKind::OwnDrafts,
            ReferenceKind::CanonicalViaPromotionQueue,
        ]),
        changes: ChangeScope::any(),
        quotas: ChainQuotas {
            max_ops_per_window: 10_000_000,
            window_duration_ms: 60_000,
            storage_bytes: 1 << 40,
            footprint_paths: 1 << 30,
            max_bytes_per_op: 64 << 20,
        },
        issued_at_ms: 0,
        expires_at_ms: FIXTURE_EXPIRES_AT_MS,
    }
}

/// A repository authority, an agent, and a granted chain from the authority to the agent.
pub struct ChainFixture {
    pub authority: SigningKey,
    pub agent: SigningKey,
    pub chain: CapabilityChain,
    /// Chain prefixes, shortest first, in grant order.
    prefixes: Vec<CapabilityChain>,
}

impl ChainFixture {
    /// A chain of `depth` links (1 to 3): authority, then intermediate keys, then the agent.
    /// `paths` narrows the leaf link's path scope (`None`: whole repository).
    pub fn new(depth: usize, paths: Option<Vec<String>>) -> Self {
        assert!((1..=3).contains(&depth), "fixture depth 1..=3");
        let authority = SigningKey::from_bytes(&[0x11; 32]);
        let mids = [
            SigningKey::from_bytes(&[0x22; 32]),
            SigningKey::from_bytes(&[0x33; 32]),
        ];
        let agent = SigningKey::from_bytes(&[0x44; 32]);
        let mut signer = authority.clone();
        let mut parent = ROOT_PARENT;
        let mut links = Vec::new();
        let mut prefixes = Vec::new();
        let audiences: Vec<SigningKey> = mids[..depth - 1]
            .iter()
            .cloned()
            .chain([agent.clone()])
            .collect();
        for (i, audience) in audiences.into_iter().enumerate() {
            let mut caveats = wide_caveats();
            if i + 1 == depth {
                if let Some(p) = &paths {
                    caveats.paths = PathScope::new(p.clone()).expect("valid fixture path scope");
                }
            }
            let link = CapabilityLink::issue(
                &signer,
                parent,
                [0xA0 + i as u8; 32],
                repo(),
                audience.verifying_key().to_bytes(),
                caveats,
            );
            parent = link.digest();
            links.push(link);
            prefixes.push(CapabilityChain::new(links.clone()));
            signer = audience;
        }
        Self {
            authority,
            agent,
            chain: CapabilityChain::new(links),
            prefixes,
        }
    }

    pub fn agent_did(&self) -> String {
        encode_did_key_ed25519(&self.agent.verifying_key().to_bytes())
    }

    /// An enforcer that trusts the authority and has granted every link at `WalSeq(0)`.
    pub fn enforcer(&self) -> PolicyEnforcer {
        let mut e = PolicyEnforcer::new();
        e.register_repo_authority(
            repo(),
            encode_did_key_ed25519(&self.authority.verifying_key().to_bytes()),
        );
        for c in &self.prefixes {
            e.grant_link(c, WalSeq(0), 1).expect("fixture link grants");
        }
        e
    }
}

/// A signed envelope by `agent` upserting `files` and deleting `deletes`, plus its blobs.
/// Paths are sorted, as the envelope requires.
pub fn envelope(
    agent: &SigningKey,
    label: &str,
    files: &[(&str, Vec<u8>)],
    deletes: &[&str],
    created_at_ms: u64,
) -> (ChangesetEnvelope, Vec<(BlobDigest, Vec<u8>)>) {
    let mut mutations = Vec::new();
    let mut blobs = Vec::new();
    for (path, bytes) in files {
        let d = BlobDigest::compute(bytes);
        mutations.push(PathMutation {
            path: (*path).to_string(),
            op: MutationOp::Upsert {
                mode: FileMode::Regular644,
                blob_digest: d,
                size_bytes: bytes.len() as u64,
            },
        });
        blobs.push((d, bytes.clone()));
    }
    for path in deletes {
        mutations.push(PathMutation {
            path: (*path).to_string(),
            op: MutationOp::Delete,
        });
    }
    mutations.sort_by(|a, b| a.path.cmp(&b.path));
    let mut env = ChangesetEnvelope {
        version: SYNAPSE_ENVELOPE_VERSION,
        repo_id: repo(),
        base_git_oid: GitOid([0x5A; 20]),
        parent_changesets: Vec::new(),
        author_did: encode_did_key_ed25519(&agent.verifying_key().to_bytes()),
        idempotency_key: IdempotencyKey::from_label(label),
        created_at_ms,
        intent_summary: format!("G1 fixture change {label}"),
        mutations,
        evidence_receipts: Vec::new(),
        signature: Vec::new(),
    };
    env.sign(agent);
    (env, blobs)
}

fn digest(n: u8) -> BlobDigest {
    let mut d = [n; 32];
    d[0] = n;
    BlobDigest(d)
}

/// At least one valid frame of every kind, with edge cases (empty lists, empty chunk,
/// depth 1 and depth 3 chains, an envelope with evidence and a delete, every option tag).
pub fn sample_frames() -> Vec<Frame> {
    let deep = ChainFixture::new(3, None);
    let shallow = ChainFixture::new(1, None);
    let (env, _) = envelope(
        &deep.agent,
        "sample",
        &[("crates/a.rs", b"fn a() {}\n".to_vec())],
        &["docs/old.md"],
        7,
    );
    let mut env_evidence = env.clone();
    env_evidence.evidence_receipts.push(EvidenceAttachment {
        gate_name: "unit".into(),
        passed: true,
        artifact_digest: [9u8; 32],
        summary: "ok".into(),
    });
    env_evidence.sign(&deep.agent);
    let req = submit_request(&deep.agent, deep.chain.clone(), &env, [1u8; 32], 7).expect("req");
    let mut req_scoped =
        submit_request(&deep.agent, deep.chain.clone(), &env_evidence, [2u8; 32], 8).expect("req");
    req_scoped.scope.reference = Some(ReferenceKind::OwnDrafts);
    req_scoped.scope.join_change = Some(synapse_core::ChangeId([3u8; 16]));
    let (env1, _) = envelope(&shallow.agent, "shallow", &[], &["x"], 9);
    let mut req_shallow =
        submit_request(&shallow.agent, shallow.chain.clone(), &env1, [4u8; 32], 9).expect("req");
    req_shallow.scope.reference = Some(ReferenceKind::CanonicalViaPromotionQueue);
    let bodies = vec![
        FrameBody::Hello(Hello {
            max_frame_body: 4096,
            max_pending_chunk_bytes: 1 << 20,
        }),
        FrameBody::Have(Have {
            repo_id: repo(),
            digests: vec![],
        }),
        FrameBody::Have(Have {
            repo_id: repo(),
            digests: vec![digest(1), digest(2), digest(3)],
        }),
        FrameBody::Want(Want { digests: vec![] }),
        FrameBody::Want(Want {
            digests: vec![digest(2)],
        }),
        FrameBody::Chunk(Chunk {
            digest: BlobDigest::compute(b""),
            bytes: vec![],
        }),
        FrameBody::Chunk(Chunk {
            digest: BlobDigest::compute(b"fn a() {}\n"),
            bytes: b"fn a() {}\n".to_vec(),
        }),
        FrameBody::Submit(Box::new(req)),
        FrameBody::Submit(Box::new(req_scoped)),
        FrameBody::Submit(Box::new(req_shallow)),
        FrameBody::Accepted(Accepted {
            wal_seq: WalSeq(42),
            changeset_id: ChangesetId([6u8; 32]),
            duplicate: false,
        }),
        FrameBody::Accepted(Accepted {
            wal_seq: WalSeq(u64::MAX),
            changeset_id: ChangesetId([0u8; 32]),
            duplicate: true,
        }),
        FrameBody::Refused(Refused {
            code: RefusalCode::WireProtocolViolation,
            message: "Submit before wanted chunk".into(),
        }),
        FrameBody::Refused(Refused {
            code: RefusalCode::AuthChainBroken,
            message: String::new(),
        }),
    ];
    bodies
        .into_iter()
        .enumerate()
        .map(|(i, body)| Frame {
            request_id: i as u32 * 7919,
            body,
        })
        .collect()
}

/// A fresh empty directory under the system temp directory.
pub fn temp_dir(label: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "synapse-wire-{label}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("create temp dir");
    dir
}

/// A shared group-commit store (default group-commit policy, strict recovery).
pub fn open_store(dir: &std::path::Path) -> std::sync::Arc<synapse_store::SharedStore> {
    std::sync::Arc::new(
        synapse_store::SharedStore::open(
            dir,
            synapse_store::FsyncPolicy::GROUP_COMMIT_DEFAULT,
            synapse_store::RecoveryPolicy::StrictFailClosed,
            synapse_store::StoreLimits::default(),
        )
        .expect("open shared store"),
    )
}

/// Server time used by fixture servers (milliseconds).
pub const FIXTURE_NOW_MS: u64 = 1_000_000;

/// A wire server for [`REPO`] over `store`, trusting `fx`'s authority, with a fixed clock.
pub fn server(
    fx: &ChainFixture,
    store: std::sync::Arc<synapse_store::SharedStore>,
) -> crate::WireServer {
    crate::WireServer::new(
        crate::ServerConfig {
            repo_id: repo(),
            read_limits: crate::WireLimits::default(),
            max_pending_chunk_bytes: crate::session::DEFAULT_MAX_PENDING_CHUNK_BYTES,
        },
        store,
        fx.enforcer(),
        std::sync::Arc::new(|| FIXTURE_NOW_MS),
    )
    .expect("wire server")
}
