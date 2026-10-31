//! Writes an A2 segment store (64 KiB segments, blobs of 20 to 40 KB stored whole in the
//! segments, a checkpoint with its version 1 segment index, then frames after it) with
//! the A2 store code, plus `EXPECT` (committed sequence and state root).

use ed25519_dalek::SigningKey;
use std::path::PathBuf;
use synapse_core::{
    BlobDigest, ChangesetEnvelope, FileMode, GitOid, IdempotencyKey, MutationOp, PathMutation,
    RepoId, SYNAPSE_ENVELOPE_VERSION,
};
use synapse_store::{FsyncPolicy, RecoveryPolicy, StoreLimits, SynapseStore};

fn bytes(len: usize, seed: u64) -> Vec<u8> {
    let mut x = seed | 1;
    (0..len)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            b'a' + ((x >> 24) % 26) as u8
        })
        .collect()
}

fn main() {
    let out = PathBuf::from(std::env::args().nth(1).expect("usage: generator <out dir>"));
    assert!(!out.exists(), "{} exists", out.display());
    let limits = StoreLimits {
        segment_bytes: 64 * 1024,
        wal_prealloc_bytes: 16 * 1024,
        ..Default::default()
    };
    let mut store = SynapseStore::open(
        &out,
        FsyncPolicy::GROUP_COMMIT_DEFAULT,
        RecoveryPolicy::StrictFailClosed,
        limits,
    )
    .unwrap();
    let key = SigningKey::from_bytes(&[0xA2; 32]);
    for i in 0..12u64 {
        let files: Vec<(String, Vec<u8>)> = (0..1 + i % 2)
            .map(|f| (format!("src/f{i}-{f}.rs"), bytes(20_000 + (i as usize * 1700) % 20_000, 100 * i + f)))
            .collect();
        let blobs: Vec<(BlobDigest, Vec<u8>)> = files
            .iter()
            .map(|(_, c)| (BlobDigest::compute(c), c.clone()))
            .collect();
        let mut env = ChangesetEnvelope {
            version: SYNAPSE_ENVELOPE_VERSION,
            repo_id: RepoId::new("aien-spark/synapse").unwrap(),
            base_git_oid: GitOid::compute_blob(b"base"),
            parent_changesets: vec![],
            author_did: String::new(),
            idempotency_key: IdempotencyKey::from_label(&format!("a2-fixture-{i}")),
            created_at_ms: 1000 + i,
            intent_summary: format!("A2 fixture change {i}"),
            mutations: files
                .iter()
                .map(|(p, c)| PathMutation {
                    path: p.clone(),
                    op: MutationOp::Upsert {
                        mode: FileMode::Regular644,
                        blob_digest: BlobDigest::compute(c),
                        size_bytes: c.len() as u64,
                    },
                })
                .collect(),
            evidence_receipts: vec![],
            signature: vec![],
        };
        env.sign(&key);
        store.ingest_changeset(env, &blobs).unwrap();
        if i == 7 {
            store.checkpoint_and_compact(1000).unwrap();
        }
    }
    let root = store.state_root_digest(None).unwrap();
    let seq = store.committed_seq();
    drop(store);
    std::fs::write(
        out.join("EXPECT"),
        format!(
            "committed_seq {}\nstate_root {}\nwritten_by A2 commit 6431fcf (synapse-store segment store)\n",
            seq.0,
            hex::encode(root)
        ),
    )
    .unwrap();
}
