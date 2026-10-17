//! ADR 0003 step B5 (issue #29): the `DerivedRevisionAdmitted` WAL record (kind 11) round
//! trips through the binary codec and malformed bytes are refused typed. Admission, replay
//! verification and recomputation are tested through `synapse-api`
//! (`tests/b5_derivation_attestation.rs`), which holds the tree store.

use ed25519_dalek::SigningKey;
use sha2::{Digest, Sha256};
use synapse_core::{
    BlobDigest, ChainPath, ChangeId, ChangesetId, DerivationAttestation, DerivationInput,
    DerivationRule, DerivedRevision, FileMode, MergeTier, MutationOp, PathMutation, RepoId,
    RevisionContent, TreeDigest,
};
use synapse_store::codec::{decode_record, encode_record};
use synapse_store::WalRecord;

/// 32 bytes derived from a label (no literal key material).
fn label(s: &str) -> [u8; 32] {
    Sha256::digest(format!("synapse b5 store test: {s}").as_bytes()).into()
}

fn derived(rule: DerivationRule, inputs: Vec<DerivationInput>) -> DerivedRevision {
    let mut change = [0u8; 16];
    change.copy_from_slice(&label("change")[..16]);
    let content = RevisionContent {
        change_id: ChangeId(change),
        base_tree: TreeDigest(label("base")),
        parents: vec![],
        mutations: vec![PathMutation {
            path: "src/lib.rs".into(),
            op: MutationOp::Upsert {
                mode: FileMode::Regular644,
                blob_digest: BlobDigest::compute(b"x"),
                size_bytes: 1,
            },
        }],
        intent_summary: "derived".into(),
    };
    let attestation = DerivationAttestation::sign(
        &SigningKey::from_bytes(&label("server")),
        RepoId::new("aien-spark/synapse").unwrap(),
        rule,
        inputs,
        content.changeset_id(),
        TreeDigest(label("output")),
    );
    DerivedRevision {
        content,
        attestation,
    }
}

#[test]
fn b5_derived_revision_records_round_trip_and_malformed_bytes_are_refused_typed() {
    let a = ChangesetId(label("a"));
    let b = ChangesetId(label("b"));
    let records = [
        derived(
            DerivationRule::Rebase,
            vec![
                DerivationInput::Revision(a),
                DerivationInput::Tree(TreeDigest(label("onto"))),
            ],
        ),
        derived(
            DerivationRule::Merge {
                tier: MergeTier::T0Path,
            },
            vec![
                DerivationInput::Tree(TreeDigest(label("base"))),
                DerivationInput::Revision(a),
                DerivationInput::Revision(b),
            ],
        ),
    ]
    .map(|derived| WalRecord::DerivedRevisionAdmitted {
        derived,
        chain: ChainPath::new(vec![label("chain")]).unwrap(),
        admitted_at_ms: 7,
    });
    for record in records {
        assert_eq!(record.kind_byte(), 11);
        let bytes = encode_record(&record).unwrap();
        assert_eq!(decode_record(&bytes, 1 << 20).unwrap(), record);
        for cut in 0..bytes.len() {
            assert!(decode_record(&bytes[..cut], 1 << 20).is_err(), "cut {cut}");
        }
        let mut longer = bytes.clone();
        longer.push(0);
        assert!(decode_record(&longer, 1 << 20).is_err());
        // Flip each byte after the header: refused or decodes to a different record, never a
        // panic.
        for i in 2..bytes.len() {
            let mut b = bytes.clone();
            b[i] ^= 0x41;
            if let Ok(r) = decode_record(&b, 1 << 20) {
                assert_ne!(r, record);
            }
        }
        // No v1 JSON form.
        assert!(serde_json::to_vec(&record).is_err());
    }
}
