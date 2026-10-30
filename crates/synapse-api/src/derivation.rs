//! Server-derived revisions through the service (ADR 0003 step B5): the C1 tree store as the
//! [`DerivationTrees`] every rule is recomputed on, derivation by the server, admission, and
//! replica verification of the revision log. See `docs/B5_DERIVATION_ATTESTATION.md`.

use crate::tree::{TreeEdit, TreeFile, TreeStore};
use crate::SynapseService;
use ed25519_dalek::SigningKey;
use std::collections::BTreeMap;
use synapse_core::{
    BlobDigest, ChangesetId, DerivationInput, DerivationRule, DerivationTrees, DerivedRevision,
    GitOid, MutationOp, PathMutation, RefusalCode, RevisionContent, ServerKeyRegistry,
    SynapseError, SynapseResult, TreeDigest,
};
use synapse_store::{AdmissionAuthority, RevisionOutcome, WalRecord};

/// The tree store seen as [`DerivationTrees`]. `git_oids` carries the Git blob OID of every
/// blob a rule may upsert: a bridge attribute of tree files that never affects a `TreeDigest`.
pub struct ServiceDerivationTrees<'a> {
    trees: &'a mut TreeStore,
    git_oids: BTreeMap<BlobDigest, GitOid>,
}

impl DerivationTrees for ServiceDerivationTrees<'_> {
    fn holds_tree(&mut self, tree: TreeDigest) -> bool {
        self.trees.contains(tree)
    }

    fn apply_mutations(
        &mut self,
        base: TreeDigest,
        mutations: &[PathMutation],
    ) -> SynapseResult<TreeDigest> {
        let mut edit = TreeEdit::new(self.trees, base)?;
        for m in mutations {
            match &m.op {
                MutationOp::Upsert {
                    mode,
                    blob_digest,
                    size_bytes,
                } => {
                    let git_blob_oid = *self.git_oids.get(blob_digest).ok_or_else(|| {
                        SynapseError::new(
                            RefusalCode::BlobNotFound,
                            format!("blob {blob_digest} of path {} is not readable", m.path),
                        )
                    })?;
                    let file = TreeFile {
                        mode: *mode,
                        blob_digest: *blob_digest,
                        size_bytes: *size_bytes,
                        git_blob_oid,
                    };
                    edit.upsert(self.trees, &m.path, file)?;
                }
                MutationOp::Delete => edit.delete(self.trees, &m.path)?,
            }
        }
        edit.finish(self.trees)
    }

    fn changed_paths(&mut self, from: TreeDigest, to: TreeDigest) -> SynapseResult<Vec<String>> {
        Ok(self
            .trees
            .diff(from, to)?
            .into_iter()
            .map(|e| e.path)
            .collect())
    }
}

impl SynapseService {
    /// Git blob OIDs of every readable upserted blob of `contents` (unreadable blobs are left
    /// out; a rule that needs one then fails with `BlobNotFound`).
    fn git_oids_of<'c>(
        &self,
        contents: impl IntoIterator<Item = &'c RevisionContent>,
    ) -> BTreeMap<BlobDigest, GitOid> {
        let mut out = BTreeMap::new();
        for c in contents {
            for m in &c.mutations {
                if let MutationOp::Upsert { blob_digest, .. } = &m.op {
                    if out.contains_key(blob_digest) {
                        continue;
                    }
                    if let Ok(raw) = self.read_blob_bytes(*blob_digest, None) {
                        out.insert(*blob_digest, GitOid::compute_blob(&raw));
                    }
                }
            }
        }
        out
    }

    /// Contents of the input revisions `inputs` names that this repository has admitted.
    fn input_contents(&self, inputs: &[DerivationInput]) -> Vec<RevisionContent> {
        inputs
            .iter()
            .filter_map(|i| match i {
                DerivationInput::Revision(id) => self
                    .store
                    .get_revision(&self.repo_id, *id)
                    .ok()
                    .map(|r| r.content),
                DerivationInput::Tree(_) => None,
            })
            .collect()
    }

    /// Derive a revision as the server: recompute `rule` on `inputs` over the tree store and
    /// sign the attestation with the server's machine key `server`. Nothing is admitted.
    pub fn derive_revision(
        &mut self,
        server: &SigningKey,
        rule: DerivationRule,
        inputs: Vec<DerivationInput>,
    ) -> SynapseResult<DerivedRevision> {
        let sources = self.input_contents(&inputs);
        let git_oids = self.git_oids_of(&sources);
        let store = &self.store;
        let repo = self.repo_id.clone();
        let lookup = |id: ChangesetId| store.get_revision(&repo, id).ok().map(|r| r.content);
        let mut trees = ServiceDerivationTrees {
            trees: &mut self.trees,
            git_oids,
        };
        DerivedRevision::derive(
            server,
            self.repo_id.clone(),
            rule,
            inputs,
            &lookup,
            &mut trees,
        )
    }

    /// Admit a server-derived revision (ADR 0003 B5) under `authority` (the chain that asked
    /// for it or proposed it, already authorized by the caller). `keys` is the repository
    /// identity log (`synapse_radicle::IdentityLog`). The attestation must name this service's
    /// repository (`AuthCrossRepoDenied`); the store then checks the derivation and recomputes
    /// it over the tree store.
    pub fn admit_derived_revision(
        &mut self,
        derived: DerivedRevision,
        authority: AdmissionAuthority,
        keys: &dyn ServerKeyRegistry,
        now_ms: u64,
    ) -> SynapseResult<RevisionOutcome> {
        if derived.attestation.repo_id != self.repo_id {
            return Err(SynapseError::new(
                RefusalCode::AuthCrossRepoDenied,
                "derivation attestation repo_id does not match service repo_id",
            ));
        }
        let mut sources = self.input_contents(&derived.attestation.inputs);
        sources.push(derived.content.clone());
        let git_oids = self.git_oids_of(&sources);
        let mut trees = ServiceDerivationTrees {
            trees: &mut self.trees,
            git_oids,
        };
        self.store
            .admit_derived_revision(derived, authority, keys, &mut trees, now_ms)
    }

    /// Verify `records` as a replica (see `synapse_store::verify_revision_log`), recomputing
    /// every derived revision over this service's tree store. Returns the number of records
    /// verified.
    pub fn verify_revision_records(
        &mut self,
        records: &[(synapse_core::WalSeq, WalRecord)],
        keys: &dyn ServerKeyRegistry,
    ) -> SynapseResult<usize> {
        let contents = records.iter().filter_map(|(_, r)| match r {
            WalRecord::RevisionAdmitted { envelope, .. } => Some(&envelope.content),
            WalRecord::DerivedRevisionAdmitted { derived, .. } => Some(&derived.content),
            _ => None,
        });
        let git_oids = self.git_oids_of(contents);
        let mut trees = ServiceDerivationTrees {
            trees: &mut self.trees,
            git_oids,
        };
        synapse_store::verify_revision_log(records, keys, &mut trees)
    }

    /// Verify this service's own revision log as a replica would after replay.
    pub fn verify_revision_log(&mut self, keys: &dyn ServerKeyRegistry) -> SynapseResult<usize> {
        let records = self.store.revision_records().to_vec();
        self.verify_revision_records(&records, keys)
    }
}
