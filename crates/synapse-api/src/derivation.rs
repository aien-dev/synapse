//! Server-derived revisions through the service (ADR 0003 step B5): the C1 tree store as the
//! [`DerivationTrees`] every rule is recomputed on, derivation by the server, admission, and
//! replica verification of the revision log. See `docs/B5_DERIVATION_ATTESTATION.md`.

use crate::tree::{algebra_node, algebra_put_node, TreeEdit, TreeFile, TreeStore};
use crate::SynapseService;
use ed25519_dalek::SigningKey;
use std::collections::BTreeMap;
use synapse_core::{
    BlobDigest, ChangesetId, ConflictTerm, ConflictTrees, DerivationInput, DerivationRule,
    DerivationTrees, DerivedRevision, EntryState, FileMode, GitOid, MergeTier, MutationOp,
    NodeEntry, PathMutation, RefusalCode, RevisionContent, ServerKeyRegistry, SynapseError,
    SynapseResult, TreeDigest,
};
use synapse_store::{AdmissionAuthority, RevisionOutcome, SynapseStore, WalRecord};

/// The tree store seen as [`DerivationTrees`].
///
/// A tree file also carries the Git blob OID of its blob (a bridge attribute that never
/// affects a `TreeDigest`). `git_oids` starts with the OIDs the caller computed and remembers
/// the OID of every file read from a tree; any other blob a rule writes (an upsert, or a file
/// state a conflict sum resolves to, step D2) is hashed on demand from the bytes this adapter
/// can read: `produced`, `blobs`, the store when it is lent (`store`), then the base-tree
/// files (`base_blobs`), the lookup order of `SynapseService::read_blob_bytes`.
///
/// `blobs` holds the bytes a tier T1 merge reads (the input revisions' upserted blobs and the
/// base files at their paths, loaded before the rule runs) and `produced` the merged files a
/// rule wrote through [`DerivationTrees::put_blob`].
///
/// Admission cannot lend the store (it mutates it) and need not: every file of the recomputed
/// result is either read from an input tree or upserted by the derived revision's own
/// mutations, whose OIDs the caller computes first.
pub struct ServiceDerivationTrees<'a> {
    trees: &'a mut TreeStore,
    git_oids: BTreeMap<BlobDigest, GitOid>,
    blobs: BTreeMap<BlobDigest, Vec<u8>>,
    produced: BTreeMap<BlobDigest, Vec<u8>>,
    store: Option<&'a SynapseStore>,
    base_blobs: &'a BTreeMap<BlobDigest, Vec<u8>>,
}

impl ServiceDerivationTrees<'_> {
    /// The Git blob OID of `digest`, remembered or hashed from the readable bytes; `None` when
    /// this adapter cannot read the blob.
    fn git_oid(&mut self, digest: BlobDigest) -> Option<GitOid> {
        if let Some(oid) = self.git_oids.get(&digest) {
            return Some(*oid);
        }
        let stored = self
            .store
            .and_then(|s| s.get_blob_visible(digest, None, None).ok());
        let bytes = self
            .produced
            .get(&digest)
            .or_else(|| self.blobs.get(&digest))
            .or(stored.as_ref())
            .or_else(|| self.base_blobs.get(&digest))?;
        let oid = GitOid::compute_blob(bytes);
        self.git_oids.insert(digest, oid);
        Some(oid)
    }
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
                    let git_blob_oid = self.git_oid(*blob_digest).ok_or_else(|| {
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
                MutationOp::Conflict(term) => {
                    edit.set_conflict(self.trees, &m.path, term.clone())?
                }
            }
        }
        edit.finish(self.trees)
    }

    fn file_at(
        &mut self,
        tree: TreeDigest,
        path: &str,
    ) -> SynapseResult<Option<(FileMode, BlobDigest)>> {
        Ok(self
            .trees
            .lookup(tree, path)?
            .map(|f| (f.mode, f.blob_digest)))
    }

    fn blob_bytes(&mut self, digest: BlobDigest) -> SynapseResult<Vec<u8>> {
        self.produced
            .get(&digest)
            .or_else(|| self.blobs.get(&digest))
            .cloned()
            .ok_or_else(|| {
                SynapseError::new(
                    RefusalCode::BlobNotFound,
                    format!("blob {digest} is not readable by this derivation"),
                )
            })
    }

    fn put_blob(&mut self, bytes: Vec<u8>) -> SynapseResult<BlobDigest> {
        let digest = BlobDigest::compute(&bytes);
        self.git_oids
            .entry(digest)
            .or_insert_with(|| GitOid::compute_blob(&bytes));
        self.produced.insert(digest, bytes);
        Ok(digest)
    }

    /// A merged file the rule produced, or a base-tree file (step D2: a conflict sum can
    /// restore a file only a base tree holds, which the store must then write with the record).
    fn produced_blob(&self, digest: BlobDigest) -> Option<&[u8]> {
        self.produced
            .get(&digest)
            .or_else(|| self.base_blobs.get(&digest))
            .map(Vec::as_slice)
    }
}

impl ConflictTrees for ServiceDerivationTrees<'_> {
    fn node(&mut self, tree: TreeDigest) -> SynapseResult<Vec<(String, NodeEntry)>> {
        algebra_node(self.trees, &mut self.git_oids, tree)
    }

    fn put_node(&mut self, entries: Vec<(String, NodeEntry)>) -> SynapseResult<TreeDigest> {
        // A file state of the sum may come from a conflict term rather than a tree read, so
        // its OID is looked up first; an unreadable blob is refused by `algebra_put_node`.
        for (_, e) in &entries {
            if let NodeEntry::State(EntryState::File { blob_digest, .. }) = e {
                self.git_oid(*blob_digest);
            }
        }
        algebra_put_node(self.trees, &self.git_oids, entries)
    }
}

impl SynapseService {
    /// Git blob OIDs of every readable upserted blob of `contents`, computed before admission
    /// lends the tree store without the blob store (unreadable blobs are left out; a rule that
    /// needs one then fails with `BlobNotFound`).
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

    /// The bytes a tier T1 merge of `contents` reads: every upserted blob, and the file at each
    /// mutated path of each content's base tree. Empty unless `rule` is a tier T1 merge (other
    /// rules never read file bytes). Blobs this replica cannot read are left out; the rule then
    /// refuses with `BlobNotFound` if it needs them.
    fn merge_blobs(
        &mut self,
        rule: DerivationRule,
        contents: &[RevisionContent],
    ) -> BTreeMap<BlobDigest, Vec<u8>> {
        let mut out = BTreeMap::new();
        if rule
            != (DerivationRule::Merge {
                tier: MergeTier::T1Region,
            })
        {
            return out;
        }
        let mut wanted = Vec::new();
        for c in contents {
            for m in &c.mutations {
                if let MutationOp::Upsert { blob_digest, .. } = &m.op {
                    wanted.push(*blob_digest);
                }
                if let Ok(Some(f)) = self.trees.lookup(c.base_tree, &m.path) {
                    wanted.push(f.blob_digest);
                }
            }
        }
        for d in wanted {
            if let std::collections::btree_map::Entry::Vacant(slot) = out.entry(d) {
                if let Ok(bytes) = self.read_blob_bytes(d, None) {
                    slot.insert(bytes);
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

    /// The tree of an admitted envelope v2 revision: its base tree with its mutations applied
    /// (ADR 0003 step D2). The base tree must be held (`DerivationInputMismatch` otherwise).
    pub fn revision_tree(&mut self, id: ChangesetId) -> SynapseResult<TreeDigest> {
        let content = self.store.get_revision(&self.repo_id, id)?.content;
        if !self.trees.contains(content.base_tree) {
            return Err(SynapseError::new(
                RefusalCode::DerivationInputMismatch,
                format!(
                    "base tree {} of revision {id} is not held by this replica",
                    content.base_tree
                ),
            ));
        }
        let mut trees = ServiceDerivationTrees {
            trees: &mut self.trees,
            git_oids: BTreeMap::new(),
            blobs: BTreeMap::new(),
            produced: BTreeMap::new(),
            store: Some(&self.store),
            base_blobs: &self.base_blobs,
        };
        trees.apply_mutations(content.base_tree, &content.mutations)
    }

    /// The conflict entries of a native tree, with their paths (ADR 0003 step D2): a
    /// conflicted tree can always be read.
    pub fn tree_conflicts(
        &mut self,
        tree: TreeDigest,
    ) -> SynapseResult<Vec<(String, ConflictTerm)>> {
        self.trees.conflicts(tree)
    }

    /// Materialize every file of a native tree, for a build (ADR 0003 step D2). A tree that
    /// holds a conflict entry is refused (`TreeConflicted`).
    pub fn materialize_tree(&mut self, tree: TreeDigest) -> SynapseResult<Vec<(String, TreeFile)>> {
        self.trees.files(tree)
    }

    /// The promotion gate of ADR 0003 step D2: a revision whose tree holds any conflict entry
    /// cannot be promoted (`TreeConflicted`), whether its own mutations record the conflict or
    /// it is based on a conflicted tree without resolving it. The promotion queue (step E2)
    /// calls it before it merges and tests a revision.
    pub fn check_promotion(&mut self, id: ChangesetId) -> SynapseResult<()> {
        let tree = self.revision_tree(id)?;
        self.trees.refuse_conflicted(tree, "promotion")
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
        let blobs = self.merge_blobs(rule, &sources);
        let store = &self.store;
        let repo = self.repo_id.clone();
        let lookup = |id: ChangesetId| store.get_revision(&repo, id).ok().map(|r| r.content);
        let mut trees = ServiceDerivationTrees {
            trees: &mut self.trees,
            git_oids: BTreeMap::new(),
            blobs,
            produced: BTreeMap::new(),
            store: Some(store),
            base_blobs: &self.base_blobs,
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
        let blobs = self.merge_blobs(derived.attestation.rule, &sources);
        sources.push(derived.content.clone());
        let git_oids = self.git_oids_of(&sources);
        let mut trees = ServiceDerivationTrees {
            trees: &mut self.trees,
            git_oids,
            blobs,
            produced: BTreeMap::new(),
            store: None,
            base_blobs: &self.base_blobs,
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
        let mut t1_inputs = Vec::new();
        for (_, r) in records {
            if let WalRecord::DerivedRevisionAdmitted { derived, .. } = r {
                if derived.attestation.rule
                    == (DerivationRule::Merge {
                        tier: MergeTier::T1Region,
                    })
                {
                    t1_inputs
                        .extend(self.record_input_contents(records, &derived.attestation.inputs));
                }
            }
        }
        let blobs = self.merge_blobs(
            DerivationRule::Merge {
                tier: MergeTier::T1Region,
            },
            &t1_inputs,
        );
        let mut trees = ServiceDerivationTrees {
            trees: &mut self.trees,
            git_oids: BTreeMap::new(),
            blobs,
            produced: BTreeMap::new(),
            store: Some(&self.store),
            base_blobs: &self.base_blobs,
        };
        synapse_store::verify_revision_log(records, keys, &mut trees)
    }

    /// Contents of the revisions `inputs` names, from `records` (a replica verifies records it
    /// may not have admitted itself).
    fn record_input_contents(
        &self,
        records: &[(synapse_core::WalSeq, WalRecord)],
        inputs: &[DerivationInput],
    ) -> Vec<RevisionContent> {
        inputs
            .iter()
            .filter_map(|i| match i {
                DerivationInput::Revision(id) => records.iter().find_map(|(_, r)| match r {
                    WalRecord::RevisionAdmitted { envelope, .. }
                        if envelope.attestation.changeset_id == *id =>
                    {
                        Some(envelope.content.clone())
                    }
                    WalRecord::DerivedRevisionAdmitted { derived, .. }
                        if derived.attestation.output_changeset == *id =>
                    {
                        Some(derived.content.clone())
                    }
                    _ => None,
                }),
                DerivationInput::Tree(_) => None,
            })
            .collect()
    }

    /// Verify this service's own revision log as a replica would after replay.
    pub fn verify_revision_log(&mut self, keys: &dyn ServerKeyRegistry) -> SynapseResult<usize> {
        let records = self.store.revision_records().to_vec();
        self.verify_revision_records(&records, keys)
    }
}
