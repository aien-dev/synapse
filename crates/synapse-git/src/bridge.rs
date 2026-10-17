//! ADR 0003 step H1 cut 2: the native side of the Git bridge (section 5.10). See
//! `docs/H1_GIT_BRIDGE.md`.
//!
//! * [`import_repository`] / [`import_history`]: a repository's full history into the store as
//!   WAL kind 10 records (`synapse_store::git_bridge`). Blobs become stored blobs, trees become
//!   canonical `TreeDigest` nodes (C1), commits become imported revisions that keep every byte
//!   after their `tree` and `parent` lines, annotated tags keep every byte after their `object`
//!   line, and the references are recorded last. Every object is converted and checked before
//!   the first record is written, so a refused repository leaves the store unchanged.
//! * [`export_store`]: a new bare repository from the store alone. Imported objects are rebuilt
//!   from their native form and the stored bytes, and each must hash to the Git ID it was
//!   imported under. Native revisions (envelope v2) are written with generated, deterministic
//!   commit fields.

use crate::object::{parse_commit_links, parse_tag_target, parse_tree, GitTreeEntry};
use crate::repo::{export_repository, ExportReceipt, GitHistory, GitRepository, ReadLimits};
use crate::{GitObject, ObjectKind};
use std::collections::{BTreeMap, HashMap};
use std::path::Path;
use synapse_core::{
    decode_tree_node, tree_entry_order, validate_tree_entry_name, BlobDigest, ChangesetId,
    FileMode, GitOid, MutationOp, RefusalCode, RepoId, SynapseError, SynapseResult, TreeDigest,
    TreeNodeEncoder, TreeNodeEntryKind,
};
use synapse_store::git_bridge::{
    check_git_ref_names, GitBlobMapping, GitBridgeEntry, GitBridgeRepo, GitBridgeTarget,
    GitImportedCommit, GitImportedRefs, GitImportedTag, GitTreeMapping,
};
use synapse_store::SynapseStore;

/// Most object mappings in one `Objects` record.
pub const MAX_MAPPINGS_PER_RECORD: usize = 4096;

/// Author email of an exported native revision (its name is the first author's DID).
pub const NATIVE_AUTHOR_EMAIL: &str = "agent@synapse.aienos.local";

/// Committer line identity of an exported native revision.
pub const NATIVE_COMMITTER: &str = "Synapse Engine <synapse@aienos.local>";

fn not_representable(msg: impl Into<String>) -> SynapseError {
    SynapseError::new(RefusalCode::GitObjectNotRepresentable, msg)
}

fn corrupt(msg: impl Into<String>) -> SynapseError {
    SynapseError::new(RefusalCode::GitObjectCorrupt, msg)
}

/// What an import wrote.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ImportReceipt {
    pub blobs: usize,
    pub trees: usize,
    pub commits: usize,
    pub tags: usize,
    pub refs: usize,
    /// Kind 10 records written.
    pub records_written: usize,
    /// Records skipped because the store already held them (a repeated import).
    pub records_skipped: usize,
}

/// Read `git_dir`'s full history under `limits` and import it as `repo_id`.
pub fn import_repository(
    store: &mut SynapseStore,
    repo_id: &RepoId,
    git_dir: &Path,
    limits: ReadLimits,
) -> SynapseResult<ImportReceipt> {
    let history = GitRepository::open_with_limits(git_dir, limits)?.full_history()?;
    import_history(store, repo_id, &history)
}

/// A Git tree entry mode as a native entry: a file mode, or `None` for a subtree. Only the
/// modes Git writes today are representable (`100644`, `100755`, `120000`, `40000`).
fn native_mode(mode: &[u8]) -> SynapseResult<Option<FileMode>> {
    match mode {
        b"100644" => Ok(Some(FileMode::Regular644)),
        b"100755" => Ok(Some(FileMode::Executable755)),
        b"120000" => Ok(Some(FileMode::Symlink120000)),
        b"40000" => Ok(None),
        other => Err(not_representable(format!(
            "tree entry mode {:?} has no native form (gitlinks and legacy modes are not imported)",
            String::from_utf8_lossy(other)
        ))),
    }
}

/// The Git tree a canonical node stands for. Entries keep the node's order, which is Git's
/// tree order; `blob_oid` and `tree_oid` give the Git ID of each entry.
fn git_tree_of_node(
    node: &[u8],
    blob_oid: &dyn Fn(BlobDigest) -> SynapseResult<GitOid>,
    tree_oid: &dyn Fn(TreeDigest) -> SynapseResult<GitOid>,
) -> SynapseResult<GitObject> {
    let mut entries = Vec::new();
    for e in decode_tree_node(node)? {
        let (mode, oid) = match e.kind {
            TreeNodeEntryKind::File { mode, blob, .. } => {
                (mode.git_octal_str().as_bytes().to_vec(), blob_oid(blob)?)
            }
            TreeNodeEntryKind::Dir(child) => (b"40000".to_vec(), tree_oid(child)?),
        };
        entries.push(GitTreeEntry {
            mode,
            name: e.name.into_bytes(),
            oid,
        });
    }
    Ok(GitObject::new(
        ObjectKind::Tree,
        crate::object::encode_tree(&entries),
    ))
}

/// `tree <hex>\n` then `parent <hex>\n` for each parent: the part of a commit the native
/// form stores as links.
fn commit_link_lines(tree: GitOid, parents: &[GitOid]) -> Vec<u8> {
    let mut out = format!("tree {}\n", tree.to_hex()).into_bytes();
    for p in parents {
        out.extend_from_slice(format!("parent {}\n", p.to_hex()).as_bytes());
    }
    out
}

/// Order `oids` so every object comes after the objects `links` names (iterative depth first,
/// so a long history cannot overflow the stack). A link to an object outside `oids` is
/// ignored here (the caller resolves it).
fn links_first(
    oids: &[GitOid],
    links: &dyn Fn(GitOid) -> SynapseResult<Vec<GitOid>>,
) -> SynapseResult<Vec<GitOid>> {
    let members: std::collections::HashSet<GitOid> = oids.iter().copied().collect();
    let mut done: std::collections::HashSet<GitOid> = std::collections::HashSet::new();
    let mut order = Vec::with_capacity(oids.len());
    for &root in oids {
        let mut stack = vec![(root, false)];
        while let Some((oid, expanded)) = stack.pop() {
            if done.contains(&oid) {
                continue;
            }
            if expanded {
                done.insert(oid);
                order.push(oid);
                continue;
            }
            stack.push((oid, true));
            for l in links(oid)? {
                if members.contains(&l) && !done.contains(&l) {
                    stack.push((l, false));
                }
            }
        }
    }
    Ok(order)
}

/// Import `history` as `repo_id`. Every object is converted first; a refusal (unrepresentable
/// tree, non-canonical commit or tag layout, invalid reference name, a blob over the store's
/// blob cap) happens before anything is written. Records then go in dependency order: objects
/// (blobs, then trees, children first), commits (parents first), tags, and one `Refs` record.
/// Importing the same history again writes nothing.
pub fn import_history(
    store: &mut SynapseStore,
    repo_id: &RepoId,
    history: &GitHistory,
) -> SynapseResult<ImportReceipt> {
    let limits = store.limits().clone();
    let of_kind = |k: ObjectKind| -> Vec<GitOid> {
        history
            .objects
            .iter()
            .filter(|(_, o)| o.kind == k)
            .map(|(oid, _)| *oid)
            .collect()
    };
    let object = |oid: GitOid| -> SynapseResult<&GitObject> {
        history
            .objects
            .get(&oid)
            .ok_or_else(|| corrupt(format!("object {oid} is not in the history")))
    };

    // Blobs.
    let mut blobs: HashMap<GitOid, (BlobDigest, u64)> = HashMap::new();
    let mut blob_oids: HashMap<BlobDigest, GitOid> = HashMap::new();
    let blob_list = of_kind(ObjectKind::Blob);
    for &oid in &blob_list {
        let payload = &object(oid)?.payload;
        let size = payload.len() as u64;
        if size > limits.max_blob_bytes {
            return Err(SynapseError::new(
                RefusalCode::QuotaPayloadTooLarge,
                format!(
                    "Git blob {oid} holds {size} bytes, over the store's max_blob_bytes {}",
                    limits.max_blob_bytes
                ),
            ));
        }
        let digest = BlobDigest::compute(payload);
        blobs.insert(oid, (digest, size));
        blob_oids.insert(digest, oid);
    }

    // Trees, children first.
    let tree_list = of_kind(ObjectKind::Tree);
    let tree_order = links_first(&tree_list, &|oid| {
        Ok(parse_tree(&object(oid)?.payload)?
            .into_iter()
            .filter(|e| e.mode == b"40000" || e.mode == b"040000")
            .map(|e| e.oid)
            .collect())
    })?;
    let mut trees: HashMap<GitOid, (TreeDigest, Vec<u8>)> = HashMap::new();
    let mut tree_oids: HashMap<TreeDigest, GitOid> = HashMap::new();
    for &oid in &tree_order {
        let entries = parse_tree(&object(oid)?.payload)?;
        let count = u32::try_from(entries.len())
            .map_err(|_| not_representable(format!("tree {oid} has too many entries")))?;
        let mut enc = TreeNodeEncoder::new(count);
        for e in &entries {
            let name = std::str::from_utf8(&e.name).map_err(|_| {
                not_representable(format!("tree {oid} has an entry name that is not UTF-8"))
            })?;
            validate_tree_entry_name(name)
                .map_err(|err| not_representable(format!("tree {oid}: {}", err.message)))?;
            let pushed = match native_mode(&e.mode)? {
                Some(mode) => {
                    let (blob, size) = *blobs.get(&e.oid).ok_or_else(|| {
                        corrupt(format!("tree {oid} names {} which is not a blob", e.oid))
                    })?;
                    enc.file(name, mode, &blob, size)
                }
                None => {
                    let (child, _) = trees.get(&e.oid).ok_or_else(|| {
                        corrupt(format!("tree {oid} names {} which is not a tree", e.oid))
                    })?;
                    if *child == TreeDigest::empty() {
                        return Err(not_representable(format!(
                            "tree {oid} holds an empty subtree {name:?}"
                        )));
                    }
                    enc.dir(name, child)
                }
            };
            pushed.map_err(|err| not_representable(format!("tree {oid}: {}", err.message)))?;
        }
        let (digest, node) = enc
            .finish()
            .map_err(|err| not_representable(format!("tree {oid}: {}", err.message)))?;
        // The node must give back exactly this tree (mode spelling, order, names).
        let rebuilt = git_tree_of_node(
            &node,
            &|b| {
                blob_oids
                    .get(&b)
                    .copied()
                    .ok_or_else(|| corrupt(format!("blob {b} has no Git ID")))
            },
            &|t| {
                tree_oids
                    .get(&t)
                    .copied()
                    .ok_or_else(|| corrupt(format!("tree {t} has no Git ID")))
            },
        )?;
        if rebuilt.oid() != oid {
            return Err(not_representable(format!(
                "tree {oid} is not in Git's canonical layout (its native form rebuilds as {})",
                rebuilt.oid()
            )));
        }
        tree_oids.insert(digest, oid);
        trees.insert(oid, (digest, node));
    }

    // Commits, parents first.
    let commit_list = of_kind(ObjectKind::Commit);
    let commit_order = links_first(&commit_list, &|oid| {
        Ok(parse_commit_links(&object(oid)?.payload)?.parents)
    })?;
    let mut commits: HashMap<GitOid, ChangesetId> = HashMap::new();
    let mut commit_entries = Vec::with_capacity(commit_order.len());
    for &oid in &commit_order {
        let payload = &object(oid)?.payload;
        let links = parse_commit_links(payload)?;
        let prefix = commit_link_lines(links.tree, &links.parents);
        if !payload.starts_with(&prefix) {
            return Err(not_representable(format!(
                "commit {oid} does not start with its tree and parent lines in canonical form"
            )));
        }
        let (tree, _) = trees
            .get(&links.tree)
            .ok_or_else(|| corrupt(format!("commit {oid} names tree {} not read", links.tree)))?;
        let parents = links
            .parents
            .iter()
            .map(|p| {
                commits
                    .get(p)
                    .copied()
                    .ok_or_else(|| corrupt(format!("commit {oid} names parent {p} not read")))
            })
            .collect::<SynapseResult<Vec<_>>>()?;
        let c = GitImportedCommit {
            git_oid: oid,
            tree: *tree,
            parents,
            headers: payload[prefix.len()..].to_vec(),
        };
        commits.insert(oid, c.changeset_id());
        commit_entries.push(c);
    }

    // Annotated tags, inner tags first.
    let target_of = |oid: GitOid, tags: &HashMap<GitOid, ()>| -> SynapseResult<GitBridgeTarget> {
        let kind = object(oid)?.kind;
        let missing = || corrupt(format!("{} {oid} was not imported", kind.name()));
        Ok(match kind {
            ObjectKind::Commit => GitBridgeTarget::Commit(*commits.get(&oid).ok_or_else(missing)?),
            ObjectKind::Tree => GitBridgeTarget::Tree(trees.get(&oid).ok_or_else(missing)?.0),
            ObjectKind::Blob => GitBridgeTarget::Blob(blobs.get(&oid).ok_or_else(missing)?.0),
            ObjectKind::Tag => {
                tags.get(&oid).ok_or_else(missing)?;
                GitBridgeTarget::Tag(oid)
            }
        })
    };
    let tag_list = of_kind(ObjectKind::Tag);
    let tag_order = links_first(&tag_list, &|oid| {
        Ok(vec![parse_tag_target(&object(oid)?.payload)?.0])
    })?;
    let mut tags: HashMap<GitOid, ()> = HashMap::new();
    let mut tag_entries = Vec::with_capacity(tag_order.len());
    for &oid in &tag_order {
        let payload = &object(oid)?.payload;
        let (target, _) = parse_tag_target(payload)?;
        let prefix = format!("object {}\n", target.to_hex());
        if !payload.starts_with(prefix.as_bytes()) {
            return Err(not_representable(format!(
                "tag {oid} does not start with its object line in canonical form"
            )));
        }
        tag_entries.push(GitImportedTag {
            git_oid: oid,
            target: target_of(target, &tags)?,
            rest: payload[prefix.len()..].to_vec(),
        });
        tags.insert(oid, ());
    }

    // References (checked now, written last).
    check_git_ref_names(
        history.refs.keys().map(String::as_str),
        history.head.as_deref(),
    )?;
    let refs = GitImportedRefs {
        refs: history
            .refs
            .iter()
            .map(|(name, oid)| Ok((name.clone(), target_of(*oid, &tags)?)))
            .collect::<SynapseResult<Vec<_>>>()?,
        head: history.head.clone(),
    };

    // Write.
    let mut receipt = ImportReceipt {
        blobs: blob_list.len(),
        trees: tree_order.len(),
        commits: commit_entries.len(),
        tags: tag_entries.len(),
        refs: refs.refs.len(),
        ..ImportReceipt::default()
    };
    let mut write = |store: &mut SynapseStore,
                     entry: GitBridgeEntry,
                     bytes: &[(BlobDigest, &[u8])]|
     -> SynapseResult<()> {
        match store.record_git_import(repo_id, entry, bytes)? {
            Some(_) => receipt.records_written += 1,
            None => receipt.records_skipped += 1,
        }
        Ok(())
    };
    // Objects records: at most MAX_MAPPINGS_PER_RECORD mappings, and inline blob bytes plus
    // tree node bytes within max_total_changeset_bytes.
    let budget = limits.max_total_changeset_bytes;
    let mut batch_blobs: Vec<GitBlobMapping> = Vec::new();
    let mut batch_bytes: Vec<(BlobDigest, &[u8])> = Vec::new();
    let mut batch_trees: Vec<GitTreeMapping> = Vec::new();
    let mut used = 0u64;
    let mut flush = |store: &mut SynapseStore,
                     batch_blobs: &mut Vec<GitBlobMapping>,
                     batch_bytes: &mut Vec<(BlobDigest, &[u8])>,
                     batch_trees: &mut Vec<GitTreeMapping>,
                     used: &mut u64|
     -> SynapseResult<()> {
        if batch_blobs.is_empty() && batch_trees.is_empty() {
            return Ok(());
        }
        let entry = GitBridgeEntry::Objects {
            blobs: std::mem::take(batch_blobs),
            trees: std::mem::take(batch_trees),
        };
        write(store, entry, batch_bytes)?;
        batch_bytes.clear();
        *used = 0;
        Ok(())
    };
    for &oid in &blob_list {
        let payload = object(oid)?.payload.as_slice();
        let (digest, size) = blobs[&oid];
        if batch_blobs.len() == MAX_MAPPINGS_PER_RECORD || used + size > budget {
            flush(
                store,
                &mut batch_blobs,
                &mut batch_bytes,
                &mut batch_trees,
                &mut used,
            )?;
        }
        batch_blobs.push(GitBlobMapping {
            git_oid: oid,
            blob: digest,
            size_bytes: size,
        });
        batch_bytes.push((digest, payload));
        used += size;
    }
    for &oid in &tree_order {
        let (_, node) = &trees[&oid];
        let size = node.len() as u64;
        if batch_blobs.len() + batch_trees.len() >= MAX_MAPPINGS_PER_RECORD || used + size > budget
        {
            flush(
                store,
                &mut batch_blobs,
                &mut batch_bytes,
                &mut batch_trees,
                &mut used,
            )?;
        }
        batch_trees.push(GitTreeMapping {
            git_oid: oid,
            node: node.clone(),
        });
        used += size;
    }
    flush(
        store,
        &mut batch_blobs,
        &mut batch_bytes,
        &mut batch_trees,
        &mut used,
    )?;
    for c in commit_entries {
        write(store, GitBridgeEntry::Commit(c), &[])?;
    }
    for t in tag_entries {
        write(store, GitBridgeEntry::Tag(t), &[])?;
    }
    write(store, GitBridgeEntry::Refs(refs), &[])?;
    Ok(receipt)
}

/// Git IDs of the imported objects of one repository, by native identity.
struct ImportedIds {
    blobs: HashMap<BlobDigest, GitOid>,
    trees: HashMap<TreeDigest, GitOid>,
    commits: HashMap<ChangesetId, GitOid>,
}

impl ImportedIds {
    fn of(repo: Option<&GitBridgeRepo>) -> Self {
        let mut ids = Self {
            blobs: HashMap::new(),
            trees: HashMap::new(),
            commits: HashMap::new(),
        };
        if let Some(r) = repo {
            ids.blobs = r.blobs().iter().map(|(oid, (d, _))| (*d, *oid)).collect();
            ids.trees = r.trees().iter().map(|(oid, d)| (*d, *oid)).collect();
            ids.commits = r.commits().map(|(oid, (id, _))| (*id, *oid)).collect();
        }
        ids
    }

    fn target(&self, t: &GitBridgeTarget) -> SynapseResult<GitOid> {
        let missing = || corrupt(format!("bridge target {t:?} has no Git ID"));
        Ok(match t {
            GitBridgeTarget::Commit(id) => *self.commits.get(id).ok_or_else(missing)?,
            GitBridgeTarget::Tree(d) => *self.trees.get(d).ok_or_else(missing)?,
            GitBridgeTarget::Blob(b) => *self.blobs.get(b).ok_or_else(missing)?,
            GitBridgeTarget::Tag(oid) => *oid,
        })
    }
}

/// One file of a flattened native tree.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FlatFile {
    mode: FileMode,
    blob: BlobDigest,
    size: u64,
}

/// Export state: every object written so far, by Git ID.
struct Exporter<'a> {
    store: &'a SynapseStore,
    repo_id: &'a RepoId,
    objects: BTreeMap<GitOid, GitObject>,
    /// Git blob IDs of blobs read for native trees.
    native_blobs: HashMap<BlobDigest, GitOid>,
    /// Result trees of the native revisions exported so far (a native child names its
    /// parent's result as its `base_tree`).
    native_trees: HashMap<TreeDigest, BTreeMap<String, FlatFile>>,
    ids: ImportedIds,
}

impl Exporter<'_> {
    fn add(&mut self, object: GitObject) -> GitOid {
        let oid = object.oid();
        self.objects.entry(oid).or_insert(object);
        oid
    }

    /// Add `object`, which must hash to the Git ID it was imported under.
    fn add_checked(&mut self, object: GitObject, expected: GitOid) -> SynapseResult<()> {
        let oid = object.oid();
        if oid != expected {
            return Err(corrupt(format!(
                "stored {} rebuilds as {oid}, not its imported Git ID {expected}",
                object.kind.name()
            )));
        }
        self.objects.entry(oid).or_insert(object);
        Ok(())
    }

    fn blob_oid(&mut self, blob: BlobDigest) -> SynapseResult<GitOid> {
        if let Some(oid) = self.ids.blobs.get(&blob).or(self.native_blobs.get(&blob)) {
            return Ok(*oid);
        }
        let bytes = self.store.get_blob_visible(blob, None, None)?;
        let oid = self.add(GitObject::new(ObjectKind::Blob, bytes));
        self.native_blobs.insert(blob, oid);
        Ok(oid)
    }

    fn export_imported(&mut self, repo: &GitBridgeRepo) -> SynapseResult<()> {
        for (oid, (digest, size)) in repo.blobs() {
            let bytes = self.store.get_blob_visible(*digest, None, None)?;
            if bytes.len() as u64 != *size {
                return Err(corrupt(format!(
                    "stored blob of Git blob {oid} holds {} bytes, not {size}",
                    bytes.len()
                )));
            }
            self.add_checked(GitObject::new(ObjectKind::Blob, bytes), *oid)?;
        }
        for (oid, digest) in repo.trees() {
            let node = self.store.git_bridge_tree_node(*digest).ok_or_else(|| {
                SynapseError::new(
                    RefusalCode::TreeNodeNotFound,
                    format!("tree node {digest} of Git tree {oid} is not stored"),
                )
            })?;
            let ids = &self.ids;
            let tree = git_tree_of_node(node, &|b| ids.target(&GitBridgeTarget::Blob(b)), &|t| {
                ids.target(&GitBridgeTarget::Tree(t))
            })?;
            self.add_checked(tree, *oid)?;
        }
        for (oid, (_, c)) in repo.commits() {
            let tree = self.ids.target(&GitBridgeTarget::Tree(c.tree))?;
            let parents = c
                .parents
                .iter()
                .map(|p| self.ids.target(&GitBridgeTarget::Commit(*p)))
                .collect::<SynapseResult<Vec<_>>>()?;
            let mut payload = commit_link_lines(tree, &parents);
            payload.extend_from_slice(&c.headers);
            self.add_checked(GitObject::new(ObjectKind::Commit, payload), *oid)?;
        }
        for (oid, t) in repo.tags() {
            let target = self.ids.target(&t.target)?;
            let mut payload = format!("object {}\n", target.to_hex()).into_bytes();
            payload.extend_from_slice(&t.rest);
            self.add_checked(GitObject::new(ObjectKind::Tag, payload), *oid)?;
        }
        Ok(())
    }

    /// Flatten the tree `root` (an imported tree, a native revision's result tree exported
    /// before, or the empty tree) into path to file.
    fn flatten(&self, root: TreeDigest) -> SynapseResult<BTreeMap<String, FlatFile>> {
        if let Some(files) = self.native_trees.get(&root) {
            return Ok(files.clone());
        }
        let mut files = BTreeMap::new();
        let mut stack = vec![(String::new(), root)];
        while let Some((prefix, digest)) = stack.pop() {
            if digest == TreeDigest::empty() {
                continue;
            }
            let node = self.store.git_bridge_tree_node(digest).ok_or_else(|| {
                SynapseError::new(
                    RefusalCode::TreeNodeNotFound,
                    format!("base tree node {digest} is not stored in the bridge"),
                )
            })?;
            for e in decode_tree_node(node)? {
                let path = format!("{prefix}{}", e.name);
                match e.kind {
                    TreeNodeEntryKind::File {
                        mode,
                        blob,
                        size_bytes,
                    } => {
                        files.insert(
                            path,
                            FlatFile {
                                mode,
                                blob,
                                size: size_bytes,
                            },
                        );
                    }
                    TreeNodeEntryKind::Dir(child) => stack.push((format!("{path}/"), child)),
                }
            }
        }
        Ok(files)
    }

    /// Write the Git trees of `files` (a flat path map); returns the root tree's Git ID and
    /// its C1 `TreeDigest` (the same canonical nodes the tree store builds).
    fn write_tree(
        &mut self,
        files: &BTreeMap<String, FlatFile>,
    ) -> SynapseResult<(GitOid, TreeDigest)> {
        enum Node {
            File(FlatFile),
            Dir(BTreeMap<String, Node>),
        }
        enum Node2 {
            File(FlatFile),
            Dir(TreeDigest),
        }
        let mut root: BTreeMap<String, Node> = BTreeMap::new();
        for (path, f) in files {
            let mut dir = &mut root;
            let mut segs: Vec<&str> = path.split('/').collect();
            let name = segs.pop().unwrap_or_default();
            for s in segs {
                let slot = dir
                    .entry(s.to_string())
                    .or_insert_with(|| Node::Dir(BTreeMap::new()));
                dir = match slot {
                    Node::Dir(d) => d,
                    Node::File(_) => {
                        return Err(corrupt(format!("path {path} lies below a file")));
                    }
                };
            }
            dir.insert(name.to_string(), Node::File(*f));
        }
        fn emit(
            ex: &mut Exporter<'_>,
            dir: &BTreeMap<String, Node>,
        ) -> SynapseResult<(GitOid, TreeDigest)> {
            let mut entries: Vec<(bool, &str, GitTreeEntry, Node2)> = Vec::new();
            for (name, node) in dir {
                let (is_dir, mode, oid, native) = match node {
                    Node::File(f) => (
                        false,
                        f.mode.git_octal_str().as_bytes().to_vec(),
                        ex.blob_oid(f.blob)?,
                        Node2::File(*f),
                    ),
                    Node::Dir(d) => {
                        let (oid, digest) = emit(ex, d)?;
                        (true, b"40000".to_vec(), oid, Node2::Dir(digest))
                    }
                };
                entries.push((
                    is_dir,
                    name,
                    GitTreeEntry {
                        mode,
                        name: name.as_bytes().to_vec(),
                        oid,
                    },
                    native,
                ));
            }
            entries.sort_by(|a, b| tree_entry_order(a.1, a.0, b.1, b.0));
            let count = u32::try_from(entries.len())
                .map_err(|_| not_representable("a native tree has too many entries"))?;
            let mut enc = TreeNodeEncoder::new(count);
            for (_, name, _, native) in &entries {
                match native {
                    Node2::File(f) => enc.file(name, f.mode, &f.blob, f.size)?,
                    Node2::Dir(d) => enc.dir(name, d)?,
                }
            }
            let (digest, _) = enc.finish()?;
            let list: Vec<GitTreeEntry> = entries.into_iter().map(|e| e.2).collect();
            let oid = ex.add(GitObject::new(
                ObjectKind::Tree,
                crate::object::encode_tree(&list),
            ));
            Ok((oid, digest))
        }
        emit(self, &root)
    }

    /// The Git commit of native revision `id` (and of its native ancestors), deterministic:
    /// tree = `base_tree` (the empty tree, an imported tree, or the result tree of a native
    /// revision exported before it) with the revision's mutations applied (an upsert replaces a file at
    /// an ancestor path and everything below its own path; a delete removes only a file);
    /// parents in the revision's order (imported commits by their Git ID); author the first
    /// attestation's DID with `NATIVE_AUTHOR_EMAIL`, committer `NATIVE_COMMITTER`, both at
    /// time 0 +0000; message the intent summary, a blank line, and `Synapse-Changeset-Id` and
    /// `Synapse-Change-Id` trailers.
    fn native_commit(
        &mut self,
        id: ChangesetId,
        done: &mut HashMap<ChangesetId, GitOid>,
    ) -> SynapseResult<GitOid> {
        let mut stack = vec![(id, false)];
        while let Some((cs, expanded)) = stack.pop() {
            if done.contains_key(&cs) || self.ids.commits.contains_key(&cs) {
                continue;
            }
            let rev = self.store.get_revision(self.repo_id, cs)?;
            if !expanded {
                stack.push((cs, true));
                for p in &rev.content.parents {
                    if !done.contains_key(p) && !self.ids.commits.contains_key(p) {
                        stack.push((*p, false));
                    }
                }
                continue;
            }
            let mut files = self.flatten(rev.content.base_tree)?;
            for m in &rev.content.mutations {
                match &m.op {
                    MutationOp::Upsert {
                        mode,
                        blob_digest,
                        size_bytes,
                    } => {
                        for (i, _) in m.path.match_indices('/') {
                            files.remove(&m.path[..i]);
                        }
                        let below = format!("{}/", m.path);
                        let doomed: Vec<String> = files
                            .range(below.clone()..)
                            .take_while(|(p, _)| p.starts_with(&below))
                            .map(|(p, _)| p.clone())
                            .collect();
                        for p in doomed {
                            files.remove(&p);
                        }
                        files.insert(
                            m.path.clone(),
                            FlatFile {
                                mode: *mode,
                                blob: *blob_digest,
                                size: *size_bytes,
                            },
                        );
                    }
                    MutationOp::Delete => {
                        files.remove(&m.path);
                    }
                }
            }
            let (tree, digest) = self.write_tree(&files)?;
            self.native_trees.insert(digest, files);
            let parents = rev
                .content
                .parents
                .iter()
                .map(|p| {
                    done.get(p)
                        .or(self.ids.commits.get(p))
                        .copied()
                        .ok_or_else(|| corrupt(format!("parent {p} has no Git commit")))
                })
                .collect::<SynapseResult<Vec<_>>>()?;
            let author = rev
                .attestations
                .first()
                .map(|a| a.author_did())
                .ok_or_else(|| corrupt(format!("revision {cs} has no attestation")))?;
            let mut payload = commit_link_lines(tree, &parents);
            payload.extend_from_slice(
                format!(
                    "author {author} <{NATIVE_AUTHOR_EMAIL}> 0 +0000\ncommitter {NATIVE_COMMITTER} 0 +0000\n\n{}\n\nSynapse-Changeset-Id: {}\nSynapse-Change-Id: {}\n",
                    rev.content.intent_summary,
                    cs.to_hex(),
                    rev.content.change_id.to_hex()
                )
                .as_bytes(),
            );
            let oid = self.add(GitObject::new(ObjectKind::Commit, payload));
            done.insert(cs, oid);
        }
        done.get(&id)
            .or(self.ids.commits.get(&id))
            .copied()
            .ok_or_else(|| corrupt(format!("revision {id} was not exported")))
    }
}

/// Export `repo_id` from `store` alone as the new bare repository `dest` (one pack). Imported
/// objects and references are rebuilt from the bridge records and stored blobs; each object
/// must hash to its imported Git ID (`GitObjectCorrupt` otherwise). `native_refs` adds a
/// reference for each native revision named (written with its native ancestors, see the
/// native commit rule in `docs/H1_GIT_BRIDGE.md`); a name already imported is `PathInvalid`.
/// `HEAD` is the imported `HEAD` (default `refs/heads/main`). The same store state always gives
/// the same pack bytes.
pub fn export_store(
    store: &SynapseStore,
    repo_id: &RepoId,
    native_refs: &BTreeMap<String, ChangesetId>,
    dest: &Path,
) -> SynapseResult<ExportReceipt> {
    let repo = store.git_bridge_repo(repo_id);
    let mut ex = Exporter {
        store,
        repo_id,
        objects: BTreeMap::new(),
        native_blobs: HashMap::new(),
        native_trees: HashMap::new(),
        ids: ImportedIds::of(repo),
    };
    let mut refs: BTreeMap<String, GitOid> = BTreeMap::new();
    let mut head = None;
    if let Some(r) = repo {
        ex.export_imported(r)?;
        if let Some(imported) = r.refs() {
            for (name, target) in &imported.refs {
                refs.insert(name.clone(), ex.ids.target(target)?);
            }
            head = imported.head.clone();
        }
    }
    let mut done = HashMap::new();
    for (name, id) in native_refs {
        if refs.contains_key(name) {
            return Err(SynapseError::new(
                RefusalCode::PathInvalid,
                format!("native reference {name} is already an imported reference"),
            ));
        }
        let oid = ex.native_commit(*id, &mut done)?;
        refs.insert(name.clone(), oid);
    }
    check_git_ref_names(refs.keys().map(String::as_str), head.as_deref())?;
    let objects: Vec<GitObject> = ex.objects.into_values().collect();
    export_repository(dest, &objects, &refs, head.as_deref())
}
