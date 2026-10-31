//! ADR 0003 step H1 (issue #48), cut 2: the persistent `GitOid` map, native import into the
//! store (WAL kind 10), export from the stored state with identical Git object IDs, and
//! deterministic export of native revisions. The system `git` builds fixture history and
//! checks the exported repositories (`cat-file`, `for-each-ref`, `fsck --full --strict`); it is
//! never used by the bridge itself.

mod common;

use common::*;
use ed25519_dalek::SigningKey;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use synapse_core::{
    BlobDigest, ChainPath, ChangeId, ChangesetEnvelopeV2, ChangesetId, FileMode, GitOid,
    IdempotencyKey, MutationOp, PathMutation, RefusalCode, RepoId, RevisionContent, SynapseResult,
    TreeDigest, WalSeq,
};
use synapse_git::{export_store, import_repository, ImportReceipt, ReadLimits};
use synapse_store::git_bridge::{
    GitBlobMapping, GitBridgeEntry, GitBridgeTarget, GitImportedCommit, GitImportedRefs,
    GitTreeMapping,
};
use synapse_store::{
    AdmissionAuthority, FsyncPolicy, RecoveryPolicy, RevisionOutcome, StoreLimits, SynapseStore,
};

fn limits() -> StoreLimits {
    StoreLimits {
        wal_prealloc_bytes: 64 * 1024,
        ..Default::default()
    }
}

fn open_store(dir: &Path, limits: StoreLimits) -> SynapseStore {
    SynapseStore::open(
        dir,
        FsyncPolicy::EveryCommit,
        RecoveryPolicy::StrictFailClosed,
        limits,
    )
    .unwrap()
}

fn repo_id() -> RepoId {
    RepoId::new("aien-dev/h1-fixture").unwrap()
}

/// A 32-byte value derived from a label (keys and idempotency keys in these tests are never
/// literal constants).
fn derived(label: &str) -> [u8; 32] {
    Sha256::digest(label.as_bytes()).into()
}

fn import(store: &mut SynapseStore, git_dir: &Path) -> SynapseResult<ImportReceipt> {
    import_repository(store, &repo_id(), git_dir, ReadLimits::default())
}

fn export(store: &SynapseStore, native: &BTreeMap<String, ChangesetId>, dest: &Path) -> GitOid {
    export_store(store, &repo_id(), native, dest)
        .unwrap_or_else(|e| panic!("export refused: {e}"))
        .pack_checksum
}

fn object_ids(dir: &Path) -> BTreeSet<GitOid> {
    git_all_objects(dir).keys().copied().collect()
}

/// The fixture repository with every object in one pack (as a clone would hold it).
fn fixture(label: &str) -> PathBuf {
    let dir = temp_dir(label);
    build_fixture(&dir);
    git(&dir, &["repack", "-a", "-d", "-q"]);
    dir
}

#[test]
fn h1_import_then_export_from_the_store_gives_identical_ids_refs_and_fsck_strict_clean() {
    let src = fixture("c2-round");
    let root = temp_dir("c2-round-out");
    let mut store = open_store(&root.join("store"), limits());
    let receipt = import(&mut store, &src.join(".git")).expect("import");
    assert!(receipt.commits >= 20 && receipt.tags >= 6, "{receipt:?}");
    assert_eq!(receipt.records_skipped, 0);
    let dest = root.join("export.git");
    export(&store, &BTreeMap::new(), &dest);
    assert_fsck_strict_clean(&dest);
    let source_ids = object_ids(&src);
    assert_eq!(
        object_ids(&dest),
        source_ids,
        "every object, identical Git IDs"
    );
    for (oid, (kind, payload)) in git_all_objects(&dest) {
        let (k, p) = &git_all_objects(&src)[&oid];
        assert_eq!((&kind, &payload), (k, p), "object {oid}");
    }
    assert_eq!(git_refs(&dest), git_refs(&src), "references");
    assert_eq!(
        git_text(&dest, &["symbolic-ref", "HEAD"]),
        git_text(&src, &["symbolic-ref", "HEAD"])
    );
    // The persistent map: every commit to (ChangesetId, TreeDigest), the tree digest being
    // the one its Git tree maps to, and every parent an imported revision.
    let bridge = store.git_bridge_repo(&repo_id()).expect("bridge map");
    let mut commits = 0;
    for (oid, (kind, payload)) in git_all_objects(&src) {
        if kind != "commit" {
            continue;
        }
        commits += 1;
        let (id, tree) = bridge.commit(oid).expect("commit mapped");
        let text = String::from_utf8_lossy(&payload).to_string();
        let tree_oid = GitOid::from_hex(&text[5..45]).unwrap();
        assert_eq!(bridge.tree(tree_oid), Some(tree), "tree of {oid}");
        let c = bridge.commit_by_changeset(id).expect("reverse map");
        assert_eq!(c.git_oid, oid);
    }
    assert_eq!(commits, receipt.commits);
    // The same history imported again writes nothing.
    let again = import(&mut store, &src.join(".git")).expect("re-import");
    assert_eq!(again.records_written, 0, "{again:?}");
    fs::remove_dir_all(&root).unwrap();
    fs::remove_dir_all(&src).unwrap();
}

#[test]
fn h1_bridge_map_survives_reopen_and_checkpoint_with_the_same_export() {
    let src = fixture("c2-reopen");
    let root = temp_dir("c2-reopen-out");
    let store_dir = root.join("store");
    let mut store = open_store(&store_dir, limits());
    import(&mut store, &src.join(".git")).expect("import");
    let first = export(&store, &BTreeMap::new(), &root.join("a.git"));
    let state_root = store.state_root_digest(None).unwrap();
    drop(store);
    let mut store = open_store(&store_dir, limits());
    assert_eq!(store.state_root_digest(None).unwrap(), state_root);
    assert_eq!(
        export(&store, &BTreeMap::new(), &root.join("b.git")),
        first,
        "replay rebuilds the same map"
    );
    store.checkpoint_and_compact(10_000).expect("checkpoint");
    assert_eq!(
        export(&store, &BTreeMap::new(), &root.join("c.git")),
        first,
        "compaction keeps the bridge blobs and records"
    );
    drop(store);
    let store = open_store(&store_dir, limits());
    assert_eq!(store.state_root_digest(None).unwrap(), state_root);
    assert_eq!(
        export(&store, &BTreeMap::new(), &root.join("d.git")),
        first,
        "a checkpoint load rebuilds the same map"
    );
    assert_fsck_strict_clean(&root.join("d.git"));
    fs::remove_dir_all(&root).unwrap();
    fs::remove_dir_all(&src).unwrap();
}

/// Admit one native revision on top of the imported `main` tip: it edits a file, deletes a
/// file, and turns `README.md` into a directory.
fn upsert(path: &str, body: &[u8]) -> PathMutation {
    PathMutation {
        path: path.into(),
        op: MutationOp::Upsert {
            mode: FileMode::Regular644,
            blob_digest: BlobDigest::compute(body),
            size_bytes: body.len() as u64,
        },
    }
}

/// Admit one native revision (keys, change and idempotency key derived from `label`).
fn admit(
    store: &mut SynapseStore,
    parent: ChangesetId,
    base_tree: TreeDigest,
    mutations: Vec<PathMutation>,
    bodies: &[&[u8]],
    label: &str,
) -> ChangesetId {
    let content = RevisionContent {
        change_id: ChangeId(
            derived(&format!("{label} change"))[..16]
                .try_into()
                .unwrap(),
        ),
        base_tree,
        parents: vec![parent],
        mutations,
        intent_summary: format!("{label} on imported history"),
    };
    let author = SigningKey::from_bytes(&derived(&format!("{label} author")));
    let env = ChangesetEnvelopeV2::sign_new(
        &author,
        repo_id(),
        content,
        IdempotencyKey(derived(&format!("{label} idempotency"))),
        1_000,
    );
    let blobs: Vec<(BlobDigest, Vec<u8>)> = bodies
        .iter()
        .map(|b| (BlobDigest::compute(b), b.to_vec()))
        .collect();
    let chain = ChainPath::new(vec![derived("h1 chain root"), derived("h1 chain agent")]).unwrap();
    let authority = AdmissionAuthority {
        chain,
        change_scope: Vec::new(),
    };
    match store.admit_revision(env, &blobs, authority, 5_000).unwrap() {
        RevisionOutcome::Admitted { changeset_id, .. } => changeset_id,
        other => panic!("expected an admission, got {other:?}"),
    }
}

/// Admit one native revision on top of the imported `main` tip: it edits a file, deletes a
/// file, and turns `README.md` into a directory.
fn admit_native(store: &mut SynapseStore, src: &Path) -> ChangesetId {
    let tip = GitOid::from_hex(&git_text(src, &["rev-parse", "refs/heads/main"])).unwrap();
    let (parent, base_tree) = store
        .git_bridge_repo(&repo_id())
        .unwrap()
        .commit(tip)
        .unwrap();
    let lib: &[u8] = b"pub fn one() -> u32 { 42 }\n";
    let inner: &[u8] = b"now a directory\n";
    let mutations = vec![
        upsert("README.md/inner.txt", inner),
        PathMutation {
            path: "data/empty.txt".into(),
            op: MutationOp::Delete,
        },
        upsert("src/lib.rs", lib),
    ];
    admit(
        store,
        parent,
        base_tree,
        mutations,
        &[inner, lib],
        "h1 native",
    )
}

#[test]
fn h1_a_native_child_of_a_native_revision_exports_on_its_parents_result_tree() {
    let src = fixture("c2-chain");
    let root = temp_dir("c2-chain-out");
    let mut store = open_store(&root.join("store"), limits());
    import(&mut store, &src.join(".git")).expect("import");
    let first = admit_native(&mut store, &src);
    let one = BTreeMap::from([("refs/heads/agent".to_string(), first)]);
    let a = root.join("a.git");
    export(&store, &one, &a);
    // The first revision's result tree, as an independent path computes it: the import of
    // the exported repository converts its Git tree to a TreeDigest.
    let mut other = open_store(&root.join("other"), limits());
    import(&mut other, &a).expect("re-import of the export");
    let tip = GitOid::from_hex(&git_text(&a, &["rev-parse", "refs/heads/agent"])).unwrap();
    let (_, result) = other
        .git_bridge_repo(&repo_id())
        .unwrap()
        .commit(tip)
        .unwrap();
    drop(other);
    let body: &[u8] = b"second\n";
    let second = admit(
        &mut store,
        first,
        result,
        vec![upsert("docs/second.md", body)],
        &[body],
        "h1 native child",
    );
    let both = BTreeMap::from([
        ("refs/heads/agent".to_string(), first),
        ("refs/heads/agent2".to_string(), second),
    ]);
    let b = root.join("b.git");
    export(&store, &both, &b);
    assert_fsck_strict_clean(&b);
    assert_eq!(
        git_text(&b, &["rev-parse", "refs/heads/agent2^"]),
        tip.to_hex(),
        "the child's parent is the first native commit, unchanged"
    );
    let diff = git_text(
        &b,
        &[
            "diff-tree",
            "-r",
            "--name-status",
            "refs/heads/agent",
            "refs/heads/agent2",
        ],
    );
    assert_eq!(
        diff, "A\tdocs/second.md",
        "the child adds exactly its one file"
    );
    fs::remove_dir_all(&root).unwrap();
    fs::remove_dir_all(&src).unwrap();
}

#[test]
fn h1_native_revisions_export_deterministically_on_imported_history() {
    let src = fixture("c2-native");
    let root = temp_dir("c2-native-out");
    let store_dir = root.join("store");
    let mut store = open_store(&store_dir, limits());
    import(&mut store, &src.join(".git")).expect("import");
    let id = admit_native(&mut store, &src);
    let native = BTreeMap::from([("refs/heads/agent".to_string(), id)]);
    let a = export(&store, &native, &root.join("a.git"));
    let b = export(&store, &native, &root.join("b.git"));
    assert_eq!(a, b, "two exports give the same pack");
    drop(store);
    let store = open_store(&store_dir, limits());
    assert_eq!(
        export(&store, &native, &root.join("c.git")),
        a,
        "the same pack after a reopen"
    );
    let dest = root.join("a.git");
    assert_fsck_strict_clean(&dest);
    let main = git_text(&src, &["rev-parse", "refs/heads/main"]);
    let commit = git_text(&dest, &["cat-file", "-p", "refs/heads/agent"]);
    assert!(commit.contains(&format!("\nparent {main}\n")), "{commit}");
    assert!(
        commit.contains(" <agent@synapse.aienos.local> 0 +0000\n"),
        "{commit}"
    );
    assert!(
        commit.contains("committer Synapse Engine <synapse@aienos.local> 0 +0000\n"),
        "{commit}"
    );
    assert!(
        commit.contains(&format!("Synapse-Changeset-Id: {}", id.to_hex())),
        "{commit}"
    );
    let files = git_text(&dest, &["ls-tree", "-r", "--name-only", "refs/heads/agent"]);
    let files: BTreeSet<&str> = files.lines().collect();
    assert!(files.contains("README.md/inner.txt"));
    assert!(!files.contains("README.md") && !files.contains("data/empty.txt"));
    assert_eq!(
        git_text(&dest, &["show", "refs/heads/agent:src/lib.rs"]),
        "pub fn one() -> u32 { 42 }"
    );
    // Everything else is the parent's tree, unchanged.
    let parent_files = git_text(&src, &["ls-tree", "-r", "--name-only", "refs/heads/main"]);
    for f in parent_files.lines() {
        if f != "README.md" && f != "data/empty.txt" {
            assert!(files.contains(f), "{f} kept");
        }
    }
    // Imported references are unchanged beside the native one.
    let mut expected = git_refs(&src);
    expected.insert(
        "refs/heads/agent".into(),
        GitOid::from_hex(&git_text(&dest, &["rev-parse", "refs/heads/agent"])).unwrap(),
    );
    assert_eq!(git_refs(&dest), expected);
    fs::remove_dir_all(&root).unwrap();
    fs::remove_dir_all(&src).unwrap();
}

// ---------------------------------------------------------------------------------------
// Hostile input at the import boundary: refused typed, before anything is written.
// ---------------------------------------------------------------------------------------

/// A small repository whose `main` holds one commit of `tree` (raw tree bytes written with
/// `hash-object --literally`, which accepts what Git itself would never write).
fn repo_with_raw_tree(label: &str, raw_tree: &[u8]) -> PathBuf {
    let dir = temp_dir(label);
    git(&dir, &["init", "-q", "-b", "main"]);
    let out = git_raw(
        &dir,
        &["hash-object", "-t", "tree", "--literally", "-w", "--stdin"],
        Some(raw_tree),
    );
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let tree = String::from_utf8(out.stdout).unwrap().trim().to_string();
    let commit = git_text(&dir, &["commit-tree", &tree, "-m", "crafted"]);
    git(&dir, &["update-ref", "refs/heads/main", &commit]);
    dir
}

fn blob(dir: &Path, body: &[u8]) -> [u8; 20] {
    let out = git_raw(dir, &["hash-object", "-w", "--stdin"], Some(body));
    GitOid::from_hex(String::from_utf8(out.stdout).unwrap().trim())
        .unwrap()
        .0
}

fn tree_entry(mode: &str, name: &[u8], oid: [u8; 20]) -> Vec<u8> {
    let mut e = format!("{mode} ").into_bytes();
    e.extend_from_slice(name);
    e.push(0);
    e.extend_from_slice(&oid);
    e
}

/// Import `git_dir` into a fresh store and require refusal with `code` and an untouched store.
fn assert_import_refused(git_dir: &Path, limits: StoreLimits, code: RefusalCode, case: &str) {
    let root = temp_dir("c2-refused-store");
    let mut store = open_store(&root, limits);
    let before = store.committed_seq();
    match import(&mut store, git_dir) {
        Err(e) => assert_eq!(e.code, code, "{case}: wrong refusal: {e}"),
        Ok(r) => panic!("{case}: imported instead of refusing: {r:?}"),
    }
    assert_eq!(store.committed_seq(), before, "{case}: nothing written");
    assert!(store.git_bridge_repo(&repo_id()).is_none(), "{case}");
    drop(store);
    fs::remove_dir_all(&root).unwrap();
}

#[test]
fn h1_import_refuses_trees_with_no_native_form_before_writing() {
    let scratch = temp_dir("c2-blobs");
    git(&scratch, &["init", "-q"]);
    let a = blob(&scratch, b"a\n");
    let cases: Vec<(&str, Vec<u8>)> = vec![
        ("legacy mode 100664", tree_entry("100664", b"a.txt", a)),
        ("gitlink 160000", tree_entry("160000", b"sub", a)),
        ("name .git", tree_entry("100644", b".git", a)),
        ("name not UTF-8", tree_entry("100644", b"caf\xe9", a)),
        (
            "entries out of order",
            [tree_entry("100644", b"b", a), tree_entry("100644", b"a", a)].concat(),
        ),
        (
            "duplicate names",
            [tree_entry("100644", b"a", a), tree_entry("100644", b"a", a)].concat(),
        ),
    ];
    for (case, raw) in cases {
        let dir = repo_with_raw_tree("c2-raw-tree", &raw);
        // The gitlink names no object in this repository (the reader skips gitlinks); every
        // other entry names the blob, written into this repository too.
        blob(&dir, b"a\n");
        assert_import_refused(
            &dir.join(".git"),
            limits(),
            RefusalCode::GitObjectNotRepresentable,
            case,
        );
        fs::remove_dir_all(&dir).unwrap();
    }
    // A zero-padded directory mode (`040000`) is a subtree Git would write as `40000`.
    let dir = temp_dir("c2-mode-040000");
    git(&dir, &["init", "-q", "-b", "main"]);
    let inner = repo_raw_tree_object(&dir, &tree_entry("100644", b"a", blob(&dir, b"a\n")));
    let outer = repo_raw_tree_object(&dir, &tree_entry("040000", b"d", inner));
    let commit = git_text(&dir, &["commit-tree", &GitOid(outer).to_hex(), "-m", "x"]);
    git(&dir, &["update-ref", "refs/heads/main", &commit]);
    assert_import_refused(
        &dir.join(".git"),
        limits(),
        RefusalCode::GitObjectNotRepresentable,
        "directory mode 040000",
    );
    fs::remove_dir_all(&dir).unwrap();
    fs::remove_dir_all(&scratch).unwrap();
}

fn repo_raw_tree_object(dir: &Path, raw: &[u8]) -> [u8; 20] {
    let out = git_raw(
        dir,
        &["hash-object", "-t", "tree", "--literally", "-w", "--stdin"],
        Some(raw),
    );
    assert!(out.status.success());
    GitOid::from_hex(String::from_utf8(out.stdout).unwrap().trim())
        .unwrap()
        .0
}

#[test]
fn h1_import_refuses_reference_names_that_would_write_outside_before_writing() {
    let src = temp_dir("c2-ref-escape");
    git(&src, &["init", "-q", "-b", "main"]);
    write(&src, "a.txt", b"a\n");
    commit_all(&src, "one");
    let tip = git_text(&src, &["rev-parse", "HEAD"]);
    // The repository reader refuses a malformed reference name (`GitObjectCorrupt`, cut 1);
    // the bridge refuses names that are valid alone but collide on disk (`PathInvalid`).
    let corrupt = RefusalCode::GitObjectCorrupt;
    for (case, lines, code) in [
        (
            "dot-dot path",
            format!("{tip} refs/heads/../../../escape\n"),
            corrupt,
        ),
        (
            "absolute-looking",
            format!("{tip} refs//heads/x\n"),
            corrupt,
        ),
        (
            "file and directory",
            format!("{tip} refs/heads/a\n{tip} refs/heads/a/b\n"),
            RefusalCode::PathInvalid,
        ),
        ("outside refs/", format!("{tip} HEAD2\n"), corrupt),
    ] {
        fs::write(src.join(".git/packed-refs"), lines).unwrap();
        assert_import_refused(&src.join(".git"), limits(), code, case);
    }
    assert!(!src.join("escape").exists() && !src.parent().unwrap().join("escape").exists());
    fs::remove_dir_all(&src).unwrap();
}

#[test]
fn h1_import_refuses_a_blob_over_the_store_cap_before_writing() {
    let src = temp_dir("c2-big-blob");
    git(&src, &["init", "-q", "-b", "main"]);
    write(&src, "small.txt", b"small\n");
    write(&src, "big.bin", &noise(4096, 3));
    commit_all(&src, "one");
    let small = StoreLimits {
        max_blob_bytes: 4095,
        ..limits()
    };
    assert_import_refused(
        &src.join(".git"),
        small,
        RefusalCode::QuotaPayloadTooLarge,
        "blob over max_blob_bytes",
    );
    fs::remove_dir_all(&src).unwrap();
}

/// Crafted kind 10 entries handed straight to the store (as a replica or a buggy importer
/// could): each is refused typed and nothing is written.
#[test]
fn h1_store_refuses_crafted_bridge_entries() {
    let root = temp_dir("c2-crafted");
    let mut store = open_store(&root, limits());
    let repo = repo_id();
    let body = b"hello\n".as_slice();
    let digest = BlobDigest::compute(body);
    let oid = GitOid::compute_blob(body);
    let mapping = GitBlobMapping {
        git_oid: oid,
        blob: digest,
        size_bytes: body.len() as u64,
    };
    let objects = |blobs: Vec<GitBlobMapping>, trees: Vec<GitTreeMapping>| {
        GitBridgeEntry::Objects { blobs, trees }
    };
    let seq: WalSeq = store
        .record_git_import(
            &repo,
            objects(vec![mapping.clone()], vec![]),
            &[(digest, body)],
        )
        .unwrap()
        .expect("written");
    let refused = |store: &mut SynapseStore,
                   entry: GitBridgeEntry,
                   blobs: &[(BlobDigest, &[u8])],
                   code: RefusalCode,
                   case: &str| {
        match store.record_git_import(&repo, entry, blobs) {
            Err(e) => assert_eq!(e.code, code, "{case}: {e}"),
            Ok(s) => panic!("{case}: accepted ({s:?})"),
        }
        assert_eq!(store.committed_seq(), seq, "{case}: nothing written");
    };
    // The same Git blob remapped to other bytes.
    let other = b"other\n".as_slice();
    let remap = GitBlobMapping {
        blob: BlobDigest::compute(other),
        size_bytes: other.len() as u64,
        ..mapping.clone()
    };
    refused(
        &mut store,
        objects(vec![remap], vec![]),
        &[(BlobDigest::compute(other), other)],
        RefusalCode::GitObjectCorrupt,
        "Git ID remapped",
    );
    // A size that is not the blob's.
    let wrong_size = GitBlobMapping {
        git_oid: GitOid::compute_blob(other),
        blob: BlobDigest::compute(other),
        size_bytes: 99,
    };
    refused(
        &mut store,
        objects(vec![wrong_size], vec![]),
        &[(BlobDigest::compute(other), other)],
        RefusalCode::BlobDigestMismatch,
        "declared size",
    );
    // A blob neither provided nor stored.
    let missing = GitBlobMapping {
        git_oid: GitOid::compute_blob(other),
        blob: BlobDigest::compute(other),
        size_bytes: other.len() as u64,
    };
    refused(
        &mut store,
        objects(vec![missing], vec![]),
        &[],
        RefusalCode::BlobNotFound,
        "missing blob",
    );
    // Bytes that do not hash to their declared digest.
    refused(
        &mut store,
        objects(vec![mapping.clone()], vec![]),
        &[(digest, other)],
        RefusalCode::BlobDigestMismatch,
        "blob bytes",
    );
    // A tree node that is not canonical (one declared entry, none present).
    let bad_node = GitTreeMapping {
        git_oid: GitOid::compute_git_object("tree", b"x"),
        node: 1u32.to_le_bytes().to_vec(),
    };
    refused(
        &mut store,
        objects(vec![], vec![bad_node]),
        &[],
        RefusalCode::TreeNodeMalformed,
        "malformed node",
    );
    // A commit on a tree or parent that was never imported.
    let commit = |tree: TreeDigest, parents: Vec<ChangesetId>| {
        GitBridgeEntry::Commit(GitImportedCommit {
            git_oid: GitOid::compute_git_object("commit", b"crafted"),
            tree,
            parents,
            headers: b"author a <a@b> 0 +0000\ncommitter a <a@b> 0 +0000\n\nm\n".to_vec(),
        })
    };
    refused(
        &mut store,
        commit(TreeDigest(derived("unknown tree")), vec![]),
        &[],
        RefusalCode::TreeNodeNotFound,
        "unknown tree",
    );
    refused(
        &mut store,
        commit(
            TreeDigest::empty(),
            vec![ChangesetId(derived("unknown parent"))],
        ),
        &[],
        RefusalCode::ParentChangesetNotFound,
        "unknown parent",
    );
    // References: a name that escapes, and a target never imported.
    let refs = |name: &str, target: GitBridgeTarget| {
        GitBridgeEntry::Refs(GitImportedRefs {
            refs: vec![(name.to_string(), target)],
            head: None,
        })
    };
    refused(
        &mut store,
        refs("refs/heads/../../x", GitBridgeTarget::Blob(digest)),
        &[],
        RefusalCode::PathInvalid,
        "ref name",
    );
    refused(
        &mut store,
        refs(
            "refs/heads/x",
            GitBridgeTarget::Commit(ChangesetId(derived("never imported"))),
        ),
        &[],
        RefusalCode::GitObjectCorrupt,
        "ref target",
    );
    drop(store);
    fs::remove_dir_all(&root).unwrap();
}

/// Review of #96, B1: every record is checked against the store's limits (WAL frame cap,
/// changeset bytes) before the first write, so a record the store would refuse late leaves
/// the store untouched instead of half imported.
#[test]
fn h1_import_refuses_a_record_over_the_store_limits_before_writing() {
    // One commit whose message alone is larger than the WAL frame cap.
    let src = temp_dir("c2-huge-commit");
    git(&src, &["init", "-q", "-b", "main"]);
    write(&src, "a.txt", b"a\n");
    git(&src, &["add", "-A"]);
    let tree = git_text(&src, &["write-tree"]);
    let message = "m".repeat(100 * 1024);
    let out = git_raw(
        &src,
        &["commit-tree", &tree, "-F", "-"],
        Some(message.as_bytes()),
    );
    assert!(out.status.success());
    let commit = String::from_utf8(out.stdout).unwrap().trim().to_string();
    git(&src, &["update-ref", "refs/heads/main", &commit]);
    let tight = StoreLimits {
        max_blob_bytes: 4 * 1024,
        max_total_changeset_bytes: 16 * 1024,
        max_wal_record_bytes: 64 * 1024,
        ..limits()
    };
    assert_import_refused(
        &src.join(".git"),
        tight.clone(),
        RefusalCode::QuotaPayloadTooLarge,
        "commit record over max_wal_record_bytes",
    );
    // The same store, refused once under the tight limits, then imports the repository
    // in full under the default limits and exports it with identical IDs.
    let root = temp_dir("c2-huge-commit-store");
    {
        let mut store = open_store(&root, tight);
        let refusal = import(&mut store, &src.join(".git")).expect_err("over the frame cap");
        assert_eq!(refusal.code, RefusalCode::QuotaPayloadTooLarge, "{refusal}");
        assert_eq!(store.committed_seq(), WalSeq(0));
    }
    let mut store = open_store(&root, limits());
    import(&mut store, &src.join(".git")).expect("import under the default limits");
    let dest = root.join("export.git");
    export(&store, &BTreeMap::new(), &dest);
    assert_fsck_strict_clean(&dest);
    assert_eq!(object_ids(&dest), object_ids(&src));
    drop(store);
    fs::remove_dir_all(&root).unwrap();
    fs::remove_dir_all(&src).unwrap();
    // A blob within max_blob_bytes but over max_total_changeset_bytes (a custom config).
    let src = temp_dir("c2-blob-over-changeset");
    git(&src, &["init", "-q", "-b", "main"]);
    write(&src, "small.txt", b"small\n");
    write(&src, "mid.bin", &noise(6 * 1024, 5));
    commit_all(&src, "one");
    let skewed = StoreLimits {
        max_blob_bytes: 8 * 1024,
        max_total_changeset_bytes: 4 * 1024,
        ..limits()
    };
    assert_import_refused(
        &src.join(".git"),
        skewed,
        RefusalCode::QuotaPayloadTooLarge,
        "blob over max_total_changeset_bytes",
    );
    fs::remove_dir_all(&src).unwrap();
}

/// Review of #96, B2: the store checks every Git ID it is handed against the content it
/// maps (re-hashed with the workspace SHA-1), and refuses a Git ID twice in one entry, so a
/// crafted record cannot poison the map; a correct import still works afterwards.
#[test]
fn h1_store_refuses_git_ids_that_do_not_match_their_content() {
    let root = temp_dir("c2-poison");
    let mut store = open_store(&root.join("store"), limits());
    let repo = RepoId::new("aien-dev/h1-poison").unwrap();
    let a = b"alpha\n".as_slice();
    let b = b"bravo\n".as_slice();
    let (da, db) = (BlobDigest::compute(a), BlobDigest::compute(b));
    let x = GitOid::compute_blob(a);
    let map = |oid: GitOid, blob: BlobDigest, len: usize| GitBlobMapping {
        git_oid: oid,
        blob,
        size_bytes: len as u64,
    };
    let refused = |store: &mut SynapseStore,
                   entry: GitBridgeEntry,
                   blobs: &[(BlobDigest, &[u8])],
                   case: &str| {
        match store.record_git_import(&repo, entry, blobs) {
            Err(e) => assert_eq!(e.code, RefusalCode::GitObjectCorrupt, "{case}: {e}"),
            Ok(s) => panic!("{case}: accepted ({s:?})"),
        }
        assert_eq!(store.committed_seq(), WalSeq(0), "{case}: nothing written");
        assert!(store.git_bridge_repo(&repo).is_none(), "{case}: no map");
    };
    refused(
        &mut store,
        GitBridgeEntry::Objects {
            blobs: vec![map(x, da, a.len()), map(x, db, b.len())],
            trees: vec![],
        },
        &[(da, a), (db, b)],
        "one Git ID mapped to two blobs in one entry",
    );
    refused(
        &mut store,
        GitBridgeEntry::Objects {
            blobs: vec![map(x, db, b.len())],
            trees: vec![],
        },
        &[(db, b)],
        "a blob under another blob's Git ID",
    );
    // A tree under a wrong Git ID (its node names blob `a`, mapped in the same entry).
    let mut enc = synapse_core::TreeNodeEncoder::new(1);
    enc.file("a.txt", FileMode::Regular644, &da, a.len() as u64)
        .unwrap();
    let (tree_digest, node) = enc.finish().unwrap();
    refused(
        &mut store,
        GitBridgeEntry::Objects {
            blobs: vec![map(x, da, a.len())],
            trees: vec![GitTreeMapping {
                git_oid: GitOid::compute_git_object("tree", b"not this tree"),
                node: node.clone(),
            }],
        },
        &[(da, a)],
        "a tree under a wrong Git ID",
    );
    // The correct objects are accepted after those refusals.
    let mut tree_payload = b"100644 a.txt\0".to_vec();
    tree_payload.extend_from_slice(&x.0);
    let tree_oid = GitOid::compute_git_object("tree", &tree_payload);
    let node_again = node.clone();
    store
        .record_git_import(
            &repo,
            GitBridgeEntry::Objects {
                blobs: vec![map(x, da, a.len())],
                trees: vec![GitTreeMapping {
                    git_oid: tree_oid,
                    node,
                }],
            },
            &[(da, a)],
        )
        .expect("the correct objects")
        .expect("written");
    // A tree in another repository naming that blob, which no Git blob of that repository
    // maps (export there would have no Git ID for it).
    let other = RepoId::new("aien-dev/h1-other").unwrap();
    let before = store.committed_seq();
    match store.record_git_import(
        &other,
        GitBridgeEntry::Objects {
            blobs: vec![],
            trees: vec![GitTreeMapping {
                git_oid: tree_oid,
                node: node_again,
            }],
        },
        &[],
    ) {
        Err(e) => assert_eq!(e.code, RefusalCode::BlobNotFound, "{e}"),
        Ok(s) => panic!("a tree naming a blob its repository does not map: accepted ({s:?})"),
    }
    assert_eq!(store.committed_seq(), before, "nothing written");
    let headers = b"author a <a@b> 0 +0000\ncommitter a <a@b> 0 +0000\n\nm\n".to_vec();
    let mut commit_payload = format!("tree {}\n", tree_oid.to_hex()).into_bytes();
    commit_payload.extend_from_slice(&headers);
    let commit_oid = GitOid::compute_git_object("commit", &commit_payload);
    let commit = |git_oid: GitOid| {
        GitBridgeEntry::Commit(GitImportedCommit {
            git_oid,
            tree: tree_digest,
            parents: vec![],
            headers: headers.clone(),
        })
    };
    let refused_after = |store: &mut SynapseStore, entry: GitBridgeEntry, case: &str| {
        let before = store.committed_seq();
        match store.record_git_import(&repo, entry, &[]) {
            Err(e) => assert_eq!(e.code, RefusalCode::GitObjectCorrupt, "{case}: {e}"),
            Ok(s) => panic!("{case}: accepted ({s:?})"),
        }
        assert_eq!(store.committed_seq(), before, "{case}: nothing written");
    };
    refused_after(
        &mut store,
        commit(GitOid::compute_git_object("commit", b"another commit")),
        "a commit under a wrong Git ID",
    );
    store
        .record_git_import(&repo, commit(commit_oid), &[])
        .expect("the correct commit")
        .expect("written");
    let mut same_content = commit_oid;
    same_content.0[0] ^= 1;
    refused_after(
        &mut store,
        commit(same_content),
        "a second Git ID for the same commit content",
    );
    let seq = store.committed_seq();
    let tag = |git_oid: GitOid| {
        GitBridgeEntry::Tag(synapse_store::git_bridge::GitImportedTag {
            git_oid,
            target: GitBridgeTarget::Blob(da),
            rest: b"type blob\ntag v1\ntagger a <a@b> 0 +0000\n\nt\n".to_vec(),
        })
    };
    match store.record_git_import(
        &repo,
        tag(GitOid::compute_git_object("tag", b"another tag")),
        &[],
    ) {
        Err(e) => assert_eq!(e.code, RefusalCode::GitObjectCorrupt, "{e}"),
        Ok(s) => panic!("a tag under a wrong Git ID: accepted ({s:?})"),
    }
    assert_eq!(store.committed_seq(), seq, "nothing written");
    // After every refusal a full import into the same repository still works: export gives
    // the fixture with identical IDs plus exactly the three objects mapped above.
    let src = fixture("c2-poison-src");
    import_repository(&mut store, &repo, &src.join(".git"), ReadLimits::default())
        .expect("a correct import after refusals");
    let dest = root.join("export.git");
    export_store(&store, &repo, &BTreeMap::new(), &dest).expect("export");
    assert_fsck_strict_clean(&dest);
    let mut expected = object_ids(&src);
    expected.extend([x, tree_oid, commit_oid]);
    assert_eq!(object_ids(&dest), expected);
    assert_eq!(git_refs(&dest), git_refs(&src), "references");
    drop(store);
    fs::remove_dir_all(&src).unwrap();
    fs::remove_dir_all(&root).unwrap();
}

/// Real repository round trip through the store (ignored by default: CI has no such
/// clone). `SYNAPSE_H1_REAL_REPO` names a `git clone --mirror` directory; run under
/// `/usr/bin/time -v` for peak RSS.
#[test]
#[ignore]
fn h1_real_repository_round_trips_through_the_store_with_identical_ids() {
    let Ok(src) = std::env::var("SYNAPSE_H1_REAL_REPO") else {
        panic!("set SYNAPSE_H1_REAL_REPO to a mirror clone's git directory");
    };
    let src = PathBuf::from(src);
    let root = temp_dir("c2-real");
    let big = StoreLimits {
        max_blob_bytes: 1 << 30,
        max_total_changeset_bytes: 64 << 20,
        ..limits()
    };
    let mut store = open_store(&root.join("store"), big.clone());
    let started = std::time::Instant::now();
    let receipt = import(&mut store, &src).expect("import");
    let imported = started.elapsed();
    drop(store);
    let started = std::time::Instant::now();
    let store = open_store(&root.join("store"), big);
    let reopened = started.elapsed();
    let dest = root.join("export.git");
    let started = std::time::Instant::now();
    let pack = export_store(&store, &repo_id(), &BTreeMap::new(), &dest).expect("export");
    let exported = started.elapsed();
    assert_fsck_strict_clean(&dest);
    assert_eq!(git_refs(&dest), git_refs(&src), "references");
    let reachable = |d: &Path| -> BTreeSet<String> {
        git_text(d, &["rev-list", "--objects", "--all"])
            .lines()
            .map(|l| l[..40].to_string())
            .collect()
    };
    let src_reachable = reachable(&src);
    let dst_all: BTreeSet<String> = object_ids(&dest).iter().map(|o| o.to_hex()).collect();
    assert_eq!(src_reachable, dst_all, "identical object IDs");
    println!(
        "real repository {} through the store: {receipt:?}; import {:.1} s, reopen (WAL replay) {:.1} s, export {:.1} s, pack {} bytes",
        src.display(),
        imported.as_secs_f64(),
        reopened.as_secs_f64(),
        exported.as_secs_f64(),
        pack.pack_bytes
    );
    fs::remove_dir_all(&root).unwrap();
}
