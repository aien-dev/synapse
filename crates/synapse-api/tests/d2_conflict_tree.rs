//! ADR 0003 step D2 at the tree store: conflict entries in the shared Merkle tree, their
//! refusals (whole-tree listings and Git-shaped diffs), resolution by ordinary mutations, and
//! the conflict algebra over the real store. See `docs/D2_CONFLICT_TERMS.md`.

use synapse_api::{TreeAlgebra, TreeCacheConfig, TreeEdit, TreeFile, TreeStore};
use synapse_core::{
    diff_mutations, reduce, sum_trees, BlobDigest, ConflictKind, ConflictTerm, EntryState,
    FileMode, GitOid, MutationOp, Reduced, RefusalCode, TreeDigest,
};

fn tf(content: &str, mode: FileMode) -> TreeFile {
    TreeFile {
        mode,
        blob_digest: BlobDigest::compute(content.as_bytes()),
        size_bytes: content.len() as u64,
        git_blob_oid: GitOid::compute_blob(content.as_bytes()),
    }
}

fn st(f: TreeFile) -> EntryState {
    EntryState::File {
        mode: f.mode,
        blob_digest: f.blob_digest,
        size_bytes: f.size_bytes,
    }
}

fn store() -> TreeStore {
    TreeStore::new(TreeCacheConfig::default()).unwrap()
}

fn build(s: &mut TreeStore, files: &[(&str, TreeFile)]) -> TreeDigest {
    let empty = s.insert(synapse_api::TreeNode::new(Vec::new()).unwrap());
    let mut e = TreeEdit::new(s, empty).unwrap();
    for (p, f) in files {
        e.upsert(s, p, *f).unwrap();
    }
    e.finish(s).unwrap()
}

fn term(base: EntryState, a: EntryState, b: EntryState) -> ConflictTerm {
    match reduce(vec![a, b], vec![base]).unwrap() {
        Reduced::Conflict(c) => c,
        r => panic!("not a conflict: {r:?}"),
    }
}

/// Apply path mutations the way a revision's tree is built.
fn apply(s: &mut TreeStore, base: TreeDigest, muts: &[synapse_core::PathMutation]) -> TreeDigest {
    let mut e = TreeEdit::new(s, base).unwrap();
    for m in muts {
        match &m.op {
            MutationOp::Upsert {
                mode,
                blob_digest,
                size_bytes,
            } => {
                // Contents in these tests are the decimal size, so the Git OID is recoverable.
                let f = TreeFile {
                    mode: *mode,
                    blob_digest: *blob_digest,
                    size_bytes: *size_bytes,
                    git_blob_oid: OIDS.with(|o| o.borrow()[blob_digest]),
                };
                e.upsert(s, &m.path, f).unwrap();
            }
            MutationOp::Delete => e.delete(s, &m.path).unwrap(),
            MutationOp::Conflict(t) => e.set_conflict(s, &m.path, t.clone()).unwrap(),
        }
    }
    e.finish(s).unwrap()
}

thread_local! {
    static OIDS: std::cell::RefCell<std::collections::BTreeMap<BlobDigest, GitOid>> =
        Default::default();
}

fn remember(f: TreeFile) -> TreeFile {
    OIDS.with(|o| o.borrow_mut().insert(f.blob_digest, f.git_blob_oid));
    f
}

#[test]
fn d2_tree_conflict_entries_are_counted_read_and_refused_for_materialization() {
    let mut s = store();
    let (v0, v1, v2) = (
        tf("v0\n", FileMode::Regular644),
        tf("v1\n", FileMode::Regular644),
        tf("v2\n", FileMode::Regular644),
    );
    let other = tf("other\n", FileMode::Regular644);
    let base = build(
        &mut s,
        &[("src/f", v0), ("src/g", other), ("README", other)],
    );
    let t = term(st(v0), st(v1), st(v2));

    let mut e = TreeEdit::new(&mut s, base).unwrap();
    e.set_conflict(&mut s, "src/f", t.clone()).unwrap();
    let conflicted = e.finish(&mut s).unwrap();
    assert_ne!(conflicted, base);
    assert_eq!(s.get(conflicted).unwrap().conflict_count(), 1);
    assert_eq!(s.get(conflicted).unwrap().file_count(), 2);
    // Read: the conflict is listed with its path, and a path lookup of it finds no file.
    assert_eq!(
        s.conflicts(conflicted).unwrap(),
        vec![("src/f".into(), t.clone())]
    );
    assert_eq!(s.lookup(conflicted, "src/f").unwrap(), None);
    assert_eq!(s.lookup(conflicted, "src/g").unwrap(), Some(other));
    // Materialization (whole-tree listings) and Git-shaped diffs are refused.
    let refused = |r: Result<(), synapse_core::SynapseError>| r.unwrap_err().code;
    assert_eq!(
        refused(s.files(conflicted).map(drop)),
        RefusalCode::TreeConflicted
    );
    assert_eq!(
        refused(s.page_files(conflicted, "", 0, 10).map(drop)),
        RefusalCode::TreeConflicted
    );
    assert_eq!(
        refused(s.count_files(conflicted, "src/").map(drop)),
        RefusalCode::TreeConflicted
    );
    assert_eq!(
        refused(s.diff(base, conflicted).map(drop)),
        RefusalCode::TreeConflicted
    );
    // A tree without conflicts is unaffected.
    assert_eq!(s.files(base).unwrap().len(), 3);

    // Resolution is an ordinary upsert at the path: the tree equals one built with the file.
    let mut r = TreeEdit::new(&mut s, conflicted).unwrap();
    r.upsert(&mut s, "src/f", v2).unwrap();
    let resolved = r.finish(&mut s).unwrap();
    assert_eq!(
        resolved,
        build(
            &mut s,
            &[("src/f", v2), ("src/g", other), ("README", other)]
        )
    );
    assert_eq!(s.get(resolved).unwrap().conflict_count(), 0);
    // A delete removes a conflict entry; an upsert below it replaces it with a directory.
    let mut d = TreeEdit::new(&mut s, conflicted).unwrap();
    d.delete(&mut s, "src/f").unwrap();
    let deleted = d.finish(&mut s).unwrap();
    assert_eq!(
        deleted,
        build(&mut s, &[("src/g", other), ("README", other)])
    );
    let mut b = TreeEdit::new(&mut s, conflicted).unwrap();
    b.upsert(&mut s, "src/f/inner", v1).unwrap();
    let below = b.finish(&mut s).unwrap();
    assert_eq!(s.get(below).unwrap().conflict_count(), 0);
    assert_eq!(s.lookup(below, "src/f/inner").unwrap(), Some(v1));
    // The digest covers the term and does not depend on edit order.
    let mut o = TreeEdit::new(&mut s, base).unwrap();
    o.upsert(&mut s, "README", v1).unwrap();
    o.set_conflict(&mut s, "src/f", t.clone()).unwrap();
    let one = o.finish(&mut s).unwrap();
    let mut p = TreeEdit::new(&mut s, base).unwrap();
    p.set_conflict(&mut s, "src/f", t.clone()).unwrap();
    p.upsert(&mut s, "README", v1).unwrap();
    assert_eq!(one, p.finish(&mut s).unwrap());
    let mut q = TreeEdit::new(&mut s, base).unwrap();
    q.set_conflict(&mut s, "src/f", term(st(v0), st(v1), st(other)))
        .unwrap();
    assert_ne!(q.finish(&mut s).unwrap(), conflicted);
}

#[test]
fn d2_tree_algebra_over_the_store_round_trips_through_mutations() {
    let mut s = store();
    let f = |c: &str| remember(tf(c, FileMode::Regular644));
    let (v0, c, b1, b2, keep) = (f("v0\n"), f("c\n"), f("b1\n"), f("b2\n"), f("keep\n"));
    let exe = remember(tf("v0\n", FileMode::Executable755));
    let lnk = remember(tf("v0\n", FileMode::Symlink120000));
    let base = build(
        &mut s,
        &[("src/f", v0), ("m", v0), ("gone", v0), ("keep", keep)],
    );
    let side = build(
        &mut s,
        &[
            ("src/f", c),
            ("m", exe),
            ("gone", c),
            ("x", c),
            ("keep", keep),
        ],
    );
    let on1 = build(
        &mut s,
        &[("src/f", b1), ("m", lnk), ("x/y", b1), ("keep", keep)],
    );
    let on2 = build(
        &mut s,
        &[("src/f", b2), ("m", lnk), ("x/y", b1), ("keep", keep)],
    );

    let mut alg = TreeAlgebra::new(&mut s);
    let r1 = sum_trees(&mut alg, &[on1, side], &[base]).unwrap();
    let r2 = sum_trees(&mut alg, &[on2, r1], &[on1]).unwrap();
    let direct = sum_trees(&mut alg, &[on2, side], &[base]).unwrap();
    let reverted = sum_trees(&mut alg, &[r1, base], &[side]).unwrap();
    // The derived revision's content: mutations from the new base to the result.
    let muts1 = diff_mutations(&mut alg, on1, r1).unwrap();
    drop(alg);

    // Rebasing twice equals one rebase; reverting gives the onto tree back.
    assert_eq!(r2, direct);
    assert_eq!(reverted, on1);
    // Typed terms: content (src/f), mode (m), modify/delete (gone), file/directory (x).
    let kinds: Vec<(String, ConflictKind)> = s
        .conflicts(r1)
        .unwrap()
        .into_iter()
        .map(|(p, t)| (p, t.kind()))
        .collect();
    assert_eq!(
        kinds,
        vec![
            ("gone".into(), ConflictKind::ModifyDelete),
            ("m".into(), ConflictKind::Mode),
            ("src/f".into(), ConflictKind::Content),
            ("x".into(), ConflictKind::FileDirectory),
        ]
    );
    // Applying the mutations to the new base rebuilds exactly the summed tree.
    assert_eq!(apply(&mut s, on1, &muts1), r1);
    assert_eq!(s.get(r1).unwrap().conflict_count(), 4);
    assert_eq!(s.lookup(r1, "keep").unwrap(), Some(keep));
}
