use super::*;
use crate::tree::TreeNodeEncoder;
use crate::RefusalCode;
use std::collections::{BTreeMap, HashMap};

/// Tree nodes in memory, hashed with the canonical encoder; counts node reads.
#[derive(Default)]
struct Mem {
    nodes: HashMap<TreeDigest, Vec<(String, NodeEntry)>>,
    reads: usize,
}

impl ConflictTrees for Mem {
    fn node(&mut self, tree: TreeDigest) -> SynapseResult<Vec<(String, NodeEntry)>> {
        self.reads += 1;
        Ok(self.nodes.get(&tree).expect("node held").clone())
    }

    fn put_node(&mut self, mut entries: Vec<(String, NodeEntry)>) -> SynapseResult<TreeDigest> {
        entries.sort_by(node_entry_order);
        let mut enc = TreeNodeEncoder::new(entries.len() as u32);
        for (name, e) in &entries {
            match e {
                NodeEntry::State(EntryState::File {
                    mode,
                    blob_digest,
                    size_bytes,
                }) => enc.file(name, *mode, blob_digest, *size_bytes)?,
                NodeEntry::State(EntryState::Dir(d)) => enc.dir(name, d)?,
                NodeEntry::State(EntryState::Absent) => panic!("absent entry stored"),
                NodeEntry::Conflict(c) => enc.conflict(name, c)?,
            }
        }
        let (d, _) = enc.finish()?;
        self.nodes.insert(d, entries);
        Ok(d)
    }
}

fn file(content: &str) -> EntryState {
    file_mode(content, FileMode::Regular644)
}

fn file_mode(content: &str, mode: FileMode) -> EntryState {
    EntryState::File {
        mode,
        blob_digest: BlobDigest::compute(content.as_bytes()),
        size_bytes: content.len() as u64,
    }
}

impl Mem {
    /// A tree from `(path, leaf)` pairs (files or conflict entries).
    fn tree(&mut self, leaves: &[(&str, NodeEntry)]) -> TreeDigest {
        let mut top: BTreeMap<String, Vec<(String, NodeEntry)>> = BTreeMap::new();
        let mut here = Vec::new();
        for (path, e) in leaves {
            match path.split_once('/') {
                Some((dir, rest)) => top
                    .entry(dir.to_string())
                    .or_default()
                    .push((rest.to_string(), e.clone())),
                None => here.push((path.to_string(), e.clone())),
            }
        }
        for (dir, sub) in top {
            let sub: Vec<(&str, NodeEntry)> =
                sub.iter().map(|(p, e)| (p.as_str(), e.clone())).collect();
            let d = self.tree(&sub);
            here.push((dir, NodeEntry::State(EntryState::Dir(d))));
        }
        self.put_node(here).unwrap()
    }

    fn files(&mut self, leaves: &[(&str, EntryState)]) -> TreeDigest {
        let l: Vec<(&str, NodeEntry)> = leaves
            .iter()
            .map(|(p, s)| (*p, NodeEntry::State(*s)))
            .collect();
        self.tree(&l)
    }

    /// Every leaf of `tree` with its full path.
    fn leaves(&mut self, tree: TreeDigest) -> Vec<(String, NodeEntry)> {
        let mut out = Vec::new();
        self.walk(tree, "", &mut out);
        out
    }

    fn walk(&mut self, tree: TreeDigest, prefix: &str, out: &mut Vec<(String, NodeEntry)>) {
        for (name, e) in self.nodes[&tree].clone() {
            let path = join(prefix, &name);
            match e {
                NodeEntry::State(EntryState::Dir(d)) => self.walk(d, &path, out),
                other => out.push((path, other)),
            }
        }
    }

    fn conflict_at(&mut self, tree: TreeDigest, path: &str) -> ConflictTerm {
        match self.leaves(tree).into_iter().find(|(p, _)| p == path) {
            Some((_, NodeEntry::Conflict(c))) => c,
            other => panic!("no conflict at {path}: {other:?}"),
        }
    }
}

fn three_way(base: EntryState, a: EntryState, b: EntryState) -> ConflictTerm {
    match reduce(vec![a, b], vec![base]).unwrap() {
        Reduced::Conflict(c) => c,
        r => panic!("not a conflict: {r:?}"),
    }
}

/// Deterministic generator (SplitMix64).
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }
}

#[test]
fn d2_reduction_cancels_only_identical_states_in_any_order() {
    let pool = [
        EntryState::Absent,
        file("a"),
        file("b"),
        file_mode("a", FileMode::Executable755),
        file_mode("a", FileMode::Symlink120000),
        EntryState::Dir(TreeDigest([7; 32])),
    ];
    let mut rng = Rng(0xD2);
    for _ in 0..2000 {
        let n = 1 + rng.below(4) as usize;
        let adds: Vec<EntryState> = (0..=n)
            .map(|_| pool[rng.below(pool.len() as u64) as usize])
            .collect();
        let removes: Vec<EntryState> = (0..n)
            .map(|_| pool[rng.below(pool.len() as u64) as usize])
            .collect();
        let want = reduce(adds.clone(), removes.clone()).unwrap();
        // Any order of the terms gives the same reduced form.
        let (mut a2, mut r2) = (adds.clone(), removes.clone());
        a2.reverse();
        r2.rotate_left(rng.below(n as u64) as usize);
        assert_eq!(reduce(a2, r2).unwrap(), want);
        // The reduced form is the multiset difference, by counting.
        let count = |v: &[EntryState], s: &EntryState| v.iter().filter(|x| *x == s).count() as i64;
        for s in &pool {
            let net = count(&adds, s) - count(&removes, s);
            match &want {
                Reduced::Resolved(x) => assert_eq!(net, i64::from(x == s), "{s:?}"),
                Reduced::Conflict(c) => {
                    assert_eq!(count(c.adds(), s) - count(c.removes(), s), net);
                    assert!(count(c.adds(), s) == 0 || count(c.removes(), s) == 0);
                }
            }
        }
    }
    // Unbalanced sums are refused.
    assert_eq!(
        reduce(vec![file("a")], vec![file("b")]).unwrap_err().code,
        RefusalCode::EnvelopeMalformed
    );
}

#[test]
fn d2_typed_terms_round_trip_and_malformed_terms_are_refused() {
    let base = file("v0");
    let typed = [
        (
            three_way(base, file("v1"), EntryState::Absent),
            ConflictKind::ModifyDelete,
        ),
        (
            three_way(
                EntryState::Absent,
                file("f"),
                EntryState::Dir(TreeDigest([3; 32])),
            ),
            ConflictKind::FileDirectory,
        ),
        (
            three_way(
                base,
                file_mode("v0", FileMode::Executable755),
                file_mode("v0", FileMode::Symlink120000),
            ),
            ConflictKind::Mode,
        ),
        (
            three_way(base, file("v1"), file("v2")),
            ConflictKind::Content,
        ),
    ];
    for (term, kind) in &typed {
        assert_eq!(term.kind(), *kind);
        let bytes = term.encode();
        let back = ConflictTerm::decode(&bytes).unwrap();
        assert_eq!(&back, term);
        assert_eq!(back.kind(), *kind);
    }
    let good = typed[3].0.encode();
    let refuse = |b: &[u8]| ConflictTerm::decode(b).unwrap_err().code;
    // Zero removes, more than the bound, trailing bytes, truncated, unknown state tag.
    let mut zero = good.clone();
    zero[0] = 0;
    assert_eq!(refuse(&zero), RefusalCode::EnvelopeMalformed);
    let mut many = good.clone();
    many[0] = (MAX_CONFLICT_REMOVES + 1) as u8;
    assert_eq!(refuse(&many), RefusalCode::EnvelopeMalformed);
    let mut trailing = good.clone();
    trailing.push(0);
    assert_eq!(refuse(&trailing), RefusalCode::EnvelopeMalformed);
    assert_eq!(
        refuse(&good[..good.len() - 1]),
        RefusalCode::EnvelopeMalformed
    );
    let mut tag = good.clone();
    tag[1] = 9;
    assert_eq!(refuse(&tag), RefusalCode::EnvelopeMalformed);
    // Unsorted adds, and a state both added and removed.
    let (v1, v2, v0) = (file("v1"), file("v2"), base);
    let raw = |adds: &[EntryState], removes: &[EntryState]| {
        let mut b = vec![removes.len() as u8];
        for s in adds.iter().chain(removes) {
            s.encode_into(&mut b);
        }
        b
    };
    let (lo, hi) = if v1 < v2 { (v1, v2) } else { (v2, v1) };
    assert!(ConflictTerm::decode(&raw(&[lo, hi], &[v0])).is_ok());
    assert_eq!(
        refuse(&raw(&[hi, lo], &[v0])),
        RefusalCode::EnvelopeMalformed
    );
    assert_eq!(
        refuse(&raw(&[lo, hi], &[lo])),
        RefusalCode::EnvelopeMalformed
    );
}

#[test]
fn d2_rebase_twice_cancels_to_a_plain_three_way_conflict_and_revert_is_clean() {
    let mut m = Mem::default();
    let (f0, f1, f2, f3) = (file("f0"), file("c"), file("b1"), file("b2"));
    let other = file("other");
    let b = m.files(&[("src/f", f0), ("src/g", other), ("docs/x", other)]);
    let c = m.files(&[("src/f", f1), ("src/g", other), ("docs/x", other)]);
    let b1 = m.files(&[("src/f", f2), ("src/g", other), ("docs/x", other)]);
    let b2 = m.files(&[("src/f", f3), ("src/g", other), ("docs/x", other)]);

    // Rebase c from b onto b1: a three-way conflict on src/f.
    let r1 = sum_trees(&mut m, &[b1, c], &[b]).unwrap();
    let t1 = m.conflict_at(r1, "src/f");
    assert_eq!(t1, three_way(f0, f1, f2));
    assert_eq!(t1.kind(), ConflictKind::Content);
    // Rebase again, from b1 onto b2: b1's state cancels, leaving the plain three-way
    // conflict of c against b2 over b, exactly what one rebase from b to b2 gives.
    let r2 = sum_trees(&mut m, &[b2, r1], &[b1]).unwrap();
    assert_eq!(m.conflict_at(r2, "src/f"), three_way(f0, f1, f3));
    assert_eq!(r2, sum_trees(&mut m, &[b2, c], &[b]).unwrap());
    // Reverting c on top of the conflicted r1 gives b1 back: a clean tree.
    let reverted = sum_trees(&mut m, &[r1, b], &[c]).unwrap();
    assert_eq!(reverted, b1);
    assert!(m
        .leaves(reverted)
        .iter()
        .all(|(_, e)| !matches!(e, NodeEntry::Conflict(_))));
    // Reverting the conflicted r1 itself on top of r1 gives its base b1.
    assert_eq!(sum_trees(&mut m, &[r1, b1], &[r1]).unwrap(), b1);
}

#[test]
fn d2_modify_delete_file_directory_and_mode_conflicts_are_typed_terms() {
    let mut m = Mem::default();
    let (v0, v1) = (file("v0"), file("v1"));
    let keep = file("keep");
    let b = m.files(&[("a", v0), ("m", v0), ("keep", keep)]);
    // Side A: modify a, add file x, make m executable.
    let a = m.files(&[
        ("a", v1),
        ("m", file_mode("v0", FileMode::Executable755)),
        ("x", file("x")),
        ("keep", keep),
    ]);
    // Side B: delete a, add directory x/, make m a symlink.
    let bb = m.files(&[
        ("m", file_mode("v0", FileMode::Symlink120000)),
        ("x/y", file("y")),
        ("keep", keep),
    ]);
    let r = sum_trees(&mut m, &[a, bb], &[b]).unwrap();
    assert_eq!(m.conflict_at(r, "a").kind(), ConflictKind::ModifyDelete);
    let fd = m.conflict_at(r, "x");
    assert_eq!(fd.kind(), ConflictKind::FileDirectory);
    assert!(fd.adds().iter().any(|s| matches!(s, EntryState::Dir(_))));
    assert_eq!(m.conflict_at(r, "m").kind(), ConflictKind::Mode);
    let leaves = m.leaves(r);
    assert!(leaves.contains(&("keep".into(), NodeEntry::State(keep))));
    assert_eq!(leaves.len(), 4);
}

#[test]
fn d2_directories_sum_entry_by_entry_and_equal_subtrees_are_not_read() {
    let mut m = Mem::default();
    let x = file("x");
    let mut big: Vec<(String, EntryState)> = (0..50)
        .map(|i| (format!("vendor/lib{i}"), file(&format!("{i}"))))
        .collect();
    big.push(("src/a".into(), file("a0")));
    big.push(("src/b".into(), file("b0")));
    let as_ref = |v: &[(String, EntryState)]| -> Vec<(String, EntryState)> { v.to_vec() };
    let build = |m: &mut Mem, v: &[(String, EntryState)]| {
        let l: Vec<(&str, EntryState)> = v.iter().map(|(p, s)| (p.as_str(), *s)).collect();
        m.files(&l)
    };
    let base = build(&mut m, &big);
    let mut left = as_ref(&big);
    left.iter_mut().find(|(p, _)| p == "src/a").unwrap().1 = file("a1");
    let mut right = as_ref(&big);
    right.iter_mut().find(|(p, _)| p == "src/b").unwrap().1 = file("b1");
    right.push(("src/new/n".into(), x));
    let (l, r) = (build(&mut m, &left), build(&mut m, &right));
    m.reads = 0;
    let sum = sum_trees(&mut m, &[l, r], &[base]).unwrap();
    // root, src (three versions each): vendor/ is equal everywhere and cancels unread.
    assert_eq!(m.reads, 6);
    let mut want = as_ref(&left);
    want.iter_mut().find(|(p, _)| p == "src/b").unwrap().1 = file("b1");
    want.push(("src/new/n".into(), x));
    assert_eq!(sum, build(&mut m, &want));
}

#[test]
fn d2_diff_mutations_write_files_conflicts_and_deletes_in_path_order() {
    let mut m = Mem::default();
    let (v0, v1) = (file("v0"), file("v1"));
    let from = m.files(&[("a", v0), ("d/x", v0), ("d/y", v0), ("f", v0), ("z", v0)]);
    let term = three_way(v0, v1, EntryState::Absent);
    let to = m.tree(&[
        ("a", NodeEntry::State(v1)),
        ("d", NodeEntry::State(v0)),
        ("f/inner", NodeEntry::State(v1)),
        ("z", NodeEntry::Conflict(term.clone())),
    ]);
    let muts = diff_mutations(&mut m, from, to).unwrap();
    let upsert = |p: &str, s: EntryState| match s {
        EntryState::File {
            mode,
            blob_digest,
            size_bytes,
        } => PathMutation {
            path: p.into(),
            op: MutationOp::Upsert {
                mode,
                blob_digest,
                size_bytes,
            },
        },
        _ => unreachable!(),
    };
    assert_eq!(
        muts,
        vec![
            upsert("a", v1),
            // Directory d becomes file d: one upsert replaces the directory.
            upsert("d", v0),
            // File f becomes directory f/: its leaves are written below it.
            upsert("f/inner", v1),
            PathMutation {
                path: "z".into(),
                op: MutationOp::Conflict(term),
            },
        ]
    );
    // A removed directory deletes every leaf below it.
    let gone = m.files(&[("a", v0), ("f", v0), ("z", v0)]);
    let dels = diff_mutations(&mut m, from, gone).unwrap();
    let paths: Vec<&str> = dels.iter().map(|d| d.path.as_str()).collect();
    assert_eq!(paths, ["d/x", "d/y"]);
    assert!(dels.iter().all(|d| d.op == MutationOp::Delete));
    assert!(diff_mutations(&mut m, from, from).unwrap().is_empty());
}

#[test]
fn d2_a_sum_past_the_term_bound_is_refused() {
    let mut m = Mem::default();
    // Each rebase of a conflicted entry onto a new, different version adds one term pair.
    let base = m.files(&[("f", file("base"))]);
    let mut acc = m.files(&[("f", file("side"))]);
    let mut prev = base;
    let mut refused = None;
    for i in 0..=MAX_CONFLICT_REMOVES {
        let next = m.files(&[("f", file(&format!("v{i}")))]);
        // Rebase onto `next` without the previous base cancelling (a fresh base every time).
        match sum_trees(&mut m, &[next, acc], &[prev]) {
            Ok(t) => acc = t,
            Err(e) => {
                refused = Some((i, e.code));
                break;
            }
        }
        prev = m.files(&[("f", file(&format!("unrelated{i}")))]);
    }
    let (i, code) = refused.expect("the bound is reached");
    assert_eq!(code, RefusalCode::EnvelopeMalformed);
    assert_eq!(i, MAX_CONFLICT_REMOVES);
}
