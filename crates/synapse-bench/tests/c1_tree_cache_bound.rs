//! C1 acceptance (ADR 0003 section 9 step 4): the shared Merkle tree cache stays under its
//! configured bound under the Gate 4 query load, and cold (build) and warm (paging) queries
//! are distinguishable.
//!
//! The load has the Gate 4 query cell's shape (`crates/synapse-bench/src/query.rs`): a
//! population of 8 agents x 50 proposals, then 400 samples each of `tree` (every page),
//! `diff` (base to changeset), and `read_file` on random changesets, from one reader. The
//! bound is set to the minimum so the population does not fit and the store must evict and
//! rebuild; every answer is still compared per entry with Git.

use synapse_api::{TreeCacheConfig, TreeTarget, MIN_TREE_CACHE_BYTES};
use synapse_bench::fixture;
use synapse_bench::rng::SplitMix64;
use synapse_bench::synapse_arm;
use synapse_bench::tree_parity::{first_mismatch, synthetic_fixture, temp_dir, ParityPair};
use synapse_bench::workload::{generate_write_workload, EditOp, Proposal};
use synapse_core::ChangesetId;

const AGENTS: usize = 8;
const OPS_PER_AGENT: usize = 50;
const SAMPLES: usize = 400;

struct Populated {
    root: std::path::PathBuf,
    pair: ParityPair,
    /// (changeset, Git commit, proposal) in submission order.
    props: Vec<(ChangesetId, String, Proposal)>,
}

fn populate(label: &str) -> Populated {
    let root = temp_dir(label);
    let base = synthetic_fixture(&root, 96, 24).unwrap();
    let clone = root.join("fixture");
    let mut pair = ParityPair::open(&clone, &base, &root.join("work"), 0xC1B, AGENTS).unwrap();
    let listed = fixture::list_base_tree(&clone, &base).unwrap();
    let full = fixture::load_full_base(&clone, &listed).unwrap();
    let files = fixture::editable_from_full_base(&listed, &full);
    let workload = generate_write_workload(0xC1B, 10_000, AGENTS, OPS_PER_AGENT, &files);
    let mut props = Vec::new();
    for p in workload.iter().flatten() {
        let (cs, commit) = pair.apply(p).unwrap();
        props.push((cs, commit, p.clone()));
    }
    Populated { root, pair, props }
}

fn assert_under_bound(pair: &ParityPair, max: usize, when: &str) {
    let s = pair.svc.tree_store().stats();
    assert!(
        s.total_bytes <= max,
        "{when}: tree cache holds {} accounted bytes, over the {} byte bound",
        s.total_bytes,
        max
    );
}

#[test]
fn c1_memory_stays_under_the_configured_bound_under_the_gate4_query_load() {
    let Populated {
        root,
        mut pair,
        props,
    } = populate("bound");
    let max = MIN_TREE_CACHE_BYTES;
    pair.svc
        .set_tree_cache_config(TreeCacheConfig { max_bytes: max })
        .unwrap();
    let n = props.len();
    assert_eq!(n, AGENTS * OPS_PER_AGENT);
    let mut rng = SplitMix64::derive(0xC1B, &[0x0E_E7]);
    let mut reads = 0usize;
    for s in 0..SAMPLES {
        // tree: every page, compared per entry with `git ls-tree -r`.
        let i = rng.below(n);
        let (git, syn) = pair
            .tree_pair(TreeTarget::Changeset(props[i].0), &props[i].1)
            .unwrap();
        assert_eq!(first_mismatch(&git, &syn), None, "tree sample {s}");
        assert_under_bound(&pair, max, "after tree");
        // diff: base to changeset, compared per entry with `git diff-tree -r --raw`.
        let i = rng.below(n);
        let (git, syn) = pair
            .diff_pair(TreeTarget::Changeset(props[i].0), &props[i].1)
            .unwrap();
        assert_eq!(first_mismatch(&git, &syn), None, "diff sample {s}");
        assert_under_bound(&pair, max, "after diff");
        // read_file: an upserted file of a random changeset returns the proposal's bytes.
        let i = rng.below(n);
        let p = &props[i].2;
        if let Some((path, content)) = p.edits.iter().find_map(|e| match &e.op {
            EditOp::Upsert { content, .. } => Some((e.path.clone(), content.clone())),
            EditOp::Delete => None,
        }) {
            let now = synapse_bench::unix_now_ms();
            let req = synapse_arm::build_read_request(
                &pair.ids.agents[0],
                &pair.ids.repo_id,
                (TreeTarget::Changeset(props[i].0), path, None),
                &format!("c1/bound/read/{s}"),
                now,
            )
            .unwrap();
            let bytes = pair.svc.read_file(&req, now).unwrap();
            assert_eq!(bytes.as_slice(), content.as_slice(), "read_file sample {s}");
            reads += 1;
            assert_under_bound(&pair, max, "after read_file");
        }
    }
    let s = pair.svc.tree_store().stats();
    println!("c1 bound test stats after the query load: {s:?}");
    assert!(reads > 0);
    assert!(
        s.high_water_bytes <= max,
        "high water {} > bound {max}",
        s.high_water_bytes
    );
    assert!(
        s.nodes_evicted > 0 && s.roots_evicted > 0,
        "the load must not fit in the bound, or the test proves nothing: {s:?}"
    );
    assert!(s.memoized_roots < n, "every root still memoized: {s:?}");
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn c1_cold_build_then_warm_paging_with_structural_sharing() {
    let Populated {
        root,
        mut pair,
        props,
    } = populate("cold-warm");
    // Fresh store: no changeset root is memoized.
    pair.svc
        .set_tree_cache_config(TreeCacheConfig::default())
        .unwrap();
    let base_root = pair
        .svc
        .tree_digest(TreeTarget::BaseGitCommit(pair.base_oid), None)
        .unwrap();
    for i in [0usize, props.len() / 2, props.len() - 1] {
        let target = TreeTarget::Changeset(props[i].0);
        let before = pair.svc.tree_store().stats();
        let root_digest = pair.svc.tree_digest(target, None).unwrap();
        let built = pair.svc.tree_store().stats();
        assert_eq!(
            built.root_builds,
            before.root_builds + 1,
            "first query is cold"
        );
        assert_ne!(
            root_digest, base_root,
            "a changeset with edits has its own root"
        );
        // Structural sharing: a cold build writes only the nodes on the edited paths.
        let p = &props[i].2;
        let depth = p
            .edits
            .iter()
            .map(|e| e.path.matches('/').count() + 1)
            .max()
            .unwrap();
        let new_nodes = built.nodes_inserted - before.nodes_inserted;
        assert!(
            new_nodes as usize <= depth * p.edits.len(),
            "cold build inserted {new_nodes} nodes for {} edits of depth <= {depth}",
            p.edits.len()
        );
        // Warm: the same root again, then a full paged listing, build nothing.
        assert_eq!(pair.svc.tree_digest(target, None).unwrap(), root_digest);
        let (total, first) = pair.svc.tree_page(target, "", 0, 256, None).unwrap();
        let mut seen = first.len() as u64;
        while seen < total {
            let (_, page) = pair.svc.tree_page(target, "", seen, 256, None).unwrap();
            assert!(!page.is_empty());
            seen += page.len() as u64;
        }
        let warm = pair.svc.tree_store().stats();
        assert_eq!(
            warm.root_builds, built.root_builds,
            "warm queries build nothing"
        );
        assert!(
            warm.root_hits >= built.root_hits + 2,
            "warm queries hit the memo"
        );
        assert_eq!(warm.nodes_inserted, built.nodes_inserted);
    }
    let _ = std::fs::remove_dir_all(&root);
}
