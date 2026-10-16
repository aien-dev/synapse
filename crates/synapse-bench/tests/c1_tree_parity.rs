//! C1 acceptance (ADR 0003 section 9 step 4): tree and diff parity with `git ls-tree -r` and
//! `git diff-tree`, per entry (mode, type, object id, path) and in order.
//!
//! The CI tests use a synthetic repository plus a Gate 4 shaped population (8 agents x 50
//! proposals) and hand-written edge cases (`T` status, file and directory replacement). The
//! `#[ignore]`d test repeats the population check on the real Gate 4 fixture
//! (`aien-sovereign-core` at the pinned commit); run it with `--ignored` where the fixture is
//! present (`C1_FIXTURE_REPO`, default `~/workspace/aien-sovereign-core`).

use synapse_api::TreeTarget;
use synapse_bench::fixture;
use synapse_bench::tree_parity::{
    edge_case_proposals, first_mismatch, synthetic_fixture, temp_dir, ParityPair,
};
use synapse_bench::workload::generate_write_workload;

/// Gate 4 fixture commit (aien-sovereign-core, pinned by the Gate 4 qualification).
const GATE4_FIXTURE_REV: &str = "1b6e340d48417dfbcfe2df56d48a0696a3a9b250";

fn mismatch_report(what: &str, kind: &str, git: &[String], syn: &[String]) -> Option<String> {
    first_mismatch(git, syn).map(|m| {
        format!(
            "{what}: {kind} parity mismatch at entry {} of {} (git) / {} (synapse)\n  git:     {:?}\n  synapse: {:?}",
            m.index,
            git.len(),
            syn.len(),
            m.git,
            m.synapse
        )
    })
}

fn assert_tree_parity(pair: &mut ParityPair, target: TreeTarget, commit: &str, what: &str) {
    let (git, syn) = pair.tree_pair(target, commit).unwrap();
    assert!(!git.is_empty(), "{what}: git ls-tree returned nothing");
    if let Some(r) = mismatch_report(what, "tree", &git, &syn) {
        panic!("{r}");
    }
}

fn assert_diff_parity(pair: &mut ParityPair, target: TreeTarget, commit: &str, what: &str) {
    let (git, syn) = pair.diff_pair(target, commit).unwrap();
    if let Some(r) = mismatch_report(what, "diff", &git, &syn) {
        panic!("{r}");
    }
}

/// Populate `agents x ops` Gate 4 proposals and check every changeset's tree and diff.
fn population_parity(clone: &std::path::Path, base: &str, agents: usize, ops: usize) -> usize {
    let work = temp_dir("population");
    let mut pair = ParityPair::open(clone, base, &work, 0xC1, agents).unwrap();
    let base_target = TreeTarget::BaseGitCommit(pair.base_oid);
    assert_tree_parity(&mut pair, base_target, base, "base tree");
    let listed = fixture::list_base_tree(clone, base).unwrap();
    let full = fixture::load_full_base(clone, &listed).unwrap();
    let files = fixture::editable_from_full_base(&listed, &full);
    let workload = generate_write_workload(0xC1, 10_000, agents, ops, &files);
    let mut checked = 0;
    for p in workload.iter().flatten() {
        let (cs, commit) = pair.apply(p).unwrap();
        let what = format!("agent {} proposal {}", p.agent, p.index);
        assert_tree_parity(&mut pair, TreeTarget::Changeset(cs), &commit, &what);
        assert_diff_parity(&mut pair, TreeTarget::Changeset(cs), &commit, &what);
        checked += 1;
    }
    let _ = std::fs::remove_dir_all(&work);
    checked
}

#[test]
fn c1_tree_parity_with_git_ls_tree_r_on_gate4_shaped_population() {
    let root = temp_dir("synthetic-population");
    let base = synthetic_fixture(&root, 48, 24).unwrap();
    let checked = population_parity(&root.join("fixture"), &base, 8, 50);
    assert_eq!(checked, 400);
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn c1_tree_and_diff_parity_with_git_on_edge_cases() {
    let root = temp_dir("edge-cases");
    let base = synthetic_fixture(&root, 8, 12).unwrap();
    let clone = root.join("fixture");
    let work = root.join("work");
    let mut pair = ParityPair::open(&clone, &base, &work, 0xC1E, 2).unwrap();
    // Every case is checked before failing, so one run shows each mismatch.
    let mut failures = Vec::new();
    for p in edge_case_proposals() {
        let (cs, commit) = pair.apply(&p).unwrap();
        let target = TreeTarget::Changeset(cs);
        let (git, syn) = pair.tree_pair(target, &commit).unwrap();
        failures.extend(mismatch_report(&p.summary, "tree", &git, &syn));
        let (git, syn) = pair.diff_pair(target, &commit).unwrap();
        failures.extend(mismatch_report(&p.summary, "diff", &git, &syn));
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
#[ignore = "needs the Gate 4 fixture repository (run with --ignored where it is present)"]
fn c1_tree_and_diff_parity_with_git_on_gate4_fixture() {
    let src = std::env::var("C1_FIXTURE_REPO").unwrap_or_else(|_| {
        format!(
            "{}/workspace/aien-sovereign-core",
            std::env::var("HOME").unwrap_or_default()
        )
    });
    let root = temp_dir("gate4-fixture");
    let clone = root.join("clone");
    fixture::clone_no_checkout(std::path::Path::new(&src), &clone).unwrap();
    let checked = population_parity(&clone, GATE4_FIXTURE_REV, 8, 50);
    assert_eq!(checked, 400);
    println!("c1 gate4 fixture parity: base tree plus {checked} changesets, tree and diff, per entry: all equal");
    let _ = std::fs::remove_dir_all(&root);
}
