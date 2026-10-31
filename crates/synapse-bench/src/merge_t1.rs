//! Merge tier T1 (ADR 0003 step D1) against Git: the Gate 4 conflict scenario derived as tier T1
//! merges through the service and compared, pair by pair, with `git merge-tree --write-tree`.
//!
//! For every unordered pair of scenario proposals (admitted as envelope v2 revisions on the
//! pinned base) the cell records whether the server derived a T1 merge and whether Git merged
//! the pair cleanly. For every pair both merged, every path either proposal touched must hold
//! the same blob (by `BlobDigest`) and mode in Git's merged tree and in the derived revision's
//! output; and the attestation must name tier T1 and the canonical merge order. Checks are
//! computed from those observations, never asserted in advance.

use crate::fixture;
use crate::git_arm;
use crate::gitcmd::run_git;
use crate::workload::{build_conflict_scenario, classify_pair, EditOp, PairClass};
use crate::write_jsonl;
use ed25519_dalek::SigningKey;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::path::PathBuf;
use synapse_api::{SynapseService, TreeTarget};
use synapse_core::{
    BlobDigest, ChainPath, ChangeId, ChangesetEnvelopeV2, ChangesetId, DerivationInput,
    DerivationRule, FileMode, GitOid, IdempotencyKey, MergeTier, MutationOp, PathMutation,
    RevisionContent,
};
use synapse_store::{AdmissionAuthority, FsyncPolicy, RecoveryPolicy, StoreLimits};

const T1: DerivationRule = DerivationRule::Merge {
    tier: MergeTier::T1Region,
};

/// Input for the T1 merge cell.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MergeT1Spec {
    pub seed: u64,
    pub clone_dir: PathBuf,
    pub base_commit: String,
    pub cell_dir: PathBuf,
    pub trace_path: PathBuf,
}

/// Observation for one unordered pair.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MergeT1Observation {
    pub a: usize,
    pub b: usize,
    pub class: PairClass,
    /// The server derived a tier T1 merge.
    pub synapse_merged: bool,
    /// The refusal, when it did not.
    pub synapse_refusal: Option<String>,
    /// `git merge-tree` merged cleanly (exit 0), reported a conflict (exit 1), or failed.
    pub git_clean: Option<bool>,
    pub git_error: Option<String>,
    /// Paths both merged but whose blob or mode differs (empty when they agree).
    pub differing_paths: Vec<String>,
    /// The attestation names tier T1 and the inputs in the canonical merge order.
    pub attestation_ok: bool,
}

/// One computed check.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MergeT1Check {
    pub check: String,
    pub passed: bool,
    pub detail: String,
}

/// Result of the T1 merge cell.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MergeT1Result {
    pub pairs: usize,
    pub synapse_merged: usize,
    pub git_clean: usize,
    pub git_errors: usize,
    /// Merged by Synapse but a conflict for Git: must be zero.
    pub merged_but_git_conflict: usize,
    /// Merged by both with a different result: must be zero.
    pub merged_with_different_tree: usize,
    /// Clean for Git but refused by Synapse (conservatism, reported).
    pub refused_but_git_clean: usize,
    pub disjoint_hunk_pairs: usize,
    pub disjoint_hunk_pairs_merged: usize,
    pub by_class: BTreeMap<String, (usize, usize, usize)>,
    pub checks: Vec<MergeT1Check>,
}

fn derived_key(seed: u64, what: &str) -> SigningKey {
    let d: [u8; 32] = Sha256::digest(format!("synapse d1 merge cell {seed} {what}")).into();
    SigningKey::from_bytes(&d)
}

/// Mode and blob digest of `path` in Git tree `tree`, `None` when absent.
fn git_entry(
    clone: &std::path::Path,
    tree: &str,
    path: &str,
) -> Result<Option<(String, BlobDigest)>, String> {
    let ls = run_git(clone, &[], &[], &["ls-tree", tree, "--", path], None)?;
    if ls.code != Some(0) {
        return Err(format!("ls-tree {tree} {path}: exit {:?}", ls.code));
    }
    let line = String::from_utf8_lossy(&ls.stdout).to_string();
    let Some(line) = line.lines().next() else {
        return Ok(None);
    };
    let mode = line
        .split_whitespace()
        .next()
        .unwrap_or_default()
        .to_string();
    let oid = line
        .split_whitespace()
        .nth(2)
        .unwrap_or_default()
        .to_string();
    let blob = run_git(clone, &[], &[], &["cat-file", "blob", &oid], None)?;
    if blob.code != Some(0) {
        return Err(format!("cat-file {oid}: exit {:?}", blob.code));
    }
    Ok(Some((mode, BlobDigest::compute(&blob.stdout))))
}

fn git_mode(mode: FileMode) -> &'static str {
    match mode {
        FileMode::Regular644 => "100644",
        FileMode::Executable755 => "100755",
        FileMode::Symlink120000 => "120000",
    }
}

/// Run the T1 merge cell.
pub fn run_merge_t1_cell(spec: &MergeT1Spec) -> Result<MergeT1Result, String> {
    std::fs::create_dir_all(&spec.cell_dir)
        .map_err(|e| format!("mkdir {}: {e}", spec.cell_dir.display()))?;
    let clone = spec.clone_dir.as_path();
    let base = fixture::list_base_tree(clone, &spec.base_commit)?;
    let full = fixture::load_full_base(clone, &base)?;
    let files = fixture::editable_from_full_base(&base, &full);
    let scenario = build_conflict_scenario(spec.seed, &files)?;
    drop(files);

    let repo =
        synapse_core::RepoId::new(crate::synapse_arm::BENCH_REPO_ID).map_err(|e| e.to_string())?;
    let mut svc = SynapseService::open(
        spec.cell_dir.join("synapse-store"),
        repo.clone(),
        FsyncPolicy::BatchWindow { max_records: 1024 },
        RecoveryPolicy::StrictFailClosed,
        StoreLimits::default(),
    )
    .map_err(|e| e.to_string())?;
    let base_oid = GitOid::from_hex(&spec.base_commit).map_err(|e| e.to_string())?;
    svc.register_base_tree(base_oid, full)
        .map_err(|e| e.to_string())?;
    let base_tree = svc
        .tree_digest(TreeTarget::BaseGitCommit(base_oid), None)
        .map_err(|e| e.to_string())?;
    let plumbing = git_arm::g3_setup_agent(
        clone,
        &spec.base_commit,
        &spec.cell_dir.join("plumbing"),
        0,
        &[],
    )?;
    let chain = ChainPath::new(vec![Sha256::digest(b"synapse d1 merge cell chain").into()])
        .map_err(|e| e.to_string())?;
    let server = derived_key(spec.seed, "server");

    let mut ids: Vec<ChangesetId> = Vec::new();
    let mut commits: Vec<String> = Vec::new();
    for (i, sp) in scenario.iter().enumerate() {
        let mut blobs = Vec::new();
        let mutations: Vec<PathMutation> = sp
            .proposal
            .edits
            .iter()
            .map(|e| PathMutation {
                path: e.path.clone(),
                op: match &e.op {
                    EditOp::Upsert { mode, content } => {
                        let d = BlobDigest::compute(content);
                        blobs.push((d, content.to_vec()));
                        MutationOp::Upsert {
                            mode: *mode,
                            blob_digest: d,
                            size_bytes: content.len() as u64,
                        }
                    }
                    EditOp::Delete => MutationOp::Delete,
                },
            })
            .collect();
        let mut change = [0u8; 16];
        change[..8].copy_from_slice(&(i as u64).to_le_bytes());
        change[8..].copy_from_slice(&spec.seed.to_le_bytes());
        let content = RevisionContent {
            change_id: ChangeId(change),
            base_tree,
            parents: vec![],
            mutations,
            intent_summary: format!("gate4 conflict scenario proposal {i}"),
        };
        let mut idem = [0u8; 32];
        idem[..8].copy_from_slice(&(i as u64).to_le_bytes());
        let env = ChangesetEnvelopeV2::sign_new(
            &derived_key(spec.seed, "agent"),
            repo.clone(),
            content,
            IdempotencyKey(idem),
            crate::unix_now_ms(),
        );
        ids.push(env.changeset_id());
        let authority = AdmissionAuthority {
            chain: chain.clone(),
            change_scope: vec![],
        };
        svc.store_mut()
            .admit_revision(env, &blobs, authority, crate::unix_now_ms())
            .map_err(|e| format!("admit proposal {i}: {e}"))?;
        commits.push(git_arm::g3_op(
            clone,
            &spec.base_commit,
            &plumbing,
            &sp.proposal,
            &[],
        )?);
    }

    let mut rows = Vec::new();
    let n = scenario.len();
    for a in 0..n {
        for b in (a + 1)..n {
            let class = classify_pair(scenario[a].group, scenario[b].group);
            let mut order = [ids[a], ids[b]];
            order.sort();
            let mut inputs = vec![DerivationInput::Tree(base_tree)];
            inputs.extend(order.iter().map(|id| DerivationInput::Revision(*id)));
            let derived = svc.derive_revision(&server, T1, inputs.clone());
            let run = run_git(
                clone,
                &[],
                &[],
                &["merge-tree", "--write-tree", &commits[a], &commits[b]],
                None,
            );
            let (git_clean, git_error, git_tree) = match run {
                Ok(r) if r.code == Some(0) => {
                    let tree = String::from_utf8_lossy(&r.stdout)
                        .lines()
                        .next()
                        .unwrap_or_default()
                        .to_string();
                    (Some(true), None, Some(tree))
                }
                Ok(r) if r.code == Some(1) => (Some(false), None, None),
                Ok(r) => (
                    None,
                    Some(format!("exit {:?}: {}", r.code, r.stderr_tail())),
                    None,
                ),
                Err(e) => (None, Some(e), None),
            };
            let mut differing = Vec::new();
            let mut attestation_ok = false;
            if let (Ok(d), Some(tree)) = (&derived, &git_tree) {
                attestation_ok = d.attestation.rule == T1 && d.attestation.inputs == inputs;
                let touched: std::collections::BTreeSet<&str> = scenario[a]
                    .proposal
                    .edits
                    .iter()
                    .chain(&scenario[b].proposal.edits)
                    .map(|e| e.path.as_str())
                    .collect();
                for path in touched {
                    let ours = d
                        .content
                        .mutations
                        .iter()
                        .find(|m| m.path == path)
                        .map(|m| match &m.op {
                            MutationOp::Upsert {
                                mode, blob_digest, ..
                            } => Some((git_mode(*mode).to_string(), *blob_digest)),
                            MutationOp::Delete => None,
                        })
                        .ok_or_else(|| format!("merge output lacks touched path {path}"))?;
                    if ours != git_entry(clone, tree, path)? {
                        differing.push(path.to_string());
                    }
                }
            }
            rows.push(MergeT1Observation {
                a,
                b,
                class,
                synapse_merged: derived.is_ok(),
                synapse_refusal: derived.as_ref().err().map(|e| e.to_string()),
                git_clean,
                git_error,
                differing_paths: differing,
                attestation_ok,
            });
        }
    }
    write_jsonl(&spec.trace_path, &rows)?;

    let count = |f: &dyn Fn(&MergeT1Observation) -> bool| rows.iter().filter(|r| f(r)).count();
    let merged = count(&|r| r.synapse_merged);
    let git_clean = count(&|r| r.git_clean == Some(true));
    let git_errors = count(&|r| r.git_clean.is_none());
    let false_merges = count(&|r| r.synapse_merged && r.git_clean == Some(false));
    let different = count(&|r| r.synapse_merged && !r.differing_paths.is_empty());
    let bad_attestation =
        count(&|r| r.synapse_merged && r.git_clean == Some(true) && !r.attestation_ok);
    let refused_clean = count(&|r| !r.synapse_merged && r.git_clean == Some(true));
    let hunk_pairs = count(&|r| r.class == PairClass::DisjointHunksSameFile);
    let hunk_merged = count(&|r| r.class == PairClass::DisjointHunksSameFile && r.synapse_merged);
    let mut by_class: BTreeMap<String, (usize, usize, usize)> = BTreeMap::new();
    for r in &rows {
        let e = by_class.entry(format!("{:?}", r.class)).or_default();
        e.0 += 1;
        e.1 += usize::from(r.synapse_merged);
        e.2 += usize::from(r.git_clean == Some(true));
    }
    let checks = vec![
        MergeT1Check {
            check: "The disjoint-hunk pairs merge at tier T1".into(),
            passed: hunk_pairs > 0 && hunk_merged == hunk_pairs,
            detail: format!("{hunk_merged} of {hunk_pairs} merged"),
        },
        MergeT1Check {
            check: "No pair Git reports as conflicting is merged".into(),
            passed: false_merges == 0 && git_errors == 0,
            detail: format!(
                "{false_merges} merged Git conflicts, {git_errors} merge-tree errors, {} pairs",
                rows.len()
            ),
        },
        MergeT1Check {
            check: "Every merged tree equals Git's merge result on every touched path".into(),
            passed: different == 0,
            detail: format!("{different} merged pairs differ from Git"),
        },
        MergeT1Check {
            check: "Every merge attestation records tier T1 and the canonical merge order".into(),
            passed: bad_attestation == 0,
            detail: format!("{bad_attestation} attestations without them"),
        },
    ];
    Ok(MergeT1Result {
        pairs: rows.len(),
        synapse_merged: merged,
        git_clean,
        git_errors,
        merged_but_git_conflict: false_merges,
        merged_with_different_tree: different,
        refused_but_git_clean: refused_clean,
        disjoint_hunk_pairs: hunk_pairs,
        disjoint_hunk_pairs_merged: hunk_merged,
        by_class,
        checks,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fixture::test_support::{make_fixture_repo, temp_dir};
    use crate::fixture::{clone_no_checkout, configure_bench_clone};
    use synapse_core::merge::region_merge;

    /// Acceptance of step D1 on the Gate 4 conflict scenario (23 proposals, 253 pairs).
    #[test]
    fn d1_gate4_conflict_scenario_t1_merges_match_git_on_all_253_pairs() {
        let root = temp_dir("merge-t1");
        let commit = make_fixture_repo(&root, 16, 70);
        let clone = root.join("clone");
        clone_no_checkout(&root.join("fixture"), &clone).unwrap();
        configure_bench_clone(&clone).unwrap();
        let spec = MergeT1Spec {
            seed: 3,
            clone_dir: clone,
            base_commit: commit,
            cell_dir: root.join("cell"),
            trace_path: root.join("merge-t1.jsonl"),
        };
        let r = run_merge_t1_cell(&spec).unwrap();
        assert_eq!(r.pairs, 253);
        assert_eq!(r.disjoint_hunk_pairs, 3);
        // On this scenario T1 merges every pair Git merges (identical changes included).
        assert_eq!(r.refused_but_git_clean, 0, "{:?}", r.by_class);
        for c in &r.checks {
            assert!(c.passed, "{}: {}", c.check, c.detail);
        }
        eprintln!("d1 merge cell: {r:?}");
        let _ = std::fs::remove_dir_all(&root);
    }

    struct Rng(u64);
    impl Rng {
        fn below(&mut self, n: u64) -> u64 {
            self.0 = self
                .0
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            (self.0 >> 33) % n
        }
    }

    fn random_edit(rng: &mut Rng, base: &[String], tag: &str) -> Vec<String> {
        let mut v = base.to_vec();
        for k in 0..1 + rng.below(3) {
            let at = rng.below(v.len() as u64 + 1) as usize;
            match rng.below(3) {
                0 if at < v.len() => v[at] = format!("{tag} {k}"),
                1 if at < v.len() => {
                    v.remove(at);
                }
                _ => v.insert(at, ["x", "y", "{", "}"][rng.below(4) as usize].to_string()),
            }
        }
        v
    }

    fn text(lines: &[String]) -> Vec<u8> {
        lines
            .iter()
            .flat_map(|l| format!("{l}\n").into_bytes())
            .collect()
    }

    /// Differential check of the region rule against `git merge-file` on random small files
    /// with many repeated lines: every merge `region_merge` reports clean is clean in Git with
    /// byte-identical output.
    #[test]
    fn d1_region_merge_never_merges_what_git_merge_file_refuses() {
        let dir = temp_dir("merge-file");
        let mut rng = Rng(0xD1);
        let (mut merged, mut refused_clean) = (0, 0);
        for case in 0..10_000 {
            let n = 4 + rng.below(16) as usize;
            let base: Vec<String> = (0..n)
                .map(|i| match rng.below(3) {
                    0 => "x".to_string(),
                    1 => "}".to_string(),
                    _ => format!("line {i}"),
                })
                .collect();
            let a = random_edit(&mut rng, &base, "A");
            let b = random_edit(&mut rng, &base, "B");
            let (tb, ta, tbb) = (text(&base), text(&a), text(&b));
            for (name, bytes) in [("base", &tb), ("a", &ta), ("b", &tbb)] {
                std::fs::write(dir.join(name), bytes).unwrap();
            }
            let git = run_git(
                &dir,
                &[],
                &[],
                &["merge-file", "-p", "a", "base", "b"],
                None,
            )
            .unwrap();
            let ours = region_merge(&tb, &[&ta, &tbb]);
            match ours {
                Ok(m) => {
                    merged += 1;
                    assert_eq!(git.code, Some(0), "case {case}: we merged a Git conflict");
                    assert_eq!(git.stdout, m, "case {case}: merge differs from Git");
                }
                Err(_) => refused_clean += usize::from(git.code == Some(0) && ta != tbb),
            }
        }
        eprintln!(
            "d1 merge-file differential: {merged} merged, {refused_clean} refused but clean in Git"
        );
        assert!(merged >= 2_000, "only {merged} clean merges exercised");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
