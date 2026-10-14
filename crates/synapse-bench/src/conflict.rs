//! Conflict-resolution correctness against generator ground truth and Git three-way merges.
//!
//! For every unordered pair of scenario proposals the cell records:
//! * the generator's declared class ([`PairClass`]) and therefore the pair's expected
//!   outcome under Synapse's documented path-level rule;
//! * whether `SynapseService::conflicts` flagged the pair (queried from each side);
//! * whether `git merge-tree --write-tree` reported a conflict (exit 1) or merged cleanly
//!   (exit 0).
//!
//! Checks are computed from those observations, never asserted in advance.

use crate::fixture;
use crate::git_arm;
use crate::gitcmd::run_git;
use crate::synapse_arm;
use crate::workload::{build_conflict_scenario, classify_pair, PairClass, ScenarioGroup};
use crate::write_jsonl;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
use synapse_api::{ConflictQueryPayload, PageRequest, SynapseService, DEFAULT_MAX_PAGE_SIZE};
use synapse_core::ChangesetId;
use synapse_store::{FsyncPolicy, IngestOutcome, RecoveryPolicy};

/// Input for the conflict-correctness cell.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConflictSpec {
    pub seed: u64,
    pub clone_dir: PathBuf,
    pub base_commit: String,
    pub cell_dir: PathBuf,
    pub trace_path: PathBuf,
}

/// Observation for one unordered pair.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PairObservation {
    pub a: usize,
    pub b: usize,
    pub group_a: ScenarioGroup,
    pub group_b: ScenarioGroup,
    pub class: PairClass,
    pub path_level_expected: bool,
    pub synapse_flagged: bool,
    pub git_expected_conflict: bool,
    pub git_conflict: Option<bool>,
    pub git_error: Option<String>,
}

/// Counts for one pair class.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ClassCounts {
    pub pairs: usize,
    pub synapse_flagged: usize,
    pub git_conflicts: usize,
}

/// Computed check with its pass state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConflictCheck {
    pub check: String,
    pub passed: bool,
    pub detail: String,
}

/// Result of the conflict-correctness cell.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConflictResult {
    pub proposals: usize,
    pub pairs: usize,
    pub path_level_expected_conflicts: usize,
    pub synapse_flagged: usize,
    pub synapse_vs_ground_truth_mismatches: usize,
    pub git_conflicts: usize,
    pub git_errors: usize,
    pub git_vs_generator_mismatches: usize,
    /// Git reports a conflict but Synapse did not flag the pair.
    pub false_negatives_vs_git: usize,
    /// Synapse flagged the pair but Git merged it cleanly (path-level conservatism).
    pub over_flags_vs_git: usize,
    pub by_class: BTreeMap<String, ClassCounts>,
    pub checks: Vec<ConflictCheck>,
}

fn conflicting_peers(
    svc: &mut SynapseService,
    agent: &synapse_arm::AgentIdentity,
    repo_id: &synapse_core::RepoId,
    candidate: ChangesetId,
) -> Result<BTreeSet<ChangesetId>, String> {
    let mut peers = BTreeSet::new();
    let mut cursor: Option<String> = None;
    let mut counter = 0u64;
    loop {
        counter += 1;
        let payload = ConflictQueryPayload {
            candidate,
            against: None,
            page: PageRequest {
                cursor: cursor.clone(),
                limit: DEFAULT_MAX_PAGE_SIZE,
                min_visible_seq: None,
                snapshot_seq: None,
            },
        };
        let label = format!("gate4/conflict/{}/{counter}", candidate.to_hex());
        let now = crate::unix_now_ms();
        let req = synapse_arm::build_read_request(agent, repo_id, payload, &label, now)?;
        let page = svc.conflicts(&req, now).map_err(|e| e.to_string())?;
        for c in &page.items {
            peers.insert(c.conflicting_changeset);
        }
        match page.next_cursor {
            Some(next) => cursor = Some(next),
            None => break,
        }
    }
    Ok(peers)
}

/// Run the conflict-correctness cell.
pub fn run_conflict_cell(spec: &ConflictSpec) -> Result<ConflictResult, String> {
    std::fs::create_dir_all(&spec.cell_dir)
        .map_err(|e| format!("mkdir {}: {e}", spec.cell_dir.display()))?;
    let clone = spec.clone_dir.as_path();
    let base = fixture::list_base_tree(clone, &spec.base_commit)?;
    let full = fixture::load_full_base(clone, &base)?;
    let files = fixture::editable_from_full_base(&base, &full);
    let scenario = build_conflict_scenario(spec.seed, &files)?;
    drop(files);

    let ids = synapse_arm::issue_identities(spec.seed, 1, crate::unix_now_ms())?;
    let mut svc = synapse_arm::open_service(
        &spec.cell_dir.join("synapse-store"),
        &ids,
        FsyncPolicy::BatchWindow { max_records: 1024 },
        RecoveryPolicy::StrictFailClosed,
    )?;
    let base_oid = synapse_arm::register_base(&mut svc, &spec.base_commit, full)?;
    let plumbing = git_arm::g3_setup_agent(
        clone,
        &spec.base_commit,
        &spec.cell_dir.join("plumbing"),
        0,
        &[],
    )?;

    let mut ids_by_index: Vec<ChangesetId> = Vec::new();
    let mut commits: Vec<String> = Vec::new();
    for (i, sp) in scenario.iter().enumerate() {
        let label = format!("gate4/conflict-scenario/{i}");
        let now = crate::unix_now_ms();
        let req = synapse_arm::build_submit_request(
            &ids.agents[0],
            &ids.repo_id,
            base_oid,
            &sp.proposal,
            &label,
            now,
        )?;
        let cs = match svc.submit(&req, now).map_err(|e| e.to_string())? {
            IngestOutcome::Committed { changeset_id, .. }
            | IngestOutcome::IdempotentDuplicate { changeset_id, .. } => changeset_id,
        };
        ids_by_index.push(cs);
        commits.push(git_arm::g3_op(
            clone,
            &spec.base_commit,
            &plumbing,
            &sp.proposal,
            &[],
        )?);
    }
    let index_of: BTreeMap<ChangesetId, usize> = ids_by_index
        .iter()
        .enumerate()
        .map(|(i, id)| (*id, i))
        .collect();

    let mut flagged: BTreeSet<(usize, usize)> = BTreeSet::new();
    for (i, cs) in ids_by_index.iter().enumerate() {
        for peer in conflicting_peers(&mut svc, &ids.agents[0], &ids.repo_id, *cs)? {
            let j = *index_of
                .get(&peer)
                .ok_or("conflicts returned an unknown changeset")?;
            flagged.insert((i.min(j), i.max(j)));
        }
    }

    let mut rows = Vec::new();
    let n = scenario.len();
    for a in 0..n {
        for b in (a + 1)..n {
            let class = classify_pair(scenario[a].group, scenario[b].group);
            let run = run_git(
                clone,
                &[],
                &[],
                &["merge-tree", "--write-tree", &commits[a], &commits[b]],
                None,
            );
            let (git_conflict, git_error) = match run {
                Ok(r) if r.code == Some(0) => (Some(false), None),
                Ok(r) if r.code == Some(1) => (Some(true), None),
                Ok(r) => (
                    None,
                    Some(format!("exit {:?}: {}", r.code, r.stderr_tail())),
                ),
                Err(e) => (None, Some(e)),
            };
            rows.push(PairObservation {
                a,
                b,
                group_a: scenario[a].group,
                group_b: scenario[b].group,
                class,
                path_level_expected: class.path_level_conflict_expected(),
                synapse_flagged: flagged.contains(&(a, b)),
                git_expected_conflict: class.git_conflict_expected(),
                git_conflict,
                git_error,
            });
        }
    }
    write_jsonl(&spec.trace_path, &rows)?;

    let mut by_class: BTreeMap<String, ClassCounts> = BTreeMap::new();
    for r in &rows {
        let e = by_class.entry(format!("{:?}", r.class)).or_default();
        e.pairs += 1;
        e.synapse_flagged += usize::from(r.synapse_flagged);
        e.git_conflicts += usize::from(r.git_conflict == Some(true));
    }
    let mismatches = rows
        .iter()
        .filter(|r| r.synapse_flagged != r.path_level_expected)
        .count();
    let git_errors = rows.iter().filter(|r| r.git_conflict.is_none()).count();
    let git_vs_generator = rows
        .iter()
        .filter(|r| r.git_conflict.is_some_and(|g| g != r.git_expected_conflict))
        .count();
    let false_negatives = rows
        .iter()
        .filter(|r| r.git_conflict == Some(true) && !r.synapse_flagged)
        .count();
    let over_flags = rows
        .iter()
        .filter(|r| r.git_conflict == Some(false) && r.synapse_flagged)
        .count();
    let flagged_count = rows.iter().filter(|r| r.synapse_flagged).count();
    let git_conflicts = rows.iter().filter(|r| r.git_conflict == Some(true)).count();
    let clean_pairs = rows.iter().filter(|r| !r.synapse_flagged).count();

    let checks = vec![
        ConflictCheck {
            check: "Synapse flagged set equals generator ground truth (path-level rule)".into(),
            passed: mismatches == 0,
            detail: format!("{mismatches} mismatching pairs of {}", rows.len()),
        },
        ConflictCheck {
            check: "Every Git textual conflict is flagged by Synapse (zero false negatives)".into(),
            passed: false_negatives == 0 && git_errors == 0,
            detail: format!(
                "{false_negatives} false negatives, {git_errors} merge-tree errors, {git_conflicts} Git conflicts"
            ),
        },
        ConflictCheck {
            check: "Every pair Synapse reports clean merges cleanly in Git".into(),
            passed: false_negatives == 0 && git_errors == 0,
            detail: format!("{clean_pairs} pairs reported clean by Synapse"),
        },
        ConflictCheck {
            check: "Git outcomes match the generator's expectation (scenario sanity)".into(),
            passed: git_vs_generator == 0 && git_errors == 0,
            detail: format!("{git_vs_generator} pairs differ from expectation"),
        },
    ];

    Ok(ConflictResult {
        proposals: n,
        pairs: rows.len(),
        path_level_expected_conflicts: rows.iter().filter(|r| r.path_level_expected).count(),
        synapse_flagged: flagged_count,
        synapse_vs_ground_truth_mismatches: mismatches,
        git_conflicts,
        git_errors,
        git_vs_generator_mismatches: git_vs_generator,
        false_negatives_vs_git: false_negatives,
        over_flags_vs_git: over_flags,
        by_class,
        checks,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fixture::test_support::{make_fixture_repo, temp_dir};
    use crate::fixture::{clone_no_checkout, configure_bench_clone};

    #[test]
    fn conflict_cell_matches_ground_truth_and_git_on_small_fixture() {
        let root = temp_dir("conflict");
        let commit = make_fixture_repo(&root, 16, 70);
        let clone = root.join("clone");
        clone_no_checkout(&root.join("fixture"), &clone).unwrap();
        configure_bench_clone(&clone).unwrap();
        let spec = ConflictSpec {
            seed: 3,
            clone_dir: clone,
            base_commit: commit,
            cell_dir: root.join("cell"),
            trace_path: root.join("conflict.jsonl"),
        };
        let r = run_conflict_cell(&spec).unwrap();
        assert_eq!(r.proposals, 23);
        assert_eq!(r.pairs, 253);
        for c in &r.checks {
            assert!(c.passed, "{}: {}", c.check, c.detail);
        }
        assert_eq!(r.by_class["DisjointHunksSameFile"].pairs, 3);
        assert_eq!(r.by_class["DisjointHunksSameFile"].git_conflicts, 0);
        let _ = std::fs::remove_dir_all(&root);
    }
}
