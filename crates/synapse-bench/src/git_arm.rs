//! Conventional Git workflow arms.
//!
//! * G1: a fresh `git worktree add -b` checkout per proposal (today's hive practice).
//! * G2: one persistent worktree per agent; each proposal does `git checkout -B` back
//!   to the base, edits files, `git add`, and `git commit`.
//! * G3: checkout-free plumbing with a per-agent temporary index (`GIT_INDEX_FILE`):
//!   copy the base index, `hash-object -w`, `update-index --index-info`, `write-tree`,
//!   `commit-tree`, `update-ref`.
//! * G3F: G3 with `-c core.fsync=all -c core.fsyncMethod=fsync` on every command.
//!
//! Every arm keeps every proposal as a commit on its own branch (no deletes during timing).

use crate::gitcmd::git_ok;
use crate::path_str;
use crate::workload::{EditOp, Proposal};
use std::ffi::OsStr;
use std::path::{Path, PathBuf};

/// Extra config for the G3F arm (values from git-config(1), git 2.43).
pub const FSYNC_ALL_CONFIG: &[(&str, &str)] =
    &[("core.fsync", "all"), ("core.fsyncMethod", "fsync")];

/// Branch name for one proposal.
pub fn proposal_branch(agent: usize, index: usize) -> String {
    format!("bench/a{agent:03}/p{index:05}")
}

fn commit_message(p: &Proposal) -> String {
    format!("{}\n", p.summary)
}

/// Write the proposal's edits into a checked-out worktree and return the touched paths.
pub fn apply_edits_to_worktree(wt: &Path, p: &Proposal) -> Result<Vec<String>, String> {
    let mut paths = Vec::with_capacity(p.edits.len());
    for e in &p.edits {
        let target = wt.join(&e.path);
        match &e.op {
            EditOp::Upsert { content, .. } => {
                if let Some(parent) = target.parent() {
                    std::fs::create_dir_all(parent)
                        .map_err(|err| format!("mkdir {}: {err}", parent.display()))?;
                }
                std::fs::write(&target, content.as_slice())
                    .map_err(|err| format!("write {}: {err}", target.display()))?;
            }
            EditOp::Delete => {
                std::fs::remove_file(&target)
                    .map_err(|err| format!("remove {}: {err}", target.display()))?;
            }
        }
        paths.push(e.path.clone());
    }
    Ok(paths)
}

fn add_and_commit(wt: &Path, p: &Proposal, paths: &[String]) -> Result<(), String> {
    let mut args: Vec<&str> = vec!["add", "-A", "--"];
    args.extend(paths.iter().map(|s| s.as_str()));
    git_ok(wt, &[], &[], &args, None)?;
    let msg = commit_message(p);
    git_ok(wt, &[], &[], &["commit", "-q", "-m", &msg], None)?;
    Ok(())
}

/// G1 operation: new worktree and branch at the base, edit, add, commit.
pub fn g1_op(clone: &Path, base: &str, wt_root: &Path, p: &Proposal) -> Result<PathBuf, String> {
    let wt = wt_root.join(format!("a{:03}-p{:05}", p.agent, p.index));
    let branch = proposal_branch(p.agent, p.index);
    git_ok(
        clone,
        &[],
        &[],
        &["worktree", "add", "-q", "-b", &branch, path_str(&wt)?, base],
        None,
    )?;
    let paths = apply_edits_to_worktree(&wt, p)?;
    add_and_commit(&wt, p, &paths)?;
    Ok(wt)
}

/// G2 setup: one detached worktree per agent at the base (counted as setup, not per op).
pub fn g2_setup_agent(
    clone: &Path,
    base: &str,
    wt_root: &Path,
    agent: usize,
) -> Result<PathBuf, String> {
    let wt = wt_root.join(format!("agent-{agent:03}"));
    git_ok(
        clone,
        &[],
        &[],
        &["worktree", "add", "-q", "--detach", path_str(&wt)?, base],
        None,
    )?;
    Ok(wt)
}

/// G2 operation: reset the agent's worktree to a new branch at the base, edit, add, commit.
pub fn g2_op(wt: &Path, base: &str, p: &Proposal) -> Result<(), String> {
    let branch = proposal_branch(p.agent, p.index);
    git_ok(wt, &[], &[], &["checkout", "-q", "-B", &branch, base], None)?;
    let paths = apply_edits_to_worktree(wt, p)?;
    add_and_commit(wt, p, &paths)
}

/// Per-agent state for the plumbing arms.
#[derive(Debug, Clone)]
pub struct PlumbingAgent {
    pub template_index: PathBuf,
    pub work_index: PathBuf,
    pub scratch_dir: PathBuf,
}

/// G3/G3F setup: build the agent's base index once with `git read-tree`.
pub fn g3_setup_agent(
    clone: &Path,
    base: &str,
    agent_root: &Path,
    agent: usize,
    config: &[(&str, &str)],
) -> Result<PlumbingAgent, String> {
    let dir = agent_root.join(format!("agent-{agent:03}"));
    let scratch_dir = dir.join("scratch");
    std::fs::create_dir_all(&scratch_dir)
        .map_err(|e| format!("mkdir {}: {e}", scratch_dir.display()))?;
    let template_index = dir.join("base.index");
    let env: [(&str, &OsStr); 1] = [("GIT_INDEX_FILE", template_index.as_os_str())];
    git_ok(clone, config, &env, &["read-tree", base], None)?;
    Ok(PlumbingAgent {
        template_index,
        work_index: dir.join("work.index"),
        scratch_dir,
    })
}

/// G3/G3F operation: build a commit for `p` without any working-tree checkout.
/// Returns the new commit OID (hex).
pub fn g3_op(
    clone: &Path,
    base: &str,
    agent: &PlumbingAgent,
    p: &Proposal,
    config: &[(&str, &str)],
) -> Result<String, String> {
    std::fs::copy(&agent.template_index, &agent.work_index)
        .map_err(|e| format!("copy base index: {e}"))?;
    let env: [(&str, &OsStr); 1] = [("GIT_INDEX_FILE", agent.work_index.as_os_str())];

    let mut scratch_paths = String::new();
    let mut upsert_meta: Vec<(&str, &str)> = Vec::new();
    for (n, e) in p.edits.iter().enumerate() {
        if let EditOp::Upsert { mode, content } = &e.op {
            let f = agent.scratch_dir.join(format!("blob-{n}"));
            std::fs::write(&f, content.as_slice())
                .map_err(|err| format!("write scratch {}: {err}", f.display()))?;
            scratch_paths.push_str(path_str(&f)?);
            scratch_paths.push('\n');
            upsert_meta.push((mode.git_octal_str(), e.path.as_str()));
        }
    }
    let oids: Vec<String> = if upsert_meta.is_empty() {
        Vec::new()
    } else {
        let out = git_ok(
            clone,
            config,
            &[],
            &["hash-object", "-w", "--no-filters", "--stdin-paths"],
            Some(scratch_paths.into_bytes()),
        )?;
        String::from_utf8_lossy(&out)
            .lines()
            .map(|l| l.trim().to_string())
            .collect()
    };
    if oids.len() != upsert_meta.len() {
        return Err(format!(
            "hash-object returned {} ids for {} blobs",
            oids.len(),
            upsert_meta.len()
        ));
    }

    let mut index_info = String::new();
    let mut oid_iter = oids.iter();
    let mut meta_iter = upsert_meta.iter();
    for e in &p.edits {
        match &e.op {
            EditOp::Upsert { .. } => {
                let (mode, path) = meta_iter.next().ok_or("upsert metadata underflow")?;
                let oid = oid_iter.next().ok_or("hash-object id underflow")?;
                index_info.push_str(&format!("{mode} {oid}\t{path}\n"));
            }
            EditOp::Delete => {
                index_info.push_str(&format!(
                    "0 0000000000000000000000000000000000000000\t{}\n",
                    e.path
                ));
            }
        }
    }
    git_ok(
        clone,
        config,
        &env,
        &["update-index", "--index-info"],
        Some(index_info.into_bytes()),
    )?;
    let tree = git_ok(clone, config, &env, &["write-tree"], None)?;
    let tree = String::from_utf8_lossy(&tree).trim().to_string();
    let msg = commit_message(p);
    let commit = git_ok(
        clone,
        config,
        &[],
        &["commit-tree", &tree, "-p", base, "-m", &msg],
        None,
    )?;
    let commit = String::from_utf8_lossy(&commit).trim().to_string();
    let refname = format!("refs/heads/{}", proposal_branch(p.agent, p.index));
    git_ok(clone, config, &[], &["update-ref", &refname, &commit], None)?;
    Ok(commit)
}

/// Remove every worktree directory under `wt_root` and prune their registrations.
pub fn remove_worktrees(clone: &Path, wt_root: &Path) -> Result<(), String> {
    if wt_root.exists() {
        std::fs::remove_dir_all(wt_root)
            .map_err(|e| format!("remove {}: {e}", wt_root.display()))?;
    }
    git_ok(clone, &[], &[], &["worktree", "prune"], None)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fixture::test_support::{make_fixture_repo, temp_dir};
    use crate::fixture::{
        clone_no_checkout, configure_bench_clone, list_base_tree, load_editable_files,
    };
    use crate::gitcmd::git_line;
    use crate::workload::generate_write_workload;

    #[test]
    fn all_git_arms_produce_identical_trees_for_the_same_proposal() {
        let root = temp_dir("git-arms");
        let commit = make_fixture_repo(&root, 10, 24);
        let clone = root.join("clone");
        clone_no_checkout(&root.join("fixture"), &clone).unwrap();
        configure_bench_clone(&clone).unwrap();
        let base = list_base_tree(&clone, &commit).unwrap();
        let files = load_editable_files(&clone, &base).unwrap();
        let work = generate_write_workload(11, 0, 1, 6, &files);

        let wt_root = root.join("g1");
        let agent_root = root.join("g3");
        let g2_wt = g2_setup_agent(&clone, &commit, &root.join("g2"), 0).unwrap();
        let plumbing = g3_setup_agent(&clone, &commit, &agent_root, 0, &[]).unwrap();
        let plumbing_f = g3_setup_agent(&clone, &commit, &agent_root, 1, FSYNC_ALL_CONFIG).unwrap();

        for p in &work[0] {
            let g1_wt = g1_op(&clone, &commit, &wt_root, p).unwrap();
            let g1_tree = git_line(&g1_wt, &["rev-parse", "HEAD^{tree}"]).unwrap();
            g2_op(&g2_wt, &commit, p).unwrap();
            let g2_tree = git_line(&g2_wt, &["rev-parse", "HEAD^{tree}"]).unwrap();
            let g3_commit = g3_op(&clone, &commit, &plumbing, p, &[]).unwrap();
            let g3_tree =
                git_line(&clone, &["rev-parse", &format!("{g3_commit}^{{tree}}")]).unwrap();
            let g3f_commit = g3_op(&clone, &commit, &plumbing_f, p, FSYNC_ALL_CONFIG).unwrap();
            let g3f_tree =
                git_line(&clone, &["rev-parse", &format!("{g3f_commit}^{{tree}}")]).unwrap();
            assert_eq!(g1_tree, g2_tree);
            assert_eq!(g2_tree, g3_tree);
            assert_eq!(g3_tree, g3f_tree);
        }
        remove_worktrees(&clone, &wt_root).unwrap();
        remove_worktrees(&clone, &root.join("g2")).unwrap();
        let listed = git_line(&clone, &["worktree", "list"]).unwrap();
        assert_eq!(listed.lines().count(), 1);
        let _ = std::fs::remove_dir_all(&root);
    }
}
