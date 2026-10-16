//! Tree and diff parity between Synapse and Git (ADR 0003 section 9 step 4, C1).
//!
//! Every comparison is per entry, not a count: a Synapse tree listing is rendered in the
//! exact line shape of `git ls-tree -r --full-tree` (`<mode> blob <oid>\t<path>`), and a
//! Synapse diff in the exact shape of `git diff-tree -r --raw --no-renames --no-abbrev`
//! (`:<old mode> <new mode> <old oid> <new oid> <status>\t<path>`), and both sides are
//! compared line for line, in order. Synapse answers come from the public signed `tree`
//! and `diff` APIs (all pages, one pinned snapshot), so the check covers what a client sees.
//!
//! The module also builds the small synthetic Git repository the CI tests use (the Gate 4
//! fixture is not available on CI runners) and applies [`Proposal`]s to both systems.

use crate::fixture::{self, configure_bench_clone};
use crate::git_arm;
use crate::gitcmd::{git_line, git_ok};
use crate::synapse_arm::{self, AgentIdentity, BenchIdentities};
use crate::workload::{EditOp, FileEdit, Proposal};
use std::path::{Path, PathBuf};
use synapse_api::{
    DiffEntry, DiffQueryPayload, PageRequest, PageResponse, SynapseService, TreeQueryPayload,
    TreeTarget, VirtualTreeEntry, DEFAULT_MAX_PAGE_SIZE,
};
use synapse_core::{ChangesetId, GitOid, WalSeq};
use synapse_store::{FsyncPolicy, IngestOutcome, RecoveryPolicy};

const ZERO_MODE: &str = "000000";
const ZERO_OID: &str = "0000000000000000000000000000000000000000";

/// First differing line of a parity comparison (or a length difference).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParityMismatch {
    pub index: usize,
    pub git: Option<String>,
    pub synapse: Option<String>,
}

/// Compare two line lists in order; `None` when equal.
pub fn first_mismatch(git: &[String], synapse: &[String]) -> Option<ParityMismatch> {
    let n = git.len().max(synapse.len());
    (0..n)
        .find(|&i| git.get(i) != synapse.get(i))
        .map(|i| ParityMismatch {
            index: i,
            git: git.get(i).cloned(),
            synapse: synapse.get(i).cloned(),
        })
}

fn split_nul(bytes: &[u8]) -> Result<Vec<String>, String> {
    bytes
        .split(|&b| b == 0)
        .filter(|s| !s.is_empty())
        .map(|s| String::from_utf8(s.to_vec()).map_err(|e| format!("non UTF-8 git output: {e}")))
        .collect()
}

/// `git ls-tree -r -z --full-tree <rev>` as `<mode> <type> <oid>\t<path>` lines.
pub fn git_ls_tree_r(repo: &Path, rev: &str) -> Result<Vec<String>, String> {
    let out = git_ok(
        repo,
        &[],
        &[],
        &["ls-tree", "-r", "-z", "--full-tree", rev],
        None,
    )?;
    split_nul(&out)
}

/// `git diff-tree -r -z --raw --no-renames --no-abbrev <old> <new>` as
/// `:<old mode> <new mode> <old oid> <new oid> <status>\t<path>` lines.
pub fn git_diff_tree_raw(repo: &Path, old: &str, new: &str) -> Result<Vec<String>, String> {
    let out = git_ok(
        repo,
        &[],
        &[],
        &[
            "diff-tree",
            "-r",
            "-z",
            "--raw",
            "--no-renames",
            "--no-abbrev",
            old,
            new,
        ],
        None,
    )?;
    // With -z each record is `:<meta>\0<path>\0`.
    let fields = split_nul(&out)?;
    if fields.len() % 2 != 0 {
        return Err(format!("odd diff-tree -z field count {}", fields.len()));
    }
    Ok(fields
        .chunks(2)
        .map(|c| format!("{}\t{}", c[0], c[1]))
        .collect())
}

/// One Synapse tree entry in `git ls-tree -r` line shape.
pub fn ls_tree_line(e: &VirtualTreeEntry) -> String {
    format!(
        "{} blob {}\t{}",
        e.mode.git_octal_str(),
        e.git_blob_oid.to_hex(),
        e.path
    )
}

/// One Synapse diff entry in `git diff-tree --raw` line shape.
pub fn diff_tree_line(d: &DiffEntry) -> String {
    let side = |e: &Option<VirtualTreeEntry>| match e {
        Some(e) => (e.mode.git_octal_str().to_string(), e.git_blob_oid.to_hex()),
        None => (ZERO_MODE.to_string(), ZERO_OID.to_string()),
    };
    let (om, oo) = side(&d.old_entry);
    let (nm, no) = side(&d.new_entry);
    format!(
        ":{om} {nm} {oo} {no} {}\t{}",
        d.status.git_status_char(),
        d.path
    )
}

/// A reader that issues signed `tree` and `diff` requests and collects every page.
pub struct ApiReader<'a> {
    pub agent: &'a AgentIdentity,
    pub ids: &'a BenchIdentities,
    pub counter: u64,
}

impl ApiReader<'_> {
    fn pages<P, T>(
        &mut self,
        svc: &mut SynapseService,
        make: impl Fn(PageRequest) -> P,
        api: fn(
            &mut SynapseService,
            &synapse_auth::AuthenticatedRequest<P>,
            u64,
        ) -> synapse_core::SynapseResult<PageResponse<T>>,
    ) -> Result<Vec<T>, String>
    where
        P: serde::Serialize,
    {
        let mut cursor: Option<String> = None;
        let mut snapshot: Option<WalSeq> = None;
        let mut items = Vec::new();
        loop {
            self.counter += 1;
            let now = crate::unix_now_ms();
            let page = PageRequest {
                cursor: cursor.clone(),
                limit: DEFAULT_MAX_PAGE_SIZE,
                min_visible_seq: None,
                snapshot_seq: snapshot,
            };
            let req = synapse_arm::build_read_request(
                self.agent,
                &self.ids.repo_id,
                make(page),
                &format!("c1/parity/{}", self.counter),
                now,
            )?;
            let resp = api(svc, &req, now).map_err(|e| e.to_string())?;
            snapshot = Some(resp.snapshot_seq);
            items.extend(resp.items);
            match resp.next_cursor {
                Some(next) => cursor = Some(next),
                None => return Ok(items),
            }
        }
    }

    /// Every entry of `target` through the paginated `tree` API, as `ls-tree -r` lines.
    pub fn ls_tree_r(
        &mut self,
        svc: &mut SynapseService,
        target: TreeTarget,
    ) -> Result<Vec<String>, String> {
        let entries = self.pages(
            svc,
            |page| TreeQueryPayload {
                target,
                path_prefix: None,
                page,
            },
            |svc, req, now| svc.tree(req, now),
        )?;
        Ok(entries.iter().map(ls_tree_line).collect())
    }

    /// Every entry of `base -> target` through the paginated `diff` API, as raw diff lines.
    pub fn diff_tree_raw(
        &mut self,
        svc: &mut SynapseService,
        base: TreeTarget,
        target: TreeTarget,
    ) -> Result<Vec<String>, String> {
        let entries = self.pages(
            svc,
            |page| DiffQueryPayload { base, target, page },
            |svc, req, now| svc.diff(req, now),
        )?;
        Ok(entries.iter().map(diff_tree_line).collect())
    }
}

/// A Synapse service and a Git clone holding the same base commit and proposals.
pub struct ParityPair {
    pub clone: PathBuf,
    pub base_commit: String,
    pub base_oid: GitOid,
    pub ids: BenchIdentities,
    pub svc: SynapseService,
    plumbing: git_arm::PlumbingAgent,
    work: PathBuf,
    submitted: u64,
}

impl ParityPair {
    /// Open a fresh Synapse store under `work`, register `base_commit` of `clone` as the base
    /// tree, and prepare the Git plumbing index used to commit proposals.
    pub fn open(
        clone: &Path,
        base_commit: &str,
        work: &Path,
        seed: u64,
        agents: usize,
    ) -> Result<Self, String> {
        let base = fixture::list_base_tree(clone, base_commit)?;
        let full = fixture::load_full_base(clone, &base)?;
        let ids = synapse_arm::issue_identities(seed, agents.max(1), crate::unix_now_ms())?;
        let mut svc = synapse_arm::open_service(
            &work.join("synapse-store"),
            &ids,
            FsyncPolicy::BatchWindow { max_records: 1024 },
            RecoveryPolicy::StrictFailClosed,
        )?;
        let base_oid = synapse_arm::register_base(&mut svc, base_commit, full)?;
        let plumbing = git_arm::g3_setup_agent(clone, base_commit, &work.join("plumbing"), 0, &[])?;
        Ok(Self {
            clone: clone.to_path_buf(),
            base_commit: base_commit.to_string(),
            base_oid,
            ids,
            svc,
            plumbing,
            work: work.to_path_buf(),
            submitted: 0,
        })
    }

    /// Submit `p` to Synapse (agent `p.agent`) and commit it to Git on the base commit.
    /// Returns the changeset id and the Git commit id.
    pub fn apply(&mut self, p: &Proposal) -> Result<(ChangesetId, String), String> {
        self.submitted += 1;
        let label = format!(
            "c1/parity/submit/{}/{}",
            self.work.display(),
            self.submitted
        );
        let now = crate::unix_now_ms();
        let agent = &self.ids.agents[p.agent % self.ids.agents.len()];
        let req = synapse_arm::build_submit_request(
            agent,
            &self.ids.repo_id,
            self.base_oid,
            p,
            &label,
            now,
        )?;
        let cs = match self.svc.submit(&req, now).map_err(|e| e.to_string())? {
            IngestOutcome::Committed { changeset_id, .. }
            | IngestOutcome::IdempotentDuplicate { changeset_id, .. } => changeset_id,
        };
        let commit = git_arm::g3_op(&self.clone, &self.base_commit, &self.plumbing, p, &[])?;
        Ok((cs, commit))
    }

    /// `git ls-tree -r <commit>` and the Synapse `tree` listing of `target`.
    pub fn tree_pair(
        &mut self,
        target: TreeTarget,
        commit: &str,
    ) -> Result<(Vec<String>, Vec<String>), String> {
        let git = git_ls_tree_r(&self.clone, commit)?;
        let mut reader = ApiReader {
            agent: &self.ids.agents[0],
            ids: &self.ids,
            counter: self.submitted * 1_000_000,
        };
        let syn = reader.ls_tree_r(&mut self.svc, target)?;
        Ok((git, syn))
    }

    /// `git diff-tree -r --raw <base> <commit>` and the Synapse `diff` from the base tree.
    pub fn diff_pair(
        &mut self,
        target: TreeTarget,
        commit: &str,
    ) -> Result<(Vec<String>, Vec<String>), String> {
        let git = git_diff_tree_raw(&self.clone, &self.base_commit, commit)?;
        let base = TreeTarget::BaseGitCommit(self.base_oid);
        let mut reader = ApiReader {
            agent: &self.ids.agents[0],
            ids: &self.ids,
            counter: self.submitted * 1_000_000 + 500_000,
        };
        let syn = reader.diff_tree_raw(&mut self.svc, base, target)?;
        Ok((git, syn))
    }
}

/// Build a synthetic repository at `<root>/fixture` with nested directories, an executable,
/// a symlink, names that test Git's directory ordering (`a-b`, `a.c`, `a/`), and `n_files`
/// text files of `lines` lines (each at least the Gate 4 editable size). Returns the commit.
pub fn synthetic_fixture(root: &Path, n_files: usize, lines: usize) -> Result<String, String> {
    let repo = root.join("fixture");
    let mkdir = |p: &Path| std::fs::create_dir_all(p).map_err(|e| format!("mkdir: {e}"));
    let write = |p: &Path, b: &[u8]| std::fs::write(p, b).map_err(|e| format!("write: {e}"));
    for d in ["src/nested/deep", "docs", "a"] {
        mkdir(&repo.join(d))?;
    }
    git_ok(&repo, &[], &[], &["init", "-q", "-b", "main"], None)?;
    configure_bench_clone(&repo)?;
    for i in 0..n_files {
        let mut body = String::new();
        for l in 0..lines {
            body.push_str(&format!("synthetic file {i} line {l} with padding text\n"));
        }
        let path = match i % 4 {
            0 => repo.join(format!("src/nested/file{i:03}.txt")),
            1 => repo.join(format!("src/nested/deep/file{i:03}.txt")),
            2 => repo.join(format!("docs/page{i:03}.md")),
            _ => repo.join(format!("src/file{i:03}.txt")),
        };
        write(&path, body.as_bytes())?;
    }
    write(&repo.join("a/inner.txt"), b"inside a/\n")?;
    write(&repo.join("a-b"), b"dash sorts before slash\n")?;
    write(&repo.join("a.c"), b"dot sorts before slash\n")?;
    write(&repo.join("run.sh"), b"#!/bin/sh\necho synthetic\n")?;
    let mut perm = std::fs::metadata(repo.join("run.sh"))
        .map_err(|e| e.to_string())?
        .permissions();
    std::os::unix::fs::PermissionsExt::set_mode(&mut perm, 0o755);
    std::fs::set_permissions(repo.join("run.sh"), perm).map_err(|e| e.to_string())?;
    std::os::unix::fs::symlink("run.sh", repo.join("link")).map_err(|e| e.to_string())?;
    git_ok(&repo, &[], &[], &["add", "-A"], None)?;
    git_ok(
        &repo,
        &[],
        &[],
        &["commit", "-q", "-m", "synthetic C1 base"],
        None,
    )?;
    git_line(&repo, &["rev-parse", "HEAD"])
}

/// A unique temporary directory for one test.
pub fn temp_dir(label: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "synapse-c1-{label}-{}-{}",
        std::process::id(),
        crate::unix_now_ms()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::fs::create_dir_all(&dir);
    dir
}

fn upsert(path: &str, mode: synapse_core::FileMode, content: &[u8]) -> FileEdit {
    FileEdit {
        path: path.to_string(),
        op: EditOp::Upsert {
            mode,
            content: std::sync::Arc::new(content.to_vec()),
        },
    }
}

fn delete(path: &str) -> FileEdit {
    FileEdit {
        path: path.to_string(),
        op: EditOp::Delete,
    }
}

/// Hand-written proposals that cover every raw diff status Git can produce without rename
/// detection, against [`synthetic_fixture`]: add, modify, delete, mode change (`M`),
/// symlink to file and file to symlink (`T`), file replaced by a directory and directory
/// replaced by a file (`D` plus `A`), and new nested directories.
pub fn edge_case_proposals() -> Vec<Proposal> {
    use synapse_core::FileMode::{Regular644, Symlink120000};
    let p = |index: usize, summary: &str, mut edits: Vec<FileEdit>| {
        edits.sort_by(|a, b| a.path.cmp(&b.path));
        Proposal {
            agent: index % 2,
            index,
            summary: summary.to_string(),
            edits,
        }
    };
    vec![
        p(
            0,
            "add modify delete",
            vec![
                upsert("new/dir/file.txt", Regular644, b"brand new\n"),
                upsert("a-b", Regular644, b"modified dash file\n"),
                delete("a.c"),
            ],
        ),
        p(
            1,
            "mode change only (run.sh is executable in the base)",
            vec![upsert("run.sh", Regular644, b"#!/bin/sh\necho synthetic\n")],
        ),
        p(
            2,
            "symlink becomes a regular file",
            vec![upsert("link", Regular644, b"run.sh")],
        ),
        p(
            3,
            "regular file becomes a symlink",
            vec![upsert("a-b", Symlink120000, b"a.c")],
        ),
        p(
            4,
            "file replaced by a directory",
            vec![
                delete("a.c"),
                upsert("a.c/child.txt", Regular644, b"child\n"),
            ],
        ),
        p(
            5,
            "directory replaced by a file",
            vec![
                delete("a/inner.txt"),
                upsert("a", Regular644, b"a is a file now\n"),
            ],
        ),
        p(
            6,
            "upsert below an existing file",
            vec![upsert(
                "a-b/under.txt",
                Regular644,
                b"git replaces the file\n",
            )],
        ),
        p(
            7,
            "upsert over an existing directory",
            vec![upsert("docs", Regular644, b"git replaces the directory\n")],
        ),
    ]
}
