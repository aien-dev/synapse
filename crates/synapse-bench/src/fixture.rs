//! Representative fixture handling: isolated clones of a pinned real repository,
//! base tree listing, and bulk blob loading through a persistent `git cat-file --batch`.
//!
//! The original fixture repository is only ever read by `git clone --local`, which
//! hardlinks or copies its object files into a new directory. Every measurement then
//! runs against that private clone (or a clone of it).

use crate::gitcmd::{git_line, git_ok};
use crate::path_str;
use std::io::{BufRead, BufReader, Read, Write};
use std::path::Path;
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::sync::Arc;
use synapse_core::FileMode;

/// Directory prefix for files that the synthetic workloads add to the fixture.
pub const BENCH_PATH_PREFIX: &str = "synapse-gate4-bench";

/// Smallest and largest file sizes eligible for synthetic edits.
pub const EDITABLE_MIN_BYTES: u64 = 256;
pub const EDITABLE_MAX_BYTES: u64 = 64 * 1024;
/// Minimum line count for an editable file.
pub const EDITABLE_MIN_LINES: usize = 8;

/// One file entry of the pinned base commit tree.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BaseEntry {
    pub path: String,
    pub mode: FileMode,
    pub git_oid_hex: String,
    pub size_bytes: u64,
}

/// The pinned base commit and its file entries.
#[derive(Debug, Clone)]
pub struct BaseTree {
    pub commit_hex: String,
    pub tree_hex: String,
    pub entries: Vec<BaseEntry>,
    /// Entries skipped because their mode is not a regular file, executable, or symlink
    /// (the same filter `SynapseService::import_base_tree_from_git_repo` applies).
    pub skipped_entries: usize,
}

impl BaseTree {
    pub fn total_bytes(&self) -> u64 {
        self.entries.iter().map(|e| e.size_bytes).sum()
    }
}

/// A text file from the base tree that synthetic proposals may modify or delete.
#[derive(Debug, Clone)]
pub struct EditableFile {
    pub path: String,
    pub content: Arc<Vec<u8>>,
    pub line_count: usize,
}

/// `git clone --no-checkout --local --quiet <src> <dest>`.
pub fn clone_no_checkout(src: &Path, dest: &Path) -> Result<(), String> {
    let parent = dest
        .parent()
        .ok_or_else(|| format!("clone destination has no parent: {}", dest.display()))?;
    std::fs::create_dir_all(parent).map_err(|e| format!("create {}: {e}", parent.display()))?;
    git_ok(
        parent,
        &[],
        &[],
        &[
            "clone",
            "--no-checkout",
            "--local",
            "--quiet",
            path_str(src)?,
            path_str(dest)?,
        ],
        None,
    )?;
    Ok(())
}

/// Repository-local settings applied to every benchmark clone. Automatic `gc` and
/// maintenance are disabled so that no arm pays for (or skips) a background repack.
pub const BENCH_CLONE_CONFIG: &[(&str, &str)] = &[
    ("gc.auto", "0"),
    ("maintenance.auto", "false"),
    ("user.name", "Synapse Gate4 Bench"),
    ("user.email", "gate4-bench@synapse.invalid"),
    ("commit.gpgsign", "false"),
];

/// Apply [`BENCH_CLONE_CONFIG`] to `clone`.
pub fn configure_bench_clone(clone: &Path) -> Result<(), String> {
    for (k, v) in BENCH_CLONE_CONFIG {
        git_ok(clone, &[], &[], &["config", k, v], None)?;
    }
    Ok(())
}

/// Resolve `rev` and list its tree (`git ls-tree -r -z -l`).
pub fn list_base_tree(repo: &Path, rev: &str) -> Result<BaseTree, String> {
    let commit_hex = git_line(
        repo,
        &["rev-parse", "--verify", &format!("{rev}^{{commit}}")],
    )?;
    let tree_hex = git_line(repo, &["rev-parse", "--verify", &format!("{rev}^{{tree}}")])?;
    let out = git_ok(
        repo,
        &[],
        &[],
        &["ls-tree", "-r", "-z", "-l", &commit_hex],
        None,
    )?;
    let mut entries = Vec::new();
    let mut skipped = 0usize;
    for record in out.split(|&b| b == 0) {
        if record.is_empty() {
            continue;
        }
        let text =
            std::str::from_utf8(record).map_err(|e| format!("non-UTF-8 ls-tree record: {e}"))?;
        let (meta, path) = text
            .split_once('\t')
            .ok_or_else(|| format!("malformed ls-tree record: {text}"))?;
        let cols: Vec<&str> = meta.split_whitespace().collect();
        if cols.len() < 4 {
            return Err(format!("malformed ls-tree metadata: {meta}"));
        }
        let mode = match cols[0] {
            "100644" => FileMode::Regular644,
            "100755" => FileMode::Executable755,
            "120000" => FileMode::Symlink120000,
            _ => {
                skipped += 1;
                continue;
            }
        };
        let size_bytes = cols[3]
            .parse::<u64>()
            .map_err(|e| format!("bad ls-tree size {}: {e}", cols[3]))?;
        entries.push(BaseEntry {
            path: path.to_string(),
            mode,
            git_oid_hex: cols[2].to_string(),
            size_bytes,
        });
    }
    Ok(BaseTree {
        commit_hex,
        tree_hex,
        entries,
        skipped_entries: skipped,
    })
}

/// A persistent `git cat-file --batch` process (one spawn, many object reads).
pub struct CatFileBatch {
    child: Child,
    stdin: Option<ChildStdin>,
    stdout: BufReader<ChildStdout>,
}

impl CatFileBatch {
    pub fn spawn(repo: &Path) -> Result<Self, String> {
        let mut child = Command::new("git")
            .arg("-C")
            .arg(repo)
            .args(["cat-file", "--batch"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|e| format!("spawn git cat-file --batch: {e}"))?;
        let stdin = child.stdin.take().ok_or("cat-file stdin unavailable")?;
        let stdout = child.stdout.take().ok_or("cat-file stdout unavailable")?;
        Ok(Self {
            child,
            stdin: Some(stdin),
            stdout: BufReader::new(stdout),
        })
    }

    /// Read one object named by `spec` (an OID or `<rev>:<path>`).
    pub fn read(&mut self, spec: &str) -> Result<Vec<u8>, String> {
        let stdin = self.stdin.as_mut().ok_or("cat-file stdin already closed")?;
        stdin
            .write_all(format!("{spec}\n").as_bytes())
            .and_then(|_| stdin.flush())
            .map_err(|e| format!("write cat-file request: {e}"))?;
        let mut header = String::new();
        self.stdout
            .read_line(&mut header)
            .map_err(|e| format!("read cat-file header: {e}"))?;
        let header = header.trim_end();
        if header.ends_with(" missing") || header.ends_with(" ambiguous") || header.is_empty() {
            return Err(format!("cat-file could not resolve {spec}: {header}"));
        }
        let size: usize = header
            .rsplit(' ')
            .next()
            .and_then(|s| s.parse().ok())
            .ok_or_else(|| format!("malformed cat-file header: {header}"))?;
        let mut buf = vec![0u8; size + 1];
        self.stdout
            .read_exact(&mut buf)
            .map_err(|e| format!("read cat-file body for {spec}: {e}"))?;
        buf.truncate(size);
        Ok(buf)
    }

    /// Close stdin and wait for the process so its CPU time is counted in `RUSAGE_CHILDREN`.
    pub fn finish(mut self) -> Result<(), String> {
        drop(self.stdin.take());
        let status = self
            .child
            .wait()
            .map_err(|e| format!("wait cat-file: {e}"))?;
        if status.success() {
            Ok(())
        } else {
            Err(format!("git cat-file --batch exited with {status}"))
        }
    }
}

/// Load the bytes of `entries` (in order) through one `git cat-file --batch` process.
pub fn load_blobs(repo: &Path, entries: &[&BaseEntry]) -> Result<Vec<Vec<u8>>, String> {
    let mut batch = CatFileBatch::spawn(repo)?;
    let mut out = Vec::with_capacity(entries.len());
    for e in entries {
        out.push(batch.read(&e.git_oid_hex)?);
    }
    batch.finish()?;
    Ok(out)
}

/// Load every base entry as `(path, mode, bytes)` for `SynapseService::register_base_tree`.
pub fn load_full_base(
    repo: &Path,
    base: &BaseTree,
) -> Result<Vec<(String, FileMode, Vec<u8>)>, String> {
    let refs: Vec<&BaseEntry> = base.entries.iter().collect();
    let blobs = load_blobs(repo, &refs)?;
    Ok(base
        .entries
        .iter()
        .zip(blobs)
        .map(|(e, b)| (e.path.clone(), e.mode, b))
        .collect())
}

fn editable_from_bytes(path: &str, bytes: &[u8]) -> Option<EditableFile> {
    if bytes.contains(&0) {
        return None;
    }
    let text = std::str::from_utf8(bytes).ok()?;
    let line_count = text.lines().count();
    if line_count < EDITABLE_MIN_LINES {
        return None;
    }
    Some(EditableFile {
        path: path.to_string(),
        content: Arc::new(bytes.to_vec()),
        line_count,
    })
}

fn is_editable_candidate(e: &BaseEntry) -> bool {
    e.mode == FileMode::Regular644
        && (EDITABLE_MIN_BYTES..=EDITABLE_MAX_BYTES).contains(&e.size_bytes)
        && !e.path.starts_with(BENCH_PATH_PREFIX)
}

/// Select editable text files (sorted by path) by loading only size-eligible candidates.
pub fn load_editable_files(repo: &Path, base: &BaseTree) -> Result<Vec<EditableFile>, String> {
    let candidates: Vec<&BaseEntry> = base
        .entries
        .iter()
        .filter(|e| is_editable_candidate(e))
        .collect();
    let blobs = load_blobs(repo, &candidates)?;
    let mut files: Vec<EditableFile> = candidates
        .iter()
        .zip(blobs.iter())
        .filter_map(|(e, b)| editable_from_bytes(&e.path, b))
        .collect();
    files.sort_by(|a, b| a.path.cmp(&b.path));
    Ok(files)
}

/// Select editable files from an already loaded full base (same rule as [`load_editable_files`]).
pub fn editable_from_full_base(
    base: &BaseTree,
    full: &[(String, FileMode, Vec<u8>)],
) -> Vec<EditableFile> {
    let mut files: Vec<EditableFile> = base
        .entries
        .iter()
        .zip(full.iter())
        .filter(|(e, _)| is_editable_candidate(e))
        .filter_map(|(e, (_, _, bytes))| editable_from_bytes(&e.path, bytes))
        .collect();
    files.sort_by(|a, b| a.path.cmp(&b.path));
    files
}

#[cfg(test)]
pub mod test_support {
    //! Small synthetic Git fixture for unit tests (no network, no external repository).
    use super::*;

    /// Create a repository with `n_files` text files of `lines` lines each plus a
    /// nested directory and an executable script, committed on branch `main`.
    pub fn make_fixture_repo(root: &Path, n_files: usize, lines: usize) -> String {
        let repo = root.join("fixture");
        std::fs::create_dir_all(repo.join("src/nested")).unwrap();
        git_ok(&repo, &[], &[], &["init", "-q", "-b", "main"], None).unwrap();
        configure_bench_clone(&repo).unwrap();
        for i in 0..n_files {
            let mut body = String::new();
            for l in 0..lines {
                body.push_str(&format!(
                    "fixture file {i} line {l} with some padding text\n"
                ));
            }
            let path = if i % 3 == 0 {
                repo.join(format!("src/nested/file{i:02}.txt"))
            } else {
                repo.join(format!("src/file{i:02}.txt"))
            };
            std::fs::write(path, body).unwrap();
        }
        std::fs::write(repo.join("run.sh"), "#!/bin/sh\necho fixture\n").unwrap();
        let mut perm = std::fs::metadata(repo.join("run.sh"))
            .unwrap()
            .permissions();
        std::os::unix::fs::PermissionsExt::set_mode(&mut perm, 0o755);
        std::fs::set_permissions(repo.join("run.sh"), perm).unwrap();
        git_ok(&repo, &[], &[], &["add", "-A"], None).unwrap();
        git_ok(
            &repo,
            &[],
            &[],
            &["commit", "-q", "-m", "fixture base"],
            None,
        )
        .unwrap();
        git_line(&repo, &["rev-parse", "HEAD"]).unwrap()
    }

    pub fn temp_dir(label: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "synapse-bench-test-{label}-{}-{}",
            std::process::id(),
            crate::unix_now_ms()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }
}

#[cfg(test)]
mod tests {
    use super::test_support::*;
    use super::*;

    #[test]
    fn list_and_load_match_git_object_ids() {
        let root = temp_dir("fixture");
        let commit = make_fixture_repo(&root, 6, 20);
        let repo = root.join("fixture");
        let base = list_base_tree(&repo, &commit).unwrap();
        assert_eq!(base.commit_hex, commit);
        assert_eq!(base.entries.len(), 7);
        let full = load_full_base(&repo, &base).unwrap();
        for (entry, (_, _, bytes)) in base.entries.iter().zip(full.iter()) {
            assert_eq!(
                synapse_core::GitOid::compute_blob(bytes).to_hex(),
                entry.git_oid_hex
            );
        }
        let editable = load_editable_files(&repo, &base).unwrap();
        assert_eq!(editable.len(), 6);
        assert_eq!(editable_from_full_base(&base, &full).len(), 6);
        let _ = std::fs::remove_dir_all(&root);
    }
}
