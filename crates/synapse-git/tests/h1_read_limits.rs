//! ADR 0003 step H1 (issue #48): the configurable read limits of the native Git reader
//! (`ReadLimits`, review of PR #90 finding B2). The system `git` only builds fixture history.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use synapse_core::RefusalCode;
use synapse_git::{GitRepository, ReadLimits};

fn temp_dir(label: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "synapse-h1-limits-{label}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    fs::create_dir_all(&dir).unwrap();
    dir
}

fn git(dir: &Path, args: &[&str]) -> String {
    let out = Command::new("git")
        .arg("-C")
        .arg(dir)
        .args(args)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_AUTHOR_NAME", "Fixture Author")
        .env("GIT_AUTHOR_EMAIL", "author@fixture.invalid")
        .env("GIT_AUTHOR_DATE", "1700000000 +0000")
        .env("GIT_COMMITTER_NAME", "Fixture Committer")
        .env("GIT_COMMITTER_EMAIL", "committer@fixture.invalid")
        .env("GIT_COMMITTER_DATE", "1700000000 +0000")
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "git {args:?} failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8(out.stdout).unwrap().trim().to_string()
}

/// A repository with a few commits; packed (`git gc`) or loose. Returns its `.git` directory
/// and the total size of its reachable objects as Git reports it.
fn repo(label: &str, packed: bool) -> (PathBuf, u64) {
    let work = temp_dir(label);
    git(&work, &["init", "-q", "-b", "main"]);
    for i in 0..4 {
        fs::write(work.join("f.txt"), format!("version {i}\n").repeat(200)).unwrap();
        git(&work, &["add", "-A"]);
        git(&work, &["commit", "-q", "-m", &format!("c{i}")]);
    }
    if packed {
        git(&work, &["gc", "-q", "--aggressive", "--prune=now"]);
    }
    let sizes = git(
        &work,
        &[
            "cat-file",
            "--batch-all-objects",
            "--batch-check=%(objectsize)",
        ],
    );
    let total = sizes.lines().map(|l| l.parse::<u64>().unwrap()).sum();
    (work.join(".git"), total)
}

fn code_of(git_dir: &Path, limits: ReadLimits) -> Option<RefusalCode> {
    GitRepository::open_with_limits(git_dir, limits)
        .and_then(|mut r| r.full_history())
        .err()
        .map(|e| e.code)
}

#[test]
fn h1_total_object_budget_is_enforced_for_packed_and_loose_objects() {
    for packed in [true, false] {
        let (dir, total) = repo(
            if packed {
                "budget-packed"
            } else {
                "budget-loose"
            },
            packed,
        );
        let fits = ReadLimits {
            max_total_object_bytes: total,
            ..ReadLimits::default()
        };
        assert_eq!(code_of(&dir, fits), None, "packed={packed}: exact budget");
        let short = ReadLimits {
            max_total_object_bytes: total - 1,
            ..ReadLimits::default()
        };
        assert_eq!(
            code_of(&dir, short),
            Some(RefusalCode::QuotaPayloadTooLarge),
            "packed={packed}: one byte short"
        );
    }
}

#[test]
fn h1_per_object_cap_is_enforced_for_packed_and_loose_objects() {
    for packed in [true, false] {
        let (dir, _) = repo(if packed { "cap-packed" } else { "cap-loose" }, packed);
        let limits = ReadLimits {
            max_object_bytes: 100,
            ..ReadLimits::default()
        };
        assert_eq!(
            code_of(&dir, limits),
            Some(RefusalCode::QuotaPayloadTooLarge),
            "packed={packed}"
        );
    }
}

#[test]
fn h1_pack_file_and_ref_file_caps_are_enforced() {
    let (dir, _) = repo("file-caps", true);
    let limits = ReadLimits {
        max_pack_files_bytes: 64,
        ..ReadLimits::default()
    };
    assert_eq!(
        code_of(&dir, limits),
        Some(RefusalCode::QuotaPayloadTooLarge)
    );
    let limits = ReadLimits {
        max_packed_refs_bytes: 8,
        ..ReadLimits::default()
    };
    assert_eq!(
        code_of(&dir, limits),
        Some(RefusalCode::QuotaPayloadTooLarge),
        "packed-refs over its cap"
    );
    let limits = ReadLimits {
        max_ref_file_bytes: 8,
        ..ReadLimits::default()
    };
    assert_eq!(
        code_of(&dir, limits),
        Some(RefusalCode::QuotaPayloadTooLarge),
        "HEAD over its cap"
    );
}

#[test]
fn h1_lock_files_under_refs_are_skipped() {
    let (dir, _) = repo("lock", false);
    let tip = fs::read_to_string(dir.join("refs/heads/main")).unwrap();
    fs::write(dir.join("refs/heads/main.lock"), tip).unwrap();
    let mut r = GitRepository::open(&dir).unwrap();
    let (refs, _) = r.refs().unwrap();
    assert_eq!(refs.keys().collect::<Vec<_>>(), ["refs/heads/main"]);
    r.full_history().unwrap();
}
