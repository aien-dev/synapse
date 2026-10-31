//! Fixture helpers shared by the H1 tests (issue #48). The system `git` is used only as an
//! independent oracle and fixture builder.
#![allow(dead_code)]

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use synapse_core::GitOid;
use synapse_git::{GitHistory, GitObject};

pub fn temp_dir(label: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "synapse-h1-{label}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    fs::create_dir_all(&dir).unwrap();
    dir
}

/// Run `git -C dir args` with no user or system configuration and fixed identities and dates,
/// so fixture history is the same on every host.
pub fn git_raw(dir: &Path, args: &[&str], stdin: Option<&[u8]>) -> Output {
    let mut cmd = Command::new("git");
    cmd.arg("-C")
        .arg(dir)
        .args(args)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_AUTHOR_NAME", "Fixture Author")
        .env("GIT_AUTHOR_EMAIL", "author@fixture.invalid")
        .env("GIT_AUTHOR_DATE", "1700000000 +0000")
        .env("GIT_COMMITTER_NAME", "Fixture Committer")
        .env("GIT_COMMITTER_EMAIL", "committer@fixture.invalid")
        .env("GIT_COMMITTER_DATE", "1700000000 +0000");
    if let Some(input) = stdin {
        use std::io::Write;
        cmd.stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped());
        let mut child = cmd.spawn().unwrap();
        child.stdin.take().unwrap().write_all(input).unwrap();
        child.wait_with_output().unwrap()
    } else {
        cmd.output().unwrap()
    }
}

pub fn git(dir: &Path, args: &[&str]) -> Vec<u8> {
    let out = git_raw(dir, args, None);
    assert!(
        out.status.success(),
        "git {args:?} failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    out.stdout
}

pub fn git_text(dir: &Path, args: &[&str]) -> String {
    String::from_utf8(git(dir, args))
        .unwrap()
        .trim()
        .to_string()
}

pub fn write(dir: &Path, rel: &str, bytes: &[u8]) {
    let path = dir.join(rel);
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, bytes).unwrap();
}

pub fn commit_all(dir: &Path, msg: &str) {
    git(dir, &["add", "-A"]);
    git(dir, &["commit", "-q", "--allow-empty", "-m", msg]);
}

/// Deterministic pseudo-random bytes (xorshift), so the binary blob is incompressible.
pub fn noise(len: usize, seed: u64) -> Vec<u8> {
    let mut x = seed | 1;
    (0..len)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x as u8
        })
        .collect()
}

/// Real Git history with every shape the bridge must carry: nested trees, executable files,
/// a symlink, an empty file, an incompressible binary, a large compressible file revised many
/// times (delta material), a two-parent merge, an octopus merge, an empty commit, annotated
/// tags of a commit, a tree, a blob and another tag, a lightweight tag, and a commit with a
/// multi-line signature header and an `encoding` header.
pub fn build_fixture(dir: &Path) {
    git(dir, &["init", "-q", "-b", "main"]);
    let mut big = String::new();
    for i in 0..6000 {
        big.push_str(&format!(
            "line {i}: the quick brown fox jumps over the lazy dog\n"
        ));
    }
    write(dir, "README.md", b"# fixture\n");
    write(dir, "src/lib.rs", b"pub fn one() -> u32 { 1 }\n");
    write(dir, "src/deep/nested/mod.rs", b"// nested\n");
    write(dir, "data/empty.txt", b"");
    write(dir, "data/noise.bin", &noise(40_000, 7));
    write(dir, "docs/big.txt", big.as_bytes());
    write(dir, "tools/run.sh", b"#!/bin/sh\necho run\n");
    let mut perms = fs::metadata(dir.join("tools/run.sh"))
        .unwrap()
        .permissions();
    std::os::unix::fs::PermissionsExt::set_mode(&mut perms, 0o755);
    fs::set_permissions(dir.join("tools/run.sh"), perms).unwrap();
    std::os::unix::fs::symlink("../README.md", dir.join("docs/readme-link")).unwrap();
    commit_all(dir, "initial");
    for rev in 0..12 {
        let edited = big.replace(
            &format!("line {}:", rev * 400),
            &format!("LINE {} (rev {rev}):", rev * 400),
        );
        write(dir, "docs/big.txt", edited.as_bytes());
        write(
            dir,
            "src/lib.rs",
            format!("pub fn one() -> u32 {{ {rev} }}\n").as_bytes(),
        );
        commit_all(dir, &format!("revision {rev}"));
    }
    git(dir, &["tag", "-a", "v1", "-m", "release v1"]);
    git(dir, &["tag", "light"]);
    git(dir, &["checkout", "-q", "-b", "feature"]);
    write(dir, "src/feature.rs", b"pub fn feature() {}\n");
    commit_all(dir, "feature work");
    git(dir, &["checkout", "-q", "main"]);
    write(dir, "src/main_only.rs", b"fn main_only() {}\n");
    commit_all(dir, "main work");
    git(
        dir,
        &["merge", "-q", "--no-ff", "feature", "-m", "merge feature"],
    );
    for name in ["oct-a", "oct-b"] {
        git(dir, &["checkout", "-q", "-b", name, "main"]);
        write(dir, &format!("{name}.txt"), name.as_bytes());
        commit_all(dir, name);
    }
    git(dir, &["checkout", "-q", "main"]);
    git(
        dir,
        &["merge", "-q", "--no-ff", "oct-a", "oct-b", "-m", "octopus"],
    );
    commit_all(dir, "empty commit");
    let tree = git_text(dir, &["rev-parse", "HEAD^{tree}"]);
    let blob = git_text(dir, &["rev-parse", "HEAD:README.md"]);
    git(
        dir,
        &["tag", "-a", "tree-tag", &tree, "-m", "a tag of a tree"],
    );
    git(
        dir,
        &["tag", "-a", "blob-tag", &blob, "-m", "a tag of a blob"],
    );
    git(
        dir,
        &[
            "tag",
            "-a",
            "-f",
            "nested-tag",
            "v1",
            "-m",
            "a tag of a tag",
        ],
    );
    // Objects reachable only through a tag: a blob in no tree, and an inner tag whose own
    // reference is deleted, so only the outer tag reaches it.
    let out = git_raw(
        dir,
        &["hash-object", "-w", "--stdin"],
        Some(b"reachable only through a tag\n"),
    );
    let lone_blob = String::from_utf8(out.stdout).unwrap().trim().to_string();
    git(
        dir,
        &[
            "tag",
            "-a",
            "lone-blob-tag",
            &lone_blob,
            "-m",
            "tag of a lone blob",
        ],
    );
    git(dir, &["tag", "-a", "inner", "v1", "-m", "inner tag"]);
    git(
        dir,
        &["tag", "-a", "-f", "outer-only", "inner", "-m", "outer tag"],
    );
    git(dir, &["tag", "-d", "inner"]);
    // A commit with a multi-line signature header and an encoding header, written as raw
    // bytes (no signing key is involved: the header is opaque data to Git and to the bridge).
    let head = git_text(dir, &["rev-parse", "HEAD"]);
    let raw = format!(
        "tree {tree}\nparent {head}\n\
author Fixture Author <author@fixture.invalid> 1700000001 +0100\n\
committer Fixture Committer <committer@fixture.invalid> 1700000002 -0230\n\
encoding ISO-8859-1\n\
gpgsig -----BEGIN PGP SIGNATURE-----\n \n iQEzBAABCAAdFiEEfixture\n =abcd\n -----END PGP SIGNATURE-----\n\
\nsigned commit with caf\u{e9}\n"
    );
    let out = git_raw(
        dir,
        &["hash-object", "-t", "commit", "-w", "--stdin"],
        Some(raw.as_bytes()),
    );
    assert!(out.status.success());
    let signed = String::from_utf8(out.stdout).unwrap().trim().to_string();
    git(dir, &["update-ref", "refs/heads/signed", &signed]);
}

/// `git cat-file --batch-all-objects --batch`: every object in the database as (kind, payload).
pub fn git_all_objects(dir: &Path) -> BTreeMap<GitOid, (String, Vec<u8>)> {
    let out = git(dir, &["cat-file", "--batch-all-objects", "--batch"]);
    let mut objects = BTreeMap::new();
    let mut rest = &out[..];
    while !rest.is_empty() {
        let nl = rest.iter().position(|&b| b == b'\n').unwrap();
        let header = std::str::from_utf8(&rest[..nl]).unwrap();
        let mut parts = header.split(' ');
        let oid = GitOid::from_hex(parts.next().unwrap()).unwrap();
        let kind = parts.next().unwrap().to_string();
        let size: usize = parts.next().unwrap().parse().unwrap();
        let payload = rest[nl + 1..nl + 1 + size].to_vec();
        objects.insert(oid, (kind, payload));
        rest = &rest[nl + 1 + size + 1..];
    }
    objects
}

pub fn git_refs(dir: &Path) -> BTreeMap<String, GitOid> {
    git_text(dir, &["for-each-ref", "--format=%(refname) %(objectname)"])
        .lines()
        .map(|l| {
            let (name, oid) = l.split_once(' ').unwrap();
            (name.to_string(), GitOid::from_hex(oid).unwrap())
        })
        .collect()
}

pub fn assert_history_matches_git(history: &GitHistory, dir: &Path) {
    let oracle = git_all_objects(dir);
    let native: BTreeSet<GitOid> = history.objects.keys().copied().collect();
    let expected: BTreeSet<GitOid> = oracle.keys().copied().collect();
    assert_eq!(
        native, expected,
        "native reachable set != git object database"
    );
    for (oid, object) in &history.objects {
        let (kind, payload) = &oracle[oid];
        assert_eq!(object.kind.name(), kind, "kind of {oid}");
        assert_eq!(&object.payload, payload, "payload of {oid}");
        assert_eq!(object.oid(), *oid);
    }
    assert_eq!(history.refs, git_refs(dir), "references");
}

pub fn assert_fsck_strict_clean(dir: &Path) {
    let out = git_raw(dir, &["fsck", "--full", "--strict", "--no-dangling"], None);
    let stderr = String::from_utf8_lossy(&out.stderr);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success() && !stderr.contains("error") && !stderr.contains("warning"),
        "git fsck --full --strict failed in {}:\n{stdout}\n{stderr}",
        dir.display()
    );
}

/// Number of entries whose pack type (`gitformat-pack`: 3 bits after the MSB of the first byte) is `t`.
pub fn count_entry_type(pack: &[u8], entries: &[synapse_git::PackIndexEntry], t: u8) -> usize {
    entries
        .iter()
        .filter(|e| (pack[e.offset as usize] >> 4) & 0x07 == t)
        .count()
}

pub fn objects_of(history: &GitHistory) -> Vec<GitObject> {
    history.objects.values().cloned().collect()
}
