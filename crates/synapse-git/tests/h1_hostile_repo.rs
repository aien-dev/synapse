//! ADR 0003 step H1 (issue #48): a crafted repository must not hang the native reader, make
//! it read outside the repository, or make it allocate without bound (review of PR #90,
//! findings B1 and B2). Every case calls only `GitRepository::open` and `full_history`, the
//! import entry points. The system `git` builds ordinary fixture history; the hostile parts
//! (a pipe, links, a delta bomb pack) are made by hand.
//!
//! A case that would block (a pipe) runs in a thread with a deadline, so a regression fails
//! the test instead of hanging the test runner.

use sha1::{Digest, Sha1};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::mpsc;
use std::time::Duration;
use synapse_core::{GitOid, RefusalCode, SynapseResult};
use synapse_git::pack::{crc32, write_idx, PackIndexEntry};
use synapse_git::{zlib_compress_store, GitRepository};

fn temp_dir(label: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "synapse-h1-hostile-{label}-{}-{}",
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

/// A small repository with two commits on `main`; returns its `.git` directory and the tip.
fn small_repo(label: &str) -> (PathBuf, PathBuf, String) {
    let root = temp_dir(label);
    let work = root.join("work");
    fs::create_dir_all(&work).unwrap();
    git(&work, &["init", "-q", "-b", "main"]);
    fs::write(work.join("a.txt"), b"one\n").unwrap();
    git(&work, &["add", "-A"]);
    git(&work, &["commit", "-q", "-m", "one"]);
    fs::write(work.join("a.txt"), b"two\n").unwrap();
    git(&work, &["add", "-A"]);
    git(&work, &["commit", "-q", "-m", "two"]);
    let tip = git(&work, &["rev-parse", "HEAD"]);
    (root, work.join(".git"), tip)
}

fn read_history(git_dir: &Path) -> SynapseResult<usize> {
    let mut repo = GitRepository::open(git_dir)?;
    Ok(repo.full_history()?.objects.len())
}

fn assert_refused(result: SynapseResult<usize>, code: RefusalCode, case: &str) {
    match result {
        Err(e) => assert_eq!(e.code, code, "{case}: refused with the wrong code: {e}"),
        Ok(n) => panic!("{case}: read {n} objects instead of refusing"),
    }
}

/// Run `full_history` on `git_dir` in a thread. If it has not returned within `deadline`,
/// open `pipe` for writing (which releases a reader blocked opening it) and fail.
fn read_history_with_deadline(git_dir: &Path, pipe: &Path, case: &str) -> SynapseResult<usize> {
    let (tx, rx) = mpsc::channel();
    let dir = git_dir.to_path_buf();
    let handle = std::thread::spawn(move || {
        let _ = tx.send(read_history(&dir));
    });
    match rx.recv_timeout(Duration::from_secs(10)) {
        Ok(result) => {
            handle.join().unwrap();
            result
        }
        Err(_) => {
            // Release the blocked open so the thread ends, then fail.
            drop(fs::OpenOptions::new().write(true).open(pipe));
            let _ = rx.recv_timeout(Duration::from_secs(10));
            panic!("{case}: full_history blocked on a pipe for more than 10 s");
        }
    }
}

fn mkfifo(path: &Path) {
    let status = Command::new("mkfifo").arg(path).status().unwrap();
    assert!(status.success(), "mkfifo {}", path.display());
}

#[test]
fn h1_hostile_fifo_reference_is_refused_without_blocking() {
    let (_root, git_dir, _) = small_repo("fifo-ref");
    let pipe = git_dir.join("refs/heads/pipe");
    mkfifo(&pipe);
    let result = read_history_with_deadline(&git_dir, &pipe, "FIFO ref");
    assert_refused(result, RefusalCode::PathInvalid, "FIFO ref");
}

#[test]
fn h1_hostile_fifo_packed_refs_and_head_are_refused_without_blocking() {
    for name in ["packed-refs", "HEAD"] {
        let (_root, git_dir, _) = small_repo("fifo-file");
        let pipe = git_dir.join(name);
        let _ = fs::remove_file(&pipe);
        mkfifo(&pipe);
        let result = read_history_with_deadline(&git_dir, &pipe, name);
        assert_refused(result, RefusalCode::PathInvalid, name);
    }
}

#[test]
fn h1_hostile_fifo_loose_object_is_refused_without_blocking() {
    let (_root, git_dir, tip) = small_repo("fifo-object");
    let path = git_dir.join("objects").join(&tip[..2]).join(&tip[2..]);
    fs::remove_file(&path).unwrap();
    mkfifo(&path);
    let result = read_history_with_deadline(&git_dir, &path, "FIFO loose object");
    assert_refused(result, RefusalCode::PathInvalid, "FIFO loose object");
}

#[test]
fn h1_hostile_reference_linked_to_dev_zero_is_refused() {
    let (_root, git_dir, _) = small_repo("dev-zero");
    std::os::unix::fs::symlink("/dev/zero", git_dir.join("refs/heads/zero")).unwrap();
    assert_refused(
        read_history(&git_dir),
        RefusalCode::PathInvalid,
        "ref -> /dev/zero",
    );
}

#[test]
fn h1_hostile_reference_linked_outside_the_repository_is_refused() {
    let (root, git_dir, tip) = small_repo("outside-link");
    // A file outside the repository that holds a valid object ID: following the link would
    // read it as a reference.
    let outside = root.join("outside-ref");
    fs::write(&outside, format!("{tip}\n")).unwrap();
    std::os::unix::fs::symlink(&outside, git_dir.join("refs/heads/out")).unwrap();
    assert_refused(
        read_history(&git_dir),
        RefusalCode::PathInvalid,
        "ref -> file outside",
    );
    // A linked directory under refs/ is refused the same way (no walk into the host tree).
    let (_root2, git_dir2, _) = small_repo("outside-dir");
    std::os::unix::fs::symlink("/dev", git_dir2.join("refs/dev")).unwrap();
    assert_refused(
        read_history(&git_dir2),
        RefusalCode::PathInvalid,
        "refs/dev -> /dev",
    );
}

#[test]
fn h1_hostile_oversized_reference_file_is_refused() {
    let (_root, git_dir, tip) = small_repo("big-ref");
    let mut text = format!("{tip}\n");
    text.push_str(&" ".repeat(1 << 20));
    fs::write(git_dir.join("refs/heads/big"), text).unwrap();
    assert_refused(
        read_history(&git_dir),
        RefusalCode::QuotaPayloadTooLarge,
        "1 MiB ref",
    );
}

#[test]
fn h1_detached_head_commit_is_collected() {
    let (_root, git_dir, _) = small_repo("detached");
    let work = git_dir.parent().unwrap();
    git(work, &["checkout", "-q", "--detach"]);
    fs::write(work.join("a.txt"), b"detached\n").unwrap();
    git(work, &["add", "-A"]);
    git(work, &["commit", "-q", "-m", "only on a detached HEAD"]);
    let detached = GitOid::from_hex(&git(work, &["rev-parse", "HEAD"])).unwrap();
    let mut repo = GitRepository::open(&git_dir).unwrap();
    let history = repo.full_history().unwrap();
    assert!(
        history.objects.contains_key(&detached),
        "a commit reachable only from a detached HEAD was dropped"
    );
    // Git's own view of everything reachable includes it.
    let all = git(work, &["rev-list", "--all", "--objects"]);
    assert_eq!(all.lines().count(), history.objects.len());
}

/// The Git blob ID of `base` repeated `copies` times then the byte `tail`, from the system
/// `git hash-object` (the oracle; hashing 256 MiB natively in a debug test build is slow).
fn git_hash_blob(base: &[u8], copies: u64, tail: u8) -> GitOid {
    use std::io::Write;
    let mut child = Command::new("git")
        .args(["hash-object", "--stdin"])
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    {
        let mut stdin = child.stdin.take().unwrap();
        for _ in 0..copies {
            stdin.write_all(base).unwrap();
        }
        stdin.write_all(&[tail]).unwrap();
    }
    let out = child.wait_with_output().unwrap();
    assert!(out.status.success());
    GitOid::from_hex(String::from_utf8(out.stdout).unwrap().trim()).unwrap()
}

fn entry_header(pack_type: u8, size: u64) -> Vec<u8> {
    let mut out = vec![(pack_type << 4) | (size & 0x0f) as u8];
    let mut rest = size >> 4;
    while rest != 0 {
        *out.last_mut().unwrap() |= 0x80;
        out.push((rest & 0x7f) as u8);
        rest >>= 7;
    }
    out
}

fn size_varint(mut n: u64, out: &mut Vec<u8>) {
    loop {
        let byte = (n & 0x7f) as u8;
        n >>= 7;
        if n == 0 {
            out.push(byte);
            return;
        }
        out.push(byte | 0x80);
    }
}

fn ofs_back(back: u64) -> Vec<u8> {
    let mut n = back;
    let mut out = vec![(n & 0x7f) as u8];
    n >>= 7;
    while n != 0 {
        n -= 1;
        out.push(0x80 | (n & 0x7f) as u8);
        n >>= 7;
    }
    out.reverse();
    out
}

/// A bare repository whose one pack holds a 64 KiB blob and `deltas` offset deltas against it,
/// each about 4 KiB long and resolving to 256 MiB plus one distinguishing byte, each named by
/// a tag. Returns the repository and the pack's size in bytes.
fn delta_bomb(label: &str, deltas: u8) -> (PathBuf, usize) {
    let dir = temp_dir(label);
    let base: Vec<u8> = (0..65_536u32).map(|i| (i * 7 % 251) as u8).collect();
    let copies = 4096u64;
    let result_size = copies * base.len() as u64 + 1;
    let mut pack = b"PACK".to_vec();
    pack.extend_from_slice(&2u32.to_be_bytes());
    pack.extend_from_slice(&(1 + u32::from(deltas)).to_be_bytes());
    let mut entries = Vec::new();

    let start = pack.len();
    pack.extend_from_slice(&entry_header(3, base.len() as u64));
    pack.extend_from_slice(&zlib_compress_store(&base));
    entries.push(PackIndexEntry {
        oid: GitOid::compute_git_object("blob", &base),
        offset: start as u64,
        crc32: crc32(&pack[start..]),
    });
    let mut refs = Vec::new();
    for i in 0..deltas {
        let mut delta = Vec::new();
        size_varint(base.len() as u64, &mut delta);
        size_varint(result_size, &mut delta);
        // Copy op with no offset or size bytes: copy 0x10000 bytes from offset 0.
        delta.extend(std::iter::repeat_n(0x80u8, copies as usize));
        delta.extend_from_slice(&[1, i]);
        let at = pack.len();
        pack.extend_from_slice(&entry_header(6, delta.len() as u64));
        pack.extend_from_slice(&ofs_back((at - start) as u64));
        pack.extend_from_slice(&zlib_compress_store(&delta));
        let oid = git_hash_blob(&base, copies, i);
        entries.push(PackIndexEntry {
            oid,
            offset: at as u64,
            crc32: crc32(&pack[at..]),
        });
        refs.push((format!("refs/tags/t{i}"), oid));
    }
    let checksum: [u8; 20] = Sha1::digest(&pack).into();
    pack.extend_from_slice(&checksum);
    let idx = write_idx(&entries, GitOid(checksum));
    let pack_dir = dir.join("objects/pack");
    fs::create_dir_all(&pack_dir).unwrap();
    fs::create_dir_all(dir.join("refs/tags")).unwrap();
    let name = format!("pack-{}", GitOid(checksum).to_hex());
    fs::write(pack_dir.join(format!("{name}.pack")), &pack).unwrap();
    fs::write(pack_dir.join(format!("{name}.idx")), &idx).unwrap();
    for (name, oid) in refs {
        fs::write(dir.join(name), format!("{}\n", oid.to_hex())).unwrap();
    }
    fs::write(dir.join("HEAD"), b"ref: refs/heads/main\n").unwrap();
    (dir, pack.len())
}

#[test]
fn h1_hostile_delta_bomb_pack_is_refused_before_it_is_resolved() {
    // Five deltas of 256 MiB each from a pack under 100 KB: 1.25 GiB declared, over the
    // default 1 GiB budget. The refusal must come from the declared sizes, before anything
    // is resolved, so this test allocates almost nothing.
    let (dir, pack_bytes) = delta_bomb("delta-bomb", 5);
    assert!(pack_bytes < 100_000, "bomb pack is {pack_bytes} bytes");
    let started = std::time::Instant::now();
    assert_refused(
        read_history(&dir),
        RefusalCode::QuotaPayloadTooLarge,
        "delta bomb",
    );
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "refusal took {:?}; it must not resolve the deltas",
        started.elapsed()
    );
}
