//! ADR 0003 step H1 (issue #48), first cut: the native Git object layer. The system `git` is
//! used here only as an independent oracle (it builds fixture history, then checks what the
//! native reader read and what the native exporter wrote: `cat-file`, `for-each-ref`,
//! `verify-pack`, `fsck --full --strict`, `clone`). Nothing in `synapse-git` starts a Git
//! process for these paths.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use synapse_core::{GitOid, RefusalCode};
use synapse_git::pack::{decode_idx, PackReader};
use synapse_git::{export_repository, GitHistory, GitObject, GitRepository, ObjectKind};

fn temp_dir(label: &str) -> PathBuf {
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
fn git_raw(dir: &Path, args: &[&str], stdin: Option<&[u8]>) -> Output {
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

fn git(dir: &Path, args: &[&str]) -> Vec<u8> {
    let out = git_raw(dir, args, None);
    assert!(
        out.status.success(),
        "git {args:?} failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    out.stdout
}

fn git_text(dir: &Path, args: &[&str]) -> String {
    String::from_utf8(git(dir, args))
        .unwrap()
        .trim()
        .to_string()
}

fn write(dir: &Path, rel: &str, bytes: &[u8]) {
    let path = dir.join(rel);
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, bytes).unwrap();
}

fn commit_all(dir: &Path, msg: &str) {
    git(dir, &["add", "-A"]);
    git(dir, &["commit", "-q", "--allow-empty", "-m", msg]);
}

/// Deterministic pseudo-random bytes (xorshift), so the binary blob is incompressible.
fn noise(len: usize, seed: u64) -> Vec<u8> {
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
fn build_fixture(dir: &Path) {
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
fn git_all_objects(dir: &Path) -> BTreeMap<GitOid, (String, Vec<u8>)> {
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

fn git_refs(dir: &Path) -> BTreeMap<String, GitOid> {
    git_text(dir, &["for-each-ref", "--format=%(refname) %(objectname)"])
        .lines()
        .map(|l| {
            let (name, oid) = l.split_once(' ').unwrap();
            (name.to_string(), GitOid::from_hex(oid).unwrap())
        })
        .collect()
}

fn assert_history_matches_git(history: &GitHistory, dir: &Path) {
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

fn assert_fsck_strict_clean(dir: &Path) {
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
fn count_entry_type(pack: &[u8], entries: &[synapse_git::PackIndexEntry], t: u8) -> usize {
    entries
        .iter()
        .filter(|e| (pack[e.offset as usize] >> 4) & 0x07 == t)
        .count()
}

fn objects_of(history: &GitHistory) -> Vec<GitObject> {
    history.objects.values().cloned().collect()
}

#[test]
fn h1_native_reader_resolves_symbolic_ref_chains_and_loose_shadowing() {
    let dir = temp_dir("symbolic-ref");
    build_fixture(&dir);
    let packed_target = git_text(&dir, &["rev-parse", "refs/heads/main"]);
    let loose_target = git_text(&dir, &["rev-parse", "refs/heads/feature"]);
    git(
        &dir,
        &["update-ref", "refs/remotes/origin/main", &packed_target],
    );
    git(&dir, &["pack-refs", "--all"]);
    // The loose symbolic ref shadows the packed direct ref of the same name.
    git(
        &dir,
        &[
            "symbolic-ref",
            "refs/remotes/origin/main",
            "refs/heads/feature",
        ],
    );
    git(
        &dir,
        &[
            "symbolic-ref",
            "refs/remotes/origin/alias",
            "refs/remotes/origin/main",
        ],
    );
    git(
        &dir,
        &[
            "symbolic-ref",
            "refs/remotes/origin/HEAD",
            "refs/remotes/origin/alias",
        ],
    );

    let (refs, _) = GitRepository::open(&dir.join(".git"))
        .unwrap()
        .refs()
        .unwrap();
    let resolved = GitOid::from_hex(&loose_target).unwrap();
    for name in [
        "refs/remotes/origin/HEAD",
        "refs/remotes/origin/alias",
        "refs/remotes/origin/main",
    ] {
        assert_eq!(refs.get(name), Some(&resolved), "resolved {name}");
    }
    fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn h1_native_reader_refuses_symbolic_ref_cycles_and_dangling_targets() {
    for (label, aliases) in [
        (
            "cycle",
            vec![
                ("refs/remotes/origin/one", "refs/remotes/origin/two"),
                ("refs/remotes/origin/two", "refs/remotes/origin/one"),
            ],
        ),
        (
            "dangling",
            vec![("refs/remotes/origin/HEAD", "refs/remotes/origin/missing")],
        ),
        (
            "escaping",
            vec![("refs/remotes/origin/HEAD", "../../outside")],
        ),
        (
            "malformed",
            vec![("refs/remotes/origin/HEAD", "refs/remotes//broken")],
        ),
    ] {
        let dir = temp_dir(label);
        build_fixture(&dir);
        for (name, target) in aliases {
            write(
                &dir.join(".git"),
                name,
                format!("ref: {target}\n").as_bytes(),
            );
        }
        let err = GitRepository::open(&dir.join(".git"))
            .unwrap()
            .refs()
            .unwrap_err();
        assert_eq!(err.code, RefusalCode::GitObjectCorrupt, "{label}: {err}");
        fs::remove_dir_all(&dir).unwrap();
    }
}

#[test]
fn h1_native_reader_reads_every_loose_object_exactly_as_git() {
    let dir = temp_dir("loose");
    build_fixture(&dir);
    let packs = fs::read_dir(dir.join(".git/objects/pack")).unwrap().count();
    assert_eq!(packs, 0, "fixture must start with loose objects only");
    let history = GitRepository::open(&dir.join(".git"))
        .unwrap()
        .full_history()
        .unwrap();
    assert_history_matches_git(&history, &dir);
    assert_eq!(history.head.as_deref(), Some("refs/heads/main"));
    let kinds: BTreeSet<ObjectKind> = history.objects.values().map(|o| o.kind).collect();
    assert_eq!(kinds.len(), 4, "commits, trees, blobs and tags present");
    fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn h1_native_reader_resolves_offset_deltas_in_git_packs_and_matches_git_idx() {
    let dir = temp_dir("ofs");
    build_fixture(&dir);
    git(
        &dir,
        &[
            "repack",
            "-a",
            "-d",
            "-f",
            "-q",
            "--depth=50",
            "--window=250",
        ],
    );
    git(&dir, &["pack-refs", "--all"]);
    let pack_dir = dir.join(".git/objects/pack");
    let idx_path = fs::read_dir(&pack_dir)
        .unwrap()
        .map(|e| e.unwrap().path())
        .find(|p| p.extension().is_some_and(|x| x == "idx"))
        .unwrap();
    let verify = git_text(&dir, &["verify-pack", "-v", idx_path.to_str().unwrap()]);
    assert!(
        verify.contains("chain length = "),
        "fixture pack must hold deltas:\n{verify}"
    );
    let history = GitRepository::open(&dir.join(".git"))
        .unwrap()
        .full_history()
        .unwrap();
    assert_history_matches_git(&history, &dir);
    // Native indexing of the same pack reproduces Git's own index: every name, offset, CRC.
    let pack = fs::read(idx_path.with_extension("pack")).unwrap();
    let native = PackReader::index(pack.clone()).unwrap();
    assert!(
        count_entry_type(&pack, native.entries(), 6) > 0,
        "Git pack holds OBJ_OFS_DELTA entries"
    );
    let (git_entries, _) = decode_idx(&fs::read(&idx_path).unwrap()).unwrap();
    assert_eq!(native.entries(), &git_entries[..]);
    fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn h1_native_indexer_resolves_reference_deltas_from_git_pack_objects() {
    let dir = temp_dir("ref");
    build_fixture(&dir);
    let list = git(&dir, &["rev-list", "--objects", "--all"]);
    // Without --delta-base-offset, pack-objects writes OBJ_REF_DELTA entries.
    let out = git_raw(
        &dir,
        &[
            "pack-objects",
            "--stdout",
            "-q",
            "--window=250",
            "--depth=50",
        ],
        Some(&list),
    );
    assert!(out.status.success());
    let mut reader = PackReader::index(out.stdout.clone()).unwrap();
    assert!(
        count_entry_type(&out.stdout, reader.entries(), 7) > 0,
        "pack-objects output holds OBJ_REF_DELTA entries"
    );
    let oracle = git_all_objects(&dir);
    assert_eq!(reader.entries().len(), oracle.len());
    for (oid, (kind, payload)) in &oracle {
        let object = reader.read(*oid).unwrap().unwrap();
        assert_eq!(object.kind.name(), kind);
        assert_eq!(&object.payload, payload);
    }
    fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn h1_full_history_exports_as_a_pack_with_identical_object_ids_and_fsck_strict_clean() {
    let dir = temp_dir("export-src");
    build_fixture(&dir);
    git(&dir, &["repack", "-a", "-d", "-q"]);
    let history = GitRepository::open(&dir.join(".git"))
        .unwrap()
        .full_history()
        .unwrap();
    let out = temp_dir("export-dst");
    let dest = out.join("exported.git");
    let receipt = export_repository(
        &dest,
        &objects_of(&history),
        &history.refs,
        history.head.as_deref(),
    )
    .unwrap();
    assert_eq!(receipt.object_count, history.objects.len());
    // Only the pack and its index: no loose objects.
    let loose: Vec<_> = fs::read_dir(dest.join("objects"))
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .filter(|n| n != "pack" && n != "info")
        .collect();
    assert!(loose.is_empty(), "loose object directories {loose:?}");
    git(&dest, &["verify-pack", receipt.idx_path.to_str().unwrap()]);
    assert_fsck_strict_clean(&dest);
    // Identical Git object IDs and references, by Git's own reading of both repositories.
    let src_objects = git_all_objects(&dir);
    let dst_objects = git_all_objects(&dest);
    assert_eq!(src_objects, dst_objects, "object databases differ");
    assert_eq!(git_refs(&dir), git_refs(&dest), "references differ");
    assert_eq!(
        git_text(&dir, &["rev-parse", "HEAD"]),
        git_text(&dest, &["rev-parse", "HEAD"])
    );
    // And the exported repository works as a Git remote.
    let clone = out.join("clone");
    let status = Command::new("git")
        .args(["clone", "-q"])
        .arg(&dest)
        .arg(&clone)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .status()
        .unwrap();
    assert!(status.success());
    assert_eq!(
        fs::read(clone.join("docs/big.txt")).unwrap(),
        fs::read(dir.join("docs/big.txt")).unwrap()
    );
    fs::remove_dir_all(&dir).unwrap();
    fs::remove_dir_all(&out).unwrap();
}

#[test]
fn h1_export_is_deterministic_and_never_overwrites_a_repository() {
    let dir = temp_dir("det-src");
    build_fixture(&dir);
    let history = GitRepository::open(&dir.join(".git"))
        .unwrap()
        .full_history()
        .unwrap();
    let out = temp_dir("det-dst");
    let mut objects = objects_of(&history);
    let a = export_repository(&out.join("a.git"), &objects, &history.refs, None).unwrap();
    objects.reverse();
    let b = export_repository(&out.join("b.git"), &objects, &history.refs, None).unwrap();
    assert_eq!(a.pack_checksum, b.pack_checksum);
    assert_eq!(
        fs::read(&a.pack_path).unwrap(),
        fs::read(&b.pack_path).unwrap()
    );
    assert_eq!(
        fs::read(&a.idx_path).unwrap(),
        fs::read(&b.idx_path).unwrap()
    );
    let err = export_repository(&out.join("a.git"), &objects, &history.refs, None).unwrap_err();
    assert_eq!(err.code, RefusalCode::PathInvalid);
    let err = export_repository(&dir.join(".git"), &objects, &history.refs, None).unwrap_err();
    assert_eq!(
        err.code,
        RefusalCode::PathInvalid,
        "existing repository refused"
    );
    let mut bad_refs = history.refs.clone();
    bad_refs.insert("refs/heads/missing".into(), GitOid([0xab; 20]));
    let err = export_repository(&out.join("c.git"), &objects, &bad_refs, None).unwrap_err();
    assert_eq!(err.code, RefusalCode::GitObjectCorrupt);
    fs::remove_dir_all(&dir).unwrap();
    fs::remove_dir_all(&out).unwrap();
}

#[test]
fn h1_damaged_or_incomplete_repositories_are_refused_typed() {
    let dir = temp_dir("damaged");
    build_fixture(&dir);
    let readme = git_text(&dir, &["rev-parse", "HEAD:README.md"]);
    let path = dir
        .join(".git/objects")
        .join(&readme[..2])
        .join(&readme[2..]);
    let mut bytes = fs::read(&path).unwrap();
    fs::set_permissions(&path, std::os::unix::fs::PermissionsExt::from_mode(0o644)).unwrap();
    let last = bytes.len() - 6;
    bytes[last] ^= 0x01;
    fs::write(&path, &bytes).unwrap();
    let mut repo = GitRepository::open(&dir.join(".git")).unwrap();
    let err = repo
        .read_object(GitOid::from_hex(&readme).unwrap())
        .unwrap_err();
    assert_eq!(err.code, RefusalCode::GitObjectCorrupt);
    fs::remove_file(&path).unwrap();
    let err = repo.full_history().unwrap_err();
    assert_eq!(err.code, RefusalCode::GitObjectCorrupt);
    assert!(err.message.contains("missing"), "{}", err.message);
    fs::remove_dir_all(&dir).unwrap();
}

/// Full history of a real repository (path in `SYNAPSE_H1_REAL_REPO`, a full non-shallow
/// clone): native read, native export as one pack, then Git's own check that the export holds
/// the same object IDs and references and passes `fsck --full --strict`. Ignored by default
/// because CI has no such clone; run locally with `--ignored`.
#[test]
#[ignore]
fn h1_real_repository_full_history_round_trips_with_identical_object_ids() {
    let Ok(src) = std::env::var("SYNAPSE_H1_REAL_REPO") else {
        panic!("set SYNAPSE_H1_REAL_REPO to a full clone's git directory");
    };
    let src = PathBuf::from(src);
    let history = GitRepository::open(&src).unwrap().full_history().unwrap();
    let out = temp_dir("real");
    let dest = out.join("exported.git");
    let receipt = export_repository(
        &dest,
        &objects_of(&history),
        &history.refs,
        history.head.as_deref(),
    )
    .unwrap();
    assert_fsck_strict_clean(&dest);
    // Every reference resolves to the same object in both; the exported database holds
    // exactly the objects reachable in the source (`rev-list --objects --all`).
    assert_eq!(git_refs(&src), git_refs(&dest));
    let reachable = |d: &Path| -> BTreeSet<String> {
        git_text(d, &["rev-list", "--objects", "--all"])
            .lines()
            .map(|l| l[..40].to_string())
            .collect()
    };
    let src_reachable = reachable(&src);
    assert_eq!(src_reachable, reachable(&dest));
    let dst_all: BTreeSet<String> = git_all_objects(&dest).keys().map(|o| o.to_hex()).collect();
    assert_eq!(
        src_reachable, dst_all,
        "export holds only reachable objects"
    );
    let commits = history
        .objects
        .values()
        .filter(|o| o.kind == ObjectKind::Commit)
        .count();
    println!(
        "real repository {}: {} objects ({commits} commits), {} refs, pack {} bytes",
        src.display(),
        history.objects.len(),
        history.refs.len(),
        receipt.pack_bytes
    );
    fs::remove_dir_all(&out).unwrap();
}
