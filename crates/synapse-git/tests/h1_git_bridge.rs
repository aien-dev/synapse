//! ADR 0003 step H1 (issue #48), first cut: the native Git object layer. The system `git` is
//! used here only as an independent oracle (it builds fixture history, then checks what the
//! native reader read and what the native exporter wrote: `cat-file`, `for-each-ref`,
//! `verify-pack`, `fsck --full --strict`, `clone`). Nothing in `synapse-git` starts a Git
//! process for these paths.

mod common;

use common::*;
use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use synapse_core::{GitOid, RefusalCode};
use synapse_git::pack::{decode_idx, PackReader};
use synapse_git::{export_repository, GitRepository, ObjectKind};

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
