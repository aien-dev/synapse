//! Hostile store files (issue #58): FIFOs, symlinks to devices, oversized records and a
//! FIFO `STORE_ID` must give a prompt, typed refusal, never a hang or an unbounded read,
//! and must never be overwritten. Every store call runs under a 5 s watchdog so a
//! regression fails the test instead of hanging the suite.

use std::fs;
use std::os::unix::fs::FileTypeExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::mpsc;
use std::time::Duration;
use synapse_coord::{
    ClaimOutcome, CoordError, CoordStore, Holder, RecordRefusal, Workspace, MAX_RECORD_BYTES,
    STORE_ID_FILE,
};

static N: AtomicU32 = AtomicU32::new(0);

struct Fx {
    base: PathBuf,
    store: PathBuf,
    top: PathBuf,
}
impl Drop for Fx {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.base);
    }
}

fn fx(tag: &str) -> Fx {
    let base = std::env::temp_dir().join(format!(
        "synapse-coord-hostile-{tag}-{}-{}",
        std::process::id(),
        N.fetch_add(1, Ordering::SeqCst)
    ));
    let _ = fs::remove_dir_all(&base);
    let top = base.join("wa");
    fs::create_dir_all(top.join("src")).unwrap();
    fs::write(top.join("src/a.rs"), "a").unwrap();
    Fx {
        store: base.join("store"),
        top,
        base,
    }
}

fn ws(top: &Path) -> Workspace {
    Workspace::worktree(top.to_str().unwrap(), Holder::git("A", "0123", "4567"))
}

fn mkfifo(p: &Path) {
    let c = std::ffi::CString::new(p.to_str().unwrap()).unwrap();
    // SAFETY: valid NUL-terminated path.
    assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o644) }, 0, "{p:?}");
}

/// Run `f` on a thread; fail (instead of hanging) if it does not answer within 5 s.
fn within<T: Send + 'static>(what: &str, f: impl FnOnce() -> T + Send + 'static) -> T {
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let _ = tx.send(f());
    });
    rx.recv_timeout(Duration::from_secs(5))
        .unwrap_or_else(|_| panic!("{what} did not answer within 5 s"))
}

/// A store with one live claim (so `dirs/`, `agents/` and `STORE_ID` exist).
fn seeded(f: &Fx) {
    let r = CoordStore::open(&f.store)
        .claim(&ws(&f.top), "alice", ".", "src/a.rs", "edit", Some(600))
        .unwrap();
    assert!(matches!(r, ClaimOutcome::Claimed { .. }));
}

fn sniff(f: &Fx) -> Result<synapse_coord::Sniff, CoordError> {
    let (store, top) = (f.store.clone(), f.top.clone());
    within("sniff", move || {
        CoordStore::open(store).sniff(&ws(&top), "bob", ".")
    })
}

fn claim(f: &Fx, target: &str) -> Result<ClaimOutcome, CoordError> {
    let (store, top, target) = (f.store.clone(), f.top.clone(), target.to_string());
    within("claim", move || {
        CoordStore::open(store).claim(&ws(&top), "bob", ".", &target, "edit", Some(60))
    })
}

fn refusal(r: Result<impl std::fmt::Debug, CoordError>) -> (PathBuf, RecordRefusal) {
    match r {
        Err(CoordError::RefusedRecord { path, reason }) => (path, reason),
        other => panic!("expected RefusedRecord, got {other:?}"),
    }
}

fn is_fifo(p: &Path) -> bool {
    fs::symlink_metadata(p).unwrap().file_type().is_fifo()
}

#[test]
fn fifo_record_in_dirs_is_refused_promptly() {
    let f = fx("fifo-dirs");
    seeded(&f);
    let evil = f.store.join("dirs/evil.json");
    mkfifo(&evil);
    let (p, r) = refusal(sniff(&f));
    assert_eq!((p, r), (evil.clone(), RecordRefusal::NotRegular("fifo")));
    // A mutation refuses too (its prune reads every record) and leaves the FIFO in place.
    let (p, r) = refusal(claim(&f, "src/b.rs"));
    assert_eq!((p, r), (evil.clone(), RecordRefusal::NotRegular("fifo")));
    assert!(is_fifo(&evil));
    // Moving it aside restores service.
    fs::remove_file(&evil).unwrap();
    assert_eq!(sniff(&f).unwrap().locks.len(), 1);
}

#[test]
fn fifo_record_in_agents_is_refused_promptly() {
    let f = fx("fifo-agents");
    seeded(&f);
    let evil = f.store.join("agents/evil.json");
    mkfifo(&evil);
    assert_eq!(
        refusal(sniff(&f)),
        (evil.clone(), RecordRefusal::NotRegular("fifo"))
    );
    assert_eq!(
        refusal(claim(&f, "src/b.rs")),
        (evil.clone(), RecordRefusal::NotRegular("fifo"))
    );
    assert!(is_fifo(&evil));
}

#[test]
fn fifo_as_the_record_being_claimed_is_never_replaced() {
    let f = fx("fifo-target");
    seeded(&f);
    // The record for directory `src` is a FIFO; claiming in `src` must refuse, not rename
    // a fresh record over it.
    let evil = f.store.join("dirs/src.json");
    let _ = fs::remove_file(&evil);
    mkfifo(&evil);
    let (store, top) = (f.store.clone(), f.top.clone());
    let r = within("claim in src", move || {
        CoordStore::open(store).claim(&ws(&top), "bob", "src", "a.rs", "edit", Some(60))
    });
    assert_eq!(
        refusal(r),
        (evil.clone(), RecordRefusal::NotRegular("fifo"))
    );
    assert!(is_fifo(&evil));
}

#[test]
fn fifo_store_id_is_refused_promptly() {
    let f = fx("fifo-storeid");
    seeded(&f);
    let id = f.store.join(STORE_ID_FILE);
    fs::remove_file(&id).unwrap();
    mkfifo(&id);
    assert_eq!(
        refusal(sniff(&f)),
        (id.clone(), RecordRefusal::NotRegular("fifo"))
    );
    assert_eq!(
        refusal(claim(&f, "src/b.rs")),
        (id.clone(), RecordRefusal::NotRegular("fifo"))
    );
    let store = f.store.clone();
    assert_eq!(
        refusal(within("store_id", move || CoordStore::open(store).store_id())),
        (id.clone(), RecordRefusal::NotRegular("fifo"))
    );
    // A fresh store whose first mutating open finds a FIFO marker refuses and keeps it.
    let g = fx("fifo-storeid-fresh");
    fs::create_dir_all(&g.store).unwrap();
    let gid = g.store.join(STORE_ID_FILE);
    mkfifo(&gid);
    assert_eq!(
        refusal(claim(&g, "src/a.rs")),
        (gid.clone(), RecordRefusal::NotRegular("fifo"))
    );
    assert!(is_fifo(&gid));
    assert!(is_fifo(&id));
}

#[test]
fn symlink_record_to_dev_zero_is_refused_without_reading() {
    let f = fx("devzero");
    seeded(&f);
    let z = f.store.join("dirs/zero.json");
    std::os::unix::fs::symlink("/dev/zero", &z).unwrap();
    assert_eq!(refusal(sniff(&f)), (z.clone(), RecordRefusal::Symlink));
    assert_eq!(
        refusal(claim(&f, "src/b.rs")),
        (z.clone(), RecordRefusal::Symlink)
    );
    // The link is left as found.
    assert_eq!(fs::read_link(&z).unwrap(), PathBuf::from("/dev/zero"));
    // A symlink to a regular, valid record is refused too: records are never followed.
    fs::remove_file(&z).unwrap();
    let real = f.base.join("real.json");
    fs::write(&real, b"{}").unwrap();
    std::os::unix::fs::symlink(&real, &z).unwrap();
    assert_eq!(refusal(sniff(&f)), (z, RecordRefusal::Symlink));
}

#[test]
fn oversize_record_is_refused_and_cap_is_inclusive() {
    let f = fx("oversize");
    seeded(&f);
    let big = f.store.join("dirs/big.json");
    // Sparse file one byte over the cap: refused from fstat, nothing is read.
    let h = fs::File::create(&big).unwrap();
    h.set_len(MAX_RECORD_BYTES + 1).unwrap();
    drop(h);
    assert_eq!(
        refusal(sniff(&f)),
        (
            big.clone(),
            RecordRefusal::TooLarge {
                limit: MAX_RECORD_BYTES
            }
        )
    );
    assert_eq!(
        fs::metadata(&big).unwrap().len(),
        MAX_RECORD_BYTES + 1,
        "not overwritten"
    );
    // Exactly at the cap is read (and is valid JSON padded with spaces).
    let mut at = b"{}".to_vec();
    at.resize(MAX_RECORD_BYTES as usize, b' ');
    fs::write(&big, &at).unwrap();
    assert_eq!(sniff(&f).unwrap().locks.len(), 1);
}

#[test]
fn non_record_entries_are_ignored_and_symlinked_dirs_not_followed() {
    let f = fx("ignored");
    seeded(&f);
    // A FIFO without the .json suffix is not a record name: ignored, never opened.
    mkfifo(&f.store.join("dirs/notes.fifo"));
    // A symlinked directory (here a self loop) is not walked.
    std::os::unix::fs::symlink(f.store.join("dirs"), f.store.join("dirs/loop")).unwrap();
    assert_eq!(sniff(&f).unwrap().locks.len(), 1);
    assert!(matches!(
        claim(&f, "src/b.rs").unwrap(),
        ClaimOutcome::Claimed { .. }
    ));
}

#[test]
fn planted_lock_file_fifo_is_refused() {
    let f = fx("lockfifo");
    seeded(&f);
    let lp = f.store.join(".lock");
    fs::remove_file(&lp).unwrap();
    mkfifo(&lp);
    assert_eq!(
        refusal(claim(&f, "src/b.rs")),
        (lp.clone(), RecordRefusal::NotRegular("fifo"))
    );
    assert!(is_fifo(&lp));
    // Read-only sniff takes no lock, so it still answers.
    assert_eq!(sniff(&f).unwrap().locks.len(), 1);
}

/// Issue #63 item 1: a symlinked directory component under `dirs/` is refused for reads and
/// writes alike (listing already skips it), and nothing is written through it.
#[test]
fn symlinked_dir_component_under_dirs_is_refused_and_not_written_through() {
    let f = fx("symlinkdir");
    seeded(&f);
    fs::create_dir_all(f.top.join("sub/deep")).unwrap();
    fs::write(f.top.join("sub/deep/x.rs"), "x").unwrap();
    let outside = f.base.join("outside");
    fs::create_dir_all(&outside).unwrap();
    let link = f.store.join("dirs/sub");
    std::os::unix::fs::symlink(&outside, &link).unwrap();
    assert_eq!(
        refusal(claim(&f, "sub/deep/x.rs")),
        (link.clone(), RecordRefusal::Symlink)
    );
    assert_eq!(
        fs::read_dir(&outside).unwrap().count(),
        0,
        "nothing may be written through the symlinked directory"
    );
    // A regular file planted where a subdirectory is expected is refused as not a directory.
    fs::remove_file(&link).unwrap();
    fs::write(&link, "not a dir").unwrap();
    assert_eq!(
        refusal(claim(&f, "sub/deep/x.rs")),
        (link.clone(), RecordRefusal::NotDirectory)
    );
    // Removing it restores service: the record is created under a real directory.
    fs::remove_file(&link).unwrap();
    assert!(matches!(
        claim(&f, "sub/deep/x.rs").unwrap(),
        ClaimOutcome::Claimed { .. }
    ));
    assert!(fs::symlink_metadata(&link).unwrap().is_dir());
}

/// Issue #63 item 4: a directory planted as `.lock` is a typed refusal, not `Io(EISDIR)`.
#[test]
fn planted_lock_file_directory_is_refused() {
    let f = fx("lockdir");
    seeded(&f);
    let lp = f.store.join(".lock");
    fs::remove_file(&lp).unwrap();
    fs::create_dir(&lp).unwrap();
    assert_eq!(
        refusal(claim(&f, "src/b.rs")),
        (lp.clone(), RecordRefusal::NotRegular("directory"))
    );
    assert!(fs::symlink_metadata(&lp).unwrap().is_dir());
}

/// Issue #63 item 3: `synapse-coord canon` uses the bounded, non-blocking read, so a FIFO or
/// an oversize file is refused promptly instead of hanging or being read whole.
#[test]
fn canon_refuses_fifo_and_oversize_promptly() {
    let f = fx("canon");
    fs::create_dir_all(&f.base).unwrap();
    let fifo = f.base.join("p.json");
    mkfifo(&fifo);
    let big = f.base.join("big.json");
    let mut body = vec![b' '; synapse_coord::MAX_RECORD_BYTES as usize + 1];
    body[0] = b'{';
    *body.last_mut().unwrap() = b'}';
    fs::write(&big, &body).unwrap();
    let ok = f.base.join("ok.json");
    fs::write(&ok, br#"{ "b": 1, "a": 2 }"#).unwrap();
    for (p, want_ok) in [(fifo, false), (big, false), (ok, true)] {
        let st = within("canon", move || {
            std::process::Command::new(env!("CARGO_BIN_EXE_synapse-coord"))
                .arg("canon")
                .arg(&p)
                .output()
                .unwrap()
        });
        assert_eq!(st.status.success(), want_ok, "{st:?}");
    }
}
