//! Store identity marker (issue #15): creation, races, expecting-open refusals, crash
//! safety, and the split-coordination-root negative control.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU32, Ordering};
use synapse_coord::{
    ClaimOutcome, CoordError, CoordStore, Holder, NoOracle, StoreId, Workspace, STORE_ID_FILE,
};

static N: AtomicU32 = AtomicU32::new(0);

struct Scratch(PathBuf);
impl Scratch {
    fn new(tag: &str) -> Scratch {
        let p = std::env::temp_dir().join(format!(
            "synapse-coord-id-{tag}-{}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::SeqCst)
        ));
        let _ = fs::remove_dir_all(&p);
        fs::create_dir_all(&p).unwrap();
        Scratch(p)
    }
}
impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn ws(agent: &str) -> Workspace {
    let mut h = Holder::synapse("lane/main", &"ab".repeat(32), &"cd".repeat(32));
    h.session = Some(format!("{agent}-sess"));
    Workspace::with_oracle(format!("/synapse/ws/{agent}"), h, Box::new(NoOracle))
}

fn claim(cs: &CoordStore, agent: &str, target: &str) -> Result<ClaimOutcome, CoordError> {
    cs.claim(&ws(agent), agent, ".", target, "edit", None)
}

fn cli(store: &Path, args: &[&str]) -> Command {
    let mut c = Command::new(env!("CARGO_BIN_EXE_synapse-coord"));
    c.arg("--store").arg(store).args(args);
    c
}

fn marker(root: &Path) -> Vec<u8> {
    fs::read(root.join(STORE_ID_FILE)).unwrap()
}

#[test]
fn first_mutation_creates_marker_and_sniff_shows_it() {
    let s = Scratch::new("first");
    let root = s.0.join("crumb/v1");
    let cs = CoordStore::open(&root);
    assert_eq!(cs.store_id().unwrap(), None, "opening creates nothing");
    let sn = cs.sniff(&ws("a"), "a", ".").unwrap();
    assert_eq!(sn.store_id, None, "a read never creates the marker");
    assert!(sn.render(&ws("a"), "a").contains("store id: (none yet)"));
    assert!(!root.exists(), "sniff wrote nothing");

    assert!(matches!(
        claim(&cs, "a", "src/x.c").unwrap(),
        ClaimOutcome::Claimed { .. }
    ));
    let id = cs
        .store_id()
        .unwrap()
        .expect("first mutation created the marker");
    assert_eq!(marker(&root), id.encode());
    assert_eq!(cs.ensure_store_id().unwrap(), id, "idempotent");
    let sn = cs.sniff(&ws("a"), "a", ".").unwrap();
    assert_eq!(sn.store_id, Some(id));
    assert!(sn
        .render(&ws("a"), "a")
        .contains(&format!("  store id: {id}\n")));
}

#[test]
fn concurrent_first_opens_agree_on_one_id_threads_and_processes() {
    for round in 0..5 {
        let s = Scratch::new(&format!("race{round}"));
        let root = s.0.join("crumb/v1");
        let kids: Vec<_> = (0..8)
            .map(|_| {
                cli(&root, &["id"])
                    .stdout(std::process::Stdio::piped())
                    .spawn()
                    .unwrap()
            })
            .collect();
        let thread_ids: Vec<StoreId> = std::thread::scope(|sc| {
            let hs: Vec<_> = (0..16)
                .map(|i| {
                    let root = &root;
                    sc.spawn(move || {
                        let cs = CoordStore::open(root);
                        if i % 2 == 0 {
                            cs.ensure_store_id().unwrap()
                        } else {
                            claim(&cs, &format!("t{i}"), &format!("f{i}.c")).unwrap();
                            cs.store_id().unwrap().unwrap()
                        }
                    })
                })
                .collect();
            hs.into_iter().map(|h| h.join().unwrap()).collect()
        });
        let proc_ids: Vec<StoreId> = kids
            .into_iter()
            .map(|k| {
                let o = k.wait_with_output().unwrap();
                assert!(o.status.success());
                StoreId::parse_hex(String::from_utf8(o.stdout).unwrap().trim()).unwrap()
            })
            .collect();
        let on_disk = StoreId::decode(&marker(&root)).unwrap();
        for id in thread_ids.iter().chain(&proc_ids) {
            assert_eq!(*id, on_disk, "round {round}: every opener sees one id");
        }
        let stray: Vec<_> = fs::read_dir(&root)
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().into_string().unwrap())
            .filter(|n| n.starts_with("STORE_ID.tmp"))
            .collect();
        assert!(stray.is_empty(), "temporary markers cleaned up: {stray:?}");
    }
}

#[test]
fn expecting_open_refuses_missing_marker_and_creates_nothing() {
    let s = Scratch::new("missing");
    let root = s.0.join("crumb/v1");
    // A store crumb.c has used but no Synapse opener has marked: layout without STORE_ID.
    for d in ["dirs", "agents", "continuations", "ledger"] {
        fs::create_dir_all(root.join(d)).unwrap();
    }
    let id = StoreId::random().unwrap();
    match CoordStore::open_expecting(&root, id) {
        Err(CoordError::StoreIdMissing { root: r }) => assert_eq!(r, root),
        other => panic!("expected StoreIdMissing, got {other:?}"),
    }
    let empty = s.0.join("never/used");
    assert!(matches!(
        CoordStore::open_expecting(&empty, id),
        Err(CoordError::StoreIdMissing { .. })
    ));
    assert!(!empty.exists(), "refusal creates nothing");
    assert!(!root.join(STORE_ID_FILE).exists());
}

#[test]
fn expecting_open_refuses_mismatch_and_writes_nothing() {
    let s = Scratch::new("mismatch");
    let a = s.0.join("a/crumb/v1");
    let b = s.0.join("b/crumb/v1");
    let id_a = CoordStore::open(&a).ensure_store_id().unwrap();
    let id_b = CoordStore::open(&b).ensure_store_id().unwrap();
    assert_ne!(id_a, id_b, "two stores, two ids");
    match CoordStore::open_expecting(&b, id_a) {
        Err(CoordError::StoreIdMismatch {
            expected, found, ..
        }) => assert_eq!((expected, found), (id_a, id_b)),
        other => panic!("expected StoreIdMismatch, got {other:?}"),
    }
    let ok = CoordStore::open_expecting(&a, id_a).unwrap();
    assert_eq!(ok.expected_store_id(), Some(id_a));
    assert!(matches!(
        claim(&ok, "a", "x.c").unwrap(),
        ClaimOutcome::Claimed { .. }
    ));
    assert!(!b.join("dirs/_root.json").exists());
}

#[test]
fn expectation_is_rechecked_inside_every_transaction() {
    let s = Scratch::new("recheck");
    let root = s.0.join("crumb/v1");
    let id = CoordStore::open(&root).ensure_store_id().unwrap();
    let cs = CoordStore::open_expecting(&root, id).unwrap();
    assert!(matches!(
        claim(&cs, "a", "x.c").unwrap(),
        ClaimOutcome::Claimed { .. }
    ));
    // The root is repointed / replaced after the handle was opened.
    let other = StoreId::random().unwrap();
    fs::write(root.join(STORE_ID_FILE), other.encode()).unwrap();
    assert!(matches!(
        claim(&cs, "a", "y.c"),
        Err(CoordError::StoreIdMismatch { .. })
    ));
    assert!(matches!(
        cs.sniff(&ws("a"), "a", "."),
        Err(CoordError::StoreIdMismatch { .. })
    ));
    fs::remove_file(root.join(STORE_ID_FILE)).unwrap();
    assert!(matches!(
        cs.ensure_store_id(),
        Err(CoordError::StoreIdMissing { .. })
    ));
    assert!(
        !root.join(STORE_ID_FILE).exists(),
        "an expecting handle never creates a marker"
    );
}

#[test]
fn unreadable_marker_is_refused_not_rewritten() {
    let s = Scratch::new("unreadable");
    let root = s.0.join("crumb/v1");
    fs::create_dir_all(&root).unwrap();
    let junk = b"crumb-coord-store-id/9 0123\n";
    fs::write(root.join(STORE_ID_FILE), junk).unwrap();
    let cs = CoordStore::open(&root);
    assert!(matches!(
        claim(&cs, "a", "x.c"),
        Err(CoordError::StoreIdUnreadable { .. })
    ));
    assert_eq!(marker(&root), junk);
}

#[test]
fn crash_before_marker_link_leaves_no_marker_then_recovers() {
    let s = Scratch::new("crash");
    let root = s.0.join("crumb/v1");
    let st = cli(&root, &["id"])
        .env("SYNAPSE_COORD_FAULT", "storeid-before-link")
        .stderr(std::process::Stdio::null())
        .status()
        .unwrap();
    assert!(!st.success(), "process aborted at the fault point");
    assert!(!root.join(STORE_ID_FILE).exists(), "no torn marker");
    assert!(fs::read_dir(&root).unwrap().any(|e| e
        .unwrap()
        .file_name()
        .to_string_lossy()
        .starts_with("STORE_ID.tmp")));
    let o = cli(&root, &["id"]).output().unwrap();
    assert!(o.status.success());
    let id = StoreId::parse_hex(String::from_utf8(o.stdout).unwrap().trim()).unwrap();
    assert_eq!(StoreId::decode(&marker(&root)).unwrap(), id);
}

#[test]
fn marker_survives_pruning_expiry_and_close() {
    let s = Scratch::new("survive");
    let root = s.0.join("crumb/v1");
    let t0 = 1_800_000_000;
    let cs = CoordStore::open(&root).with_clock(move || t0);
    claim(&cs, "a", "x.c").unwrap();
    let before = marker(&root);
    cs.close(&ws("a"), "a", ".", "x.c", "modify", Some("done"))
        .unwrap();
    claim(&cs, "b", "y.c").unwrap();
    // Two days later: every lock, agent and whisper is pruned on the next mutation.
    let later = CoordStore::open(&root).with_clock(move || t0 + 2 * 86_400);
    claim(&later, "c", "z.c").unwrap();
    assert_eq!(marker(&root), before);
}

/// Negative control for the split-brain finding: two tools configured with different
/// roots both grant a claim on one file. Without an expectation nothing notices; the
/// expecting open refuses the wrong root.
#[test]
fn split_roots_are_silent_without_expectation_and_refused_with_it() {
    let s = Scratch::new("split");
    let right = s.0.join("repo/.git/crumb/v1");
    let wrong = s.0.join("elsewhere/crumb/v1");
    let registered = CoordStore::open(&right).ensure_store_id().unwrap();

    let git_side = CoordStore::open(&right);
    let synapse_misconfigured = CoordStore::open(&wrong);
    let a = claim(&git_side, "git-agent", "src/runtime.c").unwrap();
    let b = claim(&synapse_misconfigured, "syn-agent", "src/runtime.c").unwrap();
    assert!(
        matches!(a, ClaimOutcome::Claimed { .. }) && matches!(b, ClaimOutcome::Claimed { .. }),
        "the old failure: both agents own src/runtime.c"
    );

    // Same misconfiguration, opened as Synapse now does: refused.
    assert!(matches!(
        CoordStore::open_expecting(&wrong, registered),
        Err(CoordError::StoreIdMismatch { .. })
    ));
    let fresh_wrong = s.0.join("fresh/crumb/v1");
    assert!(matches!(
        CoordStore::open_expecting(&fresh_wrong, registered),
        Err(CoordError::StoreIdMissing { .. })
    ));
    // Correctly configured: the claim is blocked as it should be.
    let good = CoordStore::open_expecting(&right, registered).unwrap();
    assert!(matches!(
        claim(&good, "syn-agent", "src/runtime.c").unwrap(),
        ClaimOutcome::Blocked { .. }
    ));
}
