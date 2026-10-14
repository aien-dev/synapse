//! Ports of the RFC-0002 scenarios in aien-architecture 29780e5 `tools/crumb/test.sh`
//! (claim/block/close, T1..T7), plus crash-mid-write and byte-format checks.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU32, Ordering};
use synapse_coord::{
    ClaimOutcome, CloseOutcome, CoordError, CoordStore, Holder, NoOracle, Workspace,
};

static N: AtomicU32 = AtomicU32::new(0);

struct Scratch(PathBuf);
impl Scratch {
    fn new(tag: &str) -> Scratch {
        let p = std::env::temp_dir().join(format!(
            "synapse-coord-{tag}-{}-{}",
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

/// Two "worktrees" of one repository (wa on branch A, wb on branch B) and one store.
struct Fixture {
    _s: Scratch,
    store: PathBuf,
    wa: PathBuf,
    wb: PathBuf,
}

fn fixture(tag: &str) -> Fixture {
    let s = Scratch::new(tag);
    let store = s.0.join("store/crumb/v1");
    let wa = s.0.join("wa");
    let wb = s.0.join("wb");
    for w in [&wa, &wb] {
        fs::create_dir_all(w.join("src")).unwrap();
        fs::write(w.join("src/runtime.c"), "a").unwrap();
        fs::write(w.join("src/other.c"), "b").unwrap();
    }
    Fixture {
        _s: s,
        store,
        wa,
        wb,
    }
}

fn ws(top: &Path, branch: &str) -> Workspace {
    let mut h = Holder::git(branch, "0123456789ab", "ba9876543210");
    h.session = Some(format!("{branch}-session"));
    Workspace::worktree(top.to_str().unwrap(), h)
}

fn claimed(o: ClaimOutcome) -> String {
    match o {
        ClaimOutcome::Claimed { key } => key,
        ClaimOutcome::Blocked { key, holder } => {
            panic!("expected claim of {key}, held by {holder:?}")
        }
    }
}

fn blocked(o: ClaimOutcome) -> String {
    match o {
        ClaimOutcome::Blocked { holder, .. } => holder.holder,
        ClaimOutcome::Claimed { key } => panic!("expected {key} to be blocked"),
    }
}

#[test]
fn claim_block_update_whisper_close_history() {
    let f = fixture("basic");
    let cs = CoordStore::open(&f.store);
    let a = ws(&f.wa, "A");
    assert_eq!(
        claimed(
            cs.claim(&a, "laneA", "src", "runtime.c", "refactor", Some(600))
                .unwrap()
        ),
        "src/runtime.c"
    );
    assert_eq!(
        blocked(
            cs.claim(&a, "laneB", "src", "runtime.c", "also", None)
                .unwrap()
        ),
        "laneA"
    );
    claimed(
        cs.claim(&a, "laneB", "src", "other.c", "other file", None)
            .unwrap(),
    );
    cs.update(&a, "laneA", "src", "still on runtime.c", None)
        .unwrap();
    cs.whisper(
        &a,
        "laneA",
        "src",
        Some("laneB"),
        "runtime done soon",
        Some("high"),
        Some("src/runtime.c"),
    )
    .unwrap();
    let s = cs.sniff(&a, "laneB", "src").unwrap();
    assert!(s
        .whispers
        .iter()
        .any(|w| w.from == "laneA" && w.to.as_deref() == Some("laneB")));
    assert!(
        cs.sniff(&a, "laneC", "src").unwrap().whispers.is_empty(),
        "directed whisper hidden from others"
    );
    assert!(matches!(
        cs.close(&a, "laneB", "src", "runtime.c", "modify", None)
            .unwrap(),
        CloseOutcome::Refused { .. }
    ));
    assert!(matches!(
        cs.close(
            &a,
            "laneA",
            "src",
            "runtime.c",
            "modify",
            Some("done, ready")
        )
        .unwrap(),
        CloseOutcome::Closed {
            lock_was_held: true,
            ..
        }
    ));
    let s = cs.sniff(&a, "x", ".").unwrap();
    assert!(
        !s.locks.iter().any(|l| l.key == "src/runtime.c"),
        "lock released"
    );
    let rec = fs::read_to_string(f.store.join("dirs/src.json")).unwrap();
    assert!(rec.contains("\"history\"") && rec.contains("\"action\": \"modify\""));
    assert!(!f.wa.join("src/.crumb.local").exists());
    // laneA held nothing else: presence record removed; laneB still holds other.c.
    assert!(!f.store.join("agents/laneA.json").exists());
    assert!(f.store.join("agents/laneB.json").exists());
    assert!(matches!(
        cs.whisper(&a, "x", "src", None, "m", Some("urgent"), None),
        Err(CoordError::BadPriority(_))
    ));
    assert!(matches!(
        cs.close(&a, "laneB", "src", "other.c", "fix", None),
        Err(CoordError::BadAction(_))
    ));
}

#[test]
fn t1_t2_t3_t4_cross_workspace_visibility_conflict_release() {
    let f = fixture("cross");
    let cs = CoordStore::open(&f.store);
    let (a, b) = (ws(&f.wa, "A"), ws(&f.wb, "B"));
    claimed(
        cs.claim(&a, "agent-a", "src", "runtime.c", "rewrite runtime", None)
            .unwrap(),
    );
    let s = cs.sniff(&b, "agent-b", "src").unwrap();
    let l = s
        .locks
        .iter()
        .find(|l| l.key == "src/runtime.c")
        .expect("T1 B sees A's lock");
    assert_eq!((l.holder.as_str(), l.branch.as_str()), ("agent-a", "A"));
    let (w, agents, conflicts) = &s.other_workspaces[0];
    assert_eq!(w, f.wa.to_str().unwrap());
    assert_eq!(agents, &vec!["agent-a".to_string()]);
    assert_eq!(conflicts, &vec!["src/runtime.c".to_string()]);
    // T2
    blocked(
        cs.claim(&b, "agent-b", "src", "runtime.c", "also", None)
            .unwrap(),
    );
    blocked(
        cs.claim(
            &b,
            "agent-b",
            ".",
            "src/runtime.c",
            "repo-relative form",
            None,
        )
        .unwrap(),
    );
    cs.whisper(
        &a,
        "agent-a",
        "src",
        Some("agent-b"),
        "runtime half done",
        Some("high"),
        None,
    )
    .unwrap();
    assert!(cs
        .sniff(&b, "agent-b", "src")
        .unwrap()
        .whispers
        .iter()
        .any(|w| w.message == "runtime half done"));
    // T3
    assert!(matches!(
        cs.close(&b, "agent-b", "src", "runtime.c", "modify", None)
            .unwrap(),
        CloseOutcome::Refused { .. }
    ));
    cs.close(&a, "agent-a", "src", "runtime.c", "modify", Some("done"))
        .unwrap();
    claimed(
        cs.claim(&b, "agent-b", "src", "runtime.c", "my turn", None)
            .unwrap(),
    );
    cs.close(&b, "agent-b", "src", "runtime.c", "modify", None)
        .unwrap();
    // T4
    claimed(
        cs.claim(&a, "agent-a", "src", "one.c", "one", None)
            .unwrap(),
    );
    claimed(
        cs.claim(&b, "agent-b", "src", "two.c", "two", None)
            .unwrap(),
    );
    let keys: Vec<_> = cs
        .sniff(&a, "agent-a", "src")
        .unwrap()
        .locks
        .into_iter()
        .map(|l| l.key)
        .collect();
    assert!(keys.contains(&"src/one.c".into()) && keys.contains(&"src/two.c".into()));
}

fn cli(f: &Fixture, top: &Path, args: &[&str]) -> Command {
    let mut c = Command::new(env!("CARGO_BIN_EXE_synapse-coord"));
    c.arg("--store")
        .arg(&f.store)
        .arg("--top")
        .arg(top)
        .arg("--branch")
        .arg("X");
    c.args(args);
    c
}

#[test]
fn t5_concurrent_processes_no_lost_updates_and_one_winner() {
    let f = fixture("t5");
    let tops = [&f.wa, &f.wb];
    let kids: Vec<_> = (1..=8)
        .map(|i| {
            cli(
                &f,
                tops[i % 2],
                &[
                    "claim",
                    &format!("cagent{i}"),
                    "src",
                    &format!("c{i}.c"),
                    "par",
                ],
            )
            .output()
        })
        .collect();
    for k in kids {
        assert!(k.unwrap().status.success());
    }
    let cs = CoordStore::open(&f.store);
    let n = cs
        .sniff(&ws(&f.wa, "A"), "x", "src")
        .unwrap()
        .locks
        .iter()
        .filter(|l| l.key.starts_with("src/c"))
        .count();
    assert_eq!(n, 8, "8 concurrent claims on 8 targets: 8 locks survive");

    let children: Vec<_> = (1..=8)
        .map(|i| {
            cli(
                &f,
                tops[i % 2],
                &["claim", &format!("sagent{i}"), "src", "same.c", "race"],
            )
            .stdout(std::process::Stdio::null())
            .spawn()
            .unwrap()
        })
        .collect();
    let codes: Vec<i32> = children
        .into_iter()
        .map(|mut c| c.wait().unwrap().code().unwrap())
        .collect();
    assert_eq!(
        codes.iter().filter(|c| **c == 0).count(),
        1,
        "exactly one winner: {codes:?}"
    );
    assert_eq!(
        codes.iter().filter(|c| **c == 2).count(),
        7,
        "seven blocked: {codes:?}"
    );
    let same = cs
        .sniff(&ws(&f.wa, "A"), "x", "src")
        .unwrap()
        .locks
        .iter()
        .filter(|l| l.key == "src/same.c")
        .count();
    assert_eq!(same, 1);
}

#[test]
fn t5_concurrent_threads_in_one_process() {
    let f = fixture("t5thr");
    let wins = std::thread::scope(|s| {
        let hs: Vec<_> = (0..16)
            .map(|i| {
                let f = &f;
                s.spawn(move || {
                    let cs = CoordStore::open(&f.store);
                    let w = ws(if i % 2 == 0 { &f.wa } else { &f.wb }, "T");
                    claimed(
                        cs.claim(&w, &format!("t{i}"), "src", &format!("d{i}.c"), "par", None)
                            .unwrap(),
                    );
                    matches!(
                        cs.claim(&w, &format!("t{i}"), "src", "same.c", "race", None)
                            .unwrap(),
                        ClaimOutcome::Claimed { .. }
                    )
                })
            })
            .collect();
        hs.into_iter()
            .map(|h| h.join().unwrap())
            .filter(|w| *w)
            .count()
    });
    assert_eq!(wins, 1);
    let locks = CoordStore::open(&f.store)
        .sniff(&ws(&f.wa, "A"), "x", "src")
        .unwrap()
        .locks;
    assert_eq!(locks.len(), 17, "16 distinct + 1 raced lock");
}

#[test]
fn t6_expiry_prunes_dead_lock_and_agent() {
    let f = fixture("t6");
    let t0 = 1_800_000_000;
    let early = CoordStore::open(&f.store).with_clock(move || t0);
    let late = CoordStore::open(&f.store).with_clock(move || t0 + 2);
    let (a, b) = (ws(&f.wa, "A"), ws(&f.wb, "B"));
    claimed(
        early
            .claim(&a, "dead-agent", "src", "ttl.c", "crashes", Some(1))
            .unwrap(),
    );
    // Scent TTL for a claim is max(SCENT_TTL, lock ttl): the agent is still present, the lock is not.
    assert!(
        late.sniff(&b, "x", "src").unwrap().locks.is_empty(),
        "expired lock hidden from sniff"
    );
    claimed(
        late.claim(&b, "live-agent", "src", "ttl.c", "takes over", None)
            .unwrap(),
    );
    let s = late.sniff(&b, "x", "src").unwrap();
    assert!(s.locks.iter().all(|l| l.holder != "dead-agent"));
    // Agent presence expires after its own TTL and the record is unlinked on the next mutation.
    let much_later =
        CoordStore::open(&f.store).with_clock(move || t0 + synapse_coord::SCENT_TTL + 5);
    much_later.update(&b, "other", "src", "tick", None).unwrap();
    assert!(!f.store.join("agents/dead-agent.json").exists());
    // Whisper retention: 24 h.
    early
        .whisper(&a, "old", "src", None, "stale note", None, None)
        .unwrap();
    let day_later =
        CoordStore::open(&f.store).with_clock(move || t0 + synapse_coord::WHISPER_RETENTION + 1);
    assert!(day_later.sniff(&a, "x", "src").unwrap().whispers.is_empty());
}

#[test]
fn t7_path_normalization_and_escape_refusal() {
    let f = fixture("t7");
    let cs = CoordStore::open(&f.store);
    let (a, b) = (ws(&f.wa, "A"), ws(&f.wb, "B"));
    let abs_a = format!("{}/src/abs.c", f.wa.display());
    assert_eq!(
        claimed(cs.claim(&a, "agent-a", ".", &abs_a, "abs", None).unwrap()),
        "src/abs.c"
    );
    let abs_b = format!("{}/src/abs.c", f.wb.display());
    blocked(
        cs.claim(&b, "agent-b", "src", &abs_b, "abs b", None)
            .unwrap(),
    );
    blocked(
        cs.claim(&b, "agent-b", "src", "../src/./abs.c", "dots", None)
            .unwrap(),
    );
    let outside = format!("{}/elsewhere.c", f.wa.display());
    assert!(matches!(
        cs.claim(&b, "agent-b", ".", &outside, "x", None),
        Err(CoordError::OutsideWorkspace { .. })
    ));
    assert!(matches!(
        cs.claim(&b, "agent-b", ".", "../../etc/passwd", "x", None),
        Err(CoordError::EscapesRoot { .. })
    ));
    assert!(matches!(
        cs.claim(&b, "agent-b", "..", "x.c", "x", None),
        Err(CoordError::EscapesRoot { .. })
    ));
    // Root-relative target named from a subdirectory: resolved via the oracle, as crumb.c does.
    fs::write(f.wa.join("README"), "r").unwrap();
    assert_eq!(
        claimed(cs.claim(&a, "agent-a", "src", "README", "x", None).unwrap()),
        "README"
    );
    // Without a tree a relative target from a subdirectory is refused (crumb.c would resolve it
    // by file existence; a guess could key one file twice). From the root it is unambiguous.
    let blind = Workspace::with_oracle("/nowhere", Holder::default(), Box::new(NoOracle));
    assert!(matches!(
        blind.target_key("README", "src"),
        Err(CoordError::AmbiguousWithoutTree { .. })
    ));
    assert!(matches!(
        blind.target_key("src/x.c", "docs"),
        Err(CoordError::AmbiguousWithoutTree { .. })
    ));
    assert_eq!(blind.target_key("README", ".").unwrap(), "README");
    assert_eq!(blind.target_key("src/x.c", ".").unwrap(), "src/x.c");
    assert_eq!(
        blind.target_key("/nowhere/src/x.c", "docs").unwrap(),
        "src/x.c"
    );
}

#[test]
fn session_id_is_never_a_pid() {
    let f = fixture("sess");
    let cs = CoordStore::open(&f.store);
    let w = Workspace::worktree(f.wa.to_str().unwrap(), Holder::git("A", "h", "b"));
    cs.update(&w, "agent-a", "src", "focus", None).unwrap();
    let rec = fs::read_to_string(f.store.join("agents/agent-a.json")).unwrap();
    assert!(rec.contains("\"session\": \"agent-a@"), "{rec}");
}

#[test]
fn crash_torn_tmp_files_are_ignored() {
    let f = fixture("torn");
    let cs = CoordStore::open(&f.store);
    let a = ws(&f.wa, "A");
    claimed(
        cs.claim(&a, "agent-a", "src", "runtime.c", "x", None)
            .unwrap(),
    );
    let good = fs::read(f.store.join("dirs/src.json")).unwrap();
    // Leftovers of writers that died mid-write (crumb.c and Rust both name tmp files <record>.tmp<pid>).
    fs::write(
        f.store.join("dirs/src.json.tmp4242"),
        b"{\"locks\": {\"src/oth",
    )
    .unwrap();
    fs::write(f.store.join("agents/ghost.json.tmp7"), b"").unwrap();
    fs::create_dir_all(f.store.join("dirs/deep")).unwrap();
    fs::write(f.store.join("dirs/deep/x.json.tmp1"), b"garbage").unwrap();
    let s = cs.sniff(&a, "x", "src").unwrap();
    assert_eq!(s.locks.len(), 1);
    assert_eq!(s.agents.len(), 1);
    blocked(
        cs.claim(&ws(&f.wb, "B"), "agent-b", "src", "runtime.c", "y", None)
            .unwrap(),
    );
    assert_eq!(
        fs::read(f.store.join("dirs/src.json")).unwrap(),
        good,
        "refused claim writes nothing new"
    );
}

#[test]
fn crash_between_tmp_write_and_rename_leaves_store_valid() {
    let f = fixture("abort");
    let cs = CoordStore::open(&f.store);
    let a = ws(&f.wa, "A");
    claimed(
        cs.claim(&a, "agent-a", "src", "runtime.c", "first", None)
            .unwrap(),
    );
    let before = fs::read(f.store.join("dirs/src.json")).unwrap();
    // A real process dies (SIGABRT) after its tmp file is fsynced, before rename, holding the OS lock.
    let out = cli(&f, &f.wb, &["claim", "agent-b", "src", "other.c", "doomed"])
        .env("SYNAPSE_COORD_FAULT", "before-rename")
        .output()
        .unwrap();
    assert!(!out.status.success(), "child must have crashed");
    let leftovers: Vec<_> = fs::read_dir(f.store.join("dirs"))
        .unwrap()
        .filter_map(|e| e.ok())
        .map(|e| e.file_name().into_string().unwrap())
        .filter(|n| n.contains(".tmp"))
        .collect();
    assert!(!leftovers.is_empty(), "the crash left a tmp file behind");
    assert_eq!(
        fs::read(f.store.join("dirs/src.json")).unwrap(),
        before,
        "old record intact"
    );
    // OS released the dead process's lock; the half-done claim never happened; store is usable.
    let s = cs.sniff(&a, "x", "src").unwrap();
    assert_eq!(
        s.locks.iter().map(|l| l.key.as_str()).collect::<Vec<_>>(),
        vec!["src/runtime.c"]
    );
    claimed(
        cs.claim(&ws(&f.wb, "B"), "agent-b", "src", "other.c", "retry", None)
            .unwrap(),
    );
}

#[test]
fn corrupt_record_is_refused_not_overwritten() {
    let f = fixture("corrupt");
    fs::create_dir_all(f.store.join("dirs")).unwrap();
    fs::write(f.store.join("dirs/src.json"), b"{broken").unwrap();
    let cs = CoordStore::open(&f.store);
    let r = cs.claim(&ws(&f.wa, "A"), "a", "src", "runtime.c", "x", None);
    assert!(matches!(r, Err(CoordError::CorruptRecord { .. })));
    assert_eq!(fs::read(f.store.join("dirs/src.json")).unwrap(), b"{broken");
}

#[test]
fn record_bytes_match_crumb_c_layout() {
    let f = fixture("bytes");
    let t0 = 1_800_000_000; // 2027-01-15T08:00:00Z
    let cs = CoordStore::open(&f.store).with_clock(move || t0);
    let top = f.wa.to_str().unwrap();
    let mut h = Holder::synapse("lane/main", &"ab".repeat(32), &"cd".repeat(32));
    h.session = Some("s1".into());
    let w = Workspace::worktree(top, h);
    claimed(
        cs.claim(&w, "agent-a", "src", "runtime.c", "rewrite", None)
            .unwrap(),
    );
    let dir = fs::read_to_string(f.store.join("dirs/src.json")).unwrap();
    let expect_dir = format!(
        "{{\n  \"schema_version\": \"1.0.0\",\n  \"directory\": \"src\",\n  \"locks\": {{\n    \"src/runtime.c\": {{\n      \"holder\": \"agent-a\",\n      \"session\": \"s1\",\n      \"target\": \"src/runtime.c\",\n      \"intent\": \"rewrite\",\n      \"worktree\": \"{top}\",\n      \"branch\": \"lane/main\",\n      \"head\": \"abababababab\",\n      \"base\": \"cdcdcdcdcdcd\",\n      \"acquired_at\": \"2027-01-15T08:00:00Z\",\n      \"ttl_seconds\": 1800,\n      \"synapse_revision\": \"{}\"\n    }}\n  }}\n}}\n",
        "ab".repeat(32)
    );
    assert_eq!(dir, expect_dir);
    let ag = fs::read_to_string(f.store.join("agents/agent-a.json")).unwrap();
    let expect_ag = format!(
        "{{\n  \"agent\": \"agent-a\",\n  \"session\": \"s1\",\n  \"focus\": \"rewrite\",\n  \"dir\": \"src\",\n  \"worktree\": \"{top}\",\n  \"branch\": \"lane/main\",\n  \"head\": \"abababababab\",\n  \"base\": \"cdcdcdcdcdcd\",\n  \"updated_at\": \"2027-01-15T08:00:00Z\",\n  \"ttl_seconds\": 3600,\n  \"synapse_revision\": \"{}\"\n}}\n",
        "ab".repeat(32)
    );
    assert_eq!(ag, expect_ag);
    assert!(f.store.join(".lock").exists());
    for sub in ["dirs", "agents", "continuations", "ledger"] {
        assert!(f.store.join(sub).is_dir());
    }
}

#[test]
fn unknown_fields_survive_and_history_is_capped() {
    let f = fixture("unknown");
    let cs = CoordStore::open(&f.store);
    let a = ws(&f.wa, "A");
    fs::create_dir_all(f.store.join("dirs")).unwrap();
    fs::write(
        f.store.join("dirs/src.json"),
        b"{\"schema_version\":\"1.0.0\",\"directory\":\"src\",\"x_future\":{\"k\":[1,2.5e3,true,null]},\"legacy_imported\":[\"/wt\"]}",
    )
    .unwrap();
    for i in 0..25 {
        cs.close(&a, "agent-a", "src", &format!("f{i}.c"), "audit", None)
            .unwrap();
    }
    let rec = fs::read_to_string(f.store.join("dirs/src.json")).unwrap();
    assert!(rec.contains("\"x_future\": {\n    \"k\": [\n      1,\n      2.5e3,\n      true,\n      null\n    ]\n  }"));
    assert!(rec.contains("\"legacy_imported\""));
    assert_eq!(
        rec.matches("\"action\": \"audit\"").count(),
        synapse_coord::HISTORY_CAP
    );
    assert!(
        !rec.contains("src/f4.c") && rec.contains("src/f5.c"),
        "oldest entries dropped"
    );
}
