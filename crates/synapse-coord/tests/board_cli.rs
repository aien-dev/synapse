//! Board through the real binary (issue #83): concurrent writer processes, crashes at every
//! fault point, subscriber kill and cursor resume, a lost wake datagram, and hostile files.
//! Every child runs under a 5 s watchdog (killed and failed past it), like tests/hostile.rs.

use std::collections::BTreeSet;
use std::fs;
use std::io::Write;
use std::os::unix::fs::symlink;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant};
use synapse_coord::json::{self, J};

const BIN: &str = env!("CARGO_BIN_EXE_synapse-coord");
static N: AtomicU32 = AtomicU32::new(0);

struct Fx {
    root: PathBuf,
}
impl Drop for Fx {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

fn fx(name: &str) -> Fx {
    let root = std::env::temp_dir().join(format!(
        "sb-cli-{name}-{}-{}",
        std::process::id(),
        N.fetch_add(1, Ordering::SeqCst)
    ));
    let _ = fs::remove_dir_all(&root);
    let f = Fx { root };
    let o = run(&f.root, None, &["init"], &[]);
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    f
}

fn cmd(root: &Path, session: Option<&str>, args: &[&str], env: &[(&str, &str)]) -> Command {
    let mut c = Command::new(BIN);
    c.arg("board").arg("--board-root").arg(root);
    if let Some(s) = session {
        c.arg("--session").arg(s);
    }
    c.args(args)
        .env_remove("SYNAPSE_COORD_FAULT")
        .env_remove("SYNAPSE_BOARD_ID")
        .env_remove("SYNAPSE_BOARD_SESSION")
        .env_remove("CRUMB_SESSION");
    for (k, v) in env {
        c.env(k, v);
    }
    c.stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    c
}

/// Wait for a child under the 5 s watchdog.
fn finish(mut ch: Child, what: &str) -> Output {
    let t = Instant::now();
    loop {
        if ch.try_wait().unwrap().is_some() {
            return ch.wait_with_output().unwrap();
        }
        if t.elapsed() > Duration::from_secs(5) {
            let _ = ch.kill();
            let _ = ch.wait();
            panic!("{what} hung past the 5 s watchdog");
        }
        std::thread::sleep(Duration::from_millis(2));
    }
}

fn run(root: &Path, session: Option<&str>, args: &[&str], env: &[(&str, &str)]) -> Output {
    finish(
        cmd(root, session, args, env).spawn().unwrap(),
        &args.join(" "),
    )
}

fn lines(o: &Output) -> Vec<J> {
    String::from_utf8_lossy(&o.stdout)
        .lines()
        .map(|l| json::parse(l.as_bytes()).unwrap_or_else(|| panic!("not JSON: {l}")))
        .collect()
}

fn num(j: &J, k: &str) -> Option<u64> {
    match j.get(k) {
        Some(J::Num(t)) => std::str::from_utf8(t).ok()?.parse().ok(),
        _ => None,
    }
}

fn s(j: &J, k: &str) -> Option<String> {
    j.str_of(k)
}

fn summary(o: &Output) -> J {
    lines(o).pop().expect("a summary line")
}

fn ok(o: &Output) -> J {
    assert!(
        o.status.success(),
        "exit {:?}: {} {}",
        o.status.code(),
        String::from_utf8_lossy(&o.stdout),
        String::from_utf8_lossy(&o.stderr)
    );
    summary(o)
}

/// A refusal: exit 2 and the named error.
fn refused(o: &Output, name: &str) {
    assert_eq!(
        o.status.code(),
        Some(2),
        "{} {}",
        String::from_utf8_lossy(&o.stdout),
        String::from_utf8_lossy(&o.stderr)
    );
    assert_eq!(s(&summary(o), "error").as_deref(), Some(name));
}

fn register(f: &Fx, session: &str, tag: &str) {
    ok(&run(&f.root, Some(session), &["register", tag], &[]));
}

fn post(f: &Fx, session: &str, text: &str, extra: &[&str]) -> u64 {
    let mut a = vec!["post", "--thread", "t", "--topic", "lane/x", "--text", text];
    a.extend_from_slice(extra);
    num(&ok(&run(&f.root, Some(session), &a, &[])), "id").unwrap()
}

/// Every event on the board, by id, through the operator view.
fn all(f: &Fx) -> Vec<(u64, String)> {
    let o = run(&f.root, None, &["read", "--all", "--limit", "1024"], &[]);
    let mut v = lines(&o);
    let sum = v.pop().unwrap();
    assert_eq!(sum.get("ok"), Some(&J::True), "{:?}", sum);
    v.iter()
        .map(|j| (num(j, "id").unwrap(), s(j, "text").unwrap()))
        .collect()
}

fn check_ok(f: &Fx) {
    let o = run(&f.root, None, &["check"], &[]);
    assert!(
        o.status.success(),
        "check: {}",
        String::from_utf8_lossy(&o.stdout)
    );
}

fn concurrent_writers(writers: usize, per: usize) {
    let f = fx(&format!("conc{writers}"));
    for w in 0..writers {
        register(&f, &format!("s{w}"), &format!("w{w}"));
    }
    let root = f.root.clone();
    let handles: Vec<_> = (0..writers)
        .map(|w| {
            let root = root.clone();
            std::thread::spawn(move || {
                let mut ids = Vec::new();
                for i in 0..per {
                    let text = format!("w{w}-{i}");
                    let o = finish(
                        cmd(
                            &root,
                            Some(&format!("s{w}")),
                            &[
                                "post", "--thread", "t", "--topic", "lane/x", "--text", &text,
                            ],
                            &[],
                        )
                        .spawn()
                        .unwrap(),
                        "post",
                    );
                    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
                    ids.push(num(&summary(&o), "id").unwrap());
                }
                ids
            })
        })
        .collect();
    let mut acked = BTreeSet::new();
    for h in handles {
        for id in h.join().unwrap() {
            assert!(acked.insert(id), "id {id} acknowledged twice");
        }
    }
    let total = (writers * per) as u64;
    assert_eq!(
        acked,
        (1..=total).collect::<BTreeSet<_>>(),
        "no lost, no duplicate id"
    );
    let ev = all(&f);
    assert_eq!(ev.len() as u64, total);
    let texts: BTreeSet<_> = ev.iter().map(|e| e.1.clone()).collect();
    assert_eq!(texts.len() as u64, total, "every body exactly once");
    for (k, (id, _)) in ev.iter().enumerate() {
        assert_eq!(*id, k as u64 + 1);
    }
    check_ok(&f);
}

#[test]
fn concurrent_writers_1() {
    concurrent_writers(1, 24);
}

#[test]
fn concurrent_writers_4() {
    concurrent_writers(4, 12);
}

#[test]
fn concurrent_writers_8() {
    concurrent_writers(8, 8);
}

#[test]
fn concurrent_writers_32() {
    concurrent_writers(32, 4);
}

/// Crash a post at `point`, then show: every acknowledged event survives, the board checks
/// clean after the next post, and ids stay contiguous with no duplicate.
fn crash_at(point: &str) -> (Fx, J) {
    let f = fx(&format!("crash-{point}"));
    register(&f, "sa", "alpha");
    register(&f, "sb", "beta");
    ok(&run(
        &f.root,
        Some("sb"),
        &["subscribe", "--topic", "lane/x"],
        &[],
    ));
    for i in 1..=3 {
        assert_eq!(post(&f, "sa", &format!("acked {i}"), &["--to", "beta"]), i);
    }
    let o = run(
        &f.root,
        Some("sa"),
        &[
            "post", "--thread", "t", "--topic", "lane/x", "--to", "beta", "--text", "crashing",
        ],
        &[("SYNAPSE_COORD_FAULT", point)],
    );
    assert_eq!(
        o.status.code(),
        Some(86),
        "{point}: the post must die at the fault"
    );
    assert!(lines(&o).is_empty(), "{point}: no ACK was printed");
    let after = ok(&run(
        &f.root,
        Some("sa"),
        &[
            "post", "--thread", "t", "--topic", "lane/x", "--to", "beta", "--text", "after",
        ],
        &[],
    ));
    let ev = all(&f);
    for i in 1..=3u64 {
        assert_eq!(ev[i as usize - 1], (i, format!("acked {i}")), "{point}");
    }
    for (k, (id, _)) in ev.iter().enumerate() {
        assert_eq!(*id, k as u64 + 1, "{point}: contiguous ids");
    }
    assert_eq!(ev.last().unwrap().1, "after");
    check_ok(&f);
    // the addressed reader sees every surviving event through its inbox index
    let o = run(
        &f.root,
        Some("sb"),
        &["read", "--mine", "--limit", "100"],
        &[],
    );
    let n = lines(&o).len() - 1;
    assert_eq!(n, ev.len(), "{point}: inbox index agrees after recovery");
    (f, after)
}

#[test]
fn crash_torn_journal_write_is_cut_and_named() {
    let (_f, after) = crash_at("torn-journal-write");
    assert_eq!(num(&after, "id"), Some(4));
    assert!(
        num(&after, "torn_tail_at").is_some(),
        "torn tail named: {after:?}"
    );
}

#[test]
fn crash_before_journal_fsync_adopts_complete_frame() {
    let (_f, after) = crash_at("before-journal-fsync");
    // The process died, the kernel kept the page: a complete verifying frame is adopted.
    assert_eq!(num(&after, "id"), Some(5));
}

#[test]
fn crash_after_journal_before_index_repairs_indexes() {
    let (_f, after) = crash_at("after-journal-before-index");
    assert_eq!(num(&after, "id"), Some(5));
}

#[test]
fn crash_before_table_entry_adopts() {
    let (_f, after) = crash_at("before-table-entry");
    assert_eq!(num(&after, "id"), Some(5));
}

#[test]
fn crash_before_ack_keeps_committed_event() {
    let (f, after) = crash_at("before-ack");
    assert_eq!(num(&after, "id"), Some(5));
    assert_eq!(all(&f)[3].1, "crashing", "committed before the ACK, kept");
}

#[test]
fn crash_between_compaction_renames_rebuilds_table() {
    let f = fx("crash-compact");
    register(&f, "sa", "alpha");
    for i in 1..=6 {
        post(&f, "sa", &format!("e{i}"), &[]);
    }
    let o = run(
        &f.root,
        None,
        &["compact", "--keep-since", "4"],
        &[("SYNAPSE_COORD_FAULT", "compact-between-renames")],
    );
    assert_eq!(o.status.code(), Some(86));
    // A reader alone heals the cut: writer recovery rebuilds journal.idx, cuts nothing.
    let g = fx("crash-compact-reader");
    register(&g, "sa", "alpha");
    for i in 1..=6 {
        post(&g, "sa", &format!("e{i}"), &[]);
    }
    let og = run(
        &g.root,
        None,
        &["compact", "--keep-since", "4"],
        &[("SYNAPSE_COORD_FAULT", "compact-between-renames")],
    );
    assert_eq!(og.status.code(), Some(86));
    let ids: Vec<u64> = all(&g).iter().map(|e| e.0).collect();
    assert_eq!(ids, vec![4, 5, 6]);
    check_ok(&g);
    let r = ok(&run(&f.root, None, &["recover"], &[]));
    assert_eq!(r.get("table_rebuilt"), Some(&J::True), "{r:?}");
    post(&f, "sa", "e7", &[]);
    let ev = all(&f);
    let ids: Vec<u64> = ev.iter().map(|e| e.0).collect();
    assert_eq!(
        ids,
        vec![4, 5, 6, 7],
        "kept events survive the cut compaction"
    );
    check_ok(&f);
}

#[test]
fn subscriber_kill_and_cursor_resume_has_no_gap() {
    let f = fx("resume");
    register(&f, "sa", "alpha");
    register(&f, "sb", "beta");
    ok(&run(
        &f.root,
        Some("sb"),
        &["subscribe", "--thread", "t"],
        &[],
    ));
    for i in 1..=10 {
        post(&f, "sa", &format!("e{i}"), &[]);
    }
    let r = run(&f.root, Some("sb"), &["read", "--limit", "4"], &[]);
    assert_eq!(lines(&r).len(), 5);
    ok(&run(&f.root, Some("sb"), &["ack", "4"], &[]));
    // a watcher takes deliveries, then is killed before it acks
    let w = cmd(
        &f.root,
        Some("sb"),
        &["watch", "--follow", "1000", "--timeout-ms", "4000"],
        &[],
    )
    .spawn()
    .unwrap();
    for i in 11..=13 {
        post(&f, "sa", &format!("e{i}"), &[]);
    }
    std::thread::sleep(Duration::from_millis(150));
    let mut w = w;
    w.kill().unwrap();
    let _ = w.wait();
    // restart: resume from acked, every unprocessed event comes back, in order, no gap
    let r = run(&f.root, Some("sb"), &["read", "--limit", "100"], &[]);
    let mut v = lines(&r);
    v.pop();
    let ids: Vec<u64> = v.iter().map(|j| num(j, "id").unwrap()).collect();
    assert_eq!(ids, (5..=13).collect::<Vec<_>>());
    ok(&run(&f.root, Some("sb"), &["ack", "13"], &[]));
    ok(&run(&f.root, Some("sb"), &["ack", "7"], &[])); // idempotent below the cursor
    let r = run(&f.root, Some("sb"), &["read"], &[]);
    assert_eq!(lines(&r).len(), 1, "nothing left after the ack");
}

#[test]
fn lost_datagram_watch_times_out_and_still_reads() {
    let f = fx("lostwake");
    register(&f, "sa", "alpha");
    register(&f, "sb", "beta");
    let w = cmd(&f.root, Some("sb"), &["watch", "--timeout-ms", "400"], &[])
        .spawn()
        .unwrap();
    std::thread::sleep(Duration::from_millis(100));
    let t = Instant::now();
    let p = ok(&run(
        &f.root,
        Some("sa"),
        &[
            "post", "--thread", "t", "--topic", "lane/x", "--to", "beta", "--text", "quiet",
        ],
        &[("SYNAPSE_COORD_FAULT", "drop-wake")],
    ));
    assert_eq!(num(&p, "woke"), Some(0), "the wake was dropped");
    let o = finish(w, "watch");
    let sum = ok(&o);
    assert_eq!(
        num(&sum, "count"),
        Some(1),
        "read after the timeout: {sum:?}"
    );
    assert_eq!(num(&sum, "wakes"), Some(0));
    assert!(t.elapsed() >= Duration::from_millis(200));
}

#[test]
fn hostile_inputs_refused_by_name() {
    let f = fx("hostile");
    register(&f, "sa", "alpha");
    register(&f, "sb", "beta");
    register(&f, "sc", "gamma");
    post(&f, "sa", "first", &["--to", "beta"]);
    // oversize text
    let big = "x".repeat(4097);
    refused(
        &run(
            &f.root,
            Some("sa"),
            &["post", "--thread", "t", "--topic", "lane/x", "--text", &big],
            &[],
        ),
        "TooLarge",
    );
    // unregistered session
    refused(
        &run(&f.root, Some("nobody"), &["read"], &[]),
        "NotRegistered",
    );
    // unauthorised audience: gamma neither addressed nor subscribed sees nothing
    let r = run(&f.root, Some("sc"), &["read"], &[]);
    assert_eq!(lines(&r).len(), 1);
    // wrong mission
    refused(
        &run(
            &f.root,
            None,
            &[
                "--expect-board-id",
                "00000000000000000000000000000001",
                "check",
            ],
            &[],
        ),
        "BoardIdMismatch",
    );
    // bogus cursor ids
    refused(
        &run(&f.root, Some("sb"), &["read", "--after", "999"], &[]),
        "CursorAhead",
    );
    fs::create_dir_all(f.root.join("cursors")).unwrap();
    fs::write(
        f.root.join("cursors/beta.json"),
        "{\"v\":\"aien-board/1\",\"tag\":\"beta\",\"delivered\":999,\"acked\":0,\"expired\":false}\n",
    )
    .unwrap();
    refused(&run(&f.root, Some("sb"), &["read"], &[]), "BadCursor");
    fs::remove_file(f.root.join("cursors/beta.json")).unwrap();
    // truncated frame appended: the next post cuts and names it
    {
        let mut j = fs::OpenOptions::new()
            .append(true)
            .open(f.root.join("journal.log"))
            .unwrap();
        j.write_all(&[40, 0, 0, 0, 1, 2]).unwrap();
    }
    assert_eq!(all(&f).len(), 1, "readers ignore the unacknowledged tail");
    let p = ok(&run(
        &f.root,
        Some("sa"),
        &[
            "post", "--thread", "t", "--topic", "lane/x", "--text", "second",
        ],
        &[],
    ));
    assert_eq!(num(&p, "id"), Some(2));
    assert!(num(&p, "torn_tail_at").is_some());
    check_ok(&f);
}

#[test]
fn foreign_mission_frame_refused() {
    let a = fx("mission-a");
    let b = fx("mission-b");
    for f in [&a, &b] {
        register(f, "sa", "alpha");
        post(f, "sa", "same", &[]);
    }
    post(&b, "sa", "from b", &[]);
    let ja = fs::read(a.root.join("journal.log")).unwrap();
    let jb = fs::read(b.root.join("journal.log")).unwrap();
    // board b's frame #2 (mission b) planted after board a's frame #1
    fs::OpenOptions::new()
        .append(true)
        .open(a.root.join("journal.log"))
        .unwrap()
        .write_all(&jb[ja.len()..])
        .unwrap();
    refused(
        &run(
            &a.root,
            Some("sa"),
            &["post", "--thread", "t", "--topic", "lane/x", "--text", "x"],
            &[],
        ),
        "ForeignMission",
    );
}

#[test]
fn planted_symlink_and_fifo_refused_promptly() {
    for name in ["journal.log", "journal.idx", "cursors/beta.json"] {
        for kind in ["symlink", "fifo"] {
            let f = fx("plant");
            register(&f, "sa", "alpha");
            register(&f, "sb", "beta");
            post(&f, "sa", "e1", &["--to", "beta"]);
            ok(&run(&f.root, Some("sb"), &["read"], &[]));
            let p = f.root.join(name);
            fs::remove_file(&p).unwrap();
            if kind == "symlink" {
                symlink("/dev/zero", &p).unwrap();
            } else {
                let st = Command::new("mkfifo").arg(&p).status().unwrap();
                assert!(st.success());
            }
            let post_args = ["post", "--thread", "t", "--topic", "lane/x", "--text", "x"];
            let cases: Vec<&[&str]> = if name.starts_with("cursors") {
                vec![&["read"]]
            } else {
                vec![&["read"], &post_args]
            };
            for args in cases {
                let o = run(&f.root, Some("sb"), args, &[]);
                refused(&o, "Refused");
            }
        }
    }
}
