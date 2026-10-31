//! Board core (issue #83): tags, posting, addressing, subscriptions, cursors, `get`, `ack`,
//! idempotency, restart, the index/journal agreement check and wake sockets, through the
//! library API. Every board call that touches a planted file runs under a 5 s watchdog so a
//! hang fails the test instead of the suite.

use std::fs;
use std::os::unix::fs::symlink;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::mpsc;
use std::time::{Duration, Instant};
use synapse_coord::board::{Board, BoardError, Kind, Post, Resume, Sub, Wake};

static N: AtomicU32 = AtomicU32::new(0);

struct Fx {
    root: PathBuf,
}
impl Drop for Fx {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

fn fx(name: &str) -> (Fx, Board) {
    let root = std::env::temp_dir().join(format!(
        "sb-core-{name}-{}-{}",
        std::process::id(),
        N.fetch_add(1, Ordering::SeqCst)
    ));
    let _ = fs::remove_dir_all(&root);
    let b = Board::init(&root).unwrap();
    (Fx { root }, b)
}

fn watchdog<T: Send + 'static>(f: impl FnOnce() -> T + Send + 'static) -> T {
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let _ = tx.send(f());
    });
    rx.recv_timeout(Duration::from_secs(5))
        .expect("board call hung past the 5 s watchdog")
}

fn mkfifo(p: &Path) {
    let st = std::process::Command::new("mkfifo")
        .arg(p)
        .status()
        .unwrap();
    assert!(st.success());
}

fn reg(b: &Board, session: &str, tag: &str) {
    b.register(session, tag, None).unwrap();
}

fn post(b: &Board, session: &str, tag: &str, thread: &str, to: &[&str], text: &str) -> u64 {
    let mut p = Post::new(
        &b.whoami(session).unwrap(),
        thread,
        "lane/test",
        Kind::Finding,
        text,
    );
    assert_eq!(p.from_tag, tag);
    p.to = to.iter().map(|s| s.to_string()).collect();
    b.post(&p).unwrap().id
}

fn ids(batch: &synapse_coord::board::ReadBatch) -> Vec<(u64, bool)> {
    batch
        .events
        .iter()
        .map(|d| (d.event.id, d.addressed))
        .collect()
}

#[test]
fn tag_collision_refused_and_reregister_idempotent() {
    let (_f, b) = fx("tag");
    let r = b.register("s-one", "lane-a-board", None).unwrap();
    assert!(!r.refreshed);
    let r = b.register("s-one", "lane-a-board", None).unwrap();
    assert!(r.refreshed, "same session re-registering is idempotent");
    match b.register("s-two", "lane-a-board", None) {
        Err(BoardError::TagTaken { tag, holder }) => {
            assert_eq!(tag, "lane-a-board");
            assert_eq!(holder, "s-one");
        }
        other => panic!("expected TagTaken, got {other:?}"),
    }
    match b.register("s-one", "other-tag", None) {
        Err(BoardError::SessionTagged { tag, .. }) => assert_eq!(tag, "lane-a-board"),
        other => panic!("expected SessionTagged, got {other:?}"),
    }
    let me = b.whoami("s-one").unwrap();
    assert_eq!(
        (me.tag.as_str(), me.session.as_str()),
        ("lane-a-board", "s-one")
    );
    assert!(matches!(
        b.whoami("s-two"),
        Err(BoardError::NotRegistered { .. })
    ));
    for bad in ["", "../x", "a/b", ".hidden", &"x".repeat(65)] {
        assert!(
            matches!(
                b.register("s-three", bad, None),
                Err(BoardError::BadName { .. })
            ),
            "tag {bad:?} must be refused, not rewritten"
        );
    }
    b.unregister("s-one").unwrap();
    reg(&b, "s-two", "lane-a-board");
}

#[test]
fn addressing_and_thread_visibility() {
    // `to` sets addressing, not visibility: a thread subscriber sees addressed events too,
    // unflagged; the addressees see them flagged and first.
    let (_f, b) = fx("vis");
    reg(&b, "sa", "alpha");
    reg(&b, "sb", "beta");
    reg(&b, "sc", "gamma");
    reg(&b, "sd", "delta");
    b.subscribe("sc", &Sub::Thread("t-83".into())).unwrap();
    b.subscribe("sb", &Sub::Topic("lane/test".into())).unwrap();
    let q = post(&b, "sa", "alpha", "t-83", &["beta"], "question for beta");
    let a = post(&b, "sb", "beta", "t-83", &["alpha"], "answer for alpha");
    let other = post(&b, "sd", "delta", "t-other", &[], "unaddressed elsewhere");

    let c = b.read_since("sc", 0, 100).unwrap();
    assert_eq!(
        ids(&c),
        vec![(q, false), (a, false)],
        "gamma follows the thread"
    );
    assert!(!c.more);

    let beta = b.read_since("sb", 0, 100).unwrap();
    // addressed first, then subscribed (topic lane/test); own answer excluded.
    assert_eq!(ids(&beta), vec![(q, true), (other, false)]);

    let alpha = b.read_since("sa", 0, 100).unwrap();
    assert_eq!(
        ids(&alpha),
        vec![(a, true)],
        "alpha follows nothing, sees only its address"
    );

    let delta = b.read_since("sd", 0, 100).unwrap();
    assert!(
        delta.events.is_empty(),
        "nobody receives a thread they did not follow"
    );

    assert!(b.get("sc", q).unwrap().is_some());
    assert!(b.get("sd", q).unwrap().is_none(), "get respects visibility");
    assert!(
        b.get("sa", q).unwrap().is_none(),
        "own post is not delivered back"
    );
    assert!(b.get("sa", 999).unwrap().is_none());

    let mine = b.read_mine("sb", 0, 100).unwrap();
    assert_eq!(ids(&mine), vec![(q, true)]);
    let inbox = b.inbox("beta", 100).unwrap();
    assert_eq!(ids(&inbox), vec![(q, true)]);
}

#[test]
fn subscribe_unsubscribe_and_limits() {
    let (_f, b) = fx("subs");
    reg(&b, "sa", "alpha");
    reg(&b, "sb", "beta");
    b.subscribe("sb", &Sub::Topic("lane/test".into())).unwrap();
    let s = b.subscriptions("sb").unwrap();
    assert_eq!(s.topics, vec!["lane/test".to_string()]);
    let ids_posted: Vec<u64> = (0..10)
        .map(|i| post(&b, "sa", "alpha", "t", &[], &format!("e{i}")))
        .collect();
    let first = b.read_since("sb", 0, 4).unwrap();
    assert_eq!(first.events.len(), 4);
    assert!(first.more);
    let rest = b.read_since("sb", first.through, 100).unwrap();
    let mut all: Vec<u64> = first.events.iter().map(|d| d.event.id).collect();
    all.extend(rest.events.iter().map(|d| d.event.id));
    assert_eq!(all, ids_posted, "paged reads have no gap and no duplicate");
    b.unsubscribe("sb", &Sub::Topic("lane/test".into()))
        .unwrap();
    post(&b, "sa", "alpha", "t", &[], "after unsubscribe");
    assert!(b
        .read_since("sb", rest.through, 100)
        .unwrap()
        .events
        .is_empty());
    assert!(matches!(
        b.subscribe("sb", &Sub::Topic("../escape".into())),
        Err(BoardError::BadName { .. })
    ));
}

#[test]
fn cursor_deliver_ack_resume() {
    let (_f, b) = fx("cursor");
    reg(&b, "sa", "alpha");
    reg(&b, "sb", "beta");
    let e1 = post(&b, "sa", "alpha", "t", &["beta"], "one");
    let e2 = post(&b, "sa", "alpha", "t", &["beta"], "two");
    assert_eq!(b.acked("sb").unwrap(), 0);
    let d = b.deliver("sb", 100, Resume::Delivered).unwrap();
    assert_eq!(ids(&d), vec![(e1, true), (e2, true)]);
    assert!(b
        .deliver("sb", 100, Resume::Delivered)
        .unwrap()
        .events
        .is_empty());
    // A crash before ack: resuming from acked hands both out again, same ids.
    let again = b.deliver("sb", 100, Resume::Acked).unwrap();
    assert_eq!(ids(&again), vec![(e1, true), (e2, true)]);
    b.ack("sb", e1).unwrap();
    assert_eq!(b.acked("sb").unwrap(), e1);
    // idempotent at or below the cursor: no error, never moves backwards
    b.ack("sb", e1).unwrap();
    b.ack("sb", 0).unwrap();
    assert_eq!(b.acked("sb").unwrap(), e1);
    match b.ack("sb", e2 + 5) {
        Err(BoardError::AckBeyondCommitted { id, last }) => assert_eq!((id, last), (e2 + 5, e2)),
        other => panic!("expected AckBeyondCommitted, got {other:?}"),
    }
    let after_ack = b.deliver("sb", 100, Resume::Acked).unwrap();
    assert_eq!(ids(&after_ack), vec![(e2, true)]);
    // A new session that takes the tag over (after release) resumes the same cursor.
    b.unregister("sb").unwrap();
    reg(&b, "sb2", "beta");
    assert_eq!(b.acked("sb2").unwrap(), e1);
}

#[test]
fn addressed_events_found_via_index_after_restart() {
    let (f, b) = fx("restart");
    reg(&b, "sa", "alpha");
    reg(&b, "sb", "beta");
    let mut want = Vec::new();
    for i in 0..5 {
        post(&b, "sa", "alpha", "t", &[], &format!("noise {i}"));
        want.push(post(
            &b,
            "sa",
            "alpha",
            "t",
            &["beta"],
            &format!("for beta {i}"),
        ));
    }
    let id = b.id();
    drop(b);
    let b = Board::open_expecting(&f.root, id).unwrap();
    let mine = b.read_mine("sb", 0, 100).unwrap();
    assert_eq!(
        mine.events.iter().map(|d| d.event.id).collect::<Vec<_>>(),
        want
    );
    assert!(b.check().unwrap().ok());
    // The read is an index read: with the inbox index gone, nothing is found by scanning
    // the journal, and `check` names the disagreement.
    fs::remove_file(f.root.join("inbox/beta.idx")).unwrap();
    assert!(b.read_mine("sb", 0, 100).unwrap().events.is_empty());
    let rep = b.check().unwrap();
    assert!(!rep.ok());
    assert!(
        rep.problems
            .iter()
            .any(|p| p.contains("beta.idx") && p.contains("missing")),
        "{:?}",
        rep.problems
    );
}

#[test]
fn idempotency_dedup_and_conflict() {
    let (_f, b) = fx("idem");
    reg(&b, "sa", "alpha");
    reg(&b, "sb", "beta");
    let mk = |session: &str, text: &str| {
        let mut p = Post::new(
            &b.whoami(session).unwrap(),
            "t",
            "lane/test",
            Kind::Ready,
            text,
        );
        p.idem = Some("ready:t:1".into());
        p
    };
    let r1 = b.post(&mk("sa", "ready")).unwrap();
    let r2 = b.post(&mk("sa", "ready")).unwrap();
    assert!(!r1.dedup && r2.dedup);
    assert_eq!(r1.id, r2.id);
    // the same body from another agent dedups to the same event too
    let r3 = b.post(&mk("sb", "ready")).unwrap();
    assert_eq!(r3.id, r1.id);
    match b.post(&mk("sa", "different text")) {
        Err(BoardError::IdempotencyConflict { existing, .. }) => assert_eq!(existing, r1.id),
        other => panic!("expected IdempotencyConflict, got {other:?}"),
    }
    assert_eq!(b.bounds().unwrap().1, r1.id, "no extra event was written");
}

#[test]
fn hostile_inbox_and_agents_files_refused() {
    let (f, b) = fx("hostile");
    reg(&b, "sa", "alpha");
    post(&b, "sa", "alpha", "t", &[], "warm up");
    // symlink planted as an addressee's inbox index
    symlink("/dev/zero", f.root.join("inbox/beta.idx")).unwrap();
    let b2 = Board::open(&f.root).unwrap();
    let r = watchdog(move || {
        let me = b2.whoami("sa").unwrap();
        let mut p = Post::new(&me, "t", "lane/test", Kind::Finding, "to beta");
        p.to = vec!["beta".into()];
        b2.post(&p)
    });
    assert!(matches!(r, Err(BoardError::Refused { .. })), "{r:?}");
    assert_eq!(b.bounds().unwrap().1, 1, "a refused post is not committed");
    // FIFO planted as an agent binding
    mkfifo(&f.root.join("agents/gamma.json"));
    let b3 = Board::open(&f.root).unwrap();
    let r = watchdog(move || b3.register("sg", "gamma", None));
    assert!(matches!(r, Err(BoardError::Refused { .. })), "{r:?}");
    let b4 = Board::open(&f.root).unwrap();
    let r = watchdog(move || b4.whoami("sa"));
    assert!(matches!(r, Err(BoardError::Refused { .. })), "{r:?}");
    // FIFO planted as a reader's inbox
    fs::remove_file(f.root.join("agents/gamma.json")).unwrap();
    fs::remove_file(f.root.join("inbox/beta.idx")).unwrap();
    reg(&b, "sb", "beta");
    mkfifo(&f.root.join("inbox/beta.idx"));
    let b5 = Board::open(&f.root).unwrap();
    let r = watchdog(move || b5.read_mine("sb", 0, 10));
    assert!(matches!(r, Err(BoardError::Refused { .. })), "{r:?}");
}

#[test]
fn wake_socket_wakes_and_times_out() {
    let (_f, b) = fx("wake");
    reg(&b, "sa", "alpha");
    reg(&b, "sb", "beta");
    let w = b.watcher("sb").unwrap();
    assert!(matches!(
        b.watcher("sb"),
        Err(BoardError::WatcherBusy { .. })
    ));
    let t = Instant::now();
    assert_eq!(w.wait(Duration::from_millis(50)).unwrap(), Wake::TimedOut);
    assert!(t.elapsed() < Duration::from_secs(2));
    let id = post(&b, "sa", "alpha", "t", &["beta"], "wake up");
    assert_eq!(w.wait(Duration::from_secs(5)).unwrap(), Wake::Woke(id));
    drop(w);
    // undelivered events wake at once without a datagram
    assert_eq!(
        b.wait("sb", Duration::from_secs(5)).unwrap(),
        Wake::Woke(id)
    );
    b.deliver("sb", 100, Resume::Delivered).unwrap();
    assert_eq!(
        b.wait("sb", Duration::from_millis(20)).unwrap(),
        Wake::TimedOut
    );
}
