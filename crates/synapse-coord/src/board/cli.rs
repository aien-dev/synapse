//! `synapse-coord board ...`: the command-line face of the board.
//!
//! Output is one compact JSON object per line on stdout: events first, then one summary
//! object carrying `"ok"` and the [`UNTRUSTED_NOTICE`](super::UNTRUSTED_NOTICE). `--human`
//! prints readable lines instead. Exit codes: 0 ok, 1 usage or I/O error, 2 a named
//! refusal (the summary's `"error"` is [`BoardError::name`]).
//!
//! ```text
//! synapse-coord board [--board-root DIR] [--expect-board-id HEX] [--session S] [--human] <verb> ...
//!   init                                   create the board (BOARD_ID) if absent
//!   id                                     print the mission id
//!   register <tag> [--ttl SECS]            bind a tag to this session
//!   unregister                             release this session's tag
//!   whoami                                 print this session's tag and session id
//!   agents                                 every tag binding (operator view)
//!   post --thread T --topic P [--kind K] [--to TAG]... [--parent ID] [--idem KEY]
//!        [--ref REPO KIND VALUE]... (--text S | --text-file F)
//!        [--pointer-whisper STORE TOP DIR]
//!   read [--from acked|delivered] [--after ID] [--limit N] [--peek] [--mine] [--all]
//!   inbox <tag> [--limit N]                unread events addressed to a tag (operator view)
//!   subscribe (--topic T | --thread T)     follow a topic or thread
//!   unsubscribe (--topic T | --thread T)
//!   subscriptions
//!   watch [--timeout-ms N] [--limit N] [--from delivered|acked] [--follow N] [--stamp]
//!   ack <id> | ack --accept-gap
//!   compact --keep-since ID [--expire-cursors]
//!   check                                  index/journal agreement (read-only)
//!   recover                                reconcile a torn tail now (normally done by post)
//! ```
//!
//! Environment fallbacks: `SYNAPSE_BOARD_ROOT`, `SYNAPSE_BOARD_ID`, and for the session
//! `SYNAPSE_BOARD_SESSION` then `CRUMB_SESSION`.

use super::frame::{compact, num_u64};
use super::{
    Board, BoardError, BoardId, Delivered, Kind, Post, ReadBatch, Ref, RefKind, Resume, Sub, Wake,
    MAX_TEXT_BYTES, UNTRUSTED_NOTICE,
};
use crate::json::J;
use crate::{CoordStore, Holder, NoOracle, Workspace};
use std::io::Write;
use std::path::PathBuf;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// Default `watch` timeout.
const DEFAULT_WATCH_MS: u64 = 30_000;
const DEFAULT_LIMIT: usize = 256;

enum Fail {
    Usage(String),
    Board(BoardError),
}

impl From<BoardError> for Fail {
    fn from(e: BoardError) -> Fail {
        Fail::Board(e)
    }
}

fn usage(m: impl Into<String>) -> Fail {
    Fail::Usage(m.into())
}

struct Ctx {
    root: Option<PathBuf>,
    expect: Option<BoardId>,
    session: Option<String>,
    human: bool,
    out: std::io::StdoutLock<'static>,
}

impl Ctx {
    fn board(&self) -> Result<Board, Fail> {
        let root = self
            .root
            .clone()
            .ok_or_else(|| usage("--board-root (or SYNAPSE_BOARD_ROOT) is required"))?;
        Ok(match self.expect {
            Some(id) => Board::open_expecting(root, id)?,
            None => Board::open(root)?,
        })
    }

    fn session(&self) -> Result<&str, Fail> {
        self.session.as_deref().ok_or_else(|| {
            usage("--session (or SYNAPSE_BOARD_SESSION / CRUMB_SESSION) is required")
        })
    }

    fn line(&mut self, j: &J) {
        let mut b = compact(j);
        b.push(b'\n');
        let _ = self.out.write_all(&b);
    }

    /// A readable line, printed only under `--human`.
    fn human(&mut self, s: &str) {
        if self.human {
            let _ = writeln!(self.out, "{s}");
        }
    }

    fn summary(&mut self, cmd: &str, mut o: J) {
        if self.human {
            let _ = self.out.flush();
            return;
        }
        let mut s = J::obj();
        s.set("ok", J::True);
        s.set("cmd", J::str(cmd));
        if let J::Obj(kv) = &mut o {
            for (k, v) in std::mem::take(kv) {
                s.set(&String::from_utf8_lossy(&k), v);
            }
        }
        s.set("untrusted", J::str(UNTRUSTED_NOTICE));
        self.line(&s);
        let _ = self.out.flush();
    }

    fn event(&mut self, d: &Delivered, stamp: Option<u128>) {
        if self.human {
            let e = &d.event;
            let to = if e.to.is_empty() {
                String::new()
            } else {
                format!(" -> {}", e.to.join(","))
            };
            let flag = if d.addressed { " [to you]" } else { "" };
            self.human(&format!(
                "#{} {} {}{to}{flag} ({} / {}): {}",
                e.id,
                e.kind.as_str(),
                e.from_tag,
                e.thread,
                e.topic,
                e.text.replace('\n', "\n    ")
            ));
            return;
        }
        let mut j = d.event.to_json();
        j.set("addressed", if d.addressed { J::True } else { J::False });
        if let Some(ns) = stamp {
            j.set("recv_unix_ns", J::Num(ns.to_string().into_bytes()));
        }
        self.line(&j);
    }

    fn batch(&mut self, cmd: &str, b: &ReadBatch, stamp: Option<u128>) {
        if self.human {
            self.human(&format!("-- {UNTRUSTED_NOTICE} --"));
        }
        for d in &b.events {
            self.event(d, stamp);
        }
        if self.human && b.events.is_empty() {
            self.human("(nothing new)");
        }
        let mut o = J::obj();
        o.set("count", num_u64(b.events.len() as u64));
        o.set("after", num_u64(b.after));
        o.set("through", num_u64(b.through));
        o.set("more", if b.more { J::True } else { J::False });
        o.set("base", num_u64(b.base));
        o.set("last", num_u64(b.last));
        if let Some(t) = b.torn_entry {
            o.set("in_flight", num_u64(t));
        }
        self.summary(cmd, o);
    }
}

fn now_ns() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0)
}

struct Args(Vec<String>);

impl Args {
    fn take(&mut self, flag: &str) -> Result<String, Fail> {
        if self.0.is_empty() {
            return Err(usage(format!("{flag} needs a value")));
        }
        Ok(self.0.remove(0))
    }
    fn num(&mut self, flag: &str) -> Result<u64, Fail> {
        let v = self.take(flag)?;
        v.parse()
            .map_err(|_| usage(format!("{flag} needs a number, got {v:?}")))
    }
    fn next_flag(&mut self) -> Option<String> {
        if self.0.is_empty() {
            None
        } else {
            Some(self.0.remove(0))
        }
    }
}

fn resume(s: &str) -> Result<Resume, Fail> {
    match s {
        "acked" => Ok(Resume::Acked),
        "delivered" => Ok(Resume::Delivered),
        _ => Err(usage(format!("--from takes acked or delivered, got {s:?}"))),
    }
}

/// Run a board subcommand; returns the process exit code.
pub fn run(args: &[String]) -> i32 {
    let env = |k: &str| std::env::var(k).ok().filter(|v| !v.is_empty());
    let mut ctx = Ctx {
        root: env("SYNAPSE_BOARD_ROOT").map(PathBuf::from),
        expect: None,
        session: env("SYNAPSE_BOARD_SESSION").or_else(|| env("CRUMB_SESSION")),
        human: false,
        out: std::io::stdout().lock(),
    };
    let mut a = Args(args.to_vec());
    let mut expect = env("SYNAPSE_BOARD_ID");
    let r = (|| -> Result<(), Fail> {
        while a.0.first().is_some_and(|f| f.starts_with("--")) {
            let f = a.0.remove(0);
            match f.as_str() {
                "--board-root" => ctx.root = Some(a.take(&f)?.into()),
                "--expect-board-id" => expect = Some(a.take(&f)?),
                "--session" => ctx.session = Some(a.take(&f)?),
                "--human" => ctx.human = true,
                _ => return Err(usage(format!("unknown flag {f}"))),
            }
        }
        if let Some(h) = expect {
            ctx.expect = Some(
                BoardId::parse_hex(&h)
                    .ok_or_else(|| usage(format!("--expect-board-id: not a board id: {h:?}")))?,
            );
        }
        let verb = a.next_flag().ok_or_else(|| usage("missing verb"))?;
        dispatch(&mut ctx, &verb, a)
    })();
    match r {
        Ok(()) => 0,
        Err(Fail::Usage(m)) => {
            eprintln!("synapse-coord board: {m}");
            1
        }
        Err(Fail::Board(e)) => {
            let mut o = J::obj();
            o.set("ok", J::False);
            o.set("error", J::str(e.name()));
            o.set("message", J::str(&e.to_string()));
            ctx.line(&o);
            let _ = ctx.out.flush();
            eprintln!("synapse-coord board: {}: {e}", e.name());
            match e {
                BoardError::Io { .. } => 1,
                _ => 2,
            }
        }
    }
}

fn dispatch(ctx: &mut Ctx, verb: &str, mut a: Args) -> Result<(), Fail> {
    match verb {
        "init" => {
            let root = ctx
                .root
                .clone()
                .ok_or_else(|| usage("--board-root (or SYNAPSE_BOARD_ROOT) is required"))?;
            let b = Board::init(root)?;
            if let Some(e) = ctx.expect {
                if e != b.id() {
                    return Err(BoardError::BoardIdMismatch {
                        root: b.root().to_path_buf(),
                        expected: e,
                        found: b.id(),
                    }
                    .into());
                }
            }
            ctx.human(&b.mission());
            let mut o = J::obj();
            o.set("mission", J::str(&b.mission()));
            o.set("root", J::str(&b.root().display().to_string()));
            ctx.summary("init", o);
        }
        "id" => {
            let b = ctx.board()?;
            ctx.human(&b.mission());
            let mut o = J::obj();
            o.set("mission", J::str(&b.mission()));
            ctx.summary("id", o);
        }
        "register" => {
            let tag = a.take("register <tag>")?;
            let mut ttl = None;
            while let Some(f) = a.next_flag() {
                match f.as_str() {
                    "--ttl" => ttl = Some(a.num(&f)? as i64),
                    _ => return Err(usage(format!("register: unknown argument {f}"))),
                }
            }
            let b = ctx.board()?;
            let r = b.register(ctx.session()?, &tag, ttl)?;
            ctx.human(&format!("{} = {}", r.me.tag, r.me.session));
            let mut o = J::obj();
            o.set("tag", J::str(&r.me.tag));
            o.set("session", J::str(&r.me.session));
            o.set("refreshed", if r.refreshed { J::True } else { J::False });
            o.set("expires_at", J::num(r.expires_at));
            ctx.summary("register", o);
        }
        "unregister" => {
            let b = ctx.board()?;
            let me = b.unregister(ctx.session()?)?;
            let mut o = J::obj();
            o.set("tag", J::str(&me.tag));
            ctx.summary("unregister", o);
        }
        "whoami" => {
            let b = ctx.board()?;
            let me = b.whoami(ctx.session()?)?;
            ctx.human(&format!("{} {}", me.tag, me.session));
            let mut o = J::obj();
            o.set("tag", J::str(&me.tag));
            o.set("session", J::str(&me.session));
            o.set("mission", J::str(&b.mission()));
            ctx.summary("whoami", o);
        }
        "agents" => {
            let b = ctx.board()?;
            let all = b.agents()?;
            for (tag, session, live) in &all {
                if ctx.human {
                    ctx.human(&format!(
                        "{tag} {session}{}",
                        if *live { "" } else { " (expired)" }
                    ));
                } else {
                    let mut j = J::obj();
                    j.set("tag", J::str(tag));
                    j.set("session", J::str(session));
                    j.set("live", if *live { J::True } else { J::False });
                    ctx.line(&j);
                }
            }
            let mut o = J::obj();
            o.set("count", num_u64(all.len() as u64));
            ctx.summary("agents", o);
        }
        "post" => post(ctx, a)?,
        "read" => read(ctx, a)?,
        "inbox" => {
            let tag = a.take("inbox <tag>")?;
            let mut limit = DEFAULT_LIMIT;
            while let Some(f) = a.next_flag() {
                match f.as_str() {
                    "--limit" => limit = a.num(&f)? as usize,
                    _ => return Err(usage(format!("inbox: unknown argument {f}"))),
                }
            }
            let b = ctx.board()?;
            let batch = b.inbox(&tag, limit)?;
            ctx.batch("inbox", &batch, None);
        }
        "subscribe" | "unsubscribe" => {
            let sub = match (a.next_flag().as_deref(), a.next_flag()) {
                (Some("--topic"), Some(t)) => Sub::Topic(t),
                (Some("--thread"), Some(t)) => Sub::Thread(t),
                _ => return Err(usage(format!("{verb} (--topic T | --thread T)"))),
            };
            let b = ctx.board()?;
            let s = if verb == "subscribe" {
                b.subscribe(ctx.session()?, &sub)?
            } else {
                b.unsubscribe(ctx.session()?, &sub)?
            };
            subs_summary(ctx, verb, &s);
        }
        "subscriptions" => {
            let b = ctx.board()?;
            let s = b.subscriptions(ctx.session()?)?;
            subs_summary(ctx, "subscriptions", &s);
        }
        "watch" => watch(ctx, a)?,
        "ack" => {
            let b = ctx.board()?;
            let what = a.take("ack <id> | ack --accept-gap")?;
            let c = if what == "--accept-gap" {
                b.accept_gap(ctx.session()?)?
            } else {
                let id = what
                    .parse()
                    .map_err(|_| usage(format!("ack needs an id, got {what:?}")))?;
                b.ack(ctx.session()?, id)?
            };
            let mut o = J::obj();
            o.set("acked", num_u64(c.acked));
            o.set("delivered", num_u64(c.delivered));
            ctx.summary("ack", o);
        }
        "compact" => {
            let mut keep = None;
            let mut expire = false;
            while let Some(f) = a.next_flag() {
                match f.as_str() {
                    "--keep-since" => keep = Some(a.num(&f)?),
                    "--expire-cursors" => expire = true,
                    _ => return Err(usage(format!("compact: unknown argument {f}"))),
                }
            }
            let keep = keep.ok_or_else(|| usage("compact --keep-since ID"))?;
            let b = ctx.board()?;
            let r = b.compact(keep, expire)?;
            let mut o = J::obj();
            o.set("base", num_u64(r.base));
            o.set("last", num_u64(r.last));
            o.set("dropped_events", num_u64(r.dropped_events));
            o.set("bytes_before", num_u64(r.bytes_before));
            o.set("bytes_after", num_u64(r.bytes_after));
            o.set("expired", super::frame::j_list(&r.expired));
            ctx.summary("compact", o);
        }
        "check" => {
            let b = ctx.board()?;
            let r = b.check()?;
            for p in &r.problems {
                if ctx.human {
                    ctx.human(&format!("problem: {p}"));
                } else {
                    let mut j = J::obj();
                    j.set("problem", J::str(p));
                    ctx.line(&j);
                }
            }
            if !r.ok() {
                let mut o = J::obj();
                o.set("ok", J::False);
                o.set("error", J::str("CheckFailed"));
                o.set("problems", num_u64(r.problems.len() as u64));
                ctx.line(&o);
                eprintln!(
                    "synapse-coord board: CheckFailed: {} problem(s)",
                    r.problems.len()
                );
                let _ = ctx.out.flush();
                std::process::exit(2);
            }
            ctx.human(&format!("ok: events {}..={}", r.base, r.last));
            let mut o = J::obj();
            o.set("base", num_u64(r.base));
            o.set("last", num_u64(r.last));
            o.set("events", num_u64(r.events));
            o.set("journal_bytes", num_u64(r.journal_bytes));
            ctx.summary("check", o);
        }
        "recover" => {
            let b = ctx.board()?;
            let r = b.recover()?;
            let mut o = J::obj();
            o.set(
                "torn_tail_at",
                r.torn_tail_at.map(num_u64).unwrap_or(J::Null),
            );
            o.set("torn_bytes", num_u64(r.torn_bytes));
            o.set(
                "adopted",
                J::Arr(r.adopted.iter().map(|i| num_u64(*i)).collect()),
            );
            o.set(
                "dropped_table_entry",
                if r.dropped_table_entry {
                    J::True
                } else {
                    J::False
                },
            );
            o.set(
                "table_rebuilt",
                if r.table_rebuilt { J::True } else { J::False },
            );
            ctx.summary("recover", o);
        }
        _ => return Err(usage(format!("unknown verb {verb:?}"))),
    }
    Ok(())
}

fn subs_summary(ctx: &mut Ctx, cmd: &str, s: &super::Subscriptions) {
    ctx.human(&format!(
        "topics: {}\nthreads: {}",
        s.topics.join(", "),
        s.threads.join(", ")
    ));
    let mut o = J::obj();
    o.set("topics", super::frame::j_list(&s.topics));
    o.set("threads", super::frame::j_list(&s.threads));
    ctx.summary(cmd, o);
}

fn post(ctx: &mut Ctx, mut a: Args) -> Result<(), Fail> {
    let (mut thread, mut topic, mut kind) = (None, None, Kind::Finding);
    let (mut to, mut refs) = (Vec::new(), Vec::new());
    let (mut parent, mut idem, mut text, mut pointer) = (None, None, None, None);
    while let Some(f) = a.next_flag() {
        match f.as_str() {
            "--thread" => thread = Some(a.take(&f)?),
            "--topic" => topic = Some(a.take(&f)?),
            "--kind" => {
                let k = a.take(&f)?;
                kind = Kind::parse(&k).ok_or_else(|| usage(format!("unknown kind {k:?}")))?;
            }
            "--to" => to.push(a.take(&f)?),
            "--parent" => parent = Some(a.num(&f)?),
            "--idem" => idem = Some(a.take(&f)?),
            "--ref" => {
                let repo = a.take(&f)?;
                let k = a.take(&f)?;
                let value = a.take(&f)?;
                let kind =
                    RefKind::parse(&k).ok_or_else(|| usage(format!("unknown ref kind {k:?}")))?;
                refs.push(Ref { repo, kind, value });
            }
            "--text" => text = Some(a.take(&f)?),
            "--text-file" => {
                let p = PathBuf::from(a.take(&f)?);
                let b = crate::record::read_bounded(&p, MAX_TEXT_BYTES as u64)
                    .map_err(BoardError::from)?
                    .ok_or_else(|| usage(format!("{} does not exist", p.display())))?;
                text = Some(
                    String::from_utf8(b)
                        .map_err(|_| usage(format!("{} is not UTF-8", p.display())))?,
                );
            }
            "--pointer-whisper" => {
                pointer = Some((a.take(&f)?, a.take(&f)?, a.take(&f)?));
            }
            _ => return Err(usage(format!("post: unknown argument {f}"))),
        }
    }
    let thread = thread.ok_or_else(|| usage("post needs --thread"))?;
    let topic = topic.ok_or_else(|| usage("post needs --topic"))?;
    let text = text.ok_or_else(|| usage("post needs --text or --text-file"))?;
    let b = ctx.board()?;
    let me = b.whoami(ctx.session()?)?;
    let mut p = Post::new(&me, &thread, &topic, kind, &text);
    p.to = to;
    p.parent = parent;
    p.idem = idem;
    p.refs = refs;
    let r = b.post(&p)?;
    let mut o = J::obj();
    o.set("id", num_u64(r.id));
    o.set("mission", J::str(&r.mission.to_hex()));
    o.set("dedup", if r.dedup { J::True } else { J::False });
    o.set("woke", num_u64(r.woke as u64));
    if let Some(t) = r.recovery.torn_tail_at {
        o.set("torn_tail_at", num_u64(t));
    }
    if !r.recovery.adopted.is_empty() {
        o.set(
            "adopted",
            J::Arr(r.recovery.adopted.iter().map(|i| num_u64(*i)).collect()),
        );
    }
    let mut pointer_err = None;
    if let Some((store, top, dir)) = pointer {
        let cs = CoordStore::open(store);
        let ws = Workspace::with_oracle(top, Holder::default(), Box::new(NoOracle));
        match b.pointer_whisper(&cs, &ws, &me.tag, &dir, r.id) {
            Ok(()) => o.set("pointer_whisper", J::str(&b.pointer_text(r.id))),
            Err(e) => {
                o.set("pointer_whisper_error", J::str(&e.to_string()));
                pointer_err = Some(e);
            }
        }
    }
    ctx.human(&format!(
        "posted #{}{}",
        r.id,
        if r.dedup { " (already posted)" } else { "" }
    ));
    ctx.summary("post", o);
    match pointer_err {
        // The post is committed; only the optional pointer failed.
        Some(e) => Err(Fail::Board(e)),
        None => Ok(()),
    }
}

fn read(ctx: &mut Ctx, mut a: Args) -> Result<(), Fail> {
    let (mut from, mut after, mut limit) = (Resume::Acked, None, DEFAULT_LIMIT);
    let (mut peek, mut mine, mut all) = (false, false, false);
    while let Some(f) = a.next_flag() {
        match f.as_str() {
            "--from" => from = resume(&a.take(&f)?)?,
            "--after" => after = Some(a.num(&f)?),
            "--limit" => limit = a.num(&f)? as usize,
            "--peek" => peek = true,
            "--mine" => mine = true,
            "--all" => all = true,
            _ => return Err(usage(format!("read: unknown argument {f}"))),
        }
    }
    let b = ctx.board()?;
    let batch = if all {
        b.read_all(after, limit)?
    } else {
        let session = ctx.session()?.to_string();
        if mine || peek || after.is_some() {
            // Pure reads: the shared cursor never moves.
            let start = match after {
                Some(x) => x,
                None => {
                    let me = b.whoami(&session)?;
                    b.start_after(&me.tag, from)?
                }
            };
            if mine {
                b.read_mine(&session, start, limit)?
            } else {
                b.read_since(&session, start, limit)?
            }
        } else {
            b.deliver(&session, limit, from)?
        }
    };
    ctx.batch("read", &batch, None);
    Ok(())
}

fn watch(ctx: &mut Ctx, mut a: Args) -> Result<(), Fail> {
    let (mut timeout, mut limit, mut from) = (DEFAULT_WATCH_MS, DEFAULT_LIMIT, Resume::Delivered);
    let (mut follow, mut stamp) = (None, false);
    while let Some(f) = a.next_flag() {
        match f.as_str() {
            "--timeout-ms" => timeout = a.num(&f)?,
            "--limit" => limit = a.num(&f)? as usize,
            "--from" => from = resume(&a.take(&f)?)?,
            "--follow" => follow = Some(a.num(&f)?),
            "--stamp" => stamp = true,
            _ => return Err(usage(format!("watch: unknown argument {f}"))),
        }
    }
    let b = ctx.board()?;
    let session = ctx.session()?.to_string();
    // Bind before the first read so a post between read and wait still wakes us.
    let w = b.watcher(&session)?;
    let want = follow.unwrap_or(1);
    let mut got = 0u64;
    let mut wakes = 0u64;
    let mut timed_out = false;
    let mut first_from = Some(from);
    let mut last: Option<ReadBatch>;
    loop {
        let r = first_from.take().unwrap_or(Resume::Delivered);
        let batch = b.deliver(&session, limit, r)?;
        let ns = stamp.then(now_ns);
        for d in &batch.events {
            ctx.event(d, ns);
        }
        let _ = ctx.out.flush();
        got += batch.events.len() as u64;
        last = Some(batch);
        if got >= want {
            break;
        }
        if last.as_ref().is_some_and(|l| l.more) {
            continue;
        }
        let t0 = Instant::now();
        match w.wait(Duration::from_millis(timeout))? {
            Wake::Woke(_) => wakes += 1,
            Wake::TimedOut => {
                // A lost datagram costs latency, never an event: read once more.
                let batch = b.deliver(&session, limit, Resume::Delivered)?;
                let ns = stamp.then(now_ns);
                for d in &batch.events {
                    ctx.event(d, ns);
                }
                got += batch.events.len() as u64;
                last = Some(batch);
                if got >= want || t0.elapsed() >= Duration::from_millis(timeout) {
                    timed_out = got < want;
                    break;
                }
            }
        }
    }
    let mut o = J::obj();
    o.set("count", num_u64(got));
    o.set("wakes", num_u64(wakes));
    o.set("timed_out", if timed_out { J::True } else { J::False });
    if let Some(l) = last {
        o.set("through", num_u64(l.through));
        o.set("last", num_u64(l.last));
    }
    ctx.summary("watch", o);
    Ok(())
}
