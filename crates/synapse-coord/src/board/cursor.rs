//! Subscriptions, cursors, `read_since`, `deliver` and `ack`.
//!
//! A tag receives (a) every event addressed to it (`to` lists the tag), found through
//! `inbox/<tag>.idx` and flagged `addressed`, and (b) every event on a topic or thread it
//! subscribed to, found through `topics/<topic>.idx` and the thread keys of `journal.idx`.
//! `to` sets addressing, not visibility: an event addressed to other tags is still seen
//! (unflagged) by the subscribers of its thread or topic. Nobody receives a thread or topic
//! they did not follow unless it is addressed to them. A tag never receives its own posts.
//! Nothing is found by scanning journal bodies.
//!
//! The cursor `cursors/<tag>.json` holds `delivered` (highest id handed out) and `acked`
//! (highest id the agent confirmed it processed). Reading from `acked` after a crash
//! returns every unprocessed event again (at-least-once, stable ids); reading from
//! `delivered` returns only what was never handed out.

use super::frame::{as_string, as_u64, compact, j_list, key_hash, num_u64, str_list, H_THREAD};
use super::journal::{
    ensure_dir, fcntl_lock, inbox_file, read_ids_after, topic_file, FileLock, Snapshot,
};
use super::{
    validate_name, validate_tag, Board, BoardError, Event, Me, MAX_READ_LIMIT, MAX_SUBSCRIPTIONS,
    PROTOCOL,
};
use crate::json::{self, J};
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Mutex;

const MAX_CURSOR_BYTES: u64 = 4096;
const MAX_SUBS_BYTES: u64 = 64 * 1024;
static TAG_LOCKS: Mutex<()> = Mutex::new(());

/// One subscription.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Sub {
    Topic(String),
    Thread(String),
}

/// A tag's subscriptions.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Subscriptions {
    pub topics: Vec<String>,
    pub threads: Vec<String>,
}

/// A tag's durable cursor.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Cursor {
    pub delivered: u64,
    pub acked: u64,
    pub expired: bool,
    /// False when the tag has never read (the cursor then starts at the board's base).
    pub exists: bool,
}

/// Where a cursor-driven read starts.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Resume {
    /// After `delivered`: only events never handed out.
    Delivered,
    /// After `acked`: everything not yet confirmed (use after a restart).
    Acked,
}

/// One event of a batch, with whether it was addressed to the reader.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Delivered {
    pub event: Event,
    pub addressed: bool,
}

/// A read result. `events` holds addressed events first, then subscribed ones, each in id
/// order. Every matching id `<= through` is in this batch or an earlier one; the next read
/// continues after `through`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ReadBatch {
    pub events: Vec<Delivered>,
    pub after: u64,
    pub through: u64,
    pub base: u64,
    pub last: u64,
    /// A table entry in flight (a concurrent post) was not read; it is not committed yet.
    pub torn_entry: Option<u64>,
    /// True when the batch was cut by `limit`: read again after `through`.
    pub more: bool,
}

struct TagLock(#[allow(dead_code)] FileLock);

impl Board {
    fn tag_lock(&self, tag: &str) -> Result<TagLock, BoardError> {
        let d = ensure_dir(self.root(), "cursors")?;
        Ok(TagLock(fcntl_lock(
            self.root(),
            &d.join(format!("{tag}.lock")),
            &TAG_LOCKS,
        )?))
    }

    fn cursor_path(&self, tag: &str) -> PathBuf {
        self.root().join("cursors").join(format!("{tag}.json"))
    }

    fn subs_path(&self, tag: &str) -> PathBuf {
        self.root().join("subs").join(format!("{tag}.json"))
    }

    /// The tag's cursor (a missing file is a fresh cursor, `exists: false`).
    pub fn cursor(&self, tag: &str) -> Result<Cursor, BoardError> {
        validate_tag(tag)?;
        let p = self.cursor_path(tag);
        crate::record::check_real_parents(self.root(), &p)?;
        let Some(b) = crate::record::read_bounded(&p, MAX_CURSOR_BYTES)? else {
            return Ok(Cursor::default());
        };
        let bad = |r: &str| BoardError::BadCursor {
            path: p.clone(),
            reason: r.into(),
        };
        let j = json::parse(&b).ok_or_else(|| bad("not JSON"))?;
        if as_string(j.get("v")).as_deref() != Some(PROTOCOL)
            || as_string(j.get("tag")).as_deref() != Some(tag)
        {
            return Err(bad("not this tag's aien-board/1 cursor"));
        }
        let c = Cursor {
            delivered: as_u64(j.get("delivered")).ok_or_else(|| bad("delivered is not an id"))?,
            acked: as_u64(j.get("acked")).ok_or_else(|| bad("acked is not an id"))?,
            expired: match j.get("expired") {
                Some(J::True) => true,
                Some(J::False) => false,
                _ => return Err(bad("expired is not a boolean")),
            },
            exists: true,
        };
        if c.acked > c.delivered {
            return Err(bad("acked is beyond delivered"));
        }
        let (_, last) = self.bounds()?;
        if c.delivered > last {
            return Err(bad("delivered is beyond the last committed event"));
        }
        Ok(c)
    }

    fn write_cursor(&self, tag: &str, c: &Cursor) -> Result<(), BoardError> {
        let mut o = J::obj();
        o.set("v", J::str(PROTOCOL));
        o.set("tag", J::str(tag));
        o.set("delivered", num_u64(c.delivered));
        o.set("acked", num_u64(c.acked));
        o.set("expired", if c.expired { J::True } else { J::False });
        let mut data = compact(&o);
        data.push(b'\n');
        crate::durable_write(self.root(), &self.cursor_path(tag), &data)?;
        Ok(())
    }

    /// The tag's subscriptions (empty when it never subscribed).
    pub fn subscriptions_of(&self, tag: &str) -> Result<Subscriptions, BoardError> {
        validate_tag(tag)?;
        let p = self.subs_path(tag);
        crate::record::check_real_parents(self.root(), &p)?;
        let Some(b) = crate::record::read_bounded(&p, MAX_SUBS_BYTES)? else {
            return Ok(Subscriptions::default());
        };
        let bad = |r: &str| BoardError::Corrupt {
            path: p.clone(),
            offset: 0,
            reason: r.into(),
        };
        let j = json::parse(&b).ok_or_else(|| bad("not JSON"))?;
        if as_string(j.get("v")).as_deref() != Some(PROTOCOL)
            || as_string(j.get("tag")).as_deref() != Some(tag)
        {
            return Err(bad("not this tag's aien-board/1 subscriptions"));
        }
        let s = Subscriptions {
            topics: str_list(j.get("topics")).ok_or_else(|| bad("bad topics"))?,
            threads: str_list(j.get("threads")).ok_or_else(|| bad("bad threads"))?,
        };
        if s.topics.len() + s.threads.len() > MAX_SUBSCRIPTIONS {
            return Err(BoardError::TooManySubscriptions {
                limit: MAX_SUBSCRIPTIONS,
            });
        }
        for t in &s.topics {
            validate_name("topic", t)?;
        }
        for t in &s.threads {
            validate_name("thread", t)?;
        }
        Ok(s)
    }

    fn change_subs(&self, me: &Me, sub: &Sub, add: bool) -> Result<Subscriptions, BoardError> {
        self.check_binding(me)?;
        let (field, name) = match sub {
            Sub::Topic(t) => ("topic", t),
            Sub::Thread(t) => ("thread", t),
        };
        validate_name(field, name)?;
        let _l = self.tag_lock(&me.tag)?;
        ensure_dir(self.root(), "subs")?;
        let mut s = self.subscriptions_of(&me.tag)?;
        let list = match sub {
            Sub::Topic(_) => &mut s.topics,
            Sub::Thread(_) => &mut s.threads,
        };
        let had = list.contains(name);
        if add && !had {
            list.push(name.clone());
        } else if !add && had {
            list.retain(|x| x != name);
        } else {
            return Ok(s);
        }
        if s.topics.len() + s.threads.len() > MAX_SUBSCRIPTIONS {
            return Err(BoardError::TooManySubscriptions {
                limit: MAX_SUBSCRIPTIONS,
            });
        }
        let mut o = J::obj();
        o.set("v", J::str(PROTOCOL));
        o.set("tag", J::str(&me.tag));
        o.set("topics", j_list(&s.topics));
        o.set("threads", j_list(&s.threads));
        let mut data = compact(&o);
        data.push(b'\n');
        crate::durable_write(self.root(), &self.subs_path(&me.tag), &data)?;
        Ok(s)
    }

    /// The subscriptions of the tag this session holds.
    pub fn subscriptions(&self, session: &str) -> Result<Subscriptions, BoardError> {
        let me = self.whoami(session)?;
        self.subscriptions_of(&me.tag)
    }

    pub fn subscribe(&self, session: &str, sub: &Sub) -> Result<Subscriptions, BoardError> {
        let me = self.whoami(session)?;
        self.change_subs(&me, sub, true)
    }

    pub fn unsubscribe(&self, session: &str, sub: &Sub) -> Result<Subscriptions, BoardError> {
        let me = self.whoami(session)?;
        self.change_subs(&me, sub, false)
    }

    /// Events for `tag` after `after` (at most `limit`): addressed first, then subscribed.
    /// Pure read: no cursor moves.
    pub fn read_since(
        &self,
        session: &str,
        after: u64,
        limit: usize,
    ) -> Result<ReadBatch, BoardError> {
        let me = &self.whoami(session)?;
        let subs = self.subscriptions_of(&me.tag)?;
        self.read_for(&me.tag, &subs, after, limit, false)
    }

    /// Only the events addressed to `me` after `after` (an inbox index read). Pure read.
    pub fn read_mine(
        &self,
        session: &str,
        after: u64,
        limit: usize,
    ) -> Result<ReadBatch, BoardError> {
        let me = &self.whoami(session)?;
        self.read_for(&me.tag, &Subscriptions::default(), after, limit, true)
    }

    /// Operator view: unread (after the tag's `acked`) events addressed to `tag`. Needs no
    /// session and moves nothing.
    pub fn inbox(&self, tag: &str, limit: usize) -> Result<ReadBatch, BoardError> {
        validate_tag(tag)?;
        let after = self.start_after(tag, Resume::Acked)?;
        self.read_for(tag, &Subscriptions::default(), after, limit, true)
    }

    /// Operator view (`board read --all`): every event after `after`, ignoring
    /// subscriptions and audience. Exists for the human CLI only.
    pub fn read_all(&self, after: u64, limit: usize) -> Result<ReadBatch, BoardError> {
        self.with_retry(|| {
            let snap = Snapshot::take(self)?;
            let after = check_after(&snap, after)?;
            let limit = limit.clamp(1, MAX_READ_LIMIT);
            let mut b = batch(&snap, after);
            let mut id = after + 1;
            while id <= snap.last && b.events.len() < limit {
                b.events.push(Delivered {
                    event: snap.get(id)?,
                    addressed: false,
                });
                id += 1;
            }
            b.through = id - 1;
            b.more = b.through < snap.last;
            Ok(b)
        })
    }

    pub(crate) fn start_after(&self, tag: &str, from: Resume) -> Result<u64, BoardError> {
        let c = self.cursor(tag)?;
        let (base, _) = self.bounds()?;
        if c.expired {
            return Err(BoardError::CursorExpired {
                tag: tag.into(),
                base,
            });
        }
        if !c.exists {
            return Ok(base.saturating_sub(1));
        }
        Ok(match from {
            Resume::Delivered => c.delivered,
            Resume::Acked => c.acked,
        })
    }

    /// Cursor-driven read: from `delivered` or `acked`, then advance `delivered` to
    /// `through`. A tag that never read starts at the board's base.
    pub fn deliver(
        &self,
        session: &str,
        limit: usize,
        from: Resume,
    ) -> Result<ReadBatch, BoardError> {
        let me = &self.whoami(session)?;
        let after = self.start_after(&me.tag, from)?;
        let subs = self.subscriptions_of(&me.tag)?;
        let b = self.read_for(&me.tag, &subs, after, limit, false)?;
        let _l = self.tag_lock(&me.tag)?;
        let mut c = self.cursor(&me.tag)?;
        if c.expired {
            return Err(BoardError::CursorExpired {
                tag: me.tag.clone(),
                base: b.base,
            });
        }
        if !c.exists {
            c.acked = after;
            c.delivered = after;
        }
        if b.through > c.delivered || !c.exists {
            c.delivered = c.delivered.max(b.through);
            self.write_cursor(&me.tag, &c)?;
        }
        Ok(b)
    }

    /// Confirm processing through `id`. Idempotent at or below the cursor (a no-op that
    /// never moves it backwards); refuses ids beyond the last committed event.
    pub fn ack(&self, session: &str, id: u64) -> Result<Cursor, BoardError> {
        let me = &self.whoami(session)?;
        let (base, last) = self.bounds()?;
        let _l = self.tag_lock(&me.tag)?;
        let mut c = self.cursor(&me.tag)?;
        if c.expired {
            return Err(BoardError::CursorExpired {
                tag: me.tag.clone(),
                base,
            });
        }
        if id > last {
            return Err(BoardError::AckBeyondCommitted { id, last });
        }
        if c.exists && id <= c.acked {
            return Ok(c);
        }
        c.acked = id;
        c.delivered = c.delivered.max(id);
        c.exists = true;
        self.write_cursor(&me.tag, &c)?;
        Ok(c)
    }

    /// The highest id this session's tag confirmed (the board's `base - 1` when it never
    /// acked).
    pub fn acked(&self, session: &str) -> Result<u64, BoardError> {
        let me = self.whoami(session)?;
        let c = self.cursor(&me.tag)?;
        if c.exists {
            return Ok(c.acked);
        }
        let (base, _) = self.bounds()?;
        Ok(base.saturating_sub(1))
    }

    /// One event by id, only when it is visible to this session's tag: addressed to it,
    /// or on a thread or topic it subscribed to, and not its own post. `None` otherwise
    /// (also for ids compacted away or never committed).
    pub fn get(&self, session: &str, id: u64) -> Result<Option<Event>, BoardError> {
        let me = self.whoami(session)?;
        let subs = self.subscriptions_of(&me.tag)?;
        self.with_retry(|| {
            let snap = Snapshot::take(self)?;
            if id == 0 || id < snap.base || id > snap.last {
                return Ok(None);
            }
            let ev = snap.get(id)?;
            let visible = ev.from_tag != me.tag
                && (ev.to.iter().any(|t| t == &me.tag)
                    || subs.topics.contains(&ev.topic)
                    || subs.threads.contains(&ev.thread));
            Ok(visible.then_some(ev))
        })
    }

    /// Accept the gap of an expired cursor: it restarts at the board's base, explicitly.
    pub fn accept_gap(&self, session: &str) -> Result<Cursor, BoardError> {
        let me = &self.whoami(session)?;
        let (base, _) = self.bounds()?;
        let _l = self.tag_lock(&me.tag)?;
        let mut c = self.cursor(&me.tag)?;
        let start = base.saturating_sub(1);
        c.acked = c.acked.max(start);
        c.delivered = c.delivered.max(c.acked);
        c.expired = false;
        c.exists = true;
        self.write_cursor(&me.tag, &c)?;
        Ok(c)
    }

    pub(crate) fn all_cursors(&self) -> Result<Vec<(String, Cursor)>, BoardError> {
        let dir = self.root().join("cursors");
        let Ok(rd) = std::fs::read_dir(&dir) else {
            return Ok(Vec::new());
        };
        let mut tags: Vec<String> = rd
            .filter_map(|e| e.ok())
            .filter_map(|e| e.file_name().to_str().map(str::to_string))
            .filter_map(|n| n.strip_suffix(".json").map(str::to_string))
            .filter(|t| validate_tag(t).is_ok())
            .collect();
        tags.sort();
        tags.into_iter()
            .map(|t| self.cursor(&t).map(|c| (t, c)))
            .collect()
    }

    pub(crate) fn expire_cursors(&self, tags: &[String]) -> Result<(), BoardError> {
        for t in tags {
            let _l = self.tag_lock(t)?;
            let mut c = self.cursor(t)?;
            c.expired = true;
            self.write_cursor(t, &c)?;
        }
        Ok(())
    }

    fn with_retry<T>(&self, mut f: impl FnMut() -> Result<T, BoardError>) -> Result<T, BoardError> {
        let mut tries = 0;
        loop {
            match f() {
                Err(BoardError::IndexMismatch { .. }) if tries < 3 => {
                    tries += 1;
                    std::thread::sleep(std::time::Duration::from_millis(5 << tries));
                }
                r => return r,
            }
        }
    }

    fn read_for(
        &self,
        tag: &str,
        subs: &Subscriptions,
        after: u64,
        limit: usize,
        mine_only: bool,
    ) -> Result<ReadBatch, BoardError> {
        self.with_retry(|| self.read_once(tag, subs, after, limit, mine_only))
    }

    fn read_once(
        &self,
        tag: &str,
        subs: &Subscriptions,
        after: u64,
        limit: usize,
        mine_only: bool,
    ) -> Result<ReadBatch, BoardError> {
        let snap = Snapshot::take(self)?;
        let after = check_after(&snap, after)?;
        let limit = limit.clamp(1, MAX_READ_LIMIT);
        let mut b = batch(&snap, after);
        if snap.last == 0 || after >= snap.last {
            return Ok(b);
        }
        let maxe = self.limits().max_events;
        // id -> addressed. Each source contributes its lowest `limit` ids above `after`,
        // so the lowest `limit` of the union are exact.
        let mut cand: BTreeMap<u64, bool> = BTreeMap::new();
        let mut cut = false;
        let (ids, more) =
            read_ids_after(&inbox_file(self.root(), tag), after, snap.last, limit, maxe)?;
        cut |= more;
        for id in ids {
            cand.insert(id, true);
        }
        if !mine_only {
            for t in &subs.topics {
                let (ids, more) =
                    read_ids_after(&topic_file(self.root(), t), after, snap.last, limit, maxe)?;
                cut |= more;
                for id in ids {
                    cand.entry(id).or_insert(false);
                }
            }
            if !subs.threads.is_empty() {
                let hs: Vec<u64> = subs
                    .threads
                    .iter()
                    .map(|t| key_hash(H_THREAD, t.as_bytes()))
                    .collect();
                let mut hits = 0usize;
                snap.scan(after + 1, |e| {
                    if hs.contains(&e.thread_h) {
                        if hits == limit {
                            cut = true;
                            return Ok(false);
                        }
                        hits += 1;
                        cand.entry(e.id).or_insert(false);
                    }
                    Ok(true)
                })?;
            }
        }
        let cut = cut || cand.len() > limit;
        let chosen: Vec<(u64, bool)> = cand.into_iter().take(limit).collect();
        b.more = cut;
        b.through = if cut {
            chosen.last().map(|c| c.0).unwrap_or(after)
        } else {
            snap.last
        };
        let mut addressed = Vec::new();
        let mut subscribed = Vec::new();
        for (id, _) in chosen {
            let ev = snap.get(id)?;
            if ev.from_tag == tag {
                continue;
            }
            if ev.to.iter().any(|t| t == tag) {
                addressed.push(Delivered {
                    event: ev,
                    addressed: true,
                });
            } else if !mine_only
                && (subs.topics.contains(&ev.topic) || subs.threads.contains(&ev.thread))
            {
                subscribed.push(Delivered {
                    event: ev,
                    addressed: false,
                });
            }
            // Anything else is a hash collision: not for this reader, and not a gap.
        }
        addressed.extend(subscribed);
        b.events = addressed;
        Ok(b)
    }
}

fn check_after(snap: &Snapshot, after: u64) -> Result<u64, BoardError> {
    if after > snap.last {
        return Err(BoardError::CursorAhead {
            after,
            last: snap.last,
        });
    }
    if snap.base > 0 && after + 1 < snap.base {
        return Err(BoardError::Compacted {
            after,
            base: snap.base,
        });
    }
    Ok(after)
}

fn batch(snap: &Snapshot, after: u64) -> ReadBatch {
    ReadBatch {
        events: Vec::new(),
        after,
        through: after,
        base: snap.base,
        last: snap.last,
        torn_entry: snap.torn_entry,
        more: false,
    }
}
