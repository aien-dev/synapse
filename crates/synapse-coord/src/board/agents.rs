//! Tags: a human-readable name an agent binds to its session (`agents/<tag>.json`).
//!
//! A tag is identity **for addressing only**: messages are addressed to tags, cursors and
//! subscriptions belong to tags (so an agent that comes back under a new session, after its
//! old binding expired or was released, resumes the same inbox). It is not authentication:
//! anyone who can write the board root can bind any free tag. The binding is live for its
//! `ttl` after `seen_at`; posts refresh it. A tag bound to a live different session is
//! refused with [`BoardError::TagTaken`].

use super::frame::{as_string, compact};
use super::journal::{ensure_dir, fsync_dir, BoardLock};
use super::{validate_session, validate_tag, Board, BoardError, PROTOCOL};
use crate::json::{self, J};
use std::fs;
use std::path::PathBuf;

/// Default binding lifetime: 4 hours after the last register or post.
pub const DEFAULT_TAG_TTL: i64 = 4 * 3600;
/// Longest binding lifetime accepted: 7 days.
pub const MAX_TAG_TTL: i64 = 7 * 86400;
/// Most bindings scanned by `whoami`.
const MAX_AGENTS: usize = 4096;
const MAX_BINDING_BYTES: u64 = 4096;

/// A resolved identity: a live binding of `tag` to `session`.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Me {
    pub tag: String,
    pub session: String,
}

/// Result of [`Board::register`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Registration {
    pub me: Me,
    /// True when this session already held the tag (idempotent re-register).
    pub refreshed: bool,
    pub expires_at: i64,
}

#[derive(Clone, Debug)]
pub(crate) struct Binding {
    pub tag: String,
    pub session: String,
    pub registered_at: i64,
    pub seen_at: i64,
    pub ttl: i64,
}

impl Binding {
    fn live(&self, now: i64) -> bool {
        now - self.seen_at <= self.ttl
    }
    fn to_json(&self) -> J {
        let mut o = J::obj();
        o.set("v", J::str(PROTOCOL));
        o.set("tag", J::str(&self.tag));
        o.set("session", J::str(&self.session));
        o.set("registered_at", J::num(self.registered_at));
        o.set("seen_at", J::num(self.seen_at));
        o.set("ttl", J::num(self.ttl));
        o
    }
}

fn i64_field(j: &J, k: &str) -> Option<i64> {
    match j.get(k) {
        Some(J::Num(t)) => std::str::from_utf8(t).ok()?.parse().ok(),
        _ => None,
    }
}

impl Board {
    fn binding_path(&self, tag: &str) -> PathBuf {
        self.root().join("agents").join(format!("{tag}.json"))
    }

    fn read_binding(&self, tag: &str) -> Result<Option<Binding>, BoardError> {
        let p = self.binding_path(tag);
        crate::record::check_real_parents(self.root(), &p)?;
        let Some(b) = crate::record::read_bounded(&p, MAX_BINDING_BYTES)? else {
            return Ok(None);
        };
        let bad = |r: &str| BoardError::Corrupt {
            path: p.clone(),
            offset: 0,
            reason: r.to_string(),
        };
        let j = json::parse(&b).ok_or_else(|| bad("not JSON"))?;
        if as_string(j.get("v")).as_deref() != Some(PROTOCOL) {
            return Err(bad("not an aien-board/1 binding"));
        }
        let b = Binding {
            tag: as_string(j.get("tag")).ok_or_else(|| bad("no tag"))?,
            session: as_string(j.get("session")).ok_or_else(|| bad("no session"))?,
            registered_at: i64_field(&j, "registered_at").ok_or_else(|| bad("no registered_at"))?,
            seen_at: i64_field(&j, "seen_at").ok_or_else(|| bad("no seen_at"))?,
            ttl: i64_field(&j, "ttl").ok_or_else(|| bad("no ttl"))?,
        };
        if b.tag != tag {
            return Err(bad("binding names another tag than its file"));
        }
        validate_session(&b.session)?;
        Ok(Some(b))
    }

    fn write_binding(&self, b: &Binding) -> Result<(), BoardError> {
        let mut data = compact(&b.to_json());
        data.push(b'\n');
        crate::durable_write(self.root(), &self.binding_path(&b.tag), &data)?;
        Ok(())
    }

    /// Every binding on the board (bounded; a hostile file under `agents/` is refused).
    pub(crate) fn bindings(&self) -> Result<Vec<Binding>, BoardError> {
        let dir = self.root().join("agents");
        let Ok(rd) = fs::read_dir(&dir) else {
            return Ok(Vec::new());
        };
        let mut tags = Vec::new();
        for ent in rd.filter_map(|e| e.ok()) {
            let name = ent.file_name();
            let Some(n) = name.to_str() else { continue };
            let Some(tag) = n.strip_suffix(".json") else {
                continue;
            };
            if validate_tag(tag).is_err() {
                continue;
            }
            tags.push(tag.to_string());
            if tags.len() > MAX_AGENTS {
                return Err(BoardError::TooLarge {
                    field: "agents",
                    len: tags.len(),
                    limit: MAX_AGENTS,
                });
            }
        }
        tags.sort();
        let mut out = Vec::new();
        for t in tags {
            if let Some(b) = self.read_binding(&t)? {
                out.push(b);
            }
        }
        Ok(out)
    }

    /// Bind `tag` to `session` (under the writer lock). Idempotent for the same session;
    /// [`BoardError::TagTaken`] when another session holds it live;
    /// [`BoardError::SessionTagged`] when this session holds another live tag.
    pub fn register(
        &self,
        session: &str,
        tag: &str,
        ttl: Option<i64>,
    ) -> Result<Registration, BoardError> {
        validate_tag(tag)?;
        validate_session(session)?;
        let ttl = ttl.unwrap_or(DEFAULT_TAG_TTL);
        if !(1..=MAX_TAG_TTL).contains(&ttl) {
            return Err(BoardError::TooLarge {
                field: "ttl seconds",
                len: ttl.max(0) as usize,
                limit: MAX_TAG_TTL as usize,
            });
        }
        let _lock = BoardLock::acquire(self.root())?;
        self.check_id_locked()?;
        ensure_dir(self.root(), "agents")?;
        let now = self.now();
        let existing = self.read_binding(tag)?;
        if let Some(b) = &existing {
            if b.session != session && b.live(now) {
                return Err(BoardError::TagTaken {
                    tag: tag.into(),
                    holder: b.session.clone(),
                });
            }
        }
        if let Some(other) = self
            .bindings()?
            .into_iter()
            .find(|b| b.session == session && b.tag != tag && b.live(now))
        {
            return Err(BoardError::SessionTagged {
                session: session.into(),
                tag: other.tag,
            });
        }
        let refreshed = existing
            .as_ref()
            .is_some_and(|b| b.session == session && b.live(now));
        let b = Binding {
            tag: tag.into(),
            session: session.into(),
            registered_at: if refreshed {
                existing.map(|b| b.registered_at).unwrap_or(now)
            } else {
                now
            },
            seen_at: now,
            ttl,
        };
        self.write_binding(&b)?;
        Ok(Registration {
            me: Me {
                tag: tag.into(),
                session: session.into(),
            },
            refreshed,
            expires_at: now + ttl,
        })
    }

    /// Release this session's tag (its cursor and subscriptions stay with the tag).
    pub fn unregister(&self, session: &str) -> Result<Me, BoardError> {
        let me = &self.whoami(session)?;
        let _lock = BoardLock::acquire(self.root())?;
        self.check_id_locked()?;
        self.check_binding(me)?;
        let p = self.binding_path(&me.tag);
        fs::remove_file(&p).map_err(super::io_err(&p))?;
        fsync_dir(&self.root().join("agents"));
        Ok(me.clone())
    }

    /// The live tag this session holds, else [`BoardError::NotRegistered`].
    pub fn whoami(&self, session: &str) -> Result<Me, BoardError> {
        validate_session(session)?;
        let now = self.now();
        self.bindings()?
            .into_iter()
            .find(|b| b.session == session && b.live(now))
            .map(|b| Me {
                tag: b.tag,
                session: b.session,
            })
            .ok_or_else(|| BoardError::NotRegistered {
                session: session.into(),
            })
    }

    /// Every binding as `(tag, session, live)`, for the operator view.
    pub fn agents(&self) -> Result<Vec<(String, String, bool)>, BoardError> {
        let now = self.now();
        Ok(self
            .bindings()?
            .into_iter()
            .map(|b| {
                let live = b.live(now);
                (b.tag, b.session, live)
            })
            .collect())
    }

    /// Verify that `me` is still a live binding (a handle cannot outlive its tag).
    pub(crate) fn check_binding(&self, me: &Me) -> Result<Binding, BoardError> {
        validate_tag(&me.tag)?;
        validate_session(&me.session)?;
        match self.read_binding(&me.tag)? {
            Some(b) if b.session == me.session && b.live(self.now()) => Ok(b),
            _ => Err(BoardError::NotRegistered {
                session: me.session.clone(),
            }),
        }
    }

    /// Refresh `seen_at` when half the TTL has passed (caller holds the writer lock).
    pub(crate) fn touch_locked(&self, _me: &Me, b: &Binding) -> Result<(), BoardError> {
        let now = self.now();
        if now - b.seen_at > b.ttl / 2 {
            let mut nb = b.clone();
            nb.seen_at = now;
            self.write_binding(&nb)?;
        }
        Ok(())
    }
}
