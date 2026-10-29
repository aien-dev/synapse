//! On-disk codec of the board: CRC-32C, the journal frame, the fixed-width table entry, the
//! compact one-line JSON printer, and the event body <-> [`J`] mapping.
//!
//! Journal frame: `u32 len (LE) | u32 crc32c(body) (LE) | body`, where `body` is one compact
//! JSON object followed by `\n`. A frame whose length or checksum does not verify is never
//! returned (see the torn-tail rule in `journal.rs`).

use super::{BoardError, BoardId, Event, Kind, Ref, RefKind, PROTOCOL};
use crate::json::{self, J};

/// Bytes before the body: length and checksum.
pub(crate) const FRAME_HEADER: u64 = 8;
/// Largest frame body accepted on write or read (64 KiB). The field limits keep a real event
/// far below this; the cap bounds what a hostile length field can make a reader allocate.
pub const MAX_FRAME_BYTES: u32 = 64 * 1024;
/// Fixed width of one `journal.idx` table entry.
pub(crate) const ENTRY_BYTES: u64 = 64;
/// Fixed width of one `topics/*.idx` / `inbox/*.idx` entry (a little-endian event id).
pub(crate) const ID_BYTES: u64 = 8;

const fn crc_table() -> [u32; 256] {
    let mut t = [0u32; 256];
    let mut i = 0;
    while i < 256 {
        let mut c = i as u32;
        let mut k = 0;
        while k < 8 {
            c = if c & 1 != 0 {
                (c >> 1) ^ 0x82F6_3B78
            } else {
                c >> 1
            };
            k += 1;
        }
        t[i] = c;
        i += 1;
    }
    t
}
static CRC: [u32; 256] = crc_table();

/// CRC-32C (Castagnoli), the checksum of every frame body and table entry.
pub fn crc32c(data: &[u8]) -> u32 {
    let mut c = !0u32;
    for &b in data {
        c = CRC[((c ^ b as u32) & 0xff) as usize] ^ (c >> 8);
    }
    !c
}

/// FNV-1a 64 over a domain byte and the key. Only a filter: every hit is verified against
/// the real event, so a collision costs one extra frame read, never a wrong delivery.
/// Never 0 (0 means "no key").
pub(crate) fn key_hash(domain: u8, key: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for &b in std::iter::once(&domain).chain(key) {
        h ^= b as u64;
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    h.max(1)
}
pub(crate) const H_TOPIC: u8 = b't';
pub(crate) const H_THREAD: u8 = b'h';
pub(crate) const H_IDEM: u8 = b'i';

/// `len | crc | body`.
pub(crate) fn encode_frame(body: &[u8]) -> Vec<u8> {
    let mut f = Vec::with_capacity(body.len() + FRAME_HEADER as usize);
    f.extend_from_slice(&(body.len() as u32).to_le_bytes());
    f.extend_from_slice(&crc32c(body).to_le_bytes());
    f.extend_from_slice(body);
    f
}

/// One `journal.idx` entry: where event `id` lives and the filter keys of its body.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Entry {
    pub id: u64,
    pub offset: u64,
    pub len: u32,
    pub crc: u32,
    pub topic_h: u64,
    pub thread_h: u64,
    pub idem_h: u64,
}

impl Entry {
    pub fn encode(&self) -> [u8; ENTRY_BYTES as usize] {
        let mut b = [0u8; ENTRY_BYTES as usize];
        b[0..8].copy_from_slice(&self.id.to_le_bytes());
        b[8..16].copy_from_slice(&self.offset.to_le_bytes());
        b[16..20].copy_from_slice(&self.len.to_le_bytes());
        b[20..24].copy_from_slice(&self.crc.to_le_bytes());
        b[24..32].copy_from_slice(&self.topic_h.to_le_bytes());
        b[32..40].copy_from_slice(&self.thread_h.to_le_bytes());
        b[40..48].copy_from_slice(&self.idem_h.to_le_bytes());
        let c = crc32c(&b[..60]);
        b[60..64].copy_from_slice(&c.to_le_bytes());
        b
    }
    /// `None` when the entry checksum or the reserved bytes do not verify.
    pub fn decode(b: &[u8]) -> Option<Entry> {
        if b.len() != ENTRY_BYTES as usize || b[48..60].iter().any(|&x| x != 0) {
            return None;
        }
        let u64_at = |i: usize| u64::from_le_bytes(b[i..i + 8].try_into().unwrap_or([0; 8]));
        let u32_at = |i: usize| u32::from_le_bytes(b[i..i + 4].try_into().unwrap_or([0; 4]));
        if u32_at(60) != crc32c(&b[..60]) {
            return None;
        }
        Some(Entry {
            id: u64_at(0),
            offset: u64_at(8),
            len: u32_at(16),
            crc: u32_at(20),
            topic_h: u64_at(24),
            thread_h: u64_at(32),
            idem_h: u64_at(40),
        })
    }
    pub fn frame_end(&self) -> u64 {
        self.offset + FRAME_HEADER + self.len as u64
    }
}

/// JSON string escape for the one-line form (same escapes as `json::J::dump`).
fn escape(b: &mut Vec<u8>, s: &[u8]) {
    b.push(b'"');
    for &c in s {
        match c {
            b'"' => b.extend_from_slice(b"\\\""),
            b'\\' => b.extend_from_slice(b"\\\\"),
            b'\n' => b.extend_from_slice(b"\\n"),
            b'\r' => b.extend_from_slice(b"\\r"),
            b'\t' => b.extend_from_slice(b"\\t"),
            0x08 => b.extend_from_slice(b"\\b"),
            0x0c => b.extend_from_slice(b"\\f"),
            0x7f => b.extend_from_slice(b"\\u007f"),
            c if c < 0x20 => b.extend_from_slice(format!("\\u{c:04x}").as_bytes()),
            c => b.push(c),
        }
    }
    b.push(b'"');
}

/// One-line JSON (no whitespace) of a [`J`] value, without a trailing newline. This is the
/// frame body format and the CLI machine output format.
pub fn compact(j: &J) -> Vec<u8> {
    let mut b = Vec::new();
    compact_into(j, &mut b);
    b
}

fn compact_into(j: &J, b: &mut Vec<u8>) {
    match j {
        J::Null => b.extend_from_slice(b"null"),
        J::True => b.extend_from_slice(b"true"),
        J::False => b.extend_from_slice(b"false"),
        J::Num(t) => b.extend_from_slice(t),
        J::Str(s) => escape(b, s),
        J::Arr(a) => {
            b.push(b'[');
            for (i, v) in a.iter().enumerate() {
                if i > 0 {
                    b.push(b',');
                }
                compact_into(v, b);
            }
            b.push(b']');
        }
        J::Obj(m) => {
            b.push(b'{');
            for (i, (k, v)) in m.iter().enumerate() {
                if i > 0 {
                    b.push(b',');
                }
                escape(b, k);
                b.push(b':');
                compact_into(v, b);
            }
            b.push(b'}');
        }
    }
}

pub(crate) fn num_u64(x: u64) -> J {
    J::Num(x.to_string().into_bytes())
}

/// A JSON number that is a plain non-negative decimal integer fitting `u64`.
pub(crate) fn as_u64(j: Option<&J>) -> Option<u64> {
    match j {
        Some(J::Num(t)) if !t.is_empty() && t.len() <= 20 && t.iter().all(u8::is_ascii_digit) => {
            std::str::from_utf8(t).ok()?.parse().ok()
        }
        _ => None,
    }
}

fn as_i64(j: Option<&J>) -> Option<i64> {
    match j {
        Some(J::Num(t)) => {
            let s = std::str::from_utf8(t).ok()?;
            let digits = s.strip_prefix('-').unwrap_or(s);
            if digits.is_empty() || !digits.bytes().all(|c| c.is_ascii_digit()) {
                return None;
            }
            s.parse().ok()
        }
        _ => None,
    }
}

pub(crate) fn as_string(j: Option<&J>) -> Option<String> {
    match j {
        Some(J::Str(s)) => String::from_utf8(s.clone()).ok(),
        _ => None,
    }
}

pub(crate) fn str_list(j: Option<&J>) -> Option<Vec<String>> {
    match j {
        Some(J::Arr(a)) => a.iter().map(|v| as_string(Some(v))).collect(),
        _ => None,
    }
}

pub(crate) fn j_list(v: &[String]) -> J {
    J::Arr(v.iter().map(|s| J::str(s)).collect())
}

impl Event {
    /// The event body as a [`J`] object, fields in protocol order (`v`, `id`, `from_tag`,
    /// `from`, ...).
    pub fn to_json(&self) -> J {
        let mut e = J::obj();
        e.set("v", J::str(PROTOCOL));
        e.set("id", num_u64(self.id));
        e.set("from_tag", J::str(&self.from_tag));
        e.set("from", J::str(&self.from));
        e.set("mission", J::str(&self.mission.to_hex()));
        e.set("thread", J::str(&self.thread));
        e.set("topic", J::str(&self.topic));
        e.set("to", j_list(&self.to));
        e.set("kind", J::str(self.kind.as_str()));
        e.set(
            "parent",
            match self.parent {
                Some(p) => num_u64(p),
                None => J::Null,
            },
        );
        e.set("ts", J::num(self.ts));
        e.set("text", J::str(&self.text));
        e.set(
            "refs",
            J::Arr(
                self.refs
                    .iter()
                    .map(|r| {
                        let mut o = J::obj();
                        o.set("repo", J::str(&r.repo));
                        o.set("kind", J::str(r.kind.as_str()));
                        o.set("value", J::str(&r.value));
                        o
                    })
                    .collect(),
            ),
        );
        e.set(
            "idem",
            match &self.idem {
                Some(k) => J::str(k),
                None => J::Null,
            },
        );
        e
    }

    /// Strict parse of an event body. Every field limit is checked again: a journal is a
    /// store file, so a planted body is refused the same way a bad post is.
    pub fn from_json(j: &J) -> Result<Event, String> {
        if !j.is_obj() {
            return Err("body is not an object".into());
        }
        let v = as_string(j.get("v")).ok_or("no protocol version")?;
        if v != PROTOCOL {
            return Err(format!("protocol {v:?} is not {PROTOCOL}"));
        }
        let s = |k: &str| as_string(j.get(k)).ok_or(format!("field {k} missing or not a string"));
        let mission_hex = s("mission")?;
        let mission =
            BoardId::parse_hex(&mission_hex).ok_or(format!("bad mission {mission_hex:?}"))?;
        let kind_s = s("kind")?;
        let refs = match j.get("refs") {
            Some(J::Arr(a)) => a
                .iter()
                .map(|r| {
                    let rk = as_string(r.get("kind")).ok_or("ref kind")?;
                    Ok(Ref {
                        repo: as_string(r.get("repo")).ok_or("ref repo")?,
                        kind: RefKind::parse(&rk).ok_or(format!("bad ref kind {rk:?}"))?,
                        value: as_string(r.get("value")).ok_or("ref value")?,
                    })
                })
                .collect::<Result<Vec<_>, String>>()?,
            _ => return Err("refs missing".into()),
        };
        let e = Event {
            id: as_u64(j.get("id")).ok_or("bad id")?,
            from_tag: s("from_tag")?,
            from: s("from")?,
            mission,
            thread: s("thread")?,
            topic: s("topic")?,
            to: str_list(j.get("to")).ok_or("bad to list")?,
            kind: Kind::parse(&kind_s).ok_or(format!("bad kind {kind_s:?}"))?,
            parent: match j.get("parent") {
                Some(J::Null) => None,
                p => Some(as_u64(p).ok_or("bad parent")?),
            },
            ts: as_i64(j.get("ts")).ok_or("bad ts")?,
            text: s("text")?,
            refs,
            idem: match j.get("idem") {
                Some(J::Null) => None,
                Some(J::Str(_)) => Some(s("idem")?),
                _ => return Err("bad idem".into()),
            },
        };
        super::validate_event_fields(&e).map_err(|err| err.to_string())?;
        Ok(e)
    }

    /// The frame body bytes: one-line JSON plus `\n`.
    pub(crate) fn body(&self) -> Vec<u8> {
        let mut b = compact(&self.to_json());
        b.push(b'\n');
        b
    }

    /// Parse a verified frame body.
    pub(crate) fn from_body(body: &[u8]) -> Result<Event, String> {
        if body.last() != Some(&b'\n') {
            return Err("body does not end with a newline".into());
        }
        let j = json::parse(body).ok_or("body is not JSON")?;
        Event::from_json(&j)
    }
}

/// Error helper: a refusal about a board file.
pub(crate) fn corrupt(
    path: &std::path::Path,
    offset: u64,
    reason: impl Into<String>,
) -> BoardError {
    BoardError::Corrupt {
        path: path.to_path_buf(),
        offset,
        reason: reason.into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crc32c_known_vector() {
        assert_eq!(crc32c(b"123456789"), 0xE306_9283);
        assert_eq!(crc32c(b""), 0);
    }

    #[test]
    fn entry_round_trip_and_tamper() {
        let e = Entry {
            id: 7,
            offset: 1234,
            len: 99,
            crc: 5,
            topic_h: 11,
            thread_h: 12,
            idem_h: 0,
        };
        let mut b = e.encode();
        assert_eq!(Entry::decode(&b), Some(e));
        b[3] ^= 1;
        assert_eq!(Entry::decode(&b), None);
    }

    #[test]
    fn compact_is_one_line() {
        let mut j = J::obj();
        j.set("a", J::str("x\ny\"\u{7f}"));
        j.set("b", J::Arr(vec![J::num(1), J::Null]));
        assert_eq!(
            compact(&j),
            br#"{"a":"x\ny\"\u007f","b":[1,null]}"#.to_vec()
        );
        assert_eq!(json::parse(&compact(&j)), Some(j));
    }
}
