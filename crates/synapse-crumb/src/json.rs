//! Strict, bounded JSON reader for Directory Crumb documents.
//!
//! Stricter than the `crumb.c` reader on purpose: nesting is capped at
//! [`MAX_JSON_DEPTH`], duplicate object keys are refused, raw control characters
//! inside strings are refused, numbers follow the RFC 8259 grammar, and lone
//! UTF-16 surrogates in `\u` escapes are refused instead of being replaced.

use std::collections::BTreeSet;

/// Maximum container nesting depth (objects and arrays) accepted in a `.crumb`.
pub const MAX_JSON_DEPTH: usize = 32;

/// A parsed JSON value. Object members keep document order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JsonValue {
    Null,
    Bool(bool),
    /// Number kept as its validated source text.
    Number(String),
    String(String),
    Array(Vec<JsonValue>),
    Object(Vec<(String, JsonValue)>),
}

impl JsonValue {
    /// Member lookup on an object; `None` for non-objects or absent keys.
    pub fn get(&self, key: &str) -> Option<&JsonValue> {
        match self {
            JsonValue::Object(members) => members.iter().find(|(k, _)| k == key).map(|(_, v)| v),
            _ => None,
        }
    }

    pub fn as_str(&self) -> Option<&str> {
        match self {
            JsonValue::String(s) => Some(s),
            _ => None,
        }
    }
}

/// Why a document is not acceptable JSON under the strict rules.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JsonError {
    /// Grammar violation at the given byte offset.
    Syntax { offset: usize },
    /// Nesting deeper than [`MAX_JSON_DEPTH`].
    TooDeep,
    /// The same key appears twice in one object.
    DuplicateKey { offset: usize },
}

/// Parse a complete JSON document. Leading and trailing JSON whitespace is allowed.
pub fn parse(text: &str) -> Result<JsonValue, JsonError> {
    let mut p = Parser {
        b: text.as_bytes(),
        i: 0,
        depth: 0,
    };
    p.ws();
    let v = p.value()?;
    p.ws();
    if p.i != p.b.len() {
        return Err(JsonError::Syntax { offset: p.i });
    }
    Ok(v)
}

struct Parser<'a> {
    b: &'a [u8],
    i: usize,
    depth: usize,
}

impl Parser<'_> {
    fn err(&self) -> JsonError {
        JsonError::Syntax { offset: self.i }
    }

    fn peek(&self) -> Option<u8> {
        self.b.get(self.i).copied()
    }

    fn ws(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\t' | b'\n' | b'\r')) {
            self.i += 1;
        }
    }

    fn eat(&mut self, c: u8) -> Result<(), JsonError> {
        if self.peek() == Some(c) {
            self.i += 1;
            Ok(())
        } else {
            Err(self.err())
        }
    }

    fn literal(&mut self, word: &[u8], v: JsonValue) -> Result<JsonValue, JsonError> {
        if self.b[self.i..].starts_with(word) {
            self.i += word.len();
            Ok(v)
        } else {
            Err(self.err())
        }
    }

    fn value(&mut self) -> Result<JsonValue, JsonError> {
        match self.peek() {
            Some(b'{') => self.container(true),
            Some(b'[') => self.container(false),
            Some(b'"') => Ok(JsonValue::String(self.string()?)),
            Some(b't') => self.literal(b"true", JsonValue::Bool(true)),
            Some(b'f') => self.literal(b"false", JsonValue::Bool(false)),
            Some(b'n') => self.literal(b"null", JsonValue::Null),
            Some(b'-' | b'0'..=b'9') => self.number(),
            _ => Err(self.err()),
        }
    }

    fn container(&mut self, object: bool) -> Result<JsonValue, JsonError> {
        self.depth += 1;
        if self.depth > MAX_JSON_DEPTH {
            return Err(JsonError::TooDeep);
        }
        self.i += 1;
        self.ws();
        let close = if object { b'}' } else { b']' };
        let mut members: Vec<(String, JsonValue)> = Vec::new();
        // Duplicate check in O(log n) per key: a 64 KiB object holds about 8,000 keys, and a
        // linear scan per key made such a file cost O(n^2) (review finding on PR #13).
        let mut seen: BTreeSet<String> = BTreeSet::new();
        let mut items: Vec<JsonValue> = Vec::new();
        if self.peek() == Some(close) {
            self.i += 1;
        } else {
            loop {
                self.ws();
                if object {
                    let key_offset = self.i;
                    if self.peek() != Some(b'"') {
                        return Err(self.err());
                    }
                    let key = self.string()?;
                    if !seen.insert(key.clone()) {
                        return Err(JsonError::DuplicateKey { offset: key_offset });
                    }
                    self.ws();
                    self.eat(b':')?;
                    self.ws();
                    let v = self.value()?;
                    members.push((key, v));
                } else {
                    let v = self.value()?;
                    items.push(v);
                }
                self.ws();
                match self.peek() {
                    Some(b',') => self.i += 1,
                    Some(c) if c == close => {
                        self.i += 1;
                        break;
                    }
                    _ => return Err(self.err()),
                }
            }
        }
        self.depth -= 1;
        Ok(if object {
            JsonValue::Object(members)
        } else {
            JsonValue::Array(items)
        })
    }

    fn hex4(&mut self) -> Result<u32, JsonError> {
        let s = self.b.get(self.i..self.i + 4).ok_or_else(|| self.err())?;
        let mut v = 0u32;
        for &c in s {
            let d = (c as char)
                .to_digit(16)
                .ok_or(JsonError::Syntax { offset: self.i })?;
            v = v * 16 + d;
        }
        self.i += 4;
        Ok(v)
    }

    fn string(&mut self) -> Result<String, JsonError> {
        self.eat(b'"')?;
        let mut out: Vec<u8> = Vec::new();
        loop {
            let c = self.peek().ok_or_else(|| self.err())?;
            match c {
                b'"' => {
                    self.i += 1;
                    break;
                }
                b'\\' => {
                    self.i += 1;
                    let e = self.peek().ok_or_else(|| self.err())?;
                    self.i += 1;
                    let ch = match e {
                        b'"' => '"',
                        b'\\' => '\\',
                        b'/' => '/',
                        b'b' => '\u{8}',
                        b'f' => '\u{c}',
                        b'n' => '\n',
                        b'r' => '\r',
                        b't' => '\t',
                        b'u' => {
                            let hi = self.hex4()?;
                            let cp = if (0xD800..0xDC00).contains(&hi) {
                                if self.b.get(self.i..self.i + 2) != Some(b"\\u") {
                                    return Err(self.err());
                                }
                                self.i += 2;
                                let lo = self.hex4()?;
                                if !(0xDC00..0xE000).contains(&lo) {
                                    return Err(self.err());
                                }
                                0x10000 + ((hi - 0xD800) << 10) + (lo - 0xDC00)
                            } else if (0xDC00..0xE000).contains(&hi) {
                                return Err(self.err());
                            } else {
                                hi
                            };
                            char::from_u32(cp).ok_or_else(|| self.err())?
                        }
                        _ => return Err(JsonError::Syntax { offset: self.i - 1 }),
                    };
                    let mut buf = [0u8; 4];
                    out.extend_from_slice(ch.encode_utf8(&mut buf).as_bytes());
                }
                0x00..=0x1F => return Err(self.err()),
                _ => {
                    out.push(c);
                    self.i += 1;
                }
            }
        }
        // Input is a &str and escapes produce valid UTF-8, so this cannot fail.
        String::from_utf8(out).map_err(|_| self.err())
    }

    fn digits(&mut self) -> usize {
        let start = self.i;
        while matches!(self.peek(), Some(b'0'..=b'9')) {
            self.i += 1;
        }
        self.i - start
    }

    fn number(&mut self) -> Result<JsonValue, JsonError> {
        let start = self.i;
        if self.peek() == Some(b'-') {
            self.i += 1;
        }
        match self.peek() {
            Some(b'0') => self.i += 1,
            Some(b'1'..=b'9') => {
                self.digits();
            }
            _ => return Err(self.err()),
        }
        if self.peek() == Some(b'.') {
            self.i += 1;
            if self.digits() == 0 {
                return Err(self.err());
            }
        }
        if matches!(self.peek(), Some(b'e' | b'E')) {
            self.i += 1;
            if matches!(self.peek(), Some(b'+' | b'-')) {
                self.i += 1;
            }
            if self.digits() == 0 {
                return Err(self.err());
            }
        }
        let text = std::str::from_utf8(&self.b[start..self.i]).map_err(|_| self.err())?;
        Ok(JsonValue::Number(text.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_nested_document() {
        let v =
            parse(r#" {"a": [1, -2.5e3, true, null, "x\u00e9\ud83d\ude00"], "b": {}} "#).unwrap();
        assert_eq!(
            v.get("a"),
            Some(&JsonValue::Array(vec![
                JsonValue::Number("1".into()),
                JsonValue::Number("-2.5e3".into()),
                JsonValue::Bool(true),
                JsonValue::Null,
                JsonValue::String("x\u{e9}\u{1F600}".into()),
            ]))
        );
        assert_eq!(v.get("b"), Some(&JsonValue::Object(vec![])));
    }

    #[test]
    fn refuses_duplicate_keys() {
        assert_eq!(
            parse(r#"{"a": 1, "a": 2}"#),
            Err(JsonError::DuplicateKey { offset: 9 })
        );
    }

    #[test]
    fn refuses_depth_over_cap_and_accepts_cap() {
        let ok = format!(
            "{}{}",
            "[".repeat(MAX_JSON_DEPTH),
            "]".repeat(MAX_JSON_DEPTH)
        );
        assert!(parse(&ok).is_ok());
        let deep = format!(
            "{}{}",
            "[".repeat(MAX_JSON_DEPTH + 1),
            "]".repeat(MAX_JSON_DEPTH + 1)
        );
        assert_eq!(parse(&deep), Err(JsonError::TooDeep));
    }

    #[test]
    fn refuses_loose_grammar() {
        for bad in [
            "{\"a\": 01}",
            "{\"a\": 1.}",
            "{\"a\": +1}",
            "{\"a\": \"\u{1}\"}",
            "{\"a\": \"\\ud800\"}",
            "{\"a\": \"\\x\"}",
            "{\"a\": 1,}",
            "{\"a\": 1} x",
            "{'a': 1}",
            "",
        ] {
            assert!(
                matches!(parse(bad), Err(JsonError::Syntax { .. })),
                "{bad:?}"
            );
        }
    }
}

#[cfg(test)]
mod cost_tests {
    use super::*;
    use std::time::{Duration, Instant};

    /// Largest-key-count object that fits in `MAX_CRUMB_BYTES` (64 KiB): short distinct keys.
    fn widest_object() -> String {
        let mut s = String::from("{");
        let mut i = 0usize;
        loop {
            let member = format!("\"{i:x}\":0,");
            if s.len() + member.len() + 1 > 64 * 1024 {
                break;
            }
            s.push_str(&member);
            i += 1;
        }
        s.pop();
        s.push('}');
        s
    }

    /// Regression for the O(n^2) duplicate-key scan (PR #13 review): before the fix this
    /// document took about 170 ms in a debug build and 42 ms in release; after, about 9 ms and
    /// 1.6 ms. The bound is the fastest of five runs, so a briefly loaded machine does not
    /// fail it, and it sits several times away from both the old and the new cost.
    #[test]
    fn widest_object_parses_in_linear_time() {
        let doc = widest_object();
        assert!(doc.len() <= 64 * 1024);
        match parse(&doc).unwrap() {
            JsonValue::Object(m) => assert!(m.len() > 7_000, "{}", m.len()),
            other => panic!("{other:?}"),
        }
        let fastest = (0..5)
            .map(|_| {
                let start = Instant::now();
                parse(&doc).unwrap();
                start.elapsed()
            })
            .min()
            .unwrap();
        let bound = if cfg!(debug_assertions) {
            Duration::from_millis(60)
        } else {
            Duration::from_millis(10)
        };
        assert!(fastest < bound, "{fastest:?} >= {bound:?}");
    }
}
