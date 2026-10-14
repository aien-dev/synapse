//! Minimal ordered JSON document model, byte-compatible with the one inside `crumb.c`
//! (aien-architecture 29780e5, `jparse`/`jprint`/`jescape`).
//!
//! Why not serde_json: records written by this crate and by `crumb.c` must be byte-identical
//! for the same logical content (key order preserved, two-space indent, `": "` separator,
//! trailing newline, `\u007f` escaped, numbers kept as their source text, unknown fields
//! kept in place). Strings are raw bytes, exactly as the C tool treats them.

/// One JSON value. Object members keep insertion order; numbers keep their source text.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum J {
    Null,
    True,
    False,
    Num(Vec<u8>),
    Str(Vec<u8>),
    Arr(Vec<J>),
    Obj(Vec<(Vec<u8>, J)>),
}

impl J {
    pub fn obj() -> J {
        J::Obj(Vec::new())
    }
    pub fn str(s: &str) -> J {
        J::Str(nul_cut(s.as_bytes()).to_vec())
    }
    pub fn num(x: i64) -> J {
        J::Num(x.to_string().into_bytes())
    }
    pub fn is_obj(&self) -> bool {
        matches!(self, J::Obj(_))
    }
    /// `jget`: member of an object, `None` for non-objects.
    pub fn get(&self, key: &str) -> Option<&J> {
        match self {
            J::Obj(m) => m.iter().find(|(k, _)| k == key.as_bytes()).map(|(_, v)| v),
            _ => None,
        }
    }
    pub fn get_mut(&mut self, key: &str) -> Option<&mut J> {
        match self {
            J::Obj(m) => m
                .iter_mut()
                .find(|(k, _)| k == key.as_bytes())
                .map(|(_, v)| v),
            _ => None,
        }
    }
    /// `jset`: replace in place if present, else append. No-op on non-objects.
    pub fn set(&mut self, key: &str, v: J) {
        if let J::Obj(m) = self {
            if let Some(slot) = m.iter_mut().find(|(k, _)| k == key.as_bytes()) {
                slot.1 = v;
            } else {
                m.push((key.as_bytes().to_vec(), v));
            }
        }
    }
    /// `jdel`.
    pub fn del(&mut self, key: &str) {
        if let J::Obj(m) = self {
            if let Some(i) = m.iter().position(|(k, _)| k == key.as_bytes()) {
                m.remove(i);
            }
        }
    }
    /// `jstrval`: the string value of a member, lossily decoded for display and comparison.
    pub fn str_of(&self, key: &str) -> Option<String> {
        match self.get(key) {
            Some(J::Str(s)) => Some(String::from_utf8_lossy(s).into_owned()),
            _ => None,
        }
    }
    /// `jstrval` as raw bytes.
    pub fn bytes_of(&self, key: &str) -> Option<&[u8]> {
        match self.get(key) {
            Some(J::Str(s)) => Some(s),
            _ => None,
        }
    }
    /// `jlong`: `atol` of a number member, `dflt` when absent or not a number.
    pub fn long_of(&self, key: &str, dflt: i64) -> i64 {
        match self.get(key) {
            Some(J::Num(t)) => atol(t),
            _ => dflt,
        }
    }
    /// `jobj_of`: get-or-create an object member (a non-object member is replaced).
    pub fn obj_of(&mut self, key: &str) -> &mut J {
        if !matches!(self.get(key), Some(J::Obj(_))) {
            self.set(key, J::obj());
        }
        self.get_mut(key).expect("member just set")
    }
    /// `jarr_of`: get-or-create an array member (a non-array member is replaced).
    pub fn arr_of(&mut self, key: &str) -> &mut Vec<J> {
        if !matches!(self.get(key), Some(J::Arr(_))) {
            self.set(key, J::Arr(Vec::new()));
        }
        match self.get_mut(key) {
            Some(J::Arr(a)) => a,
            _ => unreachable!("member just set to an array"),
        }
    }
    /// `jdump`: pretty print plus trailing newline, exactly as `crumb.c`.
    pub fn dump(&self) -> Vec<u8> {
        let mut b = Vec::new();
        print(self, &mut b, 0);
        b.push(b'\n');
        b
    }
}

/// C strings end at the first NUL byte; mirror that everywhere a string enters the model.
fn nul_cut(b: &[u8]) -> &[u8] {
    match b.iter().position(|&c| c == 0) {
        Some(i) => &b[..i],
        None => b,
    }
}

/// C `atol`: optional leading whitespace, optional sign, decimal digits; stops at anything else.
pub fn atol(t: &[u8]) -> i64 {
    let mut i = 0;
    while i < t.len() && matches!(t[i], b' ' | b'\t' | b'\n' | b'\r' | 0x0b | 0x0c) {
        i += 1;
    }
    let neg = match t.get(i) {
        Some(b'-') => {
            i += 1;
            true
        }
        Some(b'+') => {
            i += 1;
            false
        }
        _ => false,
    };
    let mut v: i64 = 0;
    while i < t.len() && t[i].is_ascii_digit() {
        v = v.saturating_mul(10).saturating_add(i64::from(t[i] - b'0'));
        i += 1;
    }
    if neg {
        -v
    } else {
        v
    }
}

fn escape(b: &mut Vec<u8>, s: &[u8]) {
    b.push(b'"');
    for &c in nul_cut(s) {
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

fn indent(b: &mut Vec<u8>, n: usize) {
    b.extend(std::iter::repeat_n(b' ', n));
}

fn print(j: &J, b: &mut Vec<u8>, ind: usize) {
    match j {
        J::Null => b.extend_from_slice(b"null"),
        J::True => b.extend_from_slice(b"true"),
        J::False => b.extend_from_slice(b"false"),
        J::Num(t) => b.extend_from_slice(t),
        J::Str(s) => escape(b, s),
        J::Arr(a) => {
            if a.is_empty() {
                b.extend_from_slice(b"[]");
                return;
            }
            b.extend_from_slice(b"[\n");
            for (i, v) in a.iter().enumerate() {
                indent(b, ind + 2);
                print(v, b, ind + 2);
                b.extend_from_slice(if i + 1 < a.len() { b",\n" } else { b"\n" });
            }
            indent(b, ind);
            b.push(b']');
        }
        J::Obj(m) => {
            if m.is_empty() {
                b.extend_from_slice(b"{}");
                return;
            }
            b.extend_from_slice(b"{\n");
            for (i, (k, v)) in m.iter().enumerate() {
                indent(b, ind + 2);
                escape(b, k);
                b.extend_from_slice(b": ");
                print(v, b, ind + 2);
                b.extend_from_slice(if i + 1 < m.len() { b",\n" } else { b"\n" });
            }
            indent(b, ind);
            b.push(b'}');
        }
    }
}

struct P<'a> {
    s: &'a [u8],
    i: usize,
    depth: u32,
    err: bool,
}

impl P<'_> {
    fn peek(&self) -> u8 {
        self.s.get(self.i).copied().unwrap_or(0)
    }
    fn at(&self, k: usize) -> u8 {
        self.s.get(self.i + k).copied().unwrap_or(0)
    }
    fn ws(&mut self) {
        while matches!(self.peek(), b' ' | b'\t' | b'\n' | b'\r') {
            self.i += 1;
        }
    }
    fn hex4(&self, from: usize) -> Option<u32> {
        let mut v = 0u32;
        for k in 0..4 {
            let c = self.at(from + k);
            v <<= 4;
            v |= match c {
                b'0'..=b'9' => u32::from(c - b'0'),
                b'a'..=b'f' => u32::from(c - b'a' + 10),
                b'A'..=b'F' => u32::from(c - b'A' + 10),
                _ => return None,
            };
        }
        Some(v)
    }
    fn string(&mut self) -> Vec<u8> {
        let mut b = Vec::new();
        self.i += 1;
        while self.peek() != 0 && self.peek() != b'"' {
            if self.peek() == b'\\' {
                self.i += 1;
                match self.peek() {
                    b'n' => b.push(b'\n'),
                    b't' => b.push(b'\t'),
                    b'r' => b.push(b'\r'),
                    b'b' => b.push(0x08),
                    b'f' => b.push(0x0c),
                    c @ (b'/' | b'\\' | b'"') => b.push(c),
                    b'u' => {
                        let Some(mut c) = self.hex4(1) else {
                            self.err = true;
                            return b;
                        };
                        self.i += 4;
                        if (0xD800..0xDC00).contains(&c)
                            && self.at(1) == b'\\'
                            && self.at(2) == b'u'
                        {
                            if let Some(d) = self.hex4(3) {
                                if (0xDC00..0xE000).contains(&d) {
                                    c = 0x10000 + ((c - 0xD800) << 10) + (d - 0xDC00);
                                    self.i += 6;
                                }
                            }
                        }
                        put_utf8(&mut b, c);
                    }
                    _ => {
                        self.err = true;
                        return b;
                    }
                }
                self.i += 1;
            } else {
                b.push(self.peek());
                self.i += 1;
            }
        }
        if self.peek() != b'"' {
            self.err = true;
        } else {
            self.i += 1;
        }
        nul_cut(&b).to_vec()
    }
    fn value(&mut self) -> Option<J> {
        self.ws();
        self.depth += 1;
        if self.err || self.depth > 64 {
            self.err = true;
            return None;
        }
        let c = self.peek();
        let r = if c == b'{' {
            let mut r = J::obj();
            self.i += 1;
            self.ws();
            if self.peek() == b'}' {
                self.i += 1;
            } else {
                loop {
                    self.ws();
                    if self.peek() != b'"' {
                        self.err = true;
                        break;
                    }
                    let k = self.string();
                    self.ws();
                    if self.peek() != b':' {
                        self.err = true;
                        break;
                    }
                    self.i += 1;
                    let Some(v) = self.value() else { break };
                    if let J::Obj(m) = &mut r {
                        if let Some(slot) = m.iter_mut().find(|(kk, _)| *kk == k) {
                            slot.1 = v;
                        } else {
                            m.push((k, v));
                        }
                    }
                    self.ws();
                    match self.peek() {
                        b',' => {
                            self.i += 1;
                        }
                        b'}' => {
                            self.i += 1;
                            break;
                        }
                        _ => {
                            self.err = true;
                            break;
                        }
                    }
                }
            }
            Some(r)
        } else if c == b'[' {
            let mut a = Vec::new();
            self.i += 1;
            self.ws();
            if self.peek() == b']' {
                self.i += 1;
            } else {
                while let Some(v) = self.value() {
                    a.push(v);
                    self.ws();
                    match self.peek() {
                        b',' => {
                            self.i += 1;
                        }
                        b']' => {
                            self.i += 1;
                            break;
                        }
                        _ => {
                            self.err = true;
                            break;
                        }
                    }
                }
            }
            Some(J::Arr(a))
        } else if c == b'"' {
            Some(J::Str(self.string()))
        } else if self.s[self.i.min(self.s.len())..].starts_with(b"true") {
            self.i += 4;
            Some(J::True)
        } else if self.s[self.i.min(self.s.len())..].starts_with(b"false") {
            self.i += 5;
            Some(J::False)
        } else if self.s[self.i.min(self.s.len())..].starts_with(b"null") {
            self.i += 4;
            Some(J::Null)
        } else if c == b'-' || c.is_ascii_digit() {
            let s = self.i;
            while matches!(self.peek(), b'-' | b'+' | b'.' | b'e' | b'E' | b'0'..=b'9') {
                self.i += 1;
            }
            let t = self.s[s..self.i].to_vec();
            if !strtod_full(&t) {
                self.err = true;
            }
            Some(J::Num(t))
        } else {
            self.err = true;
            None
        };
        self.depth -= 1;
        if self.err {
            None
        } else {
            r
        }
    }
}

/// True when C `strtod` would consume the whole token (decimal forms only: the token
/// alphabet is `-+.eE0-9`, so hex, inf and nan cannot occur).
fn strtod_full(t: &[u8]) -> bool {
    let mut i = 0;
    if matches!(t.first(), Some(b'-' | b'+')) {
        i += 1;
    }
    let int_start = i;
    while i < t.len() && t[i].is_ascii_digit() {
        i += 1;
    }
    let mut digits = i - int_start;
    if i < t.len() && t[i] == b'.' {
        i += 1;
        let f = i;
        while i < t.len() && t[i].is_ascii_digit() {
            i += 1;
        }
        digits += i - f;
    }
    if digits == 0 {
        return false;
    }
    if i < t.len() && (t[i] == b'e' || t[i] == b'E') {
        i += 1;
        if matches!(t.get(i), Some(b'-' | b'+')) {
            i += 1;
        }
        let e = i;
        while i < t.len() && t[i].is_ascii_digit() {
            i += 1;
        }
        if i == e {
            return false;
        }
    }
    i == t.len()
}

fn put_utf8(b: &mut Vec<u8>, mut c: u32) {
    if (0xD800..0xE000).contains(&c) {
        c = 0xFFFD;
    }
    if c < 0x80 {
        b.push(c as u8);
    } else if c < 0x800 {
        b.push((0xC0 | (c >> 6)) as u8);
        b.push((0x80 | (c & 63)) as u8);
    } else if c < 0x10000 {
        b.push((0xE0 | (c >> 12)) as u8);
        b.push((0x80 | ((c >> 6) & 63)) as u8);
        b.push((0x80 | (c & 63)) as u8);
    } else {
        b.push((0xF0 | (c >> 18)) as u8);
        b.push((0x80 | ((c >> 12) & 63)) as u8);
        b.push((0x80 | ((c >> 6) & 63)) as u8);
        b.push((0x80 | (c & 63)) as u8);
    }
}

/// `jparse` over file bytes. Like `slurp` + `jparse` in C, the document ends at the first NUL.
pub fn parse(src: &[u8]) -> Option<J> {
    let s = nul_cut(src);
    let mut p = P {
        s,
        i: 0,
        depth: 0,
        err: false,
    };
    let j = p.value()?;
    p.ws();
    if p.i < s.len() {
        None
    } else {
        Some(j)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_matches_c_layout() {
        let src =
            b"{\"a\":1,\"b\":[],\"c\":{},\"d\":[\"x\",{\"e\":null}],\"f\":\"q\\u007f\\u0001\\\"\"}";
        let j = parse(src).unwrap();
        let out = String::from_utf8(j.dump()).unwrap();
        assert_eq!(
            out,
            "{\n  \"a\": 1,\n  \"b\": [],\n  \"c\": {},\n  \"d\": [\n    \"x\",\n    {\n      \"e\": null\n    }\n  ],\n  \"f\": \"q\\u007f\\u0001\\\"\"\n}\n"
        );
    }

    #[test]
    fn numbers_and_errors() {
        assert!(parse(b"1.5e3").is_some());
        assert!(parse(b"1e").is_none());
        assert!(parse(b"-").is_none());
        assert!(parse(b"{broken").is_none());
        assert!(parse(b"{} x").is_none());
        assert_eq!(atol(b"1.5e3"), 1);
        assert_eq!(atol(b"-42"), -42);
    }

    #[test]
    fn duplicate_key_overwrites_in_place() {
        let j = parse(b"{\"a\":1,\"b\":2,\"a\":3}").unwrap();
        assert_eq!(j.dump(), b"{\n  \"a\": 3,\n  \"b\": 2\n}\n".to_vec());
    }
}
