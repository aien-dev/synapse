//! Secret scanning at admission (ADR 0003 section 5.13, step M1).
//!
//! Every blob an agent submits is scanned before the store sees it, so a refused secret never
//! reaches the WAL, the content store, an index, or a cache. A hit refuses the whole admission
//! with [`RefusalCode::SecretDetected`]. The refusal names the blob digest, the rule, the rule
//! set version, and the byte offset; it never contains the matched bytes, and this module keeps
//! no copy of them.
//!
//! The scanner is a hand-written single pass over raw bytes (binary safe, no UTF-8
//! assumption, no regular expressions). Each position does a bounded amount of work, and the
//! windows that longer checks walk cannot overlap without bound, so time is linear in the input
//! length and memory is constant. The rule set is versioned data ([`SECRET_RULESET_VERSION`]).
//!
//! Policy (refuse by default): there is no allowlist and no override. Clearly fake
//! documentation values (`EXAMPLE`, `fake`, `your`, `xxxxxxxx`, very low character variety) are not
//! secrets and are admitted.

use synapse_core::{BlobDigest, RefusalCode, SynapseError, SynapseResult};

/// Version of the rule set below. Bump it whenever a rule is added, removed, or changed.
pub const SECRET_RULESET_VERSION: u16 = 1;

/// One rule of the secret-scanning rule set.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SecretRule {
    /// A PEM or OpenSSH private key block (`BEGIN ... PRIVATE KEY`) with a key body.
    PrivateKeyBlock,
    /// An AWS access key id (`AKIA` or `ASIA` plus 16 characters).
    AwsAccessKeyId,
    /// A GitHub classic token (`ghp_`, `gho_`, `ghu_`, `ghs_`, `ghr_`).
    GithubToken,
    /// A GitHub fine-grained personal access token (`github_pat_`).
    GithubFineGrainedToken,
    /// A Slack token (`xoxb-`, `xoxp-`, ...).
    SlackToken,
    /// A Slack incoming webhook URL.
    SlackWebhook,
    /// A Stripe live secret or restricted key.
    StripeLiveKey,
    /// An Anthropic API key (`sk-ant-`).
    AnthropicKey,
    /// An OpenAI API key (project, service account, admin, or legacy format).
    OpenAiKey,
    /// A high-entropy value assigned to a secret-like name (`token = "..."`).
    SecretAssignment,
}

impl SecretRule {
    /// Stable identifier of the rule, used in refusal text.
    pub fn id(self) -> &'static str {
        match self {
            SecretRule::PrivateKeyBlock => "private-key-block",
            SecretRule::AwsAccessKeyId => "aws-access-key-id",
            SecretRule::GithubToken => "github-token",
            SecretRule::GithubFineGrainedToken => "github-fine-grained-token",
            SecretRule::SlackToken => "slack-token",
            SecretRule::SlackWebhook => "slack-webhook",
            SecretRule::StripeLiveKey => "stripe-live-key",
            SecretRule::AnthropicKey => "anthropic-key",
            SecretRule::OpenAiKey => "openai-key",
            SecretRule::SecretAssignment => "secret-assignment",
        }
    }
}

/// Where a rule matched. Carries no matched bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SecretFinding {
    pub rule: SecretRule,
    /// Byte offset of the start of the match inside the scanned input.
    pub offset: usize,
}

/// Scan `bytes` and return the first finding, if any.
pub fn scan(bytes: &[u8]) -> Option<SecretFinding> {
    Scanner::new(bytes).scan_all()
}

/// Scan and also return the number of byte inspections made, for the linear-time bound tests.
#[doc(hidden)]
pub fn scan_with_steps(bytes: &[u8]) -> (Option<SecretFinding>, u64) {
    let mut s = Scanner::new(bytes);
    let found = s.scan_all();
    (found, s.steps)
}

/// Refuse the admission if any blob matches a rule. The error never contains blob bytes.
pub fn check_blobs(blobs: &[(BlobDigest, Vec<u8>)]) -> SynapseResult<()> {
    for (digest, bytes) in blobs {
        if let Some(f) = scan(bytes) {
            return Err(refusal(*digest, f));
        }
    }
    Ok(())
}

fn refusal(digest: BlobDigest, f: SecretFinding) -> SynapseError {
    SynapseError::new(
        RefusalCode::SecretDetected,
        format!(
            "blob {digest} refused: matched secret rule {} (rule set v{}) at byte offset {}",
            f.rule.id(),
            SECRET_RULESET_VERSION,
            f.offset
        ),
    )
}

// Bounds on every window a rule walks. Each is a constant, so the work per position is bounded.
const PEM_LABEL_MAX: usize = 48;
const PEM_BODY_WINDOW: usize = 512;
const PEM_BODY_MIN: usize = 64;
const TOKEN_MAX: usize = 255;
const IDENT_MAX: usize = 64;
const SPACE_MAX: usize = 4;
const VALUE_MIN: usize = 20;
const VALUE_MAX: usize = 128;

const SECRET_NAMES: &[&[u8]] = &[
    b"secret",
    b"token",
    b"password",
    b"passwd",
    b"passphrase",
    b"pwd",
    b"apikey",
    b"api_key",
    b"api-key",
    b"accesskey",
    b"access_key",
    b"access-key",
    b"privatekey",
    b"private_key",
    b"private-key",
    b"credential",
    b"authkey",
    b"auth_key",
];

const FAKE_MARKERS: &[&[u8]] = &[
    b"example",
    b"fake",
    b"dummy",
    b"placeholder",
    b"redacted",
    b"changeme",
    b"your",
    b"xxxxxxxx",
];

fn is_tok(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_' || b == b'-'
}
fn is_upper_digit(b: u8) -> bool {
    b.is_ascii_uppercase() || b.is_ascii_digit()
}
fn is_alnum_us(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}
fn is_alnum_dash(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'-'
}
fn is_b64(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'+' || b == b'/' || b == b'='
}
fn is_ident(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_' || b == b'-' || b == b'.'
}
fn is_value(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'_' | b'-' | b'.')
}
fn is_space(b: u8) -> bool {
    b == b' ' || b == b'\t'
}
fn is_quote(b: u8) -> bool {
    b == b'"' || b == b'\'' || b == b'`'
}

fn contains_ci(hay: &[u8], needle: &[u8]) -> bool {
    hay.len() >= needle.len()
        && hay
            .windows(needle.len())
            .any(|w| w.eq_ignore_ascii_case(needle))
}

fn distinct_bytes(s: &[u8]) -> usize {
    let mut seen = [false; 256];
    let mut n = 0;
    for &b in s {
        if !seen[b as usize] {
            seen[b as usize] = true;
            n += 1;
        }
    }
    n
}

/// A clearly fake documentation value: a fake marker or too little character variety.
fn looks_fake(body: &[u8]) -> bool {
    distinct_bytes(body) < 8 || FAKE_MARKERS.iter().any(|m| contains_ci(body, m))
}

/// Shannon entropy in bits per byte.
fn entropy(s: &[u8]) -> f64 {
    let mut counts = [0u32; 256];
    for &b in s {
        counts[b as usize] += 1;
    }
    let n = s.len() as f64;
    counts
        .iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = f64::from(c) / n;
            -p * p.log2()
        })
        .sum()
}

struct Scanner<'a> {
    b: &'a [u8],
    steps: u64,
}

impl<'a> Scanner<'a> {
    fn new(b: &'a [u8]) -> Self {
        Self { b, steps: 0 }
    }

    fn at(&self, i: usize) -> Option<u8> {
        self.b.get(i).copied()
    }

    fn lit(&mut self, i: usize, lit: &[u8]) -> bool {
        self.steps += lit.len() as u64;
        self.b.get(i..i + lit.len()) == Some(lit)
    }

    /// Length of the run of `pred` bytes from `i`, counting at most `cap + 1` bytes so callers
    /// can tell a run longer than `cap`.
    fn run(&mut self, i: usize, pred: fn(u8) -> bool, cap: usize) -> usize {
        let end = self.b.len().min(i.saturating_add(cap + 1));
        let n = self
            .b
            .get(i..end)
            .map_or(0, |w| w.iter().position(|&c| !pred(c)).unwrap_or(w.len()));
        self.steps += n as u64 + 1;
        n
    }

    fn left_boundary(&self, i: usize) -> bool {
        i == 0 || !is_tok(self.b[i - 1])
    }

    fn scan_all(&mut self) -> Option<SecretFinding> {
        for i in 0..self.b.len() {
            self.steps += 1;
            let rule = match self.b[i] {
                b'-' => self.pem(i),
                b'A' => self.aws(i),
                b'g' => self.github(i),
                b'x' => self.slack(i),
                b'h' => self.slack_webhook(i),
                b's' | b'r' => self.sk(i),
                b'=' | b':' => self.assignment(i),
                _ => None,
            };
            if let Some(rule) = rule {
                return Some(SecretFinding { rule, offset: i });
            }
        }
        None
    }

    fn pem(&mut self, i: usize) -> Option<SecretRule> {
        if !self.lit(i, b"-----BEGIN ") {
            return None;
        }
        let label_start = i + 11;
        let label_len = self.run(
            label_start,
            |c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == b' ',
            PEM_LABEL_MAX,
        );
        if label_len > PEM_LABEL_MAX {
            return None;
        }
        let label = &self.b[label_start..label_start + label_len];
        if !(label.ends_with(b"PRIVATE KEY") || label == b"PGP PRIVATE KEY BLOCK") {
            return None;
        }
        let body_start = label_start + label_len;
        if !self.lit(body_start, b"-----") {
            return None;
        }
        let start = body_start + 5;
        let end = self.b.len().min(start + PEM_BODY_WINDOW);
        let window = &self.b[start..end];
        self.steps += window.len() as u64;
        let mut b64 = 0usize;
        let mut other = 0usize;
        for &c in window {
            match c {
                b'-' => break,
                b'\r' | b'\n' | b' ' | b'\t' => {}
                c if is_b64(c) => b64 += 1,
                _ => other += 1,
            }
        }
        let body_ok = b64 >= PEM_BODY_MIN && other * 4 <= b64;
        body_ok.then_some(SecretRule::PrivateKeyBlock)
    }

    fn aws(&mut self, i: usize) -> Option<SecretRule> {
        if !self.left_boundary(i) || !(self.lit(i, b"AKIA") || self.lit(i, b"ASIA")) {
            return None;
        }
        let n = self.run(i + 4, is_upper_digit, 16);
        if n != 16 || self.at(i + 20).is_some_and(|c| c.is_ascii_alphanumeric()) {
            return None;
        }
        let body = &self.b[i + 4..i + 20];
        (!looks_fake(body)).then_some(SecretRule::AwsAccessKeyId)
    }

    fn github(&mut self, i: usize) -> Option<SecretRule> {
        if !self.left_boundary(i) {
            return None;
        }
        if self.lit(i, b"github_pat_") {
            let n = self.run(i + 11, is_alnum_us, TOKEN_MAX);
            let body = &self.b[i + 11..i + 11 + n.min(TOKEN_MAX)];
            return ((80..=TOKEN_MAX).contains(&n) && !looks_fake(body))
                .then_some(SecretRule::GithubFineGrainedToken);
        }
        let prefix_ok = self.lit(i, b"gh")
            && matches!(self.at(i + 2), Some(b'p' | b'o' | b'u' | b's' | b'r'))
            && self.at(i + 3) == Some(b'_');
        if !prefix_ok {
            return None;
        }
        let n = self.run(i + 4, |c| c.is_ascii_alphanumeric(), 36);
        if n != 36 || self.at(i + 40).is_some_and(is_tok) {
            return None;
        }
        (!looks_fake(&self.b[i + 4..i + 40])).then_some(SecretRule::GithubToken)
    }

    fn slack(&mut self, i: usize) -> Option<SecretRule> {
        let prefix_ok = self.left_boundary(i)
            && self.lit(i, b"xox")
            && matches!(
                self.at(i + 3),
                Some(b'b' | b'p' | b'a' | b'r' | b's' | b'o')
            )
            && self.at(i + 4) == Some(b'-');
        if !prefix_ok {
            return None;
        }
        let n = self.run(i + 5, is_alnum_dash, TOKEN_MAX);
        if !(20..=TOKEN_MAX).contains(&n) {
            return None;
        }
        let body = &self.b[i + 5..i + 5 + n];
        let dashes = body.iter().filter(|&&c| c == b'-').count();
        let digits = body.iter().filter(|c| c.is_ascii_digit()).count();
        (dashes >= 2 && digits >= 10 && !looks_fake(body)).then_some(SecretRule::SlackToken)
    }

    fn slack_webhook(&mut self, i: usize) -> Option<SecretRule> {
        const PREFIX: &[u8] = b"hooks.slack.com/services/";
        if !self.lit(i, PREFIX) {
            return None;
        }
        let start = i + PREFIX.len();
        let n = self.run(start, |c| c.is_ascii_alphanumeric() || c == b'/', TOKEN_MAX);
        if !(40..=TOKEN_MAX).contains(&n) {
            return None;
        }
        let body = &self.b[start..start + n];
        let slashes = body.iter().filter(|&&c| c == b'/').count();
        (slashes >= 2 && !looks_fake(body)).then_some(SecretRule::SlackWebhook)
    }

    fn sk(&mut self, i: usize) -> Option<SecretRule> {
        if !self.left_boundary(i) {
            return None;
        }
        if self.lit(i, b"sk_live_") || self.lit(i, b"rk_live_") {
            let n = self.run(i + 8, |c| c.is_ascii_alphanumeric(), TOKEN_MAX);
            let body = &self.b[i + 8..i + 8 + n.min(TOKEN_MAX)];
            return ((24..=TOKEN_MAX).contains(&n) && !looks_fake(body))
                .then_some(SecretRule::StripeLiveKey);
        }
        if !self.lit(i, b"sk-") {
            return None;
        }
        let (rule, start, min) = if self.lit(i, b"sk-ant-") {
            (SecretRule::AnthropicKey, i + 7, 32)
        } else if self.lit(i, b"sk-proj-") || self.lit(i, b"sk-admin-") {
            let len = if self.at(i + 3) == Some(b'p') { 8 } else { 9 };
            (SecretRule::OpenAiKey, i + len, 40)
        } else if self.lit(i, b"sk-svcacct-") {
            (SecretRule::OpenAiKey, i + 11, 40)
        } else {
            // Legacy OpenAI key: 48 alphanumerics with the base64 "OpenAI" marker inside.
            let n = self.run(i + 3, |c| c.is_ascii_alphanumeric(), 48);
            if n != 48 || self.at(i + 51).is_some_and(is_tok) {
                return None;
            }
            let body = &self.b[i + 3..i + 51];
            return body
                .windows(8)
                .any(|w| w == b"T3BlbkFJ")
                .then_some(SecretRule::OpenAiKey);
        };
        let n = self.run(start, is_tok, TOKEN_MAX);
        let body = &self.b[start..start + n.min(TOKEN_MAX)];
        ((min..=TOKEN_MAX).contains(&n) && !looks_fake(body)).then_some(rule)
    }

    /// `name = value`, `name: value`, `name := value`, `name => value`, with the name holding
    /// a secret-like word and the value a high-entropy literal.
    fn assignment(&mut self, i: usize) -> Option<SecretRule> {
        let op = self.b[i];
        let prev = if i > 0 { Some(self.b[i - 1]) } else { None };
        let next = self.at(i + 1);
        self.steps += 2;
        let mut name_end = i;
        let mut value_from = i + 1;
        if op == b':' {
            // `:=` is handled at the `=`; `::` is a path separator.
            if matches!(next, Some(b'=' | b':')) || prev == Some(b':') {
                return None;
            }
        } else {
            if next == Some(b'=')
                || matches!(
                    prev,
                    Some(
                        b'=' | b'!'
                            | b'<'
                            | b'>'
                            | b'+'
                            | b'-'
                            | b'*'
                            | b'/'
                            | b'|'
                            | b'&'
                            | b'^'
                            | b'%'
                    )
                )
            {
                return None;
            }
            if prev == Some(b':') {
                name_end = i - 1;
            }
            if next == Some(b'>') {
                value_from = i + 2;
            }
        }

        // Name, walking back over a few spaces and one closing quote.
        let mut j = name_end;
        let mut k = 0;
        while k < SPACE_MAX && j > 0 && is_space(self.b[j - 1]) {
            j -= 1;
            k += 1;
        }
        if j > 0 && is_quote(self.b[j - 1]) {
            j -= 1;
        }
        let mut name_len = 0;
        while name_len < IDENT_MAX && j > name_len && is_ident(self.b[j - 1 - name_len]) {
            name_len += 1;
        }
        self.steps += (k + name_len + 1) as u64;
        if name_len == 0 {
            return None;
        }
        let name = &self.b[j - name_len..j];
        if !SECRET_NAMES.iter().any(|w| contains_ci(name, w)) {
            return None;
        }

        // Value, after a few spaces and an optional opening quote.
        let mut v = value_from + self.run(value_from, is_space, SPACE_MAX).min(SPACE_MAX);
        let quote = self.at(v).filter(|&c| is_quote(c));
        if quote.is_some() {
            v += 1;
        }
        let n = self.run(v, is_value, VALUE_MAX);
        if !(VALUE_MIN..=VALUE_MAX).contains(&n) {
            return None;
        }
        let value = &self.b[v..v + n];
        let mut after = v + n;
        let pad = self.run(after, |c| c == b'=', 2).min(2);
        after += pad;
        match quote {
            Some(q) if self.at(after) != Some(q) => return None,
            None if matches!(self.at(after), Some(b'(' | b'[' | b'{' | b'<')) => return None,
            _ => {}
        }
        self.steps += n as u64;
        let has_digit = value.iter().any(|c| c.is_ascii_digit());
        let has_alpha = value.iter().any(|c| c.is_ascii_alphabetic());
        if !has_digit || !has_alpha || looks_fake(value) {
            return None;
        }
        let h = entropy(value);
        let hex = value.iter().all(|c| c.is_ascii_hexdigit());
        let strong = if hex { n >= 32 && h >= 3.0 } else { h >= 3.5 };
        strong.then_some(SecretRule::SecretAssignment)
    }
}
