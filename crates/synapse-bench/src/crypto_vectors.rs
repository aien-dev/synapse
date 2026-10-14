//! Digest and signature test vectors for the Omega port: ADR 0003 section 9 step J3.
//!
//! The Rust crates are the specification-by-test for the Omega port (ADR 0003
//! section 5.12). This module fixes what "match the Rust crates exactly" means for
//! the two primitives J3 ports:
//!
//! - SHA-256: the digest the `sha2` crate gives for each message.
//! - Ed25519 verification: the three decisions `ed25519-dalek` makes for each
//!   (public key, signature, message): whether the key decodes
//!   (`VerifyingKey::from_bytes`), whether `Verifier::verify` accepts (used by
//!   `synapse-core`, `synapse-auth`, `synapse-radicle`), and whether `verify_strict`
//!   accepts (used by `synapse-evidence`). The two verification calls disagree on
//!   some inputs (small-order keys), so a port must reproduce both.
//!
//! The corpus is a language-neutral binary file (ADR 0003 P5: fixed width, little
//! endian, length prefixed), written by [`encode`] and read by [`decode`]:
//!
//! ```text
//! header   magic "SYNJ3VEC" (8) | version u16 = 1 | reserved u16 = 0 | count u32
//! record   kind u8 = 1 (SHA-256)  | len u32 | message[len] | digest[32]
//!          kind u8 = 2 (Ed25519)  | verdict u8 | public_key[32] | signature[64]
//!                                 | len u32 | message[len]
//!          verdict bits: 0 key decodes, 1 verify accepts, 2 verify_strict accepts;
//!          bits 3 to 7 are zero
//! trailer  SHA-256 of every preceding byte (32)
//! ```
//!
//! A message longer than [`MAX_MESSAGE_BYTES`] is refused before anything is
//! allocated for it.

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use sha2::{Digest, Sha256};
use std::fmt;

pub const CORPUS_MAGIC: [u8; 8] = *b"SYNJ3VEC";
pub const CORPUS_VERSION: u16 = 1;
/// Largest message a corpus record may declare.
pub const MAX_MESSAGE_BYTES: u32 = 1 << 20;
/// The sealed corpus, relative to the repository root.
pub const CORPUS_PATH: &str = "evidence/j3-crypto-vectors/vectors.bin";
/// SHA-256 of the sealed corpus, so the seal is checked by a test, not by hand.
pub const CORPUS_SHA256: &str = "";

pub const KIND_SHA256: u8 = 1;
pub const KIND_ED25519: u8 = 2;
/// Message of the small-order key case.
pub const SMALL_ORDER_MESSAGE: &[u8] = b"synapse j3 small-order key";

/// The decisions `ed25519-dalek` makes for one (key, signature, message).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ed25519Verdict {
    pub key_decodes: bool,
    pub verify: bool,
    pub verify_strict: bool,
}

/// One corpus record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Vector {
    Sha256 {
        message: Vec<u8>,
        digest: [u8; 32],
    },
    Ed25519 {
        public_key: [u8; 32],
        signature: [u8; 64],
        message: Vec<u8>,
        verdict: Ed25519Verdict,
    },
}

/// Why a corpus file was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CorpusError {
    BadMagic,
    UnsupportedVersion(u16),
    ReservedHeaderBits(u16),
    Truncated { at: usize },
    UnknownKind { at: usize, kind: u8 },
    ReservedVerdictBits { at: usize, verdict: u8 },
    MessageTooLong { at: usize, len: u32 },
    TrailingBytes { at: usize },
    ChecksumMismatch,
}

impl fmt::Display for CorpusError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

/// A corpus record whose recorded answer differs from the Rust crates.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Mismatch {
    pub index: usize,
    pub detail: String,
}
/// The SHA-256 record for `message`, digest from the `sha2` crate.
pub fn sha256_vector(message: &[u8]) -> Vector {
    Vector::Sha256 {
        message: message.to_vec(),
        digest: Sha256::digest(message).into(),
    }
}

/// The decisions `ed25519-dalek` makes for (key, signature, message).
pub fn ed25519_verdict(
    public_key: &[u8; 32],
    signature: &[u8; 64],
    message: &[u8],
) -> Ed25519Verdict {
    let sig = Signature::from_bytes(signature);
    match VerifyingKey::from_bytes(public_key) {
        Err(_) => Ed25519Verdict {
            key_decodes: false,
            verify: false,
            verify_strict: false,
        },
        Ok(key) => Ed25519Verdict {
            key_decodes: true,
            verify: key.verify(message, &sig).is_ok(),
            verify_strict: key.verify_strict(message, &sig).is_ok(),
        },
    }
}

/// The Ed25519 record for (key, signature, message), verdict from `ed25519-dalek`.
pub fn ed25519_vector(public_key: [u8; 32], signature: [u8; 64], message: &[u8]) -> Vector {
    Vector::Ed25519 {
        verdict: ed25519_verdict(&public_key, &signature, message),
        public_key,
        signature,
        message: message.to_vec(),
    }
}

/// Deterministic message of `len` bytes.
fn pattern(len: usize, salt: u8) -> Vec<u8> {
    (0..len)
        .map(|j| (j as u8).wrapping_mul(31).wrapping_add(salt) ^ (j >> 8) as u8)
        .collect()
}

fn unhex<const N: usize>(s: &str) -> [u8; N] {
    let v = hex::decode(s).expect("fixed hex literal");
    v.try_into().expect("fixed hex literal length")
}

/// RFC 8032 section 7.1 TEST 1 to TEST 3: (public key, message, signature).
const RFC8032: [(&str, &str, &str); 3] = [
    (
        "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
        "",
        "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
    ),
    (
        "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
        "72",
        "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00",
    ),
    (
        "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
        "af82",
        "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a",
    ),
];

/// L, the order of the Ed25519 base point (RFC 8032 section 5.1), little endian.
const ED25519_L: &str = "edd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010";

/// `signature` with L added to its S half: the same point equation, non-canonical S.
fn with_s_plus_l(signature: [u8; 64]) -> [u8; 64] {
    let l: [u8; 32] = unhex(ED25519_L);
    let mut out = signature;
    let mut carry = 0u16;
    for i in 0..32 {
        let t = signature[32 + i] as u16 + l[i] as u16 + carry;
        out[32 + i] = t as u8;
        carry = t >> 8;
    }
    out
}

/// The fixed list of cases, every answer computed by the Rust crates.
pub fn rust_corpus() -> Vec<Vector> {
    let mut c = Vec::new();

    // SHA-256: FIPS 180-4 examples, every length from 1 to 257 bytes (across the
    // 55/56 padding split and the 64-byte block edges), larger sizes including the
    // Gate 4 change (11,949 bytes) and the A0 probe block (16 KiB), and constant
    // all-zero and all-one messages.
    for m in [
        &b""[..],
        b"abc",
        b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
        b"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
    ] {
        c.push(sha256_vector(m));
    }
    for len in 1..=257 {
        c.push(sha256_vector(&pattern(len, 7)));
    }
    for len in [1000, 4096, 11_949, 16_384, 65_536] {
        c.push(sha256_vector(&pattern(len, 11)));
    }
    for byte in [0x00, 0xff] {
        for len in [64, 1024] {
            c.push(sha256_vector(&vec![byte; len]));
        }
    }

    // Ed25519: the RFC 8032 vectors.
    for (pk, msg, sig) in RFC8032 {
        let msg = hex::decode(msg).expect("fixed hex literal");
        c.push(ed25519_vector(unhex(pk), unhex(sig), &msg));
    }
    // Signatures by deterministic keys over messages of several sizes.
    for (i, len) in [0usize, 1, 63, 64, 65, 256, 1024, 11_949]
        .into_iter()
        .enumerate()
    {
        let mut seed = [0u8; 32];
        seed[0] = 0x4a;
        seed[1] = i as u8;
        let key = ed25519_dalek::SigningKey::from_bytes(&seed);
        let msg = pattern(len, i as u8);
        let sig = ed25519_dalek::Signer::sign(&key, &msg).to_bytes();
        c.push(ed25519_vector(key.verifying_key().to_bytes(), sig, &msg));
    }
    // Refusals and edge cases around RFC 8032 TEST 1.
    let pk1: [u8; 32] = unhex(RFC8032[0].0);
    let sig1: [u8; 64] = unhex(RFC8032[0].2);
    let pk2: [u8; 32] = unhex(RFC8032[1].0);
    let flip = |i: usize, bit: u8| {
        let mut s = sig1;
        s[i] ^= bit;
        s
    };
    c.push(ed25519_vector(pk1, sig1, b"\x01")); // changed message
    c.push(ed25519_vector(pk1, flip(0, 1), b"")); // changed R
    c.push(ed25519_vector(pk1, flip(32, 1), b"")); // changed S
    c.push(ed25519_vector(pk1, flip(63, 0x80), b"")); // high bit of S set
    c.push(ed25519_vector(pk1, with_s_plus_l(sig1), b"")); // S + L
    c.push(ed25519_vector(pk2, sig1, b"")); // another key
                                            // Small-order keys with R = identity and S = 0: the identity, and the point of
                                            // order 2 (y = -1). `verify` and `verify_strict` disagree here.
    let mut identity = [0u8; 32];
    identity[0] = 1;
    let mut small_sig = [0u8; 64];
    small_sig[..32].copy_from_slice(&identity);
    c.push(ed25519_vector(identity, small_sig, SMALL_ORDER_MESSAGE));
    let order2: [u8; 32] =
        unhex("ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f");
    c.push(ed25519_vector(order2, small_sig, SMALL_ORDER_MESSAGE));
    // Non-canonical encoding of the identity (y = p + 1).
    let noncanonical: [u8; 32] =
        unhex("eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f");
    c.push(ed25519_vector(noncanonical, small_sig, SMALL_ORDER_MESSAGE));
    // The first key of the form [k, 0, ..., 0] that does not decode to a point.
    if let Some(bad) = (2u8..=255)
        .map(|k| {
            let mut b = [0u8; 32];
            b[0] = k;
            b
        })
        .find(|b| VerifyingKey::from_bytes(b).is_err())
    {
        c.push(ed25519_vector(bad, sig1, b""));
    }
    c
}

/// Named Ed25519 cases that separate implementations which agree on ordinary
/// signatures (see the tests for the wrong implementation each one catches).
pub fn ed25519_edge_cases() -> Vec<(&'static str, Vector)> {
    Vec::new()
}

const HEADER_BYTES: usize = 16;
const TRAILER_BYTES: usize = 32;

pub fn encode(vectors: &[Vector]) -> Vec<u8> {
    let mut b = Vec::new();
    b.extend_from_slice(&CORPUS_MAGIC);
    b.extend_from_slice(&CORPUS_VERSION.to_le_bytes());
    b.extend_from_slice(&0u16.to_le_bytes());
    b.extend_from_slice(&(vectors.len() as u32).to_le_bytes());
    for v in vectors {
        match v {
            Vector::Sha256 { message, digest } => {
                b.push(KIND_SHA256);
                b.extend_from_slice(&(message.len() as u32).to_le_bytes());
                b.extend_from_slice(message);
                b.extend_from_slice(digest);
            }
            Vector::Ed25519 {
                public_key,
                signature,
                message,
                verdict,
            } => {
                b.push(KIND_ED25519);
                b.push(
                    verdict.key_decodes as u8
                        | (verdict.verify as u8) << 1
                        | (verdict.verify_strict as u8) << 2,
                );
                b.extend_from_slice(public_key);
                b.extend_from_slice(signature);
                b.extend_from_slice(&(message.len() as u32).to_le_bytes());
                b.extend_from_slice(message);
            }
        }
    }
    let sum: [u8; 32] = Sha256::digest(&b).into();
    b.extend_from_slice(&sum);
    b
}

/// Bounds-checked reader over the record area.
struct Reader<'a> {
    b: &'a [u8],
    at: usize,
}

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], CorpusError> {
        let end = self
            .at
            .checked_add(n)
            .filter(|&e| e <= self.b.len())
            .ok_or(CorpusError::Truncated { at: self.at })?;
        let s = &self.b[self.at..end];
        self.at = end;
        Ok(s)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], CorpusError> {
        let mut out = [0u8; N];
        out.copy_from_slice(self.take(N)?);
        Ok(out)
    }

    fn message(&mut self) -> Result<Vec<u8>, CorpusError> {
        let at = self.at;
        let len = u32::from_le_bytes(self.array()?);
        if len > MAX_MESSAGE_BYTES {
            return Err(CorpusError::MessageTooLong { at, len });
        }
        Ok(self.take(len as usize)?.to_vec())
    }
}

pub fn decode(bytes: &[u8]) -> Result<Vec<Vector>, CorpusError> {
    if bytes.len() < HEADER_BYTES + TRAILER_BYTES {
        return Err(CorpusError::Truncated { at: bytes.len() });
    }
    if bytes[..8] != CORPUS_MAGIC {
        return Err(CorpusError::BadMagic);
    }
    let version = u16::from_le_bytes([bytes[8], bytes[9]]);
    if version != CORPUS_VERSION {
        return Err(CorpusError::UnsupportedVersion(version));
    }
    let reserved = u16::from_le_bytes([bytes[10], bytes[11]]);
    if reserved != 0 {
        return Err(CorpusError::ReservedHeaderBits(reserved));
    }
    let body = &bytes[..bytes.len() - TRAILER_BYTES];
    if Sha256::digest(body)[..] != bytes[body.len()..] {
        return Err(CorpusError::ChecksumMismatch);
    }
    let count = u32::from_le_bytes([bytes[12], bytes[13], bytes[14], bytes[15]]);
    let mut r = Reader {
        b: body,
        at: HEADER_BYTES,
    };
    let mut out = Vec::new();
    for _ in 0..count {
        let at = r.at;
        let kind = r.array::<1>()?[0];
        out.push(match kind {
            KIND_SHA256 => {
                let message = r.message()?;
                Vector::Sha256 {
                    message,
                    digest: r.array()?,
                }
            }
            KIND_ED25519 => {
                let verdict_at = r.at;
                let v = r.array::<1>()?[0];
                if v & !0b111 != 0 {
                    return Err(CorpusError::ReservedVerdictBits {
                        at: verdict_at,
                        verdict: v,
                    });
                }
                Vector::Ed25519 {
                    verdict: Ed25519Verdict {
                        key_decodes: v & 1 != 0,
                        verify: v & 2 != 0,
                        verify_strict: v & 4 != 0,
                    },
                    public_key: r.array()?,
                    signature: r.array()?,
                    message: r.message()?,
                }
            }
            kind => return Err(CorpusError::UnknownKind { at, kind }),
        });
    }
    if r.at != body.len() {
        return Err(CorpusError::TrailingBytes { at: r.at });
    }
    Ok(out)
}

/// Recompute every record with the Rust crates; the first difference is returned.
pub fn check_against_rust_crates(vectors: &[Vector]) -> Result<(), Mismatch> {
    for (index, v) in vectors.iter().enumerate() {
        let again = match v {
            Vector::Sha256 { message, .. } => sha256_vector(message),
            Vector::Ed25519 {
                public_key,
                signature,
                message,
                ..
            } => ed25519_vector(*public_key, *signature, message),
        };
        if &again != v {
            return Err(Mismatch {
                index,
                detail: format!("recorded {v:?}, Rust crates give {again:?}"),
            });
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests;
