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
    let _ = (message, Sha256::new());
    unimplemented!("J3 skeleton")
}

/// The Ed25519 record for (key, signature, message), verdict from `ed25519-dalek`.
pub fn ed25519_vector(public_key: [u8; 32], signature: [u8; 64], message: &[u8]) -> Vector {
    let _ = (public_key, signature, message);
    let _ = |k: VerifyingKey, m: &[u8], s: &Signature| k.verify(m, s);
    unimplemented!("J3 skeleton")
}

/// The fixed list of cases, every answer computed by the Rust crates.
pub fn rust_corpus() -> Vec<Vector> {
    Vec::new()
}

pub fn encode(vectors: &[Vector]) -> Vec<u8> {
    let _ = vectors;
    Vec::new()
}

pub fn decode(bytes: &[u8]) -> Result<Vec<Vector>, CorpusError> {
    let _ = bytes;
    Ok(Vec::new())
}

/// Recompute every record with the Rust crates; the first difference is returned.
pub fn check_against_rust_crates(vectors: &[Vector]) -> Result<(), Mismatch> {
    let _ = vectors;
    Ok(())
}

#[cfg(test)]
mod tests;
