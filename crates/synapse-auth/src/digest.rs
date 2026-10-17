//! Request payload digest (issue #92).
//!
//! `payload_sha256` is defined as SHA-256 over the payload's compact `serde_json` encoding, and
//! `payload_bytes_len` is at least that encoding's length. The agent signs both through
//! `AuthenticatedRequest::canonical_signable_bytes`, so the definition is part of the protocol
//! and does not change here. What changes is only how the bytes reach the hash: the serializer
//! writes them through a small fixed staging buffer straight into SHA-256 instead of first
//! collecting the whole JSON text in one growing `Vec` (`serde_json::to_vec`) and hashing that.
//!
//! Equivalence with `SHA-256(serde_json::to_vec(payload))`:
//! * `serde_json::to_vec(v)` is `v.serialize(&mut Serializer::new(Vec::with_capacity(128)))`,
//!   and `Serializer::new` is `Serializer::with_formatter(_, CompactFormatter)`, where
//!   `CompactFormatter` overrides nothing (`impl Formatter for CompactFormatter {}`): every
//!   byte comes from the `Formatter` trait's default methods.
//! * [`DigestFormatter`] also takes every default method except `write_u8`, which it answers
//!   from a table instead of `itoa`. The table's 256 entries are checked against
//!   `serde_json::to_vec(&v)` for every `u8` value in the unit tests below.
//! * The serializer drives the formatter the same way whatever the writer is, so the byte
//!   sequence is identical; the writer only decides where the bytes go. SHA-256 depends only
//!   on that sequence, not on how it is split across `update` calls, and the counted length is
//!   the number of bytes written. Writes never fail, so a serialization error comes only from
//!   the payload's `Serialize` impl, the same error with the same message as before.
//!
//! The parity tests in `crates/synapse-api/tests/payload_digest_parity.rs` check the result
//! against the old computation over the A1 malformed corpus and recorded requests.

use serde::Serialize;
use serde_json::ser::Formatter;
use sha2::{Digest, Sha256};
use std::io;
use synapse_core::{RefusalCode, SynapseError, SynapseResult};

/// Size of the staging buffer between the JSON serializer and SHA-256.
pub(crate) const DIGEST_STAGING_BYTES: usize = 8 * 1024;

/// `io::Write` sink that hashes everything written to it and counts the bytes.
struct DigestWriter {
    staged: Vec<u8>,
    hasher: Sha256,
    hashed: u64,
}

impl DigestWriter {
    fn new() -> Self {
        Self {
            staged: Vec::with_capacity(DIGEST_STAGING_BYTES),
            hasher: Sha256::new(),
            hashed: 0,
        }
    }

    fn drain(&mut self) {
        self.hasher.update(&self.staged);
        self.hashed += self.staged.len() as u64;
        self.staged.clear();
    }

    /// The staging buffer cannot take `data`: hash what is staged, then stage `data`, or hash
    /// it directly when it is at least a buffer long.
    #[cold]
    #[inline(never)]
    fn spill(&mut self, data: &[u8]) {
        self.drain();
        if data.len() >= DIGEST_STAGING_BYTES {
            self.hasher.update(data);
            self.hashed += data.len() as u64;
        } else {
            self.staged.extend_from_slice(data);
        }
    }

    fn finish(mut self) -> ([u8; 32], u64) {
        self.drain();
        (self.hasher.finalize().into(), self.hashed)
    }
}

impl io::Write for DigestWriter {
    #[inline]
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        self.write_all(data)?;
        Ok(data.len())
    }

    #[inline(always)]
    fn write_all(&mut self, data: &[u8]) -> io::Result<()> {
        // The buffer never grows past its initial capacity: what does not fit spills.
        if self.staged.capacity() - self.staged.len() >= data.len() {
            self.staged.extend_from_slice(data);
        } else {
            self.spill(data);
        }
        Ok(())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// Decimal text of every `u8` (`[digits.., len]`), built at compile time.
const fn decimal_u8_table() -> [[u8; 4]; 256] {
    let mut table = [[0u8; 4]; 256];
    let mut i = 0;
    while i < 256 {
        let v = i as u8;
        table[i] = if v >= 100 {
            [b'0' + v / 100, b'0' + v / 10 % 10, b'0' + v % 10, 3]
        } else if v >= 10 {
            [b'0' + v / 10, b'0' + v % 10, 0, 2]
        } else {
            [b'0' + v, 0, 0, 1]
        };
        i += 1;
    }
    table
}

static DECIMAL_U8: [[u8; 4]; 256] = decimal_u8_table();

/// `CompactFormatter` with a table lookup for `u8` (blob bytes are `Vec<u8>`, one JSON number
/// per byte, so this is the hot path). Every other method is the trait default, exactly as in
/// `CompactFormatter`.
struct DigestFormatter;

impl Formatter for DigestFormatter {
    #[inline]
    fn write_u8<W>(&mut self, writer: &mut W, value: u8) -> io::Result<()>
    where
        W: ?Sized + io::Write,
    {
        let entry = &DECIMAL_U8[value as usize];
        writer.write_all(&entry[..entry[3] as usize])
    }
}

/// SHA-256 of `payload`'s compact `serde_json` encoding, and that encoding's length in bytes.
///
/// Byte-for-byte the same result as hashing `serde_json::to_vec(payload)` and taking its
/// length, without ever holding the encoding in memory. A serialization failure is refused with
/// `IoFailure` and the same message the old code used.
pub fn payload_digest<T: Serialize + ?Sized>(payload: &T) -> SynapseResult<([u8; 32], u64)> {
    let mut sink = DigestWriter::new();
    payload
        .serialize(&mut serde_json::Serializer::with_formatter(
            &mut sink,
            DigestFormatter,
        ))
        .map_err(|e| {
            SynapseError::new(RefusalCode::IoFailure, format!("serialize payload: {e}"))
        })?;
    Ok(sink.finish())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decimal_table_matches_serde_json_for_every_u8() {
        for v in 0..=u8::MAX {
            let entry = &DECIMAL_U8[v as usize];
            assert_eq!(
                &entry[..entry[3] as usize],
                serde_json::to_vec(&v).unwrap().as_slice(),
                "{v}"
            );
            // Also as a map key, where serde_json quotes the number.
            let key = std::collections::BTreeMap::from([(v, ())]);
            let mut out = Vec::new();
            key.serialize(&mut serde_json::Serializer::with_formatter(
                &mut out,
                DigestFormatter,
            ))
            .unwrap();
            assert_eq!(out, serde_json::to_vec(&key).unwrap(), "key {v}");
        }
    }

    #[test]
    fn every_write_size_around_the_staging_buffer_hashes_the_same_bytes() {
        use std::io::Write;
        // Byte strings written in pieces of every size from 1 to past two buffers.
        let data: Vec<u8> = (0..3 * DIGEST_STAGING_BYTES)
            .map(|i| (i * 31 % 251) as u8)
            .collect();
        for piece in [
            1,
            7,
            DIGEST_STAGING_BYTES - 1,
            DIGEST_STAGING_BYTES,
            DIGEST_STAGING_BYTES + 1,
            2 * DIGEST_STAGING_BYTES + 3,
        ] {
            let mut w = DigestWriter::new();
            for chunk in data.chunks(piece) {
                w.write_all(chunk).unwrap();
            }
            assert!(w.staged.capacity() <= DIGEST_STAGING_BYTES, "piece {piece}");
            let want: [u8; 32] = Sha256::digest(&data).into();
            assert_eq!(w.finish(), (want, data.len() as u64), "piece {piece}");
        }
    }
}
