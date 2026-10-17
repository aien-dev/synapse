//! Native RFC 1950 (zlib) and RFC 1951 (DEFLATE) decoder for reading Git objects (ADR 0003
//! step H1). Git stores every loose object and every packed entry as a zlib stream
//! (`gitformat-pack`: "compressed data"); a pack entry does not record its compressed length,
//! so [`zlib_decompress`] reports how many input bytes the stream used.
//!
//! The decoder is bounded: output never grows past the caller's `max_out`, every read is
//! checked against the input that remains, and every malformed stream is refused with
//! `RefusalCode::GitObjectCorrupt`. It never panics on any input.

use synapse_core::{RefusalCode, SynapseError, SynapseResult};

fn corrupt(msg: impl Into<String>) -> SynapseError {
    SynapseError::new(RefusalCode::GitObjectCorrupt, msg)
}

/// Decompress one zlib stream at the start of `input` into at most `max_out` bytes.
/// Returns the decompressed bytes and the number of input bytes the stream used (header,
/// DEFLATE blocks, and the Adler-32 trailer). Refuses preset dictionaries, a bad header
/// check, an Adler-32 mismatch, and output over `max_out`.
pub fn zlib_decompress(input: &[u8], max_out: usize) -> SynapseResult<(Vec<u8>, usize)> {
    if input.len() < 2 {
        return Err(corrupt("zlib stream shorter than its 2-byte header"));
    }
    let (cmf, flg) = (input[0], input[1]);
    if cmf & 0x0f != 8 || cmf >> 4 > 7 {
        return Err(corrupt(
            "zlib header is not DEFLATE with a window of at most 32 KiB",
        ));
    }
    if (u16::from(cmf) << 8 | u16::from(flg)) % 31 != 0 {
        return Err(corrupt("zlib header check bits are wrong"));
    }
    if flg & 0x20 != 0 {
        return Err(corrupt("zlib preset dictionary is not used by Git"));
    }
    let mut inf = Inflater {
        input,
        pos: 2,
        bit_buf: 0,
        bit_count: 0,
        out: Vec::new(),
        max_out,
        prefix: false,
    };
    inf.run()?;
    // Discard the bits left in the last partial byte, then read the big-endian Adler-32.
    let pos = inf.pos;
    let trailer = input
        .get(pos..pos + 4)
        .ok_or_else(|| corrupt("zlib stream truncated before its Adler-32 trailer"))?;
    let expected = u32::from_be_bytes([trailer[0], trailer[1], trailer[2], trailer[3]]);
    if crate::adler32(&inf.out) != expected {
        return Err(corrupt("zlib Adler-32 checksum mismatch"));
    }
    Ok((inf.out, pos + 4))
}

/// Internal marker: a prefix decode filled its `n` bytes.
const PREFIX_FULL: &str = "zlib prefix decode reached its length";

/// Decompress only the first `n` bytes of the zlib stream at the start of `input` (fewer if the
/// stream ends sooner). Used to read a declared size (a loose object header, a delta's result
/// size) before anything is allocated for the whole object. The stream is not checked past
/// those bytes and the Adler-32 trailer is not read; a later full decode checks both.
pub fn zlib_inflate_prefix(input: &[u8], n: usize) -> SynapseResult<Vec<u8>> {
    if input.len() < 2 {
        return Err(corrupt("zlib stream shorter than its 2-byte header"));
    }
    let (cmf, flg) = (input[0], input[1]);
    if cmf & 0x0f != 8 || cmf >> 4 > 7 || (u16::from(cmf) << 8 | u16::from(flg)) % 31 != 0 {
        return Err(corrupt("zlib header is invalid"));
    }
    if flg & 0x20 != 0 {
        return Err(corrupt("zlib preset dictionary is not used by Git"));
    }
    let mut inf = Inflater {
        input,
        pos: 2,
        bit_buf: 0,
        bit_count: 0,
        out: Vec::with_capacity(n.min(4096)),
        max_out: n,
        prefix: true,
    };
    match inf.run() {
        Ok(()) => Ok(inf.out),
        Err(e) if e.message == PREFIX_FULL => Ok(inf.out),
        Err(e) => Err(e),
    }
}

const MAX_BITS: usize = 15;

/// Canonical Huffman decoding table (RFC 1951 section 3.2.2): symbol counts per code length
/// and the symbols ordered by code.
struct Huffman {
    counts: [u16; MAX_BITS + 1],
    symbols: Vec<u16>,
}

impl Huffman {
    fn new(lengths: &[u8]) -> SynapseResult<Self> {
        let mut counts = [0u16; MAX_BITS + 1];
        for &len in lengths {
            counts[usize::from(len)] += 1;
        }
        // Over-subscribed code sets are refused; incomplete ones are allowed (RFC 1951 permits
        // a single distance code), and an unused code then fails at decode time.
        let mut left: i32 = 1;
        for &count in &counts[1..] {
            left <<= 1;
            left -= i32::from(count);
            if left < 0 {
                return Err(corrupt("DEFLATE Huffman code set is over-subscribed"));
            }
        }
        let mut offsets = [0u16; MAX_BITS + 2];
        for len in 1..=MAX_BITS {
            offsets[len + 1] = offsets[len] + counts[len];
        }
        let mut symbols = vec![0u16; lengths.len()];
        for (symbol, &len) in lengths.iter().enumerate() {
            if len != 0 {
                let slot = &mut offsets[usize::from(len)];
                symbols[usize::from(*slot)] = symbol as u16;
                *slot += 1;
            }
        }
        Ok(Self { counts, symbols })
    }
}

const LENGTH_BASE: [u16; 29] = [
    3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31, 35, 43, 51, 59, 67, 83, 99, 115, 131,
    163, 195, 227, 258,
];
const LENGTH_EXTRA: [u8; 29] = [
    0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0,
];
const DIST_BASE: [u16; 30] = [
    1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193, 257, 385, 513, 769, 1025, 1537,
    2049, 3073, 4097, 6145, 8193, 12289, 16385, 24577,
];
const DIST_EXTRA: [u8; 30] = [
    0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13,
    13,
];
/// Order in which code length code lengths are sent (RFC 1951 section 3.2.7).
const CLEN_ORDER: [usize; 19] = [
    16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15,
];

struct Inflater<'a> {
    input: &'a [u8],
    pos: usize,
    bit_buf: u32,
    bit_count: u32,
    out: Vec<u8>,
    max_out: usize,
    /// Stop with [`PREFIX_FULL`] once `max_out` bytes are out instead of refusing.
    prefix: bool,
}

impl Inflater<'_> {
    fn bits(&mut self, need: u32) -> SynapseResult<u32> {
        while self.bit_count < need {
            let byte = *self
                .input
                .get(self.pos)
                .ok_or_else(|| corrupt("DEFLATE stream truncated"))?;
            self.pos += 1;
            self.bit_buf |= u32::from(byte) << self.bit_count;
            self.bit_count += 8;
        }
        let value = self.bit_buf & ((1u32 << need) - 1);
        self.bit_buf >>= need;
        self.bit_count -= need;
        Ok(value)
    }

    fn push(&mut self, byte: u8) -> SynapseResult<()> {
        if self.out.len() >= self.max_out {
            if self.prefix {
                return Err(corrupt(PREFIX_FULL));
            }
            return Err(corrupt(format!(
                "decompressed data exceeds the declared {} bytes",
                self.max_out
            )));
        }
        self.out.push(byte);
        Ok(())
    }

    fn run(&mut self) -> SynapseResult<()> {
        loop {
            let last = self.bits(1)? == 1;
            match self.bits(2)? {
                0 => self.stored()?,
                1 => {
                    let (lit, dist) = fixed_tables()?;
                    self.codes(&lit, &dist)?;
                }
                2 => {
                    let (lit, dist) = self.dynamic_tables()?;
                    self.codes(&lit, &dist)?;
                }
                _ => return Err(corrupt("DEFLATE block type 3 is reserved")),
            }
            if last {
                return Ok(());
            }
        }
    }

    fn stored(&mut self) -> SynapseResult<()> {
        self.bit_buf = 0;
        self.bit_count = 0;
        let header = self
            .input
            .get(self.pos..self.pos + 4)
            .ok_or_else(|| corrupt("DEFLATE stored block header truncated"))?;
        let len = u16::from_le_bytes([header[0], header[1]]);
        let nlen = u16::from_le_bytes([header[2], header[3]]);
        if len != !nlen {
            return Err(corrupt("DEFLATE stored block length check failed"));
        }
        self.pos += 4;
        let len = usize::from(len);
        let data = self
            .input
            .get(self.pos..self.pos + len)
            .ok_or_else(|| corrupt("DEFLATE stored block truncated"))?;
        if self.out.len() + len > self.max_out {
            if self.prefix {
                let room = self.max_out - self.out.len();
                self.out.extend_from_slice(&data[..room]);
                return Err(corrupt(PREFIX_FULL));
            }
            return Err(corrupt(format!(
                "decompressed data exceeds the declared {} bytes",
                self.max_out
            )));
        }
        self.out.extend_from_slice(data);
        self.pos += len;
        Ok(())
    }

    fn decode(&mut self, h: &Huffman) -> SynapseResult<u16> {
        let (mut code, mut first, mut index) = (0i32, 0i32, 0i32);
        for len in 1..=MAX_BITS {
            code |= self.bits(1)? as i32;
            let count = i32::from(h.counts[len]);
            if code - count < first {
                return Ok(h.symbols[(index + (code - first)) as usize]);
            }
            index += count;
            first += count;
            first <<= 1;
            code <<= 1;
        }
        Err(corrupt("DEFLATE Huffman code is not in the code set"))
    }

    fn dynamic_tables(&mut self) -> SynapseResult<(Huffman, Huffman)> {
        let nlen = self.bits(5)? as usize + 257;
        let ndist = self.bits(5)? as usize + 1;
        let ncode = self.bits(4)? as usize + 4;
        if nlen > 286 || ndist > 30 {
            return Err(corrupt("DEFLATE dynamic block declares too many codes"));
        }
        let mut clen = [0u8; 19];
        for &slot in CLEN_ORDER.iter().take(ncode) {
            clen[slot] = self.bits(3)? as u8;
        }
        let clen_code = Huffman::new(&clen)?;
        let mut lengths = vec![0u8; nlen + ndist];
        let mut i = 0;
        while i < nlen + ndist {
            let symbol = self.decode(&clen_code)?;
            let (value, repeat) = match symbol {
                0..=15 => (symbol as u8, 1),
                16 => {
                    if i == 0 {
                        return Err(corrupt("DEFLATE repeat with no previous length"));
                    }
                    (lengths[i - 1], 3 + self.bits(2)? as usize)
                }
                17 => (0, 3 + self.bits(3)? as usize),
                _ => (0, 11 + self.bits(7)? as usize),
            };
            if i + repeat > nlen + ndist {
                return Err(corrupt("DEFLATE code lengths overrun the declared count"));
            }
            lengths[i..i + repeat].fill(value);
            i += repeat;
        }
        if lengths[256] == 0 {
            return Err(corrupt("DEFLATE dynamic block has no end-of-block code"));
        }
        Ok((
            Huffman::new(&lengths[..nlen])?,
            Huffman::new(&lengths[nlen..])?,
        ))
    }

    fn codes(&mut self, lit: &Huffman, dist: &Huffman) -> SynapseResult<()> {
        loop {
            let symbol = self.decode(lit)?;
            match symbol {
                0..=255 => self.push(symbol as u8)?,
                256 => return Ok(()),
                257..=285 => {
                    let idx = usize::from(symbol - 257);
                    let len = usize::from(LENGTH_BASE[idx])
                        + self.bits(u32::from(LENGTH_EXTRA[idx]))? as usize;
                    let dsym = usize::from(self.decode(dist)?);
                    if dsym >= 30 {
                        return Err(corrupt("DEFLATE distance code out of range"));
                    }
                    let distance = usize::from(DIST_BASE[dsym])
                        + self.bits(u32::from(DIST_EXTRA[dsym]))? as usize;
                    if distance > self.out.len() {
                        return Err(corrupt("DEFLATE distance reaches before the output start"));
                    }
                    let start = self.out.len() - distance;
                    for k in 0..len {
                        let byte = self.out[start + k];
                        self.push(byte)?;
                    }
                }
                _ => return Err(corrupt("DEFLATE length code out of range")),
            }
        }
    }
}

fn fixed_tables() -> SynapseResult<(Huffman, Huffman)> {
    let mut lengths = [0u8; 288];
    lengths[..144].fill(8);
    lengths[144..256].fill(9);
    lengths[256..280].fill(7);
    lengths[280..].fill(8);
    Ok((Huffman::new(&lengths)?, Huffman::new(&[5u8; 30])?))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::zlib_compress_store;

    #[test]
    fn prefix_decode_stops_at_its_length_without_inflating_the_rest() {
        let raw: Vec<u8> = (0..200_000usize).map(|i| (i * 7 % 251) as u8).collect();
        let z = zlib_compress_store(&raw);
        for n in [0usize, 1, 20, 65_535, 65_540, 199_999, 200_000, 300_000] {
            let out = zlib_inflate_prefix(&z, n).unwrap();
            assert_eq!(out, raw[..n.min(raw.len())], "prefix {n}");
        }
        assert!(zlib_inflate_prefix(&z[..1], 4).is_err(), "short header");
        assert!(
            zlib_inflate_prefix(&[0x78, 0x00], 4).is_err(),
            "bad check bits"
        );
    }

    #[test]
    fn stored_blocks_round_trip_and_report_consumed_length() {
        for len in [0usize, 1, 100, 65_535, 65_536, 200_000] {
            let raw: Vec<u8> = (0..len).map(|i| (i * 7 % 251) as u8).collect();
            let mut z = zlib_compress_store(&raw);
            let used = z.len();
            z.extend_from_slice(b"trailing pack bytes");
            let (out, consumed) = zlib_decompress(&z, len).unwrap();
            assert_eq!(out, raw);
            assert_eq!(consumed, used);
        }
    }

    #[test]
    fn output_over_the_declared_size_is_refused() {
        let z = zlib_compress_store(b"0123456789");
        let err = zlib_decompress(&z, 9).unwrap_err();
        assert_eq!(err.code, RefusalCode::GitObjectCorrupt);
    }

    #[test]
    fn every_truncation_and_bit_flip_is_refused_or_exact_without_panic() {
        let z = zlib_compress_store(b"tree data\nblob data\n");
        for cut in 0..z.len() {
            assert!(zlib_decompress(&z[..cut], 1 << 16).is_err());
        }
        for bit in 0..z.len() * 8 {
            let mut d = z.clone();
            d[bit / 8] ^= 1 << (bit % 8);
            if let Ok((out, _)) = zlib_decompress(&d, 1 << 16) {
                // Only a flip the checksums cannot see may decode; it must still be exact.
                assert_eq!(crate::adler32(&out).to_be_bytes(), d[d.len() - 4..]);
            }
        }
    }
}
