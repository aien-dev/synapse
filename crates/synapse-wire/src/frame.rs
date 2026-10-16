//! Binary wire frames (ADR 0003 section 9, step G1).
//!
//! Frame = 16-byte header, then `body_len` bytes of body. Little-endian, fixed width:
//!
//! | Bytes | Field |
//! | :--- | :--- |
//! | 0..4 | magic `SYNW` |
//! | 4 | version `1` |
//! | 5 | kind (1 hello, 2 have, 3 want, 4 chunk, 5 submit, 6 accepted, 7 refused) |
//! | 6 | flags `0` (any other value is refused) |
//! | 7 | reserved `0` (any other value is refused) |
//! | 8..12 | `request_id` u32 |
//! | 12..16 | `body_len` u32 |
//!
//! Body primitives follow the A1 codec (`synapse_store::codec`): `u8`, `u16`, `u32`, `u64`
//! little endian; byte strings and strings `u32 len | bytes` (strings UTF-8); sequences
//! `u32 count | items`; fixed arrays raw; option and enum tags one byte. There is exactly one
//! encoding per frame: any other tag, trailing byte, invalid UTF-8, invalid `RepoId`,
//! unsorted or repeated digest, or non-canonical capability chain is refused, so decode then
//! encode gives the input bytes back.
//!
//! Untrusted input: `body_len` is checked against the negotiated cap before anything is
//! allocated or read, and every inner length and count is checked against the cap and the
//! bytes left in the body. The body decoder only ever sees the body slice, so it cannot read
//! past the frame into the next one.

use crate::probe::{NoProbe, Probe};
use synapse_auth::{
    Capability, CapabilityChain, ChainedRequest, ReferenceKind, RequestScope, MAX_CHAIN_DEPTH,
};
use synapse_core::{
    BlobDigest, ChangeId, ChangesetId, RefusalCode, RepoId, SynapseError, SynapseResult, WalSeq,
};

/// Frame magic.
pub const WIRE_MAGIC: [u8; 4] = *b"SYNW";
/// Frame format version.
pub const WIRE_VERSION: u8 = 1;
/// Fixed header length.
pub const FRAME_HEADER_LEN: usize = 16;
/// Default cap on a frame's declared body length (16 MiB).
pub const DEFAULT_MAX_FRAME_BODY: u32 = 16 << 20;
/// Longest refusal code name carried by a `Refused` frame.
pub const MAX_REFUSAL_CODE_LEN: usize = 64;

/// Limits a peer applies to frames it reads.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WireLimits {
    /// Largest declared body length accepted; larger declarations are refused before any
    /// allocation or read.
    pub max_frame_body: u32,
}

impl Default for WireLimits {
    fn default() -> Self {
        Self {
            max_frame_body: DEFAULT_MAX_FRAME_BODY,
        }
    }
}

/// Frame kind byte.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum FrameKind {
    Hello = 1,
    Have = 2,
    Want = 3,
    Chunk = 4,
    Submit = 5,
    Accepted = 6,
    Refused = 7,
}

impl FrameKind {
    /// Every kind, in kind-byte order.
    pub const ALL: [FrameKind; 7] = [
        Self::Hello,
        Self::Have,
        Self::Want,
        Self::Chunk,
        Self::Submit,
        Self::Accepted,
        Self::Refused,
    ];

    pub fn byte(self) -> u8 {
        self as u8
    }

    pub fn from_byte(b: u8) -> Option<Self> {
        Self::ALL.get(usize::from(b).wrapping_sub(1)).copied()
    }

    pub fn name(self) -> &'static str {
        match self {
            Self::Hello => "Hello",
            Self::Have => "Have",
            Self::Want => "Want",
            Self::Chunk => "Chunk",
            Self::Submit => "Submit",
            Self::Accepted => "Accepted",
            Self::Refused => "Refused",
        }
    }
}

/// Opening frame of each side: the limits it will apply to frames it reads.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hello {
    pub max_frame_body: u32,
    /// Largest total of chunk bytes the receiver buffers for one negotiation.
    pub max_pending_chunk_bytes: u64,
}

/// Sender offers the chunks a change needs (strictly increasing digests).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Have {
    pub repo_id: RepoId,
    pub digests: Vec<BlobDigest>,
}

/// Receiver asks for the offered chunks it lacks (strictly increasing digests).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Want {
    pub digests: Vec<BlobDigest>,
}

/// One chunk's content. Until G2 a chunk is a whole blob and its digest is the `BlobDigest`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Chunk {
    pub digest: BlobDigest,
    pub bytes: Vec<u8>,
}

/// The change is durable at `wal_seq` (or was already, for an idempotent duplicate).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Accepted {
    pub wal_seq: WalSeq,
    pub changeset_id: ChangesetId,
    pub duplicate: bool,
}

/// A typed refusal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Refused {
    pub code: RefusalCode,
    pub message: String,
}

/// A frame body by kind.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FrameBody {
    Hello(Hello),
    Have(Have),
    Want(Want),
    Chunk(Chunk),
    /// A capability-chained request whose payload is one `synapse_store::codec`
    /// binary envelope.
    Submit(Box<ChainedRequest>),
    Accepted(Accepted),
    Refused(Refused),
}

impl FrameBody {
    pub fn kind(&self) -> FrameKind {
        match self {
            Self::Hello(_) => FrameKind::Hello,
            Self::Have(_) => FrameKind::Have,
            Self::Want(_) => FrameKind::Want,
            Self::Chunk(_) => FrameKind::Chunk,
            Self::Submit(_) => FrameKind::Submit,
            Self::Accepted(_) => FrameKind::Accepted,
            Self::Refused(_) => FrameKind::Refused,
        }
    }
}

/// One frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frame {
    pub request_id: u32,
    pub body: FrameBody,
}

/// Parsed and checked header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FrameHeader {
    pub kind: FrameKind,
    pub request_id: u32,
    pub body_len: u32,
}

impl FrameHeader {
    /// Header plus body length.
    pub fn frame_len(&self) -> usize {
        FRAME_HEADER_LEN + self.body_len as usize
    }
}

/// Typed refusal from the frame decoder. `at` is the absolute byte offset in the frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WireRefusal {
    /// The input ends before a field: `need` more bytes were required.
    Truncated { at: usize, need: usize },
    /// The first four bytes are not `SYNW`.
    BadMagic { found: [u8; 4] },
    /// The version byte is not [`WIRE_VERSION`].
    VersionUnsupported { found: u8 },
    /// The flags byte is not zero.
    FlagsNonZero { found: u8 },
    /// The reserved byte is not zero.
    ReservedNonZero { found: u8 },
    /// The kind byte names no frame kind.
    UnknownKind { found: u8 },
    /// A declared length or count needs more than the cap allows.
    LengthOverCap { at: usize, declared: u64, cap: u64 },
    /// Bytes remain after the last field of the body.
    TrailingBytes { at: usize, count: usize },
    /// A tag byte (capability, reference kind, option, bool) has no meaning.
    UnknownTag {
        at: usize,
        field: &'static str,
        tag: u8,
    },
    /// A string is not UTF-8.
    InvalidUtf8 { at: usize },
    /// A repository id fails `RepoId::new`.
    InvalidRepoId { at: usize },
    /// A second encoding of the same value would exist (unsorted or repeated digests,
    /// a capability chain that does not re-encode to its bytes).
    NotCanonical { at: usize, field: &'static str },
    /// The embedded capability chain is refused by its own decoder.
    Chain { at: usize, code: RefusalCode },
    /// A `Refused` frame names no known refusal code.
    UnknownRefusalCode { at: usize },
}

impl WireRefusal {
    /// Short stable name of the refusal kind.
    pub fn kind(&self) -> &'static str {
        match self {
            Self::Truncated { .. } => "Truncated",
            Self::BadMagic { .. } => "BadMagic",
            Self::VersionUnsupported { .. } => "VersionUnsupported",
            Self::FlagsNonZero { .. } => "FlagsNonZero",
            Self::ReservedNonZero { .. } => "ReservedNonZero",
            Self::UnknownKind { .. } => "UnknownKind",
            Self::LengthOverCap { .. } => "LengthOverCap",
            Self::TrailingBytes { .. } => "TrailingBytes",
            Self::UnknownTag { .. } => "UnknownTag",
            Self::InvalidUtf8 { .. } => "InvalidUtf8",
            Self::InvalidRepoId { .. } => "InvalidRepoId",
            Self::NotCanonical { .. } => "NotCanonical",
            Self::Chain { .. } => "Chain",
            Self::UnknownRefusalCode { .. } => "UnknownRefusalCode",
        }
    }

    /// The refusal as a `SynapseError` with code `WireFrameMalformed`.
    pub fn into_error(self) -> SynapseError {
        SynapseError::new(
            RefusalCode::WireFrameMalformed,
            format!("wire frame: {} ({self:?})", self.kind()),
        )
    }
}

type Decoded<T> = Result<T, WireRefusal>;

// ---------------------------------------------------------------------------------------
// Encoder
// ---------------------------------------------------------------------------------------

fn too_large(what: &str) -> SynapseError {
    SynapseError::new(
        RefusalCode::QuotaPayloadTooLarge,
        format!("{what} exceeds the 32-bit length field"),
    )
}

struct Writer(Vec<u8>);

impl Writer {
    fn u8(&mut self, v: u8) {
        self.0.push(v);
    }
    fn u32(&mut self, v: u32) {
        self.0.extend_from_slice(&v.to_le_bytes());
    }
    fn u64(&mut self, v: u64) {
        self.0.extend_from_slice(&v.to_le_bytes());
    }
    fn raw(&mut self, b: &[u8]) {
        self.0.extend_from_slice(b);
    }
    fn len(&mut self, n: usize, what: &str) -> SynapseResult<()> {
        self.u32(u32::try_from(n).map_err(|_| too_large(what))?);
        Ok(())
    }
    fn bytes(&mut self, b: &[u8], what: &str) -> SynapseResult<()> {
        self.len(b.len(), what)?;
        self.raw(b);
        Ok(())
    }
    fn str(&mut self, s: &str, what: &str) -> SynapseResult<()> {
        self.bytes(s.as_bytes(), what)
    }
    fn digests(&mut self, d: &[BlobDigest]) -> SynapseResult<()> {
        if d.windows(2).any(|w| w[0].0 >= w[1].0) {
            return Err(SynapseError::new(
                RefusalCode::WireFrameMalformed,
                "digests must be strictly increasing",
            ));
        }
        self.len(d.len(), "digest count")?;
        d.iter().for_each(|x| self.raw(&x.0));
        Ok(())
    }
}

fn refusal_code_name(code: RefusalCode) -> String {
    format!("{code:?}")
}

fn put_body(w: &mut Writer, body: &FrameBody) -> SynapseResult<()> {
    match body {
        FrameBody::Hello(h) => {
            w.u32(h.max_frame_body);
            w.u64(h.max_pending_chunk_bytes);
        }
        FrameBody::Have(h) => {
            RepoId::new(h.repo_id.as_str())?;
            w.str(h.repo_id.as_str(), "repository id")?;
            w.digests(&h.digests)?;
        }
        FrameBody::Want(x) => w.digests(&x.digests)?,
        FrameBody::Chunk(c) => {
            w.raw(&c.digest.0);
            w.bytes(&c.bytes, "chunk")?;
        }
        FrameBody::Submit(r) => {
            let n = r.chain.links.len();
            if n == 0 || n > MAX_CHAIN_DEPTH {
                return Err(SynapseError::new(
                    RefusalCode::AuthChainBroken,
                    format!("chain length {n} outside 1..={MAX_CHAIN_DEPTH}"),
                ));
            }
            w.bytes(&r.chain.encode(), "capability chain")?;
            RepoId::new(r.target_repo_id.as_str())?;
            w.str(r.target_repo_id.as_str(), "repository id")?;
            w.raw(&r.agent_key);
            w.u8(r.required_capability.tag_byte());
            w.len(r.scope.paths.len(), "scope path count")?;
            for p in &r.scope.paths {
                w.str(p, "scope path")?;
            }
            w.u8(r.scope.reference.map_or(0, ReferenceKind::tag_byte));
            match r.scope.join_change {
                None => w.u8(0),
                Some(id) => {
                    w.u8(1);
                    w.raw(&id.0);
                }
            }
            w.raw(&r.request_nonce);
            w.u64(r.timestamp_ms);
            w.bytes(&r.payload, "payload")?;
            w.raw(&r.agent_signature);
        }
        FrameBody::Accepted(a) => {
            w.u64(a.wal_seq.0);
            w.raw(&a.changeset_id.0);
            w.u8(u8::from(a.duplicate));
        }
        FrameBody::Refused(r) => {
            w.str(&refusal_code_name(r.code), "refusal code")?;
            w.str(&r.message, "refusal message")?;
        }
    }
    Ok(())
}

/// Encode one frame. Fails only when a field cannot be represented (a length above `u32`,
/// an invalid repository id, unsorted digests, an empty or over-deep chain).
pub fn encode_frame(frame: &Frame) -> SynapseResult<Vec<u8>> {
    let mut w = Writer(Vec::with_capacity(64));
    w.raw(&WIRE_MAGIC);
    w.u8(WIRE_VERSION);
    w.u8(frame.body.kind().byte());
    w.u8(0);
    w.u8(0);
    w.u32(frame.request_id);
    w.u32(0);
    put_body(&mut w, &frame.body)?;
    let body_len = w.0.len() - FRAME_HEADER_LEN;
    let body_len = u32::try_from(body_len).map_err(|_| too_large("frame body"))?;
    w.0[12..16].copy_from_slice(&body_len.to_le_bytes());
    Ok(w.0)
}

/// Encode one frame and refuse it (`QuotaPayloadTooLarge`) when its body exceeds the
/// peer's `max_frame_body`, since the peer would refuse it anyway.
pub fn encode_frame_within(frame: &Frame, limits: &WireLimits) -> SynapseResult<Vec<u8>> {
    let bytes = encode_frame(frame)?;
    let body = bytes.len() - FRAME_HEADER_LEN;
    if body as u64 > u64::from(limits.max_frame_body) {
        return Err(SynapseError::new(
            RefusalCode::QuotaPayloadTooLarge,
            format!(
                "{} frame body {body} exceeds the peer's max_frame_body {}",
                frame.body.kind().name(),
                limits.max_frame_body
            ),
        ));
    }
    Ok(bytes)
}

// ---------------------------------------------------------------------------------------
// Decoder
// ---------------------------------------------------------------------------------------

/// Record that the decoder reached this source line.
macro_rules! cov {
    ($r:expr) => {
        $r.probe.site(line!())
    };
}

struct Reader<'b, 'p, P: Probe> {
    buf: &'b [u8],
    pos: usize,
    /// Absolute offset of `buf[0]` in the frame (for refusal offsets and the probe).
    base: usize,
    cap: u64,
    probe: &'p mut P,
}

impl<'b, P: Probe> Reader<'b, '_, P> {
    fn at(&self) -> usize {
        self.base + self.pos
    }

    fn remaining(&self) -> usize {
        self.buf.len() - self.pos
    }

    fn take(&mut self, n: usize) -> Decoded<&'b [u8]> {
        if n > self.remaining() {
            cov!(self);
            return Err(WireRefusal::Truncated {
                at: self.at(),
                need: n - self.remaining(),
            });
        }
        let s = &self.buf[self.pos..self.pos + n];
        self.pos += n;
        let end = self.at();
        self.probe.touched(end);
        Ok(s)
    }

    fn array<const N: usize>(&mut self) -> Decoded<[u8; N]> {
        let mut a = [0u8; N];
        a.copy_from_slice(self.take(N)?);
        Ok(a)
    }

    fn u8(&mut self) -> Decoded<u8> {
        Ok(self.take(1)?[0])
    }
    fn u32(&mut self) -> Decoded<u32> {
        Ok(u32::from_le_bytes(self.array()?))
    }
    fn u64(&mut self) -> Decoded<u64> {
        Ok(u64::from_le_bytes(self.array()?))
    }

    /// A `u32` length of a byte run: checked against the cap, then the body.
    fn byte_len(&mut self) -> Decoded<usize> {
        let at = self.at();
        let n = self.u32()?;
        if u64::from(n) > self.cap {
            cov!(self);
            return Err(WireRefusal::LengthOverCap {
                at,
                declared: u64::from(n),
                cap: self.cap,
            });
        }
        let n = n as usize;
        if n > self.remaining() {
            cov!(self);
            return Err(WireRefusal::Truncated {
                at: self.at(),
                need: n - self.remaining(),
            });
        }
        cov!(self);
        Ok(n)
    }

    fn bytes(&mut self) -> Decoded<Vec<u8>> {
        let n = self.byte_len()?;
        Ok(self.take(n)?.to_vec())
    }

    fn str(&mut self) -> Decoded<String> {
        let at = self.at();
        let n = self.byte_len()?;
        let raw = self.take(n)?;
        match std::str::from_utf8(raw) {
            Ok(s) => {
                cov!(self);
                Ok(s.to_owned())
            }
            Err(_) => {
                cov!(self);
                Err(WireRefusal::InvalidUtf8 { at })
            }
        }
    }

    /// A `u32` count of items at least `min_item` bytes each: checked against the cap and
    /// the body before anything is reserved.
    fn count(&mut self, min_item: usize) -> Decoded<usize> {
        let at = self.at();
        let n = self.u32()?;
        let need = u64::from(n) * min_item as u64;
        if need > self.cap {
            cov!(self);
            return Err(WireRefusal::LengthOverCap {
                at,
                declared: need,
                cap: self.cap,
            });
        }
        if need > self.remaining() as u64 {
            cov!(self);
            return Err(WireRefusal::Truncated {
                at: self.at(),
                need: need as usize - self.remaining(),
            });
        }
        cov!(self);
        Ok(n as usize)
    }

    fn repo(&mut self) -> Decoded<RepoId> {
        let at = self.at();
        let s = self.str()?;
        match RepoId::new(s) {
            Ok(r) => {
                cov!(self);
                Ok(r)
            }
            Err(_) => {
                cov!(self);
                Err(WireRefusal::InvalidRepoId { at })
            }
        }
    }

    /// `u32 count | digest*count`, strictly increasing.
    fn digests(&mut self) -> Decoded<Vec<BlobDigest>> {
        let n = self.count(32)?;
        let mut out: Vec<BlobDigest> = Vec::with_capacity(n);
        for _ in 0..n {
            let at = self.at();
            let d = BlobDigest(self.array()?);
            if out.last().is_some_and(|p| p.0 >= d.0) {
                cov!(self);
                return Err(WireRefusal::NotCanonical {
                    at,
                    field: "digest order",
                });
            }
            cov!(self);
            out.push(d);
        }
        Ok(out)
    }

    fn finish(&mut self) -> Decoded<()> {
        if self.remaining() != 0 {
            cov!(self);
            return Err(WireRefusal::TrailingBytes {
                at: self.at(),
                count: self.remaining(),
            });
        }
        cov!(self);
        Ok(())
    }
}

fn capability_from_tag(tag: u8) -> Option<Capability> {
    match tag {
        1 => Some(Capability::Read),
        2 => Some(Capability::Propose),
        3 => Some(Capability::Evaluate),
        4 => Some(Capability::Review),
        5 => Some(Capability::Publish),
        6 => Some(Capability::Undo),
        _ => None,
    }
}

fn refusal_code_from_name(name: &str) -> Option<RefusalCode> {
    if name.is_empty() || name.len() > MAX_REFUSAL_CODE_LEN {
        return None;
    }
    if !name.bytes().all(|b| b.is_ascii_alphanumeric()) {
        return None;
    }
    let code: RefusalCode = serde_json::from_value(serde_json::Value::String(name.into())).ok()?;
    (refusal_code_name(code) == name).then_some(code)
}

fn get_submit<P: Probe>(r: &mut Reader<'_, '_, P>) -> Decoded<ChainedRequest> {
    let chain_at = r.at();
    let chain_bytes = {
        let n = r.byte_len()?;
        r.take(n)?
    };
    let chain = match CapabilityChain::decode(chain_bytes) {
        Ok(c) => c,
        Err(e) => {
            cov!(r);
            return Err(WireRefusal::Chain {
                at: chain_at,
                code: e.code,
            });
        }
    };
    if chain.encode() != chain_bytes {
        cov!(r);
        return Err(WireRefusal::NotCanonical {
            at: chain_at,
            field: "capability chain",
        });
    }
    cov!(r);
    let target_repo_id = r.repo()?;
    let agent_key = r.array()?;
    let cap_at = r.at();
    let cap_tag = r.u8()?;
    let Some(required_capability) = capability_from_tag(cap_tag) else {
        cov!(r);
        return Err(WireRefusal::UnknownTag {
            at: cap_at,
            field: "capability",
            tag: cap_tag,
        });
    };
    cov!(r);
    let n = r.count(4)?;
    let mut paths = Vec::with_capacity(n);
    for _ in 0..n {
        paths.push(r.str()?);
    }
    let ref_at = r.at();
    let reference = match r.u8()? {
        0 => None,
        1 => Some(ReferenceKind::OwnDrafts),
        2 => Some(ReferenceKind::CanonicalViaPromotionQueue),
        tag => {
            cov!(r);
            return Err(WireRefusal::UnknownTag {
                at: ref_at,
                field: "reference kind",
                tag,
            });
        }
    };
    cov!(r);
    let join_at = r.at();
    let join_change = match r.u8()? {
        0 => None,
        1 => Some(ChangeId(r.array()?)),
        tag => {
            cov!(r);
            return Err(WireRefusal::UnknownTag {
                at: join_at,
                field: "join change option",
                tag,
            });
        }
    };
    cov!(r);
    let request_nonce = r.array()?;
    let timestamp_ms = r.u64()?;
    let payload = r.bytes()?;
    let agent_signature = r.array()?;
    cov!(r);
    Ok(ChainedRequest {
        chain,
        target_repo_id,
        agent_key,
        required_capability,
        scope: RequestScope {
            paths,
            reference,
            join_change,
        },
        request_nonce,
        timestamp_ms,
        payload,
        agent_signature,
    })
}

fn get_body<P: Probe>(r: &mut Reader<'_, '_, P>, kind: FrameKind) -> Decoded<FrameBody> {
    let body = match kind {
        FrameKind::Hello => {
            cov!(r);
            FrameBody::Hello(Hello {
                max_frame_body: r.u32()?,
                max_pending_chunk_bytes: r.u64()?,
            })
        }
        FrameKind::Have => {
            cov!(r);
            let repo_id = r.repo()?;
            FrameBody::Have(Have {
                repo_id,
                digests: r.digests()?,
            })
        }
        FrameKind::Want => {
            cov!(r);
            FrameBody::Want(Want {
                digests: r.digests()?,
            })
        }
        FrameKind::Chunk => {
            cov!(r);
            let digest = BlobDigest(r.array()?);
            FrameBody::Chunk(Chunk {
                digest,
                bytes: r.bytes()?,
            })
        }
        FrameKind::Submit => {
            cov!(r);
            FrameBody::Submit(Box::new(get_submit(r)?))
        }
        FrameKind::Accepted => {
            cov!(r);
            let wal_seq = WalSeq(r.u64()?);
            let changeset_id = ChangesetId(r.array()?);
            let at = r.at();
            let duplicate = match r.u8()? {
                0 => false,
                1 => true,
                tag => {
                    cov!(r);
                    return Err(WireRefusal::UnknownTag {
                        at,
                        field: "duplicate",
                        tag,
                    });
                }
            };
            FrameBody::Accepted(Accepted {
                wal_seq,
                changeset_id,
                duplicate,
            })
        }
        FrameKind::Refused => {
            cov!(r);
            let at = r.at();
            let name = r.str()?;
            let Some(code) = refusal_code_from_name(&name) else {
                cov!(r);
                return Err(WireRefusal::UnknownRefusalCode { at });
            };
            FrameBody::Refused(Refused {
                code,
                message: r.str()?,
            })
        }
    };
    r.finish()?;
    Ok(body)
}

fn header_probed<P: Probe>(
    bytes: &[u8],
    limits: &WireLimits,
    probe: &mut P,
) -> Decoded<FrameHeader> {
    let mut r = Reader {
        buf: bytes,
        pos: 0,
        base: 0,
        cap: u64::from(limits.max_frame_body),
        probe,
    };
    let h: [u8; FRAME_HEADER_LEN] = r.array()?;
    cov!(r);
    let magic: [u8; 4] = h[0..4].try_into().expect("4 bytes");
    if magic != WIRE_MAGIC {
        cov!(r);
        return Err(WireRefusal::BadMagic { found: magic });
    }
    if h[4] != WIRE_VERSION {
        cov!(r);
        return Err(WireRefusal::VersionUnsupported { found: h[4] });
    }
    let Some(kind) = FrameKind::from_byte(h[5]) else {
        cov!(r);
        return Err(WireRefusal::UnknownKind { found: h[5] });
    };
    if h[6] != 0 {
        cov!(r);
        return Err(WireRefusal::FlagsNonZero { found: h[6] });
    }
    if h[7] != 0 {
        cov!(r);
        return Err(WireRefusal::ReservedNonZero { found: h[7] });
    }
    let request_id = u32::from_le_bytes(h[8..12].try_into().expect("4 bytes"));
    let body_len = u32::from_le_bytes(h[12..16].try_into().expect("4 bytes"));
    if body_len > limits.max_frame_body {
        cov!(r);
        return Err(WireRefusal::LengthOverCap {
            at: 12,
            declared: u64::from(body_len),
            cap: u64::from(limits.max_frame_body),
        });
    }
    cov!(r);
    Ok(FrameHeader {
        kind,
        request_id,
        body_len,
    })
}

/// Parse and check the 16-byte header (magic, version, kind, flags, reserved, and the
/// declared body length against `limits`). Reads at most [`FRAME_HEADER_LEN`] bytes.
pub fn decode_header(bytes: &[u8], limits: &WireLimits) -> Result<FrameHeader, WireRefusal> {
    header_probed(bytes, limits, &mut NoProbe)
}

/// Decode a body of exactly `header.body_len` bytes (as read from a stream after
/// [`decode_header`]).
pub fn decode_body(
    header: &FrameHeader,
    body: &[u8],
    limits: &WireLimits,
) -> Result<Frame, WireRefusal> {
    body_probed(header, body, limits, &mut NoProbe)
}

fn body_probed<P: Probe>(
    header: &FrameHeader,
    body: &[u8],
    limits: &WireLimits,
    probe: &mut P,
) -> Decoded<Frame> {
    if body.len() != header.body_len as usize {
        return Err(WireRefusal::Truncated {
            at: FRAME_HEADER_LEN + body.len().min(header.body_len as usize),
            need: (header.body_len as usize).saturating_sub(body.len()),
        });
    }
    let mut r = Reader {
        buf: body,
        pos: 0,
        base: FRAME_HEADER_LEN,
        cap: u64::from(limits.max_frame_body),
        probe,
    };
    let body = get_body(&mut r, header.kind)?;
    Ok(Frame {
        request_id: header.request_id,
        body,
    })
}

/// Decode the first frame of `buf` (a stream buffer that may hold more frames after it).
/// Returns the frame and the number of bytes it occupies. Only the first
/// `16 + body_len` bytes are ever read.
pub fn decode_frame(buf: &[u8], limits: &WireLimits) -> Result<(Frame, usize), WireRefusal> {
    decode_frame_probed(buf, limits, &mut NoProbe)
}

/// [`decode_frame`] reporting decoder states and reads to `probe` (used by the fuzzer).
pub fn decode_frame_probed<P: Probe>(
    buf: &[u8],
    limits: &WireLimits,
    probe: &mut P,
) -> Result<(Frame, usize), WireRefusal> {
    let header = header_probed(buf, limits, probe)?;
    let end = header.frame_len();
    if buf.len() < end {
        probe.site(line!());
        return Err(WireRefusal::Truncated {
            at: buf.len(),
            need: end - buf.len(),
        });
    }
    let frame = body_probed(&header, &buf[FRAME_HEADER_LEN..end], limits, probe)?;
    Ok((frame, end))
}
