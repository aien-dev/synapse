//! Shared-memory ring for local agents (ADR 0003 section 9 step G3, experiment X5).
//!
//! A [`RingRegion`] holds two single-producer, single-consumer byte rings, one per
//! direction. Each side owns a [`RingSender`] on one ring and a [`RingReceiver`] on the
//! other; [`RingStream`] joins the two into a byte stream, so the G1 frame reader
//! ([`crate::transport::FrameConn`]) and the have-want session run over the ring unchanged.
//!
//! The peer is hostile. Every word of the region is writable by both sides, so:
//!
//! * Each side keeps its own index (the sender its `head`, the receiver its `tail`) and its
//!   own copy of the ring configuration. It publishes them to the region and never reads
//!   them back. A word the peer overwrites changes nothing for this side.
//! * Every value read from the region (the peer's index, a record's length and sequence
//!   number) is loaded once into a local, checked, and only then used. A record's payload
//!   is copied into the receiver's own buffer before anyone validates it, so the bytes a
//!   frame decoder checks are the bytes it uses.
//! * Every position is the index masked by the power-of-two capacity, and every access is
//!   a bounds-checked slice index, so no input can address memory outside the ring.
//! * All shared accesses are atomics with explicit orderings: the sender writes a record
//!   with relaxed stores, then publishes `head` with a release store; the receiver loads
//!   `head` with acquire, then the record with relaxed loads, then publishes `tail` with
//!   release (so the sender cannot reuse space the receiver is still copying).
//! * The first refusal poisons the endpoint: framing can no longer be trusted, so it refuses
//!   every later call, as the G1 stream reader closes a connection on a malformed frame.
//!
//! # Layout
//!
//! All fields are little-endian `u64` words. One ring is [`CONTROL_WORDS`] words of control
//! block followed by `capacity / 8` data words; the region is ring 0 then ring 1. The
//! creator sends on ring 0 and receives on ring 1.
//!
//! | Word | Field | Written by |
//! | :--- | :--- | :--- |
//! | 0 | magic `SYNRING1` | creator, at set-up |
//! | 1 | capacity in bytes | creator, at set-up |
//! | 2 | start index | creator, at set-up |
//! | 8 | `head`: bytes published | sender |
//! | 9 | closed (0 or 1) | sender |
//! | 16 | `tail`: bytes consumed | receiver |
//! | 17 | receiver sleeping (0 or 1) | receiver |
//! | 24 | doorbell (wake counter; futex word on Linux) | sender |
//!
//! Indices are byte counters that only grow and wrap at 2^64 (wrapping arithmetic). A
//! record is a 16-byte header (`len` word, `seq` word), then `len` payload bytes padded with
//! zeros to a multiple of 8. Records may wrap across the end of the data area. `seq` starts
//! at 0 and counts records; the receiver refuses any other value, so no record is accepted
//! twice and none is skipped.
//!
//! # Waiting
//!
//! A receiver with nothing to read polls for [`RingConfig::spin`], then sleeps on the
//! doorbell word (a futex on Linux, with a 10 ms timeout so a peer that never rings costs a
//! delay, never a hang; a 50 microsecond sleep elsewhere). A sender rings the doorbell only
//! when the receiver says it is sleeping. A sender whose ring is full polls and yields.

use std::fmt;
use std::sync::atomic::{fence, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use synapse_core::{RefusalCode, SynapseError, SynapseResult};

/// Ring magic, word 0 of each ring.
pub const RING_MAGIC: u64 = u64::from_le_bytes(*b"SYNRING1");
/// Record header: `len` word and `seq` word.
pub const RECORD_HEADER_LEN: usize = 16;
/// Words of control block in front of each ring's data (four 64-byte lines).
pub const CONTROL_WORDS: usize = 32;

/// Word offsets inside one ring's control block (see the module table).
pub mod layout {
    pub const MAGIC: usize = 0;
    pub const CAPACITY: usize = 1;
    pub const START: usize = 2;
    pub const HEAD: usize = 8;
    pub const CLOSED: usize = 9;
    pub const TAIL: usize = 16;
    pub const RX_SLEEPING: usize = 17;
    pub const DOORBELL: usize = 24;
}

const MIN_CAPACITY: usize = 64;
const MAX_CAPACITY: usize = 1 << 30;
/// How long a sleeping receiver waits before it looks again on its own.
const SLEEP_TIMEOUT: Duration = Duration::from_millis(10);

/// Ring parameters. Both sides must use the same values; each keeps its own copy and only
/// checks the region's set-up words against it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RingConfig {
    /// Data bytes per direction: a power of two from 64 to 2^30.
    pub capacity: usize,
    /// Largest record payload, from 1 to `capacity - 16`. Longer writes are split.
    pub max_record: usize,
    /// First byte index, a multiple of 8 (tests start near `u64::MAX` to cross the wrap).
    pub start: u64,
    /// How long a receiver polls before it sleeps.
    pub spin: Duration,
}

impl Default for RingConfig {
    fn default() -> Self {
        Self {
            capacity: 1 << 20,
            max_record: 256 << 10,
            start: 0,
            spin: Duration::from_micros(50),
        }
    }
}

impl RingConfig {
    /// Check the parameters.
    pub fn validate(&self) -> Result<(), RingRefusal> {
        if !self.capacity.is_power_of_two()
            || self.capacity < MIN_CAPACITY
            || self.capacity > MAX_CAPACITY
        {
            return Err(RingRefusal::BadConfig(
                "capacity must be a power of two from 64 to 2^30",
            ));
        }
        if self.max_record == 0 || self.max_record > self.capacity - RECORD_HEADER_LEN {
            return Err(RingRefusal::BadConfig(
                "max_record must be from 1 to capacity - 16",
            ));
        }
        if !self.start.is_multiple_of(8) {
            return Err(RingRefusal::BadConfig("start must be a multiple of 8"));
        }
        Ok(())
    }

    fn data_words(&self) -> usize {
        self.capacity / 8
    }

    /// Words in one ring (control block and data).
    pub fn ring_words(&self) -> usize {
        CONTROL_WORDS + self.data_words()
    }

    /// Words in a region (two rings).
    pub fn region_words(&self) -> usize {
        2 * self.ring_words()
    }

    /// Bytes in a region (two rings).
    pub fn region_bytes(&self) -> usize {
        8 * self.region_words()
    }

    /// Word offset of ring `ring` (0 or 1) inside a region.
    pub fn ring_base(&self, ring: usize) -> usize {
        ring * self.ring_words()
    }
}

/// Bytes a record of `len` payload bytes occupies (header plus padded payload). `len` is
/// at most `max_record`, so this cannot overflow.
pub fn record_span(len: usize) -> usize {
    RECORD_HEADER_LEN + len.div_ceil(8) * 8
}

/// Typed refusal from the ring. Everything after set-up is the peer breaking the protocol.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RingRefusal {
    /// The local configuration is invalid.
    BadConfig(&'static str),
    /// The region does not have the size the configuration needs.
    RegionSize { need: usize, found: usize },
    /// A set-up word (magic, capacity, start) differs from the local configuration.
    HeaderMismatch {
        ring: usize,
        field: &'static str,
        found: u64,
    },
    /// The shared region could be shrunk by the peer (no `F_SEAL_SHRINK` seal), which would
    /// let it fault the reader; refused before mapping.
    RegionNotSealed,
    /// The peer's index is not a multiple of 8.
    IndexMisaligned { which: &'static str, found: u64 },
    /// The peer's index is outside the range its own past and this side's index allow: the
    /// sender's `head` more than `capacity` ahead of the receiver's `tail` or behind it, or
    /// the receiver's `tail` ahead of `head` or behind where it was.
    IndexOutOfRange {
        which: &'static str,
        found: u64,
        low: u64,
        high: u64,
    },
    /// The sender's `head` moved back behind a value this side already saw.
    IndexRegressed { found: u64, seen: u64 },
    /// Published bytes end inside a record: `need` bytes were required, `available` were
    /// published.
    TornRecord { need: u64, available: u64 },
    /// A record declares more payload than `max_record`.
    LengthOverCap { declared: u64, cap: u64 },
    /// A record carries the wrong sequence number (a replay, a skip, or garbage).
    SequenceMismatch { expected: u64, found: u64 },
    /// A local send of more than `max_record` bytes (not a peer fault; nothing is written).
    RecordTooLarge { len: usize, cap: usize },
    /// A send after this side closed its sender.
    SenderClosed,
}

impl RingRefusal {
    /// Short stable name of the refusal kind.
    pub fn kind(&self) -> &'static str {
        match self {
            Self::BadConfig(_) => "BadConfig",
            Self::RegionSize { .. } => "RegionSize",
            Self::HeaderMismatch { .. } => "HeaderMismatch",
            Self::RegionNotSealed => "RegionNotSealed",
            Self::IndexMisaligned { .. } => "IndexMisaligned",
            Self::IndexOutOfRange { .. } => "IndexOutOfRange",
            Self::IndexRegressed { .. } => "IndexRegressed",
            Self::TornRecord { .. } => "TornRecord",
            Self::LengthOverCap { .. } => "LengthOverCap",
            Self::SequenceMismatch { .. } => "SequenceMismatch",
            Self::RecordTooLarge { .. } => "RecordTooLarge",
            Self::SenderClosed => "SenderClosed",
        }
    }

    /// The refusal as a `SynapseError` with code `WireRingViolation`.
    pub fn into_error(self) -> SynapseError {
        SynapseError::new(
            RefusalCode::WireRingViolation,
            format!("wire ring: {} ({self:?})", self.kind()),
        )
    }
}

impl fmt::Display for RingRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "wire ring: {} ({self:?})", self.kind())
    }
}

impl std::error::Error for RingRefusal {}

enum Memory {
    Heap(Box<[AtomicU64]>),
    #[cfg(all(target_os = "linux", target_pointer_width = "64"))]
    Shared(crate::shm::Mapping),
}

/// Memory holding two rings: on the heap for one process, or a sealed shared mapping
/// ([`RingRegion::create_shared`], [`RingRegion::attach_shared`]) for two.
pub struct RingRegion {
    cfg: RingConfig,
    mem: Memory,
}

/// Which end of the region a side is: the creator sends on ring 0, the attacher on ring 1.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Side {
    Creator,
    Attacher,
}

impl RingRegion {
    /// A region on this process's heap (both sides in one process; tests and models).
    pub fn in_process(cfg: RingConfig) -> Result<Arc<Self>, RingRefusal> {
        cfg.validate()?;
        let words = (0..cfg.region_words()).map(|_| AtomicU64::new(0)).collect();
        let region = Self {
            cfg,
            mem: Memory::Heap(words),
        };
        region.init();
        Ok(Arc::new(region))
    }

    /// A new sealed shared-memory region (Linux `memfd`, sealed against shrinking and
    /// growing). Another process attaches with [`Self::attach_shared`] on
    /// [`Self::attach_path`].
    #[cfg(all(target_os = "linux", target_pointer_width = "64"))]
    pub fn create_shared(cfg: RingConfig) -> SynapseResult<Arc<Self>> {
        cfg.validate().map_err(RingRefusal::into_error)?;
        let map = crate::shm::Mapping::create(cfg.region_bytes()).map_err(io_error)?;
        let region = Self {
            cfg,
            mem: Memory::Shared(map),
        };
        region.init();
        Ok(Arc::new(region))
    }

    /// Attach to a region another process created. Refused unless the file is sealed against
    /// shrinking, has exactly the configured size, and carries the configured set-up words.
    #[cfg(all(target_os = "linux", target_pointer_width = "64"))]
    pub fn attach_shared(path: &std::path::Path, cfg: RingConfig) -> SynapseResult<Arc<Self>> {
        cfg.validate().map_err(RingRefusal::into_error)?;
        let map = match crate::shm::Mapping::attach(path, cfg.region_bytes()) {
            Ok(m) => m,
            Err(crate::shm::AttachError::Refused(r)) => return Err(r.into_error()),
            Err(crate::shm::AttachError::Io(e)) => return Err(io_error(e)),
        };
        let region = Self {
            cfg,
            mem: Memory::Shared(map),
        };
        region.verify().map_err(RingRefusal::into_error)?;
        Ok(Arc::new(region))
    }

    /// A path another process of the same user can open to attach (`/proc/<pid>/fd/<fd>`);
    /// `None` for a heap region.
    pub fn attach_path(&self) -> Option<std::path::PathBuf> {
        match &self.mem {
            Memory::Heap(_) => None,
            #[cfg(all(target_os = "linux", target_pointer_width = "64"))]
            Memory::Shared(m) => Some(m.attach_path()),
        }
    }

    /// The configuration this side uses.
    pub fn config(&self) -> &RingConfig {
        &self.cfg
    }

    /// Every word of the region. Public so tests can play a hostile peer; production code
    /// only goes through [`RingSender`] and [`RingReceiver`].
    pub fn words(&self) -> &[AtomicU64] {
        match &self.mem {
            Memory::Heap(w) => w,
            #[cfg(all(target_os = "linux", target_pointer_width = "64"))]
            Memory::Shared(m) => m.words(),
        }
    }

    fn init(&self) {
        let w = self.words();
        for ring in 0..2 {
            let b = self.cfg.ring_base(ring);
            w[b + layout::CAPACITY].store(self.cfg.capacity as u64, Ordering::Relaxed);
            w[b + layout::START].store(self.cfg.start, Ordering::Relaxed);
            w[b + layout::HEAD].store(self.cfg.start, Ordering::Relaxed);
            w[b + layout::TAIL].store(self.cfg.start, Ordering::Relaxed);
            w[b + layout::CLOSED].store(0, Ordering::Relaxed);
            w[b + layout::RX_SLEEPING].store(0, Ordering::Relaxed);
            w[b + layout::DOORBELL].store(0, Ordering::Relaxed);
            w[b + layout::MAGIC].store(RING_MAGIC, Ordering::Release);
        }
    }

    fn verify(&self) -> Result<(), RingRefusal> {
        let w = self.words();
        if w.len() != self.cfg.region_words() {
            return Err(RingRefusal::RegionSize {
                need: self.cfg.region_bytes(),
                found: w.len() * 8,
            });
        }
        for ring in 0..2 {
            let b = self.cfg.ring_base(ring);
            let checks = [
                ("magic", layout::MAGIC, RING_MAGIC),
                ("capacity", layout::CAPACITY, self.cfg.capacity as u64),
                ("start", layout::START, self.cfg.start),
            ];
            for (field, off, want) in checks {
                let found = w[b + off].load(Ordering::Acquire);
                if found != want {
                    return Err(RingRefusal::HeaderMismatch { ring, field, found });
                }
            }
        }
        Ok(())
    }

    /// The sender and receiver for `side`.
    pub fn endpoints(self: &Arc<Self>, side: Side) -> (RingSender, RingReceiver) {
        let (tx, rx) = match side {
            Side::Creator => (0, 1),
            Side::Attacher => (1, 0),
        };
        (
            RingSender::new(self.clone(), tx),
            RingReceiver::new(self.clone(), rx),
        )
    }

    /// A [`RingStream`] for `side`.
    pub fn stream(self: &Arc<Self>, side: Side) -> RingStream {
        let (tx, rx) = self.endpoints(side);
        RingStream::new(tx, rx)
    }
}

#[cfg(all(target_os = "linux", target_pointer_width = "64"))]
fn io_error(e: std::io::Error) -> SynapseError {
    SynapseError::new(RefusalCode::IoFailure, format!("wire ring: {e}"))
}

/// One ring as seen by one endpoint: bounds-checked access to its control and data words.
struct RingView {
    region: Arc<RingRegion>,
    base: usize,
    data_mask: u64,
}

impl RingView {
    fn new(region: Arc<RingRegion>, ring: usize) -> Self {
        let cfg = *region.config();
        Self {
            base: cfg.ring_base(ring),
            data_mask: (cfg.data_words() - 1) as u64,
            region,
        }
    }

    fn ctl(&self, off: usize) -> &AtomicU64 {
        &self.region.words()[self.base + off]
    }

    /// The data word holding byte index `index` (a multiple of 8). The mask keeps the
    /// position inside the data area for every `index`; the slice index is bounds-checked.
    fn data(&self, index: u64) -> &AtomicU64 {
        let pos = ((index / 8) & self.data_mask) as usize;
        &self.region.words()[self.base + CONTROL_WORDS + pos]
    }

    fn ring_doorbell(&self) {
        let bell = self.ctl(layout::DOORBELL);
        bell.fetch_add(1, Ordering::Release);
        doorbell_wake(bell);
    }
}

/// The writing end of one ring.
pub struct RingSender {
    view: RingView,
    cfg: RingConfig,
    head: u64,
    tail_seen: u64,
    seq: u64,
    closed: bool,
    poisoned: Option<RingRefusal>,
}

impl RingSender {
    fn new(region: Arc<RingRegion>, ring: usize) -> Self {
        let cfg = *region.config();
        Self {
            view: RingView::new(region, ring),
            cfg,
            head: cfg.start,
            tail_seen: cfg.start,
            seq: 0,
            closed: false,
            poisoned: None,
        }
    }

    fn poison(&mut self, r: RingRefusal) -> RingRefusal {
        self.poisoned = Some(r.clone());
        r
    }

    /// Bytes free for new records, after checking the receiver's published `tail`.
    fn free(&mut self) -> Result<u64, RingRefusal> {
        let tail = self.view.ctl(layout::TAIL).load(Ordering::Acquire);
        if !tail.is_multiple_of(8) {
            return Err(self.poison(RingRefusal::IndexMisaligned {
                which: "tail",
                found: tail,
            }));
        }
        // The receiver's tail may only move forward from where it was, and never past head.
        if tail.wrapping_sub(self.tail_seen) > self.head.wrapping_sub(self.tail_seen) {
            return Err(self.poison(RingRefusal::IndexOutOfRange {
                which: "tail",
                found: tail,
                low: self.tail_seen,
                high: self.head,
            }));
        }
        self.tail_seen = tail;
        Ok(self.cfg.capacity as u64 - self.head.wrapping_sub(tail))
    }

    /// Write one record if it fits now. `Ok(false)`: the ring is full, nothing written.
    pub fn try_send(&mut self, payload: &[u8]) -> Result<bool, RingRefusal> {
        if let Some(r) = &self.poisoned {
            return Err(r.clone());
        }
        if self.closed {
            return Err(RingRefusal::SenderClosed);
        }
        if payload.len() > self.cfg.max_record {
            return Err(RingRefusal::RecordTooLarge {
                len: payload.len(),
                cap: self.cfg.max_record,
            });
        }
        let span = record_span(payload.len()) as u64;
        if self.free()? < span {
            return Ok(false);
        }
        let mut at = self.head;
        self.view
            .data(at)
            .store(payload.len() as u64, Ordering::Relaxed);
        self.view
            .data(at.wrapping_add(8))
            .store(self.seq, Ordering::Relaxed);
        at = at.wrapping_add(RECORD_HEADER_LEN as u64);
        for chunk in payload.chunks(8) {
            let mut word = [0u8; 8];
            word[..chunk.len()].copy_from_slice(chunk);
            self.view
                .data(at)
                .store(u64::from_le_bytes(word), Ordering::Relaxed);
            at = at.wrapping_add(8);
        }
        self.head = self.head.wrapping_add(span);
        self.seq += 1;
        self.view
            .ctl(layout::HEAD)
            .store(self.head, Ordering::Release);
        // Pairs with the receiver's fence between "I am sleeping" and its last look at head:
        // either it sees the new head, or this side sees it sleeping and rings.
        fence(Ordering::SeqCst);
        if self.view.ctl(layout::RX_SLEEPING).load(Ordering::Relaxed) != 0 {
            self.view.ring_doorbell();
        }
        Ok(true)
    }

    /// Write one record, waiting (polling, then yielding) while the ring is full.
    pub fn send(&mut self, payload: &[u8]) -> Result<(), RingRefusal> {
        let mut backoff = Backoff::new();
        while !self.try_send(payload)? {
            backoff.snooze();
        }
        Ok(())
    }

    /// Mark the ring closed: the receiver reads what was published, then sees the end.
    pub fn close(&mut self) {
        if !self.closed {
            self.closed = true;
            self.view.ctl(layout::CLOSED).store(1, Ordering::Release);
            self.view.ring_doorbell();
        }
    }

    /// Records written so far.
    pub fn records_sent(&self) -> u64 {
        self.seq
    }
}

impl Drop for RingSender {
    fn drop(&mut self) {
        self.close();
    }
}

/// What [`RingReceiver::try_recv`] found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecvStatus {
    /// One record was copied into the caller's buffer.
    Record,
    /// Nothing published yet.
    Empty,
    /// The sender closed and every published record was read.
    Closed,
}

/// The reading end of one ring.
pub struct RingReceiver {
    view: RingView,
    cfg: RingConfig,
    tail: u64,
    head_seen: u64,
    seq: u64,
    poisoned: Option<RingRefusal>,
}

impl RingReceiver {
    fn new(region: Arc<RingRegion>, ring: usize) -> Self {
        let cfg = *region.config();
        Self {
            view: RingView::new(region, ring),
            cfg,
            tail: cfg.start,
            head_seen: cfg.start,
            seq: 0,
            poisoned: None,
        }
    }

    fn poison(&mut self, r: RingRefusal) -> RingRefusal {
        self.poisoned = Some(r.clone());
        r
    }

    /// Copy the next record into `out` (replacing its contents) if one is published.
    pub fn try_recv(&mut self, out: &mut Vec<u8>) -> Result<RecvStatus, RingRefusal> {
        if let Some(r) = &self.poisoned {
            return Err(r.clone());
        }
        // Closed first, then head: a sender stores head before closed (both release), so
        // seeing closed means the head loaded next is final.
        let closed = self.view.ctl(layout::CLOSED).load(Ordering::Acquire) != 0;
        let head = self.view.ctl(layout::HEAD).load(Ordering::Acquire);
        if !head.is_multiple_of(8) {
            return Err(self.poison(RingRefusal::IndexMisaligned {
                which: "head",
                found: head,
            }));
        }
        let cap = self.cfg.capacity as u64;
        let available = head.wrapping_sub(self.tail);
        if available > cap {
            return Err(self.poison(RingRefusal::IndexOutOfRange {
                which: "head",
                found: head,
                low: self.tail,
                high: self.tail.wrapping_add(cap),
            }));
        }
        if available < self.head_seen.wrapping_sub(self.tail) {
            return Err(self.poison(RingRefusal::IndexRegressed {
                found: head,
                seen: self.head_seen,
            }));
        }
        self.head_seen = head;
        if available == 0 {
            return Ok(if closed {
                RecvStatus::Closed
            } else {
                RecvStatus::Empty
            });
        }
        if available < RECORD_HEADER_LEN as u64 {
            return Err(self.poison(RingRefusal::TornRecord {
                need: RECORD_HEADER_LEN as u64,
                available,
            }));
        }
        // Each header word is loaded once; the checks and the copy use these locals.
        let len = self.view.data(self.tail).load(Ordering::Relaxed);
        let seq = self
            .view
            .data(self.tail.wrapping_add(8))
            .load(Ordering::Relaxed);
        if len > self.cfg.max_record as u64 {
            return Err(self.poison(RingRefusal::LengthOverCap {
                declared: len,
                cap: self.cfg.max_record as u64,
            }));
        }
        let len = len as usize;
        let span = record_span(len) as u64;
        if span > available {
            return Err(self.poison(RingRefusal::TornRecord {
                need: span,
                available,
            }));
        }
        if seq != self.seq {
            return Err(self.poison(RingRefusal::SequenceMismatch {
                expected: self.seq,
                found: seq,
            }));
        }
        out.clear();
        out.reserve(len);
        let mut at = self.tail.wrapping_add(RECORD_HEADER_LEN as u64);
        let mut left = len;
        while left > 0 {
            let word = self.view.data(at).load(Ordering::Relaxed).to_le_bytes();
            let n = left.min(8);
            out.extend_from_slice(&word[..n]);
            left -= n;
            at = at.wrapping_add(8);
        }
        self.tail = self.tail.wrapping_add(span);
        self.seq += 1;
        self.view
            .ctl(layout::TAIL)
            .store(self.tail, Ordering::Release);
        Ok(RecvStatus::Record)
    }

    /// Copy the next record into `out`, waiting for it. `Ok(false)`: the sender closed and
    /// every record was read.
    pub fn recv(&mut self, out: &mut Vec<u8>) -> Result<bool, RingRefusal> {
        let started = Instant::now();
        let mut polls = 0u32;
        loop {
            match self.try_recv(out)? {
                RecvStatus::Record => return Ok(true),
                RecvStatus::Closed => return Ok(false),
                RecvStatus::Empty => {}
            }
            polls = polls.wrapping_add(1);
            if polls.is_multiple_of(64) && started.elapsed() >= self.cfg.spin {
                break;
            }
            std::hint::spin_loop();
        }
        loop {
            self.view
                .ctl(layout::RX_SLEEPING)
                .store(1, Ordering::SeqCst);
            fence(Ordering::SeqCst);
            let bell = self.view.ctl(layout::DOORBELL).load(Ordering::SeqCst);
            let status = self.try_recv(out);
            match status {
                Ok(RecvStatus::Empty) => {
                    doorbell_wait(self.view.ctl(layout::DOORBELL), bell, SLEEP_TIMEOUT)
                }
                other => {
                    self.view
                        .ctl(layout::RX_SLEEPING)
                        .store(0, Ordering::Relaxed);
                    return other.map(|s| s == RecvStatus::Record);
                }
            }
        }
    }

    /// Records accepted so far.
    pub fn records_received(&self) -> u64 {
        self.seq
    }
}

/// Polling, then yielding, then short sleeps.
struct Backoff {
    n: u32,
}

impl Backoff {
    fn new() -> Self {
        Self { n: 0 }
    }

    fn snooze(&mut self) {
        self.n = self.n.saturating_add(1);
        if self.n < 64 {
            std::hint::spin_loop();
        } else if self.n < 128 {
            std::thread::yield_now();
        } else {
            std::thread::sleep(Duration::from_micros(50));
        }
    }
}

#[cfg(all(target_os = "linux", target_pointer_width = "64"))]
fn doorbell_wait(word: &AtomicU64, seen: u64, timeout: Duration) {
    crate::shm::futex_wait(word, seen as u32, timeout);
}

#[cfg(all(target_os = "linux", target_pointer_width = "64"))]
fn doorbell_wake(word: &AtomicU64) {
    crate::shm::futex_wake(word);
}

#[cfg(not(all(target_os = "linux", target_pointer_width = "64")))]
fn doorbell_wait(_word: &AtomicU64, _seen: u64, _timeout: Duration) {
    std::thread::sleep(Duration::from_micros(50));
}

#[cfg(not(all(target_os = "linux", target_pointer_width = "64")))]
fn doorbell_wake(_word: &AtomicU64) {}

/// A byte stream over a region: writes are buffered and published as records on
/// [`std::io::Write::flush`] (split at `max_record`); reads return record bytes in order.
/// A ring refusal surfaces as an `InvalidData` I/O error carrying the [`RingRefusal`],
/// which the frame transport turns into `WireRingViolation`. Dropping the stream closes its
/// sender.
pub struct RingStream {
    tx: RingSender,
    rx: RingReceiver,
    out: Vec<u8>,
    inbuf: Vec<u8>,
    pos: usize,
}

impl RingStream {
    pub fn new(tx: RingSender, rx: RingReceiver) -> Self {
        Self {
            tx,
            rx,
            out: Vec::new(),
            inbuf: Vec::new(),
            pos: 0,
        }
    }

    /// Records (sent, received) so far.
    pub fn records(&self) -> (u64, u64) {
        (self.tx.records_sent(), self.rx.records_received())
    }
}

fn ring_io(r: RingRefusal) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidData, r)
}

impl std::io::Read for RingStream {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        while self.pos == self.inbuf.len() {
            self.pos = 0;
            if !self.rx.recv(&mut self.inbuf).map_err(ring_io)? {
                self.inbuf.clear();
                return Ok(0);
            }
        }
        let n = buf.len().min(self.inbuf.len() - self.pos);
        buf[..n].copy_from_slice(&self.inbuf[self.pos..self.pos + n]);
        self.pos += n;
        Ok(n)
    }
}

impl std::io::Write for RingStream {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.out.extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        let max = self.tx.cfg.max_record;
        for chunk in self.out.chunks(max) {
            self.tx.send(chunk).map_err(ring_io)?;
        }
        self.out.clear();
        Ok(())
    }
}
