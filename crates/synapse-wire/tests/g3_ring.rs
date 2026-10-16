//! G3 acceptance (ADR 0003 section 9 row 26): a hostile writer (bad lengths, index wrap,
//! torn frames) cannot make the reader panic, read outside the ring, or accept a frame
//! twice; no frame is lost or duplicated in a model test. Supporting: the sealed shared
//! region, two processes, a hostile reader, and the G1 session carried over the ring.
//!
//! "Read outside the ring": every ring access is a bounds-checked slice index of the
//! region's words, so an out-of-ring position would panic instead of reading. The tests
//! below therefore check "no panic" under `catch_unwind` for every hostile input, and the
//! negative control shows that a reader without the masking and checks does panic (that
//! is, would read outside the ring if it were written with raw pointers) on the same inputs.

use std::collections::VecDeque;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use synapse_core::RefusalCode;
use synapse_wire::frame::{decode_frame, encode_frame, WireLimits};
use synapse_wire::ring::{layout, record_span, RecvStatus, CONTROL_WORDS, RECORD_HEADER_LEN};
use synapse_wire::session::submit_request;
use synapse_wire::testkit::{envelope, open_store, sample_frames, server, temp_dir, ChainFixture};
use synapse_wire::{
    FrameConn, RingConfig, RingReceiver, RingRefusal, RingRegion, RingSender, Side, WireClient,
};

// ---------------------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------------------

struct SplitMix(u64);

impl SplitMix {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }
}

fn cfg(capacity: usize, max_record: usize, start: u64) -> RingConfig {
    RingConfig {
        capacity,
        max_record,
        start,
        spin: Duration::from_micros(20),
    }
}

/// Starts that cross the 2^64 index wrap, the data-area wrap, and the plain case.
const STARTS: [u64; 4] = [0, u64::MAX - 7, u64::MAX - 7 - 128, 1 << 63];

/// Ring 0 is written by the creator and read by the attacher: the tests play a hostile
/// creator by writing ring 0's words directly, and read with the attacher's receiver.
fn hostile_ring(c: RingConfig) -> (Arc<RingRegion>, RingSender, RingReceiver) {
    let region = RingRegion::in_process(c).unwrap();
    let (tx, _) = region.endpoints(Side::Creator);
    let (_, rx) = region.endpoints(Side::Attacher);
    (region, tx, rx)
}

fn ctl(region: &RingRegion, off: usize) -> &AtomicU64 {
    &region.words()[region.config().ring_base(0) + off]
}

fn data(region: &RingRegion, index: u64) -> &AtomicU64 {
    let c = region.config();
    let pos = ((index / 8) as usize) & (c.capacity / 8 - 1);
    &region.words()[c.ring_base(0) + CONTROL_WORDS + pos]
}

/// Payload `i` of `len` bytes: the record number in the first bytes, then a pattern.
fn payload(i: u64, len: usize) -> Vec<u8> {
    let mut v: Vec<u8> = (0..len)
        .map(|j| (i as u8).wrapping_mul(31).wrapping_add(j as u8))
        .collect();
    let n = len.min(8);
    v[..n].copy_from_slice(&i.to_le_bytes()[..n]);
    v
}

/// Run `f` and require that it does not panic.
fn no_panic<T>(what: &str, f: impl FnOnce() -> T) -> T {
    match catch_unwind(AssertUnwindSafe(f)) {
        Ok(v) => v,
        Err(_) => panic!("reader panicked on hostile input: {what}"),
    }
}

/// After a refusal the receiver stays refused with the same refusal.
fn assert_poisoned(rx: &mut RingReceiver, first: &RingRefusal) {
    let mut out = Vec::new();
    for _ in 0..3 {
        assert_eq!(rx.try_recv(&mut out).as_ref(), Err(first));
    }
}

// ---------------------------------------------------------------------------------------
// Hostile writer: bad lengths
// ---------------------------------------------------------------------------------------

#[test]
fn hostile_writer_bad_lengths_cannot_make_the_reader_panic_or_read_outside_the_ring() {
    let (capacity, max_record) = (256usize, 120usize);
    // (declared len, bytes published, expected refusal kind)
    let cases: [(u64, u64, &str); 9] = [
        (max_record as u64 + 1, 256, "LengthOverCap"),
        (u64::MAX, 64, "LengthOverCap"),
        (u64::MAX - 7, 64, "LengthOverCap"),
        (1 << 63, 64, "LengthOverCap"),
        (capacity as u64, 256, "LengthOverCap"),
        (usize::MAX as u64 - 15, 256, "LengthOverCap"),
        // A legal length whose payload was not all published.
        (100, 64, "TornRecord"),
        (max_record as u64, 128, "TornRecord"),
        (9, 24, "TornRecord"),
    ];
    for start in STARTS {
        for (len, published, kind) in cases {
            let (region, _tx, mut rx) = hostile_ring(cfg(capacity, max_record, start));
            data(&region, start).store(len, Ordering::Relaxed);
            data(&region, start.wrapping_add(8)).store(0, Ordering::Relaxed);
            ctl(&region, layout::HEAD).store(start.wrapping_add(published), Ordering::Release);
            let mut out = Vec::new();
            let got = no_panic(&format!("len {len} published {published}"), || {
                rx.try_recv(&mut out)
            });
            let err = got.expect_err("hostile length accepted");
            assert_eq!(err.kind(), kind, "len {len} published {published}: {err:?}");
            assert!(out.is_empty(), "bytes delivered for a refused record");
            assert_eq!(rx.records_received(), 0);
            assert_poisoned(&mut rx, &err);
        }
    }
}

// ---------------------------------------------------------------------------------------
// Hostile writer: index wrap
// ---------------------------------------------------------------------------------------

#[test]
fn hostile_writer_index_wrap_cannot_make_the_reader_panic_or_read_outside_the_ring() {
    let capacity = 256u64;
    for start in STARTS {
        // (published head, expected refusal kind)
        let cases: [(u64, &str); 8] = [
            (start.wrapping_add(capacity + 8), "IndexOutOfRange"),
            (start.wrapping_add(u64::MAX - 7), "IndexOutOfRange"),
            (start.wrapping_sub(8), "IndexOutOfRange"),
            (start.wrapping_add(1 << 63), "IndexOutOfRange"),
            (start ^ (1 << 62), "IndexOutOfRange"),
            (start.wrapping_add(4), "IndexMisaligned"),
            (start.wrapping_add(capacity + 1), "IndexMisaligned"),
            (u64::MAX, "IndexMisaligned"),
        ];
        for (head, kind) in cases {
            let (region, _tx, mut rx) = hostile_ring(cfg(capacity as usize, 64, start));
            ctl(&region, layout::HEAD).store(head, Ordering::Release);
            let mut out = Vec::new();
            let err = no_panic(&format!("start {start} head {head}"), || {
                rx.try_recv(&mut out)
            })
            .expect_err("hostile head accepted");
            assert_eq!(err.kind(), kind, "start {start} head {head}: {err:?}");
            assert_poisoned(&mut rx, &err);
        }

        // Head moved back behind a value the reader already saw (but not behind its tail).
        let (region, mut tx, mut rx) = hostile_ring(cfg(capacity as usize, 64, start));
        let mut out = Vec::new();
        tx.try_send(&payload(0, 10)).unwrap();
        let after_one = ctl(&region, layout::HEAD).load(Ordering::Acquire);
        tx.try_send(&payload(1, 10)).unwrap();
        assert_eq!(rx.try_recv(&mut out), Ok(RecvStatus::Record));
        ctl(&region, layout::HEAD).store(after_one, Ordering::Release);
        let err = no_panic("head regressed", || rx.try_recv(&mut out)).unwrap_err();
        assert_eq!(err.kind(), "IndexRegressed", "{err:?}");
        assert_eq!(rx.records_received(), 1);
    }
}

#[test]
fn honest_indices_wrap_past_u64_max_and_the_ring_end_without_loss() {
    for start in STARTS {
        let (_region, mut tx, mut rx) = hostile_ring(cfg(128, 100, start));
        let mut out = Vec::new();
        for i in 0..2_000u64 {
            let p = payload(i, (i % 101) as usize);
            assert!(
                tx.try_send(&p).unwrap(),
                "record {i} did not fit an empty ring"
            );
            assert_eq!(rx.try_recv(&mut out), Ok(RecvStatus::Record));
            assert_eq!(out, p, "record {i} start {start}");
        }
        assert_eq!(rx.try_recv(&mut out), Ok(RecvStatus::Empty));
    }
}

// ---------------------------------------------------------------------------------------
// Hostile writer: torn frames
// ---------------------------------------------------------------------------------------

#[test]
fn hostile_writer_torn_frames_are_refused_and_payloads_are_copied_out_before_validation() {
    // 1. A record published before its payload was written: head ends inside it.
    for start in STARTS {
        for published in [8u64, 16, 24, 40] {
            let (region, _tx, mut rx) = hostile_ring(cfg(256, 200, start));
            data(&region, start).store(64, Ordering::Relaxed);
            ctl(&region, layout::HEAD).store(start.wrapping_add(published), Ordering::Release);
            let mut out = Vec::new();
            let err = no_panic("torn record", || rx.try_recv(&mut out)).unwrap_err();
            assert_eq!(err.kind(), "TornRecord", "{err:?}");
        }
    }

    // 2. A frame cut across a record that is then closed: the G1 stream reader refuses it
    //    with a typed refusal, never a panic or a partial frame.
    let frame = sample_frames()
        .iter()
        .map(|f| encode_frame(f).unwrap())
        .max_by_key(Vec::len)
        .unwrap();
    for cut in [1usize, 8, 15, 16, 17, frame.len() / 2, frame.len() - 1] {
        let region = RingRegion::in_process(cfg(1 << 16, 1 << 14, 0)).unwrap();
        let (mut tx, _) = region.endpoints(Side::Creator);
        tx.send(&frame[..cut]).unwrap();
        tx.close();
        let mut conn = FrameConn::new(region.stream(Side::Attacher), WireLimits::default());
        let err = no_panic("torn frame", || conn.recv()).unwrap_err();
        assert_eq!(
            err.code,
            RefusalCode::WireFrameMalformed,
            "cut {cut}: {err:?}"
        );
    }

    // 3. Garbage where a frame should be: typed refusal from the frame decoder.
    let region = RingRegion::in_process(cfg(1 << 16, 1 << 14, 0)).unwrap();
    let (mut tx, _) = region.endpoints(Side::Creator);
    let mut bad = frame.clone();
    bad[0] ^= 0xFF;
    tx.send(&bad).unwrap();
    let mut conn = FrameConn::new(region.stream(Side::Attacher), WireLimits::default());
    assert_eq!(
        conn.recv().unwrap_err().code,
        RefusalCode::WireFrameMalformed
    );

    // 4. The writer keeps rewriting the record's bytes while the reader copies it out. The
    //    reader validates its own copy, so deciding twice on that copy gives the same
    //    answer whatever the writer does meanwhile.
    let frames: Vec<Vec<u8>> = sample_frames()
        .iter()
        .map(|f| encode_frame(f).unwrap())
        .collect();
    // A mutator that races the sender can also land on a header word; the reader then
    // refuses (and is poisoned), and the next round starts on a fresh region.
    let (mut decoded, mut refused, mut ring_refused) = (0u32, 0u32, 0u32);
    for round in 0..200u64 {
        if decoded + refused >= 5_000 {
            break;
        }
        let region = RingRegion::in_process(cfg(1 << 12, 1 << 11, u64::MAX - 7)).unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let mutator = {
            let (region, stop) = (region.clone(), stop.clone());
            std::thread::spawn(move || {
                let mut r = SplitMix(round);
                let c = *region.config();
                let base = c.ring_base(0) + CONTROL_WORDS;
                while !stop.load(Ordering::Relaxed) {
                    // Only words above 2^20: payload words, not a record header (len at
                    // most max_record, seq below 2,000) unless the race described above.
                    let w = &region.words()[base + r.below((c.capacity / 8) as u64) as usize];
                    let v = w.load(Ordering::Relaxed);
                    if v > 1 << 20 {
                        w.store(v ^ (1 << r.below(64)), Ordering::Relaxed);
                    }
                }
            })
        };
        let (mut tx, _) = region.endpoints(Side::Creator);
        let (_, mut rx) = region.endpoints(Side::Attacher);
        let mut out = Vec::new();
        for i in 0..2_000usize {
            if tx.try_send(&frames[i % frames.len()]).is_err() {
                break;
            }
            match no_panic("record rewritten during copy", || rx.try_recv(&mut out)) {
                Ok(RecvStatus::Record) => {
                    let a = decode_frame(&out, &WireLimits::default());
                    let b = decode_frame(&out, &WireLimits::default());
                    assert_eq!(a, b, "decision changed on the private copy");
                    if a.is_ok() {
                        decoded += 1
                    } else {
                        refused += 1
                    }
                }
                Ok(other) => panic!("published record not read: {other:?}"),
                Err(_) => {
                    ring_refused += 1;
                    break;
                }
            }
        }
        stop.store(true, Ordering::Relaxed);
        mutator.join().unwrap();
    }
    // Both outcomes of validating a rewritten copy were reached.
    assert!(
        decoded > 0 && refused > 0,
        "decoded {decoded} refused {refused} ring refusals {ring_refused}"
    );
}

// ---------------------------------------------------------------------------------------
// Hostile writer: no record accepted twice
// ---------------------------------------------------------------------------------------

#[test]
fn hostile_writer_cannot_make_the_reader_accept_a_record_twice() {
    for start in STARTS {
        let c = cfg(256, 64, start);
        let mut out = Vec::new();

        // Replay: the writer copies record 0 (sequence 0) to the next position.
        let (region, mut tx, mut rx) = hostile_ring(c);
        let p0 = payload(0, 20);
        tx.try_send(&p0).unwrap();
        assert_eq!(rx.try_recv(&mut out), Ok(RecvStatus::Record));
        let span = record_span(p0.len()) as u64;
        for k in 0..span / 8 {
            let v = data(&region, start.wrapping_add(8 * k)).load(Ordering::Relaxed);
            data(&region, start.wrapping_add(span + 8 * k)).store(v, Ordering::Relaxed);
        }
        ctl(&region, layout::HEAD).store(start.wrapping_add(2 * span), Ordering::Release);
        let err = no_panic("replayed record", || rx.try_recv(&mut out)).unwrap_err();
        assert_eq!(
            err,
            RingRefusal::SequenceMismatch {
                expected: 1,
                found: 0
            }
        );
        assert_eq!(rx.records_received(), 1);

        // Rewind: the writer moves head back behind a record already read, to republish it.
        let (region, mut tx, mut rx) = hostile_ring(c);
        tx.try_send(&payload(0, 20)).unwrap();
        assert_eq!(rx.try_recv(&mut out), Ok(RecvStatus::Record));
        ctl(&region, layout::HEAD).store(start, Ordering::Release);
        let err = no_panic("rewound head", || rx.try_recv(&mut out)).unwrap_err();
        assert_eq!(err.kind(), "IndexOutOfRange", "{err:?}");
        ctl(&region, layout::HEAD).store(start.wrapping_add(span), Ordering::Release);
        assert_eq!(rx.try_recv(&mut out), Err(err));
        assert_eq!(rx.records_received(), 1);

        // The writer resets the shared tail word (the reader's published position): the
        // reader keeps its own tail, so the record is not read again.
        let (region, mut tx, mut rx) = hostile_ring(c);
        tx.try_send(&payload(0, 20)).unwrap();
        tx.try_send(&payload(1, 20)).unwrap();
        assert_eq!(rx.try_recv(&mut out), Ok(RecvStatus::Record));
        assert_eq!(out, payload(0, 20));
        ctl(&region, layout::TAIL).store(start, Ordering::Release);
        assert_eq!(rx.try_recv(&mut out), Ok(RecvStatus::Record));
        assert_eq!(out, payload(1, 20));
        assert_eq!(rx.try_recv(&mut out), Ok(RecvStatus::Empty));
        assert_eq!(rx.records_received(), 2);

        // Skip: a record whose sequence number jumps ahead is refused (nothing skipped).
        let (region, _tx, mut rx) = hostile_ring(c);
        data(&region, start).store(4, Ordering::Relaxed);
        data(&region, start.wrapping_add(8)).store(5, Ordering::Relaxed);
        ctl(&region, layout::HEAD).store(start.wrapping_add(24), Ordering::Release);
        let err = rx.try_recv(&mut out).unwrap_err();
        assert_eq!(err.kind(), "SequenceMismatch");
    }
}

/// Random hostile pokes of control and data words, interleaved with honest sends. Checks,
/// per step: no panic; a delivered record is no longer than `max_record`; the receiver's
/// accepted count rises by exactly one per delivered record and never otherwise; once
/// refused it stays refused. Records delivered before the first poke equal what was sent.
#[test]
fn hostile_writer_random_pokes_never_panic_and_never_deliver_a_record_twice() {
    let mut kinds = std::collections::BTreeMap::<&'static str, u32>::new();
    let boundary = |r: &mut SplitMix, start: u64, cap: u64| -> u64 {
        let v = [
            0,
            1,
            7,
            8,
            16,
            cap - 8,
            cap,
            cap + 8,
            u64::MAX,
            u64::MAX - 7,
            1 << 63,
            r.next(),
        ];
        let base = if r.below(2) == 0 { start } else { 0 };
        base.wrapping_add(v[r.below(v.len() as u64) as usize])
    };
    for seed in 0..3_000u64 {
        let mut r = SplitMix(seed);
        let start = STARTS[(seed % 4) as usize];
        let c = cfg(256, 96, start);
        let (region, mut tx, mut rx) = hostile_ring(c);
        let mut out = Vec::new();
        let mut sent = VecDeque::new();
        let mut poked = false;
        let mut refused: Option<RingRefusal> = None;
        for step in 0..200u32 {
            match r.below(8) {
                0..=2 => {
                    let i = u64::from(step);
                    let p = payload(i, r.below(97) as usize);
                    if let Ok(true) = tx.try_send(&p) {
                        sent.push_back(p);
                    }
                }
                3 => {
                    poked = true;
                    let off = [
                        layout::HEAD,
                        layout::TAIL,
                        layout::CLOSED,
                        layout::DOORBELL,
                        layout::RX_SLEEPING,
                    ][r.below(5) as usize];
                    ctl(&region, off).store(boundary(&mut r, start, 256), Ordering::Release);
                }
                4 => {
                    poked = true;
                    let at = start.wrapping_add(8 * r.below(32));
                    data(&region, at).store(boundary(&mut r, 0, 96), Ordering::Relaxed);
                }
                _ => {
                    let before = rx.records_received();
                    let got = no_panic(&format!("seed {seed} step {step}"), || {
                        rx.try_recv(&mut out)
                    });
                    match got {
                        Ok(RecvStatus::Record) => {
                            assert!(refused.is_none(), "delivered after a refusal");
                            assert_eq!(rx.records_received(), before + 1);
                            assert!(out.len() <= c.max_record);
                            let want = sent.pop_front();
                            if !poked {
                                assert_eq!(Some(&out), want.as_ref(), "seed {seed}");
                            }
                        }
                        Ok(_) => assert_eq!(rx.records_received(), before),
                        Err(e) => {
                            assert_eq!(rx.records_received(), before);
                            if let Some(first) = &refused {
                                assert_eq!(&e, first, "refusal changed");
                            } else {
                                *kinds.entry(e.kind()).or_default() += 1;
                                refused = Some(e);
                            }
                        }
                    }
                }
            }
        }
    }
    // The pokes reach every peer-fault check (the detectors are live).
    for k in [
        "IndexOutOfRange",
        "IndexMisaligned",
        "IndexRegressed",
        "TornRecord",
        "LengthOverCap",
        "SequenceMismatch",
    ] {
        assert!(kinds.contains_key(k), "{k} never hit: {kinds:?}");
    }
}

/// Negative control: a reader that trusts the writer (no masking, no length, index or
/// sequence check) fails on the same hostile inputs, so the tests above can fail.
#[test]
fn negative_control_trusting_reader_panics_or_accepts_twice_on_the_same_inputs() {
    /// Reads like `try_recv` but trusts every word it loads.
    fn trusting_recv(region: &RingRegion, tail: &mut u64, out: &mut Vec<u8>) -> bool {
        let c = region.config();
        let base = c.ring_base(0);
        let w = region.words();
        let head = w[base + layout::HEAD].load(Ordering::Acquire);
        if head == *tail {
            return false;
        }
        // No mask: the position is used as given.
        let at = |i: u64| base + CONTROL_WORDS + (i / 8) as usize % (1 << 40);
        let len = w[at(*tail)].load(Ordering::Relaxed) as usize;
        out.clear();
        for k in 0..len.div_ceil(8) {
            let word = w[at(tail.wrapping_add(16 + 8 * k as u64))].load(Ordering::Relaxed);
            out.extend_from_slice(&word.to_le_bytes());
        }
        out.truncate(len);
        *tail = tail.wrapping_add(record_span(len) as u64);
        true
    }

    // Bad length: reads past the ring, which in safe Rust is a panic.
    let (region, _tx, _rx) = hostile_ring(cfg(256, 120, 0));
    data(&region, 0).store(4096, Ordering::Relaxed);
    ctl(&region, layout::HEAD).store(64, Ordering::Release);
    let mut out = Vec::new();
    let mut tail = 0u64;
    assert!(
        catch_unwind(AssertUnwindSafe(|| trusting_recv(
            &region, &mut tail, &mut out
        )))
        .is_err(),
        "trusting reader survived a bad length"
    );

    // Index wrap: an honest record near the end of the index space, read without the mask.
    let (region, mut tx, _rx) = hostile_ring(cfg(256, 120, u64::MAX - 7));
    tx.try_send(&payload(0, 40)).unwrap();
    let mut tail = u64::MAX - 7;
    assert!(
        catch_unwind(AssertUnwindSafe(|| trusting_recv(
            &region, &mut tail, &mut out
        )))
        .is_err(),
        "trusting reader survived the index wrap"
    );

    // Replay: the trusting reader accepts record 0 twice.
    let (region, mut tx, _rx) = hostile_ring(cfg(256, 64, 0));
    let p0 = payload(0, 20);
    tx.try_send(&p0).unwrap();
    let mut tail = 0u64;
    assert!(trusting_recv(&region, &mut tail, &mut out));
    let span = record_span(p0.len()) as u64;
    for k in 0..span / 8 {
        let v = data(&region, 8 * k).load(Ordering::Relaxed);
        data(&region, span + 8 * k).store(v, Ordering::Relaxed);
    }
    ctl(&region, layout::HEAD).store(2 * span, Ordering::Release);
    assert!(trusting_recv(&region, &mut tail, &mut out));
    assert_eq!(out, p0, "the trusting reader accepted record 0 twice");
}

// ---------------------------------------------------------------------------------------
// Model test: nothing lost, nothing duplicated
// ---------------------------------------------------------------------------------------

/// A random schedule of sends and receives against a queue model, over small rings that
/// wrap thousands of times, with starts on both sides of the 2^64 index wrap. Every record
/// received equals the model's next record; a full ring is full by the model's own count;
/// after close, the ring drains exactly the model and then reports the end.
#[test]
fn model_test_no_frame_is_lost_or_duplicated() {
    let mut total = 0u64;
    for seed in 0..400u64 {
        let mut r = SplitMix(seed ^ 0xD1CE);
        let capacity = [64usize, 128, 256, 1024][(seed % 4) as usize];
        let max_record =
            [1usize, 8, capacity / 2, capacity - RECORD_HEADER_LEN][(seed / 4 % 4) as usize];
        let start = STARTS[(seed / 16 % 4) as usize];
        let (_region, mut tx, mut rx) = hostile_ring(cfg(capacity, max_record, start));
        let mut model: VecDeque<Vec<u8>> = VecDeque::new();
        let mut in_ring = 0usize;
        let mut out = Vec::new();
        let mut next = 0u64;
        for _ in 0..3_000 {
            if r.below(2) == 0 {
                let len = if r.below(4) == 0 {
                    max_record
                } else {
                    r.below(max_record as u64 + 1) as usize
                };
                let p = payload(next, len);
                let fits = in_ring + record_span(len) <= capacity;
                assert_eq!(
                    tx.try_send(&p),
                    Ok(fits),
                    "seed {seed}: full by model {fits}"
                );
                if fits {
                    in_ring += record_span(len);
                    model.push_back(p);
                    next += 1;
                }
            } else {
                match rx.try_recv(&mut out).unwrap() {
                    RecvStatus::Record => {
                        let want = model.pop_front().expect("record the model never sent");
                        assert_eq!(out, want, "seed {seed}");
                        in_ring -= record_span(want.len());
                        total += 1;
                    }
                    RecvStatus::Empty => assert!(model.is_empty(), "seed {seed}: lost record"),
                    RecvStatus::Closed => panic!("closed before close"),
                }
            }
        }
        tx.close();
        while let Some(want) = model.pop_front() {
            assert_eq!(rx.try_recv(&mut out), Ok(RecvStatus::Record));
            assert_eq!(out, want);
            total += 1;
        }
        assert_eq!(rx.try_recv(&mut out), Ok(RecvStatus::Closed));
        assert_eq!(rx.records_received(), tx.records_sent());
    }
    assert!(total > 100_000, "model exercised only {total} records");
}

/// Two threads over a sealed shared mapping, the receiver on a second mapping of the same
/// memory: every record arrives once, in order, intact.
#[cfg(target_os = "linux")]
#[test]
fn model_test_two_threads_two_mappings_no_record_lost_or_duplicated() {
    let c = cfg(1 << 12, 1 << 10, u64::MAX - 1023);
    let region = RingRegion::create_shared(c).unwrap();
    let other = RingRegion::attach_shared(&region.attach_path().unwrap(), c).unwrap();
    let n = 200_000u64;
    let writer = {
        let region = region.clone();
        std::thread::spawn(move || {
            let (mut tx, _) = region.endpoints(Side::Creator);
            for i in 0..n {
                tx.send(&payload(i, (i % 1025) as usize)).unwrap();
            }
        })
    };
    let (_, mut rx) = other.endpoints(Side::Attacher);
    let mut out = Vec::new();
    let mut i = 0u64;
    while rx.recv(&mut out).unwrap() {
        assert_eq!(out, payload(i, (i % 1025) as usize), "record {i}");
        i += 1;
    }
    writer.join().unwrap();
    assert_eq!(i, n);
}

// ---------------------------------------------------------------------------------------
// Shared region, processes, hostile reader, session
// ---------------------------------------------------------------------------------------

#[cfg(target_os = "linux")]
#[test]
fn attached_peer_cannot_shrink_or_grow_the_sealed_region() {
    let c = cfg(1 << 12, 1 << 10, 0);
    let region = RingRegion::create_shared(c).unwrap();
    let f = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(region.attach_path().unwrap())
        .unwrap();
    assert!(f.set_len(64).is_err(), "peer shrank the region");
    assert!(f.set_len(1 << 24).is_err(), "peer grew the region");
    assert_eq!(f.metadata().unwrap().len(), c.region_bytes() as u64);
}

#[cfg(target_os = "linux")]
#[test]
fn attach_refuses_an_unsealed_wrong_size_or_mismatched_region() {
    let c = cfg(1 << 12, 1 << 10, 0);
    // An ordinary file of the right size: no seals, so the peer could shrink it.
    let dir = temp_dir("g3-unsealed");
    let path = dir.join("ring");
    std::fs::write(&path, vec![0u8; c.region_bytes()]).unwrap();
    let err = RingRegion::attach_shared(&path, c).err().unwrap();
    assert_eq!(err.code, RefusalCode::WireRingViolation, "{err:?}");
    assert!(err.message.contains("RegionNotSealed"), "{}", err.message);

    let region = RingRegion::create_shared(c).unwrap();
    let path = region.attach_path().unwrap();
    let bigger = RingConfig {
        capacity: 1 << 13,
        ..c
    };
    let err = RingRegion::attach_shared(&path, bigger).err().unwrap();
    assert!(err.message.contains("RegionSize"), "{}", err.message);
    let moved = RingConfig { start: 64, ..c };
    let err = RingRegion::attach_shared(&path, moved).err().unwrap();
    assert!(err.message.contains("HeaderMismatch"), "{}", err.message);
}

#[cfg(target_os = "linux")]
#[test]
fn cross_process_ring_delivers_every_record_once_in_order() {
    const ENV: &str = "SYNAPSE_G3_CHILD_RING";
    const N: u64 = 50_000;
    let c = cfg(1 << 14, 1 << 12, u64::MAX - 4095);
    if let Ok(path) = std::env::var(ENV) {
        // Child: attach and send on ring 1.
        let region = RingRegion::attach_shared(std::path::Path::new(&path), c).unwrap();
        let (mut tx, _) = region.endpoints(Side::Attacher);
        for i in 0..N {
            tx.send(&payload(i, (i % 4097) as usize)).unwrap();
        }
        return;
    }
    let region = RingRegion::create_shared(c).unwrap();
    let mut child = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "cross_process_ring_delivers_every_record_once_in_order",
            "--test-threads=1",
            "--quiet",
        ])
        .env(ENV, region.attach_path().unwrap())
        .stdout(std::process::Stdio::null())
        .spawn()
        .unwrap();
    let (_, mut rx) = region.endpoints(Side::Creator);
    let mut out = Vec::new();
    let mut i = 0u64;
    while rx.recv(&mut out).unwrap() {
        assert_eq!(out, payload(i, (i % 4097) as usize), "record {i}");
        i += 1;
    }
    assert!(child.wait().unwrap().success());
    assert_eq!(i, N);
}

#[test]
fn hostile_reader_tail_is_refused_by_the_sender() {
    for start in STARTS {
        for (tail, kind) in [
            (start.wrapping_add(64), "IndexOutOfRange"),
            (start.wrapping_sub(8), "IndexOutOfRange"),
            (start.wrapping_add(1 << 63), "IndexOutOfRange"),
            (start.wrapping_add(3), "IndexMisaligned"),
        ] {
            let (region, mut tx, _rx) = hostile_ring(cfg(256, 64, start));
            tx.try_send(&payload(0, 8)).unwrap();
            ctl(&region, layout::TAIL).store(tail, Ordering::Release);
            let err = no_panic("hostile tail", || tx.try_send(&payload(1, 8))).unwrap_err();
            assert_eq!(err.kind(), kind, "start {start} tail {tail}: {err:?}");
        }
    }
}

#[test]
fn ring_refusal_reaches_the_frame_transport_as_wire_ring_violation() {
    let (region, _tx, _rx) = hostile_ring(cfg(1 << 12, 1 << 10, 0));
    ctl(&region, layout::HEAD).store(1 << 20, Ordering::Release);
    let mut conn = FrameConn::new(region.stream(Side::Attacher), WireLimits::default());
    let err = conn.recv().unwrap_err();
    assert_eq!(err.code, RefusalCode::WireRingViolation, "{err:?}");
}

#[cfg(target_os = "linux")]
#[test]
fn ring_stream_carries_the_g1_session_and_acknowledges_durable_changes() {
    let dir = temp_dir("g3-session");
    let fx = ChainFixture::new(2, None);
    let mut last = None;
    {
        let region = RingRegion::create_shared(RingConfig::default()).unwrap();
        let store = open_store(&dir);
        let srv = server(&fx, store.clone());
        let path = region.attach_path().unwrap();
        let attached = RingRegion::attach_shared(&path, RingConfig::default()).unwrap();
        let s = srv.clone();
        let t = std::thread::spawn(move || s.serve(attached.stream(Side::Attacher)));
        let mut client =
            WireClient::connect(region.stream(Side::Creator), WireLimits::default()).unwrap();
        let shared: Vec<u8> = (0..3000).map(|i| (i * 7) as u8).collect();
        for i in 0..20u64 {
            let new: Vec<u8> = (0..3967).map(|j| (i as usize * 13 + j) as u8).collect();
            let (p_new, p_shared) = (format!("ring/c{i}.rs"), format!("ring/s{i}.rs"));
            let (env, blobs) = envelope(
                &fx.agent,
                &format!("ring-{i}"),
                &[(p_new.as_str(), new), (p_shared.as_str(), shared.clone())],
                &[],
                100 + i,
            );
            let mut nonce = [0u8; 32];
            nonce[..8].copy_from_slice(&i.to_le_bytes());
            let req = submit_request(&fx.agent, fx.chain.clone(), &env, nonce, 100 + i).unwrap();
            let rep = client.submit(&req, &blobs).unwrap();
            assert!(!rep.accepted.duplicate);
            assert_eq!(rep.wanted, if i == 0 { 2 } else { 1 }, "change {i}");
            last = Some(rep.accepted.wal_seq);
        }
        assert_eq!(store.read().committed_seq(), last.unwrap());
        drop(client);
        let stats = t.join().unwrap().unwrap();
        assert!(stats.frames_received >= 60);
    }
    // Durable: a fresh open of the directory sees every acknowledged change.
    let reopened = open_store(&dir);
    assert_eq!(reopened.read().committed_seq(), last.unwrap());
}
