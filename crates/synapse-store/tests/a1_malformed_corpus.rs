//! ADR 0003 A1 acceptance: a fixed corpus of truncated, bit-flipped, and oversized-length
//! frames is each refused with a typed refusal, with no panic and no allocation above
//! the frame's declared length cap.
//!
//! The corpus is generated deterministically from the v1 fixture records (one record of
//! each `WalRecord` kind, re-encoded as binary v2 frames) and from one binary checkpoint:
//! * every truncation of every frame (lengths 0 to len - 1);
//! * every single-bit flip of every frame;
//! * the header length field set to cap + 1, 2 x cap and `u32::MAX`;
//! * frames with valid checksums whose inner length or count fields declare remaining + 1,
//!   cap + 1 and `u32::MAX`;
//! * every truncation and every single-bit flip of the checkpoint file.
//!
//! A counting global allocator records the largest single allocation made by the calling
//! thread while a decode runs. The cap is `CAP` bytes, set just above the largest valid
//! frame so that it binds.

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::collections::BTreeMap;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::Path;
use synapse_core::{RefusalCode, SynapseError, WalSeq};
use synapse_store::codec::{
    decode_checkpoint_v2, encode_checkpoint_v2, encode_record, CheckpointState, CODEC_V2,
    WAL_FLAG_CODEC_V2,
};
use synapse_store::{
    decode_wal_frame, encode_wal_frame, wal_frame_from_payload, CheckpointManifest, RecordCodec,
    WalRecord, WAL_HEADER_LEN,
};

struct Counting;

thread_local! {
    static TRACK: Cell<bool> = const { Cell::new(false) };
    static PEAK: Cell<usize> = const { Cell::new(0) };
}

fn note(size: usize) {
    let _ = TRACK.try_with(|t| {
        if t.get() {
            let _ = PEAK.try_with(|p| p.set(p.get().max(size)));
        }
    });
}

unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        note(layout.size());
        System.alloc(layout)
    }
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        note(layout.size());
        System.alloc_zeroed(layout)
    }
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        note(new_size);
        System.realloc(ptr, layout, new_size)
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        System.dealloc(ptr, layout)
    }
}

#[global_allocator]
static GLOBAL: Counting = Counting;

/// Run `f` and return its result with the largest single allocation it made.
fn measured<T>(f: impl FnOnce() -> T) -> (std::thread::Result<T>, usize) {
    PEAK.with(|p| p.set(0));
    TRACK.with(|t| t.set(true));
    let r = catch_unwind(AssertUnwindSafe(f));
    TRACK.with(|t| t.set(false));
    (r, PEAK.with(|p| p.get()))
}

const CAP: u64 = 2048;

fn fixture(rel: &str) -> Vec<u8> {
    std::fs::read(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/a1-v1")
            .join(rel),
    )
    .unwrap()
}

/// First record of each kind from the v1 fixture log.
fn one_record_per_kind() -> Vec<WalRecord> {
    let log = fixture("v1-wal-log/wal.log");
    let mut by_kind = BTreeMap::new();
    let mut at = 0;
    while at < log.len() {
        let len = u32::from_le_bytes(log[at + 48..at + 52].try_into().unwrap()) as usize;
        let payload = &log[at + WAL_HEADER_LEN..at + WAL_HEADER_LEN + len];
        let r: WalRecord = serde_json::from_slice(payload).unwrap();
        by_kind.entry(r.kind_byte()).or_insert(r);
        at += WAL_HEADER_LEN + len;
    }
    assert_eq!(by_kind.len(), 6);
    by_kind.into_values().collect()
}

#[derive(Default)]
struct Tally {
    cases: usize,
    by_code: BTreeMap<String, usize>,
    peak: usize,
}

impl Tally {
    fn refused(
        &mut self,
        class: &str,
        what: &str,
        out: (std::thread::Result<Result<impl Sized, SynapseError>>, usize),
        allowed: &[RefusalCode],
    ) {
        let (r, peak) = out;
        let r = r.unwrap_or_else(|_| panic!("{class} {what}: decoder panicked"));
        let e = match r {
            Ok(_) => panic!("{class} {what}: accepted, expected a refusal"),
            Err(e) => e,
        };
        assert!(
            allowed.is_empty() || allowed.contains(&e.code),
            "{class} {what}: refused with {:?}, expected one of {allowed:?}: {}",
            e.code,
            e.message
        );
        assert!(
            peak as u64 <= CAP,
            "{class} {what}: allocated {peak} bytes, above the cap {CAP}"
        );
        self.cases += 1;
        self.peak = self.peak.max(peak);
        *self.by_code.entry(format!("{:?}", e.code)).or_default() += 1;
    }
}

/// Offsets of length or count fields inside the binary record of each kind, from the
/// documented layout (`codec.rs`): kind byte -> [(offset, minimum bytes per unit)].
fn length_fields(record: &WalRecord, bin: &[u8]) -> Vec<usize> {
    let u32_at = |o: usize| u32::from_le_bytes(bin[o..o + 4].try_into().unwrap()) as usize;
    match record {
        // version u16, then repo_id length; then base oid, then the parent count.
        WalRecord::ChangesetIngest { .. } => {
            let repo = 4;
            let parents = repo + 4 + u32_at(repo) + 20;
            vec![repo, parents]
        }
        // changeset id, then the first string's length.
        WalRecord::EvaluationAttached { .. } | WalRecord::ReviewRecorded { .. } => vec![34],
        // repo_id length first.
        WalRecord::GitProjected { .. } | WalRecord::CanonicalPromoted { .. } => vec![2],
        WalRecord::LeaseUpdated { .. } => vec![],
    }
}

#[test]
fn a1_malformed_frame_corpus_is_refused_typed_without_panic_or_allocation_above_the_cap() {
    let records = one_record_per_kind();
    let mut largest = 0;
    let mut frames = Vec::new();
    for r in &records {
        let (frame, _) =
            encode_wal_frame(WalSeq(1), [0u8; 32], r, RecordCodec::BinaryV2, CAP).unwrap();
        assert_eq!(frame[7], WAL_FLAG_CODEC_V2);
        largest = largest.max(frame.len() - WAL_HEADER_LEN);
        // Positive control: the undamaged frame decodes to its record.
        let (ok, peak) = measured(|| decode_wal_frame(&frame, CAP));
        let d = ok.unwrap().unwrap();
        assert_eq!(&d.record, r);
        assert_eq!(d.codec, RecordCodec::BinaryV2);
        assert_eq!(d.frame_len, frame.len());
        assert!(peak as u64 <= CAP);
        frames.push((r.clone(), frame));
    }
    assert!(
        (largest as u64) < CAP,
        "cap {CAP} must admit the largest valid payload {largest}"
    );

    let mut t: BTreeMap<&str, Tally> = BTreeMap::new();
    for (r, frame) in &frames {
        let kind = r.kind_byte();
        for n in 0..frame.len() {
            t.entry("truncated").or_default().refused(
                "truncated",
                &format!("kind {kind} to {n} bytes"),
                measured(|| decode_wal_frame(&frame[..n], CAP)),
                &[RefusalCode::WalTornFrame],
            );
        }
        for bit in 0..frame.len() * 8 {
            let mut f = frame.clone();
            f[bit / 8] ^= 1 << (bit % 8);
            t.entry("bit_flipped").or_default().refused(
                "bit_flipped",
                &format!("kind {kind} bit {bit}"),
                measured(|| decode_wal_frame(&f, CAP)),
                &[],
            );
        }
        for declared in [CAP + 1, 2 * CAP, u64::from(u32::MAX)] {
            let mut f = frame.clone();
            f[48..52].copy_from_slice(&(declared as u32).to_le_bytes());
            t.entry("oversized_frame_length").or_default().refused(
                "oversized_frame_length",
                &format!("kind {kind} declares {declared}"),
                measured(|| decode_wal_frame(&f, CAP)),
                &[RefusalCode::QuotaPayloadTooLarge],
            );
        }
        let bin = encode_record(r).unwrap();
        assert_eq!(bin[0], CODEC_V2);
        for off in length_fields(r, &bin) {
            for declared in [
                (bin.len() - off - 4 + 1) as u64,
                CAP + 1,
                u64::from(u32::MAX),
            ] {
                let mut p = bin.clone();
                p[off..off + 4].copy_from_slice(&(declared as u32).to_le_bytes());
                // Valid checksums: only the codec stands between this frame and replay.
                let (f, _) =
                    wal_frame_from_payload(WalSeq(1), [0u8; 32], kind, WAL_FLAG_CODEC_V2, &p);
                t.entry("oversized_inner_length").or_default().refused(
                    "oversized_inner_length",
                    &format!("kind {kind} field at {off} declares {declared}"),
                    measured(|| decode_wal_frame(&f, CAP)),
                    &[RefusalCode::WalRecordMalformed],
                );
            }
        }
    }

    // Checkpoint file: every truncation and every bit flip.
    let manifest: CheckpointManifest =
        serde_json::from_slice(&fixture("v1-wal-log/checkpoint.v1")).unwrap();
    let state = CheckpointState::from_v1_manifest(manifest).unwrap();
    let (ckpt, _) = encode_checkpoint_v2(&state, [1u8; 32], [2u8; 32]).unwrap();
    assert!(decode_checkpoint_v2(&ckpt).is_ok(), "positive control");
    for n in 0..ckpt.len() {
        t.entry("checkpoint_truncated").or_default().refused(
            "checkpoint_truncated",
            &format!("to {n} bytes"),
            measured(|| decode_checkpoint_v2(&ckpt[..n])),
            &[RefusalCode::CheckpointCorrupt],
        );
    }
    for bit in 0..ckpt.len() * 8 {
        let mut c = ckpt.clone();
        c[bit / 8] ^= 1 << (bit % 8);
        t.entry("checkpoint_bit_flipped").or_default().refused(
            "checkpoint_bit_flipped",
            &format!("bit {bit}"),
            measured(|| decode_checkpoint_v2(&c)),
            &[RefusalCode::CheckpointCorrupt],
        );
    }

    let mut total = 0;
    println!("A1 malformed corpus (cap {CAP} bytes, largest valid payload {largest} bytes):");
    for (class, tally) in &t {
        total += tally.cases;
        println!(
            "  {class}: {} refused, largest allocation {} bytes, codes {:?}",
            tally.cases, tally.peak, tally.by_code
        );
    }
    println!("  total: {total} refused, 0 panics, 0 accepted");
    for class in [
        "truncated",
        "bit_flipped",
        "oversized_frame_length",
        "oversized_inner_length",
        "checkpoint_truncated",
        "checkpoint_bit_flipped",
    ] {
        assert!(
            t.get(class).is_some_and(|x| x.cases > 0),
            "{class} is empty"
        );
    }
}
