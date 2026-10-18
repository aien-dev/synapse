//! D2 (ADR 0003 section 9 step 20): conflict entries stay inside the tree store's byte
//! accounting. Its own test binary, because the counting allocator is process-wide.

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicIsize, Ordering};
struct Counting;

static LIVE: AtomicIsize = AtomicIsize::new(0);

// SAFETY: every call forwards to the system allocator unchanged; only a counter is updated.
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let p = unsafe { System.alloc(layout) };
        if !p.is_null() {
            LIVE.fetch_add(layout.size() as isize, Ordering::Relaxed);
        }
        p
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) };
        LIVE.fetch_sub(layout.size() as isize, Ordering::Relaxed);
    }
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        let p = unsafe { System.alloc_zeroed(layout) };
        if !p.is_null() {
            LIVE.fetch_add(layout.size() as isize, Ordering::Relaxed);
        }
        p
    }
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        let p = unsafe { System.realloc(ptr, layout, new_size) };
        if !p.is_null() {
            LIVE.fetch_add(
                new_size as isize - layout.size() as isize,
                Ordering::Relaxed,
            );
        }
        p
    }
}

#[global_allocator]
static ALLOC: Counting = Counting;

use synapse_api::{TreeCacheConfig, TreeEdit, TreeFile, TreeStore};
use synapse_core::{reduce, BlobDigest, EntryState, FileMode, GitOid, Reduced, TreeDigest};

fn file(i: u64) -> TreeFile {
    let content = format!("content {i}\n");
    TreeFile {
        mode: FileMode::Regular644,
        blob_digest: BlobDigest::compute(content.as_bytes()),
        size_bytes: content.len() as u64,
        git_blob_oid: GitOid::compute_blob(content.as_bytes()),
    }
}

fn state(i: u64) -> EntryState {
    let f = file(i);
    EntryState::File {
        mode: f.mode,
        blob_digest: f.blob_digest,
        size_bytes: f.size_bytes,
    }
}

/// ADR 0003 step D2: conflict entries (their term vectors) are inside the tree store's memory
/// accounting. Same method as C1's heap test: a counting allocator, a bound small enough to
/// force eviction, and the live heap checked against the accounted total after every edit.
#[test]
fn d2_conflict_entries_are_inside_the_tree_store_accounting() {
    const MAX: usize = 2 * 1024 * 1024;
    let live_before = LIVE.load(Ordering::SeqCst);
    let mut store = TreeStore::new(TreeCacheConfig { max_bytes: MAX }).unwrap();
    let mut edit = TreeEdit::new(&mut store, TreeDigest::empty()).unwrap();
    for i in 0..4_000u64 {
        edit.upsert(&mut store, &format!("d{}/f{i}", i % 80), file(i))
            .unwrap();
    }
    let base = edit.finish(&mut store).unwrap();
    store.pin(base).unwrap();
    let mut worst_ratio = 0.0f64;
    for k in 0..2_000u64 {
        let mut edit = TreeEdit::new(&mut store, base).unwrap();
        for j in 0..3u64 {
            let i = (k * 7919 + j * 104_729) % 4_000;
            // Terms of 1 to 8 removes, built with spare capacity by cancellation.
            let n = 1 + (k + j) % 8;
            let mut adds: Vec<EntryState> =
                (0..=n).map(|x| state(10_000_000 + k * 100 + x)).collect();
            let mut removes: Vec<EntryState> =
                (0..n).map(|x| state(20_000_000 + k * 100 + x)).collect();
            adds.push(state(i));
            removes.push(state(i));
            let Reduced::Conflict(term) = reduce(adds, removes).unwrap() else {
                unreachable!("distinct states never resolve")
            };
            edit.set_conflict(&mut store, &format!("d{}/f{i}", i % 80), term)
                .unwrap();
        }
        let _root = edit.finish(&mut store).unwrap();
        let live = (LIVE.load(Ordering::SeqCst) - live_before) as usize;
        let s = store.stats();
        assert!(
            live <= s.total_bytes,
            "edit {k}: live heap {live} bytes exceeds the accounted {} bytes",
            s.total_bytes
        );
        assert!(
            s.total_bytes <= MAX,
            "edit {k}: accounted {} > bound {MAX}",
            s.total_bytes
        );
        worst_ratio = worst_ratio.max(live as f64 / s.total_bytes as f64);
    }
    let s = store.stats();
    assert!(s.nodes_evicted > 0, "the load must exceed the bound: {s:?}");
    // Never over the bound, not even between edits (C1 accounted hash tables by their reported
    // capacity, which drops as evictions leave deleted slots, and overshot under this load).
    assert!(
        s.high_water_bytes <= MAX,
        "high water {} > bound {MAX}",
        s.high_water_bytes
    );
    println!("d2 heap accounting: worst live/accounted = {worst_ratio:.3}; final stats {s:?}");
}
