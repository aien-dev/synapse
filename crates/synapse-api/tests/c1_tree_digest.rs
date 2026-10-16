//! C1 (ADR 0003 section 9 step 4): the tree store's byte accounting never falls below the
//! heap it really holds, so "accounted bytes <= bound" implies "heap <= bound".
//!
//! A counting global allocator tracks live heap bytes (requested sizes). This binary holds a
//! single test so no other test allocates concurrently. The store is driven past its bound
//! (evicting) with many changeset-like edits of a base tree; after every edit the live heap
//! attributable to the store is compared with its accounted `total_bytes` and the bound.

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicIsize, Ordering};
use synapse_api::{TreeCacheConfig, TreeEdit, TreeFile, TreeStore};
use synapse_core::{BlobDigest, FileMode, GitOid, TreeDigest};

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

fn file(i: u64) -> TreeFile {
    let content = format!("content {i}\n");
    TreeFile {
        mode: FileMode::Regular644,
        blob_digest: BlobDigest::compute(content.as_bytes()),
        size_bytes: content.len() as u64,
        git_blob_oid: GitOid::compute_blob(content.as_bytes()),
    }
}

fn path(dir: u64, f: u64) -> String {
    format!(
        "crates/c{:02}/src/m{:02}/file_{f:04}.rs",
        dir % 40,
        dir / 40
    )
}

#[test]
fn c1_tree_store_accounting_covers_the_real_heap_under_eviction() {
    const MAX: usize = 2 * 1024 * 1024;
    let live_before = LIVE.load(Ordering::SeqCst);
    let mut store = TreeStore::new(TreeCacheConfig { max_bytes: MAX }).unwrap();
    // Base: 4,000 files in 80 directories, pinned like a registered base tree.
    let mut edit = TreeEdit::new(&mut store, TreeDigest::empty()).unwrap();
    for i in 0..4_000u64 {
        edit.upsert(&mut store, &path(i % 80, i), file(i)).unwrap();
    }
    let base = edit.finish(&mut store).unwrap();
    store.pin(base).unwrap();
    let mut worst_ratio = 0.0f64;
    for k in 0..2_000u64 {
        let mut edit = TreeEdit::new(&mut store, base).unwrap();
        for j in 0..3u64 {
            let i = (k * 7919 + j * 104_729) % 4_000;
            edit.upsert(&mut store, &path(i % 80, i), file(1_000_000 + k * 3 + j))
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
    println!("c1 heap accounting: worst live/accounted = {worst_ratio:.3}; final stats {s:?}");
}
