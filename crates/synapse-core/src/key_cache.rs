//! Bounded per-thread cache of decoded Ed25519 verifying keys (issue #93).
//!
//! `VerifyingKey::from_bytes` decompresses the curve point on every call. One accepted
//! submit verifies the changeset envelope (author key, [`crate::ChangesetEnvelope::validate`]),
//! the grant (authority key) and the request (agent key, both in `synapse-auth`), and these
//! keys repeat across requests, so the decoded key is cached here, keyed by the exact 32 key
//! bytes. The cache lives in this crate so the envelope check and `synapse-auth` share it.
//! Only the decode is cached: every signature is still verified in full, with the same
//! `verify` or `verify_strict` call as before, by the existing `ed25519-dalek` crate.
//!
//! Bounds and refusals:
//! - Only keys that decode are cached. Bytes that do not decode are refused on every call,
//!   exactly as before (the caller maps the error to its refusal code), and never enter
//!   the cache, so churn of invalid keys cannot grow it.
//! - At most [`KEY_CACHE_CAPACITY`] keys per thread; the oldest insertion is evicted first.
//!   Churn of valid keys (each new key one decode) therefore keeps the cache at the cap.
//! - Per thread: no lock on the verify path and nothing shared between threads.

use ed25519_dalek::{SignatureError, VerifyingKey};
use std::cell::RefCell;
use std::collections::{HashMap, VecDeque};

/// Most decoded keys one thread keeps.
pub const KEY_CACHE_CAPACITY: usize = 64;

#[derive(Default)]
struct KeyCache {
    keys: HashMap<[u8; 32], VerifyingKey>,
    /// Insertion order, oldest first; always the same key set as `keys`.
    order: VecDeque<[u8; 32]>,
    /// Point decodes performed (cache misses that reached `VerifyingKey::from_bytes`).
    decodes: u64,
}

thread_local! {
    static CACHE: RefCell<KeyCache> = RefCell::new(KeyCache::default());
}

/// The decoded verifying key for `bytes`: from this thread's cache, or decoded with
/// `VerifyingKey::from_bytes` (and cached when it decodes). Same result and same error as
/// calling `VerifyingKey::from_bytes(bytes)` directly.
pub fn cached_verifying_key(bytes: &[u8; 32]) -> Result<VerifyingKey, SignatureError> {
    CACHE
        .try_with(|cell| {
            let mut cache = cell.borrow_mut();
            if let Some(key) = cache.keys.get(bytes) {
                return Ok(*key);
            }
            cache.decodes += 1;
            let key = VerifyingKey::from_bytes(bytes)?;
            if cache.keys.len() >= KEY_CACHE_CAPACITY {
                if let Some(oldest) = cache.order.pop_front() {
                    cache.keys.remove(&oldest);
                }
            }
            cache.keys.insert(*bytes, key);
            cache.order.push_back(*bytes);
            Ok(key)
        })
        // Thread-local storage already torn down (thread exit): decode without caching.
        .unwrap_or_else(|_| VerifyingKey::from_bytes(bytes))
}

/// `(cached keys, point decodes)` for the calling thread. Diagnostic only: tests use it to
/// count decodes; it changes nothing.
#[doc(hidden)]
pub fn key_cache_stats() -> (usize, u64) {
    CACHE.with(|cell| {
        let cache = cell.borrow();
        debug_assert_eq!(cache.keys.len(), cache.order.len());
        (cache.keys.len(), cache.decodes)
    })
}

#[cfg(test)]
mod tests;
