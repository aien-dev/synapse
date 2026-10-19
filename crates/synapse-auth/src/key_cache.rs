//! Decoded-key cache for the grant, request and capability-chain checks (issue #93).
//!
//! The cache itself lives in `synapse_core::key_cache` so the changeset envelope check shares
//! it; see that module for the bounds and refusal rules.

pub(crate) use synapse_core::cached_verifying_key as verifying_key;
pub use synapse_core::KEY_CACHE_CAPACITY;

/// `(cached keys, point decodes)` for this thread.
#[cfg(test)]
pub(crate) fn stats() -> (usize, u64) {
    synapse_core::key_cache_stats()
}

#[cfg(test)]
mod tests;
