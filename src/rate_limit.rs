// ABOUTME: Binary-side glue for the transcription rate limiter.
// ABOUTME: Re-exports the pure core and binds it to Fastly KV via a newtype.

pub use blossom_core::rate_limit::*;

use std::time::Duration;

use fastly::kv_store::KVStore;

/// Fastly KV backing for the pure limiter. A local newtype is required so the
/// foreign `CounterStore` trait can be implemented for the foreign `KVStore`
/// type without tripping the orphan rule.
pub struct KvCounterStore<'a>(pub &'a KVStore);

impl CounterStore for KvCounterStore<'_> {
    fn read(&self, key: &str) -> Option<u32> {
        match self.0.lookup(key) {
            Ok(mut found) => found.take_body().into_string().trim().parse().ok(),
            Err(_) => None,
        }
    }

    fn write(&self, key: &str, value: u32, ttl: Duration) {
        let _ = self
            .0
            .build_insert()
            .time_to_live(ttl)
            .execute(key, value.to_string());
    }
}
