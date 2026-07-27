// ABOUTME: Binary-side glue for the transcription rate limiter.
// ABOUTME: Binds the pure core to Fastly KV compare-and-swap via a newtype.

pub use blossom_core::rate_limit::*;

use std::time::Duration;

use fastly::kv_store::{InsertMode, KVStore, KVStoreError};

/// Fastly KV backing for the pure limiter. A local newtype is required so the
/// foreign `CounterStore` trait can be implemented for the foreign `KVStore`
/// type without tripping the orphan rule.
pub struct KvCounterStore<'a>(pub &'a KVStore);

impl CounterStore for KvCounterStore<'_> {
    fn read(&self, key: &str) -> Option<(u32, u64)> {
        match self.0.lookup(key) {
            Ok(mut found) => {
                let generation = found.current_generation();
                let count = found.take_body().into_string().trim().parse().ok()?;
                Some((count, generation))
            }
            Err(_) => None,
        }
    }

    fn create(&self, key: &str, value: u32, ttl: Duration) -> CasResult {
        // `Add` inserts only if the key is absent, failing with
        // `ItemPreconditionFailed` when another request created it first.
        match self
            .0
            .build_insert()
            .mode(InsertMode::Add)
            .time_to_live(ttl)
            .execute(key, value.to_string())
        {
            Ok(()) => CasResult::Committed,
            Err(KVStoreError::ItemPreconditionFailed) => CasResult::Conflict,
            Err(_) => CasResult::Failed,
        }
    }

    fn update(&self, key: &str, value: u32, ttl: Duration, expected_generation: u64) -> CasResult {
        // Default `Overwrite` mode, but only if the stored generation still
        // matches — otherwise the value changed under us since `read`.
        match self
            .0
            .build_insert()
            .if_generation_match(expected_generation)
            .time_to_live(ttl)
            .execute(key, value.to_string())
        {
            Ok(()) => CasResult::Committed,
            Err(KVStoreError::ItemPreconditionFailed) => CasResult::Conflict,
            Err(_) => CasResult::Failed,
        }
    }
}
