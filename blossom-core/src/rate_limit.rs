// ABOUTME: Fixed-window rate limiting for the edge transcription proxy.
// ABOUTME: Pure bucket/decision logic + a store-agnostic enforcer, all unit-tested.

use std::time::Duration;

/// Per-identity limits for the `/transcribe` proxy. Fixed-window, best-effort —
/// mirrors divine-moderation-service's KV limiter: a window is the wall-clock
/// slice `floor(now / window_secs)`, with one counter per (scope, id, window).
///
/// Transcription is expensive (ffmpeg extraction + a paid ASR provider call per
/// request), so the limits are deliberately low. Tune them here.
pub const PUBKEY_LIMIT: u32 = 20;
pub const PUBKEY_WINDOW_SECS: u64 = 60;
pub const IP_LIMIT: u32 = 40;
pub const IP_WINDOW_SECS: u64 = 60;

/// Key prefix so rate-limit counters never collide with the metadata keys that
/// share the `blossom_metadata` KV store.
const KEY_PREFIX: &str = "ratelimit:transcribe:";

/// A single fixed-window limit: at most `limit` requests per `window_secs`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RateLimit {
    pub limit: u32,
    pub window_secs: u64,
}

impl RateLimit {
    pub const fn new(limit: u32, window_secs: u64) -> Self {
        Self { limit, window_secs }
    }
}

/// The wall-clock window a timestamp falls into.
pub fn bucket_for(now_secs: u64, window_secs: u64) -> u64 {
    now_secs / window_secs.max(1)
}

/// Seconds until the current window rolls over — the `Retry-After` value.
pub fn retry_after_secs(now_secs: u64, window_secs: u64) -> u64 {
    let window = window_secs.max(1);
    window - (now_secs % window)
}

/// KV counter key for one (scope, id, window) triple.
pub fn counter_key(scope: &str, id: &str, bucket: u64) -> String {
    format!("{KEY_PREFIX}{scope}:{id}:{bucket}")
}

/// Pure fixed-window decision given the count already recorded this window.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    /// Under the limit; the caller should persist `next_count`.
    Allowed { next_count: u32 },
    /// At or over the limit; reject with this `Retry-After`.
    Limited { retry_after_secs: u64 },
}

/// Decide whether one more request is allowed, given the current window count.
pub fn decide(current: u32, cfg: RateLimit, now_secs: u64) -> Decision {
    if current >= cfg.limit {
        Decision::Limited {
            retry_after_secs: retry_after_secs(now_secs, cfg.window_secs),
        }
    } else {
        Decision::Allowed {
            next_count: current + 1,
        }
    }
}

/// TTL to attach on write: two windows, so an idle client's final bucket is
/// still reaped shortly after it can no longer be hit.
pub fn write_ttl(cfg: RateLimit) -> Duration {
    Duration::from_secs(cfg.window_secs.saturating_mul(2))
}

/// A counter backend, abstracted so the read-modify-write path can be tested
/// against a fake here and bound to Fastly KV in the binary crate (which owns
/// the concrete `KVStore` and can satisfy the orphan rule via a newtype).
pub trait CounterStore {
    /// Current count for `key`, or `None` if absent/unreadable.
    fn read(&self, key: &str) -> Option<u32>;
    /// Persist `value` for `key` with the given TTL. Best-effort; the
    /// implementation swallows failures.
    fn write(&self, key: &str, value: u32, ttl: Duration);
}

/// Enforce one limit for one identity, incrementing its window counter.
///
/// Returns `Some(retry_after_secs)` when the request is over the limit, `None`
/// when it is allowed. Non-atomic and best-effort: a store that reads `None`
/// (miss or backend error) is treated as a fresh window, so a KV outage fails
/// open rather than blocking a legitimate path — the same contract as the
/// moderation-service limiter.
pub fn enforce<S: CounterStore>(
    store: &S,
    scope: &str,
    id: &str,
    cfg: RateLimit,
    now_secs: u64,
) -> Option<u64> {
    let bucket = bucket_for(now_secs, cfg.window_secs);
    let key = counter_key(scope, id, bucket);
    let current = store.read(&key).unwrap_or(0);

    match decide(current, cfg, now_secs) {
        Decision::Limited { retry_after_secs } => Some(retry_after_secs),
        Decision::Allowed { next_count } => {
            store.write(&key, next_count, write_ttl(cfg));
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::collections::HashMap;

    /// In-memory fake mirroring the fixed-window write semantics (ignores TTL,
    /// which the KV backend enforces server-side and is not part of the
    /// decision logic).
    #[derive(Default)]
    struct FakeStore {
        map: RefCell<HashMap<String, u32>>,
    }

    impl CounterStore for FakeStore {
        fn read(&self, key: &str) -> Option<u32> {
            self.map.borrow().get(key).copied()
        }

        fn write(&self, key: &str, value: u32, _ttl: Duration) {
            self.map.borrow_mut().insert(key.to_string(), value);
        }
    }

    const CFG: RateLimit = RateLimit::new(3, 60);

    #[test]
    fn bucket_advances_once_per_window() {
        assert_eq!(bucket_for(0, 60), 0);
        assert_eq!(bucket_for(59, 60), 0);
        assert_eq!(bucket_for(60, 60), 1);
        assert_eq!(bucket_for(121, 60), 2);
    }

    #[test]
    fn bucket_never_divides_by_zero() {
        assert_eq!(bucket_for(120, 0), 120);
    }

    #[test]
    fn retry_after_counts_down_to_window_edge() {
        assert_eq!(retry_after_secs(0, 60), 60);
        assert_eq!(retry_after_secs(1, 60), 59);
        assert_eq!(retry_after_secs(59, 60), 1);
        assert_eq!(retry_after_secs(60, 60), 60);
    }

    #[test]
    fn counter_key_is_scoped_and_prefixed() {
        assert_eq!(counter_key("pk", "abc", 7), "ratelimit:transcribe:pk:abc:7");
        assert_ne!(counter_key("pk", "abc", 7), counter_key("ip", "abc", 7));
    }

    #[test]
    fn decide_allows_until_limit_then_blocks() {
        assert_eq!(decide(0, CFG, 10), Decision::Allowed { next_count: 1 });
        assert_eq!(decide(2, CFG, 10), Decision::Allowed { next_count: 3 });
        assert_eq!(
            decide(3, CFG, 10),
            Decision::Limited {
                retry_after_secs: 50
            }
        );
        assert_eq!(
            decide(9, CFG, 10),
            Decision::Limited {
                retry_after_secs: 50
            }
        );
    }

    #[test]
    fn write_ttl_is_two_windows() {
        assert_eq!(write_ttl(CFG), Duration::from_secs(120));
    }

    #[test]
    fn enforce_allows_first_n_then_limits_within_a_window() {
        let store = FakeStore::default();
        let now = 10;

        assert_eq!(enforce(&store, "pk", "a", CFG, now), None);
        assert_eq!(enforce(&store, "pk", "a", CFG, now), None);
        assert_eq!(enforce(&store, "pk", "a", CFG, now), None);
        // Fourth request in the same window is over the limit of 3.
        assert_eq!(enforce(&store, "pk", "a", CFG, now), Some(50));
    }

    #[test]
    fn enforce_resets_when_the_window_rolls() {
        let store = FakeStore::default();

        for _ in 0..3 {
            assert_eq!(enforce(&store, "pk", "a", CFG, 10), None);
        }
        assert_eq!(enforce(&store, "pk", "a", CFG, 10), Some(50));

        // Next window (>= 60s) gets a fresh counter.
        assert_eq!(enforce(&store, "pk", "a", CFG, 60), None);
    }

    #[test]
    fn enforce_isolates_distinct_identities_and_scopes() {
        let store = FakeStore::default();

        for _ in 0..3 {
            assert_eq!(enforce(&store, "pk", "a", CFG, 10), None);
        }
        assert_eq!(enforce(&store, "pk", "a", CFG, 10), Some(50));

        // A different pubkey has its own budget.
        assert_eq!(enforce(&store, "pk", "b", CFG, 10), None);
        // The same id under the IP scope is a separate counter too.
        assert_eq!(enforce(&store, "ip", "a", CFG, 10), None);
    }
}
