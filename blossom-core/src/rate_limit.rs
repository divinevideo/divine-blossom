// ABOUTME: Fixed-window rate limiting for the edge transcription proxy.
// ABOUTME: Pure bucket/decision logic + a compare-and-swap enforcer, all unit-tested.

use std::time::Duration;

/// Per-identity limits for the `/transcribe` proxy. Fixed-window: a window is
/// the wall-clock slice `floor(now / window_secs)`, with one counter per
/// (scope, id, window).
///
/// Transcription is expensive (ffmpeg extraction + a paid ASR provider call per
/// request), so the limits are deliberately low. Tune them here.
pub const PUBKEY_LIMIT: u32 = 10;
pub const PUBKEY_WINDOW_SECS: u64 = 3600;
pub const IP_LIMIT: u32 = 20;
pub const IP_WINDOW_SECS: u64 = 3600;

/// Retries for a lost compare-and-swap before giving up and failing open. A
/// counter is a single hot key, so contention is between the handful of
/// requests racing the same window; a small bound is plenty.
pub const MAX_CAS_ATTEMPTS: u32 = 5;

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

/// Result of a conditional write. `Conflict` is a lost compare-and-swap that
/// should be retried; `Failed` is a backend error that fails open.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CasResult {
    Committed,
    Conflict,
    Failed,
}

/// A generation-versioned counter backend, abstracted so the compare-and-swap
/// path can be tested against a fake here and bound to Fastly KV in the binary
/// crate (which owns the concrete `KVStore` and can satisfy the orphan rule via
/// a newtype).
pub trait CounterStore {
    /// Current `(count, generation)` for `key`, or `None` if absent/unreadable.
    fn read(&self, key: &str) -> Option<(u32, u64)>;
    /// Insert `value` only if `key` is absent (create). `Conflict` means it
    /// already existed — another request won the race.
    fn create(&self, key: &str, value: u32, ttl: Duration) -> CasResult;
    /// Overwrite `key` with `value` only if its stored generation still equals
    /// `expected_generation`. `Conflict` means it changed under us.
    fn update(&self, key: &str, value: u32, ttl: Duration, expected_generation: u64) -> CasResult;
}

/// Enforce one limit for one identity via read → decide → compare-and-swap.
///
/// Returns `Some(retry_after_secs)` when over the limit, `None` when allowed.
/// The CAS closes the lost-update race a plain read-then-overwrite would have:
/// a concurrent burst that all read the same count can no longer all commit the
/// same increment — the losers see `Conflict` and re-read. Best-effort at the
/// edges: a backend error or exhausted contention fails open, so the abuse
/// control never blocks a legitimate request.
pub fn enforce<S: CounterStore>(
    store: &S,
    scope: &str,
    id: &str,
    cfg: RateLimit,
    now_secs: u64,
) -> Option<u64> {
    let key = counter_key(scope, id, bucket_for(now_secs, cfg.window_secs));
    let ttl = write_ttl(cfg);

    for _ in 0..MAX_CAS_ATTEMPTS {
        let write = match store.read(&key) {
            None => match decide(0, cfg, now_secs) {
                Decision::Limited { retry_after_secs } => return Some(retry_after_secs),
                Decision::Allowed { next_count } => store.create(&key, next_count, ttl),
            },
            Some((current, generation)) => match decide(current, cfg, now_secs) {
                Decision::Limited { retry_after_secs } => return Some(retry_after_secs),
                Decision::Allowed { next_count } => store.update(&key, next_count, ttl, generation),
            },
        };

        match write {
            CasResult::Committed => return None,
            CasResult::Conflict => continue,
            CasResult::Failed => return None,
        }
    }

    // Contention exhausted the retry budget — fail open rather than block.
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::collections::HashMap;

    /// In-memory generation-versioned fake with fault injection, mirroring the
    /// Fastly KV semantics the real adapter relies on (Add-if-absent, overwrite
    /// only on matching generation). TTL is ignored — Fastly enforces it
    /// server-side and it's not part of the decision logic.
    struct FakeStore {
        map: RefCell<HashMap<String, (u32, u64)>>,
        conflicts_remaining: RefCell<u32>,
        always_fail: bool,
    }

    impl FakeStore {
        fn new() -> Self {
            Self {
                map: RefCell::new(HashMap::new()),
                conflicts_remaining: RefCell::new(0),
                always_fail: false,
            }
        }

        fn with_injected_conflicts(count: u32) -> Self {
            let s = Self::new();
            *s.conflicts_remaining.borrow_mut() = count;
            s
        }

        fn failing() -> Self {
            Self {
                always_fail: true,
                ..Self::new()
            }
        }

        /// Returns an injected fault for this write, or `None` to proceed.
        fn injected(&self) -> Option<CasResult> {
            if self.always_fail {
                return Some(CasResult::Failed);
            }
            let mut remaining = self.conflicts_remaining.borrow_mut();
            if *remaining > 0 {
                *remaining -= 1;
                return Some(CasResult::Conflict);
            }
            None
        }
    }

    impl CounterStore for FakeStore {
        fn read(&self, key: &str) -> Option<(u32, u64)> {
            self.map.borrow().get(key).copied()
        }

        fn create(&self, key: &str, value: u32, _ttl: Duration) -> CasResult {
            if let Some(fault) = self.injected() {
                return fault;
            }
            let mut map = self.map.borrow_mut();
            if map.contains_key(key) {
                return CasResult::Conflict;
            }
            map.insert(key.to_string(), (value, 1));
            CasResult::Committed
        }

        fn update(
            &self,
            key: &str,
            value: u32,
            _ttl: Duration,
            expected_generation: u64,
        ) -> CasResult {
            if let Some(fault) = self.injected() {
                return fault;
            }
            let mut map = self.map.borrow_mut();
            match map.get(key) {
                Some(&(_, generation)) if generation == expected_generation => {
                    map.insert(key.to_string(), (value, generation + 1));
                    CasResult::Committed
                }
                _ => CasResult::Conflict,
            }
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
    }

    #[test]
    fn write_ttl_is_two_windows() {
        assert_eq!(write_ttl(CFG), Duration::from_secs(120));
    }

    #[test]
    fn enforce_allows_first_n_then_limits_within_a_window() {
        let store = FakeStore::new();
        let now = 10;

        assert_eq!(enforce(&store, "pk", "a", CFG, now), None);
        assert_eq!(enforce(&store, "pk", "a", CFG, now), None);
        assert_eq!(enforce(&store, "pk", "a", CFG, now), None);
        // Fourth request in the same window is over the limit of 3.
        assert_eq!(enforce(&store, "pk", "a", CFG, now), Some(50));
    }

    #[test]
    fn enforce_resets_when_the_window_rolls() {
        let store = FakeStore::new();

        for _ in 0..3 {
            assert_eq!(enforce(&store, "pk", "a", CFG, 10), None);
        }
        assert_eq!(enforce(&store, "pk", "a", CFG, 10), Some(50));

        // Next window (>= 60s) gets a fresh counter.
        assert_eq!(enforce(&store, "pk", "a", CFG, 60), None);
    }

    #[test]
    fn enforce_isolates_distinct_identities_and_scopes() {
        let store = FakeStore::new();

        for _ in 0..3 {
            assert_eq!(enforce(&store, "pk", "a", CFG, 10), None);
        }
        assert_eq!(enforce(&store, "pk", "a", CFG, 10), Some(50));

        // A different pubkey has its own budget.
        assert_eq!(enforce(&store, "pk", "b", CFG, 10), None);
        // The same id under the IP scope is a separate counter too.
        assert_eq!(enforce(&store, "ip", "a", CFG, 10), None);
    }

    #[test]
    fn enforce_retries_past_a_transient_conflict() {
        // First write loses the race once, then commits on retry.
        let store = FakeStore::with_injected_conflicts(1);

        assert_eq!(enforce(&store, "pk", "a", CFG, 10), None);
        // The retry still recorded exactly one request: the next two are
        // allowed and the fourth is limited.
        assert_eq!(enforce(&store, "pk", "a", CFG, 10), None);
        assert_eq!(enforce(&store, "pk", "a", CFG, 10), None);
        assert_eq!(enforce(&store, "pk", "a", CFG, 10), Some(50));
    }

    #[test]
    fn enforce_fails_open_when_contention_exhausts_retries() {
        // Every attempt conflicts: never blocks a legitimate request.
        let store = FakeStore::with_injected_conflicts(MAX_CAS_ATTEMPTS + 5);
        assert_eq!(enforce(&store, "pk", "a", CFG, 10), None);
    }

    #[test]
    fn enforce_fails_open_on_backend_error() {
        let store = FakeStore::failing();
        assert_eq!(enforce(&store, "pk", "a", CFG, 10), None);
    }
}
