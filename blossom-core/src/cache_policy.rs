// ABOUTME: Shared cache policy for immutable blobs and repairable derivatives.
// ABOUTME: Keeps browser and edge cache lifetimes testable outside Fastly Compute.

use crate::types::BlobStatus;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CacheHeaders<'a> {
    pub cache_control: &'static str,
    pub surrogate_control: &'static str,
    pub surrogate_key: &'a str,
}

/// Full content-addressed objects may live in the Compute service's internal
/// read-through cache for a year. Access control still runs before that cache
/// is consulted; this policy applies only to the storage subrequest made after
/// the viewer has been authorized.
pub const IMMUTABLE_STORAGE_CACHE_TTL_SECS: u32 = 31_536_000;
pub const IMMUTABLE_STORAGE_CACHE_SWR_SECS: u32 = 86_400;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ImmutableStorageCachePolicy {
    Store {
        ttl_seconds: u32,
        stale_while_revalidate_seconds: u32,
    },
    DoNotStore,
}

/// Cache only a complete storage response. A partial response must never
/// populate the shared object key, and missing/error responses must remain
/// retryable so a later upload or origin recovery can succeed immediately.
pub fn immutable_storage_cache_policy(status: u16) -> ImmutableStorageCachePolicy {
    if status == 200 {
        ImmutableStorageCachePolicy::Store {
            ttl_seconds: IMMUTABLE_STORAGE_CACHE_TTL_SECS,
            stale_while_revalidate_seconds: IMMUTABLE_STORAGE_CACHE_SWR_SECS,
        }
    } else {
        ImmutableStorageCachePolicy::DoNotStore
    }
}

pub fn immutable_blob_cache_headers(hash: &str) -> CacheHeaders<'_> {
    CacheHeaders {
        cache_control: "public, max-age=31536000, immutable",
        surrogate_control: "max-age=31536000",
        surrogate_key: hash,
    }
}

pub fn mutable_derivative_cache_headers(hash: &str) -> CacheHeaders<'_> {
    CacheHeaders {
        cache_control: "public, max-age=86400",
        surrogate_control: "max-age=31536000",
        surrogate_key: hash,
    }
}

/// Headers for responses that must not be stored in browser or shared caches.
/// The Surrogate-Key is still carried so a moderation purge can evict any edge
/// copy cached before the status changed.
pub fn private_no_store_cache_headers(hash: &str) -> CacheHeaders<'_> {
    CacheHeaders {
        cache_control: "private, no-store",
        surrogate_control: "no-store",
        surrogate_key: hash,
    }
}

/// Cache policy for responses whose cacheability is driven by the blob's
/// moderation status. The match is exhaustive so a future `BlobStatus`
/// variant fails to compile until a policy is chosen for it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BlobCachePolicy {
    /// Content is moderated and content-addressed: immutable, one-year public caching.
    ImmutablePublic,
    /// Public while moderation runs, but revocable: short browser TTL with a
    /// long edge TTL that `purge_edge_cache` can invalidate by Surrogate-Key.
    RevocablePublic,
    /// Must not be stored in shared caches.
    PrivateNoStore,
}

pub fn blob_cache_policy(status: BlobStatus) -> BlobCachePolicy {
    match status {
        BlobStatus::Active => BlobCachePolicy::ImmutablePublic,
        BlobStatus::Pending => BlobCachePolicy::RevocablePublic,
        BlobStatus::Restricted
        | BlobStatus::AgeRestricted
        | BlobStatus::Banned
        | BlobStatus::Deleted => BlobCachePolicy::PrivateNoStore,
    }
}

/// Whether a response for this status must stay private. Routes that serve
/// derivative content (HLS, variants, transcripts) branch on this so every
/// status decision flows through the single exhaustive [`blob_cache_policy`]
/// match: a future `BlobStatus` variant fails to compile there instead of
/// silently inheriting public derivative caching.
pub fn status_requires_private_response(status: BlobStatus) -> bool {
    blob_cache_policy(status) == BlobCachePolicy::PrivateNoStore
}

/// The headers a serving route must send for a cache policy. Production routes
/// apply this mapping instead of re-stating it, so the policy-to-headers
/// decision is covered by the executing blossom-core tests.
pub fn cache_headers_for_policy<'a>(policy: BlobCachePolicy, hash: &'a str) -> CacheHeaders<'a> {
    match policy {
        BlobCachePolicy::ImmutablePublic => immutable_blob_cache_headers(hash),
        BlobCachePolicy::RevocablePublic => mutable_derivative_cache_headers(hash),
        BlobCachePolicy::PrivateNoStore => private_no_store_cache_headers(hash),
    }
}

#[cfg(test)]
mod tests {
    use super::{
        blob_cache_policy, cache_headers_for_policy, immutable_blob_cache_headers,
        immutable_storage_cache_policy, mutable_derivative_cache_headers,
        status_requires_private_response, BlobCachePolicy, ImmutableStorageCachePolicy,
        IMMUTABLE_STORAGE_CACHE_SWR_SECS, IMMUTABLE_STORAGE_CACHE_TTL_SECS,
    };
    use crate::types::BlobStatus;

    fn max_age(cache_control: &str) -> u64 {
        cache_control
            .split("max-age=")
            .nth(1)
            .and_then(|rest| rest.split(|c: char| !c.is_ascii_digit()).next())
            .and_then(|digits| digits.parse().ok())
            .expect("Cache-Control must carry a numeric max-age")
    }

    #[test]
    fn blobs_are_immutable_for_a_year() {
        let headers = immutable_blob_cache_headers("abc123");

        assert_eq!(headers.cache_control, "public, max-age=31536000, immutable");
        assert_eq!(headers.surrogate_control, "max-age=31536000");
        assert_eq!(headers.surrogate_key, "abc123");
    }

    #[test]
    fn derivatives_are_not_immutable() {
        let cache_control = mutable_derivative_cache_headers("abc123").cache_control;

        assert!(cache_control.contains("public"));
        assert!(!cache_control.contains("immutable"));
    }

    #[test]
    fn repaired_derivatives_reach_browsers_within_a_day() {
        let headers = mutable_derivative_cache_headers("abc123");

        assert!(max_age(headers.cache_control) <= 86_400);
    }

    // The outer VCL fetch snippet refuses to cache any response whose
    // Cache-Control matches `private` or `no-store`, which is what keeps
    // non-Active content out of the shared edge cache. These tests pin the
    // header text that check matches on, so changing the wording fails CI here
    // instead of silently re-enabling the edge caching of private responses.
    #[test]
    fn public_cache_headers_carry_the_token_the_vcl_matches() {
        for cache_control in [
            immutable_blob_cache_headers("abc123").cache_control,
            mutable_derivative_cache_headers("abc123").cache_control,
        ] {
            assert!(
                cache_control.contains("public"),
                "vcl_fetch caches credentialed responses only when Cache-Control \
                 contains `public`; got {cache_control:?}"
            );
            assert!(
                !cache_control.contains("private") && !cache_control.contains("no-store"),
                "vcl_fetch refuses to cache anything matching private/no-store; \
                 got {cache_control:?}"
            );
        }
    }

    #[test]
    fn derivatives_keep_a_long_purgeable_edge_ttl() {
        let headers = mutable_derivative_cache_headers("abc123");

        assert_eq!(headers.surrogate_control, "max-age=31536000");
        assert_eq!(headers.surrogate_key, "abc123");
    }

    #[test]
    fn every_cache_policy_sends_the_headers_its_name_promises() {
        // The edge binary's tests are compile-only in CI, so these literals
        // are the executing coverage for the header strings each policy must
        // send on every serving route.
        for (policy, cache_control, surrogate_control) in [
            (
                BlobCachePolicy::ImmutablePublic,
                "public, max-age=31536000, immutable",
                "max-age=31536000",
            ),
            (
                BlobCachePolicy::RevocablePublic,
                "public, max-age=86400",
                "max-age=31536000",
            ),
            (
                BlobCachePolicy::PrivateNoStore,
                "private, no-store",
                "no-store",
            ),
        ] {
            let headers = cache_headers_for_policy(policy, "abc123");

            assert_eq!(headers.cache_control, cache_control);
            assert_eq!(headers.surrogate_control, surrogate_control);
            assert_eq!(headers.surrogate_key, "abc123");
        }
    }

    #[test]
    fn moderated_statuses_route_derivatives_through_the_policy_match() {
        for status in [
            BlobStatus::Restricted,
            BlobStatus::AgeRestricted,
            BlobStatus::Banned,
            BlobStatus::Deleted,
        ] {
            assert!(status_requires_private_response(status));
        }
        assert!(!status_requires_private_response(BlobStatus::Active));
        assert!(!status_requires_private_response(BlobStatus::Pending));
    }

    #[test]
    fn active_media_stays_immutable() {
        assert_eq!(
            blob_cache_policy(BlobStatus::Active),
            BlobCachePolicy::ImmutablePublic
        );
    }

    #[test]
    fn pending_media_is_public_but_revocable() {
        assert_eq!(
            blob_cache_policy(BlobStatus::Pending),
            BlobCachePolicy::RevocablePublic
        );
    }

    #[test]
    fn moderated_media_is_never_publicly_cacheable() {
        for status in [
            BlobStatus::Restricted,
            BlobStatus::AgeRestricted,
            BlobStatus::Banned,
            BlobStatus::Deleted,
        ] {
            assert_eq!(
                blob_cache_policy(status),
                BlobCachePolicy::PrivateNoStore,
                "{:?} must not be publicly cacheable",
                status
            );
        }
    }

    #[test]
    fn full_storage_responses_are_cached_for_a_year() {
        assert_eq!(
            immutable_storage_cache_policy(200),
            ImmutableStorageCachePolicy::Store {
                ttl_seconds: IMMUTABLE_STORAGE_CACHE_TTL_SECS,
                stale_while_revalidate_seconds: IMMUTABLE_STORAGE_CACHE_SWR_SECS,
            }
        );
        assert_eq!(IMMUTABLE_STORAGE_CACHE_TTL_SECS, 31_536_000);
        assert_eq!(IMMUTABLE_STORAGE_CACHE_SWR_SECS, 86_400);
    }

    #[test]
    fn partial_or_error_storage_responses_are_never_cached() {
        for status in [206, 404, 416, 500, 503] {
            assert_eq!(
                immutable_storage_cache_policy(status),
                ImmutableStorageCachePolicy::DoNotStore,
                "status {status} must not populate the shared full-object cache"
            );
        }
    }
}
