// ABOUTME: Shared cache policy for immutable blobs and repairable derivatives.
// ABOUTME: Keeps browser and edge cache lifetimes testable outside Fastly Compute.

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PublicCacheHeaders<'a> {
    pub cache_control: &'static str,
    pub surrogate_control: &'static str,
    pub surrogate_key: &'a str,
}

pub fn immutable_blob_cache_headers(hash: &str) -> PublicCacheHeaders<'_> {
    PublicCacheHeaders {
        cache_control: "public, max-age=31536000, immutable",
        surrogate_control: "max-age=31536000",
        surrogate_key: hash,
    }
}

pub fn mutable_derivative_cache_headers(hash: &str) -> PublicCacheHeaders<'_> {
    PublicCacheHeaders {
        cache_control: "public, max-age=86400",
        surrogate_control: "max-age=31536000",
        surrogate_key: hash,
    }
}

#[cfg(test)]
mod tests {
    use super::{immutable_blob_cache_headers, mutable_derivative_cache_headers};

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

    #[test]
    fn derivatives_keep_a_long_purgeable_edge_ttl() {
        let headers = mutable_derivative_cache_headers("abc123");

        assert_eq!(headers.surrogate_control, "max-age=31536000");
        assert_eq!(headers.surrogate_key, "abc123");
    }
}
