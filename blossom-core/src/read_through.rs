// ABOUTME: Pure decision logic for read-through delivery from a mirror origin.
// ABOUTME: Feature-flag parsing, write-back eligibility, and shared object paths.

/// Source label for objects served from the authoritative GCS bucket.
pub const SOURCE_GCS: &str = "gcs";

/// Source label for objects served from the Fastly Object Storage mirror.
pub const SOURCE_FOS: &str = "fos";

/// Largest object we are willing to buffer in memory for a write-back.
///
/// Fastly Compute allows 128 MB of memory per request and a write-back holds
/// the object twice for a moment (once for the upload body, once for the
/// response body), so the ceiling has to leave generous headroom. The largest
/// media object observed in the catalogue is 27.9 MB.
pub const MAX_WRITE_BACK_BYTES: u64 = 32 * 1024 * 1024;

/// Parse a config-store feature flag.
///
/// A flag is enabled only when it is present and explicitly affirmative.
/// Absent, empty, and unparseable values are all disabled, so a missing or
/// mistyped config key can never turn a feature on.
pub fn parse_bool_flag(raw: Option<&str>) -> bool {
    match raw {
        Some(value) => matches!(
            value.trim().to_ascii_lowercase().as_str(),
            "true" | "1" | "yes" | "on"
        ),
        None => false,
    }
}

/// Why an object was or was not copied into the mirror after an origin fetch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WriteBackDecision {
    /// Copy the object into the mirror.
    Eligible,
    /// The `fos_write_back_enabled` flag is off.
    DisabledByFlag,
    /// The bytes did not come from the authoritative origin.
    SourceNotGcs,
    /// The request carried a `Range` header, so the body may be a fragment.
    RangeRequest,
    /// The origin returned something other than a complete `200` body.
    NotFullResponse,
    /// The origin did not declare a length, so buffering is unbounded.
    SizeUnknown,
    /// The object is larger than the in-memory buffering ceiling.
    TooLarge,
}

impl WriteBackDecision {
    pub fn is_eligible(&self) -> bool {
        matches!(self, WriteBackDecision::Eligible)
    }

    /// Stable short label for logging.
    pub fn reason(&self) -> &'static str {
        match self {
            WriteBackDecision::Eligible => "eligible",
            WriteBackDecision::DisabledByFlag => "disabled",
            WriteBackDecision::SourceNotGcs => "source_not_gcs",
            WriteBackDecision::RangeRequest => "range_request",
            WriteBackDecision::NotFullResponse => "not_full_response",
            WriteBackDecision::SizeUnknown => "size_unknown",
            WriteBackDecision::TooLarge => "too_large",
        }
    }
}

/// Decide whether a just-fetched object may be copied into the mirror.
///
/// Every guard is a hard requirement: only a complete, length-declared,
/// small-enough body fetched from the authoritative origin without a `Range`
/// header may be buffered and uploaded.
pub fn write_back_decision(
    enabled: bool,
    source: &str,
    status: u16,
    had_range: bool,
    content_length: Option<u64>,
    max_bytes: u64,
) -> WriteBackDecision {
    if !enabled {
        return WriteBackDecision::DisabledByFlag;
    }
    if source != SOURCE_GCS {
        return WriteBackDecision::SourceNotGcs;
    }
    if had_range {
        return WriteBackDecision::RangeRequest;
    }
    if status != 200 {
        return WriteBackDecision::NotFullResponse;
    }
    match content_length {
        None => WriteBackDecision::SizeUnknown,
        Some(0) => WriteBackDecision::SizeUnknown,
        Some(len) if len > max_bytes => WriteBackDecision::TooLarge,
        Some(_) => WriteBackDecision::Eligible,
    }
}

/// Build the path-style object path shared by every S3-compatible origin.
///
/// Both the GCS S3-compat endpoint and Fastly Object Storage address objects
/// as `/<bucket>/<key>`, so the two origins must agree on this byte for byte
/// or a mirrored object will be looked up under the wrong name.
pub fn object_path(bucket: &str, key: &str) -> String {
    format!(
        "/{}/{}",
        bucket.trim_matches('/'),
        key.trim_start_matches('/')
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn absent_flag_is_disabled() {
        assert!(!parse_bool_flag(None));
    }

    #[test]
    fn empty_and_garbage_flags_are_disabled() {
        assert!(!parse_bool_flag(Some("")));
        assert!(!parse_bool_flag(Some("   ")));
        assert!(!parse_bool_flag(Some("maybe")));
        assert!(!parse_bool_flag(Some("2")));
        assert!(!parse_bool_flag(Some("{\"enabled\":true}")));
        assert!(!parse_bool_flag(Some("truthy")));
    }

    #[test]
    fn false_flag_is_disabled() {
        assert!(!parse_bool_flag(Some("false")));
        assert!(!parse_bool_flag(Some("FALSE")));
        assert!(!parse_bool_flag(Some("0")));
        assert!(!parse_bool_flag(Some("off")));
        assert!(!parse_bool_flag(Some("no")));
    }

    #[test]
    fn affirmative_flag_is_enabled() {
        assert!(parse_bool_flag(Some("true")));
        assert!(parse_bool_flag(Some("TRUE")));
        assert!(parse_bool_flag(Some("  True  ")));
        assert!(parse_bool_flag(Some("1")));
        assert!(parse_bool_flag(Some("yes")));
        assert!(parse_bool_flag(Some("on")));
    }

    fn decide(
        enabled: bool,
        source: &str,
        status: u16,
        range: bool,
        len: Option<u64>,
    ) -> WriteBackDecision {
        write_back_decision(enabled, source, status, range, len, MAX_WRITE_BACK_BYTES)
    }

    #[test]
    fn write_back_requires_the_flag() {
        assert_eq!(
            decide(false, SOURCE_GCS, 200, false, Some(1024)),
            WriteBackDecision::DisabledByFlag
        );
    }

    #[test]
    fn write_back_only_copies_bytes_fetched_from_gcs() {
        assert_eq!(
            decide(true, SOURCE_FOS, 200, false, Some(1024)),
            WriteBackDecision::SourceNotGcs
        );
        assert_eq!(
            decide(true, "some_cdn", 200, false, Some(1024)),
            WriteBackDecision::SourceNotGcs
        );
    }

    #[test]
    fn write_back_skips_range_requests_and_partial_responses() {
        assert_eq!(
            decide(true, SOURCE_GCS, 200, true, Some(1024)),
            WriteBackDecision::RangeRequest
        );
        assert_eq!(
            decide(true, SOURCE_GCS, 206, false, Some(1024)),
            WriteBackDecision::NotFullResponse
        );
        assert_eq!(
            decide(true, SOURCE_GCS, 304, false, Some(1024)),
            WriteBackDecision::NotFullResponse
        );
    }

    #[test]
    fn write_back_requires_a_declared_non_zero_length() {
        assert_eq!(
            decide(true, SOURCE_GCS, 200, false, None),
            WriteBackDecision::SizeUnknown
        );
        assert_eq!(
            decide(true, SOURCE_GCS, 200, false, Some(0)),
            WriteBackDecision::SizeUnknown
        );
    }

    #[test]
    fn write_back_is_bounded_by_the_memory_ceiling() {
        assert_eq!(
            decide(true, SOURCE_GCS, 200, false, Some(MAX_WRITE_BACK_BYTES)),
            WriteBackDecision::Eligible
        );
        assert_eq!(
            decide(true, SOURCE_GCS, 200, false, Some(MAX_WRITE_BACK_BYTES + 1)),
            WriteBackDecision::TooLarge
        );
        assert_eq!(
            decide(true, SOURCE_GCS, 200, false, Some(5 * 1024 * 1024 * 1024)),
            WriteBackDecision::TooLarge
        );
    }

    #[test]
    fn ceiling_covers_the_largest_observed_object() {
        // Largest observed media object is 27.9 MB.
        let largest_observed = (27.9 * 1024.0 * 1024.0) as u64;
        assert!(largest_observed < MAX_WRITE_BACK_BYTES);
        assert_eq!(
            decide(true, SOURCE_GCS, 200, false, Some(largest_observed)),
            WriteBackDecision::Eligible
        );
    }

    #[test]
    fn eligible_typical_object() {
        let decision = decide(true, SOURCE_GCS, 200, false, Some(174_080));
        assert!(decision.is_eligible());
        assert_eq!(decision.reason(), "eligible");
    }

    #[test]
    fn skip_reasons_are_distinct_labels() {
        let reasons = [
            WriteBackDecision::Eligible.reason(),
            WriteBackDecision::DisabledByFlag.reason(),
            WriteBackDecision::SourceNotGcs.reason(),
            WriteBackDecision::RangeRequest.reason(),
            WriteBackDecision::NotFullResponse.reason(),
            WriteBackDecision::SizeUnknown.reason(),
            WriteBackDecision::TooLarge.reason(),
        ];
        let mut sorted = reasons.to_vec();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), reasons.len());
        assert!(!WriteBackDecision::TooLarge.is_eligible());
    }

    #[test]
    fn object_path_is_path_style() {
        assert_eq!(
            object_path("divine-blossom-media", "abc123"),
            "/divine-blossom-media/abc123"
        );
        assert_eq!(
            object_path("divine-media-delivery", "abc123"),
            "/divine-media-delivery/abc123"
        );
    }

    #[test]
    fn object_path_normalizes_stray_slashes() {
        assert_eq!(object_path("/bucket/", "key"), "/bucket/key");
        assert_eq!(object_path("bucket", "/key"), "/bucket/key");
    }

    #[test]
    fn object_path_preserves_nested_keys() {
        assert_eq!(
            object_path("bucket", "abc123/hls/index.m3u8"),
            "/bucket/abc123/hls/index.m3u8"
        );
    }

    #[test]
    fn both_origins_address_the_same_key_identically() {
        let key = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        assert_eq!(
            object_path("divine-blossom-media", key).trim_start_matches("/divine-blossom-media"),
            object_path("divine-media-delivery", key).trim_start_matches("/divine-media-delivery")
        );
    }
}
