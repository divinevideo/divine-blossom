//! Strict original-video canary eligibility and verification contract.
use serde::{Deserialize, Serialize};

pub const RESERVED_HOST: &str = "media-b2.divine.video";
pub const MAX_DEMAND_BYTES: u64 = 67_108_864;
// Each policy pass performs one vanish lookup per distinct reference. Bound
// three policy passes so adversarial references cannot exhaust execution work.
pub const MAX_DEMAND_REFERENCES: usize = 16;

#[derive(Debug, Serialize)]
pub struct DemandHint<'a> {
    version: u32,
    sha256: &'a str,
    reason: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    observed_destination_version_id: Option<&'a str>,
}
impl<'a> DemandHint<'a> {
    pub fn new(hash: &'a str, observed: Option<&'a str>) -> Option<Self> {
        if hash.len() != 64
            || original_hash("GET", &format!("/{hash}")).is_none()
            || observed.is_some_and(|v| v.is_empty() || v.len() > 1024)
        {
            return None;
        }
        Some(Self {
            version: 1,
            sha256: hash,
            reason: if observed.is_some() {
                "missing_version"
            } else {
                "missing_readiness"
            },
            observed_destination_version_id: observed,
        })
    }
}

/// One supported byte range. Multiple or malformed ranges are ignored before
/// origin I/O, consistently producing a full response rather than multipart.
pub fn single_range(value: Option<&str>) -> Option<&str> {
    let value = value?;
    let (start, end) = value.strip_prefix("bytes=")?.split_once('-')?;
    let number = |v: &str| {
        !v.is_empty() && v.bytes().all(|b| b.is_ascii_digit()) && v.parse::<u64>().is_ok()
    };
    if number(start) && number(end) && start.parse::<u64>().ok()? > end.parse::<u64>().ok()? {
        return None;
    }
    ((number(start) && (end.is_empty() || number(end))) || (start.is_empty() && number(end)))
        .then_some(value)
}

fn requested_span(range: &str, size: u64) -> Option<(u64, u64)> {
    let (start, end) = single_range(Some(range))?
        .strip_prefix("bytes=")?
        .split_once('-')?;
    if size == 0 {
        return None;
    }
    if start.is_empty() {
        let suffix = end.parse::<u64>().ok()?;
        return (suffix > 0).then(|| (size.saturating_sub(suffix), size - 1));
    }
    let start = start.parse::<u64>().ok()?;
    let end = if end.is_empty() {
        size - 1
    } else {
        end.parse::<u64>().ok()?.min(size - 1)
    };
    (start <= end && start < size).then_some((start, end))
}

pub fn demand_origin_matches(
    status: u16,
    length: Option<&str>,
    content_range: Option<&str>,
    size: u64,
    range: Option<&str>,
) -> bool {
    if status == 416 {
        return range
            .is_some_and(|r| single_range(Some(r)).is_some() && requested_span(r, size).is_none())
            && content_range == Some(format!("bytes */{size}").as_str());
    }
    if !origin_size_matches(status, length, content_range, size) {
        return false;
    }
    if status == 200 {
        return true;
    } // Origins may ignore Range.
    range
        .and_then(|r| requested_span(r, size))
        .is_some_and(|(start, end)| {
            content_range == Some(format!("bytes {start}-{end}/{size}").as_str())
        })
}

#[derive(Debug, PartialEq, Eq)]
pub enum CanaryRoute {
    Canonical,
    Canary,
    Denied,
}

/// Forwarding headers never activate the direct Compute canary.
pub fn route(configured: Option<&str>, host: &str, original_host: Option<&str>) -> CanaryRoute {
    let target = configured.unwrap_or(RESERVED_HOST);
    let host_base = host.split(':').next().unwrap_or(host);
    let concerned = host_base.eq_ignore_ascii_case(RESERVED_HOST)
        || host_base.eq_ignore_ascii_case(target)
        || original_host.is_some_and(|h| {
            h.eq_ignore_ascii_case(RESERVED_HOST) || h.eq_ignore_ascii_case(target)
        });
    if !concerned {
        return CanaryRoute::Canonical;
    }
    if configured.is_none()
        || target != RESERVED_HOST
        || host != target
        || original_host.is_some_and(|h| h != host)
    {
        return CanaryRoute::Denied;
    }
    CanaryRoute::Canary
}

pub fn original_hash(method: &str, path: &str) -> Option<String> {
    if method != "GET" && method != "HEAD" {
        return None;
    }
    let path = path.strip_prefix('/')?;
    let hash = path.strip_suffix(".mp4").unwrap_or(path);
    (hash.len() == 64
        && hash
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)))
    .then(|| hash.to_string())
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Readiness {
    pub version: u32,
    pub sha256: String,
    pub verified_sha256: String,
    pub bucket: String,
    pub key: String,
    pub size: u64,
    pub verified_at: u64,
    pub destination_version_id: String,
}
impl Readiness {
    pub fn matches(&self, hash: &str, bucket: &str, size: u64) -> bool {
        self.version == 1
            && self.sha256 == hash
            && self.verified_sha256 == hash
            && self.bucket == bucket
            && self.key == hash
            && self.size == size
            && size > 0
            && self.verified_at > 0
            && !self.destination_version_id.is_empty()
            && self.destination_version_id.len() <= 1024
    }
}

/// Validate actual origin sizes instead of inventing partial headers from metadata.
pub fn origin_size_matches(
    status: u16,
    length: Option<&str>,
    content_range: Option<&str>,
    size: u64,
) -> bool {
    let Some(length) = length.and_then(|v| v.parse::<u64>().ok()) else {
        return false;
    };
    if status == 200 {
        return length == size;
    }
    if status != 206 {
        return false;
    }
    let Some((span, total)) = content_range
        .and_then(|v| v.strip_prefix("bytes "))
        .and_then(|v| v.split_once('/'))
    else {
        return false;
    };
    let Some((start, end)) = span.split_once('-') else {
        return false;
    };
    let (Ok(start), Ok(end), Ok(total)) = (
        start.parse::<u64>(),
        end.parse::<u64>(),
        total.parse::<u64>(),
    ) else {
        return false;
    };
    total == size && start <= end && end < size && end - start + 1 == length
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn demand_ranges_validate_requested_span_and_unsatisfied_range() {
        for (range, status, length, content_range, expected) in [
            (Some("bytes=1-3"), 206, "3", Some("bytes 1-3/9"), true),
            (Some("bytes=1-3"), 206, "3", Some("bytes 2-4/9"), false),
            (Some("bytes=4-"), 206, "5", Some("bytes 4-8/9"), true),
            (Some("bytes=-3"), 206, "3", Some("bytes 6-8/9"), true),
            (Some("bytes=99-"), 416, "10", Some("bytes */9"), true),
            (Some("bytes=1-3"), 416, "0", Some("bytes */9"), false),
            (Some("bytes=0-1,3-4"), 206, "2", Some("bytes 0-1/9"), false),
            (None, 206, "3", Some("bytes 1-3/9"), false),
        ] {
            assert_eq!(
                demand_origin_matches(status, Some(length), content_range, 9, range),
                expected,
                "{range:?} {status}"
            );
        }
        assert!(demand_origin_matches(
            200,
            Some("9"),
            None,
            9,
            Some("bytes=1-3")
        ));
    }
    #[test]
    fn demand_hint_bounds_version_and_keeps_full_hash() {
        let hash = "a".repeat(64);
        let hint = DemandHint::new(&hash, Some("4_zSynthetic+version")).unwrap();
        let value = serde_json::to_value(hint).unwrap();
        assert_eq!(value["sha256"], hash);
        assert_eq!(value["version"], 1);
        assert_eq!(value["reason"], "missing_version");
        assert_eq!(
            value["observed_destination_version_id"],
            "4_zSynthetic+version"
        );
        assert!(DemandHint::new("a", None).is_none());
        assert!(DemandHint::new(&format!("{hash}.mp4"), None).is_none());
        assert!(DemandHint::new(&hash, Some(&"x".repeat(1025))).is_none());
        assert_eq!(
            serde_json::to_value(DemandHint::new(&hash, None).unwrap()).unwrap()["reason"],
            "missing_readiness"
        );
    }
    #[test]
    fn invalid_reversed_range_is_ignored_like_other_malformed_ranges() {
        assert_eq!(single_range(Some("bytes=4-3")), None);
    }
    #[test]
    fn canary_is_disabled_without_exact_host_and_rejects_forwarded_host_conflicts() {
        assert_eq!(
            route(None, "media-b2.divine.video", None),
            CanaryRoute::Denied
        );
        assert_eq!(
            route(None, "media.divine.video", None),
            CanaryRoute::Canonical
        );
        assert_eq!(
            route(Some("media-b2.divine.video"), "media.divine.video", None),
            CanaryRoute::Canonical
        );
        assert_eq!(
            route(Some("media-b2.divine.video"), "media-b2.divine.video", None),
            CanaryRoute::Canary
        );
        assert_eq!(
            route(
                Some("media-b2.divine.video"),
                "media-b2.divine.video",
                Some("media.divine.video")
            ),
            CanaryRoute::Denied
        );
        assert_eq!(
            route(
                Some("media-b2.divine.video"),
                "media.divine.video",
                Some("media-b2.divine.video")
            ),
            CanaryRoute::Denied
        );
        assert_eq!(
            route(
                Some("media-b2.divine.video"),
                "media-b2.divine.video:443",
                None
            ),
            CanaryRoute::Denied
        );
    }
    #[test]
    fn originals_only_rejects_derivatives_and_write_routes() {
        let hash = "a".repeat(64);
        for path in [format!("/{hash}"), format!("/{hash}.mp4")] {
            assert_eq!(original_hash("GET", &path), Some(hash.clone()));
            assert_eq!(original_hash("HEAD", &path), Some(hash.clone()));
        }
        for path in [
            format!("/{hash}.jpg"),
            format!("/{hash}.hls"),
            format!("/{hash}/720p"),
            "/admin".into(),
            "/upload".into(),
        ] {
            assert_eq!(original_hash("GET", &path), None);
        }
        assert_eq!(original_hash("PUT", &format!("/{hash}")), None);
        assert_eq!(original_hash("OPTIONS", &format!("/{hash}")), None);
    }
    #[test]
    fn readiness_requires_verified_hash_bucket_key_and_version() {
        let hash = "a".repeat(64);
        let value = serde_json::json!({"version":1,"sha256":hash,"verified_sha256":hash,"bucket":"private-test","key":hash,"size":9,"verified_at":1,"destination_version_id":"4_zTest"});
        let ready: Readiness = serde_json::from_value(value.clone()).unwrap();
        assert!(ready.matches(&hash, "private-test", 9));
        assert!(!ready.matches(&hash, "other", 9));
        assert!(!ready.matches(&hash, "private-test", 10));
        for (key, wrong) in [
            ("verified_sha256", serde_json::json!("b".repeat(64))),
            ("destination_version_id", serde_json::json!("")),
            ("key", serde_json::json!("other")),
            ("version", serde_json::json!(2)),
        ] {
            let mut invalid = value.clone();
            invalid[key] = wrong;
            assert!(!serde_json::from_value::<Readiness>(invalid)
                .unwrap()
                .matches(&hash, "private-test", 9));
        }
    }
    #[test]
    fn canary_origin_size_checks_range_total_and_actual_partial_length() {
        assert!(origin_size_matches(200, Some("9"), None, 9));
        assert!(!origin_size_matches(200, Some("10"), None, 9));
        assert!(origin_size_matches(206, Some("3"), Some("bytes 1-3/9"), 9));
        assert!(!origin_size_matches(
            206,
            Some("3"),
            Some("bytes 1-3/10"),
            9
        ));
        assert!(!origin_size_matches(206, Some("9"), Some("bytes 1-3/9"), 9));
        assert!(!origin_size_matches(
            206,
            Some("3"),
            Some("bytes 8-10/9"),
            9
        ));
        assert!(!origin_size_matches(206, Some("3"), None, 9));
    }
}
