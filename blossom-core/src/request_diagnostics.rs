use crate::types::{
    is_audio_path, is_hash_path, is_quality_variant_path, is_transcript_path, is_vtt_file_path,
};

/// Cap keeps the ID short enough for both the Compute sanitizer and the outer
/// VCL `substr` copy to agree while still preserving common caller IDs
/// verbatim: UUIDs (36), W3C trace ids (32), and `traceparent` values (55).
/// Longer caller values survive as their sanitized 64-character prefix, so
/// cross-service correlation stays exact while very long caller-side
/// correlation matches on the prefix only.
const MAX_REQUEST_ID_LEN: usize = 64;

/// Return whether a Compute response belongs in persistent diagnostics.
pub fn should_persist_compute_diagnostic(status: u16) -> bool {
    (500..=599).contains(&status)
}

/// Restrict an untrusted request ID to a short, injection-safe log value.
pub fn sanitize_request_id(value: &str) -> String {
    value
        .chars()
        .filter(|character| {
            character.is_ascii_alphanumeric() || *character == '-' || *character == '_'
        })
        .take(MAX_REQUEST_ID_LEN)
        .collect()
}

/// Select and sanitize an externally supplied request correlation ID.
pub fn external_request_id(
    edge_request_id: Option<&str>,
    request_id: Option<&str>,
    cf_ray: Option<&str>,
) -> Option<String> {
    edge_request_id
        .map(sanitize_request_id)
        .filter(|value| !value.is_empty())
        .or_else(|| {
            request_id
                .map(sanitize_request_id)
                .filter(|value| !value.is_empty())
        })
        .or_else(|| {
            cf_ray
                .and_then(|value| value.split('-').next())
                .map(sanitize_request_id)
                .filter(|value| !value.is_empty())
        })
}

/// Return a stable route category without retaining path parameters.
///
/// Path-shape checks reuse the exported blossom-core predicates and follow the
/// router's arm order in the Compute service so the recorded category cannot
/// drift from actual routing.
pub fn route_category(path: &str) -> &'static str {
    if path == "/" {
        "landing"
    } else if path == "/version" {
        "version"
    } else if path.ends_with(".hls") {
        "hls_master"
    } else if path.contains("/hls/") {
        "hls_content"
    } else if is_vtt_file_path(path) || is_transcript_path(path) {
        "transcript"
    } else if path.starts_with("/v1/subtitles/") {
        "subtitle_api"
    } else if path.ends_with("/provenance") {
        "provenance"
    } else if is_audio_path(path) {
        "audio"
    } else if is_quality_variant_path(path) {
        "quality_variant"
    } else if is_hash_path(path) {
        "blob"
    } else if path == "/upload" || path.starts_with("/upload/") {
        "upload"
    } else if path == "/transcribe" {
        "transcribe"
    } else if path == "/vanish" {
        "vanish"
    } else if path == "/report" {
        "report"
    } else if path == "/mirror" {
        "mirror"
    } else if path.starts_with("/list/") {
        "list"
    } else if path == "/admin" || path.starts_with("/admin/") {
        "admin"
    } else {
        "other"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitizer_preserves_allowed_ascii_and_limits_length() {
        assert_eq!(sanitize_request_id("abc123-_"), "abc123-_");
        let uuid = "8f14e45f-ceea-467f-8302-9157b1dce6d4";
        assert_eq!(sanitize_request_id(uuid), uuid);
        assert_eq!(sanitize_request_id(&"a".repeat(80)), "a".repeat(64));
    }

    #[test]
    fn persistent_compute_diagnostics_are_error_only() {
        assert!(!should_persist_compute_diagnostic(200));
        assert!(!should_persist_compute_diagnostic(404));
        assert!(should_persist_compute_diagnostic(500));
        assert!(should_persist_compute_diagnostic(502));
        assert!(should_persist_compute_diagnostic(599));
        assert!(!should_persist_compute_diagnostic(600));
    }

    #[test]
    fn sanitizer_removes_log_injection_characters() {
        assert_eq!(sanitize_request_id("abc\n[ADMIN] fake"), "abcADMINfake");
        assert_eq!(sanitize_request_id("\x1b[31mred\x1b[0m"), "31mred0m");
        assert_eq!(sanitize_request_id("\n\r\t "), "");
    }

    #[test]
    fn external_id_prefers_caller_and_falls_back_safely() {
        assert_eq!(
            external_request_id(None, Some("caller-id"), Some("cf-ray-SJC")),
            Some("caller-id".to_string())
        );
        assert_eq!(
            external_request_id(Some("edge-id"), Some("caller-id"), Some("cf-ray-SJC")),
            Some("edge-id".to_string())
        );
        assert_eq!(
            external_request_id(None, Some("\n"), Some("cf-ray-SJC")),
            Some("cf".to_string())
        );
        assert_eq!(
            external_request_id(None, None, Some("cf-ray-SJC")),
            Some("cf".to_string())
        );
        assert_eq!(external_request_id(None, Some("\n"), Some("\r")), None);
    }

    #[test]
    fn routes_do_not_retain_identifiers() {
        let hash = "a".repeat(64);
        assert_eq!(route_category(&format!("/{hash}.mp4")), "blob");
        assert_eq!(
            route_category(&format!("/{hash}/hls/segment.ts")),
            "hls_content"
        );
        assert_eq!(route_category("/admin/api/user/sensitive-value"), "admin");
        assert_eq!(route_category("/unknown?secret=value"), "other");
    }

    #[test]
    fn route_categories_match_router_predicates() {
        let hash = "a".repeat(64);
        // Transcript casing follows parse_transcript_path (case-insensitive).
        assert_eq!(route_category(&format!("/{hash}/Vtt")), "transcript");
        assert_eq!(route_category(&format!("/{hash}.vtt")), "transcript");
        // Invalid transcript-shaped paths route to 404, not "transcript".
        assert_eq!(route_category("/not-a-hash.vtt"), "other");
        // Router arm order: /hls/ wins over a /provenance suffix.
        assert_eq!(
            route_category(&format!("/{hash}/hls/provenance")),
            "hls_content"
        );
        // Quality-variant detection requires a valid hash, not just a
        // "/720p" substring.
        assert_eq!(route_category("/720p"), "other");
        assert_eq!(route_category(&format!("/{hash}/720p")), "quality_variant");
        // The blob category follows the exported is_hash_path semantics:
        // a valid hash followed by an unknown segment is not a blob route.
        assert_eq!(route_category(&format!("/{hash}/junk")), "other");
    }
}
