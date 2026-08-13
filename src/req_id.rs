// ABOUTME: Fastly request adapter for the shared request correlation ID sanitizer
// ABOUTME: Extracts caller or edge IDs and generates a local fallback when needed

use blossom_core::request_diagnostics::external_request_id;
use fastly::Request;

/// Header upstream callers (e.g. moderation-service) can send to pin a
/// correlation ID across their retry loops.
pub(crate) const REQUEST_ID_HEADER: &str = "x-request-id";
const EDGE_REQUEST_ID_HEADER: &str = "x-divine-edge-request-id";

/// Cloudflare adds this to every request. Useful as a fallback because it
/// lets an operator cross-reference Blossom stderr with CF edge logs.
const CF_RAY_HEADER: &str = "cf-ray";

/// Extract or generate a request correlation ID.
///
/// Priority:
/// 1. `x-request-id` if the caller provided one (preferred; lets upstream
///    retry loops pin the same ID across attempts).
/// 2. Leading segment of `cf-ray` (Cloudflare-provided; free correlation
///    with CF edge logs).
/// 3. Generated short hex ID derived from the current nanosecond clock.
pub(crate) fn for_request(req: &Request) -> String {
    if let Some(request_id) = external_request_id(
        req.get_header_str(EDGE_REQUEST_ID_HEADER),
        req.get_header_str(REQUEST_ID_HEADER),
        req.get_header_str(CF_RAY_HEADER),
    ) {
        return request_id;
    }
    generate()
}

fn generate() -> String {
    let ns = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0);
    format!("{:012x}", ns & 0x0000_FFFF_FFFF_FFFF)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_returns_hex_of_expected_length() {
        let id = generate();
        assert_eq!(id.len(), 12);
        assert!(id.chars().all(|c| c.is_ascii_hexdigit()));
    }
}
