// ABOUTME: Request correlation ID helper for moderation and delete log traces
// ABOUTME: Threaded through handlers so retries and partial failures are greppable across stderr

use fastly::Request;

/// Header upstream callers (e.g. moderation-service) can send to pin a
/// correlation ID across their retry loops.
pub(crate) const REQUEST_ID_HEADER: &str = "x-request-id";

/// Cloudflare adds this to every request. Useful as a fallback because it
/// lets an operator cross-reference Blossom stderr with CF edge logs.
const CF_RAY_HEADER: &str = "cf-ray";

/// Max characters kept from any external ID. Keeps log lines readable.
const MAX_LEN: usize = 16;

/// Extract or generate a request correlation ID.
///
/// Priority:
/// 1. `x-request-id` if the caller provided one (preferred; lets upstream
///    retry loops pin the same ID across attempts).
/// 2. Leading segment of `cf-ray` (Cloudflare-provided; free correlation
///    with CF edge logs).
/// 3. Generated short hex ID derived from the current nanosecond clock.
pub(crate) fn for_request(req: &Request) -> String {
    if let Some(v) = req.get_header_str(REQUEST_ID_HEADER) {
        let trimmed = v.trim();
        if !trimmed.is_empty() {
            return truncate(trimmed);
        }
    }
    if let Some(v) = req.get_header_str(CF_RAY_HEADER) {
        if let Some(left) = v.split('-').next() {
            let trimmed = left.trim();
            if !trimmed.is_empty() {
                return truncate(trimmed);
            }
        }
    }
    generate()
}

fn truncate(s: &str) -> String {
    s.chars().take(MAX_LEN).collect()
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
    fn truncate_limits_length() {
        let long = "a".repeat(32);
        assert_eq!(truncate(&long).len(), MAX_LEN);
    }

    #[test]
    fn truncate_preserves_short() {
        assert_eq!(truncate("abc123"), "abc123");
    }

    #[test]
    fn generate_returns_hex_of_expected_length() {
        let id = generate();
        assert_eq!(id.len(), 12);
        assert!(id.chars().all(|c| c.is_ascii_hexdigit()));
    }
}
