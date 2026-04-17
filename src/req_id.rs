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
        let sanitized = sanitize(v);
        if !sanitized.is_empty() {
            return sanitized;
        }
    }
    if let Some(v) = req.get_header_str(CF_RAY_HEADER) {
        if let Some(left) = v.split('-').next() {
            let sanitized = sanitize(left);
            if !sanitized.is_empty() {
                return sanitized;
            }
        }
    }
    generate()
}

/// Restrict correlation IDs to a safe log charset. Header values are
/// attacker-controllable; without filtering, an `X-Request-Id` containing
/// newlines or ANSI escapes would be echoed verbatim into stderr and could
/// forge log lines or corrupt terminal output for operators tailing logs.
fn sanitize(s: &str) -> String {
    s.chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_')
        .take(MAX_LEN)
        .collect()
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
    fn sanitize_limits_length() {
        let long = "a".repeat(32);
        assert_eq!(sanitize(&long).len(), MAX_LEN);
    }

    #[test]
    fn sanitize_preserves_short_alnum() {
        assert_eq!(sanitize("abc123-_"), "abc123-_");
    }

    #[test]
    fn sanitize_strips_log_injection_chars() {
        assert_eq!(sanitize("abc\n[ADMIN] fake"), "abcADMINfake");
        assert_eq!(sanitize("\x1b[31mred\x1b[0m"), "31mred0m");
        assert_eq!(sanitize("a b\tc\rd"), "abcd");
    }

    #[test]
    fn sanitize_empty_when_all_filtered() {
        assert_eq!(sanitize("\n\r\t "), "");
        assert_eq!(sanitize(""), "");
    }

    #[test]
    fn generate_returns_hex_of_expected_length() {
        let id = generate();
        assert_eq!(id.len(), 12);
        assert!(id.chars().all(|c| c.is_ascii_hexdigit()));
    }
}
