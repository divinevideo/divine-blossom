// ABOUTME: Pure transcription-authorization contract shared with the upload proxy.
// ABOUTME: Exact action match + BUD-11 `server`-tag host scoping, all unit-tested.

/// The action tag a transcription authorization must carry. Divine scopes
/// transcription tokens with `t=media` rather than a standard Blossom verb.
/// Matched exactly (case-sensitive) so the edge rate-limit gate accepts exactly
/// what the upload service accepts — an uppercase `MEDIA` the upload service
/// would reject must not charge quota at the edge.
pub const TRANSCRIBE_ACTION: &str = "media";

/// Hosts a transcription `server` tag may target (BUD-11 domain scope). Must
/// stay in lockstep with the upload service's allow-list: a token scoped to any
/// other host is a replay from elsewhere and charges no quota here.
pub const ALLOWED_SERVER_HOSTS: [&str; 2] = ["media.divine.video", "upload.divine.video"];

/// Whether a `t` tag value authorizes transcription. Exact, case-sensitive.
pub fn action_allowed(action: &str) -> bool {
    action == TRANSCRIBE_ACTION
}

/// Reduces a BUD-11 `server` tag value to a bare lowercase host, dropping any
/// scheme, userinfo, port, and path. Parses with `url::Url` — the exact parser
/// the upload service uses — so the authority is extracted with full URL
/// semantics rather than a hand-rolled split. That matters for parity: a
/// hand-rolled split truncates `https://media.divine.video:abc` to the allowed
/// `media.divine.video`, but `url::Url` rejects the non-numeric port, so the
/// value falls through to the whole trimmed string and fails the allow-list —
/// exactly as the upload service rejects it. Bare hosts (no scheme) get an
/// `https://` prefix before parsing. An unparseable value returns the whole
/// trimmed string, which never matches the allow-list (fail closed).
pub fn server_tag_host(value: &str) -> String {
    let trimmed = value.trim();
    let candidate = if trimmed.contains("://") {
        trimmed.to_string()
    } else {
        format!("https://{trimmed}")
    };
    url::Url::parse(&candidate)
        .ok()
        .and_then(|parsed| parsed.host_str().map(str::to_ascii_lowercase))
        .unwrap_or_else(|| trimmed.to_ascii_lowercase())
}

/// Whether a `server` tag value targets a Divine transcription host.
pub fn server_tag_allowed(server: &str) -> bool {
    ALLOWED_SERVER_HOSTS.contains(&server_tag_host(server).as_str())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn action_allowed_is_exact_and_case_sensitive() {
        assert!(action_allowed("media"));
        assert!(!action_allowed("MEDIA"));
        assert!(!action_allowed("Media"));
        assert!(!action_allowed("get"));
        assert!(!action_allowed(""));
    }

    #[test]
    fn server_tag_host_strips_scheme_port_and_path() {
        assert_eq!(server_tag_host("media.divine.video"), "media.divine.video");
        assert_eq!(
            server_tag_host("https://media.divine.video"),
            "media.divine.video"
        );
        assert_eq!(
            server_tag_host("https://media.divine.video:443/upload"),
            "media.divine.video"
        );
        assert_eq!(
            server_tag_host("HTTPS://Media.Divine.Video/"),
            "media.divine.video"
        );
    }

    #[test]
    fn server_tag_host_resists_crafted_authority_confusion() {
        // The path segment must not be mistaken for the host.
        assert_eq!(
            server_tag_host("https://evil.example/x://media.divine.video"),
            "evil.example"
        );
        // Userinfo before `@` must not be mistaken for the host.
        assert_eq!(
            server_tag_host("https://media.divine.video:x@evil.com"),
            "evil.com"
        );
        // A non-numeric port makes the authority unparseable; it must fall
        // through to the whole value, not be truncated to the allowed host.
        assert_eq!(
            server_tag_host("https://media.divine.video:abc"),
            "https://media.divine.video:abc"
        );
    }

    #[test]
    fn server_tag_allowed_accepts_only_divine_hosts() {
        assert!(server_tag_allowed("https://media.divine.video"));
        assert!(server_tag_allowed("upload.divine.video"));
        // A valid explicit port still resolves to the allowed host.
        assert!(server_tag_allowed("https://media.divine.video:443"));
        assert!(!server_tag_allowed("https://evil.example.com"));
        assert!(!server_tag_allowed("cdn.divine.video"));
        assert!(!server_tag_allowed("https://evil.example/x://media.divine.video"));
        assert!(!server_tag_allowed("https://media.divine.video:x@evil.com"));
        // Malformed port: rejected here just as the upload proxy rejects it.
        assert!(!server_tag_allowed("https://media.divine.video:abc"));
    }
}
