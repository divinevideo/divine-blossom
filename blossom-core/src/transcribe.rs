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
/// scheme, userinfo, port, and path. Mirrors the upload service's `url::Url`
/// based parser without pulling a URL dependency into the WASM edge: the
/// authority ends at the first `/`, `?`, or `#`; userinfo before an `@` is
/// stripped; a port after `:` is dropped. This defeats crafted values such as
/// `https://evil.example/x://media.divine.video` (host is `evil.example`) and
/// `https://media.divine.video:x@evil.com` (host is `evil.com`).
pub fn server_tag_host(value: &str) -> String {
    let trimmed = value.trim();
    let after_scheme = match trimmed.find("://") {
        Some(index) => &trimmed[index + 3..],
        None => trimmed,
    };
    let authority_end = after_scheme
        .find(['/', '?', '#'])
        .unwrap_or(after_scheme.len());
    let authority = &after_scheme[..authority_end];
    let host_port = match authority.rfind('@') {
        Some(index) => &authority[index + 1..],
        None => authority,
    };
    let host = match host_port.find(':') {
        Some(index) => &host_port[..index],
        None => host_port,
    };
    host.to_ascii_lowercase()
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
    }

    #[test]
    fn server_tag_allowed_accepts_only_divine_hosts() {
        assert!(server_tag_allowed("https://media.divine.video"));
        assert!(server_tag_allowed("upload.divine.video"));
        assert!(!server_tag_allowed("https://evil.example.com"));
        assert!(!server_tag_allowed("cdn.divine.video"));
        assert!(!server_tag_allowed("https://evil.example/x://media.divine.video"));
        assert!(!server_tag_allowed("https://media.divine.video:x@evil.com"));
    }
}
