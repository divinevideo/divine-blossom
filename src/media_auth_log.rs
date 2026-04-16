use crate::viewer_auth::{ViewerAuthDiagnostics, ViewerAuthState};

pub fn format_media_auth_log(
    route: &str,
    diagnostics: &ViewerAuthDiagnostics,
    outcome: &str,
) -> String {
    format!(
        concat!(
            "[MEDIA AUTH] ",
            "route={} method={} path={} host={} auth_present={} auth_state={} ",
            "normalized_request_url={} viewer_pubkey_present={} auth_error={:?} outcome={}"
        ),
        route,
        diagnostics.method,
        diagnostics.path,
        diagnostics.host.as_deref().unwrap_or("-"),
        diagnostics.auth_present,
        auth_state_label(diagnostics.auth_state),
        diagnostics.normalized_request_url.as_deref().unwrap_or("-"),
        diagnostics.viewer_pubkey.is_some(),
        diagnostics.auth_error.as_deref().unwrap_or("-"),
        outcome,
    )
}

fn auth_state_label(state: ViewerAuthState) -> &'static str {
    match state {
        ViewerAuthState::Missing => "missing",
        ViewerAuthState::InvalidScheme => "invalid_scheme",
        ViewerAuthState::ParseFailed => "parse_failed",
        ViewerAuthState::RequestUrlInvalid => "request_url_invalid",
        ViewerAuthState::ValidationFailed => "validation_failed",
        ViewerAuthState::Valid => "valid",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn diagnostics(auth_state: ViewerAuthState) -> ViewerAuthDiagnostics {
        ViewerAuthDiagnostics {
            method: "GET".into(),
            path: "/abc123".into(),
            host: Some("media.divine.video".into()),
            auth_present: auth_state != ViewerAuthState::Missing,
            auth_state,
            normalized_request_url: Some("https://media.divine.video/abc123".into()),
            viewer_pubkey: (auth_state == ViewerAuthState::Valid).then(|| "pubkey".into()),
            auth_error: (auth_state == ViewerAuthState::ValidationFailed)
                .then(|| "Method mismatch: expected GET, got HEAD".into()),
        }
    }

    #[test]
    fn format_media_auth_log_renders_anonymous_age_gate() {
        let line =
            format_media_auth_log("blob", &diagnostics(ViewerAuthState::Missing), "age_gated");

        assert!(line.contains("route=blob"));
        assert!(line.contains("auth_present=false"));
        assert!(line.contains("auth_state=missing"));
        assert!(line.contains("outcome=age_gated"));
    }

    #[test]
    fn format_media_auth_log_renders_valid_viewer_access() {
        let line = format_media_auth_log("blob", &diagnostics(ViewerAuthState::Valid), "allowed");

        assert!(line.contains("auth_present=true"));
        assert!(line.contains("auth_state=valid"));
        assert!(line.contains("viewer_pubkey_present=true"));
        assert!(line.contains("outcome=allowed"));
    }

    #[test]
    fn format_media_auth_log_renders_validation_failure() {
        let line = format_media_auth_log(
            "blob",
            &diagnostics(ViewerAuthState::ValidationFailed),
            "auth_invalid",
        );

        assert!(line.contains("auth_state=validation_failed"));
        assert!(line.contains("auth_error=\"Method mismatch: expected GET, got HEAD\""));
        assert!(line.contains("outcome=auth_invalid"));
    }
}
