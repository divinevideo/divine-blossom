//! Service credential for the public `/thumbnail/<hash>` route.
//!
//! The same guard as divine-upload-server's (divine-upload-server#52): this
//! service reads the same media bucket and serves the same route, and it can't
//! read Blossom's moderation state either. Same settings, same header, same
//! modes, so one token and one rollout cover both services.
//!
//! This service has no metrics listener, so every guarded request logs one
//! `thumbnail_token` line with `result=authenticated|missing|invalid`; a
//! log-based metric on that line is the flip signal (there are no in-process
//! counters).

use axum::http::HeaderMap;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use tracing::info;

/// Header divine-blossom sets on its `/thumbnail/<hash>` calls.
pub const HEADER: &str = "x-divine-thumbnail-token";
const TOKEN_ENV: &str = "THUMBNAIL_SERVICE_TOKEN";
const REQUIRED_ENV: &str = "THUMBNAIL_TOKEN_REQUIRED";

#[derive(Clone, PartialEq, Eq)]
pub enum Policy {
    /// No token configured: every request is served, as before this module.
    Open,
    /// Token configured, not yet required: serve everything, log what lacks it.
    Observe(String),
    /// Token required: requests without a valid token get 404.
    Required(String),
}

// The token must never reach a log line, so `Debug` names the mode only.
impl std::fmt::Debug for Policy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.mode())
    }
}

/// Why a request didn't authenticate: a caller that never sends the token
/// (`missing`) versus a mismatched copy of the secret (`invalid`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reason {
    Missing,
    Invalid,
}

impl Reason {
    pub fn label(self) -> &'static str {
        match self {
            Reason::Missing => "missing",
            Reason::Invalid => "invalid",
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum Decision {
    Allow,
    /// Served only because the token is not required yet.
    AllowUnauthenticated(Reason),
    Reject(Reason),
}

impl Policy {
    pub fn from_env() -> anyhow::Result<Self> {
        Self::from_var_lookup(|key| std::env::var(key))
    }

    #[cfg(test)]
    pub fn from_lookup(lookup: impl Fn(&str) -> Option<String>) -> anyhow::Result<Self> {
        Self::from_values(lookup(TOKEN_ENV), lookup(REQUIRED_ENV))
    }

    fn from_var_lookup(
        lookup: impl Fn(&str) -> Result<String, std::env::VarError>,
    ) -> anyhow::Result<Self> {
        let read = |key: &str| match lookup(key) {
            Ok(value) => Ok(Some(value)),
            Err(std::env::VarError::NotPresent) => Ok(None),
            Err(std::env::VarError::NotUnicode(_)) => {
                anyhow::bail!("{key} must be valid UTF-8")
            }
        };
        Self::from_values(read(TOKEN_ENV)?, read(REQUIRED_ENV)?)
    }

    fn from_values(token: Option<String>, required: Option<String>) -> anyhow::Result<Self> {
        let token = match token {
            None => None,
            Some(raw) => {
                let token = raw.trim().to_string();
                if token.is_empty() {
                    anyhow::bail!("{TOKEN_ENV} is empty");
                }
                // Visible ASCII only: anything else either can't travel in a
                // header or can never match the header text a request carries.
                if !token.bytes().all(|b| b.is_ascii_graphic()) {
                    anyhow::bail!("{TOKEN_ENV} must be visible ASCII with no spaces");
                }
                Some(token)
            }
        };
        let required = match required.as_deref().map(str::trim) {
            None | Some("") | Some("false") => false,
            Some("true") => true,
            Some(_) => anyhow::bail!("{REQUIRED_ENV} must be true or false"),
        };
        Ok(match (token, required) {
            (None, false) => Policy::Open,
            (None, true) => anyhow::bail!("{REQUIRED_ENV}=true requires {TOKEN_ENV}"),
            (Some(token), false) => Policy::Observe(token),
            (Some(token), true) => Policy::Required(token),
        })
    }

    pub fn mode(&self) -> &'static str {
        match self {
            Policy::Open => "open",
            Policy::Observe(_) => "observe",
            Policy::Required(_) => "required",
        }
    }

    pub fn decide(&self, headers: &HeaderMap) -> Decision {
        let expected = match self {
            Policy::Open => return Decision::Allow,
            Policy::Observe(token) | Policy::Required(token) => token,
        };
        let mut values = headers.get_all(HEADER).iter();
        let reason = match (values.next(), values.next()) {
            (None, None) => Reason::Missing,
            (Some(value), None) if presented_matches(value, expected) => return Decision::Allow,
            _ => Reason::Invalid,
        };
        if matches!(self, Policy::Required(_)) {
            Decision::Reject(reason)
        } else {
            Decision::AllowUnauthenticated(reason)
        }
    }

    /// One startup line describing the mode. Never includes the token.
    pub fn startup_message(&self) -> &'static str {
        match self {
            Policy::Open => "/thumbnail is unauthenticated: THUMBNAIL_SERVICE_TOKEN is not set",
            Policy::Observe(_) => {
                "/thumbnail accepts requests without the service token and logs them \
                 (THUMBNAIL_TOKEN_REQUIRED=false)"
            }
            Policy::Required(_) => "/thumbnail requires the service token",
        }
    }
}

fn presented_matches(value: &axum::http::HeaderValue, expected: &str) -> bool {
    // Compare fixed-size digests in constant time, so neither the content nor
    // the length of the configured token shapes the comparison time.
    let expected = Sha256::digest(expected.as_bytes());
    let candidate = Sha256::digest(value.as_bytes());
    expected.ct_eq(&candidate).into()
}

/// The request id the caller supplied, reduced to safe log characters.
fn request_id(headers: &HeaderMap) -> String {
    let id: String = headers
        .get("x-request-id")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_')
        .take(128)
        .collect();
    if id.is_empty() {
        "-".into()
    } else {
        id
    }
}

/// Log one line per guarded request for the log-based flip metric.
pub fn log_decision(policy: &Policy, decision: &Decision, headers: &HeaderMap) {
    if matches!(policy, Policy::Open) {
        return;
    }
    let result = match decision {
        Decision::Allow => "authenticated",
        Decision::AllowUnauthenticated(reason) | Decision::Reject(reason) => reason.label(),
    };
    info!(
        mode = policy.mode(),
        result,
        refused = matches!(decision, Decision::Reject(_)),
        request_id = %request_id(headers),
        "thumbnail_token"
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn policy(pairs: &[(&str, &str)]) -> anyhow::Result<Policy> {
        let env: HashMap<String, String> = pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        Policy::from_lookup(|key| env.get(key).cloned())
    }

    fn headers(token: Option<&str>) -> HeaderMap {
        let mut map = HeaderMap::new();
        if let Some(token) = token {
            map.insert(HEADER, token.parse().unwrap());
        }
        map
    }

    #[test]
    fn settings_select_the_mode() {
        assert_eq!(policy(&[]).unwrap(), Policy::Open);
        assert_eq!(policy(&[(REQUIRED_ENV, "false")]).unwrap(), Policy::Open);
        assert_eq!(
            policy(&[(TOKEN_ENV, " s3cret ")]).unwrap(),
            Policy::Observe("s3cret".into())
        );
        assert_eq!(
            policy(&[(TOKEN_ENV, "s3cret"), (REQUIRED_ENV, "true")]).unwrap(),
            Policy::Required("s3cret".into())
        );
    }

    #[test]
    fn bad_settings_refuse_to_start() {
        assert!(policy(&[(REQUIRED_ENV, "true")]).is_err());
        assert!(policy(&[(TOKEN_ENV, "   ")]).is_err());
        assert!(policy(&[(TOKEN_ENV, "bad\u{7f}token")]).is_err());
        assert!(policy(&[(TOKEN_ENV, "t\u{f6}ken")]).is_err());
        assert!(policy(&[(TOKEN_ENV, "two words")]).is_err());
        assert!(policy(&[(TOKEN_ENV, "s3cret"), (REQUIRED_ENV, "yes")]).is_err());
    }

    #[test]
    fn decisions_say_why_a_token_was_missing_or_wrong() {
        assert_eq!(Policy::Open.decide(&headers(None)), Decision::Allow);
        let observe = Policy::Observe("s3cret".into());
        assert_eq!(observe.decide(&headers(Some("s3cret"))), Decision::Allow);
        assert_eq!(
            observe.decide(&headers(None)),
            Decision::AllowUnauthenticated(Reason::Missing)
        );
        assert_eq!(
            observe.decide(&headers(Some("s3cre"))),
            Decision::AllowUnauthenticated(Reason::Invalid)
        );
        let required = Policy::Required("s3cret".into());
        assert_eq!(required.decide(&headers(Some("s3cret"))), Decision::Allow);
        assert_eq!(
            required.decide(&headers(None)),
            Decision::Reject(Reason::Missing)
        );
        for wrong in ["s3cret2", "Bearer s3cret", ""] {
            assert_eq!(
                required.decide(&headers(Some(wrong))),
                Decision::Reject(Reason::Invalid),
                "{wrong:?}"
            );
        }
    }

    /// Collects what the `tracing` subscriber writes during a closure.
    fn captured_logs(f: impl FnOnce()) -> String {
        #[derive(Clone, Default)]
        struct Capture(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);
        impl std::io::Write for Capture {
            fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
                self.0.lock().unwrap().extend_from_slice(buf);
                Ok(buf.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for Capture {
            type Writer = Capture;
            fn make_writer(&'a self) -> Self::Writer {
                self.clone()
            }
        }
        let capture = Capture::default();
        let subscriber = tracing_subscriber::fmt()
            .with_env_filter(crate::build_tracing_filter(None).unwrap())
            .with_writer(capture.clone())
            .with_ansi(false)
            .finish();
        tracing::subscriber::with_default(subscriber, f);
        let bytes = capture.0.lock().unwrap().clone();
        String::from_utf8(bytes).unwrap()
    }

    #[test]
    fn each_guarded_request_logs_one_flip_line_without_the_token() {
        let mut with_id = headers(Some("s3cret-token"));
        with_id.insert("x-request-id", "blossom-thumbnail-req1".parse().unwrap());
        let wrong = {
            let mut h = headers(Some("not-it"));
            h.insert("x-request-id", "blossom-thumbnail-req1".parse().unwrap());
            h
        };
        let observe = Policy::Observe("s3cret-token".into());
        let required = Policy::Required("s3cret-token".into());
        let logs = captured_logs(|| {
            for (policy, h) in [
                (&observe, &with_id),
                (&observe, &headers(None)),
                (&observe, &wrong),
                (&required, &wrong),
            ] {
                let decision = policy.decide(h);
                log_decision(policy, &decision, h);
            }
            let open = Policy::Open;
            log_decision(&open, &open.decide(&with_id), &with_id);
        });
        let lines: Vec<&str> = logs
            .lines()
            .filter(|l| l.contains("thumbnail_token"))
            .collect();
        assert_eq!(lines.len(), 4, "{logs}");
        let expect = [
            (
                "observe",
                "authenticated",
                "false",
                "blossom-thumbnail-req1",
            ),
            ("observe", "missing", "false", "-"),
            ("observe", "invalid", "false", "blossom-thumbnail-req1"),
            ("required", "invalid", "true", "blossom-thumbnail-req1"),
        ];
        for (line, (mode, result, refused, id)) in lines.iter().zip(expect) {
            assert!(line.contains(&format!("mode=\"{mode}\"")), "{line}");
            assert!(line.contains(&format!("result=\"{result}\"")), "{line}");
            assert!(line.contains(&format!("refused={refused}")), "{line}");
            assert!(line.contains(&format!("request_id={id}")), "{line}");
        }
        assert!(!logs.contains("s3cret-token"), "{logs}");
        assert!(!logs.contains("not-it"), "{logs}");
    }

    #[test]
    fn the_token_never_appears_in_debug_or_startup_output() {
        let p = Policy::Required("s3cret-value".into());
        assert!(!format!("{p:?}").contains("s3cret"));
        assert!(!p.startup_message().contains("s3cret"));
    }

    #[test]
    fn request_ids_cannot_forge_log_fields() {
        let mut map = HeaderMap::new();
        map.insert("x-request-id", "blossom-thumbnail".parse().unwrap());
        assert_eq!(request_id(&map), "blossom-thumbnail");
        map.insert("x-request-id", "a b=c\"d".parse().unwrap());
        assert_eq!(request_id(&map), "abcd");
        assert_eq!(request_id(&HeaderMap::new()), "-");
    }

    #[test]
    fn non_unicode_env_vars_fail_startup_without_exposing_values() {
        use std::ffi::OsString;
        use std::os::unix::ffi::OsStringExt;
        let bad_utf8 = OsString::from_vec(vec![0xff, 0xfe]);
        for bad_key in [TOKEN_ENV, REQUIRED_ENV] {
            let err = Policy::from_var_lookup(|key| {
                if key == bad_key {
                    Err(std::env::VarError::NotUnicode(bad_utf8.clone()))
                } else {
                    Err(std::env::VarError::NotPresent)
                }
            })
            .unwrap_err()
            .to_string();
            assert!(err.contains(bad_key), "{err}");
            assert!(err.contains("UTF-8"), "{err}");
        }
    }

    #[test]
    fn duplicate_token_headers_are_classified_as_invalid() {
        let observe = Policy::Observe("s3cret".into());
        let required = Policy::Required("s3cret".into());
        let mut dup_matching = headers(Some("s3cret"));
        dup_matching.append(HEADER, "s3cret".parse().unwrap());
        assert_eq!(
            observe.decide(&dup_matching),
            Decision::AllowUnauthenticated(Reason::Invalid)
        );
        assert_eq!(
            required.decide(&dup_matching),
            Decision::Reject(Reason::Invalid)
        );

        let mut dup_mismatched = headers(Some("s3cret"));
        dup_mismatched.append(HEADER, "other".parse().unwrap());
        assert_eq!(
            observe.decide(&dup_mismatched),
            Decision::AllowUnauthenticated(Reason::Invalid)
        );
        assert_eq!(
            required.decide(&dup_mismatched),
            Decision::Reject(Reason::Invalid)
        );
    }

    #[test]
    fn full_prefixed_request_id_is_preserved_in_logs() {
        let full_id = format!("blossom-thumbnail-{}", "a".repeat(64));
        assert_eq!(full_id.len(), 82);
        let mut map = headers(Some("s3cret-token"));
        map.insert("x-request-id", full_id.parse().unwrap());
        assert_eq!(request_id(&map), full_id);

        let observe = Policy::Observe("s3cret-token".into());
        let logs = captured_logs(|| {
            let decision = observe.decide(&map);
            log_decision(&observe, &decision, &map);
        });
        assert!(logs.contains(&format!("request_id={full_id}")), "{logs}");
    }
}
