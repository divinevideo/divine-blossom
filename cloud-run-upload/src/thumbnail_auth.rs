//! Service credential for the public `/thumbnail/<hash>` route.
//!
//! The same guard as divine-upload-server's (divine-upload-server#52): this
//! service reads the same media bucket and serves the same route, and it can't
//! read Blossom's moderation state either. Same settings, same header, same
//! modes, so one token and one rollout cover both services.
//!
//! This service has no metrics listener, so every guarded request logs one
//! `thumbnail_token` line with `result=authenticated|missing|invalid`; a
//! log-based metric on that line gives the flip signal.

use axum::http::HeaderMap;
use sha2::{Digest, Sha256};
use std::sync::atomic::{AtomicU64, Ordering};
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

static AUTHENTICATED: AtomicU64 = AtomicU64::new(0);
static MISSING: AtomicU64 = AtomicU64::new(0);
static INVALID: AtomicU64 = AtomicU64::new(0);

impl Policy {
    pub fn from_env() -> anyhow::Result<Self> {
        Self::from_lookup(|key| std::env::var(key).ok())
    }

    pub fn from_lookup(lookup: impl Fn(&str) -> Option<String>) -> anyhow::Result<Self> {
        let token = match lookup(TOKEN_ENV) {
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
        let required = match lookup(REQUIRED_ENV).as_deref().map(str::trim) {
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
        let reason = match headers.get(HEADER) {
            None => Reason::Missing,
            Some(_) if presented_matches(headers, expected) => {
                AUTHENTICATED.fetch_add(1, Ordering::Relaxed);
                return Decision::Allow;
            }
            Some(_) => Reason::Invalid,
        };
        match reason {
            Reason::Missing => MISSING.fetch_add(1, Ordering::Relaxed),
            Reason::Invalid => INVALID.fetch_add(1, Ordering::Relaxed),
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

fn presented_matches(headers: &HeaderMap, expected: &str) -> bool {
    let Some(candidate) = headers.get(HEADER).map(|v| v.as_bytes()) else {
        return false;
    };
    // Compare fixed-size digests in constant time, so neither the content nor
    // the length of the configured token shapes the comparison time.
    let expected = Sha256::digest(expected.as_bytes());
    let candidate = Sha256::digest(candidate);
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
        .take(64)
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
        target: "thumbnail_token",
        mode = policy.mode(),
        result,
        refused = matches!(decision, Decision::Reject(_)),
        request_id = %request_id(headers),
        "thumbnail_token"
    );
}

#[cfg(test)]
pub fn counts() -> (u64, u64, u64) {
    (
        AUTHENTICATED.load(Ordering::Relaxed),
        MISSING.load(Ordering::Relaxed),
        INVALID.load(Ordering::Relaxed),
    )
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

    #[test]
    fn counters_separate_authenticated_missing_and_invalid() {
        let (a, m, i) = counts();
        let p = Policy::Observe("t".into());
        p.decide(&headers(Some("t")));
        p.decide(&headers(None));
        p.decide(&headers(Some("x")));
        let (a2, m2, i2) = counts();
        assert!(a2 > a && m2 > m && i2 > i);
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
}
