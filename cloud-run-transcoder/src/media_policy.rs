// ABOUTME: Resolve video delivery permission from authoritative server metadata.
// ABOUTME: Jobs and repair credentials cannot grant encoding permission.
use anyhow::{anyhow, bail, ensure, Context, Result};
use serde::Deserialize;
use std::{sync::OnceLock, time::Duration};

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum MediaPolicy {
    CopyOnly,
    AllowEncode,
}

pub(crate) async fn resolve(config: &crate::Config, hash: &str) -> Result<MediaPolicy> {
    let Some(base) = config.media_processing_policy_url.as_deref() else {
        return Ok(MediaPolicy::CopyOnly);
    };
    let url = policy_url(base, hash)?;
    let secret = config
        .webhook_secret
        .as_deref()
        .filter(|s| !s.is_empty())
        .context("Media policy authentication is not configured")?;
    fetch_policy(client(), url, secret, hash).await
}

fn policy_url(base: &str, hash: &str) -> Result<reqwest::Url> {
    ensure!(
        crate::valid_transcode_hash(hash),
        "Invalid media policy hash"
    );
    let mut url = reqwest::Url::parse(base).map_err(|_| anyhow!("Invalid media policy URL"))?;
    ensure!(
        url.scheme() == "https"
            && url.host_str().is_some()
            && url.username().is_empty()
            && url.password().is_none()
            && url.query().is_none()
            && url.fragment().is_none(),
        "Media policy URL must be HTTPS without credentials, query or fragment"
    );
    let path = format!("{}/{}", url.path().trim_end_matches('/'), hash);
    url.set_path(&path);
    Ok(url)
}

fn client() -> &'static reqwest::Client {
    static CLIENT: OnceLock<reqwest::Client> = OnceLock::new();
    CLIENT.get_or_init(|| {
        reqwest::Client::builder()
            .timeout(Duration::from_secs(5))
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .expect("media policy HTTP client")
    })
}

async fn fetch_policy(
    client: &reqwest::Client,
    url: reqwest::Url,
    secret: &str,
    hash: &str,
) -> Result<MediaPolicy> {
    // Do not propagate transport errors or response bodies: these may contain
    // credentials or private metadata. All lookup failures remain retryable.
    let mut response = client
        .get(url)
        .bearer_auth(secret)
        .header(reqwest::header::CACHE_CONTROL, "no-store")
        .send()
        .await
        .map_err(|_| anyhow!("Media policy lookup failed"))?;
    ensure!(
        response.status().is_success(),
        "Media policy lookup was not successful"
    );
    let mut body = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|_| anyhow!("Media policy response failed"))?
    {
        if body.len() + chunk.len() > 4096 {
            bail!("Media policy response exceeds size limit");
        }
        body.extend_from_slice(&chunk);
    }
    #[derive(Deserialize)]
    struct Decision {
        sha256: String,
        policy: MediaPolicy,
    }
    let decision: Decision =
        serde_json::from_slice(&body).map_err(|_| anyhow!("Invalid media policy response"))?;
    ensure!(decision.sha256 == hash, "Media policy hash mismatch");
    Ok(decision.policy)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{extract::Request, http::StatusCode, response::IntoResponse, Router};
    use std::sync::{Arc, Mutex};

    const HASH: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    #[tokio::test]
    async fn absent_endpoint_is_copy_only_but_bad_configuration_is_an_error() {
        let config = crate::Config::from_lookup(|_| None);
        assert_eq!(resolve(&config, HASH).await.unwrap(), MediaPolicy::CopyOnly);
        for base in [
            "",
            "http://example.test/policy",
            "https://user:secret@example.test/policy",
            "https://example.test/policy?token=secret",
            "https://example.test/policy#fragment",
        ] {
            let config = crate::Config::from_lookup(|key| match key {
                "MEDIA_PROCESSING_POLICY_URL" => Some(base.into()),
                "WEBHOOK_SECRET" => Some("synthetic-secret".into()),
                _ => None,
            });
            let error = resolve(&config, HASH).await.unwrap_err();
            assert!(!format!("{error:#}").contains("secret"));
        }
        let config = crate::Config::from_lookup(|key| {
            (key == "MEDIA_PROCESSING_POLICY_URL").then(|| "https://example.test/policy".into())
        });
        assert!(resolve(&config, HASH).await.is_err());
        assert!(policy_url("https://example.test/policy", "../other").is_err());
        assert_eq!(
            policy_url("https://example.test/policy/", HASH)
                .unwrap()
                .as_str(),
            format!("https://example.test/policy/{HASH}")
        );
    }

    #[tokio::test]
    async fn authenticated_lookup_requires_success_exact_identity_and_known_permission() {
        for (status, body, expected) in [
            (
                200,
                format!(r#"{{"sha256":"{HASH}","policy":"copy_only"}}"#),
                Some(MediaPolicy::CopyOnly),
            ),
            (
                200,
                format!(r#"{{"sha256":"{HASH}","policy":"allow_encode"}}"#),
                Some(MediaPolicy::AllowEncode),
            ),
            (
                200,
                r#"{"sha256":"wrong","policy":"allow_encode"}"#.into(),
                None,
            ),
            (
                200,
                format!(r#"{{"sha256":"{HASH}","policy":"unknown"}}"#),
                None,
            ),
            (200, "{}".into(), None),
            (200, "private-malformed-body".into(), None),
            (403, "private-denied-body".into(), None),
            (503, "private-failed-body".into(), None),
            (302, "private-redirect-body".into(), None),
            (200, "x".repeat(8192), None),
        ] {
            let seen = Arc::new(Mutex::new(Vec::new()));
            let requests = seen.clone();
            let app = Router::new().fallback(move |req: Request| {
                let body = body.clone();
                requests.lock().unwrap().push((
                    req.method().clone(),
                    req.uri().path().to_string(),
                    req.headers().clone(),
                ));
                async move {
                    let mut response =
                        (StatusCode::from_u16(status).unwrap(), body).into_response();
                    if status == 302 {
                        response.headers_mut().insert(
                            axum::http::header::LOCATION,
                            "/redirect-target".parse().unwrap(),
                        );
                    }
                    response
                }
            });
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let url = reqwest::Url::parse(&format!(
                "http://{}/policy/{HASH}",
                listener.local_addr().unwrap()
            ))
            .unwrap();
            let task = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
            let result = fetch_policy(client(), url, "synthetic-secret", HASH).await;
            match expected {
                Some(expected) => assert_eq!(result.unwrap(), expected),
                None => {
                    let error = result.unwrap_err();
                    assert!(!error.is::<crate::TerminalTranscode>());
                    let message = format!("{error:#}");
                    assert!(!message.contains("private-"));
                    assert!(!message.contains("synthetic-secret"));
                }
            }
            let requests = seen.lock().unwrap();
            assert_eq!(requests.len(), 1);
            assert_eq!(requests[0].0, "GET");
            assert_eq!(requests[0].1, format!("/policy/{HASH}"));
            assert_eq!(requests[0].2["authorization"], "Bearer synthetic-secret");
            assert_eq!(requests[0].2["cache-control"], "no-store");
            task.abort();
        }
    }

    #[tokio::test]
    async fn lookup_connection_and_deadline_failures_stay_retryable() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = reqwest::Url::parse(&format!(
            "http://{}/policy/{HASH}",
            listener.local_addr().unwrap()
        ))
        .unwrap();
        let result = tokio::time::timeout(
            Duration::from_secs(7),
            fetch_policy(client(), url.clone(), "synthetic-secret", HASH),
        )
        .await
        .expect("the production policy client must enforce its own deadline");
        assert!(result.is_err());
        assert!(!result.unwrap_err().is::<crate::TerminalTranscode>());
        drop(listener);
        assert!(fetch_policy(client(), url, "synthetic-secret", HASH)
            .await
            .is_err());
    }
}
