//! Durable admission for ordinary HLS requests, including fire-and-forget
//! callers. Only the authenticated task delivery can run an ordinary encode.

use super::*;
use anyhow::bail;
use sha2::{Digest, Sha256};

const PATH: &str = "/internal/transcode";
const WORKER_HEADER: &str = "x-divine-transcode-worker";

pub(super) fn route() -> &'static str {
    PATH
}

fn worker_token(secret: &str) -> String {
    let mut digest = Sha256::new();
    digest.update(b"divine-transcoder:dispatch:v1\0");
    digest.update(secret.as_bytes());
    hex::encode(digest.finalize())
}

fn valid_worker_token(config: &Config, headers: &axum::http::HeaderMap) -> bool {
    config
        .transcode_dispatch_secret
        .as_deref()
        .filter(|secret| !secret.is_empty())
        .zip(headers.get(WORKER_HEADER))
        .is_some_and(|(secret, provided)| {
            constant_time_eq(worker_token(secret).as_bytes(), provided.as_bytes())
        })
}

/// Intake callers and authenticated Cloud Tasks delivery use separate credentials.
pub(super) fn authorize_admission(
    config: &Config,
    headers: &axum::http::HeaderMap,
) -> std::result::Result<(), Response> {
    let expected = match config.transcode_admission_secret.as_deref() {
        None if !config.transcode_admission_auth_required => return Ok(()),
        Some(secret) if !secret.is_empty() => secret,
        _ => {
            return Err((
                StatusCode::SERVICE_UNAVAILABLE,
                "transcode admission not configured",
            )
                .into_response())
        }
    };
    let values = headers.get_all("x-divine-transcode-admission");
    let mut values = values.iter();
    if values
        .next()
        .is_some_and(|value| constant_time_eq(value.as_bytes(), expected.as_bytes()))
        && values.next().is_none()
    {
        return Ok(());
    }
    Err((
        StatusCode::UNAUTHORIZED,
        "invalid transcode admission credential",
    )
        .into_response())
}

pub(super) async fn worker(
    State(state): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
    Json(request): Json<TranscodeRequest>,
) -> Response {
    if !valid_worker_token(&state.config, &headers) || request.force {
        return (StatusCode::UNAUTHORIZED, "invalid transcode delivery").into_response();
    }
    if state.config.transcode_writes_paused {
        return paused_transcode_response();
    }
    match await_repair(process_transcode(state, request)).await {
        Err(error) if error.is::<TerminalTranscode>() => {
            Json(serde_json::json!({"status": "failed"})).into_response()
        }
        result => transcode_response(result, true),
    }
}

fn task_body(target: &str, secret: &str, hash: &str, owner: Option<&str>) -> serde_json::Value {
    let payload = serde_json::json!({"hash": hash, "owner": owner});
    let body = base64::engine::general_purpose::STANDARD.encode(payload.to_string());
    serde_json::json!({
        "task": {
            "httpRequest": {
                "url": target,
                "httpMethod": "POST",
                "headers": {
                    "Content-Type": "application/json",
                    WORKER_HEADER: worker_token(secret),
                },
                "body": body,
            },
            "dispatchDeadline": "900s"
        }
    })
}

pub(super) async fn enqueue(config: &Config, request: &TranscodeRequest) -> Result<()> {
    let queue = config
        .transcode_queue
        .as_deref()
        .context("Durable transcode queue not configured")?;
    let base = config
        .transcode_worker_url
        .as_deref()
        .context("Durable transcode worker URL not configured")?;
    let secret = config
        .transcode_dispatch_secret
        .as_deref()
        .filter(|secret| !secret.is_empty())
        .context("Durable transcode worker authentication not configured")?;
    let mut url = reqwest::Url::parse(base).context("Invalid transcode worker URL")?;
    if url.scheme() != "https"
        || url.path() != "/"
        || url.query().is_some()
        || url.fragment().is_some()
        || !url.username().is_empty()
        || url.password().is_some()
    {
        bail!("Transcode worker URL must be a bare HTTPS origin");
    }
    url.set_path(PATH);
    let body = task_body(
        url.as_str(),
        secret,
        &request.hash,
        request.owner.as_deref(),
    );
    let token = fetch_gcp_access_token()
        .await
        .map_err(|_| anyhow!("Cannot authenticate Cloud Tasks admission"))?;
    let response = status_http_client()
        .post(cloud_tasks_create_url(queue))
        .bearer_auth(&token)
        .json(&body)
        .send()
        .await
        .context("Cloud Tasks transcode admission failed")?;
    let status = response.status();
    if !status.is_success() {
        let message = response.text().await.unwrap_or_default();
        invalidate_gcp_access_token_if_expired_response(&token, Some(status.as_u16()), &message);
        bail!("Cloud Tasks declined transcode admission ({status})");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn task_delivery_authentication_cannot_authorize_repairs() {
        let config = Config::from_lookup(|key| match key {
            "TRANSCODE_DISPATCH_SECRET" | "TRANSCODE_REPAIR_SECRET" => Some("synthetic".into()),
            "WEBHOOK_SECRET" => Some("rotated-webhook".into()),
            _ => None,
        });
        let payload = task_body(
            "https://worker.example/internal/transcode",
            "synthetic",
            &"a".repeat(64),
            None,
        );
        assert_eq!(payload["task"]["dispatchDeadline"], "900s");
        let encoded = payload["task"]["httpRequest"]["body"].as_str().unwrap();
        let body = base64::engine::general_purpose::STANDARD
            .decode(encoded)
            .unwrap();
        let job: TranscodeRequest = serde_json::from_slice(&body).unwrap();
        assert_eq!(job.hash, "a".repeat(64));
        assert!(!job.force);
        let mut headers = axum::http::HeaderMap::new();
        headers.insert(
            "x-cloudtasks-taskname",
            "spoofed-queue-headers".parse().unwrap(),
        );
        assert!(!valid_worker_token(&config, &headers));
        let token = payload["task"]["httpRequest"]["headers"][WORKER_HEADER]
            .as_str()
            .unwrap();
        headers.insert(WORKER_HEADER, token.parse().unwrap());
        assert!(valid_worker_token(&config, &headers));
        headers.insert("x-divine-repair-secret", token.parse().unwrap());
        assert!(authorize_transcode_repair(&config, &headers, true).is_err());
    }
}
