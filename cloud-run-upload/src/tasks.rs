// ABOUTME: Enqueues transcode work onto Cloud Tasks instead of firing a detached in-process request.
// ABOUTME: Gives bursts somewhere to buffer and gives lost work a retry, which tokio::spawn cannot.

//! Cloud Tasks enqueueing for transcode jobs.
//!
//! Triggering the transcoder with `tokio::spawn` loses work: a detached task
//! dies with its instance, and Cloud Run terminates instances constantly during
//! autoscaling churn -- most of all during the traffic burst where losing a
//! transcode matters most. There is no retry and no record, so the video simply
//! never gains its derivatives.
//!
//! A queue fixes three things at once:
//!
//!   * work survives instance termination, because the queue owns it;
//!   * a burst becomes a backlog that drains, rather than a wall of concurrent
//!     requests against a service that scales out in tens of seconds;
//!   * `maxConcurrentDispatches` becomes a real rate limit into the transcoder,
//!     which is simultaneously the cost control.
//!
//! Enqueueing is deliberately best-effort with respect to the upload: an upload
//! that succeeded must never be failed because the queue was unreachable.

use anyhow::{anyhow, Result};
use base64::Engine;
use tracing::{info, warn};

/// Where Cloud Run exposes the instance service account's access token.
const METADATA_TOKEN_URL: &str = "http://metadata.google.internal/computeMetadata/v1/\
instance/service-accounts/default/token";

/// Matches the transcoder's own `--timeout 900`. A task whose dispatch deadline
/// were shorter would be retried while the first attempt is still encoding,
/// producing duplicate work rather than recovering from anything.
const DISPATCH_DEADLINE: &str = "900s";

/// Configuration for enqueueing onto Cloud Tasks.
#[derive(Clone, Debug)]
pub struct TaskQueueConfig {
    /// Fully qualified queue: `projects/{p}/locations/{l}/queues/{q}`.
    pub queue_path: String,
    /// Service account used to mint the OIDC token the transcoder verifies.
    /// When absent, the task is dispatched without an OIDC token, which only
    /// works while the transcoder allows unauthenticated invocation.
    pub invoker_service_account: Option<String>,
}

impl TaskQueueConfig {
    /// Build from the environment. Returns `None` when no queue is configured,
    /// which leaves the caller on its previous direct-dispatch path so this can
    /// be deployed before the queue exists.
    pub fn from_env() -> Option<Self> {
        let queue_path = std::env::var("TRANSCODE_QUEUE").ok()?;
        if queue_path.trim().is_empty() {
            return None;
        }
        Some(TaskQueueConfig {
            queue_path,
            invoker_service_account: std::env::var("TRANSCODE_QUEUE_INVOKER_SA")
                .ok()
                .filter(|value| !value.trim().is_empty()),
        })
    }
}

/// The Cloud Tasks endpoint for creating a task on `queue_path`.
pub fn create_task_url(queue_path: &str) -> String {
    format!("https://cloudtasks.googleapis.com/v2/{}/tasks", queue_path)
}

/// Build the `CreateTask` request body.
///
/// Cloud Tasks requires the HTTP body to be base64-encoded, and the target URL
/// to be absolute. No task `name` is set: naming a task enables de-duplication,
/// but Google documents that de-duplicated queues have substantially lower
/// throughput, and transcoding is already idempotent because blobs are
/// content-addressed. Throughput is the property worth keeping here.
pub fn build_task_payload(
    transcoder_url: &str,
    hash: &str,
    owner: &str,
    invoker_service_account: Option<&str>,
) -> serde_json::Value {
    let body = serde_json::json!({ "hash": hash, "owner": owner }).to_string();
    let encoded = base64::engine::general_purpose::STANDARD.encode(body);

    let mut http_request = serde_json::json!({
        "url": format!("{}/transcode", transcoder_url.trim_end_matches('/')),
        "httpMethod": "POST",
        "headers": { "Content-Type": "application/json" },
        "body": encoded,
    });

    if let Some(service_account) = invoker_service_account {
        http_request["oidcToken"] =
            serde_json::json!({ "serviceAccountEmail": service_account });
    }

    serde_json::json!({
        "task": {
            "httpRequest": http_request,
            "dispatchDeadline": DISPATCH_DEADLINE,
        }
    })
}

/// Fetch an access token from the Cloud Run metadata server.
///
/// The token is returned to the caller and must never be logged.
async fn fetch_access_token(client: &reqwest::Client) -> Result<String> {
    let response = client
        .get(METADATA_TOKEN_URL)
        .header("Metadata-Flavor", "Google")
        .send()
        .await
        .map_err(|e| anyhow!("metadata server unreachable: {}", e))?;

    if !response.status().is_success() {
        return Err(anyhow!(
            "metadata server returned {} when minting an access token",
            response.status()
        ));
    }

    let parsed: serde_json::Value = response
        .json()
        .await
        .map_err(|e| anyhow!("could not parse the metadata token response: {}", e))?;

    parsed
        .get("access_token")
        .and_then(|value| value.as_str())
        .map(str::to_owned)
        .ok_or_else(|| anyhow!("metadata token response contained no access_token"))
}

/// Enqueue a transcode job. Errors are returned so the caller can log and
/// continue; they must not fail the upload that produced the object.
pub async fn enqueue_transcode(
    config: &TaskQueueConfig,
    transcoder_url: &str,
    hash: &str,
    owner: &str,
) -> Result<()> {
    let client = reqwest::Client::new();
    let token = fetch_access_token(&client).await?;
    let payload = build_task_payload(
        transcoder_url,
        hash,
        owner,
        config.invoker_service_account.as_deref(),
    );

    let response = client
        .post(create_task_url(&config.queue_path))
        .bearer_auth(token)
        .json(&payload)
        .send()
        .await
        .map_err(|e| anyhow!("could not reach Cloud Tasks: {}", e))?;

    let status = response.status();
    if status.is_success() {
        info!("Enqueued transcode task for {}", hash);
        return Ok(());
    }

    // The response body describes the rejection and contains no credentials.
    let body = response.text().await.unwrap_or_default();
    warn!("Cloud Tasks rejected the transcode task for {}: {}", hash, status);
    Err(anyhow!("Cloud Tasks returned {}: {}", status, body))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn decode_body(payload: &serde_json::Value) -> serde_json::Value {
        let encoded = payload["task"]["httpRequest"]["body"].as_str().unwrap();
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(encoded)
            .expect("body should be valid base64");
        serde_json::from_slice(&decoded).expect("body should be valid JSON")
    }

    #[test]
    fn create_task_url_targets_the_v2_tasks_collection() {
        assert_eq!(
            create_task_url("projects/p/locations/us-central1/queues/transcode"),
            "https://cloudtasks.googleapis.com/v2/projects/p/locations/us-central1/\
queues/transcode/tasks"
        );
    }

    #[test]
    fn payload_targets_the_transcode_endpoint() {
        let payload = build_task_payload("https://transcoder.example", "abc", "pk", None);
        assert_eq!(
            payload["task"]["httpRequest"]["url"],
            "https://transcoder.example/transcode"
        );
        assert_eq!(payload["task"]["httpRequest"]["httpMethod"], "POST");
    }

    #[test]
    fn payload_does_not_double_the_slash_on_a_trailing_slash_url() {
        let payload = build_task_payload("https://transcoder.example/", "abc", "pk", None);
        assert_eq!(
            payload["task"]["httpRequest"]["url"],
            "https://transcoder.example/transcode"
        );
    }

    #[test]
    fn body_is_base64_encoded_and_matches_the_direct_call_shape() {
        // The transcoder is unchanged, so the body must stay byte-identical to
        // what trigger_transcoding posts today.
        let payload = build_task_payload("https://t.example", "deadbeef", "npub1", None);
        let body = decode_body(&payload);
        assert_eq!(body["hash"], "deadbeef");
        assert_eq!(body["owner"], "npub1");
    }

    #[test]
    fn oidc_token_is_attached_when_an_invoker_is_configured() {
        let payload =
            build_task_payload("https://t.example", "abc", "pk", Some("sa@example.com"));
        assert_eq!(
            payload["task"]["httpRequest"]["oidcToken"]["serviceAccountEmail"],
            "sa@example.com"
        );
    }

    #[test]
    fn oidc_token_is_omitted_when_no_invoker_is_configured() {
        let payload = build_task_payload("https://t.example", "abc", "pk", None);
        assert!(payload["task"]["httpRequest"].get("oidcToken").is_none());
    }

    #[test]
    fn dispatch_deadline_matches_the_transcoder_request_timeout() {
        // A shorter deadline would retry while the first attempt is still
        // encoding, duplicating work rather than recovering from a failure.
        let payload = build_task_payload("https://t.example", "abc", "pk", None);
        assert_eq!(payload["task"]["dispatchDeadline"], "900s");
    }
}
