//! Workflow actor executor.
//!
//! A workflow is an external executable (Python, Ruby, bash, etc.) that guides
//! an LLM session through a deterministic process. Communication uses a simple
//! JSON-over-stdin/stdout protocol; the workflow manages its own state (typically
//! a JSON file) and can call ouija's REST API for async push operations.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::state::AppState;

const WORKFLOW_TIMEOUT: Duration = Duration::from_secs(120);
const NOTIFY_TIMEOUT: Duration = Duration::from_secs(10);
/// Maximum bytes to read from an HTTP error response body.
const HTTP_ERROR_BODY_LIMIT: usize = 4096;

/// Returned by the workflow on registration.
#[derive(Debug, Deserialize)]
pub struct WorkflowRegistration {
    /// LLM-facing interface description. Prepended to the session prompt.
    pub instructions: String,
    /// First nudge text injected after session starts. Also used as the reminder.
    #[serde(default)]
    pub inject_on_start: Option<String>,
    /// Maximum workflow calls allowed before the daemon refuses further calls.
    /// Prevents unbounded looping. Enforced by the daemon, not the workflow.
    #[serde(default)]
    pub max_calls: Option<u64>,
}

/// Generic workflow response for runtime actions.
#[derive(Debug, Deserialize)]
struct WorkflowResponse {
    message: Option<String>,
    #[serde(default)]
    error: Option<String>,
    /// Machine-checkable success criteria for the current step.
    /// When present, appended to the message so the LLM knows how to verify its work.
    #[serde(default)]
    verify: Option<String>,
}

/// Input envelope sent to the workflow on stdin.
#[derive(Debug, Serialize)]
struct WorkflowInput {
    #[serde(skip_serializing_if = "Option::is_none")]
    event: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    action: Option<String>,
    session_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    params: Option<serde_json::Value>,
}

fn is_http_workflow(path: &str) -> bool {
    path.starts_with("http://") || path.starts_with("https://")
}

/// Resolve a workflow path, making relative paths relative to `working_dir`.
/// HTTP(S) URLs are passed through unchanged.
fn resolve_path(workflow_path: &str, working_dir: Option<&str>) -> PathBuf {
    if is_http_workflow(workflow_path) {
        return PathBuf::from(workflow_path);
    }
    let p = Path::new(workflow_path);
    if p.is_absolute() {
        p.to_path_buf()
    } else if let Some(dir) = working_dir {
        Path::new(dir).join(p)
    } else {
        p.to_path_buf()
    }
}

/// POST JSON to an HTTP workflow endpoint, return the parsed response.
async fn execute_http_workflow(
    url: &str,
    input: &WorkflowInput,
    timeout: Duration,
    client: &reqwest::Client,
) -> Result<serde_json::Value, String> {
    let response = client
        .post(url)
        .timeout(timeout)
        .json(input)
        .send()
        .await
        .map_err(|e| {
            if e.is_timeout() {
                format!("workflow HTTP request timed out ({url}). Call workflow(action='status') to retry.")
            } else if e.is_connect() {
                format!("workflow HTTP connection failed ({url}): {e}. Is the server running?")
            } else {
                format!("workflow HTTP request failed ({url}): {e}")
            }
        })?;

    let status = response.status();
    if !status.is_success() {
        let mut body = response.text().await.unwrap_or_default();
        body.truncate(HTTP_ERROR_BODY_LIMIT);
        return Err(format!(
            "workflow HTTP error ({status}) from {url}: {body}\nCall workflow(action='status') to check state."
        ));
    }

    response
        .json()
        .await
        .map_err(|e| format!("workflow HTTP response from {url} is not valid JSON: {e}"))
}

/// Spawn a workflow executable, pass JSON on stdin, read JSON from stdout.
async fn execute_binary_workflow(
    workflow_path: &Path,
    input: &WorkflowInput,
    timeout: Duration,
    working_dir: Option<&str>,
    port: u16,
) -> Result<serde_json::Value, String> {
    if !workflow_path.exists() {
        return Err(format!(
            "workflow not found: {}. Check that the path is correct and the file exists.",
            workflow_path.display()
        ));
    }

    let input_json =
        serde_json::to_string(input).map_err(|e| format!("failed to serialize input: {e}"))?;

    let cwd = working_dir
        .map(Path::new)
        .unwrap_or_else(|| workflow_path.parent().unwrap_or(Path::new(".")));

    let mut child = tokio::process::Command::new(workflow_path)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .current_dir(cwd)
        .env("OUIJA_API", format!("http://127.0.0.1:{port}"))
        .env("OUIJA_SESSION_ID", &input.session_id)
        .spawn()
        .map_err(|e| format!("failed to spawn workflow: {e}"))?;

    // Write input to stdin
    if let Some(mut stdin) = child.stdin.take() {
        use tokio::io::AsyncWriteExt;
        stdin
            .write_all(input_json.as_bytes())
            .await
            .map_err(|e| format!("failed to write to workflow stdin: {e}"))?;
        // Drop stdin to close it
    }

    // Wait with timeout. wait_with_output takes ownership, but tokio drops the
    // future (and the child) on timeout, which closes pipes and reaps the process.
    let output = tokio::time::timeout(timeout, child.wait_with_output())
        .await
        .map_err(|_| "workflow timed out. The script may be hanging. Call workflow(action='status') to retry, or check the workflow script for issues.".to_string())?
        .map_err(|e| format!("workflow process error: {e}"))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!(
            "workflow crashed (exit {}): {}\nCall workflow(action='status') to check state, or workflow(action='init') to re-orient.",
            output.status,
            stderr.trim()
        ));
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    serde_json::from_str(stdout.trim())
        .map_err(|e| format!("workflow returned invalid JSON: {e}\nraw output: {stdout}\nThe workflow script may have a bug. Call workflow(action='status') to retry."))
}

/// Execute a workflow — dispatches to HTTP or binary based on the path.
async fn execute_workflow(
    workflow_path: &Path,
    input: &WorkflowInput,
    timeout: Duration,
    working_dir: Option<&str>,
    port: u16,
    http_client: Option<&reqwest::Client>,
) -> Result<serde_json::Value, String> {
    if let Some(url) = workflow_path.to_str().filter(|s| is_http_workflow(s)) {
        let client =
            http_client.ok_or_else(|| "HTTP workflow requires an HTTP client".to_string())?;
        execute_http_workflow(url, input, timeout, client).await
    } else {
        execute_binary_workflow(workflow_path, input, timeout, working_dir, port).await
    }
}

/// Call the workflow with a registration event. Returns instructions for the LLM.
pub async fn register_workflow(
    state: &Arc<AppState>,
    workflow_path: &str,
    session_id: &str,
    workflow_params: Option<&serde_json::Value>,
    working_dir: Option<&str>,
) -> Result<WorkflowRegistration, String> {
    let path = resolve_path(workflow_path, working_dir);

    let input = WorkflowInput {
        event: Some("register".into()),
        action: None,
        session_id: session_id.into(),
        params: workflow_params.cloned(),
    };

    let value = execute_workflow(
        &path,
        &input,
        WORKFLOW_TIMEOUT,
        working_dir,
        state.config.port,
        Some(&state.http_client),
    )
    .await?;

    serde_json::from_value::<WorkflowRegistration>(value)
        .map_err(|e| format!("workflow registration response missing required fields: {e}"))
}

/// Call the workflow with a runtime action from the LLM. Returns the message to show the LLM.
pub async fn call_workflow(
    state: &Arc<AppState>,
    workflow_path: &str,
    session_id: &str,
    action: &str,
    params: Option<&serde_json::Value>,
    working_dir: Option<&str>,
) -> Result<String, String> {
    let path = resolve_path(workflow_path, working_dir);

    let input = WorkflowInput {
        event: None,
        action: Some(action.into()),
        session_id: session_id.into(),
        params: params.cloned(),
    };

    let value = execute_workflow(
        &path,
        &input,
        WORKFLOW_TIMEOUT,
        working_dir,
        state.config.port,
        Some(&state.http_client),
    )
    .await?;

    let resp: WorkflowResponse =
        serde_json::from_value(value).map_err(|e| format!("invalid workflow response: {e}"))?;

    if let Some(err) = resp.error {
        return Err(err);
    }

    let message = resp
        .message
        .ok_or_else(|| "workflow returned no message".to_string())?;

    // Append verification criteria if the workflow provided them
    match resp.verify {
        Some(criteria) => Ok(format!("{message}\n\nVerify before proceeding: {criteria}")),
        None => Ok(message),
    }
}

/// Fire-and-forget lifecycle event notification to the workflow.
pub fn notify_workflow(
    state: &Arc<AppState>,
    workflow_path: &str,
    event: &str,
    session_id: &str,
    working_dir: Option<&str>,
) {
    let state = state.clone();
    let workflow_path = workflow_path.to_string();
    let event = event.to_string();
    let session_id = session_id.to_string();
    let working_dir = working_dir.map(String::from);

    tokio::spawn(async move {
        let path = resolve_path(&workflow_path, working_dir.as_deref());

        let input = WorkflowInput {
            event: Some(event.clone()),
            action: None,
            session_id: session_id.clone(),
            params: None,
        };

        if let Err(e) = execute_workflow(
            &path,
            &input,
            NOTIFY_TIMEOUT,
            working_dir.as_deref(),
            state.config.port,
            Some(&state.http_client),
        )
        .await
        {
            tracing::warn!(
                "workflow lifecycle notification '{event}' for session '{session_id}' failed: {e}"
            );
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_input(session_id: &str) -> WorkflowInput {
        WorkflowInput {
            event: Some("test".into()),
            action: None,
            session_id: session_id.into(),
            params: None,
        }
    }

    use std::sync::atomic::{AtomicU64, Ordering};
    static SCRIPT_COUNTER: AtomicU64 = AtomicU64::new(0);

    fn make_script(content: &str) -> PathBuf {
        use std::os::unix::fs::PermissionsExt;
        let n = SCRIPT_COUNTER.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join("ouija-workflow-tests");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join(format!(
            "wf-{}-{:?}-{n}.sh",
            std::process::id(),
            std::thread::current().id()
        ));
        // Write to a separate tmp file then rename — atomic, avoids ETXTBSY
        let tmp = path.with_extension("tmp");
        std::fs::write(&tmp, format!("#!/usr/bin/env bash\n{content}\n")).unwrap();
        std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o755)).unwrap();
        std::fs::rename(&tmp, &path).unwrap();
        path
    }

    #[tokio::test]
    async fn execute_workflow_valid_json() {
        let script =
            make_script(r#"cat /dev/stdin > /dev/null; echo '{"message":"hello","count":42}'"#);
        let input = make_input("sess-1");
        let result =
            execute_workflow(&script, &input, Duration::from_secs(5), None, 9999, None).await;
        let val = result.unwrap();
        assert_eq!(val["message"], "hello");
        assert_eq!(val["count"], 42);
    }

    #[tokio::test]
    async fn execute_workflow_nonzero_exit() {
        let script = make_script("cat /dev/stdin > /dev/null; echo 'something broke' >&2; exit 1");
        let input = make_input("sess-2");
        let result =
            execute_workflow(&script, &input, Duration::from_secs(5), None, 9999, None).await;
        let err = result.unwrap_err();
        assert!(
            err.contains("crashed"),
            "expected crash indicator in error: {err}"
        );
        assert!(
            err.contains("something broke"),
            "expected stderr in error: {err}"
        );
    }

    #[tokio::test]
    async fn execute_workflow_invalid_json() {
        let script = make_script("cat /dev/stdin > /dev/null; echo 'not json'");
        let input = make_input("sess-3");
        let result =
            execute_workflow(&script, &input, Duration::from_secs(5), None, 9999, None).await;
        let err = result.unwrap_err();
        assert!(err.contains("invalid JSON"), "expected JSON error: {err}");
    }

    #[tokio::test]
    async fn execute_workflow_timeout() {
        let script = make_script("sleep 60");
        let input = make_input("sess-4");
        let result =
            execute_workflow(&script, &input, Duration::from_secs(1), None, 9999, None).await;
        let err = result.unwrap_err();
        assert!(err.contains("timed out"), "expected timeout error: {err}");
    }

    #[test]
    fn resolve_path_absolute() {
        let result = resolve_path("/usr/bin/workflow", None);
        assert_eq!(result, PathBuf::from("/usr/bin/workflow"));

        let result = resolve_path("/usr/bin/workflow", Some("/other/dir"));
        assert_eq!(result, PathBuf::from("/usr/bin/workflow"));
    }

    #[test]
    fn resolve_path_relative_with_working_dir() {
        let result = resolve_path("scripts/run.sh", Some("/project"));
        assert_eq!(result, PathBuf::from("/project/scripts/run.sh"));
    }

    #[test]
    fn resolve_path_relative_without_working_dir() {
        let result = resolve_path("scripts/run.sh", None);
        assert_eq!(result, PathBuf::from("scripts/run.sh"));
    }

    #[test]
    fn resolve_path_http_url() {
        let result = resolve_path("http://localhost:8100/workflow", None);
        assert_eq!(result, PathBuf::from("http://localhost:8100/workflow"));

        // URL should not be joined with working_dir
        let result = resolve_path("http://localhost:8100/workflow", Some("/project"));
        assert_eq!(result, PathBuf::from("http://localhost:8100/workflow"));
    }

    #[test]
    fn resolve_path_https_url() {
        let result = resolve_path("https://example.com/workflow", Some("/project"));
        assert_eq!(result, PathBuf::from("https://example.com/workflow"));
    }

    #[test]
    fn is_http_workflow_detection() {
        assert!(is_http_workflow("http://localhost:8100/workflow"));
        assert!(is_http_workflow("https://example.com/workflow"));
        assert!(!is_http_workflow("/usr/bin/workflow"));
        assert!(!is_http_workflow("scripts/run.sh"));
        assert!(!is_http_workflow("httpd-workflow"));
    }

    // --- HTTP workflow tests using a real axum server ---

    use axum::Router;
    use axum::routing::post;

    /// Start a test HTTP server, return its base URL.
    async fn start_test_server(app: Router) -> (String, tokio::task::JoinHandle<()>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = tokio::spawn(async move {
            axum::serve(listener, app).await.ok();
        });
        (format!("http://127.0.0.1:{}", addr.port()), handle)
    }

    #[tokio::test]
    async fn http_workflow_valid_json() {
        let app = Router::new().route(
            "/workflow",
            post(|| async { axum::Json(serde_json::json!({"message": "hello", "count": 42})) }),
        );
        let (url, _server) = start_test_server(app).await;

        let client = reqwest::Client::new();
        let input = make_input("http-1");
        let result = execute_http_workflow(
            &format!("{url}/workflow"),
            &input,
            Duration::from_secs(5),
            &client,
        )
        .await;
        let val = result.unwrap();
        assert_eq!(val["message"], "hello");
        assert_eq!(val["count"], 42);
    }

    #[tokio::test]
    async fn http_workflow_error_status() {
        let app = Router::new().route(
            "/workflow",
            post(|| async { (axum::http::StatusCode::INTERNAL_SERVER_ERROR, "boom") }),
        );
        let (url, _server) = start_test_server(app).await;

        let client = reqwest::Client::new();
        let input = make_input("http-2");
        let err = execute_http_workflow(
            &format!("{url}/workflow"),
            &input,
            Duration::from_secs(5),
            &client,
        )
        .await
        .unwrap_err();
        assert!(err.contains("500"), "expected 500 in error: {err}");
        assert!(err.contains("boom"), "expected body in error: {err}");
    }

    #[tokio::test]
    async fn http_workflow_invalid_json_response() {
        let app = Router::new().route("/workflow", post(|| async { "not json at all" }));
        let (url, _server) = start_test_server(app).await;

        let client = reqwest::Client::new();
        let input = make_input("http-3");
        let err = execute_http_workflow(
            &format!("{url}/workflow"),
            &input,
            Duration::from_secs(5),
            &client,
        )
        .await
        .unwrap_err();
        assert!(
            err.contains("not valid JSON"),
            "expected JSON parse error: {err}"
        );
    }

    #[tokio::test]
    async fn http_workflow_connection_refused() {
        let client = reqwest::Client::new();
        let input = make_input("http-4");
        // Use a port that's almost certainly not listening
        let err = execute_http_workflow(
            "http://127.0.0.1:1/workflow",
            &input,
            Duration::from_secs(5),
            &client,
        )
        .await
        .unwrap_err();
        assert!(
            err.contains("connection failed"),
            "expected connection error: {err}"
        );
    }

    #[tokio::test]
    async fn http_workflow_timeout() {
        let app = Router::new().route(
            "/workflow",
            post(|| async {
                tokio::time::sleep(Duration::from_secs(60)).await;
                axum::Json(serde_json::json!({"message": "too late"}))
            }),
        );
        let (url, _server) = start_test_server(app).await;

        let client = reqwest::Client::new();
        let input = make_input("http-5");
        let err = execute_http_workflow(
            &format!("{url}/workflow"),
            &input,
            Duration::from_secs(1),
            &client,
        )
        .await
        .unwrap_err();
        assert!(err.contains("timed out"), "expected timeout error: {err}");
    }

    #[tokio::test]
    async fn execute_workflow_dispatches_to_http() {
        let app = Router::new().route(
            "/workflow",
            post(|| async { axum::Json(serde_json::json!({"message": "from http"})) }),
        );
        let (url, _server) = start_test_server(app).await;

        let client = reqwest::Client::new();
        let input = make_input("dispatch-1");
        let workflow_url = format!("{url}/workflow");
        let path = PathBuf::from(&workflow_url);
        let result =
            execute_workflow(&path, &input, WORKFLOW_TIMEOUT, None, 9999, Some(&client)).await;
        let val = result.unwrap();
        assert_eq!(val["message"], "from http");
    }
}
