// ABOUTME: Authenticated HTTP API for asynchronous compilation jobs
// ABOUTME: Derives audit identity from the trusted edge and scopes all job reads

use crate::{
    auth::verify_editor_request,
    domain::{CompileRequest, Job, JobStatus},
    store::JobStore,
};
use axum::{
    body::Bytes,
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use serde::Serialize;
use std::{
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};
use tokio::sync::Notify;
use uuid::Uuid;

const INITIATOR_HEADER: &str = "x-compiler-initiated-by";
const NOSTR_AUTH_HEADER: &str = "x-compiler-nostr-authorization";

#[derive(Clone)]
pub struct ApiState {
    pub store: Arc<dyn JobStore>,
    pub public_origin: String,
    pub max_jobs_per_hour: usize,
    pub worker_notify: Arc<Notify>,
}

impl ApiState {
    pub fn new(
        store: Arc<dyn JobStore>,
        public_origin: impl Into<String>,
        max_jobs_per_hour: usize,
    ) -> Self {
        Self {
            store,
            public_origin: public_origin.into(),
            max_jobs_per_hour,
            worker_notify: Arc::new(Notify::new()),
        }
    }
}

pub fn router(state: ApiState) -> Router {
    Router::new()
        .route("/health", get(health))
        .route("/api/compile", post(create_job))
        .route("/api/compile/:id", get(get_job))
        .route("/api/jobs", get(recent_jobs))
        .with_state(state)
}

async fn health() -> &'static str {
    "ok"
}

async fn create_job(State(state): State<ApiState>, headers: HeaderMap, body: Bytes) -> Response {
    let initiated_by = match trusted_initiator(&headers) {
        Ok(identity) => identity,
        Err(response) => return response,
    };
    let authorization = match header(&headers, NOSTR_AUTH_HEADER) {
        Ok(value) => value,
        Err(response) => return response,
    };
    let request: CompileRequest = match serde_json::from_slice(&body) {
        Ok(request) => request,
        Err(error) => return api_error(StatusCode::BAD_REQUEST, "invalid-request", error),
    };
    if let Err(error) = request.validate() {
        return api_error(StatusCode::BAD_REQUEST, "invalid-request", error);
    }

    let now = unix_timestamp();
    let public_url = format!("{}/api/compile", state.public_origin);
    let signer =
        match verify_editor_request(authorization, "POST", &public_url, &body, &request, now) {
            Ok(identity) => identity,
            Err(error) => {
                return api_error(StatusCode::UNAUTHORIZED, "invalid-authorization", error)
            }
        };
    let job = Job {
        id: Uuid::new_v4().to_string(),
        status: JobStatus::Queued,
        progress: 0.0,
        request,
        signer_pubkey: signer.pubkey,
        initiated_by,
        created_at: now,
        updated_at: now,
        result: None,
        error: None,
    };
    let since = now.saturating_sub(60 * 60);
    match state
        .store
        .create_limited(&job, since, state.max_jobs_per_hour)
        .await
    {
        Ok(true) => {
            state.worker_notify.notify_one();
            (
                StatusCode::ACCEPTED,
                Json(CreateJobResponse {
                    status: JobStatus::Queued,
                    job,
                }),
            )
                .into_response()
        }
        Ok(false) => api_error(
            StatusCode::TOO_MANY_REQUESTS,
            "rate-limit",
            "hourly compilation limit reached",
        ),
        Err(error) => api_error(StatusCode::INTERNAL_SERVER_ERROR, "job-store-error", error),
    }
}

async fn get_job(
    State(state): State<ApiState>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> Response {
    let initiated_by = match trusted_initiator(&headers) {
        Ok(identity) => identity,
        Err(response) => return response,
    };
    match state.store.get(&id).await {
        Ok(Some(job)) if job.initiated_by == initiated_by => Json(job).into_response(),
        Ok(_) => api_error(StatusCode::NOT_FOUND, "not-found", "job not found"),
        Err(error) => api_error(StatusCode::INTERNAL_SERVER_ERROR, "job-store-error", error),
    }
}

async fn recent_jobs(State(state): State<ApiState>, headers: HeaderMap) -> Response {
    let initiated_by = match trusted_initiator(&headers) {
        Ok(identity) => identity,
        Err(response) => return response,
    };
    match state.store.recent_for_initiator(&initiated_by, 20).await {
        Ok(jobs) => Json(jobs).into_response(),
        Err(error) => api_error(StatusCode::INTERNAL_SERVER_ERROR, "job-store-error", error),
    }
}

fn trusted_initiator(headers: &HeaderMap) -> Result<String, Response> {
    let value = header(headers, INITIATOR_HEADER)?;
    if value.len() > 320
        || !value.contains('@')
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_graphic() && byte != b',')
    {
        return Err(api_error(
            StatusCode::UNAUTHORIZED,
            "invalid-initiator",
            "trusted edge identity is missing or malformed",
        ));
    }
    Ok(value.to_ascii_lowercase())
}

fn header<'a>(headers: &'a HeaderMap, name: &str) -> Result<&'a str, Response> {
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .ok_or_else(|| {
            api_error(
                StatusCode::UNAUTHORIZED,
                "missing-header",
                format!("{name} is required"),
            )
        })
}

#[derive(Serialize)]
struct CreateJobResponse {
    status: JobStatus,
    job: Job,
}

#[derive(Serialize)]
struct ErrorResponse {
    code: &'static str,
    error: String,
}

fn api_error(status: StatusCode, code: &'static str, error: impl std::fmt::Display) -> Response {
    (
        status,
        Json(ErrorResponse {
            code,
            error: error.to_string(),
        }),
    )
        .into_response()
}

fn unix_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
