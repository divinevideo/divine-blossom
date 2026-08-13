use blossom_core::error::BlossomError;
use blossom_core::request_diagnostics::should_persist_compute_diagnostic;
use fastly::log::Endpoint;
use serde::Serialize;
use std::io::Write;
use std::time::Duration;

pub(crate) const ENDPOINT_NAME: &str = "compute-diagnostics";

#[derive(Serialize)]
struct RequestDiagnostic<'a> {
    schema: &'static str,
    request_id: &'a str,
    method: &'a str,
    route: &'a str,
    status: u16,
    backend: Option<&'a str>,
    error_category: Option<&'a str>,
    duration_ms: u128,
}

pub(crate) fn emit(
    request_id: &str,
    method: &str,
    route: &str,
    status: u16,
    error: Option<&BlossomError>,
    duration: Duration,
) {
    if !should_persist_compute_diagnostic(status) {
        return;
    }

    let record = RequestDiagnostic {
        schema: "divine.blossom.compute_request.v1",
        request_id,
        method,
        route,
        status,
        backend: backend_category(error),
        error_category: error.map(error_category),
        duration_ms: duration.as_millis(),
    };

    let Ok(line) = serde_json::to_string(&record) else {
        return;
    };
    let Ok(mut endpoint) = Endpoint::try_from_name(ENDPOINT_NAME) else {
        return;
    };
    let _ = endpoint.write_all(line.as_bytes());
}

fn backend_category(error: Option<&BlossomError>) -> Option<&'static str> {
    match error {
        Some(BlossomError::StorageError(_)) => Some("origin"),
        Some(BlossomError::MetadataError(_)) => Some("metadata"),
        _ => None,
    }
}

fn error_category(error: &BlossomError) -> &'static str {
    match error {
        BlossomError::AuthRequired(_) => "auth_required",
        BlossomError::AuthInvalid(_) => "auth_invalid",
        BlossomError::Forbidden(_) => "forbidden",
        BlossomError::NotFound(_) => "not_found",
        BlossomError::Conflict(_) => "conflict",
        BlossomError::BadRequest(_) => "bad_request",
        BlossomError::Gone(_) => "gone",
        BlossomError::RangeNotSatisfiable(_) => "range_not_satisfiable",
        BlossomError::UnprocessableEntity(_) => "unprocessable_entity",
        BlossomError::StorageError(_) => "storage",
        BlossomError::MetadataError(_) => "metadata",
        BlossomError::Internal(_) => "internal",
    }
}
