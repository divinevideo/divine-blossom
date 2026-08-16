use blossom_core::error::BlossomError;
use blossom_core::request_diagnostics::{
    persisted_error_categories, should_persist_compute_diagnostic,
};
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
    backend: Option<&'static str>,
    error_category: Option<&'static str>,
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

    let categories = error.and_then(persisted_error_categories);
    let record = RequestDiagnostic {
        schema: "divine.blossom.compute_request.v1",
        request_id,
        method,
        route,
        status,
        backend: categories.and_then(|fields| fields.backend),
        error_category: categories.map(|fields| fields.category),
        duration_ms: duration.as_millis(),
    };

    let Ok(line) = serde_json::to_string(&record) else {
        return;
    };
    if let Ok(mut endpoint) = Endpoint::try_from_name(ENDPOINT_NAME) {
        let _ = endpoint.write_all(line.as_bytes());
    }
    eprintln!("[COMPUTE_DIAGNOSTIC] {}", line);
}
