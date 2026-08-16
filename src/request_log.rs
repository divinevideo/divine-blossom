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

    let categories = error.and_then(diagnostic_categories);
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
    let Ok(mut endpoint) = Endpoint::try_from_name(ENDPOINT_NAME) else {
        return;
    };
    let _ = endpoint.write_all(line.as_bytes());
}

#[derive(Clone, Copy)]
struct PersistedCategories {
    backend: Option<&'static str>,
    category: &'static str,
}
/// Categories for a persisted diagnostic record, or `None` when the error
/// never produces a 5xx response. `BlossomError::status_code` maps only
/// StorageError (502), MetadataError (500), and Internal (500) into the 5xx
/// range, so only those three ever receive categories here. The match is
/// exhaustive with no wildcard on purpose: a variant that newly maps to 5xx
/// fails compilation in this function rather than silently logging
/// `backend: null` or a category that can never be emitted.
fn diagnostic_categories(error: &BlossomError) -> Option<PersistedCategories> {
    match error {
        BlossomError::StorageError(_) => Some(PersistedCategories {
            backend: Some("origin"),
            category: "storage",
        }),
        BlossomError::MetadataError(_) => Some(PersistedCategories {
            backend: Some("metadata"),
            category: "metadata",
        }),
        BlossomError::Internal(_) => Some(PersistedCategories {
            backend: None,
            category: "internal",
        }),
        BlossomError::AuthRequired(_)
        | BlossomError::AuthInvalid(_)
        | BlossomError::Forbidden(_)
        | BlossomError::NotFound(_)
        | BlossomError::Conflict(_)
        | BlossomError::BadRequest(_)
        | BlossomError::Gone(_)
        | BlossomError::RangeNotSatisfiable(_)
        | BlossomError::UnprocessableEntity(_) => None,
    }
}
