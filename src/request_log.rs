use blossom_core::error::BlossomError;
use blossom_core::read_through::parse_bool_flag;
use blossom_core::request_diagnostics::{
    persisted_error_categories, should_persist_blob_fetch_diagnostic,
    should_persist_compute_diagnostic, SLOW_BLOB_THRESHOLD_MS,
};
use fastly::log::Endpoint;
use fastly::Response;
use serde::Serialize;
use std::io::Write;
use std::time::Duration;

use crate::storage::BlobFetchDiagnostics;

pub(crate) const ENDPOINT_NAME: &str = "compute-diagnostics";
pub(crate) const PROBE_REQUEST_HEADER: &str = "X-Divine-Diagnostic-Probe";
const PROBE_ID_HEADER: &str = "X-Divine-Probe-Id";
const PROBE_SOURCE_HEADER: &str = "X-Divine-Probe-Source";
const PROBE_FOS_OUTCOME_HEADER: &str = "X-Divine-Probe-FOS-Outcome";
const PROBE_BUFFER_HEADER: &str = "X-Divine-Probe-Buffer";
const PROBE_WRITE_BACK_HEADER: &str = "X-Divine-Probe-Write-Back";

const DIAGNOSTIC_PREFIX: &str = "X-Divine-Internal-Diagnostic-";
const AUTHORIZATION_PRESENT_HEADER: &str = "X-Divine-Internal-Diagnostic-Authorization-Present";
const SOURCE_HEADER: &str = "X-Divine-Internal-Diagnostic-Source";
const STORAGE_CACHE_HEADER: &str = "X-Divine-Internal-Diagnostic-Storage-Cache";
const FOS_OUTCOME_HEADER: &str = "X-Divine-Internal-Diagnostic-FOS-Outcome";
const FOS_LOOKUP_MS_HEADER: &str = "X-Divine-Internal-Diagnostic-FOS-Lookup-Ms";
const GCS_FETCH_MS_HEADER: &str = "X-Divine-Internal-Diagnostic-GCS-Fetch-Ms";
const BUFFER_MS_HEADER: &str = "X-Divine-Internal-Diagnostic-Buffer-Ms";
const WRITE_BACK_MS_HEADER: &str = "X-Divine-Internal-Diagnostic-Write-Back-Ms";
const INTERNAL_PROBE_ID_HEADER: &str = "X-Divine-Internal-Diagnostic-Probe-Id";
const CONFIG_STORE: &str = "blossom_config";
const COLD_FILL_DIAGNOSTICS_FLAG: &str = "cold_fill_diagnostics_enabled";

#[derive(Default, Serialize)]
struct BlobPhases {
    authorization_present: bool,
    source: Option<String>,
    storage_cache: Option<String>,
    fos_outcome: Option<String>,
    fos_lookup_ms: Option<u128>,
    gcs_fetch_ms: Option<u128>,
    buffer_ms: Option<u128>,
    write_back_ms: Option<u128>,
}

#[derive(Serialize)]
struct RequestDiagnostic<'a> {
    schema: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    request_id: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    probe_id: Option<String>,
    method: &'a str,
    route: &'a str,
    status: u16,
    backend: Option<&'static str>,
    error_category: Option<&'static str>,
    duration_ms: u128,
    #[serde(skip_serializing_if = "Option::is_none")]
    blob_phases: Option<BlobPhases>,
    #[serde(skip_serializing_if = "Option::is_none")]
    sample_reason: Option<&'static str>,
}

pub(crate) fn attach_blob_phases(
    response: &mut Response,
    diagnostics: BlobFetchDiagnostics,
    authorization_present: bool,
    probe_id: Option<&str>,
) {
    if let Some(probe_id) = probe_id {
        response.set_header(PROBE_ID_HEADER, probe_id);
        set_optional_header(response, PROBE_SOURCE_HEADER, diagnostics.source);
        set_optional_header(response, PROBE_FOS_OUTCOME_HEADER, diagnostics.fos_outcome);
        response.set_header(
            PROBE_BUFFER_HEADER,
            if diagnostics.buffer_ms.is_some() {
                "present"
            } else {
                "absent"
            },
        );
        response.set_header(
            PROBE_WRITE_BACK_HEADER,
            if diagnostics.write_back_ms.is_some() {
                "present"
            } else {
                "absent"
            },
        );
    }
    response.set_header(
        AUTHORIZATION_PRESENT_HEADER,
        if authorization_present {
            "true"
        } else {
            "false"
        },
    );
    set_optional_header(response, SOURCE_HEADER, diagnostics.source);
    set_optional_header(response, STORAGE_CACHE_HEADER, diagnostics.storage_cache);
    set_optional_header(response, FOS_OUTCOME_HEADER, diagnostics.fos_outcome);
    set_optional_number(response, FOS_LOOKUP_MS_HEADER, diagnostics.fos_lookup_ms);
    set_optional_number(response, GCS_FETCH_MS_HEADER, diagnostics.gcs_fetch_ms);
    set_optional_number(response, BUFFER_MS_HEADER, diagnostics.buffer_ms);
    set_optional_number(response, WRITE_BACK_MS_HEADER, diagnostics.write_back_ms);
    set_optional_header(response, INTERNAL_PROBE_ID_HEADER, probe_id);
}

fn set_optional_header(response: &mut Response, name: &str, value: Option<&str>) {
    if let Some(value) = value {
        response.set_header(name, value);
    }
}

fn set_optional_number(response: &mut Response, name: &str, value: Option<u128>) {
    if let Some(value) = value {
        response.set_header(name, value.to_string());
    }
}

fn take_blob_phases(response: &mut Response) -> Option<(BlobPhases, Option<String>)> {
    let has_phases = response.contains_header(AUTHORIZATION_PRESENT_HEADER);

    let phases = BlobPhases {
        authorization_present: response.get_header_str(AUTHORIZATION_PRESENT_HEADER)
            == Some("true"),
        source: take_header(response, SOURCE_HEADER),
        storage_cache: take_header(response, STORAGE_CACHE_HEADER),
        fos_outcome: take_header(response, FOS_OUTCOME_HEADER),
        fos_lookup_ms: take_number(response, FOS_LOOKUP_MS_HEADER),
        gcs_fetch_ms: take_number(response, GCS_FETCH_MS_HEADER),
        buffer_ms: take_number(response, BUFFER_MS_HEADER),
        write_back_ms: take_number(response, WRITE_BACK_MS_HEADER),
    };
    let probe_id = take_header(response, INTERNAL_PROBE_ID_HEADER);
    response.remove_header(AUTHORIZATION_PRESENT_HEADER);
    has_phases.then_some((phases, probe_id))
}

fn take_header(response: &mut Response, name: &str) -> Option<String> {
    let value = response.get_header_str(name).map(str::to_string);
    response.remove_header(name);
    value
}

fn take_number(response: &mut Response, name: &str) -> Option<u128> {
    take_header(response, name).and_then(|value| value.parse().ok())
}

fn cold_fill_diagnostics_enabled() -> bool {
    let value = fastly::config_store::ConfigStore::try_open(CONFIG_STORE)
        .ok()
        .and_then(|store| store.try_get(COLD_FILL_DIAGNOSTICS_FLAG).ok().flatten());
    parse_bool_flag(value.as_deref())
}

fn is_enabled_cold_probe(is_cold_fill: bool, has_probe_id: bool) -> bool {
    is_cold_fill && has_probe_id && cold_fill_diagnostics_enabled()
}

pub(crate) fn emit(
    response: &mut Response,
    request_id: &str,
    method: &str,
    route: &str,
    status: u16,
    error: Option<&BlossomError>,
    duration: Duration,
) {
    let phases_and_probe = take_blob_phases(response);
    let has_blob_phases = phases_and_probe.is_some();
    let (blob_phases, probe_id) = phases_and_probe
        .map(|(phases, probe_id)| (Some(phases), probe_id))
        .unwrap_or((None, None));
    debug_assert!(
        response
            .get_header_names()
            .all(|name| !name.as_str().starts_with(DIAGNOSTIC_PREFIX)),
        "internal diagnostic header escaped extraction"
    );
    let duration_ms = duration.as_millis();
    let persist_error = should_persist_compute_diagnostic(status);
    let is_cold_fill = blob_phases.as_ref().is_some_and(|phases| {
        phases.fos_outcome.as_deref() == Some("miss") && phases.source.as_deref() == Some("gcs")
    });
    let is_enabled_cold_probe = is_enabled_cold_probe(is_cold_fill, probe_id.is_some());
    let persist_blob_fetch = should_persist_blob_fetch_diagnostic(
        status,
        route,
        duration_ms,
        has_blob_phases,
        is_cold_fill,
        is_enabled_cold_probe,
    );
    if !persist_error && !persist_blob_fetch {
        return;
    }

    let sample_reason = if persist_blob_fetch {
        match (duration_ms >= SLOW_BLOB_THRESHOLD_MS, is_cold_fill) {
            (true, true) => Some("slow_cold_fill"),
            (true, false) => Some("slow_success"),
            (false, true) => Some("cold_fill"),
            (false, false) => None,
        }
    } else {
        None
    };

    let categories = error.and_then(persisted_error_categories);
    let record = RequestDiagnostic {
        schema: if persist_blob_fetch {
            "divine.blossom.blob_fetch.v1"
        } else {
            "divine.blossom.compute_request.v1"
        },
        request_id: (!persist_blob_fetch).then_some(request_id),
        probe_id,
        method,
        route,
        status,
        backend: categories.and_then(|fields| fields.backend),
        error_category: categories.map(|fields| fields.category),
        duration_ms,
        blob_phases,
        sample_reason,
    };

    let Ok(line) = serde_json::to_string(&record) else {
        return;
    };
    if let Ok(mut endpoint) = Endpoint::try_from_name(ENDPOINT_NAME) {
        let _ = endpoint.write_all(line.as_bytes());
    }
    eprintln!("[COMPUTE_DIAGNOSTIC] {}", line);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blob_phase_headers_are_removed_before_delivery() {
        let mut response = Response::new();
        attach_blob_phases(
            &mut response,
            BlobFetchDiagnostics {
                fos_lookup_ms: Some(12),
                fos_outcome: Some("miss"),
                gcs_fetch_ms: Some(34),
                buffer_ms: Some(56),
                write_back_ms: Some(78),
                source: Some("gcs"),
                storage_cache: Some("MISS"),
            },
            true,
            Some("coldfill-test-1"),
        );

        let (phases, probe_id) = take_blob_phases(&mut response).expect("attached phases");
        assert!(phases.authorization_present);
        assert_eq!(probe_id.as_deref(), Some("coldfill-test-1"));
        assert_eq!(
            response.get_header_str(PROBE_ID_HEADER),
            Some("coldfill-test-1")
        );
        assert_eq!(response.get_header_str(PROBE_SOURCE_HEADER), Some("gcs"));
        assert_eq!(
            response.get_header_str(PROBE_FOS_OUTCOME_HEADER),
            Some("miss")
        );
        assert_eq!(
            response.get_header_str(PROBE_BUFFER_HEADER),
            Some("present")
        );
        assert_eq!(
            response.get_header_str(PROBE_WRITE_BACK_HEADER),
            Some("present")
        );
        assert_eq!(phases.source.as_deref(), Some("gcs"));
        assert_eq!(phases.fos_lookup_ms, Some(12));
        assert_eq!(phases.gcs_fetch_ms, Some(34));
        assert_eq!(phases.buffer_ms, Some(56));
        assert_eq!(phases.write_back_ms, Some(78));
        assert!(response
            .get_header_names()
            .all(|name| !name.as_str().starts_with(DIAGNOSTIC_PREFIX)));
    }

    #[test]
    fn unattached_internal_headers_are_stripped_without_becoming_diagnostics() {
        let mut response = Response::new();
        response.set_header(SOURCE_HEADER, "untrusted");

        assert!(take_blob_phases(&mut response).is_none());
        assert!(!response.contains_header(SOURCE_HEADER));
    }

    #[test]
    fn cold_fill_diagnostics_are_off_by_default() {
        assert!(!cold_fill_diagnostics_enabled());
        assert!(!is_enabled_cold_probe(true, true));
        assert!(!is_enabled_cold_probe(true, false));
        assert!(!is_enabled_cold_probe(false, true));
    }

    #[test]
    fn serialized_blob_phases_do_not_contain_object_or_identity_fields() {
        let phases = BlobPhases {
            authorization_present: true,
            source: Some("gcs".into()),
            storage_cache: Some("MISS".into()),
            fos_outcome: Some("miss".into()),
            fos_lookup_ms: Some(1),
            gcs_fetch_ms: Some(2),
            buffer_ms: Some(3),
            write_back_ms: Some(4),
        };
        let serialized = serde_json::to_value(phases).expect("serialize phases");
        let object = serialized.as_object().expect("phase object");

        for forbidden in ["hash", "path", "url", "pubkey", "authorization", "ip"] {
            assert!(
                !object.contains_key(forbidden),
                "forbidden field: {forbidden}"
            );
        }
    }
}
