// ABOUTME: Fastly glue that builds and emits upload log records to the durable endpoint
// ABOUTME: Keeps request-shaped concerns out of the pure formatter in blossom-core

use blossom_core::upload_log::{format_upload_log, UploadLogRecord, UploadRoute};
use fastly::http::header;
use fastly::Request;
use std::io::Write;
use std::time::{SystemTime, UNIX_EPOCH};

/// Name of the Fastly logging endpoint that carries these lines.
///
/// The endpoint itself lives in Fastly service configuration, not in this
/// repo, so it is invisible to git and absent from any service rebuilt from
/// scratch. Writes to a missing endpoint are dropped silently by the platform.
/// See `docs/runbooks/edge-upload-observability.md` for how to recreate it.
pub(crate) const UPLOAD_LOG_ENDPOINT: &str = "edge_upload_logs";

/// Header used to correlate an edge log line with the origin's access log.
pub(crate) const CORRELATION_HEADER: &str = "X-Request-Id";

/// Seed a record from the inbound request.
///
/// Reads declared headers only. It must never touch the body: buffering a
/// request body here to measure it would defeat the streaming proxy on exactly
/// the large uploads this instrumentation exists to observe.
pub(crate) fn start_record(
    req: &Request,
    route: UploadRoute,
    req_id: String,
) -> UploadLogRecord {
    let occurred_at_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis().min(u128::from(u64::MAX)) as u64)
        .unwrap_or(0);
    let mut record = UploadLogRecord::new(route, req_id, occurred_at_ms);

    record.content_length = req
        .get_header(header::CONTENT_LENGTH)
        .and_then(|h| h.to_str().ok())
        .and_then(|s| s.parse::<u64>().ok());

    record.content_type = req
        .get_header(header::CONTENT_TYPE)
        .and_then(|h| h.to_str().ok())
        .map(|s| s.to_string());

    // Country code only: enough to tell "uploads fail on one network" from
    // "uploads fail everywhere", without carrying anything identifying.
    if let Some(ip) = req.get_client_ip_addr() {
        record.client_ip_present = true;
        record.client_geo_country =
            fastly::geo::geo_lookup(ip).map(|geo| geo.country_code().to_string());
    }

    record
}

/// Write one record to the durable sink.
///
/// Also mirrored to stderr. That is deliberate redundancy, not duplication:
/// the endpoint is dashboard-managed config that this repo cannot assert on,
/// and if it is ever deleted the platform drops writes without erroring. The
/// stderr copy keeps `fastly log-tail` useful for confirming that the guest is
/// still emitting, though Pub/Sub remains the only durable count.
pub(crate) fn emit(record: &UploadLogRecord) {
    let line = format_upload_log(record);
    if let Ok(mut endpoint) = fastly::log::Endpoint::try_from_name(UPLOAD_LOG_ENDPOINT) {
        let _ = writeln!(endpoint, "{}", line);
    }
    eprintln!("[UPLOAD] {}", line);
}
