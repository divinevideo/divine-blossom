// ABOUTME: Structured log record for edge-proxied upload requests and its JSON formatter
// ABOUTME: Pure logic so upload observability is unit-tested without Viceroy

/// Bumped whenever the emitted field set changes incompatibly. The sink's
/// schema is owned by a different repo, so consumers need a version to key on.
pub const SCHEMA_VERSION: u32 = 2;

/// Upper bound on any free-text field copied into a log line. Error text is
/// partly attacker-influenced, and an unbounded message is both a cost and a
/// readability problem on a line-delimited sink.
pub const MAX_MESSAGE_LEN: usize = 200;

/// Placeholder substituted for anything following an auth scheme keyword.
const REDACTED: &str = "[redacted]";

/// Auth scheme keywords whose following token is a credential.
const CREDENTIAL_SCHEMES: [&str; 2] = ["nostr", "bearer"];

/// The edge-proxied upload routes. Resumable *chunk* appends are deliberately
/// absent: clients send those straight to the upload service, so they never
/// traverse this service and are already visible in origin logs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UploadRoute {
    /// `PUT /upload` — the whole request body is proxied through the edge.
    DirectPut,
    /// `POST /upload/init` — small resumable control-plane call.
    ResumableInit,
    /// `POST /upload/{id}/complete` — small resumable control-plane call.
    ResumableComplete,
}

impl UploadRoute {
    pub fn as_str(self) -> &'static str {
        match self {
            UploadRoute::DirectPut => "direct_put",
            UploadRoute::ResumableInit => "resumable_init",
            UploadRoute::ResumableComplete => "resumable_complete",
        }
    }
}

/// What happened to an upload attempt, from the edge's point of view.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UploadOutcome {
    /// Edge returned a success status.
    Ok,
    /// The proxy send did not yield a complete origin response.
    SendFailed,
    /// Origin replied, with a non-success status.
    OriginStatusError,
    /// Edge returned a 4xx of its own. Check `origin_responded` to tell an
    /// edge-side precondition failure from a rejection relayed from origin.
    ValidationRejected,
    /// Edge returned a 5xx of its own. With `origin_responded = true` this is a
    /// post-origin failure: the upload landed but the edge failed afterwards.
    EdgeError,
}

impl UploadOutcome {
    pub fn as_str(self) -> &'static str {
        match self {
            UploadOutcome::Ok => "ok",
            UploadOutcome::SendFailed => "send_failed",
            UploadOutcome::OriginStatusError => "origin_status_error",
            UploadOutcome::ValidationRejected => "validation_rejected",
            UploadOutcome::EdgeError => "edge_error",
        }
    }
}

/// One edge upload attempt. Deliberately carries no request body, no
/// `Authorization` header, and no pubkey — see `sanitize` for the guard on
/// free-text fields that could otherwise smuggle a credential in.
#[derive(Debug, Clone)]
pub struct UploadLogRecord {
    pub route: UploadRoute,
    /// Correlation ID, also forwarded to origin as `X-Request-Id`.
    pub req_id: String,
    /// Declared `Content-Length`, not a measured body size — instrumenting
    /// must never buffer the body to count it.
    pub content_length: Option<u64>,
    pub content_type: Option<String>,
    /// Whether a request body was streamed through the edge to origin.
    pub proxied_body: bool,
    /// Whether origin returned a complete HTTP response.
    pub origin_responded: bool,
    pub origin_status: Option<u16>,
    /// The error from `.send()`. This does not establish whether origin
    /// received or processed some or all of the request.
    pub send_error: Option<String>,
    /// Wall time around the origin send, present whenever a send was attempted
    /// — including when it failed.
    pub proxy_duration_ms: Option<u64>,
    /// Wall time for the whole request as seen by the edge handler.
    pub duration_ms: u64,
    pub response_status: u16,
    pub error_kind: Option<&'static str>,
    pub error_message: Option<String>,
    pub client_ip_present: bool,
    pub client_geo_country: Option<String>,
}

impl UploadLogRecord {
    /// A record for a request that has not done anything yet.
    pub fn new(route: UploadRoute, req_id: String) -> Self {
        UploadLogRecord {
            route,
            req_id,
            content_length: None,
            content_type: None,
            proxied_body: false,
            origin_responded: false,
            origin_status: None,
            send_error: None,
            proxy_duration_ms: None,
            duration_ms: 0,
            response_status: 0,
            error_kind: None,
            error_message: None,
            client_ip_present: false,
            client_geo_country: None,
        }
    }

    /// Classify the attempt. Order matters: a failed send is the case with no
    /// record anywhere else, so it outranks every other signal.
    pub fn outcome(&self) -> UploadOutcome {
        if self.send_error.is_some() {
            return UploadOutcome::SendFailed;
        }
        if let Some(status) = self.origin_status {
            if !(200..300).contains(&status) {
                return UploadOutcome::OriginStatusError;
            }
        }
        if (200..400).contains(&self.response_status) {
            return UploadOutcome::Ok;
        }
        if self.response_status < 500 {
            UploadOutcome::ValidationRejected
        } else {
            UploadOutcome::EdgeError
        }
    }
}

/// Outcome of attempting to send the request to origin.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OriginSendResult<'a> {
    /// Origin answered, with this status.
    Replied(u16),
    /// The send did not yield a complete response.
    Failed(&'a str),
}

/// Record an origin send attempt and how long it took.
///
/// The duration is recorded for both arms on purpose: a send that failed after
/// two minutes and one that failed instantly are different problems, and only
/// this field distinguishes them.
pub fn record_send_attempt(
    record: &mut UploadLogRecord,
    result: OriginSendResult<'_>,
    duration_ms: u64,
) {
    record.proxy_duration_ms = Some(duration_ms);
    match result {
        OriginSendResult::Replied(status) => {
            record.origin_responded = true;
            record.origin_status = Some(status);
        }
        OriginSendResult::Failed(error) => {
            record.origin_responded = false;
            record.origin_status = None;
            record.send_error = Some(error.to_string());
        }
    }
}

/// Record the status the edge returned for a successful handler run.
pub fn record_response(record: &mut UploadLogRecord, status: u16) {
    record.response_status = status;
}

/// Record the error the edge returned.
///
/// Additive only. An earlier `send_error` or `origin_status` must survive:
/// both a failed send and an origin rejection get wrapped into a
/// `BlossomError` before the handler returns, and overwriting here would erase
/// the distinction between "no complete response", "origin refused it", and
/// "the edge itself broke".
pub fn record_failure(record: &mut UploadLogRecord, error: &crate::error::BlossomError) {
    record.response_status = error.status_code().as_u16();
    record.error_kind = Some(error.kind());
    record.error_message = Some(error.message().to_string());
}

/// Render one record as a single-line JSON object.
///
/// Every field is always emitted, `null` when absent: the downstream sink is a
/// fixed-column table, and a key that vanishes on some rows makes
/// line-delimited ingestion inconsistent.
pub fn format_upload_log(record: &UploadLogRecord) -> String {
    let line = serde_json::json!({
        "schema": SCHEMA_VERSION,
        "route": record.route.as_str(),
        "outcome": record.outcome().as_str(),
        "req_id": sanitize_opt(Some(&record.req_id)),
        "content_length": record.content_length,
        "content_type": sanitize_opt(record.content_type.as_deref()),
        "proxied_body": record.proxied_body,
        "origin_responded": record.origin_responded,
        "origin_status": record.origin_status,
        "send_error": sanitize_opt(record.send_error.as_deref()),
        "proxy_duration_ms": record.proxy_duration_ms,
        "duration_ms": record.duration_ms,
        "response_status": record.response_status,
        "error_kind": record.error_kind,
        "error_message": sanitize_opt(record.error_message.as_deref()),
        "client_ip_present": record.client_ip_present,
        "client_geo_country": sanitize_opt(record.client_geo_country.as_deref()),
    });

    line.to_string()
}

fn sanitize_opt(value: Option<&str>) -> Option<String> {
    value.map(sanitize)
}

/// Make a free-text value safe to put on a shared, line-delimited log sink.
///
/// Control characters become spaces so a single record cannot be split into
/// two; anything following an auth scheme keyword is dropped so a credential
/// echoed back inside an error message never reaches the sink; and the result
/// is length-capped.
fn sanitize(value: &str) -> String {
    let despaced: String = value
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect();

    let mut parts: Vec<String> = Vec::new();
    let mut previous_was_scheme = false;
    for token in despaced.split_whitespace() {
        if previous_was_scheme {
            parts.push(REDACTED.to_string());
        } else {
            parts.push(token.to_string());
        }
        previous_was_scheme = CREDENTIAL_SCHEMES
            .iter()
            .any(|scheme| token.eq_ignore_ascii_case(scheme));
    }

    parts.join(" ").chars().take(MAX_MESSAGE_LEN).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record() -> UploadLogRecord {
        UploadLogRecord {
            route: UploadRoute::DirectPut,
            req_id: "abc123".into(),
            content_length: Some(1_048_576),
            content_type: Some("video/mp4".into()),
            proxied_body: true,
            origin_responded: true,
            origin_status: Some(200),
            send_error: None,
            proxy_duration_ms: Some(4200),
            duration_ms: 4300,
            response_status: 200,
            error_kind: None,
            error_message: None,
            client_ip_present: true,
            client_geo_country: Some("NZ".into()),
        }
    }

    fn parse(line: &str) -> serde_json::Value {
        serde_json::from_str(line).expect("log line must be valid JSON")
    }

    #[test]
    fn ok_upload_is_classified_ok() {
        let line = format_upload_log(&record());
        let v = parse(&line);

        assert_eq!(v["outcome"], "ok");
        assert_eq!(v["route"], "direct_put");
        assert_eq!(v["origin_status"], 200);
        assert_eq!(v["content_length"], 1_048_576);
        assert_eq!(v["duration_ms"], 4300);
    }

    #[test]
    fn send_failure_is_classified_send_failed() {
        // The edge did not receive a complete origin response.
        let mut r = record();
        r.origin_responded = false;
        r.origin_status = None;
        r.send_error = Some("connection closed by peer".into());
        r.response_status = 500;
        r.error_kind = Some("internal");

        let v = parse(&format_upload_log(&r));

        assert_eq!(v["outcome"], "send_failed");
        assert_eq!(v["send_error"], "connection closed by peer");
        assert_eq!(v["origin_responded"], false);
        assert!(v["origin_status"].is_null());
    }

    #[test]
    fn send_failure_still_records_duration() {
        // duration on the failure path is the whole point: it is what tells us
        // whether edge uploads are dying at Fastly's 120s request ceiling.
        let mut r = record();
        r.send_error = Some("timeout".into());
        r.origin_status = None;
        r.origin_responded = false;
        r.proxy_duration_ms = Some(120_000);
        r.duration_ms = 120_050;
        r.response_status = 500;

        let v = parse(&format_upload_log(&r));

        assert_eq!(v["outcome"], "send_failed");
        assert_eq!(v["proxy_duration_ms"], 120_000);
        assert_eq!(v["duration_ms"], 120_050);
    }

    #[test]
    fn non_success_origin_status_is_classified_origin_status_error() {
        let mut r = record();
        r.origin_status = Some(413);
        r.response_status = 413;
        r.error_kind = Some("bad_request");

        let v = parse(&format_upload_log(&r));

        assert_eq!(v["outcome"], "origin_status_error");
        assert_eq!(v["origin_status"], 413);
        assert_eq!(v["origin_responded"], true);
    }

    #[test]
    fn client_error_before_origin_is_classified_validation_rejected() {
        let mut r = record();
        r.origin_responded = false;
        r.origin_status = None;
        r.proxy_duration_ms = None;
        r.proxied_body = false;
        r.response_status = 400;
        r.error_kind = Some("bad_request");
        r.error_message = Some("Content-Length required".into());

        let v = parse(&format_upload_log(&r));

        assert_eq!(v["outcome"], "validation_rejected");
        assert_eq!(v["error_message"], "Content-Length required");
        assert!(v["proxy_duration_ms"].is_null());
    }

    #[test]
    fn server_error_before_origin_is_classified_edge_error() {
        let mut r = record();
        r.origin_responded = false;
        r.origin_status = None;
        r.response_status = 502;
        r.error_kind = Some("storage_error");

        let v = parse(&format_upload_log(&r));

        assert_eq!(v["outcome"], "edge_error");
    }

    #[test]
    fn edge_failure_after_successful_origin_reply_is_distinguishable() {
        // Origin accepted the upload but the edge failed afterwards (bad
        // response parse, metadata write). Without origin_responded this is
        // indistinguishable from a pre-origin edge failure.
        let mut r = record();
        r.origin_status = Some(200);
        r.response_status = 500;
        r.error_kind = Some("internal");

        let v = parse(&format_upload_log(&r));

        assert_eq!(v["outcome"], "edge_error");
        assert_eq!(v["origin_responded"], true);
        assert_eq!(v["origin_status"], 200);
    }

    #[test]
    fn resumable_routes_render_their_own_labels() {
        let mut r = record();
        r.route = UploadRoute::ResumableInit;
        assert_eq!(parse(&format_upload_log(&r))["route"], "resumable_init");

        r.route = UploadRoute::ResumableComplete;
        assert_eq!(parse(&format_upload_log(&r))["route"], "resumable_complete");
    }

    #[test]
    fn absent_optional_fields_render_as_null_not_missing() {
        // The ClickHouse schema is fixed-column; a key that disappears on some
        // rows makes JSONEachRow ingestion inconsistent.
        let mut r = record();
        r.content_length = None;
        r.content_type = None;
        r.client_geo_country = None;

        let v = parse(&format_upload_log(&r));

        assert!(v.get("content_length").is_some_and(|f| f.is_null()));
        assert!(v.get("content_type").is_some_and(|f| f.is_null()));
        assert!(v.get("client_geo_country").is_some_and(|f| f.is_null()));
    }

    #[test]
    fn nostr_credentials_are_redacted_from_messages() {
        let mut r = record();
        r.response_status = 401;
        r.error_kind = Some("auth_invalid");
        r.error_message = Some(
            "rejected header Nostr eyJpZCI6ImFiYyIsInNpZyI6ImRlYWRiZWVmIn0= for upload".into(),
        );

        let line = format_upload_log(&r);

        assert!(!line.contains("eyJpZCI6"), "auth token leaked into log: {line}");
        assert!(line.contains("[redacted]"));
    }

    #[test]
    fn bearer_credentials_are_redacted_from_messages() {
        let mut r = record();
        r.send_error = Some("upstream rejected Bearer sk-live-abcdef123456".into());

        let line = format_upload_log(&r);

        assert!(!line.contains("sk-live-abcdef123456"));
        assert!(line.contains("[redacted]"));
    }

    #[test]
    fn long_messages_are_truncated() {
        let mut r = record();
        r.error_message = Some("x".repeat(5000));

        let v = parse(&format_upload_log(&r));
        let msg = v["error_message"].as_str().unwrap();

        assert!(msg.len() <= MAX_MESSAGE_LEN + 1, "message not truncated: {}", msg.len());
    }

    #[test]
    fn control_characters_are_stripped_from_messages() {
        // Error text can carry attacker-influenced bytes; a raw newline would
        // split one record into two on a line-delimited sink.
        let mut r = record();
        r.error_message = Some("bad\ninput\r\nhere\u{1b}[31m".into());

        let v = parse(&format_upload_log(&r));
        let msg = v["error_message"].as_str().unwrap();

        assert!(!msg.contains('\n'));
        assert!(!msg.contains('\r'));
        assert!(!msg.contains('\u{1b}'));
    }

    #[test]
    fn log_line_is_a_single_line() {
        let mut r = record();
        r.error_message = Some("multi\nline\nerror".into());

        assert_eq!(format_upload_log(&r).lines().count(), 1);
    }

    #[test]
    fn schema_version_is_present_for_sink_migrations() {
        let v = parse(&format_upload_log(&record()));
        assert_eq!(v["schema"], SCHEMA_VERSION);
    }

    // --- recording the origin send attempt -------------------------------
    //
    // These cover the transitions the edge crate performs on a live request.
    // They live here because CI runs `cargo test -p blossom-core` only; the
    // edge crate's tests are type-checked but never executed, so logic left
    // in src/ is effectively untested.

    fn fresh() -> UploadLogRecord {
        UploadLogRecord::new(UploadRoute::DirectPut, "abc123".into())
    }

    #[test]
    fn recording_a_failed_send_marks_origin_unreached() {
        let mut r = fresh();
        record_send_attempt(&mut r, OriginSendResult::Failed("connection reset"), 900);

        assert_eq!(r.send_error.as_deref(), Some("connection reset"));
        assert!(!r.origin_responded);
        assert_eq!(r.origin_status, None);
        assert_eq!(r.proxy_duration_ms, Some(900));
        assert_eq!(r.outcome(), UploadOutcome::SendFailed);
    }

    #[test]
    fn recording_a_reply_marks_origin_responded() {
        let mut r = fresh();
        record_send_attempt(&mut r, OriginSendResult::Replied(201), 1500);

        assert!(r.origin_responded);
        assert_eq!(r.origin_status, Some(201));
        assert_eq!(r.send_error, None);
        assert_eq!(r.proxy_duration_ms, Some(1500));
    }

    #[test]
    fn a_failed_send_records_duration_even_at_the_timeout_ceiling() {
        // Fastly's request timeout is 120s. If uploads are dying there, this
        // is the only field that will show it.
        let mut r = fresh();
        record_send_attempt(&mut r, OriginSendResult::Failed("timed out"), 120_000);

        assert_eq!(r.proxy_duration_ms, Some(120_000));
        assert_eq!(r.outcome(), UploadOutcome::SendFailed);
    }

    #[test]
    fn recording_the_error_does_not_clobber_an_earlier_send_failure() {
        // The edge wraps a send failure into BlossomError::Internal before
        // returning it. If recording that error overwrote send_error, or if
        // the 500 status flipped the classification, the one case with no
        // record anywhere else would be filed as a generic edge error.
        let mut r = fresh();
        record_send_attempt(&mut r, OriginSendResult::Failed("connection reset"), 900);
        record_failure(
            &mut r,
            &crate::error::BlossomError::Internal(
                "Failed to proxy to upload service: connection reset".into(),
            ),
        );

        assert_eq!(r.send_error.as_deref(), Some("connection reset"));
        assert_eq!(r.response_status, 500);
        assert_eq!(r.error_kind, Some("internal"));
        assert_eq!(r.outcome(), UploadOutcome::SendFailed);
    }

    #[test]
    fn recording_a_failure_derives_status_and_kind_from_the_error() {
        let mut r = fresh();
        record_failure(
            &mut r,
            &crate::error::BlossomError::BadRequest("Content-Length required".into()),
        );

        assert_eq!(r.response_status, 400);
        assert_eq!(r.error_kind, Some("bad_request"));
        assert_eq!(r.error_message.as_deref(), Some("Content-Length required"));
        assert_eq!(r.outcome(), UploadOutcome::ValidationRejected);
    }

    #[test]
    fn recording_a_success_status_leaves_error_fields_empty() {
        let mut r = fresh();
        record_send_attempt(&mut r, OriginSendResult::Replied(200), 10);
        record_response(&mut r, 200);

        assert_eq!(r.response_status, 200);
        assert_eq!(r.error_kind, None);
        assert_eq!(r.error_message, None);
        assert_eq!(r.outcome(), UploadOutcome::Ok);
    }

    #[test]
    fn origin_rejection_survives_being_remapped_to_an_edge_error() {
        // A 413 from origin is remapped to a BlossomError before returning.
        // origin_status must still win the classification, otherwise every
        // origin rejection is miscounted as an edge-side validation failure.
        let mut r = fresh();
        record_send_attempt(&mut r, OriginSendResult::Replied(413), 2000);
        record_failure(
            &mut r,
            &crate::error::BlossomError::BadRequest("File too large".into()),
        );

        assert_eq!(r.outcome(), UploadOutcome::OriginStatusError);
        assert_eq!(r.origin_status, Some(413));
        assert!(r.origin_responded);
    }
}
