use blossom_core::delivery_telemetry::*;

const LOAD: &str = "12345678-1234-4234-9234-123456789abc";
const EVENT: &str = "22222222-2222-4222-a222-222222222222";
const REQUEST: &str = "33333333-3333-4333-b333-333333333333";

#[test]
fn cohort_requires_explicit_flag_direct_configured_host_and_uuid_v4() {
    assert!(eligible(Some("true"), true, "GET", Some(LOAD)));
    assert!(eligible(Some("true"), true, "HEAD", Some(LOAD)));
    for (flag, host, method, load) in [
        (None, true, "GET", Some(LOAD)),
        (Some("false"), true, "GET", Some(LOAD)),
        (Some("TRUE"), true, "GET", Some(LOAD)),
        (Some("true"), false, "GET", Some(LOAD)),
        (Some("true"), true, "POST", Some(LOAD)),
        (Some("true"), true, "GET", None),
        (
            Some("true"),
            true,
            "GET",
            Some("12345678-1234-1234-9234-123456789abc"),
        ),
        (
            Some("true"),
            true,
            "GET",
            Some("12345678-1234-4234-1234-123456789abc"),
        ),
        (
            Some("true"),
            true,
            "GET",
            Some("12345678-1234-4234-9234-123456789ABC"),
        ),
        (
            Some("true"),
            true,
            "GET",
            Some(" 12345678-1234-4234-9234-123456789abc"),
        ),
    ] {
        assert!(!eligible(flag, host, method, load));
    }
}

#[test]
fn all_terminal_statuses_emit_only_headers_and_exact_private_wire_fields() {
    for method in ["GET", "HEAD"] {
        for status in [100, 200, 206, 304, 400, 404, 416, 500, 503, 599] {
            let event = compute_headers(
                EVENT,
                LOAD,
                REQUEST,
                1793900000000,
                method,
                status,
                true,
                7,
                DeliveryObservation::default(),
            )
            .unwrap();
            let value = serde_json::to_value(event).unwrap();
            let expected = serde_json::json!({
                "schema":"divine.media.delivery.v1", "event_id":EVENT, "load_id":LOAD,
                "request_id":REQUEST, "occurred_at_ms":1793900000000_u64,
                "cohort":"b2_canary", "stage":"compute_headers", "method":method,
                "status":status, "range_request":true, "provider":"unknown",
                "storage_cache":"unknown", "outer_cache":"bypass", "fallback":"unknown",
                "origin_attempted":null, "header_ready_ms":7, "transfer_ms":null, "bytes_sent":null
            });
            assert_eq!(value, expected);
        }
    }
}

#[test]
fn invalid_output_and_unrepresentable_duration_are_not_fabricated() {
    assert!(compute_headers(
        "retry",
        LOAD,
        REQUEST,
        1,
        "GET",
        200,
        false,
        1,
        DeliveryObservation::default()
    )
    .is_none());
    assert!(compute_headers(
        EVENT,
        LOAD,
        "CALLER-ID",
        1,
        "GET",
        200,
        false,
        1,
        DeliveryObservation::default()
    )
    .is_none());
    assert!(compute_headers(
        EVENT,
        LOAD,
        REQUEST,
        1,
        "POST",
        200,
        false,
        1,
        DeliveryObservation::default()
    )
    .is_none());
    for status in [0, 99, 600] {
        assert!(compute_headers(
            EVENT,
            LOAD,
            REQUEST,
            1,
            "GET",
            status,
            false,
            1,
            DeliveryObservation::default()
        )
        .is_none());
    }
    let event = compute_headers(
        EVENT,
        LOAD,
        REQUEST,
        1,
        "HEAD",
        416,
        false,
        600001,
        DeliveryObservation::default(),
    )
    .unwrap();
    assert_eq!(
        serde_json::to_value(event).unwrap()["header_ready_ms"],
        serde_json::Value::Null
    );
}

#[test]
fn random_bytes_become_canonical_v4_without_clock_or_caller_identity() {
    assert_eq!(uuid_v4([0; 16]), "00000000-0000-4000-8000-000000000000");
    assert_eq!(uuid_v4([255; 16]), "ffffffff-ffff-4fff-bfff-ffffffffffff");
}

#[test]
fn missing_endpoint_reports_a_safe_counter_without_failing_delivery() {
    let outcome = write_delivery_log(None::<Vec<u8>>, "private-request-payload");
    assert_eq!(outcome, DeliveryLogOutcome::EndpointUnavailable);
    assert_eq!(
        outcome.diagnostic(),
        "playback_delivery_log outcome=endpoint_unavailable count=1"
    );
}

#[test]
fn rejected_log_write_reports_no_raw_error_or_event_payload() {
    struct Rejected;
    impl std::io::Write for Rejected {
        fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
            Err(std::io::Error::other("private auth and request details"))
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let outcome = write_delivery_log(Some(Rejected), "private-request-payload");
    assert_eq!(outcome, DeliveryLogOutcome::WriteFailed);
    assert_eq!(
        outcome.diagnostic(),
        "playback_delivery_log outcome=write_failed count=1"
    );
}

#[test]
fn accepted_log_write_preserves_raw_json_and_does_not_claim_sink_delivery() {
    let mut bytes = Vec::new();
    let outcome = write_delivery_log(Some(&mut bytes), r#"{"schema":"divine.media.delivery.v1"}"#);
    assert_eq!(bytes, b"{\"schema\":\"divine.media.delivery.v1\"}\n");
    assert_eq!(outcome, DeliveryLogOutcome::HostAccepted);
    assert_eq!(
        outcome.diagnostic(),
        "playback_delivery_log outcome=host_accepted count=1"
    );
}
