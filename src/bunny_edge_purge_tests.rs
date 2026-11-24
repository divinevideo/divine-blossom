//! Metered Viceroy integration contracts for Bunny edge cache purging.
use super::*;

fn test_hash(index: u8) -> String {
    format!("{:064x}", index)
}

fn seed_blob(hash: &str, status: &str) {
    let metadata = serde_json::json!({
        "sha256": hash,
        "size": 123,
        "type": "video/mp4",
        "uploaded": "2026-01-01T00:00:00Z",
        "owner": "b".repeat(64),
        "status": status
    });
    crate::metadata::open_store()
        .unwrap()
        .insert(&format!("blob:{hash}"), metadata.to_string())
        .unwrap();
}

fn seed_admin_session(token: &str) {
    let session = serde_json::json!({
        "provider": "github",
        "identity": "synthetic",
        "created_at": "2026-01-01T00:00:00Z",
        "expires_at": 4_102_444_800u64
    });
    crate::metadata::open_store()
        .unwrap()
        .insert(&format!("session:{token}"), session.to_string())
        .unwrap();
}

#[test]
#[ignore = "requires loopback purge backends; scripts/run-bunny-edge-purge-tests.py"]
fn transcode_webhook_purges_fastly_then_bunny_within_budget() {
    let hash = test_hash(1);
    seed_blob(&hash, "active");
    let mut req = Request::post("https://media.divine.video/admin/transcode-status");
    req.set_header("Authorization", "Bearer synthetic-webhook-secret");
    req.set_body(serde_json::json!({"sha256": hash, "status": "complete"}).to_string());
    let resp = crate::request_bindings::metered(req);
    assert_eq!(resp.get_status(), StatusCode::OK);
}

#[test]
#[ignore = "requires loopback purge backends; scripts/run-bunny-edge-purge-tests.py"]
fn missing_fastly_token_still_purges_bunny() {
    let hash = test_hash(2);
    seed_blob(&hash, "active");
    let mut req = Request::post("https://media.divine.video/admin/transcode-status");
    req.set_header("Authorization", "Bearer synthetic-webhook-secret");
    req.set_body(serde_json::json!({"sha256": hash, "status": "complete"}).to_string());
    let resp = crate::request_bindings::metered(req);
    assert_eq!(resp.get_status(), StatusCode::OK);
}

#[test]
#[ignore = "requires loopback purge backends; scripts/run-bunny-edge-purge-tests.py"]
fn admin_moderate_webhook_tracks_webhook_secret_and_purges_bunny() {
    let hash = test_hash(3);
    seed_blob(&hash, "active");
    let mut req = Request::post("https://media.divine.video/admin/moderate");
    req.set_header("Authorization", "Bearer synthetic-webhook-secret");
    req.set_body(serde_json::json!({"sha256": hash, "action": "BAN"}).to_string());
    let resp = crate::request_bindings::metered(req);
    assert_eq!(resp.get_status(), StatusCode::OK);
}

#[test]
#[ignore = "requires loopback purge backends; scripts/run-bunny-edge-purge-tests.py"]
fn admin_soft_delete_purges_fastly_and_bunny_within_budget() {
    let hash = test_hash(5);
    seed_blob(&hash, "active");
    let session = "c".repeat(64);
    seed_admin_session(&session);
    let mut req = Request::post("https://media.divine.video/admin/api/delete");
    req.set_header("Cookie", format!("admin_session={session}"));
    req.set_body(serde_json::json!({"sha256": hash, "reason": "admin soft delete"}).to_string());
    let resp = crate::request_bindings::metered(req);
    assert_eq!(resp.get_status(), StatusCode::OK);
}

#[test]
#[ignore = "requires loopback purge backends; scripts/run-bunny-edge-purge-tests.py"]
fn legacy_physical_creator_delete_preserves_origin_secret_budget() {
    let hash = test_hash(4);
    seed_blob(&hash, "active");
    let session = "d".repeat(64);
    seed_admin_session(&session);
    let mut req = Request::post("https://media.divine.video/admin/api/moderate");
    req.set_header("Cookie", format!("admin_session={session}"));
    req.set_body(
        serde_json::json!({"sha256": hash, "action": "DELETE", "reason": "creator delete"})
            .to_string(),
    );
    // Pre-existing `kv_origin::settings()` on base `main` looks up absent
    // `kv_origin_read_token` before checking `metadata_kv_store_id`, so run via
    // `handle_main` and verify Fastly+GCS+FOS ordering and 0 Bunny reads in Python.
    let mut resp = crate::handle_main(req).unwrap();
    assert_eq!(resp.get_status(), StatusCode::OK);
    let body: serde_json::Value = serde_json::from_str(&resp.take_body_str()).unwrap();
    assert_eq!(body["physical_deleted"], serde_json::json!(true));
}

#[test]
#[ignore = "requires loopback purge backends; scripts/run-bunny-edge-purge-tests.py"]
fn legacy_physical_creator_delete_early_gcs_failure_purges_bunny_fallback() {
    let hash = test_hash(6);
    seed_blob(&hash, "active");
    let session = "f".repeat(64);
    seed_admin_session(&session);
    let mut req = Request::post("https://media.divine.video/admin/api/moderate");
    req.set_header("Cookie", format!("admin_session={session}"));
    req.set_body(
        serde_json::json!({"sha256": hash, "action": "DELETE", "reason": "creator delete"})
            .to_string(),
    );
    let resp = crate::request_bindings::metered(req);
    assert!(resp.get_status().is_server_error());
}

#[test]
#[ignore = "requires loopback purge backends; scripts/run-bunny-edge-purge-tests.py"]
fn bulk_approve_batches_fastly_and_bounds_bunny_within_backend_limit() {
    let hashes: Vec<String> = (10u8..26u8).map(test_hash).collect();
    for hash in &hashes {
        seed_blob(hash, "banned");
    }
    let session = "e".repeat(64);
    seed_admin_session(&session);
    let mut req = Request::post("https://media.divine.video/admin/api/bulk-approve");
    req.set_header("Cookie", format!("admin_session={session}"));
    req.set_body(serde_json::json!({"hashes": hashes}).to_string());
    let mut resp = crate::request_bindings::metered(req);
    assert_eq!(resp.get_status(), StatusCode::OK);
    let body: serde_json::Value = serde_json::from_str(&resp.take_body_str()).unwrap();
    assert_eq!(body["approved"], serde_json::json!(16));
}
