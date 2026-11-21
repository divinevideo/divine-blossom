//! Publish verified, anonymous public media to the private Bunny origin prefix.
use crate::error::{BlossomError, Result};
use crate::{admin, canary, metadata, parent_gate, storage};
use blossom_core::bunny_worker::{Job, Operation, Outcome, Publication, Reply, Scope};

use fastly::http::{Method, StatusCode};
use fastly::{Request, Response};

use serde_json::{json, Value};

use std::io::Read;

const MAX_BODY: u64 = 8192;

pub(crate) fn invalid() -> BlossomError {
    BlossomError::BadRequest("Invalid Bunny publication request".into())
}

fn parse_publication(body: &[u8]) -> Result<Publication> {
    let publication: Publication = serde_json::from_slice(body).map_err(|_| invalid())?;
    publication.asset().ok_or_else(invalid)?;
    Ok(publication)
}

pub(crate) fn worker(scope: &Scope, operation: Operation) -> Result<Outcome> {
    let unavailable = || BlossomError::StorageError("Bunny worker response unverified".into());
    let job = Job {
        scope: scope.clone(),
        operation,
    };
    let mut request = Request::post(format!(
        "https://{}/internal/bunny-pilot/v1",
        crate::UPLOAD_SERVICE_HOST
    ))
    .with_header("Host", crate::UPLOAD_SERVICE_HOST)
    .with_header(
        "Authorization",
        format!(
            "Bearer {}",
            storage::get_secret("bunny_pilot_worker_token")?
        ),
    )
    .with_header("Content-Type", "application/json")
    .with_body(serde_json::to_vec(&job).map_err(|_| invalid())?);
    request.set_pass(true);
    let mut response = request
        .send(crate::UPLOAD_SERVICE_BACKEND)
        .map_err(|_| unavailable())?;
    if response.get_status() != StatusCode::OK {
        return Err(unavailable());
    }
    let mut bytes = Vec::new();
    response
        .take_body()
        .take(32769)
        .read_to_end(&mut bytes)
        .map_err(|_| unavailable())?;
    if bytes.len() > 32768 {
        return Err(unavailable());
    }
    let reply: Reply = serde_json::from_slice(&bytes).map_err(|_| unavailable())?;
    if reply.scope != *scope {
        return Err(unavailable());
    }
    Ok(reply.result)
}

/// A PUT with an unknown outcome keeps its fence. A settled write whose
/// verification fails hands exclusion to the durable erasure worker.
pub(crate) fn with_gate<T>(
    hash: &str,
    action: impl FnOnce(&str, &dyn Fn() -> Result<()>, &mut bool) -> Result<T>,
) -> Result<T> {
    storage::validate_bunny_pilot_publication()?;
    let mut random = [0; 16];
    getrandom::getrandom(&mut random)
        .map_err(|_| BlossomError::Internal("Bunny publication attempt unavailable".into()))?;
    let attempt = hex::encode(random);
    let generation = parent_gate::bunny_claim(hash, &attempt)?;
    let check_gate = || parent_gate::check_bunny_gate(hash, &attempt, &generation);
    let mut may_release = true;

    let result = action(&generation, &check_gate, &mut may_release);
    if may_release {
        parent_gate::bunny_release(hash, &attempt, &generation)?;
    }
    result
}

/// Retire the current inventory while this writer still owns the gate. Transfer
/// the durable removal even if immediate invalidation hit a provider error.
fn queue_cleanup(parent: &str, generation: &str) -> Result<()> {
    let retired = crate::bunny_ready::invalidate(parent);
    parent_gate::handoff_bunny_cleanup(parent, generation)?;
    retired
}

fn publish(publication: Publication) -> Result<Value> {
    let asset = publication.asset().ok_or_else(invalid)?;
    let parent = asset.hash();
    with_gate(parent, |generation, check_gate, may_release| {
        let policy = metadata::bunny_public_metadata(parent)?;
        let original_size = if asset.is_original() {
            if policy.mime_type != "video/mp4" {
                return Err(BlossomError::NotFound("Bunny original unavailable".into()));
            }
            Some(policy.size)
        } else {
            None
        };
        let scope = storage::bunny_scope()?;
        storage::enroll_bunny_parent(parent)?;
        check_gate()?;
        // After dispatch a timeout or an unreadable reply is an uncertain PUT.
        *may_release = false;
        let result = worker(
            &scope,
            Operation::Publish {
                publication: publication.clone(),
                original_size,
            },
        )?;
        let (already, verified) = match result {
            Outcome::AlreadyPublished { verified } => (true, verified),
            Outcome::Published { verified } => (false, verified),
            Outcome::ReadbackFailed => {
                queue_cleanup(parent, generation)?;
                return Err(BlossomError::StorageError(
                    "Bunny readback unverified".into(),
                ));
            }
            Outcome::Uncertain | Outcome::Verified { .. } => {
                return Err(BlossomError::StorageError(
                    "Bunny writer outcome uncertain".into(),
                ))
            }
            outcome => {
                if matches!(outcome, Outcome::DeliveryConflict) {
                    crate::bunny_ready::invalidate(parent)?;
                }
                *may_release = true;
                return Err(match outcome {
                    Outcome::SourceChanged | Outcome::DeliveryConflict => {
                        BlossomError::Conflict("Bunny source or delivery object changed".into())
                    }
                    Outcome::SourceMissing => {
                        BlossomError::NotFound("Bunny source unavailable".into())
                    }
                    _ => BlossomError::StorageError("Bunny publication rejected".into()),
                });
            }
        };
        if !scope.matches(&verified)
            || verified.asset.path != publication.path
            || verified.asset.source_sha256 != publication.sha256
        {
            return Err(BlossomError::StorageError(
                "Bunny worker evidence mismatched".into(),
            ));
        }
        if !already {
            crate::bunny_ready::invalidate(parent)?;
        }
        if let Err(error) = check_gate().and_then(|_| {
            let policy = metadata::bunny_public_metadata(parent)?;
            if asset.is_original()
                && (policy.size != verified.delivery_size as u64 || policy.mime_type != "video/mp4")
            {
                return Err(BlossomError::NotFound("Bunny original unavailable".into()));
            }
            Ok(())
        }) {
            queue_cleanup(parent, generation)?;
            return Err(error);
        }
        *may_release = true;
        let mut result = json!({"result":if already { "already_published" } else { "published" }});
        if asset.is_playlist() {
            result["delivery_sha256"] = json!(verified.asset.delivery_sha256);
        }
        Ok(result)
    })
}

pub(crate) fn reply(status: StatusCode, body: Value) -> Response {
    let mut response = Response::from_status(status);
    response.set_header("Content-Type", "application/json");
    canary::no_store(&mut response);
    response.set_body(body.to_string());
    response
}

pub(crate) fn handle(mut req: Request) -> Response {
    if !admin::extract_bearer_token(&req).is_some_and(|token| {
        admin::validate_bearer_token_against_secret_keys(&token, &["admin_token"]).is_ok()
    }) {
        return reply(
            StatusCode::UNAUTHORIZED,
            json!({"error": "Admin authentication required"}),
        );
    }
    if req.get_method() != Method::POST {
        return reply(
            StatusCode::METHOD_NOT_ALLOWED,
            json!({"error": "POST required"}),
        );
    }
    let mut body = Vec::new();
    if req
        .take_body()
        .take(MAX_BODY + 1)
        .read_to_end(&mut body)
        .is_err()
    {
        return reply(
            StatusCode::BAD_REQUEST,
            json!({"error": invalid().message()}),
        );
    }
    if body.len() as u64 > MAX_BODY {
        return reply(
            StatusCode::PAYLOAD_TOO_LARGE,
            json!({"error": "Bunny publication request too large"}),
        );
    }

    let result = if req.get_path() == "/admin/api/bunny-pilot/finalize" {
        crate::bunny_ready::finalize(&body)
    } else {
        parse_publication(&body).and_then(publish)
    };
    match result {
        Ok(body) => reply(StatusCode::OK, body),
        Err(error) => reply(error.status_code(), json!({"error": error.message()})),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ORIGINAL_HASH: &str = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
    const OTHER_HASH: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    #[test]
    fn accepts_exact_path_and_digest() {
        let body = format!(r#"{{"path":"/{OTHER_HASH}/720p.mp4","sha256":"{ORIGINAL_HASH}"}}"#);
        let publication = parse_publication(body.as_bytes()).unwrap();
        assert_eq!(publication.asset().unwrap().hash(), OTHER_HASH);
        assert_eq!(publication.sha256, ORIGINAL_HASH);
    }

    #[test]
    fn rejects_alias_unknown_field_and_mismatched_original_digest() {
        for body in [
            format!(r#"{{"path":"/{ORIGINAL_HASH}.mp4","sha256":"{ORIGINAL_HASH}"}}"#),
            format!(r#"{{"path":"/{ORIGINAL_HASH}","sha256":"{ORIGINAL_HASH}","extra":true}}"#),
            format!(r#"{{"path":"/{ORIGINAL_HASH}","sha256":"{OTHER_HASH}"}}"#),
            format!(
                r#"{{"path":"/{OTHER_HASH}/720p.mp4","sha256":"{}"}}"#,
                ORIGINAL_HASH.to_uppercase()
            ),
        ] {
            assert!(matches!(
                parse_publication(body.as_bytes()),
                Err(BlossomError::BadRequest(_))
            ));
        }
    }

    #[test]
    #[ignore = "requires loopback policy/B2/CDN backends; scripts/run-bunny-pilot-publication-tests.py"]
    fn bunny_publication_respects_authoritative_policy_and_releases_clean_attempts() {
        let case = storage::get_config("bunny_fixture_case").unwrap();
        let rendition = case == "active_rendition";
        let path = if rendition {
            format!("/{ORIGINAL_HASH}/720p.mp4")
        } else {
            format!("/{ORIGINAL_HASH}")
        };
        let token = if case == "webhook_token" {
            "fixture-webhook"
        } else {
            "fixture-admin"
        };
        let publish = || {
            let mut request =
                Request::post("https://media.divine.video/admin/api/bunny-pilot/publish")
                    .with_header("Authorization", format!("Bearer {token}"));
            request.set_body(json!({"path": path, "sha256": ORIGINAL_HASH}).to_string());
            let response = crate::request_bindings::metered(request);
            assert_eq!(
                response.get_header_str("Cache-Control"),
                Some("private, no-store")
            );
            response
        };

        let expected = match case.as_str() {
            "active" | "active_rendition" | "appeal" => StatusCode::OK,
            "webhook_token" => StatusCode::UNAUTHORIZED,
            "checksum_mismatch" => StatusCode::CONFLICT,
            "unverified_retry"
            | "rejected_put"
            | "uncertain_put"
            | "wrong_writer_scope"
            | "wrong_worker_primary"
            | "lost_worker_reply"
            | "invalid_worker_evidence" => StatusCode::BAD_GATEWAY,
            "pending" | "age_restricted" | "age_gate_after_put" | "disabled" => {
                StatusCode::NOT_FOUND
            }
            _ => panic!("unrecognized test case"),
        };
        if case == "appeal" {
            metadata::open_store()
                .unwrap()
                .insert(
                    &format!("blob:{ORIGINAL_HASH}"),
                    json!({"sha256": ORIGINAL_HASH, "type": "video/mp4", "size": 3,
                           "owner": "b".repeat(64), "status": "active", "uploaded": "2026-01-01T00:00:00Z"})
                    .to_string(),
                )
                .unwrap();
        }
        let mut response = publish();
        assert_eq!(
            response.get_status(),
            expected,
            "{}",
            response.take_body_str()
        );
        if matches!(case.as_str(), "unverified_retry" | "age_gate_after_put") {
            let store = metadata::open_store().unwrap();
            let mut entry = store
                .lookup(&format!("b2-sync:v1:{ORIGINAL_HASH}"))
                .unwrap();
            assert_eq!(
                parent_gate::parse(&entry.take_body().into_bytes()),
                Some(parent_gate::Gate::Copying {
                    attempt_id: format!("bunny-cleanup-{ORIGINAL_HASH}")
                }),
            );
            let attempts = if case == "unverified_retry" { 2 } else { 1 };
            for i in 1..=attempts {
                let request =
                    Request::post("https://media.divine.video/admin/api/b2-cdn-purge/drain?max=1")
                        .with_header("Authorization", "Bearer fixture-admin");
                let mut retry = crate::request_bindings::metered(request);
                assert_eq!(retry.get_status(), StatusCode::OK);
                let reply: Value = serde_json::from_str(&retry.take_body_str()).unwrap();
                assert_eq!(reply["result"], u8::from(i == attempts));
            }
        }
        if expected == StatusCode::OK {
            assert_eq!(response.take_body_str(), r#"{"result":"published"}"#);
            if case == "appeal" {
                let moderate = |action, status: &str| {
                    // Viceroy's in-memory KV store and the mock Fastly API use
                    // separate stores. Reflect the expected committed status in
                    // the mock API before the actual moderation's inline purge.
                    let simulated = Request::post("http://fixture.invalid/fixture/policy-status")
                        .with_body(status)
                        .send("fixture_control")
                        .unwrap();
                    assert_eq!(simulated.get_status(), StatusCode::OK);
                    let request = Request::post("https://media.divine.video/admin/api/moderate")
                        .with_header("Authorization", "Bearer fixture-admin")
                        .with_body(json!({"sha256": ORIGINAL_HASH, "action": action}).to_string());
                    let mut response = crate::request_bindings::metered(request);
                    assert_eq!(response.get_status(), StatusCode::OK);
                    let body: Value = serde_json::from_str(&response.take_body_str()).unwrap();
                    assert_eq!(body["new_status"], status);
                    assert_eq!(
                        metadata::get_blob_metadata_uncached(ORIGINAL_HASH)
                            .unwrap()
                            .unwrap()
                            .status
                            .as_api_str(),
                        status
                    );
                };
                moderate("AGE_RESTRICT", "age_restricted");
                assert_eq!(publish().get_status(), StatusCode::NOT_FOUND);
                moderate("APPROVE", "active");
                let mut reverted = publish();
                assert_eq!(reverted.get_status(), StatusCode::OK);
                assert_eq!(reverted.take_body_str(), r#"{"result":"published"}"#);

                let mut drained = 0;
                for _ in 0..2 {
                    let request = Request::post(
                        "https://media.divine.video/admin/api/b2-cdn-purge/drain?max=1",
                    )
                    .with_header("Authorization", "Bearer fixture-admin");
                    let mut response = crate::request_bindings::metered(request);
                    assert_eq!(response.get_status(), StatusCode::OK);
                    let body: Value = serde_json::from_str(&response.take_body_str()).unwrap();
                    assert_eq!(body["errors"], 0);
                    drained += body["result"].as_u64().unwrap();
                }
                assert!(drained > 0, "expected an old moderation intent to drain");
            }
            let mut retry = publish();
            assert_eq!(retry.get_status(), StatusCode::OK);
            assert_eq!(retry.take_body_str(), r#"{"result":"already_published"}"#);
        }

        let store = metadata::open_store().unwrap();
        let gate = store.lookup(&format!("b2-sync:v1:{ORIGINAL_HASH}"));
        if matches!(case.as_str(), "disabled" | "webhook_token") {
            assert!(matches!(
                gate,
                Err(fastly::kv_store::KVStoreError::ItemNotFound)
            ));
        } else if matches!(
            case.as_str(),
            "uncertain_put" | "lost_worker_reply" | "invalid_worker_evidence"
        ) {
            let mut gate = gate.unwrap();
            let Some(parent_gate::Gate::Copying { attempt_id }) =
                parent_gate::parse(&gate.take_body().into_bytes())
            else {
                panic!("uncertain writer must retain exclusion");
            };
            assert_eq!(attempt_id.len(), 32);
            assert!(attempt_id.bytes().all(|byte| byte.is_ascii_hexdigit()));
        } else {
            let mut gate = gate.unwrap();
            assert!(matches!(
                parent_gate::parse(&gate.take_body().into_bytes()),
                Some(parent_gate::Gate::Released { .. })
            ));
        }
    }
}
