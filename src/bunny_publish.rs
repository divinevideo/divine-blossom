//! Publish verified, anonymous public media to the private Bunny origin prefix.
use crate::blossom::BlobMetadata;
use crate::error::{BlossomError, Result};
use crate::{admin, canary, metadata, parent_gate, storage};
use blossom_core::bunny_pilot::Asset;
use fastly::http::{Method, StatusCode};
use fastly::{Request, Response};
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::io::Read;

const MAX_BODY: u64 = 1024;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PublishBody<'a> {
    path: &'a str,
    sha256: &'a str,
}

struct Publication<'a> {
    asset: Asset<'a>,
    sha256: &'a str,
}

fn invalid() -> BlossomError {
    BlossomError::BadRequest("Invalid Bunny publication request".into())
}

fn parse_publication(body: &[u8]) -> Result<Publication<'_>> {
    let PublishBody { path, sha256 } = serde_json::from_slice(body).map_err(|_| invalid())?;
    let asset = Asset::parse(path).ok_or_else(invalid)?;
    if sha256.len() != 64
        || !sha256
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        || (asset.is_original() && sha256 != asset.hash())
    {
        return Err(invalid());
    }
    Ok(Publication { asset, sha256 })
}

fn verified_bytes(bytes: &[u8], sha256: &str) -> bool {
    !bytes.is_empty() && hex::encode(Sha256::digest(bytes)) == sha256
}

fn existing_matches(bytes: Option<&[u8]>, sha256: &str) -> Result<bool> {
    match bytes {
        None => Ok(false),
        Some(bytes) if verified_bytes(bytes, sha256) => Ok(true),
        Some(_) => Err(BlossomError::Conflict(
            "Bunny publication would replace different bytes".into(),
        )),
    }
}

fn verify_public_metadata(asset: &Asset<'_>, source_len: u64) -> Result<()> {
    let BlobMetadata {
        mime_type, size, ..
    } = metadata::bunny_public_metadata(asset.hash())?;
    if asset.is_original() && (mime_type != "video/mp4" || size != source_len) {
        return Err(BlossomError::NotFound(
            "Bunny publication unavailable".into(),
        ));
    }
    Ok(())
}

fn publish(Publication { asset, sha256 }: Publication<'_>) -> Result<&'static str> {
    storage::validate_bunny_pilot_publication()?;
    let mut random = [0; 16];
    getrandom::getrandom(&mut random)
        .map_err(|_| BlossomError::Internal("Bunny publication attempt unavailable".into()))?;
    let hash = asset.hash();
    let attempt = format!("bunny-pilot-{}", hex::encode(random));
    let generation = parent_gate::archive_claim(hash, &attempt)?;
    let check_gate = || parent_gate::check_bunny_gate(hash, &attempt, &generation);
    let mut may_release = true;

    let result = (|| {
        let source = storage::read_bunny_pilot_asset(&asset.source_key())?
            .ok_or_else(|| BlossomError::NotFound("Bunny publication source unavailable".into()))?;
        if !verified_bytes(&source, sha256) {
            return Err(BlossomError::Conflict(
                "Bunny publication source digest changed".into(),
            ));
        }
        let source_len = source.len() as u64;
        let delivery_key = asset.delivery_key();
        let already_published = existing_matches(
            storage::read_bunny_pilot_asset(&delivery_key)?.as_deref(),
            sha256,
        )?;
        let readback = if already_published {
            check_gate()?;
            verify_public_metadata(&asset, source_len)?;
            Ok(())
        } else {
            storage::put_bunny_pilot_asset(&delivery_key, source, sha256, || {
                storage::validate_bunny_pilot_publication()?;
                check_gate()?;
                verify_public_metadata(&asset, source_len)?;
                // Erasure must wait while an interrupted PUT could still land.
                may_release = false;
                Ok(())
            })?;
            storage::read_bunny_pilot_asset(&delivery_key).and_then(|copy| {
                if copy.is_some_and(|bytes| verified_bytes(&bytes, sha256)) {
                    Ok(())
                } else {
                    Err(BlossomError::StorageError(
                        "Bunny publication readback unverified".into(),
                    ))
                }
            })
        };

        let verified = check_gate()
            .and_then(|_| verify_public_metadata(&asset, source_len))
            .and(readback);
        if let Err(error) = verified {
            may_release = false;
            let cleanup = storage::remove_bunny_delivery_copies(hash, &check_gate)
                .and_then(|_| storage::purge_bunny_pilot_hosts(&[hash.to_owned()]));
            if let Err(cleanup_error) = cleanup {
                parent_gate::handoff_bunny_cleanup(hash, &generation)?;
                return Err(cleanup_error);
            }
            may_release = true;
            return Err(error);
        }
        may_release = true;
        Ok(if already_published {
            "already_published"
        } else {
            "published"
        })
    })();

    if may_release {
        parent_gate::archive_release(hash, &attempt, &generation)?;
    }
    result
}

fn reply(status: StatusCode, body: Value) -> Response {
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

    match parse_publication(&body).and_then(publish) {
        Ok(result) => reply(StatusCode::OK, json!({"result": result})),
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
        assert_eq!(publication.asset.hash(), OTHER_HASH);
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
    fn requires_the_verified_digest_and_only_reuses_identical_objects() {
        assert!(verified_bytes(b"abc", ORIGINAL_HASH));
        assert!(!verified_bytes(b"modified", ORIGINAL_HASH));
        assert!(!verified_bytes(b"", ORIGINAL_HASH));
        assert!(!existing_matches(None, ORIGINAL_HASH).unwrap());
        assert!(existing_matches(Some(b"abc"), ORIGINAL_HASH).unwrap());
        assert!(matches!(
            existing_matches(Some(b"modified"), ORIGINAL_HASH),
            Err(BlossomError::Conflict(_))
        ));
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
            let response = crate::route_request(request).unwrap();
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
            "unverified_retry" => StatusCode::BAD_GATEWAY,
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
        if case == "unverified_retry" {
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
            let request =
                Request::post("https://media.divine.video/admin/api/b2-cdn-purge/drain?max=1")
                    .with_header("Authorization", "Bearer fixture-admin");
            let mut retry = crate::route_request(request).unwrap();
            assert_eq!(retry.get_status(), StatusCode::OK);
            let reply: Value = serde_json::from_str(&retry.take_body_str()).unwrap();
            assert_eq!(reply["result"], 1);
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
                    let mut response = crate::route_request(request).unwrap();
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
                    let mut response = crate::route_request(request).unwrap();
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
        } else {
            let mut gate = gate.unwrap();
            assert!(matches!(
                parent_gate::parse(&gate.take_body().into_bytes()),
                Some(parent_gate::Gate::Released { .. })
            ));
        }
    }
}
