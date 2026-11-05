//! Default-off private B2 playback. No upload or admin routes.
use crate::blossom::{BlobMetadata, BlobStatus};
use crate::error::{BlossomError, Result};
use crate::metadata::{get_blob_metadata_uncached, get_blob_refs, get_tombstone, open_store};
use blossom_core::canary::{self, CanaryRoute, Readiness};
use fastly::kv_store::KVStoreError;
use fastly::{Request, Response};

pub(crate) fn route(req: &Request) -> CanaryRoute {
    let configured = crate::storage::get_config("b2_canary_host").ok();
    let authority = req.get_url().host_str().unwrap_or("");
    let host = req.get_header_str("Host").unwrap_or(authority);
    let route = canary::route(
        configured.as_deref(),
        host,
        req.get_header_str("X-Original-Host"),
    );
    if route == CanaryRoute::Canary && (authority != host || req.get_url().port().is_some()) {
        return CanaryRoute::Denied;
    }
    route
}
pub(crate) fn no_store(response: &mut Response) {
    response.set_header("Cache-Control", "private, no-store");
    response.set_header("Surrogate-Control", "no-store");
    response.set_header("Pragma", "no-cache");
}
fn exists(key: &str) -> Result<bool> {
    match open_store()?.lookup(key) {
        Ok(_) => Ok(true),
        Err(KVStoreError::ItemNotFound) => Ok(false),
        Err(_) => Err(BlossomError::MetadataError(
            "Canary policy lookup unavailable".into(),
        )),
    }
}
fn approved_metadata(hash: &str) -> Result<BlobMetadata> {
    approved_metadata_with_limit(hash, false)
}
fn approved_metadata_with_limit(hash: &str, bounded: bool) -> Result<BlobMetadata> {
    let denied = || BlossomError::NotFound("Blob not found".into());
    let metadata = get_blob_metadata_uncached(hash)?.ok_or_else(denied)?;
    if metadata.sha256 != hash
        || metadata.status != BlobStatus::Active
        || !metadata.quarantine_hold_ids.is_empty()
        || !metadata.mime_type.starts_with("video/")
        || metadata.owner.len() != 64
        || !metadata.owner.bytes().all(|b| b.is_ascii_hexdigit())
        || get_tombstone(hash)?.is_some()
    {
        return Err(denied());
    }
    let mut uploaders = get_blob_refs(hash)?;
    if bounded && (metadata.size == 0 || uploaders.len() > canary::MAX_DEMAND_REFERENCES) {
        return Err(denied());
    }
    uploaders.push(metadata.owner.clone());
    uploaders.sort_unstable();
    uploaders.dedup();
    for uploader in uploaders {
        if uploader.len() != 64
            || !uploader.bytes().all(|b| b.is_ascii_hexdigit())
            || exists(&format!(
                "vanish_in_progress:v1:{}",
                uploader.to_lowercase()
            ))?
        {
            return Err(denied());
        }
    }
    Ok(metadata)
}
/// Known copy intent means temporary unavailability, after policy is approved.
/// Erasing or malformed intent remains a terminal denial.
fn copy_in_progress(hash: &str) -> Result<bool> {
    let mut lookup = match open_store()?.lookup(&format!("b2-sync:v1:{hash}")) {
        Ok(lookup) => lookup,
        Err(KVStoreError::ItemNotFound) => return Ok(false),
        Err(_) => {
            return Err(BlossomError::MetadataError(
                "Canary copy intent unavailable".into(),
            ))
        }
    };
    let denied = || BlossomError::NotFound("Blob not found".into());
    let gate: serde_json::Value =
        serde_json::from_str(&lookup.take_body().into_string()).map_err(|_| denied())?;
    if gate.get("state").and_then(serde_json::Value::as_str) == Some("copying")
        && gate
            .get("attempt_id")
            .and_then(serde_json::Value::as_str)
            .is_some_and(|id| !id.is_empty() && id.len() <= 128)
    {
        Ok(true)
    } else {
        Err(denied())
    }
}

pub(crate) fn unavailable() -> Response {
    let mut response = Response::from_status(fastly::http::StatusCode::SERVICE_UNAVAILABLE);
    response.set_header("Retry-After", "30");
    no_store(&mut response);
    crate::add_cors_headers(&mut response);
    response
}
pub(crate) fn handle(req: Request) -> Result<Response> {
    if crate::storage::get_config("b2_demand_mirror_enabled").is_ok_and(|v| v == "true") {
        return handle_demand(
            req,
            crate::storage::download_demand_b2,
            crate::storage::download_demand_gcs,
        );
    }
    handle_with_origin(req, crate::storage::download_canary_original)
}

fn recheck_demand(hash: &str, metadata: &BlobMetadata) -> Result<bool> {
    let current = approved_metadata_with_limit(hash, true)?;
    let copying = copy_in_progress(hash)?;
    if current.size != metadata.size || current.mime_type != metadata.mime_type {
        return Err(BlossomError::NotFound("Blob not found".into()));
    }
    Ok(copying)
}

fn demand_headers(
    mut response: Response,
    hash: &str,
    metadata: &BlobMetadata,
    source: &str,
) -> Response {
    eprintln!("b2-demand source={source}");
    response.set_header("Content-Type", &metadata.mime_type);
    response.set_header("X-Sha256", hash);
    response.set_header("X-Content-Length", metadata.size.to_string());
    response.set_header("X-Divine-Source", source);
    response.set_header("X-Divine-Storage-Cache", "BYPASS");
    response.set_header("Accept-Ranges", "bytes");
    crate::add_cors_headers(&mut response);
    no_store(&mut response);
    response
}

/// Add-only coalescing is best effort, but waits are finite and never detached.
#[allow(deprecated)]
fn insert_demand_hint(hash: &str, observed: Option<&str>, deadline: std::time::Instant) {
    use fastly::kv_store::InsertMode;
    let insert = || -> std::result::Result<(), &'static str> {
        let hint = canary::DemandHint::new(hash, observed).ok_or("invalid")?;
        let payload = serde_json::to_string(&hint).map_err(|_| "invalid")?;
        if payload.len() > 2048 || std::time::Instant::now() >= deadline {
            return Err("budget");
        }
        let store = open_store().map_err(|_| "unavailable")?;
        let pending = store
            .build_insert()
            .mode(InsertMode::Add)
            .execute_async(&format!("b2-demand:v1:{hash}"), payload)
            .map_err(|_| "unavailable")?;
        crate::storage::wait_for_demand_io(pending.as_u32(), deadline).map_err(|_| "budget")?;
        match store.pending_insert_wait(pending) {
            Ok(()) => {
                eprintln!("b2-demand hint=inserted");
                Ok(())
            }
            Err(KVStoreError::ItemPreconditionFailed) => {
                eprintln!("b2-demand hint=coalesced");
                Ok(())
            }
            Err(_) => Err("unavailable"),
        }
    };
    if let Err(reason) = insert() {
        eprintln!("b2-demand hint=failed reason={reason}");
    }
}

fn handle_demand(
    req: Request,
    fetch_b2: impl FnOnce(
        &Readiness,
        &fastly::http::Method,
        Option<&str>,
        std::time::Instant,
    ) -> Result<crate::storage::CanaryOrigin>,
    fetch_gcs: impl FnOnce(
        &str,
        u64,
        &fastly::http::Method,
        Option<&str>,
        std::time::Instant,
    ) -> Result<crate::storage::CanaryOrigin>,
) -> Result<Response> {
    use crate::storage::CanaryOrigin;
    use std::time::{Duration, Instant};
    let deadline = Instant::now() + crate::storage::DEMAND_IO_BUDGET;
    let hash = canary::original_hash(req.get_method_str(), req.get_path())
        .ok_or_else(|| BlossomError::NotFound("Not found".into()))?;
    let metadata = approved_metadata_with_limit(&hash, true)?;
    let copying = copy_in_progress(&hash)?;
    let eligible = metadata.size <= canary::MAX_DEMAND_BYTES;
    let range = if *req.get_method() == fastly::http::Method::HEAD {
        None
    } else {
        canary::single_range(req.get_header_str("Range"))
    };
    let mut hint: Option<Option<String>> = None;
    let mut copying_seen = copying;
    if copying {
        eprintln!("b2-demand fallback=copying");
    } else if !eligible {
        eprintln!("b2-demand fallback=oversized");
    }
    if !copying && eligible {
        let store = open_store()?;
        let ready = match store.lookup(&format!("b2-ready:{hash}")) {
            Ok(mut lookup) => {
                let body = lookup.take_body().into_string();
                if body.len() > 8192 {
                    return Err(BlossomError::StorageError(
                        "Demand readiness invalid".into(),
                    ));
                }
                let ready: Readiness = serde_json::from_str(&body)
                    .map_err(|_| BlossomError::StorageError("Demand readiness invalid".into()))?;
                let bucket = crate::storage::get_config("b2_media_bucket").map_err(|_| {
                    BlossomError::StorageError("B2 demand configuration unavailable".into())
                })?;
                if !ready.matches(&hash, &bucket, metadata.size) {
                    eprintln!("b2-demand readiness=invalid");
                    return Err(BlossomError::StorageError(
                        "Demand readiness invalid".into(),
                    ));
                }
                Some(ready)
            }
            Err(KVStoreError::ItemNotFound) => {
                eprintln!("b2-demand fallback=missing_readiness");
                hint = Some(None);
                None
            }
            Err(_) => return Ok(unavailable()),
        };
        if let Some(ready) = ready {
            let outcome = fetch_b2(&ready, req.get_method(), range, deadline);
            // Recheck even on errors: denial always beats availability/config.
            copying_seen |= recheck_demand(&hash, &metadata)?;
            match outcome? {
                CanaryOrigin::Delivered(response) if !copying_seen => {
                    return Ok(demand_headers(response, &hash, &metadata, "b2"))
                }
                CanaryOrigin::Missing => {
                    hint = Some(Some(ready.destination_version_id));
                    eprintln!("b2-demand fallback=missing_version");
                }
                CanaryOrigin::Unavailable => eprintln!("b2-demand fallback=unavailable"),
                CanaryOrigin::Delivered(_) => {}
            }
        }
    }
    let outcome = fetch_gcs(&hash, metadata.size, req.get_method(), range, deadline);
    copying_seen |= recheck_demand(&hash, &metadata)?;
    match outcome? {
        CanaryOrigin::Delivered(response) => {
            if response.get_status().is_success() && eligible && !copying_seen {
                if let Some(observed) = hint {
                    insert_demand_hint(
                        &hash,
                        observed.as_deref(),
                        (Instant::now() + Duration::from_millis(50)).min(deadline),
                    );
                }
            }
            Ok(demand_headers(response, &hash, &metadata, "gcs"))
        }
        CanaryOrigin::Missing => Err(BlossomError::NotFound("Blob not found".into())),
        CanaryOrigin::Unavailable => Ok(unavailable()),
    }
}

fn handle_with_origin(
    req: Request,
    fetch: impl FnOnce(&Readiness, &fastly::http::Method, Option<&str>) -> Result<Response>,
) -> Result<Response> {
    let hash = canary::original_hash(req.get_method_str(), req.get_path())
        .ok_or_else(|| BlossomError::NotFound("Not found".into()))?;
    let metadata = approved_metadata(&hash)?;
    if copy_in_progress(&hash)? {
        return Ok(unavailable());
    }
    let mut lookup = match open_store()?.lookup(&format!("b2-ready:{hash}")) {
        Ok(lookup) => lookup,
        Err(KVStoreError::ItemNotFound) => return Ok(unavailable()),
        Err(_) => {
            return Err(BlossomError::MetadataError(
                "Canary readiness unavailable".into(),
            ))
        }
    };
    let ready: Readiness = match serde_json::from_str(&lookup.take_body().into_string()) {
        Ok(ready) => ready,
        Err(_) => return Ok(unavailable()),
    };
    let bucket = crate::storage::get_config("b2_media_bucket")
        .map_err(|_| BlossomError::StorageError("B2 canary configuration unavailable".into()))?;
    if !ready.matches(&hash, &bucket, metadata.size) {
        return Ok(unavailable());
    }
    let response = fetch(&ready, req.get_method(), req.get_header_str("Range"))?;
    // A revocation during origin I/O wins over the fetched body.
    let current = approved_metadata(&hash)?;
    if copy_in_progress(&hash)? {
        return Ok(unavailable());
    }
    if current.size != metadata.size || current.mime_type != metadata.mime_type {
        return Err(BlossomError::NotFound("Blob not found".into()));
    }
    let mut response = response;
    if response.get_status() == fastly::http::StatusCode::SERVICE_UNAVAILABLE {
        return Ok(response);
    }
    response.set_header("Content-Type", &current.mime_type);
    response.set_header("X-Sha256", &hash);
    response.set_header("X-Content-Length", current.size.to_string());
    response.set_header("X-Divine-Source", "b2");
    response.set_header("X-Divine-Storage-Cache", "BYPASS");
    response.set_header("Accept-Ranges", "bytes");
    crate::add_cors_headers(&mut response);
    no_store(&mut response);
    Ok(response)
}

#[cfg(test)]
mod tests {
    use crate::handle_main;
    use fastly::{http::StatusCode, Request};
    #[test]
    #[ignore = "requires demand fixtures; scripts/run-b2-canary-tests.py"]
    fn demand_exhausted_deadline_starts_no_origin_request() {
        let result = crate::storage::download_demand_gcs(
            &"a".repeat(64),
            9,
            &fastly::http::Method::GET,
            None,
            std::time::Instant::now(),
        )
        .unwrap();
        assert!(matches!(result, crate::storage::CanaryOrigin::Unavailable));
    }
    #[test]
    #[ignore = "requires demand fixtures; scripts/run-b2-canary-tests.py"]
    fn demand_revocation_after_each_origin_is_terminal() {
        let hash = "a".repeat(64);
        let config = fastly::config_store::ConfigStore::open("blossom_config");
        let phase = config.get("test_revoke_phase").unwrap();
        let change = config.get("test_revoke_change").unwrap();
        let revoke = || {
            let store = crate::metadata::open_store().unwrap();
            let mut metadata = crate::metadata::get_blob_metadata_uncached(&hash)
                .unwrap()
                .unwrap();
            match change.as_str() {
                "restricted" => metadata.status = crate::blossom::BlobStatus::Restricted,
                "size" => metadata.size += 1,
                "type" => metadata.mime_type = "video/webm".into(),
                "quarantine" => {
                    store
                        .insert(
                            &format!("quarantine:v1:{hash}"),
                            r#"{"version":1,"holds":{"race":{"version":1,"active":true}}}"#,
                        )
                        .unwrap();
                }
                "vanish" => {
                    store
                        .insert(&format!("vanish_in_progress:v1:{}", metadata.owner), "{}")
                        .unwrap();
                }
                "erasing" | "malformed_gate" | "copying" => {
                    let gate = match change.as_str() {
                        "copying" => r#"{"state":"copying","attempt_id":"race"}"#,
                        "erasing" => r#"{"state":"erasing"}"#,
                        _ => r#"{"state":"copying"}"#,
                    };
                    store.insert(&format!("b2-sync:v1:{hash}"), gate).unwrap();
                }
                _ => panic!("unknown revocation fixture"),
            }
            store
                .insert(
                    &format!("blob:{hash}"),
                    serde_json::to_string(&metadata).unwrap(),
                )
                .unwrap();
        };
        let result = super::handle_demand(
            Request::get(format!("https://media-b2.divine.video/{hash}")),
            |ready, method, range, deadline| {
                let outcome = crate::storage::download_demand_b2(ready, method, range, deadline);
                if phase == "b2" {
                    revoke();
                }
                outcome
            },
            |hash, size, method, range, deadline| {
                let outcome =
                    crate::storage::download_demand_gcs(hash, size, method, range, deadline);
                if phase == "gcs" {
                    revoke();
                }
                outcome
            },
        );
        if change == "copying" {
            assert_eq!(
                result.unwrap().get_header_str("X-Divine-Source"),
                Some("gcs")
            );
        } else {
            assert_eq!(
                result
                    .expect_err("revocation must discard origin bytes")
                    .status_code()
                    .as_u16(),
                404
            );
        }
        assert!(crate::metadata::open_store()
            .unwrap()
            .lookup(&format!("b2-demand:v1:{hash}"))
            .is_err());
    }
    #[test]
    #[ignore = "requires demand fixtures; scripts/run-b2-canary-tests.py"]
    fn demand_endpoint_contract() {
        use fastly::config_store::ConfigStore;
        let config = ConfigStore::open("blossom_config");
        let expected = config
            .get("test_expected_status")
            .unwrap()
            .parse::<u16>()
            .unwrap();
        let method = config.get("test_method").unwrap_or_else(|| "GET".into());
        let mut request = Request::new(
            method,
            format!("https://media-b2.divine.video/{}", "a".repeat(64)),
        );
        if let Some(range) = config.get("test_range") {
            request.set_header("Range", range);
        }
        let mut response = handle_main(request).unwrap();
        assert_eq!(response.get_status().as_u16(), expected);
        assert_eq!(
            response.get_header_str("Cache-Control"),
            Some("private, no-store")
        );
        assert_eq!(
            response.get_header_str("Surrogate-Control"),
            Some("no-store")
        );
        if expected == 200 || expected == 206 {
            assert_eq!(
                response.get_header_str("X-Divine-Source"),
                config.get("test_source").as_deref()
            );
            assert_eq!(
                response.get_header_str("X-Divine-Storage-Cache"),
                Some("BYPASS")
            );
            assert_eq!(
                response.take_body().into_string(),
                config.get("test_body").unwrap()
            );
        } else if expected == 416 {
            assert_eq!(response.get_header_str("Content-Range"), Some("bytes */9"));
            assert_eq!(response.get_header_str("Content-Length"), Some("0"));
            assert_eq!(response.take_body().into_string(), "");
        }
        let hint = crate::metadata::open_store()
            .unwrap()
            .lookup(&format!("b2-demand:v1:{}", "a".repeat(64)));
        if let Some(reason) = config.get("test_hint") {
            let mut hint = hint.expect("successful GCS delivery must queue demand");
            let value: serde_json::Value =
                serde_json::from_str(&hint.take_body().into_string()).unwrap();
            assert_eq!(value["version"], 1);
            assert_eq!(value["sha256"], "a".repeat(64));
            assert_eq!(value["reason"], reason);
            if reason == "missing_version" {
                assert_eq!(
                    value["observed_destination_version_id"],
                    "4_zSynthetic+version"
                );
            }
        } else {
            assert!(hint.is_err(), "must not queue hint");
        }
    }
    #[test]
    fn disabled_canary_denies_reads_writes_and_admin_without_storage_access() {
        for (method, path) in [
            ("GET", format!("/{}", "a".repeat(64))),
            ("PUT", "/upload".into()),
            ("GET", "/admin".into()),
            ("HEAD", "/upload".into()),
        ] {
            let response = handle_main(Request::new(
                method,
                format!("https://media-b2.divine.video{path}"),
            ))
            .unwrap();
            assert_eq!(response.get_status(), StatusCode::NOT_FOUND);
            assert_eq!(
                response.get_header_str("Surrogate-Control"),
                Some("no-store")
            );
            assert_eq!(
                response.get_header_str("Cache-Control"),
                Some("private, no-store")
            );
        }
    }
    #[test]
    #[ignore = "requires synthetic B2 outage fixtures; scripts/run-b2-canary-tests.py"]
    fn canary_origin_outage_during_revocation_is_terminal() {
        let hash = "a".repeat(64);
        let request = Request::get(format!("https://media-b2.divine.video/{hash}"));
        let result = super::handle_with_origin(request, |ready, method, range| {
            // The real origin produces an outage response. Revoke permission at
            // this I/O boundary before the handler can decide to allow fallback.
            let response = crate::storage::download_canary_original(ready, method, range)?;
            assert_eq!(response.get_status(), StatusCode::SERVICE_UNAVAILABLE);
            let mut meta = crate::metadata::get_blob_metadata_uncached(&hash)?.unwrap();
            meta.status = crate::blossom::BlobStatus::Restricted;
            crate::metadata::open_store()?
                .insert(
                    &format!("blob:{hash}"),
                    serde_json::to_string(&meta).unwrap(),
                )
                .unwrap();
            Ok(response)
        });
        assert_eq!(
            result
                .expect_err("revocation must prevent canonical fallback")
                .status_code()
                .as_u16(),
            404
        );
    }

    #[test]
    #[ignore = "requires synthetic Viceroy fixtures; scripts/run-b2-canary-tests.py"]
    fn canary_revocation_bypasses_warm_metadata_and_readiness() {
        let hash = "a".repeat(64);
        let store = crate::metadata::open_store().unwrap();
        let mut meta = crate::metadata::get_blob_metadata(&hash).unwrap().unwrap();
        let request = || Request::get(format!("https://media-b2.divine.video/{hash}"));
        assert_eq!(handle_main(request()).unwrap().get_status(), StatusCode::OK);
        let mut ready = store.lookup(&format!("b2-ready:{hash}")).unwrap();
        let ready = ready.take_body().into_string();
        store.delete(&format!("b2-ready:{hash}")).unwrap();
        assert_eq!(
            handle_main(request()).unwrap().get_status(),
            StatusCode::SERVICE_UNAVAILABLE
        );
        store.insert(&format!("b2-ready:{hash}"), ready).unwrap();
        meta.status = crate::blossom::BlobStatus::Restricted;
        store
            .insert(
                &format!("blob:{hash}"),
                serde_json::to_string(&meta).unwrap(),
            )
            .unwrap();
        assert_eq!(
            handle_main(request()).unwrap().get_status(),
            StatusCode::NOT_FOUND
        );
        assert_eq!(
            crate::metadata::get_blob_metadata(&hash)
                .unwrap()
                .unwrap()
                .status,
            crate::blossom::BlobStatus::Active
        );
        meta.status = crate::blossom::BlobStatus::Active;
        store
            .insert(
                &format!("blob:{hash}"),
                serde_json::to_string(&meta).unwrap(),
            )
            .unwrap();
        store.insert(&format!("tombstone:{hash}"), "{}").unwrap();
        assert_eq!(
            handle_main(request()).unwrap().get_status(),
            StatusCode::NOT_FOUND
        );
    }
    #[test]
    #[ignore = "requires synthetic Viceroy fixtures; scripts/run-b2-canary-tests.py"]
    fn canary_endpoint_integration_contract() {
        let mut response = handle_main(Request::get(format!(
            "https://media-b2.divine.video/{}",
            "a".repeat(64)
        )))
        .unwrap();
        let expected = fastly::config_store::ConfigStore::open("blossom_config")
            .get("test_expected_status")
            .unwrap()
            .parse::<u16>()
            .unwrap();
        assert_eq!(response.get_status().as_u16(), expected);
        assert_eq!(
            response.get_header_str("Surrogate-Control"),
            Some("no-store")
        );
        if expected != 200 {
            assert_eq!(response.get_header_str("X-Divine-Source"), None);
        }
        if expected == 200 {
            assert_eq!(response.get_header_str("X-Divine-Source"), Some("b2"));
            assert_eq!(response.take_body().into_string(), "b2 bytes!");
            let mut request = Request::get(format!(
                "https://media-b2.divine.video/{}.mp4",
                "a".repeat(64)
            ));
            request.set_header("Range", "bytes=1-3");
            let mut partial = handle_main(request).unwrap();
            assert_eq!(partial.get_status(), StatusCode::PARTIAL_CONTENT);
            assert_eq!(partial.get_header_str("Content-Range"), Some("bytes 1-3/9"));
            assert_eq!(partial.get_header_str("Content-Length"), Some("3"));
            assert_eq!(partial.take_body().into_string(), "2 b");
            let mut invalid =
                Request::get(format!("https://media-b2.divine.video/{}", "a".repeat(64)));
            invalid.set_header("Range", "bytes=99-");
            let mut invalid = handle_main(invalid).unwrap();
            assert_eq!(invalid.get_status(), StatusCode::RANGE_NOT_SATISFIABLE);
            assert_eq!(invalid.get_header_str("Content-Range"), Some("bytes */9"));
            assert_eq!(invalid.get_header_str("Content-Length"), Some("0"));
            assert_eq!(invalid.take_body().into_string(), "");
            let mut head = handle_main(Request::head(format!(
                "https://media-b2.divine.video/{}",
                "a".repeat(64)
            )))
            .unwrap();
            assert_eq!(head.get_status(), StatusCode::OK);
            assert_eq!(head.get_header_str("Content-Length"), Some("9"));
            assert_eq!(head.take_body().into_string(), "");
            for (method, path) in [
                ("PUT", "/upload".to_string()),
                ("GET", "/admin".into()),
                ("GET", format!("/{}.jpg", "a".repeat(64))),
                ("GET", format!("/{}/720p", "a".repeat(64))),
                ("OPTIONS", "/upload".into()),
            ] {
                assert_eq!(
                    handle_main(Request::new(
                        method,
                        format!("https://media-b2.divine.video{path}")
                    ))
                    .unwrap()
                    .get_status(),
                    StatusCode::NOT_FOUND
                );
            }
            let mut conflict = Request::get("https://media-b2.divine.video/admin");
            conflict.set_header("X-Original-Host", "media.divine.video");
            assert_eq!(
                handle_main(conflict).unwrap().get_status(),
                StatusCode::NOT_FOUND
            );
        }
    }
    #[test]
    #[ignore = "requires synthetic Viceroy KV; scripts/run-b2-canary-tests.py"]
    fn canary_sync_erasure_mutex() {
        use fastly::kv_store::InsertMode;
        let store = crate::metadata::open_store().unwrap();
        let hash = "d".repeat(64);
        let key = format!("b2-sync:v1:{hash}");
        store
            .build_insert()
            .mode(InsertMode::Add)
            .execute(&key, r#"{"state":"copying","attempt_id":"synthetic"}"#)
            .unwrap();
        assert!(
            crate::metadata::claim_b2_erasure(&hash).is_err(),
            "live or crashed copy blocks erasure"
        );
        assert!(
            crate::storage::erase_b2_creator_replica(&hash).is_err(),
            "creator erasure must not reach B2 listing/deletion while copy may commit"
        );
        store.delete(&key).unwrap(); // Operator drained original writer.
        crate::metadata::claim_b2_erasure(&hash).unwrap();
        crate::metadata::claim_b2_erasure(&hash).unwrap();
        assert!(store
            .build_insert()
            .mode(InsertMode::Add)
            .execute(&key, r#"{"state":"copying","attempt_id":"late"}"#)
            .is_err());
    }
}
