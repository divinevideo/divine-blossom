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
    let denied = || BlossomError::NotFound("Blob not found".into());
    let metadata = get_blob_metadata_uncached(hash)?.ok_or_else(denied)?;
    if metadata.sha256 != hash
        || metadata.status != BlobStatus::Active
        || !metadata.mime_type.starts_with("video/")
        || metadata.owner.len() != 64
        || !metadata.owner.bytes().all(|b| b.is_ascii_hexdigit())
        || get_tombstone(hash)?.is_some()
        || exists(&format!("b2-sync:v1:{hash}"))?
    {
        return Err(denied());
    }
    let mut uploaders = get_blob_refs(hash)?;
    uploaders.push(metadata.owner.clone());
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
pub(crate) fn unavailable() -> Response {
    let mut response = Response::from_status(fastly::http::StatusCode::SERVICE_UNAVAILABLE);
    response.set_header("Retry-After", "30");
    no_store(&mut response);
    crate::add_cors_headers(&mut response);
    response
}
pub(crate) fn handle(req: Request) -> Result<Response> {
    let hash = canary::original_hash(req.get_method_str(), req.get_path())
        .ok_or_else(|| BlossomError::NotFound("Not found".into()))?;
    let metadata = approved_metadata(&hash)?;
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
    let bucket = crate::storage::get_config("b2_media_bucket")?;
    if !ready.matches(&hash, &bucket, metadata.size) {
        return Ok(unavailable());
    }
    let response = crate::storage::download_canary_original(
        &ready,
        req.get_method(),
        req.get_header_str("Range"),
    )?;
    // A revocation during origin I/O wins over the fetched body.
    let current = approved_metadata(&hash)?;
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
