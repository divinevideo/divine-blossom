//! Default-off private B2 playback. No upload or admin routes.
use crate::blossom::{BlobAccess, BlobMetadata};
use crate::error::{BlossomError, Result};
use crate::metadata::{get_blob_metadata_uncached, get_blob_refs, get_tombstone, open_store};
use blossom_core::canary::{self, CanaryRoute, Readiness};
use blossom_core::delivery_telemetry::{Cache, Fallback, Provider};
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
        || metadata.access_for(None, false) != BlobAccess::Allowed
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
pub(crate) fn copy_in_progress(hash: &str) -> Result<bool> {
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
    match crate::parent_gate::parse(&lookup.take_body().into_bytes()) {
        Some(crate::parent_gate::Gate::Copying { .. }) => Ok(true),
        Some(crate::parent_gate::Gate::Released { .. }) => Ok(false),
        _ => Err(denied()),
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
    // No media fetch has occurred. Native authorization is not a media origin.
    crate::delivery_telemetry::observe(Provider::None, Cache::Unknown);
    crate::delivery_telemetry::fallback(Fallback::None);
    if crate::storage::get_config("b2_demand_mirror_enabled").is_ok_and(|v| v == "true") {
        return handle_demand(
            req,
            crate::storage::download_demand_b2,
            crate::storage::download_demand_gcs,
        );
    }
    handle_with_origin(req, crate::storage::download_canary_original)
}

/// Production CDN misses always use the verified demand path. This does not
/// change the independently configured direct canary's fresh-read behavior.
pub(crate) fn handle_cdn(req: Request) -> Result<Response> {
    crate::delivery_telemetry::observe(Provider::None, Cache::Unknown);
    crate::delivery_telemetry::fallback(Fallback::None);
    handle_demand(
        req,
        crate::storage::download_demand_b2,
        crate::storage::download_demand_gcs,
    )
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
    let cache_enabled = crate::storage::b2_canary_cache_enabled();
    let cache_status = if cache_enabled {
        match response.get_header_str("X-Divine-Storage-Cache") {
            Some("HIT") => "HIT",
            Some("MISS") => "MISS",
            _ => "BYPASS",
        }
    } else {
        "BYPASS"
    };
    response.set_header("X-Divine-Storage-Cache", cache_status);
    crate::playback_cache::attach_diagnostics(&mut response, cache_enabled);
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
        crate::delivery_telemetry::fallback(Fallback::Copying);
        eprintln!("b2-demand fallback=copying");
    } else if !eligible {
        crate::delivery_telemetry::fallback(Fallback::Oversized);
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
                crate::delivery_telemetry::fallback(Fallback::MissingReadiness);
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
                    crate::delivery_telemetry::fallback(Fallback::MissingVersion);
                    eprintln!("b2-demand fallback=missing_version");
                }
                CanaryOrigin::Unavailable => {
                    crate::delivery_telemetry::fallback(Fallback::Unavailable);
                    eprintln!("b2-demand fallback=unavailable");
                }
                CanaryOrigin::Delivered(_) => {}
            }
        }
    }
    if copying_seen {
        crate::delivery_telemetry::fallback(Fallback::Copying);
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

    fn await_cache_collection(size: u64) {
        // EOF can precede the host collector publishing inferred length. Wait
        // for that storage event without retrying any playback/origin request.
        assert!(crate::playback_cache::wait_for_last_insert_completion(
            size,
            std::time::Instant::now() + std::time::Duration::from_millis(250),
        ));
    }
    #[test]
    #[ignore = "requires demand fixtures; scripts/run-b2-canary-tests.py"]
    fn demand_cached_large_contract() {
        use sha2::{Digest, Sha256};
        use std::io::Read;
        let config = fastly::config_store::ConfigStore::open("blossom_config");
        let hash = config.get("test_hash").unwrap();
        let size = config.get("test_size").unwrap().parse::<usize>().unwrap();
        let url = format!("https://media-b2.divine.video/{hash}");
        let started = std::time::Instant::now();
        let mut first = handle_main(Request::get(&url)).unwrap();
        if config.get("test_fragmented").as_deref() == Some("true") {
            assert!(
                started.elapsed() < std::time::Duration::from_secs(1),
                "headers waited for fragmented body"
            );
        }
        assert_eq!(first.get_status(), StatusCode::OK);
        assert_eq!(
            first.get_header_str("X-Divine-Storage-Cache"),
            Some("MISS"),
            "reason={:?} reads={:?} bytes={:?} cpu={:?}",
            first.get_header_str("X-Divine-Storage-Cache-Reason"),
            first.get_header_str("X-Divine-Storage-Cache-Buffer-Reads"),
            first.get_header_str("X-Divine-Storage-Cache-Buffered-Bytes"),
            first.get_header_str("X-Divine-Storage-Cache-Cpu-Ms")
        );
        assert_eq!(
            first.get_header_str("X-Divine-Storage-Cache-Reason"),
            Some("streaming_insert")
        );
        assert_eq!(
            first.get_header_str("X-Divine-Storage-Cache-Enabled"),
            Some("true")
        );
        assert!(first
            .get_header_str("X-Divine-Storage-Cache-Compute")
            .is_some());
        assert_eq!(
            first.get_header_str("X-Divine-Storage-Cache-Buffered-Bytes"),
            Some("0")
        );
        let reads = first
            .get_header_str("X-Divine-Storage-Cache-Buffer-Reads")
            .unwrap()
            .parse::<u64>()
            .unwrap();
        assert_eq!(reads, 0);
        assert_eq!(
            first.get_header_str("X-Divine-Storage-Cache-Fill-Mode"),
            Some("host-stream")
        );
        assert_eq!(
            first.get_header_str("X-Divine-Storage-Cache-Expected-Bytes"),
            Some(size.to_string().as_str())
        );
        let memory = first
            .get_header_str("X-Divine-Storage-Cache-Linear-Memory-Bytes")
            .unwrap()
            .parse::<u64>()
            .unwrap();
        assert!(
            memory <= 128 * 1024 * 1024,
            "committed linear memory exceeds platform heap envelope"
        );
        let cpu = first
            .get_header_str("X-Divine-Storage-Cache-Cpu-Ms")
            .unwrap()
            .parse::<u64>()
            .unwrap();
        // Keep the observation, but do not treat Viceroy CPU across different
        // hosts/runs as proof of production CPU-limit viability.
        println!(
            "\nCACHE_FILL size_bytes={size} cpu_ms={cpu} read_calls={reads} linear_bytes={memory}"
        );
        // Model downstream streaming, rather than allocating the complete
        // video inside the guest test consumer and growing its Vec past 32MiB.
        let mut body = first.take_body();
        let mut digest = Sha256::new();
        let mut received = 0;
        let mut chunk = vec![0; 64 * 1024];
        loop {
            let count = body.read(&mut chunk).unwrap();
            if count == 0 {
                break;
            }
            digest.update(&chunk[..count]);
            received += count;
        }
        assert_eq!(received, size);
        assert_eq!(hex::encode(digest.finalize()), hash);
        await_cache_collection(size as u64);
        let mut head = handle_main(Request::new("HEAD", &url)).unwrap();
        assert_eq!(head.get_header_str("X-Divine-Storage-Cache"), Some("HIT"));
        assert_eq!(head.take_body().into_string(), "");
        let mut request = Request::get(&url);
        request.set_header("Range", "bytes=0-31");
        let mut part = handle_main(request).unwrap();
        assert_eq!(part.get_status(), StatusCode::PARTIAL_CONTENT);
        assert_eq!(part.get_header_str("X-Divine-Storage-Cache"), Some("HIT"));
        assert_eq!(
            part.get_header_str("Content-Range"),
            Some(format!("bytes 0-31/{size}").as_str())
        );
        assert_eq!(part.take_body().into_bytes(), vec![b'A'; 32]);
    }

    #[test]
    #[ignore = "requires demand fixtures; scripts/run-b2-canary-tests.py"]
    fn demand_cached_oversize_streams_without_fill() {
        use sha2::{Digest, Sha256};
        use std::io::Read;
        let config = fastly::config_store::ConfigStore::open("blossom_config");
        let hash = config.get("test_hash").unwrap();
        let size = config.get("test_size").unwrap().parse::<usize>().unwrap();
        assert_eq!(size, 32 * 1024 * 1024 + 1);
        let url = format!("https://media-b2.divine.video/{hash}");
        let mut response = handle_main(Request::get(&url)).unwrap();
        assert_eq!(response.get_status(), StatusCode::OK);
        assert_eq!(
            response.get_header_str("X-Divine-Storage-Cache"),
            Some("BYPASS")
        );
        assert_eq!(
            response.get_header_str("X-Divine-Storage-Cache-Reason"),
            Some("ineligible")
        );
        assert!(response
            .get_header("X-Divine-Storage-Cache-Buffered-Bytes")
            .is_none());
        // Model streaming delivery; collecting 32MiB+1 with read_to_end can
        // double a test consumer's Vec and exhaust its unrelated guest heap.
        let mut body = response.take_body();
        let mut digest = Sha256::new();
        let mut received = 0;
        let mut chunk = vec![0; 64 * 1024];
        loop {
            let count = body.read(&mut chunk).unwrap();
            if count == 0 {
                break;
            }
            digest.update(&chunk[..count]);
            received += count;
        }
        assert_eq!(received, size);
        assert_eq!(hex::encode(digest.finalize()), hash);
        let head = handle_main(Request::new("HEAD", url)).unwrap();
        assert_eq!(head.get_status(), StatusCode::OK);
        assert_eq!(
            head.get_header_str("X-Divine-Storage-Cache"),
            Some("BYPASS")
        );
    }

    #[test]
    #[ignore = "requires demand fixtures; scripts/run-b2-canary-tests.py"]
    fn demand_cached_fill_failure_contract() {
        let config = fastly::config_store::ConfigStore::open("blossom_config");
        let hash = config.get("test_hash").unwrap();
        let body = config.get("test_body").unwrap();
        let timeout = config.get("test_cache_failure").as_deref() == Some("timeout");
        let url = format!("https://media-b2.divine.video/{hash}");
        let mut first = handle_main(Request::get(&url)).unwrap();
        if timeout {
            assert_eq!(first.get_status(), StatusCode::OK);
            assert_eq!(first.get_header_str("X-Divine-Storage-Cache"), Some("MISS"));
            assert_eq!(
                first.get_header_str("X-Divine-Storage-Cache-Reason"),
                Some("streaming_insert")
            );
            assert_eq!(first.take_body().into_string(), body);
            await_cache_collection(body.len() as u64);
        } else {
            assert_eq!(first.get_status(), StatusCode::BAD_GATEWAY);
        }
        let mut retry = handle_main(Request::get(&url)).unwrap();
        assert_eq!(retry.get_status(), StatusCode::OK);
        assert_eq!(
            retry.get_header_str("X-Divine-Storage-Cache"),
            Some(if timeout { "HIT" } else { "MISS" })
        );
        assert_eq!(retry.take_body().into_string(), body);
        if !timeout {
            await_cache_collection(body.len() as u64);
        }
        let mut warm = handle_main(Request::get(&url)).unwrap();
        assert_eq!(warm.get_header_str("X-Divine-Storage-Cache"), Some("HIT"));
        assert_eq!(warm.take_body().into_string(), body);
    }

    #[test]
    #[ignore = "requires demand fixtures; scripts/run-b2-canary-tests.py"]
    fn demand_cached_playback_contract() {
        use fastly::config_store::ConfigStore;
        let config = ConfigStore::open("blossom_config");
        let source = config.get("test_source").unwrap();
        let expected = config.get("test_body").unwrap();
        let hash = config.get("test_hash").unwrap();
        let url = format!("https://media-b2.divine.video/{hash}");
        let read = |method: &str, range: Option<&str>| {
            let mut req = Request::new(method, &url);
            if let Some(range) = range {
                req.set_header("Range", range);
            }
            handle_main(req).unwrap()
        };
        let mut first = read("GET", None);
        assert_eq!(first.get_status(), StatusCode::OK);
        assert_eq!(first.get_header_str("X-Divine-Storage-Cache"), Some("MISS"));
        assert_eq!(first.take_body().into_string(), expected);
        await_cache_collection(expected.len() as u64);
        let mut second = read("GET", None);
        assert_eq!(second.get_header_str("X-Divine-Storage-Cache"), Some("HIT"));
        assert_eq!(
            second.get_header_str("X-Divine-Storage-Cache-Reason"),
            Some("hit")
        );
        assert_eq!(
            second.get_header_str("X-Divine-Source"),
            Some(source.as_str())
        );
        assert_eq!(
            second.get_header_str("Cache-Control"),
            Some("private, no-store")
        );
        assert_eq!(second.take_body().into_string(), expected);
        let mut head = read("HEAD", None);
        assert_eq!(head.get_status(), StatusCode::OK);
        assert_eq!(head.get_header_str("X-Divine-Storage-Cache"), Some("HIT"));
        assert_eq!(head.take_body().into_string(), "");
        let mut part = read("GET", Some("bytes=1-3"));
        assert_eq!(part.get_status(), StatusCode::PARTIAL_CONTENT);
        assert_eq!(part.get_header_str("X-Divine-Storage-Cache"), Some("HIT"));
        assert_eq!(part.get_header_str("Content-Range"), Some("bytes 1-3/9"));
        assert_eq!(part.take_body().into_string(), &expected[1..4]);
        let mut unsat = read("GET", Some("bytes=9223372036854775808-"));
        assert_eq!(unsat.get_status(), StatusCode::RANGE_NOT_SATISFIABLE);
        assert_eq!(unsat.get_header_str("X-Divine-Storage-Cache"), Some("HIT"));
        assert_eq!(unsat.get_header_str("Content-Range"), Some("bytes */9"));
        assert_eq!(unsat.take_body().into_string(), "");
        fastly::http::purge::purge_surrogate_key(&hash).unwrap();
        let mut after_purge = read("GET", None);
        assert_eq!(
            after_purge.get_header_str("X-Divine-Storage-Cache"),
            Some("MISS")
        );
        assert_eq!(after_purge.take_body().into_string(), expected);
        await_cache_collection(expected.len() as u64);
        let store = crate::metadata::open_store().unwrap();
        let mut metadata = crate::metadata::get_blob_metadata_uncached(&hash)
            .unwrap()
            .unwrap();
        metadata.status = crate::blossom::BlobStatus::Restricted;
        store
            .insert(
                &format!("blob:{hash}"),
                serde_json::to_string(&metadata).unwrap(),
            )
            .unwrap();
        let denied = handle_main(Request::get(&url)).unwrap();
        assert_eq!(denied.get_status(), StatusCode::NOT_FOUND);
        metadata.status = crate::blossom::BlobStatus::Active;
        store
            .insert(
                &format!("blob:{hash}"),
                serde_json::to_string(&metadata).unwrap(),
            )
            .unwrap();
        store
            .insert(&format!("b2-sync:v1:{hash}"), r#"{"state":"erasing"}"#)
            .unwrap();
        let denied = handle_main(Request::get(&url)).unwrap();
        assert_eq!(denied.get_status(), StatusCode::NOT_FOUND);
    }

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
        let initial_status = meta.status;
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
            initial_status
        );
        meta.status = initial_status;
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
