//! Private byte caching for the opt-in demand playback path.
//!
//! Callers perform authorization, policy and readiness checks on every request,
//! before reaching this module. Cache contents never substitute for those checks.
//! Callers also validate the worker-verified pinned B2 version or authoritative
//! immutable GCS object. This cache checks full size without rehashing the body.

use crate::error::{BlossomError, Result};
use crate::storage::{wait_for_demand_io, CanaryOrigin};
use fastly::cache::core::{CacheBusyHandle, CacheError, Found, PendingTransaction, Transaction};
use fastly::http::body::StreamingBody;
use fastly::http::{Method, StatusCode};
use fastly::{Body, Response};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::cell::Cell;
use std::io::{self, Read, Write};
use std::time::{Duration, Instant};

const MAX_CACHE_BYTES: u64 = 32 * 1024 * 1024;
const BUFFER_READ_BYTES: usize = 256 * 1024;
const CACHE_NAMESPACE: &str = "divine-demand-playback-v2";
const MAX_METADATA_BYTES: usize = 4096;
const MAX_HEADER_BYTES: usize = 1024;
const CACHE_TTL: Duration = Duration::from_secs(3600);
const LOOKUP_BUDGET: Duration = Duration::from_millis(50);
const BUFFER_BUDGET: Duration = Duration::from_secs(3);
const REQUEST_CPU_BUDGET_MS: u64 = 25;

thread_local! {
    static REQUEST_CPU_BASELINE: Cell<Option<u64>> = const { Cell::new(None) };
}

/// Reset at the start of each request, including requests in a reused test VM.
pub(crate) fn begin_request() {
    REQUEST_CPU_BASELINE.set(fastly::compute_runtime::elapsed_vcpu_ms().ok());
}

fn within_cpu_budget(baseline: Option<u64>, current: Option<u64>) -> bool {
    baseline
        .zip(current)
        .and_then(|(baseline, current)| current.checked_sub(baseline))
        .is_some_and(|consumed| consumed < REQUEST_CPU_BUDGET_MS)
}

fn cpu_budget_available() -> bool {
    within_cpu_budget(
        REQUEST_CPU_BASELINE.get(),
        fastly::compute_runtime::elapsed_vcpu_ms().ok(),
    )
}

pub(crate) struct Identity<'a> {
    pub source: &'a str,
    pub host: &'a str,
    pub bucket: &'a str,
    pub key: &'a str,
    pub hash: &'a str,
    pub size: u64,
    pub version: Option<&'a str>,
}

impl Identity<'_> {
    fn digest(&self) -> String {
        // JSON's tuple encoding preserves boundaries, escaping and None versus
        // Some(""). The namespace also versions both key and metadata contracts.
        let encoded = serde_json::to_vec(&(
            CACHE_NAMESPACE,
            self.source,
            self.host,
            self.bucket,
            self.key,
            self.hash,
            self.size,
            self.version,
        ))
        .expect("string tuple serialization is infallible");
        hex::encode(Sha256::digest(encoded))
    }

    fn eligible(&self) -> bool {
        self.size <= MAX_CACHE_BYTES
            && self.hash.len() == 64
            && self
                .hash
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Metadata {
    identity: String,
    size: u64,
    etag: Option<String>,
    last_modified: Option<String>,
}

fn safe_header(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_HEADER_BYTES
        && value.bytes().all(|b| (b' '..=b'~').contains(&b))
}

impl Metadata {
    fn valid(&self, identity: &str, size: u64) -> bool {
        self.identity == identity
            && self.size == size
            && self.etag.as_deref().is_none_or(safe_header)
            && self.last_modified.as_deref().is_none_or(safe_header)
    }

    fn decode(bytes: &[u8], identity: &str, size: u64) -> Option<Self> {
        if bytes.len() > MAX_METADATA_BYTES {
            return None;
        }
        let metadata: Self = serde_json::from_slice(bytes).ok()?;
        metadata.valid(identity, size).then_some(metadata)
    }

    fn from_response(response: &Response, identity: &str, size: u64) -> Option<Self> {
        fn header(response: &Response, name: &str) -> Option<Option<String>> {
            match response.get_header(name) {
                None => Some(None),
                Some(value) => {
                    let value = value.to_str().ok()?;
                    safe_header(value).then(|| Some(value.to_owned()))
                }
            }
        }
        Some(Self {
            identity: identity.to_owned(),
            size,
            etag: header(response, "ETag")?,
            last_modified: header(response, "Last-Modified")?,
        })
    }

    fn set_headers(&self, response: &mut Response) {
        if let Some(value) = &self.etag {
            response.set_header("ETag", value.as_str());
        }
        if let Some(value) = &self.last_modified {
            response.set_header("Last-Modified", value.as_str());
        }
    }
}

// Explicitly release leadership on every early return, including origin errors.
struct CacheTransaction(Option<Transaction>);

impl Drop for CacheTransaction {
    fn drop(&mut self) {
        if let Some(transaction) = self.0.take() {
            if transaction.must_insert_or_update() {
                let _ = transaction.cancel_insert_or_update();
            }
        }
    }
}

fn lookup(key: String, deadline: Instant) -> std::result::Result<Transaction, &'static str> {
    if Instant::now() >= deadline {
        return Err("lookup_timeout");
    }
    let pending = Transaction::lookup(key.into_bytes().into())
        .execute_async()
        .map_err(|_| "lookup_start")?;
    // SAFETY: transfer ownership out solely to borrow the ABI handle for the
    // readiness wait. Reconstruct exactly once even when readiness fails; drop
    // then cancels the outstanding busy lookup without blocking on .wait().
    let raw = unsafe { pending.into_handle() }.into_abi();
    let ready = wait_for_demand_io(raw, deadline.min(Instant::now() + LOOKUP_BUDGET));
    let pending = unsafe { PendingTransaction::from_handle(CacheBusyHandle::from_abi(raw)) };
    ready.map_err(|error| {
        if error.kind() == io::ErrorKind::TimedOut {
            "lookup_timeout"
        } else {
            "lookup_select"
        }
    })?;
    pending.wait().map_err(|_| "lookup_wait")
}

fn marked(origin: CanaryOrigin, marker: &str, reason: &'static str) -> CanaryOrigin {
    match origin {
        CanaryOrigin::Delivered(mut response) => {
            response.set_header("X-Divine-Storage-Cache", marker);
            response.set_header("X-Divine-Storage-Cache-Reason", reason);
            CanaryOrigin::Delivered(response)
        }
        other => other,
    }
}

pub(crate) fn disabled(origin: CanaryOrigin) -> CanaryOrigin {
    marked(origin, "BYPASS", "disabled")
}

/// These observations belong to this request, never the cached object metadata.
/// Fixed reason codes distinguish a disabled POP from an admission bypass.
pub(crate) fn attach_diagnostics(response: &mut Response, enabled: bool) {
    response.set_header(
        "X-Divine-Storage-Cache-Enabled",
        if enabled { "true" } else { "false" },
    );
    if response
        .get_header("X-Divine-Storage-Cache-Reason")
        .is_none()
    {
        response.set_header(
            "X-Divine-Storage-Cache-Reason",
            if enabled { "unobserved" } else { "disabled" },
        );
    }
    let version = fastly::compute_runtime::service_version().to_string();
    response.set_header("X-Divine-Storage-Cache-Compute", version);
    let consumed = REQUEST_CPU_BASELINE
        .get()
        .zip(fastly::compute_runtime::elapsed_vcpu_ms().ok())
        .and_then(|(baseline, current)| current.checked_sub(baseline));
    response.set_header(
        "X-Divine-Storage-Cache-Cpu-Ms",
        consumed
            .map(|value| value.to_string())
            .unwrap_or_else(|| "unknown".into()),
    );
    // Committed linear memory includes allocator free space and does not
    // measure live guest allocations or host cache/delivery buffers.
    #[cfg(target_arch = "wasm32")]
    response.set_header(
        "X-Divine-Storage-Cache-Linear-Memory-Bytes",
        (core::arch::wasm32::memory_size::<0>() as u64 * 65_536).to_string(),
    );
}

fn cached_response(
    found: &Found,
    metadata: &Metadata,
    method: &Method,
    range: Option<&str>,
) -> Option<Response> {
    let mut response = Response::from_status(StatusCode::OK);
    metadata.set_headers(&mut response);
    response.set_header("Content-Length", metadata.size.to_string());
    if *method == Method::HEAD {
        return Some(response);
    }
    match range {
        None => response.set_body(found.to_stream().ok()?),
        Some(range) => {
            // Reject malformed/multiple ranges instead of relying on the SDK's
            // invalid-range behavior, which can silently return the whole body.
            blossom_core::canary::single_range(Some(range))?;
            match blossom_core::canary::requested_span(range, metadata.size) {
                Some((start, end)) => {
                    response.set_status(StatusCode::PARTIAL_CONTENT);
                    response.set_header("Content-Length", (end - start + 1).to_string());
                    response.set_header(
                        "Content-Range",
                        format!("bytes {start}-{end}/{}", metadata.size),
                    );
                    response.set_body(found.to_stream_from_range(Some(start), Some(end)).ok()?);
                }
                None => {
                    response.set_status(StatusCode::RANGE_NOT_SATISFIABLE);
                    response.set_header("Content-Length", "0");
                    response.set_header("Content-Range", format!("bytes */{}", metadata.size));
                }
            }
        }
    }
    Some(response)
}

#[derive(Clone, Copy)]
struct BufferStats {
    bytes: usize,
    reads: u64,
}

impl BufferStats {
    fn attach(self, response: &mut Response) {
        response.set_header(
            "X-Divine-Storage-Cache-Buffered-Bytes",
            self.bytes.to_string(),
        );
        response.set_header(
            "X-Divine-Storage-Cache-Buffer-Reads",
            self.reads.to_string(),
        );
    }
}

enum Buffered {
    Complete(Vec<u8>, BufferStats),
    Streaming(Body, &'static str, BufferStats),
    Unavailable,
}

fn begin_insert(
    transaction: Transaction,
    metadata: Vec<u8>,
    identity: &Identity<'_>,
) -> std::result::Result<(StreamingBody, Found), CacheError> {
    transaction
        .insert(CACHE_TTL)
        .stale_while_revalidate(Duration::ZERO)
        // An explicit length would make an in-progress insertion eligible for
        // HIT before finish. Let the cache infer actual length on completion.
        .surrogate_keys([identity.hash])
        .user_metadata(metadata.into())
        .execute_and_stream_back()
}

fn replay_prefix(
    mut bytes: Vec<u8>,
    stats: BufferStats,
    remainder: Body,
    reason: &'static str,
) -> Buffered {
    bytes.truncate(stats.bytes);
    let mut prefix = Body::from(bytes);
    prefix.append(remainder);
    Buffered::Streaming(prefix, reason, stats)
}

#[allow(deprecated)] // Raw unbuffered body handles keep each read deadline-bounded.
fn buffer(body: Body, size: u64, deadline: Instant) -> Buffered {
    let mut body = body.into_handle();
    // The eligibility check guarantees size <= MAX_CACHE_BYTES. Reserve the
    // exact bounded space to avoid Vec's doubling on the final excess byte.
    let limit = size as usize + 1;
    let mut bytes: Vec<u8> = Vec::new();
    let mut stats = BufferStats { bytes: 0, reads: 0 };
    if bytes.try_reserve_exact(limit).is_err() {
        return Buffered::Streaming(body.into(), "allocation", stats);
    }
    // Read requires initialized memory. Reading directly into this one buffer
    // removes the staging copy, without unsafe uninitialized slices.
    // SAFETY: try_reserve_exact established capacity >= limit, the allocation
    // has no aliases, and every u8 is initialized before increasing length.
    // Use the bulk-memory intrinsic: an element-by-element debug resize can
    // itself exhaust the admission budget before the first origin read.
    unsafe {
        bytes.as_mut_ptr().write_bytes(0, limit);
        bytes.set_len(limit);
    }
    loop {
        if !cpu_budget_available() {
            return replay_prefix(bytes, stats, body.into(), "cpu_buffer");
        }
        // SAFETY: this is a borrowed live body handle retained until after wait.
        if let Err(error) = wait_for_demand_io(unsafe { body.as_u32() }, deadline) {
            if error.kind() != io::ErrorKind::TimedOut {
                return Buffered::Unavailable;
            }
            return replay_prefix(bytes, stats, body.into(), "buffer_timeout");
        }
        let capacity = (limit - stats.bytes).min(BUFFER_READ_BYTES);
        stats.reads += 1;
        match body.read(&mut bytes[stats.bytes..stats.bytes + capacity]) {
            Ok(0) => {
                bytes.truncate(stats.bytes);
                return Buffered::Complete(bytes, stats);
            }
            Ok(read) => stats.bytes += read,
            Err(_) => return Buffered::Unavailable,
        }
        if stats.bytes as u64 > size {
            // Reaching this bound contradicts the verified advertised length.
            // Return the complete prefix for the caller's integrity rejection.
            bytes.truncate(stats.bytes);
            return Buffered::Complete(bytes, stats);
        }
    }
}

pub(crate) fn read(
    identity: Identity<'_>,
    method: &Method,
    range: Option<&str>,
    deadline: Instant,
    fetch: impl FnOnce() -> Result<CanaryOrigin>,
) -> Result<CanaryOrigin> {
    if !identity.eligible() || (*method != Method::GET && *method != Method::HEAD) {
        return fetch().map(|origin| marked(origin, "BYPASS", "ineligible"));
    }
    if !cpu_budget_available() {
        return fetch().map(|origin| marked(origin, "BYPASS", "cpu_before_lookup"));
    }
    let digest = identity.digest();
    let transaction = match lookup(format!("{CACHE_NAMESPACE}:{digest}"), deadline) {
        Ok(transaction) => transaction,
        Err(reason) => return fetch().map(|origin| marked(origin, "BYPASS", reason)),
    };
    let mut transaction = CacheTransaction(Some(transaction));
    let current = transaction.0.as_ref().expect("owned transaction");
    if let Some(found) = current.found() {
        if found.is_usable() && !found.is_stale() && found.known_length() == Some(identity.size) {
            if let Some(metadata) = Metadata::decode(&found.user_metadata(), &digest, identity.size)
            {
                if let Some(response) = cached_response(&found, &metadata, method, range) {
                    return Ok(marked(CanaryOrigin::Delivered(response), "HIT", "hit"));
                }
            }
        }
    }
    // HEAD and range misses retain their genuine origin semantics and never fill.
    if *method != Method::GET || range.is_some() || !current.must_insert_or_update() {
        drop(transaction);
        return fetch().map(|origin| marked(origin, "BYPASS", "not_fill_leader"));
    }
    let origin = fetch()?;
    let CanaryOrigin::Delivered(mut response) = origin else {
        return Ok(origin);
    };
    if response.get_status() != StatusCode::OK
        || response.get_header("Content-Range").is_some()
        || response
            .get_header_str("Content-Length")
            .and_then(|v| v.parse::<u64>().ok())
            != Some(identity.size)
    {
        return Ok(marked(
            CanaryOrigin::Delivered(response),
            "BYPASS",
            "origin_headers",
        ));
    }
    let Some(metadata) = Metadata::from_response(&response, &digest, identity.size) else {
        return Ok(marked(
            CanaryOrigin::Delivered(response),
            "BYPASS",
            "origin_metadata",
        ));
    };
    let encoded = match serde_json::to_vec(&metadata) {
        Ok(encoded) if encoded.len() <= MAX_METADATA_BYTES => encoded,
        _ => {
            return Ok(marked(
                CanaryOrigin::Delivered(response),
                "BYPASS",
                "metadata_encoding",
            ))
        }
    };
    if !cpu_budget_available() {
        return Ok(marked(
            CanaryOrigin::Delivered(response),
            "BYPASS",
            "cpu_before_buffer",
        ));
    }
    let bytes = match buffer(
        response.take_body(),
        identity.size,
        deadline.min(Instant::now() + BUFFER_BUDGET),
    ) {
        Buffered::Complete(bytes, stats) => {
            stats.attach(&mut response);
            bytes
        }
        Buffered::Streaming(body, reason, stats) => {
            stats.attach(&mut response);
            response.set_body(body);
            return Ok(marked(CanaryOrigin::Delivered(response), "BYPASS", reason));
        }
        Buffered::Unavailable => return Ok(CanaryOrigin::Unavailable),
    };
    if bytes.len() as u64 != identity.size {
        return Err(BlossomError::StorageError(
            "Demand cache content size verification failed".into(),
        ));
    }
    if !cpu_budget_available() {
        response.set_body(bytes);
        return Ok(marked(
            CanaryOrigin::Delivered(response),
            "BYPASS",
            "cpu_before_insert",
        ));
    }
    // No cache reader sees a body until the complete expected size has arrived.
    // Keep the Vec for delivery so cache-write failures are harmless.
    let inserted = begin_insert(
        transaction.0.take().expect("owned transaction"),
        encoded,
        &identity,
    )
    .map_err(|_| "insert_unavailable")
    .and_then(|(mut writer, found)| {
        writer.write_all(&bytes).map_err(|_| "insert_write")?;
        writer.finish().map_err(|_| "insert_finish")?;
        // This insertion-owned handle snapshots metadata before finish and can
        // retain an unknown length. Successful complete write+finish authorizes
        // this full stream; future lookups still require the inferred length.
        found.to_stream().map_err(|_| "insert_stream")
    });
    let (marker, reason) = match inserted {
        Ok(body) => {
            // Cache has the complete body already; returning its host stream
            // avoids another whole-buffer guest-to-host delivery copy.
            response.set_body(body);
            ("MISS", "inserted")
        }
        Err(reason) => {
            response.set_body(bytes);
            ("BYPASS", reason)
        }
    };
    Ok(marked(CanaryOrigin::Delivered(response), marker, reason))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn identity() -> Identity<'static> {
        Identity {
            source: "b2",
            host: "objects.example.test",
            bucket: "media",
            key: "objects/video",
            hash: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            size: 12,
            version: Some("version-a"),
        }
    }

    #[test]
    #[ignore = "requires Viceroy Core Cache; scripts/run-b2-canary-tests.py"]
    fn incomplete_cache_insertion_is_not_a_hit() {
        begin_request();
        let cache_identity = identity();
        let digest = cache_identity.digest();
        let encoded = serde_json::to_vec(&Metadata {
            identity: digest.clone(),
            size: cache_identity.size,
            etag: None,
            last_modified: None,
        })
        .unwrap();
        let transaction =
            Transaction::lookup(format!("{CACHE_NAMESPACE}:{digest}").into_bytes().into())
                .execute()
                .unwrap();
        let (mut writer, found) = begin_insert(transaction, encoded, &cache_identity).unwrap();
        writer.write_all(b"first").unwrap();
        writer.flush().unwrap();
        let before = read(
            identity(),
            &Method::HEAD,
            None,
            Instant::now() + Duration::from_secs(1),
            || {
                Ok(CanaryOrigin::Delivered(Response::from_status(
                    StatusCode::OK,
                )))
            },
        )
        .unwrap();
        let CanaryOrigin::Delivered(before) = before else {
            panic!("origin response required")
        };
        assert_eq!(
            before.get_header_str("X-Divine-Storage-Cache"),
            Some("BYPASS")
        );
        assert_eq!(found.known_length(), None);
        writer.write_all(b" second").unwrap();
        writer.finish().unwrap();
        assert_eq!(found.to_stream().unwrap().into_bytes(), b"first second");
        // Handles snapshot length at lookup. Host collection can complete
        // asynchronously, so observe completion only through fresh lookups.
        let mut complete = false;
        for _ in 0..50 {
            let fresh =
                Transaction::lookup(format!("{CACHE_NAMESPACE}:{digest}").into_bytes().into())
                    .execute()
                    .unwrap();
            if fresh
                .found()
                .is_some_and(|item| item.known_length() == Some(12))
            {
                complete = true;
                break;
            }
            std::thread::sleep(Duration::from_millis(1));
        }
        assert!(
            complete,
            "finished insertion must acquire inferred exact length"
        );
        let after = read(
            identity(),
            &Method::GET,
            None,
            Instant::now() + Duration::from_secs(1),
            || panic!("completed cache item should be a HIT"),
        )
        .unwrap();
        let CanaryOrigin::Delivered(mut after) = after else {
            panic!("cache response required")
        };
        assert_eq!(after.get_header_str("X-Divine-Storage-Cache"), Some("HIT"));
        assert_eq!(after.take_body().into_bytes(), b"first second");
    }

    #[test]
    #[ignore = "requires Viceroy Core Cache; scripts/run-b2-canary-tests.py"]
    fn cache_lookup_wait_is_bounded() {
        begin_request();
        let identity = identity();
        let key = format!("{CACHE_NAMESPACE}:{}", identity.digest());
        let leader = Transaction::lookup(key.into_bytes().into())
            .execute()
            .unwrap();
        assert!(leader.must_insert_or_update());
        let started = Instant::now();
        let origin = read(
            identity,
            &Method::GET,
            None,
            started + Duration::from_secs(1),
            || Ok(CanaryOrigin::Delivered(Response::from_body("uncached"))),
        )
        .unwrap();
        assert!(started.elapsed() < Duration::from_millis(500));
        let CanaryOrigin::Delivered(mut response) = origin else {
            panic!("expected origin response")
        };
        assert_eq!(
            response.get_header_str("X-Divine-Storage-Cache"),
            Some("BYPASS")
        );
        assert_eq!(
            response.get_header_str("X-Divine-Storage-Cache-Reason"),
            Some("lookup_timeout")
        );
        assert_eq!(response.take_body().into_string(), "uncached");
        leader.cancel_insert_or_update().unwrap();
    }

    #[test]
    fn request_cpu_guard_requires_known_monotonic_budget_below_limit() {
        assert!(within_cpu_budget(Some(100), Some(100)));
        assert!(within_cpu_budget(Some(100), Some(124)));
        assert!(!within_cpu_budget(Some(100), Some(125)));
        assert!(!within_cpu_budget(Some(100), Some(126)));
        assert!(!within_cpu_budget(Some(100), Some(99)));
        assert!(!within_cpu_budget(None, Some(100)));
        assert!(!within_cpu_budget(Some(100), None));
        assert!(!within_cpu_budget(None, None));
        // A fresh request's baseline measures its own consumption rather than
        // rejecting a reused VM's cumulative vCPU counter.
        assert!(within_cpu_budget(Some(10_000), Some(10_024)));
    }

    #[test]
    fn ineligible_cache_diagnostic_preserves_origin_and_contains_no_identity() {
        begin_request();
        let mut identity = identity();
        identity.size = MAX_CACHE_BYTES + 1;
        let origin = read(
            identity,
            &Method::GET,
            None,
            Instant::now() + Duration::from_secs(1),
            || Ok(CanaryOrigin::Delivered(Response::from_body("origin bytes"))),
        )
        .unwrap();
        let CanaryOrigin::Delivered(mut response) = origin else {
            panic!("expected origin response")
        };
        assert_eq!(
            response.get_header_str("X-Divine-Storage-Cache"),
            Some("BYPASS")
        );
        assert_eq!(
            response.get_header_str("X-Divine-Storage-Cache-Reason"),
            Some("ineligible")
        );
        assert_eq!(response.take_body().into_string(), "origin bytes");
    }

    #[test]
    fn cache_eligibility_enforces_size_cap_and_content_hash_shape() {
        let mut identity = identity();
        identity.size = MAX_CACHE_BYTES;
        assert!(identity.eligible());
        identity.size += 1;
        assert!(!identity.eligible());
        identity.size = 0;
        assert!(identity.eligible());
        identity.hash = "not-a-content-hash";
        assert!(!identity.eligible());
        identity.hash = "ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789";
        assert!(!identity.eligible());
    }

    #[test]
    fn normal_video_sizes_through_32mib_are_cache_eligible() {
        for size in [8, 16, 32] {
            let mut identity = identity();
            identity.size = size * 1024 * 1024;
            assert!(identity.eligible(), "{size} MiB must be admitted");
        }
        let mut identity = identity();
        identity.size = 32 * 1024 * 1024 + 1;
        assert!(!identity.eligible());
    }

    #[test]
    fn initialized_buffer_truncates_short_reads_and_caps_excess() {
        begin_request();
        let Buffered::Complete(bytes, stats) = buffer(
            Body::from("abc"),
            12,
            Instant::now() + Duration::from_secs(1),
        ) else {
            panic!("short body must reach complete-length validation")
        };
        assert_eq!(bytes, b"abc");
        assert_eq!(stats.bytes, 3);
        assert!(stats.reads > 0);
        let Buffered::Complete(bytes, stats) = buffer(
            Body::from(vec![7; 64]),
            12,
            Instant::now() + Duration::from_secs(1),
        ) else {
            panic!("oversized body must reach complete-length validation")
        };
        assert_eq!(bytes, vec![7; 13]);
        assert_eq!(stats.bytes, 13);
    }

    #[test]
    fn replay_discards_initialized_unread_capacity() {
        let mut bytes = vec![0; 33];
        bytes[..3].copy_from_slice(b"abc");
        let Buffered::Streaming(body, reason, stats) = replay_prefix(
            bytes,
            BufferStats { bytes: 3, reads: 1 },
            Body::from("def"),
            "buffer_timeout",
        ) else {
            panic!("prefix replay must stream")
        };
        assert_eq!(body.into_bytes(), b"abcdef");
        assert_eq!(reason, "buffer_timeout");
        assert_eq!(stats.bytes, 3);
    }

    #[test]
    #[ignore = "requires Viceroy Core Cache; scripts/run-b2-canary-tests.py"]
    fn aborted_cache_insert_never_serves_a_partial_hit() {
        begin_request();
        let cache_identity = identity();
        let digest = cache_identity.digest();
        let encoded = serde_json::to_vec(&Metadata {
            identity: digest.clone(),
            size: 12,
            etag: None,
            last_modified: None,
        })
        .unwrap();
        let transaction =
            Transaction::lookup(format!("{CACHE_NAMESPACE}:{digest}").into_bytes().into())
                .execute()
                .unwrap();
        let (mut writer, _found) = begin_insert(transaction, encoded, &cache_identity).unwrap();
        writer.write_all(b"first").unwrap();
        writer.flush().unwrap();
        drop(writer);
        let response = read(
            identity(),
            &Method::GET,
            None,
            Instant::now() + Duration::from_secs(1),
            || {
                let mut origin = Response::from_body("first second");
                origin.set_header("Content-Length", "12");
                Ok(CanaryOrigin::Delivered(origin))
            },
        )
        .unwrap();
        let CanaryOrigin::Delivered(mut response) = response else {
            panic!("complete origin required")
        };
        assert_ne!(
            response.get_header_str("X-Divine-Storage-Cache"),
            Some("HIT")
        );
        assert_eq!(response.take_body().into_bytes(), b"first second");
    }

    #[test]
    fn identities_separate_all_origin_and_version_fields() {
        let original = identity().digest();
        for field in 0..8 {
            let mut other = identity();
            match field {
                0 => other.source = "gcs",
                1 => other.host = "other.example.test",
                2 => other.bucket = "other",
                3 => other.key = "objects/other",
                4 => {
                    other.hash = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
                }
                5 => other.size = 13,
                6 => other.version = None,
                _ => other.version = Some("version-b"),
            }
            assert_ne!(original, other.digest(), "field {field}");
        }
        let mut a = identity();
        a.bucket = "a/b";
        a.key = "c";
        let mut b = identity();
        b.bucket = "a";
        b.key = "b/c";
        assert_ne!(a.digest(), b.digest());
        a.version = None;
        b = Identity {
            version: Some(""),
            ..a
        };
        assert_ne!(a.digest(), b.digest());
    }

    #[test]
    fn metadata_rejects_mismatch_controls_and_oversized_values() {
        let mut metadata = Metadata {
            identity: identity().digest(),
            size: 12,
            etag: Some("\"fixture\"".into()),
            last_modified: Some("Wed, 01 Jan 2025 00:00:00 GMT".into()),
        };
        let digest = metadata.identity.clone();
        let encode = |m: &Metadata| serde_json::to_vec(m).unwrap();
        assert!(Metadata::decode(&encode(&metadata), &digest, 12).is_some());
        assert!(Metadata::decode(&encode(&metadata), "other", 12).is_none());
        assert!(Metadata::decode(&encode(&metadata), &digest, 13).is_none());
        metadata.etag = Some("bad\r\nheader".into());
        assert!(Metadata::decode(&encode(&metadata), &digest, 12).is_none());
        metadata.etag = Some("x".repeat(MAX_HEADER_BYTES + 1));
        assert!(Metadata::decode(&encode(&metadata), &digest, 12).is_none());
        assert!(Metadata::decode(&vec![b' '; MAX_METADATA_BYTES + 1], &digest, 12).is_none());
    }
}
