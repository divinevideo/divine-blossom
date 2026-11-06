//! Private byte caching for the opt-in demand playback path.
//!
//! Callers perform authorization, policy and readiness checks on every request,
//! before reaching this module. Cache contents never substitute for those checks.
//! Callers also validate the worker-verified pinned B2 version or authoritative
//! immutable GCS object. This cache checks full size without rehashing the body.

use crate::error::{BlossomError, Result};
use crate::storage::{wait_for_demand_io, CanaryOrigin};
use fastly::cache::core::{CacheBusyHandle, Found, PendingTransaction, Transaction};
use fastly::http::{Method, StatusCode};
use fastly::{Body, Response};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::cell::Cell;
use std::io::{self, Read, Write};
use std::time::{Duration, Instant};

const MAX_CACHE_BYTES: u64 = 16 * 1024 * 1024;
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
            "divine-demand-playback-v1",
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

fn lookup(key: String, deadline: Instant) -> Option<Transaction> {
    if Instant::now() >= deadline {
        return None;
    }
    let pending = Transaction::lookup(key.into_bytes().into())
        .execute_async()
        .ok()?;
    // SAFETY: transfer ownership out solely to borrow the ABI handle for the
    // readiness wait. Reconstruct exactly once even when readiness fails; drop
    // then cancels the outstanding busy lookup without blocking on .wait().
    let raw = unsafe { pending.into_handle() }.into_abi();
    let ready = wait_for_demand_io(raw, deadline.min(Instant::now() + LOOKUP_BUDGET));
    let pending = unsafe { PendingTransaction::from_handle(CacheBusyHandle::from_abi(raw)) };
    ready.ok()?;
    pending.wait().ok()
}

fn marked(origin: CanaryOrigin, marker: &str) -> CanaryOrigin {
    match origin {
        CanaryOrigin::Delivered(mut response) => {
            response.set_header("X-Divine-Storage-Cache", marker);
            CanaryOrigin::Delivered(response)
        }
        other => other,
    }
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

enum Buffered {
    Complete(Vec<u8>),
    Streaming(Body),
    Unavailable,
}

#[allow(deprecated)] // Raw unbuffered body handles keep each read deadline-bounded.
fn buffer(body: Body, size: u64, deadline: Instant) -> Buffered {
    let mut body = body.into_handle();
    // The eligibility check guarantees size <= MAX_CACHE_BYTES. Reserve the
    // exact bounded space to avoid Vec's doubling on the final excess byte.
    let limit = size as usize + 1;
    let mut bytes = Vec::with_capacity(limit);
    let mut chunk = [0; 16 * 1024];
    loop {
        if !cpu_budget_available() {
            let mut prefix = Body::from(bytes);
            prefix.append(body.into());
            return Buffered::Streaming(prefix);
        }
        // SAFETY: this is a borrowed live body handle retained until after wait.
        if let Err(error) = wait_for_demand_io(unsafe { body.as_u32() }, deadline) {
            if error.kind() != io::ErrorKind::TimedOut {
                return Buffered::Unavailable;
            }
            let mut prefix = Body::from(bytes);
            prefix.append(body.into());
            return Buffered::Streaming(prefix);
        }
        let capacity = (limit - bytes.len()).min(chunk.len());
        match body.read(&mut chunk[..capacity]) {
            Ok(0) => return Buffered::Complete(bytes),
            Ok(read) => bytes.extend_from_slice(&chunk[..read]),
            Err(_) => return Buffered::Unavailable,
        }
        if bytes.len() as u64 > size {
            // Reaching this bound contradicts the verified advertised length.
            // Return the complete prefix for the caller's integrity rejection.
            return Buffered::Complete(bytes);
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
    if !identity.eligible()
        || (*method != Method::GET && *method != Method::HEAD)
        || !cpu_budget_available()
    {
        return fetch().map(|origin| marked(origin, "BYPASS"));
    }
    let digest = identity.digest();
    let Some(transaction) = lookup(format!("divine-demand-playback-v1:{digest}"), deadline) else {
        return fetch().map(|origin| marked(origin, "BYPASS"));
    };
    let mut transaction = CacheTransaction(Some(transaction));
    let current = transaction.0.as_ref().expect("owned transaction");
    if let Some(found) = current.found() {
        if found.is_usable() && !found.is_stale() && found.known_length() == Some(identity.size) {
            if let Some(metadata) = Metadata::decode(&found.user_metadata(), &digest, identity.size)
            {
                if let Some(response) = cached_response(&found, &metadata, method, range) {
                    return Ok(marked(CanaryOrigin::Delivered(response), "HIT"));
                }
            }
        }
    }
    // HEAD and range misses retain their genuine origin semantics and never fill.
    if *method != Method::GET || range.is_some() || !current.must_insert_or_update() {
        drop(transaction);
        return fetch().map(|origin| marked(origin, "BYPASS"));
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
        return Ok(marked(CanaryOrigin::Delivered(response), "BYPASS"));
    }
    let Some(metadata) = Metadata::from_response(&response, &digest, identity.size) else {
        return Ok(marked(CanaryOrigin::Delivered(response), "BYPASS"));
    };
    let encoded = match serde_json::to_vec(&metadata) {
        Ok(encoded) if encoded.len() <= MAX_METADATA_BYTES => encoded,
        _ => return Ok(marked(CanaryOrigin::Delivered(response), "BYPASS")),
    };
    if !cpu_budget_available() {
        return Ok(marked(CanaryOrigin::Delivered(response), "BYPASS"));
    }
    let bytes = match buffer(
        response.take_body(),
        identity.size,
        deadline.min(Instant::now() + BUFFER_BUDGET),
    ) {
        Buffered::Complete(bytes) => bytes,
        Buffered::Streaming(body) => {
            response.set_body(body);
            return Ok(marked(CanaryOrigin::Delivered(response), "BYPASS"));
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
        return Ok(marked(CanaryOrigin::Delivered(response), "BYPASS"));
    }
    // No cache reader sees a body until the complete expected size has arrived.
    // Keep the Vec for delivery so cache-write failures are harmless.
    let inserted = transaction
        .0
        .take()
        .expect("owned transaction")
        .insert(CACHE_TTL)
        .stale_while_revalidate(Duration::ZERO)
        .known_length(identity.size)
        .surrogate_keys([identity.hash])
        .user_metadata(encoded.into())
        .execute()
        .ok()
        .and_then(|mut writer| {
            writer.write_all(&bytes).ok()?;
            writer.finish().ok()
        })
        .is_some();
    response.set_body(bytes);
    Ok(marked(
        CanaryOrigin::Delivered(response),
        if inserted { "MISS" } else { "BYPASS" },
    ))
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
    fn cache_lookup_wait_is_bounded() {
        begin_request();
        let identity = identity();
        let key = format!("divine-demand-playback-v1:{}", identity.digest());
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
