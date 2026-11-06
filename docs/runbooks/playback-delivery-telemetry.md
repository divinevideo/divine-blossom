# Playback delivery telemetry

This producer is disabled by default. It emits the explicit
`divine.media.delivery.v1` schema to a Compute logging endpoint named
cdn-view-logs, targeting the existing topic. That endpoint still requires
operator provisioning: the current read-only preflight found it only on outer
VCL, not Compute. Follow the [endpoint setup and bounded acceptance
runbook](playback-delivery-endpoint-setup.md) before enabling the flag.
The subscriber must dispatch this schema into the operational delivery table;
these records must never become legacy views or recommendation events.

Collection requires all three conditions:

- `b2_playback_telemetry_enabled` is exactly `true` in `blossom_config`.
- The request passes the existing direct-host `b2_canary_host` routing checks.
- A GET or HEAD carries a canonical lowercase UUID v4 `X-Playback-Load-Id`.

Forwarded host headers cannot activate collection. Other methods, malformed IDs,
and disabled requests do not emit. This change adds no configuration values or
activation/deployment step. Backend schema-dispatch acceptance must precede any
operator enabling the flag. Removing the flag or setting it to `false` stops
collection independently of media delivery.

## Boundary and correlation

Every eligible request that returns an HTTP response emits once, including
4xx/5xx, HEAD, and zero-body responses. The marker is `stage=compute_headers`.
`header_ready_ms` measures monotonic time from entry to `handle_main` until its
response is ready, including policy guards. Durations outside the contract's
600000 ms range become null rather than being clamped. `transfer_ms` and
`bytes_sent` are always null: Content-Length is not observed network delivery.

WASI `random_get` supplies separate random UUID v4 event and request IDs. The
caller retry ID used by existing request logs remains unchanged and is not reused
for telemetry. `X-Playback-Request-Id` is attached to the final response only after
all routing, storage and cache work. IDs and observations are held in request
memory, never in URLs, cache keys, media objects, or cached responses. Randomness
or logging failures fail open. Each emitted record fixes its event ID, so Pub/Sub
redelivery keeps the original ID and payload. Do not regenerate records during
transport retry.

The fixed wire field set contains only correlation IDs, event time, finite
dimensions, status, and measured timing. It excludes content identifiers, URLs,
paths, IPs, account identifiers, authorization, and error text. These technical
IDs are untrusted correlation, never authorization.

## Execution observations

`delivery_telemetry::observe(Provider, Cache)` and
`delivery_telemetry::fallback(Fallback)` update request-local typed state only
while a cohort context exists. Uninstrumented paths remain `unknown`.

Canary entry records `provider=none` until a media-origin send is attempted.
Actual B2/GCS media sends record their provider and `storage_cache=bypass`;
B2 native erasure authorization is excluded. On a final storage-cache hit,
`provider=none` means the selected delivery was served from cache. Otherwise
provider identifies the last attempted media source, including transport/HTTP
failure. It is not proof of bytes received.

`origin_attempted` is an optional boolean: true when ANY media-origin send was
attempted in this execution, false when the instrumented request scope saw none,
and null when that scope is not reliably known. Request-local context starts
false; only an actual media-send site changes it to true. A later cache hit
cannot reset it. Thus failed B2 followed by a GCS fallback cache hit reports
`provider=none, storage_cache=hit, fallback=unavailable, origin_attempted=true`.
Missing readiness followed by a GCS cache hit reports `origin_attempted=false`.
Native erasure authorization, policy reads, and metadata I/O do not count as
media-origin attempts. The flat record does not describe each individual attempt.

The cache's actual return branches update typed request-local state directly.
A usable cache hit reports `storage_cache=hit`; a completed cache fill reports
`miss`; paths that decline or cannot complete caching report `bypass`, matching
the existing outward marker semantics. Failed fills are not successful MISS
fills. Cached X-Divine-Source remains fill provenance and is never read as a
telemetry provider. Fallback reasons come from the observed demand branch:
missing readiness/version, unavailable origin, copying, or oversized. Strict B2
mode never falls back and reports `fallback=none` even if it is unavailable.
Direct canary requests bypass outer VCL, so `outer_cache=bypass`.

These observations do not change cache keys, cached metadata/bytes, outward
no-store headers, policy checks, or erasure. Cache hits can still perform native
authorization and policy network calls; neither `provider=none` nor
`origin_attempted=false` means there was no network traffic at all.

## Local verification and coverage

Run:

```sh
cargo test -p blossom-core --locked
cargo check --tests --locked
cargo clippy --locked --all-targets --all-features
VICEROY=/path/to/viceroy ./scripts/run-edge-tests.sh
VICEROY=/path/to/viceroy python3 scripts/run-playback-telemetry-tests.py
VICEROY=/path/to/viceroy python3 scripts/run-playback-origin-telemetry-tests.py
VICEROY=/path/to/viceroy python3 scripts/run-playback-cache-telemetry-tests.py
```

The first telemetry runner covers opt-in/host/UUID gates, request uniqueness,
all terminal status classes, privacy, and response cache/body neutrality. The
second reuses the existing local synthetic canary origin fixtures to verify
provider/cache/fallback against actual origin execution, including authorization
failures and fallback failures. The cache runner verifies cold MISS, warm HIT,
HEAD BYPASS, missing-readiness fallback HIT, failed-B2 fallback HIT, fresh request
IDs across cached responses, and the distinct media-attempt boolean. No live
infrastructure is used.

An example headers marker (synthetic IDs and timestamp):

```json
{"schema":"divine.media.delivery.v1","event_id":"22222222-2222-4222-a222-222222222222","load_id":"12345678-1234-4234-9234-123456789abc","request_id":"33333333-3333-4333-b333-333333333333","occurred_at_ms":1793900000000,"cohort":"b2_canary","stage":"compute_headers","method":"GET","status":206,"range_request":true,"provider":"b2","storage_cache":"bypass","outer_cache":"bypass","fallback":"none","origin_attempted":true,"header_ready_ms":7,"transfer_ms":null,"bytes_sent":null}
```

This does not establish production acceptance, consent/device correctness, sink
configuration, successful ClickHouse insertion, or end-to-end correlation. A
request killed by guest termination or disconnected before returning may emit
nothing. There is no observed send-complete callback and no `edge_complete`
coverage here. Counts and quantiles require cohort/day-bounded deduplicated reads
of the operational table; this marker alone is not full delivery coverage.
