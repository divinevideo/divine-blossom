# Playback delivery telemetry

This producer is disabled by default. It emits the explicit
`divine.media.delivery.v1` schema to the existing `cdn-view-logs` logging endpoint.
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
or logging failures fail open. Each emitted line fixes its event ID, so Pub/Sub
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
B2 native erasure authorization is excluded. A source field is an attempted media
origin, including transport or HTTP failures, rather than proof of bytes received.
When both origins are attempted, the final attempted media source is reported.
Demand fallback reasons are recorded at the observed branch: missing readiness,
missing version, unavailable origin, copying, or oversized. Strict B2 mode never
falls back and reports `fallback=none` even when it returns unavailable.
Direct canary requests bypass outer VCL, so `outer_cache=bypass`.

The separate storage-cache work must integrate these typed hooks before its
telemetry is enabled. On a cache hit, set `provider=none, storage_cache=hit`;
`X-Divine-Source` on a hit describes fill provenance and must not become the
provider. On a cache miss, preserve the actual media-send provider and set
`storage_cache=miss` after the fetch hook. Read fallback from request execution,
not cached headers. A cache hit does not imply zero network traffic: native
erasure authorization and policy reads can still run. This producer does not
change caching, outward no-store headers, policy checks, or erasure.

## Local verification and coverage

Run:

```sh
cargo test -p blossom-core --locked
cargo check --tests --locked
cargo clippy --locked --all-targets --all-features
VICEROY=/path/to/viceroy ./scripts/run-edge-tests.sh
VICEROY=/path/to/viceroy python3 scripts/run-playback-telemetry-tests.py
VICEROY=/path/to/viceroy python3 scripts/run-playback-origin-telemetry-tests.py
```

The first telemetry runner covers opt-in/host/UUID gates, request uniqueness,
all terminal status classes, privacy, and response cache/body neutrality. The
second reuses the existing local synthetic canary origin fixtures to verify
provider/cache/fallback against actual origin execution, including authorization
failures and fallback failures. No live infrastructure is used.

An example headers marker (synthetic IDs and timestamp):

```json
{"schema":"divine.media.delivery.v1","event_id":"22222222-2222-4222-a222-222222222222","load_id":"12345678-1234-4234-9234-123456789abc","request_id":"33333333-3333-4333-b333-333333333333","occurred_at_ms":1793900000000,"cohort":"b2_canary","stage":"compute_headers","method":"GET","status":206,"range_request":true,"provider":"b2","storage_cache":"bypass","outer_cache":"bypass","fallback":"none","header_ready_ms":7,"transfer_ms":null,"bytes_sent":null}
```

This does not establish production acceptance, consent/device correctness, sink
configuration, successful ClickHouse insertion, or end-to-end correlation. A
request killed by guest termination or disconnected before returning may emit
nothing. There is no observed send-complete callback and no `edge_complete`
coverage here. Counts and quantiles require cohort/day-bounded deduplicated reads
of the operational table; this marker alone is not full delivery coverage.
