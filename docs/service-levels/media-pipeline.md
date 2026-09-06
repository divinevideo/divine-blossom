# Production media pipeline service levels

This document defines the measurement contract for the user-visible video
publishing pipeline. It deliberately separates an **indicator** (what is
measured), an **objective** (the agreed target), and an **enforcement value**
(the timeout or alert configured by a consumer). A measured baseline is not an
objective, and an objective is not enforceable until its row is signed off.

Issue [#284](https://github.com/divinevideo/divine-blossom/issues/284) tracks
agreement on the objectives. Until every required owner has signed off and a
representative production run has validated the definitions, rows marked
`unset` must remain informational. In particular, [#282](https://github.com/divinevideo/divine-blossom/issues/282)
and [#283](https://github.com/divinevideo/divine-blossom/issues/283) must not
derive acceptance timeouts from provisional observations in this document.

## Status vocabulary

- **Indicator**: a precisely bounded measurement with a source, eligible
  population, and failure definition.
- **Observed baseline**: evidence from a dated run. It describes that run only.
- **Objective**: a percentile target and maximum failure rate over an evaluation
  window, approved by the owners named in the row.
- **Unset**: evidence or owner approval is missing. Consumers may record the
  indicator but may not fail a build or page an operator from it.
- **Enforcement value**: a test timeout, alert threshold, or sampling control.
  It is configured separately and must cite the objective it protects.

## Pipeline boundaries and ownership

An objective needs all of the following before its status can change from
`unset`: percentile and target, maximum failure rate, evaluation window,
minimum sample size, and recorded approval from every owning team. A person's
name is added only when that person confirms ownership; a directory entry or
issue assignment is not sign-off.

| Stage | Start boundary | Completion boundary | Representative request path | Owning repository or team | Named approver | Objective status |
| --- | --- | --- | --- | --- | --- | --- |
| Direct upload completion | Client begins the authenticated `PUT /upload` request | Client receives the successful Blossom descriptor after the body is accepted, stored, and the transcode request is initiated | `PUT https://media.divine.video/upload` through Fastly to the upload service | `divine-blossom` / platform | Unconfirmed | Unset — production distribution and owner sign-off required |
| Resumable upload completion | Client begins `POST /upload/init` | Client receives a successful response from `POST /upload/<session-id>/complete` after all origin chunks have been committed | Control requests through Fastly; chunk appends directly to `upload.divine.video`; completion through Fastly | `divine-blossom` / platform | Unconfirmed | Unset — origin correlation for chunk appends is missing |
| Progressive readiness | Successful upload completion is observed | `HEAD /<hash>/720p.mp4` first returns `200` or `206` | Fastly media route backed by the deployed transcoder | `divine-blossom` / platform | Unconfirmed | Unset — pending #283 representative run and sign-off |
| HLS readiness | Successful upload completion is observed | Both `HEAD /<hash>.hls` and `HEAD /<hash>/hls/stream_720p.m3u8` first return `200` or `206` | Fastly media routes backed by the deployed transcoder | `divine-blossom` / platform | Unconfirmed | Unset — pending #283 representative run and sign-off |
| Event publish acknowledgement | Client sends the already-signed kind-34236 event to the required relay | The required relay returns a positive Nostr `OK` acknowledgement for the event id | `wss://relay.divine.video` publish | `divine-funnelcake` | Unconfirmed | Unset — cross-repository indicator and sign-off required |
| Relay indexing and query visibility | Positive publish acknowledgement is received | A new relay subscription for the exact synthetic event coordinate returns the expected event | `wss://relay.divine.video` `REQ` against Funnelcake Relay and ClickHouse | `divine-funnelcake` | Unconfirmed | Unset — cross-repository instrumentation and sign-off required |
| Canonical REST read-back | Positive publish acknowledgement is received | The canonical REST API returns the expected event for the exact synthetic coordinate | `https://api.divine.video` through `divine-router` to `funnelcake-api` and ClickHouse | `divine-router` and `divine-funnelcake` | Unconfirmed | Unset — cross-repository instrumentation and sign-off required |
| Warm media response | Request headers are completely written on an established connection after warmup | Response headers arrive and prove a cache hit | Anonymous and credentialed bare-blob and derivative paths on `https://media.divine.video` | `divine-blossom` / platform | Unconfirmed | Unset — current evidence is a baseline, not an objective |
| Cold media response | Request headers are completely written after targeted invalidation proves the synthetic object cold | Response headers arrive; full-body completion is recorded separately | Anonymous and credentialed bare-blob and derivative paths on `https://media.divine.video` | `divine-blossom` / platform | Unconfirmed | Unset — pending #217 US run and sign-off |
| Media delivery throughput | First response byte arrives | The complete response body arrives | Same routes and cache states as the response-latency rows | `divine-blossom` / platform | Unconfirmed | Unset — representative client-network evidence and sign-off required |

The relay visibility row is an origin-side service level. The production relay
is a WebSocket service behind Cloudflare; a Nostr `REQ` has no reusable HTTP
object and cannot be improved by CDN caching. The REST row is separate because
`api.divine.video` is the canonical cached HTTP read path.

Every duration and failure-rate row in the table is a candidate **user-facing
objective** because it ends at an observable client result. The component
measurements used to explain those results are **internal indicators**:
`proxy_duration_ms`, FOS lookup, GCS fetch, body buffering, write-back, cache
hit state, transcode callback delivery, and ClickHouse query time. Internal
indicators may drive diagnosis or component alerts, but they do not substitute
for the user-facing objective and must not be added together as though
independently measured phases necessarily share one request trace.

## Eligibility, fixtures, and segmentation

All stage measurements use a dedicated synthetic identity and synthetic media.
Secrets and identifiers are supplied outside the repository. Results must not
contain the signing key, reusable credentials, media hashes, event ids, or real
user identifiers. Repeated end-to-end runs use a stable addressable event
coordinate so they replace the prior event instead of creating unbounded data.

The readiness and end-to-end fixtures are valid, supported short-form MP4 files
in these declared-size buckets, matching the existing upload telemetry:

- `<256 KiB`
- `256 KiB–1 MiB`
- `1–8 MiB`
- `8–32 MiB`

The smallest supported fixture is the routine acceptance case. The other
buckets are scheduled production measurements, not required on every build.
Objects above 32 MiB are reported separately: they do not exercise the same
Fastly Object Storage write-back path, even though the upload service supports
larger files.

Every result must retain these dimensions rather than aggregating across them:

- direct versus resumable upload;
- progressive MP4 versus HLS master versus HLS variant manifest;
- bare blob versus derivative;
- anonymous versus credentialed request;
- verified cold fill versus verified cache hit;
- declared object-size bucket;
- US versus non-US region and the actual serving POP;
- connection setup, established-connection response latency, and full-body
  transfer time.

North America represented about 85% of delivered watch time in the measurement
window documented in the [corrected four-region comparison](../measurements/2026-08-07-four-region-corrected.md).
That weighting explains why a representative US client vantage point is the
primary sign-off region; it must not be used to hide failures elsewhere.
Non-US regions are evaluated separately, and no region passes by averaging it
with a faster one.

## Indicator definitions

For a stage with durations `D`, report p50, p95, and p99 when the sample size
supports them. The objective percentile is still unset until sign-off. Report
the failure rate as:

```text
failed eligible attempts / all eligible attempts
```

An eligible attempt fails when it reaches a terminal error, produces an invalid
or contradictory response, or does not reach the completion boundary inside
the separately declared observation window. A client cancellation counts as a
failure when it occurs after the stage start boundary. Invalid fixtures,
operator-aborted probes, probe-host failures before the start boundary, and
planned service maintenance are excluded and counted explicitly; they are never
silently dropped.

Each result record must state:

- UTC start and end time;
- environment, client region, and serving POP;
- fixture class, route, authentication class, and cache state;
- instrument version or commit;
- attempts, exclusions, successes, terminal failures, and timeouts;
- p50, p95, p99, and maximum duration where statistically meaningful;
- failure rate and the raw counts behind it.

The evaluation window and minimum sample size remain unset for every objective.
Those values require owner approval alongside the percentile and failure-rate
target; a one-off successful production probe is validation of the boundary,
not evidence of sustained service level.

## Measurement methods

### Upload

Use `nostr.edge_upload_logs` as documented in the [edge upload observability
runbook](../runbooks/edge-upload-observability.md). `duration_ms` bounds the
whole edge request, `proxy_duration_ms` bounds the origin send, and
`send_error` records an incomplete send. Segment by route, declared size, and
client geography. The Fastly 120-second request ceiling is an infrastructure
limit, not an objective. Counts at or above it are especially incomplete because
the edge cannot record requests terminated before its log is emitted.

Edge logs cover direct uploads and resumable control requests. Resumable chunk
appends go from the client to `upload.divine.video` and therefore require
origin-log correlation before resumable end-to-end objectives can be set.

### Progressive and HLS readiness

Use [`scripts/probe_video_readiness.py`](../../scripts/probe_video_readiness.py).
It records elapsed seconds for `720p.mp4`, the HLS master, and the 720p variant
manifest independently. A terminal derivative failure must fail the eventual
acceptance check immediately; pending `202` responses may be retried only
inside the agreed observation window. Issue #283 owns the assertion mode and
representative production evidence.

### Publish, indexing, and REST visibility

The end-to-end harness from #282 will timestamp the send boundary, positive
relay acknowledgement, exact-coordinate relay result, and exact-coordinate
canonical REST result independently. A successful acknowledgement does not
prove indexing, and relay visibility does not prove REST visibility. The
Funnelcake and Divine Router owners must confirm the protocol boundaries and
sign off before these observations become objectives.

Keycast signing completes before the event-publish stage begins and is not
silently included in its duration. If signing latency needs an objective, add a
separate Keycast-owned indicator with its own start and completion boundaries.

### Warm delivery

Use [`scripts/probe_cdn_delivery.py`](../../scripts/probe_cdn_delivery.py).
Its default warmup requests are unmeasured. It reports DNS/TCP/TLS connection
setup separately from time to response headers on an established connection,
then reports full-response throughput. Candidate comparison failures require
both the configured relative regression and the default 10 ms absolute floor;
request errors bypass that floor.

The current observed US cache-hit baseline is **13 ms established-connection
response latency** from a GCE `us-central1` vantage point, with Fastly connection
setup measured separately at 29 ms. The run used warm objects and datacenter
networking, so it is optimistic and is not an objective. The earlier 49 ms p50 /
53 ms p95 values included a fresh TLS handshake per request and are superseded.

### Cold delivery

Use [`scripts/probe-cold-blob.sh`](../../scripts/probe-cold-blob.sh) according
to the [cold-fill validation runbook](../runbooks/cold-fill-validation.md). It
uses targeted surrogate-key invalidation of fresh synthetic objects, covers
anonymous and ephemeral-credential paths, and correlates client results with
privacy-safe phase diagnostics: FOS lookup, GCS fetch, body buffering, and
write-back. Never globally purge the cache to collect a baseline.

The Christchurch baseline recorded six successful anonymous bare-blob fills
with a median of 1.744 seconds and a range of 0.757–5.836 seconds. It did not
verify cold state before the request and is not representative US evidence.
Issue #217 must supply the US anonymous, credentialed, and concurrent results
before a cold-fill objective is proposed.

The mobile client observations in that baseline included two prefetches
cancelled at 8.001 seconds. This is a client hard-failure boundary that any
delivery objective must sit safely below; it is not itself an objective and
does not establish which pipeline stage consumed the time.

## Existing sampling control

`blossom-core/src/request_diagnostics.rs` persists successful bare-blob
diagnostics at or above `SLOW_BLOB_THRESHOLD_MS = 750`. This value controls
diagnostic sampling only. It is not an agreed latency objective, alert
threshold, or evidence that a 749 ms response is acceptable.

The 750 ms value is provisional because no rationale tied to an approved
objective is recorded. Do not change it as part of #284. After the delivery
objectives are signed off, verify that the sampler captures enough slow traffic
without flooding the sink. If it does not, track and review that enforcement
change separately.

## Consumers and enforcement gate

| Consumer | Budget rows consumed | Allowed before sign-off | Enforcement after sign-off |
| --- | --- | --- | --- |
| #282 production pipeline acceptance | Direct or resumable upload, progressive/HLS readiness, publish acknowledgement, relay visibility, REST read-back, delivery | Record stage timings and explicit failures | Apply a separately reviewed timeout to each stage; never one opaque end-to-end timeout |
| #283 transcode readiness acceptance | Progressive readiness and HLS readiness | Record readiness order, pending states, and terminal failures | Bound pending retries by each signed readiness objective; terminal failures remain immediate |
| `SLOW_BLOB_THRESHOLD_MS` | Warm and cold bare-blob response indicators | Sample diagnostics at the current provisional 750 ms control | Reconcile the sampling control in a separate change; it does not enforce the objective |
| Future burn-rate alert | Any signed objective with continuous telemetry | No paging from an unset row | Alert from error-budget consumption over approved short and long windows, not from a single slow request |

An enforcement change must cite the signed objective, state the exact metric and
segments it consumes, and include a rollback path. Updating this document alone
does not authorize production probes, cache purges, configuration changes,
alerts, or acceptance-test failures.

## Sign-off and evidence checklist

- [ ] Divine Blossom/platform owners approve upload, readiness, and delivery
  definitions, percentile targets, failure rates, windows, and sample sizes.
- [ ] Funnelcake owners approve publish acknowledgement, relay visibility, and
  canonical REST read-back definitions and targets.
- [ ] Divine Router owners approve the canonical REST edge boundary.
- [ ] #217 records the representative US anonymous, credentialed, and
  concurrent cold-fill run.
- [ ] #283 records a supported production upload reaching progressive and HLS
  readiness and a controlled terminal-failure result.
- [ ] #282 runs the exact-coordinate production pipeline twice without
  accumulating unbounded artifacts.
- [ ] Each approved row records the approving person, approval link, target,
  percentile, failure rate, evaluation window, and minimum sample size.
- [ ] Only then are consuming timeouts and alerts proposed in separate,
  reviewable enforcement changes.
